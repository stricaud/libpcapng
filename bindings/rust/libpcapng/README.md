# libpcapng

Safe, idiomatic Rust bindings for [libpcapng](https://github.com/stricaud/libpcapng) — pcapng file I/O, packet dissection, TCP reassembly, live capture, and declarative protocol extension via POSA.

```toml
[dependencies]
libpcapng = "0.15"
```

The C library is compiled from vendored sources at build time. You need `libclang-dev` (or the equivalent on your platform) for the bindgen step:

```
# Debian / Ubuntu
sudo apt install libclang-dev

# macOS (comes with Xcode Command Line Tools)
xcode-select --install
```

---

## Reading a pcapng file

```rust
use libpcapng::{read_file, BLOCK_EPB, BLOCK_IDB, BLOCK_SHB};

fn main() {
    read_file("capture.pcapng", |counter, block_type, data| {
        match block_type {
            BLOCK_SHB => println!("#{counter} Section Header"),
            BLOCK_IDB => println!("#{counter} Interface Description"),
            BLOCK_EPB => println!("#{counter} Enhanced Packet  ({} bytes)", data.len()),
            _         => println!("#{counter} block 0x{block_type:08x}"),
        }
        true  // return false to stop early
    }).unwrap();
}
```

---

## Writing a pcapng file

`Writer` writes a section header, one interface, and packets. Timestamps are
microseconds since the epoch:

```rust
use libpcapng::{Writer, LINKTYPE_ETHERNET};

fn save(frames: &[Vec<u8>]) -> Result<(), libpcapng::Error> {
    let mut w = Writer::create_with(
        "out.pcapng",
        LINKTYPE_ETHERNET,
        Some("what this capture is"),   // shown in Wireshark's file properties
        Some("my-tool 1.0"),
    )?;
    for (i, frame) in frames.iter().enumerate() {
        w.packet(frame, 1_700_000_000_000_000 + i as u64 * 1000)?;
    }
    w.finish()?;                        // flush, and report a failure to do so
    Ok(())
}
```

`Writer::new` takes any `std::io::Write`, so a capture can be built in a
`Vec<u8>` or streamed somewhere that is not a file. `packet_full` is for a
packet captured only in part, or one carrying a comment:

```rust
// 40 bytes kept of a frame that was 1514 on the wire
w.packet_full(&captured, 1514, timestamp_us, Some("truncated by snaplen"))?;
```

Prefer this over `libpcapng_write_enhanced_packet_with_time_to_file` from
`ffi`: that one takes its timestamp in whole seconds, so a tool writing more
than one packet per second loses their ordering in the file.

---

## Dissecting packets

`Dissection::new` turns raw Ethernet (or other link-layer) bytes into a protocol field tree with Wireshark-style summary columns:

```rust
use libpcapng::{Dissection, LINKTYPE_ETHERNET};

fn dissect(frame: &[u8]) {
    let d = Dissection::new(frame, LINKTYPE_ETHERNET).expect("allocation failed");
    println!("{} → {}  [{}]  {}", d.src(), d.dst(), d.proto(), d.info());
    // e.g. "192.168.1.1 → 8.8.8.8  [dns]  Standard query A example.com"
}
```

### Inspecting the field tree

Walk the protocol field tree with safe accessors — no raw pointers needed:

```rust
use libpcapng::{Dissection, LINKTYPE_ETHERNET};

fn print_fields(frame: &[u8]) {
    let d = Dissection::new(frame, LINKTYPE_ETHERNET).unwrap();

    let mut field = d.root_field();
    while let Some(f) = field {
        if !f.abbrev().is_empty() {
            println!("  {}  {}  (off={}, len={})", f.abbrev(), f.label(), f.offset(), f.byte_len());
        }
        field = f.next();
    }
}
```

Drill into nested protocol layers with `first_child()`:

```rust
let mut layer = d.root_field();
while let Some(f) = layer {
    println!("[{}]", f.label());
    let mut sub = f.first_child();
    while let Some(s) = sub {
        println!("    {} = {}", s.abbrev(), s.label());
        sub = s.next();
    }
    layer = f.next();
}
```

---

## Display filters

The same Wireshark/tshark-style filter engine every tool built on libpcapng
matches rules with. Compile an expression once, then test it against as many
packets as you like:

```rust
use libpcapng::{ensure_protocols, DisplayFilter, Dissection, LINKTYPE_ETHERNET};

fn main() -> Result<(), libpcapng::Error> {
    // Decoders have to be registered before a filter naming their fields is
    // compiled — see below.
    ensure_protocols();

    let suspicious = DisplayFilter::compile(r#"http.uri contains "/cgi-bin/""#)?;

    let frame: &[u8] = read_a_frame_somehow();
    if let Some(d) = Dissection::new(frame, LINKTYPE_ETHERNET) {
        if suspicious.matches(&d) {
            println!("{} → {}  {}", d.src(), d.dst(), d.info());
        }
    }
    Ok(())
}
```

Compiling once and matching many times is the whole performance story for a
rule-driven tool. The alternative — handing an expression and a packet to the
library together — re-parses the expression and re-dissects the packet for
every rule, so thirty rules cost thirty dissections of the same bytes. This way
a packet is dissected once and each rule is a walk of the resulting tree:
roughly 7 µs against a few hundred nanoseconds.

A `DisplayFilter` is immutable and matching only reads it, so it is `Send` and
`Sync`: compile a ruleset on one thread and match it from a pool.

```rust
let filter = std::sync::Arc::new(DisplayFilter::compile("tls.server_name contains \"evil\"")?);
```

What the grammar supports:

```
existence     tcp            http.uri          dns.qname
comparison    ip.src == 10.0.0.1     tcp.port != 80     ip.ttl >= 64
operators     == eq  != ne  > gt  < lt  >= ge  <= le  contains  matches
logic         && and   || or   ! not   ( )
values        42  0x2a  "text"  1.2.3.4[/cidr]  aa:bb:cc:dd:ee:ff
byte slices   eth.src[0:3] == 00:00:5e
sets          tcp.port in {80, 443, 8080}      udp.port in {1..1024}
aliases       ip.addr  tcp.port  udp.port  eth.addr  ipv6.addr
```

An empty expression compiles to a filter that matches everything, which
`is_match_all()` reports — useful for a catch-all rule. A syntax error is an
`Err` with the engine's own message, so compiling at startup turns a typo into
a startup failure rather than a surprise on whichever packet first reached it.

### Registering the decoders

`ensure_protocols()` loads the protocol decoders — most of libpcapng's protocol
support is POSA definitions compiled into the library, held in a global
registry that is populated on demand. Three things depend on it, and all three
fail *quietly*:

* `Dissection::new` does not recognise a protocol whose decoder is absent, and
  reports the layer below instead — a plain `tcp` where there was an `http`
  request.
* A filter naming a field only resolves against decoders that are loaded, so
  `http.uri contains "/x"` silently matches nothing.
* Worker threads must not be the first to touch the registry — see
  `libpcapng/threading.h`.

Call it once at startup, before compiling any filter and before starting any
thread that dissects. It is idempotent.

---

## Adding a new protocol with POSA

POSA is a declarative grammar for packet decoders — no C required. Define your protocol in a string constant and call `load_posa`; the decoded fields integrate seamlessly with the built-in dissectors.

```rust
use libpcapng::{load_posa, Dissection, LINKTYPE_ETHERNET};

const MYPROTO_POSA: &str = "
protocol MYPROTO
    rule tcp.port == 9000
    required uint16 version
    required uint32 msg_type
        LOGIN  = 1
        LOGOUT = 2
        DATA   = 3
    required payload body

info \"MYPROTO v%d type=%d\" version, msg_type
";

fn main() {
    // Load the protocol — returns the number loaded, or an error description.
    let n = load_posa(MYPROTO_POSA).expect("posa parse error");
    println!("Loaded {n} protocol(s)");

    // From here on, Dissection::new automatically recognises MYPROTO on port 9000.
}
```

To load from a file instead, read it into a `String` first:

```rust
let src = std::fs::read_to_string("myproto.posa").unwrap();
load_posa(&src).unwrap();
```

POSA field types: `uint8/16/32/64`, `le_uint16/32/64`, `mac`, `ip4`, `ip6`, `cstring`, `payload`, `bytes<N>`, `bytes[lenfield]`, `dnsname`. Extended constructs include `repeat`, `when/else`, `bits`, `layer`, `scope`, `info`, and `color`. See the [tutorial](https://github.com/stricaud/libpcapng/blob/main/Tutorial.md).

---

## TCP reassembly

Create a `TcpReassembler` and feed segments into it with `add`. The callback receives
in-order bytes as gaps fill — direction, cumulative buffer, and everything as Rust slices:

```rust
use libpcapng::TcpReassembler;

fn main() {
    let mut reasm = TcpReassembler::new();

    // Feed a SYN segment: IPs/ports in host byte order, raw TCP flags byte.
    reasm.add(
        0xc0a80101,  // 192.168.1.1
        0xc0a80102,  // 192.168.1.2
        54321,       // src port
        80,          // dst port
        1000,        // seq
        0x02,        // SYN flag
        &[],         // no payload
        |stream| {
            println!(
                "dir={}  +{} bytes  ({} total so far)",
                stream.direction,
                stream.bytes.len(),
                stream.all_bytes.len(),
            );
        },
    );

    // TcpReassembler is freed automatically on drop.
}
```

### Reassemble streams from a pcapng file

```rust
use libpcapng::{read_file, Dissection, TcpReassembler, BLOCK_EPB, LINKTYPE_ETHERNET};

fn reassemble(path: &str) {
    let mut reasm = TcpReassembler::new();

    read_file(path, |_, block_type, data| {
        if block_type != BLOCK_EPB || data.len() < 28 { return true; }
        let pkt = &data[28..];  // skip 28-byte EPB header
        if let Some(d) = Dissection::new(pkt, LINKTYPE_ETHERNET) {
            if d.proto() == "tcp" {
                // Extract IP/TCP fields from the field tree and feed reasm.add(...)
            }
        }
        true
    }).unwrap();
}
```

---

## Live capture

Live capture uses kernel zero-copy ring buffers (Linux `PACKET_MMAP` / `TPACKET_V3`, macOS BPF). **Requires `CAP_NET_RAW` or root.**

```rust
use libpcapng::{Capture, Dissection, LINKTYPE_ETHERNET};

fn main() {
    let device = libpcapng::default_device().expect("no suitable interface found");
    println!("Capturing on {device}");

    let mut cap = Capture::open(&device).expect("open failed");

    // Optional Wireshark-compatible display filter.
    cap.set_filter("tcp.dstport == 443").expect("filter error");

    // Capture 100 packets; count <= 0 means unlimited (until Ctrl-C or cap.stop()).
    let n = cap.run(100, |pkt| {
        println!(
            "ts={:.6}  {} bytes  (wire: {})",
            pkt.timestamp_ns as f64 / 1e9,
            pkt.captured_len,
            pkt.original_len,
        );
        if let Some(d) = Dissection::new(pkt.data, LINKTYPE_ETHERNET) {
            println!("  {} → {}  [{}]  {}", d.src(), d.dst(), d.proto(), d.info());
        }
    }).expect("capture error");

    println!("Delivered {n} packets.");
    // Capture is closed automatically on drop.
}
```

### Capture to file

```rust
use libpcapng::Capture;

Capture::to_file("eth0", "out.pcapng", "tcp", 0).expect("capture failed");
// count = 0 → runs until Ctrl-C; filter = "" → no filter
```

### List available interfaces

```rust
use libpcapng::list_devices;

for dev in list_devices().unwrap() {
    println!("{}: {}", dev.name, dev.description);
}
```

---

## Low-level access

`libpcapng::ffi` re-exports the raw `pcapng-sys` bindings for anything not yet covered by the safe API:

```rust
use libpcapng::ffi;
```

---

## License

MIT
