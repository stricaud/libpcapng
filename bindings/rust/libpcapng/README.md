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
