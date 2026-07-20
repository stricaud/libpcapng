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

For advanced field inspection, use the raw pointer to the field tree via the `libpcapng::ffi` escape hatch:

```rust
use libpcapng::{Dissection, LINKTYPE_ETHERNET, ffi};
use std::ffi::CStr;

fn print_fields(frame: &[u8]) {
    let d = Dissection::new(frame, LINKTYPE_ETHERNET).unwrap();
    let mut node = d.root_ptr();
    while !node.is_null() {
        let f = unsafe { &*node };
        let abbrev = unsafe { CStr::from_ptr(f.abbrev.as_ptr()) }.to_str().unwrap_or("");
        let label  = unsafe { CStr::from_ptr(f.label.as_ptr())  }.to_str().unwrap_or("");
        if !abbrev.is_empty() {
            println!("  {abbrev}  {label}  (off={}, len={})", f.off, f.len);
        }
        node = f.next;
    }
}
```

---

## Adding a new protocol with POSA

POSA is a declarative grammar for packet decoders — no C required. Write a `.posa` file and load it at runtime; the decoded fields integrate seamlessly with the built-in dissectors.

**`myproto.posa`**:
```
protocol MYPROTO
    rule tcp.port == 9000
    required uint16 version
    required uint32 msg_type
        LOGIN  = 1
        LOGOUT = 2
        DATA   = 3
    required payload body

info "MYPROTO v%d type=%d" version, msg_type
```

**Rust**:
```rust
use libpcapng::ffi;
use std::ffi::{CStr, CString};

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

fn load_protocol() {
    let src = CString::new(MYPROTO_POSA).unwrap();
    let mut errbuf = vec![0i8; 256];
    let n = unsafe {
        ffi::pcapng_posa_load_text(src.as_ptr(), errbuf.as_mut_ptr(), 256)
    };
    assert!(n >= 0, "posa load failed: {}", unsafe {
        CStr::from_ptr(errbuf.as_ptr()).to_string_lossy()
    });
    println!("Loaded {n} protocol(s)");
}
```

POSA field types: `uint8/16/32/64`, `le_uint16/32/64`, `mac`, `ip4`, `ip6`, `cstring`, `payload`, `bytes<N>`, `bytes[lenfield]`, `dnsname`. Extended constructs include `repeat`, `when/else`, `bits`, `layer`, `scope`, `info`, and `color`. See the [tutorial](https://github.com/stricaud/libpcapng/blob/main/Tutorial.md).

---

## TCP reassembly

Feed captured segments into a reassembly context; a callback delivers the in-order byte stream as soon as gaps are filled:

```rust
use libpcapng::ffi;

fn main() {
    // Allocate a reassembly context (one per tracked connection set).
    let ctx = unsafe { ffi::pcapng_tcp_reasm_new() };
    assert!(!ctx.is_null());

    // Feed a segment: IPs and ports in host byte order, raw TCP flags byte.
    unsafe {
        ffi::pcapng_tcp_reasm_add(
            ctx,
            0xc0a80101,  // 192.168.1.1
            0xc0a80102,  // 192.168.1.2
            54321,       // src port
            80,          // dst port
            1000,        // seq
            0x02,        // SYN flag
            std::ptr::null(),  // no payload on SYN
            0,
            Some(stream_callback),
            std::ptr::null_mut(),
        );
    }

    unsafe { ffi::pcapng_tcp_reasm_free(ctx) };
}

unsafe extern "C" fn stream_callback(
    _userdata: *mut std::ffi::c_void,
    src_ip: u32, src_port: u16,
    dst_ip: u32, dst_port: u16,
    dir: i32,
    data: *const u8, len: usize,
    _all: *const u8, all_len: usize,
) {
    let bytes = std::slice::from_raw_parts(data, len);
    println!(
        "dir={dir}  {}.{}→{}.{}  +{len} bytes ({all_len} total):  {:?}",
        src_ip >> 24, src_port, dst_ip >> 24, dst_port,
        &bytes[..bytes.len().min(32)]
    );
}
```

Combine with `read_file` + `Dissection` to reassemble streams from a pcapng file:

```rust
use libpcapng::{read_file, Dissection, BLOCK_EPB, LINKTYPE_ETHERNET, ffi};
use std::ffi::CStr;

fn reassemble(path: &str) {
    let ctx = unsafe { ffi::pcapng_tcp_reasm_new() };

    read_file(path, |_, block_type, data| {
        if block_type != BLOCK_EPB || data.len() < 28 { return true; }
        // data[0..28] is the EPB header; packet starts at byte 28.
        let pkt = &data[28..];
        if let Some(d) = Dissection::new(pkt, LINKTYPE_ETHERNET) {
            if d.proto() == "tcp" {
                // extract fields via ffi and feed pcapng_tcp_reasm_add …
            }
        }
        true
    }).unwrap();

    unsafe { ffi::pcapng_tcp_reasm_free(ctx) };
}
```

---

## Live capture

Live capture uses kernel zero-copy ring buffers (Linux `PACKET_MMAP` / `TPACKET_V3`, macOS BPF). **Requires `CAP_NET_RAW` or root.**

```rust
use libpcapng::ffi;
use std::ffi::{CStr, CString};

fn main() {
    let mut errbuf = vec![0i8; ffi::PCAPNG_CAPTURE_ERRBUF_SIZE as usize];

    // Pick a device.
    let dev = unsafe { ffi::pcapng_capture_default_device(errbuf.as_mut_ptr()) };
    assert!(!dev.is_null(), "no device found");
    println!("Capturing on {}", unsafe { CStr::from_ptr(dev).to_string_lossy() });

    let cap = unsafe { ffi::pcapng_capture_open(dev, errbuf.as_mut_ptr()) };
    assert!(!cap.is_null(), "open failed: {}", unsafe {
        CStr::from_ptr(errbuf.as_ptr()).to_string_lossy()
    });

    // Optional display filter (Wireshark-compatible subset).
    let filter = CString::new("tcp.dstport == 443").unwrap();
    unsafe { ffi::pcapng_capture_set_filter(cap, filter.as_ptr(), errbuf.as_mut_ptr()) };

    // Capture 100 packets.
    unsafe { ffi::pcapng_capture_loop(cap, 100, Some(on_packet), std::ptr::null_mut()) };

    unsafe { ffi::pcapng_capture_close(cap) };
}

unsafe extern "C" fn on_packet(
    pkt: *const ffi::pcapng_packet_info_t,
    _userdata: *mut std::ffi::c_void,
) {
    let p = &*pkt;
    let data = std::slice::from_raw_parts(p.data, p.captured_len as usize);
    println!(
        "ts={:.6}  {} bytes  (wire: {})",
        p.timestamp_ns as f64 / 1e9,
        p.captured_len,
        p.original_len,
    );
    // Dissect on the fly:
    if let Some(d) = libpcapng::Dissection::new(data, libpcapng::LINKTYPE_ETHERNET) {
        println!("  {} → {}  [{}]  {}", d.src(), d.dst(), d.proto(), d.info());
    }
}
```

### Capture to file

```rust
unsafe {
    ffi::pcapng_capture_to_file(
        b"eth0\0".as_ptr() as _,
        b"out.pcapng\0".as_ptr() as _,
        b"tcp\0".as_ptr() as _,   // filter (or null)
        0,                        // 0 = until Ctrl-C
        errbuf.as_mut_ptr(),
    );
}
```

### List available interfaces

```rust
let mut count = 0i32;
let devs = unsafe { ffi::pcapng_capture_list_devices(&mut count, errbuf.as_mut_ptr()) };
for i in 0..count as usize {
    let d = unsafe { &*devs.add(i) };
    let name = unsafe { CStr::from_ptr(d.name.as_ptr()).to_string_lossy() };
    println!("{name}");
}
unsafe { ffi::pcapng_capture_free_devices(devs) };
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
