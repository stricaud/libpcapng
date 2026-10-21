//! Safe, idiomatic Rust bindings for [libpcapng](https://github.com/stricaud/libpcapng).
//!
//! # Reading a pcapng file (block-level)
//! ```no_run
//! libpcapng::read_file("capture.pcapng", |_counter, block_type, data| {
//!     println!("block type=0x{block_type:08x}  {} bytes", data.len());
//!     true
//! }).unwrap();
//! ```
//!
//! # Reading a pcapng file (packet-level)
//! ```no_run
//! libpcapng::read_packets("capture.pcapng", |pkt| {
//!     println!("ts={}  len={}  linktype={}", pkt.timestamp_ns, pkt.origlen, pkt.linktype);
//!     true
//! }).unwrap();
//! ```
//!
//! # Dissecting a packet
//! ```no_run
//! let frame: &[u8] = &[];
//! if let Some(d) = libpcapng::Dissection::new(frame, libpcapng::LINKTYPE_ETHERNET) {
//!     println!("{} → {}  [{}]  {}", d.src(), d.dst(), d.proto(), d.info());
//!     for field in d.root().children() {
//!         println!("  {} = {}", field.abbrev(), field.label());
//!     }
//! }
//! ```

use pcapng_sys as sys;
use std::ffi::{c_void, CStr, CString};
use std::path::Path;

// ── Block type constants ───────────────────────────────────────────────────

pub use sys::{
    PCAPNG_ENHANCED_PACKET_BLOCK as BLOCK_EPB,
    PCAPNG_INTERFACE_DESCRIPTION_BLOCK as BLOCK_IDB,
    PCAPNG_SECTION_HEADER_BLOCK as BLOCK_SHB,
    PCAPNG_SIMPLE_PACKET_BLOCK as BLOCK_SPB,
};

// ── Link-layer type constants ──────────────────────────────────────────────

pub const LINKTYPE_ETHERNET: u16 = 1;
pub const LINKTYPE_RAW: u16 = 101;
pub const LINKTYPE_LINUX_SLL: u16 = 113;
pub const LINKTYPE_IPV4: u16 = 228;
pub const LINKTYPE_IPV6: u16 = 229;

// ── Error ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

fn err(s: impl Into<String>) -> Error { Error(s.into()) }

fn cstr_to_str<T>(bytes: &[T]) -> &str {
    let ptr = bytes.as_ptr() as *const std::os::raw::c_char;
    unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("")
}

// ── File reading (block-level) ─────────────────────────────────────────────

struct ReadCtx<F> { cb: F }

unsafe extern "C" fn read_trampoline<F>(
    counter: u32, block_type: u32, total_len: u32,
    data: *mut u8, userdata: *mut c_void,
) -> i32
where F: FnMut(u32, u32, &[u8]) -> bool
{
    let ctx = &mut *(userdata as *mut ReadCtx<F>);
    let slice = if data.is_null() || total_len == 0 { &[] }
                else { std::slice::from_raw_parts(data, total_len as usize) };
    if (ctx.cb)(counter, block_type, slice) { 0 } else { 1 }
}

/// Read every block from a pcapng file, calling `callback` for each one.
///
/// The callback receives `(block_counter, block_type, raw_body_bytes)`.
/// Note: the body slice starts AFTER the 8-byte block header; valid body data
/// is `raw_body_bytes[..raw_body_bytes.len()-8]` (the last 8 bytes may be stale).
/// Return `true` to continue or `false` to stop early.
pub fn read_file<P, F>(path: P, callback: F) -> Result<(), Error>
where
    P: AsRef<Path>,
    F: FnMut(u32, u32, &[u8]) -> bool,
{
    let path_str = path.as_ref().to_str()
        .ok_or_else(|| err("path contains non-UTF-8 characters"))?;
    let c_path = CString::new(path_str).map_err(|e| err(e.to_string()))?;
    let mut ctx = ReadCtx { cb: callback };
    let ret = unsafe {
        sys::libpcapng_file_read(
            c_path.as_ptr() as *mut _,
            Some(read_trampoline::<F>),
            &mut ctx as *mut _ as *mut c_void,
        )
    };
    if ret < 0 { Err(err(format!("libpcapng_file_read returned {ret}"))) }
    else { Ok(()) }
}

// ── File reading (packet-level) ────────────────────────────────────────────

/// A single packet delivered by [`read_packets`].
pub struct FilePacket<'a> {
    /// Raw frame bytes.
    pub data: &'a [u8],
    /// Original on-wire length (may exceed `data.len()` if truncated).
    pub origlen: u32,
    /// Capture timestamp in nanoseconds since the UNIX epoch, scaled by the
    /// interface's `if_tsresol` — so this is comparable across captures
    /// whatever resolution each one was recorded at, and it is the same unit
    /// [`Writer::packet`] takes and the C, Python and Go bindings report.
    ///
    /// Zero for a Simple Packet Block, which carries no timestamp.
    pub timestamp_ns: u64,
    /// Link-layer type (e.g. `LINKTYPE_ETHERNET`).
    pub linktype: u16,
    /// Private Enterprise Number — `Some(pen)` only for custom blocks.
    pub custom_pen: Option<u32>,
}

/// The `if_tsresol` value an interface is defined to have when it declares
/// none: 10^-6 seconds, microseconds.
const TSRESOL_MICROSECONDS: u8 = 6;

/// Read an interface's `if_tsresol` option, or the default if it has none.
///
/// The IDB body is linktype(2) reserved(2) snaplen(4) and then options, each
/// code(2) len(2) value(len) padded to a multiple of four. Option 9 is
/// `if_tsresol`, one byte.
fn tsresol_of_idb(body: &[u8]) -> u8 {
    const IF_TSRESOL: u16 = 9;
    const OPT_ENDOFOPT: u16 = 0;

    // The caller's slice can carry a few bytes past the block's own data, so
    // every read below is bounds-checked and a short option ends the walk.
    let mut o = 8;
    while o + 4 <= body.len() {
        let code = u16::from_le_bytes([body[o], body[o + 1]]);
        let len = u16::from_le_bytes([body[o + 2], body[o + 3]]) as usize;
        if code == OPT_ENDOFOPT {
            break;
        }
        let val = o + 4;
        if val + len > body.len() {
            break;
        }
        if code == IF_TSRESOL && len >= 1 {
            return body[val];
        }
        o = val + len + ((4 - len % 4) % 4);
    }
    TSRESOL_MICROSECONDS
}

/// Convert a packet's timestamp from the interface's ticks to nanoseconds.
///
/// `if_tsresol` is a denominator: with the high bit clear the tick is
/// 10^-value seconds, with it set 2^-value. Done in `u128` because a
/// nanosecond timestamp near 2^63 times a power of ten overflows `u64` on the
/// way, and a timestamp that silently wraps is worse than a slow multiply.
fn ticks_to_ns(ticks: u64, tsresol: u8) -> u64 {
    const NS_PER_S: u128 = 1_000_000_000;
    let ticks = ticks as u128;
    let ns = if tsresol & 0x80 != 0 {
        let shift = (tsresol & 0x7f) as u32;
        if shift >= 128 { return 0; }
        ticks * NS_PER_S / (1u128 << shift)
    } else {
        let exp = tsresol as u32;
        match NS_PER_S.checked_div(10u128.checked_pow(exp).unwrap_or(u128::MAX)) {
            // Resolutions coarser than a nanosecond: scale up.
            Some(per_tick) if per_tick > 0 => ticks * per_tick,
            // Finer than a nanosecond (if_tsresol > 9): scale down.
            _ => ticks / (10u128.checked_pow(exp - 9).unwrap_or(u128::MAX)),
        }
    };
    ns.min(u64::MAX as u128) as u64
}

/// Read a pcapng (or classic pcap) file, calling `callback` once per packet.
///
/// The callback receives a [`FilePacket`] reference; return `true` to continue
/// or `false` to stop early.
pub fn read_packets<P, F>(path: P, mut callback: F) -> Result<(), Error>
where
    P: AsRef<Path>,
    F: FnMut(&FilePacket<'_>) -> bool,
{
    fn rd16(d: &[u8], o: usize) -> u16 {
        if o + 2 > d.len() { return 0; }
        u16::from_le_bytes([d[o], d[o + 1]])
    }
    fn rd32(d: &[u8], o: usize) -> u32 {
        if o + 4 > d.len() { return 0; }
        u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
    }

    let mut interfaces: Vec<(u16, u8)> = Vec::new();

    read_file(path, |_ctr, block_type, data| {
        // The C library passes the block body (block_total_length - 8 bytes
        // of valid data, plus up to 8 bytes of stale stack/next-block bytes).
        // Safe body length = data.len() - 8 (we stay well within).
        match block_type {
            // SHB: new section — reset interface list
            0x0A0D_0D0A => { interfaces.clear(); }

            // IDB: Interface Description Block — record link type and the
            // timestamp resolution, which is the part that is easy to skip.
            // An interface may declare if_tsresol, and a capture written in
            // nanoseconds read as microseconds is wrong by a factor of a
            // thousand without looking wrong at all.
            0x0000_0001 => { interfaces.push((rd16(data, 0), tsresol_of_idb(data))); }

            // EPB: Enhanced Packet Block
            0x0000_0006 => {
                let iface   = rd32(data,  0) as usize;
                let ts_hi   = rd32(data,  4) as u64;
                let ts_lo   = rd32(data,  8) as u64;
                let caplen  = rd32(data, 12) as usize;
                let origlen = rd32(data, 16);
                let ticks   = (ts_hi << 32) | ts_lo;
                let (lt, tsresol) = interfaces
                    .get(iface)
                    .copied()
                    .unwrap_or((LINKTYPE_ETHERNET, TSRESOL_MICROSECONDS));
                let end = 20 + caplen;
                if end <= data.len() {
                    let fp = FilePacket {
                        data: &data[20..end], origlen,
                        timestamp_ns: ticks_to_ns(ticks, tsresol),
                        linktype: lt, custom_pen: None,
                    };
                    return callback(&fp);
                }
            }

            // SPB: Simple Packet Block
            0x0000_0003 => {
                let origlen = rd32(data, 0);
                // Valid body bytes = data.len() - 8 (trailing BTL is 4, plus 4 stale).
                // Conservative: body_valid = data.len().saturating_sub(8)
                let body_valid = data.len().saturating_sub(8);
                let caplen = body_valid.saturating_sub(4).min(origlen as usize);
                let lt = interfaces.first().map(|(lt, _)| *lt).unwrap_or(LINKTYPE_ETHERNET);
                if 4 + caplen <= data.len() {
                    let fp = FilePacket {
                        data: &data[4..4 + caplen], origlen,
                        timestamp_ns: 0, linktype: lt, custom_pen: None,
                    };
                    return callback(&fp);
                }
            }

            // Custom Block (copyable and non-copyable)
            0x0000_0BAD | 0x4000_0BAD => {
                let pen = rd32(data, 0);
                // Custom data is body[4..body_valid-4] (exclude PEN and trailing BTL)
                let body_valid = data.len().saturating_sub(8);
                let end = body_valid.saturating_sub(4);
                let body = if end > 4 { &data[4..end] } else { &[][..] };
                let fp = FilePacket {
                    data: body, origlen: body.len() as u32,
                    timestamp_ns: 0, linktype: 0, custom_pen: Some(pen),
                };
                return callback(&fp);
            }

            _ => {}
        }
        true
    })
}

// ── File writing ───────────────────────────────────────────────────────────

/// Writes a pcapng file: a section header, one interface, and packets.
///
/// This is the counterpart to [`read_packets`], and it exists because the
/// obvious alternative does not do what a writer needs: the easy API's
/// file-level helper wants a `FILE *`, which means carrying one across the FFI
/// boundary. This goes through the block-level API and writes through
/// [`std::io::Write`] instead, so it will write to a file, a buffer, or a
/// socket.
///
/// ```no_run
/// use libpcapng::{Writer, LINKTYPE_ETHERNET};
///
/// let mut w = Writer::create("out.pcapng", LINKTYPE_ETHERNET)?;
/// # let frame: &[u8] = &[];
/// w.packet(frame, 1_700_000_000_123_456_789)?;   // nanoseconds since the epoch
/// w.finish()?;
/// # Ok::<(), libpcapng::Error>(())
/// ```
///
/// Timestamps are nanoseconds since the epoch, the unit [`FilePacket`] reports
/// and the C, Python and Go bindings use, so writing and reading need no
/// conversion between them. Everything is little-endian, which the byte-order
/// magic in the section header declares, and the interface is written with no
/// `if_tsresol` option — so what lands in the file is microseconds, the
/// format's default, and the sub-microsecond part of a timestamp is truncated.
pub struct Writer<W: std::io::Write> {
    out: W,
    packets: u64,
}

impl Writer<std::io::BufWriter<std::fs::File>> {
    /// Create a file and write its headers.
    pub fn create<P: AsRef<Path>>(path: P, linktype: u16) -> Result<Self, Error> {
        Self::create_with(path, linktype, None, None)
    }

    /// The same, with a comment and an application name recorded in the
    /// section header. Wireshark shows both under *Statistics → Capture File
    /// Properties*, which is the right place to say where a capture came from.
    pub fn create_with<P: AsRef<Path>>(
        path: P,
        linktype: u16,
        comment: Option<&str>,
        application: Option<&str>,
    ) -> Result<Self, Error> {
        let file = std::fs::File::create(path.as_ref())
            .map_err(|e| err(format!("{}: {e}", path.as_ref().display())))?;
        Writer::new(std::io::BufWriter::new(file), linktype, comment, application)
    }
}

impl<W: std::io::Write> Writer<W> {
    /// Write the section header and interface description to `out`.
    ///
    /// Takes any writer, so a capture can be built in memory with a `Vec<u8>`
    /// or streamed somewhere that is not a file.
    pub fn new(
        mut out: W,
        linktype: u16,
        comment: Option<&str>,
        application: Option<&str>,
    ) -> Result<Self, Error> {
        // The option values have to outlive the write, so they are bound here
        // rather than built inside the call that borrows them.
        let comment = comment.map(|s| s.as_bytes());
        let application = application.map(|s| s.as_bytes());

        let mut opts: Vec<sys::pcapng_option_t> = Vec::with_capacity(2);
        if let Some(c) = comment {
            opts.push(option(sys::PCAPNG_OPT_COMMENT as u16, c));
        }
        if let Some(a) = application {
            opts.push(option(sys::PCAPNG_OPT_SHB_USERAPPL as u16, a));
        }

        let shb = unsafe {
            build_block(
                sys::libpcapng_section_header_block_size_with_options(opts.as_ptr(), opts.len()),
                |buf| sys::libpcapng_section_header_block_write_with_options(
                    opts.as_ptr(), opts.len(), buf,
                ),
            )
        }?;
        out.write_all(&shb).map_err(|e| err(e.to_string()))?;

        let idb = unsafe {
            build_block(
                sys::libpcapng_interface_description_block_size_with_options(
                    std::ptr::null(), 0,
                ),
                |buf| sys::libpcapng_interface_description_block_write_with_options(
                    // Snaplen 0 is "no limit", which is the honest answer for a
                    // writer: nothing here truncated anything.
                    0, linktype, std::ptr::null(), 0, buf,
                ),
            )
        }?;
        out.write_all(&idb).map_err(|e| err(e.to_string()))?;

        Ok(Writer { out, packets: 0 })
    }

    /// Append a packet, timestamped in nanoseconds since the epoch.
    ///
    /// The file stores microseconds, so anything finer is truncated; see the
    /// type's documentation.
    pub fn packet(&mut self, frame: &[u8], timestamp_ns: u64) -> Result<(), Error> {
        self.packet_full(frame, frame.len() as u32, timestamp_ns, None)
    }

    /// Append a packet that was captured only in part, or that carries a
    /// comment.
    ///
    /// `original_len` is how long the packet was on the wire, which is larger
    /// than `frame.len()` for a capture taken with a snaplen. Readers use the
    /// difference to show that a packet was cut short.
    pub fn packet_full(
        &mut self,
        frame: &[u8],
        original_len: u32,
        timestamp_ns: u64,
        comment: Option<&str>,
    ) -> Result<(), Error> {
        let comment = comment.map(|s| s.as_bytes());
        let mut opts: Vec<sys::pcapng_option_t> = Vec::new();
        if let Some(c) = comment {
            opts.push(option(sys::PCAPNG_OPT_COMMENT as u16, c));
        }
        let (opt_ptr, nopt) =
            if opts.is_empty() { (std::ptr::null(), 0) } else { (opts.as_ptr(), opts.len()) };

        // The interface declares no if_tsresol, so the two words the block
        // carries are microseconds — the format's default.
        let ticks = timestamp_ns / 1_000;
        let ts_hi = (ticks >> 32) as u32;
        let ts_lo = (ticks & 0xffff_ffff) as u32;

        let epb = unsafe {
            build_block(
                sys::libpcapng_enhanced_packet_block_size_with_options(frame.len(), opt_ptr, nopt),
                |buf| sys::libpcapng_enhanced_packet_block_write_full(
                    frame.as_ptr(), frame.len(), original_len, 0, ts_hi, ts_lo, opt_ptr, nopt, buf,
                ),
            )
        }?;
        self.out.write_all(&epb).map_err(|e| err(e.to_string()))?;
        self.packets += 1;
        Ok(())
    }

    /// How many packets have been written.
    pub fn packets(&self) -> u64 {
        self.packets
    }

    /// Flush without giving up the writer.
    pub fn flush(&mut self) -> Result<(), Error> {
        self.out.flush().map_err(|e| err(e.to_string()))
    }

    /// Flush and hand back the underlying writer.
    ///
    /// Called explicitly, rather than left to `Drop`, so that a failed flush is
    /// reported instead of discarded — the last packets of a capture are
    /// usually the interesting ones.
    pub fn finish(mut self) -> Result<W, Error> {
        self.out.flush().map_err(|e| err(e.to_string()))?;
        Ok(self.out)
    }
}

fn option(kind: u16, value: &[u8]) -> sys::pcapng_option_t {
    sys::pcapng_option_t {
        type_: kind,
        length: value.len() as u16,
        value: value.as_ptr() as *const std::os::raw::c_void,
    }
}

/// Size a block, let the library fill it, and keep only what it actually wrote.
///
/// The two-call shape — ask the size, then write into a buffer of that size —
/// is how every block writer in `blocks.h` works. Returning the written length
/// rather than the asked-for one means a disagreement between the two shows up
/// as a short block, which a reader rejects, instead of as trailing zeroes that
/// one might silently accept.
unsafe fn build_block<F>(size: usize, write: F) -> Result<Vec<u8>, Error>
where
    F: FnOnce(*mut u8) -> usize,
{
    if size == 0 {
        return Err(err("libpcapng sized a pcapng block as zero bytes"));
    }
    let mut buf = vec![0u8; size];
    let written = write(buf.as_mut_ptr());
    if written == 0 || written > size {
        return Err(err(format!(
            "libpcapng wrote {written} bytes into a {size}-byte pcapng block"
        )));
    }
    buf.truncate(written);
    Ok(buf)
}

// ── Protocol registry ──────────────────────────────────────────────────────

/// Make sure every bundled decoder is registered.
///
/// Most of libpcapng's protocol support is POSA definitions compiled into the
/// library rather than C dissectors, and they are loaded into a global registry
/// on demand. Three things depend on that registry being populated, and all
/// three fail quietly rather than loudly if it is not:
///
/// * [`Dissection::new`] will not recognise a protocol whose decoder is absent,
///   and reports the layer below it instead — a plain `tcp` where there was an
///   `http` request.
/// * A [`DisplayFilter`] naming a field only resolves against decoders that are
///   loaded, so a filter on `http.uri` silently matches nothing.
/// * Worker threads must not be the first to touch the registry; see
///   `libpcapng/threading.h`.
///
/// Call it once at startup, before compiling any filter and before starting any
/// thread that dissects. It is idempotent and cheap to call again.
///
/// ```no_run
/// libpcapng::ensure_protocols();
/// let filter = libpcapng::DisplayFilter::compile("http.uri contains \"/cgi-bin/\"").unwrap();
/// ```
pub fn ensure_protocols() {
    unsafe { sys::pcapng_dissect_ensure_protocols() }
}

// ── Display filters ────────────────────────────────────────────────────────

/// A compiled Wireshark/tshark-style display filter.
///
/// This is the filter engine every tool built on libpcapng matches rules with.
/// Compile an expression once and test it against as many packets as you like:
///
/// ```no_run
/// use libpcapng::{ensure_protocols, DisplayFilter, Dissection, LINKTYPE_ETHERNET};
///
/// ensure_protocols();
/// let filter = DisplayFilter::compile("http.uri contains \"/cgi-bin/\"").unwrap();
///
/// # let frame: &[u8] = &[];
/// if let Some(d) = Dissection::new(frame, LINKTYPE_ETHERNET) {
///     if filter.matches(&d) {
///         println!("{}", d.info());
///     }
/// }
/// ```
///
/// Compiling once and matching many times is the whole performance story for a
/// rule-driven tool. The alternative — handing an expression and a packet to
/// the library together — re-dissects and re-parses for every rule, so thirty
/// rules cost thirty dissections of the same bytes. Here, dissection happens
/// once per packet and each rule is a walk of the resulting tree.
///
/// What the grammar supports:
///
/// ```text
///   existence     tcp            http.uri          dns.qname
///   comparison    ip.src == 10.0.0.1     tcp.port != 80     ip.ttl >= 64
///   operators     == eq  != ne  > gt  < lt  >= ge  <= le  contains  matches
///   logic         && and   || or   ! not   ( )
///   values        42  0x2a  "text"  1.2.3.4[/cidr]  aa:bb:cc:dd:ee:ff
///   byte slices   eth.src[0:3] == 00:00:5e
///   sets          tcp.port in {80, 443, 8080}      udp.port in {1..1024}
///   aliases       ip.addr  tcp.port  udp.port  eth.addr  ipv6.addr
/// ```
///
/// Freed automatically on drop.
pub struct DisplayFilter(*mut sys::pcapng_dfilter_t);

impl DisplayFilter {
    /// Compile an expression, or report why it will not compile.
    ///
    /// An empty or blank expression compiles to a filter that matches
    /// everything, which is how a catch-all rule is written.
    ///
    /// Compile at startup rather than on first use: a typo then becomes a
    /// startup failure instead of a surprise on whichever packet first reached
    /// the rule.
    pub fn compile(expr: &str) -> Result<Self, Error> {
        let c_expr = CString::new(expr).map_err(|e| err(e.to_string()))?;
        let mut errbuf = vec![0 as std::os::raw::c_char; 512];
        let ptr = unsafe {
            sys::pcapng_dfilter_compile(c_expr.as_ptr(), errbuf.as_mut_ptr(), errbuf.len())
        };
        if ptr.is_null() {
            let msg = cstr_to_str(&errbuf);
            return Err(err(if msg.is_empty() {
                format!("cannot compile display filter: {expr}")
            } else {
                msg.to_string()
            }));
        }
        Ok(DisplayFilter(ptr))
    }

    /// Does this packet match?
    ///
    /// The decoders the expression names have to be registered, or the fields
    /// it tests do not exist and it matches nothing. See [`ensure_protocols`].
    pub fn matches(&self, dissection: &Dissection) -> bool {
        unsafe { sys::pcapng_dfilter_match(self.0, dissection.root_ptr()) != 0 }
    }

    /// Match against a field tree directly, for a caller that already has one
    /// — a subtree, or a root kept separately from its `Dissection`.
    ///
    /// # Safety
    /// `root` must point into a field tree that is still alive.
    pub unsafe fn matches_root(&self, root: *mut sys::pcapng_field_t) -> bool {
        sys::pcapng_dfilter_match(self.0, root) != 0
    }

    /// True when compiled from a blank expression, so every packet matches.
    pub fn is_match_all(&self) -> bool {
        unsafe { sys::pcapng_dfilter_is_match_all(self.0) != 0 }
    }
}

impl Drop for DisplayFilter {
    fn drop(&mut self) { unsafe { sys::pcapng_dfilter_free(self.0) } }
}

// A compiled filter is immutable and `pcapng_dfilter_match` only reads it, so
// one filter can be matched from several threads at once — which is what lets a
// ruleset be compiled on the main thread and used by a pool of workers.
unsafe impl Send for DisplayFilter {}
unsafe impl Sync for DisplayFilter {}

// ── Dissection ─────────────────────────────────────────────────────────────

/// A dissected packet: protocol field tree + Wireshark-style summary columns.
///
/// Freed automatically on drop.
pub struct Dissection(*mut sys::pcapng_dissection_t);

impl Dissection {
    /// Dissect `data` as an Ethernet (or other link-layer) frame.
    ///
    /// Returns `None` only on allocation failure.
    pub fn new(data: &[u8], linktype: u16) -> Option<Self> {
        let ptr = unsafe {
            sys::pcapng_dissect(data.as_ptr(), data.len() as u32, data.len() as u32, linktype)
        };
        if ptr.is_null() { None } else { Some(Self(ptr)) }
    }

    fn inner(&self) -> &sys::pcapng_dissection_t { unsafe { &*self.0 } }

    /// Deepest recognised protocol (e.g. `"tcp"`, `"dns"`).
    pub fn proto(&self) -> &str { cstr_to_str(&self.inner().proto) }
    /// Source address (IP, MAC, or empty).
    pub fn src(&self) -> &str   { cstr_to_str(&self.inner().src)   }
    /// Destination address.
    pub fn dst(&self) -> &str   { cstr_to_str(&self.inner().dst)   }
    /// One-line human-readable summary (Info column).
    pub fn info(&self) -> &str  { cstr_to_str(&self.inner().info)  }

    /// Walk the field tree starting from the root (returns `None` only if the
    /// dissection produced no fields at all).
    pub fn root_field(&self) -> Option<Field<'_>> {
        let root = self.inner().root;
        if root.is_null() { None } else { Some(Field(unsafe { &*root })) }
    }

    /// Root field of the tree.  Panics only if allocation completely failed
    /// (i.e. `Dissection::new` returned `None`).  Use [`root_field`] for a
    /// fallible variant.
    pub fn root(&self) -> Field<'_> {
        let ptr = self.inner().root;
        assert!(!ptr.is_null(), "Dissection::root: null root — was dissection successful?");
        Field(unsafe { &*ptr })
    }

    /// Raw pointer to the root field node (for unsafe UI code that walks the
    /// field tree via C-level offsets).
    pub fn root_ptr(&self) -> *mut sys::pcapng_field_t {
        self.inner().root
    }

    /// Does this packet match `filter`?  The same test as
    /// [`DisplayFilter::matches`], written the other way round for when the
    /// packet is what you have in hand.
    pub fn matches(&self, filter: &DisplayFilter) -> bool {
        filter.matches(self)
    }
}

impl Drop for Dissection {
    fn drop(&mut self) { unsafe { sys::pcapng_dissection_free(self.0) } }
}

// ── FieldType ──────────────────────────────────────────────────────────────

/// The value type stored in a [`Field`] node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    None,
    Uint,
    Str,
    Ipv4,
    Ipv6,
    Mac,
    Bytes,
}

// ── Field ──────────────────────────────────────────────────────────────────

/// A node in the protocol field tree produced by `Dissection`.
pub struct Field<'a>(&'a sys::pcapng_field_t);

impl<'a> Field<'a> {
    /// Construct a `Field` from a raw pointer.
    ///
    /// # Safety
    /// `ptr` must be non-null and point to a valid `pcapng_field_t` that
    /// outlives `'a`.
    pub unsafe fn from_raw(ptr: *mut sys::pcapng_field_t) -> Field<'a> {
        Field(&*ptr)
    }

    /// Wireshark-style abbreviation (e.g. `"ip.src"`). Empty for structural nodes.
    pub fn abbrev(&self) -> &str { cstr_to_str(&self.0.abbrev) }
    /// Human-readable label (e.g. `"Source: 192.168.1.1"`).
    pub fn label(&self) -> &str  { cstr_to_str(&self.0.label)  }

    /// Value type of this field.
    pub fn ftype(&self) -> FieldType {
        match self.0.vtype {
            sys::pcapng_ftype_t_PCAPNG_FT_NONE  => FieldType::None,
            sys::pcapng_ftype_t_PCAPNG_FT_UINT  => FieldType::Uint,
            sys::pcapng_ftype_t_PCAPNG_FT_STR   => FieldType::Str,
            sys::pcapng_ftype_t_PCAPNG_FT_IPV4  => FieldType::Ipv4,
            sys::pcapng_ftype_t_PCAPNG_FT_IPV6  => FieldType::Ipv6,
            sys::pcapng_ftype_t_PCAPNG_FT_MAC   => FieldType::Mac,
            sys::pcapng_ftype_t_PCAPNG_FT_BYTES => FieldType::Bytes,
            _                                   => FieldType::None,
        }
    }

    /// Integer value — valid when `ftype() == FieldType::Uint`.
    pub fn uint(&self) -> u64 { self.0.u }
    /// Integer value (same as [`uint`]; older name kept for compatibility).
    pub fn value_uint(&self) -> u64 { self.0.u }

    /// Absolute byte offset of this field within the packet.
    pub fn offset(&self) -> i32 { self.0.off }
    /// Byte length of this field within the packet.
    pub fn byte_len(&self) -> i32 { self.0.len }

    /// String-formatted value for IP/MAC/string field types.
    pub fn str_value(&self) -> &str { cstr_to_str(&self.0.str_) }
    /// String-formatted value (same as [`str_value`]; older name kept for compatibility).
    pub fn value_str(&self) -> &str { cstr_to_str(&self.0.str_) }

    /// Raw bytes value — valid when `ftype() == FieldType::Bytes`.
    pub fn bytes(&self) -> &[u8] {
        let blen = self.0.blen.max(0) as usize;
        let max  = self.0.bytes.len();
        &self.0.bytes[..blen.min(max)]
    }

    /// Next sibling field at the same level.
    pub fn next(&self) -> Option<Field<'a>> {
        if self.0.next.is_null() { None }
        else { Some(Field(unsafe { &*self.0.next })) }
    }

    /// First child field (for protocol-layer nodes).
    pub fn first_child(&self) -> Option<Field<'a>> {
        if self.0.children.is_null() { None }
        else { Some(Field(unsafe { &*self.0.children })) }
    }

    /// Iterator over all direct children of this field (follows `next` links).
    pub fn children(&self) -> FieldChildren<'a> {
        FieldChildren { current: self.first_child() }
    }

    /// Collect all fields in this subtree whose abbreviation equals `abbrev`.
    ///
    /// Performs a depth-first search; returns fields in tree order.
    pub fn collect(&self, abbrev: &str) -> Vec<Field<'a>> {
        let mut out = Vec::new();
        self.collect_into(abbrev, &mut out);
        out
    }

    /// Find the first field in this subtree whose abbreviation equals `abbrev`.
    pub fn find(&self, abbrev: &str) -> Option<Field<'a>> {
        if self.abbrev() == abbrev { return Some(Field(self.0)); }
        for child in self.children() {
            if let Some(f) = child.find(abbrev) { return Some(f); }
        }
        None
    }

    fn collect_into(&self, abbrev: &str, out: &mut Vec<Field<'a>>) {
        if self.abbrev() == abbrev {
            out.push(Field(self.0));
        }
        for child in self.children() {
            child.collect_into(abbrev, out);
        }
    }
}

// ── FieldChildren iterator ─────────────────────────────────────────────────

/// Iterator over the direct children of a [`Field`] node.
pub struct FieldChildren<'a> {
    current: Option<Field<'a>>,
}

impl<'a> Iterator for FieldChildren<'a> {
    type Item = Field<'a>;

    fn next(&mut self) -> Option<Field<'a>> {
        let cur = self.current.take()?;
        self.current = cur.next();
        Some(cur)
    }
}

// ── POSA ───────────────────────────────────────────────────────────────────

/// Load one or more POSA protocol definitions from a source string.
///
/// Returns the number of protocols loaded, or an error with a description.
///
/// ```no_run
/// libpcapng::load_posa("protocol PING\n    required uint8 type\n").unwrap();
/// ```
pub fn load_posa(src: &str) -> Result<usize, Error> {
    let c_src = CString::new(src).map_err(|e| err(e.to_string()))?;
    let mut errbuf = [0i8; 256];
    let n = unsafe {
        sys::pcapng_posa_load_text(c_src.as_ptr(), errbuf.as_mut_ptr() as *mut _, 256)
    };
    if n < 0 {
        Err(err(cstr_to_str(&errbuf).to_owned()))
    } else {
        Ok(n as usize)
    }
}

/// Tell the POSA engine which flow the next dissection belongs to, so decoders
/// using `bind`/`recall` remember values per conversation.
///
/// Pass the flow's Community ID. `None` means "no conversation", under which
/// `bind` stores nothing and `recall` always misses — what happens when a
/// decoder is run over a bare buffer.
pub fn posa_set_conversation(community_id: Option<&str>) -> Result<(), Error> {
    match community_id {
        None => unsafe { sys::pcapng_posa_set_conversation(std::ptr::null()) },
        Some(id) => {
            let c = CString::new(id).map_err(|e| err(e.to_string()))?;
            unsafe { sys::pcapng_posa_set_conversation(c.as_ptr()) }
        }
    }
    Ok(())
}

/// Enable or disable `weak rule` signatures.
pub fn posa_set_weak_rules(on: bool) {
    unsafe { sys::pcapng_posa_weak_rules_enable(if on { 1 } else { 0 }) }
}

/// Whether `weak rule` signatures are currently consulted.
pub fn posa_weak_rules_enabled() -> bool {
    unsafe { sys::pcapng_posa_weak_rules_enabled() != 0 }
}

/// Forget every value remembered by `bind`.
pub fn posa_clear_binds() {
    unsafe { sys::pcapng_posa_binds_clear() }
}

/// How many values `bind` is currently remembering.
pub fn posa_bind_count() -> usize {
    unsafe { sys::pcapng_posa_bind_count() as usize }
}

/// Warnings raised by the last dissection.
pub fn posa_warnings() -> Vec<String> {
    let n = unsafe { sys::pcapng_posa_warning_count() };
    let mut out = Vec::with_capacity(n.max(0) as usize);
    for i in 0..n {
        let w = unsafe { sys::pcapng_posa_warning_at(i) };
        if !w.is_null() {
            out.push(unsafe { std::ffi::CStr::from_ptr(w) }.to_string_lossy().into_owned());
        }
    }
    out
}

/// Functions for managing POSA protocol decoders.
pub mod posa {
    use super::{cstr_to_str, err, sys, Error};
    use std::ffi::CString;
    use std::path::Path;

    /// Load POSA decoders from a `.posa` source string.
    ///
    /// Returns the number of protocols loaded, or an [`Error`] with a
    /// human-readable description on parse failure.
    pub fn load_text(src: &str) -> Result<i32, Error> {
        let c_src = CString::new(src).map_err(|e| err(e.to_string()))?;
        let mut errbuf = [0i8; 256];
        let n = unsafe {
            sys::pcapng_posa_load_text(c_src.as_ptr(), errbuf.as_mut_ptr() as *mut _, 256)
        };
        if n < 0 { Err(err(cstr_to_str(&errbuf).to_owned())) } else { Ok(n) }
    }

    /// Load POSA decoders from a `.posa` file.
    ///
    /// Returns the number of protocols loaded, or an [`Error`] on failure.
    pub fn load_file(path: &Path) -> Result<i32, Error> {
        let path_str = path.to_str()
            .ok_or_else(|| err("path contains non-UTF-8 characters"))?;
        let c_path = CString::new(path_str).map_err(|e| err(e.to_string()))?;
        let mut errbuf = [0i8; 256];
        let n = unsafe {
            sys::pcapng_posa_load_file(c_path.as_ptr(), errbuf.as_mut_ptr() as *mut _, 256)
        };
        if n < 0 { Err(err(cstr_to_str(&errbuf).to_owned())) } else { Ok(n) }
    }

    /// Total number of POSA protocols currently loaded.
    pub fn count() -> i32 {
        unsafe { sys::pcapng_posa_count() }
    }

    /// Names of all currently-loaded POSA protocols.
    pub fn protocols() -> Vec<String> {
        let n = unsafe { sys::pcapng_posa_count() };
        (0..n.max(0))
            .filter_map(|i| {
                let p = unsafe { sys::pcapng_posa_at(i) };
                if p.is_null() { None }
                else { Some(cstr_to_str(unsafe { &(*p).name }).to_owned()) }
            })
            .collect()
    }

    /// Colour-filter rules defined in loaded POSA files.
    ///
    /// Returns a `Vec` of `(filter_expression, foreground_colour, background_colour)`.
    pub fn colors() -> Vec<(String, String, String)> {
        fn to_string(p: *const std::os::raw::c_char) -> String {
            if p.is_null() { String::new() }
            else { unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned() }
        }
        let n = unsafe { sys::pcapng_posa_color_count() };
        let mut out = Vec::with_capacity(n.max(0) as usize);
        for i in 0..n {
            let mut expr: *const std::os::raw::c_char = std::ptr::null();
            let mut fg:   *const std::os::raw::c_char = std::ptr::null();
            let mut bg:   *const std::os::raw::c_char = std::ptr::null();
            let ret = unsafe {
                sys::pcapng_posa_color_get(i, &mut expr, &mut fg, &mut bg)
            };
            if ret == 0 {
                out.push((to_string(expr), to_string(fg), to_string(bg)));
            }
        }
        out
    }
}

// ── TCP reassembly (original API) ─────────────────────────────────────────

/// New bytes delivered to a reassembled TCP half-stream.
pub struct TcpStreamData<'a> {
    /// Source IP (host byte order).
    pub src_ip: u32,
    pub src_port: u16,
    /// Destination IP (host byte order).
    pub dst_ip: u32,
    pub dst_port: u16,
    /// Direction: 0 = A→B, 1 = B→A (stable across segments).
    pub direction: i32,
    /// Newly delivered in-order bytes.
    pub bytes: &'a [u8],
    /// Cumulative reassembled buffer for this half-stream so far.
    pub all_bytes: &'a [u8],
}

struct ReasmCtx<F> { cb: F }

unsafe extern "C" fn reasm_trampoline<F>(
    userdata: *mut c_void,
    src_ip: u32, src_port: u16,
    dst_ip: u32, dst_port: u16,
    dir: i32,
    data: *const u8, len: usize,
    all: *const u8, all_len: usize,
)
where F: FnMut(&TcpStreamData<'_>)
{
    let ctx = &mut *(userdata as *mut ReasmCtx<F>);
    let sd = TcpStreamData {
        src_ip, src_port, dst_ip, dst_port, direction: dir,
        bytes:     std::slice::from_raw_parts(data, len),
        all_bytes: std::slice::from_raw_parts(all,  all_len),
    };
    (ctx.cb)(&sd);
}

/// Passive TCP stream reassembler (original API — callback receives `&TcpStreamData`).
///
/// For the newer `TcpReasm` type whose callback receives an owned `TcpBytes`,
/// see [`TcpReasm`].
pub struct TcpReassembler(*mut sys::pcapng_tcp_reasm_t);

impl TcpReassembler {
    pub fn new() -> Self {
        let ptr = unsafe { sys::pcapng_tcp_reasm_new() };
        assert!(!ptr.is_null(), "pcapng_tcp_reasm_new returned null");
        Self(ptr)
    }

    /// Feed one TCP segment. `callback` is called with any in-order bytes
    /// unlocked by this segment.
    pub fn add<F>(
        &mut self,
        src_ip: u32, dst_ip: u32,
        src_port: u16, dst_port: u16,
        seq: u32, tcp_flags: u8,
        payload: &[u8],
        callback: F,
    )
    where F: FnMut(&TcpStreamData<'_>)
    {
        let mut ctx = ReasmCtx { cb: callback };
        let (ptr, len) = if payload.is_empty() {
            (std::ptr::null(), 0)
        } else {
            (payload.as_ptr(), payload.len())
        };
        unsafe {
            sys::pcapng_tcp_reasm_add(
                self.0,
                src_ip, dst_ip, src_port, dst_port,
                seq, tcp_flags, ptr, len,
                Some(reasm_trampoline::<F>),
                &mut ctx as *mut _ as *mut c_void,
            )
        }
    }
}

impl Default for TcpReassembler {
    fn default() -> Self { Self::new() }
}

impl Drop for TcpReassembler {
    fn drop(&mut self) { unsafe { sys::pcapng_tcp_reasm_free(self.0) } }
}

// ── TCP reassembly (new owned-callback API) ────────────────────────────────

/// Bytes delivered by the [`TcpReasm`] reassembler — owned copy so the
/// callback may move it into data structures.
pub struct TcpBytes {
    pub src_ip:   u32,
    pub src_port: u16,
    pub dst_ip:   u32,
    pub dst_port: u16,
    /// Direction: 0 = initiator→responder, 1 = responder→initiator.
    pub dir: i32,
    /// Newly delivered in-order bytes from this segment.
    pub data: Vec<u8>,
    /// Cumulative reassembled buffer for this half-stream so far.
    pub all: Vec<u8>,
}

struct TcpReasmCtx<F> { cb: F }

unsafe extern "C" fn tcp_reasm_trampoline<F>(
    userdata: *mut c_void,
    src_ip: u32, src_port: u16,
    dst_ip: u32, dst_port: u16,
    dir: i32,
    data: *const u8, len: usize,
    all: *const u8, all_len: usize,
)
where F: FnMut(TcpBytes)
{
    let ctx = &mut *(userdata as *mut TcpReasmCtx<F>);
    let tb = TcpBytes {
        src_ip, src_port, dst_ip, dst_port, dir,
        data: std::slice::from_raw_parts(data, len).to_vec(),
        all:  std::slice::from_raw_parts(all, all_len).to_vec(),
    };
    (ctx.cb)(tb);
}

/// Passive TCP stream reassembler.  The callback receives an owned [`TcpBytes`]
/// (data is copied out of the C buffer so it can be moved freely).
///
/// For the reference-based variant see [`TcpReassembler`].
pub struct TcpReasm(*mut sys::pcapng_tcp_reasm_t);

impl TcpReasm {
    pub fn new() -> Self {
        let ptr = unsafe { sys::pcapng_tcp_reasm_new() };
        assert!(!ptr.is_null(), "pcapng_tcp_reasm_new returned null");
        Self(ptr)
    }

    /// Feed one TCP segment.  `callback` receives owned [`TcpBytes`] for each
    /// burst of in-order bytes unlocked by this segment.
    pub fn add<F>(
        &mut self,
        src_ip: u32, dst_ip: u32,
        src_port: u16, dst_port: u16,
        seq: u32, tcp_flags: u8,
        payload: &[u8],
        callback: F,
    )
    where F: FnMut(TcpBytes)
    {
        let mut ctx = TcpReasmCtx { cb: callback };
        let (ptr, len) = if payload.is_empty() {
            (std::ptr::null(), 0)
        } else {
            (payload.as_ptr(), payload.len())
        };
        unsafe {
            sys::pcapng_tcp_reasm_add(
                self.0,
                src_ip, dst_ip, src_port, dst_port,
                seq, tcp_flags, ptr, len,
                Some(tcp_reasm_trampoline::<F>),
                &mut ctx as *mut _ as *mut c_void,
            )
        }
    }
}

impl Default for TcpReasm {
    fn default() -> Self { Self::new() }
}

impl Drop for TcpReasm {
    fn drop(&mut self) { unsafe { sys::pcapng_tcp_reasm_free(self.0) } }
}

// ── IP reassembly ──────────────────────────────────────────────────────────

/// Result of feeding one packet to the [`IpReasm`] defragmenter.
pub enum IpReasm4 {
    /// Reassembly complete — the `Vec<u8>` is the full IPv4 datagram.
    Complete(Vec<u8>),
    /// Fragment was buffered; more fragments are expected.
    Buffered,
    /// Packet is not an IPv4 fragment — pass it through unchanged.
    PassThrough,
}

extern "C" { fn free(ptr: *mut c_void); }

/// IPv4 fragment reassembler.
///
/// Feed raw Ethernet frames or raw IPv4 datagrams via [`add`](Self::add).
/// When a datagram is complete, `add` returns [`IpReasm4::Complete`] with
/// a reassembled IPv4 datagram (caller owns the allocation).
pub struct IpReasm(*mut sys::libpcapng_reasm_t);

impl IpReasm {
    pub fn new() -> Self {
        let ptr = unsafe { sys::libpcapng_reasm_new() };
        assert!(!ptr.is_null(), "libpcapng_reasm_new returned null");
        Self(ptr)
    }

    /// Feed one packet (Ethernet frame or raw IPv4 datagram).
    ///
    /// Returns:
    /// - [`IpReasm4::Complete`] — reassembly finished; contains the full datagram.
    /// - [`IpReasm4::Buffered`] — fragment stored; more fragments expected.
    /// - [`IpReasm4::PassThrough`] — packet is not a fragment; treat as-is.
    pub fn add(&mut self, data: &[u8]) -> IpReasm4 {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize   = 0;
        let ret = unsafe {
            sys::libpcapng_reasm_add(
                self.0,
                data.as_ptr(), data.len(),
                &mut out_ptr, &mut out_len,
            )
        };
        match ret {
            1 => {
                let v = if out_ptr.is_null() || out_len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(out_ptr, out_len).to_vec() }
                };
                if !out_ptr.is_null() {
                    unsafe { free(out_ptr as *mut c_void) };
                }
                IpReasm4::Complete(v)
            }
            0  => IpReasm4::Buffered,
            _  => IpReasm4::PassThrough,
        }
    }
}

impl Default for IpReasm { fn default() -> Self { Self::new() } }

impl Drop for IpReasm {
    fn drop(&mut self) { unsafe { sys::libpcapng_reasm_free(self.0) } }
}

// ── Object extraction ──────────────────────────────────────────────────────

/// Protocol selector for [`ObjectExtractor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectProto {
    Http,
    Smb,
}

/// An application-layer object (file) carved out of a capture.
#[derive(Debug)]
pub struct Object {
    pub proto:        String,
    pub frame:        i32,
    pub hostname:     String,
    pub content_type: String,
    pub filename:     String,
    pub data:         Vec<u8>,
    pub complete:     bool,
}

/// Carves HTTP or SMB objects out of a stream of raw packets.
///
/// ```no_run
/// let mut ex = libpcapng::ObjectExtractor::new(libpcapng::ObjectProto::Http);
/// // feed packets...
/// ex.finish();
/// for obj in ex.objects() {
///     println!("{}: {} bytes", obj.filename, obj.data.len());
/// }
/// ```
pub struct ObjectExtractor(*mut sys::pcapng_object_extractor_t);

impl ObjectExtractor {
    pub fn new(proto: ObjectProto) -> Self {
        let p = match proto {
            ObjectProto::Http => sys::pcapng_object_proto_t_PCAPNG_OBJ_HTTP,
            ObjectProto::Smb  => sys::pcapng_object_proto_t_PCAPNG_OBJ_SMB,
        };
        let ptr = unsafe { sys::pcapng_object_extractor_new(p) };
        assert!(!ptr.is_null(), "pcapng_object_extractor_new returned null");
        Self(ptr)
    }

    /// Feed one raw packet frame.  `data.len()` is used as the captured length.
    pub fn add_packet(&mut self, frame: i32, data: &[u8], linktype: u16) {
        unsafe {
            sys::pcapng_object_extractor_add_packet(
                self.0, frame, data.as_ptr(), data.len() as u32, linktype,
            )
        }
    }

    /// Signal end-of-capture so partial objects are finalised.
    pub fn finish(&mut self) {
        unsafe { sys::pcapng_object_extractor_finish(self.0) }
    }

    /// Return all extracted objects.
    pub fn objects(&self) -> Vec<Object> {
        let n = unsafe { sys::pcapng_object_count(self.0) };
        (0..n.max(0))
            .filter_map(|i| {
                let o = unsafe { sys::pcapng_object_at(self.0, i) };
                if o.is_null() { return None; }
                let o = unsafe { &*o };
                let data = if o.data.is_null() || o.len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(o.data, o.len).to_vec() }
                };
                Some(Object {
                    proto:        cstr_to_str(&o.proto).to_owned(),
                    frame:        o.frame,
                    hostname:     cstr_to_str(&o.hostname).to_owned(),
                    content_type: cstr_to_str(&o.content_type).to_owned(),
                    filename:     cstr_to_str(&o.filename).to_owned(),
                    data,
                    complete:     o.complete != 0,
                })
            })
            .collect()
    }
}

impl Drop for ObjectExtractor {
    fn drop(&mut self) { unsafe { sys::pcapng_object_extractor_free(self.0) } }
}

// ── Live capture ───────────────────────────────────────────────────────────

/// A packet delivered by the live capture engine.
pub struct PacketInfo<'a> {
    /// Raw frame bytes. Valid only for the duration of the callback.
    pub data: &'a [u8],
    /// Nanoseconds since the UNIX epoch.
    pub timestamp_ns: u64,
    /// Bytes present in `data`.
    pub captured_len: u32,
    /// Original on-wire length (may exceed `captured_len` if snaplen was set).
    pub original_len: u32,
    /// `PCAPNG_CAP_DIR_*` constant: 0=unknown, 1=inbound, 2=outbound.
    pub direction: i32,
}

struct CapCtx<F> { cb: F }

unsafe extern "C" fn cap_trampoline<F: FnMut(&PacketInfo<'_>)>(
    pkt: *const sys::pcapng_packet_info_t,
    userdata: *mut c_void,
) {
    let ctx = &mut *(userdata as *mut CapCtx<F>);
    let p = &*pkt;
    let info = PacketInfo {
        data:         std::slice::from_raw_parts(p.data, p.captured_len as usize),
        timestamp_ns: p.timestamp_ns,
        captured_len: p.captured_len,
        original_len: p.original_len,
        direction:    p.direction,
    };
    (ctx.cb)(&info);
}

/// Live packet capture handle (Linux `TPACKET_V3` / macOS BPF).
///
/// Requires `CAP_NET_RAW` or root.
pub struct Capture(*mut sys::pcapng_capture_t);

impl Capture {
    /// Open a capture handle on `device` (e.g. `"eth0"`, `"en0"`).
    pub fn open(device: &str) -> Result<Self, Error> {
        let c_dev = CString::new(device).map_err(|e| err(e.to_string()))?;
        let mut errbuf = [0i8; sys::PCAPNG_CAPTURE_ERRBUF_SIZE as usize];
        let ptr = unsafe { sys::pcapng_capture_open(c_dev.as_ptr(), errbuf.as_mut_ptr() as *mut _) };
        if ptr.is_null() {
            Err(err(cstr_to_str(&errbuf).to_owned()))
        } else {
            Ok(Self(ptr))
        }
    }

    /// Apply a Wireshark-compatible display filter (e.g. `"tcp.dstport == 443"`).
    pub fn set_filter(&self, expr: &str) -> Result<(), Error> {
        let c_expr = CString::new(expr).map_err(|e| err(e.to_string()))?;
        let mut errbuf = [0i8; sys::PCAPNG_CAPTURE_ERRBUF_SIZE as usize];
        let ret = unsafe {
            sys::pcapng_capture_set_filter(self.0, c_expr.as_ptr(), errbuf.as_mut_ptr() as *mut _)
        };
        if ret < 0 { Err(err(cstr_to_str(&errbuf).to_owned())) } else { Ok(()) }
    }

    /// Capture packets in a loop, calling `callback` for each one.
    ///
    /// Runs until `count` packets are delivered (`count <= 0` = unlimited),
    /// `SIGINT` is received, or [`stop`](Self::stop) / [`break_loop`](Self::break_loop)
    /// is called from another thread.
    ///
    /// Returns the number of packets delivered.
    pub fn run<F>(&self, count: i32, callback: F) -> Result<i32, Error>
    where F: FnMut(&PacketInfo<'_>)
    {
        let mut ctx = CapCtx { cb: callback };
        let n = unsafe {
            sys::pcapng_capture_loop(
                self.0, count,
                Some(cap_trampoline::<F>),
                &mut ctx as *mut _ as *mut c_void,
            )
        };
        if n < 0 { Err(err("capture loop error")) } else { Ok(n) }
    }

    /// Process one batch of packets without blocking.
    ///
    /// `count <= 0` processes all packets currently available.
    /// Returns the number of packets delivered (0 if none arrived), or -1 on error.
    pub fn dispatch<F>(&self, count: i32, callback: F) -> i32
    where F: FnMut(&PacketInfo<'_>)
    {
        let mut ctx = CapCtx { cb: callback };
        unsafe {
            sys::pcapng_capture_dispatch(
                self.0, count,
                Some(cap_trampoline::<F>),
                &mut ctx as *mut _ as *mut c_void,
            )
        }
    }

    /// Capture `count` packets directly to `output` in pcapng format.
    pub fn to_file(device: &str, output: &str, filter: &str, count: i32) -> Result<(), Error> {
        let c_dev  = CString::new(device).map_err(|e| err(e.to_string()))?;
        let c_out  = CString::new(output).map_err(|e| err(e.to_string()))?;
        let c_flt  = if filter.is_empty() { None }
                     else { Some(CString::new(filter).map_err(|e| err(e.to_string()))?) };
        let flt_ptr = c_flt.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
        let mut errbuf = [0i8; sys::PCAPNG_CAPTURE_ERRBUF_SIZE as usize];
        let ret = unsafe {
            sys::pcapng_capture_to_file(c_dev.as_ptr(), c_out.as_ptr(), flt_ptr, count, errbuf.as_mut_ptr() as *mut _)
        };
        if ret < 0 { Err(err(cstr_to_str(&errbuf).to_owned())) } else { Ok(()) }
    }

    /// Signal the capture loop to stop cleanly (safe from another thread).
    pub fn stop(&self) {
        unsafe { sys::pcapng_capture_break(self.0) }
    }

    /// Alias for [`stop`](Self::stop).
    pub fn break_loop(&self) {
        unsafe { sys::pcapng_capture_break(self.0) }
    }
}

impl Drop for Capture {
    fn drop(&mut self) { unsafe { sys::pcapng_capture_close(self.0) } }
}

/// Return the name of the first suitable non-loopback interface, or `None`.
pub fn default_device() -> Option<String> {
    let mut errbuf = [0i8; sys::PCAPNG_CAPTURE_ERRBUF_SIZE as usize];
    let ptr = unsafe { sys::pcapng_capture_default_device(errbuf.as_mut_ptr() as *mut _) };
    if ptr.is_null() { None }
    else { Some(unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()) }
}

// ── Device list ────────────────────────────────────────────────────────────

/// A single network interface returned by [`list_devices`].
pub struct Device {
    pub name: String,
    pub description: String,
    pub loopback: bool,
}

/// List all available capture interfaces.
pub fn list_devices() -> Result<Vec<Device>, Error> {
    let mut count = 0i32;
    let mut errbuf = [0i8; sys::PCAPNG_CAPTURE_ERRBUF_SIZE as usize];
    let devs = unsafe { sys::pcapng_capture_list_devices(&mut count, errbuf.as_mut_ptr() as *mut _) };
    if devs.is_null() {
        return Err(err(cstr_to_str(&errbuf).to_owned()));
    }
    let result = (0..count as usize).map(|i| {
        let d = unsafe { &*devs.add(i) };
        Device {
            name:        cstr_to_str(&d.name).to_owned(),
            description: cstr_to_str(&d.description).to_owned(),
            loopback:    d.loopback != 0,
        }
    }).collect();
    unsafe { sys::pcapng_capture_free_devices(devs) };
    Ok(result)
}

// ── Raw FFI escape hatch ───────────────────────────────────────────────────

pub use pcapng_sys as ffi;
