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
//!     println!("ts={}  len={}  linktype={}", pkt.timestamp_us, pkt.origlen, pkt.linktype);
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
    /// Capture timestamp in microseconds since the UNIX epoch.
    pub timestamp_us: u64,
    /// Link-layer type (e.g. `LINKTYPE_ETHERNET`).
    pub linktype: u16,
    /// Private Enterprise Number — `Some(pen)` only for custom blocks.
    pub custom_pen: Option<u32>,
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

    let mut interfaces: Vec<u16> = Vec::new();

    read_file(path, |_ctr, block_type, data| {
        // The C library passes the block body (block_total_length - 8 bytes
        // of valid data, plus up to 8 bytes of stale stack/next-block bytes).
        // Safe body length = data.len() - 8 (we stay well within).
        match block_type {
            // SHB: new section — reset interface list
            0x0A0D_0D0A => { interfaces.clear(); }

            // IDB: Interface Description Block — record link type
            0x0000_0001 => { interfaces.push(rd16(data, 0)); }

            // EPB: Enhanced Packet Block
            0x0000_0006 => {
                let iface   = rd32(data,  0) as usize;
                let ts_hi   = rd32(data,  4) as u64;
                let ts_lo   = rd32(data,  8) as u64;
                let caplen  = rd32(data, 12) as usize;
                let origlen = rd32(data, 16);
                let ts_us   = (ts_hi << 32) | ts_lo;
                let lt = interfaces.get(iface).copied().unwrap_or(LINKTYPE_ETHERNET);
                let end = 20 + caplen;
                if end <= data.len() {
                    let fp = FilePacket {
                        data: &data[20..end], origlen,
                        timestamp_us: ts_us, linktype: lt, custom_pen: None,
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
                let lt = interfaces.first().copied().unwrap_or(LINKTYPE_ETHERNET);
                if 4 + caplen <= data.len() {
                    let fp = FilePacket {
                        data: &data[4..4 + caplen], origlen,
                        timestamp_us: 0, linktype: lt, custom_pen: None,
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
                    timestamp_us: 0, linktype: 0, custom_pen: Some(pen),
                };
                return callback(&fp);
            }

            _ => {}
        }
        true
    })
}

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
