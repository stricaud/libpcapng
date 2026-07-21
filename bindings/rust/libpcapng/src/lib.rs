//! Safe, idiomatic Rust bindings for [libpcapng](https://github.com/stricaud/libpcapng).
//!
//! # Reading a pcapng file
//! ```no_run
//! libpcapng::read_file("capture.pcapng", |_counter, block_type, data| {
//!     println!("block type=0x{block_type:08x} len={}", data.len());
//!     true // return false to stop early
//! }).unwrap();
//! ```
//!
//! # Dissecting a packet
//! ```no_run
//! let raw: &[u8] = &[/* ethernet frame bytes */];
//! if let Some(d) = libpcapng::Dissection::new(raw, libpcapng::LINKTYPE_ETHERNET) {
//!     println!("{} → {}  [{}]  {}", d.src(), d.dst(), d.proto(), d.info());
//! }
//! ```

use pcapng_sys as sys;
use std::ffi::{c_void, CStr, CString};
use std::path::Path;

pub use sys::{
    PCAPNG_ENHANCED_PACKET_BLOCK as BLOCK_EPB,
    PCAPNG_INTERFACE_DESCRIPTION_BLOCK as BLOCK_IDB,
    PCAPNG_SECTION_HEADER_BLOCK as BLOCK_SHB,
    PCAPNG_SIMPLE_PACKET_BLOCK as BLOCK_SPB,
};

pub const LINKTYPE_ETHERNET: u16 = 1;
pub const LINKTYPE_RAW: u16 = 101;
pub const LINKTYPE_LINUX_SLL: u16 = 113;
pub const LINKTYPE_IPV4: u16 = 228;
pub const LINKTYPE_IPV6: u16 = 229;

/// Error returned by libpcapng operations.
#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

// Trampoline state: carries the Rust closure through the C callback boundary.
struct Ctx<F> {
    cb: F,
}

unsafe extern "C" fn trampoline<F>(
    counter: u32,
    block_type: u32,
    total_len: u32,
    data: *mut u8,
    userdata: *mut c_void,
) -> i32
where
    F: FnMut(u32, u32, &[u8]) -> bool,
{
    let ctx = &mut *(userdata as *mut Ctx<F>);
    let slice = if data.is_null() || total_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, total_len as usize)
    };
    if (ctx.cb)(counter, block_type, slice) {
        0
    } else {
        1
    }
}

/// Read every block from a pcapng file, calling `callback` for each one.
///
/// The callback receives `(block_counter, block_type, raw_block_bytes)`.
/// Return `true` to continue or `false` to stop early.
pub fn read_file<P, F>(path: P, callback: F) -> Result<(), Error>
where
    P: AsRef<Path>,
    F: FnMut(u32, u32, &[u8]) -> bool,
{
    let path_str = path
        .as_ref()
        .to_str()
        .ok_or_else(|| Error("path contains non-UTF-8 characters".into()))?;
    let c_path =
        CString::new(path_str).map_err(|e| Error(format!("invalid path: {e}")))?;

    let mut ctx = Ctx { cb: callback };
    let ret = unsafe {
        sys::libpcapng_file_read(
            c_path.as_ptr() as *mut _,
            Some(trampoline::<F>),
            &mut ctx as *mut _ as *mut c_void,
        )
    };

    if ret < 0 {
        Err(Error(format!("libpcapng_file_read returned {ret}")))
    } else {
        Ok(())
    }
}

/// A dissected packet: protocol field tree + summary columns.
///
/// Freed automatically on drop.
pub struct Dissection(*mut sys::pcapng_dissection_t);

impl Dissection {
    /// Dissect `data` using the given link-layer type (use the `LINKTYPE_*` constants).
    ///
    /// Returns `None` only on allocation failure.
    pub fn new(data: &[u8], linktype: u16) -> Option<Self> {
        let ptr = unsafe {
            sys::pcapng_dissect(
                data.as_ptr(),
                data.len() as u32,
                data.len() as u32,
                linktype,
            )
        };
        if ptr.is_null() {
            None
        } else {
            Some(Self(ptr))
        }
    }

    fn inner(&self) -> &sys::pcapng_dissection_t {
        unsafe { &*self.0 }
    }

    fn cstr(bytes: &[i8]) -> &str {
        let ptr = bytes.as_ptr() as *const std::os::raw::c_char;
        unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("")
    }

    /// Deepest recognised protocol name (e.g. `"tcp"`, `"dns"`).
    pub fn proto(&self) -> &str {
        Self::cstr(&self.inner().proto)
    }

    /// Source address (IP, MAC, or empty).
    pub fn src(&self) -> &str {
        Self::cstr(&self.inner().src)
    }

    /// Destination address.
    pub fn dst(&self) -> &str {
        Self::cstr(&self.inner().dst)
    }

    /// One-line human-readable summary (Wireshark-style Info column).
    pub fn info(&self) -> &str {
        Self::cstr(&self.inner().info)
    }

    /// Raw pointer to the field tree root (for advanced use via `libpcapng-sys`).
    pub fn root_ptr(&self) -> *mut sys::pcapng_field_t {
        self.inner().root
    }

    /// The root of the dissection's field tree — a safe, walkable view.
    ///
    /// The root itself is structural (no value); its [`children`](Field::children)
    /// are the protocol layers in order (Frame, Ethernet, IP, TCP, …), each with
    /// their own fields below. The view borrows the [`Dissection`], so it cannot
    /// outlive it.
    pub fn root(&self) -> Field<'_> {
        Field { ptr: self.inner().root, _p: PhantomData }
    }
}

impl Drop for Dissection {
    fn drop(&mut self) {
        unsafe { sys::pcapng_dissection_free(self.0) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Field tree — a safe, walkable view of a Dissection
// ─────────────────────────────────────────────────────────────────────────────

use std::marker::PhantomData;

/// The value carried by a dissected [`Field`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    /// Structural node (a protocol layer / grouping), no value.
    None,
    /// Unsigned integer ([`Field::uint`]).
    Uint,
    /// Text ([`Field::str_value`]).
    Str,
    /// IPv4 address: 4 raw bytes ([`Field::bytes`]), dotted-quad in [`Field::str_value`].
    Ipv4,
    /// IPv6 address: 16 raw bytes.
    Ipv6,
    /// MAC address: 6 raw bytes.
    Mac,
    /// Opaque bytes (first 16 kept).
    Bytes,
}

impl FieldType {
    fn from_raw(v: sys::pcapng_ftype_t) -> FieldType {
        match v {
            x if x == sys::pcapng_ftype_t_PCAPNG_FT_UINT => FieldType::Uint,
            x if x == sys::pcapng_ftype_t_PCAPNG_FT_STR => FieldType::Str,
            x if x == sys::pcapng_ftype_t_PCAPNG_FT_IPV4 => FieldType::Ipv4,
            x if x == sys::pcapng_ftype_t_PCAPNG_FT_IPV6 => FieldType::Ipv6,
            x if x == sys::pcapng_ftype_t_PCAPNG_FT_MAC => FieldType::Mac,
            x if x == sys::pcapng_ftype_t_PCAPNG_FT_BYTES => FieldType::Bytes,
            _ => FieldType::None,
        }
    }
}

/// A borrowed view of one node in a [`Dissection`]'s field tree.
///
/// Each field carries a Wireshark-style [`abbrev`](Field::abbrev) (`"ip.src"`,
/// `"tcp.dstport"`) for filtering, a human [`label`](Field::label) for display,
/// a typed value, and its byte [`offset`](Field::offset)/[`len`](Field::byte_len)
/// within the packet (to highlight exactly the bytes a field came from).
///
/// `Field` is `Copy` and cheap to pass around; it borrows the owning
/// [`Dissection`] so it can never dangle.
#[derive(Clone, Copy)]
pub struct Field<'a> {
    ptr: *const sys::pcapng_field_t,
    _p: PhantomData<&'a Dissection>,
}

impl<'a> Field<'a> {
    /// Wrap a raw field pointer as a borrowed view. Useful when walking a
    /// dissection tree through raw pointers (e.g. driving a TUI tree widget) and
    /// then wanting the safe accessors back.
    ///
    /// # Safety
    /// `ptr` must point to a live `pcapng_field_t` that outlives `'a` (i.e. its
    /// owning [`Dissection`] is still alive).
    pub unsafe fn from_raw(ptr: *const sys::pcapng_field_t) -> Field<'a> {
        Field { ptr, _p: PhantomData }
    }

    /// The underlying raw pointer (for identity comparisons / raw walking).
    pub fn as_ptr(&self) -> *const sys::pcapng_field_t {
        self.ptr
    }

    #[inline]
    fn node(&self) -> &sys::pcapng_field_t {
        unsafe { &*self.ptr }
    }

    fn cstr(bytes: &[std::os::raw::c_char]) -> &str {
        unsafe { CStr::from_ptr(bytes.as_ptr()) }.to_str().unwrap_or("")
    }

    /// Wireshark-style abbreviation (`"ip.src"`); `""` for structural rows.
    pub fn abbrev(&self) -> &str {
        Self::cstr(&self.node().abbrev)
    }

    /// Human-readable label shown in a detail tree.
    pub fn label(&self) -> &str {
        Self::cstr(&self.node().label)
    }

    /// The field's value type.
    pub fn ftype(&self) -> FieldType {
        FieldType::from_raw(self.node().vtype)
    }

    /// Integer value (meaningful when [`ftype`](Field::ftype) is [`FieldType::Uint`]).
    pub fn uint(&self) -> u64 {
        self.node().u
    }

    /// String value (text, or the formatted IP/MAC).
    pub fn str_value(&self) -> &str {
        Self::cstr(&self.node().str_)
    }

    /// Raw bytes (IPv4/IPv6/MAC/opaque), up to 16 bytes.
    pub fn bytes(&self) -> &[u8] {
        let n = self.node().blen.max(0) as usize;
        &self.node().bytes[..n.min(self.node().bytes.len())]
    }

    /// Absolute byte offset of this field within the packet.
    pub fn offset(&self) -> usize {
        self.node().off.max(0) as usize
    }

    /// Byte length of this field within the packet.
    pub fn byte_len(&self) -> usize {
        self.node().len.max(0) as usize
    }

    /// Whether this node has any children.
    pub fn has_children(&self) -> bool {
        !self.node().children.is_null()
    }

    /// Iterate this node's direct children, in order.
    pub fn children(&self) -> Children<'a> {
        Children { ptr: self.node().children, _p: PhantomData }
    }

    /// Number of direct children.
    pub fn child_count(&self) -> usize {
        self.children().count()
    }

    /// Collect every descendant (and self) whose abbrev equals `abbrev`.
    ///
    /// This is the primitive display filters use for multi-valued fields
    /// (`ip.addr`, `tcp.port`) with Wireshark "any" match semantics.
    pub fn collect(&self, abbrev: &str) -> Vec<Field<'a>> {
        let mut out = Vec::new();
        self.collect_into(abbrev, &mut out);
        out
    }

    fn collect_into(&self, abbrev: &str, out: &mut Vec<Field<'a>>) {
        if self.abbrev() == abbrev {
            out.push(*self);
        }
        for c in self.children() {
            c.collect_into(abbrev, out);
        }
    }

    /// The first descendant (or self) with this abbrev, if any.
    pub fn find(&self, abbrev: &str) -> Option<Field<'a>> {
        if self.abbrev() == abbrev {
            return Some(*self);
        }
        for c in self.children() {
            if let Some(f) = c.find(abbrev) {
                return Some(f);
            }
        }
        None
    }
}

/// Iterator over a [`Field`]'s direct children.
pub struct Children<'a> {
    ptr: *const sys::pcapng_field_t,
    _p: PhantomData<&'a Dissection>,
}

impl<'a> Iterator for Children<'a> {
    type Item = Field<'a>;
    fn next(&mut self) -> Option<Field<'a>> {
        if self.ptr.is_null() {
            return None;
        }
        let cur = self.ptr;
        self.ptr = unsafe { (*cur).next };
        Some(Field { ptr: cur, _p: PhantomData })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// posa — declarative .posa protocol decoders (global registry)
// ─────────────────────────────────────────────────────────────────────────────

/// Loading and querying [`.posa`](https://github.com/stricaud/libpcapng)
/// declarative decoders. These register into libpcapng's global protocol
/// registry, so once loaded they participate in [`Dissection::new`] for any
/// port/ethertype/ip-proto they bind with a `rule` line.
pub mod posa {
    use super::{sys, Error};
    use std::ffi::{CStr, CString};
    use std::path::Path;

    /// Load every `*.posa` file in a directory. Returns the number added.
    pub fn load_dir<P: AsRef<Path>>(dir: P) -> i32 {
        let c = match CString::new(dir.as_ref().to_string_lossy().as_bytes()) {
            Ok(c) => c,
            Err(_) => return -1,
        };
        unsafe { sys::pcapng_posa_load_dir(c.as_ptr()) }
    }

    /// Load a single `.posa` file. Returns the number of protocols added.
    pub fn load_file<P: AsRef<Path>>(path: P) -> Result<i32, Error> {
        let c = CString::new(path.as_ref().to_string_lossy().as_bytes())
            .map_err(|_| Error("path contains NUL".into()))?;
        let mut errbuf = [0i8; 256];
        let n = unsafe {
            sys::pcapng_posa_load_file(c.as_ptr(), errbuf.as_mut_ptr(), errbuf.len())
        };
        if n < 0 {
            let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }.to_string_lossy().into_owned();
            Err(Error(if msg.is_empty() { "posa load failed".into() } else { msg }))
        } else {
            Ok(n)
        }
    }

    /// Parse `.posa` definitions from an in-memory string.
    pub fn load_text(src: &str) -> Result<i32, Error> {
        let c = CString::new(src).map_err(|_| Error("text contains NUL".into()))?;
        let mut errbuf = [0i8; 256];
        let n = unsafe {
            sys::pcapng_posa_load_text(c.as_ptr(), errbuf.as_mut_ptr(), errbuf.len())
        };
        if n < 0 {
            let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }.to_string_lossy().into_owned();
            Err(Error(if msg.is_empty() { "posa parse failed".into() } else { msg }))
        } else {
            Ok(n)
        }
    }

    /// Remove all loaded posa protocols.
    pub fn clear() {
        unsafe { sys::pcapng_posa_clear() }
    }

    /// Number of loaded protocols.
    pub fn count() -> i32 {
        unsafe { sys::pcapng_posa_count() }
    }

    /// Names of all loaded protocols.
    pub fn protocols() -> Vec<String> {
        let n = count();
        let mut v = Vec::new();
        for i in 0..n {
            let p = unsafe { sys::pcapng_posa_at(i) };
            if p.is_null() {
                continue;
            }
            let name = unsafe { CStr::from_ptr((*p).name.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            v.push(name);
        }
        v
    }

    /// The protocol name a transport port is bound to, if any.
    /// `ip_proto` is 6 (TCP) or 17 (UDP).
    pub fn bound_port(ip_proto: i32, port: u16) -> Option<String> {
        let p = unsafe { sys::pcapng_posa_bound_port(ip_proto, port) };
        if p.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
        }
    }

    /// The `.posa` source text a protocol was parsed from, if kept.
    pub fn source(name: &str) -> Option<String> {
        let c = CString::new(name).ok()?;
        let p = unsafe { sys::pcapng_posa_source(c.as_ptr()) };
        if p.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
        }
    }

    /// A coloring rule declared inside a decoder: `(display_filter, fg, bg)`.
    pub fn colors() -> Vec<(String, String, String)> {
        let n = unsafe { sys::pcapng_posa_color_count() };
        let mut v = Vec::new();
        for i in 0..n {
            let mut expr: *const std::os::raw::c_char = std::ptr::null();
            let mut fg: *const std::os::raw::c_char = std::ptr::null();
            let mut bg: *const std::os::raw::c_char = std::ptr::null();
            let ok = unsafe { sys::pcapng_posa_color_get(i, &mut expr, &mut fg, &mut bg) };
            if ok == 0 || expr.is_null() {
                continue;
            }
            let s = |p: *const std::os::raw::c_char| {
                if p.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
                }
            };
            v.push((s(expr), s(fg), s(bg)));
        }
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet reader — yield captured packets (not raw blocks) from a pcapng file
// ─────────────────────────────────────────────────────────────────────────────

/// A captured packet yielded by [`read_packets`].
///
/// `data` borrows the reader's buffer and is only valid for the duration of the
/// callback; copy it out (e.g. `data.to_vec()`) to keep it.
pub struct Packet<'a> {
    /// The captured frame bytes (`caplen` long).
    pub data: &'a [u8],
    /// Bytes actually captured.
    pub caplen: u32,
    /// Original on-wire length (>= `caplen` if the capture was snapped short).
    pub origlen: u32,
    /// Timestamp in microseconds since the Unix epoch (assumes µs `if_tsresol`).
    pub timestamp_us: u64,
    /// Link-layer type (`LINKTYPE_*`) of the interface this packet arrived on.
    /// For a Custom Block this is [`LINKTYPE_RAW`]-agnostic and `custom_pen` is set.
    pub linktype: u16,
    /// Index of the interface (IDB) this packet arrived on.
    pub interface_id: u32,
    /// `Some(pen)` when this came from a pcapng **Custom Block** (0x00000BAD /
    /// 0x40000BAD): its Private Enterprise Number. `data` is the bytes after the
    /// PEN. `None` for ordinary captured frames.
    pub custom_pen: Option<u32>,
}

// Endianness of the current pcapng section, learned from its SHB.
#[derive(Clone, Copy)]
enum End {
    Little,
    Big,
}
impl End {
    #[inline]
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        match self {
            End::Little => u16::from_le_bytes(a),
            End::Big => u16::from_be_bytes(a),
        }
    }
    #[inline]
    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        match self {
            End::Little => u32::from_le_bytes(a),
            End::Big => u32::from_be_bytes(a),
        }
    }
}

/// Read a pcapng file and call `f` once per captured packet (EPB/SPB), rather
/// than once per raw block.
///
/// Interface link-types (from IDBs) and byte order (from the SHB) are tracked
/// automatically. Return `false` from `f` to stop early.
///
/// ```no_run
/// libpcapng::read_packets("capture.pcapng", |pkt| {
///     if let Some(d) = libpcapng::Dissection::new(pkt.data, pkt.linktype) {
///         println!("{} → {} [{}] {}", d.src(), d.dst(), d.proto(), d.info());
///     }
///     true
/// }).unwrap();
/// ```
pub fn read_packets<P, F>(path: P, mut f: F) -> Result<(), Error>
where
    P: AsRef<Path>,
    F: FnMut(Packet) -> bool,
{
    let mut end = End::Little;
    let mut linktypes: Vec<u16> = Vec::new();

    read_file(path, |_counter, block_type, raw| {
        // `raw` is the block *body* (everything after the 8-byte type+length
        // header), and its slice carries 8 uninitialised trailing bytes, so the
        // valid body is `raw[..raw.len()-8]`. All offsets below are body-relative.
        let body = &raw[..raw.len().saturating_sub(8)];
        match block_type {
            BLOCK_SHB => {
                // byte-order magic (body@0): 0x1A2B3C4D in the file's order.
                if body.len() >= 4 {
                    end = if body[0..4] == [0x4d, 0x3c, 0x2b, 0x1a] {
                        End::Little
                    } else {
                        End::Big
                    };
                }
                linktypes.clear();
            }
            BLOCK_IDB => {
                // linktype: u16 at body@0.
                let lt = if body.len() >= 2 { end.u16(&body[0..2]) } else { 1 };
                linktypes.push(lt);
            }
            BLOCK_EPB => {
                // iface@0, ts_hi@4, ts_lo@8, caplen@12, origlen@16, data@20.
                if body.len() >= 20 {
                    let iface = end.u32(&body[0..4]);
                    let ts_hi = end.u32(&body[4..8]) as u64;
                    let ts_lo = end.u32(&body[8..12]) as u64;
                    let caplen = end.u32(&body[12..16]);
                    let origlen = end.u32(&body[16..20]);
                    let start = 20usize;
                    let cl = caplen as usize;
                    if start + cl <= body.len() {
                        let lt = linktypes.get(iface as usize).copied().unwrap_or(1);
                        let pkt = Packet {
                            data: &body[start..start + cl],
                            caplen,
                            origlen,
                            timestamp_us: (ts_hi << 32) | ts_lo,
                            linktype: lt,
                            interface_id: iface,
                            custom_pen: None,
                        };
                        return f(pkt);
                    }
                }
            }
            BLOCK_SPB => {
                // origlen@0, data@4; the last 4 bytes of body are the trailing length.
                if body.len() >= 8 {
                    let origlen = end.u32(&body[0..4]);
                    let start = 4usize;
                    let avail = body.len().saturating_sub(start + 4);
                    let cl = (origlen as usize).min(avail);
                    let lt = linktypes.first().copied().unwrap_or(1);
                    let pkt = Packet {
                        data: &body[start..start + cl],
                        caplen: cl as u32,
                        origlen,
                        timestamp_us: 0,
                        linktype: lt,
                        interface_id: 0,
                        custom_pen: None,
                    };
                    return f(pkt);
                }
            }
            // Custom Block (copyable 0x00000BAD, non-copyable 0x40000BAD):
            // PEN@0, custom data@4 (last 4 bytes of body are the trailing length).
            0x0000_0BAD | 0x4000_0BAD => {
                if body.len() >= 8 {
                    let pen = end.u32(&body[0..4]);
                    let start = 4usize;
                    let payload = &body[start..body.len() - 4];
                    let pkt = Packet {
                        data: payload,
                        caplen: payload.len() as u32,
                        origlen: payload.len() as u32,
                        timestamp_us: 0,
                        linktype: linktypes.first().copied().unwrap_or(0),
                        interface_id: 0,
                        custom_pen: Some(pen),
                    };
                    return f(pkt);
                }
            }
            _ => {}
        }
        true
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Reassembly — passive TCP stream + IP fragment reassembly (library features)
// ─────────────────────────────────────────────────────────────────────────────

extern "C" {
    // libpcapng_reasm_add hands back a malloc'd datagram the caller must free.
    fn free(ptr: *mut c_void);
}

/// New in-order bytes delivered by [`TcpReasm::add`] for one half-stream.
pub struct TcpBytes<'a> {
    pub src_ip: u32,
    pub src_port: u16,
    pub dst_ip: u32,
    pub dst_port: u16,
    /// Stable 0/1 direction id (0 = side-A→B, 1 = B→A).
    pub dir: i32,
    /// The newly delivered in-order bytes.
    pub data: &'a [u8],
    /// The cumulative reassembled buffer for this half-stream.
    pub all: &'a [u8],
}

/// Passive TCP stream reassembly (libpcapng's `pcapng_tcp_reasm_*`).
///
/// Feed captured TCP segments with [`add`](TcpReasm::add); in-order bytes are
/// delivered to your closure per direction, with the cumulative buffer so far.
/// Intended for offline analysis (not a full TCP stack — no SACK/checksum).
pub struct TcpReasm(*mut sys::pcapng_tcp_reasm_t);

unsafe extern "C" fn tcp_tramp<F: FnMut(TcpBytes)>(
    ud: *mut c_void,
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    dir: std::os::raw::c_int,
    data: *const u8,
    len: usize,
    all: *const u8,
    all_len: usize,
) {
    let cb = &mut *(ud as *mut F);
    let slice = |p: *const u8, n: usize| {
        if p.is_null() || n == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(p, n)
        }
    };
    cb(TcpBytes {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        dir,
        data: slice(data, len),
        all: slice(all, all_len),
    });
}

impl TcpReasm {
    /// Create a reassembly context.
    pub fn new() -> TcpReasm {
        TcpReasm(unsafe { sys::pcapng_tcp_reasm_new() })
    }

    /// Feed one TCP segment (IPs/ports in host byte order). `flags` is the raw
    /// TCP flags byte; `payload` may be empty for pure ACK/control. The closure
    /// runs zero or more times for newly in-order bytes produced by this segment.
    pub fn add<F: FnMut(TcpBytes)>(
        &mut self,
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
        mut cb: F,
    ) {
        let (pp, pl) = if payload.is_empty() {
            (std::ptr::null(), 0usize)
        } else {
            (payload.as_ptr(), payload.len())
        };
        unsafe {
            sys::pcapng_tcp_reasm_add(
                self.0,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                seq,
                flags,
                pp,
                pl,
                Some(tcp_tramp::<F>),
                &mut cb as *mut F as *mut c_void,
            );
        }
    }
}

impl Default for TcpReasm {
    fn default() -> Self {
        TcpReasm::new()
    }
}

impl Drop for TcpReasm {
    fn drop(&mut self) {
        unsafe { sys::pcapng_tcp_reasm_free(self.0) }
    }
}

// ── Object (file) extraction ─────────────────────────────────────────────────

/// The application protocol to carve transferred files from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ObjectProto {
    /// HTTP requests/responses (de-chunked).
    Http,
    /// SMB2 files (recovered from READ responses).
    Smb,
}

/// One extracted object — a file transferred over the wire — copied out of the
/// extractor so it outlives it.
#[derive(Clone, Debug)]
pub struct Object {
    /// `"HTTP"` / `"SMB"`.
    pub proto: String,
    /// 1-based packet number the object ends in.
    pub frame: i32,
    /// HTTP `Host:` / SMB server (or an IP).
    pub hostname: String,
    /// HTTP `Content-Type` (empty for SMB).
    pub content_type: String,
    /// Filename derived from the URI / SMB path.
    pub filename: String,
    /// The object's bytes.
    pub data: Vec<u8>,
    /// Whether the full declared length was captured.
    pub complete: bool,
}

/// Carves transferred files out of captured TCP traffic — the engine behind
/// Wireshark's (and carcal's) "Export Objects". Reassembles TCP streams and
/// parses the application protocol to recover each object's bytes + metadata.
///
/// Feed packets in capture order, call [`ObjectExtractor::finish`] once, then
/// read [`ObjectExtractor::objects`].
///
/// ```no_run
/// use libpcapng::{ObjectExtractor, ObjectProto, LINKTYPE_ETHERNET};
/// let mut ex = ObjectExtractor::new(ObjectProto::Http);
/// # let frames: Vec<Vec<u8>> = vec![];
/// for (i, frame) in frames.iter().enumerate() {
///     ex.add_packet(i as i32 + 1, frame, LINKTYPE_ETHERNET);
/// }
/// ex.finish();
/// for obj in ex.objects() {
///     println!("{} ({} bytes)", obj.filename, obj.data.len());
/// }
/// ```
pub struct ObjectExtractor(*mut sys::pcapng_object_extractor_t);

impl ObjectExtractor {
    /// Create an extractor for `proto`.
    pub fn new(proto: ObjectProto) -> ObjectExtractor {
        let p = match proto {
            ObjectProto::Http => sys::pcapng_object_proto_t_PCAPNG_OBJ_HTTP,
            ObjectProto::Smb => sys::pcapng_object_proto_t_PCAPNG_OBJ_SMB,
        };
        let ptr = unsafe { sys::pcapng_object_extractor_new(p) };
        assert!(!ptr.is_null(), "pcapng_object_extractor_new returned NULL");
        ObjectExtractor(ptr)
    }

    /// Feed one captured packet (raw link-layer bytes). `frame` is its 1-based
    /// packet number. Non-TCP packets are ignored; supply packets in capture
    /// order.
    pub fn add_packet(&mut self, frame: i32, data: &[u8], linktype: u16) {
        unsafe {
            sys::pcapng_object_extractor_add_packet(
                self.0,
                frame,
                data.as_ptr(),
                data.len() as u32,
                linktype,
            )
        };
    }

    /// Parse the accumulated streams into objects. Call once, after all packets.
    pub fn finish(&mut self) {
        unsafe { sys::pcapng_object_extractor_finish(self.0) };
    }

    /// The extracted objects (each with its bytes and metadata).
    pub fn objects(&self) -> Vec<Object> {
        let n = unsafe { sys::pcapng_object_count(self.0) };
        let mut out = Vec::with_capacity(n.max(0) as usize);
        for i in 0..n {
            let p = unsafe { sys::pcapng_object_at(self.0, i) };
            if p.is_null() {
                continue;
            }
            let o = unsafe { &*p };
            let s = |a: &[std::os::raw::c_char]| {
                unsafe { CStr::from_ptr(a.as_ptr()) }.to_string_lossy().into_owned()
            };
            let data = if o.data.is_null() || o.len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(o.data, o.len) }.to_vec()
            };
            out.push(Object {
                proto: s(&o.proto),
                frame: o.frame,
                hostname: s(&o.hostname),
                content_type: s(&o.content_type),
                filename: s(&o.filename),
                data,
                complete: o.complete != 0,
            });
        }
        out
    }
}

impl Drop for ObjectExtractor {
    fn drop(&mut self) {
        unsafe { sys::pcapng_object_extractor_free(self.0) }
    }
}

/// Result of feeding a packet to [`IpReasm::add`].
pub enum IpReasm4 {
    /// Reassembly complete: a full IPv4 datagram (corrected length/checksum).
    Complete(Vec<u8>),
    /// Fragment buffered; more expected.
    Buffered,
    /// Not an IPv4 fragment — use the packet as-is.
    PassThrough,
}

/// IPv4 fragment reassembly (libpcapng's `libpcapng_reasm_*`).
pub struct IpReasm(*mut sys::libpcapng_reasm_t);

impl IpReasm {
    pub fn new() -> IpReasm {
        IpReasm(unsafe { sys::libpcapng_reasm_new() })
    }

    /// Feed one packet (raw Ethernet frame or raw IPv4 datagram, auto-detected).
    pub fn add(&mut self, pkt: &[u8]) -> IpReasm4 {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            sys::libpcapng_reasm_add(self.0, pkt.as_ptr(), pkt.len(), &mut out, &mut out_len)
        };
        match rc {
            1 => {
                let v = if out.is_null() || out_len == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(out, out_len).to_vec() }
                };
                if !out.is_null() {
                    unsafe { free(out as *mut c_void) };
                }
                IpReasm4::Complete(v)
            }
            0 => IpReasm4::Buffered,
            _ => IpReasm4::PassThrough,
        }
    }
}

impl Default for IpReasm {
    fn default() -> Self {
        IpReasm::new()
    }
}

impl Drop for IpReasm {
    fn drop(&mut self) {
        unsafe { sys::libpcapng_reasm_free(self.0) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Live capture — device discovery + zero-copy packet capture
// ─────────────────────────────────────────────────────────────────────────────

/// A network interface reported by [`list_devices`].
#[derive(Clone, Debug)]
pub struct Device {
    pub name: String,
    pub description: String,
    pub loopback: bool,
}

fn cstr_field(bytes: &[std::os::raw::c_char]) -> String {
    unsafe { CStr::from_ptr(bytes.as_ptr()) }.to_string_lossy().into_owned()
}

/// Enumerate the available capture interfaces. Does not require privileges.
pub fn list_devices() -> Result<Vec<Device>, Error> {
    let mut count: std::os::raw::c_int = 0;
    let mut errbuf = [0i8; 256];
    let ptr = unsafe { sys::pcapng_capture_list_devices(&mut count, errbuf.as_mut_ptr()) };
    if ptr.is_null() {
        let msg = cstr_field(&errbuf);
        return Err(Error(if msg.is_empty() { "list_devices failed".into() } else { msg }));
    }
    let mut out = Vec::new();
    for i in 0..count.max(0) as isize {
        let d = unsafe { &*ptr.offset(i) };
        out.push(Device {
            name: cstr_field(&d.name),
            description: cstr_field(&d.description),
            loopback: d.loopback != 0,
        });
    }
    unsafe { sys::pcapng_capture_free_devices(ptr) };
    Ok(out)
}

/// The first suitable non-loopback interface, if any.
pub fn default_device() -> Option<String> {
    let mut errbuf = [0i8; 256];
    let p = unsafe { sys::pcapng_capture_default_device(errbuf.as_mut_ptr()) };
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

/// One captured packet delivered to a [`Capture::run`] callback. `data` is a
/// zero-copy view valid only for the callback's duration — copy it to keep it.
pub struct CapturedPacket<'a> {
    pub data: &'a [u8],
    pub captured_len: u32,
    pub original_len: u32,
    /// Nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// 0 = unknown, 1 = inbound, 2 = outbound.
    pub direction: i32,
}

/// A live capture handle (libpcapng's `pcapng_capture_*`).
///
/// Requires privileges to open (root, or `CAP_NET_RAW` on Linux). Available on
/// Linux (PACKET_MMAP) and BSD/macOS (bpf); the capture backend is a stub on
/// Windows.
pub struct Capture(*mut sys::pcapng_capture_t);

unsafe extern "C" fn cap_tramp<F: FnMut(CapturedPacket)>(
    info: *const sys::pcapng_packet_info_t,
    ud: *mut c_void,
) {
    if info.is_null() {
        return;
    }
    let p = &*info;
    let data = if p.data.is_null() || p.captured_len == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(p.data, p.captured_len as usize)
    };
    let cb = &mut *(ud as *mut F);
    cb(CapturedPacket {
        data,
        captured_len: p.captured_len,
        original_len: p.original_len,
        timestamp_ns: p.timestamp_ns,
        direction: p.direction,
    });
}

impl Capture {
    /// Open a capture on `device` (see [`list_devices`] / [`default_device`]).
    pub fn open(device: &str) -> Result<Capture, Error> {
        let c = CString::new(device).map_err(|_| Error("device contains NUL".into()))?;
        let mut errbuf = [0i8; 256];
        let h = unsafe { sys::pcapng_capture_open(c.as_ptr(), errbuf.as_mut_ptr()) };
        if h.is_null() {
            let msg = cstr_field(&errbuf);
            Err(Error(if msg.is_empty() { "capture open failed".into() } else { msg }))
        } else {
            Ok(Capture(h))
        }
    }

    /// Attach an in-kernel display filter (Wireshark syntax).
    pub fn set_filter(&self, expr: &str) -> Result<(), Error> {
        let c = CString::new(expr).map_err(|_| Error("filter contains NUL".into()))?;
        let mut errbuf = [0i8; 256];
        let rc = unsafe { sys::pcapng_capture_set_filter(self.0, c.as_ptr(), errbuf.as_mut_ptr()) };
        if rc != 0 {
            let msg = cstr_field(&errbuf);
            Err(Error(if msg.is_empty() { "set_filter failed".into() } else { msg }))
        } else {
            Ok(())
        }
    }

    pub fn set_promisc(&self, on: bool) {
        unsafe { sys::pcapng_capture_set_promisc(self.0, on as std::os::raw::c_int) };
    }
    pub fn set_snaplen(&self, snaplen: u32) {
        unsafe { sys::pcapng_capture_set_snaplen(self.0, snaplen) };
    }
    pub fn set_timeout(&self, ms: i32) {
        unsafe { sys::pcapng_capture_set_timeout(self.0, ms) };
    }

    /// Capture packets, invoking `cb` for each. `count` of 0 captures until
    /// [`break_loop`](Capture::break_loop) is called (e.g. from the callback).
    pub fn run<F: FnMut(CapturedPacket)>(&self, count: i32, mut cb: F) -> i32 {
        unsafe {
            sys::pcapng_capture_loop(
                self.0,
                count,
                Some(cap_tramp::<F>),
                &mut cb as *mut F as *mut c_void,
            )
        }
    }

    /// Ask [`run`](Capture::run) to stop.
    pub fn break_loop(&self) {
        unsafe { sys::pcapng_capture_break(self.0) };
    }

    /// Process one batch of currently-available packets and return immediately —
    /// suitable for embedding in an existing event loop (e.g. a TUI). `count <=
    /// 0` processes all available. Returns packets processed (0 if none), or a
    /// negative value on error.
    pub fn dispatch<F: FnMut(CapturedPacket)>(&self, count: i32, mut cb: F) -> i32 {
        unsafe {
            sys::pcapng_capture_dispatch(
                self.0,
                count,
                Some(cap_tramp::<F>),
                &mut cb as *mut F as *mut c_void,
            )
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        unsafe { sys::pcapng_capture_close(self.0) }
    }
}

pub use pcapng_sys as ffi;
