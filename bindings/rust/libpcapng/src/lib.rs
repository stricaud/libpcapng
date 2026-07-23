//! Safe, idiomatic Rust bindings for [libpcapng](https://github.com/stricaud/libpcapng).
//!
//! # Reading a pcapng file
//! ```no_run
//! libpcapng::read_file("capture.pcapng", |_counter, block_type, data| {
//!     println!("block type=0x{block_type:08x}  {} bytes", data.len());
//!     true
//! }).unwrap();
//! ```
//!
//! # Dissecting a packet
//! ```no_run
//! let frame: &[u8] = &[];
//! if let Some(d) = libpcapng::Dissection::new(frame, libpcapng::LINKTYPE_ETHERNET) {
//!     println!("{} → {}  [{}]  {}", d.src(), d.dst(), d.proto(), d.info());
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

// ── File reading ───────────────────────────────────────────────────────────

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
/// The callback receives `(block_counter, block_type, raw_block_bytes)`.
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

    /// Walk the field tree starting from the root.
    pub fn root_field(&self) -> Option<Field<'_>> {
        let root = self.inner().root;
        if root.is_null() { None } else { Some(Field(unsafe { &*root })) }
    }
}

impl Drop for Dissection {
    fn drop(&mut self) { unsafe { sys::pcapng_dissection_free(self.0) } }
}

// ── Field ──────────────────────────────────────────────────────────────────

/// A node in the protocol field tree produced by `Dissection`.
pub struct Field<'a>(&'a sys::pcapng_field_t);

impl<'a> Field<'a> {
    /// Wireshark-style abbreviation (e.g. `"ip.src"`). Empty for structural nodes.
    pub fn abbrev(&self) -> &str { cstr_to_str(&self.0.abbrev) }
    /// Human-readable label (e.g. `"Source: 192.168.1.1"`).
    pub fn label(&self) -> &str  { cstr_to_str(&self.0.label)  }
    /// Integer value (valid when `vtype == PCAPNG_FT_UINT`).
    pub fn value_uint(&self) -> u64 { self.0.u }
    /// Absolute byte offset of this field within the packet.
    pub fn offset(&self) -> i32 { self.0.off }
    /// Byte length of this field within the packet.
    pub fn byte_len(&self) -> i32 { self.0.len }

    /// String-formatted value for IP/MAC/string field types.
    pub fn value_str(&self) -> &str { cstr_to_str(&self.0.str) }

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
        sys::pcapng_posa_load_text(c_src.as_ptr(), errbuf.as_mut_ptr(), 256)
    };
    if n < 0 {
        Err(err(cstr_to_str(&errbuf).to_owned()))
    } else {
        Ok(n as usize)
    }
}

// ── TCP reassembly ─────────────────────────────────────────────────────────

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

/// Passive TCP stream reassembler. Feed segments via [`add`](Self::add);
/// a callback delivers in-order bytes as gaps fill.
pub struct TcpReassembler(*mut sys::pcapng_tcp_reasm_t);

impl TcpReassembler {
    pub fn new() -> Self {
        let ptr = unsafe { sys::pcapng_tcp_reasm_new() };
        assert!(!ptr.is_null(), "pcapng_tcp_reasm_new returned null");
        Self(ptr)
    }

    /// Feed one TCP segment. `callback` is called (possibly multiple times) with
    /// any in-order bytes unlocked by this segment.
    ///
    /// IPs and ports are in host byte order. `tcp_flags` is the raw TCP flags byte.
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
        let ptr = unsafe { sys::pcapng_capture_open(c_dev.as_ptr(), errbuf.as_mut_ptr()) };
        if ptr.is_null() {
            Err(err(cstr_to_str(&errbuf).to_owned()))
        } else {
            Ok(Self(ptr))
        }
    }

    /// Apply a Wireshark-compatible display filter (e.g. `"tcp.dstport == 443"`).
    pub fn set_filter(&mut self, expr: &str) -> Result<(), Error> {
        let c_expr = CString::new(expr).map_err(|e| err(e.to_string()))?;
        let mut errbuf = [0i8; sys::PCAPNG_CAPTURE_ERRBUF_SIZE as usize];
        let ret = unsafe {
            sys::pcapng_capture_set_filter(self.0, c_expr.as_ptr(), errbuf.as_mut_ptr())
        };
        if ret < 0 { Err(err(cstr_to_str(&errbuf).to_owned())) } else { Ok(()) }
    }

    /// Capture packets, calling `callback` for each one.
    ///
    /// Runs until `count` packets are delivered (`count <= 0` = unlimited),
    /// `SIGINT` is received, or [`stop`](Self::stop) is called from another thread.
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

    /// Capture `count` packets directly to `output` in pcapng format.
    ///
    /// `count <= 0` captures until Ctrl-C. `filter` may be `""` for no filter.
    pub fn to_file(device: &str, output: &str, filter: &str, count: i32) -> Result<(), Error> {
        let c_dev  = CString::new(device).map_err(|e| err(e.to_string()))?;
        let c_out  = CString::new(output).map_err(|e| err(e.to_string()))?;
        let c_flt  = if filter.is_empty() { None }
                     else { Some(CString::new(filter).map_err(|e| err(e.to_string()))?) };
        let flt_ptr = c_flt.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
        let mut errbuf = [0i8; sys::PCAPNG_CAPTURE_ERRBUF_SIZE as usize];
        let ret = unsafe {
            sys::pcapng_capture_to_file(c_dev.as_ptr(), c_out.as_ptr(), flt_ptr, count, errbuf.as_mut_ptr())
        };
        if ret < 0 { Err(err(cstr_to_str(&errbuf).to_owned())) } else { Ok(()) }
    }

    /// Signal the capture loop to stop cleanly (safe to call from another thread).
    pub fn stop(&self) {
        unsafe { sys::pcapng_capture_break(self.0) }
    }
}

impl Drop for Capture {
    fn drop(&mut self) { unsafe { sys::pcapng_capture_close(self.0) } }
}

/// Return the name of the first suitable non-loopback interface, or `None`.
pub fn default_device() -> Option<String> {
    let mut errbuf = [0i8; sys::PCAPNG_CAPTURE_ERRBUF_SIZE as usize];
    let ptr = unsafe { sys::pcapng_capture_default_device(errbuf.as_mut_ptr()) };
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
    let devs = unsafe { sys::pcapng_capture_list_devices(&mut count, errbuf.as_mut_ptr()) };
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
