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

use libpcapng_sys as sys;
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
}

impl Drop for Dissection {
    fn drop(&mut self) {
        unsafe { sys::pcapng_dissection_free(self.0) }
    }
}

pub use sys as ffi;
