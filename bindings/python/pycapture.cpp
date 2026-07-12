/* pycapture.cpp — pybind11 bindings for the libpcapng live capture API.
 *
 * Exposes at the pycapng module level (not a submodule):
 *
 *   pycapng.PacketInfo                      — packet descriptor
 *   pycapng.CaptureStats                    — packet counters
 *   pycapng.Capture                         — live capture handle
 *   pycapng.capture_list_devices()          — enumerate network interfaces
 *   pycapng.capture_default_device()        — first non-loopback interface
 *   pycapng.capture_to_file()               — one-liner: capture → pcapng file
 *   pycapng.capture_print()                 — one-liner: capture → stdout
 *
 * GIL strategy:
 *   pcapng_capture_loop() blocks, so the GIL is released for its duration.
 *   The packet trampoline and field-provider trampoline each re-acquire the
 *   GIL before calling into Python and release it again on return.  This
 *   allows other Python threads to run while packets are being waited for.
 */

#include <exception>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

#include <pybind11/pybind11.h>
#include <pybind11/functional.h>
#include <pybind11/stl.h>

extern "C" {
#include <libpcapng/capture.h>
}

namespace py = pybind11;

/* ========================================================================
 * PacketInfo
 * ======================================================================== */

struct PacketInfo {
    py::bytes data;          /* copy of the captured bytes                   */
    uint32_t  captured_len;  /* bytes in data                                */
    uint32_t  original_len;  /* bytes on the wire (may be > captured_len)    */
    uint64_t  timestamp_ns;  /* nanoseconds since UNIX epoch                 */
    int       direction;     /* 0=unknown  1=inbound  2=outbound             */
};

/* ========================================================================
 * CaptureStats
 * ======================================================================== */

struct CaptureStats {
    uint64_t received;   /* packets seen by the kernel ring                  */
    uint64_t dropped;    /* packets dropped (ring full)                      */
    uint64_t passed;     /* packets delivered to the callback                */
    uint64_t filtered;   /* packets discarded by the display filter          */
};

/* ========================================================================
 * Capture class
 * ======================================================================== */

/* Context threaded through pcapng_capture_loop as userdata. */
struct LoopCtx {
    py::object         *callback;
    pcapng_capture_t   *cap;
    std::exception_ptr  exc;
};

/* Static trampolines — called from C with GIL released. */

static void pkt_trampoline(const pcapng_packet_info_t *pkt, void *ud)
{
    LoopCtx *ctx = static_cast<LoopCtx *>(ud);

    py::gil_scoped_acquire acquire;
    try {
        PacketInfo info;
        /* Zero-copy rule: data pointer valid only during this callback.
           We must copy it into a Python bytes object right here. */
        info.data         = py::bytes(reinterpret_cast<const char *>(pkt->data),
                                      pkt->captured_len);
        info.captured_len = pkt->captured_len;
        info.original_len = pkt->original_len;
        info.timestamp_ns = pkt->timestamp_ns;
        info.direction    = pkt->direction;
        (*ctx->callback)(info);
    } catch (...) {
        /* Stash the exception, ask the loop to stop, then return to C. */
        ctx->exc = std::current_exception();
        pcapng_capture_break(ctx->cap);
    }
}

/* Per-Capture state needed for the field-provider trampoline. */
struct FieldProviderCtx {
    py::object fn;     /* callable(field: str, data: bytes) -> str | None */
};

static int field_trampoline(const char *field,
                             const uint8_t *data, uint32_t len,
                             char *val_out, size_t val_size,
                             void *ud)
{
    auto *ctx = static_cast<FieldProviderCtx *>(ud);

    py::gil_scoped_acquire acquire;
    try {
        py::object result = ctx->fn(
            std::string(field),
            py::bytes(reinterpret_cast<const char *>(data), len));
        if (result.is_none()) return 0;
        std::string s = py::cast<std::string>(result);
        snprintf(val_out, val_size, "%s", s.c_str());
        return 1;
    } catch (...) {
        return 0;
    }
}

/* ──────────────────────────────────────────────────────────────────────── */

class Capture {
public:
    explicit Capture(const std::string &device)
        : _cap(nullptr), _field_ctx(nullptr)
    {
        char errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
        _cap = pcapng_capture_open(device.c_str(), errbuf);
        if (!_cap)
            throw std::runtime_error(std::string("pcapng_capture_open: ") + errbuf);
    }

    ~Capture() { close(); }

    /* Disable copy — the handle is a unique resource. */
    Capture(const Capture &)            = delete;
    Capture &operator=(const Capture &) = delete;

    /* ── configuration ── */

    void set_snaplen(uint32_t snaplen) {
        if (pcapng_capture_set_snaplen(_cap, snaplen) < 0)
            throw std::runtime_error("set_snaplen failed");
    }
    void set_promisc(bool on) {
        if (pcapng_capture_set_promisc(_cap, on ? 1 : 0) < 0)
            throw std::runtime_error("set_promisc failed");
    }
    void set_timeout(int ms) {
        if (pcapng_capture_set_timeout(_cap, ms) < 0)
            throw std::runtime_error("set_timeout failed");
    }
    void set_buffer_size(size_t bytes) {
        if (pcapng_capture_set_buffer_size(_cap, bytes) < 0)
            throw std::runtime_error("set_buffer_size failed");
    }
    void set_filter(const std::string &expr) {
        char errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
        if (pcapng_capture_set_filter(_cap, expr.c_str(), errbuf) < 0)
            throw std::runtime_error(std::string("filter error: ") + errbuf);
    }

    /*
     * set_field_provider(fn) — register a Python callable for POSA / custom
     * field lookup.
     *
     *   fn(field: str, data: bytes) -> str | None
     *
     * Return the field value as a string, or None if the field is absent in
     * this packet.  Set fn=None to unregister.
     */
    void set_field_provider(py::object fn) {
        if (fn.is_none()) {
            pcapng_capture_set_field_provider(_cap, nullptr, nullptr);
            _field_ctx.reset();
        } else {
            _field_ctx = std::make_unique<FieldProviderCtx>();
            _field_ctx->fn = fn;
            pcapng_capture_set_field_provider(_cap, field_trampoline,
                                              _field_ctx.get());
        }
    }

    /* ── capture ── */

    /*
     * loop(count, callback) — blocking capture loop.
     *
     * count <= 0 runs indefinitely (until Ctrl-C or break_loop()).
     * callback(pkt: PacketInfo) is called for each matching packet.
     *
     * The GIL is released while waiting for packets so other Python
     * threads remain responsive.  Exceptions raised in the callback are
     * propagated back to the caller of loop().
     *
     * Returns the number of packets delivered to the callback.
     */
    int loop(int count, py::object callback) {
        ensure_open();
        LoopCtx ctx = { &callback, _cap, nullptr };
        int n;
        {
            py::gil_scoped_release release;
            n = pcapng_capture_loop(_cap, count, pkt_trampoline, &ctx);
        }
        if (ctx.exc) std::rethrow_exception(ctx.exc);
        if (n < 0) throw std::runtime_error("capture_loop failed");
        return n;
    }

    /*
     * dispatch(count, callback) — process one batch of available packets
     * and return immediately.  Useful for embedding in an event loop.
     *
     * Returns packets processed this call (0 if none ready).
     */
    int dispatch(int count, py::object callback) {
        ensure_open();
        LoopCtx ctx = { &callback, _cap, nullptr };
        int n;
        {
            py::gil_scoped_release release;
            n = pcapng_capture_dispatch(_cap, count, pkt_trampoline, &ctx);
        }
        if (ctx.exc) std::rethrow_exception(ctx.exc);
        if (n < 0) throw std::runtime_error("capture_dispatch failed");
        return n;
    }

    /* Request the loop to stop.  Safe to call from another thread. */
    void break_loop() {
        if (_cap) pcapng_capture_break(_cap);
    }

    /* Return kernel + library packet counters. */
    CaptureStats get_stats() {
        ensure_open();
        pcapng_capture_stats_t s;
        if (pcapng_capture_get_stats(_cap, &s) < 0)
            throw std::runtime_error("get_stats failed");
        CaptureStats out;
        out.received = s.received;
        out.dropped  = s.dropped;
        out.passed   = s.passed;
        out.filtered = s.filtered;
        return out;
    }

    /* Release the underlying socket and mmap ring. */
    void close() {
        if (_cap) {
            pcapng_capture_close(_cap);
            _cap = nullptr;
        }
        _field_ctx.reset();
    }

    /* Context-manager support: with Capture("eth0") as cap: */
    Capture &enter() { return *this; }
    void exit(py::object, py::object, py::object) { close(); }

private:
    void ensure_open() const {
        if (!_cap) throw std::runtime_error("capture handle is closed");
    }

    pcapng_capture_t                   *_cap;
    std::unique_ptr<FieldProviderCtx>   _field_ctx;
};

/* ========================================================================
 * Module-level convenience functions
 * ======================================================================== */

static py::list list_devices_py()
{
    char errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
    int count = 0;
    pcapng_device_t *devs = pcapng_capture_list_devices(&count, errbuf);
    if (!devs && count == 0)
        throw std::runtime_error(std::string("list_devices: ") + errbuf);

    py::list result;
    for (int i = 0; i < count; i++) {
        py::dict d;
        d["name"]      = std::string(devs[i].name);
        d["loopback"]  = devs[i].loopback != 0;
        result.append(d);
    }
    free(devs);
    return result;
}

static py::object default_device_py()
{
    char errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
    const char *dev = pcapng_capture_default_device(errbuf);
    if (!dev) return py::none();
    return py::str(dev);
}

static int capture_to_file_py(const std::string &device,
                               const std::string &path,
                               py::object filter_obj,
                               int count)
{
    char errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
    std::string filter_str;
    const char *filter = nullptr;
    if (!filter_obj.is_none()) {
        filter_str = py::cast<std::string>(filter_obj);
        filter = filter_str.c_str();
    }

    /* capture_to_file blocks — release GIL */
    int n;
    {
        py::gil_scoped_release release;
        n = pcapng_capture_to_file(device.c_str(), path.c_str(),
                                   filter, count, errbuf);
    }
    if (n < 0) throw std::runtime_error(std::string(errbuf));
    return n;
}

static int capture_print_py(const std::string &device,
                             py::object filter_obj,
                             int count)
{
    char errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
    std::string filter_str;
    const char *filter = nullptr;
    if (!filter_obj.is_none()) {
        filter_str = py::cast<std::string>(filter_obj);
        filter = filter_str.c_str();
    }

    int n;
    {
        py::gil_scoped_release release;
        n = pcapng_capture_print(device.c_str(), filter, count, errbuf);
    }
    if (n < 0) throw std::runtime_error(std::string(errbuf));
    return n;
}

/* ========================================================================
 * Registration — called from PYBIND11_MODULE in pycapng.cpp
 * ======================================================================== */

void register_capture(py::module_ &m)
{
    /* ── PacketInfo ── */
    py::class_<PacketInfo>(m, "PacketInfo",
        "Packet descriptor passed to the capture callback.\n\n"
        "The ``data`` attribute is a ``bytes`` copy of the captured frame.\n"
        "``captured_len`` may be less than ``original_len`` if snaplen truncated it.")
      .def_readonly("data",         &PacketInfo::data)
      .def_readonly("captured_len", &PacketInfo::captured_len,
                    "Bytes present in ``data``.")
      .def_readonly("original_len", &PacketInfo::original_len,
                    "Original wire length (may exceed captured_len).")
      .def_readonly("timestamp_ns", &PacketInfo::timestamp_ns,
                    "Capture timestamp in nanoseconds since the UNIX epoch.")
      .def_readonly("direction",    &PacketInfo::direction,
                    "0=unknown  1=inbound  2=outbound")
      .def("__repr__", [](const PacketInfo &p) {
          return "<PacketInfo captured=" + std::to_string(p.captured_len)
               + " original=" + std::to_string(p.original_len)
               + " ts_ns="  + std::to_string(p.timestamp_ns) + ">";
      });

    /* ── CaptureStats ── */
    py::class_<CaptureStats>(m, "CaptureStats",
        "Packet counters returned by ``Capture.get_stats()``.")
      .def_readonly("received", &CaptureStats::received,
                    "Packets seen by the kernel ring.")
      .def_readonly("dropped",  &CaptureStats::dropped,
                    "Packets dropped by the kernel (ring-buffer full).")
      .def_readonly("passed",   &CaptureStats::passed,
                    "Packets delivered to the user callback.")
      .def_readonly("filtered", &CaptureStats::filtered,
                    "Packets discarded by the display filter.")
      .def("__repr__", [](const CaptureStats &s) {
          return "<CaptureStats received=" + std::to_string(s.received)
               + " dropped=" + std::to_string(s.dropped)
               + " passed=" + std::to_string(s.passed)
               + " filtered=" + std::to_string(s.filtered) + ">";
      });

    /* ── Capture ── */
    py::class_<Capture>(m, "Capture",
        "Live packet capture handle.\n\n"
        "Wraps the libpcapng live-capture API with zero-copy capture\n"
        "(Linux PACKET_MMAP / TPACKET_V3, macOS BPF) and a Wireshark-style\n"
        "display filter operating on decoded packet fields.\n\n"
        "Requires root or CAP_NET_RAW (Linux) / network entitlement (macOS).\n\n"
        "Usage::\n\n"
        "    cap = pycapng.Capture(\"eth0\")\n"
        "    cap.set_filter(\"tcp.dstport == 443\")\n"
        "    cap.loop(0, lambda pkt: print(pkt.captured_len))\n"
        "    cap.close()\n\n"
        "Or as a context manager::\n\n"
        "    with pycapng.Capture(\"eth0\") as cap:\n"
        "        cap.set_filter(\"ip and not icmp\")\n"
        "        cap.loop(100, my_callback)\n")
      .def(py::init<const std::string &>(), py::arg("device"),
           "Open a capture handle for *device* (e.g. ``\"eth0\"`` or ``\"en0\"``).\n\n"
           "Configure with the ``set_*`` methods before calling ``loop()``.")
      /* configuration */
      .def("set_snaplen", &Capture::set_snaplen, py::arg("snaplen"),
           "Set the maximum bytes captured per packet (default: 65535).")
      .def("set_promisc", &Capture::set_promisc, py::arg("on"),
           "Enable or disable promiscuous mode (default: True).")
      .def("set_timeout", &Capture::set_timeout, py::arg("ms"),
           "Set the packet-delivery timeout in milliseconds (default: 100).")
      .def("set_buffer_size", &Capture::set_buffer_size, py::arg("bytes"),
           "Set the kernel ring-buffer / BPF read-buffer size (default: 16 MB).")
      .def("set_filter", &Capture::set_filter, py::arg("expr"),
           "Compile and attach a Wireshark-style display filter.\n\n"
           "Examples::\n\n"
           "    cap.set_filter(\"tcp.dstport == 443\")\n"
           "    cap.set_filter(\"ip.src == 192.168.0.0/16 and not icmp\")\n"
           "    cap.set_filter(\"tcp.port == 80 or udp.port == 53\")\n"
           "    cap.set_filter(\"eth.addr == aa:bb:cc:dd:ee:ff\")\n\n"
           "Built-in fields: ``eth.{src,dst,type}``, ``ip.{src,dst,proto,ttl,len}``,\n"
           "``ip6.{src,dst}``, ``tcp.{srcport,dstport,flags,flags.{syn,ack,rst,fin}}``,\n"
           "``udp.{srcport,dstport}``, ``icmp.{type,code}``.\n\n"
           "Alias fields (OR-match): ``ip.addr``, ``tcp.port``, ``udp.port``, ``eth.addr``.\n\n"
           "Unknown fields are forwarded to the registered field provider (if any).\n\n"
           "Raises ``RuntimeError`` on parse error.")
      .def("set_field_provider", &Capture::set_field_provider, py::arg("fn"),
           "Register a callable for custom / POSA field lookup.\n\n"
           "Signature::\n\n"
           "    fn(field: str, data: bytes) -> str | None\n\n"
           "Called for any filter field not resolved by the built-in\n"
           "Ethernet/IP/TCP/UDP dissector.  Return the field value as a\n"
           "string, or ``None`` if absent in this packet.\n\n"
           "Pass ``None`` to unregister.\n\n"
           "Example::\n\n"
           "    def my_fields(field, data):\n"
           "        if field == \"myproto.version\":\n"
           "            return str(data[42]) if len(data) > 42 else None\n"
           "        return None\n\n"
           "    cap.set_field_provider(my_fields)\n"
           "    cap.set_filter(\"myproto.version == 2\")\n")
      /* capture */
      .def("loop", &Capture::loop,
           py::arg("count"), py::arg("callback"),
           "Blocking capture loop.\n\n"
           "Calls *callback(pkt: PacketInfo)* for each packet that matches\n"
           "the display filter (all packets if no filter is set).\n\n"
           "*count* <= 0 runs until Ctrl-C or :meth:`break_loop`.\n\n"
           "The Python GIL is released while waiting for packets, allowing\n"
           "other threads to run.  Exceptions raised inside *callback* are\n"
           "caught, the loop is stopped, and the exception is re-raised here.\n\n"
           "Returns the number of packets delivered to *callback*.")
      .def("dispatch", &Capture::dispatch,
           py::arg("count"), py::arg("callback"),
           "Process one batch of available packets and return.\n\n"
           "Suitable for embedding in an existing event loop.\n"
           "*count* <= 0 means process all currently available packets.\n\n"
           "Returns packets processed this call (0 if none were available).")
      .def("break_loop", &Capture::break_loop,
           "Ask the capture loop to stop after the current packet.\n\n"
           "Safe to call from another thread or a signal handler.")
      .def("get_stats", &Capture::get_stats,
           "Return a :class:`CaptureStats` with kernel and library counters.")
      .def("close", &Capture::close,
           "Release the capture socket and ring buffer.\n\n"
           "Called automatically by the context manager ``__exit__``.")
      /* context manager */
      .def("__enter__", &Capture::enter,
           py::return_value_policy::reference)
      .def("__exit__", &Capture::exit);

    /* ── Constants ── */
    m.attr("CAP_DIR_UNKNOWN")  = py::int_(PCAPNG_CAP_DIR_UNKNOWN);
    m.attr("CAP_DIR_INBOUND")  = py::int_(PCAPNG_CAP_DIR_INBOUND);
    m.attr("CAP_DIR_OUTBOUND") = py::int_(PCAPNG_CAP_DIR_OUTBOUND);

    /* ── Module-level functions ── */
    m.def("capture_list_devices", &list_devices_py,
        "Enumerate available network interfaces.\n\n"
        "Returns a list of dicts with keys ``'name'`` (str) and\n"
        "``'loopback'`` (bool).\n\n"
        "Example::\n\n"
        "    for dev in pycapng.capture_list_devices():\n"
        "        print(dev['name'], '(lo)' if dev['loopback'] else '')");

    m.def("capture_default_device", &default_device_py,
        "Return the name of the first non-loopback interface, or ``None``.");

    m.def("capture_to_file",
          &capture_to_file_py,
          py::arg("device"), py::arg("path"),
          py::arg("filter") = py::none(),
          py::arg("count")  = 0,
          "Capture packets from *device* and write them to a pcapng file.\n\n"
          "*filter* is an optional Wireshark-style display-filter string.\n"
          "*count* == 0 captures until Ctrl-C.\n\n"
          "Blocks with the GIL released.\n\n"
          "Returns the number of packets written, raises on error.\n\n"
          "Example::\n\n"
          "    pycapng.capture_to_file(\"eth0\", \"out.pcapng\",\n"
          "                            filter=\"tcp.dstport == 443\", count=500)");

    m.def("capture_print",
          &capture_print_py,
          py::arg("device"),
          py::arg("filter") = py::none(),
          py::arg("count")  = 0,
          "Capture packets from *device* and print one-line summaries to stdout.\n\n"
          "*count* == 0 runs until Ctrl-C.\n\n"
          "Example::\n\n"
          "    pycapng.capture_print(\"en0\", filter=\"not arp\", count=100)");
}
