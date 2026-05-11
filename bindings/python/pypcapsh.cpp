/* pypcapsh.cpp — pcapsh submodule registered inside pycapng.
 *
 * from pycapng import pcapsh
 * sh = pcapsh.PcapSH()
 * packets = sh.run_script("foo.pcapsh")
 * packets = sh.run_script("foo.pcapsh", on_packet=lambda p: print(len(p)))
 * packets = sh.run_string('wrpcap("x", Ether()/IP()/TCP()/"hello")')
 */

#include <pybind11/pybind11.h>
#include <pybind11/functional.h>
#include <pybind11/stl.h>
#include <functional>
#include <string>
#include <vector>

extern "C" {
#include "pcapsh.h"
#include <libpcapng/protocols/ssl.h>
}

namespace py = pybind11;

/* Per-run context threaded through g_packet_cb_userdata. */
struct RunCtx {
    std::vector<std::string>        pkts;
    std::function<void(py::bytes)>  on_packet;  /* may be empty */
};

static void dispatch_packet(const uint8_t *buf, size_t len, void *ud) {
    auto *ctx = static_cast<RunCtx *>(ud);
    ctx->pkts.emplace_back(reinterpret_cast<const char *>(buf), len);
    if (ctx->on_packet)
        ctx->on_packet(py::bytes(reinterpret_cast<const char *>(buf), len));
}

static std::vector<py::bytes> drain(RunCtx &ctx) {
    std::vector<py::bytes> result;
    result.reserve(ctx.pkts.size());
    for (auto &p : ctx.pkts)
        result.emplace_back(p.data(), p.size());
    return result;
}

static void setup(RunCtx &ctx, py::object on_packet) {
    if (!on_packet.is_none())
        ctx.on_packet = [cb = on_packet](py::bytes pkt) { cb(pkt); };
    g_packet_cb          = dispatch_packet;
    g_packet_cb_userdata = &ctx;
}

static void teardown() {
    g_packet_cb          = nullptr;
    g_packet_cb_userdata = nullptr;
}

class PcapSH {
public:
    PcapSH() { pcapsh_init(); }

    /* Load all .posa protocol files from a directory. Returns count loaded. */
    int load_protos(const std::string &dir) {
        return ::load_protos_dir(dir.c_str());
    }

    /* Load a single .posa file. Returns count of protocols parsed. */
    int load_posa(const std::string &path) {
        return ::parse_posa_file(path.c_str());
    }

    /* Run a .pcapsh script file.
     * on_packet(frame: bytes) is called for each packet as it is produced.
     * Returns list[bytes] of all frames (same order). */
    std::vector<py::bytes> run_script(const std::string &path,
                                      py::object on_packet = py::none()) {
        pcapsh_reset();
        RunCtx ctx;
        setup(ctx, on_packet);
        ::run_script(path.c_str());
        teardown();
        return drain(ctx);
    }

    /* Evaluate a multi-line pcapsh string.
     * on_packet(frame: bytes) is called for each packet as it is produced.
     * Returns list[bytes] of all frames. */
    std::vector<py::bytes> run_string(const std::string &code,
                                      py::object on_packet = py::none()) {
        pcapsh_reset();
        RunCtx ctx;
        setup(ctx, on_packet);
        ::run_script_from_buffer(code.c_str(), code.size());
        teardown();
        return drain(ctx);
    }
};

/* ── TLS record builders ─────────────────────────────────────────────────────*/

static py::bytes _build_tls(size_t max,
    std::function<size_t(uint8_t *, size_t)> fn) {
    std::vector<uint8_t> buf(max);
    size_t n = fn(buf.data(), max);
    return py::bytes(reinterpret_cast<char *>(buf.data()), n);
}

void register_pcapsh_submodule(py::module_ &parent) {
    auto m = parent.def_submodule("pcapsh",
        "pcapsh — execute .pcapsh scripts and receive raw Ethernet frames.\n\n"
        "Protocol definitions (.posa files) are loaded from, in order:\n"
        "  1. PCAPSH_PROTOS_DIR environment variable (if set)\n"
        "  2. The installed share/pcapsh/protos/ directory\n"
        "  3. The build-tree bin/protos/ directory (in-tree builds)\n"
        "  4. ~/.pcapsh_protos.posa (user overrides)\n"
        "\n"
        "Additional directories can be loaded at runtime via PcapSH.load_protos().");

    py::class_<PcapSH>(m, "PcapSH",
        "Script engine instance. Protocol definitions are loaded once at construction.\n\n"
        "Each call to run_script() / run_string() resets per-run state (variables,\n"
        "TCP sessions) but keeps protocol definitions intact.")
        .def(py::init<>())
        .def("load_protos", &PcapSH::load_protos, py::arg("dir"),
             "Load all .posa protocol files from *dir*. Returns the number loaded.")
        .def("load_posa", &PcapSH::load_posa, py::arg("path"),
             "Load a single .posa file. Returns the number of protocols parsed.")
        .def("run_script", &PcapSH::run_script,
             py::arg("path"), py::arg("on_packet") = py::none(),
             "Run a .pcapsh script file.\n\n"
             ":param path: Path to the .pcapsh script.\n"
             ":param on_packet: Optional callable ``on_packet(frame: bytes)`` invoked\n"
             "    for each packet as it is produced by ``wrpcap()``.\n"
             ":returns: ``list[bytes]`` — one raw Ethernet frame per ``wrpcap()`` call.")
        .def("run_string", &PcapSH::run_string,
             py::arg("code"), py::arg("on_packet") = py::none(),
             "Evaluate a multi-line pcapsh string.\n\n"
             ":param code: pcapsh source (may contain newlines, backslash continuation,\n"
             "    ``for`` loops, and ``protocol`` blocks).\n"
             ":param on_packet: Optional callable ``on_packet(frame: bytes)`` invoked\n"
             "    for each packet as it is produced by ``wrpcap()``.\n"
             ":returns: ``list[bytes]`` — one raw Ethernet frame per ``wrpcap()`` call.");

    /* ── TLS record builders ─────────────────────────────────────────────── */
    m.def("tls_client_hello",
        [](const std::string &sni) {
            return _build_tls(512, [&](uint8_t *b, size_t max) {
                return sni.empty() ? tls_build_client_hello(b, max)
                                   : tls_build_client_hello_sni(b, max, sni.c_str());
            });
        }, py::arg("sni") = "",
        "Build a TLS 1.2 ClientHello record.\n\n"
        ":param sni: Optional server name (SNI extension).");

    m.def("tls_server_hello",
        []() { return _build_tls(256, tls_build_server_hello); },
        "Build a TLS 1.2 ServerHello record.");

    m.def("tls_certificate",
        [](py::bytes cert_der) {
            auto s = static_cast<std::string>(cert_der);
            return _build_tls(8192, [&](uint8_t *b, size_t max) {
                return tls_build_certificate(b, max,
                    reinterpret_cast<const uint8_t *>(s.data()), s.size());
            });
        }, py::arg("cert_der"),
        "Wrap a DER-encoded certificate in a TLS Certificate record.");

    m.def("tls_certificate_cn",
        [](const std::string &cn) {
            return _build_tls(4096, [&](uint8_t *b, size_t max) {
                return tls_build_certificate_with_cn(b, max, cn.c_str());
            });
        }, py::arg("cn") = "example.com",
        "Build a TLS Certificate record with a generated self-signed cert.\n\n"
        ":param cn: Common Name for the certificate (default ``example.com``).");

    m.def("tls_change_cipher_spec",
        []() { return _build_tls(16, tls_build_change_cipher_spec); },
        "Build a TLS ChangeCipherSpec record.");

    m.def("tls_finished",
        []() { return _build_tls(64, tls_build_finished); },
        "Build a TLS Finished record.");

    m.def("tls_application_data",
        [](py::bytes data) {
            auto s = static_cast<std::string>(data);
            return _build_tls(s.size() + 64, [&](uint8_t *b, size_t max) {
                return tls_build_application_data(b, max,
                    reinterpret_cast<const uint8_t *>(s.data()), s.size());
            });
        }, py::arg("data"),
        "Wrap raw bytes in a TLS ApplicationData record.");
}
