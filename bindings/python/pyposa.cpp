/* pyposa.cpp — expose the posa declarative decoder engine to Python.
 *
 * posa (.posa files) is libpcapng's declarative decoder language.  The C engine
 * (lib/posa.c) can already load decoders and dissect a raw buffer into a
 * pcapng_field_t tree — the same tree the built-in dissectors produce — but that
 * capability was not reachable from Python.  These bindings surface it, so a
 * Python program can:
 *
 *     import pycapng
 *     pycapng.posa_load_dir("protos")
 *     tree = pycapng.posa_dissect("PNG", open("a.png","rb").read())
 *     # tree = {"info": "...", "consumed": N, "root": <node>}
 *     # node = {"label","abbrev","type","offset","length","value","children":[...]}
 *
 * This is what lets a hex editor drive posa decoders over arbitrary byte
 * buffers (file formats and network payloads alike), colour the hex pane from
 * each field's absolute [offset, offset+length) range, and show the parsed
 * structure in a tree — with new formats added as .posa files, no code change.
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>

extern "C" {
#include <libpcapng/posa.h>
#include <libpcapng/dissect.h>
#include <libpcapng/flow_hash.h>
}

namespace py = pybind11;

// Map a pcapng field type to a short, stable string the Python side can switch on.
static const char *ftype_name(pcapng_ftype_t t) {
  switch (t) {
    case PCAPNG_FT_NONE: return "none";
    case PCAPNG_FT_UINT: return "uint";
    case PCAPNG_FT_STR:  return "str";
    case PCAPNG_FT_IPV4: return "ipv4";
    case PCAPNG_FT_IPV6: return "ipv6";
    case PCAPNG_FT_MAC:  return "mac";
    case PCAPNG_FT_BYTES: return "bytes";
    default: return "?";
  }
}

// Build the Python value for a node from its libcaca-agnostic field record.
static py::object field_value(const pcapng_field_t *f) {
  switch (f->vtype) {
    case PCAPNG_FT_UINT:
      return py::int_((unsigned long long)f->u);
    case PCAPNG_FT_STR:
    case PCAPNG_FT_IPV4:
    case PCAPNG_FT_IPV6:
    case PCAPNG_FT_MAC:
      return py::str(f->str);
    case PCAPNG_FT_BYTES:
      return py::bytes(reinterpret_cast<const char *>(f->bytes),
                       (size_t)(f->blen > 0 ? f->blen : 0));
    case PCAPNG_FT_NONE:
    default:
      return py::none();
  }
}

// Recursively convert a pcapng_field_t subtree to a nested Python dict.
static py::dict field_to_dict(const pcapng_field_t *f) {
  py::dict d;
  d["label"] = py::str(f->label);
  d["abbrev"] = py::str(f->abbrev);
  d["type"] = py::str(ftype_name(f->vtype));
  d["offset"] = py::int_(f->off);
  d["length"] = py::int_(f->len);
  d["value"] = field_value(f);
  py::list kids;
  for (const pcapng_field_t *c = f->children; c; c = c->next)
    kids.append(field_to_dict(c));
  d["children"] = kids;
  return d;
}

void register_posa(py::module_ &m) {
  m.def("posa_load_dir",
        [](const std::string &dir) { return pcapng_posa_load_dir(dir.c_str()); },
        py::arg("directory"),
        "Load every *.posa decoder in a directory. Returns the number loaded.");

  m.def("posa_load_file",
        [](const std::string &path) {
          char err[256] = {0};
          int n = pcapng_posa_load_file(path.c_str(), err, sizeof err);
          if (n < 0) throw std::runtime_error(err[0] ? err : "posa load failed");
          return n;
        },
        py::arg("path"),
        "Load one .posa file. Returns the number of protocols parsed; raises on error.");

  m.def("posa_load_text",
        [](const std::string &src) {
          char err[256] = {0};
          int n = pcapng_posa_load_text(src.c_str(), err, sizeof err);
          if (n < 0) throw std::runtime_error(err[0] ? err : "posa parse failed");
          return n;
        },
        py::arg("source"),
        "Parse .posa decoder text from memory. Returns protocols parsed; raises on error.");

  m.def("posa_clear", &pcapng_posa_clear, "Drop all loaded posa decoders.");

  m.def("posa_set_conversation",
        [](py::object id) {
          if (id.is_none()) pcapng_posa_set_conversation(nullptr);
          else pcapng_posa_set_conversation(id.cast<std::string>().c_str());
        },
        py::arg("community_id"),
        "Set the flow that `bind`/`recall` remember values under. Pass the\n"
        "flow's Community ID, or None for a buffer with no conversation.");

  m.def("posa_weak_rules_enable",
        [](bool on) { pcapng_posa_weak_rules_enable(on ? 1 : 0); },
        py::arg("on"),
        "Enable or disable `weak rule` signatures. Weak rules are consulted\n"
        "only after strong signatures and port bindings; turning them off\n"
        "leaves only signatures strong enough to stand alone.");

  m.def("posa_weak_rules_enabled",
        []() { return pcapng_posa_weak_rules_enabled() != 0; },
        "Whether `weak rule` signatures are currently consulted.");

  m.def("posa_binds_clear", &pcapng_posa_binds_clear,
        "Forget every value remembered by `bind`.");

  m.def("posa_bind_count", &pcapng_posa_bind_count,
        "How many values `bind` is currently remembering.");

  m.def("posa_warnings",
        []() {
          py::list out;
          for (int i = 0; i < pcapng_posa_warning_count(); i++) {
            const char *w = pcapng_posa_warning_at(i);
            if (w) out.append(py::str(w));
          }
          return out;
        },
        "Warnings raised by the last posa_dissect() — today, a `recall` that\n"
        "found nothing bound. Informational: the dissection completed anyway.");

  m.def("posa_load_builtin",
        []() {
          pcapng_dissect_ensure_protocols();
          return pcapng_posa_count();
        },
        "Load the decoders bundled into the library (every .posa embedded at\n"
        "build time), once per process. Returns the decoder count afterwards.\n"
        "Dissecting a packet does this on its own; call it directly when the\n"
        "registry has to be populated before anything is dissected — asking\n"
        "posa_bound_port() what listens on a port, for one.");

  m.def("posa_count", &pcapng_posa_count, "Number of loaded posa decoders.");

  /* ── Dispatch bindings — which decoder claims a packet ───────────────────
     These answer the `rule` lines a .posa file declares:
         rule tcp.port == 502   => ModbusTCP
         rule ip.proto == 51    => AH
         rule eth.type == 0x8847 => MPLS
         rule tcp.content "SSH-" => SSH
     Given what a captured frame carries, they name the decoder to hand it to.
     All return None when no rule matches. */

  /* ── Flow hashing — the value a dispatcher shards on ─────────────────── */

  m.def("flow_hash",
        [](py::bytes data, uint16_t linktype, int mode) {
          std::string buf = data;
          return pcapng_flow_hash(reinterpret_cast<const uint8_t *>(buf.data()),
                                  (uint32_t)buf.size(), linktype,
                                  (pcapng_flow_mode_t)mode);
        },
        py::arg("frame"), py::arg("linktype") = 1, py::arg("mode") = 0,
        "Direction-independent 64-bit hash of the flow a frame belongs to.\n"
        "Both directions of a connection hash the same, so\n"
        "    worker = flow_hash(frame) % nworkers\n"
        "sends a whole conversation to one worker — which is what keeps the\n"
        "library's per-flow state coherent when several are running at once.\n"
        "mode 0 = FLOW_TUPLE (proto + addresses + ports),\n"
        "mode 1 = FLOW_IPPAIR (addresses only, for sessions that span ports).\n"
        "Returns 0, and only 0, when the frame carries no flow.");

  m.def("flow_hash_tuple",
        [](uint8_t ip_proto, py::bytes saddr, py::bytes daddr,
           uint16_t sport, uint16_t dport, int mode) {
          std::string a = saddr, b = daddr;
          if (a.size() != b.size() || (a.size() != 4 && a.size() != 16))
            throw std::runtime_error("addresses must both be 4 or 16 bytes");
          return pcapng_flow_hash_tuple(ip_proto,
                                        reinterpret_cast<const uint8_t *>(a.data()),
                                        reinterpret_cast<const uint8_t *>(b.data()),
                                        (int)a.size(), sport, dport,
                                        (pcapng_flow_mode_t)mode);
        },
        py::arg("ip_proto"), py::arg("saddr"), py::arg("daddr"),
        py::arg("sport") = 0, py::arg("dport") = 0, py::arg("mode") = 0,
        "The same hash from an already-parsed tuple. Addresses are\n"
        "network-order bytes, 4 for IPv4 or 16 for IPv6; ports are host order.");

  m.attr("FLOW_TUPLE")  = 0;
  m.attr("FLOW_IPPAIR") = 1;

  m.def("posa_bound_port",
        [](int ip_proto, uint16_t port) -> py::object {
          const char *n = pcapng_posa_bound_port(ip_proto, port);
          return n ? py::object(py::str(n)) : py::object(py::none());
        },
        py::arg("ip_proto"), py::arg("port"),
        "Decoder bound to a transport port: ip_proto is 6 (TCP) or 17 (UDP).");

  m.def("posa_bound_ipproto",
        [](int proto) -> py::object {
          const char *n = pcapng_posa_bound_ipproto(proto);
          return n ? py::object(py::str(n)) : py::object(py::none());
        },
        py::arg("ip_proto"),
        "Decoder bound to an IP protocol number (51 = AH, 50 = ESP, ...).");

  m.def("posa_bound_ethertype",
        [](uint16_t ethertype) -> py::object {
          const char *n = pcapng_posa_bound_ethertype(ethertype);
          return n ? py::object(py::str(n)) : py::object(py::none());
        },
        py::arg("ethertype"),
        "Decoder bound to an EtherType (0x8847 = MPLS, 0x888e = EAPOL, ...).");

  m.def("posa_bound_content",
        [](int ip_proto, py::bytes data, bool weak) -> py::object {
          std::string buf = data;
          const uint8_t *p = reinterpret_cast<const uint8_t *>(buf.data());
          const char *n = weak
              ? pcapng_posa_bound_content_weak(ip_proto, p, (int)buf.size())
              : pcapng_posa_bound_content(ip_proto, p, (int)buf.size());
          return n ? py::object(py::str(n)) : py::object(py::none());
        },
        py::arg("ip_proto"), py::arg("data"), py::arg("weak") = false,
        "Decoder whose payload signature matches these bytes, port-independent\n"
        "(`rule tcp.content \"SSH-\"`). weak=True consults the `weak rule`\n"
        "signatures too — suggestive rather than conclusive, so ask them only\n"
        "after a port binding and a strong signature have both come up empty.");

  m.def("posa_list",
        []() {
          std::vector<std::string> names;
          int n = pcapng_posa_count();
          for (int i = 0; i < n; i++) {
            const pcapng_posa_proto_t *p = pcapng_posa_at(i);
            if (p) names.emplace_back(p->name);
          }
          return names;
        },
        "Names of all loaded posa decoders.");

  m.def("posa_source",
        [](const std::string &name) -> py::object {
          const char *s = pcapng_posa_source(name.c_str());
          if (!s) return py::none();
          return py::str(s);
        },
        py::arg("name"),
        "The original .posa source text a decoder was parsed from (None if unknown).");

  m.def("posa_resolve",
        [](const std::string &name, py::bytes data) -> py::object {
          std::string buf = data;
          const pcapng_posa_proto_t *p = pcapng_posa_resolve(
              name.c_str(), reinterpret_cast<const uint8_t *>(buf.data()),
              (int)buf.size());
          if (!p) return py::none();
          return py::str(p->name);
        },
        py::arg("name"), py::arg("data"),
        "Resolve a decoder name (or Object<group> by first-field magic) against a buffer.");

  m.def("posa_dissect",
        [](const std::string &proto, py::bytes data, int abs_off) -> py::object {
          std::string buf = data;
          pcapng_field_t *root =
              (pcapng_field_t *)calloc(1, sizeof(pcapng_field_t));
          if (!root) throw std::runtime_error("out of memory");
          char info[192] = {0};
          pcapng_posa_reset_col();
          int consumed = pcapng_posa_dissect(
              proto.c_str(), reinterpret_cast<const uint8_t *>(buf.data()),
              (int)buf.size(), root, abs_off, info, sizeof info);
          const char *col = pcapng_posa_last_col();
          py::dict out;
          out["consumed"] = py::int_(consumed);
          out["info"] = py::str(info);
          out["col"] = col ? py::object(py::str(col)) : py::object(py::none());
          // The decoder attaches its fields as children of `root`; hand back the
          // children as the top-level nodes (root itself is just a holder).
          py::list nodes;
          for (const pcapng_field_t *c = root->children; c; c = c->next)
            nodes.append(field_to_dict(c));
          out["fields"] = nodes;
          pcapng_field_free(root);
          return (consumed <= 0 && nodes.empty()) ? py::none() : py::object(out);
        },
        py::arg("proto"), py::arg("data"), py::arg("abs_off") = 0,
        "Dissect a buffer as the named posa decoder. Returns a dict with keys "
        "'consumed', 'info', 'col', 'fields' (a nested field tree), or None if "
        "nothing decoded.");

  m.def("posa_colors",
        []() {
          std::vector<std::tuple<std::string, std::string, std::string>> out;
          int n = pcapng_posa_color_count();
          for (int i = 0; i < n; i++) {
            const char *expr = nullptr, *fg = nullptr, *bg = nullptr;
            if (pcapng_posa_color_get(i, &expr, &fg, &bg))
              out.emplace_back(expr ? expr : "", fg ? fg : "", bg ? bg : "");
          }
          return out;
        },
        "Coloring rules declared by loaded decoders: list of (expr, fg, bg).");
}
