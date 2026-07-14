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

  m.def("posa_count", &pcapng_posa_count, "Number of loaded posa decoders.");

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
