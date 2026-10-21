/* pydissect.cpp — the dissector and the display-filter engine, for Python.
 *
 *     import pycapng
 *     pycapng.ensure_protocols()
 *
 *     want = pycapng.Filter('http.uri contains "/admin"')
 *
 *     def each(pkt):
 *         d = pycapng.dissect(pkt.data, pkt.linktype)
 *         if d and want.matches(d):
 *             print(d.proto, d.src, "->", d.dst, d.info)
 *         return True
 *
 *     pycapng.foreach_packet("capture.pcapng", each)
 *
 * `Dissection` keeps the C field tree alive behind the object, so a filter is
 * matched against a tree that has already been built. That ordering is the
 * point: dissecting is the expensive part (microseconds), matching is a tree
 * walk (nanoseconds), and a program with thirty filters should dissect once,
 * not thirty times.
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <string>
#include <memory>

extern "C" {
#include <libpcapng/dissect.h>
#include <libpcapng/dfilter.h>
#include <libpcapng/linktypes.h>
}

namespace py = pybind11;

/* Defined in pyposa.cpp — one field node as a dict, children included. */
py::dict pcapng_field_to_dict(const pcapng_field_t *f);

/* ── Dissection ───────────────────────────────────────────────────────────── */

/* Owns the C dissection for as long as Python holds the object. Non-copyable:
 * two owners would free the same tree twice. */
class PyDissection {
public:
  explicit PyDissection(pcapng_dissection_t *d) : _d(d) {}
  ~PyDissection() { if (_d) pcapng_dissection_free(_d); }
  PyDissection(const PyDissection &) = delete;
  PyDissection &operator=(const PyDissection &) = delete;

  const char *proto() const { return _d ? _d->proto : ""; }
  const char *src()   const { return _d ? _d->src   : ""; }
  const char *dst()   const { return _d ? _d->dst   : ""; }
  const char *info()  const { return _d ? _d->info  : ""; }

  /* The protocol layers, each with its own children. Built on demand: most
   * callers want the summary columns and never look at the tree, and walking
   * it eagerly would cost more than the dissection did.
   *
   * `root` is an unnamed holder whose children are the layers, so it is
   * stepped over — a caller wants [frame, eth, ip, tcp, http], not one
   * anonymous node wrapping them. */
  py::list fields() const {
    py::list out;
    if (!_d || !_d->root) return out;
    const pcapng_field_t *first =
        (_d->root->abbrev[0] == '\0' && _d->root->children) ? _d->root->children
                                                            : _d->root;
    for (const pcapng_field_t *c = first; c; c = c->next)
      out.append(pcapng_field_to_dict(c));
    return out;
  }

  /* Every field in the tree, flattened to {abbrev: value}. What you want when
   * you are looking for one value and do not care where it sits. */
  py::dict flat() const {
    py::dict out;
    if (_d && _d->root) flatten(_d->root, out);
    return out;
  }

  pcapng_field_t *root() const { return _d ? _d->root : nullptr; }

  std::string repr() const {
    return std::string("<Dissection ") + proto() + " " + src() + " -> " + dst() +
           "  " + info() + ">";
  }

private:
  static void flatten(const pcapng_field_t *f, py::dict &out) {
    for (; f; f = f->next) {
      if (f->abbrev[0] && !out.contains(f->abbrev)) {
        /* A field carries either text or a number; report whichever it has,
         * so `d.flat()["tcp.dstport"]` is an int and `["http.uri"]` a str. */
        if (f->str[0])
          out[py::str(f->abbrev)] = py::str(f->str);
        else if (f->vtype == PCAPNG_FT_UINT)
          out[py::str(f->abbrev)] = py::int_(f->u);
        else
          out[py::str(f->abbrev)] = py::str("");
      }
      if (f->children) flatten(f->children, out);
    }
  }

  pcapng_dissection_t *_d;
};

/* ── Filter ───────────────────────────────────────────────────────────────── */

class PyFilter {
public:
  explicit PyFilter(const std::string &expr) : _expr(expr) {
    char err[256] = {0};
    _f = pcapng_dfilter_compile(expr.c_str(), err, sizeof err);
    if (!_f) {
      /* Compiling at construction, and raising here, is deliberate: a typo in
       * a filter should fail where it is written, not silently match nothing
       * on every packet for the rest of the run. */
      throw py::value_error(std::string("cannot compile display filter: ") +
                            (err[0] ? err : expr));
    }
  }
  ~PyFilter() { if (_f) pcapng_dfilter_free(_f); }
  PyFilter(const PyFilter &) = delete;
  PyFilter &operator=(const PyFilter &) = delete;

  bool matches(const PyDissection &d) const {
    return _f && d.root() && pcapng_dfilter_match(_f, d.root()) != 0;
  }

  /* True when compiled from an empty expression, which matches everything. */
  bool is_match_all() const { return _f && pcapng_dfilter_is_match_all(_f) != 0; }

  const std::string &expr() const { return _expr; }
  std::string repr() const { return "<Filter " + _expr + ">"; }

private:
  pcapng_dfilter_t *_f = nullptr;
  std::string _expr;
};

/* ── registration ─────────────────────────────────────────────────────────── */

void register_dissect(py::module_ &m) {
  m.def("ensure_protocols", []() { pcapng_dissect_ensure_protocols(); },
        R"doc(Load the bundled protocol decoders.

Most of libpcapng's protocol support is POSA definitions compiled into the
library, held in a registry that is populated on demand. Call this once before
dissecting or before compiling a filter that names a field: until you do,
`dissect()` reports only the layers the C dissectors handle, and a filter on
`http.uri` matches nothing because the field does not exist yet.

Idempotent, and cheap to call again.)doc");

  py::class_<PyDissection>(m, "Dissection",
      "A dissected packet: the Wireshark summary columns and the field tree.")
      .def_property_readonly("proto", &PyDissection::proto,
                             "Deepest recognised protocol, e.g. 'HTTP'.")
      .def_property_readonly("src", &PyDissection::src, "Source address.")
      .def_property_readonly("dst", &PyDissection::dst, "Destination address.")
      .def_property_readonly("info", &PyDissection::info,
                             "One-line summary — Wireshark's Info column.")
      .def_property_readonly("fields", &PyDissection::fields,
                             "The protocol layers as nested dicts.")
      .def("flat", &PyDissection::flat,
           "Every field flattened to {abbrev: value}.")
      .def("matches", [](const PyDissection &d, const PyFilter &f) { return f.matches(d); },
           py::arg("filter"), "Does this packet match the filter?")
      .def("__repr__", &PyDissection::repr);

  m.def("dissect",
        [](py::bytes data, uint16_t linktype) -> py::object {
          std::string buf = data;
          pcapng_dissection_t *d = pcapng_dissect(
              reinterpret_cast<const uint8_t *>(buf.data()),
              (uint32_t)buf.size(), (uint32_t)buf.size(), linktype);
          if (!d) return py::none();
          return py::cast(new PyDissection(d), py::return_value_policy::take_ownership);
        },
        py::arg("data"), py::arg("linktype") = (uint16_t)LINKTYPE_ETHERNET,
        R"doc(Dissect a frame into protocol layers and summary columns.

`linktype` defaults to Ethernet; a packet from `foreach_packet` carries its
own in `pkt.linktype`. Returns None only if the library could not allocate.

Call `ensure_protocols()` first, or only the built-in C dissectors apply.)doc");

  py::class_<PyFilter>(m, "Filter",
      "A compiled Wireshark-style display filter.")
      .def(py::init<const std::string &>(), py::arg("expr"),
           R"doc(Compile a display filter, raising ValueError if it will not compile.

    f = pycapng.Filter('http.uri contains "/cgi-bin/" and ip.src == 10.0.0.0/8')

Compile once and match many times: dissecting a packet costs microseconds and
matching a compiled filter against the result costs nanoseconds.

An empty expression matches everything, which `is_match_all()` reports.)doc")
      .def("matches", &PyFilter::matches, py::arg("dissection"),
           "Does this dissected packet match?")
      .def("is_match_all", &PyFilter::is_match_all,
           "True when compiled from an empty expression.")
      .def_property_readonly("expr", &PyFilter::expr, "The expression as written.")
      .def("__repr__", &PyFilter::repr);
}
