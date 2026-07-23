/*
 * JavaScript / WebAssembly bindings for libpcapng (Emscripten + embind).
 *
 * License MIT
 * Copyright (c) 2026 Sebastien Tricaud
 *
 * These bindings expose the read-only capture-analysis half of libpcapng to
 * the browser: parse a .pcap / .pcapng buffer entirely in memory, list the
 * packets (Wireshark-style summary columns), dissect any packet into a field
 * tree with byte offsets, and manage declarative (posa) dissectors at runtime.
 *
 * Live capture (lib/capture.c) is intentionally NOT part of this build: it
 * needs OS-level BPF / packet sockets that do not exist in a browser.
 */

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include <libpcapng/blocks.h>
#include <libpcapng/dissect.h>
#include <libpcapng/io.h>
#include <libpcapng/posa.h>
}

using emscripten::val;

namespace {

/* One captured packet plus its cached summary columns. */
struct Packet {
  uint32_t interface_id = 0;
  uint32_t ts_high = 0;
  uint32_t ts_low = 0;
  uint32_t caplen = 0;
  uint32_t origlen = 0;
  uint16_t linktype = PCAPNG_LINKTYPE_ETHERNET;
  std::vector<uint8_t> bytes;              /* captured bytes (caplen)          */
  std::string proto, src, dst, info;       /* summary columns (dissected once) */
};

struct Session {
  std::vector<Packet> pkts;
  std::vector<uint16_t> linktypes;         /* per interface, in IDB order      */
  bool is_classic = false;                 /* classic pcap vs pcapng           */
  void clear() {
    pkts.clear();
    linktypes.clear();
    is_classic = false;
  }
};

Session g_session;

/* Block callback shared by the classic-pcap and pcapng readers in lib/io.c.
   Classic pcap is normalised by io.c into synthetic IDB + EPB blocks, so a
   single handler covers both formats. */
int on_block(uint32_t counter, uint32_t block_type, uint32_t btl,
             unsigned char *data, void *user) {
  (void)counter;
  (void)user;

  if (block_type == PCAPNG_INTERFACE_DESCRIPTION_BLOCK) {
    pcapng_interface_description_block_light_t idb;
    memcpy(&idb, data, sizeof idb);
    g_session.linktypes.push_back(idb.linktype);
    return 0;
  }

  if (block_type == PCAPNG_ENHANCED_PACKET_BLOCK) {
    const pcapng_enhanced_packet_block_light_t *epb =
        reinterpret_cast<const pcapng_enhanced_packet_block_light_t *>(data);
    Packet p;
    p.interface_id = epb->interface_id;
    p.ts_high = epb->timestamp_high;
    p.ts_low = epb->timestamp_low;
    p.caplen = epb->captured_packet_length;
    p.origlen = epb->original_packet_length;
    const uint8_t *payload = data + sizeof(*epb);
    p.bytes.assign(payload, payload + epb->captured_packet_length);
    p.linktype = (p.interface_id < g_session.linktypes.size())
                     ? g_session.linktypes[p.interface_id]
                     : PCAPNG_LINKTYPE_ETHERNET;
    g_session.pkts.push_back(std::move(p));
    return 0;
  }

  if (block_type == PCAPNG_SIMPLE_PACKET_BLOCK) {
    if (btl < 16) return 0;
    uint32_t orig_len;
    memcpy(&orig_len, data, 4);
    uint32_t captured = btl - 16;
    uint32_t pkt_len = orig_len < captured ? orig_len : captured;
    Packet p;
    p.caplen = pkt_len;
    p.origlen = orig_len;
    const uint8_t *payload = data + 4;
    p.bytes.assign(payload, payload + pkt_len);
    p.linktype = !g_session.linktypes.empty() ? g_session.linktypes[0]
                                              : PCAPNG_LINKTYPE_ETHERNET;
    g_session.pkts.push_back(std::move(p));
    return 0;
  }

  return 0; /* SHB, NRB, ISB, … ignored for now */
}

std::string hex_of(const uint8_t *b, int n) {
  static const char *h = "0123456789abcdef";
  std::string s;
  s.reserve(static_cast<size_t>(n) * 2);
  for (int i = 0; i < n; i++) {
    s += h[b[i] >> 4];
    s += h[b[i] & 0xf];
  }
  return s;
}

std::string field_value(const pcapng_field_t *f) {
  char buf[64];
  switch (f->vtype) {
    case PCAPNG_FT_UINT:
      snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(f->u));
      return buf;
    case PCAPNG_FT_STR:
    case PCAPNG_FT_IPV4:
      return f->str;
    case PCAPNG_FT_MAC:
    case PCAPNG_FT_IPV6:
      return f->str[0] ? std::string(f->str) : hex_of(f->bytes, f->blen);
    case PCAPNG_FT_BYTES:
      return hex_of(f->bytes, f->blen);
    default:
      return "";
  }
}

val field_to_val(const pcapng_field_t *f) {
  val o = val::object();
  o.set("abbrev", std::string(f->abbrev));
  o.set("label", std::string(f->label));
  o.set("value", field_value(f));
  o.set("off", f->off);
  o.set("len", f->len);
  val kids = val::array();
  int i = 0;
  for (pcapng_field_t *c = f->children; c; c = c->next)
    kids.set(i++, field_to_val(c));
  o.set("children", kids);
  return o;
}

/* Classic pcap stores ts_sec in the "high" field and ts_usec/nsec in "low",
   whereas pcapng packs a single 64-bit tick count. Detecting the magic up
   front lets us interpret timestamps correctly. */
bool detect_classic(const uint8_t *b, size_t n) {
  if (n < 4) return false;
  uint32_t m;
  memcpy(&m, b, 4);
  return m == 0xa1b2c3d4u || m == 0xd4c3b2a1u || /* microsecond */
         m == 0xa1b23c4du || m == 0x4d3cb2a1u;   /* nanosecond  */
}

double packet_seconds(const Packet &p) {
  if (g_session.is_classic)
    return static_cast<double>(p.ts_high) +
           static_cast<double>(p.ts_low) / 1e6; /* sec + usec */
  uint64_t ticks = (static_cast<uint64_t>(p.ts_high) << 32) | p.ts_low;
  return static_cast<double>(ticks) / 1e6; /* default µs resolution */
}

/* ── Public API ─────────────────────────────────────────────────────────── */

/* Parse a .pcap / .pcapng buffer (Uint8Array) held entirely in memory.
   Returns the number of packets found. */
int loadCapture(val u8) {
  g_session.clear();
  std::vector<uint8_t> buf =
      emscripten::convertJSArrayToNumberVector<uint8_t>(u8);
  if (buf.empty()) return 0;

  g_session.is_classic = detect_classic(buf.data(), buf.size());
  libpcapng_mem_read(buf.data(), buf.size(), on_block, nullptr);

  /* Dissect each packet once for the summary columns. */
  for (auto &p : g_session.pkts) {
    pcapng_dissection_t *d =
        pcapng_dissect(p.bytes.data(), p.caplen, p.origlen, p.linktype);
    if (d) {
      p.proto = d->proto;
      p.src = d->src;
      p.dst = d->dst;
      p.info = d->info;
      pcapng_dissection_free(d);
    }
  }
  return static_cast<int>(g_session.pkts.size());
}

int getPacketCount() { return static_cast<int>(g_session.pkts.size()); }

/* The packet list: [{no, time, src, dst, proto, length, info}, …].
   `time` is seconds relative to the first packet. */
val getSummaries() {
  val arr = val::array();
  double t0 =
      g_session.pkts.empty() ? 0.0 : packet_seconds(g_session.pkts[0]);
  for (size_t i = 0; i < g_session.pkts.size(); i++) {
    const Packet &p = g_session.pkts[i];
    val o = val::object();
    o.set("no", static_cast<int>(i + 1));
    o.set("time", packet_seconds(p) - t0);
    o.set("src", p.src);
    o.set("dst", p.dst);
    o.set("proto", p.proto);
    o.set("length", static_cast<int>(p.origlen));
    o.set("info", p.info);
    arr.set(static_cast<int>(i), o);
  }
  return arr;
}

/* Full dissection of one packet: an array of protocol layers, each a field
   node {abbrev, label, value, off, len, children[]}. */
val getDetail(int index) {
  if (index < 0 || index >= static_cast<int>(g_session.pkts.size()))
    return val::null();
  Packet &p = g_session.pkts[index];
  pcapng_dissection_t *d =
      pcapng_dissect(p.bytes.data(), p.caplen, p.origlen, p.linktype);
  if (!d) return val::null();
  val layers = val::array();
  int i = 0;
  for (pcapng_field_t *c = d->root->children; c; c = c->next)
    layers.set(i++, field_to_val(c));
  pcapng_dissection_free(d);
  return layers;
}

/* Raw captured bytes of one packet, as a fresh Uint8Array (owned by JS). */
val getPacketBytes(int index) {
  if (index < 0 || index >= static_cast<int>(g_session.pkts.size()))
    return val::null();
  Packet &p = g_session.pkts[index];
  val u8 = val::global("Uint8Array").new_(val(static_cast<int>(p.bytes.size())));
  u8.call<void>("set", val(emscripten::typed_memory_view(p.bytes.size(),
                                                         p.bytes.data())));
  return u8;
}

/* ── Declarative (posa) dissectors ──────────────────────────────────────── */

/* Load one or more .posa protocol definitions from text into the engine.
   Returns {ok, added, error}. Redefining a protocol by name replaces it. */
val loadPosaText(std::string src) {
  char err[256] = {0};
  int n = pcapng_posa_load_text(src.c_str(), err, sizeof err);
  val r = val::object();
  r.set("ok", n >= 0);
  r.set("added", n);
  r.set("error", std::string(err));
  return r;
}

/* Names + metadata of the posa dissectors currently loaded. */
val listPosa() {
  val arr = val::array();
  int n = pcapng_posa_count();
  for (int i = 0; i < n; i++) {
    const pcapng_posa_proto_t *p = pcapng_posa_at(i);
    if (!p) continue;
    val o = val::object();
    o.set("name", std::string(p->name));
    o.set("display", std::string(p->display));
    o.set("abbrev", std::string(p->abbrev));
    arr.set(i, o);
  }
  return arr;
}

/* Every field abbrev the built-in C dissector can emit (for a filter/field
   reference in the UI). */
val listProtocols() {
  int count = 0;
  const char *const *names = pcapng_dissect_protocols(&count);
  val arr = val::array();
  for (int i = 0; i < count; i++) arr.set(i, std::string(names[i]));
  return arr;
}

}  // namespace

EMSCRIPTEN_BINDINGS(libpcapng) {
  emscripten::function("loadCapture", &loadCapture);
  emscripten::function("getPacketCount", &getPacketCount);
  emscripten::function("getSummaries", &getSummaries);
  emscripten::function("getDetail", &getDetail);
  emscripten::function("getPacketBytes", &getPacketBytes);
  emscripten::function("loadPosaText", &loadPosaText);
  emscripten::function("listPosa", &listPosa);
  emscripten::function("listProtocols", &listProtocols);
}
