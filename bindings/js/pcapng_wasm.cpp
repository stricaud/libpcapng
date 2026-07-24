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
#include <libpcapng/dfilter.h>
#include <libpcapng/dissect.h>
#include <libpcapng/io.h>
#include <libpcapng/objects.h>
#include <libpcapng/posa.h>
#include <libpcapng/reassembly_tcp.h>
}

#include <algorithm>
#include <unordered_map>

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
  std::string comment;                     /* pcapng opt_comment               */
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
    /* parse EPB options for a comment (opt_comment == 1) */
    {
      uint32_t caplen = epb->captured_packet_length;
      uint32_t pad = (4 - (caplen % 4)) % 4;
      size_t off = sizeof(*epb) + caplen + pad;
      size_t body = btl >= 12 ? (size_t)btl - 12 : 0;
      while (off + 4 <= body) {
        uint16_t code, olen;
        memcpy(&code, data + off, 2);
        memcpy(&olen, data + off + 2, 2);
        if (code == 0) break;
        if (code == PCAPNG_OPT_COMMENT && off + 4 + olen <= body)
          p.comment.assign((const char *)(data + off + 4), olen);
        off += 4 + olen + ((4 - (olen % 4)) % 4);
      }
    }
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

/* Absolute epoch seconds of the first packet (for absolute time display). */
double getStartTime() {
  return g_session.pkts.empty() ? 0.0 : packet_seconds(g_session.pkts[0]);
}

/* Values of a single field (by abbrev) for every packet — a custom column.
   Returns an array of strings aligned with the packet list ("" if absent). */
val getFieldColumn(std::string abbrev) {
  val arr = val::array();
  for (size_t i = 0; i < g_session.pkts.size(); i++) {
    Packet &p = g_session.pkts[i];
    std::string out;
    pcapng_dissection_t *d =
        pcapng_dissect(p.bytes.data(), p.caplen, p.origlen, p.linktype);
    if (d) {
      pcapng_field_t *hit[1];
      if (pcapng_field_collect(d->root, abbrev.c_str(), hit, 1) > 0)
        out = field_value(hit[0]);
      pcapng_dissection_free(d);
    }
    arr.set((int)i, out);
  }
  return arr;
}

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

/* ── Transport (L4) location, conversations & stream reassembly ──────────────
 * A small self-contained frame parser (Ethernet/VLAN → IPv4/IPv6 → TCP/UDP),
 * ported from carscal's l4.rs, used for conversation keys and Follow Stream. */

struct L4 {
  int proto = 0;                 /* 6 = TCP, 17 = UDP, 0 = not located          */
  std::string src_ip, dst_ip;
  std::vector<uint8_t> src_raw, dst_raw;
  uint16_t sport = 0, dport = 0;
  uint32_t seq = 0;
  uint32_t ack = 0;
  uint16_t window = 0;
  uint8_t flags = 0;
  size_t payoff = 0, paylen = 0;
};

std::string fmt_ipv4(const uint8_t *b) {
  char s[16];
  snprintf(s, sizeof s, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
  return s;
}
std::string fmt_ipv6(const uint8_t *b) {
  char s[48];
  snprintf(s, sizeof s, "%x:%x:%x:%x:%x:%x:%x:%x",
           (b[0] << 8) | b[1], (b[2] << 8) | b[3], (b[4] << 8) | b[5],
           (b[6] << 8) | b[7], (b[8] << 8) | b[9], (b[10] << 8) | b[11],
           (b[12] << 8) | b[13], (b[14] << 8) | b[15]);
  return s;
}

/* Returns 1 and sets *ip_off/*v6 if an IP header is located for this linktype. */
int ip_offset(const uint8_t *f, size_t n, uint16_t linktype, size_t *ip_off,
              int *v6) {
  if (linktype == PCAPNG_LINKTYPE_ETHERNET) {
    if (n < 14) return 0;
    size_t off = 12;
    uint16_t et = (f[off] << 8) | f[off + 1];
    off += 2;
    while (et == 0x8100 || et == 0x88a8) {
      if (off + 4 > n) return 0;
      et = (f[off + 2] << 8) | f[off + 3];
      off += 4;
    }
    if (et == 0x0800) { *ip_off = off; *v6 = 0; return 1; }
    if (et == 0x86dd) { *ip_off = off; *v6 = 1; return 1; }
    return 0;
  }
  if (linktype == PCAPNG_LINKTYPE_RAW || linktype == PCAPNG_LINKTYPE_IPV4 ||
      linktype == PCAPNG_LINKTYPE_IPV6) {
    if (n < 1) return 0;
    *v6 = (f[0] >> 4) == 6 || linktype == PCAPNG_LINKTYPE_IPV6;
    *ip_off = 0;
    return 1;
  }
  if (linktype == PCAPNG_LINKTYPE_NULL) {
    if (n < 4) return 0;
    *v6 = f[0] != 2;
    *ip_off = 4;
    return 1;
  }
  return 0;
}

bool locate_l4(const uint8_t *f, size_t n, uint16_t linktype, L4 *out) {
  size_t ip_off;
  int v6;
  if (!ip_offset(f, n, linktype, &ip_off, &v6)) return false;
  size_t l4_off;
  if (!v6) {
    if (n < ip_off + 20) return false;
    size_t ihl = (f[ip_off] & 0x0f) * 4;
    if (ihl < 20 || n < ip_off + ihl) return false;
    out->proto = f[ip_off + 9];
    out->src_ip = fmt_ipv4(f + ip_off + 12);
    out->dst_ip = fmt_ipv4(f + ip_off + 16);
    out->src_raw.assign(f + ip_off + 12, f + ip_off + 16);
    out->dst_raw.assign(f + ip_off + 16, f + ip_off + 20);
    l4_off = ip_off + ihl;
  } else {
    if (n < ip_off + 40) return false;
    out->proto = f[ip_off + 6];
    out->src_ip = fmt_ipv6(f + ip_off + 8);
    out->dst_ip = fmt_ipv6(f + ip_off + 24);
    out->src_raw.assign(f + ip_off + 8, f + ip_off + 24);
    out->dst_raw.assign(f + ip_off + 24, f + ip_off + 40);
    l4_off = ip_off + 40;
  }
  if (out->proto == 6) {
    if (n < l4_off + 20) return false;
    out->sport = (f[l4_off] << 8) | f[l4_off + 1];
    out->dport = (f[l4_off + 2] << 8) | f[l4_off + 3];
    out->seq = ((uint32_t)f[l4_off + 4] << 24) | ((uint32_t)f[l4_off + 5] << 16) |
               ((uint32_t)f[l4_off + 6] << 8) | f[l4_off + 7];
    out->ack = ((uint32_t)f[l4_off + 8] << 24) | ((uint32_t)f[l4_off + 9] << 16) |
               ((uint32_t)f[l4_off + 10] << 8) | f[l4_off + 11];
    size_t data_off = (f[l4_off + 12] >> 4) * 4;
    out->flags = f[l4_off + 13];
    out->window = (uint16_t)((f[l4_off + 14] << 8) | f[l4_off + 15]);
    out->payoff = l4_off + (data_off < 20 ? 20 : data_off);
    out->paylen = n > out->payoff ? n - out->payoff : 0;
    return true;
  }
  if (out->proto == 17) {
    if (n < l4_off + 8) return false;
    out->sport = (f[l4_off] << 8) | f[l4_off + 1];
    out->dport = (f[l4_off + 2] << 8) | f[l4_off + 3];
    out->payoff = l4_off + 8;
    out->paylen = n > out->payoff ? n - out->payoff : 0;
    return true;
  }
  return false;
}

/* Direction-independent conversation key. */
std::string conv_key(const L4 &l) {
  std::string a = l.src_ip + "/" + std::to_string(l.sport);
  std::string b = l.dst_ip + "/" + std::to_string(l.dport);
  const std::string &lo = a <= b ? a : b;
  const std::string &hi = a <= b ? b : a;
  return std::to_string(l.proto) + "|" + lo + "|" + hi;
}

uint32_t ipv4_u32(const std::vector<uint8_t> &raw) {
  if (raw.size() != 4) return 0;
  return ((uint32_t)raw[0] << 24) | ((uint32_t)raw[1] << 16) |
         ((uint32_t)raw[2] << 8) | raw[3];
}

/* TCP/UDP conversations: [{id, proto, addrA, portA, addrB, portB, packets,
   bytes, firstPacket}]. `firstPacket` can be passed to getStream(). */
val getConversations() {
  std::vector<val> rows;
  std::unordered_map<std::string, int> idx;
  for (size_t i = 0; i < g_session.pkts.size(); i++) {
    const Packet &p = g_session.pkts[i];
    L4 l;
    if (!locate_l4(p.bytes.data(), p.bytes.size(), p.linktype, &l)) continue;
    std::string k = conv_key(l);
    auto it = idx.find(k);
    if (it == idx.end()) {
      val o = val::object();
      o.set("id", (int)i);            /* representative packet index */
      o.set("proto", std::string(l.proto == 6 ? "TCP" : "UDP"));
      o.set("addrA", l.src_ip);
      o.set("portA", (int)l.sport);
      o.set("addrB", l.dst_ip);
      o.set("portB", (int)l.dport);
      o.set("packets", 1);
      o.set("bytes", (double)p.caplen);
      idx[k] = (int)rows.size();
      rows.push_back(o);
    } else {
      val &o = rows[it->second];
      o.set("packets", o["packets"].as<int>() + 1);
      o.set("bytes", o["bytes"].as<double>() + (double)p.caplen);
    }
  }
  val arr = val::array();
  for (size_t i = 0; i < rows.size(); i++) arr.set((int)i, rows[i]);
  return arr;
}

/* ── Protocol hierarchy ──────────────────────────────────────────────────── */
struct HNode {
  std::string abbrev, name;
  double packets = 0, bytes = 0;
  std::vector<HNode> kids;
};
HNode *h_child(HNode *p, const std::string &ab, const std::string &nm) {
  for (auto &c : p->kids)
    if (c.abbrev == ab) return &c;
  p->kids.push_back(HNode{ab, nm, 0, 0, {}});
  return &p->kids.back();
}
val h_to_val(const HNode &n) {
  val o = val::object();
  o.set("abbrev", n.abbrev);
  o.set("name", n.name);
  o.set("packets", n.packets);
  o.set("bytes", n.bytes);
  val ch = val::array();
  for (size_t i = 0; i < n.kids.size(); i++) ch.set((int)i, h_to_val(n.kids[i]));
  o.set("children", ch);
  return o;
}

/* Nested protocol tree (Frame → Ethernet → IP → TCP → …) with per-node packet
   and byte counts. Returns the top-level nodes. */
val getProtocolHierarchy() {
  HNode root;
  for (Packet &p : g_session.pkts) {
    pcapng_dissection_t *d =
        pcapng_dissect(p.bytes.data(), p.caplen, p.origlen, p.linktype);
    if (!d) continue;
    HNode *cur = &root;
    for (pcapng_field_t *layer = d->root->children; layer; layer = layer->next) {
      std::string ab = layer->abbrev[0] ? layer->abbrev : "?";
      std::string nm = layer->label;
      size_t comma = nm.find(',');
      if (comma != std::string::npos) nm = nm.substr(0, comma);
      cur = h_child(cur, ab, nm);
      cur->packets++;
      cur->bytes += p.caplen;
    }
    pcapng_dissection_free(d);
  }
  val arr = val::array();
  for (size_t i = 0; i < root.kids.size(); i++) arr.set((int)i, h_to_val(root.kids[i]));
  return arr;
}

/* Per-host endpoint statistics (any IP packet, TCP/UDP or not). */
val getEndpoints() {
  struct Ep { double packets = 0, bytes = 0, txp = 0, txb = 0, rxp = 0, rxb = 0; std::string addr; };
  std::vector<Ep> eps;
  std::unordered_map<std::string, int> idx;
  auto bump = [&](const std::string &a, double bytes, bool tx) {
    auto it = idx.find(a);
    int i;
    if (it == idx.end()) { Ep e; e.addr = a; i = (int)eps.size(); idx[a] = i; eps.push_back(e); }
    else i = it->second;
    Ep &e = eps[i];
    e.packets++; e.bytes += bytes;
    if (tx) { e.txp++; e.txb += bytes; } else { e.rxp++; e.rxb += bytes; }
  };

  for (const Packet &p : g_session.pkts) {
    const uint8_t *f = p.bytes.data();
    size_t n = p.bytes.size(), ip_off;
    int v6;
    if (!ip_offset(f, n, p.linktype, &ip_off, &v6)) continue;
    std::string src, dst;
    if (!v6) {
      if (n < ip_off + 20) continue;
      src = fmt_ipv4(f + ip_off + 12);
      dst = fmt_ipv4(f + ip_off + 16);
    } else {
      if (n < ip_off + 40) continue;
      src = fmt_ipv6(f + ip_off + 8);
      dst = fmt_ipv6(f + ip_off + 24);
    }
    bump(src, (double)p.caplen, true);
    bump(dst, (double)p.caplen, false);
  }

  val arr = val::array();
  for (size_t i = 0; i < eps.size(); i++) {
    val o = val::object();
    o.set("address", eps[i].addr);
    o.set("packets", eps[i].packets);
    o.set("bytes", eps[i].bytes);
    o.set("txPackets", eps[i].txp);
    o.set("txBytes", eps[i].txb);
    o.set("rxPackets", eps[i].rxp);
    o.set("rxBytes", eps[i].rxb);
    arr.set((int)i, o);
  }
  return arr;
}

struct ReasmState {
  std::vector<uint8_t> bufs[2];
  uint32_t dir_ip[2] = {0, 0};
  uint16_t dir_port[2] = {0, 0};
  bool dir_set[2] = {false, false};
  /* newly-delivered chunks in arrival order, for an interleaved view */
  std::vector<std::pair<int, std::vector<uint8_t>>> segs;
};

void reasm_cb(void *ud, uint32_t sip, uint16_t sport, uint32_t dip,
              uint16_t dport, int dir, const uint8_t *data, size_t len,
              const uint8_t *all, size_t all_len) {
  (void)dip; (void)dport;
  ReasmState *s = static_cast<ReasmState *>(ud);
  int d = dir & 1;
  s->bufs[d].assign(all, all + all_len);
  s->dir_ip[d] = sip;
  s->dir_port[d] = sport;
  s->dir_set[d] = true;
  if (len) s->segs.emplace_back(d, std::vector<uint8_t>(data, data + len));
}

val make_u8(const std::vector<uint8_t> &v) {
  val u8 = val::global("Uint8Array").new_(val((int)v.size()));
  if (!v.empty())
    u8.call<void>("set",
                  val(emscripten::typed_memory_view(v.size(), v.data())));
  return u8;
}

/* Follow the conversation that packet `index` belongs to. TCP is reassembled by
   libpcapng's reassembler; UDP is concatenated in capture order. Returns
   {ok, proto, clientIp, clientPort, serverIp, serverPort, packets,
    client:Uint8Array, server:Uint8Array}. */
val getStream(int index) {
  if (index < 0 || index >= (int)g_session.pkts.size()) return val::null();
  const Packet &sp = g_session.pkts[index];
  L4 sel;
  if (!locate_l4(sp.bytes.data(), sp.bytes.size(), sp.linktype, &sel))
    return val::null();
  std::string key = conv_key(sel);
  bool is_tcp = sel.proto == 6;

  bool have_client = false;
  std::string client_ip, server_ip;
  uint16_t client_port = 0, server_port = 0;
  std::vector<uint8_t> client_raw;
  int packets = 0;

  ReasmState st;
  pcapng_tcp_reasm_t *r = is_tcp ? pcapng_tcp_reasm_new() : nullptr;
  std::vector<uint8_t> udp_client, udp_server;

  for (const Packet &p : g_session.pkts) {
    L4 l;
    if (!locate_l4(p.bytes.data(), p.bytes.size(), p.linktype, &l)) continue;
    if (conv_key(l) != key) continue;
    packets++;
    if (!have_client) {
      have_client = true;
      client_ip = l.src_ip; client_port = l.sport; client_raw = l.src_raw;
      server_ip = l.dst_ip; server_port = l.dport;
    }
    bool is_client = l.src_ip == client_ip && l.sport == client_port;
    const uint8_t *pl = p.bytes.data() + l.payoff;
    if (r) {
      pcapng_tcp_reasm_add(r, ipv4_u32(l.src_raw), ipv4_u32(l.dst_raw), l.sport,
                           l.dport, l.seq, l.flags, l.paylen ? pl : nullptr,
                           l.paylen, reasm_cb, &st);
    } else if (l.paylen) {
      auto &dst = is_client ? udp_client : udp_server;
      dst.insert(dst.end(), pl, pl + l.paylen);
      st.segs.emplace_back(is_client ? 0 : 1,
                           std::vector<uint8_t>(pl, pl + l.paylen));
    }
  }

  std::vector<uint8_t> client_bytes, server_bytes;
  int cd = 0; /* which reasm dir id is the client */
  if (is_tcp) {
    uint32_t ckey_ip = ipv4_u32(client_raw);
    cd = -1;
    for (int d = 0; d < 2; d++)
      if (st.dir_set[d] && st.dir_ip[d] == ckey_ip && st.dir_port[d] == client_port)
        cd = d;
    if (cd < 0) cd = 0;
    client_bytes = std::move(st.bufs[cd]);
    server_bytes = std::move(st.bufs[1 - cd]);
    pcapng_tcp_reasm_free(r);
  } else {
    client_bytes = std::move(udp_client);
    server_bytes = std::move(udp_server);
  }

  /* interleaved segments in arrival order: {dir: 0=client→server, 1=server→client} */
  val segArr = val::array();
  for (size_t i = 0; i < st.segs.size(); i++) {
    val s = val::object();
    s.set("dir", st.segs[i].first == cd ? 0 : 1);
    s.set("data", make_u8(st.segs[i].second));
    segArr.set((int)i, s);
  }

  val o = val::object();
  o.set("segments", segArr);
  o.set("ok", true);
  o.set("proto", std::string(is_tcp ? "TCP" : "UDP"));
  o.set("clientIp", client_ip);
  o.set("clientPort", (int)client_port);
  o.set("serverIp", server_ip);
  o.set("serverPort", (int)server_port);
  o.set("packets", packets);
  o.set("client", make_u8(client_bytes));
  o.set("server", make_u8(server_bytes));
  return o;
}

/* Per-packet timeline for the conversation of packet `index` — for the TCP
   stream graph. Returns {clientIp, clientPort, serverIp, serverPort,
   packets:[{no, time, seq, ack, len, win, dir, flags}]}. */
val getStreamPackets(int index) {
  if (index < 0 || index >= (int)g_session.pkts.size()) return val::null();
  const Packet &sp = g_session.pkts[index];
  L4 sel;
  if (!locate_l4(sp.bytes.data(), sp.bytes.size(), sp.linktype, &sel)) return val::null();
  std::string key = conv_key(sel);

  bool have_client = false;
  std::string client_ip, server_ip;
  uint16_t client_port = 0, server_port = 0;

  val arr = val::array();
  int k = 0;
  for (size_t i = 0; i < g_session.pkts.size(); i++) {
    const Packet &p = g_session.pkts[i];
    L4 l;
    if (!locate_l4(p.bytes.data(), p.bytes.size(), p.linktype, &l)) continue;
    if (conv_key(l) != key) continue;
    if (!have_client) {
      have_client = true;
      client_ip = l.src_ip; client_port = l.sport;
      server_ip = l.dst_ip; server_port = l.dport;
    }
    int dir = (l.src_ip == client_ip && l.sport == client_port) ? 0 : 1;
    val o = val::object();
    o.set("no", (int)(i + 1));
    o.set("time", packet_seconds(p));
    o.set("seq", (double)l.seq);
    o.set("ack", (double)l.ack);
    o.set("len", (int)l.paylen);
    o.set("win", (int)l.window);
    o.set("dir", dir);
    o.set("flags", (int)l.flags);
    arr.set(k++, o);
  }

  val r = val::object();
  r.set("clientIp", client_ip);
  r.set("clientPort", (int)client_port);
  r.set("serverIp", server_ip);
  r.set("serverPort", (int)server_port);
  r.set("packets", arr);
  return r;
}

/* ── Object (file) extraction — HTTP / SMB ──────────────────────────────────
   Extract transferred files from the whole capture using libpcapng's object
   extractor. Returns [{proto, frame, hostname, contentType, filename,
   complete, data:Uint8Array}]. */
val extractObjects(std::string protoStr) {
  std::string p = protoStr;
  std::transform(p.begin(), p.end(), p.begin(), ::tolower);
  pcapng_object_proto_t proto = p == "smb" ? PCAPNG_OBJ_SMB : PCAPNG_OBJ_HTTP;
  pcapng_object_extractor_t *ex = pcapng_object_extractor_new(proto);
  val arr = val::array();
  if (!ex) return arr;
  for (size_t i = 0; i < g_session.pkts.size(); i++) {
    const Packet &pk = g_session.pkts[i];
    pcapng_object_extractor_add_packet(ex, (int)(i + 1), pk.bytes.data(),
                                       pk.caplen, pk.linktype);
  }
  pcapng_object_extractor_finish(ex);
  int n = pcapng_object_count(ex);
  for (int i = 0; i < n; i++) {
    const pcapng_object_t *o = pcapng_object_at(ex, i);
    if (!o) continue;
    val obj = val::object();
    obj.set("proto", std::string(o->proto));
    obj.set("frame", o->frame);
    obj.set("hostname", std::string(o->hostname));
    obj.set("contentType", std::string(o->content_type));
    obj.set("filename", std::string(o->filename));
    obj.set("complete", (bool)o->complete);
    std::vector<uint8_t> data(o->data, o->data + o->len);
    obj.set("data", make_u8(data));
    arr.set(i, obj);
  }
  pcapng_object_extractor_free(ex);
  return arr;
}

/* ── Packet comments (pcapng opt_comment) ───────────────────────────────────*/
std::string getComment(int index) {
  if (index < 0 || index >= (int)g_session.pkts.size()) return "";
  return g_session.pkts[index].comment;
}
void setComment(int index, std::string text) {
  if (index < 0 || index >= (int)g_session.pkts.size()) return;
  g_session.pkts[index].comment = text;
}
/* Indices of packets that carry a comment (for a comment list / export). */
val getCommentedPackets() {
  val arr = val::array();
  int k = 0;
  for (size_t i = 0; i < g_session.pkts.size(); i++)
    if (!g_session.pkts[i].comment.empty()) arr.set(k++, (int)i);
  return arr;
}

/* ── Export a subset of packets as a new pcapng ──────────────────────────────
   `indices` is a JS array of packet indices (any order). Produces a complete
   pcapng (SHB + one IDB per original interface + an EPB per packet) with
   timestamps normalised to microseconds. Returns a Uint8Array. */
val exportPcapng(val indices) {
  std::vector<uint8_t> out;
  size_t base;

  /* SHB */
  size_t shb = libpcapng_section_header_block_size();
  base = out.size(); out.resize(base + shb);
  libpcapng_section_header_block_write(out.data() + base);

  /* one IDB per interface (preserve interface_id indexing) */
  std::vector<uint16_t> lts = g_session.linktypes;
  if (lts.empty()) lts.push_back(PCAPNG_LINKTYPE_ETHERNET);
  size_t idbsz = libpcapng_interface_description_block_size();
  for (uint16_t lt : lts) {
    base = out.size(); out.resize(base + idbsz);
    libpcapng_interface_description_block_write_with_linktype(0, out.data() + base, lt);
  }
  int nidb = (int)lts.size();

  int n = indices["length"].as<int>();
  for (int k = 0; k < n; k++) {
    int idx = indices[k].as<int>();
    if (idx < 0 || idx >= (int)g_session.pkts.size()) continue;
    Packet &p = g_session.pkts[idx];
    uint32_t iface = p.interface_id < (uint32_t)nidb ? p.interface_id : 0;
    /* normalise to a 64-bit microsecond count (IDB default if_tsresol = 1e-6) */
    uint64_t ts = g_session.is_classic
                      ? (uint64_t)p.ts_high * 1000000ull + p.ts_low
                      : (((uint64_t)p.ts_high) << 32) | p.ts_low;
    pcapng_option_t opt;
    const pcapng_option_t *opts = NULL;
    size_t nopt = 0;
    if (!p.comment.empty()) {
      opt.type = PCAPNG_OPT_COMMENT;
      opt.length = (uint16_t)p.comment.size();
      opt.value = p.comment.data();
      opts = &opt;
      nopt = 1;
    }
    size_t sz = libpcapng_enhanced_packet_block_size_with_options(p.caplen, opts, nopt);
    base = out.size(); out.resize(base + sz);
    libpcapng_enhanced_packet_block_write_full(p.bytes.data(), p.caplen, p.origlen,
                                               iface, (uint32_t)(ts >> 32),
                                               (uint32_t)(ts & 0xffffffffu), opts, nopt,
                                               out.data() + base);
  }
  return make_u8(out);
}

/* ── Display filters (Wireshark-style) ──────────────────────────────────────
   Backed by libpcapng's pcapng_dfilter engine, evaluated against each packet's
   dissection tree. */

/* Validate an expression: {ok, error}. */
val validateFilter(std::string expr) {
  char err[192] = {0};
  pcapng_dfilter_t *f = pcapng_dfilter_compile(expr.c_str(), err, sizeof err);
  val r = val::object();
  r.set("ok", f != nullptr);
  r.set("error", std::string(f ? "" : err));
  if (f) pcapng_dfilter_free(f);
  return r;
}

/* Boolean mask (Uint8Array, one byte per packet) of packets matching `expr`. */
val matchFilter(std::string expr) {
  char err[192] = {0};
  pcapng_dfilter_t *f = pcapng_dfilter_compile(expr.c_str(), err, sizeof err);
  size_t n = g_session.pkts.size();
  std::vector<uint8_t> mask(n, 0);
  if (f && !pcapng_dfilter_is_match_all(f)) {
    for (size_t i = 0; i < n; i++) {
      Packet &p = g_session.pkts[i];
      pcapng_dissection_t *d =
          pcapng_dissect(p.bytes.data(), p.caplen, p.origlen, p.linktype);
      if (d) {
        mask[i] = pcapng_dfilter_match(f, d->root) ? 1 : 0;
        pcapng_dissection_free(d);
      }
    }
  } else {
    std::fill(mask.begin(), mask.end(), 1);
  }
  if (f) pcapng_dfilter_free(f);
  return make_u8(mask);
}

/* Evaluate several filters at once. Each packet is dissected a single time and
   tested against every compiled filter — ideal for the multi-series IO graph.
   Returns an array of Uint8Array masks, aligned with `exprs`. An invalid
   expression yields an all-zero mask. */
val matchFilters(val exprs) {
  int nf = exprs["length"].as<int>();
  size_t n = g_session.pkts.size();
  std::vector<pcapng_dfilter_t *> filters(nf, nullptr);
  std::vector<int> matchAll(nf, 0);
  for (int j = 0; j < nf; j++) {
    std::string e = exprs[j].as<std::string>();
    filters[j] = pcapng_dfilter_compile(e.c_str(), nullptr, 0);
    matchAll[j] = filters[j] ? pcapng_dfilter_is_match_all(filters[j]) : 0;
  }

  std::vector<std::vector<uint8_t>> masks(nf, std::vector<uint8_t>(n, 0));
  for (size_t i = 0; i < n; i++) {
    Packet &p = g_session.pkts[i];
    /* Only dissect if at least one filter actually needs it. */
    bool needDissect = false;
    for (int j = 0; j < nf; j++)
      if (filters[j] && !matchAll[j]) needDissect = true;
    pcapng_dissection_t *d = nullptr;
    if (needDissect)
      d = pcapng_dissect(p.bytes.data(), p.caplen, p.origlen, p.linktype);
    for (int j = 0; j < nf; j++) {
      if (!filters[j]) continue;              /* invalid → all zero */
      if (matchAll[j]) { masks[j][i] = 1; continue; }
      if (d) masks[j][i] = pcapng_dfilter_match(filters[j], d->root) ? 1 : 0;
    }
    if (d) pcapng_dissection_free(d);
  }

  for (int j = 0; j < nf; j++)
    if (filters[j]) pcapng_dfilter_free(filters[j]);

  val arr = val::array();
  for (int j = 0; j < nf; j++) arr.set(j, make_u8(masks[j]));
  return arr;
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
  emscripten::function("getStartTime", &getStartTime);
  emscripten::function("getFieldColumn", &getFieldColumn);
  emscripten::function("getDetail", &getDetail);
  emscripten::function("getPacketBytes", &getPacketBytes);
  emscripten::function("getConversations", &getConversations);
  emscripten::function("getEndpoints", &getEndpoints);
  emscripten::function("getProtocolHierarchy", &getProtocolHierarchy);
  emscripten::function("getStream", &getStream);
  emscripten::function("getStreamPackets", &getStreamPackets);
  emscripten::function("extractObjects", &extractObjects);
  emscripten::function("validateFilter", &validateFilter);
  emscripten::function("matchFilter", &matchFilter);
  emscripten::function("matchFilters", &matchFilters);
  emscripten::function("exportPcapng", &exportPcapng);
  emscripten::function("getComment", &getComment);
  emscripten::function("setComment", &setComment);
  emscripten::function("getCommentedPackets", &getCommentedPackets);
  emscripten::function("loadPosaText", &loadPosaText);
  emscripten::function("listPosa", &listPosa);
  emscripten::function("listProtocols", &listProtocols);
}
