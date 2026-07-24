/* dissect.c — the generic dissection engine: bytes → a pcapng_field tree.
 *
 * Each protocol is a structural node (abbrev = the protocol name, e.g. "ip")
 * whose children are its fields (abbrev = Wireshark name, e.g. "ip.src"), each
 * carrying its absolute byte offset/length. Public entry point: pcapng_dissect.
 */
#include <libpcapng/dissect.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef _WIN32
#  include <libpcapng/win_compat.h>
#else
#  include <arpa/inet.h>
#endif

#include <libpcapng/protocols/ntp.h>   /* struct libpcapng_ntp_hdr (wire layout)   */
#include <libpcapng/protocols/bootp.h> /* struct libpcapng_bootp_hdr (DHCP/BOOTP)  */
#include <libpcapng/protocols/ssl.h>   /* TLS_CONTENT_*, TLS_VERSION_* constants    */
#include <libpcapng/posa.h>            /* declarative decoders (e.g. bundled RDP)   */
#include "builtin_protos.h"           /* g_builtin_posa_protos[] — embedded .posa  */

/* LINKTYPE_* aliases so the ported dissector body is unchanged. */
#define LINKTYPE_NULL      PCAPNG_LINKTYPE_NULL
#define LINKTYPE_ETHERNET  PCAPNG_LINKTYPE_ETHERNET
#define LINKTYPE_RAW       PCAPNG_LINKTYPE_RAW
#define LINKTYPE_LINUX_SLL PCAPNG_LINKTYPE_LINUX_SLL
#define LINKTYPE_IPV4      PCAPNG_LINKTYPE_IPV4
#define LINKTYPE_IPV6      PCAPNG_LINKTYPE_IPV6

/* ── field-tree helpers ─────────────────────────────────────────────────── */
static pcapng_field_t *pf_new(const char *abbrev, pcapng_ftype_t vtype)
{
  pcapng_field_t *f = calloc(1, sizeof *f);
  if (!f) return NULL;
  if (abbrev) snprintf(f->abbrev, sizeof f->abbrev, "%s", abbrev);
  f->vtype = vtype;
  return f;
}
static pcapng_field_t *pf_add(pcapng_field_t *parent, const char *abbrev, pcapng_ftype_t vtype)
{
  pcapng_field_t *f = pf_new(abbrev, vtype);
  if (!f) return NULL;
  f->parent = parent;
  if (parent) {
    if (parent->last_child) parent->last_child->next = f; else parent->children = f;
    parent->last_child = f;
  }
  return f;
}
void pcapng_field_free(pcapng_field_t *root)
{
  pcapng_field_t *c, *n;
  if (!root) return;
  for (c = root->children; c; c = n) { n = c->next; pcapng_field_free(c); }
  free(root);
}
static void pf_set_label(pcapng_field_t *f, const char *fmt, ...)
{
  va_list ap;
  if (!f) return;
  va_start(ap, fmt); vsnprintf(f->label, sizeof f->label, fmt, ap); va_end(ap);
}
static void pf_set_uint(pcapng_field_t *f, uint64_t v) { if (f) { f->vtype = PCAPNG_FT_UINT; f->u = v; } }
static void pf_set_str(pcapng_field_t *f, const char *s)
{ if (f) { f->vtype = PCAPNG_FT_STR; snprintf(f->str, sizeof f->str, "%s", s ? s : ""); } }
static void pf_set_ipv4(pcapng_field_t *f, const uint8_t ip[4])
{
  if (!f) return;
  f->vtype = PCAPNG_FT_IPV4; memcpy(f->bytes, ip, 4); f->blen = 4;
  snprintf(f->str, sizeof f->str, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}
static void pf_set_ipv6(pcapng_field_t *f, const uint8_t ip[16])
{
  static const char hx[] = "0123456789abcdef";
  char *p = f->str; int i;
  if (!f) return;
  f->vtype = PCAPNG_FT_IPV6; memcpy(f->bytes, ip, 16); f->blen = 16;
  for (i = 0; i < 16; i += 2) {
    if (i) *p++ = ':';
    *p++ = hx[(ip[i] >> 4) & 0xf]; *p++ = hx[ip[i] & 0xf];
    *p++ = hx[(ip[i+1] >> 4) & 0xf]; *p++ = hx[ip[i+1] & 0xf];
  }
  *p = '\0';
}
static void pf_set_mac(pcapng_field_t *f, const uint8_t mac[6])
{
  if (!f) return;
  f->vtype = PCAPNG_FT_MAC; memcpy(f->bytes, mac, 6); f->blen = 6;
  snprintf(f->str, sizeof f->str, "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
static void pf_set_bytes(pcapng_field_t *f, const uint8_t *b, int n)
{
  if (!f) return;
  f->vtype = PCAPNG_FT_BYTES;
  if (n > PCAPNG_FIELD_BYTES_MAX) n = PCAPNG_FIELD_BYTES_MAX;
  if (n < 0) n = 0;
  memcpy(f->bytes, b, (size_t)n); f->blen = n;
}
int pcapng_field_count(const pcapng_field_t *parent)
{
  int n = 0; const pcapng_field_t *c;
  if (!parent) return 0;
  for (c = parent->children; c; c = c->next) n++;
  return n;
}
pcapng_field_t *pcapng_field_child_at(const pcapng_field_t *parent, int index)
{
  pcapng_field_t *c;
  if (!parent || index < 0) return NULL;
  for (c = parent->children; c; c = c->next) if (index-- == 0) return c;
  return NULL;
}
static void collect_rec(pcapng_field_t *node, const char *abbrev, pcapng_field_t **out, int max, int *n)
{
  pcapng_field_t *c;
  if (!node) return;
  if (node->abbrev[0] && strcmp(node->abbrev, abbrev) == 0 && *n < max) out[(*n)++] = node;
  for (c = node->children; c; c = c->next) collect_rec(c, abbrev, out, max, n);
}
int pcapng_field_collect(pcapng_field_t *root, const char *abbrev, pcapng_field_t **out, int max)
{ int n = 0; collect_rec(root, abbrev, out, max, &n); return n; }

/* ── safe big/little-endian readers ─────────────────────────────────────── */
static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t be32(const uint8_t *p)
{ return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

/* dissection context: summary sink (may be NULL) + packet base for byte ranges */
typedef struct { pcapng_dissection_t *sum; const uint8_t *base; } dctx_t;

/* record a node's absolute byte range within the packet (for a hex pane) */
static void set_range(dctx_t *c, pcapng_field_t *n, const uint8_t *p, int len)
{
  if (n && c->base) { n->off = (int)(p - c->base); n->len = len; }
}

static void set_proto(dctx_t *c, const char *name)
{ if (c->sum) snprintf(c->sum->proto, sizeof c->sum->proto, "%s", name); }
static void set_info(dctx_t *c, const char *fmt, ...)
{
  va_list ap;
  if (!c->sum) return;
  va_start(ap, fmt);
  vsnprintf(c->sum->info, sizeof c->sum->info, fmt, ap);
  va_end(ap);
}
static void set_src(dctx_t *c, const char *s)
{ if (c->sum) snprintf(c->sum->src, sizeof c->sum->src, "%s", s); }
static void set_dst(dctx_t *c, const char *s)
{ if (c->sum) snprintf(c->sum->dst, sizeof c->sum->dst, "%s", s); }

/* ── bundled declarative decoders (posa) ─────────────────────────────────────
 * RDP is described entirely in posa (rdp.posa) rather than hand-written C. The
 * source is embedded so the decoder ships with the library and binds itself to
 * TCP/3389 via its `rule` line. Additional protocols can be added the same way. */
static const char POSA_BUILTIN_RDP[] =
  "protocol TPKT\n"
  "    col \"RDP\"\n"
  "    abbrev \"rdp\"\n"
  "    required uint8  version\n"
  "    required uint8  reserved\n"
  "    required uint16 length\n"
  "    layer   cotp    COTP\n"
  "protocol COTP\n"
  "    abbrev \"cotp\"\n"
  "    required uint8  li\n"
  "    required uint8  pdu_type\n"
  "        CR = 0xe0\n"
  "        CC = 0xd0\n"
  "        DT = 0xf0\n"
  "    scope   li\n"
  "        when pdu_type & 0xf0 == 0xe0:\n"
  "            required uint16 dst_ref\n"
  "            required uint16 src_ref\n"
  "            required uint8  class\n"
  "            layer neg RDP_NEGOTIATION\n"
  "        when pdu_type & 0xf0 == 0xd0:\n"
  "            required uint16 dst_ref\n"
  "            required uint16 src_ref\n"
  "            required uint8  class\n"
  "            layer neg RDP_NEGOTIATION\n"
  "        when pdu_type & 0xf0 == 0xf0:\n"
  "            required uint8  eot\n"
  "    info \"COTP %s\" pdu_type\n"
  "protocol RDP_NEGOTIATION\n"
  "    abbrev \"rdp\"\n"
  "    optional string cookie until \"\\r\\n\"\n"
  "    when remaining >= 8:\n"
  "        required uint8 type\n"
  "            Request  = 1\n"
  "            Response = 2\n"
  "            Failure  = 3\n"
  "        required uint8     flags\n"
  "        required le_uint16 length\n"
  "        required le_uint32 protocols\n"
  "            TLS     = 0x1\n"
  "            CredSSP = 0x3\n"
  "    info \"%s Negotiate %s\" cookie, type\n"
  "rule tcp.port == 3389 => TPKT\n";

static int g_posa_builtin_loaded;
static void posa_ensure_builtin(void)
{
  int i;
  if (g_posa_builtin_loaded) return;
  g_posa_builtin_loaded = 1;
  /* Every .posa in bin/protos, embedded at build time. */
  for (i = 0; g_builtin_posa_protos[i]; i++)
    pcapng_posa_load_text(g_builtin_posa_protos[i], NULL, 0);
  /* Load the known-good RDP definition last so it wins over any bundled rdp.posa. */
  pcapng_posa_load_text(POSA_BUILTIN_RDP, NULL, 0);
}

/* Run the posa decoder named by a `rule`, if there is one. Returns 1 when it
   handled the payload — callers check this before falling back to built-in C,
   which is what lets a .posa file take a protocol over without a rebuild. */
static int run_posa(dctx_t *c, const char *proto, const uint8_t *pl, int pll,
                    pcapng_field_t *root)
{
  const pcapng_posa_proto_t *pp;
  const char *col;
  char info[192] = "";
  if (!proto || pll <= 0) return 0;
  pcapng_posa_reset_col();
  pcapng_posa_dissect(proto, pl, pll, root, c->base ? (int)(pl - c->base) : 0, info, sizeof info);
  pp = pcapng_posa_find(proto);
  col = pcapng_posa_last_col();                     /* the innermost `col`, e.g. SMB2 */
  if (!col) col = (pp && pp->display[0]) ? pp->display : proto;
  set_proto(c, col);
  { char *ip = info; while (*ip == ' ') ip++;      /* trim leading pad from empty args */
    if (*ip) set_info(c, "%s", ip); }
  return 1;
}

/* Apply a posa decoder bound (by a rule) to this transport port, if any. */
static int try_posa_app(dctx_t *c, uint16_t sp, uint16_t dp, int ipproto,
                        const uint8_t *pl, int pll, pcapng_field_t *root)
{
  const char *proto = pcapng_posa_bound_port(ipproto, dp);
  if (!proto) proto = pcapng_posa_bound_port(ipproto, sp);
  return run_posa(c, proto, pl, pll, root);
}

/* …and the ones bound below the transport layer: `rule ip.proto == 2 => IGMP`,
   `rule eth.type == 0x88cc => LLDP`. */
static int try_posa_ipproto(dctx_t *c, int num, const uint8_t *pl, int pll, pcapng_field_t *root)
{ return run_posa(c, pcapng_posa_bound_ipproto(num), pl, pll, root); }

static int try_posa_ethertype(dctx_t *c, uint16_t type, const uint8_t *pl, int pll, pcapng_field_t *root)
{ return run_posa(c, pcapng_posa_bound_ethertype(type), pl, pll, root); }

/* forward decls */
static void dissect_l3(dctx_t *c, uint16_t ethertype, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_ipv4(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_ipv6(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_arp (dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_tcp (dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_udp (dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_icmp(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_dns (dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root, const char *proto);
static void dissect_ntp (dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_igmp(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_gre (dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_dhcp(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_snmp(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_radius(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_nbns(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_tls (dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_ssh (dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_http(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_quic(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_data(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root);
static void dissect_text(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root,
                         const char *abbrev, const char *name);

/* ── frame (always present) ─────────────────────────────────────────────── */
static void dissect_frame(dctx_t *c, const uint8_t *data, uint32_t caplen, uint32_t origlen,
                          pcapng_field_t *root)
{
  pcapng_field_t *fr = pf_add(root, "frame", PCAPNG_FT_NONE);
  pcapng_field_t *f;
  pf_set_label(fr, "Frame: %u bytes on wire, %u captured", origlen, caplen);
  set_range(c, fr, data, (int)caplen);
  f = pf_add(fr, "frame.len", PCAPNG_FT_UINT);
  pf_set_uint(f, origlen);
  pf_set_label(f, "Frame Length: %u", origlen);
  f = pf_add(fr, "frame.cap_len", PCAPNG_FT_UINT);
  pf_set_uint(f, caplen);
  pf_set_label(f, "Capture Length: %u", caplen);
}

/* ── Ethernet ───────────────────────────────────────────────────────────── */
static void dissect_ethernet(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *eth, *f;
  uint16_t type;
  char dsts[24], srcs[24];

  if (len < 14) { set_proto(c, "Ethernet"); return; }
  snprintf(dsts, sizeof dsts, "%02x:%02x:%02x:%02x:%02x:%02x", d[0],d[1],d[2],d[3],d[4],d[5]);
  snprintf(srcs, sizeof srcs, "%02x:%02x:%02x:%02x:%02x:%02x", d[6],d[7],d[8],d[9],d[10],d[11]);
  type = be16(d + 12);

  eth = pf_add(root, "eth", PCAPNG_FT_NONE);
  pf_set_label(eth, "Ethernet II, Src: %s, Dst: %s", srcs, dsts);
  set_range(c, eth, d, 14);

  f = pf_add(eth, "eth.dst", PCAPNG_FT_MAC); pf_set_mac(f, d);
  pf_set_label(f, "Destination: %s", dsts); set_range(c, f, d, 6);
  f = pf_add(eth, "eth.src", PCAPNG_FT_MAC); pf_set_mac(f, d + 6);
  pf_set_label(f, "Source: %s", srcs); set_range(c, f, d + 6, 6);
  f = pf_add(eth, "eth.type", PCAPNG_FT_UINT); pf_set_uint(f, type);
  pf_set_label(f, "Type: 0x%04x", type); set_range(c, f, d + 12, 2);

  set_proto(c, "Ethernet");
  set_src(c, srcs);
  set_dst(c, dsts);
  set_info(c, "Ethernet II");

  /* 802.1Q VLAN tag — step over one tag for L3 dispatch. */
  if (type == 0x8100 && len >= 18) {
    uint16_t vid = be16(d + 14) & 0x0fff;
    pcapng_field_t *v = pf_add(root, "vlan", PCAPNG_FT_NONE);
    pcapng_field_t *vf = pf_add(v, "vlan.id", PCAPNG_FT_UINT);
    pf_set_uint(vf, vid);
    pf_set_label(v, "802.1Q Virtual LAN, ID: %u", vid);
    pf_set_label(vf, "VLAN ID: %u", vid);
    dissect_l3(c, be16(d + 16), d + 18, len - 18, root);
    return;
  }
  dissect_l3(c, type, d + 14, len - 14, root);
}

static void dissect_l3(dctx_t *c, uint16_t ethertype, const uint8_t *d, int len, pcapng_field_t *root)
{
  if (len <= 0) return;
  if (try_posa_ethertype(c, ethertype, d, len, root)) return;   /* a .posa claims it */
  switch (ethertype) {
  case 0x0800: dissect_ipv4(c, d, len, root); break;
  case 0x86DD: dissect_ipv6(c, d, len, root); break;
  case 0x0806: dissect_arp (c, d, len, root); break;
  default: break;
  }
}

/* ── IPv4 ───────────────────────────────────────────────────────────────── */
static const char *ipproto_name(uint8_t p)
{
  switch (p) {
  case 1:  return "ICMP";
  case 2:  return "IGMP";
  case 6:  return "TCP";
  case 17: return "UDP";
  case 41: return "IPv6";
  case 47: return "GRE";
  case 50: return "ESP";
  case 89: return "OSPF";
  default: return "IP";
  }
}

static void dissect_ipv4(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *ip, *f;
  int ihl;
  uint8_t proto;
  uint16_t total;
  char ss[16], ds[16];

  if (len < 20) { set_proto(c, "IPv4"); return; }
  ihl   = (d[0] & 0x0f) * 4;
  total = be16(d + 2);
  proto = d[9];
  snprintf(ss, sizeof ss, "%u.%u.%u.%u", d[12], d[13], d[14], d[15]);
  snprintf(ds, sizeof ds, "%u.%u.%u.%u", d[16], d[17], d[18], d[19]);

  ip = pf_add(root, "ip", PCAPNG_FT_NONE);
  pf_set_label(ip, "Internet Protocol Version 4, Src: %s, Dst: %s", ss, ds);
  set_range(c, ip, d, ihl >= 20 ? ihl : 20);

  f = pf_add(ip, "ip.version", PCAPNG_FT_UINT); pf_set_uint(f, d[0] >> 4);
  pf_set_label(f, "Version: %u", d[0] >> 4); set_range(c, f, d, 1);
  f = pf_add(ip, "ip.hdr_len", PCAPNG_FT_UINT); pf_set_uint(f, ihl);
  pf_set_label(f, "Header Length: %d bytes", ihl); set_range(c, f, d, 1);
  f = pf_add(ip, "ip.dsfield", PCAPNG_FT_UINT); pf_set_uint(f, d[1]);
  pf_set_label(f, "Differentiated Services Field: 0x%02x", d[1]); set_range(c, f, d + 1, 1);
  f = pf_add(ip, "ip.len", PCAPNG_FT_UINT); pf_set_uint(f, total);
  pf_set_label(f, "Total Length: %u", total); set_range(c, f, d + 2, 2);
  f = pf_add(ip, "ip.id", PCAPNG_FT_UINT); pf_set_uint(f, be16(d + 4));
  pf_set_label(f, "Identification: 0x%04x (%u)", be16(d + 4), be16(d + 4)); set_range(c, f, d + 4, 2);
  f = pf_add(ip, "ip.flags", PCAPNG_FT_UINT); pf_set_uint(f, d[6] >> 5);
  pf_set_label(f, "Flags: 0x%02x", d[6] >> 5); set_range(c, f, d + 6, 1);
  f = pf_add(ip, "ip.frag_offset", PCAPNG_FT_UINT); pf_set_uint(f, be16(d + 6) & 0x1fff);
  pf_set_label(f, "Fragment Offset: %u", be16(d + 6) & 0x1fff); set_range(c, f, d + 6, 2);
  f = pf_add(ip, "ip.ttl", PCAPNG_FT_UINT); pf_set_uint(f, d[8]);
  pf_set_label(f, "Time to Live: %u", d[8]); set_range(c, f, d + 8, 1);
  f = pf_add(ip, "ip.proto", PCAPNG_FT_UINT); pf_set_uint(f, proto);
  pf_set_label(f, "Protocol: %s (%u)", ipproto_name(proto), proto); set_range(c, f, d + 9, 1);
  f = pf_add(ip, "ip.checksum", PCAPNG_FT_UINT); pf_set_uint(f, be16(d + 10));
  pf_set_label(f, "Header Checksum: 0x%04x", be16(d + 10)); set_range(c, f, d + 10, 2);
  f = pf_add(ip, "ip.src", PCAPNG_FT_IPV4); pf_set_ipv4(f, d + 12);
  pf_set_label(f, "Source Address: %s", ss); set_range(c, f, d + 12, 4);
  f = pf_add(ip, "ip.dst", PCAPNG_FT_IPV4); pf_set_ipv4(f, d + 16);
  pf_set_label(f, "Destination Address: %s", ds); set_range(c, f, d + 16, 4);

  set_proto(c, "IPv4");
  set_src(c, ss);
  set_dst(c, ds);
  set_info(c, "%s", ipproto_name(proto));

  if (ihl < 20 || ihl > len) ihl = 20;
  {
    const uint8_t *pl = d + ihl;
    int pll = len - ihl;
    if (pll < 0) pll = 0;
    /* a .posa that claims this IP protocol wins over the built-in C */
    if (proto != 6 && proto != 17 && try_posa_ipproto(c, proto, pl, pll, root)) return;
    switch (proto) {
    case 1:  dissect_icmp(c, pl, pll, root); break;
    case 2:  dissect_igmp(c, pl, pll, root); break;
    case 6:  dissect_tcp (c, pl, pll, root); break;
    case 17: dissect_udp (c, pl, pll, root); break;
    case 47: dissect_gre (c, pl, pll, root); break;
    default: break;
    }
  }
}

/* ── IPv6 (base header only; no extension-header walking) ───────────────── */
static void dissect_ipv6(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *ip, *f;
  uint8_t nxt;
  char ss[40], ds[40];

  if (len < 40) { set_proto(c, "IPv6"); return; }
  nxt = d[6];

  f = pf_add(root, "ipv6", PCAPNG_FT_NONE);
  ip = f;
  set_range(c, ip, d, 40);
  { pcapng_field_t *s = pf_add(ip, "ipv6.src", PCAPNG_FT_IPV6); pf_set_ipv6(s, d + 8);
    snprintf(ss, sizeof ss, "%s", s->str);
    pf_set_label(s, "Source Address: %s", ss); set_range(c, s, d + 8, 16); }
  { pcapng_field_t *dd = pf_add(ip, "ipv6.dst", PCAPNG_FT_IPV6); pf_set_ipv6(dd, d + 24);
    snprintf(ds, sizeof ds, "%s", dd->str);
    pf_set_label(dd, "Destination Address: %s", ds); set_range(c, dd, d + 24, 16); }
  pf_set_label(ip, "Internet Protocol Version 6, Src: %s, Dst: %s", ss, ds);

  f = pf_add(ip, "ipv6.plen", PCAPNG_FT_UINT); pf_set_uint(f, be16(d + 4));
  pf_set_label(f, "Payload Length: %u", be16(d + 4)); set_range(c, f, d + 4, 2);
  f = pf_add(ip, "ipv6.nxt", PCAPNG_FT_UINT); pf_set_uint(f, nxt);
  pf_set_label(f, "Next Header: %s (%u)", ipproto_name(nxt), nxt); set_range(c, f, d + 6, 1);
  f = pf_add(ip, "ipv6.hlim", PCAPNG_FT_UINT); pf_set_uint(f, d[7]);
  pf_set_label(f, "Hop Limit: %u", d[7]); set_range(c, f, d + 7, 1);

  set_proto(c, "IPv6");
  set_src(c, ss);
  set_dst(c, ds);
  set_info(c, "%s", ipproto_name(nxt));

  {
    const uint8_t *pl = d + 40;
    int pll = len - 40;
    /* a .posa that claims this next-header wins over the built-in C */
    if (nxt != 6 && nxt != 17 && try_posa_ipproto(c, nxt, pl, pll, root)) return;
    switch (nxt) {
    case 6:  dissect_tcp(c, pl, pll, root); break;
    case 17: dissect_udp(c, pl, pll, root); break;
    case 58: { /* ICMPv6 — minimal */
      pcapng_field_t *ic = pf_add(root, "icmpv6", PCAPNG_FT_NONE);
      if (pll >= 2) {
        pcapng_field_t *t = pf_add(ic, "icmpv6.type", PCAPNG_FT_UINT); pf_set_uint(t, pl[0]);
        pf_set_label(t, "Type: %u", pl[0]);
      }
      pf_set_label(ic, "Internet Control Message Protocol v6");
      set_proto(c, "ICMPv6");
      break;
    }
    default: break;
    }
  }
}

/* ── ARP ────────────────────────────────────────────────────────────────── */
static void dissect_arp(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *a, *f;
  uint16_t op;
  char sip[16], dip[16], smac[24], dmac[24];

  if (len < 28) { set_proto(c, "ARP"); return; }
  op = be16(d + 6);
  snprintf(smac, sizeof smac, "%02x:%02x:%02x:%02x:%02x:%02x", d[8],d[9],d[10],d[11],d[12],d[13]);
  snprintf(sip,  sizeof sip,  "%u.%u.%u.%u", d[14], d[15], d[16], d[17]);
  snprintf(dmac, sizeof dmac, "%02x:%02x:%02x:%02x:%02x:%02x", d[18],d[19],d[20],d[21],d[22],d[23]);
  snprintf(dip,  sizeof dip,  "%u.%u.%u.%u", d[24], d[25], d[26], d[27]);

  a = pf_add(root, "arp", PCAPNG_FT_NONE);
  pf_set_label(a, "Address Resolution Protocol (%s)", op == 1 ? "request" : op == 2 ? "reply" : "?");
  set_range(c, a, d, 28);
  f = pf_add(a, "arp.opcode", PCAPNG_FT_UINT); pf_set_uint(f, op);
  pf_set_label(f, "Opcode: %u", op); set_range(c, f, d + 6, 2);
  f = pf_add(a, "arp.src.hw_mac", PCAPNG_FT_MAC); pf_set_mac(f, d + 8);
  pf_set_label(f, "Sender MAC address: %s", smac); set_range(c, f, d + 8, 6);
  f = pf_add(a, "arp.src.proto_ipv4", PCAPNG_FT_IPV4); pf_set_ipv4(f, d + 14);
  pf_set_label(f, "Sender IP address: %s", sip); set_range(c, f, d + 14, 4);
  f = pf_add(a, "arp.dst.hw_mac", PCAPNG_FT_MAC); pf_set_mac(f, d + 18);
  pf_set_label(f, "Target MAC address: %s", dmac); set_range(c, f, d + 18, 6);
  f = pf_add(a, "arp.dst.proto_ipv4", PCAPNG_FT_IPV4); pf_set_ipv4(f, d + 24);
  pf_set_label(f, "Target IP address: %s", dip); set_range(c, f, d + 24, 4);

  set_proto(c, "ARP");
  set_src(c, smac);
  set_dst(c, dmac);
  if (op == 1)      set_info(c, "Who has %s? Tell %s", dip, sip);
  else if (op == 2) set_info(c, "%s is at %s", sip, smac);
  else              set_info(c, "ARP opcode %u", op);
}

/* ── TCP ────────────────────────────────────────────────────────────────── */
static void dissect_tcp(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *t, *f;
  uint16_t sp, dp;
  uint8_t flags;
  int doff;
  char fs[40];

  if (len < 20) { set_proto(c, "TCP"); return; }
  sp = be16(d + 0);
  dp = be16(d + 2);
  doff = ((d[12] >> 4) & 0x0f) * 4;
  flags = d[13];

  fs[0] = '\0';
  if (flags & 0x02) strcat(fs, "SYN ");
  if (flags & 0x10) strcat(fs, "ACK ");
  if (flags & 0x01) strcat(fs, "FIN ");
  if (flags & 0x04) strcat(fs, "RST ");
  if (flags & 0x08) strcat(fs, "PSH ");
  if (flags & 0x20) strcat(fs, "URG ");
  if (fs[0]) fs[strlen(fs) - 1] = '\0';

  t = pf_add(root, "tcp", PCAPNG_FT_NONE);
  pf_set_label(t, "Transmission Control Protocol, Src Port: %u, Dst Port: %u", sp, dp);
  set_range(c, t, d, (doff >= 20 && doff <= len) ? doff : 20);
  f = pf_add(t, "tcp.srcport", PCAPNG_FT_UINT); pf_set_uint(f, sp);
  pf_set_label(f, "Source Port: %u", sp); set_range(c, f, d + 0, 2);
  f = pf_add(t, "tcp.dstport", PCAPNG_FT_UINT); pf_set_uint(f, dp);
  pf_set_label(f, "Destination Port: %u", dp); set_range(c, f, d + 2, 2);
  f = pf_add(t, "tcp.seq", PCAPNG_FT_UINT); pf_set_uint(f, be32(d + 4));
  pf_set_label(f, "Sequence Number: %u", be32(d + 4)); set_range(c, f, d + 4, 4);
  f = pf_add(t, "tcp.ack", PCAPNG_FT_UINT); pf_set_uint(f, be32(d + 8));
  pf_set_label(f, "Acknowledgment Number: %u", be32(d + 8)); set_range(c, f, d + 8, 4);
  f = pf_add(t, "tcp.hdr_len", PCAPNG_FT_UINT); pf_set_uint(f, doff);
  pf_set_label(f, "Header Length: %d bytes", doff); set_range(c, f, d + 12, 1);
  f = pf_add(t, "tcp.flags", PCAPNG_FT_UINT); pf_set_uint(f, flags);
  pf_set_label(f, "Flags: 0x%03x (%s)", flags, fs); set_range(c, f, d + 12, 2);
  /* Individual flag bits, as Wireshark names them. The display filter has no
     bitwise operator, so without these there is no way to ask "was this a
     reset?" — which is exactly what a coloring rule wants to say. */
  {
    static const struct { const char *ab; const char *name; unsigned bit; } TF[] = {
      { "tcp.flags.fin", "FIN",  0x001 }, { "tcp.flags.syn", "SYN", 0x002 },
      { "tcp.flags.reset", "RST", 0x004 }, { "tcp.flags.push", "PSH", 0x008 },
      { "tcp.flags.ack", "ACK",  0x010 }, { "tcp.flags.urg", "URG", 0x020 },
      { "tcp.flags.ece", "ECE",  0x040 }, { "tcp.flags.cwr", "CWR", 0x080 },
    };
    size_t k;
    for (k = 0; k < sizeof TF / sizeof TF[0]; k++) {
      pcapng_field_t *b = pf_add(f, TF[k].ab, PCAPNG_FT_UINT);
      unsigned on = (flags & TF[k].bit) ? 1u : 0u;
      pf_set_uint(b, on);
      pf_set_label(b, "%s: %u", TF[k].name, on);
      set_range(c, b, d + 12, 2);
    }
  }
  f = pf_add(t, "tcp.window_size", PCAPNG_FT_UINT); pf_set_uint(f, be16(d + 14));
  pf_set_label(f, "Window: %u", be16(d + 14)); set_range(c, f, d + 14, 2);
  f = pf_add(t, "tcp.checksum", PCAPNG_FT_UINT); pf_set_uint(f, be16(d + 16));
  pf_set_label(f, "Checksum: 0x%04x", be16(d + 16)); set_range(c, f, d + 16, 2);
  f = pf_add(t, "tcp.urgent_pointer", PCAPNG_FT_UINT); pf_set_uint(f, be16(d + 18));
  pf_set_label(f, "Urgent Pointer: %u", be16(d + 18)); set_range(c, f, d + 18, 2);

  /* TCP options: present when the data offset exceeds the 20-byte base header. */
  if (doff > 20 && doff <= len) {
    pcapng_field_t *opts = pf_add(t, "tcp.options", PCAPNG_FT_NONE);
    int o = 20;
    pf_set_label(opts, "Options (%d bytes)", doff - 20);
    set_range(c, opts, d + 20, doff - 20);
    while (o < doff) {
      uint8_t kind = d[o];
      if (kind == 0) {                                   /* End of Option List */
        pcapng_field_t *op = pf_add(opts, "tcp.options.eol", PCAPNG_FT_NONE);
        pf_set_label(op, "End of Option List (EOL)"); set_range(c, op, d + o, 1);
        break;
      } else if (kind == 1) {                            /* No-Operation       */
        pcapng_field_t *op = pf_add(opts, "tcp.options.nop", PCAPNG_FT_NONE);
        pf_set_label(op, "No-Operation (NOP)"); set_range(c, op, d + o, 1);
        o++;
      } else {                                           /* kind, length, data */
        int olen = (o + 1 < doff) ? d[o + 1] : 2;
        pcapng_field_t *op = pf_add(opts, "tcp.options.option", PCAPNG_FT_NONE);
        if (olen < 2) olen = 2;
        if (o + olen > doff) olen = doff - o;
        switch (kind) {
        case 2: pf_set_label(op, "Maximum Segment Size: %u",
                             (olen >= 4) ? be16(d + o + 2) : 0); break;
        case 3: pf_set_label(op, "Window Scale: %u (multiply by %u)",
                             (olen >= 3) ? d[o + 2] : 0,
                             (olen >= 3) ? (1u << d[o + 2]) : 1); break;
        case 4: pf_set_label(op, "SACK Permitted"); break;
        case 5: pf_set_label(op, "SACK (%d bytes)", olen); break;
        case 8: pf_set_label(op, "Timestamps: TSval %u, TSecr %u",
                             (olen >= 10) ? be32(d + o + 2) : 0,
                             (olen >= 10) ? be32(d + o + 6) : 0); break;
        default: pf_set_label(op, "Option: Kind %u, Length %d", kind, olen); break;
        }
        set_range(c, op, d + o, olen);
        o += olen;
      }
    }
  }

  set_proto(c, "TCP");
  set_info(c, "%u \xe2\x86\x92 %u [%s] Seq=%u Win=%u Len=%d",
           sp, dp, fs, be32(d + 4), be16(d + 14),
           len - doff > 0 ? len - doff : 0);

  if (doff < 20 || doff > len) doff = 20;
  {
    const uint8_t *pl = d + doff;
    int pll = len - doff;
    if (pll <= 0) return;
    if (try_posa_app(c, sp, dp, 6, pl, pll, root)) return;   /* posa-bound (e.g. RDP) */
#define TP(x) (sp == (x) || dp == (x))
    if      (TP(80) || TP(8080) || TP(8000) || TP(8888) || TP(3128))
                                     dissect_http(c, pl, pll, root);
    else if (TP(443) || TP(8443))    dissect_tls(c, pl, pll, root);
    else if (TP(22))                 dissect_ssh(c, pl, pll, root);
    else if (TP(21))                 dissect_text(c, pl, pll, root, "ftp", "FTP");
    else if (TP(25) || TP(587))      dissect_text(c, pl, pll, root, "smtp", "SMTP");
    else if (TP(110))                dissect_text(c, pl, pll, root, "pop", "POP");
    else if (TP(143))                dissect_text(c, pl, pll, root, "imap", "IMAP");
    else if (TP(23))                 dissect_text(c, pl, pll, root, "telnet", "Telnet");
    else if (TP(6667))               dissect_text(c, pl, pll, root, "irc", "IRC");
    else if (TP(6379))               dissect_text(c, pl, pll, root, "redis", "Redis");
    else if (TP(53) && pll > 2)      dissect_dns(c, pl + 2, pll - 2, root, "dns"); /* TCP DNS: 2-byte len prefix */
    else if (pll > 0)                dissect_data(c, pl, pll, root);  /* undissected payload */
#undef TP
  }
}

/* ── UDP ────────────────────────────────────────────────────────────────── */
static void dissect_udp(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *u, *f;
  uint16_t sp, dp, ln;

  if (len < 8) { set_proto(c, "UDP"); return; }
  sp = be16(d + 0);
  dp = be16(d + 2);
  ln = be16(d + 4);

  u = pf_add(root, "udp", PCAPNG_FT_NONE);
  pf_set_label(u, "User Datagram Protocol, Src Port: %u, Dst Port: %u", sp, dp);
  set_range(c, u, d, 8);
  f = pf_add(u, "udp.srcport", PCAPNG_FT_UINT); pf_set_uint(f, sp);
  pf_set_label(f, "Source Port: %u", sp); set_range(c, f, d + 0, 2);
  f = pf_add(u, "udp.dstport", PCAPNG_FT_UINT); pf_set_uint(f, dp);
  pf_set_label(f, "Destination Port: %u", dp); set_range(c, f, d + 2, 2);
  f = pf_add(u, "udp.length", PCAPNG_FT_UINT); pf_set_uint(f, ln);
  pf_set_label(f, "Length: %u", ln); set_range(c, f, d + 4, 2);
  f = pf_add(u, "udp.checksum", PCAPNG_FT_UINT); pf_set_uint(f, be16(d + 6));
  pf_set_label(f, "Checksum: 0x%04x", be16(d + 6)); set_range(c, f, d + 6, 2);

  set_proto(c, "UDP");
  set_info(c, "%u \xe2\x86\x92 %u  Len=%d", sp, dp, len - 8);

  {
    const uint8_t *pl = d + 8;
    int pll = len - 8;
    if (pll <= 0) return;
    if (try_posa_app(c, sp, dp, 17, pl, pll, root)) return;   /* posa-bound (by rule) */
#define UP(x) (sp == (x) || dp == (x))
    if      (UP(53))                 dissect_dns(c, pl, pll, root, "dns");
    else if (UP(5353))               dissect_dns(c, pl, pll, root, "mdns");
    else if (UP(5355))               dissect_dns(c, pl, pll, root, "llmnr");
    else if (UP(123))                dissect_ntp(c, pl, pll, root);
    else if (UP(67) || UP(68))       dissect_dhcp(c, pl, pll, root);
    else if (UP(137))                dissect_nbns(c, pl, pll, root);
    else if (UP(161) || UP(162))     dissect_snmp(c, pl, pll, root);
    else if (UP(1812)||UP(1813)||UP(1645)||UP(1646)) dissect_radius(c, pl, pll, root);
    else if (UP(514))                dissect_text(c, pl, pll, root, "syslog", "Syslog");
    else if (UP(443) || UP(80))      dissect_quic(c, pl, pll, root);  /* QUIC over UDP */
    else if (pll > 0)                dissect_data(c, pl, pll, root);  /* undissected payload */
#undef UP
  }
}

/* ── NTP (uses libpcapng's struct libpcapng_ntp_hdr for the wire layout) ──── */
static const char *ntp_mode_name(int m)
{
  switch (m) {
  case 1: return "symmetric active";
  case 2: return "symmetric passive";
  case 3: return "client";
  case 4: return "server";
  case 5: return "broadcast";
  case 6: return "control";
  case 7: return "private";
  default: return "reserved";
  }
}

static void dissect_ntp(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  const struct libpcapng_ntp_hdr *n = (const struct libpcapng_ntp_hdr *)d;
  pcapng_field_t *ntp, *f;
  int li, vn, mode;

  if (len < (int)sizeof *n) { set_proto(c, "NTP"); return; }
  li   = (n->li_vn_mode >> 6) & 0x3;
  vn   = (n->li_vn_mode >> 3) & 0x7;
  mode =  n->li_vn_mode       & 0x7;

  ntp = pf_add(root, "ntp", PCAPNG_FT_NONE);
  pf_set_label(ntp, "Network Time Protocol (NTPv%d, %s)", vn, ntp_mode_name(mode));
  set_range(c, ntp, d, len);

  f = pf_add(ntp, "ntp.flags", PCAPNG_FT_UINT); pf_set_uint(f, n->li_vn_mode);
  pf_set_label(f, "Flags: 0x%02x (Leap=%d, Version=%d, Mode=%d %s)",
                   n->li_vn_mode, li, vn, mode, ntp_mode_name(mode)); set_range(c, f, d + 0, 1);
  f = pf_add(ntp, "ntp.stratum", PCAPNG_FT_UINT); pf_set_uint(f, n->stratum);
  pf_set_label(f, "Peer Clock Stratum: %u", n->stratum); set_range(c, f, d + 1, 1);
  f = pf_add(ntp, "ntp.ppoll", PCAPNG_FT_UINT); pf_set_uint(f, n->poll);
  pf_set_label(f, "Peer Polling Interval: %u", n->poll); set_range(c, f, d + 2, 1);
  f = pf_add(ntp, "ntp.precision", PCAPNG_FT_UINT); pf_set_uint(f, (uint8_t)n->precision);
  pf_set_label(f, "Peer Clock Precision: %d", (int)n->precision); set_range(c, f, d + 3, 1);
  f = pf_add(ntp, "ntp.rootdelay", PCAPNG_FT_UINT); pf_set_uint(f, ntohl(n->root_delay));
  pf_set_label(f, "Root Delay: %u", ntohl(n->root_delay)); set_range(c, f, d + 4, 4);
  f = pf_add(ntp, "ntp.rootdispersion", PCAPNG_FT_UINT); pf_set_uint(f, ntohl(n->root_dispersion));
  pf_set_label(f, "Root Dispersion: %u", ntohl(n->root_dispersion)); set_range(c, f, d + 8, 4);
  f = pf_add(ntp, "ntp.refid", PCAPNG_FT_UINT); pf_set_uint(f, ntohl(n->ref_id));
  pf_set_label(f, "Reference ID: 0x%08x", ntohl(n->ref_id)); set_range(c, f, d + 12, 4);
  f = pf_add(ntp, "ntp.xmt", PCAPNG_FT_UINT); pf_set_uint(f, ntohl(n->tx_timestamp_secs));
  pf_set_label(f, "Transmit Timestamp (seconds): %u", ntohl(n->tx_timestamp_secs));
  if (len >= 44) set_range(c, f, d + 40, 4);

  set_proto(c, "NTP");
  set_info(c, "NTPv%d %s", vn, ntp_mode_name(mode));
}

/* ── ICMP ───────────────────────────────────────────────────────────────── */
static void dissect_icmp(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *ic, *f;
  if (len < 4) { set_proto(c, "ICMP"); return; }
  ic = pf_add(root, "icmp", PCAPNG_FT_NONE);
  pf_set_label(ic, "Internet Control Message Protocol");
  set_range(c, ic, d, len < 8 ? len : 8);
  f = pf_add(ic, "icmp.type", PCAPNG_FT_UINT); pf_set_uint(f, d[0]);
  pf_set_label(f, "Type: %u", d[0]); set_range(c, f, d + 0, 1);
  f = pf_add(ic, "icmp.code", PCAPNG_FT_UINT); pf_set_uint(f, d[1]);
  pf_set_label(f, "Code: %u", d[1]); set_range(c, f, d + 1, 1);
  f = pf_add(ic, "icmp.checksum", PCAPNG_FT_UINT); pf_set_uint(f, be16(d + 2));
  pf_set_label(f, "Checksum: 0x%04x", be16(d + 2)); set_range(c, f, d + 2, 2);
  set_proto(c, "ICMP");
  if      (d[0] == 8) set_info(c, "Echo (ping) request");
  else if (d[0] == 0) set_info(c, "Echo (ping) reply");
  else                set_info(c, "Type %u Code %u", d[0], d[1]);
}

/* ── DNS (header + first query name) ────────────────────────────────────── */
static int dns_name(const uint8_t *base, int len, int off, char *out, int outsz)
{
  int op = 0, jumped = 0, safety = 0;
  out[0] = '\0';
  while (off < len && base[off] && safety++ < 128) {
    int lab = base[off];
    if ((lab & 0xc0) == 0xc0) {           /* compression pointer */
      if (off + 1 >= len) break;
      if (!jumped) jumped = 1;
      off = ((lab & 0x3f) << 8) | base[off + 1];
      continue;
    }
    off++;
    if (op && op < outsz - 1) out[op++] = '.';
    while (lab-- > 0 && off < len && op < outsz - 1) out[op++] = (char)base[off++];
  }
  out[op] = '\0';
  return op;
}

static void dissect_dns(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root, const char *proto)
{
  pcapng_field_t *dns, *f;
  uint16_t id, flags, qd, an;
  char qname[256] = "";

  if (len < 12) { set_proto(c, "DNS"); return; }
  id = be16(d + 0); flags = be16(d + 2); qd = be16(d + 4); an = be16(d + 6);

  dns = pf_add(root, proto, PCAPNG_FT_NONE);
  pf_set_label(dns, "Domain Name System (%s)", (flags & 0x8000) ? "response" : "query");
  set_range(c, dns, d, len);
  f = pf_add(dns, "dns.id", PCAPNG_FT_UINT); pf_set_uint(f, id);
  pf_set_label(f, "Transaction ID: 0x%04x", id); set_range(c, f, d + 0, 2);
  f = pf_add(dns, "dns.flags", PCAPNG_FT_UINT); pf_set_uint(f, flags);
  pf_set_label(f, "Flags: 0x%04x", flags); set_range(c, f, d + 2, 2);
  f = pf_add(dns, "dns.count.queries", PCAPNG_FT_UINT); pf_set_uint(f, qd);
  pf_set_label(f, "Questions: %u", qd); set_range(c, f, d + 4, 2);
  f = pf_add(dns, "dns.count.answers", PCAPNG_FT_UINT); pf_set_uint(f, an);
  pf_set_label(f, "Answer RRs: %u", an); set_range(c, f, d + 6, 2);

  if (qd > 0) {
    int nlen = dns_name(d, len, 12, qname, sizeof qname);
    f = pf_add(dns, "dns.qry.name", PCAPNG_FT_STR); pf_set_str(f, qname);
    pf_set_label(f, "Query Name: %s", qname);
    /* label bytes span the encoded name (length octets + labels + root) */
    set_range(c, f, d + 12, nlen > 0 ? nlen + 2 : 1);
  }

  set_proto(c, "DNS");
  set_info(c, "%s 0x%04x %s", (flags & 0x8000) ? "response" : "query", id, qname);
}

/* ── small helpers ──────────────────────────────────────────────────────── */
static void printable_line(const uint8_t *d, int len, char *out, int outsz)
{
  int i = 0, o = 0;
  while (i < len && d[i] != '\n' && d[i] != '\r' && o < outsz - 1) {
    out[o++] = (d[i] >= 32 && d[i] < 127) ? (char)d[i] : '.';
    i++;
  }
  out[o] = '\0';
}

/* ── undissected payload (Wireshark's "Data") ───────────────────────────── */
static void dissect_data(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *dn, *f;
  char hex[51];
  int i, n, o = 0;
  if (len <= 0) return;
  dn = pf_add(root, "data", PCAPNG_FT_NONE);
  set_range(c, dn, d, len);
  pf_set_label(dn, "Data (%d byte%s)", len, len == 1 ? "" : "s");

  f = pf_add(dn, "data.len", PCAPNG_FT_UINT); pf_set_uint(f, len);
  pf_set_label(f, "Length: %d", len);

  n = len < 16 ? len : 16;
  for (i = 0; i < n; i++) o += snprintf(hex + o, sizeof hex - o, "%02x", d[i]);
  f = pf_add(dn, "data.data", PCAPNG_FT_BYTES); pf_set_bytes(f, d, len);
  set_range(c, f, d, len);
  pf_set_label(f, "Data: %s%s", hex, len > 16 ? "\xe2\x80\xa6" : "");
}

/* ── generic line-oriented text protocol (FTP/SMTP/POP/IMAP/Telnet/IRC/…) ── */
static void dissect_text(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root,
                         const char *abbrev, const char *name)
{
  pcapng_field_t *n, *f;
  char line[160], ab[PCAPNG_FIELD_ABBREV_MAX];
  if (len <= 0) { set_proto(c, name); return; }
  n = pf_add(root, abbrev, PCAPNG_FT_NONE);
  pf_set_label(n, "%s", name);
  set_range(c, n, d, len);
  printable_line(d, len, line, sizeof line);
  snprintf(ab, sizeof ab, "%s.line", abbrev);
  f = pf_add(n, ab, PCAPNG_FT_STR);
  pf_set_str(f, line);
  pf_set_label(f, "%s", line);
  set_proto(c, name);
  set_info(c, "%s", line[0] ? line : name);
}

/* ── HTTP (request/status line + headers) ───────────────────────────────── */
static void dissect_http(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *h, *f;
  char line[256];
  int i = 0, first = 1;

  h = pf_add(root, "http", PCAPNG_FT_NONE);
  pf_set_label(h, "Hypertext Transfer Protocol");
  set_range(c, h, d, len);
  set_proto(c, "HTTP");

  while (i < len) {
    int o = 0;
    while (i < len && d[i] != '\n' && o < (int)sizeof line - 1) {
      if (d[i] != '\r') line[o++] = (d[i] >= 32 && d[i] < 127) ? (char)d[i] : '.';
      i++;
    }
    if (i < len && d[i] == '\n') i++;
    line[o] = '\0';
    if (o == 0) break;                       /* blank line ends the headers */
    if (first) {
      int is_resp = (strncmp(line, "HTTP/", 5) == 0);
      first = 0;
      pf_set_label(h, "Hypertext Transfer Protocol (%s)", is_resp ? "response" : "request");
      f = pf_add(h, is_resp ? "http.response.line" : "http.request.line", PCAPNG_FT_STR);
      pf_set_str(f, line); pf_set_label(f, "%s", line);
      set_info(c, "%s", line);
    } else {
      f = pf_add(h, "http.header", PCAPNG_FT_STR);
      pf_set_str(f, line); pf_set_label(f, "%s", line);
    }
  }
}

/* ── TLS/SSL (record layer + handshake type + ClientHello SNI) ──────────── */
static const char *tls_ct_name(uint8_t ct)
{
  switch (ct) {
  case 20: return "Change Cipher Spec";
  case 21: return "Alert";
  case TLS_CONTENT_HANDSHAKE: return "Handshake";
  case TLS_CONTENT_APPDATA:   return "Application Data";
  case 24: return "Heartbeat";
  default: return "Unknown";
  }
}
static const char *tls_hs_name(uint8_t h)
{
  switch (h) {
  case 1:  return "Client Hello";
  case 2:  return "Server Hello";
  case 4:  return "New Session Ticket";
  case 11: return "Certificate";
  case 12: return "Server Key Exchange";
  case 13: return "Certificate Request";
  case 14: return "Server Hello Done";
  case 16: return "Client Key Exchange";
  case 20: return "Finished";
  default: return "Handshake Message";
  }
}
static const char *tls_ver_name(uint16_t v)
{
  switch (v) {
  case 0x0300: return "SSL 3.0";
  case 0x0301: return "TLS 1.0";
  case 0x0302: return "TLS 1.1";
  case 0x0303: return "TLS 1.2";
  case 0x0304: return "TLS 1.3";
  default: return "?";
  }
}
static void tls_extract_sni(const uint8_t *d, int len, char *out, int outsz)
{
  int p, extend, extlen;
  out[0] = '\0';
  if (len < 6 || d[5] != 1) return;          /* ClientHello only */
  p = 9 + 2 + 32;                            /* hs hdr + version + random */
  if (p >= len) return;
  p += 1 + d[p];                             /* session id */
  if (p + 2 > len) return;
  p += 2 + be16(d + p);                      /* cipher suites */
  if (p + 1 > len) return;
  p += 1 + d[p];                             /* compression methods */
  if (p + 2 > len) return;
  extlen = be16(d + p); p += 2;
  extend = p + extlen; if (extend > len) extend = len;
  while (p + 4 <= extend) {
    int et = be16(d + p), el = be16(d + p + 2);
    p += 4;
    if (et == 0) {                           /* server_name extension */
      if (p + 5 <= len) {
        int nl = be16(d + p + 3);
        if (p + 5 + nl <= len && nl < outsz) { memcpy(out, d + p + 5, (size_t)nl); out[nl] = '\0'; }
      }
      return;
    }
    p += el;
  }
}
static void dissect_tls(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *t, *f;
  uint8_t ct;
  uint16_t ver, rl;
  if (len < 5) { set_proto(c, "TLS"); return; }
  ct = d[0]; ver = be16(d + 1); rl = be16(d + 3);
  if (ct < 20 || ct > 24) { set_proto(c, "TLS"); return; }  /* mid-stream / not a record */

  t = pf_add(root, "tls", PCAPNG_FT_NONE);
  pf_set_label(t, "Transport Layer Security (%s, %s)", tls_ver_name(ver), tls_ct_name(ct));
  set_range(c, t, d, len);
  f = pf_add(t, "tls.record.content_type", PCAPNG_FT_UINT); pf_set_uint(f, ct);
  pf_set_label(f, "Content Type: %s (%u)", tls_ct_name(ct), ct); set_range(c, f, d, 1);
  f = pf_add(t, "tls.record.version", PCAPNG_FT_UINT); pf_set_uint(f, ver);
  pf_set_label(f, "Version: %s (0x%04x)", tls_ver_name(ver), ver); set_range(c, f, d + 1, 2);
  f = pf_add(t, "tls.record.length", PCAPNG_FT_UINT); pf_set_uint(f, rl);
  pf_set_label(f, "Length: %u", rl); set_range(c, f, d + 3, 2);
  set_proto(c, "TLS");

  if (ct == TLS_CONTENT_HANDSHAKE && len >= 6) {
    uint8_t hs = d[5];
    f = pf_add(t, "tls.handshake.type", PCAPNG_FT_UINT); pf_set_uint(f, hs);
    pf_set_label(f, "Handshake Type: %s (%u)", tls_hs_name(hs), hs); set_range(c, f, d + 5, 1);
    if (hs == 1) {
      char sni[128];
      tls_extract_sni(d, len, sni, sizeof sni);
      if (sni[0]) {
        f = pf_add(t, "tls.handshake.extensions_server_name", PCAPNG_FT_STR);
        pf_set_str(f, sni); pf_set_label(f, "Server Name: %s", sni);
        set_info(c, "Client Hello (SNI=%s)", sni);
      } else set_info(c, "Client Hello");
    } else set_info(c, "%s", tls_hs_name(hs));
  } else {
    /* non-handshake record (Application Data / Alert / ChangeCipherSpec): show
       the record body as a field so it maps to the trailing bytes, like
       Wireshark's "Encrypted Application Data". */
    int avail = len - 5;
    int bodylen = (rl < avail) ? rl : avail;
    if (bodylen > 0) {
      char hex[51]; int i, hn, o = 0;
      const char *ab = (ct == TLS_CONTENT_APPDATA) ? "tls.app_data" : "tls.record.fragment";
      f = pf_add(t, ab, PCAPNG_FT_BYTES);
      pf_set_bytes(f, d + 5, bodylen);
      set_range(c, f, d + 5, bodylen);
      hn = bodylen < 16 ? bodylen : 16;
      for (i = 0; i < hn; i++) o += snprintf(hex + o, sizeof hex - o, "%02x", d[5 + i]);
      pf_set_label(f, "%s: %s%s",
                   (ct == TLS_CONTENT_APPDATA) ? "Encrypted Application Data" : "Fragment",
                   hex, bodylen > 16 ? "\xe2\x80\xa6" : "");
    }
    set_info(c, "%s", tls_ct_name(ct));
  }
}

/* ── SSH (banner line or binary packet) ─────────────────────────────────── */
static void dissect_ssh(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *s, *f;
  s = pf_add(root, "ssh", PCAPNG_FT_NONE);
  pf_set_label(s, "SSH Protocol");
  set_range(c, s, d, len);
  set_proto(c, "SSH");
  if (len >= 4 && memcmp(d, "SSH-", 4) == 0) {
    char line[128];
    printable_line(d, len, line, sizeof line);
    f = pf_add(s, "ssh.protocol", PCAPNG_FT_STR); pf_set_str(f, line);
    pf_set_label(f, "Protocol: %s", line);
    set_range(c, f, d, (int)strlen(line));
    set_info(c, "%s", line);
  } else if (len >= 4) {
    uint32_t plen = be32(d);
    f = pf_add(s, "ssh.packet_length", PCAPNG_FT_UINT); pf_set_uint(f, plen);
    pf_set_label(f, "Packet Length: %u", plen);
    set_range(c, f, d, 4);
    set_info(c, "Encrypted packet (len=%u)", plen);
  }
}

/* ── IGMP ───────────────────────────────────────────────────────────────── */
static const char *igmp_type(uint8_t t)
{
  switch (t) {
  case 0x11: return "Membership Query";
  case 0x12: return "v1 Membership Report";
  case 0x16: return "v2 Membership Report";
  case 0x17: return "Leave Group";
  case 0x22: return "v3 Membership Report";
  default:   return "IGMP";
  }
}
static void dissect_igmp(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *g, *f;
  if (len < 8) { set_proto(c, "IGMP"); return; }
  g = pf_add(root, "igmp", PCAPNG_FT_NONE);
  pf_set_label(g, "Internet Group Management Protocol");
  set_range(c, g, d, len);
  f = pf_add(g, "igmp.type", PCAPNG_FT_UINT); pf_set_uint(f, d[0]);
  pf_set_label(f, "Type: %s (0x%02x)", igmp_type(d[0]), d[0]);
  set_range(c, f, d + 0, 1);
  f = pf_add(g, "igmp.max_resp", PCAPNG_FT_UINT); pf_set_uint(f, d[1]);
  pf_set_label(f, "Max Resp Time: %u", d[1]);
  set_range(c, f, d + 1, 1);
  f = pf_add(g, "igmp.checksum", PCAPNG_FT_UINT); pf_set_uint(f, be16(d + 2));
  pf_set_label(f, "Checksum: 0x%04x", be16(d + 2));
  set_range(c, f, d + 2, 2);
  /* A v3 membership report has no group address here — bytes 6..7 are the number
     of group records that follow, so only claim an address for the layouts that
     actually carry one. */
  if (d[0] != 0x22) {
    f = pf_add(g, "igmp.maddr", PCAPNG_FT_IPV4); pf_set_ipv4(f, d + 4);
    pf_set_label(f, "Multicast Address: %s", f->str);
    set_range(c, f, d + 4, 4);
  } else {
    f = pf_add(g, "igmp.num_grp_recs", PCAPNG_FT_UINT); pf_set_uint(f, be16(d + 6));
    pf_set_label(f, "Num Group Records: %u", be16(d + 6));
    set_range(c, f, d + 6, 2);
  }
  set_proto(c, "IGMP");
  set_info(c, "%s", igmp_type(d[0]));
}

/* ── GRE ────────────────────────────────────────────────────────────────── */
static void dissect_gre(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *g, *f;
  uint16_t flags, proto;
  if (len < 4) { set_proto(c, "GRE"); return; }
  flags = be16(d); proto = be16(d + 2);
  g = pf_add(root, "gre", PCAPNG_FT_NONE);
  pf_set_label(g, "Generic Routing Encapsulation");
  set_range(c, g, d, len < 4 ? len : 4);
  f = pf_add(g, "gre.flags_and_version", PCAPNG_FT_UINT); pf_set_uint(f, flags);
  pf_set_label(f, "Flags and Version: 0x%04x", flags);
  set_range(c, f, d + 0, 2);
  f = pf_add(g, "gre.proto", PCAPNG_FT_UINT); pf_set_uint(f, proto);
  pf_set_label(f, "Protocol Type: 0x%04x", proto);
  set_range(c, f, d + 2, 2);
  set_proto(c, "GRE");
  set_info(c, "Encapsulated 0x%04x", proto);
  if (flags == 0 && len > 4) dissect_l3(c, proto, d + 4, len - 4, root);  /* no optional fields */
}

/* ── DHCP / BOOTP (uses libpcapng's struct libpcapng_bootp_hdr) ─────────── */
static const char *dhcp_msgtype(uint8_t t)
{
  switch (t) {
  case 1: return "Discover"; case 2: return "Offer";  case 3: return "Request";
  case 4: return "Decline";  case 5: return "ACK";    case 6: return "NAK";
  case 7: return "Release";  case 8: return "Inform";
  default: return "?";
  }
}
static void dissect_dhcp(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  const struct libpcapng_bootp_hdr *b = (const struct libpcapng_bootp_hdr *)d;
  pcapng_field_t *dh, *f;
  int off;
  uint8_t msgtype = 0;
  if (len < 236) { set_proto(c, "DHCP"); return; }

  dh = pf_add(root, "dhcp", PCAPNG_FT_NONE);
  set_range(c, dh, d, len);
  f = pf_add(dh, "dhcp.op", PCAPNG_FT_UINT); pf_set_uint(f, b->op);
  pf_set_label(f, "Message op code: %s (%u)",
                   b->op == 1 ? "Boot Request" : b->op == 2 ? "Boot Reply" : "?", b->op);
  f = pf_add(dh, "dhcp.id", PCAPNG_FT_UINT); pf_set_uint(f, ntohl(b->xid));
  pf_set_label(f, "Transaction ID: 0x%08x", ntohl(b->xid));
  f = pf_add(dh, "dhcp.ip.client", PCAPNG_FT_IPV4); pf_set_ipv4(f, (const uint8_t *)&b->ciaddr);
  pf_set_label(f, "Client IP address: %s", f->str);
  f = pf_add(dh, "dhcp.ip.your", PCAPNG_FT_IPV4); pf_set_ipv4(f, (const uint8_t *)&b->yiaddr);
  pf_set_label(f, "Your (client) IP address: %s", f->str);
  f = pf_add(dh, "dhcp.ip.server", PCAPNG_FT_IPV4); pf_set_ipv4(f, (const uint8_t *)&b->siaddr);
  pf_set_label(f, "Next server IP address: %s", f->str);
  f = pf_add(dh, "dhcp.hw.mac_addr", PCAPNG_FT_MAC); pf_set_mac(f, b->chaddr);
  pf_set_label(f, "Client MAC address: %s", f->str);

  off = 236;
  if (off + 4 <= len && d[off] == 0x63 && d[off+1] == 0x82 && d[off+2] == 0x53 && d[off+3] == 0x63) {
    off += 4;
    while (off < len) {
      uint8_t code = d[off++], ol;
      if (code == 0xff) break;          /* end */
      if (code == 0x00) continue;       /* pad */
      if (off >= len) break;
      ol = d[off++];
      if (off + ol > len) break;
      if (code == 53 && ol >= 1) {
        msgtype = d[off];
        f = pf_add(dh, "dhcp.option.dhcp", PCAPNG_FT_UINT); pf_set_uint(f, msgtype);
        pf_set_label(f, "DHCP Message Type: %s (%u)", dhcp_msgtype(msgtype), msgtype);
      }
      off += ol;
    }
  }
  pf_set_label(dh, "Dynamic Host Configuration Protocol (%s)",
                   msgtype ? dhcp_msgtype(msgtype) : (b->op == 1 ? "Request" : "Reply"));
  set_proto(c, "DHCP");
  if (msgtype) set_info(c, "DHCP %s", dhcp_msgtype(msgtype));
  else         set_info(c, "BOOTP %s", b->op == 1 ? "Request" : "Reply");
}

/* ── NBNS (NetBIOS Name Service header) ─────────────────────────────────── */
static void dissect_nbns(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *n, *f;
  uint16_t id, flags, qd;
  if (len < 12) { set_proto(c, "NBNS"); return; }
  id = be16(d); flags = be16(d + 2); qd = be16(d + 4);
  n = pf_add(root, "nbns", PCAPNG_FT_NONE);
  pf_set_label(n, "NetBIOS Name Service");
  set_range(c, n, d, len);
  f = pf_add(n, "nbns.id", PCAPNG_FT_UINT); pf_set_uint(f, id);
  pf_set_label(f, "Transaction ID: 0x%04x", id);
  set_range(c, f, d + 0, 2);
  f = pf_add(n, "nbns.flags", PCAPNG_FT_UINT); pf_set_uint(f, flags);
  pf_set_label(f, "Flags: 0x%04x", flags);
  set_range(c, f, d + 2, 2);
  f = pf_add(n, "nbns.count.queries", PCAPNG_FT_UINT); pf_set_uint(f, qd);
  pf_set_label(f, "Questions: %u", qd);
  set_range(c, f, d + 4, 2);
  set_proto(c, "NBNS");
  set_info(c, "%s 0x%04x", (flags & 0x8000) ? "response" : "query", id);
}

/* ── SNMP (minimal ASN.1: version + community) ──────────────────────────── */
static long asn1_len(const uint8_t *d, int len, int *off)
{
  int l;
  if (*off >= len) return -1;
  l = d[(*off)++];
  if (l & 0x80) { int n = l & 0x7f; l = 0; while (n-- > 0 && *off < len) l = (l << 8) | d[(*off)++]; }
  return l;
}
static const char *snmp_ver(long v)
{ return v == 0 ? "v1" : v == 1 ? "v2c" : v == 3 ? "v3" : "?"; }
static void dissect_snmp(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *s, *f;
  int off = 0, i;
  long version = -1;
  char comm[128] = "";
  int voff = 0, vlen = 0, coff = 0, clen = 0;   /* where each value sat on the wire */
  if (len < 2 || d[0] != 0x30) { set_proto(c, "SNMP"); return; }
  off = 1; (void)asn1_len(d, len, &off);             /* sequence length */
  if (off < len && d[off] == 0x02) {                 /* version INTEGER */
    long vl, v = 0;
    off++; vl = asn1_len(d, len, &off);
    voff = off; vlen = (int)vl;
    for (i = 0; i < vl && off < len; i++) v = (v << 8) | d[off++];
    version = v;
  }
  if (off < len && d[off] == 0x04) {                 /* community OCTET STRING */
    long cl; int o = 0;
    off++; cl = asn1_len(d, len, &off);
    coff = off; clen = (int)cl;
    for (i = 0; i < cl && off < len && o < (int)sizeof comm - 1; i++, off++)
      comm[o++] = (d[off] >= 32 && d[off] < 127) ? (char)d[off] : '.';
    comm[o] = '\0';
  }
  s = pf_add(root, "snmp", PCAPNG_FT_NONE);
  pf_set_label(s, "Simple Network Management Protocol");
  set_range(c, s, d, len);
  if (version >= 0) {
    f = pf_add(s, "snmp.version", PCAPNG_FT_UINT); pf_set_uint(f, (uint64_t)version);
    pf_set_label(f, "version: %s (%ld)", snmp_ver(version), version);
    set_range(c, f, d + voff, vlen);
  }
  if (comm[0]) {
    f = pf_add(s, "snmp.community", PCAPNG_FT_STR); pf_set_str(f, comm);
    pf_set_label(f, "community: %s", comm);
    set_range(c, f, d + coff, clen);
  }
  set_proto(c, "SNMP");
  set_info(c, "%s%s%s", snmp_ver(version), comm[0] ? " community=" : "", comm);
}

/* ── RADIUS ─────────────────────────────────────────────────────────────── */
static const char *radius_code(uint8_t code)
{
  switch (code) {
  case 1:  return "Access-Request";   case 2:  return "Access-Accept";
  case 3:  return "Access-Reject";    case 4:  return "Accounting-Request";
  case 5:  return "Accounting-Response"; case 11: return "Access-Challenge";
  default: return "RADIUS";
  }
}
static void dissect_radius(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *r, *f;
  if (len < 4) { set_proto(c, "RADIUS"); return; }
  r = pf_add(root, "radius", PCAPNG_FT_NONE);
  pf_set_label(r, "RADIUS Protocol");
  set_range(c, r, d, len);
  f = pf_add(r, "radius.code", PCAPNG_FT_UINT); pf_set_uint(f, d[0]);
  pf_set_label(f, "Code: %s (%u)", radius_code(d[0]), d[0]);
  set_range(c, f, d + 0, 1);
  f = pf_add(r, "radius.id", PCAPNG_FT_UINT); pf_set_uint(f, d[1]);
  pf_set_label(f, "Identifier: %u", d[1]);
  set_range(c, f, d + 1, 1);
  f = pf_add(r, "radius.length", PCAPNG_FT_UINT); pf_set_uint(f, be16(d + 2));
  pf_set_label(f, "Length: %u", be16(d + 2));
  set_range(c, f, d + 2, 2);
  set_proto(c, "RADIUS");
  set_info(c, "%s id=%u", radius_code(d[0]), d[1]);
}

/* ── QUIC (IETF; headers only — payload is encrypted) ───────────────────── */
static const char *quic_lpt(uint8_t t)
{
  switch (t) {
  case 0: return "Initial"; case 1: return "0-RTT";
  case 2: return "Handshake"; case 3: return "Retry";
  default: return "?";
  }
}
static void dissect_quic(dctx_t *c, const uint8_t *d, int len, pcapng_field_t *root)
{
  pcapng_field_t *q, *f;
  uint8_t b0;
  if (len < 1) { set_proto(c, "QUIC"); return; }
  b0 = d[0];
  /* Heuristic guard: a long header has the high two bits set (0xC0); a short
     header has 0x40 set and 0x80 clear. Anything else isn't QUIC v1-ish —
     surface the bytes as a Data node so they stay selectable. */
  if (!(b0 & 0x40)) { set_proto(c, "QUIC"); dissect_data(c, d, len, root); return; }

  q = pf_add(root, "quic", PCAPNG_FT_NONE);
  set_range(c, q, d, len);
  set_proto(c, "QUIC");

  if (b0 & 0x80) {                              /* long header */
    uint32_t ver;
    uint8_t pt = (b0 >> 4) & 0x03;
    int off, dl, sl;
    pf_set_label(q, "QUIC IETF (long header)");
    f = pf_add(q, "quic.header_form", PCAPNG_FT_UINT); pf_set_uint(f, 1);
    pf_set_label(f, "Header Form: Long Header (1)");
    if (len < 6) { set_info(c, "QUIC long header"); return; }
    ver = be32(d + 1);
    f = pf_add(q, "quic.version", PCAPNG_FT_UINT); pf_set_uint(f, ver);
    pf_set_label(f, "Version: 0x%08x", ver);
    f = pf_add(q, "quic.long.packet_type", PCAPNG_FT_UINT); pf_set_uint(f, pt);
    pf_set_label(f, "Packet Type: %s (%u)", ver == 0 ? "Version Negotiation" : quic_lpt(pt), pt);
    off = 5;
    dl = d[off++];
    if (off + dl <= len) {
      f = pf_add(q, "quic.dcid", PCAPNG_FT_BYTES); pf_set_bytes(f, d + off, dl);
      pf_set_label(f, "Destination Connection ID: %d bytes", dl);
      off += dl;
    }
    if (off < len) {
      sl = d[off++];
      if (off + sl <= len) {
        f = pf_add(q, "quic.scid", PCAPNG_FT_BYTES); pf_set_bytes(f, d + off, sl);
        pf_set_label(f, "Source Connection ID: %d bytes", sl);
        off += sl;
      }
    }
    set_info(c, "QUIC %s", ver == 0 ? "Version Negotiation" : quic_lpt(pt));
    if (off < len) dissect_data(c, d + off, len - off, q);  /* token/length/PN/payload */
  } else {                                      /* short header (1-RTT) */
    pf_set_label(q, "QUIC IETF (short header, protected)");
    f = pf_add(q, "quic.header_form", PCAPNG_FT_UINT); pf_set_uint(f, 0);
    pf_set_label(f, "Header Form: Short Header (0)");
    set_info(c, "QUIC protected payload");
    if (len > 1) dissect_data(c, d + 1, len - 1, q);  /* protected 1-RTT payload */
  }
}

/* ── linktype entry ─────────────────────────────────────────────────────── */
static pcapng_field_t *do_dissect(const uint8_t *data, uint32_t caplen, uint32_t origlen,
                                  uint16_t linktype, pcapng_dissection_t *sum)
{
  dctx_t c;
  pcapng_field_t *root = pf_new("", PCAPNG_FT_NONE);
  const uint8_t *d = data;
  int len = (int)caplen;
  posa_ensure_builtin();           /* load bundled posa decoders (RDP, …) once */
  c.sum = sum;
  c.base = data;
  if (!root) return NULL;

  dissect_frame(&c, data, caplen, origlen, root);
  set_proto(&c, "?");
  set_info(&c, "");

  switch (linktype) {
  case LINKTYPE_ETHERNET:
    dissect_ethernet(&c, d, len, root);
    break;
  case LINKTYPE_RAW:
  case LINKTYPE_IPV4:
    if (len > 0 && (d[0] >> 4) == 6) dissect_ipv6(&c, d, len, root);
    else                             dissect_ipv4(&c, d, len, root);
    break;
  case LINKTYPE_IPV6:
    dissect_ipv6(&c, d, len, root);
    break;
  case LINKTYPE_NULL:
    /* 4-byte address-family header, host byte order; 2 = AF_INET */
    if (len >= 4) {
      uint32_t af = (uint32_t)d[0] | ((uint32_t)d[1] << 8) |
                    ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 24);
      if (af == 2)               dissect_ipv4(&c, d + 4, len - 4, root);
      else if (af == 24 || af == 30 || af == 28) dissect_ipv6(&c, d + 4, len - 4, root);
    }
    break;
  case LINKTYPE_LINUX_SLL:
    if (len >= 16) dissect_l3(&c, be16(d + 14), d + 16, len - 16, root);
    break;
  default:
    /* Unknown link layer: best-effort treat as raw IP. */
    if (len > 0 && (d[0] >> 4) == 4) dissect_ipv4(&c, d, len, root);
    break;
  }
  return root;
}

/* ── public entry point ─────────────────────────────────────────────────── */
pcapng_dissection_t *pcapng_dissect(const uint8_t *data, uint32_t caplen,
                                    uint32_t origlen, uint16_t linktype)
{
  pcapng_dissection_t *d = calloc(1, sizeof *d);
  if (!d) return NULL;
  if (!origlen) origlen = caplen;
  d->root = do_dissect(data, caplen, origlen, linktype, d);
  if (!d->root) { free(d); return NULL; }
  return d;
}

void pcapng_dissection_free(pcapng_dissection_t *d)
{
  if (!d) return;
  pcapng_field_free(d->root);
  free(d);
}

/* ── introspection: protocols this dissector emits ──────────────────────── */
const char *const *pcapng_dissect_protocols(int *count)
{
  static const char *const P[] = {
    "frame","eth","vlan","ip","ipv6","arp","tcp","udp","icmp","icmpv6",
    "igmp","gre","dns","mdns","llmnr","nbns","ntp","dhcp","snmp","radius",
    "syslog","tls","ssh","http","ftp","smtp","pop","imap","telnet","irc",
    "redis","quic","data"
  };
  if (count) *count = (int)(sizeof P / sizeof P[0]);
  return P;
}
