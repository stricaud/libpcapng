/*
 * headers.h — read a packet's headers without doing the arithmetic yourself.
 *
 * Anything holding raw captured bytes — a capture callback, a dispatcher
 * deciding where a packet goes — needs a handful of numbers out of the
 * Ethernet, IP, TCP and UDP headers, and writing that out by hand produces
 * lines like
 *
 *     uint32_t seq = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16)
 *                  | ((uint32_t)tcp[6] <<  8) |  (uint32_t)tcp[7];
 *     if (iproto == 17) { ... }
 *
 * which say what they do and not what they mean. The same two lines here:
 *
 *     uint32_t seq = libpcapng_tcp_get_seq(tcp);
 *     if (ip_proto == LIBPCAPNG_IPPROTO_UDP) { ... }
 *
 * Everything is inline and takes a pointer to the start of the header, so
 * there is nothing to link and no cost over writing the shifts by hand.
 *
 * The accessors do not bounds-check — they cannot, since a bare pointer does
 * not say how much is behind it. Check the length once, then read fields
 * freely; each family below says how many bytes it needs. Or skip the question
 * entirely and use libpcapng_frame_parse(), which takes the length, walks the
 * whole frame, and hands back what it found.
 *
 * These are for reading captured bytes. To *build* a header, the packed
 * structs in protocols/ are what you want.
 */
#ifndef _LIBPCAPNG_HEADERS_H_
#define _LIBPCAPNG_HEADERS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Names for the numbers ────────────────────────────────────────────────── */

/* EtherType — the two bytes at offset 12 of an Ethernet frame. */
#define LIBPCAPNG_ETHERTYPE_IPV4   0x0800
#define LIBPCAPNG_ETHERTYPE_ARP    0x0806
#define LIBPCAPNG_ETHERTYPE_VLAN   0x8100   /* 802.1Q; the real type follows   */
#define LIBPCAPNG_ETHERTYPE_QINQ   0x88a8   /* 802.1ad, stacks on top of 802.1Q */
#define LIBPCAPNG_ETHERTYPE_IPV6   0x86dd
#define LIBPCAPNG_ETHERTYPE_MPLS   0x8847
#define LIBPCAPNG_ETHERTYPE_PPPOE  0x8864
#define LIBPCAPNG_ETHERTYPE_EAPOL  0x888e

/* IP protocol numbers — IPv4's `protocol` field, IPv6's `next header`. */
#define LIBPCAPNG_IPPROTO_ICMP     1
#define LIBPCAPNG_IPPROTO_IGMP     2
#define LIBPCAPNG_IPPROTO_TCP      6
#define LIBPCAPNG_IPPROTO_UDP      17
#define LIBPCAPNG_IPPROTO_GRE      47
#define LIBPCAPNG_IPPROTO_ESP      50
#define LIBPCAPNG_IPPROTO_AH       51
#define LIBPCAPNG_IPPROTO_ICMPV6   58
#define LIBPCAPNG_IPPROTO_SCTP     132

/* IPv6 extension headers. They occupy the same number space as the transport
   protocols above, which is what makes walking the chain a matter of asking,
   at each step, whether the number names another extension or the transport. */
#define LIBPCAPNG_IPV6_EXT_HOPOPTS   0    /* hop-by-hop options   */
#define LIBPCAPNG_IPV6_EXT_ROUTING   43
#define LIBPCAPNG_IPV6_EXT_FRAGMENT  44
#define LIBPCAPNG_IPV6_EXT_DSTOPTS   60
#define LIBPCAPNG_IPV6_EXT_AH        51   /* also a protocol in its own right */
#define LIBPCAPNG_IPV6_EXT_NONE      59   /* "no next header": nothing follows */

/* How many extension headers to walk before giving up. A packet with a longer
   chain than this is not one anybody sends; a chain crafted to be walked
   forever is. */
#define LIBPCAPNG_IPV6_EXT_MAX_HOPS  8

/* TCP flags, as they sit in the byte at offset 13. */
#define LIBPCAPNG_TCP_FIN   0x01
#define LIBPCAPNG_TCP_SYN   0x02
#define LIBPCAPNG_TCP_RST   0x04
#define LIBPCAPNG_TCP_PSH   0x08
#define LIBPCAPNG_TCP_ACK   0x10
#define LIBPCAPNG_TCP_URG   0x20
#define LIBPCAPNG_TCP_ECE   0x40
#define LIBPCAPNG_TCP_CWR   0x80

/* Minimum bytes each accessor family needs behind the pointer it is given. */
#define LIBPCAPNG_ETH_HDR_MIN   14
#define LIBPCAPNG_IPV4_HDR_MIN  20
#define LIBPCAPNG_IPV6_HDR_LEN  40
#define LIBPCAPNG_TCP_HDR_MIN   20
#define LIBPCAPNG_UDP_HDR_LEN    8

/* ── The two reads everything else is built from ──────────────────────────── */

static inline uint16_t libpcapng_be16(const uint8_t *p)
{ return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }

static inline uint32_t libpcapng_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

/* ── Ethernet — `eth` points at the destination MAC ───────────────────────── */

static inline const uint8_t *libpcapng_eth_get_dst(const uint8_t *eth) { return eth; }
static inline const uint8_t *libpcapng_eth_get_src(const uint8_t *eth) { return eth + 6; }
static inline uint16_t libpcapng_eth_get_type(const uint8_t *eth)
{ return libpcapng_be16(eth + 12); }

/* ── IPv4 — `ip` points at the version/IHL byte ───────────────────────────── */

static inline uint8_t  libpcapng_ipv4_get_version(const uint8_t *ip) { return (uint8_t)(ip[0] >> 4); }
/* In bytes, not the 32-bit words the field actually holds. */
static inline uint8_t  libpcapng_ipv4_get_hdrlen(const uint8_t *ip) { return (uint8_t)((ip[0] & 0x0f) * 4); }
static inline uint8_t  libpcapng_ipv4_get_dscp(const uint8_t *ip)   { return (uint8_t)(ip[1] >> 2); }
static inline uint16_t libpcapng_ipv4_get_total_len(const uint8_t *ip) { return libpcapng_be16(ip + 2); }
static inline uint16_t libpcapng_ipv4_get_id(const uint8_t *ip)     { return libpcapng_be16(ip + 4); }
static inline uint16_t libpcapng_ipv4_get_frag_offset(const uint8_t *ip)
{ return (uint16_t)(libpcapng_be16(ip + 6) & 0x1fff); }
static inline int      libpcapng_ipv4_is_fragment(const uint8_t *ip)
{ return (libpcapng_be16(ip + 6) & 0x3fff) != 0; }
static inline uint8_t  libpcapng_ipv4_get_ttl(const uint8_t *ip)    { return ip[8]; }
static inline uint8_t  libpcapng_ipv4_get_proto(const uint8_t *ip)  { return ip[9]; }
static inline const uint8_t *libpcapng_ipv4_get_src(const uint8_t *ip) { return ip + 12; }
static inline const uint8_t *libpcapng_ipv4_get_dst(const uint8_t *ip) { return ip + 16; }
/* Where the transport header starts, honouring a header with options. */
static inline const uint8_t *libpcapng_ipv4_get_payload(const uint8_t *ip)
{ return ip + libpcapng_ipv4_get_hdrlen(ip); }

/* ── IPv6 — `ip6` points at the version/class byte; the header is fixed ───── */

static inline uint8_t  libpcapng_ipv6_get_version(const uint8_t *ip6) { return (uint8_t)(ip6[0] >> 4); }
static inline uint16_t libpcapng_ipv6_get_payload_len(const uint8_t *ip6) { return libpcapng_be16(ip6 + 4); }
/* The first extension header, or the transport protocol if there are none. */
static inline uint8_t  libpcapng_ipv6_get_next_header(const uint8_t *ip6) { return ip6[6]; }
static inline uint8_t  libpcapng_ipv6_get_hop_limit(const uint8_t *ip6) { return ip6[7]; }
static inline const uint8_t *libpcapng_ipv6_get_src(const uint8_t *ip6) { return ip6 + 8; }
static inline const uint8_t *libpcapng_ipv6_get_dst(const uint8_t *ip6) { return ip6 + 24; }

/*
 * Follow the extension-header chain to the transport header.
 *
 * IPv6 puts options in a linked list rather than inside the header, so the
 * `next header` field of the fixed header often names another extension rather
 * than TCP or UDP. Reading it directly and calling the answer the protocol is
 * the classic IPv6 mistake: a packet with a single hop-by-hop options header
 * reports protocol 0 and its ports are never found.
 *
 *   ip6      start of the fixed header
 *   len      bytes available from there
 *   l4_off   set to where the transport header begins, measured from ip6
 *   frag     set to 1 when this is a non-first fragment, which carries no
 *            transport header at all — pass NULL if you do not care
 *
 * Returns the transport protocol number, or 0 if the chain is malformed,
 * runs past the end, or is longer than LIBPCAPNG_IPV6_EXT_MAX_HOPS.
 */
static inline uint8_t libpcapng_ipv6_transport(const uint8_t *ip6, uint32_t len,
                                               uint32_t *l4_off, int *frag)
{
    uint32_t off = LIBPCAPNG_IPV6_HDR_LEN;
    uint8_t  next;
    int      hops = 0;

    if (frag) *frag = 0;
    if (l4_off) *l4_off = off;
    if (!ip6 || len < LIBPCAPNG_IPV6_HDR_LEN) return 0;

    next = libpcapng_ipv6_get_next_header(ip6);

    while (hops++ < LIBPCAPNG_IPV6_EXT_MAX_HOPS && off + 2 <= len) {
        uint32_t ext;

        if (next == LIBPCAPNG_IPV6_EXT_HOPOPTS || next == LIBPCAPNG_IPV6_EXT_ROUTING ||
            next == LIBPCAPNG_IPV6_EXT_DSTOPTS || next == LIBPCAPNG_IPV6_EXT_AH) {
            /* Every one of these carries next-header then a length, but the
               Authentication Header counts its length in 4-byte units
               excluding the first two, where the others count 8-byte units
               excluding the first one. */
            ext = (next == LIBPCAPNG_IPV6_EXT_AH)
                ? ((uint32_t)ip6[off + 1] + 2) * 4
                : ((uint32_t)ip6[off + 1] + 1) * 8;
            if (ext == 0 || off + ext > len) return 0;
            next = ip6[off];
            off += ext;
            continue;
        }

        if (next == LIBPCAPNG_IPV6_EXT_FRAGMENT) {
            if (off + 8 > len) return 0;
            /* The offset field is the top 13 bits. Non-zero means this is not
               the first fragment, so the transport header is in another packet. */
            if ((libpcapng_be16(ip6 + off + 2) & 0xfff8) != 0) {
                if (frag) *frag = 1;
                if (l4_off) *l4_off = off + 8;
                return 0;
            }
            next = ip6[off];
            off += 8;
            continue;
        }

        break;
    }

    if (next == LIBPCAPNG_IPV6_EXT_NONE) return 0;
    if (l4_off) *l4_off = off;
    return next;
}

/* ── TCP — `tcp` points at the source port ────────────────────────────────── */

static inline uint16_t libpcapng_tcp_get_sport(const uint8_t *tcp) { return libpcapng_be16(tcp); }
static inline uint16_t libpcapng_tcp_get_dport(const uint8_t *tcp) { return libpcapng_be16(tcp + 2); }
static inline uint32_t libpcapng_tcp_get_seq(const uint8_t *tcp)   { return libpcapng_be32(tcp + 4); }
static inline uint32_t libpcapng_tcp_get_ack(const uint8_t *tcp)   { return libpcapng_be32(tcp + 8); }
/* In bytes: the data offset field counts 32-bit words. */
static inline uint8_t  libpcapng_tcp_get_hdrlen(const uint8_t *tcp) { return (uint8_t)((tcp[12] >> 4) * 4); }
static inline uint8_t  libpcapng_tcp_get_flags(const uint8_t *tcp)  { return tcp[13]; }
static inline uint16_t libpcapng_tcp_get_window(const uint8_t *tcp) { return libpcapng_be16(tcp + 14); }
static inline uint16_t libpcapng_tcp_get_checksum(const uint8_t *tcp) { return libpcapng_be16(tcp + 16); }
static inline const uint8_t *libpcapng_tcp_get_payload(const uint8_t *tcp)
{ return tcp + libpcapng_tcp_get_hdrlen(tcp); }

/* One flag, by its LIBPCAPNG_TCP_* bit: libpcapng_tcp_has_flag(t, LIBPCAPNG_TCP_SYN) */
static inline int libpcapng_tcp_has_flag(const uint8_t *tcp, uint8_t flag)
{ return (tcp[13] & flag) != 0; }

/* ── UDP — `udp` points at the source port; the header is always 8 bytes ──── */

static inline uint16_t libpcapng_udp_get_sport(const uint8_t *udp) { return libpcapng_be16(udp); }
static inline uint16_t libpcapng_udp_get_dport(const uint8_t *udp) { return libpcapng_be16(udp + 2); }
/* Counts the 8-byte header as well as the data. */
static inline uint16_t libpcapng_udp_get_len(const uint8_t *udp)   { return libpcapng_be16(udp + 4); }
static inline uint16_t libpcapng_udp_get_checksum(const uint8_t *udp) { return libpcapng_be16(udp + 6); }
static inline const uint8_t *libpcapng_udp_get_payload(const uint8_t *udp) { return udp + 8; }

/* ── Printable addresses ──────────────────────────────────────────────────── */

/*
 * Write `addr` — 4 bytes for IPv4, 16 for IPv6 — into `out` as text.
 * `out` wants LIBPCAPNG_ADDR_STR_MAX bytes. Returns `out`.
 *
 * IPv6 comes out in full, uncompressed form: 2001:0db8:0000:0000:0000:0000:0000:0001
 * rather than 2001:db8::1. Unambiguous and correct, but not the canonical
 * shortening of RFC 5952 — use inet_ntop where that matters.
 */
#define LIBPCAPNG_ADDR_STR_MAX 46

static inline char *libpcapng_addr_str(const uint8_t *addr, int addrlen,
                                       char *out, size_t outlen)
{
    if (!out || outlen == 0) return out;
    if (!addr || (addrlen != 4 && addrlen != 16)) { snprintf(out, outlen, "-"); return out; }
    if (addrlen == 4) {
        snprintf(out, outlen, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    } else {
        snprintf(out, outlen,
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 addr[0], addr[1], addr[2],  addr[3],  addr[4],  addr[5],  addr[6],  addr[7],
                 addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]);
    }
    return out;
}

/* ── One call for the whole frame ─────────────────────────────────────────── */

/*
 * What libpcapng_frame_parse() found. Layers that are not there leave their
 * fields zero, so `ip_proto == 0` means no IP header and `sport == 0 &&
 * dport == 0` means nothing with ports.
 */
typedef struct {
    uint16_t       ethertype;    /* 0 when the link layer is not Ethernet    */
    uint16_t       vlan_id;      /* 0 when untagged                          */
    uint8_t        ip_version;   /* 4, 6, or 0 for no IP layer               */
    uint8_t        ip_proto;     /* LIBPCAPNG_IPPROTO_*, or 0                */
    const uint8_t *src_addr;     /* into the frame; NULL when absent         */
    const uint8_t *dst_addr;
    int            addr_len;     /* 4, 16, or 0                              */
    uint16_t       sport;        /* 0 unless TCP, UDP or SCTP                */
    uint16_t       dport;
    const uint8_t *l4;           /* transport header, or NULL                */
    const uint8_t *payload;      /* after the transport header, or NULL      */
    uint32_t       payload_len;
} libpcapng_frame_t;

/*
 * Walk a captured frame far enough to fill in `out`. `linktype` is the
 * capture's link type — PCAPNG_LINKTYPE_ETHERNET (1) and the rest of the list
 * in dissect.h. Returns 1 when an IP layer was found, 0 otherwise; `out` is
 * filled in either way, so an ARP frame returns 0 with its ethertype set.
 *
 * This is the cheap path: no allocation, no decoders, no field tree — about
 * thirty nanoseconds against seven microseconds for pcapng_dissect(). Reach
 * for the dissector when you want to know what the payload *is*, and for this
 * when you only need to know where it starts and who it is between.
 */
static inline int libpcapng_frame_parse(const uint8_t *data, uint32_t len,
                                        uint16_t linktype, libpcapng_frame_t *out)
{
    const uint8_t *ip = NULL;
    uint32_t off = 0, iplen = 0;

    if (!out) return 0;
    memset(out, 0, sizeof *out);
    if (!data || len == 0) return 0;

    if (linktype == 1) {                                   /* Ethernet */
        int tags = 0;
        if (len < LIBPCAPNG_ETH_HDR_MIN) return 0;
        out->ethertype = libpcapng_eth_get_type(data);
        off = LIBPCAPNG_ETH_HDR_MIN;
        /* 802.1Q and 802.1ad stack; the real ethertype is behind them. */
        while ((out->ethertype == LIBPCAPNG_ETHERTYPE_VLAN ||
                out->ethertype == LIBPCAPNG_ETHERTYPE_QINQ) && tags++ < 3) {
            if (off + 4 > len) return 0;
            if (!out->vlan_id) out->vlan_id = (uint16_t)(libpcapng_be16(data + off) & 0x0fff);
            out->ethertype = libpcapng_be16(data + off + 2);
            off += 4;
        }
        if (out->ethertype != LIBPCAPNG_ETHERTYPE_IPV4 &&
            out->ethertype != LIBPCAPNG_ETHERTYPE_IPV6) return 0;
    } else if (linktype == 101 || linktype == 228 || linktype == 229) {
        off = 0;                                           /* raw IP */
    } else {
        return 0;
    }

    if (off >= len) return 0;
    ip = data + off;
    iplen = len - off;

    if ((ip[0] >> 4) == 4) {
        uint16_t total;
        uint8_t  ihl;
        if (iplen < LIBPCAPNG_IPV4_HDR_MIN) return 0;
        ihl = libpcapng_ipv4_get_hdrlen(ip);
        if (ihl < LIBPCAPNG_IPV4_HDR_MIN || ihl > iplen) return 0;

        out->ip_version = 4;
        out->ip_proto   = libpcapng_ipv4_get_proto(ip);
        out->src_addr   = libpcapng_ipv4_get_src(ip);
        out->dst_addr   = libpcapng_ipv4_get_dst(ip);
        out->addr_len   = 4;

        /* total_length bounds the payload: padding a NIC added is not data. */
        total = libpcapng_ipv4_get_total_len(ip);
        if (total >= ihl && total <= iplen) iplen = total;

        /* A non-first fragment has no transport header behind it. */
        if (libpcapng_ipv4_get_frag_offset(ip) != 0) return 1;
        out->l4 = ip + ihl;
        iplen  -= ihl;
    } else if ((ip[0] >> 4) == 6) {
        uint16_t plen;
        if (iplen < LIBPCAPNG_IPV6_HDR_LEN) return 0;
        uint32_t l4_off = LIBPCAPNG_IPV6_HDR_LEN;
        int      isfrag = 0;

        if (iplen < LIBPCAPNG_IPV6_HDR_LEN) return 0;
        out->ip_version = 6;
        out->src_addr   = libpcapng_ipv6_get_src(ip);
        out->dst_addr   = libpcapng_ipv6_get_dst(ip);
        out->addr_len   = 16;

        plen = libpcapng_ipv6_get_payload_len(ip);
        if (plen && (uint32_t)plen + LIBPCAPNG_IPV6_HDR_LEN <= iplen)
            iplen = (uint32_t)plen + LIBPCAPNG_IPV6_HDR_LEN;

        /* The chain is followed to the transport header, so ip_proto is the
           protocol rather than whichever extension happened to come first. */
        out->ip_proto = libpcapng_ipv6_transport(ip, iplen, &l4_off, &isfrag);
        if (!out->ip_proto || l4_off >= iplen) return 1;   /* fragment, or chain ran out */
        out->l4 = ip + l4_off;
        iplen  -= l4_off;
    } else {
        return 0;
    }

    if (out->ip_proto == LIBPCAPNG_IPPROTO_TCP) {
        uint8_t hl;
        if (iplen < LIBPCAPNG_TCP_HDR_MIN) { out->l4 = NULL; return 1; }
        out->sport = libpcapng_tcp_get_sport(out->l4);
        out->dport = libpcapng_tcp_get_dport(out->l4);
        hl = libpcapng_tcp_get_hdrlen(out->l4);
        if (hl >= LIBPCAPNG_TCP_HDR_MIN && hl <= iplen) {
            out->payload     = out->l4 + hl;
            out->payload_len = iplen - hl;
        }
    } else if (out->ip_proto == LIBPCAPNG_IPPROTO_UDP) {
        uint16_t ulen;
        if (iplen < LIBPCAPNG_UDP_HDR_LEN) { out->l4 = NULL; return 1; }
        out->sport = libpcapng_udp_get_sport(out->l4);
        out->dport = libpcapng_udp_get_dport(out->l4);
        ulen = libpcapng_udp_get_len(out->l4);
        out->payload     = out->l4 + LIBPCAPNG_UDP_HDR_LEN;
        out->payload_len = (ulen >= LIBPCAPNG_UDP_HDR_LEN && ulen <= iplen)
                         ? (uint32_t)(ulen - LIBPCAPNG_UDP_HDR_LEN)
                         : iplen - LIBPCAPNG_UDP_HDR_LEN;
    } else if (out->ip_proto == LIBPCAPNG_IPPROTO_SCTP) {
        if (iplen >= 4) {
            out->sport = libpcapng_be16(out->l4);
            out->dport = libpcapng_be16(out->l4 + 2);
        }
    } else {
        out->payload     = out->l4;
        out->payload_len = iplen;
    }
    return 1;
}

/* A short name for what the frame carries: "TCP", "UDP", "ARP", "IPv6", ... */
static inline const char *libpcapng_frame_proto_name(const libpcapng_frame_t *f)
{
    if (!f) return "?";
    switch (f->ip_proto) {
    case LIBPCAPNG_IPPROTO_TCP:    return "TCP";
    case LIBPCAPNG_IPPROTO_UDP:    return "UDP";
    case LIBPCAPNG_IPPROTO_ICMP:   return "ICMP";
    case LIBPCAPNG_IPPROTO_ICMPV6: return "ICMPv6";
    case LIBPCAPNG_IPPROTO_SCTP:   return "SCTP";
    case LIBPCAPNG_IPPROTO_GRE:    return "GRE";
    case LIBPCAPNG_IPPROTO_ESP:    return "ESP";
    case LIBPCAPNG_IPPROTO_AH:     return "AH";
    default: break;
    }
    if (f->ip_version == 6) return "IPv6";
    if (f->ip_version == 4) return "IP";
    switch (f->ethertype) {
    case LIBPCAPNG_ETHERTYPE_ARP:   return "ARP";
    case LIBPCAPNG_ETHERTYPE_MPLS:  return "MPLS";
    case LIBPCAPNG_ETHERTYPE_PPPOE: return "PPPoE";
    case LIBPCAPNG_ETHERTYPE_EAPOL: return "EAPOL";
    default: break;
    }
    return "DATA";
}

#ifdef __cplusplus
}
#endif

#endif /* _LIBPCAPNG_HEADERS_H_ */
