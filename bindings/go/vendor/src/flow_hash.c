/*
 * flow_hash.c — the hash a dispatcher shards flows on.
 *
 * Two jobs: canonicalise a 5-tuple so both directions agree, and walk enough of
 * a frame to find that tuple. The walk is deliberately not the dissector — no
 * tree, no allocation, no decoder lookup — because this runs on the reader
 * thread, ahead of the work it is dividing up, and anything spent here is spent
 * on the one core the pipeline cannot parallelise.
 *
 * See flow_hash.h for what the value is for, and threading.h for why pinning a
 * flow to one thread is what makes the library's per-flow state sound.
 *
 * License MIT
 */
#include <libpcapng/flow_hash.h>
#include <libpcapng/dissect.h>   /* PCAPNG_LINKTYPE_*                        */
#include <libpcapng/headers.h>   /* the shared header accessors and constants */

#include <string.h>

/* ── the hash ─────────────────────────────────────────────────────────────── */

uint64_t pcapng_flow_hash_tuple(uint8_t ip_proto,
                                const uint8_t *saddr, const uint8_t *daddr,
                                int addrlen, uint16_t sport, uint16_t dport,
                                pcapng_flow_mode_t mode)
{
    const uint8_t *lo = saddr, *hi = daddr;
    uint16_t plo = sport, phi = dport;
    uint64_t h = 1469598103934665603ULL;          /* FNV-1a offset basis */
    int i, cmp;

    if (!saddr || !daddr || (addrlen != 4 && addrlen != 16)) return 0;

    if (mode == PCAPNG_FLOW_IPPAIR) { ip_proto = 0; plo = phi = 0; }

    /* Order the endpoints so the two directions of a connection agree. Ports
       break the tie when a host talks to itself. */
    cmp = memcmp(saddr, daddr, (size_t)addrlen);
    if (cmp > 0 || (cmp == 0 && plo > phi)) {
        lo = daddr; hi = saddr;
        if (mode != PCAPNG_FLOW_IPPAIR) { plo = dport; phi = sport; }
    }

#define FNV(x) do { h ^= (uint8_t)(x); h *= 1099511628211ULL; } while (0)
    FNV(ip_proto);
    for (i = 0; i < addrlen; i++) FNV(lo[i]);
    for (i = 0; i < addrlen; i++) FNV(hi[i]);
    FNV(plo >> 8); FNV(plo & 0xff);
    FNV(phi >> 8); FNV(phi & 0xff);
#undef FNV

    /* Avalanche. FNV-1a leaves its low bits depending on very little of the
       input — its last act is a multiply, so the bottom bits of the result are
       the bottom bits of one multiply of one byte. Both consumers read exactly
       those bits: a dispatcher takes `hash % nworkers`, and the dissector's own
       flow table takes `key & (FLOWTAB_SIZE-1)`. Without this finaliser 4096
       flows landed in two of eight buckets. It is the splitmix64 mix, three
       shift-xors and two multiplies, and costs about a nanosecond. */
    h ^= h >> 30; h *= 0xbf58476d1ce4e5b9ULL;
    h ^= h >> 27; h *= 0x94d049bb133111ebULL;
    h ^= h >> 31;

    /* 0 is reserved for "no flow", and callers use it as an empty-slot marker. */
    return h ? h : 1;
}

/* ── finding the tuple in a frame ─────────────────────────────────────────── */

/* Ports for the protocols that have them where we expect them. Anything else
   hashes on addresses alone, which is correct: it has no ports to hash. */
static void l4_ports(uint8_t proto, const uint8_t *l4, uint32_t l4len,
                     uint16_t *sport, uint16_t *dport)
{
    *sport = *dport = 0;
    if (l4len < 4) return;
    if (proto == LIBPCAPNG_IPPROTO_TCP || proto == LIBPCAPNG_IPPROTO_UDP || proto == LIBPCAPNG_IPPROTO_SCTP) {
        *sport = libpcapng_be16(l4);
        *dport = libpcapng_be16(l4 + 2);
    }
}

static uint64_t hash_ipv4(const uint8_t *d, uint32_t len, pcapng_flow_mode_t mode)
{
    uint32_t ihl;
    uint16_t sp, dp;
    uint16_t total;

    if (len < LIBPCAPNG_IPV4_HDR_MIN || libpcapng_ipv4_get_version(d) != 4) return 0;
    ihl = libpcapng_ipv4_get_hdrlen(d);
    if (ihl < LIBPCAPNG_IPV4_HDR_MIN || ihl > len) return 0;

    /* total_length bounds the payload; trailing padding a NIC added is not it. */
    total = libpcapng_ipv4_get_total_len(d);
    if (total >= ihl && total <= len) len = total;

    /* A non-first fragment has no transport header to read ports from, so it
       hashes on addresses — which still lands it on the flow's own worker. */
    if (libpcapng_ipv4_get_frag_offset(d) != 0)
        return pcapng_flow_hash_tuple(libpcapng_ipv4_get_proto(d),
                                      libpcapng_ipv4_get_src(d),
                                      libpcapng_ipv4_get_dst(d), 4, 0, 0, mode);

    l4_ports(libpcapng_ipv4_get_proto(d), d + ihl, len - ihl, &sp, &dp);
    return pcapng_flow_hash_tuple(libpcapng_ipv4_get_proto(d),
                                  libpcapng_ipv4_get_src(d),
                                  libpcapng_ipv4_get_dst(d), 4, sp, dp, mode);
}

static uint64_t hash_ipv6(const uint8_t *d, uint32_t len, pcapng_flow_mode_t mode)
{
    uint32_t l4_off = LIBPCAPNG_IPV6_HDR_LEN;
    uint16_t sp = 0, dp = 0;
    uint8_t  next;
    int      isfrag = 0;

    if (len < LIBPCAPNG_IPV6_HDR_LEN || libpcapng_ipv6_get_version(d) != 6) return 0;

    /* The same chain walk libpcapng_frame_parse() uses — one implementation, so
       a hash and a parse of the same packet cannot disagree about where the
       transport header is. */
    next = libpcapng_ipv6_transport(d, len, &l4_off, &isfrag);

    /* A non-first fragment has no ports to read, and a chain that ran out has
       none to find; both hash on the addresses, which still lands the packet on
       its own flow's worker. */
    if (next && l4_off <= len)
        l4_ports(next, d + l4_off, len - l4_off, &sp, &dp);

    return pcapng_flow_hash_tuple(isfrag ? libpcapng_ipv6_get_next_header(d) : next,
                                  libpcapng_ipv6_get_src(d),
                                  libpcapng_ipv6_get_dst(d), 16, sp, dp, mode);
}

static uint64_t hash_l3(uint16_t ethertype, const uint8_t *d, uint32_t len,
                        pcapng_flow_mode_t mode)
{
    if (ethertype == LIBPCAPNG_ETHERTYPE_IPV4) return hash_ipv4(d, len, mode);
    if (ethertype == LIBPCAPNG_ETHERTYPE_IPV6) return hash_ipv6(d, len, mode);
    return 0;
}

uint64_t pcapng_flow_hash(const uint8_t *data, uint32_t len, uint16_t linktype,
                          pcapng_flow_mode_t mode)
{
    if (!data || len == 0) return 0;

    switch (linktype) {
    case PCAPNG_LINKTYPE_ETHERNET: {
        uint16_t et;
        uint32_t off = 14;
        int tags = 0;
        if (len < LIBPCAPNG_ETH_HDR_MIN) return 0;
        et = libpcapng_eth_get_type(data);
        /* 802.1Q and 802.1ad, which stack. */
        while ((et == LIBPCAPNG_ETHERTYPE_VLAN || et == LIBPCAPNG_ETHERTYPE_QINQ ||
                et == 0x9100) && tags++ < 3) {
            if (off + 4 > len) return 0;
            et = libpcapng_be16(data + off + 2);
            off += 4;
        }
        return hash_l3(et, data + off, len - off, mode);
    }
    case PCAPNG_LINKTYPE_RAW:
    case PCAPNG_LINKTYPE_IPV4:
        return (data[0] >> 4) == 6 ? hash_ipv6(data, len, mode)
                                   : hash_ipv4(data, len, mode);
    case PCAPNG_LINKTYPE_IPV6:
        return hash_ipv6(data, len, mode);
    case PCAPNG_LINKTYPE_NULL: {
        /* 4-byte address family, host byte order. */
        uint32_t af;
        if (len < 4) return 0;
        af = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
             ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
        if (af == 2) return hash_ipv4(data + 4, len - 4, mode);
        if (af == 24 || af == 28 || af == 30) return hash_ipv6(data + 4, len - 4, mode);
        return 0;
    }
    case PCAPNG_LINKTYPE_LINUX_SLL:
        if (len < 16) return 0;
        return hash_l3(libpcapng_be16(data + 14), data + 16, len - 16, mode);
    default:
        /* Same best-effort guess the dissector makes for an unknown link layer. */
        if ((data[0] >> 4) == 4) return hash_ipv4(data, len, mode);
        if ((data[0] >> 4) == 6) return hash_ipv6(data, len, mode);
        return 0;
    }
}
