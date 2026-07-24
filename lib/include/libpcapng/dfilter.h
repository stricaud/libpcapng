#ifndef _LIBPCAPNG_DFILTER_H_
#define _LIBPCAPNG_DFILTER_H_

#include <stddef.h>
#include <libpcapng/dissect.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Wireshark/tshark-compatible display filters ─────────────────────────────
 *
 * Compile a display-filter expression once, then test it against the field
 * tree that pcapng_dissect() produces for each packet. This is the single
 * filter engine shared by tools built on libpcapng.
 *
 * Supported:
 *   - field existence:   tcp        ip.addr        dns.qry.name
 *   - comparisons:       ip.src == 10.0.0.1   tcp.port != 80   ip.ttl >= 64
 *     operators:         ==  eq   !=  ne   >  gt   <  lt   >=  ge   <=  le
 *                        contains   matches  (substring; not full regex)
 *   - boolean logic:     &&  and    ||  or    !  not    ( )
 *   - value forms:       decimal / 0xHEX, "quoted string", 1.2.3.4[/cidr],
 *                        aa:bb:cc:dd:ee:ff
 *   - field aliases:     ip.addr→{ip.src,ip.dst}, tcp.port→{srcport,dstport},
 *                        udp.port, eth.addr, ipv6.addr  (Wireshark "any" match)
 */

typedef struct pcapng_dfilter pcapng_dfilter_t;

/* Compile an expression. An empty/blank expression matches everything.
   Returns NULL on a syntax error and writes a message to errbuf (if given). */
pcapng_dfilter_t *pcapng_dfilter_compile(const char *expr, char *errbuf, size_t errlen);

/* 1 if the packet whose dissection root is `root` matches the filter. A NULL
   filter or a match-all filter returns 1. */
int pcapng_dfilter_match(const pcapng_dfilter_t *f, pcapng_field_t *root);

/* 1 if the filter matches everything (was compiled from an empty expression). */
int pcapng_dfilter_is_match_all(const pcapng_dfilter_t *f);

void pcapng_dfilter_free(pcapng_dfilter_t *f);

#ifdef __cplusplus
}
#endif

#endif /* _LIBPCAPNG_DFILTER_H_ */
