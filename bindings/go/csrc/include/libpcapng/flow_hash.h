/*
 * flow_hash.h — a cheap, direction-independent hash of a packet's flow.
 *
 * The value a dispatcher shards on. Both directions of a connection hash the
 * same, so pinning a flow to a worker with
 *
 *     worker = pcapng_flow_hash(frame, len, linktype, PCAPNG_FLOW_TUPLE) % nworkers;
 *
 * sends every packet of that flow, in both directions, to one worker. That is
 * what makes libpcapng's per-flow state safe to use from several threads: the
 * sticky protocol classification, a decoder's `bind`/`recall` memory and the
 * TLS session table are all per-thread, and per-thread is only correct if a
 * flow never moves between threads. See threading.h.
 *
 * Not the Community ID. That is also derived from the canonicalised 5-tuple and
 * partitions flows identically, but it is SHA-1 plus base64 returning a string
 * — about 316 ns a packet against 2 ns here. Community ID's job is agreeing
 * with Zeek, Suricata and Wireshark on a name for a flow, which is worth SHA-1.
 * Choosing a worker is not. Use pcapng_community_id() to label, this to route.
 */
#ifndef _LIBPCAPNG_FLOW_HASH_H_
#define _LIBPCAPNG_FLOW_HASH_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* Protocol, both addresses, both ports. The default, and what the
       dissector itself keys on. */
    PCAPNG_FLOW_TUPLE  = 0,
    /* Addresses only, ignoring protocol and ports — so every connection
       between one pair of hosts lands on one worker. Use it when a session
       spans ports that the packets alone do not tie together: FTP's data
       channel, SIP plus its RTP streams, anything negotiating a second
       connection in its payload. Coarser, so it balances less evenly. */
    PCAPNG_FLOW_IPPAIR = 1
} pcapng_flow_mode_t;

/*
 * Hash the flow a frame belongs to.
 *
 * `linktype` is the capture's link type (PCAPNG_LINKTYPE_ETHERNET and the
 * others dissect.h lists); Ethernet frames may carry 802.1Q/802.1ad tags.
 * IPv4 and IPv6 are both understood, as are TCP, UDP and SCTP ports; any other
 * IP protocol hashes on addresses with both ports zero.
 *
 * Returns 0 — and only 0 — when no flow could be derived: a non-IP frame, a
 * truncated header, an unsupported link type. A real flow never hashes to 0.
 */
uint64_t pcapng_flow_hash(const uint8_t *data, uint32_t len, uint16_t linktype,
                          pcapng_flow_mode_t mode);

/*
 * The same hash from an already-parsed tuple, for a caller that has the fields
 * to hand and does not want the frame walked again.
 *
 *   addrs    network-order bytes; `addrlen` is 4 (IPv4) or 16 (IPv6)
 *   ports    host order; pass 0/0 for a protocol without them
 *
 * Endpoints are canonicalised internally, so swapping source and destination
 * gives the same value. Never returns 0.
 */
uint64_t pcapng_flow_hash_tuple(uint8_t ip_proto,
                                const uint8_t *saddr, const uint8_t *daddr,
                                int addrlen, uint16_t sport, uint16_t dport,
                                pcapng_flow_mode_t mode);

#ifdef __cplusplus
}
#endif

#endif /* _LIBPCAPNG_FLOW_HASH_H_ */
