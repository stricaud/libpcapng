/* community_id.h — Community ID flow hashing (Corelight spec v1).
 *
 * A deterministic, direction-independent identifier for a network flow, derived
 * from the 5-tuple (proto, addrs, ports). The same value is produced regardless
 * of capture direction, so it correlates flows across Zeek, Suricata, Wireshark
 * and this library. libpcapng also uses it internally as a flow key to make
 * protocol classification sticky across a flow's packets.
 */
#ifndef LIBPCAPNG_COMMUNITY_ID_H
#define LIBPCAPNG_COMMUNITY_ID_H

#include <stddef.h>
#include <stdint.h>

/* Write the Community ID ("1:<base64 sha1>") for one flow into `out`.
 *   proto    IP protocol number (6 TCP, 17 UDP, …)
 *   saddr/daddr  network-order address bytes; `addrlen` is 4 (IPv4) or 16 (IPv6)
 *   sport/dport  transport ports in host order (pass 0/0 for portless protocols)
 *   seed     hashing seed (0 is the conventional default)
 * The endpoints are canonicalised internally, so swapping src/dst yields the
 * same string. `out` should be at least 32 bytes; the result is NUL-terminated. */
void pcapng_community_id(uint8_t proto,
                        const uint8_t *saddr, const uint8_t *daddr, int addrlen,
                        uint16_t sport, uint16_t dport, uint16_t seed,
                        char *out, size_t outlen);

#endif /* LIBPCAPNG_COMMUNITY_ID_H */
