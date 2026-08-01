#ifndef LIBPCAPNG_REASSEMBLY_H
#define LIBPCAPNG_REASSEMBLY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum number of incomplete datagrams tracked simultaneously.
 * When the table is full the oldest entry is evicted. */
#define LIBPCAPNG_REASM_MAX_DATAGRAMS 64

/* Maximum reassembled IP payload (RFC 791 maximum datagram size). */
#define LIBPCAPNG_REASM_MAX_PAYLOAD 65535

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t ip_id;
    uint8_t  proto;
    uint8_t  used;

    uint8_t  have_first;         /* received the frag_off==0 fragment */
    uint8_t  have_last;          /* received the MF==0 fragment */
    uint16_t total_data_len;     /* total payload length (set when MF==0 seen) */
    uint32_t bytes_recvd;        /* payload bytes received so far */

    uint8_t  ip_hdr[60];         /* saved IP header from the frag_off==0 fragment */
    uint8_t  ip_hdr_len;

    uint8_t  buf[LIBPCAPNG_REASM_MAX_PAYLOAD];   /* reassembled payload */
    uint8_t  recvd[LIBPCAPNG_REASM_MAX_PAYLOAD]; /* byte-presence bitmap */

    uint32_t birth_seq;          /* allocation sequence for LRU eviction */
} libpcapng_reasm_entry_t;

typedef struct {
    libpcapng_reasm_entry_t table[LIBPCAPNG_REASM_MAX_DATAGRAMS];
    uint32_t                seq;
} libpcapng_reasm_t;

/* Allocate a new reassembly context. */
libpcapng_reasm_t *libpcapng_reasm_new(void);

/* Free a reassembly context (discards all pending state). */
void libpcapng_reasm_free(libpcapng_reasm_t *ctx);

/* Feed one packet into the reassembler.
 *
 * pkt / pkt_len: raw Ethernet frame *or* raw IPv4 datagram — auto-detected.
 * out / out_len: set on return value 1 (caller must free(*out) with free()).
 *
 * Return values:
 *   1  — reassembly complete; *out points to a malloc'd IPv4 datagram with
 *          corrected total-length, cleared fragment flags, and valid checksum.
 *   0  — fragment buffered; more fragments expected.
 *  -1  — packet is not an IPv4 fragment (pass through as-is) or is invalid.
 */
int libpcapng_reasm_add(libpcapng_reasm_t *ctx,
                         const uint8_t *pkt, size_t pkt_len,
                         uint8_t **out, size_t *out_len);

#ifdef __cplusplus
}
#endif
#endif /* LIBPCAPNG_REASSEMBLY_H */
