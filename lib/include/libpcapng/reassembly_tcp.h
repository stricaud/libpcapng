#ifndef LIBPCAPNG_REASSEMBLY_TCP_H
#define LIBPCAPNG_REASSEMBLY_TCP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Passive TCP stream reassembly ───────────────────────────────────────────
 *
 * Reassembles the byte stream of a passively captured TCP connection. Flows are
 * keyed and direction-normalized with libpcapng_normalize_flow_direction(); each
 * half-stream buffers payload ordered by the observed sequence numbers. In-order
 * bytes are delivered immediately via the callback; a small set of out-of-order
 * segments is held and drained as gaps fill.
 *
 * This is intended for offline analysis (segments mostly arrive in order). It is
 * not a full TCP/IP stack: it does not validate checksums, handle SACK, or model
 * every edge of sequence-number wrap.
 */

typedef struct pcapng_tcp_reasm pcapng_tcp_reasm_t;

/* Invoked when new in-order bytes arrive for a half-stream.
 *   dir       : stable 0/1 direction id (0 = side-A→B, 1 = B→A)
 *   src/dst   : this direction's real IPs/ports (host byte order)
 *   data,len  : the newly delivered in-order bytes
 *   all,alllen: the cumulative reassembled buffer for this half-stream
 */
typedef void (*pcapng_tcp_stream_cb)(void *userdata,
                                     uint32_t src_ip, uint16_t src_port,
                                     uint32_t dst_ip, uint16_t dst_port,
                                     int dir,
                                     const uint8_t *data, size_t len,
                                     const uint8_t *all, size_t all_len);

/* Allocate / free a reassembly context. */
pcapng_tcp_reasm_t *pcapng_tcp_reasm_new(void);
void                pcapng_tcp_reasm_free(pcapng_tcp_reasm_t *ctx);

/* Feed one TCP segment (IPs/ports in host byte order). `tcp_flags` is the raw
 * TCP flags byte (SYN/FIN are used to anchor the stream). `payload` may be NULL
 * when `payload_len` is 0 (pure ACK / control). The callback is invoked zero or
 * more times for newly in-order bytes produced by this segment. */
void pcapng_tcp_reasm_add(pcapng_tcp_reasm_t *ctx,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint32_t seq, uint8_t tcp_flags,
                          const uint8_t *payload, size_t payload_len,
                          pcapng_tcp_stream_cb cb, void *userdata);

#ifdef __cplusplus
}
#endif

#endif /* LIBPCAPNG_REASSEMBLY_TCP_H */
