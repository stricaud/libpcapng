#ifndef _LIBPCAPNG_TCP_MSS_H_
#define _LIBPCAPNG_TCP_MSS_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t mss;
    uint32_t seq;
} tcp_mss_ctx_t;

/* Split payload into MSS-sized chunks */
size_t tcp_mss_segment(
    tcp_mss_ctx_t *ctx,
    const uint8_t *in,
    size_t in_len,
    uint8_t **out_segments,
    size_t *out_sizes,
    size_t max_segments
);

#ifdef __cplusplus
}
#endif

#endif
