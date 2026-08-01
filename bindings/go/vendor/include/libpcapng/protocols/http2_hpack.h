#ifndef _LIBPCAPNG_HTTP2_HPACK_H_
#define _LIBPCAPNG_HTTP2_HPACK_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Minimal HPACK encoder (static table only, Chrome-like subset) */

typedef struct {
    uint32_t stream_id;
} h2_hpack_ctx_t;

/* Encode a single header block (no dynamic table) */
size_t h2_hpack_encode_headers(
    h2_hpack_ctx_t *ctx,
    uint8_t *out,
    size_t max_len,
    const char *method,
    const char *path,
    const char *scheme,
    const char *authority,
    const char *user_agent
);

#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_HTTP2_HPACK_H_

