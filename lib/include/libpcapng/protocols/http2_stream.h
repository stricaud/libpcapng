#ifndef _LIBPCAPNG_HTTP2_STREAM_H_
#define _LIBPCAPNG_HTTP2_STREAM_H_

#include <stdint.h>
#include <stddef.h>
#include "http2_hpack.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t stream_id;
    h2_hpack_ctx_t hpack;
} http2_stream_t;

size_t http2_build_preface(uint8_t *out, size_t max_len);
size_t http2_build_settings(uint8_t *out, size_t max_len);

size_t http2_build_request(
    http2_stream_t *ctx,
    uint8_t *out,
    size_t max_len,
    const char *method,
    const char *path,
    const char *host,
    const char *ua,
    const uint8_t *body,
    size_t body_len
);

#ifdef __cplusplus
}
#endif

#endif
