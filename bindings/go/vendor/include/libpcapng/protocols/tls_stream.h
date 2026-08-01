#ifndef _LIBPCAPNG_TLS_STREAM_H_
#define _LIBPCAPNG_TLS_STREAM_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t write_seq;
    uint8_t  tls13;
} tls_stream_t;

/* Wrap application data into TLS record(s) */
size_t tls_stream_write(
    tls_stream_t *ctx,
    uint8_t *out,
    size_t max_len,
    const uint8_t *in,
    size_t in_len
);

#ifdef __cplusplus
}
#endif

#endif
