#include <string.h>

#include <libpcapng/protocols/tls_stream.h>

size_t tls_stream_write(
    tls_stream_t *ctx,
    uint8_t *out,
    size_t max_len,
    const uint8_t *in,
    size_t in_len)
{
    /* TLS record header */
    if (max_len < in_len + 5) return 0;

    out[0] = 0x17; /* application data */
    out[1] = 0x03;
    out[2] = 0x03;

    out[3] = (in_len >> 8) & 0xff;
    out[4] = (in_len & 0xff);

    memcpy(out + 5, in, in_len);

    ctx->write_seq += in_len;

    return in_len + 5;
}
