#include <string.h>

#include <libpcapng/protocols/http2_stream.h>

size_t http2_build_preface(uint8_t *out, size_t max_len)
{
    const char *p = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    size_t len = strlen(p);
    if (len > max_len) return 0;
    memcpy(out, p, len);
    return len;
}

size_t http2_build_settings(uint8_t *out, size_t max_len)
{
    if (max_len < 9) return 0;
    out[0] = 0x00; out[1] = 0x00; out[2] = 0x00;
    out[3] = 0x04; /* SETTINGS */
    out[4] = 0x00;
    out[5] = 0x00;
    out[6] = 0x00;
    out[7] = 0x00;
    out[8] = 0x00;
    return 9;
}

size_t http2_build_request(
    http2_stream_t *ctx,
    uint8_t *out,
    size_t max_len,
    const char *method,
    const char *path,
    const char *host,
    const char *ua,
    const uint8_t *body,
    size_t body_len)
{
    uint8_t hdr[512];
    size_t hlen = h2_hpack_encode_headers(
        &ctx->hpack, hdr, sizeof(hdr),
        method, path, "https", host, ua
    );

    if (hlen + body_len + 9 > max_len) return 0;

    /* HEADERS frame */
    out[0] = (hlen >> 16) & 0xff;
    out[1] = (hlen >> 8) & 0xff;
    out[2] = hlen & 0xff;
    out[3] = 0x01;
    out[4] = 0x05;
    out[5] = 0x00;
    out[6] = 0x00;
    out[7] = 0x01;

    memcpy(out + 9, hdr, hlen);

    if (body_len > 0) {
        memcpy(out + 9 + hlen, body, body_len);
    }

    return 9 + hlen + body_len;
}
