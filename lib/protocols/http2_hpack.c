#include <string.h>

#include <libpcapng/protocols/http2_hpack.h>

/* VERY minimal: literal headers (no compression table) */

static size_t put_kv(uint8_t *out, size_t max,
                     const char *k, const char *v)
{
    size_t klen = strlen(k);
    size_t vlen = strlen(v);

    if (2 + klen + vlen > max) return 0;

    out[0] = 0x00; /* literal header */
    out[1] = (uint8_t)klen;
    memcpy(out + 2, k, klen);
    memcpy(out + 2 + klen, v, vlen);

    return 2 + klen + vlen;
}

size_t h2_hpack_encode_headers(
    h2_hpack_ctx_t *ctx,
    uint8_t *out,
    size_t max_len,
    const char *method,
    const char *path,
    const char *scheme,
    const char *authority,
    const char *ua)
{
    size_t off = 0;

    off += put_kv(out + off, max_len - off, ":method", method);
    off += put_kv(out + off, max_len - off, ":path", path);
    off += put_kv(out + off, max_len - off, ":scheme", scheme);
    off += put_kv(out + off, max_len - off, ":authority", authority);
    off += put_kv(out + off, max_len - off, "user-agent", ua);

    return off;
}
