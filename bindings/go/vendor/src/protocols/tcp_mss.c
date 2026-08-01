#include <string.h>

#include <libpcapng/protocols/tcp_mss.h>

size_t tcp_mss_segment(
    tcp_mss_ctx_t *ctx,
    const uint8_t *in,
    size_t in_len,
    uint8_t **out_segments,
    size_t *out_sizes,
    size_t max_segments)
{
    size_t count = 0;
    size_t offset = 0;

    while (offset < in_len && count < max_segments) {
        size_t chunk = ctx->mss;
        if (chunk > in_len - offset)
            chunk = in_len - offset;

        out_segments[count] = (uint8_t *)(in + offset);
        out_sizes[count] = chunk;

        offset += chunk;
        count++;
    }

    return count;
}
