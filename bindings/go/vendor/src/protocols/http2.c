#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libpcapng/protocols/http2.h>

static size_t h2_frame(uint8_t type, uint8_t flags,
                       uint32_t stream_id,
                       const uint8_t *payload, size_t len,
                       uint8_t *out)
{
    out[0] = (len >> 16) & 0xff;
    out[1] = (len >> 8) & 0xff;
    out[2] = len & 0xff;
    out[3] = type;
    out[4] = flags;

    out[5] = (stream_id >> 24) & 0x7f;
    out[6] = (stream_id >> 16) & 0xff;
    out[7] = (stream_id >> 8) & 0xff;
    out[8] = stream_id & 0xff;

    memcpy(out + 9, payload, len);
    return 9 + len;
}

size_t h2_build_preface(uint8_t *out, size_t max_len)
{
    const char *preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    size_t len = strlen(preface);
    memcpy(out, preface, len);
    return len;
}

size_t h2_build_settings(uint8_t *out, size_t max_len)
{
    uint8_t payload[6];

    // SETTINGS_MAX_CONCURRENT_STREAMS = 100
    payload[0] = 0x00; payload[1] = 0x03;
    payload[2] = 0x00; payload[3] = 0x00;
    payload[4] = 0x00; payload[5] = 0x64;

    return h2_frame(H2_FRAME_SETTINGS, 0x00, 0, payload, sizeof(payload), out);
}

/* Minimal HEADERS (no HPACK, just fake block) */
size_t h2_build_headers(uint8_t *out, size_t max_len, uint32_t stream_id)
{
    uint8_t fake_headers[] = {
        0x82, // :method GET (indexed)
        0x84, // :path /
        0x86, // :scheme http
        0x41, 0x0f, // :authority (literal, len=15)
        'l','o','c','a','l','h','o','s','t'
    };

    return h2_frame(H2_FRAME_HEADERS, 0x05, stream_id,
                    fake_headers, sizeof(fake_headers), out);
}

size_t h2_build_data(uint8_t *out, size_t max_len,
                     uint32_t stream_id,
                     const uint8_t *data, size_t data_len)
{
    return h2_frame(H2_FRAME_DATA, 0x01, stream_id,
                    data, data_len, out);
}
