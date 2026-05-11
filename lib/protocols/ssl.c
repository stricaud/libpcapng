#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <libpcapng/protocols/ssl.h>

/* Client random is fixed for reproducibility (32 bytes of 0x11). */
static const uint8_t CLIENT_RANDOM[32] = {
    0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11, 0x11,0x11,0x11,0x11,
};
static const uint8_t SERVER_RANDOM[32] = {
    0x22,0x22,0x22,0x22, 0x22,0x22,0x22,0x22,
    0x22,0x22,0x22,0x22, 0x22,0x22,0x22,0x22,
    0x22,0x22,0x22,0x22, 0x22,0x22,0x22,0x22,
    0x22,0x22,0x22,0x22, 0x22,0x22,0x22,0x22,
};

static char g_key_label[256] = "";

static size_t tls_record(uint8_t type,
                         const uint8_t *payload, size_t payload_len,
                         uint8_t *out)
{
    out[0] = type;
    out[1] = 0x03;
    out[2] = 0x03;
    uint16_t len = htons((uint16_t)payload_len);
    memcpy(out + 3, &len, 2);
    memcpy(out + 5, payload, payload_len);
    return 5 + payload_len;
}

size_t tls_build_client_hello(uint8_t *out, size_t max_len)
{
    uint8_t body[512];
    size_t off = 0;

    body[off++] = 0x01; /* ClientHello */
    body[off++] = 0x00; body[off++] = 0x00; body[off++] = 0x00; /* len placeholder */

    size_t start = off;
    body[off++] = 0x03; body[off++] = 0x03; /* TLS 1.2 */
    memcpy(body + off, CLIENT_RANDOM, 32);
    off += 32;
    body[off++] = 0x00; /* session id len */
    body[off++] = 0x00; body[off++] = 0x02; /* 1 cipher suite */
    body[off++] = 0x00; body[off++] = 0x00; /* TLS_NULL_WITH_NULL_NULL */
    body[off++] = 0x01; body[off++] = 0x00; /* compression: none */

    size_t len = off - start;
    body[1] = (uint8_t)((len >> 16) & 0xff);
    body[2] = (uint8_t)((len >>  8) & 0xff);
    body[3] = (uint8_t)(len & 0xff);

    return tls_record(TLS_CONTENT_HANDSHAKE, body, off, out);
}

size_t tls_build_server_hello(uint8_t *out, size_t max_len)
{
    uint8_t body[256];
    size_t off = 0;

    body[off++] = 0x02; /* ServerHello */
    body[off++] = 0x00; body[off++] = 0x00; body[off++] = 0x00;

    size_t start = off;
    body[off++] = 0x03; body[off++] = 0x03;
    memcpy(body + off, SERVER_RANDOM, 32);
    off += 32;
    body[off++] = 0x00; /* session id */
    body[off++] = 0x00; body[off++] = 0x00; /* TLS_NULL_WITH_NULL_NULL */
    body[off++] = 0x00; /* compression: none */

    size_t len = off - start;
    body[1] = (uint8_t)((len >> 16) & 0xff);
    body[2] = (uint8_t)((len >>  8) & 0xff);
    body[3] = (uint8_t)(len & 0xff);

    return tls_record(TLS_CONTENT_HANDSHAKE, body, off, out);
}

size_t tls_build_certificate(uint8_t *out, size_t max_len,
                             const uint8_t *cert, size_t cert_len)
{
    uint8_t body[2048];
    size_t off = 0;

    body[off++] = 0x0b; /* Certificate */
    body[off++] = 0x00; body[off++] = 0x00; body[off++] = 0x00;

    size_t start = off;
    if (cert && cert_len) {
        /* one certificate in the list */
        uint32_t chain_len = (uint32_t)(cert_len + 3);
        body[off++] = (uint8_t)((chain_len >> 16) & 0xff);
        body[off++] = (uint8_t)((chain_len >>  8) & 0xff);
        body[off++] = (uint8_t)(chain_len & 0xff);
        body[off++] = (uint8_t)((cert_len >> 16) & 0xff);
        body[off++] = (uint8_t)((cert_len >>  8) & 0xff);
        body[off++] = (uint8_t)(cert_len & 0xff);
        memcpy(body + off, cert, cert_len);
        off += cert_len;
    } else {
        /* empty certificate list — valid for anonymous cipher suites */
        body[off++] = 0x00; body[off++] = 0x00; body[off++] = 0x00;
    }

    size_t len = off - start;
    body[1] = (uint8_t)((len >> 16) & 0xff);
    body[2] = (uint8_t)((len >>  8) & 0xff);
    body[3] = (uint8_t)(len & 0xff);

    return tls_record(TLS_CONTENT_HANDSHAKE, body, off, out);
}

size_t tls_build_change_cipher_spec(uint8_t *out, size_t max_len)
{
    uint8_t ccs = 0x01;
    return tls_record(TLS_CONTENT_CCS, &ccs, 1, out);
}

size_t tls_build_finished(uint8_t *out, size_t max_len)
{
    uint8_t verify[12];
    memset(verify, 0xaa, sizeof(verify));

    uint8_t body[32];
    size_t off = 0;
    body[off++] = 0x14; /* Finished */
    body[off++] = 0x00; body[off++] = 0x00; body[off++] = (uint8_t)sizeof(verify);
    memcpy(body + off, verify, sizeof(verify));
    off += sizeof(verify);

    return tls_record(TLS_CONTENT_HANDSHAKE, body, off, out);
}

size_t tls_build_application_data(uint8_t *out, size_t max_len,
                                  const uint8_t *data, size_t data_len)
{
    return tls_record(TLS_CONTENT_APPDATA, data, data_len, out);
}

void tls_set_key_label(const char *label)
{
    if (label)
        strncpy(g_key_label, label, sizeof(g_key_label) - 1);
    else
        g_key_label[0] = '\0';
}

const char *tls_get_key_label(void)
{
    return g_key_label;
}

void tls_get_client_random_hex(char *out64)
{
    for (int i = 0; i < 32; i++)
        snprintf(out64 + i*2, 3, "%02x", CLIENT_RANDOM[i]);
}
