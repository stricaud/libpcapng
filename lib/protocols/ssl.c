#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <libpcapng/protocols/ssl.h>

static size_t tls_record(uint8_t type,
                         const uint8_t *payload,
                         size_t payload_len,
                         uint8_t *out)
{
    out[0] = type;
    out[1] = 0x03; // TLS 1.2
    out[2] = 0x03;
    uint16_t len = htons(payload_len);
    memcpy(out + 3, &len, 2);
    memcpy(out + 5, payload, payload_len);
    return 5 + payload_len;
}

size_t tls_build_client_hello(uint8_t *out, size_t max_len)
{
    uint8_t body[512];
    size_t off = 0;

    body[off++] = 0x01; // Handshake: ClientHello
    body[off++] = 0x00; body[off++] = 0x00; body[off++] = 0x00; // len placeholder

    size_t start = off;

    body[off++] = 0x03; body[off++] = 0x03; // TLS 1.2

    memset(body + off, 0x11, 32); // random
    off += 32;

    body[off++] = 0x00; // session id len

    body[off++] = 0x00; body[off++] = 0x02; // cipher len
    body[off++] = 0x00; body[off++] = 0x2f; // TLS_RSA_WITH_AES_128_CBC_SHA

    body[off++] = 0x01; // compression len
    body[off++] = 0x00;

    size_t len = off - start;
    body[1] = (len >> 16) & 0xff;
    body[2] = (len >> 8) & 0xff;
    body[3] = (len) & 0xff;

    return tls_record(TLS_CONTENT_HANDSHAKE, body, off, out);
}

size_t tls_build_server_hello(uint8_t *out, size_t max_len)
{
    uint8_t body[256];
    size_t off = 0;

    body[off++] = 0x02; // ServerHello
    body[off++] = 0x00; body[off++] = 0x00; body[off++] = 0x00;

    size_t start = off;

    body[off++] = 0x03; body[off++] = 0x03;
    memset(body + off, 0x22, 32);
    off += 32;

    body[off++] = 0x00; // session id
    body[off++] = 0x00; body[off++] = 0x2f; // cipher
    body[off++] = 0x00; // compression

    size_t len = off - start;
    body[1] = (len >> 16) & 0xff;
    body[2] = (len >> 8) & 0xff;
    body[3] = (len) & 0xff;

    return tls_record(TLS_CONTENT_HANDSHAKE, body, off, out);
}

size_t tls_build_certificate(uint8_t *out, size_t max_len,
                             const uint8_t *cert, size_t cert_len)
{
    uint8_t body[2048];
    size_t off = 0;

    body[off++] = 0x0b; // Certificate
    body[off++] = 0x00; body[off++] = 0x00; body[off++] = 0x00;

    size_t start = off;

    uint32_t chain_len = cert_len + 3;
    body[off++] = (chain_len >> 16) & 0xff;
    body[off++] = (chain_len >> 8) & 0xff;
    body[off++] = chain_len & 0xff;

    body[off++] = (cert_len >> 16) & 0xff;
    body[off++] = (cert_len >> 8) & 0xff;
    body[off++] = cert_len & 0xff;

    memcpy(body + off, cert, cert_len);
    off += cert_len;

    size_t len = off - start;
    body[1] = (len >> 16) & 0xff;
    body[2] = (len >> 8) & 0xff;
    body[3] = len & 0xff;

    return tls_record(TLS_CONTENT_HANDSHAKE, body, off, out);
}

size_t tls_build_finished(uint8_t *out, size_t max_len)
{
    uint8_t verify[12];
    memset(verify, 0xaa, sizeof(verify));

    uint8_t body[32];
    size_t off = 0;

    body[off++] = 0x14; // Finished
    body[off++] = 0x00; body[off++] = 0x00; body[off++] = sizeof(verify);

    memcpy(body + off, verify, sizeof(verify));
    off += sizeof(verify);

    return tls_record(TLS_CONTENT_HANDSHAKE, body, off, out);
}

size_t tls_build_application_data(uint8_t *out, size_t max_len,
                                  const uint8_t *data, size_t data_len)
{
    return tls_record(TLS_CONTENT_APPDATA, data, data_len, out);
}
