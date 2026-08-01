#ifndef _LIBPCAPNG_SSL_H_
#define _LIBPCAPNG_SSL_H_

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TLS_CONTENT_CCS       20
#define TLS_CONTENT_HANDSHAKE 22
#define TLS_CONTENT_APPDATA   23

#define TLS_VERSION_1_2 0x0303

/* Cipher used for simulated TLS: NULL (no encryption, content visible in Wireshark) */
#define TLS_CIPHER_NULL 0x0000

size_t tls_build_client_hello(uint8_t *out, size_t max_len);
size_t tls_build_client_hello_sni(uint8_t *out, size_t max_len, const char *sni);
size_t tls_build_server_hello(uint8_t *out, size_t max_len);
size_t tls_build_certificate(uint8_t *out, size_t max_len, const uint8_t *cert, size_t cert_len);
size_t tls_build_certificate_with_cn(uint8_t *out, size_t max_len, const char *cn);
size_t tls_build_change_cipher_spec(uint8_t *out, size_t max_len);
size_t tls_build_finished(uint8_t *out, size_t max_len);
size_t tls_build_application_data(uint8_t *out, size_t max_len, const uint8_t *data, size_t data_len);

/* Session key access (for NSS keylog output) */
void        tls_set_key_label(const char *label);
const char *tls_get_key_label(void);
void        tls_get_client_random_hex(char *out64); /* 32 bytes → 64 hex chars + NUL */

#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_SSL_H_
