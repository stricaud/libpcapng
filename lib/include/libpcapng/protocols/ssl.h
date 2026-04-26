#ifndef _LIBPCAPNG_SSL_H_
#define _LIBPCAPNG_SSL_H_

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TLS_CONTENT_HANDSHAKE 22
#define TLS_CONTENT_APPDATA   23

#define TLS_VERSION_1_2 0x0303

size_t tls_build_client_hello(uint8_t *out, size_t max_len);
size_t tls_build_server_hello(uint8_t *out, size_t max_len);
size_t tls_build_certificate(uint8_t *out, size_t max_len, const uint8_t *cert, size_t cert_len);
size_t tls_build_finished(uint8_t *out, size_t max_len);
size_t tls_build_application_data(uint8_t *out, size_t max_len, const uint8_t *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_SSL_H_
