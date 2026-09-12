/*
 * tls_keylog.h — NSS TLS keylog consumer.
 *
 * Load a keylog file (the kind produced by Firefox, Chrome, curl with
 * SSLKEYLOGFILE set, or by pcapsh -s) and let the dissector decrypt
 * TLS Application Data records inline.
 *
 * License MIT
 */
#ifndef LIBPCAPNG_TLS_KEYLOG_H
#define LIBPCAPNG_TLS_KEYLOG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int pcapng_tls_keylog_load_file(const char *path);
int pcapng_tls_keylog_load_text(const char *text);
void pcapng_tls_keylog_clear(void);
int pcapng_tls_keylog_loaded(void);

/* Feed a Decryption Secrets Block body (type 0x544c534b "TLSK") so the store
 * is populated automatically when reading a pcapng file that was saved with
 * embedded session keys (e.g. from a browser). */
void pcapng_tls_keylog_ingest_dsb(const uint8_t *body, uint32_t len);
void tls_keylog_on_client_hello(uint64_t flow_key, const uint8_t *client_random);
void tls_keylog_on_server_hello(uint64_t flow_key, const uint8_t *server_random, uint16_t cipher_suite, uint16_t negotiated_version);
int tls_keylog_decrypt(uint64_t flow_key, int from_client, const uint8_t *rec, int reclen, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* LIBPCAPNG_TLS_KEYLOG_H */
