#ifndef _LIBPCAPNG_ASN1_H_
#define _LIBPCAPNG_ASN1_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Encode BER length into buf; return bytes written (1, 2, or 3 bytes) */
size_t asn1_encode_length(uint8_t *buf, size_t len);

/* Generic TLV encoder: tag (1 byte), length, value; returns total bytes written */
size_t asn1_tlv(uint8_t *buf, uint8_t tag, const uint8_t *val, size_t val_len);

/* INTEGER (tag 0x02): encodes value using minimum bytes with proper sign extension */
size_t asn1_integer(uint8_t *buf, int32_t value);

/* BOOLEAN (tag 0x01): 0xFF = true, 0x00 = false */
size_t asn1_boolean(uint8_t *buf, int value);

/* ENUMERATED (tag 0x0A): same encoding as INTEGER */
size_t asn1_enumerated(uint8_t *buf, int32_t value);

/* OCTET STRING (tag 0x04) */
size_t asn1_octet_string(uint8_t *buf, const uint8_t *data, size_t len);

/* SEQUENCE (tag 0x30, constructed) */
size_t asn1_sequence(uint8_t *buf, const uint8_t *content, size_t content_len);

/* Context-specific constructed wrapper: tag = 0xA0 | tag_num */
size_t asn1_context(uint8_t *buf, uint8_t tag_num, const uint8_t *content, size_t content_len);

#ifdef __cplusplus
}
#endif

#endif /* _LIBPCAPNG_ASN1_H_ */
