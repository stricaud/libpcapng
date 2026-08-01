#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <libpcapng/protocols/asn1.h>

size_t asn1_encode_length(uint8_t *buf, size_t len)
{
    if (len < 0x80) {
        buf[0] = (uint8_t)len;
        return 1;
    } else if (len <= 0xFF) {
        buf[0] = 0x81;
        buf[1] = (uint8_t)len;
        return 2;
    } else if (len <= 0xFFFF) {
        buf[0] = 0x82;
        buf[1] = (uint8_t)(len >> 8);
        buf[2] = (uint8_t)(len & 0xFF);
        return 3;
    } else {
        buf[0] = 0x83;
        buf[1] = (uint8_t)(len >> 16);
        buf[2] = (uint8_t)(len >> 8);
        buf[3] = (uint8_t)(len & 0xFF);
        return 4;
    }
}

size_t asn1_tlv(uint8_t *buf, uint8_t tag, const uint8_t *val, size_t val_len)
{
    size_t off = 0;
    buf[off++] = tag;
    off += asn1_encode_length(buf + off, val_len);
    if (val && val_len > 0)
        memcpy(buf + off, val, val_len);
    return off + val_len;
}

size_t asn1_integer(uint8_t *buf, int32_t value)
{
    uint8_t tmp[5];
    size_t len;

    if (value >= 0) {
        /* Non-negative: use minimum bytes, ensure MSB is 0 for positive */
        if (value <= 0x7F) {
            tmp[0] = (uint8_t)value;
            len = 1;
        } else if (value <= 0x7FFF) {
            tmp[0] = (uint8_t)(value >> 8);
            tmp[1] = (uint8_t)(value & 0xFF);
            len = 2;
        } else if (value <= 0x7FFFFF) {
            tmp[0] = (uint8_t)(value >> 16);
            tmp[1] = (uint8_t)(value >> 8);
            tmp[2] = (uint8_t)(value & 0xFF);
            len = 3;
        } else {
            tmp[0] = (uint8_t)(value >> 24);
            tmp[1] = (uint8_t)(value >> 16);
            tmp[2] = (uint8_t)(value >> 8);
            tmp[3] = (uint8_t)(value & 0xFF);
            len = 4;
        }
    } else {
        /* Negative: two's complement, use minimum bytes */
        if (value >= -128) {
            tmp[0] = (uint8_t)(int8_t)value;
            len = 1;
        } else if (value >= -32768) {
            tmp[0] = (uint8_t)(value >> 8);
            tmp[1] = (uint8_t)(value & 0xFF);
            len = 2;
        } else if (value >= -8388608) {
            tmp[0] = (uint8_t)(value >> 16);
            tmp[1] = (uint8_t)(value >> 8);
            tmp[2] = (uint8_t)(value & 0xFF);
            len = 3;
        } else {
            tmp[0] = (uint8_t)(value >> 24);
            tmp[1] = (uint8_t)(value >> 16);
            tmp[2] = (uint8_t)(value >> 8);
            tmp[3] = (uint8_t)(value & 0xFF);
            len = 4;
        }
    }
    return asn1_tlv(buf, 0x02, tmp, len);
}

size_t asn1_boolean(uint8_t *buf, int value)
{
    uint8_t v = value ? 0xFF : 0x00;
    return asn1_tlv(buf, 0x01, &v, 1);
}

size_t asn1_enumerated(uint8_t *buf, int32_t value)
{
    uint8_t tmp[2];
    size_t len;
    if (value >= 0 && value <= 127) {
        tmp[0] = (uint8_t)value;
        len = 1;
    } else {
        tmp[0] = (uint8_t)(value >> 8);
        tmp[1] = (uint8_t)(value & 0xFF);
        len = 2;
    }
    return asn1_tlv(buf, 0x0A, tmp, len);
}

size_t asn1_octet_string(uint8_t *buf, const uint8_t *data, size_t len)
{
    return asn1_tlv(buf, 0x04, data, len);
}

size_t asn1_sequence(uint8_t *buf, const uint8_t *content, size_t content_len)
{
    return asn1_tlv(buf, 0x30, content, content_len);
}

size_t asn1_context(uint8_t *buf, uint8_t tag_num, const uint8_t *content, size_t content_len)
{
    return asn1_tlv(buf, 0xA0 | tag_num, content, content_len);
}
