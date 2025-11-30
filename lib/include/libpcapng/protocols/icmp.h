#ifndef _LIBPCAPNG_ICMP_H_
#define _LIBPCAPNG_ICMP_H_

#include <stdint.h>

#include "ipv4.h"

#ifdef __cplusplus
extern "C" {
#endif

struct libpcapng_icmp_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} __attribute__((packed));

void libpcapng_icmp_packet_build(const uint8_t src_mac[6], const uint8_t dst_mac[6], uint32_t src_ip, uint32_t dst_ip, uint8_t icmp_type, uint8_t icmp_code, uint16_t identifier, uint16_t sequence, const uint8_t *payload, size_t payload_len, uint8_t *frame_out, size_t *frame_len);

#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_ICMP_H_
