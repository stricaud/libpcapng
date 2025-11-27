#ifndef _LIBPCAPNG_UDP_H_
#define _LIBPCAPNG_UDP_H_

#include <stdint.h>

#include "ipv4.h"

#ifdef __cplusplus
extern "C" {
#endif

struct libpcapng_udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t checksum;
} __attribute__((packed));

static uint16_t libpcapng_udp_checksum(const struct libpcapng_ipv4_hdr *ip, const struct libpcapng_udp_hdr *udp, const uint8_t *payload, size_t payload_len);
void libpcapng_fill_udp_header(struct libpcapng_udp_hdr *udp, uint16_t sport, uint16_t dport, uint16_t length);
void libpcapng_udp_packet_build(const uint8_t src_mac[6], const uint8_t dst_mac[6], uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const uint8_t *payload, size_t payload_len, uint8_t *frame_out, size_t *frame_len);
  
#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_UDP_H_
