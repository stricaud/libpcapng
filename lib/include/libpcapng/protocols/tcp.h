#ifndef _LIBPCAPNG_TCP_H_
#define _LIBPCAPNG_TCP_H_

#include <stdint.h>

#include "ipv4.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t ece:1;
    uint16_t cwr:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t doff:4;
    uint16_t res1:4;
    uint16_t cwr:1;
    uint16_t ece:1;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
#else
#error "Please fix <endian.h>"
#endif
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
} __attribute__((packed));

void libpcapng_fill_tcp_header(struct tcp_hdr *tcp, uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window);
uint16_t libpcapng_tcp_checksum(const struct libpcapng_ipv4_hdr *ip, const struct tcp_hdr *tcp, const uint8_t *payload, size_t payload_len);
void libpcapng_tcp_packet_build(const uint8_t src_mac[6], const uint8_t dst_mac[6], uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq, uint32_t ack, uint8_t flags, const uint8_t *payload, size_t payload_len, uint8_t *frame_out, size_t *frame_len);
  
#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_TCP_H_
