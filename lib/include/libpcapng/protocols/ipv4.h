#ifndef _LIBPCAPNG_IPV4_H_
#define _LIBPCAPNG_IPV4_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct libpcapng_ipv4_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl:4;
    uint8_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version:4;
    uint8_t ihl:4;
#else
#error "Please fix <endian.h>"
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

uint16_t libpcapng_ip_checksum(void *vdata, size_t length);
uint32_t libpcapng_ipv4_to_host_order(const char *ipstr);
uint32_t libpcapng_ipv4_to_network_order(const char *ipstr);
void libpcapng_fill_ipv4_header(struct libpcapng_ipv4_hdr *ip, uint32_t saddr, uint32_t daddr, uint16_t total_len, uint8_t protocol);
  
#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_IPV4_H_
