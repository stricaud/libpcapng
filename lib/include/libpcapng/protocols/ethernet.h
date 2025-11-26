#ifndef _LIBPCAPNG_ETHERNET_H_
#define _LIBPCAPNG_ETHERNET_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct libpcapng_eth_hdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
} __attribute__((packed));

int libpcapng_mac_str_to_bytes(const char *mac_str, uint8_t mac[6]);
  
#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_ETHERNET_H_
