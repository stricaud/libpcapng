#ifndef _LIBPCAPNG_BOOTP_H_
#define _LIBPCAPNG_BOOTP_H_

#include <stdint.h>

#include "ipv4.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BOOTP_HDR_LEN 236a
  
struct libpcapng_bootp_hdr {
    uint8_t  op;        // 1=request, 2=reply
    uint8_t  htype;     // hardware type (1 = Ethernet)
    uint8_t  hlen;      // hardware addr length (6)
    uint8_t  hops;
    uint32_t xid;       // transaction ID
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;    // client IP
    uint32_t yiaddr;    // your IP (offer)
    uint32_t siaddr;    // DHCP server IP
    uint32_t giaddr;    // relay agent
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint8_t  options[]; // DHCP options follow
} __attribute__((packed));
  
#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_BOOTP_H_
