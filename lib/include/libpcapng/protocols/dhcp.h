#ifndef _LIBPCAPNG_DHCP_H_
#define _LIBPCAPNG_DHCP_H_

#include <stdint.h>

#include "ipv4.h"
#include "bootp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DHCP_FRAME_MAXLENGTH 1500

void libpcapng_build_dhcp_discover(const uint8_t src_mac[6],
				   uint32_t ip_src,
				   uint16_t sport, uint16_t dport,
				   uint32_t xid,
				   uint8_t *frame_out, size_t *frame_len);

void libpcapng_build_dhcp_offer(const uint8_t server_mac[6],
				const uint8_t client_mac[6],
				uint32_t server_ip,
				uint32_t offered_ip,
				uint32_t xid,
				uint16_t sport,
				uint16_t dport,
				uint8_t *frame_out,
				size_t *frame_len);  
  
#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_DHCP_H_
