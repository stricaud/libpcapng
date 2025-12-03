#ifndef _LIBPCAPNG_NTP_H_
#define _LIBPCAPNG_NTP_H_

#include <stdint.h>

#include "ipv4.h"

#ifdef __cplusplus
extern "C" {
#endif

struct libpcapng_ntp_hdr {
    uint8_t li_vn_mode;   // Leap Indicator + Version + Mode
    uint8_t stratum;
    uint8_t poll;
    int8_t precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t ref_id;
    uint32_t ref_timestamp_secs;
    uint32_t ref_timestamp_frac;
    uint32_t orig_timestamp_secs;
    uint32_t orig_timestamp_frac;
    uint32_t recv_timestamp_secs;
    uint32_t recv_timestamp_frac;
    uint32_t tx_timestamp_secs;
    uint32_t tx_timestamp_frac;
} __attribute__((packed));

void libpcapng_build_ntp_request(const uint8_t src_mac[6],
				 const uint8_t dst_mac[6],
				 uint32_t src_ip,
				 uint32_t dst_ip,
				 uint16_t src_port,
				 uint16_t dst_port,
				 uint8_t *frame_out,
				 size_t *frame_len);
  
void libpcapng_build_ntp_reply(const uint8_t src_mac[6],
			       const uint8_t dst_mac[6],
			       uint32_t src_ip,
			       uint32_t dst_ip,
			       uint16_t src_port,
			       uint16_t dst_port,
			       const struct libpcapng_ntp_hdr *request,
			       uint8_t *frame_out,
			       size_t *frame_len);

#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_NTP_H_
