#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#include <libpcapng/protocols/udp.h>
#include <libpcapng/protocols/ntp.h>

void libpcapng_build_ntp_request(const uint8_t src_mac[6],
				 const uint8_t dst_mac[6],
				 uint32_t src_ip,
				 uint32_t dst_ip,
				 uint16_t src_port,
				 uint16_t dst_port,
				 uint8_t *frame_out,
				 size_t *frame_len)
{
    struct libpcapng_ntp_hdr ntp;
    memset(&ntp, 0, sizeof(ntp));

    // LI=0, VN=4, Mode=3 (client request)
    ntp.li_vn_mode = (0 << 6) | (4 << 3) | 3;

    // Build UDP packet
    libpcapng_udp_packet_build(
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        (uint8_t *)&ntp,
        sizeof(ntp),
        frame_out,
        frame_len
    );
}

void libpcapng_build_ntp_reply(const uint8_t src_mac[6],
			       const uint8_t dst_mac[6],
			       uint32_t src_ip,
			       uint32_t dst_ip,
			       uint16_t src_port,
			       uint16_t dst_port,
			       const struct libpcapng_ntp_hdr *request,
			       uint8_t *frame_out,
			       size_t *frame_len)
{
    struct libpcapng_ntp_hdr ntp;
    memset(&ntp, 0, sizeof(ntp));

    // LI=0, VN=4, Mode=4 (server reply)
    ntp.li_vn_mode = (0 << 6) | (4 << 3) | 4;

    // Copy client transmit timestamp as Originate Timestamp
    ntp.orig_timestamp_secs = request->tx_timestamp_secs;
    ntp.orig_timestamp_frac = request->tx_timestamp_frac;

    // Server receive timestamp
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ntp.recv_timestamp_secs = htonl((uint32_t)ts.tv_sec + 2208988800UL); // UNIX -> NTP epoch
    ntp.recv_timestamp_frac = 0;

    // Server transmit timestamp (reply)
    ntp.tx_timestamp_secs = ntp.recv_timestamp_secs;
    ntp.tx_timestamp_frac = ntp.recv_timestamp_frac;

    libpcapng_udp_packet_build(
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        (uint8_t *)&ntp,
        sizeof(ntp),
        frame_out,
        frame_len
    );
}
