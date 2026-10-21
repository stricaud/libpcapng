#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef _WIN32
#  include <libpcapng/win_compat.h>
#else
#  include <arpa/inet.h>
#endif

#include <libpcapng/protocols/ethernet.h>
#include <libpcapng/protocols/ipv4.h>
#include <libpcapng/protocols/icmp.h>

static uint16_t libpcapng_icmp_checksum(const uint8_t *buf, size_t len)
{
    uint32_t sum = 0;

    const uint16_t *u16 = (const uint16_t *)buf;
    while (len >= 2) {
        sum += ntohs(*u16++);
        len -= 2;
    }

    if (len == 1) {
        sum += ((uint32_t)buf[(buf - (const uint8_t*)u16)] << 8);
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    uint16_t res = ~sum;
    if (res == 0) res = 0xFFFF;

    return htons(res);
}

void libpcapng_fill_icmp_header(struct libpcapng_icmp_hdr *icmp,
                                uint8_t type, uint8_t code,
                                uint16_t identifier, uint16_t seq)
{
    memset(icmp, 0, sizeof(*icmp));
    icmp->type = type;
    icmp->code = code;
    icmp->identifier = htons(identifier);
    icmp->sequence   = htons(seq);
    icmp->checksum   = 0;   // filled later
}

void libpcapng_icmp_packet_build(const uint8_t src_mac[6], const uint8_t dst_mac[6],
                                 uint32_t src_ip, uint32_t dst_ip,
                                 uint8_t icmp_type, uint8_t icmp_code,
                                 uint16_t identifier, uint16_t sequence,
                                 const uint8_t *payload, size_t payload_len,
                                 uint8_t *frame_out, size_t *frame_len)
{
    uint8_t frame[65536];
    size_t offset = 0;

    // Ethernet
    struct libpcapng_eth_hdr eth;
    memcpy(eth.dst, dst_mac, 6);
    memcpy(eth.src, src_mac, 6);
    eth.ethertype = htons(0x0800);
    memcpy(frame + offset, &eth, sizeof(eth));
    offset += sizeof(eth);

    // IPv4
    struct libpcapng_ipv4_hdr ip;
    uint16_t icmp_len = sizeof(struct libpcapng_icmp_hdr) + payload_len;
    uint16_t ip_total_len = sizeof(struct libpcapng_ipv4_hdr) + icmp_len;

    libpcapng_fill_ipv4_header(&ip, src_ip, dst_ip, ip_total_len, IPPROTO_ICMP);
    memcpy(frame + offset, &ip, sizeof(ip));
    offset += sizeof(ip);

    // ICMP
    struct libpcapng_icmp_hdr icmp;
    libpcapng_fill_icmp_header(&icmp, icmp_type, icmp_code, identifier, sequence);

    /* MSVC does not support C99 VLAs; use heap allocation instead. */
    uint8_t *icmp_buf = (uint8_t *)malloc(icmp_len);
    if (icmp_buf) {
        memcpy(icmp_buf, &icmp, sizeof(icmp));
        if (payload_len > 0)
            memcpy(icmp_buf + sizeof(icmp), payload, payload_len);
        icmp.checksum = libpcapng_icmp_checksum(icmp_buf, icmp_len);
        free(icmp_buf);
    }

    memcpy(frame + offset, &icmp, sizeof(icmp));
    offset += sizeof(icmp);

    // Payload
    if (payload_len > 0) {
        memcpy(frame + offset, payload, payload_len);
        offset += payload_len;
    }

    *frame_len = offset;
    memcpy(frame_out, frame, offset);
}
