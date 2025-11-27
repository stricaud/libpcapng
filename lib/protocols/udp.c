#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <libpcapng/protocols/ethernet.h>
#include <libpcapng/protocols/udp.h>

static uint16_t libpcapng_udp_checksum(const struct libpcapng_ipv4_hdr *ip,
                                       const struct libpcapng_udp_hdr *udp,
                                       const uint8_t *payload,
                                       size_t payload_len)
{
    uint32_t sum = 0;

    // Pseudo-header
    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += (ip->saddr)       & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += (ip->daddr)       & 0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += udp->len;

    const uint16_t *u16 = (const uint16_t *)udp;
    for (size_t i = 0; i < sizeof(*udp)/2; i++)
        sum += ntohs(u16[i]);

    const uint8_t *ptr = payload;
    while (payload_len >= 2) {
        sum += (ptr[0] << 8) | ptr[1];
        ptr += 2;
        payload_len -= 2;
    }

    if (payload_len == 1) {
        sum += (ptr[0] << 8);
    }

    // fold 32 → 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    uint16_t checksum = ~sum;
    if (checksum == 0) checksum = 0xFFFF;

    return htons(checksum);
}


void libpcapng_fill_udp_header(struct libpcapng_udp_hdr *udp,
                               uint16_t sport,
                               uint16_t dport,
                               uint16_t length)
{
    memset(udp, 0, sizeof(*udp));
    udp->sport = htons(sport);
    udp->dport = htons(dport);
    udp->len   = htons(length);
    udp->checksum = 0;
}

void libpcapng_udp_packet_build(const uint8_t src_mac[6], const uint8_t dst_mac[6],
                                uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                const uint8_t *payload, size_t payload_len,
                                uint8_t *frame_out, size_t *frame_len)
{
    uint8_t frame[65536];
    size_t offset = 0;

    struct libpcapng_eth_hdr eth;
    memcpy(eth.dst, dst_mac, 6);
    memcpy(eth.src, src_mac, 6);
    eth.ethertype = htons(0x0800);
    memcpy(frame + offset, &eth, sizeof(eth));
    offset += sizeof(eth);

    struct libpcapng_ipv4_hdr ip;
    uint16_t udp_len = sizeof(struct libpcapng_udp_hdr) + payload_len;
    uint16_t ip_total_len = sizeof(struct libpcapng_ipv4_hdr) + udp_len;

    libpcapng_fill_ipv4_header(&ip, src_ip, dst_ip, ip_total_len, IPPROTO_UDP);
    memcpy(frame + offset, &ip, sizeof(ip));
    offset += sizeof(ip);

    struct libpcapng_udp_hdr udp;
    libpcapng_fill_udp_header(&udp, src_port, dst_port, udp_len);
    udp.checksum = libpcapng_udp_checksum(&ip, &udp, payload, payload_len);

    memcpy(frame + offset, &udp, sizeof(udp));
    offset += sizeof(udp);

    if (payload_len > 0) {
        memcpy(frame + offset, payload, payload_len);
        offset += payload_len;
    }

    *frame_len = offset;
    memcpy(frame_out, frame, *frame_len);
}
