#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <libpcapng/protocols/ethernet.h>
#include <libpcapng/protocols/tcp.h>

uint16_t libpcapng_tcp_checksum(const struct libpcapng_ipv4_hdr *ip, const struct tcp_hdr *tcp, const uint8_t *payload, size_t payload_len) {
    uint32_t sum = 0;
    // pseudo-header
    uint32_t saddr = ntohl(ip->saddr);
    uint32_t daddr = ntohl(ip->daddr);
    sum += (saddr >> 16) & 0xffff;
    sum += saddr & 0xffff;
    sum += (daddr >> 16) & 0xffff;
    sum += daddr & 0xffff;
    sum += htons(ip->protocol);
    uint16_t tcp_len = htons(sizeof(struct tcp_hdr) + payload_len);
    sum += tcp_len;

    // TCP header
    const uint8_t *tcpbytes = (const uint8_t*)tcp;
    for (size_t i = 0; i + 1 < sizeof(struct tcp_hdr); i += 2) {
        uint16_t w = (tcpbytes[i] << 8) | tcpbytes[i+1];
        sum += w;
    }

    for (size_t i = 0; i + 1 < payload_len; i += 2) {
        uint16_t w = (payload[i] << 8) | payload[i+1];
        sum += w;
    }
    if (payload_len & 1) {
        uint16_t w = (payload[payload_len - 1] << 8);
        sum += w;
    }

    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return htons(~sum & 0xffff);
}

// fill TCP header (without checksum)
void libpcapng_fill_tcp_header(struct tcp_hdr *tcp, uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window) {
    memset(tcp, 0, sizeof(*tcp));
    tcp->sport = htons(sport);
    tcp->dport = htons(dport);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff = 5; // no options
    tcp->fin = (flags & 0x01) ? 1 : 0;
    tcp->syn = (flags & 0x02) ? 1 : 0;
    tcp->rst = (flags & 0x04) ? 1 : 0;
    tcp->psh = (flags & 0x08) ? 1 : 0;
    tcp->ack = (flags & 0x10) ? 1 : 0;
    tcp->urg = (flags & 0x20) ? 1 : 0;
    tcp->window = htons(window);
    tcp->checksum = 0;
    tcp->urg_ptr = 0;
}

void libpcapng_tcp_packet_build(const uint8_t src_mac[6], const uint8_t dst_mac[6],
				uint32_t src_ip, uint32_t dst_ip,
				uint16_t src_port, uint16_t dst_port,
				uint32_t seq, uint32_t ack, uint8_t flags,
				const uint8_t *payload, size_t payload_len,
				uint8_t *frame_out, size_t *frame_len) {

    uint8_t frame[65536];
    size_t offset = 0;

    struct libpcapng_eth_hdr eth;
    memcpy(eth.dst, dst_mac, 6);
    memcpy(eth.src, src_mac, 6);
    eth.ethertype = htons(0x0800); // IPv4
    memcpy(frame + offset, &eth, sizeof(eth));
    offset += sizeof(eth);

    struct libpcapng_ipv4_hdr ip;
    uint16_t ip_total_len = sizeof(struct libpcapng_ipv4_hdr) + sizeof(struct tcp_hdr) + payload_len;
    libpcapng_fill_ipv4_header(&ip, src_ip, dst_ip, ip_total_len, IPPROTO_TCP);
    memcpy(frame + offset, &ip, sizeof(ip));
    offset += sizeof(ip);

    struct tcp_hdr tcp;
    libpcapng_fill_tcp_header(&tcp, src_port, dst_port, seq, ack, flags, 65535);
    // compute tcp checksum with pseudo-header
    tcp.checksum = libpcapng_tcp_checksum(&ip, &tcp, payload, payload_len);
    memcpy(frame + offset, &tcp, sizeof(tcp));
    offset += sizeof(tcp);

    if (payload_len > 0) {
        memcpy(frame + offset, payload, payload_len);
        offset += payload_len;
    }
    
    *frame_len = offset;
    memcpy(frame_out, frame, *frame_len);
}
