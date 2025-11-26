#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <libpcapng/protocols/ipv4.h>

uint16_t libpcapng_ip_checksum(void *vdata, size_t length) {
    char *data = (char *)vdata;
    uint32_t acc = 0xffff;

    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }

    // Handle odd byte at end, if any.
    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) acc -= 0xffff;
    }

    return htons(~acc & 0xffff);
}

uint32_t libpcapng_ipv4_to_host_order(const char *ipstr) {
    struct in_addr addr;

    if (inet_pton(AF_INET, ipstr, &addr) != 1) {
        return 0;  // invalid IP
    }

    return ntohl(addr.s_addr);
}

// build IPv4 header (fill fields and compute checksum)
void libpcapng_fill_ipv4_header(struct libpcapng_ipv4_hdr *ip, uint32_t saddr, uint32_t daddr, uint16_t total_len, uint8_t protocol) {
    memset(ip, 0, sizeof(*ip));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(total_len);
    ip->id = htons(rand() & 0xffff);
    ip->frag_off = htons(0);
    ip->ttl = 64;
    ip->protocol = protocol;
    ip->saddr = htonl(saddr);
    ip->daddr = htonl(daddr);
    ip->checksum = 0;
    ip->checksum = libpcapng_ip_checksum(ip, sizeof(struct libpcapng_ipv4_hdr));
}
