#ifndef _LIBPCAPNG_DNS_H_
#define _LIBPCAPNG_DNS_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct libpcapng_dns_hdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

void libpcapng_fill_dns_header(struct libpcapng_dns_hdr *dns, uint16_t id, int qr, int opcode, int aa, int tc, int rd, int ra, int rcode, uint16_t qdcount, uint16_t ancount, uint16_t nscount, uint16_t arcount);
size_t libpcapng_dns_encode_qname(const char *name, uint8_t *out, size_t max_len);
size_t libpcapng_dns_build_question(uint8_t *buf, size_t max_len, const char *qname, uint16_t qtype, uint16_t qclass);
size_t libpcapng_dns_build_query(uint8_t *buf, size_t max_len, uint16_t id, int rd, const char *qname, uint16_t qtype, uint16_t qclass);
size_t libpcapng_dns_build_answer_a(uint8_t *buf, size_t max_len, uint16_t qname_offset, uint32_t ipv4_be, uint32_t ttl);
size_t libpcapng_dns_build_response(uint8_t *buf, size_t max_len, uint16_t id, const char *qname, uint16_t qtype, uint16_t qclass, uint32_t ip_be, uint32_t ttl);
void libpcapng_dns_packet_build(const uint8_t src_mac[6], const uint8_t dst_mac[6], uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const struct libpcapng_dns_hdr *libpcapng_dns_hdr, const uint8_t *dns_body, size_t dns_body_len, uint8_t *frame_out, size_t *frame_len);

  
#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_DNS_H_
