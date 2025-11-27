#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libpcapng/protocols/udp.h>
#include <libpcapng/protocols/dns.h>

void libpcapng_fill_dns_header(struct libpcapng_dns_hdr *dns,
                               uint16_t id,
                               int qr, int opcode, int aa, int tc, int rd,
                               int ra, int rcode,
                               uint16_t qdcount,
                               uint16_t ancount,
                               uint16_t nscount,
                               uint16_t arcount)
{
    memset(dns, 0, sizeof(*dns));

    dns->id = htons(id);

    uint16_t flags = 0;

    flags |= (qr & 1) << 15;
    flags |= (opcode & 0xF) << 11;
    flags |= (aa & 1) << 10;
    flags |= (tc & 1) << 9;
    flags |= (rd & 1) << 8;
    flags |= (ra & 1) << 7;
    flags |= (rcode & 0xF);

    dns->flags   = htons(flags);
    dns->qdcount = htons(qdcount);
    dns->ancount = htons(ancount);
    dns->nscount = htons(nscount);
    dns->arcount = htons(arcount);
}

// Encode "www.example.com" → [3]www[7]example[3]com[0]
size_t libpcapng_dns_encode_qname(const char *name, uint8_t *out, size_t max_len)
{
    if (!name || !out || max_len == 0) return 0;
    
    size_t offset = 0;
    const char *start = name;
    const char *dot;

    while ((dot = strchr(start, '.'))) {
        uint8_t len = dot - start;
        
        // Check if we have space for: length byte + label + at least null terminator
        if (offset + 1 + len + 1 > max_len) return 0;
        
        out[offset++] = len;
        memcpy(out + offset, start, len);
        offset += len;
        start = dot + 1;
    }

    uint8_t len = strlen(start);
    
    // Check if we have space for: length byte + final label + null terminator
    if (offset + 1 + len + 1 > max_len) return 0;
    
    out[offset++] = len;
    memcpy(out + offset, start, len);
    offset += len;

    out[offset++] = 0;

    return offset;
}

size_t libpcapng_dns_build_question(uint8_t *buf,
                                    size_t max_len,
                                    const char *qname,
                                    uint16_t qtype,
                                    uint16_t qclass)
{
    if (!buf || !qname || max_len == 0) return 0;
    
    size_t offset = 0;
    
    // Encode the qname
    size_t qname_len = libpcapng_dns_encode_qname(qname, buf + offset, max_len - offset);
    if (qname_len == 0) return 0;  // encoding failed (buffer too small)
    
    offset += qname_len;
    
    // Check if we have space for qtype (2 bytes) + qclass (2 bytes)
    if (offset + 4 > max_len) return 0;
    
    uint16_t t = htons(qtype);
    uint16_t c = htons(qclass);

    memcpy(buf + offset, &t, 2); offset += 2;
    memcpy(buf + offset, &c, 2); offset += 2;
    
    return offset;
}

size_t libpcapng_dns_build_query(uint8_t *buf,
                                 size_t max_len,
                                 uint16_t id,
                                 int rd,
                                 const char *qname,
                                 uint16_t qtype,
                                 uint16_t qclass)
{
    if (!buf || !qname || max_len < sizeof(struct libpcapng_dns_hdr)) return 0;
    
    struct libpcapng_dns_hdr dns;
    libpcapng_fill_dns_header(&dns,
                              id,
                              0,0,0,0, rd,0,0, // QR=0(query), RD=rd
                              1,0,0,0);         // 1 question

    // Header is already in network byte order from libpcapng_fill_dns_header
    memcpy(buf, &dns, sizeof(dns));

    size_t qlen = libpcapng_dns_build_question(buf + sizeof(dns), 
                                               max_len - sizeof(dns),
                                               qname, qtype, qclass);
    if (qlen == 0) return 0;  // question build failed
    
    return sizeof(dns) + qlen;
}

size_t libpcapng_dns_build_answer_a(uint8_t *buf,
                                    size_t max_len,
                                    uint16_t qname_offset,
                                    uint32_t ipv4_be,
                                    uint32_t ttl)
{
    if (!buf || max_len < 16) return 0;  // minimum size for an A record answer
    
    size_t offset = 0;

    // NAME pointer: C0 XX (2 bytes)
    if (offset + 2 > max_len) return 0;
    buf[offset++] = 0xC0;
    buf[offset++] = qname_offset;

    // Check space for: type(2) + class(2) + ttl(4) + rdlen(2) + rdata(4) = 14 bytes
    if (offset + 14 > max_len) return 0;
    
    uint16_t type  = htons(1); // A
    uint16_t class = htons(1); // IN
    uint32_t ttl_be = htonl(ttl);
    uint16_t rdlen = htons(4);
 
    memcpy(buf + offset, &type, 2); offset += 2;
    memcpy(buf + offset, &class, 2); offset += 2;
    memcpy(buf + offset, &ttl_be, 4); offset += 4;
    memcpy(buf + offset, &rdlen, 2); offset += 2;
    
    memcpy(buf + offset, &ipv4_be, 4); offset += 4;

    return offset;
}

size_t libpcapng_dns_build_response(uint8_t *buf,
                                    size_t max_len,
                                    uint16_t id,
                                    const char *qname,
                                    uint16_t qtype,
                                    uint16_t qclass,
                                    uint32_t ip_be,
                                    uint32_t ttl)
{
    if (!buf || !qname || max_len < sizeof(struct libpcapng_dns_hdr)) return 0;
    
    struct libpcapng_dns_hdr dns;
    libpcapng_fill_dns_header(&dns,
                              id,
                              1,0,1,0,1,1,0, // QR=1(response), AA=1, RD=1, RA=1
                              1,1,0,0);       // 1 question, 1 answer

    // Header is already in network byte order from libpcapng_fill_dns_header
    memcpy(buf, &dns, sizeof(dns));

    size_t offset = sizeof(dns);
    size_t remaining = max_len - offset;
    
    // Build question
    size_t qlen = libpcapng_dns_build_question(buf + offset, remaining,
                                               qname, qtype, qclass);
    if (qlen == 0) return 0;
    
    offset += qlen;
    remaining -= qlen;

    // Answer uses name pointer to question start
    uint16_t qname_offset = sizeof(dns);
    size_t alen = libpcapng_dns_build_answer_a(buf + offset, remaining,
                                               qname_offset, ip_be, ttl);
    if (alen == 0) return 0;
    
    offset += alen;

    return offset;
}

void libpcapng_dns_packet_build(const uint8_t src_mac[6],
                                const uint8_t dst_mac[6],
                                uint32_t src_ip,
                                uint32_t dst_ip,
                                uint16_t src_port,
                                uint16_t dst_port,
                                const struct libpcapng_dns_hdr *dns_hdr,
                                const uint8_t *dns_body,
                                size_t dns_body_len,
                                uint8_t *frame_out,
                                size_t *frame_len)
{
    if (!dns_hdr || !frame_out || !frame_len) return;

    size_t payload_len = sizeof(*dns_hdr) + dns_body_len;

    uint8_t *udp_payload = malloc(payload_len);
    if (!udp_payload) {
      return;
    }

    memcpy(udp_payload, dns_hdr, sizeof(*dns_hdr));
    if (dns_body && dns_body_len > 0) {
        memcpy(udp_payload + sizeof(*dns_hdr), dns_body, dns_body_len);
    }

    libpcapng_udp_packet_build(src_mac, dst_mac,
                               src_ip, dst_ip,
                               src_port, dst_port,
                               udp_payload, payload_len,
                               frame_out, frame_len);

    free(udp_payload);
}
