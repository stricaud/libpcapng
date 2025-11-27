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
size_t libpcapng_dns_encode_qname(const char *name, uint8_t *out)
{
    size_t len = 0;
    const char *start = name;
    const char *dot;

    while ((dot = strchr(start, '.'))) {
        int label_len = dot - start;
        out[len++] = label_len;
        memcpy(out + len, start, label_len);
        len += label_len;
        start = dot + 1;
    }

    // last label
    int label_len = strlen(start);
    out[len++] = label_len;
    memcpy(out + len, start, label_len);
    len += label_len;

    out[len++] = 0;  // end of qname
    return len;
}

size_t libpcapng_dns_build_question(uint8_t *buf,
                                    const char *qname,
                                    uint16_t qtype,
                                    uint16_t qclass)
{
    size_t offset = 0;
    offset += libpcapng_dns_encode_qname(qname, buf + offset);

    uint16_t *u16 = (uint16_t *)(buf + offset);
    u16[0] = htons(qtype);
    u16[1] = htons(qclass);
    return offset + 4;
}

size_t libpcapng_dns_build_answer_a(uint8_t *buf,
                                    const char *name,
                                    uint32_t ipv4_be,
                                    uint32_t ttl)  // seconds
{
    size_t offset = 0;

    offset += libpcapng_dns_encode_qname(name, buf + offset);

    uint16_t *u16 = (uint16_t *)(buf + offset);
    u16[0] = htons(1);       // TYPE=A
    u16[1] = htons(1);       // CLASS=IN
    offset += 4;

    uint32_t *u32 = (uint32_t *)(buf + offset);
    *u32 = htonl(ttl);
    offset += 4;

    u16 = (uint16_t *)(buf + offset);
    u16[0] = htons(4);       // RDLENGTH=4
    offset += 2;

    memcpy(buf + offset, &ipv4_be, 4);
    offset += 4;

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

    // total length of payload
    size_t payload_len = sizeof(*dns_hdr) + dns_body_len;

    // allocate dynamically
    uint8_t *udp_payload = malloc(payload_len);
    if (!udp_payload) return;  // allocation failed

    // copy header and body
    memcpy(udp_payload, dns_hdr, sizeof(*dns_hdr));
    if (dns_body && dns_body_len > 0) {
        memcpy(udp_payload + sizeof(*dns_hdr), dns_body, dns_body_len);
    }

    // build UDP packet
    libpcapng_udp_packet_build(src_mac, dst_mac,
                               src_ip, dst_ip,
                               src_port, dst_port,
                               udp_payload, payload_len,
                               frame_out, frame_len);

    free(udp_payload);
}
