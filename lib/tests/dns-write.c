#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include <libpcapng/protocols/dns.h>
#include <libpcapng/easyapi.h>
#include <libpcapng/linktypes.h>

// Maximum safe DNS packet size (standard DNS UDP limit)
#define DNS_MAX_SIZE 512

int main(void) {
    FILE *pcapout = fopen("dns_example.pcapng", "wb");
    if (!pcapout) {
        perror("fopen");
        return 1;
    }

    // Write PCAPNG header
    libpcapng_write_header_to_file_with_linktype(pcapout, LINKTYPE_ETHERNET);

    uint8_t frame[65536];
    size_t frame_len;

    // MAC addresses
    uint8_t client_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t server_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    // IP addresses (as host byte order integers)
    uint32_t client_ip = (192 << 24) | (168 << 16) | (1 << 8) | 100;  // 192.168.1.100
    uint32_t server_ip = (8 << 24) | (8 << 16) | (8 << 8) | 8;        // 8.8.8.8

    // DNS query buffer
    uint8_t dns_query[DNS_MAX_SIZE];
    size_t query_len;

    // DNS response buffer
    uint8_t dns_response[DNS_MAX_SIZE];
    size_t response_len;

    printf("Building DNS query packet...\n");
    
    // Build DNS query: "www.example.com" A record, transaction ID 0x1234
    query_len = libpcapng_dns_build_query(
        dns_query,
        DNS_MAX_SIZE,        // buffer size
        0x1234,              // transaction ID
        1,                   // recursion desired
        "www.example.com",   // domain name
        1,                   // qtype: A record
        1                    // qclass: IN (Internet)
    );

    // Security check: ensure we didn't overflow
    if (query_len == 0 || query_len > DNS_MAX_SIZE) {
        fprintf(stderr, "ERROR: DNS query failed or too large\n");
        fclose(pcapout);
        return 1;
    }

    // Build complete query packet
    libpcapng_dns_packet_build(
        client_mac, server_mac,
        client_ip, server_ip,
        54321, 53,           // src_port, dst_port
        (struct libpcapng_dns_hdr*)dns_query,
        dns_query + sizeof(struct libpcapng_dns_hdr),
        query_len - sizeof(struct libpcapng_dns_hdr),
        frame, &frame_len
    );

    // Write query packet to file
    libpcapng_write_enhanced_packet_to_file(pcapout, frame, frame_len);
    printf("Query packet written (%zu bytes)\n", frame_len);

    printf("Building DNS response packet with multiple answers...\n");

    // Build DNS response header with 3 answers
    struct libpcapng_dns_hdr dns_hdr;
    libpcapng_fill_dns_header(&dns_hdr,
        0x1234,              // same transaction ID
        1, 0, 1, 0, 1, 1, 0, // QR=1(response), AA=1, RD=1, RA=1
        1, 3, 0, 0);         // 1 question, 3 answers
    
    // Copy header to buffer
    memcpy(dns_response, &dns_hdr, sizeof(dns_hdr));
    size_t offset = sizeof(dns_hdr);
    
    // Security: track remaining space
    size_t remaining = DNS_MAX_SIZE - offset;
    
    // Add the question
    size_t question_len = libpcapng_dns_build_question(dns_response + offset, 
                                                       remaining,
                                                       "www.example.com", 1, 1);
    if (question_len == 0 || question_len > remaining) {
        fprintf(stderr, "ERROR: Buffer overflow prevented in question section\n");
        fclose(pcapout);
        return 1;
    }
    offset += question_len;
    remaining -= question_len;
    
    // Remember where the question name starts (for pointer compression)
    uint16_t qname_offset = sizeof(dns_hdr);
    
    // Add first answer: 93.184.216.34
    uint32_t ip1 = htonl((93 << 24) | (184 << 16) | (216 << 8) | 34);
    size_t answer1_len = libpcapng_dns_build_answer_a(dns_response + offset,
                                                       remaining,
                                                       qname_offset, ip1, 300);
    if (answer1_len == 0 || answer1_len > remaining) {
        fprintf(stderr, "ERROR: Buffer overflow prevented in answer 1\n");
        fclose(pcapout);
        return 1;
    }
    offset += answer1_len;
    remaining -= answer1_len;
    
    // Add second answer: 93.184.216.35
    uint32_t ip2 = htonl((93 << 24) | (184 << 16) | (216 << 8) | 35);
    size_t answer2_len = libpcapng_dns_build_answer_a(dns_response + offset, remaining,
                                                       qname_offset, ip2, 300);
    if (answer2_len > remaining) {
        fprintf(stderr, "ERROR: Buffer overflow prevented in answer 2\n");
        fclose(pcapout);
        return 1;
    }
    offset += answer2_len;
    remaining -= answer2_len;
    
    // Add third answer: 93.184.216.36
    uint32_t ip3 = htonl((93 << 24) | (184 << 16) | (216 << 8) | 36);
    size_t answer3_len = libpcapng_dns_build_answer_a(dns_response + offset, remaining,
                                                       qname_offset, ip3, 300);
    if (answer3_len > remaining) {
        fprintf(stderr, "ERROR: Buffer overflow prevented in answer 3\n");
        fclose(pcapout);
        return 1;
    }
    offset += answer3_len;
    
    response_len = offset;

    // Final security check
    assert(response_len <= DNS_MAX_SIZE);

    // Build complete response packet (swap src/dst)
    libpcapng_dns_packet_build(
        server_mac, client_mac,
        server_ip, client_ip,
        53, 54321,           // src_port, dst_port (swapped)
        (struct libpcapng_dns_hdr*)dns_response,
        dns_response + sizeof(struct libpcapng_dns_hdr),
        response_len - sizeof(struct libpcapng_dns_hdr),
        frame, &frame_len
    );

    // Write response packet to file
    libpcapng_write_enhanced_packet_to_file(pcapout, frame, frame_len);
    printf("Response packet written (%zu bytes)\n", frame_len);

    fclose(pcapout);
    printf("Done! Created dns_example.pcapng\n");
    printf("Open with: wireshark dns_example.pcapng\n");

    return 0;
}
