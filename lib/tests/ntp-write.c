#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include <libpcapng/protocols/ntp.h>
#include <libpcapng/protocols/udp.h>
#include <libpcapng/protocols/ipv4.h>
#include <libpcapng/protocols/ethernet.h>

#include <libpcapng/easyapi.h>
#include <libpcapng/linktypes.h>


int main() {
    uint8_t frame_out[1500];
    size_t frame_len;

    // Example MAC addresses
    uint8_t client_mac[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    uint8_t server_mac[6] = {0xde,0xad,0xbe,0xef,0x00,0x01};

    // IP addresses in network byte order
    uint32_t client_ip = libpcapng_ipv4_to_host_order("192.168.1.42");
    uint32_t server_ip = libpcapng_ipv4_to_host_order("192.168.1.1");

    uint16_t src_port = 123; 
    uint16_t dst_port = 123; 

    uint32_t xid = 0x12345678; // transaction ID

    FILE *pcapout = fopen("ntp_example.pcapng", "wb");
    if (!pcapout) {
        perror("fopen");
        return 1;
    }

    // Write PCAPNG header
    libpcapng_write_header_to_file_with_linktype(pcapout, LINKTYPE_ETHERNET);
    
    libpcapng_build_ntp_request(
        client_mac,
        server_mac,
        client_ip,
        server_ip,
        src_port,
        dst_port,
        frame_out,
        &frame_len
    );

    libpcapng_write_enhanced_packet_to_file(pcapout, frame_out, frame_len);

    struct libpcapng_ntp_hdr *req_hdr = (struct libpcapng_ntp_hdr *)(frame_out + sizeof(struct libpcapng_eth_hdr) + sizeof(struct libpcapng_ipv4_hdr) + sizeof(struct libpcapng_udp_hdr));
    libpcapng_build_ntp_reply(server_mac, client_mac,
                    server_ip, client_ip,
                    src_port, dst_port,
                    req_hdr,
                    frame_out, &frame_len);

    libpcapng_write_enhanced_packet_to_file(pcapout, frame_out, frame_len); 

    fclose(pcapout);
    
    return 0;
}
