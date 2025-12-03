#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include <libpcapng/protocols/dhcp.h>
#include <libpcapng/protocols/udp.h>
#include <libpcapng/easyapi.h>
#include <libpcapng/linktypes.h>


int main() {
    uint8_t discover_frame[DHCP_FRAME_MAXLENGTH];
    size_t discover_len;

    uint8_t offer_frame[DHCP_FRAME_MAXLENGTH];
    size_t offer_len;

    // Example MAC addresses
    uint8_t client_mac[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    uint8_t server_mac[6] = {0xde,0xad,0xbe,0xef,0x00,0x01};

    // IP addresses in network byte order
    uint32_t client_ip = inet_addr("0.0.0.0");       // for discover, usually 0.0.0.0
    uint32_t server_ip = inet_addr("192.168.1.1");   // DHCP server IP
    uint32_t offered_ip = inet_addr("192.168.1.100");// IP being offered in DHCPOFFER

    uint16_t src_port = 68;  // client port
    uint16_t dst_port = 67;  // server port

    uint32_t xid = 0x12345678; // transaction ID

    FILE *pcapout = fopen("dhcp_example.pcapng", "wb");
    if (!pcapout) {
        perror("fopen");
        return 1;
    }

    // Write PCAPNG header
    libpcapng_write_header_to_file_with_linktype(pcapout, LINKTYPE_ETHERNET);
    
    libpcapng_build_dhcp_discover(
				  client_mac,
				  client_ip,
				  src_port,
				  dst_port,
				  xid,
				  discover_frame,
				  &discover_len
				  );

    libpcapng_write_enhanced_packet_to_file(pcapout, discover_frame, discover_len);

    /* printf("DHCP DISCOVER packet built, length: %zu bytes\n", discover_len); */

    libpcapng_build_dhcp_offer(
			       server_mac,
			       client_mac,
			       server_ip,
			       offered_ip,
			       xid,
			       dst_port,
			       src_port,  // swap ports: server->client
			       offer_frame,
			       &offer_len
			       );
    
    /* printf("DHCP OFFER packet built, length: %zu bytes\n", offer_len); */
    libpcapng_write_enhanced_packet_to_file(pcapout, offer_frame, offer_len); 

    fclose(pcapout);
    
    return 0;
}
