#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <libpcapng/easyapi.h>
#include <libpcapng/linktypes.h>

#include <libpcapng/protocols/ethernet.h>
#include <libpcapng/protocols/ipv4.h>
#include <libpcapng/protocols/dns.h>

int main(void) {

  FILE *pcapout;
  uint8_t frame[65536];
  size_t frame_len;

  uint8_t dnsbuf[512];
  size_t dns_len = 0;

  pcapout = fopen("out.pcapng", "wb");
  libpcapng_write_header_to_file_with_linktype(pcapout, LINKTYPE_ETHERNET);
  fflush(pcapout);
  
  struct libpcapng_dns_hdr dns;
  libpcapng_fill_dns_header(&dns, 0x1234,
			    0,0,0,0,1,0,0,   // query, recursion desired
			    1,0,0,0);        // 1 question
  
  dns_len += sizeof(dns);
  
  dns_len += libpcapng_dns_build_question(dnsbuf + dns_len,
					  "www.example.com",
					  1,  // A
					  1); // IN
  uint8_t src_mac[6] = {0x02,0x00,0x00,0x00,0x00,0x01};
  uint8_t dst_mac[6] = {0x02,0x00,0x00,0x00,0x00,0x02};
  
  libpcapng_dns_packet_build(src_mac, dst_mac,
			     libpcapng_ipv4_to_host_order("1.2.3.4"),
			     libpcapng_ipv4_to_host_order("9.5.4.3"),
			     12345, 53,
			     &dns,
			     dnsbuf + sizeof(dns),
			     dns_len - sizeof(dns),
			     frame, &frame_len);

  libpcapng_write_enhanced_packet_to_file(pcapout, frame, frame_len);

  fflush(pcapout);
  fclose(pcapout);

  return 0;
}
