#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libpcapng/protocols/udp.h>
#include <libpcapng/protocols/dhcp.h>

static const uint8_t DHCP_MAGIC_COOKIE[4] = {
    0x63, 0x82, 0x53, 0x63
};

#define DHCP_OPT_MSGTYPE   53
#define DHCP_OPT_SERVERID  54
#define DHCP_OPT_SUBNETMASK 1
#define DHCP_OPT_ROUTER     3
#define DHCP_OPT_DNS        6
#define DHCP_OPT_REQIP     50
#define DHCP_OPT_END       255

#define DHCPDISCOVER 1
#define DHCPOFFER    2

static uint8_t *libpcapng_dhcp_opt(uint8_t *buf, uint8_t code, uint8_t len, const void *val)
{
    buf[0] = code;
    buf[1] = len;
    memcpy(buf + 2, val, len);
    return buf + 2 + len;
}

static uint8_t *libpcapng_dhcp_opt_u8(uint8_t *buf, uint8_t code, uint8_t value)
{
    buf[0] = code;
    buf[1] = 1;
    buf[2] = value;
    return buf + 3;
}

void libpcapng_build_dhcp_discover(const uint8_t src_mac[6],
				   uint32_t ip_src,
				   uint16_t sport, uint16_t dport,
				   uint32_t xid,
				   uint8_t *frame_out, size_t *frame_len)
{
    uint8_t bootp[1024];
    memset(bootp, 0, sizeof(bootp));

    struct libpcapng_bootp_hdr *b = (struct libpcapng_bootp_hdr *)bootp;
    b->op    = 1;      // request
    b->htype = 1;      // Ethernet
    b->hlen  = 6;
    b->xid   = htonl(xid);

    memcpy(b->chaddr, src_mac, 6);

    // DHCP options
    uint8_t *opt = b->options;

    memcpy(opt, DHCP_MAGIC_COOKIE, 4);
    opt += 4;

    opt = libpcapng_dhcp_opt_u8(opt, DHCP_OPT_MSGTYPE, DHCPDISCOVER);

    opt[0] = DHCP_OPT_END;
    opt++;

    size_t bootp_len = (opt - (uint8_t *)bootp);

    uint8_t dst_mac[6];
    memset(dst_mac, 0xFF, 6);

    uint32_t dst_ip = libpcapng_ipv4_to_network_order("255.255.255.255");

    libpcapng_udp_packet_build(
        src_mac, dst_mac,
        ip_src, dst_ip,
        sport, dport,
        bootp, bootp_len,
        frame_out, frame_len
    );
}

void libpcapng_build_dhcp_offer(const uint8_t server_mac[6],
				const uint8_t client_mac[6],
				uint32_t server_ip,      // network byte order
				uint32_t offered_ip,     // network byte order
				uint32_t xid,
				uint16_t sport,
				uint16_t dport,
				uint8_t *frame_out,
				size_t *frame_len)
{
    uint8_t bootp[1024];
    memset(bootp, 0, sizeof(bootp));

    struct libpcapng_bootp_hdr *b = (struct libpcapng_bootp_hdr *)bootp;
    b->op    = 2;      // reply
    b->htype = 1;      // Ethernet
    b->hlen  = 6;
    b->xid   = htonl(xid);
    b->flags = htons(0x8000); // broadcast
    b->yiaddr = offered_ip;   // IP being offered
    b->siaddr = server_ip;    // DHCP server IP
    memcpy(b->chaddr, client_mac, 6);

    // DHCP options
    uint8_t *opt = b->options;

    // Magic cookie
    memcpy(opt, DHCP_MAGIC_COOKIE, sizeof(DHCP_MAGIC_COOKIE));
    opt += sizeof(DHCP_MAGIC_COOKIE);

    // Message type: OFFER
    opt = libpcapng_dhcp_opt_u8(opt, DHCP_OPT_MSGTYPE, DHCPOFFER);

    // Server Identifier
    opt = libpcapng_dhcp_opt(opt, DHCP_OPT_SERVERID, 4, &server_ip);

    // Subnet mask: 255.255.255.0
    uint32_t mask = htonl(0xFFFFFF00);
    opt = libpcapng_dhcp_opt(opt, DHCP_OPT_SUBNETMASK, 4, &mask);

    // End
    *opt++ = DHCP_OPT_END;

    size_t bootp_len = (opt - (uint8_t *)bootp);

    // Broadcast MAC for client
    uint8_t dst_mac[6];
    memset(dst_mac, 0xFF, 6);

    // Broadcast IP for client
    uint32_t dst_ip = 0xFFFFFFFF;

    libpcapng_udp_packet_build(
        server_mac, dst_mac,
        server_ip, dst_ip,
        sport, dport,
        bootp, bootp_len,
        frame_out, frame_len
    );
}
