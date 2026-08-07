/*
 * filter.c — Wireshark-compatible capture filter tests
 *
 * Tests pcapng_capture_filter_match() against hand-crafted packet bytes
 * that cover every filter feature: field existence, comparisons, boolean
 * logic, in{} sets, IPv4 CIDR, byte slices, slice bitmasks.
 *
 * Build via cmake (registered as the Filter ctest target), or manually:
 *   cc -I../include -o filter filter.c -lpcapng
 *   ./filter
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libpcapng/capture.h>

/* ── Minimal test harness ──────────────────────────────────────────────── */

static int g_tests  = 0;
static int g_passed = 0;
static int g_failed = 0;
static const char *g_suite = "";

#define SUITE(name)  do { g_suite = (name); printf("\n[%s]\n", g_suite); } while(0)

#define CHECK(expr) do {                                                       \
    g_tests++;                                                                 \
    if (expr) {                                                                \
        g_passed++;                                                            \
        printf("  PASS  %s\n", #expr);                                        \
    } else {                                                                   \
        g_failed++;                                                            \
        printf("  FAIL  %s  (%s:%d)\n", #expr, __FILE__, __LINE__);          \
    }                                                                          \
} while(0)

#define LT_ETHERNET 1
#define LT_RAW      101

/* match() / nomatch() / err() — readable test shorthands */
static int match(const char *expr, const uint8_t *pkt, uint32_t len, uint16_t lt)
{
    char errbuf[256] = "";
    int r = pcapng_capture_filter_match(expr, pkt, len, lt, errbuf);
    if (r == -1) printf("      compile error for '%s': %s\n", expr, errbuf);
    return r == 1;
}
static int nomatch(const char *expr, const uint8_t *pkt, uint32_t len, uint16_t lt)
{
    char errbuf[256] = "";
    int r = pcapng_capture_filter_match(expr, pkt, len, lt, errbuf);
    if (r == -1) printf("      compile error for '%s': %s\n", expr, errbuf);
    return r == 0;
}
static int compile_err(const char *expr)
{
    return pcapng_capture_filter_match(expr, NULL, 0, LT_ETHERNET, NULL) == -1;
}

/* ── Packet fixtures ───────────────────────────────────────────────────── */

/*
 * PKT_TCP_SYN — Ethernet/IPv4/TCP SYN
 *
 *   Ether:  dst=ff:ff:ff:ff:ff:ff  src=aa:bb:cc:dd:ee:ff  type=0x0800
 *   IPv4:   src=192.168.1.1  dst=10.0.0.1  proto=6(TCP)  TTL=64  IHL=5
 *   TCP:    sport=12345(0x3039)  dport=80(0x0050)  flags=SYN(0x02)  off=5
 *
 *   Slice landmarks (relative to each layer base):
 *     eth[12:2] = 0x0800   eth[6:6] = aa:bb:cc:dd:ee:ff (src)
 *     ip[0]     = 0x45     ip[8]    = 64(TTL)   ip[9]=6(proto)
 *     ip[12:4]  = c0a80101 (src)    ip[16:4] = 0a000001 (dst)
 *     tcp[0:2]  = 0x3039 (sport)    tcp[2:2] = 0x0050 (dport)
 *     tcp[13]   = 0x02 (SYN)        tcp[12]  = 0x50 (data offset)
 *     frame[14] = 0x45 (start of IPv4 within Ethernet frame)
 */
static const uint8_t PKT_TCP_SYN[] = {
    /* Ethernet */
    0xff,0xff,0xff,0xff,0xff,0xff, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x08,0x00,
    /* IPv4 */
    0x45,0x00,0x00,0x28, 0x00,0x01,0x00,0x00, 0x40,0x06,0x00,0x00,
    0xc0,0xa8,0x01,0x01, 0x0a,0x00,0x00,0x01,
    /* TCP */
    0x30,0x39,0x00,0x50, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x50,0x02,0xff,0xff, 0x00,0x00,0x00,0x00
};
static const uint32_t PKT_TCP_SYN_LEN = sizeof PKT_TCP_SYN;

/*
 * PKT_TCP_ACKPSH — Ethernet/IPv4/TCP PSH+ACK (no SYN, no RST, no FIN)
 *
 *   IPv4:  src=172.16.0.1  dst=172.16.0.2  proto=6  TTL=128
 *   TCP:   sport=50000(0xc350)  dport=443(0x01bb)  flags=PSH+ACK(0x18)
 */
static const uint8_t PKT_TCP_ACKPSH[] = {
    /* Ethernet */
    0xde,0xad,0xbe,0xef,0x00,0x01, 0x00,0x11,0x22,0x33,0x44,0x55, 0x08,0x00,
    /* IPv4 */
    0x45,0x00,0x00,0x28, 0x00,0x04,0x00,0x00, 0x80,0x06,0x00,0x00,
    0xac,0x10,0x00,0x01, 0xac,0x10,0x00,0x02,
    /* TCP */
    0xc3,0x50,0x01,0xbb, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x01,
    0x50,0x18,0x20,0x00, 0x00,0x00,0x00,0x00
};
static const uint32_t PKT_TCP_ACKPSH_LEN = sizeof PKT_TCP_ACKPSH;

/*
 * PKT_TCP_RST — TCP RST+ACK
 *
 *   IPv4:  src=10.0.0.2  dst=10.0.0.1
 *   TCP:   sport=80(0x0050)  dport=54321(0xd431)  flags=RST+ACK(0x14)
 */
static const uint8_t PKT_TCP_RST[] = {
    /* Ethernet */
    0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x08,0x00,
    /* IPv4 */
    0x45,0x00,0x00,0x28, 0x00,0x05,0x00,0x00, 0x40,0x06,0x00,0x00,
    0x0a,0x00,0x00,0x02, 0x0a,0x00,0x00,0x01,
    /* TCP */
    0x00,0x50,0xd4,0x31, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x01,
    0x50,0x14,0x00,0x00, 0x00,0x00,0x00,0x00
};
static const uint32_t PKT_TCP_RST_LEN = sizeof PKT_TCP_RST;

/*
 * PKT_UDP_DNS — Ethernet/IPv4/UDP (DNS query, dport=53)
 *
 *   IPv4:  src=10.0.0.5  dst=8.8.8.8  proto=17(UDP)  TTL=64
 *   UDP:   sport=54321(0xd431)  dport=53(0x0035)  len=8
 */
static const uint8_t PKT_UDP_DNS[] = {
    /* Ethernet */
    0xff,0xff,0xff,0xff,0xff,0xff, 0x00,0x11,0x22,0x33,0x44,0x55, 0x08,0x00,
    /* IPv4 */
    0x45,0x00,0x00,0x1c, 0x00,0x02,0x00,0x00, 0x40,0x11,0x00,0x00,
    0x0a,0x00,0x00,0x05, 0x08,0x08,0x08,0x08,
    /* UDP */
    0xd4,0x31,0x00,0x35, 0x00,0x08,0x00,0x00
};
static const uint32_t PKT_UDP_DNS_LEN = sizeof PKT_UDP_DNS;

/*
 * PKT_UDP_NTP — Ethernet/IPv4/UDP NTP (dport=123)
 *
 *   IPv4:  src=192.168.0.10  dst=129.6.15.28  proto=17
 *   UDP:   sport=40000(0x9c40)  dport=123(0x007b)
 */
static const uint8_t PKT_UDP_NTP[] = {
    /* Ethernet */
    0x00,0x11,0x22,0x33,0x44,0x55, 0x66,0x77,0x88,0x99,0xaa,0xbb, 0x08,0x00,
    /* IPv4 */
    0x45,0x00,0x00,0x1c, 0x00,0x03,0x00,0x00, 0x40,0x11,0x00,0x00,
    0xc0,0xa8,0x00,0x0a, 0x81,0x06,0x0f,0x1c,
    /* UDP */
    0x9c,0x40,0x00,0x7b, 0x00,0x08,0x00,0x00
};
static const uint32_t PKT_UDP_NTP_LEN = sizeof PKT_UDP_NTP;

/*
 * PKT_ICMP — Ethernet/IPv4/ICMP echo request
 *
 *   IPv4:  src=10.10.0.5  dst=1.1.1.1  proto=1(ICMP)  TTL=64
 *   ICMP:  type=8(echo-request)  code=0
 */
static const uint8_t PKT_ICMP[] = {
    /* Ethernet */
    0x00,0x01,0x02,0x03,0x04,0x05, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x08,0x00,
    /* IPv4 */
    0x45,0x00,0x00,0x1c, 0x00,0x06,0x00,0x00, 0x40,0x01,0x00,0x00,
    0x0a,0x0a,0x00,0x05, 0x01,0x01,0x01,0x01,
    /* ICMP */
    0x08,0x00,0xf7,0xff, 0x00,0x01,0x00,0x01
};
static const uint32_t PKT_ICMP_LEN = sizeof PKT_ICMP;

/*
 * PKT_ARP — Ethernet/ARP request
 *
 *   Ether:  dst=ff:ff:ff:ff:ff:ff  src=aa:bb:cc:dd:ee:ff  type=0x0806
 *   ARP:    op=REQUEST(1)  spa=192.168.1.1  tpa=192.168.1.254
 */
static const uint8_t PKT_ARP[] = {
    /* Ethernet */
    0xff,0xff,0xff,0xff,0xff,0xff, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x08,0x06,
    /* ARP */
    0x00,0x01,0x08,0x00, 0x06,0x04,0x00,0x01,
    0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0xc0,0xa8,0x01,0x01,
    0x00,0x00,0x00,0x00,0x00,0x00, 0xc0,0xa8,0x01,0xfe
};
static const uint32_t PKT_ARP_LEN = sizeof PKT_ARP;

/*
 * PKT_IPV6_TCP — Ethernet/IPv6/TCP SYN
 *
 *   Ether:  type=0x86dd
 *   IPv6:   src=fd00::1  dst=fd00::2  next=6(TCP)  hop_limit=64
 *   TCP:    sport=60000(0xea60)  dport=8080(0x1f90)  flags=SYN(0x02)
 */
static const uint8_t PKT_IPV6_TCP[] = {
    /* Ethernet */
    0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x86,0xdd,
    /* IPv6 */
    0x60,0x00,0x00,0x00, 0x00,0x14,0x06,0x40,
    /* src fd00::1 */
    0xfd,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
    /* dst fd00::2 */
    0xfd,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
    /* TCP */
    0xea,0x60,0x1f,0x90, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x50,0x02,0xff,0xff, 0x00,0x00,0x00,0x00
};
static const uint32_t PKT_IPV6_TCP_LEN = sizeof PKT_IPV6_TCP;

/*
 * PKT_TCP_PRIV — TCP with dst port in a low/privileged range (dport=22/SSH)
 *
 *   IPv4:  src=198.51.100.1  dst=203.0.113.10
 *   TCP:   sport=32768(0x8000)  dport=22(0x0016)  flags=SYN(0x02)
 */
static const uint8_t PKT_TCP_SSH[] = {
    /* Ethernet */
    0x11,0x22,0x33,0x44,0x55,0x66, 0x77,0x88,0x99,0xaa,0xbb,0xcc, 0x08,0x00,
    /* IPv4 */
    0x45,0x00,0x00,0x28, 0x00,0x07,0x00,0x00, 0x40,0x06,0x00,0x00,
    0xc6,0x33,0x64,0x01, 0xcb,0x00,0x71,0x0a,
    /* TCP */
    0x80,0x00,0x00,0x16, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x50,0x02,0xff,0xff, 0x00,0x00,0x00,0x00
};
static const uint32_t PKT_TCP_SSH_LEN = sizeof PKT_TCP_SSH;

/*
 * PKT_VLAN_TCP — Ethernet 802.1Q / IPv4 / TCP SYN, VID=100
 *
 *   Ether: outer type=0x8100  TCI=0x0064(VID=100)  inner type=0x0800
 *   IPv4:  src=192.168.1.1  dst=10.0.0.1  proto=6  TTL=64  total=40
 *   TCP:   sport=12345  dport=80  SYN
 */
static const uint8_t PKT_VLAN_TCP[] = {
    /* Ethernet */
    0x11,0x22,0x33,0x44,0x55,0x66, 0xaa,0xbb,0xcc,0xdd,0xee,0xff, 0x81,0x00,
    /* VLAN TCI (PCP=0,DEI=0,VID=100) + inner EtherType */
    0x00,0x64, 0x08,0x00,
    /* IPv4 */
    0x45,0x00,0x00,0x28, 0x00,0x0a,0x00,0x00, 0x40,0x06,0x00,0x00,
    0xc0,0xa8,0x01,0x01, 0x0a,0x00,0x00,0x01,
    /* TCP */
    0x30,0x39,0x00,0x50, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x50,0x02,0xff,0xff, 0x00,0x00,0x00,0x00
};
static const uint32_t PKT_VLAN_TCP_LEN = sizeof PKT_VLAN_TCP;

/*
 * PKT_IPV6_ICMP6 — Ethernet/IPv6/ICMPv6 echo request
 *
 *   IPv6:   src=fd00::1  dst=fd00::2  next=58(ICMPv6)  hop=64
 *   ICMPv6: type=128(echo-request)  code=0
 */
static const uint8_t PKT_IPV6_ICMP6[] = {
    /* Ethernet */
    0x00,0x01,0x02,0x03,0x04,0x05, 0x06,0x07,0x08,0x09,0x0a,0x0b, 0x86,0xdd,
    /* IPv6 */
    0x60,0x00,0x00,0x00, 0x00,0x08,0x3a,0x40,
    0xfd,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
    0xfd,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
    /* ICMPv6 echo request */
    0x80,0x00,0x00,0x00, 0x00,0x01,0x00,0x01
};
static const uint32_t PKT_IPV6_ICMP6_LEN = sizeof PKT_IPV6_ICMP6;

/* ── Bidirectional packet builder ──────────────────────────────────────── */

/*
 * mk_pkt — write a minimal Ethernet/IPv4/TCP frame into buf[].
 * total size = 54 + dlen bytes.
 * IP total length = 40 + dlen (IP header + TCP header + payload).
 * Checksum fields are left as zero (kernel never validates them in tests).
 */
static void mk_pkt(uint8_t *buf, uint32_t bufsize,
                   const uint8_t srcip[4], const uint8_t dstip[4],
                   uint16_t sport, uint16_t dport,
                   uint8_t flags, uint32_t seq, uint32_t ack_n, uint16_t win,
                   uint32_t dlen)
{
    uint32_t total = 54u + dlen;
    if (total > bufsize) return;
    memset(buf, 0, total);
    /* Ethernet: ethertype = IPv4 */
    buf[12] = 0x08; buf[13] = 0x00;
    /* IPv4: IHL=5, TTL=64, proto=6 */
    buf[14] = 0x45;
    uint16_t iplen = (uint16_t)(40u + dlen);
    buf[16] = (uint8_t)(iplen >> 8); buf[17] = (uint8_t)iplen;
    buf[22] = 0x40; buf[23] = 0x06;
    memcpy(buf + 26, srcip, 4); memcpy(buf + 30, dstip, 4);
    /* TCP */
    buf[34] = (uint8_t)(sport >> 8); buf[35] = (uint8_t)sport;
    buf[36] = (uint8_t)(dport >> 8); buf[37] = (uint8_t)dport;
    buf[38] = (uint8_t)(seq  >> 24); buf[39] = (uint8_t)(seq  >> 16);
    buf[40] = (uint8_t)(seq  >>  8); buf[41] = (uint8_t)(seq);
    buf[42] = (uint8_t)(ack_n >> 24); buf[43] = (uint8_t)(ack_n >> 16);
    buf[44] = (uint8_t)(ack_n >>  8); buf[45] = (uint8_t)(ack_n);
    buf[46] = 0x50;      /* data offset = 5 */
    buf[47] = flags;
    buf[48] = (uint8_t)(win >> 8); buf[49] = (uint8_t)win;
}

/* IPs and ports for the bidirectional test flows */
static const uint8_t _IP_A[4] = {10, 0, 0, 1};
static const uint8_t _IP_B[4] = {10, 0, 0, 2};
#define MK_AB(buf_, flags_, seq_, ack_, win_, dlen_) \
    mk_pkt((buf_), sizeof(buf_), _IP_A, _IP_B, 1234, 80, \
           (flags_), (seq_), (ack_), (win_), (dlen_))
#define MK_BA(buf_, flags_, seq_, ack_, win_, dlen_) \
    mk_pkt((buf_), sizeof(buf_), _IP_B, _IP_A, 80, 1234, \
           (flags_), (seq_), (ack_), (win_), (dlen_))

/* ── Tests ─────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== capture filter tests ===\n");

    /* ── Field existence ─────────────────────────────────────────────────── */
    SUITE("Field existence");

    CHECK(match  ("tcp",  PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    CHECK(nomatch("tcp",  PKT_UDP_DNS,  PKT_UDP_DNS_LEN,  LT_ETHERNET));
    CHECK(match  ("udp",  PKT_UDP_DNS,  PKT_UDP_DNS_LEN,  LT_ETHERNET));
    CHECK(nomatch("udp",  PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    CHECK(match  ("ip",   PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    CHECK(match  ("ip",   PKT_UDP_DNS,  PKT_UDP_DNS_LEN,  LT_ETHERNET));
    CHECK(nomatch("ip",   PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(match  ("ip6",  PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(nomatch("ip6",  PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    CHECK(match  ("icmp", PKT_ICMP,     PKT_ICMP_LEN,     LT_ETHERNET));
    CHECK(nomatch("icmp", PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    CHECK(match  ("arp",  PKT_ARP,      PKT_ARP_LEN,      LT_ETHERNET));
    CHECK(nomatch("arp",  PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));

    /* ── IPv4 address comparisons ────────────────────────────────────────── */
    SUITE("IPv4 address comparisons");

    CHECK(match  ("ip.src == 192.168.1.1", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("ip.src == 192.168.1.2", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("ip.dst == 10.0.0.1",    PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("ip.dst == 10.0.0.2",    PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* ip.addr matches either src or dst */
    CHECK(match  ("ip.addr == 192.168.1.1", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("ip.addr == 10.0.0.1",    PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("ip.addr == 1.2.3.4",     PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));

    /* ── IPv4 CIDR ───────────────────────────────────────────────────────── */
    SUITE("IPv4 CIDR");

    CHECK(match  ("ip.src == 192.168.1.0/24",  PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("ip.src == 192.168.0.0/16",  PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("ip.src == 192.168.2.0/24",  PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("ip.dst == 10.0.0.0/8",      PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("ip.dst == 172.16.0.0/12",   PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* dns packet: dst=8.8.8.8 */
    CHECK(match  ("ip.dst == 8.8.8.0/24",      PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(nomatch("ip.dst == 8.8.4.0/24",      PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));

    /* ── TCP port comparisons ────────────────────────────────────────────── */
    SUITE("TCP port comparisons");

    CHECK(match  ("tcp.dstport == 80",   PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(nomatch("tcp.dstport == 443",  PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(match  ("tcp.srcport == 12345",PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(match  ("tcp.dstport == 443",  PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    CHECK(match  ("tcp.srcport == 50000",PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    /* tcp.port matches either direction */
    CHECK(match  ("tcp.port == 80",      PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(match  ("tcp.port == 12345",   PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(nomatch("tcp.port == 8080",    PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(match  ("tcp.dstport == 22",   PKT_TCP_SSH,   PKT_TCP_SSH_LEN,   LT_ETHERNET));

    /* ── UDP port comparisons ────────────────────────────────────────────── */
    SUITE("UDP port comparisons");

    CHECK(match  ("udp.dstport == 53",   PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(nomatch("udp.dstport == 80",   PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("udp.srcport == 54321",PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("udp.port == 53",      PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("udp.dstport == 123",  PKT_UDP_NTP, PKT_UDP_NTP_LEN, LT_ETHERNET));
    CHECK(match  ("udp.port == 123",     PKT_UDP_NTP, PKT_UDP_NTP_LEN, LT_ETHERNET));
    CHECK(nomatch("udp.port == 443",     PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));

    /* ── TCP flags ───────────────────────────────────────────────────────── */
    SUITE("TCP flags");

    CHECK(match  ("tcp.flags == 2",      PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(nomatch("tcp.flags == 2",      PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    CHECK(match  ("tcp.flags == 0x18",   PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    CHECK(match  ("tcp.flags == 0x14",   PKT_TCP_RST,   PKT_TCP_RST_LEN,   LT_ETHERNET));
    /* individual flag fields */
    CHECK(match  ("tcp.flags.syn == 1",  PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(nomatch("tcp.flags.syn == 1",  PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    CHECK(match  ("tcp.flags.ack == 1",  PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    CHECK(nomatch("tcp.flags.ack == 1",  PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(match  ("tcp.flags.rst == 1",  PKT_TCP_RST,   PKT_TCP_RST_LEN,   LT_ETHERNET));
    CHECK(nomatch("tcp.flags.rst == 1",  PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(match  ("tcp.flags.fin == 0",  PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));

    /* ── IP protocol and TTL ─────────────────────────────────────────────── */
    SUITE("IP protocol and TTL");

    CHECK(match  ("ip.proto == 6",   PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("ip.proto == 17",  PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("ip.proto == 1",   PKT_ICMP,    PKT_ICMP_LEN,    LT_ETHERNET));
    CHECK(nomatch("ip.proto == 6",   PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("ip.ttl == 64",    PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("ip.ttl >= 64",    PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("ip.ttl <= 128",   PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("ip.ttl > 64",     PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* PKT_TCP_ACKPSH has TTL=128 */
    CHECK(match  ("ip.ttl == 128",   PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    CHECK(match  ("ip.ttl > 64",     PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));

    /* ── Ethernet ────────────────────────────────────────────────────────── */
    SUITE("Ethernet");

    CHECK(match  ("eth.type == 0x0800", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("eth.type == 0x0806", PKT_ARP,     PKT_ARP_LEN,     LT_ETHERNET));
    CHECK(match  ("eth.type == 0x86dd", PKT_IPV6_TCP,PKT_IPV6_TCP_LEN,LT_ETHERNET));
    CHECK(nomatch("eth.type == 0x0800", PKT_ARP,     PKT_ARP_LEN,     LT_ETHERNET));
    CHECK(match  ("eth.dst == ff:ff:ff:ff:ff:ff", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("eth.src == aa:bb:cc:dd:ee:ff", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("eth.src == 00:11:22:33:44:55", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* eth.addr matches src or dst */
    CHECK(match  ("eth.addr == ff:ff:ff:ff:ff:ff", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("eth.addr == aa:bb:cc:dd:ee:ff", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("eth.addr == 11:22:33:44:55:66", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));

    /* ── ICMP type/code ──────────────────────────────────────────────────── */
    SUITE("ICMP type/code");

    CHECK(match  ("icmp.type == 8", PKT_ICMP, PKT_ICMP_LEN, LT_ETHERNET));
    CHECK(nomatch("icmp.type == 0", PKT_ICMP, PKT_ICMP_LEN, LT_ETHERNET));
    CHECK(match  ("icmp.code == 0", PKT_ICMP, PKT_ICMP_LEN, LT_ETHERNET));

    /* ── Boolean logic ───────────────────────────────────────────────────── */
    SUITE("Boolean logic");

    CHECK(match  ("tcp and ip.src == 192.168.1.1",   PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("tcp and ip.src == 192.168.1.2",   PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("tcp or udp",   PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("tcp or udp",   PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(nomatch("tcp or udp",   PKT_ICMP,    PKT_ICMP_LEN,    LT_ETHERNET));
    CHECK(match  ("not udp",      PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("not tcp",      PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("not tcp",      PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    /* operator aliases: &&  ||  ! */
    CHECK(match  ("tcp && ip.src == 192.168.1.1",  PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("tcp || udp",                    PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("!udp",                          PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* parentheses */
    CHECK(match  ("(tcp or udp) and not icmp",     PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("(tcp or icmp) and ip.ttl == 64",PKT_ICMP,    PKT_ICMP_LEN,    LT_ETHERNET));
    /* compound */
    CHECK(match  ("ip.src == 192.168.1.1 and tcp.dstport == 80",  PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("ip.src == 192.168.1.1 and tcp.dstport == 443", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));

    /* ── in{} set membership ─────────────────────────────────────────────── */
    SUITE("in{} set membership");

    CHECK(match  ("tcp.dstport in {80 443 8080}",  PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("tcp.dstport in {443 8080 8443}", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("tcp.dstport in {443 8080 8443}", PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    CHECK(match  ("tcp.port in {80 443}",           PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("udp.dstport in {53 67 68 123}",  PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(nomatch("udp.dstport in {80 443}",         PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("ip.proto in {6 17}",              PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("ip.proto in {6 17}",              PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(nomatch("ip.proto in {6 17}",              PKT_ICMP,    PKT_ICMP_LEN,    LT_ETHERNET));

    /* ── Byte slice notation: proto[offset] ─────────────────────────────── */
    SUITE("Byte slice: single byte");

    /* ip[9] = protocol field (byte 9 of IP header) */
    CHECK(match  ("ip[9] == 6",    PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("ip[9] == 17",   PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("ip[9] == 1",    PKT_ICMP,    PKT_ICMP_LEN,    LT_ETHERNET));
    CHECK(nomatch("ip[9] == 6",    PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    /* ip[8] = TTL */
    CHECK(match  ("ip[8] == 64",   PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("ip[8] >= 64",   PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* ip[0] = version+IHL: 0x45 for standard IPv4 */
    CHECK(match  ("ip[0] == 0x45", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* tcp[13] = flags byte */
    CHECK(match  ("tcp[13] == 2",    PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(nomatch("tcp[13] == 2",    PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    CHECK(match  ("tcp[13] == 0x18", PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    CHECK(match  ("tcp[13] == 0x14", PKT_TCP_RST,   PKT_TCP_RST_LEN,   LT_ETHERNET));
    /* icmp[0] = ICMP type */
    CHECK(match  ("icmp[0] == 8", PKT_ICMP, PKT_ICMP_LEN, LT_ETHERNET));
    CHECK(match  ("icmp[1] == 0", PKT_ICMP, PKT_ICMP_LEN, LT_ETHERNET));
    /* udp[3] = low byte of dst port (53 = 0x35) */
    CHECK(match  ("udp[3] == 0x35", PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));

    /* ── Byte slice: multi-byte (proto[offset:len]) ──────────────────────── */
    SUITE("Byte slice: multi-byte");

    /* tcp[0:2] = source port as big-endian uint16 */
    CHECK(match  ("tcp[0:2] == 0x3039", PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(match  ("tcp[0:2] == 12345",  PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    /* tcp[2:2] = destination port */
    CHECK(match  ("tcp[2:2] == 0x0050", PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(match  ("tcp[2:2] == 80",     PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(match  ("tcp[2:2] == 443",    PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    CHECK(nomatch("tcp[2:2] == 443",    PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    /* ip[12:4] = source IPv4 address as big-endian uint32: 192.168.1.1 = 0xc0a80101 */
    CHECK(match  ("ip[12:4] == 0xc0a80101", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("ip[12:4] == 0xc0a80102", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* ip[16:4] = dest IPv4 address: 10.0.0.1 = 0x0a000001 */
    CHECK(match  ("ip[16:4] == 0x0a000001", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* eth[12:2] = EtherType */
    CHECK(match  ("eth[12:2] == 0x0800", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("eth[12:2] == 0x0806", PKT_ARP,     PKT_ARP_LEN,     LT_ETHERNET));
    CHECK(match  ("eth[12:2] == 0x86dd", PKT_IPV6_TCP,PKT_IPV6_TCP_LEN,LT_ETHERNET));
    /* udp[2:2] = dst port */
    CHECK(match  ("udp[2:2] == 53",  PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("udp[2:2] == 123", PKT_UDP_NTP, PKT_UDP_NTP_LEN, LT_ETHERNET));

    /* ── Byte slice: frame[] — absolute offset from packet start ─────────── */
    SUITE("Byte slice: frame[]");

    /* frame[0..5] = Ethernet dst MAC bytes */
    CHECK(match  ("frame[0] == 0xff",   PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("frame[5] == 0xff",   PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* frame[12:2] = EtherType (same as eth[12:2]) */
    CHECK(match  ("frame[12:2] == 0x0800", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* frame[14] = first byte of IPv4 header */
    CHECK(match  ("frame[14] == 0x45",  PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* frame[23] = IPv4 proto (14+9) */
    CHECK(match  ("frame[23] == 6",     PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("frame[23] == 17",    PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));

    /* ── Byte slice bitmask: proto[off:len]&mask ─────────────────────────── */
    SUITE("Byte slice bitmask");

    /* tcp[13]&0x02 — isolate SYN bit */
    CHECK(match  ("tcp[13]&0x02 == 0x02", PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(nomatch("tcp[13]&0x02 == 0x02", PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    CHECK(nomatch("tcp[13]&0x02 == 0x02", PKT_TCP_RST,   PKT_TCP_RST_LEN,   LT_ETHERNET));

    /* tcp[13]&0x10 — isolate ACK bit */
    CHECK(match  ("tcp[13]&0x10 == 0x10", PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    CHECK(nomatch("tcp[13]&0x10 == 0x10", PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    /* ACK is set in RST+ACK */
    CHECK(match  ("tcp[13]&0x10 == 0x10", PKT_TCP_RST,   PKT_TCP_RST_LEN,   LT_ETHERNET));

    /* tcp[13]&0x04 — isolate RST bit */
    CHECK(match  ("tcp[13]&0x04 == 0x04", PKT_TCP_RST,   PKT_TCP_RST_LEN,   LT_ETHERNET));
    CHECK(nomatch("tcp[13]&0x04 == 0x04", PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(nomatch("tcp[13]&0x04 == 0x04", PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));

    /* tcp[13]&0x01 — FIN bit (not set in any of our test packets) */
    CHECK(match  ("tcp[13]&0x01 == 0",    PKT_TCP_SYN,   PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(match  ("tcp[13]&0x01 == 0",    PKT_TCP_ACKPSH,PKT_TCP_ACKPSH_LEN,LT_ETHERNET));
    CHECK(match  ("tcp[13]&0x01 == 0",    PKT_TCP_RST,   PKT_TCP_RST_LEN,   LT_ETHERNET));

    /* tcp[13]&0x03 — SYN+FIN together (never set simultaneously in valid traffic) */
    CHECK(nomatch("tcp[13]&0x03 == 0x03", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));

    /* ip[0]&0xf0 — IP version nibble (should be 0x40 for IPv4) */
    CHECK(match  ("ip[0]&0xf0 == 0x40",   PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("ip[0]&0xf0 == 0x40",   PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));

    /* ip[0]&0x0f — IHL nibble (5 for no options) */
    CHECK(match  ("ip[0]&0x0f == 5",      PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));

    /* ip[6:2]&0x1fff — fragment offset (0 = not fragmented) */
    CHECK(match  ("ip[6:2]&0x1fff == 0",  PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("ip[6:2]&0x1fff == 0",  PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));

    /* eth[12:2] & 0x00ff — low byte of EtherType */
    CHECK(match  ("eth[12:2]&0x00ff == 0x0000", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));

    /* Bitmask combined with boolean */
    CHECK(match  ("tcp and tcp[13]&0x02 == 2",  PKT_TCP_SYN,    PKT_TCP_SYN_LEN,   LT_ETHERNET));
    CHECK(match  ("tcp and tcp[13]&0x10 == 0x10 and ip.dst == 172.16.0.2",
                  PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));
    CHECK(nomatch("tcp and tcp[13]&0x02 == 2 and tcp[2:2] == 443",
                  PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));

    /* ── Bounds checking — out-of-range slices should not match ─────────── */
    SUITE("Slice bounds checking");

    /* access beyond packet end: should return 0 (no match), not crash */
    CHECK(nomatch("tcp[100] == 0",  PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    CHECK(nomatch("ip[100]  == 0",  PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    CHECK(nomatch("frame[200] == 0",PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    /* tcp slice on a UDP packet: no tcp layer → no match */
    CHECK(nomatch("tcp[0] == 0",    PKT_UDP_DNS,  PKT_UDP_DNS_LEN,  LT_ETHERNET));
    /* udp slice on TCP packet */
    CHECK(nomatch("udp[0] == 0",    PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));

    /* ── Compile errors ──────────────────────────────────────────────────── */
    SUITE("Compile errors");

    CHECK(compile_err("ip.src =="));           /* missing value */
    CHECK(compile_err("tcp.port in {}"));       /* empty set */
    CHECK(compile_err("@badfield == 1"));       /* bad character */

    /* ── IPv6 existence ──────────────────────────────────────────────────── */
    SUITE("IPv6");

    CHECK(match  ("ip6",  PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(match  ("ipv6", PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(nomatch("ip",   PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(match  ("tcp",  PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    /* slice into IPv6 TCP layer */
    CHECK(match  ("tcp[2:2] == 8080",  PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(match  ("tcp[13]&0x02 == 2", PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));

    /* ── comma-separated in{} ───────────────────────────────────────────────
     * Both whitespace and commas must be accepted as value separators.       */
    SUITE("in{} comma separators");

    CHECK(match  ("tcp.dstport in {80, 443, 8080}", PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(nomatch("tcp.dstport in {443, 8080}",     PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("tcp.dstport in {443, 8080}",     PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));
    CHECK(match  ("udp.dstport in {53, 67, 123}",   PKT_UDP_DNS,    PKT_UDP_DNS_LEN,    LT_ETHERNET));
    CHECK(match  ("ip.proto in {6, 17}",            PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("ip.proto in {6, 17}",            PKT_UDP_DNS,    PKT_UDP_DNS_LEN,    LT_ETHERNET));
    CHECK(nomatch("ip.proto in {6, 17}",            PKT_ICMP,       PKT_ICMP_LEN,       LT_ETHERNET));

    /* ── range notation in{} ─────────────────────────────────────────────── */
    SUITE("in{} range notation (lo..hi)");

    CHECK(match  ("tcp.dstport in {1..1024}",   PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));  /* 80 */
    CHECK(nomatch("tcp.dstport in {1..79}",     PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    CHECK(nomatch("tcp.dstport in {81..1024}",  PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    CHECK(match  ("tcp.dstport in {80..80}",    PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    CHECK(match  ("tcp.port in {1..1024}",      PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));  /* src 12345 or dst 80 */
    CHECK(match  ("ip.ttl in {60..128}",        PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));  /* TTL=64 */
    CHECK(nomatch("ip.ttl in {65..255}",        PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    /* mix: discrete values and a range */
    CHECK(match  ("tcp.dstport in {22, 80..90, 443}", PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("tcp.dstport in {22, 80..90, 443}", PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));
    CHECK(match  ("tcp.dstport in {22, 80..90, 443}", PKT_TCP_SSH,    PKT_TCP_SSH_LEN,    LT_ETHERNET));

    /* ── ip6.addr alias ──────────────────────────────────────────────────── */
    SUITE("ip6.addr alias");

    CHECK(match  ("ip6.addr == fd00::1", PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(match  ("ip6.addr == fd00::2", PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(nomatch("ip6.addr == fd00::3", PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(match  ("ipv6.addr == fd00::1",PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(nomatch("ip6.addr == fd00::1", PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));

    /* ── VLAN ─────────────────────────────────────────────────────────────── */
    SUITE("VLAN 802.1Q");

    CHECK(match  ("vlan",           PKT_VLAN_TCP, PKT_VLAN_TCP_LEN, LT_ETHERNET));
    CHECK(nomatch("vlan",           PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    CHECK(match  ("vlan.id == 100", PKT_VLAN_TCP, PKT_VLAN_TCP_LEN, LT_ETHERNET));
    CHECK(nomatch("vlan.id == 200", PKT_VLAN_TCP, PKT_VLAN_TCP_LEN, LT_ETHERNET));
    CHECK(nomatch("vlan.id == 100", PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));
    /* VLAN-tagged frame: IP/TCP fields still resolve after tag is stripped */
    CHECK(match  ("tcp and vlan.id == 100",  PKT_VLAN_TCP, PKT_VLAN_TCP_LEN, LT_ETHERNET));
    CHECK(match  ("ip.src == 192.168.1.1",   PKT_VLAN_TCP, PKT_VLAN_TCP_LEN, LT_ETHERNET));
    CHECK(match  ("tcp.dstport == 80",        PKT_VLAN_TCP, PKT_VLAN_TCP_LEN, LT_ETHERNET));
    CHECK(match  ("vlan.id in {100, 200}",   PKT_VLAN_TCP, PKT_VLAN_TCP_LEN, LT_ETHERNET));
    CHECK(nomatch("vlan.id in {200, 300}",   PKT_VLAN_TCP, PKT_VLAN_TCP_LEN, LT_ETHERNET));

    /* ── IPv6 CIDR ───────────────────────────────────────────────────────── */
    SUITE("IPv6 CIDR / prefix matching");

    /* exact match */
    CHECK(match  ("ip6.src == fd00::1",    PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(nomatch("ip6.src == fd00::2",    PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    /* /64 prefix */
    CHECK(match  ("ip6.src == fd00::/64",  PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(match  ("ip6.dst == fd00::/64",  PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(nomatch("ip6.src == fe80::/64",  PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    /* /128 same as exact */
    CHECK(match  ("ip6.src == fd00::1/128",PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(nomatch("ip6.src == fd00::2/128",PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    /* ip6.addr alias + CIDR */
    CHECK(match  ("ip6.addr == fd00::/64", PKT_IPV6_TCP, PKT_IPV6_TCP_LEN, LT_ETHERNET));
    CHECK(nomatch("ip6.addr == fd00::/64", PKT_TCP_SYN,  PKT_TCP_SYN_LEN,  LT_ETHERNET));

    /* ── contains operator ───────────────────────────────────────────────── */
    SUITE("contains (byte-sequence search)");

    /* EtherType 0x0800 is at frame[12:2] in every IPv4 frame */
    CHECK(match  ("frame contains 0x0800",     PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("frame contains 0xdeadbeef", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* Source IP 192.168.1.1 = c0:a8:01:01 */
    CHECK(match  ("frame contains 0xc0a80101", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("frame contains 0xc0a80102", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* ip layer search */
    CHECK(match  ("ip contains 0x0a000001",    PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* tcp layer: dport=80=0x0050 at tcp[2:2] */
    CHECK(match  ("tcp contains 0x0050",       PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("tcp contains 0x01bb",       PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* udp layer: dport=53=0x0035 */
    CHECK(match  ("udp contains 0x0035",       PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    /* no-match on absent layer */
    CHECK(nomatch("tcp contains 0x0050",       PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));

    /* ── matches operator (POSIX ERE) ───────────────────────────────────── */
    SUITE("matches (POSIX ERE)");

    /* matches on non-string built-in fields: no match (they are not FV_STR) */
    CHECK(nomatch("ip.src matches \"192\\.\"",  PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* these all compile cleanly */
    CHECK(!compile_err("dns.qry.name matches \"\\\\.example\\\\.com$\""));
    CHECK(!compile_err("http.host matches \"^www\\\\.\\.\""));
    /* invalid regex: compile-time error at regex compile step → no match, no crash */
    CHECK(nomatch("ip.src matches \"[invalid\"", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));

    /* ── len() ──────────────────────────────────────────────────────────────
     * PKT_TCP_SYN (54 B): ip_total=40, ip_hlen=20, tcp_hlen=20, tcp_pl=0
     * PKT_UDP_DNS (42 B): ip_total=28, ip_hlen=20, udp_len=8,   udp_pl=0  */
    SUITE("Function: len()");

    /* len(frame) — total captured bytes */
    CHECK(match  ("len(frame) == 54", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("len(frame) > 50",  PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("len(frame) < 50",  PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("len(frame) == 42", PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("len(frame) < 50",  PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));

    /* len(ip) — IP total-length header field */
    CHECK(match  ("len(ip) == 40",  PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("len(ip) == 28",  PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(nomatch("len(ip) == 40",  PKT_ARP,     PKT_ARP_LEN,     LT_ETHERNET));

    /* len(ip.payload) — IP total minus IP header */
    CHECK(match  ("len(ip.payload) == 20", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("len(ip.payload) == 8",  PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));

    /* len(tcp) — TCP header length from data-offset nibble */
    CHECK(match  ("len(tcp) == 20",        PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("len(tcp) == 20",        PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));
    CHECK(nomatch("len(tcp)",              PKT_UDP_DNS,    PKT_UDP_DNS_LEN,    LT_ETHERNET));

    /* len(tcp.payload) — bytes after TCP header (computed from IP total len) */
    CHECK(match  ("len(tcp.payload) == 0", PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("len(tcp.payload) == 0", PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));

    /* len(udp) — UDP length field (header + payload) */
    CHECK(match  ("len(udp) == 8",         PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(nomatch("len(udp)",              PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));

    /* len(udp.payload) — UDP length minus 8-byte header */
    CHECK(match  ("len(udp.payload) == 0", PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));

    /* len() combined with other predicates */
    CHECK(match  ("tcp and len(frame) > 40", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("tcp and len(frame) < 40", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("tcp and len(tcp.payload) == 0", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));

    /* ── upper() / lower() ───────────────────────────────────────────────────
     * These functions transform FV_STR values.  Built-in numeric/IP fields
     * return FV_UINT/FV_IPV4, so upper()/lower() on them returns no match —
     * the intent is for provider-backed string fields (dns.qry.name, etc.).  */
    SUITE("Function: upper() / lower()");

    /* non-string built-in: silently no-match, do not crash */
    CHECK(nomatch("lower(ip.src) == \"192.168.1.1\"", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("upper(ip.src) == \"192.168.1.1\"", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* unresolved inner field: no match */
    CHECK(nomatch("lower(noexist.field) == \"test\"", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* expressions compile and evaluate without error */
    CHECK(!compile_err("lower(dns.qry.name) == \"example.com\""));
    CHECK(!compile_err("upper(http.host) == \"EXAMPLE.COM\""));
    CHECK(!compile_err("lower(myproto.msg) == \"hello\" and tcp"));

    /* ── Named bitwise AND: tcp.flags & mask ──────────────────────────────
     * PKT_TCP_SYN:    tcp.flags=0x02 (SYN)
     * PKT_TCP_ACKPSH: tcp.flags=0x18 (PSH+ACK) */
    SUITE("Named bitwise AND");

    CHECK(match  ("tcp.flags & 0x02 == 0x02", PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(nomatch("tcp.flags & 0x02 == 0x02", PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));
    CHECK(match  ("tcp.flags & 0x10 == 0x10", PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));
    CHECK(nomatch("tcp.flags & 0x10 == 0x10", PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("tcp.flags & 0x02 != 0",    PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(nomatch("tcp.flags & 0x02 != 0",    PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));
    /* ip.proto masked */
    CHECK(match  ("ip.proto & 0xff == 6",     PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(nomatch("ip.proto & 0xf0 == 0x10",  PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));

    /* ── in() with parentheses ─────────────────────────────────────────── */
    SUITE("in() parentheses");

    /* tcp.port in (80, 443) — parentheses must work like braces */
    CHECK(match  ("tcp.dstport in (80, 443)",      PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("tcp.dstport in (443, 80)",      PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(nomatch("tcp.dstport in (443, 8080)",    PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("tcp.dstport in (443, 8080, 80)", PKT_TCP_SYN,   PKT_TCP_SYN_LEN,    LT_ETHERNET));
    /* same as braces for IPv4 */
    CHECK(match  ("ip.proto in (6, 17)",           PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("ip.proto in (6, 17)",           PKT_UDP_DNS,    PKT_UDP_DNS_LEN,    LT_ETHERNET));

    /* ── frame.len ─────────────────────────────────────────────────────────
     * PKT_TCP_SYN = 54 bytes, PKT_UDP_DNS = 42 bytes */
    SUITE("frame.len");

    CHECK(match  ("frame.len == 54",  PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("frame.len == 54",  PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("frame.len == 42",  PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("frame.len > 50",   PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("frame.len > 50",   PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("frame.len >= 42",  PKT_UDP_DNS, PKT_UDP_DNS_LEN, LT_ETHERNET));
    CHECK(match  ("frame.len < 60",   PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(match  ("tcp and frame.len == 54", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));

    /* ── tcp.ack and tcp.window_size ───────────────────────────────────────
     * PKT_TCP_SYN:    ack=0  window=0xffff(65535)
     * PKT_TCP_ACKPSH: ack=1  window=0x2000(8192) */
    SUITE("tcp.ack / tcp.window_size");

    CHECK(match  ("tcp.ack == 0",        PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(nomatch("tcp.ack != 0",        PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("tcp.ack == 1",        PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));
    CHECK(match  ("tcp.ack > 0",         PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));

    CHECK(match  ("tcp.window_size == 65535", PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("tcp.window_size == 8192",  PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));
    CHECK(nomatch("tcp.window_size == 0",     PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("tcp.window_size > 1000",   PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));

    /* tcp.flags.psh: PKT_TCP_SYN flags=0x02 (no PSH), PKT_TCP_ACKPSH flags=0x18 (PSH+ACK) */
    CHECK(nomatch("tcp.flags.psh == 1", PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("tcp.flags.psh == 1", PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));

    /* ── ICMPv6 ─────────────────────────────────────────────────────────── */
    SUITE("ICMPv6");

    CHECK(match  ("icmpv6",             PKT_IPV6_ICMP6, PKT_IPV6_ICMP6_LEN, LT_ETHERNET));
    CHECK(nomatch("icmpv6",             PKT_IPV6_TCP,   PKT_IPV6_TCP_LEN,   LT_ETHERNET));
    CHECK(nomatch("icmpv6",             PKT_ICMP,       PKT_ICMP_LEN,       LT_ETHERNET));
    CHECK(match  ("icmpv6.type == 128", PKT_IPV6_ICMP6, PKT_IPV6_ICMP6_LEN, LT_ETHERNET));
    CHECK(nomatch("icmpv6.type == 8",   PKT_IPV6_ICMP6, PKT_IPV6_ICMP6_LEN, LT_ETHERNET));
    CHECK(match  ("icmpv6.code == 0",   PKT_IPV6_ICMP6, PKT_IPV6_ICMP6_LEN, LT_ETHERNET));
    /* icmp (v4) must not match ICMPv6 packet and vice versa */
    CHECK(nomatch("icmp",               PKT_IPV6_ICMP6, PKT_IPV6_ICMP6_LEN, LT_ETHERNET));
    CHECK(match  ("icmp",               PKT_ICMP,       PKT_ICMP_LEN,       LT_ETHERNET));

    /* ── ARP fields ─────────────────────────────────────────────────────────
     * PKT_ARP: op=REQUEST(1)  spa=192.168.1.1  tpa=192.168.1.254
     *          sha=aa:bb:cc:dd:ee:ff  tha=00:00:00:00:00:00 */
    SUITE("ARP fields");

    CHECK(match  ("arp.opcode == 1",                 PKT_ARP, PKT_ARP_LEN, LT_ETHERNET));
    CHECK(nomatch("arp.opcode == 2",                 PKT_ARP, PKT_ARP_LEN, LT_ETHERNET));
    CHECK(match  ("arp.src.proto_ipv4 == 192.168.1.1",   PKT_ARP, PKT_ARP_LEN, LT_ETHERNET));
    CHECK(nomatch("arp.src.proto_ipv4 == 10.0.0.1",      PKT_ARP, PKT_ARP_LEN, LT_ETHERNET));
    CHECK(match  ("arp.dst.proto_ipv4 == 192.168.1.254", PKT_ARP, PKT_ARP_LEN, LT_ETHERNET));
    CHECK(match  ("arp.src.hw_mac == aa:bb:cc:dd:ee:ff", PKT_ARP, PKT_ARP_LEN, LT_ETHERNET));
    /* no ARP fields on non-ARP packets */
    CHECK(nomatch("arp.opcode == 1",                 PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));

    /* ── Named-field slices ──────────────────────────────────────────────── */
    SUITE("Named-field slices");

    /* eth.src[0:3] = first 3 bytes of source MAC in PKT_TCP_SYN = aa:bb:cc = 0xaabbcc */
    CHECK(match  ("eth.src[0:3] == 0xaabbcc", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("eth.src[0:3] == 0x112233", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* eth.dst[0] = 0xff (broadcast) */
    CHECK(match  ("eth.dst[0] == 0xff",        PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    /* ip.src[0] = 0xc0 (192.168.1.1 → first byte) */
    CHECK(match  ("ip.src[0] == 0xc0",         PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));
    CHECK(nomatch("ip.src[0] == 0x0a",         PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));

    /* ── Negative slice offsets ───────────────────────────────────────────── */
    SUITE("Negative slice offsets");

    /* tcp[-7] = tcp[13] (flags byte) in PKT_TCP_SYN = 0x02 (SYN) */
    CHECK(match  ("tcp[-7] == 0x02",   PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(nomatch("tcp[-7] == 0x18",   PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(match  ("tcp[-7] == 0x18",   PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));
    /* tcp[-1] = last byte of 20-byte TCP header (urgent ptr low byte = 0x00) */
    CHECK(match  ("tcp[-1] == 0x00",   PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    /* frame[-1] = last byte of frame */
    CHECK(match  ("frame[-1] == 0x00", PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));

    /* ── tcp.analysis.retransmission ────────────────────────────────────────
     *
     * Requires pcapng_capture_filter_match_ex() + a persistent flow table.
     * We craft a minimal TCP stream:
     *   pkt A: SYN  seq=1000             → NOT a retransmission
     *   pkt B: SYN  seq=1000  (again)    → IS  a retransmission
     *   pkt C: data seq=1001 len=100     → NOT a retransmission
     *   pkt D: data seq=1001 len=100     → IS  a retransmission (same seq)
     *   pkt E: data seq=1101 len=50      → NOT a retransmission (new data)
     *
     * Ethernet/IPv4/TCP helper — build a packet with given seq, flags, iplen.
     * ip_total_len includes IP header (20) + TCP header (20) + data.
     */
    SUITE("tcp.analysis.retransmission");
    {
        /* Build reusable packet template: eth/ipv4/tcp
         * src=10.0.0.1:1234  dst=10.0.0.2:80 */
#define MAKE_TCP(pkt_, flags_, seq_, iplen_) do { \
    uint8_t _s = (uint8_t)(((seq_) >> 24) & 0xff); \
    uint8_t _s1= (uint8_t)(((seq_) >> 16) & 0xff); \
    uint8_t _s2= (uint8_t)(((seq_) >>  8) & 0xff); \
    uint8_t _s3= (uint8_t)(((seq_)      ) & 0xff); \
    uint8_t _il= (uint8_t)(((iplen_) >> 8) & 0xff); \
    uint8_t _il1=(uint8_t)(((iplen_)     ) & 0xff); \
    static const uint8_t _tmpl[] = { \
        /* Ethernet */ \
        0x00,0x00,0x00,0x00,0x00,0x02, 0x00,0x00,0x00,0x00,0x00,0x01, 0x08,0x00, \
        /* IPv4: IHL=5 TOS=0 total=? id=0 TTL=64 proto=6 */ \
        0x45,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x40,0x06,0x00,0x00, \
        0x0a,0x00,0x00,0x01, 0x0a,0x00,0x00,0x02, \
        /* TCP: sport=1234(0x04D2) dport=80(0x0050) seq=? ack=0 off=5 flags=? win=8192 */ \
        0x04,0xd2,0x00,0x50, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, \
        0x50,0x00,0x20,0x00, 0x00,0x00,0x00,0x00 \
    }; \
    memcpy((pkt_), _tmpl, sizeof _tmpl); \
    /* patch ip total len */ (pkt_)[16] = _il; (pkt_)[17] = _il1; \
    /* patch seq */          (pkt_)[38] = _s;  (pkt_)[39] = _s1; \
                             (pkt_)[40] = _s2; (pkt_)[41] = _s3; \
    /* patch flags */        (pkt_)[47] = (flags_); \
} while(0)

        const char *retr_expr = "tcp.analysis.retransmission == 1";
        const char *not_retr  = "tcp.analysis.retransmission == 0";

        pcapng_flow_table_t *ft = pcapng_flow_table_create();

        /* stateless match always returns 0 for retransmission */
        uint8_t pktA[58]; MAKE_TCP(pktA, 0x02, 1000, 40);  /* SYN, seq=1000, no data */
        CHECK(nomatch(retr_expr, pktA, sizeof pktA, LT_ETHERNET));

        /* feed pkt A (SYN, seq=1000) — first SYN, NOT a retransmission */
        CHECK(pcapng_capture_filter_match_ex(not_retr,  pktA, sizeof pktA, LT_ETHERNET, ft, NULL) == 1);

        /* pkt B: duplicate SYN, same seq=1000 → retransmission */
        uint8_t pktB[58]; MAKE_TCP(pktB, 0x02, 1000, 40);
        CHECK(pcapng_capture_filter_match_ex(retr_expr, pktB, sizeof pktB, LT_ETHERNET, ft, NULL) == 1);

        /* pkt C: data, seq=1001, ip_total=140 → 100 bytes of payload, first time → NOT retr */
        uint8_t pktC[154]; memset(pktC, 0, sizeof pktC);
        MAKE_TCP(pktC, 0x10, 1001, 140);  /* ACK+data */
        CHECK(pcapng_capture_filter_match_ex(not_retr,  pktC, sizeof pktC, LT_ETHERNET, ft, NULL) == 1);

        /* pkt D: same seq=1001, len=100 → retransmission */
        uint8_t pktD[154]; memset(pktD, 0, sizeof pktD);
        MAKE_TCP(pktD, 0x10, 1001, 140);
        CHECK(pcapng_capture_filter_match_ex(retr_expr, pktD, sizeof pktD, LT_ETHERNET, ft, NULL) == 1);

        /* pkt E: new data seq=1101, len=50 → NOT retransmission */
        uint8_t pktE[104]; memset(pktE, 0, sizeof pktE);
        MAKE_TCP(pktE, 0x10, 1101, 90);
        CHECK(pcapng_capture_filter_match_ex(not_retr,  pktE, sizeof pktE, LT_ETHERNET, ft, NULL) == 1);

        /* pkt F: partial overlap — seq=1120, len=50, straddles max(1151)
         * seq_end=1170 > 1151 → out_of_order, NOT a plain retransmission.
         * Both assertions in one call so flow state is only advanced once. */
        uint8_t pktF[104]; memset(pktF, 0, sizeof pktF);
        MAKE_TCP(pktF, 0x10, 1120, 90);  /* seq=1120, len=50, seq_end=1170 */
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.out_of_order == 1 and tcp.analysis.retransmission == 0",
              pktF, sizeof pktF, LT_ETHERNET, ft, NULL) == 1);

        /* pkt G: fully within seen range (max now 1170 after F) → retransmission */
        uint8_t pktG[104]; memset(pktG, 0, sizeof pktG);
        MAKE_TCP(pktG, 0x10, 1001, 90);  /* seq=1001, len=50, seq_end=1051 ≤ 1170 */
        CHECK(pcapng_capture_filter_match_ex(retr_expr, pktG, sizeof pktG, LT_ETHERNET, ft, NULL) == 1);

        pcapng_flow_table_free(ft);
#undef MAKE_TCP
    }

    /* ── tcp.analysis.duplicate_ack / window_update ─────────────────────── */
    SUITE("tcp.analysis.duplicate_ack");
    {
        /* A→B SYN, A→B data(100), B→A ACK(first), B→A same ACK(dup#1),
         * B→A same ACK(dup#2), B→A same ACK different win(window_update) */
        pcapng_flow_table_t *ft = pcapng_flow_table_create();

        uint8_t d1[54];  MK_AB(d1, 0x02, 1000, 0, 8192, 0);        /* A: SYN */
        pcapng_capture_filter_match_ex("tcp", d1, 54, LT_ETHERNET, ft, NULL);

        uint8_t d2[154]; memset(d2, 0, 154);
        MK_AB(d2, 0x10, 1001, 0, 8192, 100);                        /* A: data */
        pcapng_capture_filter_match_ex("tcp", d2, 154, LT_ETHERNET, ft, NULL);

        uint8_t d3[54];  MK_BA(d3, 0x10, 2000, 1101, 8192, 0);     /* B: ACK (first) */
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.duplicate_ack == 0", d3, 54, LT_ETHERNET, ft, NULL) == 1);

        /* Both assertions in one call to avoid double-advancing flow state. */
        uint8_t d4[54];  MK_BA(d4, 0x10, 2000, 1101, 8192, 0);     /* B: dup ACK #1 */
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.duplicate_ack == 1 and tcp.analysis.duplicate_ack_num == 1",
              d4, 54, LT_ETHERNET, ft, NULL) == 1);

        uint8_t d5[54];  MK_BA(d5, 0x10, 2000, 1101, 8192, 0);     /* B: dup ACK #2 */
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.duplicate_ack_num == 2", d5, 54, LT_ETHERNET, ft, NULL) == 1);

        uint8_t d6[54];  MK_BA(d6, 0x10, 2000, 1101, 4096, 0);     /* B: win update */
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.window_update == 1 and tcp.analysis.duplicate_ack == 0",
              d6, 54, LT_ETHERNET, ft, NULL) == 1);

        pcapng_flow_table_free(ft);
    }

    /* ── tcp.analysis.zero_window / zero_window_probe / probe_ack ────────── */
    SUITE("tcp.analysis.zero_window");
    {
        pcapng_flow_table_t *ft = pcapng_flow_table_create();

        uint8_t z1[54]; MK_AB(z1, 0x02, 1000, 0, 8192, 0);         /* A: SYN */
        pcapng_capture_filter_match_ex("tcp", z1, 54, LT_ETHERNET, ft, NULL);

        uint8_t z2[54]; MK_AB(z2, 0x10, 1001, 0, 8192, 0);         /* A: ACK, win nonzero */
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.zero_window == 0", z2, 54, LT_ETHERNET, ft, NULL) == 1);

        uint8_t z3[54]; MK_BA(z3, 0x10, 2000, 1001, 0, 0);         /* B: win=0 */
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.zero_window == 1", z3, 54, LT_ETHERNET, ft, NULL) == 1);

        /* A probes with 1 byte → zero_window_probe */
        uint8_t z4[55]; memset(z4, 0, 55);
        MK_AB(z4, 0x10, 1001, 2001, 8192, 1);
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.zero_window_probe == 1", z4, 55, LT_ETHERNET, ft, NULL) == 1);

        /* B ACKs the probe → zero_window_probe_ack */
        uint8_t z5[54]; MK_BA(z5, 0x10, 2000, 1002, 0, 0);
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.zero_window_probe_ack == 1", z5, 54, LT_ETHERNET, ft, NULL) == 1);

        pcapng_flow_table_free(ft);
    }

    /* ── tcp.analysis.keep_alive / keep_alive_ack ────────────────────────── */
    SUITE("tcp.analysis.keep_alive");
    {
        pcapng_flow_table_t *ft = pcapng_flow_table_create();

        /* Establish: A SYN, A data(100), B ACK(1101) */
        uint8_t k1[54];  MK_AB(k1, 0x02, 1000, 0, 8192, 0);
        pcapng_capture_filter_match_ex("tcp", k1, 54, LT_ETHERNET, ft, NULL);

        uint8_t k2[154]; memset(k2, 0, 154);
        MK_AB(k2, 0x10, 1001, 0, 8192, 100);
        pcapng_capture_filter_match_ex("tcp", k2, 154, LT_ETHERNET, ft, NULL);

        uint8_t k3[54];  MK_BA(k3, 0x10, 2000, 1101, 8192, 0);     /* B: ACK(1101) */
        pcapng_capture_filter_match_ex("tcp", k3, 54, LT_ETHERNET, ft, NULL);

        /* A: keep-alive — seq = B's last_ack(1101) - 1 = 1100, len=0 */
        uint8_t k4[54];  MK_AB(k4, 0x10, 1100, 2001, 8192, 0);
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.keep_alive == 1", k4, 54, LT_ETHERNET, ft, NULL) == 1);

        /* B: keep-alive-ack — pure ACK after receiving keep-alive */
        uint8_t k5[54];  MK_BA(k5, 0x10, 2001, 1101, 8192, 0);
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.keep_alive_ack == 1", k5, 54, LT_ETHERNET, ft, NULL) == 1);

        /* normal new data is NOT keep_alive */
        uint8_t k6[104]; memset(k6, 0, 104);
        MK_AB(k6, 0x10, 1101, 2001, 8192, 50);
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.keep_alive == 0", k6, 104, LT_ETHERNET, ft, NULL) == 1);

        pcapng_flow_table_free(ft);
    }

    /* ── tcp.analysis.fast_retransmission ───────────────────────────────── */
    SUITE("tcp.analysis.fast_retransmission");
    {
        /* A sends data, B acks, A sends more data, B sends 3 dup ACKs, A retransmits */
        pcapng_flow_table_t *ft = pcapng_flow_table_create();

        uint8_t f1[54];  MK_AB(f1, 0x02, 1000, 0, 8192, 0);         /* A: SYN */
        pcapng_capture_filter_match_ex("tcp", f1, 54, LT_ETHERNET, ft, NULL);

        uint8_t f2[154]; memset(f2, 0, 154);
        MK_AB(f2, 0x10, 1001, 0, 8192, 100);                         /* A: data(1001+100) */
        pcapng_capture_filter_match_ex("tcp", f2, 154, LT_ETHERNET, ft, NULL);

        uint8_t f3[54];  MK_BA(f3, 0x10, 2000, 1101, 8192, 0);      /* B: ACK(1101) */
        pcapng_capture_filter_match_ex("tcp", f3, 54, LT_ETHERNET, ft, NULL);

        uint8_t f4[154]; memset(f4, 0, 154);
        MK_AB(f4, 0x10, 1101, 2001, 8192, 100);                      /* A: data(1101+100) */
        pcapng_capture_filter_match_ex("tcp", f4, 154, LT_ETHERNET, ft, NULL);

        /* B: 3 dup ACKs (still at 1101 — didn't receive 1101+100) */
        uint8_t fa[54]; MK_BA(fa, 0x10, 2000, 1101, 8192, 0);
        pcapng_capture_filter_match_ex("tcp", fa, 54, LT_ETHERNET, ft, NULL);
        uint8_t fb[54]; MK_BA(fb, 0x10, 2000, 1101, 8192, 0);
        pcapng_capture_filter_match_ex("tcp", fb, 54, LT_ETHERNET, ft, NULL);
        uint8_t fc[54]; MK_BA(fc, 0x10, 2000, 1101, 8192, 0);
        pcapng_capture_filter_match_ex("tcp", fc, 54, LT_ETHERNET, ft, NULL);

        /* A: retransmit seq=1101 (after 3 dup ACKs → fast retransmission) */
        uint8_t f5[154]; memset(f5, 0, 154);
        MK_AB(f5, 0x10, 1101, 2001, 8192, 100);
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.fast_retransmission == 1", f5, 154, LT_ETHERNET, ft, NULL) == 1);
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.retransmission == 1", f5, 154, LT_ETHERNET, ft, NULL) == 1);

        pcapng_flow_table_free(ft);
    }

    /* ── tcp.analysis.spurious_retransmission ────────────────────────────── */
    SUITE("tcp.analysis.spurious_retransmission");
    {
        /* A sends data, B fully acks it, A retransmits old data → spurious */
        pcapng_flow_table_t *ft = pcapng_flow_table_create();

        uint8_t s1[54];  MK_AB(s1, 0x02, 1000, 0, 8192, 0);
        pcapng_capture_filter_match_ex("tcp", s1, 54, LT_ETHERNET, ft, NULL);

        uint8_t s2[154]; memset(s2, 0, 154);
        MK_AB(s2, 0x10, 1001, 0, 8192, 100);                         /* A: data */
        pcapng_capture_filter_match_ex("tcp", s2, 154, LT_ETHERNET, ft, NULL);

        uint8_t s3[54]; MK_BA(s3, 0x10, 2000, 1101, 8192, 0);       /* B: ACK(1101) */
        pcapng_capture_filter_match_ex("tcp", s3, 54, LT_ETHERNET, ft, NULL);

        /* A: retransmit seq=1001 — B already acked past 1101 → spurious */
        uint8_t s4[154]; memset(s4, 0, 154);
        MK_AB(s4, 0x10, 1001, 2001, 8192, 100);
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.spurious_retransmission == 1", s4, 154, LT_ETHERNET, ft, NULL) == 1);
        /* spurious implies retransmission */
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.retransmission == 1", s4, 154, LT_ETHERNET, ft, NULL) == 1);
        /* but NOT fast (no 3 dup ACKs) */
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.fast_retransmission == 0", s4, 154, LT_ETHERNET, ft, NULL) == 1);

        pcapng_flow_table_free(ft);
    }

    /* ── tcp.analysis.bytes_in_flight ───────────────────────────────────── */
    SUITE("tcp.analysis.bytes_in_flight");
    {
        /* A: SYN, data(100), B: ACK(1101), A: data(200) → bif=200 */
        pcapng_flow_table_t *ft = pcapng_flow_table_create();

        uint8_t b1[54];  MK_AB(b1, 0x02, 1000, 0, 8192, 0);         /* A: SYN */
        pcapng_capture_filter_match_ex("tcp", b1, 54, LT_ETHERNET, ft, NULL);

        uint8_t b2[154]; memset(b2, 0, 154);
        MK_AB(b2, 0x10, 1001, 0, 8192, 100);                         /* A: data(100) */
        pcapng_capture_filter_match_ex("tcp", b2, 154, LT_ETHERNET, ft, NULL);

        /* A: data(200) before any ACK from B → advance state, bif not computed */
        uint8_t b3[254]; memset(b3, 0, 254);
        MK_AB(b3, 0x10, 1101, 0, 8192, 200);                         /* A: data(200), max→1301 */
        pcapng_capture_filter_match_ex("tcp", b3, 254, LT_ETHERNET, ft, NULL);

        uint8_t b4[54];  MK_BA(b4, 0x10, 2000, 1101, 8192, 0);      /* B: ACK(1101) */
        pcapng_capture_filter_match_ex("tcp", b4, 54, LT_ETHERNET, ft, NULL);

        /* A: more data seq=1301, len=50 → max=1351, bif = 1351 - 1101 = 250 */
        uint8_t b5[104]; memset(b5, 0, 104);
        MK_AB(b5, 0x10, 1301, 2001, 8192, 50);
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.bytes_in_flight == 250", b5, 104, LT_ETHERNET, ft, NULL) == 1);

        /* B acks everything → bif drops to 50 on next A→B packet */
        uint8_t b6[54];  MK_BA(b6, 0x10, 2000, 1351, 8192, 0);      /* B: ACK(1351) */
        pcapng_capture_filter_match_ex("tcp", b6, 54, LT_ETHERNET, ft, NULL);

        uint8_t b7[54];  MK_AB(b7, 0x10, 1351, 2001, 8192, 0);      /* A: pure ACK */
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.bytes_in_flight == 0", b7, 54, LT_ETHERNET, ft, NULL) == 1);

        pcapng_flow_table_free(ft);
    }

    /* ── tcp.analysis.lost_segment ──────────────────────────────────────── */
    SUITE("tcp.analysis.lost_segment");
    {
        pcapng_flow_table_t *ft = pcapng_flow_table_create();

        uint8_t l1[54];  MK_AB(l1, 0x02, 1000, 0, 8192, 0);         /* A: SYN */
        pcapng_capture_filter_match_ex("tcp", l1, 54, LT_ETHERNET, ft, NULL);

        uint8_t l2[154]; memset(l2, 0, 154);
        MK_AB(l2, 0x10, 1001, 0, 8192, 100);                         /* A: data(1001+100) */
        pcapng_capture_filter_match_ex("tcp", l2, 154, LT_ETHERNET, ft, NULL);

        /* A: jump to seq=1301, skipping 1101..1300 → lost_segment, not retransmission.
         * Both in one call so state is advanced only once. */
        uint8_t l3[104]; memset(l3, 0, 104);
        MK_AB(l3, 0x10, 1301, 0, 8192, 50);
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.lost_segment == 1 and tcp.analysis.retransmission == 0",
              l3, 104, LT_ETHERNET, ft, NULL) == 1);

        /* next in-order packet is normal */
        uint8_t l4[54];  MK_AB(l4, 0x10, 1351, 0, 8192, 0);         /* A: ACK, in order */
        CHECK(pcapng_capture_filter_match_ex(
              "tcp.analysis.lost_segment == 0", l4, 54, LT_ETHERNET, ft, NULL) == 1);

        pcapng_flow_table_free(ft);
    }

    /* ── Filter aliases ──────────────────────────────────────────────────── */
    SUITE("Filter aliases");

    /* expression alias: whole-string substitution */
    pcapng_filter_alias_add("new TCP connections",
                            "tcp.flags.syn == 1 and tcp.flags.ack == 0");
    CHECK(match  ("new TCP connections", PKT_TCP_SYN,    PKT_TCP_SYN_LEN,    LT_ETHERNET));
    CHECK(nomatch("new TCP connections", PKT_TCP_ACKPSH, PKT_TCP_ACKPSH_LEN, LT_ETHERNET));
    CHECK(nomatch("new TCP connections", PKT_UDP_DNS,    PKT_UDP_DNS_LEN,    LT_ETHERNET));

    /* expression alias with leading/trailing whitespace in the call */
    CHECK(match  (" new TCP connections ", PKT_TCP_SYN, PKT_TCP_SYN_LEN, LT_ETHERNET));

    /* ── Summary ─────────────────────────────────────────────────────────── */
    printf("\n=== Results: %d/%d passed", g_passed, g_tests);
    if (g_failed) printf(", %d FAILED", g_failed);
    printf(" ===\n");
    return g_failed ? 1 : 0;
}
