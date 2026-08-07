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

    /* ── Summary ─────────────────────────────────────────────────────────── */
    printf("\n=== Results: %d/%d passed", g_passed, g_tests);
    if (g_failed) printf(", %d FAILED", g_failed);
    printf(" ===\n");
    return g_failed ? 1 : 0;
}
