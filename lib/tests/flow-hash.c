/*
 * flow-hash.c — the properties a dispatcher relies on.
 *
 * pcapng_flow_hash() only earns its place if both directions of a connection
 * hash the same (or a flow's packets split across workers and every per-thread
 * table in the library becomes wrong) and different flows mostly do not (or the
 * workers do not balance). Everything here checks one of those two things.
 *
 * Build via cmake (registered as the Flow-Hash ctest target).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libpcapng/flow_hash.h>
#include <libpcapng/dissect.h>

static int g_pass, g_fail;

#define SUITE(name) printf("\n[%s]\n", (name))
#define CHECK(label, expr) do {                                          \
    if (expr) { g_pass++; printf("  PASS  %s\n", label); }             \
    else      { g_fail++; printf("  FAIL  %s  (%s:%d)\n",              \
                                 label, __FILE__, __LINE__); }          \
} while (0)

/* Ethernet/IPv4/TCP, 10.0.0.1:12345 -> 10.0.0.2:502, with a 12-byte payload. */
static uint8_t ETH_TCP[66] = {
    0x00,0x00,0x00,0x00,0x00,0x00, 0x02,0x02,0x02,0x02,0x02,0x02, 0x08,0x00,
    0x45,0x00,0x00,0x34,0x00,0x01,0x00,0x00,0x40,0x06,0x66,0xc1,
    0x0a,0x00,0x00,0x01, 0x0a,0x00,0x00,0x02,
    0x30,0x39,0x01,0xf6,0,0,0,0,0,0,0,0,0x50,0x18,0xff,0xff,0,0,0,0,
    0x00,0x01,0x00,0x00,0x00,0x06,0x01,0x03,0x00,0x00,0x00,0x01,
};

/* The same flow the other way: addresses and ports swapped. */
static uint8_t ETH_TCP_REV[66];

static void build_reverse(void)
{
    memcpy(ETH_TCP_REV, ETH_TCP, sizeof ETH_TCP);
    memcpy(ETH_TCP_REV + 26, ETH_TCP + 30, 4);   /* src ip  <- dst ip  */
    memcpy(ETH_TCP_REV + 30, ETH_TCP + 26, 4);   /* dst ip  <- src ip  */
    memcpy(ETH_TCP_REV + 34, ETH_TCP + 36, 2);   /* src port <- dst port */
    memcpy(ETH_TCP_REV + 36, ETH_TCP + 34, 2);
}

/* The same frame with an 802.1Q tag spliced in after the MACs. */
static uint8_t ETH_VLAN[70];

static void build_vlan(void)
{
    memcpy(ETH_VLAN, ETH_TCP, 12);
    ETH_VLAN[12] = 0x81; ETH_VLAN[13] = 0x00;    /* TPID */
    ETH_VLAN[14] = 0x00; ETH_VLAN[15] = 0x64;    /* VLAN 100 */
    memcpy(ETH_VLAN + 16, ETH_TCP + 12, sizeof ETH_TCP - 12);
}

int main(void)
{
    build_reverse();
    build_vlan();

    const uint32_t L = (uint32_t)sizeof ETH_TCP;
    const uint16_t ETH = PCAPNG_LINKTYPE_ETHERNET;

    uint64_t fwd = pcapng_flow_hash(ETH_TCP,     L, ETH, PCAPNG_FLOW_TUPLE);
    uint64_t rev = pcapng_flow_hash(ETH_TCP_REV, L, ETH, PCAPNG_FLOW_TUPLE);

    SUITE("direction independence — the property sharding depends on");
    CHECK("a flow hashes to something", fwd != 0);
    CHECK("both directions hash the same", fwd == rev);

    SUITE("the tuple form agrees with the frame form");
    {
        uint8_t a[4] = {10,0,0,1}, b[4] = {10,0,0,2};
        uint64_t t = pcapng_flow_hash_tuple(6, a, b, 4, 12345, 502, PCAPNG_FLOW_TUPLE);
        CHECK("walking the frame and passing the tuple agree", t == fwd);
        CHECK("the tuple form is direction-independent too",
              pcapng_flow_hash_tuple(6, b, a, 4, 502, 12345, PCAPNG_FLOW_TUPLE) == t);
    }

    SUITE("flows that differ, hash differently");
    {
        uint8_t a[4] = {10,0,0,1}, b[4] = {10,0,0,2}, c[4] = {10,0,0,3};
        uint64_t base = pcapng_flow_hash_tuple(6, a, b, 4, 12345, 502, PCAPNG_FLOW_TUPLE);
        CHECK("a different port is a different flow",
              pcapng_flow_hash_tuple(6, a, b, 4, 12346, 502, PCAPNG_FLOW_TUPLE) != base);
        CHECK("a different peer is a different flow",
              pcapng_flow_hash_tuple(6, a, c, 4, 12345, 502, PCAPNG_FLOW_TUPLE) != base);
        CHECK("a different protocol is a different flow",
              pcapng_flow_hash_tuple(17, a, b, 4, 12345, 502, PCAPNG_FLOW_TUPLE) != base);
    }

    SUITE("ippair mode — one worker per host pair");
    {
        uint8_t a[4] = {10,0,0,1}, b[4] = {10,0,0,2}, c[4] = {10,0,0,3};
        uint64_t p = pcapng_flow_hash_tuple(6, a, b, 4, 12345, 502, PCAPNG_FLOW_IPPAIR);
        CHECK("ports are ignored",
              pcapng_flow_hash_tuple(6, a, b, 4, 999, 21, PCAPNG_FLOW_IPPAIR) == p);
        CHECK("protocol is ignored",
              pcapng_flow_hash_tuple(17, a, b, 4, 53, 53, PCAPNG_FLOW_IPPAIR) == p);
        CHECK("direction is still ignored",
              pcapng_flow_hash_tuple(6, b, a, 4, 502, 12345, PCAPNG_FLOW_IPPAIR) == p);
        CHECK("a different host pair is different",
              pcapng_flow_hash_tuple(6, a, c, 4, 12345, 502, PCAPNG_FLOW_IPPAIR) != p);
        CHECK("it is not the 5-tuple hash", p != pcapng_flow_hash(ETH_TCP, L, ETH, PCAPNG_FLOW_TUPLE));
    }

    SUITE("link layers");
    CHECK("an 802.1Q tag does not change the flow",
          pcapng_flow_hash(ETH_VLAN, sizeof ETH_VLAN, ETH, PCAPNG_FLOW_TUPLE) == fwd);
    CHECK("the same IP packet raw hashes the same",
          pcapng_flow_hash(ETH_TCP + 14, L - 14, PCAPNG_LINKTYPE_RAW, PCAPNG_FLOW_TUPLE) == fwd);

    SUITE("no flow means 0, and only then");
    {
        uint8_t arp[42]; memset(arp, 0, sizeof arp);
        arp[12] = 0x08; arp[13] = 0x06;                 /* ethertype ARP */
        CHECK("a non-IP frame has no flow", pcapng_flow_hash(arp, sizeof arp, ETH, PCAPNG_FLOW_TUPLE) == 0);
        CHECK("a runt frame has no flow", pcapng_flow_hash(ETH_TCP, 8, ETH, PCAPNG_FLOW_TUPLE) == 0);
        CHECK("a truncated IP header has no flow", pcapng_flow_hash(ETH_TCP, 20, ETH, PCAPNG_FLOW_TUPLE) == 0);
        CHECK("NULL data has no flow", pcapng_flow_hash(NULL, 66, ETH, PCAPNG_FLOW_TUPLE) == 0);
    }

    SUITE("IPv6");
    {
        uint8_t v6[74]; memset(v6, 0, sizeof v6);
        v6[12] = 0x86; v6[13] = 0xdd;
        v6[14] = 0x60;                                   /* version 6 */
        v6[18] = 0x00; v6[19] = 20;                      /* payload length */
        v6[20] = 6;                                      /* next header: TCP */
        v6[21] = 64;                                     /* hop limit */
        v6[22 + 15] = 1;                                 /* src ::1 */
        v6[38 + 15] = 2;                                 /* dst ::2 */
        v6[54] = 0x30; v6[55] = 0x39;                    /* sport 12345 */
        v6[56] = 0x01; v6[57] = 0xf6;                    /* dport 502 */
        uint64_t h6 = pcapng_flow_hash(v6, sizeof v6, ETH, PCAPNG_FLOW_TUPLE);
        CHECK("an IPv6 flow hashes", h6 != 0);
        CHECK("and not to the v4 flow's value", h6 != fwd);

        uint8_t r6[74]; memcpy(r6, v6, sizeof v6);
        memcpy(r6 + 22, v6 + 38, 16); memcpy(r6 + 38, v6 + 22, 16);
        memcpy(r6 + 54, v6 + 56, 2);  memcpy(r6 + 56, v6 + 54, 2);
        CHECK("both directions of it agree",
              pcapng_flow_hash(r6, sizeof r6, ETH, PCAPNG_FLOW_TUPLE) == h6);
    }

    SUITE("it partitions evenly enough to be worth sharding on");
    {
        /* 4096 flows over 8 workers. A hash that clumps would leave some
           workers idle while others queue; ±25% of even is a loose bound that
           still catches a genuinely bad mixer. */
        int bucket[8] = {0};
        uint8_t a[4] = {10,0,0,1}, b[4] = {10,0,0,2};
        for (int i = 0; i < 4096; i++) {
            b[2] = (uint8_t)(i >> 8); b[3] = (uint8_t)i;
            bucket[pcapng_flow_hash_tuple(6, a, b, 4, (uint16_t)(1024 + i), 443,
                                          PCAPNG_FLOW_TUPLE) % 8]++;
        }
        int lo = bucket[0], hi = bucket[0];
        for (int i = 1; i < 8; i++) { if (bucket[i] < lo) lo = bucket[i];
                                      if (bucket[i] > hi) hi = bucket[i]; }
        printf("      buckets:");
        for (int i = 0; i < 8; i++) printf(" %d", bucket[i]);
        printf("   (even would be 512)\n");
        CHECK("no worker is starved", lo > 512 - 128);
        CHECK("no worker is swamped", hi < 512 + 128);
    }

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
