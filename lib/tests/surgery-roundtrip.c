/*
 * surgery-roundtrip.c — integration tests for the pcapng surgery API.
 *
 * Creates a synthetic pcapng file in memory/temp, then exercises
 * filter_file, merge, split, anonymize, and inject_packet, verifying
 * packet counts and output validity after each operation.
 *
 * Build via cmake (Surgery-Roundtrip ctest target).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <libpcapng/easyapi.h>
#include <libpcapng/linktypes.h>
#include <libpcapng/blocks.h>
#include <libpcapng/io.h>
#include <libpcapng/surgery.h>

/* ── test harness ─────────────────────────────────────────────────────────── */

static int g_pass = 0, g_fail = 0;

#define CHECK(label, expr) do {                                         \
    if (expr) { g_pass++; printf("  PASS  %s\n", label); }            \
    else       { g_fail++; printf("  FAIL  %s  (%s:%d)\n",            \
                                  label, __FILE__, __LINE__); }        \
} while(0)

#define SUITE(name) printf("\n[%s]\n", name)

/* ── helpers ──────────────────────────────────────────────────────────────── */

/* Build a minimal Ethernet/IPv4/UDP frame in buf[]; returns length.
 * src_ip / dst_ip in host byte order.  payload is arbitrary bytes. */
static size_t make_udp_frame(uint8_t *buf,
                              uint32_t src_ip, uint32_t dst_ip,
                              uint16_t sport,  uint16_t dport,
                              const uint8_t *payload, uint16_t plen)
{
    uint8_t  *p   = buf;
    uint16_t  udp = 8 + plen;
    uint16_t  ip  = 20 + udp;

    /* Ethernet */
    memset(p, 0x00, 6); p += 6;   /* dst MAC */
    memset(p, 0x11, 6); p += 6;   /* src MAC */
    p[0] = 0x08; p[1] = 0x00; p += 2;

    /* IPv4 */
    uint8_t *iph = p;
    p[0]  = 0x45;
    p[1]  = 0;
    p[2]  = (uint8_t)(ip >> 8);   p[3]  = (uint8_t)(ip);
    p[4]  = 0;                     p[5]  = 1;   /* id */
    p[6]  = 0;                     p[7]  = 0;   /* frag */
    p[8]  = 64;                    p[9]  = 17;  /* TTL, UDP */
    p[10] = 0;                     p[11] = 0;   /* cksum placeholder */
    p[12] = (uint8_t)(src_ip>>24); p[13] = (uint8_t)(src_ip>>16);
    p[14] = (uint8_t)(src_ip>>8);  p[15] = (uint8_t)(src_ip);
    p[16] = (uint8_t)(dst_ip>>24); p[17] = (uint8_t)(dst_ip>>16);
    p[18] = (uint8_t)(dst_ip>>8);  p[19] = (uint8_t)(dst_ip);

    /* IP checksum */
    uint32_t ck = 0;
    for (int i = 0; i < 20; i += 2) ck += (iph[i]<<8)|iph[i+1];
    while (ck >> 16) ck = (ck & 0xffff) + (ck >> 16);
    ck = ~ck & 0xffff;
    iph[10] = (uint8_t)(ck>>8); iph[11] = (uint8_t)(ck);
    p += 20;

    /* UDP */
    p[0] = (uint8_t)(sport>>8); p[1] = (uint8_t)(sport);
    p[2] = (uint8_t)(dport>>8); p[3] = (uint8_t)(dport);
    p[4] = (uint8_t)(udp>>8);   p[5] = (uint8_t)(udp);
    p[6] = 0;                   p[7] = 0;   /* checksum (zero = unchecked) */
    p += 8;

    memcpy(p, payload, plen);
    return 14 + ip;
}

/* Write a pcapng file with `n_pkts` UDP packets and return path (static buf). */
static const char *write_test_pcapng(const char *path, int n_pkts)
{
    FILE *f = fopen(path, "wb");
    assert(f);
    libpcapng_write_header_to_file_with_linktype(f, LINKTYPE_ETHERNET);

    uint8_t  frame[256];
    uint8_t  payload[4] = {0xde, 0xad, 0xbe, 0xef};
    uint32_t src = (10<<24)|(0<<16)|(0<<8)|1;   /* 10.0.0.1 */
    uint32_t dst = (10<<24)|(0<<16)|(0<<8)|2;   /* 10.0.0.2 */

    for (int i = 0; i < n_pkts; i++) {
        /* alternate source IP so filter tests can select a subset */
        uint32_t s = (i % 2 == 0) ? src : (src | 0x10); /* 10.0.0.1 or 10.0.0.17 */
        size_t len = make_udp_frame(frame, s, dst, 12345, 5000 + i, payload, 4);
        libpcapng_write_enhanced_packet_to_file(f, frame, len);
    }
    fclose(f);
    return path;
}

/* Count EPBs in a pcapng file. */
static int cb_count_epb(uint32_t counter, uint32_t btype,
                         uint32_t blen, unsigned char *data, void *ud)
{
    (void)counter; (void)blen; (void)data;
    if (btype == PCAPNG_ENHANCED_PACKET_BLOCK)
        (*(int *)ud)++;
    return 0;
}

static int count_packets(const char *path)
{
    int n = 0;
    libpcapng_file_read((char *)path, cb_count_epb, &n);
    return n;
}

/* ── tests ────────────────────────────────────────────────────────────────── */

static void test_filter(void)
{
    SUITE("filter_file");

    const char *src = "/tmp/surg_src.pcapng";
    const char *out = "/tmp/surg_filter.pcapng";

    write_test_pcapng(src, 10);
    CHECK("source has 10 packets", count_packets(src) == 10);

    char errbuf[PCAPNG_SURGERY_ERRBUF_SIZE];
    /* Even-indexed packets have src 10.0.0.1; odd have 10.0.0.17 → 5 each */
    int r = pcapng_filter_file(src, out, "ip.src == 10.0.0.1", errbuf);
    CHECK("filter returns 5", r == 5);
    CHECK("output has 5 packets", count_packets(out) == 5);

    /* Filter that matches nothing */
    r = pcapng_filter_file(src, out, "ip.src == 192.168.99.99", errbuf);
    CHECK("filter-nomatch returns 0", r == 0);
    CHECK("nomatch output is empty", count_packets(out) == 0);

    /* Filter that matches all */
    r = pcapng_filter_file(src, out, "udp", errbuf);
    CHECK("filter-all returns 10", r == 10);
    CHECK("filter-all output has 10 packets", count_packets(out) == 10);
}

static void test_merge(void)
{
    SUITE("merge");

    const char *a   = "/tmp/surg_a.pcapng";
    const char *b   = "/tmp/surg_b.pcapng";
    const char *out = "/tmp/surg_merge.pcapng";

    write_test_pcapng(a,  6);
    write_test_pcapng(b, 10);

    const char *inputs[2] = {a, b};
    char errbuf[PCAPNG_SURGERY_ERRBUF_SIZE];
    int r = pcapng_merge(inputs, 2, out, NULL, errbuf);
    CHECK("merge returns 16", r == 16);
    CHECK("merged output has 16 packets", count_packets(out) == 16);

    /* merge of a single file is a copy */
    r = pcapng_merge(inputs, 1, out, NULL, errbuf);
    CHECK("merge-single returns 6", r == 6);
    CHECK("merge-single output has 6 packets", count_packets(out) == 6);
}

static void test_split(void)
{
    SUITE("split");

    const char *src = "/tmp/surg_split_src.pcapng";
    write_test_pcapng(src, 7);

    pcapng_split_opts_t opts = {.max_packets = 3, .max_bytes = 0};
    char errbuf[PCAPNG_SURGERY_ERRBUF_SIZE];
    int r = pcapng_split(src, "/tmp/surg_split_%04d.pcapng", &opts, errbuf);
    CHECK("split of 7 with max 3 creates 3 files", r == 3);

    int total = 0;
    total += count_packets("/tmp/surg_split_0000.pcapng");
    total += count_packets("/tmp/surg_split_0001.pcapng");
    total += count_packets("/tmp/surg_split_0002.pcapng");
    CHECK("split files contain 7 packets total", total == 7);
    CHECK("first split file has 3 packets",  count_packets("/tmp/surg_split_0000.pcapng") == 3);
    CHECK("second split file has 3 packets", count_packets("/tmp/surg_split_0001.pcapng") == 3);
    CHECK("third split file has 1 packet",   count_packets("/tmp/surg_split_0002.pcapng") == 1);

    /* exact multiple */
    write_test_pcapng(src, 6);
    r = pcapng_split(src, "/tmp/surg_split_%04d.pcapng", &opts, errbuf);
    CHECK("split of 6 with max 3 creates 2 files", r == 2);
}

static void test_anonymize(void)
{
    SUITE("anonymize");

    const char *src = "/tmp/surg_anon_src.pcapng";
    const char *out = "/tmp/surg_anon.pcapng";

    write_test_pcapng(src, 4);

    pcapng_anon_opts_t opts = {.seed = 0, .anonymize_mac = 1};
    char errbuf[PCAPNG_SURGERY_ERRBUF_SIZE];
    int r = pcapng_anonymize(src, out, &opts, errbuf);
    CHECK("anonymize returns 4", r == 4);
    CHECK("anonymized output has 4 packets", count_packets(out) == 4);

    /* determinism: two runs with same seed produce identical files */
    const char *out2 = "/tmp/surg_anon2.pcapng";
    pcapng_anonymize(src, out2, &opts, errbuf);

    FILE *f1 = fopen(out,  "rb");
    FILE *f2 = fopen(out2, "rb");
    assert(f1 && f2);
    fseek(f1, 0, SEEK_END); long sz1 = ftell(f1); rewind(f1);
    fseek(f2, 0, SEEK_END); long sz2 = ftell(f2); rewind(f2);

    int identical = (sz1 == sz2);
    if (identical) {
        uint8_t b1[256], b2[256];
        size_t n;
        while ((n = fread(b1, 1, sizeof(b1), f1)) > 0) {
            fread(b2, 1, n, f2);
            if (memcmp(b1, b2, n)) { identical = 0; break; }
        }
    }
    fclose(f1); fclose(f2);
    CHECK("anonymize is deterministic", identical);
}

static void test_inject(void)
{
    SUITE("inject_packet");

    const char *src = "/tmp/surg_inject_src.pcapng";
    const char *out = "/tmp/surg_inject.pcapng";

    write_test_pcapng(src, 5);
    CHECK("source has 5 packets", count_packets(src) == 5);

    uint8_t  payload[4] = {0xca, 0xfe, 0xba, 0xbe};
    uint8_t  frame[256];
    uint32_t ip_src = (192<<24)|(168<<16)|1;
    uint32_t ip_dst = (192<<24)|(168<<16)|2;
    size_t   flen = make_udp_frame(frame, ip_src, ip_dst, 9999, 1234, payload, 4);

    char errbuf[PCAPNG_SURGERY_ERRBUF_SIZE];
    /* ts_us = 0 → append */
    int r = pcapng_inject_packet(src, out, frame, (uint32_t)flen, 0, 0, errbuf);
    CHECK("inject returns 0", r == 0);
    CHECK("injected output has 6 packets", count_packets(out) == 6);
}

int main(void)
{
    printf("=== surgery-roundtrip ===\n");

    test_filter();
    test_merge();
    test_split();
    test_anonymize();
    test_inject();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
