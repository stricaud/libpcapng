#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <libpcapng/reassembly.h>
#include <libpcapng/protocols/ipv4.h>

/* ── helpers ──────────────────────────────────────────────────────────────── */

static void fill_ip_header(uint8_t *hdr,
    uint32_t src, uint32_t dst, uint8_t proto,
    uint16_t ip_id, uint16_t frag_off_bytes, int more_frags,
    uint16_t payload_len)
{
    uint16_t tot_len   = 20 + payload_len;
    uint16_t frag_word = (frag_off_bytes / 8) & 0x1fff;
    if (more_frags) frag_word |= 0x2000;

    hdr[0]  = (4 << 4) | 5;                    /* version 4, IHL 5 */
    hdr[1]  = 0;
    hdr[2]  = (uint8_t)(tot_len >> 8);
    hdr[3]  = (uint8_t)(tot_len & 0xff);
    hdr[4]  = (uint8_t)(ip_id >> 8);
    hdr[5]  = (uint8_t)(ip_id & 0xff);
    hdr[6]  = (uint8_t)(frag_word >> 8);
    hdr[7]  = (uint8_t)(frag_word & 0xff);
    hdr[8]  = 64;                               /* TTL */
    hdr[9]  = proto;
    hdr[10] = 0; hdr[11] = 0;                  /* checksum placeholder */
    hdr[12] = (uint8_t)(src >> 24); hdr[13] = (uint8_t)(src >> 16);
    hdr[14] = (uint8_t)(src >>  8); hdr[15] = (uint8_t)(src);
    hdr[16] = (uint8_t)(dst >> 24); hdr[17] = (uint8_t)(dst >> 16);
    hdr[18] = (uint8_t)(dst >>  8); hdr[19] = (uint8_t)(dst);

    uint16_t cksum = libpcapng_ip_checksum(hdr, 20);
    hdr[10] = (uint8_t)(cksum >> 8);
    hdr[11] = (uint8_t)(cksum & 0xff);
}

/* Build a fragment into buf[]; return total packet length. */
static size_t make_frag(uint8_t *buf,
    uint32_t src, uint32_t dst, uint8_t proto, uint16_t ip_id,
    uint16_t frag_off_bytes, int more_frags,
    const uint8_t *payload, uint16_t payload_len)
{
    fill_ip_header(buf, src, dst, proto, ip_id,
                   frag_off_bytes, more_frags, payload_len);
    memcpy(buf + 20, payload, payload_len);
    return 20 + payload_len;
}

/* Wrap an IP packet in a minimal Ethernet II frame. */
static size_t wrap_eth(uint8_t *out, const uint8_t *ip_pkt, size_t ip_len)
{
    memset(out, 0, 12);         /* dst + src MAC = all-zero */
    out[12] = 0x08; out[13] = 0x00;   /* EtherType IPv4 */
    memcpy(out + 14, ip_pkt, ip_len);
    return 14 + ip_len;
}

/* ── tests ────────────────────────────────────────────────────────────────── */

static void test_in_order(void)
{
    libpcapng_reasm_t *r = libpcapng_reasm_new();
    assert(r);

    /* 500-byte payload split 200 + 200 + 100 */
    uint8_t payload[500];
    for (int i = 0; i < 500; i++) payload[i] = (uint8_t)i;

    uint8_t f1[220], f2[220], f3[120];
    uint8_t *out; size_t out_len;
    int rc;

    size_t l1 = make_frag(f1, 0x0a000001, 0x0a000002, 17, 0x1234,   0, 1, payload,       200);
    size_t l2 = make_frag(f2, 0x0a000001, 0x0a000002, 17, 0x1234, 200, 1, payload + 200, 200);
    size_t l3 = make_frag(f3, 0x0a000001, 0x0a000002, 17, 0x1234, 400, 0, payload + 400, 100);

    rc = libpcapng_reasm_add(r, f1, l1, &out, &out_len);
    assert(rc == 0);
    rc = libpcapng_reasm_add(r, f2, l2, &out, &out_len);
    assert(rc == 0);
    rc = libpcapng_reasm_add(r, f3, l3, &out, &out_len);
    assert(rc == 1);
    assert(out && out_len == 520);

    /* verify IP header fields */
    uint16_t tot_len   = (uint16_t)((out[2] << 8) | out[3]);
    uint16_t frag_word = (uint16_t)((out[6] << 8) | out[7]);
    assert(tot_len   == 520);
    assert(frag_word == 0);

    /* verify payload */
    assert(memcmp(out + 20, payload, 500) == 0);

    /* verify checksum */
    uint8_t hdr_copy[20];
    memcpy(hdr_copy, out, 20);
    hdr_copy[10] = 0; hdr_copy[11] = 0;
    assert(libpcapng_ip_checksum(hdr_copy, 20) == (uint16_t)((out[10] << 8) | out[11]));

    free(out);
    libpcapng_reasm_free(r);
    printf("test_in_order: PASS\n");
}

static void test_out_of_order(void)
{
    libpcapng_reasm_t *r = libpcapng_reasm_new();
    assert(r);

    uint8_t payload[500];
    for (int i = 0; i < 500; i++) payload[i] = (uint8_t)(i ^ 0xaa);

    uint8_t f1[220], f2[220], f3[120];
    uint8_t *out; size_t out_len;

    size_t l1 = make_frag(f1, 0x0a000001, 0x0a000002, 6, 0xabcd,   0, 1, payload,       200);
    size_t l2 = make_frag(f2, 0x0a000001, 0x0a000002, 6, 0xabcd, 200, 1, payload + 200, 200);
    size_t l3 = make_frag(f3, 0x0a000001, 0x0a000002, 6, 0xabcd, 400, 0, payload + 400, 100);

    /* arrive: last → first → middle */
    int rc = libpcapng_reasm_add(r, f3, l3, &out, &out_len);
    assert(rc == 0);
    rc = libpcapng_reasm_add(r, f1, l1, &out, &out_len);
    assert(rc == 0);
    rc = libpcapng_reasm_add(r, f2, l2, &out, &out_len);
    assert(rc == 1);
    assert(out && memcmp(out + 20, payload, 500) == 0);

    free(out);
    libpcapng_reasm_free(r);
    printf("test_out_of_order: PASS\n");
}

static void test_ethernet_input(void)
{
    libpcapng_reasm_t *r = libpcapng_reasm_new();
    assert(r);

    uint8_t payload[300];
    memset(payload, 0x55, sizeof(payload));

    uint8_t ip1[220], ip2[120];
    uint8_t eth1[234], eth2[134];
    uint8_t *out; size_t out_len;

    size_t l1 = make_frag(ip1, 0xc0a80101, 0xc0a80102, 17, 0x0001,   0, 1, payload,       200);
    size_t l2 = make_frag(ip2, 0xc0a80101, 0xc0a80102, 17, 0x0001, 200, 0, payload + 200, 100);

    size_t el1 = wrap_eth(eth1, ip1, l1);
    size_t el2 = wrap_eth(eth2, ip2, l2);

    int rc = libpcapng_reasm_add(r, eth1, el1, &out, &out_len);
    assert(rc == 0);
    rc = libpcapng_reasm_add(r, eth2, el2, &out, &out_len);
    assert(rc == 1);
    assert(out && out_len == 320);
    assert(memcmp(out + 20, payload, 300) == 0);

    free(out);
    libpcapng_reasm_free(r);
    printf("test_ethernet_input: PASS\n");
}

static void test_non_fragment(void)
{
    libpcapng_reasm_t *r = libpcapng_reasm_new();
    assert(r);

    /* unfragmented packet: MF=0, frag_off=0 */
    uint8_t pkt[28];
    memset(pkt + 20, 0xbb, 8);
    fill_ip_header(pkt, 0x01020304, 0x05060708, 17, 0x9999, 0, 0, 8);

    uint8_t *out; size_t out_len;
    int rc = libpcapng_reasm_add(r, pkt, 28, &out, &out_len);
    assert(rc == -1);
    assert(out == NULL);

    libpcapng_reasm_free(r);
    printf("test_non_fragment: PASS\n");
}

static void test_two_streams(void)
{
    /* two concurrent fragmented streams with different IP IDs */
    libpcapng_reasm_t *r = libpcapng_reasm_new();
    assert(r);

    uint8_t pA[100], pB[80];
    memset(pA, 0xAA, 100); memset(pB, 0xBB, 80);

    uint8_t fA1[140], fA2[120];
    uint8_t fB1[140], fB2[100];
    uint8_t *out; size_t out_len;

    /* stream A: ip_id=0x0001, 100+100 bytes (two equal frags for simplicity: 8-byte aligned) */
    /* actually 8-byte aligned: first frag = 96 bytes, second = 4 bytes would work; let's use 104+100 */
    uint8_t pA_full[200]; memset(pA_full, 0xAA, 200);
    uint8_t pB_full[160]; memset(pB_full, 0xBB, 160);

    size_t lA1 = make_frag(fA1, 0x0a000001, 0x0a000002, 17, 0x0001,   0, 1, pA_full,       104);
    size_t lA2 = make_frag(fA2, 0x0a000001, 0x0a000002, 17, 0x0001, 104, 0, pA_full + 104,  96);
    size_t lB1 = make_frag(fB1, 0x0a000001, 0x0a000002, 17, 0x0002,   0, 1, pB_full,        80);
    size_t lB2 = make_frag(fB2, 0x0a000001, 0x0a000002, 17, 0x0002,  80, 0, pB_full + 80,   80);

    /* interleave: A1 B1 A2 B2 */
    assert(libpcapng_reasm_add(r, fA1, lA1, &out, &out_len) == 0);
    assert(libpcapng_reasm_add(r, fB1, lB1, &out, &out_len) == 0);

    int rc = libpcapng_reasm_add(r, fA2, lA2, &out, &out_len);
    assert(rc == 1 && out_len == 220);
    assert(memcmp(out + 20, pA_full, 200) == 0);
    free(out);

    rc = libpcapng_reasm_add(r, fB2, lB2, &out, &out_len);
    assert(rc == 1 && out_len == 180);
    assert(memcmp(out + 20, pB_full, 160) == 0);
    free(out);

    libpcapng_reasm_free(r);
    printf("test_two_streams: PASS\n");
}

int main(void)
{
    test_in_order();
    test_out_of_order();
    test_ethernet_input();
    test_non_fragment();
    test_two_streams();
    printf("All reassembly tests passed.\n");
    return 0;
}
