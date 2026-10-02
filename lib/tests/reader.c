/*
 * reader.c — pcapng_read_packets(), the packet-level view of a capture.
 *
 * The thing under test is everything a caller used to have to do by hand:
 * the Enhanced and Simple Packet Block layouts, the interface table that turns
 * an interface id into a link type, the timestamp resolution an interface
 * declares, and a packet counter that counts packets rather than blocks.
 *
 * Captures are built byte by byte here rather than loaded from a file, so what
 * is being asserted is visible next to the assertion.
 *
 * Build via cmake (registered as the Reader ctest target).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libpcapng/blocks.h>
#include <libpcapng/reader.h>

static int pass, fail;
#define CK(l,e) do{ if(e){pass++;printf("  ok    %s\n",l);} \
                    else {fail++;printf("  FAIL  %s  (%s:%d)\n",l,__FILE__,__LINE__);} }while(0)

/* ── building a capture ───────────────────────────────────────────────────── */

typedef struct { uint8_t b[4096]; size_t n; } buf_t;

static void put32(buf_t *b, uint32_t v)
{ b->b[b->n++] = (uint8_t)v; b->b[b->n++] = (uint8_t)(v>>8);
  b->b[b->n++] = (uint8_t)(v>>16); b->b[b->n++] = (uint8_t)(v>>24); }
static void put16(buf_t *b, uint16_t v)
{ b->b[b->n++] = (uint8_t)v; b->b[b->n++] = (uint8_t)(v>>8); }
static void putn(buf_t *b, const void *p, size_t n)
{ memcpy(b->b + b->n, p, n); b->n += n; }

static void add_shb(buf_t *b)
{
    put32(b, PCAPNG_SECTION_HEADER_BLOCK);
    put32(b, 28);
    put32(b, 0x1A2B3C4D);                 /* byte-order magic */
    put16(b, 1); put16(b, 0);             /* version 1.0 */
    put32(b, 0xffffffffu); put32(b, 0xffffffffu);   /* section length: unknown */
    put32(b, 28);
}

/* tsresol < 0 leaves the option out, so the default applies. */
static void add_idb(buf_t *b, uint16_t linktype, int tsresol)
{
    uint32_t total = (tsresol >= 0) ? 20 + 8 + 4 : 20;
    put32(b, PCAPNG_INTERFACE_DESCRIPTION_BLOCK);
    put32(b, total);
    put16(b, linktype); put16(b, 0);
    put32(b, 65535);                      /* snaplen */
    if (tsresol >= 0) {
        put16(b, 9); put16(b, 1);         /* option 9 = if_tsresol, length 1 */
        b->b[b->n++] = (uint8_t)tsresol;
        b->b[b->n++] = 0; b->b[b->n++] = 0; b->b[b->n++] = 0;   /* pad to 4 */
        put16(b, 0); put16(b, 0);         /* opt_endofopt */
    }
    put32(b, total);
}

static void add_epb(buf_t *b, uint32_t iface, uint64_t ticks,
                    const uint8_t *data, uint32_t caplen, uint32_t origlen)
{
    uint32_t pad = (4 - (caplen % 4)) % 4;
    uint32_t total = 8 + 20 + caplen + pad + 4;
    put32(b, PCAPNG_ENHANCED_PACKET_BLOCK);
    put32(b, total);
    put32(b, iface);
    put32(b, (uint32_t)(ticks >> 32));
    put32(b, (uint32_t)(ticks & 0xffffffffu));
    put32(b, caplen);
    put32(b, origlen);
    putn(b, data, caplen);
    memset(b->b + b->n, 0, pad); b->n += pad;
    put32(b, total);
}

static void add_spb(buf_t *b, const uint8_t *data, uint32_t len, uint32_t origlen)
{
    uint32_t pad = (4 - (len % 4)) % 4;
    uint32_t total = 8 + 4 + len + pad + 4;
    put32(b, PCAPNG_SIMPLE_PACKET_BLOCK);
    put32(b, total);
    put32(b, origlen);
    putn(b, data, len);
    memset(b->b + b->n, 0, pad); b->n += pad;
    put32(b, total);
}

/* ── collecting what the reader hands back ────────────────────────────────── */

#define MAX_SEEN 16
typedef struct {
    pcapng_packet_t p[MAX_SEEN];
    uint8_t         data[MAX_SEEN][256];
    int             n;
    int             stop_after;     /* 0 = never stop */
} seen_t;

static int collect(const pcapng_packet_t *pkt, void *ud)
{
    seen_t *s = (seen_t *)ud;
    if (s->n < MAX_SEEN) {
        uint32_t n = pkt->captured_len < 256 ? pkt->captured_len : 256;
        s->p[s->n] = *pkt;
        memcpy(s->data[s->n], pkt->data, n);
        s->p[s->n].data = s->data[s->n];        /* the C pointer dies with the call */
        s->n++;
    }
    return (s->stop_after && s->n >= s->stop_after) ? 1 : 0;
}

static long run(const buf_t *b, seen_t *s)
{
    memset(s, 0, sizeof *s);
    return pcapng_read_packets_mem(b->b, b->n, collect, s);
}

static long run_stop(const buf_t *b, seen_t *s, int after)
{
    memset(s, 0, sizeof *s);
    s->stop_after = after;
    return pcapng_read_packets_mem(b->b, b->n, collect, s);
}

int main(void)
{
    static const uint8_t FRAME[8] = { 1,2,3,4,5,6,7,8 };
    buf_t b; seen_t s; long n;

    printf("=== reader ===\n");

    printf("\n[an interface id becomes a link type]\n");
    memset(&b, 0, sizeof b);
    add_shb(&b);
    add_idb(&b, 1, -1);                      /* interface 0: Ethernet */
    add_idb(&b, 228, -1);                    /* interface 1: raw IPv4 */
    add_epb(&b, 0, 1000000, FRAME, 8, 8);
    add_epb(&b, 1, 2000000, FRAME, 8, 8);
    n = run(&b, &s);
    CK("two packets, and only the packets", n == 2 && s.n == 2);
    CK("index counts packets, not blocks", s.p[0].index == 1 && s.p[1].index == 2);
    CK("first resolves to its own interface", s.p[0].linktype == 1);
    CK("second resolves to the other one", s.p[1].linktype == 228);
    CK("interface id is reported", s.p[0].interface_id == 0 && s.p[1].interface_id == 1);
    CK("frame bytes are the frame", memcmp(s.p[0].data, FRAME, 8) == 0);

    printf("\n[timestamp resolution comes from the interface]\n");
    /* Default: no if_tsresol, so the ticks are microseconds. 1500000 us. */
    memset(&b, 0, sizeof b);
    add_shb(&b); add_idb(&b, 1, -1);
    add_epb(&b, 0, 1500000, FRAME, 8, 8);
    run(&b, &s);
    CK("absent if_tsresol means microseconds", s.p[0].timestamp_ns == 1500000000ULL);
    CK("and the packet says it has one", s.p[0].has_timestamp == 1);

    /* if_tsresol 9: the same count is now nanoseconds, a thousand times less. */
    memset(&b, 0, sizeof b);
    add_shb(&b); add_idb(&b, 1, 9);
    add_epb(&b, 0, 1500000, FRAME, 8, 8);
    run(&b, &s);
    CK("if_tsresol 9 means nanoseconds", s.p[0].timestamp_ns == 1500000ULL);

    /* if_tsresol 3: milliseconds. */
    memset(&b, 0, sizeof b);
    add_shb(&b); add_idb(&b, 1, 3);
    add_epb(&b, 0, 1500, FRAME, 8, 8);
    run(&b, &s);
    CK("if_tsresol 3 means milliseconds", s.p[0].timestamp_ns == 1500000000ULL);

    /* The high bit makes it a power of two: 2^-10 of a second per tick. */
    memset(&b, 0, sizeof b);
    add_shb(&b); add_idb(&b, 1, 0x80 | 10);
    add_epb(&b, 0, 1024, FRAME, 8, 8);
    run(&b, &s);
    CK("if_tsresol with the high bit set is a power of two",
       s.p[0].timestamp_ns == 1000000000ULL);

    /* Sub-second precision must survive, not be lost to integer division. */
    memset(&b, 0, sizeof b);
    add_shb(&b); add_idb(&b, 1, -1);
    add_epb(&b, 0, 1234567, FRAME, 8, 8);
    run(&b, &s);
    CK("the fraction is kept", s.p[0].timestamp_ns == 1234567000ULL);

    printf("\n[Simple Packet Blocks]\n");
    memset(&b, 0, sizeof b);
    add_shb(&b); add_idb(&b, 1, -1);
    add_spb(&b, FRAME, 8, 8);
    run(&b, &s);
    CK("an SPB is a packet", s.n == 1);
    CK("it has no timestamp, and does not pretend to",
       s.p[0].has_timestamp == 0 && s.p[0].timestamp_ns == 0);
    CK("it inherits interface 0's link type", s.p[0].linktype == 1);
    CK("its bytes are right", memcmp(s.p[0].data, FRAME, 8) == 0);

    /* An SPB records the original length only. When that exceeds what the block
       actually holds, the stored length is what is there — reading `original_len`
       bytes would run past the end, which is the bug this guards. */
    memset(&b, 0, sizeof b);
    add_shb(&b); add_idb(&b, 1, -1);
    add_spb(&b, FRAME, 8, 1500);
    run(&b, &s);
    CK("captured_len is clamped to what the block holds", s.p[0].captured_len == 8);
    CK("original_len still reports the wire length", s.p[0].original_len == 1500);
    CK("and the packet knows it is truncated",
       s.p[0].captured_len < s.p[0].original_len);

    printf("\n[a capture with no interface description]\n");
    memset(&b, 0, sizeof b);
    add_shb(&b);
    add_epb(&b, 0, 1000000, FRAME, 8, 8);
    run(&b, &s);
    CK("the packet still arrives", s.n == 1);
    CK("falling back to Ethernet rather than guessing wildly", s.p[0].linktype == 1);

    printf("\n[a captured length that lies]\n");
    /* caplen claims more than the block can hold. Reading it would walk off the
       end of the buffer, so the block is skipped instead. */
    memset(&b, 0, sizeof b);
    add_shb(&b); add_idb(&b, 1, -1);
    { uint32_t total = 8 + 20 + 8 + 4;
      put32(&b, PCAPNG_ENHANCED_PACKET_BLOCK); put32(&b, total);
      put32(&b, 0); put32(&b, 0); put32(&b, 1000000);
      put32(&b, 9999);                       /* caplen: a lie */
      put32(&b, 9999);
      putn(&b, FRAME, 8);
      put32(&b, total); }
    add_epb(&b, 0, 2000000, FRAME, 8, 8);    /* a good one after it */
    n = run(&b, &s);
    CK("the lying block is skipped", n == 1 && s.n == 1);
    CK("and the good one after it is still read", s.p[0].timestamp_ns == 2000000000ULL);

    printf("\n[stopping early]\n");
    memset(&b, 0, sizeof b);
    add_shb(&b); add_idb(&b, 1, -1);
    add_epb(&b, 0, 1000000, FRAME, 8, 8);
    add_epb(&b, 0, 2000000, FRAME, 8, 8);
    add_epb(&b, 0, 3000000, FRAME, 8, 8);
    n = run_stop(&b, &s, 2);
    CK("a callback returning non-zero stops the walk", n == 2 && s.n == 2);

    printf("\n[the block-type predicates]\n");
    CK("an EPB needs 20 bytes of body",
       pcapng_block_is_epb(PCAPNG_ENHANCED_PACKET_BLOCK, 20) &&
       !pcapng_block_is_epb(PCAPNG_ENHANCED_PACKET_BLOCK, 19));
    CK("an SPB needs 4", pcapng_block_is_spb(PCAPNG_SIMPLE_PACKET_BLOCK, 4) &&
                         !pcapng_block_is_spb(PCAPNG_SIMPLE_PACKET_BLOCK, 3));
    CK("an IDB needs 8", pcapng_block_is_idb(PCAPNG_INTERFACE_DESCRIPTION_BLOCK, 8) &&
                         !pcapng_block_is_idb(PCAPNG_INTERFACE_DESCRIPTION_BLOCK, 7));
    CK("the type has to match too",
       !pcapng_block_is_epb(PCAPNG_SIMPLE_PACKET_BLOCK, 64));
    CK("has_packet covers all three packet-carrying kinds",
       pcapng_block_has_packet(PCAPNG_ENHANCED_PACKET_BLOCK, 20) &&
       pcapng_block_has_packet(PCAPNG_SIMPLE_PACKET_BLOCK, 4) &&
       pcapng_block_has_packet(PCAPNG_PACKET_BLOCK, 20) &&
       !pcapng_block_has_packet(PCAPNG_SECTION_HEADER_BLOCK, 64));

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
