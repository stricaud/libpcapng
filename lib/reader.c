/*
 * reader.c — see reader.h.
 *
 * License MIT
 */
#include <libpcapng/reader.h>

#include <stdlib.h>
#include <string.h>

#include <libpcapng/blocks.h>
#include <libpcapng/io.h>

/* Block bodies, as the spec lays them out, measured from the first byte after
   the type and total-length words. */
#define IDB_BODY_MIN   8    /* linktype(2) reserved(2) snaplen(4)              */
#define EPB_BODY_MIN  20    /* iface(4) ts_hi(4) ts_lo(4) caplen(4) origlen(4) */
#define SPB_BODY_MIN   4    /* original_len(4)                                 */
#define PB_BODY_MIN   20    /* iface(2) drops(2) ts_hi(4) ts_lo(4) cap(4) orig(4) */

/* A block's eight bytes of type and length, plus the four of trailing length,
   are not part of the body the callback is handed. */
#define BLOCK_OVERHEAD 12

#define MAX_INTERFACES 256

int pcapng_block_is_idb(uint32_t t, size_t n)
{ return t == PCAPNG_INTERFACE_DESCRIPTION_BLOCK && n >= IDB_BODY_MIN; }
int pcapng_block_is_epb(uint32_t t, size_t n)
{ return t == PCAPNG_ENHANCED_PACKET_BLOCK && n >= EPB_BODY_MIN; }
int pcapng_block_is_spb(uint32_t t, size_t n)
{ return t == PCAPNG_SIMPLE_PACKET_BLOCK && n >= SPB_BODY_MIN; }
int pcapng_block_is_packet(uint32_t t, size_t n)
{ return t == PCAPNG_PACKET_BLOCK && n >= PB_BODY_MIN; }
int pcapng_block_has_packet(uint32_t t, size_t n)
{ return pcapng_block_is_epb(t, n) || pcapng_block_is_spb(t, n) || pcapng_block_is_packet(t, n); }

/* ── interface table ──────────────────────────────────────────────────────── */

typedef struct {
    uint16_t linktype;
    /* if_tsresol, as the spec encodes it. A timestamp is a count of these. */
    uint64_t ticks_per_sec;
} iface_t;

typedef struct {
    iface_t          ifaces[MAX_INTERFACES];
    int              niface;
    uint64_t         index;
    pcapng_read_packet_cb cb;
    void            *user;
    long             delivered;
    int              stopped;
} ctx_t;

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * if_tsresol (option code 9) is one byte. With the top bit clear it is a power
 * of ten, with it set a power of two — so 6 means microseconds, the default
 * when the option is absent, and 9 means nanoseconds. Everything else in the
 * IDB's options is skipped.
 */
static uint64_t idb_ticks_per_sec(const uint8_t *body, size_t len)
{
    size_t off = IDB_BODY_MIN;
    uint64_t ticks = 1000000ULL;              /* microseconds unless told otherwise */

    while (off + 4 <= len) {
        uint16_t code = le16(body + off);
        uint16_t olen = le16(body + off + 2);
        size_t   padded = ((size_t)olen + 3u) & ~(size_t)3u;

        if (code == 0) break;                 /* opt_endofopt */
        if (off + 4 + padded > len) break;
        if (code == 9 && olen >= 1) {
            uint8_t v = body[off + 4];
            int exp = v & 0x7f;
            if (exp > 63) break;              /* nonsense; keep the default */
            if (v & 0x80) {
                ticks = 1ULL << exp;          /* 2^exp ticks per second */
            } else {
                uint64_t p = 1;
                int i;
                /* 10^exp, refusing to overflow rather than wrapping. */
                for (i = 0; i < exp; i++) {
                    if (p > 1844674407370955161ULL) { p = 0; break; }
                    p *= 10;
                }
                if (p) ticks = p;
            }
            break;
        }
        off += 4 + padded;
    }
    return ticks ? ticks : 1000000ULL;
}

static void iface_add(ctx_t *c, const uint8_t *body, size_t len)
{
    iface_t *f;
    if (c->niface >= MAX_INTERFACES) return;
    f = &c->ifaces[c->niface++];
    f->linktype      = le16(body);
    f->ticks_per_sec = idb_ticks_per_sec(body, len);
}

/* An interface id with no IDB behind it is a malformed file. Ethernet is the
   assumption the rest of the library makes in that case, so it is the one made
   here too rather than inventing a different one. */
static const iface_t *iface_get(const ctx_t *c, uint32_t id)
{
    static const iface_t fallback = { 1, 1000000ULL };
    return ((int)id < c->niface) ? &c->ifaces[id] : &fallback;
}

static uint64_t ts_to_ns(uint64_t ticks, uint64_t ticks_per_sec)
{
    uint64_t sec  = ticks / ticks_per_sec;
    uint64_t rest = ticks % ticks_per_sec;
    /* Scale the sub-second part without losing it to integer division and
       without overflowing on a nanosecond-resolution capture. */
    return sec * 1000000000ULL + (rest * 1000000000ULL) / ticks_per_sec;
}

/* ── the block walk ───────────────────────────────────────────────────────── */

static int on_block(uint32_t counter, uint32_t type, uint32_t total_len,
                    unsigned char *data, void *userdata)
{
    ctx_t *c = (ctx_t *)userdata;
    pcapng_packet_t pkt;
    size_t body_len;

    (void)counter;
    if (c->stopped) return 0;
    if (total_len < BLOCK_OVERHEAD) return 0;
    body_len = (size_t)total_len - BLOCK_OVERHEAD;

    if (pcapng_block_is_idb(type, body_len)) {
        iface_add(c, (const uint8_t *)data, body_len);
        return 0;
    }

    memset(&pkt, 0, sizeof pkt);
    pkt.block_type = type;

    if (pcapng_block_is_epb(type, body_len)) {
        const uint8_t *b = (const uint8_t *)data;
        const iface_t *f;
        uint64_t ticks;

        pkt.interface_id = le32(b);
        ticks            = ((uint64_t)le32(b + 4) << 32) | le32(b + 8);
        pkt.captured_len = le32(b + 12);
        pkt.original_len = le32(b + 16);
        if ((size_t)pkt.captured_len + EPB_BODY_MIN > body_len) return 0;  /* truncated */

        f = iface_get(c, pkt.interface_id);
        pkt.linktype      = f->linktype;
        pkt.timestamp_ns  = ts_to_ns(ticks, f->ticks_per_sec);
        pkt.has_timestamp = 1;
        pkt.data          = b + EPB_BODY_MIN;

    } else if (pcapng_block_is_spb(type, body_len)) {
        const uint8_t *b = (const uint8_t *)data;
        uint32_t avail = (uint32_t)(body_len - SPB_BODY_MIN);

        /* A Simple Packet Block records only the original length; what was
           actually stored is whatever fits in the block, so the two have to be
           reconciled rather than trusted. */
        pkt.original_len = le32(b);
        pkt.captured_len = (pkt.original_len < avail) ? pkt.original_len : avail;
        pkt.interface_id = 0;
        pkt.linktype     = iface_get(c, 0)->linktype;
        pkt.data         = b + SPB_BODY_MIN;

    } else if (pcapng_block_is_packet(type, body_len)) {
        /* The obsolete Packet Block, superseded by the EPB in pcapng but still
           present in files written by older tools. */
        const uint8_t *b = (const uint8_t *)data;
        const iface_t *f;
        uint64_t ticks;

        pkt.interface_id = le16(b);
        ticks            = ((uint64_t)le32(b + 4) << 32) | le32(b + 8);
        pkt.captured_len = le32(b + 12);
        pkt.original_len = le32(b + 16);
        if ((size_t)pkt.captured_len + PB_BODY_MIN > body_len) return 0;

        f = iface_get(c, pkt.interface_id);
        pkt.linktype      = f->linktype;
        pkt.timestamp_ns  = ts_to_ns(ticks, f->ticks_per_sec);
        pkt.has_timestamp = 1;
        pkt.data          = b + PB_BODY_MIN;

    } else {
        return 0;                            /* SHB, NRB, DSB, custom, ... */
    }

    pkt.index = ++c->index;
    c->delivered++;
    if (c->cb && c->cb(&pkt, c->user) != 0) c->stopped = 1;
    return 0;
}

static void ctx_init(ctx_t *c, pcapng_read_packet_cb cb, void *user)
{
    memset(c, 0, sizeof *c);
    c->cb = cb;
    c->user = user;
}

long pcapng_read_packets(const char *path, pcapng_read_packet_cb cb, void *user)
{
    ctx_t c;
    FILE *fp;
    if (!path) return -1;
    fp = fopen(path, "rb");
    if (!fp) return -1;
    ctx_init(&c, cb, user);
    libpcapng_fp_read(fp, on_block, &c);
    fclose(fp);
    return c.delivered;
}

long pcapng_read_packets_fp(FILE *fp, pcapng_read_packet_cb cb, void *user)
{
    ctx_t c;
    if (!fp) return -1;
    ctx_init(&c, cb, user);
    libpcapng_fp_read(fp, on_block, &c);
    return c.delivered;
}

long pcapng_read_packets_mem(const uint8_t *buf, size_t len,
                             pcapng_read_packet_cb cb, void *user)
{
    ctx_t c;
    if (!buf) return -1;
    ctx_init(&c, cb, user);
    libpcapng_mem_read(buf, len, on_block, &c);
    return c.delivered;
}
