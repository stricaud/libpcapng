/*
 * License MIT
 * Copyright (c) 2026 Sebastien Tricaud
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#ifdef _WIN32
#  include <libpcapng/win_compat.h>
#else
#  include <unistd.h>
#endif

#include <libpcapng/io.h>
#include <libpcapng/blocks.h>
#include <libpcapng/capture.h>
#include <libpcapng/surgery.h>

/* ── Internal streaming reader ───────────────────────────────────────────────
 *
 * libpcapng_fp_read uses a fixed 65535-byte stack buffer which silently drops
 * large blocks (e.g. DSBs or NRBs with many entries).  This reader allocates
 * dynamically and handles arbitrarily large blocks.
 *
 * Callback receives the same signature as foreach_pcapng_block_cb:
 *   (block_counter, block_type, block_total_length, data, userdata)
 * where data points to block body AFTER the 8-byte header, INCLUDING the
 * trailing 4-byte block_total_length.
 *
 * Returns 0 on clean EOF, -1 on I/O error or malformed block.
 */
static int surgery_fp_read(FILE *fp,
                            foreach_pcapng_block_cb cb,
                            void *userdata)
{
    uint32_t hdr[2];
    uint64_t ctr = 1;
    unsigned char *buf = NULL;
    size_t buf_cap = 0;

    while (fread(hdr, 1, 8, fp) == 8) {
        uint32_t block_type         = hdr[0];
        uint32_t block_total_length = hdr[1];

        if (block_total_length < 12) {
            free(buf);
            return -1;
        }

        size_t body_len = block_total_length - 8;
        if (body_len > buf_cap) {
            free(buf);
            buf = (unsigned char *)malloc(body_len);
            if (!buf) return -1;
            buf_cap = body_len;
        }

        if (fread(buf, 1, body_len, fp) != body_len) {
            free(buf);
            return -1;
        }

        cb((uint32_t)ctr, block_type, block_total_length, buf, userdata);
        ctr++;
    }

    free(buf);
    return feof(fp) ? 0 : -1;
}

/* Copy one block verbatim to fp_out.
 * block_type and block_total_length are the already-read header fields;
 * data is the body (block_total_length - 8 bytes). */
static int block_copy(FILE *fp_out,
                      uint32_t block_type,
                      uint32_t block_total_length,
                      const unsigned char *data)
{
    uint32_t hdr[2] = { block_type, block_total_length };
    if (fwrite(hdr, 1, 8, fp_out) != 8)                             return -1;
    if (fwrite(data, 1, block_total_length - 8, fp_out)
            != block_total_length - 8)                               return -1;
    return 0;
}

/* ── Interface-ID → linktype table ──────────────────────────────────────────*/

#define MAX_INTERFACES 256

typedef struct {
    uint16_t linktypes[MAX_INTERFACES];
    int      count;
} idb_table_t;

static void idb_table_init(idb_table_t *t)
{
    memset(t, 0, sizeof(*t));
}

static void idb_table_add(idb_table_t *t, const unsigned char *data)
{
    if (t->count >= MAX_INTERFACES) return;
    uint16_t lt;
    memcpy(&lt, data, 2);
    t->linktypes[t->count++] = lt;
}

static uint16_t idb_table_get(const idb_table_t *t, uint32_t iface_id)
{
    if ((int)iface_id < t->count)
        return t->linktypes[iface_id];
    return 1; /* fallback: Ethernet */
}

/* ── FNV-1a (32-bit) ─────────────────────────────────────────────────────── */

static uint32_t fnv1a32(const uint8_t *data, size_t len)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++)
        h = (h ^ data[i]) * 16777619u;
    return h;
}

/* ── IPv4 header checksum ────────────────────────────────────────────────── */

static uint16_t ipv4_checksum(const uint8_t *hdr, int hdr_len)
{
    uint32_t sum = 0;
    for (int i = 0; i < hdr_len; i += 2) {
        uint16_t w;
        memcpy(&w, hdr + i, 2);
        sum += w;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

/* ════════════════════════════════════════════════════════════════════════════
 * 1.  pcapng_filter_file
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    FILE        *out;
    const char  *filter_expr;
    char        *errbuf;
    idb_table_t  idbs;
    int          written;
    int          error;
} filter_ctx_t;

static int filter_cb(uint32_t block_counter, uint32_t block_type,
                     uint32_t block_total_length, unsigned char *data,
                     void *userdata)
{
    (void)block_counter;
    filter_ctx_t *ctx = (filter_ctx_t *)userdata;
    if (ctx->error) return 0;

    switch (block_type) {
    case PCAPNG_INTERFACE_DESCRIPTION_BLOCK:
        idb_table_add(&ctx->idbs, data);
        if (block_copy(ctx->out, block_type, block_total_length, data) < 0)
            ctx->error = 1;
        break;

    case PCAPNG_ENHANCED_PACKET_BLOCK: {
        uint32_t iface_id, caplen;
        memcpy(&iface_id, data +  0, 4);
        memcpy(&caplen,   data + 12, 4);

        uint32_t pad = (4 - (caplen % 4)) % 4;
        if (block_total_length < 8 + 20 + caplen + pad + 4) {
            ctx->error = 1;
            break;
        }

        const uint8_t *pkt = data + 20;
        uint16_t lt = idb_table_get(&ctx->idbs, iface_id);

        char local_errbuf[PCAPNG_SURGERY_ERRBUF_SIZE] = {0};
        int r = pcapng_capture_filter_match(ctx->filter_expr,
                                            pkt, caplen, lt,
                                            local_errbuf);
        if (r < 0) {
            if (ctx->errbuf) {
                strncpy(ctx->errbuf, local_errbuf, PCAPNG_SURGERY_ERRBUF_SIZE - 1);
                ctx->errbuf[PCAPNG_SURGERY_ERRBUF_SIZE - 1] = '\0';
            }
            ctx->error = 1;
            break;
        }
        if (r == 1) {
            if (block_copy(ctx->out, block_type, block_total_length, data) < 0)
                ctx->error = 1;
            else
                ctx->written++;
        }
        break;
    }

    default:
        /* SHB, NRB, ISB, DSB, and anything else pass through */
        if (block_copy(ctx->out, block_type, block_total_length, data) < 0)
            ctx->error = 1;
        break;
    }

    return 0;
}

int pcapng_filter_file(const char *input, const char *output,
                       const char *filter_expr, char *errbuf)
{
    FILE *in = fopen(input, "rb");
    if (!in) {
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                             "cannot open %s: %s", input, strerror(errno));
        return -1;
    }
    FILE *out = fopen(output, "wb");
    if (!out) {
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                             "cannot open %s: %s", output, strerror(errno));
        fclose(in);
        return -1;
    }

    filter_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.out         = out;
    ctx.filter_expr = filter_expr;
    ctx.errbuf      = errbuf;
    idb_table_init(&ctx.idbs);

    surgery_fp_read(in, filter_cb, &ctx);

    fclose(in);
    fclose(out);
    return ctx.error ? -1 : ctx.written;
}

/* ════════════════════════════════════════════════════════════════════════════
 * 2.  pcapng_merge
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    FILE *out;
    int   idb_offset;  /* value to add to every EPB interface_id in this file */
    int   idb_count;   /* IDB blocks seen in this file so far */
    int   written;     /* EPBs written */
    int   error;
} merge_ctx_t;

static int merge_cb(uint32_t block_counter, uint32_t block_type,
                    uint32_t block_total_length, unsigned char *data,
                    void *userdata)
{
    (void)block_counter;
    merge_ctx_t *ctx = (merge_ctx_t *)userdata;
    if (ctx->error) return 0;

    switch (block_type) {
    case PCAPNG_SECTION_HEADER_BLOCK:
        /* Only the first file's SHB (already written before the loop) passes */
        break;

    case PCAPNG_INTERFACE_DESCRIPTION_BLOCK:
        ctx->idb_count++;
        if (block_copy(ctx->out, block_type, block_total_length, data) < 0)
            ctx->error = 1;
        break;

    case PCAPNG_ENHANCED_PACKET_BLOCK: {
        uint32_t iface_id;
        memcpy(&iface_id, data, 4);
        iface_id += (uint32_t)ctx->idb_offset;

        /* Write header */
        uint32_t hdr[2] = { block_type, block_total_length };
        if (fwrite(hdr, 1, 8, ctx->out) != 8) { ctx->error = 1; break; }

        /* Write rewritten interface_id, then the rest of the body */
        if (fwrite(&iface_id, 1, 4, ctx->out) != 4) { ctx->error = 1; break; }
        size_t rest = block_total_length - 8 - 4;
        if (fwrite(data + 4, 1, rest, ctx->out) != rest) { ctx->error = 1; break; }

        ctx->written++;
        break;
    }

    default:
        if (block_copy(ctx->out, block_type, block_total_length, data) < 0)
            ctx->error = 1;
        break;
    }

    return 0;
}

int pcapng_merge(const char **inputs, int n_inputs, const char *output,
                 const pcapng_merge_opts_t *opts, char *errbuf)
{
    (void)opts; /* sort_by_timestamp not yet implemented */

    FILE *out = fopen(output, "wb");
    if (!out) {
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                             "cannot open %s: %s", output, strerror(errno));
        return -1;
    }

    /* Write a single fresh SHB */
    size_t shb_sz = libpcapng_section_header_block_size();
    unsigned char *shb_buf = (unsigned char *)malloc(shb_sz);
    if (!shb_buf) {
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE, "out of memory");
        fclose(out); return -1;
    }
    libpcapng_section_header_block_write(shb_buf);
    if (fwrite(shb_buf, 1, shb_sz, out) != shb_sz) {
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE, "write error");
        free(shb_buf); fclose(out); return -1;
    }
    free(shb_buf);

    int total_written   = 0;
    int cumulative_idbs = 0;

    for (int i = 0; i < n_inputs; i++) {
        FILE *in = fopen(inputs[i], "rb");
        if (!in) {
            if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                                 "cannot open %s: %s", inputs[i], strerror(errno));
            fclose(out); return -1;
        }

        merge_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.out        = out;
        ctx.idb_offset = cumulative_idbs;

        surgery_fp_read(in, merge_cb, &ctx);
        fclose(in);

        if (ctx.error) {
            if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                                 "I/O error processing %s", inputs[i]);
            fclose(out); return -1;
        }

        cumulative_idbs += ctx.idb_count;
        total_written   += ctx.written;
    }

    fclose(out);
    return total_written;
}

/* ════════════════════════════════════════════════════════════════════════════
 * 3.  pcapng_split
 * ══════════════════════════════════════════════════════════════════════════ */

/* IDB buffer accumulated from the start of the current section, replayed at
 * the top of every new output file. */
#define SPLIT_IDB_BUF_MAX (64 * 1024)

typedef struct {
    const char          *pattern;
    const pcapng_split_opts_t *opts;

    /* current output file */
    FILE     *out;
    int       file_index;
    uint64_t  pkt_count;   /* EPBs in current file */
    uint64_t  byte_count;  /* bytes written to current file */
    int       files_created;
    int       error;

    /* buffered IDB blocks (replayed at each new file header) */
    unsigned char idb_buf[SPLIT_IDB_BUF_MAX];
    size_t        idb_buf_len;

    /* buffered SHB for replay */
    unsigned char shb_buf[256];
    size_t        shb_buf_len;
} split_ctx_t;

static int split_open_file(split_ctx_t *ctx)
{
    char fname[4096];
    snprintf(fname, sizeof(fname), ctx->pattern, ctx->file_index++);

    if (ctx->out) fclose(ctx->out);
    ctx->out = fopen(fname, "wb");
    if (!ctx->out) { ctx->error = 1; return -1; }

    ctx->pkt_count  = 0;
    ctx->byte_count = 0;
    ctx->files_created++;

    /* Replay SHB */
    if (ctx->shb_buf_len &&
        fwrite(ctx->shb_buf, 1, ctx->shb_buf_len, ctx->out) != ctx->shb_buf_len) {
        ctx->error = 1; return -1;
    }
    ctx->byte_count += ctx->shb_buf_len;

    /* Replay all IDBs seen so far */
    if (ctx->idb_buf_len &&
        fwrite(ctx->idb_buf, 1, ctx->idb_buf_len, ctx->out) != ctx->idb_buf_len) {
        ctx->error = 1; return -1;
    }
    ctx->byte_count += ctx->idb_buf_len;

    return 0;
}

static int split_cb(uint32_t block_counter, uint32_t block_type,
                    uint32_t block_total_length, unsigned char *data,
                    void *userdata)
{
    (void)block_counter;
    split_ctx_t *ctx = (split_ctx_t *)userdata;
    if (ctx->error) return 0;

    switch (block_type) {
    case PCAPNG_SECTION_HEADER_BLOCK:
        /* Cache the SHB for replay at the top of every subsequent output file. */
        if (block_total_length <= sizeof(ctx->shb_buf)) {
            uint32_t hdr[2] = { block_type, block_total_length };
            memcpy(ctx->shb_buf, hdr, 8);
            memcpy(ctx->shb_buf + 8, data, block_total_length - 8);
            ctx->shb_buf_len = block_total_length;
        }
        ctx->idb_buf_len = 0; /* reset IDB buffer on new section */

        if (!ctx->out) {
            /* First file: open directly without going through split_open_file,
             * because the SHB replay buffer was just populated above and the
             * IDB buffer is still empty — split_open_file would write nothing
             * useful anyway. */
            char fname[4096];
            snprintf(fname, sizeof(fname), ctx->pattern, ctx->file_index++);
            ctx->out = fopen(fname, "wb");
            if (!ctx->out) { ctx->error = 1; break; }
            ctx->files_created++;
            ctx->pkt_count  = 0;
            ctx->byte_count = 0;
        }
        if (block_copy(ctx->out, block_type, block_total_length, data) < 0)
            ctx->error = 1;
        else
            ctx->byte_count += block_total_length;
        break;

    case PCAPNG_INTERFACE_DESCRIPTION_BLOCK: {
        /* Append to IDB replay buffer */
        size_t needed = block_total_length;
        if (ctx->idb_buf_len + needed <= SPLIT_IDB_BUF_MAX) {
            uint32_t hdr[2] = { block_type, block_total_length };
            memcpy(ctx->idb_buf + ctx->idb_buf_len, hdr, 8);
            memcpy(ctx->idb_buf + ctx->idb_buf_len + 8,
                   data, block_total_length - 8);
            ctx->idb_buf_len += needed;
        }
        if (block_copy(ctx->out, block_type, block_total_length, data) < 0)
            ctx->error = 1;
        else
            ctx->byte_count += block_total_length;
        break;
    }

    case PCAPNG_ENHANCED_PACKET_BLOCK: {
        /* Check split conditions before writing */
        int need_split = 0;
        if (ctx->opts) {
            if (ctx->opts->max_packets &&
                ctx->pkt_count >= ctx->opts->max_packets)
                need_split = 1;
            if (ctx->opts->max_bytes &&
                ctx->byte_count + block_total_length > ctx->opts->max_bytes)
                need_split = 1;
        }

        if (need_split) {
            if (split_open_file(ctx) < 0) break;
        }

        if (block_copy(ctx->out, block_type, block_total_length, data) < 0)
            ctx->error = 1;
        else {
            ctx->pkt_count++;
            ctx->byte_count += block_total_length;
        }
        break;
    }

    default:
        if (ctx->out) {
            if (block_copy(ctx->out, block_type, block_total_length, data) < 0)
                ctx->error = 1;
            else
                ctx->byte_count += block_total_length;
        }
        break;
    }

    return 0;
}

int pcapng_split(const char *input, const char *output_pattern,
                 const pcapng_split_opts_t *opts, char *errbuf)
{
    FILE *in = fopen(input, "rb");
    if (!in) {
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                             "cannot open %s: %s", input, strerror(errno));
        return -1;
    }

    split_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pattern = output_pattern;
    ctx.opts    = opts;

    surgery_fp_read(in, split_cb, &ctx);
    fclose(in);

    if (ctx.out) fclose(ctx.out);
    return ctx.error ? -1 : ctx.files_created;
}

/* ════════════════════════════════════════════════════════════════════════════
 * 4.  pcapng_anonymize
 * ══════════════════════════════════════════════════════════════════════════ */

/* Anonymise 2 bytes of an address component using FNV-1a seeded with seed. */
static void anon2(uint8_t *a, uint64_t seed)
{
    uint8_t in[10];
    memcpy(in, &seed, 8);
    in[8] = a[0];
    in[9] = a[1];
    uint32_t h = fnv1a32(in, 10);
    a[0] = (h >> 8) & 0xff;
    a[1] =  h       & 0xff;
}

/* Anonymise `n` bytes starting at `a`, 2 bytes at a time. */
static void anon_bytes(uint8_t *a, int n, uint64_t seed)
{
    for (int i = 0; i < n; i += 2)
        anon2(a + i, seed ^ (uint64_t)i);
}

typedef struct {
    FILE                   *out;
    const pcapng_anon_opts_t *opts;
    idb_table_t             idbs;
    int                     processed;
    int                     error;
} anon_ctx_t;

static void anon_epb_packet(uint8_t *pkt, uint32_t caplen,
                             uint16_t linktype, const pcapng_anon_opts_t *opts)
{
    if (linktype != 1 /* ETHERNET */ || caplen < 14) return;

    uint8_t *eth = pkt;

    /* Optionally anonymise MACs: preserve OUI (first 3), alter last 3 */
    if (opts->anonymize_mac) {
        anon_bytes(eth + 3, 3, opts->seed ^ 0xDEAD000000000000ULL); /* dst */
        anon_bytes(eth + 9, 3, opts->seed ^ 0xBEEF000000000000ULL); /* src */
    }

    uint16_t ethertype;
    memcpy(&ethertype, eth + 12, 2);
    ethertype = (uint16_t)((ethertype >> 8) | (ethertype << 8)); /* BE→host */

    /* Skip VLAN tags */
    uint8_t *payload = eth + 14;
    uint32_t remaining = caplen - 14;
    while ((ethertype == 0x8100 || ethertype == 0x88A8) && remaining >= 4) {
        memcpy(&ethertype, payload + 2, 2);
        ethertype = (uint16_t)((ethertype >> 8) | (ethertype << 8));
        payload   += 4;
        remaining -= 4;
    }

    if (ethertype == 0x0800) {
        /* IPv4 */
        if (remaining < 20) return;
        int ihl = (payload[0] & 0x0f) * 4;
        if ((uint32_t)ihl > remaining) return;

        /* Preserve /16: anonymise last 2 octets of src and dst */
        anon_bytes(payload + 14, 2, opts->seed ^ 0x1111111111111111ULL); /* src[2:4] */
        anon_bytes(payload + 18, 2, opts->seed ^ 0x2222222222222222ULL); /* dst[2:4] */

        /* Recompute IPv4 header checksum */
        payload[10] = 0;
        payload[11] = 0;
        uint16_t csum = ipv4_checksum(payload, ihl);
        memcpy(payload + 10, &csum, 2);

    } else if (ethertype == 0x86DD) {
        /* IPv6 */
        if (remaining < 40) return;
        /* Preserve /64: anonymise last 8 bytes of src (offset 16) and dst (offset 32) */
        anon_bytes(payload + 16, 8, opts->seed ^ 0x3333333333333333ULL); /* src[8:16] */
        anon_bytes(payload + 32, 8, opts->seed ^ 0x4444444444444444ULL); /* dst[8:16] */
        /* No IPv6 header checksum to recompute */
    }
}

static int anon_cb(uint32_t block_counter, uint32_t block_type,
                   uint32_t block_total_length, unsigned char *data,
                   void *userdata)
{
    (void)block_counter;
    anon_ctx_t *ctx = (anon_ctx_t *)userdata;
    if (ctx->error) return 0;

    switch (block_type) {
    case PCAPNG_INTERFACE_DESCRIPTION_BLOCK:
        idb_table_add(&ctx->idbs, data);
        if (block_copy(ctx->out, block_type, block_total_length, data) < 0)
            ctx->error = 1;
        break;

    case PCAPNG_ENHANCED_PACKET_BLOCK: {
        uint32_t iface_id, caplen;
        memcpy(&iface_id, data +  0, 4);
        memcpy(&caplen,   data + 12, 4);

        uint32_t pad = (4 - (caplen % 4)) % 4;
        size_t   min_body = 20 + caplen + pad + 4;
        if (block_total_length < 8 + min_body) {
            ctx->error = 1;
            break;
        }

        /* Copy body so we can mutate the packet bytes */
        size_t body_len = block_total_length - 8;
        unsigned char *body = (unsigned char *)malloc(body_len);
        if (!body) { ctx->error = 1; break; }
        memcpy(body, data, body_len);

        uint16_t lt = idb_table_get(&ctx->idbs, iface_id);
        anon_epb_packet(body + 20, caplen, lt, ctx->opts);

        uint32_t hdr[2] = { block_type, block_total_length };
        if (fwrite(hdr,  1, 8,        ctx->out) != 8 ||
            fwrite(body, 1, body_len, ctx->out) != body_len)
            ctx->error = 1;
        else
            ctx->processed++;

        free(body);
        break;
    }

    default:
        if (block_copy(ctx->out, block_type, block_total_length, data) < 0)
            ctx->error = 1;
        break;
    }

    return 0;
}

int pcapng_anonymize(const char *input, const char *output,
                     const pcapng_anon_opts_t *opts, char *errbuf)
{
    static const pcapng_anon_opts_t default_opts = { 0, 0 };
    if (!opts) opts = &default_opts;

    FILE *in = fopen(input, "rb");
    if (!in) {
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                             "cannot open %s: %s", input, strerror(errno));
        return -1;
    }
    FILE *out = fopen(output, "wb");
    if (!out) {
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                             "cannot open %s: %s", output, strerror(errno));
        fclose(in); return -1;
    }

    anon_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.out  = out;
    ctx.opts = opts;
    idb_table_init(&ctx.idbs);

    surgery_fp_read(in, anon_cb, &ctx);

    fclose(in);
    fclose(out);
    return ctx.error ? -1 : ctx.processed;
}

/* ════==═══════════════════════════════════════════════════════════════════════
 * 5.  pcapng_inject_packet
 *
 * Strategy: two-pass via a temp file.
 *   Pass 1: copy all blocks to temp; record file offset of first EPB whose
 *           timestamp > ts_us (or EOF if none).
 *   Pass 2: copy temp[0..insert_offset) → output, write injected EPB,
 *           copy temp[insert_offset..EOF) → output.
 *
 * This works correctly for any file size because it is purely sequential I/O.
 * ═══==═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    FILE    *tmp;
    uint64_t ts_us;
    long     insert_at;
    int      found;     /* insert point already determined */
    int      error;
} inject_pass1_ctx_t;

static int inject_pass1_cb(uint32_t block_counter, uint32_t block_type,
                            uint32_t block_total_length, unsigned char *data,
                            void *userdata)
{
    (void)block_counter;
    inject_pass1_ctx_t *ctx = (inject_pass1_ctx_t *)userdata;
    if (ctx->error) return 0;

    /* Record the offset before we write this block */
    long off_before = ftell(ctx->tmp);

    if (block_type == PCAPNG_ENHANCED_PACKET_BLOCK && !ctx->found) {
        uint32_t ts_hi, ts_lo;
        memcpy(&ts_hi, data + 4, 4);
        memcpy(&ts_lo, data + 8, 4);
        uint64_t ts = ((uint64_t)ts_hi << 32) | ts_lo;
        /* pcapng default timestamp resolution is microseconds */
        if (ts > ctx->ts_us) {
            ctx->insert_at = off_before;
            ctx->found     = 1;
        }
    }

    /* Copy block to temp */
    uint32_t hdr[2] = { block_type, block_total_length };
    size_t   body   = block_total_length - 8;
    if (fwrite(hdr,  1, 8,    ctx->tmp) != 8 ||
        fwrite(data, 1, body, ctx->tmp) != body)
        ctx->error = 1;

    return 0;
}

int pcapng_inject_packet(const char *input, const char *output,
                         const uint8_t *pkt, uint32_t pkt_len,
                         uint64_t ts_us, uint32_t interface_id,
                         char *errbuf)
{
    /* Open input */
    FILE *in = fopen(input, "rb");
    if (!in) {
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                             "cannot open %s: %s", input, strerror(errno));
        return -1;
    }

    /* Open temp file */
    FILE *tmp = tmpfile();
    if (!tmp) {
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                             "tmpfile: %s", strerror(errno));
        fclose(in);
        return -1;
    }

    /* Pass 1: stream input → tmp, find insert point */
    inject_pass1_ctx_t p1;
    memset(&p1, 0, sizeof(p1));
    p1.tmp       = tmp;
    p1.ts_us     = ts_us;
    p1.insert_at = -1; /* -1 means append at end */

    surgery_fp_read(in, inject_pass1_cb, &p1);
    fclose(in);

    if (p1.error) {
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                             "I/O error reading input");
        fclose(tmp);
        return -1;
    }

    long tmp_end = ftell(tmp);
    long insert_at = (p1.insert_at < 0) ? tmp_end : p1.insert_at;

    /* Build the injected EPB in memory */
    uint32_t ts_hi = (uint32_t)(ts_us >> 32);
    uint32_t ts_lo = (uint32_t)(ts_us & 0xffffffffu);

    size_t   epb_sz  = libpcapng_enhanced_packet_block_size(pkt_len);
    unsigned char *epb_buf = (unsigned char *)malloc(epb_sz);
    if (!epb_buf) {
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE, "out of memory");
        fclose(tmp);
        return -1;
    }
    libpcapng_enhanced_packet_block_write_full(
        pkt, pkt_len, pkt_len, interface_id, ts_hi, ts_lo, NULL, 0, epb_buf);

    /* Pass 2: write output = tmp[0..insert_at) + injected EPB + tmp[insert_at..end) */
    FILE *out = fopen(output, "wb");
    if (!out) {
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                             "cannot open %s: %s", output, strerror(errno));
        free(epb_buf);
        fclose(tmp);
        return -1;
    }

    rewind(tmp);

    /* Copy prefix */
    unsigned char copy_buf[8192];
    long remaining = insert_at;
    while (remaining > 0) {
        size_t chunk = (remaining > (long)sizeof(copy_buf))
                       ? sizeof(copy_buf) : (size_t)remaining;
        if (fread(copy_buf, 1, chunk, tmp) != chunk ||
            fwrite(copy_buf, 1, chunk, out) != chunk) {
            free(epb_buf);
            fclose(tmp); fclose(out);
            if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                                 "I/O error writing prefix");
            return -1;
        }
        remaining -= (long)chunk;
    }

    /* Write injected EPB */
    if (fwrite(epb_buf, 1, epb_sz, out) != epb_sz) {
        free(epb_buf); fclose(tmp); fclose(out);
        if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                             "I/O error writing injected block");
        return -1;
    }
    free(epb_buf);

    /* Copy suffix */
    remaining = tmp_end - insert_at;
    while (remaining > 0) {
        size_t chunk = (remaining > (long)sizeof(copy_buf))
                       ? sizeof(copy_buf) : (size_t)remaining;
        if (fread(copy_buf, 1, chunk, tmp) != chunk ||
            fwrite(copy_buf, 1, chunk, out) != chunk) {
            fclose(tmp); fclose(out);
            if (errbuf) snprintf(errbuf, PCAPNG_SURGERY_ERRBUF_SIZE,
                                 "I/O error writing suffix");
            return -1;
        }
        remaining -= (long)chunk;
    }

    fclose(tmp);
    fclose(out);
    return 0;
}
