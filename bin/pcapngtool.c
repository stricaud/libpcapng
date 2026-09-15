/*
 * pcapngtool — pcapng file manipulation utility.
 *
 * Subcommands:
 *   info        Print metadata and statistics about a pcapng file
 *   filter      Copy packets matching a display filter expression
 *   merge       Concatenate multiple pcapng files
 *   split       Split a pcapng file by packet count or file size
 *   anonymize   Anonymize IP/MAC addresses
 *   inject      Inject a raw packet into a pcapng file
 *   decrypt     Embed a TLS keylog file as a DSB block
 *   strip-dsb   Remove all Decryption Secrets Blocks
 *
 * License MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>

#include <libpcapng/libpcapng.h>
#include <libpcapng/io.h>
#include <libpcapng/blocks.h>
#include <libpcapng/easyapi.h>
#include <libpcapng/surgery.h>
#include <libpcapng/tls_keylog.h>
#include <libpcapng/capture.h>
#include "pipeline.h"
#include <libpcapng/capture.h>
#include <libpcapng/dissect.h>

#define ERRBUF_SIZE 256

/* ── colour output ────────────────────────────────────────────────────────── */
#define BOLD  "\033[1m"
#define DIM   "\033[2m"
#define CYN   "\033[36m"
#define GRN   "\033[32m"
#define RED   "\033[31m"
#define YEL   "\033[33m"
#define RST   "\033[0m"

static int g_color = 1;
#define C(x) (g_color ? (x) : "")

/* ── helpers ─────────────────────────────────────────────────────────────── */

static void die(const char *msg)
{
    fprintf(stderr, "%sError:%s %s\n", C(RED), C(RST), msg);
    exit(1);
}

static void diefmt(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    fprintf(stderr, "%sError:%s ", C(RED), C(RST));
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

/* ── pcapng "info" data gathered by streaming ────────────────────────────── */
typedef struct {
    uint64_t pkt_count;
    uint64_t byte_count;         /* sum of original_len */
    uint64_t captured_bytes;     /* sum of captured_len */
    int      idb_count;
    uint16_t linktypes[64];
    uint32_t snaplens[64];
    uint64_t first_ts_us;        /* microseconds */
    uint64_t last_ts_us;
    int      has_ts;
    int      dsb_count;          /* decryption secrets blocks */
} info_ctx_t;

static int info_block_cb(uint32_t blk_ctr, uint32_t btype, uint32_t btl,
                          unsigned char *data, void *ud)
{
    info_ctx_t *ctx = (info_ctx_t *)ud;
    (void)blk_ctr;

    if (btype == PCAPNG_INTERFACE_DESCRIPTION_BLOCK && ctx->idb_count < 64) {
        int i = ctx->idb_count;
        ctx->linktypes[i] = (uint16_t)(data[0] | (data[1] << 8));
        ctx->snaplens[i]  = (uint32_t)(data[4] | (data[5]<<8) | (data[6]<<16) | (data[7]<<24));
        ctx->idb_count++;
    } else if (btype == PCAPNG_ENHANCED_PACKET_BLOCK) {
        uint32_t ts_hi = (uint32_t)(data[4]|(data[5]<<8)|(data[6]<<16)|(data[7]<<24));
        uint32_t ts_lo = (uint32_t)(data[8]|(data[9]<<8)|(data[10]<<16)|(data[11]<<24));
        uint32_t caplen = (uint32_t)(data[12]|(data[13]<<8)|(data[14]<<16)|(data[15]<<24));
        uint32_t origlen = (uint32_t)(data[16]|(data[17]<<8)|(data[18]<<16)|(data[19]<<24));
        uint64_t ts_us = ((uint64_t)ts_hi << 32 | ts_lo);  /* assuming 1us resolution */
        ctx->captured_bytes += caplen;
        ctx->byte_count += origlen;
        ctx->pkt_count++;
        if (!ctx->has_ts) { ctx->first_ts_us = ts_us; ctx->has_ts = 1; }
        if (ts_us > ctx->last_ts_us) ctx->last_ts_us = ts_us;
    } else if (btype == PCAPNG_DECRYPTION_SECRETS_BLOCK) {
        ctx->dsb_count++;
    }
    (void)btl;
    return 0;
}

static const char *linktype_name(uint16_t lt)
{
    switch (lt) {
    case 1:   return "Ethernet";
    case 12:  return "Raw IP";
    case 101: return "Raw IPv4";
    case 113: return "Linux SLL";
    case 227: return "SocketCAN";
    case 228: return "Raw IPv6";
    case 252: return "USB";
    default:  return "Unknown";
    }
}

static void human_size(uint64_t bytes, char *out, size_t outsz)
{
    if (bytes >= 1024*1024*1024)
        snprintf(out, outsz, "%.2f GiB", bytes / (double)(1024*1024*1024));
    else if (bytes >= 1024*1024)
        snprintf(out, outsz, "%.2f MiB", bytes / (double)(1024*1024));
    else if (bytes >= 1024)
        snprintf(out, outsz, "%.2f KiB", bytes / (double)1024);
    else
        snprintf(out, outsz, "%llu B", (unsigned long long)bytes);
}

/* ── subcommand: info ────────────────────────────────────────────────────── */
static int cmd_info(int argc, char **argv)
{
    if (argc < 1) { fputs("Usage: pcapngtool info FILE...\n", stderr); return 1; }

    for (int a = 0; a < argc; a++) {
        const char *path = argv[a];
        FILE *fp = fopen(path, "rb");
        if (!fp) { fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno)); continue; }

        info_ctx_t ctx; memset(&ctx, 0, sizeof ctx);
        libpcapng_fp_read(fp, info_block_cb, &ctx);
        fclose(fp);

        char cap_sz[32], orig_sz[32];
        human_size(ctx.captured_bytes, cap_sz, sizeof cap_sz);
        human_size(ctx.byte_count, orig_sz, sizeof orig_sz);

        printf("%s%s%s\n", C(BOLD), path, C(RST));
        printf("  Packets    : %s%llu%s\n", C(CYN), (unsigned long long)ctx.pkt_count, C(RST));
        printf("  Captured   : %s\n", cap_sz);
        printf("  On-wire    : %s\n", orig_sz);
        printf("  Interfaces : %d\n", ctx.idb_count);
        for (int i = 0; i < ctx.idb_count; i++) {
            printf("    [%d] %-14s  snaplen=%u\n", i,
                   linktype_name(ctx.linktypes[i]), ctx.snaplens[i]);
        }
        if (ctx.dsb_count)
            printf("  DSB blocks : %d (embedded TLS secrets)\n", ctx.dsb_count);
        if (ctx.has_ts) {
            uint64_t dur_us = ctx.last_ts_us - ctx.first_ts_us;
            printf("  Duration   : %.6f s\n", dur_us / 1e6);
        }
        if (a + 1 < argc) putchar('\n');
    }
    return 0;
}

/* ── subcommand: filter ──────────────────────────────────────────────────── */

/* Shared by every worker. It holds nothing a worker writes: the expression is
   const, and each verdict goes back into the block's own batch entry. */
typedef struct {
    const char *expr;
    FILE       *out;
    long        kept;
    int         failed;
    char        err[ERRBUF_SIZE];
} filter_job_t;

/* Worker thread. Matching a filter that names a decoder field dissects the
   packet, which is the expensive part and the reason to spread this out at all
   — a filter of plain header fields is ~300 ns a packet and gains nothing. */
static int filter_work(const pipeline_block_t *b, int worker, void *vctx)
{
    filter_job_t *job = (filter_job_t *)vctx;
    char err[ERRBUF_SIZE] = {0};
    int r;

    (void)worker;
    r = pcapng_capture_filter_match(job->expr, b->pkt, b->caplen, b->linktype, err);
    if (r < 0) {
        /* A bad expression is the same for every packet, so whichever worker
           notices first wins the race to report it and the rest agree. */
        if (!job->failed) {
            snprintf(job->err, sizeof job->err, "%s", err);
            job->failed = 1;
        }
        return 0;
    }
    return r;
}

/* Calling thread, in file order. Non-packet blocks arrive with verdict 1 and
   are copied through, which keeps the section header, the interface
   descriptions and anything else where the input had them. */
static int filter_emit(const pipeline_block_t *b, int verdict, void *vctx)
{
    filter_job_t *job = (filter_job_t *)vctx;
    uint32_t hdr[2];

    if (job->failed) return -1;
    if (!verdict) return 0;

    hdr[0] = b->block_type;
    hdr[1] = b->block_len;
    if (fwrite(hdr, 1, 8, job->out) != 8 ||
        fwrite(b->block, 1, b->block_len - 8, job->out) != b->block_len - 8) {
        snprintf(job->err, sizeof job->err, "write failed: %s", strerror(errno));
        job->failed = 1;
        return -1;
    }
    if (b->block_type == PCAPNG_ENHANCED_PACKET_BLOCK) job->kept++;
    return 0;
}

static int cmd_filter(int argc, char **argv)
{
    const char *expr   = NULL;
    const char *infile = NULL;
    const char *outfile = NULL;
    int jobs = 1;

    for (int i = 0; i < argc; i++) {
        if ((!strcmp(argv[i], "-f") || !strcmp(argv[i], "--filter")) && i+1 < argc)
            { expr = argv[++i]; continue; }
        if ((!strcmp(argv[i], "-j") || !strcmp(argv[i], "--jobs")) && i+1 < argc)
            { jobs = atoi(argv[++i]);
              if (jobs <= 0) jobs = pipeline_default_workers();
              continue; }
        if (!infile)  { infile  = argv[i]; continue; }
        if (!outfile) { outfile = argv[i]; continue; }
    }
    if (!expr || !infile || !outfile) {
        fputs("Usage: pcapngtool filter [-j N] -f EXPR INPUT OUTPUT\n"
              "  -j N   match on N worker threads (0 = one per core).\n"
              "         Packets are pinned to a worker by flow, and output\n"
              "         stays in input order. Worth it only for a filter that\n"
              "         names a decoder field and so has to dissect.\n", stderr);
        return 1;
    }

    char errbuf[ERRBUF_SIZE] = {0};

    if (jobs <= 1) {
        int n = pcapng_filter_file(infile, outfile, expr, errbuf);
        if (n < 0) { fprintf(stderr, "filter: %s\n", errbuf); return 1; }
        fprintf(stderr, "%d packet(s) written to %s\n", n, outfile);
        return 0;
    }

    filter_job_t job;
    memset(&job, 0, sizeof job);
    job.expr = expr;
    job.out  = fopen(outfile, "wb");
    if (!job.out) {
        fprintf(stderr, "filter: cannot open %s: %s\n", outfile, strerror(errno));
        return 1;
    }

    long n = pipeline_run(infile, jobs, filter_work, filter_emit, &job,
                          errbuf, sizeof errbuf);
    fclose(job.out);

    if (n < 0 || job.failed) {
        fprintf(stderr, "filter: %s\n", job.failed ? job.err : errbuf);
        remove(outfile);
        return 1;
    }
    fprintf(stderr, "%ld packet(s) written to %s (%d workers)\n",
            job.kept, outfile, jobs);
    return 0;
}

/* ── subcommand: merge ───────────────────────────────────────────────────── */
static int cmd_merge(int argc, char **argv)
{
    const char *outfile = NULL;
    const char **inputs = NULL;
    int n_inputs = 0;
    int sort_ts  = 0;

    for (int i = 0; i < argc; i++) {
        if ((!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) && i+1 < argc)
            { outfile = argv[++i]; continue; }
        if (!strcmp(argv[i], "--sort") || !strcmp(argv[i], "-s"))
            { sort_ts = 1; continue; }
        /* treat as input file */
        inputs = (const char **)realloc((void *)inputs, (size_t)(n_inputs + 1) * sizeof *inputs);
        inputs[n_inputs++] = argv[i];
    }
    if (!outfile || n_inputs < 1) {
        fputs("Usage: pcapngtool merge -o OUTPUT [--sort] FILE...\n", stderr);
        free((void *)inputs);
        return 1;
    }

    pcapng_merge_opts_t opts; memset(&opts, 0, sizeof opts);
    opts.sort_by_timestamp = sort_ts;

    char errbuf[ERRBUF_SIZE] = {0};
    int n = pcapng_merge(inputs, n_inputs, outfile, &opts, errbuf);
    free((void *)inputs);
    if (n < 0) { fprintf(stderr, "merge: %s\n", errbuf); return 1; }
    fprintf(stderr, "%d packet(s) written to %s\n", n, outfile);
    return 0;
}

/* ── subcommand: split ───────────────────────────────────────────────────── */
static int cmd_split(int argc, char **argv)
{
    const char *pattern = NULL;
    const char *infile  = NULL;
    uint32_t max_pkts   = 0;
    uint64_t max_bytes  = 0;

    for (int i = 0; i < argc; i++) {
        if ((!strcmp(argv[i], "-p") || !strcmp(argv[i], "--packets")) && i+1 < argc)
            { max_pkts = (uint32_t)atoi(argv[++i]); continue; }
        if ((!strcmp(argv[i], "-b") || !strcmp(argv[i], "--bytes")) && i+1 < argc)
            { max_bytes = (uint64_t)strtoull(argv[++i], NULL, 10); continue; }
        if ((!strcmp(argv[i], "-o") || !strcmp(argv[i], "--pattern")) && i+1 < argc)
            { pattern = argv[++i]; continue; }
        if (!infile) { infile = argv[i]; continue; }
    }
    if (!infile || !pattern || (!max_pkts && !max_bytes)) {
        fputs("Usage: pcapngtool split INPUT -o PATTERN [-p N] [-b BYTES]\n"
              "  PATTERN must contain %d or %04d (e.g. out%04d.pcapng)\n"
              "  -p N     split every N packets\n"
              "  -b BYTES split when output exceeds BYTES bytes\n", stderr);
        return 1;
    }

    pcapng_split_opts_t opts; memset(&opts, 0, sizeof opts);
    opts.max_packets = max_pkts;
    opts.max_bytes   = max_bytes;

    char errbuf[ERRBUF_SIZE] = {0};
    int n = pcapng_split(infile, pattern, &opts, errbuf);
    if (n < 0) { fprintf(stderr, "split: %s\n", errbuf); return 1; }
    fprintf(stderr, "%d file(s) written\n", n);
    return 0;
}

/* ── subcommand: anonymize ───────────────────────────────────────────────── */
static int cmd_anonymize(int argc, char **argv)
{
    const char *infile  = NULL;
    const char *outfile = NULL;
    uint64_t seed       = 0x6c69627063617067ULL;  /* "libpcapg" */
    int anon_mac        = 0;

    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--seed") && i+1 < argc)
            { seed = strtoull(argv[++i], NULL, 0); continue; }
        if (!strcmp(argv[i], "--mac") || !strcmp(argv[i], "--anonymize-mac"))
            { anon_mac = 1; continue; }
        if (!infile)  { infile  = argv[i]; continue; }
        if (!outfile) { outfile = argv[i]; continue; }
    }
    if (!infile || !outfile) {
        fputs("Usage: pcapngtool anonymize [--seed N] [--mac] INPUT OUTPUT\n"
              "  --seed N   UINT64 seed for anonymization (default: built-in)\n"
              "  --mac      also anonymize MAC addresses\n", stderr);
        return 1;
    }

    pcapng_anon_opts_t opts; memset(&opts, 0, sizeof opts);
    opts.seed         = seed;
    opts.anonymize_mac = anon_mac;

    char errbuf[ERRBUF_SIZE] = {0};
    int n = pcapng_anonymize(infile, outfile, &opts, errbuf);
    if (n < 0) { fprintf(stderr, "anonymize: %s\n", errbuf); return 1; }
    fprintf(stderr, "%d packet(s) anonymized to %s\n", n, outfile);
    return 0;
}

/* ── subcommand: inject ──────────────────────────────────────────────────── */
static int cmd_inject(int argc, char **argv)
{
    const char *infile  = NULL;
    const char *outfile = NULL;
    const char *hexdata = NULL;
    uint64_t ts_us      = 0;
    uint32_t iface      = 0;

    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--ts") && i+1 < argc)
            { ts_us = strtoull(argv[++i], NULL, 10); continue; }
        if (!strcmp(argv[i], "--iface") && i+1 < argc)
            { iface = (uint32_t)atoi(argv[++i]); continue; }
        if ((!strcmp(argv[i], "-d") || !strcmp(argv[i], "--data")) && i+1 < argc)
            { hexdata = argv[++i]; continue; }
        if (!infile)  { infile  = argv[i]; continue; }
        if (!outfile) { outfile = argv[i]; continue; }
    }
    if (!infile || !outfile || !hexdata) {
        fputs("Usage: pcapngtool inject INPUT OUTPUT -d HEXBYTES [--ts US] [--iface ID]\n"
              "  -d HEXBYTES  packet bytes as hex (e.g. ffffffffffff...)\n"
              "  --ts US      timestamp in microseconds (default: 0)\n"
              "  --iface ID   interface_id in the output file (default: 0)\n", stderr);
        return 1;
    }

    /* decode hex */
    size_t hexlen = strlen(hexdata);
    if (hexlen % 2 != 0) { fputs("inject: hex string must have even length\n", stderr); return 1; }
    uint8_t *pkt = (uint8_t *)malloc(hexlen / 2 + 1);
    if (!pkt) die("out of memory");
    size_t pkt_len = 0;
    for (size_t h = 0; h < hexlen; h += 2) {
        char hi = hexdata[h], lo = hexdata[h+1];
        int v = 0;
        if (hi >= '0' && hi <= '9') v = (hi-'0') << 4;
        else if (hi >= 'a' && hi <= 'f') v = (hi-'a'+10) << 4;
        else if (hi >= 'A' && hi <= 'F') v = (hi-'A'+10) << 4;
        else { fputs("inject: invalid hex\n", stderr); free(pkt); return 1; }
        if (lo >= '0' && lo <= '9') v |= lo-'0';
        else if (lo >= 'a' && lo <= 'f') v |= lo-'a'+10;
        else if (lo >= 'A' && lo <= 'F') v |= lo-'A'+10;
        else { fputs("inject: invalid hex\n", stderr); free(pkt); return 1; }
        pkt[pkt_len++] = (uint8_t)v;
    }

    char errbuf[ERRBUF_SIZE] = {0};
    int rc = pcapng_inject_packet(infile, outfile, pkt, (uint32_t)pkt_len, ts_us, iface, errbuf);
    free(pkt);
    if (rc < 0) { fprintf(stderr, "inject: %s\n", errbuf); return 1; }
    fprintf(stderr, "Packet injected into %s\n", outfile);
    return 0;
}

/* ── subcommand: decrypt (embed TLS keylog as DSB) ───────────────────────── */
typedef struct {
    FILE    *out;
    int      wrote_dsb;
    size_t   keylog_len;
    char    *keylog_data;
} decrypt_embed_ctx_t;

static int decrypt_copy_cb(uint32_t blk_ctr, uint32_t btype, uint32_t btl,
                             unsigned char *data, void *ud)
{
    decrypt_embed_ctx_t *ctx = (decrypt_embed_ctx_t *)ud;
    (void)blk_ctr;

    /* Skip existing DSB blocks — we'll add a fresh one */
    if (btype == PCAPNG_DECRYPTION_SECRETS_BLOCK) return 0;

    /* After the first IDB, write the DSB so Wireshark finds it early */
    if (!ctx->wrote_dsb && btype == PCAPNG_INTERFACE_DESCRIPTION_BLOCK) {
        /* write IDB first */
        uint32_t hdr[2] = {btype, btl};
        fwrite(hdr, 8, 1, ctx->out);
        fwrite(data, btl - 8, 1, ctx->out);

        /* then write DSB with keylog content */
        size_t sec_sz = libpcapng_decryption_secrets_block_size(ctx->keylog_len);
        unsigned char *sec_buf = (unsigned char *)malloc(sec_sz);
        if (sec_buf) {
            libpcapng_decryption_secrets_block_write(
                0x544c534b /* TLSK */,
                (unsigned char *)ctx->keylog_data, ctx->keylog_len, sec_buf);
            fwrite(sec_buf, sec_sz, 1, ctx->out);
            free(sec_buf);
        }
        ctx->wrote_dsb = 1;
        return 0;
    }

    /* copy block verbatim */
    uint32_t hdr[2] = {btype, btl};
    fwrite(hdr, 8, 1, ctx->out);
    fwrite(data, btl - 8, 1, ctx->out);
    return 0;
}

static int cmd_decrypt(int argc, char **argv)
{
    const char *keylog  = NULL;
    const char *infile  = NULL;
    const char *outfile = NULL;

    for (int i = 0; i < argc; i++) {
        if ((!strcmp(argv[i], "-k") || !strcmp(argv[i], "--keylog")) && i+1 < argc)
            { keylog = argv[++i]; continue; }
        if (!infile)  { infile  = argv[i]; continue; }
        if (!outfile) { outfile = argv[i]; continue; }
    }
    if (!infile || !outfile || !keylog) {
        fputs("Usage: pcapngtool decrypt INPUT OUTPUT -k KEYLOG\n"
              "  Embeds a TLS NSS keylog as a DSB block so Wireshark can decrypt inline.\n"
              "  -k KEYLOG  path to the NSS keylog file (SSLKEYLOGFILE format)\n", stderr);
        return 1;
    }

    /* Read keylog file */
    FILE *kf = fopen(keylog, "rb");
    if (!kf) { fprintf(stderr, "Cannot open keylog %s: %s\n", keylog, strerror(errno)); return 1; }
    fseek(kf, 0, SEEK_END); long klen = ftell(kf); fseek(kf, 0, SEEK_SET);
    if (klen <= 0) { fputs("Empty keylog file\n", stderr); fclose(kf); return 1; }
    char *kdata = (char *)malloc((size_t)klen + 1);
    if (!kdata) die("out of memory");
    fread(kdata, 1, (size_t)klen, kf); kdata[klen] = '\0';
    fclose(kf);

    FILE *in  = fopen(infile,  "rb");
    FILE *out = fopen(outfile, "wb");
    if (!in  ) { fprintf(stderr, "Cannot open %s: %s\n", infile,  strerror(errno)); free(kdata); return 1; }
    if (!out ) { fprintf(stderr, "Cannot open %s: %s\n", outfile, strerror(errno)); free(kdata); fclose(in); return 1; }

    decrypt_embed_ctx_t ctx; memset(&ctx, 0, sizeof ctx);
    ctx.out         = out;
    ctx.keylog_data = kdata;
    ctx.keylog_len  = (size_t)klen;

    libpcapng_fp_read(in, decrypt_copy_cb, &ctx);

    /* If no IDB was found (empty/malformed), still write the DSB at end */
    if (!ctx.wrote_dsb) {
        size_t sec_sz = libpcapng_decryption_secrets_block_size(ctx.keylog_len);
        unsigned char *sec_buf = (unsigned char *)malloc(sec_sz);
        if (sec_buf) {
            libpcapng_decryption_secrets_block_write(
                0x544c534b, (unsigned char *)ctx.keylog_data, ctx.keylog_len, sec_buf);
            fwrite(sec_buf, sec_sz, 1, out);
            free(sec_buf);
        }
    }

    fclose(in); fclose(out); free(kdata);
    fprintf(stderr, "Keylog embedded into %s\n", outfile);
    return 0;
}

/* ── subcommand: strip-dsb ───────────────────────────────────────────────── */
typedef struct { FILE *out; int removed; } strip_ctx_t;

static int strip_dsb_cb(uint32_t bc, uint32_t bt, uint32_t btl, unsigned char *d, void *ud)
{
    strip_ctx_t *ctx = (strip_ctx_t *)ud;
    (void)bc;
    if (bt == PCAPNG_DECRYPTION_SECRETS_BLOCK) { ctx->removed++; return 0; }
    uint32_t hdr[2] = {bt, btl};
    fwrite(hdr, 8, 1, ctx->out);
    fwrite(d, btl - 8, 1, ctx->out);
    return 0;
}

static int cmd_strip_dsb(int argc, char **argv)
{
    const char *infile = NULL, *outfile = NULL;
    for (int i = 0; i < argc; i++) {
        if (!infile)  infile  = argv[i];
        else if (!outfile) outfile = argv[i];
    }
    if (!infile || !outfile) {
        fputs("Usage: pcapngtool strip-dsb INPUT OUTPUT\n", stderr); return 1;
    }
    FILE *in  = fopen(infile,  "rb");
    FILE *out = fopen(outfile, "wb");
    if (!in || !out) { perror(in ? outfile : infile); if (in) fclose(in); if (out) fclose(out); return 1; }
    strip_ctx_t ctx = { out, 0 };
    libpcapng_fp_read(in, strip_dsb_cb, &ctx);
    fclose(in); fclose(out);
    fprintf(stderr, "%d DSB block(s) removed, written to %s\n", ctx.removed, outfile);
    return 0;
}

/* ── top-level usage ──────────────────────────────────────────────────────── */
static void usage(const char *prog)
{
    printf("%sUsage:%s %s%s%s SUBCOMMAND [options]\n\n",
           C(BOLD), C(RST), C(BOLD), prog, C(RST));
    printf("%sSubcommands:%s\n", C(BOLD), C(RST));
    printf("  %sinfo%s       FILE...          Print metadata and statistics\n", C(CYN), C(RST));
    printf("  %sfilter%s   [-j N] -f EXPR IN OUT   Copy packets matching a display filter\n", C(CYN), C(RST));
    printf("  %smerge%s     -o OUT FILE...   Concatenate pcapng files\n", C(CYN), C(RST));
    printf("  %ssplit%s     IN -o PAT -p N   Split by packet count or file size\n", C(CYN), C(RST));
    printf("  %sanonymize%s IN OUT           Anonymize IP/MAC addresses\n", C(CYN), C(RST));
    printf("  %sinject%s    IN OUT -d HEX    Inject a raw packet\n", C(CYN), C(RST));
    printf("  %sdecrypt%s   IN OUT -k KEYS   Embed TLS keylog as DSB block\n", C(CYN), C(RST));
    printf("  %sstrip-dsb%s IN OUT           Remove all DSB blocks\n", C(CYN), C(RST));
    printf("\nRun %s%s SUBCOMMAND%s with no arguments for subcommand help.\n",
           C(DIM), prog, C(RST));
}

int main(int argc, char **argv)
{
    /* Disable colour when not a terminal */
    if (!isatty(fileno(stdout)) || !isatty(fileno(stderr))) g_color = 0;

    if (argc < 2) { usage(argv[0]); return 0; }

    const char *cmd = argv[1];
    argc -= 2; argv += 2;

    if (!strcmp(cmd, "info"))       return cmd_info(argc, argv);
    if (!strcmp(cmd, "filter"))     return cmd_filter(argc, argv);
    if (!strcmp(cmd, "merge"))      return cmd_merge(argc, argv);
    if (!strcmp(cmd, "split"))      return cmd_split(argc, argv);
    if (!strcmp(cmd, "anonymize"))  return cmd_anonymize(argc, argv);
    if (!strcmp(cmd, "inject"))     return cmd_inject(argc, argv);
    if (!strcmp(cmd, "decrypt"))    return cmd_decrypt(argc, argv);
    if (!strcmp(cmd, "strip-dsb"))  return cmd_strip_dsb(argc, argv);

    fprintf(stderr, "Unknown subcommand '%s'\n\n", cmd);
    usage(argv[-2]);
    return 1;
}
