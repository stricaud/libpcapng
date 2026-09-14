/*
 * concurrency.c — hold the library to the threading contract in threading.h.
 *
 * Several threads dissect at once and every result is checked, both the field
 * tree and the summary the caller reads back. Before the per-thread storage
 * this file exists to protect, roughly two dissections in five reported the
 * wrong protocol: the summary column was a single global, so a DNS packet
 * would happily label itself Modbus because another thread had just finished
 * one.
 *
 * Wrong answers are what this asserts on. The underlying data races are what
 * actually cause them, and a race can hide on a given run, so CI should also
 * build this under ThreadSanitizer:
 *
 *     cc -fsanitize=thread -I../include concurrency.c -lpcapng -lpthread
 *
 * Build via cmake (registered as the Concurrency ctest target).
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libpcapng/dissect.h>
#include <libpcapng/posa.h>
#include <libpcapng/capture.h>
#include <libpcapng/easyapi.h>
#include <libpcapng/io.h>
#include <libpcapng/blocks.h>
#include <libpcapng/linktypes.h>
#include <libpcapng/flow_hash.h>

#define NTHREADS 8
#define NITERS   1500

static int g_pass, g_fail;

#define CHECK(label, expr) do {                                          \
    if (expr) { g_pass++; printf("  PASS  %s\n", label); }             \
    else      { g_fail++; printf("  FAIL  %s  (%s:%d)\n",              \
                                 label, __FILE__, __LINE__); }          \
} while (0)

/* ── test packets ─────────────────────────────────────────────────────────── */

/* Ethernet/IPv4/TCP, Modbus/TCP read-holding-registers request to port 502. */
static const uint8_t MODBUS[66] = {
    0x00,0x00,0x00,0x00,0x00,0x00, 0x02,0x02,0x02,0x02,0x02,0x02, 0x08,0x00,
    0x45,0x00,0x00,0x34,0x00,0x01,0x00,0x00,0x40,0x06,0x66,0xc1,
    0x0a,0x00,0x00,0x01, 0x0a,0x00,0x00,0x02,
    0x30,0x39,0x01,0xf6,0,0,0,0,0,0,0,0,0x50,0x18,0xff,0xff,0,0,0,0,
    0x00,0x01,0x00,0x00,0x00,0x06,0x01,0x03,0x00,0x00,0x00,0x01,
};

/* Ethernet/IPv4/UDP, a DNS query for www.example.com to port 53. A different
   decoder and a different flow, so a thread pair races over both. */
static const uint8_t DNSQ[75] = {
    0x00,0x00,0x00,0x00,0x00,0x00, 0x02,0x02,0x02,0x02,0x02,0x02, 0x08,0x00,
    0x45,0x00,0x00,0x3d,0x00,0x01,0x00,0x00,0x40,0x11,0x00,0x00,
    0x0a,0x00,0x00,0x01, 0x08,0x08,0x08,0x08,
    0xc0,0x00,0x00,0x35,0x00,0x29,0x00,0x00,
    0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
    0x03,'w','w','w',0x07,'e','x','a','m','p','l','e',0x03,'c','o','m',0x00,
    0x00,0x01,0x00,0x01,
};

/* ── 1. concurrent dissection: tree and summary both ──────────────────────── */

static int g_bad_tree, g_bad_proto;

static void *t_dissect(void *arg)
{
    int dns = (int)(intptr_t)arg & 1;
    const uint8_t *pkt   = dns ? DNSQ : MODBUS;
    uint32_t       len   = dns ? (uint32_t)sizeof DNSQ : (uint32_t)sizeof MODBUS;
    const char    *proto = dns ? "DNS" : "Modbus/TCP";
    const char    *field = dns ? "dns.id" : "ModbusTCP.function_code";
    uint64_t       want  = dns ? 0x1234 : 3;

    for (int i = 0; i < NITERS; i++) {
        pcapng_dissection_t *d = pcapng_dissect(pkt, len, len, 1);
        if (!d) { __atomic_fetch_add(&g_bad_tree, 1, __ATOMIC_RELAXED); continue; }

        pcapng_field_t *hits[2];
        if (pcapng_field_collect(d->root, field, hits, 2) < 1 || hits[0]->u != want)
            __atomic_fetch_add(&g_bad_tree, 1, __ATOMIC_RELAXED);

        /* The summary is the part that used to come from shared globals. */
        if (strcmp(d->proto, proto) != 0)
            __atomic_fetch_add(&g_bad_proto, 1, __ATOMIC_RELAXED);

        pcapng_dissection_free(d);
    }
    return NULL;
}

/* ── 2. many distinct flows, so sticky classification keeps inserting ─────── */

static int g_bad_flow;

static void *t_flows(void *arg)
{
    int id = (int)(intptr_t)arg;
    for (int i = 0; i < NITERS; i++) {
        uint8_t pkt[sizeof MODBUS];
        memcpy(pkt, MODBUS, sizeof pkt);
        /* A new source port every iteration is a new flow every iteration, so
           the per-thread flow table is written rather than settling read-only. */
        uint16_t sport = (uint16_t)(1024 + ((id * NITERS + i) & 0x7fff));
        pkt[34] = (uint8_t)(sport >> 8);
        pkt[35] = (uint8_t)sport;

        pcapng_dissection_t *d = pcapng_dissect(pkt, sizeof pkt, sizeof pkt, 1);
        if (!d || strcmp(d->proto, "Modbus/TCP") != 0)
            __atomic_fetch_add(&g_bad_flow, 1, __ATOMIC_RELAXED);
        if (d) pcapng_dissection_free(d);
    }
    return NULL;
}

/* ── 3. capture filters, both kinds of field ──────────────────────────────── */

static int g_bad_filter;
static const char *g_expr;

static void *t_filter(void *arg)
{
    (void)arg;
    for (int i = 0; i < NITERS; i++)
        if (pcapng_capture_filter_match(g_expr, MODBUS, sizeof MODBUS, 1, NULL) != 1)
            __atomic_fetch_add(&g_bad_filter, 1, __ATOMIC_RELAXED);
    return NULL;
}

/* ── 4. a pcapng file per thread ──────────────────────────────────────────── */

static int g_bad_io;

static int count_epb(uint32_t c, uint32_t type, uint32_t len, unsigned char *d, void *ud)
{ (void)c; (void)len; (void)d; if (type == PCAPNG_ENHANCED_PACKET_BLOCK) (*(int *)ud)++; return 0; }

static void *t_io(void *arg)
{
    int id = (int)(intptr_t)arg;
    char path[256];
    snprintf(path, sizeof path, "/tmp/pcapng_mt_%d.pcapng", id);

    /* The writer takes a non-const buffer, so hand it a copy of our own. */
    uint8_t frame[sizeof MODBUS];
    memcpy(frame, MODBUS, sizeof frame);

    FILE *f = fopen(path, "wb");
    if (!f) { __atomic_fetch_add(&g_bad_io, 1, __ATOMIC_RELAXED); return NULL; }
    libpcapng_write_header_to_file_with_linktype(f, LINKTYPE_ETHERNET);
    for (int i = 0; i < 200; i++)
        libpcapng_write_enhanced_packet_to_file(f, frame, sizeof frame);
    fclose(f);

    int n = 0;
    libpcapng_file_read(path, count_epb, &n);
    if (n != 200) __atomic_fetch_add(&g_bad_io, 1, __ATOMIC_RELAXED);
    remove(path);
    return NULL;
}

/* ── 5. the lazy registry load, entered by every thread at once ───────────── */

/* This one has to run before anything else in the process dissects, because the
   thing it exercises happens once per process: pcapng_dissect() builds the
   decoder registry on first use, and threads arriving together used to each
   decide it was unloaded and build it on top of each other. A half-built
   registry does not merely mislabel — it mis-decodes, so the field value is
   what this checks. */
static int g_bad_cold;

static void *t_cold(void *arg)
{
    (void)arg;
    for (int i = 0; i < 200; i++) {
        pcapng_dissection_t *d = pcapng_dissect(MODBUS, sizeof MODBUS, sizeof MODBUS, 1);
        if (!d) { __atomic_fetch_add(&g_bad_cold, 1, __ATOMIC_RELAXED); continue; }
        pcapng_field_t *hits[2];
        if (pcapng_field_collect(d->root, "ModbusTCP.function_code", hits, 2) < 1
            || hits[0]->u != 3)
            __atomic_fetch_add(&g_bad_cold, 1, __ATOMIC_RELAXED);
        pcapng_dissection_free(d);
    }
    return NULL;
}

/* ── 6. a decoder that remembers across a flow's packets ──────────────────── */

/* `bind` stores a value under the flow's conversation key; `recall` reads it
   back from a later packet. Both sides are per-flow state reached through
   globals, so two threads dissecting different flows at once used to overwrite
   each other's conversation key and recall the wrong flow's value. */
static const char *BINDER_POSA =
    "Object<main> Binder\n"
    "    abbrev \"binder\"\n"
    "    uint8 kind defaults(1)\n"
    "    uint8 slot defaults(0)\n"
    "    uint16 value defaults(0)\n"
    "    when kind == 1:\n"
    "        bind seen[slot] = value\n"
    "    when kind == 2:\n"
    "        recall seen[slot] as remembered \"Remembered\"\n";

static int g_bad_bind;

static void *t_bind(void *arg)
{
    int id = (int)(intptr_t)arg;
    /* Each thread owns a conversation and a value, the way flow-pinned
       dispatch would give it whole flows. */
    char conv[32];
    snprintf(conv, sizeof conv, "1:thread-%d", id);
    uint16_t mine = (uint16_t)(0x1000 + id);

    for (int i = 0; i < NITERS; i++) {
        uint8_t store[4] = { 1, 0, (uint8_t)(mine >> 8), (uint8_t)(mine & 0xff) };
        uint8_t load[4]  = { 2, 0, 0, 0 };
        pcapng_field_t *root;
        char info[192];

        pcapng_posa_set_conversation(conv);
        root = calloc(1, sizeof *root);
        pcapng_posa_dissect("Binder", store, sizeof store, root, 0, info, sizeof info);
        pcapng_field_free(root);

        pcapng_posa_set_conversation(conv);
        root = calloc(1, sizeof *root);
        info[0] = '\0';
        pcapng_posa_dissect("Binder", load, sizeof load, root, 0, info, sizeof info);

        /* A recalled field carries the bound field's display text, so compare
           the string rather than the number. */
        char expect[16];
        snprintf(expect, sizeof expect, "%u", (unsigned)mine);

        pcapng_field_t *hits[2];
        int n = pcapng_field_collect(root, "binder.remembered", hits, 2);
        if (n < 1 || strcmp(hits[0]->str, expect) != 0)
            __atomic_fetch_add(&g_bad_bind, 1, __ATOMIC_RELAXED);
        pcapng_field_free(root);
    }
    return NULL;
}

/* ── 7. the flow hash a dispatcher would shard on ─────────────────────────── */

static int g_bad_hash;

static void *t_hash(void *arg)
{
    (void)arg;
    uint8_t a[4] = {10,0,0,1}, b[4] = {10,0,0,2};
    uint64_t want = pcapng_flow_hash_tuple(6, a, b, 4, 12345, 502, PCAPNG_FLOW_TUPLE);
    for (int i = 0; i < NITERS; i++) {
        if (pcapng_flow_hash(MODBUS, sizeof MODBUS, 1, PCAPNG_FLOW_TUPLE) != want)
            __atomic_fetch_add(&g_bad_hash, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

/* ── harness ──────────────────────────────────────────────────────────────── */

static void spawn(void *(*fn)(void *))
{
    pthread_t th[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) pthread_create(&th[i], NULL, fn, (void *)(intptr_t)i);
    for (int i = 0; i < NTHREADS; i++) pthread_join(th[i], NULL);
}

int main(void)
{
    printf("=== concurrency ===\n%d threads, %d iterations each\n", NTHREADS, NITERS);

    /* First, deliberately, and before anything else here touches the library:
       let every thread race into the lazy registry load at once. Calling
       pcapng_dissect_ensure_protocols() up front is the documented way to avoid
       the wait, and every suite after this one benefits from it — but the guard
       has to hold for callers who do not. */
    printf("\n[cold start — threads race into the first dissection]\n");
    spawn(t_cold);
    CHECK("the registry survives being loaded under contention", g_bad_cold == 0);

    /* From here on the registry is loaded, which is the state a well-behaved
       caller arranges before starting threads. */
    pcapng_dissect_ensure_protocols();

    printf("\n[concurrent dissection]\n");
    spawn(t_dissect);
    CHECK("field tree correct in every thread", g_bad_tree == 0);
    CHECK("summary protocol correct in every thread", g_bad_proto == 0);

    printf("\n[sticky flow classification, many flows]\n");
    spawn(t_flows);
    CHECK("flow table keeps its answers per thread", g_bad_flow == 0);

    printf("\n[capture filter — built-in header field]\n");
    g_expr = "tcp.dstport == 502";
    spawn(t_filter);
    CHECK("header-field filter matches in every thread", g_bad_filter == 0);

    printf("\n[capture filter — decoder field, dissects per packet]\n");
    g_bad_filter = 0;
    g_expr = "ModbusTCP.function_code == 3";
    spawn(t_filter);
    CHECK("decoder-field filter matches in every thread", g_bad_filter == 0);

    printf("\n[pcapng file I/O, one file per thread]\n");
    spawn(t_io);
    CHECK("every thread wrote and read back its own file", g_bad_io == 0);

    printf("\n[decoder `bind`/`recall`, one conversation per thread]\n");
    {
        char err[256] = "";
        if (pcapng_posa_load_text(BINDER_POSA, err, sizeof err) < 0) {
            printf("  SKIP  cannot load the Binder decoder: %s\n", err);
        } else {
            spawn(t_bind);
            CHECK("each thread recalls its own conversation's value", g_bad_bind == 0);
        }
    }

    printf("\n[flow hash — what a dispatcher shards on]\n");
    spawn(t_hash);
    CHECK("the same packet hashes the same in every thread", g_bad_hash == 0);

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
