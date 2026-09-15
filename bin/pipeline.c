/*
 * pipeline.c — see pipeline.h.
 *
 * License MIT
 */
#include "pipeline.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libpcapng/blocks.h>
#include <libpcapng/dissect.h>
#include <libpcapng/flow_hash.h>
#include <libpcapng/io.h>

#ifndef _WIN32
#  include <pthread.h>
#  include <unistd.h>
#  define PIPELINE_THREADS 1
#else
#  define PIPELINE_THREADS 0
#endif

/* A batch is bounded by both count and bytes: a capture of jumbo frames would
   otherwise hold far more memory than one of ACKs at the same block count. */
#define BATCH_BLOCKS  8192
#define BATCH_BYTES   (16u * 1024u * 1024u)

/* ── interface id → link type ─────────────────────────────────────────────── */

#define MAX_INTERFACES 256

typedef struct {
    uint16_t linktypes[MAX_INTERFACES];
    int      count;
} idb_table_t;

static void idb_add(idb_table_t *t, const unsigned char *data)
{
    uint16_t lt;
    if (t->count >= MAX_INTERFACES) return;
    memcpy(&lt, data, 2);
    t->linktypes[t->count++] = lt;
}

static uint16_t idb_get(const idb_table_t *t, uint32_t id)
{
    return ((int)id < t->count) ? t->linktypes[id] : 1;   /* default Ethernet */
}

/* ── batch ────────────────────────────────────────────────────────────────── */

typedef struct {
    pipeline_block_t b;
    int              worker;    /* -1 = not work for anyone */
    int              verdict;
} entry_t;

typedef struct {
    entry_t  *e;
    int       n;
    uint8_t  *bytes;            /* block bodies, copied: the reader reuses its own buffer */
    size_t    used, cap;
} batch_t;

typedef struct {
    batch_t          batch;
    idb_table_t      idbs;
    uint64_t         seq;
    int              nworkers;
    pipeline_work_fn work;
    pipeline_emit_fn emit;
    void            *ctx;
    long             emitted;
    void            *pool;      /* pool_t * while threads are running */
    int              stop;      /* emit asked to stop, or we ran out of memory */
    char            *errbuf;
    size_t           errlen;
} run_t;

static void fail(run_t *r, const char *msg)
{
    if (r->errbuf && r->errlen && !r->stop)
        snprintf(r->errbuf, r->errlen, "%s", msg);
    r->stop = 1;
}

/* Copy a block body into the batch's arena and hand back where it landed.
   Returns NULL when the arena cannot grow, which stops the run. */
static const uint8_t *batch_store(batch_t *t, const unsigned char *data, size_t len)
{
    if (t->used + len > t->cap) {
        size_t want = t->cap ? t->cap * 2 : (1u << 20);
        uint8_t *p;
        while (want < t->used + len) want *= 2;
        p = (uint8_t *)realloc(t->bytes, want);
        if (!p) return NULL;
        t->bytes = p;
        t->cap = want;
    }
    memcpy(t->bytes + t->used, data, len);
    t->used += len;
    return t->bytes + (t->used - len);
}

/* The arena moves when it grows, so block pointers are fixed up only once the
   batch is closed and nothing more will be appended. */
static void batch_rebase(batch_t *t)
{
    size_t off = 0;
    int i;
    for (i = 0; i < t->n; i++) {
        t->e[i].b.block = t->bytes + off;
        if (t->e[i].b.pkt) t->e[i].b.pkt = t->bytes + off + 20;
        off += t->e[i].b.block_len - 8;
    }
}

/* ── workers ──────────────────────────────────────────────────────────────── */

static void worker_body(run_t *r, int id)
{
    int i;
    for (i = 0; i < r->batch.n; i++)
        if (r->batch.e[i].worker == id)
            r->batch.e[i].verdict = r->work(&r->batch.e[i].b, id, r->ctx);
}

/*
 * Workers live for the whole run, not for a batch.
 *
 * That is a correctness requirement before it is a performance one. Everything
 * the library remembers about a flow between packets — the sticky protocol
 * classification, a decoder's `bind`/`recall` memory, a TLS session's derived
 * keys — lives in thread-local storage. End a thread and all of it goes with
 * it, so threads spawned per batch would hand every flow a fresh, empty memory
 * each time a batch turned over. That is exactly the state pinning flows to
 * threads exists to preserve.
 *
 * Worker 0 is the calling thread, so N workers means N-1 spawned: the reader
 * has nothing to do while a batch is in flight and may as well take a share.
 */
#if PIPELINE_THREADS

typedef struct pool pool_t;

typedef struct {
    pool_t *pool;
    int     id;
} slot_t;

struct pool {
    pthread_mutex_t mu;
    pthread_cond_t  go;          /* a batch is ready to work on */
    pthread_cond_t  done;        /* a worker finished its share */
    run_t          *r;
    unsigned        generation;  /* bumped once per batch */
    int             finished;    /* workers done with the current generation */
    int             quit;
    int             nspawned;
    pthread_t       th[32];
    slot_t          slot[32];
};

static void *worker_main(void *arg)
{
    slot_t   *s = (slot_t *)arg;
    pool_t   *p = s->pool;
    unsigned  seen = 0;

    for (;;) {
        pthread_mutex_lock(&p->mu);
        while (!p->quit && p->generation == seen)
            pthread_cond_wait(&p->go, &p->mu);
        if (p->quit) { pthread_mutex_unlock(&p->mu); return NULL; }
        seen = p->generation;
        pthread_mutex_unlock(&p->mu);

        worker_body(p->r, s->id);

        pthread_mutex_lock(&p->mu);
        p->finished++;
        pthread_cond_signal(&p->done);
        pthread_mutex_unlock(&p->mu);
    }
}

static int pool_start(pool_t *p, run_t *r)
{
    int i, want = r->nworkers - 1;          /* worker 0 is the calling thread */

    memset(p, 0, sizeof *p);
    p->r = r;
    if (want > 31) want = 31;
    if (pthread_mutex_init(&p->mu, NULL) != 0) return -1;
    if (pthread_cond_init(&p->go, NULL) != 0)   { pthread_mutex_destroy(&p->mu); return -1; }
    if (pthread_cond_init(&p->done, NULL) != 0) { pthread_cond_destroy(&p->go);
                                                  pthread_mutex_destroy(&p->mu); return -1; }
    for (i = 0; i < want; i++) {
        p->slot[i].pool = p;
        p->slot[i].id   = i + 1;
        if (pthread_create(&p->th[i], NULL, worker_main, &p->slot[i]) != 0) break;
        p->nspawned++;
    }
    /* Fewer threads than asked for is not a failure: whatever did not start has
       its share done inline, so the run is slower and still correct. */
    return 0;
}

static void pool_stop(pool_t *p)
{
    int i;
    pthread_mutex_lock(&p->mu);
    p->quit = 1;
    pthread_cond_broadcast(&p->go);
    pthread_mutex_unlock(&p->mu);
    for (i = 0; i < p->nspawned; i++) pthread_join(p->th[i], NULL);
    pthread_cond_destroy(&p->done);
    pthread_cond_destroy(&p->go);
    pthread_mutex_destroy(&p->mu);
}

static void pool_run_batch(pool_t *p, run_t *r)
{
    int i;

    pthread_mutex_lock(&p->mu);
    p->finished = 0;
    p->generation++;
    pthread_cond_broadcast(&p->go);
    pthread_mutex_unlock(&p->mu);

    worker_body(r, 0);                                  /* the calling thread's share */
    for (i = p->nspawned + 1; i < r->nworkers; i++)
        worker_body(r, i);                              /* shares of threads that never started */

    pthread_mutex_lock(&p->mu);
    while (p->finished < p->nspawned)
        pthread_cond_wait(&p->done, &p->mu);
    pthread_mutex_unlock(&p->mu);
}

#endif /* PIPELINE_THREADS */

static void batch_process(run_t *r)
{
    if (r->batch.n == 0) return;
    batch_rebase(&r->batch);

#if PIPELINE_THREADS
    if (r->pool) { pool_run_batch((pool_t *)r->pool, r); return; }
#endif
    { int i; for (i = 0; i < r->nworkers; i++) worker_body(r, i); }
}

static void batch_flush(run_t *r)
{
    int i;
    batch_process(r);
    for (i = 0; i < r->batch.n && !r->stop; i++) {
        if (r->emit(&r->batch.e[i].b, r->batch.e[i].verdict, r->ctx) < 0) {
            r->stop = 1;
            break;
        }
        r->emitted++;
    }
    r->batch.n = 0;
    r->batch.used = 0;
}

/* ── reader ───────────────────────────────────────────────────────────────── */

static int read_cb(uint32_t counter, uint32_t type, uint32_t total_len,
                   unsigned char *data, void *ud)
{
    run_t *r = (run_t *)ud;
    entry_t *e;
    size_t body;
    const uint8_t *stored;

    (void)counter;
    if (r->stop) return 0;
    if (total_len < 12) return 0;                  /* not a block we can echo */
    body = total_len - 8;

    /* The link type has to be learnt before the packets that cite it, so the
       IDB is read here rather than on a worker. */
    if (type == PCAPNG_INTERFACE_DESCRIPTION_BLOCK) idb_add(&r->idbs, data);

    if (r->batch.n >= BATCH_BLOCKS || r->batch.used + body > BATCH_BYTES)
        batch_flush(r);
    if (r->stop) return 0;

    stored = batch_store(&r->batch, data, body);
    if (!stored) { fail(r, "out of memory buffering a batch"); return 0; }

    e = &r->batch.e[r->batch.n++];
    memset(e, 0, sizeof *e);
    e->b.seq        = r->seq++;
    e->b.block_type = type;
    e->b.block_len  = total_len;
    e->b.block      = stored;                       /* rebased before use */
    e->worker       = -1;
    e->verdict      = 1;                            /* pass anything work never sees */

    if (type == PCAPNG_ENHANCED_PACKET_BLOCK && body >= 20) {
        uint32_t iface, caplen;
        memcpy(&iface,  data +  0, 4);
        memcpy(&caplen, data + 12, 4);
        if ((size_t)caplen + 20 <= body) {
            uint32_t hi, lo;
            uint64_t h;
            memcpy(&hi, data + 4, 4);
            memcpy(&lo, data + 8, 4);
            e->b.ts = ((uint64_t)hi << 32) | lo;
            e->b.pkt      = stored + 20;
            e->b.caplen   = caplen;
            e->b.linktype = idb_get(&r->idbs, iface);

            /* Flow-pinned, the whole point: both directions of a connection
               hash the same, so one worker sees the whole conversation and the
               library's per-thread state stays coherent. A block with no flow
               to speak of — ARP, a runt — spreads on its sequence number
               instead, which cannot upset anything because it has no flow
               state to keep. */
            h = pcapng_flow_hash(e->b.pkt, caplen, e->b.linktype, PCAPNG_FLOW_TUPLE);
            e->worker = (int)((h ? h : e->b.seq) % (uint64_t)r->nworkers);
        }
    }
    return 0;
}

/* ── entry points ─────────────────────────────────────────────────────────── */

int pipeline_default_workers(void)
{
#if PIPELINE_THREADS && defined(_SC_NPROCESSORS_ONLN)
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n > 1) return (int)(n > 32 ? 32 : n);
#endif
    return 1;
}

long pipeline_run(const char *path, int nworkers,
                  pipeline_work_fn work, pipeline_emit_fn emit, void *ctx,
                  char *errbuf, size_t errlen)
{
    run_t r;
    FILE *fp;
    long out;

    if (!path || !work || !emit) {
        if (errbuf && errlen) snprintf(errbuf, errlen, "pipeline_run: missing argument");
        return -1;
    }
    if (nworkers < 1) nworkers = 1;
#if !PIPELINE_THREADS
    nworkers = 1;
#endif

    memset(&r, 0, sizeof r);
    r.nworkers = nworkers;
    r.work = work; r.emit = emit; r.ctx = ctx;
    r.errbuf = errbuf; r.errlen = errlen;

    r.batch.e = (entry_t *)calloc(BATCH_BLOCKS, sizeof *r.batch.e);
    if (!r.batch.e) {
        if (errbuf && errlen) snprintf(errbuf, errlen, "out of memory");
        return -1;
    }

    /* The registry must be built before any worker dissects: the lazy load
       inside pcapng_dissect() is guarded, but threads racing into it wait ~85 ms
       apiece for nothing. See libpcapng/threading.h. */
    pcapng_dissect_ensure_protocols();

    fp = fopen(path, "rb");
    if (!fp) {
        if (errbuf && errlen)
            snprintf(errbuf, errlen, "cannot open %s: %s", path, strerror(errno));
        free(r.batch.e);
        return -1;
    }
#if PIPELINE_THREADS
    pool_t pool;
    if (nworkers > 1 && pool_start(&pool, &r) == 0) r.pool = &pool;
#endif

    libpcapng_fp_read(fp, read_cb, &r);
    fclose(fp);

    if (!r.stop) batch_flush(&r);

#if PIPELINE_THREADS
    if (r.pool) { pool_stop(&pool); r.pool = NULL; }
#endif

    out = r.stop && r.errbuf && r.errbuf[0] ? -1 : r.emitted;
    free(r.batch.e);
    free(r.batch.bytes);
    return out;
}
