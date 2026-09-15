/*
 * parallel_dissect.c — dissect a capture across threads, print in file order.
 *
 * The smallest complete use of the pipeline. It counts protocols and prints a
 * line per packet, but the shape is what matters:
 *
 *   work()   runs on a worker thread. One packet, one dissection. It must not
 *            touch anything another worker touches without saying so.
 *   emit()   runs on the calling thread, once per block, in file order. This
 *            is where output belongs, and why the output is ordered.
 *
 * Two rules make it safe, both from libpcapng/threading.h:
 *
 *   1. Load the decoders before any thread dissects. pipeline_run() does this
 *      for you; a program calling pcapng_dissect() from its own threads must
 *      call pcapng_dissect_ensure_protocols() itself.
 *   2. Give a thread whole flows. The pipeline does that with
 *      pcapng_flow_hash(), so a connection is only ever examined by one
 *      worker and the per-thread state stays coherent.
 *
 * Build (in-tree; -lcrypto only because the library was built with OpenSSL
 * for TLS decryption):
 *   cc -I lib/include -I bin -o parallel_dissect \
 *      examples/parallel_dissect.c bin/pipeline.c \
 *      build/lib/libpcapng_static.a -lcrypto -lpthread
 *
 * Run:
 *   ./parallel_dissect capture.pcapng 8
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libpcapng/blocks.h>
#include <libpcapng/dissect.h>

#include "pipeline.h"

/* The verdict a worker hands back is one int, so the protocols worth counting
   are agreed here and a worker returns an index into this table. Anything
   richer — the protocol name itself, a list of matches — needs a per-worker
   buffer that emit() can read, because a worker cannot return memory the
   pipeline does not own. */
static const char *const PROTOS[] = { "other", "HTTP", "DNS", "TLS", "Modbus/TCP" };
#define NPROTOS ((int)(sizeof PROTOS / sizeof PROTOS[0]))

typedef struct {
    unsigned long packets;
    unsigned long count[NPROTOS];
} tally_t;

/*
 * Worker thread.
 *
 * The verdict is one int, so this hands back a small code rather than the
 * dissection itself: a tree allocated here would have to outlive the batch,
 * and the pipeline does not own it. Anything richer than a code wants a
 * per-worker buffer that emit() can read.
 */
static int work(const pipeline_block_t *b, int worker, void *ctx)
{
    pcapng_dissection_t *d;
    int i, code = 0;

    (void)worker; (void)ctx;

    d = pcapng_dissect(b->pkt, b->caplen, b->caplen, b->linktype);
    if (!d) return 0;

    /* d->proto is the deepest protocol recognised — the application one, so
       an HTTP request reads "HTTP" rather than "TCP". */
    for (i = 1; i < NPROTOS; i++)
        if (!strcmp(d->proto, PROTOS[i])) { code = i; break; }

    pcapng_dissection_free(d);
    return code;
}

/* Calling thread, in file order — so printf here needs no lock and the output
   is the same however many workers ran. */
static int emit(const pipeline_block_t *b, int verdict, void *ctx)
{
    tally_t *t = (tally_t *)ctx;

    /* Only packet blocks were shown to work(); everything else arrives with
       the pipeline's default verdict of 1 and must not be counted as one. */
    if (b->block_type != PCAPNG_ENHANCED_PACKET_BLOCK || !b->pkt) return 0;
    t->packets++;

    if (verdict < 0 || verdict >= NPROTOS) verdict = 0;
    t->count[verdict]++;

    if (t->packets <= 10)
        printf("  %6llu  %5u bytes  %s\n",
               (unsigned long long)t->packets, b->caplen, PROTOS[verdict]);
    return 0;
}

int main(int argc, char **argv)
{
    tally_t t;
    char errbuf[256] = "";
    int workers;
    long n;

    if (argc < 2) {
        fprintf(stderr, "usage: %s CAPTURE.pcapng [workers]\n", argv[0]);
        return 2;
    }
    workers = (argc > 2) ? atoi(argv[2]) : pipeline_default_workers();

    memset(&t, 0, sizeof t);
    printf("dissecting %s on %d worker(s)\n", argv[1], workers);

    n = pipeline_run(argv[1], workers, work, emit, &t, errbuf, sizeof errbuf);
    if (n < 0) {
        fprintf(stderr, "error: %s\n", errbuf);
        return 1;
    }

    printf("\n  %lu packet(s)\n", t.packets);
    { int i;
      for (i = 0; i < NPROTOS; i++)
        if (t.count[i]) printf("    %-12s %lu\n", PROTOS[i], t.count[i]); }
    return 0;
}
