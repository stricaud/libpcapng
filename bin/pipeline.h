/*
 * pipeline.h — read a pcapng, work on its packets in parallel, emit in order.
 *
 * The threading lives here, in the tool, and not in libpcapng: the library
 * links no threading runtime precisely so that a host with its own concurrency
 * model does not have to fight one. What the library provides is the part that
 * makes parallel dissection sound — per-thread flow state, and a flow hash to
 * pin flows to threads with. This assembles those into the arrangement
 * Suricata calls autofp: one reader, flow-pinned workers, ordered output.
 *
 *   reader        walks the file once, in order, numbering blocks
 *     |           and shelving a batch of them
 *     v
 *   workers       pcapng_flow_hash(frame) % nworkers picks the worker, so
 *     |           every packet of a flow — both directions — lands on one
 *     v           thread and the library's per-thread state stays coherent
 *   emit          the batch is handed back on the calling thread, in the
 *                 order it was read
 *
 * Order is not recovered at the end; it is never given up. A batch is an array
 * indexed by file position, workers write only their own entries' verdicts, and
 * the emit callback walks the array front to back. There is no reorder buffer
 * and no way for output to escape input order.
 *
 * The cost is a barrier per batch: the batch finishes when its slowest worker
 * does. With many flows that is close to even — the flow hash spreads 4096
 * flows across 8 workers to within ±7%. A capture dominated by one enormous
 * flow cannot be parallelised at all by this or any flow-pinned scheme, and
 * degrades to single-threaded rather than to wrong.
 *
 * License MIT
 */
#ifndef PCAPNG_PIPELINE_H
#define PCAPNG_PIPELINE_H

#include <stddef.h>
#include <stdint.h>

/* One block, as the reader found it. `pkt`/`caplen`/`linktype` are filled in
   only for packet blocks; everything else has pkt == NULL and passes straight
   through to emit. `block` is the block body — what follows the 8-byte
   type/length header — so writing it back out verbatim is:

       fwrite(&(uint32_t[2]){ b->block_type, b->block_len }, 1, 8, fp);
       fwrite(b->block, 1, b->block_len - 8, fp);                             */
typedef struct {
    uint64_t       seq;         /* position in the file, 0-based */
    uint32_t       block_type;
    const uint8_t *block;
    uint32_t       block_len;   /* block_total_length, header included */
    const uint8_t *pkt;         /* frame bytes, or NULL */
    uint32_t       caplen;
    uint16_t       linktype;
    /* Capture time, in the interface's units — microseconds since the epoch
       unless the IDB carries an if_tsresol option saying otherwise, which this
       does not read. 0 for a non-packet block. */
    uint64_t       ts;
} pipeline_block_t;

/*
 * Called on a worker thread, for packet blocks only, possibly for many blocks
 * at once across threads. Must touch nothing shared without saying so: `ctx`
 * is the same pointer every worker gets, `worker` is 0..nworkers-1 for indexing
 * per-worker scratch. Whatever it returns is handed to emit as `verdict`.
 */
typedef int (*pipeline_work_fn)(const pipeline_block_t *b, int worker, void *ctx);

/*
 * Called on the calling thread, for every block, in file order. `verdict` is
 * what work returned, or 1 for a block work never saw. Return < 0 to stop.
 */
typedef int (*pipeline_emit_fn)(const pipeline_block_t *b, int verdict, void *ctx);

/*
 * Run the pipeline over `path`.
 *
 * nworkers <= 1 runs everything inline on the calling thread, with no threads
 * created at all — the same code path, so a bug shows up in both.
 *
 * Returns the number of blocks emitted, or -1 with errbuf filled.
 */
long pipeline_run(const char *path, int nworkers,
                  pipeline_work_fn work, pipeline_emit_fn emit, void *ctx,
                  char *errbuf, size_t errlen);

/* Worker threads a machine can usefully run, for a default. Never 0. */
int pipeline_default_workers(void);

#endif /* PCAPNG_PIPELINE_H */
