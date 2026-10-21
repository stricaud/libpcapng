/*
 * threading.h — what libpcapng promises, and does not promise, across threads.
 *
 * The library takes no locks and links no threading runtime. What it does
 * instead is keep per-dissection state off shared globals, so that two threads
 * dissecting two packets do not interfere. This header holds the one construct
 * that needs spelling per compiler.
 *
 * ── The one rule ───────────────────────────────────────────────────────────
 *
 *   Give a thread whole flows. Every piece of state a dissection carries
 *   between packets is per-flow — the sticky protocol classification, a
 *   decoder's `bind`/`recall` memory, a TLS session's derived keys — and all
 *   of it is per-thread. That is only sound if a flow never moves between
 *   threads. Split one flow across two workers and each sees half a
 *   conversation: the ClientHello reaches one and the encrypted records the
 *   other, a `bind` lands in one thread and the `recall` looks in another.
 *
 *   pcapng_flow_hash() exists for exactly this. Both directions of a
 *   connection hash the same, so
 *
 *       worker = pcapng_flow_hash(frame, len, linktype, PCAPNG_FLOW_TUPLE) % n;
 *
 *   pins a flow to a worker. See flow_hash.h.
 *
 * ── What is safe ───────────────────────────────────────────────────────────
 *
 *   pcapng_dissect() and pcapng_posa_dissect() from any number of threads.
 *   The field tree is allocated per call; the summary a dissection reports —
 *   protocol column, warnings — is per-thread, as is the sticky flow table.
 *
 *   Decoders using `bind`/`recall`, and TLS decryption, under the rule above:
 *   the conversation memory and the TLS session table are per-thread.
 *
 *   Reading and writing pcapng files, one FILE * per thread. io.c, blocks.c,
 *   objects.c and easyapi.c hold no shared state at all.
 *
 *   One pcapng_capture_t per thread. A capture handle owns its filter, flow
 *   table, statistics and ring buffers.
 *
 *   Compiling a display filter and matching it (dfilter.c is stateless).
 *
 *   pcapng_flow_hash() — pure, no state at all.
 *
 * ── What is not ────────────────────────────────────────────────────────────
 *
 *   Loading while dissecting. The decoder registry and the TLS keylog store
 *   are shared and written with no synchronisation, so pcapng_posa_load_*(),
 *   pcapng_posa_clear() and pcapng_tls_keylog_load_*() must not run while
 *   another thread is dissecting. Load everything up front.
 *
 *   The one load that is guarded is the lazy bundled-decoder load inside
 *   pcapng_dissect(), because threads reach it without meaning to. Racing
 *   into it is correct but slow — see pcapng_once below, and prefer calling
 *   pcapng_dissect_ensure_protocols() once before starting threads.
 *
 *   Per-thread state costs thread-local storage: ~1.3 MB a thread, nearly all
 *   of it the flow table (384 KB) and the conversation memory (896 KB). It is
 *   demand-paged, so only the slots a thread touches become resident.
 */
#ifndef _LIBPCAPNG_THREADING_H_
#define _LIBPCAPNG_THREADING_H_

/*
 * PCAPNG_THREAD_LOCAL — one instance of a variable per thread.
 *
 * Used for the small amount of state a dissection carries between the
 * functions that build it and the caller that reads it back. Without it those
 * are plain globals and two concurrent dissections overwrite each other's
 * answers.
 *
 * A compiler with no thread-local storage gets an empty definition, which is
 * exactly the old shared-global behaviour: correct single-threaded, racy
 * otherwise. Every compiler the project actually builds with has one.
 */
#if defined(__cplusplus) && __cplusplus >= 201103L
#  define PCAPNG_THREAD_LOCAL thread_local
#elif defined(_MSC_VER)
#  define PCAPNG_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  define PCAPNG_THREAD_LOCAL _Thread_local
#elif defined(__GNUC__) || defined(__clang__)
#  define PCAPNG_THREAD_LOCAL __thread
#else
#  define PCAPNG_THREAD_LOCAL
#endif

/*
 * pcapng_once — run an initialiser exactly once, even if several threads reach
 * it together. Internal; used to guard the lazy decoder-registry load.
 *
 *     static pcapng_once_t once = PCAPNG_ONCE_INIT;
 *     if (pcapng_once_begin(&once)) { ...initialise...; pcapng_once_end(&once); }
 *
 * A thread that loses the race waits for the winner to finish, by spinning:
 * there is no blocking primitive here because the library links no threading
 * runtime. That wait is only ever paid by a caller who ignored the rule above
 * and let threads race into the first dissection — loading the bundled
 * decoders takes ~85 ms, which is a long spin. Call
 * pcapng_dissect_ensure_protocols() once up front and there is no contention
 * at all: the fast path is a single acquire load.
 *
 * Needs C11 atomics. Without them PCAPNG_HAVE_ONCE is 0 and the guard is a
 * plain flag — exactly today's behaviour, correct single-threaded, and the
 * documented call-it-first rule becomes mandatory rather than merely advised.
 */
#if !defined(__cplusplus) && !defined(PCAPNG_NO_ATOMICS) && \
    defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && \
    !defined(__STDC_NO_ATOMICS__) && !defined(_WIN32)

#include <stdatomic.h>
#include <sched.h>

#define PCAPNG_HAVE_ONCE 1
typedef atomic_int pcapng_once_t;
#define PCAPNG_ONCE_INIT 0

/* 0 = untouched, 1 = a thread is initialising, 2 = done. */
static inline int pcapng_once_begin(pcapng_once_t *once)
{
    int expected = 0;
    if (atomic_load_explicit(once, memory_order_acquire) == 2) return 0;
    if (atomic_compare_exchange_strong_explicit(once, &expected, 1,
                                                memory_order_acq_rel,
                                                memory_order_acquire))
        return 1;                                   /* we won; caller initialises */
    while (atomic_load_explicit(once, memory_order_acquire) != 2)
        sched_yield();                              /* someone else is on it */
    return 0;
}

static inline void pcapng_once_end(pcapng_once_t *once)
{
    atomic_store_explicit(once, 2, memory_order_release);
}

#else

#define PCAPNG_HAVE_ONCE 0
typedef int pcapng_once_t;
#define PCAPNG_ONCE_INIT 0

static inline int pcapng_once_begin(pcapng_once_t *once)
{ if (*once) return 0; *once = 1; return 1; }

static inline void pcapng_once_end(pcapng_once_t *once) { *once = 2; }

#endif

#endif /* _LIBPCAPNG_THREADING_H_ */
