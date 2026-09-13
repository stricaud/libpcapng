/*
 * surgery.h — streaming pcapng file manipulation without full in-memory load.
 *
 * License MIT
 */
#ifndef LIBPCAPNG_SURGERY_H
#define LIBPCAPNG_SURGERY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PCAPNG_SURGERY_ERRBUF_SIZE 256

/* ── Options structs ────────────────────────────────────────────────────── */

typedef struct {
    int sort_by_timestamp;  /* merge in timestamp order (requires buffering) */
} pcapng_merge_opts_t;

typedef struct {
    uint32_t max_packets;   /* start a new file every N packets (0 = no limit) */
    uint64_t max_bytes;     /* start a new file when output exceeds N bytes     */
} pcapng_split_opts_t;

typedef struct {
    uint64_t seed;          /* seed for address anonymization (0 = use default) */
    int      anonymize_mac; /* 1 = also anonymize MAC addresses                 */
} pcapng_anon_opts_t;

/* ── Operations ─────────────────────────────────────────────────────────── */

/* Copy only packets matching a display filter expression.
 * SHB/IDB/NRB/DSB/ISB blocks are always passed through unchanged.
 * Returns number of packets written, or -1 on error (errbuf filled). */
int pcapng_filter_file(const char *input, const char *output, const char *filter_expr, char *errbuf);

/* Concatenate multiple pcapng files into one output file.
 * A fresh SHB is written; IDB interface_ids are renumbered to avoid collisions.
 * opts may be NULL (sequential concatenation, no timestamp sorting).
 * Returns total packets written, or -1 on error (errbuf filled). */
int pcapng_merge(const char **inputs, int n_inputs, const char *output, const pcapng_merge_opts_t *opts, char *errbuf);

/* Split a pcapng file into multiple output files.
 * output_pattern must contain a printf %d specifier (e.g. "out%04d.pcapng").
 * Each output file begins with an SHB + all IDBs seen so far.
 * Returns number of files created, or -1 on error (errbuf filled). */
int pcapng_split(const char *input, const char *output_pattern, const pcapng_split_opts_t *opts, char *errbuf);

/* Anonymize IP addresses (and optionally MACs) in all EPB packets.
 * IPv4: last 2 octets replaced by a deterministic hash (preserves /16 prefix).
 * IPv6: last 8 bytes replaced by a deterministic hash.
 * MAC:  last 3 bytes replaced (preserves OUI) when opts->anonymize_mac is set.
 * IPv4 header checksums are recomputed; TCP/UDP checksums are zeroed.
 * opts may be NULL (uses built-in seed, MAC anonymization off).
 * Returns number of packets processed, or -1 on error (errbuf filled). */
int pcapng_anonymize(const char *input, const char *output, const pcapng_anon_opts_t *opts, char *errbuf);

/* Inject a single raw packet into a pcapng file.
 * The packet is inserted so that timestamps remain monotonically increasing;
 * if ts_us is 0, the packet is appended at the end.
 * interface_id refers to an IDB already present in the input file.
 * Returns 0 on success, -1 on error (errbuf filled). */
int pcapng_inject_packet(const char *input, const char *output, const uint8_t *pkt, uint32_t pkt_len, uint64_t ts_us, uint32_t interface_id, char *errbuf);

#ifdef __cplusplus
}
#endif

#endif /* LIBPCAPNG_SURGERY_H */
