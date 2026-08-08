/*
 * capture.h — live packet capture API for libpcapng
 *
 * Provides zero-copy packet capture (Linux PACKET_MMAP/TPACKET_V3,
 * macOS BPF) with an integrated Wireshark-style display filter that
 * operates on decoded packet fields, plus POSA protocol extension
 * via a custom field-provider hook.
 *
 * Typical usage:
 *
 *   char errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
 *   pcapng_capture_t *cap = pcapng_capture_open("eth0", errbuf);
 *   pcapng_capture_set_filter(cap, "tcp.dstport == 443", errbuf);
 *   pcapng_capture_loop(cap, 0, my_callback, NULL);
 *   pcapng_capture_close(cap);
 *
 * Zero-copy contract:
 *   pcapng_packet_info_t.data is a direct pointer into the kernel ring
 *   buffer (Linux) or the BPF read buffer (macOS).  It is valid ONLY
 *   for the duration of the callback.  Copy the bytes if you need them
 *   beyond that point.
 *
 * Privileges:
 *   Linux: requires CAP_NET_RAW or root.
 *   macOS: requires root or the com.apple.security.network.packet-filter
 *          entitlement.
 *
 * License: MIT
 * Copyright (c) 2024 Sebastien Tricaud
 */
#ifndef _LIBPCAPNG_CAPTURE_H_
#define _LIBPCAPNG_CAPTURE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PCAPNG_CAPTURE_ERRBUF_SIZE  256

/* ── Packet direction ─────────────────────────────────────────────────── */
#define PCAPNG_CAP_DIR_UNKNOWN   0
#define PCAPNG_CAP_DIR_INBOUND   1
#define PCAPNG_CAP_DIR_OUTBOUND  2

/* ── Packet info passed to the callback ─────────────────────────────── */
typedef struct {
    const uint8_t  *data;           /* zero-copy pointer — valid only during callback */
    uint32_t        captured_len;   /* bytes present in data[]                         */
    uint32_t        original_len;   /* bytes on the wire (may be > captured_len)       */
    uint64_t        timestamp_ns;   /* nanoseconds since the UNIX epoch                */
    int             direction;      /* PCAPNG_CAP_DIR_*                                */
} pcapng_packet_info_t;

/* ── Capture statistics ─────────────────────────────────────────────── */
typedef struct {
    uint64_t  received;   /* packets received by the kernel                  */
    uint64_t  dropped;    /* packets dropped by the kernel (ring-buffer full) */
    uint64_t  passed;     /* packets delivered to the user callback           */
    uint64_t  filtered;   /* packets discarded by the display filter          */
} pcapng_capture_stats_t;

/* ── Interface descriptor ───────────────────────────────────────────── */
typedef struct {
    char  name[64];         /* "eth0", "en0", "lo", …                         */
    char  description[128]; /* human-readable description or empty string      */
    int   loopback;         /* 1 if this is the loopback interface             */
} pcapng_device_t;

/* ── User callback ──────────────────────────────────────────────────── */
typedef void (*pcapng_packet_cb)(const pcapng_packet_info_t *pkt, void *userdata);

/* ── Custom field provider for POSA / application-level fields ─────────
 *
 * Register with pcapng_capture_set_field_provider().
 *
 * The library calls this for any field name not recognised by the
 * built-in Ethernet/IP/TCP/UDP dissector — e.g. "myproto.version".
 * Write a string representation of the value into value_out and return 1
 * if the field is present in this packet, or return 0 if it is absent.
 *
 * Integration with pcapsh POSA:
 *   pcapng_capture_set_field_provider(cap, pcapsh_posa_field_get, NULL);
 */
typedef int (*pcapng_field_provider_t)(
    const char     *field,        /* field name, e.g. "myproto.msg_type"     */
    const uint8_t  *pkt_data,     /* raw captured bytes                      */
    uint32_t        pkt_len,
    char           *value_out,    /* write string representation here        */
    size_t          value_size,   /* sizeof(value_out)                       */
    void           *ctx
);

/* ── Opaque capture handle ──────────────────────────────────────────── */
typedef struct pcapng_capture pcapng_capture_t;

/* ======================================================================
 * Device discovery
 * ====================================================================== */

/*
 * pcapng_capture_list_devices — enumerate network interfaces.
 *
 * Returns a malloc'd array of *count entries.  Free with
 * pcapng_capture_free_devices().  Returns NULL on error with a
 * description in errbuf.
 */
pcapng_device_t *pcapng_capture_list_devices(int *count, char *errbuf);
void             pcapng_capture_free_devices(pcapng_device_t *devs);

/*
 * pcapng_capture_default_device — return the name of the first suitable
 * non-loopback interface (static buffer, do not free).
 * Returns NULL if none found.
 */
const char *pcapng_capture_default_device(char *errbuf);

/* ======================================================================
 * Open / configure
 * ====================================================================== */

/*
 * pcapng_capture_open — create a capture handle for `device`.
 *
 * The handle is not yet active; configure it with the setters below,
 * then start capturing with pcapng_capture_loop() or _dispatch().
 *
 * Returns NULL on error.
 */
pcapng_capture_t *pcapng_capture_open(const char *device, char *errbuf);

/* All setters return 0 on success, -1 on error. */

/* Maximum bytes captured per packet (default: 65535). */
int pcapng_capture_set_snaplen(pcapng_capture_t *, uint32_t snaplen);

/* Put the interface into promiscuous mode (default: on). */
int pcapng_capture_set_promisc(pcapng_capture_t *, int on);

/* Packet-delivery timeout in milliseconds (default: 100). */
int pcapng_capture_set_timeout(pcapng_capture_t *, int ms);

/* Total ring-buffer / read-buffer size in bytes (default: 16 MB). */
int pcapng_capture_set_buffer_size(pcapng_capture_t *, size_t bytes);

/*
 * pcapng_capture_set_filter — compile and attach a display filter.
 *
 * Expression syntax (Wireshark-compatible subset):
 *   Existence:    tcp    udp    ip    ip6    icmp    arp
 *   Comparison:   ip.src == 1.2.3.4    tcp.dstport != 80    ip.ttl >= 64
 *   CIDR:         ip.src == 192.168.0.0/16
 *   Boolean:      and/&&   or/||   not/!   ( )
 *   Byte slice:   tcp[13] == 0x02    tcp[0:2] == 0x1234    tcp[13]&0x02 == 0x02
 *   Functions:    len(frame) > 100   len(tcp.payload) == 0
 *                 lower(field) == "value"   upper(field) == "VALUE"
 *     len() layers: frame | ip | ip.payload | tcp | tcp.payload | udp | udp.payload
 *     upper/lower only transform FV_STR fields (custom provider or dns.qry.name etc.)
 *
 * Built-in fields:
 *   frame.len  frame.cap_len
 *   eth.src  eth.dst  eth.type
 *   ip.src   ip.dst   ip.proto  ip.ttl  ip.len
 *   ip6.src  ip6.dst  (aliases: ipv6.src  ipv6.dst)
 *   tcp.srcport  tcp.dstport  tcp.flags  tcp.seq  tcp.ack
 *   tcp.window_size  tcp.window_size_value
 *   tcp.flags.syn  tcp.flags.ack  tcp.flags.rst  tcp.flags.fin
 *   tcp.flags.psh  tcp.flags.urg
 *   udp.srcport  udp.dstport  udp.len
 *   icmp.type   icmp.code
 *   icmpv6.type icmpv6.code
 *   arp.opcode  arp.src.proto_ipv4  arp.dst.proto_ipv4
 *   arp.src.hw_mac  arp.dst.hw_mac
 *   vlan.id
 *
 * Alias fields (match either side):
 *   ip.addr  →  ip.src  or  ip.dst
 *   ip6.addr → ip6.src  or  ip6.dst  (also ipv6.addr)
 *   tcp.port →  tcp.srcport  or  tcp.dstport
 *   udp.port →  udp.srcport  or  udp.dstport
 *   eth.addr →  eth.src  or  eth.dst
 *
 * Named-field bitwise AND (tcp.flags & 0x02 != 0):
 *   Any numeric field can be masked: field & mask op value
 *   e.g. tcp.flags & 0x12 == 0x02   (SYN set, ACK clear)
 *
 * Named-field slices (eth.src[0:3] == 0xaabbcc):
 *   Supported bases: eth.src  eth.dst  ip.src  ip.dst  ip6.src  ip6.dst
 *   Negative offsets: tcp[-7] == 0x02  (7th byte from end)
 *
 * POSA lookup function:
 *   coap.code == lookup(CREATED)
 *   The provider receives "__lookup__:CREATED" and returns the numeric value.
 *
 * Unknown fields are passed to the registered field provider (if any).
 *
 * Returns 0 on success, -1 on parse error (see errbuf).
 */
int pcapng_capture_set_filter(pcapng_capture_t *, const char *expr, char *errbuf);

/*
 * pcapng_capture_filter_match — stateless filter evaluation against raw bytes.
 *
 * Compiles `expr` and immediately evaluates it against `data[0..len-1]`.
 * linktype: LINKTYPE_ETHERNET (1) or LINKTYPE_RAW (101).
 *
 * Returns  1  if the packet matches,
 *          0  if it does not,
 *         -1  on compile error (errbuf filled when non-NULL).
 *
 * Note: tcp.analysis.retransmission always returns 0 here (no flow state).
 * Use pcapng_capture_filter_match_ex() with a flow table for stateful detection.
 */
int pcapng_capture_filter_match(const char *expr,
                                const uint8_t *data, uint32_t len,
                                uint16_t linktype,
                                char *errbuf);

/* ── Stateful flow tracking (tcp.analysis.*) ──────────────────────────────
 *
 * pcapng_capture_t automatically creates and owns a flow table; every packet
 * processed by pcapng_capture_loop() / _dispatch() updates it.
 *
 * For one-shot / scripting use, create a standalone table, feed packets to
 * pcapng_capture_filter_match_ex() in order, and free when done.
 *
 * Supported tcp.analysis fields (all return 0 without a flow table):
 *   tcp.analysis.retransmission        — seq below high-water mark (data re-sent)
 *   tcp.analysis.fast_retransmission   — retransmit after ≥3 dup ACKs from peer
 *   tcp.analysis.spurious_retransmission — retransmit of already-acked data
 *   tcp.analysis.duplicate_ack         — pure ACK, same ACK#, same window
 *   tcp.analysis.duplicate_ack_num     — consecutive count of duplicate ACKs
 *   tcp.analysis.zero_window           — window field = 0 in this packet
 *   tcp.analysis.zero_window_probe     — 1-byte probe to a zero-window peer
 *   tcp.analysis.zero_window_probe_ack — ACK of a zero-window probe
 *   tcp.analysis.keep_alive            — seq = peer_last_ack − 1, len ≤ 1
 *   tcp.analysis.keep_alive_ack        — ACK of a keep-alive
 *   tcp.analysis.window_update         — pure ACK, same ACK#, different window
 *   tcp.analysis.out_of_order          — seq behind hw-mark but extends past it
 *   tcp.analysis.bytes_in_flight       — bytes sent but not yet acked by peer
 *   tcp.analysis.lost_segment          — gap detected (seq jumped forward)
 */
typedef struct pcapng_flow_table pcapng_flow_table_t;

pcapng_flow_table_t *pcapng_flow_table_create(void);
void                 pcapng_flow_table_free(pcapng_flow_table_t *);

/*
 * pcapng_capture_filter_match_ex — stateful filter evaluation.
 *
 * Same as pcapng_capture_filter_match() but accepts a persistent flow table.
 * Pass the same table for each successive packet to accumulate TCP state.
 * `table` may be NULL (equivalent to the stateless variant).
 */
int pcapng_capture_filter_match_ex(const char *expr,
                                    const uint8_t *data, uint32_t len,
                                    uint16_t linktype,
                                    pcapng_flow_table_t *table,
                                    char *errbuf);

/*
 * pcapng_capture_set_field_provider — register a POSA / custom field hook.
 *
 * Called for any field name not resolved by the built-in dissector.
 * Pass fn=NULL to unregister.
 *
 * The provider also receives synthetic field names used by the filter engine:
 *   "__lookup__:NAME" — resolve a POSA symbolic name (e.g. "CREATED") to its
 *                       numeric value string (e.g. "0x41").  Used by lookup().
 */
void pcapng_capture_set_field_provider(pcapng_capture_t *,
                                        pcapng_field_provider_t fn,
                                        void *ctx);

/* ── Filter alias management ──────────────────────────────────────────────
 *
 * Aliases let you define shorthand names for filter expressions and
 * multi-field expansions that are checked every time a filter is compiled.
 *
 * Two kinds of alias:
 *
 *   Expression alias (key contains spaces):
 *     When an entire filter string (trimmed) equals the key, it is replaced
 *     by the value before parsing.
 *     Example:  "new TCP connections" → "tcp.flags.syn == 1 and tcp.flags.ack == 0"
 *
 *     Keys may include "$1" as a positional variable; the matching portion of
 *     the user's input is captured and substituted wherever $1 appears in the
 *     value, allowing parameterised natural-language filters:
 *       key:   "show packets containing $1"
 *       value: "frame contains $1"
 *       usage: show packets containing "password"  →  frame contains "password"
 *
 *   Field alias (key has no spaces):
 *     When the key appears as a field name inside a filter, it expands to
 *     each comma-separated target field with OR semantics — the first field
 *     present in the packet matches (same as ip.addr → ip.src or ip.dst).
 *     Example:  "host.name" → "dns.qry.name, http.host, tls.handshake.extensions_server_name"
 *
 * Aliases are global; they apply to every capture handle and to
 * pcapng_capture_filter_match().
 */

/*
 * pcapng_filter_alias_add — register one alias programmatically.
 * Returns 0 on success, -1 if the table is full (CAP_MAX_ALIASES = 256).
 */
int pcapng_filter_alias_add(const char *from, const char *to);

/*
 * pcapng_filter_aliases_load — load aliases from a config file.
 *
 * File format (one entry per line):
 *   # comment
 *   failed dns = udp.dstport == 53 or udp.srcport == 53
 *   host.name  = dns.qry.name, http.host, tls.handshake.extensions_server_name
 *
 * Returns 0 on success, -1 on open failure (errbuf filled).
 */
int pcapng_filter_aliases_load(const char *path, char *errbuf);

/* ======================================================================
 * Run
 * ====================================================================== */

/*
 * pcapng_capture_loop — capture packets, calling `cb` for each.
 *
 * Runs until:
 *   - `count` packets have been passed to cb  (count <= 0 → unlimited)
 *   - pcapng_capture_break() is called
 *   - SIGINT is received
 *   - A fatal error occurs
 *
 * Returns the total number of packets delivered to cb, or -1 on error.
 */
int pcapng_capture_loop(pcapng_capture_t *, int count,
                         pcapng_packet_cb cb, void *userdata);

/*
 * pcapng_capture_dispatch — process one batch of packets and return.
 *
 * Suitable for embedding in an existing event loop.  count <= 0 means
 * "process all packets currently available."
 *
 * Returns packets processed this call (0 if none arrived), -1 on error.
 */
int pcapng_capture_dispatch(pcapng_capture_t *, int count,
                             pcapng_packet_cb cb, void *userdata);

/* Signal the capture loop to stop cleanly.  Safe from signal handlers. */
void pcapng_capture_break(pcapng_capture_t *);

/* ======================================================================
 * Statistics
 * ====================================================================== */
int pcapng_capture_get_stats(pcapng_capture_t *, pcapng_capture_stats_t *);

/* ======================================================================
 * Convenience one-shot functions
 * ====================================================================== */

/*
 * pcapng_capture_to_file — capture to a pcapng file.
 *
 * Opens `device`, optionally applies `filter` (may be NULL), writes
 * packets to `path` in pcapng format.  count == 0 runs until SIGINT.
 *
 * Returns packets written, or -1 on error.
 */
int pcapng_capture_to_file(const char *device, const char *path,
                            const char *filter, int count, char *errbuf);

/*
 * pcapng_capture_print — capture and print one-line packet summaries.
 *
 * Opens `device`, optionally applies `filter` (may be NULL), prints
 * summaries to stdout.  count == 0 runs until SIGINT.
 *
 * Returns packets printed, or -1 on error.
 */
int pcapng_capture_print(const char *device, const char *filter,
                          int count, char *errbuf);

/* ======================================================================
 * Close
 * ====================================================================== */
void pcapng_capture_close(pcapng_capture_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBPCAPNG_CAPTURE_H_ */
