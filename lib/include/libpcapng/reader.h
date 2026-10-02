/*
 * reader.h — read a pcapng as packets rather than as blocks.
 *
 * libpcapng_file_read() and friends hand over blocks: a type, a length, and a
 * pointer at the body. That is the right shape for rewriting a file, and the
 * wrong shape for the far more common job of looking at its packets, because
 * everything the caller actually wanted has to be dug out by hand:
 *
 *     if block_type == 6 and len(block_data) >= 20:
 *         iface, _hi, _lo, cap, _orig = struct.unpack_from("<IIIII", block_data, 0)
 *         linktype = interfaces[iface] if iface < len(interfaces) else DLT_EN10MB
 *         index[0] += 1
 *         packets.append(Packet(index[0], block_data[20:20+cap], linktype))
 *
 * Every caller then reimplements the same four things — the Enhanced Packet
 * Block layout, the Simple Packet Block layout, the interface table that turns
 * an interface id into a link type, and a packet counter. Getting any of them
 * subtly wrong is quiet: a stale link type decodes the right bytes as the wrong
 * protocol, and a Simple Packet Block whose length exceeds what was captured
 * reads past the end.
 *
 * This does it once:
 *
 *     static int on_packet(const pcapng_packet_t *p, void *user)
 *     {
 *         printf("%llu  %u bytes  linktype %u\n",
 *                (unsigned long long)p->index, p->captured_len, p->linktype);
 *         return 0;                 // non-zero stops the walk
 *     }
 *     long n = pcapng_read_packets("capture.pcapng", on_packet, NULL);
 *
 * Non-packet blocks are handled rather than reported: interface descriptions
 * are absorbed into the link-type and timestamp-resolution tables that later
 * packets need, and everything else is skipped. Use libpcapng_file_read()
 * directly when the blocks themselves are the point.
 */
#ifndef _LIBPCAPNG_READER_H_
#define _LIBPCAPNG_READER_H_

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One captured packet, with everything needed to make sense of it. */
typedef struct {
    uint64_t       index;          /* 1-based position among the packets      */
    const uint8_t *data;           /* the frame; valid for this call only     */
    uint32_t       captured_len;   /* bytes in `data`                         */
    uint32_t       original_len;   /* bytes on the wire, >= captured_len      */
    uint32_t       interface_id;   /* which IDB it belongs to                 */
    uint16_t       linktype;       /* resolved from that IDB                  */

    /* Nanoseconds since the UNIX epoch, scaled by the interface's declared
       resolution (if_tsresol, microseconds unless it says otherwise).
       has_timestamp is 0 for a Simple Packet Block, which carries none —
       timestamp_ns is then 0 rather than a guess. */
    uint64_t       timestamp_ns;
    int            has_timestamp;

    uint32_t       block_type;     /* PCAPNG_ENHANCED_PACKET_BLOCK, &c.       */
} pcapng_packet_t;

/* Return non-zero to stop the walk early.
   Named apart from capture.h's pcapng_packet_cb, which is the live-capture
   callback and takes a different argument entirely. */
typedef int (*pcapng_read_packet_cb)(const pcapng_packet_t *pkt, void *user);

/*
 * Walk the packets of a capture, in file order.
 *
 * Returns how many packets the callback was given, or -1 if the input could
 * not be opened or read. Stopping early is not an error: the count so far is
 * returned.
 */
long pcapng_read_packets(const char *path, pcapng_read_packet_cb cb, void *user);
long pcapng_read_packets_fp(FILE *fp, pcapng_read_packet_cb cb, void *user);
long pcapng_read_packets_mem(const uint8_t *buf, size_t len,
                             pcapng_read_packet_cb cb, void *user);

/*
 * Block-type predicates, for code that does work at the block level and wants
 * to say what it means. Each checks the type *and* that the body is long enough
 * for the fields that type promises, which is the half that tends to be
 * forgotten.
 */
int pcapng_block_is_idb(uint32_t block_type, size_t body_len);
int pcapng_block_is_epb(uint32_t block_type, size_t body_len);
int pcapng_block_is_spb(uint32_t block_type, size_t body_len);
int pcapng_block_is_packet(uint32_t block_type, size_t body_len);   /* obsolete type 2 */
/* True for any block that carries a frame: EPB, SPB or the obsolete one. */
int pcapng_block_has_packet(uint32_t block_type, size_t body_len);

#ifdef __cplusplus
}
#endif

#endif /* _LIBPCAPNG_READER_H_ */
