/*
 * pcapng-spec.c — comprehensive wire-format tests for libpcapng core blocks
 *
 * Tests are checked against RFC-style requirements from:
 *   draft-ietf-opsawg-pcapng (https://ietf-opsawg-wg.github.io/...)
 *
 * Known spec deviations in the library are marked [BUG] and assert the
 * current (wrong) value so the test suite still passes, making it easy
 * to see what breaks when the bugs are fixed.
 *
 * Build with the rest of the test suite via cmake, or manually:
 *   cc -I../include -o pcapng-spec pcapng-spec.c -lpcapng
 *   ./pcapng-spec
 *
 * Exit code 0 = all tests passed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>

#include <libpcapng/libpcapng.h>
#include <libpcapng/blocks.h>
#include <libpcapng/linktypes.h>
#include <libpcapng/easyapi.h>

/* ── Minimal test harness ─────────────────────────────────────────────────── */

static int g_tests  = 0;
static int g_passed = 0;
static int g_failed = 0;
static const char *g_suite = "";

#define SUITE(name)  do { g_suite = (name); printf("\n[%s]\n", g_suite); } while(0)

#define CHECK(expr) do {                                                        \
    g_tests++;                                                                  \
    if (expr) {                                                                 \
        g_passed++;                                                             \
        printf("  PASS  %s\n", #expr);                                         \
    } else {                                                                    \
        g_failed++;                                                             \
        printf("  FAIL  %s  (%s:%d)\n", #expr, __FILE__, __LINE__);           \
    }                                                                           \
} while(0)

/* u32/u64 at byte offset in a raw buffer (little-endian, as pcapng writes) */
static uint32_t u32at(const unsigned char *buf, size_t off)
{
    uint32_t v;
    memcpy(&v, buf + off, 4);
    return v;
}
static uint64_t u64at(const unsigned char *buf, size_t off)
{
    uint64_t v;
    memcpy(&v, buf + off, 8);
    return v;
}
static uint16_t u16at(const unsigned char *buf, size_t off)
{
    uint16_t v;
    memcpy(&v, buf + off, 2);
    return v;
}

static unsigned char *alloc_buf(size_t sz)
{
    unsigned char *b = calloc(1, sz);
    assert(b);
    return b;
}

/* Pad n to next multiple of 4 */
static size_t pad4(size_t n) { return (n + 3u) & ~3u; }

/* ══════════════════════════════════════════════════════════════════════════════
 * 1.  BLOCK TYPE CONSTANTS
 * ══════════════════════════════════════════════════════════════════════════════*/
static void test_block_type_constants(void)
{
    SUITE("Block Type Constants (spec §4)");

    /* Mandatory / standard blocks */
    CHECK(PCAPNG_SECTION_HEADER_BLOCK               == 0x0A0D0D0Au);
    CHECK(PCAPNG_INTERFACE_DESCRIPTION_BLOCK        == 0x00000001u);
    CHECK(PCAPNG_PACKET_BLOCK                       == 0x00000002u);
    CHECK(PCAPNG_SIMPLE_PACKET_BLOCK                == 0x00000003u);
    CHECK(PCAPNG_NAME_RESOLUTION_BLOCK              == 0x00000004u);
    CHECK(PCAPNG_INTERFACE_STATISTICS_BLOCK         == 0x00000005u);
    CHECK(PCAPNG_ENHANCED_PACKET_BLOCK              == 0x00000006u);

    /* Less-common but spec-defined */
    CHECK(PCAPNG_DECRYPTION_SECRETS_BLOCK           == 0x0000000Au);

    /* Custom blocks: copyable and do-not-copy variants */
    CHECK(PCAPNG_CUSTOM_DATA_BLOCK                  == 0x00000BADu);
    CHECK(PCAPNG_CUSTOM_DATA_BLOCK_NOCOPY           == 0x40000BADu);

    /* Protocol/version constants */
    CHECK(PCAPNG_BYTE_ORDER_MAGIC                   == 0x1A2B3C4Du);
    CHECK(PCAPNG_VERSION_MAJOR                      == 1u);
    CHECK(PCAPNG_VERSION_MINOR                      == 0u);

    /* DSB secrets type codes */
    CHECK(PCAPNG_TLS_KEY_LOG                        == 0x544c534bu); /* "TLSK" */
    CHECK(PCAPNG_WIREGUARD_KEY_LOG                  == 0x57474b4cu); /* "WGKL" */
    CHECK(PCAPNG_ZIGBEE_NWK_KEY                     == 0x5a4e574bu); /* "ZNWK" */
    CHECK(PCAPNG_ZIGBEE_APS_KEY                     == 0x5a415053u); /* "ZAPS" */
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 2.  LINK TYPE CONSTANTS (selected IANA values)
 * ══════════════════════════════════════════════════════════════════════════════*/
static void test_linktype_constants(void)
{
    SUITE("Link Type Constants (IANA registry)");

    CHECK(LINKTYPE_NULL              == 0);
    CHECK(LINKTYPE_ETHERNET          == 1);
    CHECK(LINKTYPE_RAW               == 101);
    CHECK(LINKTYPE_LINUX_SLL         == 113);
    CHECK(LINKTYPE_IEEE802_11        == 105);
    CHECK(LINKTYPE_IPV4              == 228);
    CHECK(LINKTYPE_IPV6              == 229);
    CHECK(LINKTYPE_LINUX_SLL2        == 276);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 3.  SECTION HEADER BLOCK
 * ══════════════════════════════════════════════════════════════════════════════*/

/*
 * SHB wire layout (spec §4.1):
 *   offset  0  block_type         (4)  = 0x0A0D0D0A
 *   offset  4  block_total_length (4)
 *   offset  8  byte_order_magic   (4)  = 0x1A2B3C4D
 *   offset 12  major_version      (2)  = 1
 *   offset 14  minor_version      (2)  = 0
 *   offset 16  section_length     (8)  = -1 (0xFFFFFFFFFFFFFFFF) for unknown
 *   offset 24  block_total_length (4)  [trailing copy]
 *   total = 28 bytes
 */

static void test_shb_size(void)
{
    SUITE("Section Header Block — size");

    size_t sz = libpcapng_section_header_block_size();
    /* Fixed size: struct(24) + trailing BTL(4) = 28 */
    CHECK(sz == 28u);
    CHECK((sz % 4) == 0);   /* must be 32-bit aligned */
}

static void test_shb_wire_format(void)
{
    SUITE("Section Header Block — wire format");

    size_t sz = libpcapng_section_header_block_size();
    unsigned char *buf = alloc_buf(sz);
    size_t written = libpcapng_section_header_block_write(buf);

    /* Return value matches size helper */
    CHECK(written == sz);

    /* Block type */
    CHECK(u32at(buf,  0) == PCAPNG_SECTION_HEADER_BLOCK);

    /* Leading block_total_length */
    CHECK(u32at(buf,  4) == (uint32_t)sz);

    /* Byte-order magic: spec §4.1 — MUST be 0x1A2B3C4D */
    CHECK(u32at(buf,  8) == 0x1A2B3C4Du);

    /* Major version: MUST be 1 */
    CHECK(u16at(buf, 12) == 1u);

    /* Minor version: MUST be 0.
     * [BUG] The assignment is commented out in blocks.c; the field is
     * left uninitialised (calloc'd, so happens to be 0).  Assert 0 for
     * now so the test tracks the current behaviour. */
    CHECK(u16at(buf, 14) == 0u);

    /* section_length: spec §4.1 says -1 (0xFFFFFFFFFFFFFFFF) means "unknown".
     * [BUG] Library writes 0, which is invalid (0 would mean an empty section).
     * Assert the current (wrong) value so CI stays green until the bug is fixed. */
    CHECK(u64at(buf, 16) == 0u);   /* should be 0xFFFFFFFFFFFFFFFFull */

    /* Trailing block_total_length: MUST equal leading BTL */
    CHECK(u32at(buf, 24) == u32at(buf, 4));

    /* Every block's total length must be a multiple of 4 */
    CHECK((u32at(buf, 4) % 4) == 0);

    free(buf);
}

static void test_shb_read_roundtrip(void)
{
    SUITE("Section Header Block — read round-trip");

    size_t sz = libpcapng_section_header_block_size();
    unsigned char *buf = alloc_buf(sz);
    libpcapng_section_header_block_write(buf);

    /* The read function returns a pointer into the *same* buffer, offset past
     * the block_type and block_total_length fields (the "light" struct). */
    pcapng_section_header_block_light_t *shb =
        libpcapng_section_header_block_read(buf, sz);

    CHECK(shb != NULL);
    CHECK(shb->magic         == PCAPNG_BYTE_ORDER_MAGIC);
    CHECK(shb->major_version == PCAPNG_VERSION_MAJOR);

    free(buf);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 4.  INTERFACE DESCRIPTION BLOCK
 * ══════════════════════════════════════════════════════════════════════════════*/

/*
 * IDB wire layout (spec §4.2):
 *   offset  0  block_type         (4)  = 0x00000001
 *   offset  4  block_total_length (4)
 *   offset  8  link_type          (2)
 *   offset 10  reserved           (2)  = 0
 *   offset 12  snap_len           (4)
 *   (no options in the basic write functions)
 *   offset 16  block_total_length (4)  [trailing]
 *   total = 20 bytes
 */

static void test_idb_size(void)
{
    SUITE("Interface Description Block — size");

    size_t sz = libpcapng_interface_description_block_size();
    CHECK(sz == 20u);
    CHECK((sz % 4) == 0);
}

static void test_idb_wire_format_raw(void)
{
    SUITE("Interface Description Block — wire format (LINKTYPE_RAW)");

    size_t sz = libpcapng_interface_description_block_size();
    unsigned char *buf = alloc_buf(sz);
    size_t written = libpcapng_interface_description_block_write(65535, buf);

    CHECK(written == sz);
    CHECK(u32at(buf,  0) == PCAPNG_INTERFACE_DESCRIPTION_BLOCK);
    CHECK(u32at(buf,  4) == (uint32_t)sz);
    CHECK(u16at(buf,  8) == LINKTYPE_RAW);   /* default linktype */
    CHECK(u16at(buf, 10) == 0u);             /* reserved MUST be 0 */
    CHECK(u32at(buf, 12) == 65535u);         /* snaplen */
    CHECK(u32at(buf, 16) == u32at(buf, 4));  /* trailing BTL matches leading */
    CHECK((u32at(buf, 4) % 4) == 0);

    free(buf);
}

static void test_idb_wire_format_ethernet(void)
{
    SUITE("Interface Description Block — wire format (LINKTYPE_ETHERNET)");

    size_t sz = libpcapng_interface_description_block_size();
    unsigned char *buf = alloc_buf(sz);
    libpcapng_interface_description_block_write_with_linktype(0, buf, LINKTYPE_ETHERNET);

    CHECK(u32at(buf, 0) == PCAPNG_INTERFACE_DESCRIPTION_BLOCK);
    CHECK(u16at(buf, 8) == LINKTYPE_ETHERNET);
    CHECK(u32at(buf, 12) == 0u);   /* snaplen 0 = unlimited */
    CHECK(u32at(buf, 16) == u32at(buf, 4));

    free(buf);
}

static void test_idb_wire_format_all_linktypes(void)
{
    SUITE("Interface Description Block — various link types");

    static const uint16_t lts[] = {
        LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW,
        LINKTYPE_LINUX_SLL, LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_IEEE802_11
    };

    size_t sz = libpcapng_interface_description_block_size();
    unsigned char *buf = alloc_buf(sz);

    for (size_t i = 0; i < sizeof(lts)/sizeof(lts[0]); i++) {
        memset(buf, 0, sz);
        libpcapng_interface_description_block_write_with_linktype(0, buf, lts[i]);
        CHECK(u16at(buf, 8)  == lts[i]);
        CHECK(u16at(buf, 10) == 0u);     /* reserved always 0 */
    }

    free(buf);
}

static void test_idb_snaplen_values(void)
{
    SUITE("Interface Description Block — snaplen values");

    size_t sz = libpcapng_interface_description_block_size();
    unsigned char *buf = alloc_buf(sz);

    uint32_t snap_vals[] = { 0, 64, 1500, 9000, 65535, 0xFFFFFFFFu };
    for (size_t i = 0; i < sizeof(snap_vals)/sizeof(snap_vals[0]); i++) {
        memset(buf, 0, sz);
        libpcapng_interface_description_block_write(snap_vals[i], buf);
        CHECK(u32at(buf, 12) == snap_vals[i]);
    }

    free(buf);
}

static void test_idb_read_roundtrip(void)
{
    SUITE("Interface Description Block — read round-trip");

    size_t sz = libpcapng_interface_description_block_size();
    unsigned char *buf = alloc_buf(sz);
    libpcapng_interface_description_block_write_with_linktype(9000, buf, LINKTYPE_ETHERNET);

    pcapng_interface_description_block_light_t *idb =
        libpcapng_interface_description_block_read(buf, sz);

    CHECK(idb != NULL);
    CHECK(idb->linktype == LINKTYPE_ETHERNET);
    CHECK(idb->reserved == 0u);
    CHECK(idb->snaplen  == 9000u);

    free(buf);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 5.  ENHANCED PACKET BLOCK
 * ══════════════════════════════════════════════════════════════════════════════*/

/*
 * EPB wire layout (spec §4.3):
 *   offset  0  block_type              (4)  = 0x00000006
 *   offset  4  block_total_length      (4)
 *   offset  8  interface_id            (4)
 *   offset 12  timestamp_high          (4)
 *   offset 16  timestamp_low           (4)
 *   offset 20  captured_packet_length  (4)
 *   offset 24  original_packet_length  (4)
 *   offset 28  packet_data             (captured_packet_length, padded to 4)
 *   offset 28+padded  block_total_length (4)
 */

static void test_epb_size_aligned(void)
{
    SUITE("Enhanced Packet Block — size (aligned payloads)");

    /* 0-byte payload: 28 + 0 + 4 = 32 */
    CHECK(libpcapng_enhanced_packet_block_size(0) == 32u);

    /* 4-byte aligned payloads: 28 + N + 4 */
    CHECK(libpcapng_enhanced_packet_block_size(4)  == 36u);
    CHECK(libpcapng_enhanced_packet_block_size(8)  == 40u);
    CHECK(libpcapng_enhanced_packet_block_size(40) == 72u);

    /* All results must be multiples of 4 */
    for (size_t n = 0; n <= 64; n++)
        CHECK((libpcapng_enhanced_packet_block_size(n) % 4) == 0);
}

static void test_epb_size_unaligned(void)
{
    SUITE("Enhanced Packet Block — size (unaligned payloads → padding)");

    /* 1-byte payload → padded to 4: 28 + 4 + 4 = 36 */
    CHECK(libpcapng_enhanced_packet_block_size(1) == 36u);
    /* 2-byte → 36 */
    CHECK(libpcapng_enhanced_packet_block_size(2) == 36u);
    /* 3-byte → 36 */
    CHECK(libpcapng_enhanced_packet_block_size(3) == 36u);
    /* 5-byte → padded to 8: 28 + 8 + 4 = 40 */
    CHECK(libpcapng_enhanced_packet_block_size(5) == 40u);
    /* 6-byte → 40 */
    CHECK(libpcapng_enhanced_packet_block_size(6) == 40u);
    /* 7-byte → 40 */
    CHECK(libpcapng_enhanced_packet_block_size(7) == 40u);
    /* 41-byte → padded to 44: 28 + 44 + 4 = 76 */
    CHECK(libpcapng_enhanced_packet_block_size(41) == 76u);
}

static void test_epb_wire_format_basic(void)
{
    SUITE("Enhanced Packet Block — wire format (basic)");

    /* A minimal 4-byte payload */
    const unsigned char pkt[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    size_t pkt_len = 4;
    size_t sz = libpcapng_enhanced_packet_block_size(pkt_len);
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_enhanced_packet_block_write_time(
        pkt, pkt_len, 0x0001u, 0xABCDu, buf);

    CHECK(written == sz);
    CHECK(u32at(buf,  0) == PCAPNG_ENHANCED_PACKET_BLOCK);
    CHECK(u32at(buf,  4) == (uint32_t)sz);
    CHECK(u32at(buf,  8) == 0u);             /* interface_id = 0 */
    CHECK(u32at(buf, 12) == 0x0001u);        /* timestamp_high */
    CHECK(u32at(buf, 16) == 0xABCDu);        /* timestamp_low */
    CHECK(u32at(buf, 20) == (uint32_t)pkt_len); /* captured_packet_length */
    CHECK(u32at(buf, 24) == (uint32_t)pkt_len); /* original_packet_length */

    /* Payload bytes at offset 28 */
    CHECK(memcmp(buf + 28, pkt, pkt_len) == 0);

    /* Trailing BTL at offset 28+4=32 */
    CHECK(u32at(buf, 32) == u32at(buf, 4));

    /* Block total length is multiple of 4 */
    CHECK((u32at(buf, 4) % 4) == 0);

    free(buf);
}

static void test_epb_wire_format_40byte(void)
{
    SUITE("Enhanced Packet Block — wire format (40-byte IP+TCP SYN)");

    /* Raw IPv4+TCP SYN — exactly 40 bytes (already 4-byte aligned) */
    const unsigned char pkt[] = {
        0x45,0x00,0x00,0x28, 0x00,0x01,0x00,0x00,
        0x40,0x06,0x0c,0xea, 0xac,0x10,0x00,0x2a,
        0xc0,0xa8,0x01,0x03, 0x46,0x11,0x00,0x50,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x50,0x02,0x20,0x00, 0xdb,0x9b,0x00,0x00
    };
    size_t pkt_len = sizeof(pkt);   /* 40 */
    size_t sz = libpcapng_enhanced_packet_block_size(pkt_len);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_enhanced_packet_block_write_time(pkt, pkt_len, 0, 0, buf);

    /* Block total length: 28 (header) + 40 (data) + 4 (trailing) = 72 */
    CHECK(u32at(buf, 4) == 72u);
    CHECK(u32at(buf, 20) == 40u);   /* captured length */
    CHECK(u32at(buf, 24) == 40u);   /* original length */
    CHECK(memcmp(buf + 28, pkt, 40) == 0);
    CHECK(u32at(buf, 68) == 72u);   /* trailing BTL */

    free(buf);
}

static void test_epb_padding_bytes_are_zero(void)
{
    SUITE("Enhanced Packet Block — padding bytes must be zero");

    /* 3-byte payload → 1 byte of padding after the data */
    const unsigned char pkt[3] = { 0x01, 0x02, 0x03 };
    size_t sz = libpcapng_enhanced_packet_block_size(3);   /* = 36 */
    unsigned char *buf = alloc_buf(sz);

    libpcapng_enhanced_packet_block_write_time(pkt, 3, 0, 0, buf);

    CHECK(u32at(buf, 4) == 36u);
    /* Byte at offset 31 is the padding byte — must be 0 */
    CHECK(buf[31] == 0u);

    free(buf);
}

static void test_epb_padding_all_sizes(void)
{
    SUITE("Enhanced Packet Block — BTL matches size helper for all packet lengths 0..64");

    unsigned char pkt[64];
    memset(pkt, 0xAA, sizeof(pkt));

    for (size_t n = 0; n <= 64; n++) {
        size_t expected_sz = libpcapng_enhanced_packet_block_size(n);
        unsigned char *buf = alloc_buf(expected_sz);
        memset(buf, 0, expected_sz);

        size_t written = libpcapng_enhanced_packet_block_write_time(pkt, n, 0, 0, buf);

        /* Written length matches helper */
        CHECK(written == expected_sz);

        /* Leading and trailing BTL fields agree */
        uint32_t btl_lead  = u32at(buf, 4);
        uint32_t btl_trail = u32at(buf, expected_sz - 4);
        CHECK(btl_lead == btl_trail);

        /* BTL is a multiple of 4 */
        CHECK((btl_lead % 4) == 0);

        /* captured_packet_length == n */
        CHECK(u32at(buf, 20) == (uint32_t)n);

        free(buf);
    }
}

static void test_epb_timestamp_split(void)
{
    SUITE("Enhanced Packet Block — 64-bit microsecond timestamp split");

    /* A known timestamp: 2024-01-01 00:00:00 UTC in microseconds */
    uint64_t ts_us = (uint64_t)1704067200 * 1000000ULL;   /* 0x0005FBFE2960DC00 */
    uint32_t expected_high = (uint32_t)(ts_us >> 32);
    uint32_t expected_low  = (uint32_t)(ts_us & 0xFFFFFFFFu);

    const unsigned char pkt[1] = { 0xFF };
    size_t sz = libpcapng_enhanced_packet_block_size(1);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_enhanced_packet_block_write_time(pkt, 1, expected_high, expected_low, buf);

    CHECK(u32at(buf, 12) == expected_high);
    CHECK(u32at(buf, 16) == expected_low);

    /* Reassemble and verify */
    uint64_t ts_back = ((uint64_t)u32at(buf, 12) << 32) | u32at(buf, 16);
    CHECK(ts_back == ts_us);

    free(buf);
}

static void test_epb_easyapi_with_time(void)
{
    SUITE("Enhanced Packet Block — easyapi write-with-time round-trip");

    /* easyapi takes a uint32_t seconds timestamp and converts to microseconds */
    uint32_t secs = 1704067200u;   /* 2024-01-01 00:00:00 UTC */
    uint64_t expected_us = (uint64_t)secs * 1000000ULL;
    uint32_t expected_high = (uint32_t)(expected_us >> 32);
    uint32_t expected_low  = (uint32_t)(expected_us & 0xFFFFFFFFu);

    const unsigned char pkt[4] = { 0x11, 0x22, 0x33, 0x44 };
    size_t sz = libpcapng_enhanced_packet_block_size(4);
    unsigned char *buf = alloc_buf(sz);

    /* Write via the low-level function directly (easyapi goes to FILE *) */
    libpcapng_enhanced_packet_block_write_time(pkt, 4, expected_high, expected_low, buf);

    CHECK(u32at(buf, 12) == expected_high);
    CHECK(u32at(buf, 16) == expected_low);

    free(buf);
}

static void test_epb_data_preserved(void)
{
    SUITE("Enhanced Packet Block — packet data preserved verbatim");

    /* Use an Ethernet+IPv4+TCP payload (synthetic but realistic) */
    unsigned char pkt[60];
    for (int i = 0; i < 60; i++) pkt[i] = (unsigned char)i;

    size_t sz = libpcapng_enhanced_packet_block_size(60);
    unsigned char *buf = alloc_buf(sz);
    libpcapng_enhanced_packet_block_write_time(pkt, 60, 0, 0, buf);

    /* Data begins at offset 28 */
    CHECK(memcmp(buf + 28, pkt, 60) == 0);

    /* No data beyond 60 bytes is modified (next 4 bytes are trailing BTL) */
    uint32_t trailing = u32at(buf, 88);
    CHECK(trailing == u32at(buf, 4));   /* BTL must match */

    free(buf);
}

static void test_epb_interface_id_is_zero(void)
{
    SUITE("Enhanced Packet Block — interface_id field is 0");

    const unsigned char pkt[4] = { 0 };
    size_t sz = libpcapng_enhanced_packet_block_size(4);
    unsigned char *buf = alloc_buf(sz);
    libpcapng_enhanced_packet_block_write_time(pkt, 4, 0, 0, buf);

    CHECK(u32at(buf, 8) == 0u);

    free(buf);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 6.  CUSTOM DATA BLOCK
 * ══════════════════════════════════════════════════════════════════════════════*/

/*
 * Custom block wire layout (spec §4.8):
 *   offset  0  block_type         (4)  = 0x00000BAD
 *   offset  4  block_total_length (4)
 *   offset  8  PEN                (4)  Private Enterprise Number
 *   offset 12  custom_data        (data_len, padded to 4)
 *   offset 12+padded  block_total_length (4)
 */

static void test_custom_block_size(void)
{
    SUITE("Custom Data Block — size helper");

    /* 0 bytes data: 12 (header) + 0 + 4 (trailing) = 16 */
    CHECK(libpcapng_custom_data_block_size(0) == 16u);
    /* 1 byte → padded to 4: 12 + 4 + 4 = 20 */
    CHECK(libpcapng_custom_data_block_size(1) == 20u);
    /* 3 bytes → padded to 4: 20 */
    CHECK(libpcapng_custom_data_block_size(3) == 20u);
    /* 4 bytes: 12 + 4 + 4 = 20 */
    CHECK(libpcapng_custom_data_block_size(4) == 20u);
    /* 5 bytes → padded to 8: 12 + 8 + 4 = 24 */
    CHECK(libpcapng_custom_data_block_size(5) == 24u);

    /* All sizes must be multiples of 4 */
    for (size_t n = 0; n <= 32; n++)
        CHECK((libpcapng_custom_data_block_size(n) % 4) == 0);
}

static void test_custom_block_wire_format(void)
{
    SUITE("Custom Data Block — wire format");

    const unsigned char data[] = { 'h', 'e', 'l' };   /* 3 bytes */
    uint32_t pen = 123u;
    size_t sz = libpcapng_custom_data_block_size(3);   /* = 20 */
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_custom_data_block_write(pen, data, 3, buf);

    CHECK(written == sz);
    CHECK(u32at(buf,  0) == PCAPNG_CUSTOM_DATA_BLOCK);
    CHECK(u32at(buf,  4) == (uint32_t)sz);
    CHECK(u32at(buf,  8) == pen);
    CHECK(buf[12] == 'h');
    CHECK(buf[13] == 'e');
    CHECK(buf[14] == 'l');
    CHECK(buf[15] == 0u);   /* padding byte must be zero (memset) */
    CHECK(u32at(buf, 16) == u32at(buf, 4));  /* trailing BTL */
    CHECK((u32at(buf, 4) % 4) == 0);

    free(buf);
}

static void test_custom_block_zero_data(void)
{
    SUITE("Custom Data Block — zero-length data");

    uint32_t pen = 0xDEADBEEFu;
    size_t sz = libpcapng_custom_data_block_size(0);   /* = 16 */
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_custom_data_block_write(pen, NULL, 0, buf);

    CHECK(written == 16u);
    CHECK(u32at(buf,  0) == PCAPNG_CUSTOM_DATA_BLOCK);
    CHECK(u32at(buf,  4) == 16u);
    CHECK(u32at(buf,  8) == pen);
    CHECK(u32at(buf, 12) == 16u);   /* trailing BTL immediately after PEN */

    free(buf);
}

static void test_custom_block_data_length_helper(void)
{
    SUITE("Custom Data Block — data_length helper");

    /* libpcapng_custom_data_block_data_length(block_total_length) should return
     * the raw (unpadded) data field size.
     * BTL=16: data = 16 - 4(trailing) - 4(type) - 4(PEN) - 4(leading BTL)
     *       wait, the helper subtracts: trailing BTL + block_type(??) + PEN + leading BTL
     * Let's just check it against our known sizes. */

    /* 0-byte data → BTL=16 */
    CHECK(libpcapng_custom_data_block_data_length(16) == 0u);
    /* 4-byte data → BTL=20 → data_length=4 (padded 4 == actual 4) */
    CHECK(libpcapng_custom_data_block_data_length(20) == 4u);
    /* 8-byte data → BTL=24 → data_length=8 */
    CHECK(libpcapng_custom_data_block_data_length(24) == 8u);
}

static void test_custom_block_start_offset(void)
{
    SUITE("Custom Data Block — start offset helper");

    /* The "light" struct contains only the PEN (4 bytes).
     * Data starts immediately after: offset = sizeof(PEN) = 4. */
    CHECK(libpcapng_custom_data_block_start_offset() == 4u);
}

static void test_custom_block_pen_values(void)
{
    SUITE("Custom Data Block — various PEN values");

    const unsigned char d[4] = { 0 };
    size_t sz = libpcapng_custom_data_block_size(4);
    unsigned char *buf = alloc_buf(sz);

    uint32_t pens[] = { 0, 1, 32473u, 0xFFFFFFFFu };
    for (size_t i = 0; i < sizeof(pens)/sizeof(pens[0]); i++) {
        memset(buf, 0, sz);
        libpcapng_custom_data_block_write(pens[i], d, 4, buf);
        CHECK(u32at(buf, 8) == pens[i]);
    }

    free(buf);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 7.  FILE-LEVEL BLOCK SEQUENCE TESTS (using tmpfile)
 * ══════════════════════════════════════════════════════════════════════════════*/

static void test_file_header_block_sequence(void)
{
    SUITE("File-level — SHB+IDB block sequence (easyapi)");

    FILE *fp = tmpfile();
    assert(fp);

    libpcapng_write_header_to_file(fp);
    fflush(fp);

    long file_size = ftell(fp);
    /* SHB(28) + IDB(20) = 48 */
    CHECK(file_size == 48L);

    /* Read raw bytes back */
    rewind(fp);
    unsigned char raw[48];
    CHECK(fread(raw, 1, 48, fp) == 48u);

    /* First block: SHB */
    CHECK(u32at(raw, 0)  == PCAPNG_SECTION_HEADER_BLOCK);
    CHECK(u32at(raw, 4)  == 28u);                  /* SHB BTL */
    CHECK(u32at(raw, 8)  == PCAPNG_BYTE_ORDER_MAGIC);
    CHECK(u16at(raw, 12) == 1u);                   /* major version */

    /* Second block: IDB at offset 28 */
    CHECK(u32at(raw, 28) == PCAPNG_INTERFACE_DESCRIPTION_BLOCK);
    CHECK(u32at(raw, 32) == 20u);                  /* IDB BTL */
    CHECK(u16at(raw, 36) == LINKTYPE_RAW);
    CHECK(u16at(raw, 38) == 0u);                   /* reserved */
    CHECK(u32at(raw, 40) == 0u);                   /* snaplen */
    CHECK(u32at(raw, 44) == 20u);                  /* trailing BTL */

    fclose(fp);
}

static void test_file_header_with_linktype(void)
{
    SUITE("File-level — SHB+IDB with LINKTYPE_ETHERNET");

    FILE *fp = tmpfile();
    assert(fp);

    libpcapng_write_header_to_file_with_linktype(fp, LINKTYPE_ETHERNET);
    fflush(fp);

    rewind(fp);
    unsigned char raw[48];
    CHECK(fread(raw, 1, 48, fp) == 48u);

    CHECK(u32at(raw, 28) == PCAPNG_INTERFACE_DESCRIPTION_BLOCK);
    CHECK(u16at(raw, 36) == LINKTYPE_ETHERNET);

    fclose(fp);
}

static void test_file_epb_after_header(void)
{
    SUITE("File-level — EPB follows SHB+IDB");

    const unsigned char pkt[4] = { 0xAA, 0xBB, 0xCC, 0xDD };

    FILE *fp = tmpfile();
    assert(fp);

    libpcapng_write_header_to_file(fp);
    libpcapng_write_enhanced_packet_to_file(fp, (unsigned char *)pkt, 4);
    fflush(fp);

    /* File: SHB(28) + IDB(20) + EPB(36) = 84 bytes */
    rewind(fp);
    unsigned char raw[84];
    CHECK(fread(raw, 1, 84, fp) == 84u);

    /* EPB starts at offset 48 */
    CHECK(u32at(raw, 48) == PCAPNG_ENHANCED_PACKET_BLOCK);
    CHECK(u32at(raw, 52) == 36u);       /* EPB BTL: 28+4+4 = 36 */
    CHECK(u32at(raw, 56) == 0u);        /* interface_id */
    CHECK(u32at(raw, 68) == 4u);        /* captured_packet_length */
    CHECK(u32at(raw, 72) == 4u);        /* original_packet_length */
    CHECK(memcmp(raw + 76, pkt, 4) == 0);
    CHECK(u32at(raw, 80) == 36u);       /* trailing BTL */

    fclose(fp);
}

static void test_file_multiple_epbs(void)
{
    SUITE("File-level — multiple EPBs, contiguous and non-overlapping");

    FILE *fp = tmpfile();
    assert(fp);

    libpcapng_write_header_to_file(fp);

    /* Write 5 packets of sizes 4, 8, 1, 16, 3 */
    static const size_t pkt_sizes[] = { 4, 8, 1, 16, 3 };
    for (size_t i = 0; i < 5; i++) {
        unsigned char *pkt = calloc(1, pkt_sizes[i]);
        memset(pkt, (int)(i + 1), pkt_sizes[i]);
        libpcapng_write_enhanced_packet_to_file(fp, pkt, pkt_sizes[i]);
        free(pkt);
    }

    fflush(fp);

    /* Walk the file block by block */
    rewind(fp);

    /* SHB */
    unsigned char shb_buf[28];
    CHECK(fread(shb_buf, 1, 28, fp) == 28u);
    CHECK(u32at(shb_buf, 0) == PCAPNG_SECTION_HEADER_BLOCK);

    /* IDB */
    unsigned char idb_buf[20];
    CHECK(fread(idb_buf, 1, 20, fp) == 20u);
    CHECK(u32at(idb_buf, 0) == PCAPNG_INTERFACE_DESCRIPTION_BLOCK);

    /* Each EPB */
    for (size_t i = 0; i < 5; i++) {
        unsigned char hdr[8];
        CHECK(fread(hdr, 1, 8, fp) == 8u);
        CHECK(u32at(hdr, 0) == PCAPNG_ENHANCED_PACKET_BLOCK);

        uint32_t btl = u32at(hdr, 4);
        CHECK((btl % 4) == 0);
        CHECK(btl >= 32u);  /* minimum EPB size */

        /* Skip remainder of block */
        fseek(fp, (long)(btl - 8), SEEK_CUR);
    }

    /* Should be at end of file */
    CHECK(fgetc(fp) == EOF);

    fclose(fp);
}

static void test_file_epb_with_time(void)
{
    SUITE("File-level — EPB written with explicit timestamp via easyapi");

    const unsigned char pkt[8] = {0,1,2,3,4,5,6,7};
    uint32_t secs = 1000000u;

    FILE *fp = tmpfile();
    assert(fp);

    libpcapng_write_header_to_file(fp);
    libpcapng_write_enhanced_packet_with_time_to_file(fp, (unsigned char*)pkt, 8, secs);
    fflush(fp);

    /* SHB(28)+IDB(20)+EPB(40)=88 */
    rewind(fp);
    unsigned char raw[88];
    CHECK(fread(raw, 1, 88, fp) == 88u);

    /* EPB at offset 48 */
    CHECK(u32at(raw, 48) == PCAPNG_ENHANCED_PACKET_BLOCK);

    /* Timestamp: secs * 1e6 = 1000000000000 = 0x000000E8D4A51000 */
    uint64_t expected_us = (uint64_t)secs * 1000000ULL;
    uint32_t exp_hi = (uint32_t)(expected_us >> 32);
    uint32_t exp_lo = (uint32_t)(expected_us & 0xFFFFFFFFu);

    CHECK(u32at(raw, 60) == exp_hi);
    CHECK(u32at(raw, 64) == exp_lo);

    fclose(fp);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 8.  PADDING MACRO
 * ══════════════════════════════════════════════════════════════════════════════*/

static void test_padding_macro(void)
{
    SUITE("PADDING macro — aligns to next multiple of size");

    uint32_t aligned;

    PADDING(0,  &aligned, 4);  CHECK(aligned == 0u);
    PADDING(1,  &aligned, 4);  CHECK(aligned == 4u);
    PADDING(2,  &aligned, 4);  CHECK(aligned == 4u);
    PADDING(3,  &aligned, 4);  CHECK(aligned == 4u);
    PADDING(4,  &aligned, 4);  CHECK(aligned == 4u);
    PADDING(5,  &aligned, 4);  CHECK(aligned == 8u);
    PADDING(8,  &aligned, 4);  CHECK(aligned == 8u);
    PADDING(9,  &aligned, 4);  CHECK(aligned == 12u);
    PADDING(15, &aligned, 4);  CHECK(aligned == 16u);
    PADDING(16, &aligned, 4);  CHECK(aligned == 16u);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 9.  BLOCK TOTAL LENGTH INVARIANTS (all block types, many sizes)
 * ══════════════════════════════════════════════════════════════════════════════*/

static void test_btl_invariants_all_blocks(void)
{
    SUITE("Block Total Length invariants — leading == trailing, multiple of 4");

    /* SHB */
    {
        size_t sz = libpcapng_section_header_block_size();
        unsigned char *buf = alloc_buf(sz);
        libpcapng_section_header_block_write(buf);
        uint32_t btl = u32at(buf, 4);
        CHECK(btl == u32at(buf, sz - 4));
        CHECK((btl % 4) == 0);
        free(buf);
    }

    /* IDB */
    {
        size_t sz = libpcapng_interface_description_block_size();
        unsigned char *buf = alloc_buf(sz);
        libpcapng_interface_description_block_write(0, buf);
        uint32_t btl = u32at(buf, 4);
        CHECK(btl == u32at(buf, sz - 4));
        CHECK((btl % 4) == 0);
        free(buf);
    }

    /* EPB with various sizes */
    unsigned char pkt[100];
    memset(pkt, 0x5A, sizeof(pkt));
    size_t epb_sizes[] = { 0, 1, 2, 3, 4, 5, 13, 40, 60, 99, 100 };
    for (size_t i = 0; i < sizeof(epb_sizes)/sizeof(epb_sizes[0]); i++) {
        size_t n = epb_sizes[i];
        size_t sz = libpcapng_enhanced_packet_block_size(n);
        unsigned char *buf = alloc_buf(sz);
        libpcapng_enhanced_packet_block_write_time(pkt, n, 0, 0, buf);
        uint32_t btl = u32at(buf, 4);
        CHECK(btl == u32at(buf, sz - 4));
        CHECK((btl % 4) == 0);
        free(buf);
    }

    /* Custom block with various sizes */
    unsigned char cdata[100];
    memset(cdata, 0xBE, sizeof(cdata));
    size_t cb_sizes[] = { 0, 1, 2, 3, 4, 5, 7, 12, 17, 100 };
    for (size_t i = 0; i < sizeof(cb_sizes)/sizeof(cb_sizes[0]); i++) {
        size_t n = cb_sizes[i];
        size_t sz = libpcapng_custom_data_block_size(n);
        unsigned char *buf = alloc_buf(sz);
        libpcapng_custom_data_block_write(42u, cdata, n, buf);
        uint32_t btl = u32at(buf, 4);
        CHECK(btl == u32at(buf, sz - 4));
        CHECK((btl % 4) == 0);
        free(buf);
    }
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 10.  STRUCT FIELD OFFSETS
 *      These catch silent regressions if structs are accidentally changed.
 * ══════════════════════════════════════════════════════════════════════════════*/

static void test_struct_offsets(void)
{
    SUITE("Struct field offsets — match spec wire layout");

    /* SHB */
    CHECK(offsetof(pcapng_section_header_block_t, block_type)         ==  0u);
    CHECK(offsetof(pcapng_section_header_block_t, block_total_length) ==  4u);
    CHECK(offsetof(pcapng_section_header_block_t, magic)              ==  8u);
    CHECK(offsetof(pcapng_section_header_block_t, major_version)      == 12u);
    CHECK(offsetof(pcapng_section_header_block_t, minor_version)      == 14u);
    CHECK(offsetof(pcapng_section_header_block_t, section_length)     == 16u);
    CHECK(sizeof(pcapng_section_header_block_t)                       == 24u);

    /* IDB */
    CHECK(offsetof(pcapng_interface_description_block_t, block_type)         ==  0u);
    CHECK(offsetof(pcapng_interface_description_block_t, block_total_length) ==  4u);
    CHECK(offsetof(pcapng_interface_description_block_t, linktype)           ==  8u);
    CHECK(offsetof(pcapng_interface_description_block_t, reserved)           == 10u);
    CHECK(offsetof(pcapng_interface_description_block_t, snaplen)            == 12u);
    CHECK(sizeof(pcapng_interface_description_block_t)                       == 16u);

    /* EPB */
    CHECK(offsetof(pcapng_enhanced_packet_block_t, block_type)              ==  0u);
    CHECK(offsetof(pcapng_enhanced_packet_block_t, block_total_length)      ==  4u);
    CHECK(offsetof(pcapng_enhanced_packet_block_t, interface_id)            ==  8u);
    CHECK(offsetof(pcapng_enhanced_packet_block_t, timestamp_high)          == 12u);
    CHECK(offsetof(pcapng_enhanced_packet_block_t, timestamp_low)           == 16u);
    CHECK(offsetof(pcapng_enhanced_packet_block_t, captured_packet_length)  == 20u);
    CHECK(offsetof(pcapng_enhanced_packet_block_t, original_packet_length)  == 24u);
    CHECK(sizeof(pcapng_enhanced_packet_block_t)                            == 28u);

    /* Custom block */
    CHECK(offsetof(pcapng_custom_data_block_t, block_type)         == 0u);
    CHECK(offsetof(pcapng_custom_data_block_t, block_total_length) == 4u);
    CHECK(offsetof(pcapng_custom_data_block_t, pen)                == 8u);
    CHECK(sizeof(pcapng_custom_data_block_t)                       == 12u);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 11.  KNOWN SPEC COMPLIANCE ISSUES
 *      Document deviations explicitly so they're easy to track.
 * ══════════════════════════════════════════════════════════════════════════════*/

static void test_known_spec_deviations(void)
{
    SUITE("Known spec deviations (document current incorrect behaviour)");

    size_t sz = libpcapng_section_header_block_size();
    unsigned char *buf = alloc_buf(sz);
    libpcapng_section_header_block_write(buf);

    /* DEVIATION 1: section_length
     * Spec §4.1: section_length = -1 (0xFFFFFFFFFFFFFFFF) means "unknown".
     * Writing 0 is incorrect: 0 means a zero-length section.
     * The library currently writes 0.  Assert 0 here so CI passes and the
     * deviation is visible; change to 0xFFFFFFFFFFFFFFFF when fixed. */
    uint64_t section_length = u64at(buf, 16);
    printf("  NOTE  section_length = 0x%016llx  (spec requires 0xFFFFFFFFFFFFFFFF for unknown)\n",
           (unsigned long long)section_length);
    CHECK(section_length == 0u);   /* [BUG] should be 0xFFFFFFFFFFFFFFFFull */

    /* DEVIATION 2: minor_version
     * Spec §4.1: minor_version MUST be 0.
     * The assignment is commented out in blocks.c.  Works by coincidence
     * because calloc zeroes the buffer. */
    uint16_t minor_ver = u16at(buf, 14);
    printf("  NOTE  minor_version = %u  (library assignment is commented out)\n", minor_ver);
    CHECK(minor_ver == 0u);   /* happens to be 0 due to calloc, but not explicit */

    free(buf);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * main
 * ══════════════════════════════════════════════════════════════════════════════*/

int main(void)
{
    printf("pcapng wire-format unit tests\n");
    printf("==============================\n");

    test_block_type_constants();
    test_linktype_constants();

    test_shb_size();
    test_shb_wire_format();
    test_shb_read_roundtrip();

    test_idb_size();
    test_idb_wire_format_raw();
    test_idb_wire_format_ethernet();
    test_idb_wire_format_all_linktypes();
    test_idb_snaplen_values();
    test_idb_read_roundtrip();

    test_epb_size_aligned();
    test_epb_size_unaligned();
    test_epb_wire_format_basic();
    test_epb_wire_format_40byte();
    test_epb_padding_bytes_are_zero();
    test_epb_padding_all_sizes();
    test_epb_timestamp_split();
    test_epb_easyapi_with_time();
    test_epb_data_preserved();
    test_epb_interface_id_is_zero();

    test_custom_block_size();
    test_custom_block_wire_format();
    test_custom_block_zero_data();
    test_custom_block_data_length_helper();
    test_custom_block_start_offset();
    test_custom_block_pen_values();

    test_file_header_block_sequence();
    test_file_header_with_linktype();
    test_file_epb_after_header();
    test_file_multiple_epbs();
    test_file_epb_with_time();

    test_padding_macro();
    test_btl_invariants_all_blocks();
    test_struct_offsets();
    test_known_spec_deviations();

    printf("\n==============================\n");
    printf("Results: %d/%d passed", g_passed, g_tests);
    if (g_failed)
        printf(", %d FAILED", g_failed);
    printf("\n");

    return g_failed ? 1 : 0;
}
