/*
 * pcapng-spec.c — comprehensive wire-format tests for libpcapng core blocks
 *
 * Tests are checked against RFC-style requirements from:
 *   draft-ietf-opsawg-pcapng (https://ietf-opsawg-wg.github.io/...)
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

    /* DSB secrets type codes — original set */
    CHECK(PCAPNG_TLS_KEY_LOG                        == 0x544c534bu); /* "TLSK" */
    CHECK(PCAPNG_WIREGUARD_KEY_LOG                  == 0x57474b4cu); /* "WGKL" */
    CHECK(PCAPNG_ZIGBEE_NWK_KEY                     == 0x5a4e574bu); /* "ZNWK" */
    CHECK(PCAPNG_ZIGBEE_APS_KEY                     == 0x5a415053u); /* "ZAPS" */

    /* DSB secrets type codes — additional (current spec) */
    CHECK(PCAPNG_SSH_KEY_LOG                        == 0x5353484bu); /* "SSHK" */
    CHECK(PCAPNG_OPC_UA_KEY_LOG                     == 0x55414b4cu); /* "UAKL" */
    CHECK(PCAPNG_ESP_SA                             == 0x45535053u); /* "ESPS" */

    /* NRB record types */
    CHECK(PCAPNG_NRB_RECORD_END                     == 0x0000u);
    CHECK(PCAPNG_NRB_RECORD_IPV4                    == 0x0001u);
    CHECK(PCAPNG_NRB_RECORD_IPV6                    == 0x0002u);
    CHECK(PCAPNG_NRB_RECORD_EUI48                   == 0x0003u);
    CHECK(PCAPNG_NRB_RECORD_EUI64                   == 0x0004u);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 2.  OPTION CONSTANTS
 * ══════════════════════════════════════════════════════════════════════════════*/
static void test_option_constants(void)
{
    SUITE("Option code constants (spec §3.5)");

    CHECK(PCAPNG_OPT_ENDOFOPT       == 0);
    CHECK(PCAPNG_OPT_COMMENT        == 1);

    CHECK(PCAPNG_OPT_SHB_HARDWARE   == 2);
    CHECK(PCAPNG_OPT_SHB_OS         == 3);
    CHECK(PCAPNG_OPT_SHB_USERAPPL   == 4);

    CHECK(PCAPNG_OPT_IDB_NAME       == 2);
    CHECK(PCAPNG_OPT_IDB_TSRESOL    == 9);
    CHECK(PCAPNG_OPT_IDB_FCSLEN     == 13);
    CHECK(PCAPNG_OPT_IDB_TSOFFSET   == 14);
    CHECK(PCAPNG_OPT_IDB_IANA_TZNAME == 18);

    CHECK(PCAPNG_OPT_EPB_FLAGS      == 2);
    CHECK(PCAPNG_OPT_EPB_HASH       == 3);
    CHECK(PCAPNG_OPT_EPB_DROPCOUNT  == 4);
    CHECK(PCAPNG_OPT_EPB_PACKETID   == 5);
    CHECK(PCAPNG_OPT_EPB_QUEUE      == 6);
    CHECK(PCAPNG_OPT_EPB_VERDICT    == 7);
    CHECK(PCAPNG_OPT_EPB_PROCESSID  == 8);

    CHECK(PCAPNG_OPT_ISB_STARTTIME  == 2);
    CHECK(PCAPNG_OPT_ISB_IFRECV     == 4);
    CHECK(PCAPNG_OPT_ISB_USRDELIV   == 8);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 3.  EPB FLAGS BIT DEFINITIONS
 * ══════════════════════════════════════════════════════════════════════════════*/
static void test_epb_flag_constants(void)
{
    SUITE("EPB flags word bit definitions (spec §4.3.1)");

    /* Direction bits 0-1 */
    CHECK(PCAPNG_EPB_FLAG_DIR_MASK        == 0x00000003u);
    CHECK(PCAPNG_EPB_FLAG_DIR_UNKNOWN     == 0x00000000u);
    CHECK(PCAPNG_EPB_FLAG_DIR_INBOUND     == 0x00000001u);
    CHECK(PCAPNG_EPB_FLAG_DIR_OUTBOUND    == 0x00000002u);

    /* Direction values are mutually exclusive within mask */
    CHECK((PCAPNG_EPB_FLAG_DIR_INBOUND  & PCAPNG_EPB_FLAG_DIR_MASK) == PCAPNG_EPB_FLAG_DIR_INBOUND);
    CHECK((PCAPNG_EPB_FLAG_DIR_OUTBOUND & PCAPNG_EPB_FLAG_DIR_MASK) == PCAPNG_EPB_FLAG_DIR_OUTBOUND);

    /* Reception type bits 2-4 */
    CHECK(PCAPNG_EPB_FLAG_RECV_MASK       == 0x0000001Cu);
    CHECK(PCAPNG_EPB_FLAG_RECV_UNSPEC     == 0x00000000u);
    CHECK(PCAPNG_EPB_FLAG_RECV_UNICAST    == 0x00000004u);
    CHECK(PCAPNG_EPB_FLAG_RECV_MULTICAST  == 0x00000008u);
    CHECK(PCAPNG_EPB_FLAG_RECV_BROADCAST  == 0x0000000Cu);
    CHECK(PCAPNG_EPB_FLAG_RECV_PROMISC    == 0x00000010u);

    /* FCS length field bits 5-8 */
    CHECK(PCAPNG_EPB_FLAG_FCS_LEN_MASK    == 0x000001E0u);
    CHECK(PCAPNG_EPB_FLAG_FCS_LEN_SHIFT   == 5);

    /* FCS value 4 encodes to bits 7-6: (4 << 5) = 0x80 */
    CHECK(((4u << PCAPNG_EPB_FLAG_FCS_LEN_SHIFT) & PCAPNG_EPB_FLAG_FCS_LEN_MASK) == 0x00000080u);

    /* Checksum / offload flags bits 9-11 */
    CHECK(PCAPNG_EPB_FLAG_CKSUM_NOT_READY == 0x00000200u);
    CHECK(PCAPNG_EPB_FLAG_CKSUM_VALID     == 0x00000400u);
    CHECK(PCAPNG_EPB_FLAG_TCP_SEG_OFFLOAD == 0x00000800u);

    /* Link-layer error bits 16-31 */
    CHECK(PCAPNG_EPB_FLAG_LL_ERR_SYMBOL   == 0x80000000u);
    CHECK(PCAPNG_EPB_FLAG_LL_ERR_PREAMBLE == 0x40000000u);
    CHECK(PCAPNG_EPB_FLAG_LL_ERR_SFD      == 0x20000000u);
    CHECK(PCAPNG_EPB_FLAG_LL_ERR_UNALIGN  == 0x10000000u);
    CHECK(PCAPNG_EPB_FLAG_LL_ERR_IFG      == 0x08000000u);
    CHECK(PCAPNG_EPB_FLAG_LL_ERR_SHORT    == 0x04000000u);
    CHECK(PCAPNG_EPB_FLAG_LL_ERR_LONG     == 0x02000000u);
    CHECK(PCAPNG_EPB_FLAG_LL_ERR_CRC      == 0x01000000u);

    /* No overlap between direction / recv / fcs / flags */
    CHECK((PCAPNG_EPB_FLAG_DIR_MASK & PCAPNG_EPB_FLAG_RECV_MASK)    == 0u);
    CHECK((PCAPNG_EPB_FLAG_RECV_MASK & PCAPNG_EPB_FLAG_FCS_LEN_MASK)== 0u);
    CHECK((PCAPNG_EPB_FLAG_FCS_LEN_MASK & PCAPNG_EPB_FLAG_CKSUM_NOT_READY) == 0u);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 4.  LINK TYPE CONSTANTS (selected IANA values)
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
 * 5.  OPTIONS TLV ENCODING
 * ══════════════════════════════════════════════════════════════════════════════*/

static void test_options_size_empty(void)
{
    SUITE("Options — size of zero-option list is 4 (endofopt only)");

    CHECK(libpcapng_options_size(NULL, 0) == 4u);
}

static void test_options_size_aligned(void)
{
    SUITE("Options — size with aligned values");

    /* One 4-byte option: type(2)+len(2)+value(4) = 8, plus endofopt(4) = 12 */
    uint32_t val = 42u;
    pcapng_option_t opts[] = { { PCAPNG_OPT_EPB_QUEUE, 4, &val } };
    CHECK(libpcapng_options_size(opts, 1) == 12u);

    /* One 8-byte option: 4+8 = 12, plus endofopt(4) = 16 */
    uint64_t val2 = 0;
    pcapng_option_t opts2[] = { { PCAPNG_OPT_ISB_IFRECV, 8, &val2 } };
    CHECK(libpcapng_options_size(opts2, 1) == 16u);
}

static void test_options_size_unaligned(void)
{
    SUITE("Options — size with values needing padding");

    /* 1-byte value padded to 4: type(2)+len(2)+val_padded(4) = 8 + endofopt(4) = 12 */
    uint8_t v = 6;
    pcapng_option_t opts[] = { { PCAPNG_OPT_IDB_TSRESOL, 1, &v } };
    CHECK(libpcapng_options_size(opts, 1) == 12u);

    /* 3-byte value padded to 4: same 12 */
    unsigned char v3[3] = {0};
    pcapng_option_t opts3[] = { { PCAPNG_OPT_COMMENT, 3, v3 } };
    CHECK(libpcapng_options_size(opts3, 1) == 12u);

    /* 5-byte value padded to 8: 4+8 = 12 + endofopt(4) = 16 */
    unsigned char v5[5] = {0};
    pcapng_option_t opts5[] = { { PCAPNG_OPT_COMMENT, 5, v5 } };
    CHECK(libpcapng_options_size(opts5, 1) == 16u);
}

static void test_options_write_single_u8(void)
{
    SUITE("Options — write single 1-byte option (if_tsresol)");

    /*
     * Wire layout expected:
     *   [0..1]  type  = 9  (PCAPNG_OPT_IDB_TSRESOL)
     *   [2..3]  len   = 1
     *   [4]     value = 6  (microseconds: 10^-6)
     *   [5..7]  padding = 0
     *   [8..11] opt_endofopt = 0
     */
    uint8_t tsresol = 6;
    pcapng_option_t opts[] = { { PCAPNG_OPT_IDB_TSRESOL, 1, &tsresol } };
    size_t sz = libpcapng_options_size(opts, 1);
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_options_write(opts, 1, buf);

    CHECK(written == sz);
    CHECK(written == 12u);
    CHECK(u16at(buf, 0) == PCAPNG_OPT_IDB_TSRESOL);
    CHECK(u16at(buf, 2) == 1u);
    CHECK(buf[4] == 6u);
    CHECK(buf[5] == 0u);    /* padding */
    CHECK(buf[6] == 0u);
    CHECK(buf[7] == 0u);
    CHECK(u32at(buf, 8) == 0u);   /* opt_endofopt */

    free(buf);
}

static void test_options_write_single_u32(void)
{
    SUITE("Options — write single 4-byte option (epb_queue)");

    uint32_t queue = 7u;
    pcapng_option_t opts[] = { { PCAPNG_OPT_EPB_QUEUE, 4, &queue } };
    size_t sz = libpcapng_options_size(opts, 1);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_options_write(opts, 1, buf);

    CHECK(u16at(buf, 0) == PCAPNG_OPT_EPB_QUEUE);
    CHECK(u16at(buf, 2) == 4u);
    CHECK(u32at(buf, 4) == queue);
    CHECK(u32at(buf, 8) == 0u);   /* opt_endofopt */

    free(buf);
}

static void test_options_write_multiple(void)
{
    SUITE("Options — write multiple options");

    /*
     * Two options:
     *   isb_ifrecv (u64): type=4, len=8
     *   isb_ifdrop (u64): type=5, len=8
     * Each: 4+8 = 12 bytes; two = 24; plus endofopt(4) = 28
     */
    uint64_t recv = 1000u, drop = 42u;
    pcapng_option_t opts[] = {
        { PCAPNG_OPT_ISB_IFRECV, 8, &recv },
        { PCAPNG_OPT_ISB_IFDROP, 8, &drop },
    };
    size_t sz = libpcapng_options_size(opts, 2);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_options_write(opts, 2, buf);

    CHECK(sz == 28u);
    CHECK(u16at(buf,  0) == PCAPNG_OPT_ISB_IFRECV);
    CHECK(u16at(buf,  2) == 8u);
    CHECK(u32at(buf, 24) == 0u);   /* opt_endofopt */

    free(buf);
}

static void test_options_write_string(void)
{
    SUITE("Options — write string option (shb_userappl)");

    const char *appl = "libpcapng";
    uint16_t appl_len = (uint16_t)strlen(appl);
    pcapng_option_t opts[] = { { PCAPNG_OPT_SHB_USERAPPL, appl_len, appl } };
    size_t sz = libpcapng_options_size(opts, 1);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_options_write(opts, 1, buf);

    CHECK(u16at(buf, 0) == PCAPNG_OPT_SHB_USERAPPL);
    CHECK(u16at(buf, 2) == appl_len);
    CHECK(memcmp(buf + 4, appl, appl_len) == 0);
    /* padding bytes zero */
    for (size_t i = appl_len; i < pad4(appl_len); i++)
        CHECK(buf[4 + i] == 0u);

    free(buf);
}

static void test_options_endofopt_always_present(void)
{
    SUITE("Options — opt_endofopt (type=0,len=0) always at end");

    /* Even with no user options, write produces opt_endofopt */
    unsigned char buf[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    libpcapng_options_write(NULL, 0, buf);
    CHECK(u32at(buf, 0) == 0u);  /* all-zero = endofopt */

    /* With one option, endofopt follows */
    uint32_t q = 1u;
    pcapng_option_t opts[] = { { PCAPNG_OPT_EPB_QUEUE, 4, &q } };
    size_t sz = libpcapng_options_size(opts, 1);
    unsigned char *buf2 = alloc_buf(sz);
    libpcapng_options_write(opts, 1, buf2);
    CHECK(u32at(buf2, sz - 4) == 0u);  /* last 4 bytes = endofopt */
    free(buf2);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 6.  SECTION HEADER BLOCK
 * ══════════════════════════════════════════════════════════════════════════════*/

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

    CHECK(written == sz);
    CHECK(u32at(buf,  0) == PCAPNG_SECTION_HEADER_BLOCK);
    CHECK(u32at(buf,  4) == (uint32_t)sz);
    CHECK(u32at(buf,  8) == 0x1A2B3C4Du);
    CHECK(u16at(buf, 12) == 1u);
    CHECK(u16at(buf, 14) == 0u);
    /* spec §4.1: -1 (0xFFFFFFFFFFFFFFFF) = unknown section length */
    CHECK(u64at(buf, 16) == 0xFFFFFFFFFFFFFFFFull);
    CHECK(u32at(buf, 24) == u32at(buf, 4));
    CHECK((u32at(buf, 4) % 4) == 0);

    free(buf);
}

static void test_shb_read_roundtrip(void)
{
    SUITE("Section Header Block — read round-trip");

    size_t sz = libpcapng_section_header_block_size();
    unsigned char *buf = alloc_buf(sz);
    libpcapng_section_header_block_write(buf);

    pcapng_section_header_block_light_t *shb =
        libpcapng_section_header_block_read(buf, sz);

    CHECK(shb != NULL);
    CHECK(shb->magic         == PCAPNG_BYTE_ORDER_MAGIC);
    CHECK(shb->major_version == PCAPNG_VERSION_MAJOR);
    CHECK(shb->minor_version == PCAPNG_VERSION_MINOR);
    CHECK(shb->section_length == (uint64_t)-1);

    free(shb);
    free(buf);
}

static void test_shb_with_options(void)
{
    SUITE("Section Header Block — wire format with options");

    const char *appl = "test";
    uint16_t appl_len = 4;
    pcapng_option_t opts[] = { { PCAPNG_OPT_SHB_USERAPPL, appl_len, appl } };
    size_t sz = libpcapng_section_header_block_size_with_options(opts, 1);
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_section_header_block_write_with_options(opts, 1, buf);

    CHECK(written == sz);
    CHECK(u32at(buf, 0) == PCAPNG_SECTION_HEADER_BLOCK);
    CHECK(u32at(buf, 4) == (uint32_t)sz);
    CHECK(u64at(buf, 16) == 0xFFFFFFFFFFFFFFFFull);  /* section_length = -1 */

    /* Options start at offset 24 (sizeof SHB struct, before trailing BTL) */
    CHECK(u16at(buf, 24) == PCAPNG_OPT_SHB_USERAPPL);
    CHECK(u16at(buf, 26) == appl_len);
    CHECK(memcmp(buf + 28, appl, appl_len) == 0);

    /* Trailing BTL */
    CHECK(u32at(buf, sz - 4) == (uint32_t)sz);

    free(buf);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 7.  INTERFACE DESCRIPTION BLOCK
 * ══════════════════════════════════════════════════════════════════════════════*/

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
    CHECK(u16at(buf,  8) == LINKTYPE_RAW);
    CHECK(u16at(buf, 10) == 0u);
    CHECK(u32at(buf, 12) == 65535u);
    CHECK(u32at(buf, 16) == u32at(buf, 4));
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
    CHECK(u32at(buf, 12) == 0u);
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
        CHECK(u16at(buf, 10) == 0u);
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

    free(idb);
    free(buf);
}

static void test_idb_with_tsresol_option(void)
{
    SUITE("Interface Description Block — if_tsresol option");

    /*
     * if_tsresol = 9 means nanosecond resolution (10^-9).
     * MSB=0, remaining bits = 9.
     */
    uint8_t tsresol = 9;
    pcapng_option_t opts[] = { { PCAPNG_OPT_IDB_TSRESOL, 1, &tsresol } };
    size_t sz = libpcapng_interface_description_block_size_with_options(opts, 1);
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_interface_description_block_write_with_options(
        1500, LINKTYPE_ETHERNET, opts, 1, buf);

    CHECK(written == sz);
    CHECK(u32at(buf, 0) == PCAPNG_INTERFACE_DESCRIPTION_BLOCK);
    /* options start after fixed IDB body (offset 16) */
    CHECK(u16at(buf, 16) == PCAPNG_OPT_IDB_TSRESOL);
    CHECK(u16at(buf, 18) == 1u);
    CHECK(buf[20] == 9u);
    CHECK(u32at(buf, sz - 4) == (uint32_t)sz);  /* trailing BTL */

    free(buf);
}

static void test_idb_with_multiple_options(void)
{
    SUITE("Interface Description Block — multiple options");

    uint8_t tsresol = 6;
    const char *name = "eth0";
    pcapng_option_t opts[] = {
        { PCAPNG_OPT_IDB_NAME,   4,  name     },
        { PCAPNG_OPT_IDB_TSRESOL, 1, &tsresol },
    };
    size_t sz = libpcapng_interface_description_block_size_with_options(opts, 2);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_interface_description_block_write_with_options(0, LINKTYPE_ETHERNET, opts, 2, buf);

    CHECK((sz % 4) == 0);
    CHECK(u32at(buf, sz - 4) == (uint32_t)sz);
    CHECK(u16at(buf, 16) == PCAPNG_OPT_IDB_NAME);

    free(buf);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 8.  ENHANCED PACKET BLOCK
 * ══════════════════════════════════════════════════════════════════════════════*/

static void test_epb_size_aligned(void)
{
    SUITE("Enhanced Packet Block — size (aligned payloads)");

    CHECK(libpcapng_enhanced_packet_block_size(0) == 32u);
    CHECK(libpcapng_enhanced_packet_block_size(4)  == 36u);
    CHECK(libpcapng_enhanced_packet_block_size(8)  == 40u);
    CHECK(libpcapng_enhanced_packet_block_size(40) == 72u);

    for (size_t n = 0; n <= 64; n++)
        CHECK((libpcapng_enhanced_packet_block_size(n) % 4) == 0);
}

static void test_epb_size_unaligned(void)
{
    SUITE("Enhanced Packet Block — size (unaligned payloads → padding)");

    CHECK(libpcapng_enhanced_packet_block_size(1) == 36u);
    CHECK(libpcapng_enhanced_packet_block_size(2) == 36u);
    CHECK(libpcapng_enhanced_packet_block_size(3) == 36u);
    CHECK(libpcapng_enhanced_packet_block_size(5) == 40u);
    CHECK(libpcapng_enhanced_packet_block_size(6) == 40u);
    CHECK(libpcapng_enhanced_packet_block_size(7) == 40u);
    CHECK(libpcapng_enhanced_packet_block_size(41) == 76u);
}

static void test_epb_wire_format_basic(void)
{
    SUITE("Enhanced Packet Block — wire format (basic)");

    const unsigned char pkt[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    size_t pkt_len = 4;
    size_t sz = libpcapng_enhanced_packet_block_size(pkt_len);
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_enhanced_packet_block_write_time(
        pkt, pkt_len, 0x0001u, 0xABCDu, buf);

    CHECK(written == sz);
    CHECK(u32at(buf,  0) == PCAPNG_ENHANCED_PACKET_BLOCK);
    CHECK(u32at(buf,  4) == (uint32_t)sz);
    CHECK(u32at(buf,  8) == 0u);
    CHECK(u32at(buf, 12) == 0x0001u);
    CHECK(u32at(buf, 16) == 0xABCDu);
    CHECK(u32at(buf, 20) == (uint32_t)pkt_len);
    CHECK(u32at(buf, 24) == (uint32_t)pkt_len);
    CHECK(memcmp(buf + 28, pkt, pkt_len) == 0);
    CHECK(u32at(buf, 32) == u32at(buf, 4));
    CHECK((u32at(buf, 4) % 4) == 0);

    free(buf);
}

static void test_epb_wire_format_40byte(void)
{
    SUITE("Enhanced Packet Block — wire format (40-byte IP+TCP SYN)");

    const unsigned char pkt[] = {
        0x45,0x00,0x00,0x28, 0x00,0x01,0x00,0x00,
        0x40,0x06,0x0c,0xea, 0xac,0x10,0x00,0x2a,
        0xc0,0xa8,0x01,0x03, 0x46,0x11,0x00,0x50,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x50,0x02,0x20,0x00, 0xdb,0x9b,0x00,0x00
    };
    size_t pkt_len = sizeof(pkt);
    size_t sz = libpcapng_enhanced_packet_block_size(pkt_len);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_enhanced_packet_block_write_time(pkt, pkt_len, 0, 0, buf);

    CHECK(u32at(buf, 4) == 72u);
    CHECK(u32at(buf, 20) == 40u);
    CHECK(u32at(buf, 24) == 40u);
    CHECK(memcmp(buf + 28, pkt, 40) == 0);
    CHECK(u32at(buf, 68) == 72u);

    free(buf);
}

static void test_epb_padding_bytes_are_zero(void)
{
    SUITE("Enhanced Packet Block — padding bytes must be zero");

    const unsigned char pkt[3] = { 0x01, 0x02, 0x03 };
    size_t sz = libpcapng_enhanced_packet_block_size(3);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_enhanced_packet_block_write_time(pkt, 3, 0, 0, buf);

    CHECK(u32at(buf, 4) == 36u);
    CHECK(buf[31] == 0u);  /* padding byte */

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

        size_t written = libpcapng_enhanced_packet_block_write_time(pkt, n, 0, 0, buf);

        CHECK(written == expected_sz);
        CHECK(u32at(buf, 4) == u32at(buf, expected_sz - 4));
        CHECK((u32at(buf, 4) % 4) == 0);
        CHECK(u32at(buf, 20) == (uint32_t)n);

        free(buf);
    }
}

static void test_epb_timestamp_split(void)
{
    SUITE("Enhanced Packet Block — 64-bit microsecond timestamp split");

    uint64_t ts_us = (uint64_t)1704067200 * 1000000ULL;
    uint32_t expected_high = (uint32_t)(ts_us >> 32);
    uint32_t expected_low  = (uint32_t)(ts_us & 0xFFFFFFFFu);

    const unsigned char pkt[1] = { 0xFF };
    size_t sz = libpcapng_enhanced_packet_block_size(1);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_enhanced_packet_block_write_time(pkt, 1, expected_high, expected_low, buf);

    CHECK(u32at(buf, 12) == expected_high);
    CHECK(u32at(buf, 16) == expected_low);

    uint64_t ts_back = ((uint64_t)u32at(buf, 12) << 32) | u32at(buf, 16);
    CHECK(ts_back == ts_us);

    free(buf);
}

static void test_epb_data_preserved(void)
{
    SUITE("Enhanced Packet Block — packet data preserved verbatim");

    unsigned char pkt[60];
    for (int i = 0; i < 60; i++) pkt[i] = (unsigned char)i;

    size_t sz = libpcapng_enhanced_packet_block_size(60);
    unsigned char *buf = alloc_buf(sz);
    libpcapng_enhanced_packet_block_write_time(pkt, 60, 0, 0, buf);

    CHECK(memcmp(buf + 28, pkt, 60) == 0);
    CHECK(u32at(buf, 88) == u32at(buf, 4));

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

static void test_epb_nonzero_interface_id(void)
{
    SUITE("Enhanced Packet Block — non-zero interface_id (multi-interface)");

    const unsigned char pkt[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
    size_t sz = libpcapng_enhanced_packet_block_size_with_options(4, NULL, 0);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_enhanced_packet_block_write_full(
        pkt, 4, 4, 2,   /* captured=4, original=4, interface_id=2 */
        0, 0, NULL, 0, buf);

    CHECK(u32at(buf, 0) == PCAPNG_ENHANCED_PACKET_BLOCK);
    CHECK(u32at(buf, 8) == 2u);   /* interface_id = 2 */
    CHECK(u32at(buf, 20) == 4u);  /* captured_packet_length */
    CHECK(u32at(buf, 24) == 4u);  /* original_packet_length */

    free(buf);
}

static void test_epb_truncated_packet(void)
{
    SUITE("Enhanced Packet Block — truncation: captured < original");

    /* A 1500-byte packet truncated to 64 bytes */
    unsigned char pkt[64];
    memset(pkt, 0x5A, sizeof(pkt));

    size_t sz = libpcapng_enhanced_packet_block_size_with_options(64, NULL, 0);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_enhanced_packet_block_write_full(
        pkt, 64, 1500, 0,   /* captured=64, original=1500 */
        0, 0, NULL, 0, buf);

    CHECK(u32at(buf, 20) == 64u);    /* captured_packet_length = 64 */
    CHECK(u32at(buf, 24) == 1500u);  /* original_packet_length = 1500 */
    CHECK(memcmp(buf + 28, pkt, 64) == 0);

    free(buf);
}

static void test_epb_with_flags_option(void)
{
    SUITE("Enhanced Packet Block — epb_flags option wire encoding");

    /*
     * flags = inbound unicast:
     *   DIR_INBOUND (bit 0) | RECV_UNICAST (bit 2) = 0x00000005
     */
    uint32_t flags = PCAPNG_EPB_FLAG_DIR_INBOUND | PCAPNG_EPB_FLAG_RECV_UNICAST;
    pcapng_option_t opts[] = { { PCAPNG_OPT_EPB_FLAGS, 4, &flags } };

    const unsigned char pkt[4] = { 0 };
    size_t sz = libpcapng_enhanced_packet_block_size_with_options(4, opts, 1);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_enhanced_packet_block_write_full(
        pkt, 4, 4, 0, 0, 0, opts, 1, buf);

    /* EPB fixed body = 28 bytes; packet data+padding = 4 bytes; options start at 32 */
    CHECK(u16at(buf, 32) == PCAPNG_OPT_EPB_FLAGS);
    CHECK(u16at(buf, 34) == 4u);
    CHECK(u32at(buf, 36) == flags);
    CHECK(u32at(buf, sz - 4) == (uint32_t)sz);  /* trailing BTL */

    free(buf);
}

static void test_epb_with_dropcount_option(void)
{
    SUITE("Enhanced Packet Block — epb_dropcount option");

    uint64_t drops = 42u;
    pcapng_option_t opts[] = { { PCAPNG_OPT_EPB_DROPCOUNT, 8, &drops } };

    const unsigned char pkt[4] = { 0 };
    size_t sz = libpcapng_enhanced_packet_block_size_with_options(4, opts, 1);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_enhanced_packet_block_write_full(
        pkt, 4, 4, 0, 0, 0, opts, 1, buf);

    CHECK(u16at(buf, 32) == PCAPNG_OPT_EPB_DROPCOUNT);
    CHECK(u16at(buf, 34) == 8u);
    CHECK(u32at(buf, sz - 4) == (uint32_t)sz);

    free(buf);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 9.  SIMPLE PACKET BLOCK
 * ══════════════════════════════════════════════════════════════════════════════*/

/*
 * SPB wire layout (spec §4.4):
 *   offset  0  block_type              (4) = 0x00000003
 *   offset  4  block_total_length      (4)
 *   offset  8  original_packet_length  (4)
 *   offset 12  packet_data             (captured, padded to 4)
 *   offset 12+pad  block_total_length  (4)
 *
 * SPB has NO options (spec §4.4 explicitly).
 * SPB requires an IDB in the section (implicitly interface 0).
 */

static void test_spb_size(void)
{
    SUITE("Simple Packet Block — size");

    /* 0-byte: 12 + 0 + 4 = 16 */
    CHECK(libpcapng_simple_packet_block_size(0) == 16u);
    /* 4-byte: 12 + 4 + 4 = 20 */
    CHECK(libpcapng_simple_packet_block_size(4) == 20u);
    /* 1-byte padded to 4: 12 + 4 + 4 = 20 */
    CHECK(libpcapng_simple_packet_block_size(1) == 20u);
    /* 5-byte padded to 8: 12 + 8 + 4 = 24 */
    CHECK(libpcapng_simple_packet_block_size(5) == 24u);

    for (size_t n = 0; n <= 64; n++)
        CHECK((libpcapng_simple_packet_block_size(n) % 4) == 0);
}

static void test_spb_wire_format(void)
{
    SUITE("Simple Packet Block — wire format");

    const unsigned char pkt[4] = { 0x11, 0x22, 0x33, 0x44 };
    size_t sz = libpcapng_simple_packet_block_size(4);
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_simple_packet_block_write(pkt, 4, 4, buf);

    CHECK(written == sz);
    CHECK(u32at(buf,  0) == PCAPNG_SIMPLE_PACKET_BLOCK);
    CHECK(u32at(buf,  4) == (uint32_t)sz);
    CHECK(u32at(buf,  8) == 4u);              /* original_packet_length */
    CHECK(memcmp(buf + 12, pkt, 4) == 0);
    CHECK(u32at(buf, 16) == u32at(buf, 4));   /* trailing BTL */

    free(buf);
}

static void test_spb_truncation(void)
{
    SUITE("Simple Packet Block — original_length > captured (truncation)");

    unsigned char pkt[64];
    memset(pkt, 0xCC, sizeof(pkt));

    size_t sz = libpcapng_simple_packet_block_size(64);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_simple_packet_block_write(pkt, 64, 1514, buf);

    CHECK(u32at(buf, 8) == 1514u);            /* original_packet_length = 1514 */
    CHECK(u32at(buf, 4) == (uint32_t)sz);     /* BTL reflects actual captured bytes */
    CHECK(memcmp(buf + 12, pkt, 64) == 0);

    free(buf);
}

static void test_spb_padding_zero(void)
{
    SUITE("Simple Packet Block — padding bytes are zero");

    const unsigned char pkt[3] = { 0xAA, 0xBB, 0xCC };
    size_t sz = libpcapng_simple_packet_block_size(3);   /* = 20 */
    unsigned char *buf = alloc_buf(sz);

    libpcapng_simple_packet_block_write(pkt, 3, 3, buf);

    CHECK(buf[15] == 0u);  /* padding byte at offset 15 */

    free(buf);
}

static void test_spb_struct_offsets(void)
{
    SUITE("Simple Packet Block — struct field offsets");

    CHECK(offsetof(pcapng_simple_packet_block_t, block_type)             == 0u);
    CHECK(offsetof(pcapng_simple_packet_block_t, block_total_length)     == 4u);
    CHECK(offsetof(pcapng_simple_packet_block_t, original_packet_length) == 8u);
    CHECK(sizeof(pcapng_simple_packet_block_t)                           == 12u);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 10. NAME RESOLUTION BLOCK
 * ══════════════════════════════════════════════════════════════════════════════*/

/*
 * NRB wire layout (spec §4.5):
 *   offset  0  block_type         (4) = 0x00000004
 *   offset  4  block_total_length (4)
 *   offset  8  NRB records        (variable — zero or more)
 *   ...        options            (optional)
 *   ...        block_total_length (4)
 *
 * Each NRB record:
 *   [record_type:2][record_length:2][addr bytes][name NUL-terminated][padding]
 * Terminated by nrb_record_end (type=0, length=0).
 */

static void test_nrb_record_size(void)
{
    SUITE("NRB record — size helper");

    /* IPv4 (4-byte addr) + "host.local\0" (11 bytes): data=15, padded=16; +4 header = 20 */
    size_t name_len = strlen("host.local");
    size_t sz = libpcapng_nrb_record_size(4, name_len);
    CHECK(sz == 20u);   /* 4 header + pad4(4+10+1)=pad4(15)=16 */

    /* IPv6 (16-byte addr) + "a\0" (2 bytes): data=18, padded=20; +4 = 24 */
    CHECK(libpcapng_nrb_record_size(16, 1) == 24u);

    /* end record: addr=0, name=0 → data=1, padded=4; +4 = 8 */
    CHECK(libpcapng_nrb_record_size(0, 0) == 8u);
}

static void test_nrb_record_ipv4_write(void)
{
    SUITE("NRB record — IPv4 record wire format");

    const unsigned char addr[4] = { 192, 168, 1, 1 };
    const char *name = "gw.local";
    size_t name_len = strlen(name);
    size_t rec_sz = libpcapng_nrb_record_size(4, name_len);
    unsigned char *buf = alloc_buf(rec_sz);

    size_t written = libpcapng_nrb_record_write(
        PCAPNG_NRB_RECORD_IPV4, addr, 4, name, buf);

    CHECK(written == rec_sz);
    CHECK(u16at(buf, 0) == PCAPNG_NRB_RECORD_IPV4);
    CHECK(u16at(buf, 2) == (uint16_t)(4 + name_len + 1));  /* addr + name + NUL */
    CHECK(memcmp(buf + 4, addr, 4) == 0);
    CHECK(memcmp(buf + 8, name, name_len) == 0);
    CHECK(buf[8 + name_len] == 0u);  /* NUL terminator */

    free(buf);
}

static void test_nrb_record_ipv6_write(void)
{
    SUITE("NRB record — IPv6 record wire format");

    const unsigned char addr[16] = {
        0x20,0x01,0x0d,0xb8, 0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01
    };
    const char *name = "v6host";
    size_t name_len = strlen(name);
    size_t rec_sz = libpcapng_nrb_record_size(16, name_len);
    unsigned char *buf = alloc_buf(rec_sz);

    size_t written = libpcapng_nrb_record_write(
        PCAPNG_NRB_RECORD_IPV6, addr, 16, name, buf);

    CHECK(written == rec_sz);
    CHECK(u16at(buf, 0) == PCAPNG_NRB_RECORD_IPV6);
    CHECK(memcmp(buf + 4, addr, 16) == 0);

    free(buf);
}

static void test_nrb_record_end_write(void)
{
    SUITE("NRB record — nrb_record_end wire format");

    size_t rec_sz = libpcapng_nrb_record_size(0, 0);
    unsigned char *buf = alloc_buf(rec_sz);

    size_t written = libpcapng_nrb_record_write(
        PCAPNG_NRB_RECORD_END, NULL, 0, NULL, buf);

    /* record_type=0, record_length=1 (NUL terminator), padded to 4 → 8 bytes */
    CHECK(written == rec_sz);
    CHECK(u16at(buf, 0) == PCAPNG_NRB_RECORD_END);

    free(buf);
}

static void test_nrb_record_eui48_type(void)
{
    SUITE("NRB record — EUI-48 record type (new in current spec)");

    /* EUI-48 is a 6-byte MAC address */
    const unsigned char mac[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const char *name = "printer";
    size_t rec_sz = libpcapng_nrb_record_size(6, strlen(name));
    unsigned char *buf = alloc_buf(rec_sz);

    libpcapng_nrb_record_write(PCAPNG_NRB_RECORD_EUI48, mac, 6, name, buf);

    CHECK(u16at(buf, 0) == PCAPNG_NRB_RECORD_EUI48);
    CHECK(memcmp(buf + 4, mac, 6) == 0);

    free(buf);
}

static void test_nrb_record_eui64_type(void)
{
    SUITE("NRB record — EUI-64 record type (new in current spec)");

    const unsigned char eui64[8] = { 0x02,0x00,0x5E,0xFF,0xFE,0x00,0x00,0x01 };
    const char *name = "iot-node";
    size_t rec_sz = libpcapng_nrb_record_size(8, strlen(name));
    unsigned char *buf = alloc_buf(rec_sz);

    libpcapng_nrb_record_write(PCAPNG_NRB_RECORD_EUI64, eui64, 8, name, buf);

    CHECK(u16at(buf, 0) == PCAPNG_NRB_RECORD_EUI64);
    CHECK(memcmp(buf + 4, eui64, 8) == 0);

    free(buf);
}

static void test_nrb_block_wire_format(void)
{
    SUITE("Name Resolution Block — full block wire format");

    /* Build two NRB records + end record */
    const unsigned char addr1[4] = { 10, 0, 0, 1 };
    const char *name1 = "router";

    unsigned char rec_buf[256];
    size_t rpos = 0;

    rpos += libpcapng_nrb_record_write(PCAPNG_NRB_RECORD_IPV4, addr1, 4, name1, rec_buf + rpos);
    rpos += libpcapng_nrb_record_write(PCAPNG_NRB_RECORD_END,  NULL,  0, NULL,  rec_buf + rpos);

    size_t sz = libpcapng_name_resolution_block_size(rec_buf, rpos, NULL, 0);
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_name_resolution_block_write(rec_buf, rpos, NULL, 0, buf);

    CHECK(written == sz);
    CHECK(u32at(buf, 0) == PCAPNG_NAME_RESOLUTION_BLOCK);
    CHECK(u32at(buf, 4) == (uint32_t)sz);
    CHECK((u32at(buf, 4) % 4) == 0);
    CHECK(u32at(buf, sz - 4) == (uint32_t)sz);

    /* First record starts at offset 8 */
    CHECK(u16at(buf, 8) == PCAPNG_NRB_RECORD_IPV4);
    CHECK(memcmp(buf + 12, addr1, 4) == 0);

    free(buf);
}

static void test_nrb_block_with_dns_option(void)
{
    SUITE("Name Resolution Block — ns_dnsname option");

    /* Empty records (just end record) */
    unsigned char rec_buf[8];
    size_t rpos = libpcapng_nrb_record_write(PCAPNG_NRB_RECORD_END, NULL, 0, NULL, rec_buf);

    const char *dns = "8.8.8.8";
    pcapng_option_t opts[] = { { PCAPNG_OPT_NS_DNSNAME, (uint16_t)strlen(dns), dns } };
    size_t sz = libpcapng_name_resolution_block_size(rec_buf, rpos, opts, 1);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_name_resolution_block_write(rec_buf, rpos, opts, 1, buf);

    CHECK(u32at(buf, 0) == PCAPNG_NAME_RESOLUTION_BLOCK);
    CHECK(u32at(buf, sz - 4) == (uint32_t)sz);
    CHECK((sz % 4) == 0);

    free(buf);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 11. INTERFACE STATISTICS BLOCK
 * ══════════════════════════════════════════════════════════════════════════════*/

/*
 * ISB wire layout (spec §4.6):
 *   offset  0  block_type         (4) = 0x00000005
 *   offset  4  block_total_length (4)
 *   offset  8  interface_id       (4)
 *   offset 12  timestamp_high     (4)
 *   offset 16  timestamp_low      (4)
 *   offset 20  options            (optional)
 *   ...        block_total_length (4)
 */

static void test_isb_size_no_options(void)
{
    SUITE("Interface Statistics Block — size without options");

    /* sizeof ISB struct (20) + trailing BTL (4) = 24 */
    size_t sz = libpcapng_interface_statistics_block_size(NULL, 0);
    CHECK(sz == 24u);
    CHECK((sz % 4) == 0);
}

static void test_isb_wire_format(void)
{
    SUITE("Interface Statistics Block — wire format");

    size_t sz = libpcapng_interface_statistics_block_size(NULL, 0);
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_interface_statistics_block_write(
        0, 0x0001u, 0xABCDu, NULL, 0, buf);

    CHECK(written == sz);
    CHECK(u32at(buf,  0) == PCAPNG_INTERFACE_STATISTICS_BLOCK);
    CHECK(u32at(buf,  4) == (uint32_t)sz);
    CHECK(u32at(buf,  8) == 0u);       /* interface_id */
    CHECK(u32at(buf, 12) == 0x0001u);  /* timestamp_high */
    CHECK(u32at(buf, 16) == 0xABCDu);  /* timestamp_low */
    CHECK(u32at(buf, 20) == (uint32_t)sz);  /* trailing BTL (no options) */

    free(buf);
}

static void test_isb_with_counters(void)
{
    SUITE("Interface Statistics Block — counter options");

    uint64_t ifrecv = 10000u;
    uint64_t ifdrop = 5u;
    uint64_t osdrop = 1u;

    pcapng_option_t opts[] = {
        { PCAPNG_OPT_ISB_IFRECV, 8, &ifrecv },
        { PCAPNG_OPT_ISB_IFDROP, 8, &ifdrop },
        { PCAPNG_OPT_ISB_OSDROP, 8, &osdrop },
    };
    size_t sz = libpcapng_interface_statistics_block_size(opts, 3);
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_interface_statistics_block_write(
        0, 0, 0, opts, 3, buf);

    CHECK(written == sz);
    CHECK(u32at(buf, 0) == PCAPNG_INTERFACE_STATISTICS_BLOCK);
    CHECK((sz % 4) == 0);
    CHECK(u32at(buf, sz - 4) == (uint32_t)sz);

    /* Options start at offset 20 */
    CHECK(u16at(buf, 20) == PCAPNG_OPT_ISB_IFRECV);
    CHECK(u16at(buf, 22) == 8u);

    free(buf);
}

static void test_isb_interface_id(void)
{
    SUITE("Interface Statistics Block — non-zero interface_id");

    size_t sz = libpcapng_interface_statistics_block_size(NULL, 0);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_interface_statistics_block_write(3, 0, 0, NULL, 0, buf);

    CHECK(u32at(buf, 8) == 3u);  /* interface_id = 3 */

    free(buf);
}

static void test_isb_struct_offsets(void)
{
    SUITE("Interface Statistics Block — struct field offsets");

    CHECK(offsetof(pcapng_interface_statistics_block_t, block_type)       == 0u);
    CHECK(offsetof(pcapng_interface_statistics_block_t, block_total_length) == 4u);
    CHECK(offsetof(pcapng_interface_statistics_block_t, interface_id)     == 8u);
    CHECK(offsetof(pcapng_interface_statistics_block_t, timestamp_high)   == 12u);
    CHECK(offsetof(pcapng_interface_statistics_block_t, timestamp_low)    == 16u);
    CHECK(sizeof(pcapng_interface_statistics_block_t)                     == 20u);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 12. DECRYPTION SECRETS BLOCK
 * ══════════════════════════════════════════════════════════════════════════════*/

/*
 * DSB wire layout (spec §4.7):
 *   offset  0  block_type         (4) = 0x0000000A
 *   offset  4  block_total_length (4)
 *   offset  8  secrets_type       (4)
 *   offset 12  secrets_length     (4)  (unpadded byte count)
 *   offset 16  secrets_data       (secrets_length bytes, padded to 4)
 *   ...        block_total_length (4)
 */

static void test_dsb_size(void)
{
    SUITE("Decryption Secrets Block — size");

    /* 0-byte secrets: 16 (header) + 0 + 4 (trailing) = 20 */
    CHECK(libpcapng_decryption_secrets_block_size(0) == 20u);
    /* 4-byte: 16 + 4 + 4 = 24 */
    CHECK(libpcapng_decryption_secrets_block_size(4) == 24u);
    /* 1-byte padded to 4: 16 + 4 + 4 = 24 */
    CHECK(libpcapng_decryption_secrets_block_size(1) == 24u);
    /* 5-byte padded to 8: 16 + 8 + 4 = 28 */
    CHECK(libpcapng_decryption_secrets_block_size(5) == 28u);

    for (size_t n = 0; n <= 32; n++)
        CHECK((libpcapng_decryption_secrets_block_size(n) % 4) == 0);
}

static void test_dsb_wire_format_tls(void)
{
    SUITE("Decryption Secrets Block — TLS key log wire format");

    /* Minimal TLS key log entry (24 bytes) */
    const unsigned char secrets[] =
        "CLIENT_RANDOM 0123456789ABCDEF\n";
    size_t secrets_len = sizeof(secrets) - 1;

    size_t sz = libpcapng_decryption_secrets_block_size(secrets_len);
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_decryption_secrets_block_write(
        PCAPNG_TLS_KEY_LOG, secrets, secrets_len, buf);

    CHECK(written == sz);
    CHECK(u32at(buf,  0) == PCAPNG_DECRYPTION_SECRETS_BLOCK);
    CHECK(u32at(buf,  4) == (uint32_t)sz);
    CHECK(u32at(buf,  8) == PCAPNG_TLS_KEY_LOG);
    CHECK(u32at(buf, 12) == (uint32_t)secrets_len);  /* unpadded length */
    CHECK(memcmp(buf + 16, secrets, secrets_len) == 0);
    CHECK(u32at(buf, sz - 4) == (uint32_t)sz);

    free(buf);
}

static void test_dsb_all_secret_types(void)
{
    SUITE("Decryption Secrets Block — all secret type constants");

    const unsigned char dummy[4] = { 0 };
    size_t sz = libpcapng_decryption_secrets_block_size(4);
    unsigned char *buf = alloc_buf(sz);

    uint32_t types[] = {
        PCAPNG_TLS_KEY_LOG,
        PCAPNG_WIREGUARD_KEY_LOG,
        PCAPNG_ZIGBEE_NWK_KEY,
        PCAPNG_ZIGBEE_APS_KEY,
        PCAPNG_SSH_KEY_LOG,
        PCAPNG_OPC_UA_KEY_LOG,
        PCAPNG_ESP_SA,
    };

    for (size_t i = 0; i < sizeof(types)/sizeof(types[0]); i++) {
        memset(buf, 0, sz);
        libpcapng_decryption_secrets_block_write(types[i], dummy, 4, buf);
        CHECK(u32at(buf, 0) == PCAPNG_DECRYPTION_SECRETS_BLOCK);
        CHECK(u32at(buf, 8) == types[i]);
        CHECK(u32at(buf, sz - 4) == (uint32_t)sz);
    }

    free(buf);
}

static void test_dsb_padding_zero(void)
{
    SUITE("Decryption Secrets Block — padding bytes are zero");

    /* 3-byte secrets → 1 byte padding */
    const unsigned char secrets[3] = { 0xAA, 0xBB, 0xCC };
    size_t sz = libpcapng_decryption_secrets_block_size(3);
    unsigned char *buf = alloc_buf(sz);

    libpcapng_decryption_secrets_block_write(PCAPNG_TLS_KEY_LOG, secrets, 3, buf);

    CHECK(buf[19] == 0u);  /* padding byte at offset 16+3 = 19 */
    CHECK(u32at(buf, 12) == 3u);   /* secrets_length is unpadded */

    free(buf);
}

static void test_dsb_struct_offsets(void)
{
    SUITE("Decryption Secrets Block — struct field offsets");

    CHECK(offsetof(pcapng_decryption_secrets_block_t, block_type)       == 0u);
    CHECK(offsetof(pcapng_decryption_secrets_block_t, block_total_length) == 4u);
    CHECK(offsetof(pcapng_decryption_secrets_block_t, secrets_type)     == 8u);
    CHECK(offsetof(pcapng_decryption_secrets_block_t, secrets_length)   == 12u);
    CHECK(sizeof(pcapng_decryption_secrets_block_t)                     == 16u);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 13. CUSTOM DATA BLOCK
 * ══════════════════════════════════════════════════════════════════════════════*/

static void test_custom_block_size(void)
{
    SUITE("Custom Data Block — size helper");

    CHECK(libpcapng_custom_data_block_size(0) == 16u);
    CHECK(libpcapng_custom_data_block_size(1) == 20u);
    CHECK(libpcapng_custom_data_block_size(3) == 20u);
    CHECK(libpcapng_custom_data_block_size(4) == 20u);
    CHECK(libpcapng_custom_data_block_size(5) == 24u);

    for (size_t n = 0; n <= 32; n++)
        CHECK((libpcapng_custom_data_block_size(n) % 4) == 0);
}

static void test_custom_block_wire_format(void)
{
    SUITE("Custom Data Block — wire format");

    const unsigned char data[] = { 'h', 'e', 'l' };
    uint32_t pen = 123u;
    size_t sz = libpcapng_custom_data_block_size(3);
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_custom_data_block_write(pen, data, 3, buf);

    CHECK(written == sz);
    CHECK(u32at(buf,  0) == PCAPNG_CUSTOM_DATA_BLOCK);
    CHECK(u32at(buf,  4) == (uint32_t)sz);
    CHECK(u32at(buf,  8) == pen);
    CHECK(buf[12] == 'h');
    CHECK(buf[13] == 'e');
    CHECK(buf[14] == 'l');
    CHECK(buf[15] == 0u);
    CHECK(u32at(buf, 16) == u32at(buf, 4));
    CHECK((u32at(buf, 4) % 4) == 0);

    free(buf);
}

static void test_custom_block_zero_data(void)
{
    SUITE("Custom Data Block — zero-length data");

    uint32_t pen = 0xDEADBEEFu;
    size_t sz = libpcapng_custom_data_block_size(0);
    unsigned char *buf = alloc_buf(sz);

    size_t written = libpcapng_custom_data_block_write(pen, NULL, 0, buf);

    CHECK(written == 16u);
    CHECK(u32at(buf,  0) == PCAPNG_CUSTOM_DATA_BLOCK);
    CHECK(u32at(buf,  4) == 16u);
    CHECK(u32at(buf,  8) == pen);
    CHECK(u32at(buf, 12) == 16u);

    free(buf);
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
 * 14. FILE-LEVEL BLOCK SEQUENCE TESTS (using tmpfile)
 * ══════════════════════════════════════════════════════════════════════════════*/

static void test_file_header_block_sequence(void)
{
    SUITE("File-level — SHB+IDB block sequence (easyapi)");

    FILE *fp = tmpfile();
    assert(fp);

    libpcapng_write_header_to_file(fp);
    fflush(fp);

    long file_size = ftell(fp);
    CHECK(file_size == 48L);

    rewind(fp);
    unsigned char raw[48];
    CHECK(fread(raw, 1, 48, fp) == 48u);

    CHECK(u32at(raw, 0)  == PCAPNG_SECTION_HEADER_BLOCK);
    CHECK(u32at(raw, 4)  == 28u);
    CHECK(u32at(raw, 8)  == PCAPNG_BYTE_ORDER_MAGIC);
    CHECK(u16at(raw, 12) == 1u);

    CHECK(u32at(raw, 28) == PCAPNG_INTERFACE_DESCRIPTION_BLOCK);
    CHECK(u32at(raw, 32) == 20u);
    CHECK(u16at(raw, 36) == LINKTYPE_RAW);
    CHECK(u16at(raw, 38) == 0u);

    fclose(fp);
}

static void test_file_multiple_epbs(void)
{
    SUITE("File-level — multiple EPBs, contiguous and non-overlapping");

    FILE *fp = tmpfile();
    assert(fp);

    libpcapng_write_header_to_file(fp);

    static const size_t pkt_sizes[] = { 4, 8, 1, 16, 3 };
    for (size_t i = 0; i < 5; i++) {
        unsigned char *pkt = calloc(1, pkt_sizes[i]);
        memset(pkt, (int)(i + 1), pkt_sizes[i]);
        libpcapng_write_enhanced_packet_to_file(fp, pkt, pkt_sizes[i]);
        free(pkt);
    }

    fflush(fp);
    rewind(fp);

    unsigned char shb_buf[28];
    CHECK(fread(shb_buf, 1, 28, fp) == 28u);
    CHECK(u32at(shb_buf, 0) == PCAPNG_SECTION_HEADER_BLOCK);

    unsigned char idb_buf[20];
    CHECK(fread(idb_buf, 1, 20, fp) == 20u);
    CHECK(u32at(idb_buf, 0) == PCAPNG_INTERFACE_DESCRIPTION_BLOCK);

    for (size_t i = 0; i < 5; i++) {
        unsigned char hdr[8];
        CHECK(fread(hdr, 1, 8, fp) == 8u);
        CHECK(u32at(hdr, 0) == PCAPNG_ENHANCED_PACKET_BLOCK);
        uint32_t btl = u32at(hdr, 4);
        CHECK((btl % 4) == 0);
        CHECK(btl >= 32u);
        fseek(fp, (long)(btl - 8), SEEK_CUR);
    }

    CHECK(fgetc(fp) == EOF);
    fclose(fp);
}

static void test_file_unknown_block_skip(void)
{
    SUITE("File-level — unknown block type is skippable via BTL");

    /*
     * The spec requires that readers skip unknown blocks using
     * Block Type + Block Total Length at the start of every block.
     * Write a synthetic "unknown" block (type 0xBEEFCAFE) followed by a
     * known EPB, then verify the EPB is reachable by skipping the unknown.
     */
    FILE *fp = tmpfile();
    assert(fp);

    libpcapng_write_header_to_file(fp);

    /* Synthetic unknown block: 16 bytes (type + BTL + 4 payload + BTL) */
    const unsigned char unknown_block[] = {
        0xFE, 0xCA, 0xEF, 0xBE,  /* block type = 0xBEEFCAFE (LE) */
        0x10, 0x00, 0x00, 0x00,  /* block_total_length = 16 */
        0xDE, 0xAD, 0xBE, 0xEF,  /* payload */
        0x10, 0x00, 0x00, 0x00   /* trailing BTL */
    };
    fwrite(unknown_block, 1, sizeof(unknown_block), fp);

    const unsigned char pkt[4] = { 0x12, 0x34, 0x56, 0x78 };
    libpcapng_write_enhanced_packet_to_file(fp, (unsigned char*)pkt, 4);
    fflush(fp);

    /* Navigate the file: SHB(28) + IDB(20) + unknown(16) + EPB(36) */
    rewind(fp);
    unsigned char shb_buf[28];
    fread(shb_buf, 1, 28, fp);
    CHECK(u32at(shb_buf, 0) == PCAPNG_SECTION_HEADER_BLOCK);

    unsigned char idb_buf[20];
    fread(idb_buf, 1, 20, fp);
    CHECK(u32at(idb_buf, 0) == PCAPNG_INTERFACE_DESCRIPTION_BLOCK);

    /* Read unknown block type + BTL, then skip it */
    unsigned char unk_hdr[8];
    fread(unk_hdr, 1, 8, fp);
    uint32_t unk_type = u32at(unk_hdr, 0);
    uint32_t unk_btl  = u32at(unk_hdr, 4);
    CHECK(unk_type == 0xBEEFCAFEu);
    CHECK(unk_btl  == 16u);
    /* Skip remainder of unknown block */
    fseek(fp, (long)(unk_btl - 8), SEEK_CUR);

    /* Now we should be at the EPB */
    unsigned char epb_hdr[8];
    fread(epb_hdr, 1, 8, fp);
    CHECK(u32at(epb_hdr, 0) == PCAPNG_ENHANCED_PACKET_BLOCK);
    CHECK(u32at(epb_hdr, 4) == 36u);  /* 28+4+4 = 36 */

    fclose(fp);
}

static void test_file_multiple_sections(void)
{
    SUITE("File-level — multiple SHBs (multi-section file)");

    /*
     * A valid pcapng file may contain multiple SHBs.  Each SHB starts a new
     * section; the IDB within each section applies only to that section.
     */
    FILE *fp = tmpfile();
    assert(fp);

    /* Section 1 */
    libpcapng_write_header_to_file(fp);
    const unsigned char pkt1[4] = { 0x01, 0x01, 0x01, 0x01 };
    libpcapng_write_enhanced_packet_to_file(fp, (unsigned char*)pkt1, 4);

    /* Section 2 — new SHB + new IDB */
    libpcapng_write_header_to_file(fp);
    const unsigned char pkt2[4] = { 0x02, 0x02, 0x02, 0x02 };
    libpcapng_write_enhanced_packet_to_file(fp, (unsigned char*)pkt2, 4);

    fflush(fp);
    fseek(fp, 0, SEEK_END);
    long total = ftell(fp);

    /* SHB(28)+IDB(20)+EPB(36) = 84, twice = 168 */
    CHECK(total == 168L);

    /* Verify second section's SHB at offset 84 */
    rewind(fp);
    fseek(fp, 84, SEEK_SET);
    unsigned char shb2[28];
    fread(shb2, 1, 28, fp);
    CHECK(u32at(shb2, 0) == PCAPNG_SECTION_HEADER_BLOCK);
    CHECK(u32at(shb2, 8) == PCAPNG_BYTE_ORDER_MAGIC);

    fclose(fp);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 15. PADDING MACRO
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
 * 16. BLOCK TOTAL LENGTH INVARIANTS
 * ══════════════════════════════════════════════════════════════════════════════*/

static void test_btl_invariants_all_blocks(void)
{
    SUITE("Block Total Length invariants — leading == trailing, multiple of 4");

    /* SHB */
    {
        size_t sz = libpcapng_section_header_block_size();
        unsigned char *buf = alloc_buf(sz);
        libpcapng_section_header_block_write(buf);
        CHECK(u32at(buf, 4) == u32at(buf, sz - 4));
        CHECK((u32at(buf, 4) % 4) == 0);
        free(buf);
    }

    /* IDB */
    {
        size_t sz = libpcapng_interface_description_block_size();
        unsigned char *buf = alloc_buf(sz);
        libpcapng_interface_description_block_write(0, buf);
        CHECK(u32at(buf, 4) == u32at(buf, sz - 4));
        CHECK((u32at(buf, 4) % 4) == 0);
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
        CHECK(u32at(buf, 4) == u32at(buf, sz - 4));
        CHECK((u32at(buf, 4) % 4) == 0);
        free(buf);
    }

    /* SPB */
    {
        size_t sz = libpcapng_simple_packet_block_size(8);
        unsigned char *buf = alloc_buf(sz);
        libpcapng_simple_packet_block_write(pkt, 8, 8, buf);
        CHECK(u32at(buf, 4) == u32at(buf, sz - 4));
        CHECK((u32at(buf, 4) % 4) == 0);
        free(buf);
    }

    /* ISB */
    {
        size_t sz = libpcapng_interface_statistics_block_size(NULL, 0);
        unsigned char *buf = alloc_buf(sz);
        libpcapng_interface_statistics_block_write(0, 0, 0, NULL, 0, buf);
        CHECK(u32at(buf, 4) == u32at(buf, sz - 4));
        CHECK((u32at(buf, 4) % 4) == 0);
        free(buf);
    }

    /* DSB */
    {
        size_t sz = libpcapng_decryption_secrets_block_size(4);
        unsigned char *buf = alloc_buf(sz);
        const unsigned char d[4] = {0};
        libpcapng_decryption_secrets_block_write(PCAPNG_TLS_KEY_LOG, d, 4, buf);
        CHECK(u32at(buf, 4) == u32at(buf, sz - 4));
        CHECK((u32at(buf, 4) % 4) == 0);
        free(buf);
    }

    /* Custom block */
    unsigned char cdata[100];
    memset(cdata, 0xBE, sizeof(cdata));
    size_t cb_sizes[] = { 0, 1, 2, 3, 4, 5, 7, 12, 17, 100 };
    for (size_t i = 0; i < sizeof(cb_sizes)/sizeof(cb_sizes[0]); i++) {
        size_t n = cb_sizes[i];
        size_t sz = libpcapng_custom_data_block_size(n);
        unsigned char *buf = alloc_buf(sz);
        libpcapng_custom_data_block_write(42u, cdata, n, buf);
        CHECK(u32at(buf, 4) == u32at(buf, sz - 4));
        CHECK((u32at(buf, 4) % 4) == 0);
        free(buf);
    }
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 17. STRUCT FIELD OFFSETS
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

    /* NRB */
    CHECK(offsetof(pcapng_name_resolution_block_t, block_type)         == 0u);
    CHECK(offsetof(pcapng_name_resolution_block_t, block_total_length) == 4u);
    CHECK(sizeof(pcapng_name_resolution_block_t)                       == 8u);

    /* NRB record */
    CHECK(offsetof(pcapng_nrb_record_t, record_type)   == 0u);
    CHECK(offsetof(pcapng_nrb_record_t, record_length) == 2u);
    CHECK(sizeof(pcapng_nrb_record_t)                  == 4u);

    /* Custom block */
    CHECK(offsetof(pcapng_custom_data_block_t, block_type)         == 0u);
    CHECK(offsetof(pcapng_custom_data_block_t, block_total_length) == 4u);
    CHECK(offsetof(pcapng_custom_data_block_t, pen)                == 8u);
    CHECK(sizeof(pcapng_custom_data_block_t)                       == 12u);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * 18. SPEC COMPLIANCE VERIFICATION
 *     All previously-known bugs are now fixed; this section verifies the
 *     correct values and documents the previous behaviour.
 * ══════════════════════════════════════════════════════════════════════════════*/

static void test_spec_compliance(void)
{
    SUITE("Spec compliance — previously-bugged fields now correct");

    size_t sz = libpcapng_section_header_block_size();
    unsigned char *buf = alloc_buf(sz);
    libpcapng_section_header_block_write(buf);

    /* FIXED: section_length must be -1 (0xFFFFFFFFFFFFFFFF) for unknown length */
    uint64_t section_length = u64at(buf, 16);
    CHECK(section_length == 0xFFFFFFFFFFFFFFFFull);

    /* FIXED: minor_version must be 0 and now set explicitly */
    uint16_t minor_ver = u16at(buf, 14);
    CHECK(minor_ver == 0u);

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
    test_option_constants();
    test_epb_flag_constants();
    test_linktype_constants();

    test_options_size_empty();
    test_options_size_aligned();
    test_options_size_unaligned();
    test_options_write_single_u8();
    test_options_write_single_u32();
    test_options_write_multiple();
    test_options_write_string();
    test_options_endofopt_always_present();

    test_shb_size();
    test_shb_wire_format();
    test_shb_read_roundtrip();
    test_shb_with_options();

    test_idb_size();
    test_idb_wire_format_raw();
    test_idb_wire_format_ethernet();
    test_idb_wire_format_all_linktypes();
    test_idb_snaplen_values();
    test_idb_read_roundtrip();
    test_idb_with_tsresol_option();
    test_idb_with_multiple_options();

    test_epb_size_aligned();
    test_epb_size_unaligned();
    test_epb_wire_format_basic();
    test_epb_wire_format_40byte();
    test_epb_padding_bytes_are_zero();
    test_epb_padding_all_sizes();
    test_epb_timestamp_split();
    test_epb_data_preserved();
    test_epb_interface_id_is_zero();
    test_epb_nonzero_interface_id();
    test_epb_truncated_packet();
    test_epb_with_flags_option();
    test_epb_with_dropcount_option();

    test_spb_size();
    test_spb_wire_format();
    test_spb_truncation();
    test_spb_padding_zero();
    test_spb_struct_offsets();

    test_nrb_record_size();
    test_nrb_record_ipv4_write();
    test_nrb_record_ipv6_write();
    test_nrb_record_end_write();
    test_nrb_record_eui48_type();
    test_nrb_record_eui64_type();
    test_nrb_block_wire_format();
    test_nrb_block_with_dns_option();

    test_isb_size_no_options();
    test_isb_wire_format();
    test_isb_with_counters();
    test_isb_interface_id();
    test_isb_struct_offsets();

    test_dsb_size();
    test_dsb_wire_format_tls();
    test_dsb_all_secret_types();
    test_dsb_padding_zero();
    test_dsb_struct_offsets();

    test_custom_block_size();
    test_custom_block_wire_format();
    test_custom_block_zero_data();
    test_custom_block_pen_values();

    test_file_header_block_sequence();
    test_file_multiple_epbs();
    test_file_unknown_block_skip();
    test_file_multiple_sections();

    test_padding_macro();
    test_btl_invariants_all_blocks();
    test_struct_offsets();
    test_spec_compliance();

    printf("\n==============================\n");
    printf("Results: %d/%d passed", g_passed, g_tests);
    if (g_failed)
        printf(", %d FAILED", g_failed);
    printf("\n");

    return g_failed ? 1 : 0;
}
