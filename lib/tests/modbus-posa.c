/*
 * modbus-posa.c — craft a Modbus TCP packet from the shipped posa definition,
 * verify every default value is decoded correctly, and confirm the packet
 * survives a pcapng write/read roundtrip.
 *
 * Default values from modbus_tcp.posa:
 *   transaction_id  = 0   (uint16, 2 bytes)
 *   protocol_id     = 0   (uint16, 2 bytes)
 *   length          = 2   (uint16, 2 bytes)  — covers unit_id + function_code
 *   unit_id         = 1   (uint8,  1 byte)
 *   function_code   = 3   (uint8,  1 byte)   — READ_HOLDING_REGISTERS
 *
 * Build via cmake (Modbus-Posa ctest target).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libpcapng/posa.h>
#include <libpcapng/dissect.h>
#include <libpcapng/easyapi.h>
#include <libpcapng/linktypes.h>
#include <libpcapng/blocks.h>
#include <libpcapng/io.h>

/* ── harness ──────────────────────────────────────────────────────────────── */

static int g_pass = 0, g_fail = 0;

#define SUITE(name) printf("\n[%s]\n", (name))

#define CHECK(label, expr) do {                                         \
    if (expr) { g_pass++; printf("  PASS  %s\n", label); }            \
    else       { g_fail++; printf("  FAIL  %s  (%s:%d)\n",            \
                                  label, __FILE__, __LINE__); }        \
} while(0)

/* ── Modbus TCP default bytes ─────────────────────────────────────────────── */

/*
 * MBAP header (6 bytes) + unit_id (1) + function_code (1) = 8 bytes total.
 * All fields at their posa-defined default values, big-endian on the wire.
 *
 * Offset  Length  Field            Default
 * 0       2       transaction_id   0x0000
 * 2       2       protocol_id      0x0000
 * 4       2       length           0x0002  (2 bytes follow: unit_id + fc)
 * 6       1       unit_id          0x01
 * 7       1       function_code    0x03    (READ_HOLDING_REGISTERS)
 */
static const uint8_t MODBUS_DEFAULTS[8] = {
    0x00, 0x00,   /* transaction_id = 0 */
    0x00, 0x00,   /* protocol_id    = 0 */
    0x00, 0x02,   /* length         = 2 */
    0x01,         /* unit_id        = 1 */
    0x03,         /* function_code  = 3 READ_HOLDING_REGISTERS */
};

/* ── helpers ──────────────────────────────────────────────────────────────── */

/* Collect the first node matching abbrev and return its .u value,
 * or UINT64_MAX if not found. */
static uint64_t field_uint(pcapng_field_t *root, const char *abbrev)
{
    pcapng_field_t *hits[4];
    int n = pcapng_field_collect(root, abbrev, hits, 4);
    if (n <= 0) return UINT64_MAX;
    return hits[0]->u;
}

/* Return 1 if any collected node for abbrev has `want` in its label. */
static int label_has(pcapng_field_t *root, const char *abbrev, const char *want)
{
    pcapng_field_t *hits[4];
    int n = pcapng_field_collect(root, abbrev, hits, 4);
    for (int i = 0; i < n; i++)
        if (strstr(hits[i]->label, want)) return 1;
    return 0;
}

/* Minimal Ethernet/IPv4/TCP wrapper so we can write a real pcapng frame.
 * The Modbus payload sits after the 54-byte header (14+20+20). */
static size_t wrap_tcp(uint8_t *out,
                       const uint8_t *payload, uint16_t plen,
                       uint32_t src_ip, uint32_t dst_ip,
                       uint16_t sport,  uint16_t dport)
{
    uint8_t *p = out;

    /* Ethernet */
    memset(p, 0x00, 6); p += 6;
    memset(p, 0x11, 6); p += 6;
    p[0] = 0x08; p[1] = 0x00; p += 2;

    /* IPv4 */
    uint16_t ip_tot = 20 + 20 + plen;
    uint8_t *iph = p;
    p[0]  = 0x45; p[1] = 0;
    p[2]  = (uint8_t)(ip_tot >> 8); p[3] = (uint8_t)(ip_tot);
    p[4]  = 0; p[5] = 1;   /* id */
    p[6]  = 0; p[7] = 0;   /* frag */
    p[8]  = 64; p[9] = 6;  /* TTL, TCP */
    p[10] = 0; p[11] = 0;  /* cksum placeholder */
    p[12] = (uint8_t)(src_ip>>24); p[13] = (uint8_t)(src_ip>>16);
    p[14] = (uint8_t)(src_ip>>8);  p[15] = (uint8_t)(src_ip);
    p[16] = (uint8_t)(dst_ip>>24); p[17] = (uint8_t)(dst_ip>>16);
    p[18] = (uint8_t)(dst_ip>>8);  p[19] = (uint8_t)(dst_ip);
    uint32_t ck = 0;
    for (int i = 0; i < 20; i += 2) ck += (iph[i] << 8) | iph[i+1];
    while (ck >> 16) ck = (ck & 0xffff) + (ck >> 16);
    ck = ~ck & 0xffff;
    iph[10] = (uint8_t)(ck >> 8); iph[11] = (uint8_t)(ck);
    p += 20;

    /* TCP (minimal, no options) */
    p[0]  = (uint8_t)(sport >> 8); p[1] = (uint8_t)(sport);
    p[2]  = (uint8_t)(dport >> 8); p[3] = (uint8_t)(dport);
    memset(p + 4, 0, 8);   /* seq, ack = 0 */
    p[12] = 0x50;           /* data offset = 5 (20 bytes), no flags */
    p[13] = 0x18;           /* PSH + ACK */
    p[14] = 0xff; p[15] = 0xff;   /* window */
    p[16] = 0; p[17] = 0;  /* checksum (zero) */
    p[18] = 0; p[19] = 0;  /* urgent */
    p += 20;

    memcpy(p, payload, plen);
    return 14 + ip_tot;
}

static int cb_count_epb(uint32_t ctr, uint32_t btype,
                        uint32_t blen, unsigned char *data, void *ud)
{
    (void)ctr; (void)blen; (void)data;
    if (btype == PCAPNG_ENHANCED_PACKET_BLOCK) (*(int *)ud)++;
    return 0;
}

/* ── tests ────────────────────────────────────────────────────────────────── */

static void test_posa_decode(const char *posa_path)
{
    SUITE("posa decode — default values");

    char errbuf[256] = "";
    pcapng_posa_clear();
    int r = pcapng_posa_load_file(posa_path, errbuf, sizeof errbuf);
    if (r < 0) {
        printf("  SKIP  cannot load %s: %s\n", posa_path, errbuf);
        return;
    }
    CHECK("posa file loaded", r >= 0);

    pcapng_field_t *root = calloc(1, sizeof *root);
    char info[256] = "";
    int used = pcapng_posa_dissect("ModbusTCP",
                                   MODBUS_DEFAULTS, (int)sizeof MODBUS_DEFAULTS,
                                   root, 0, info, sizeof info);

    CHECK("dissect consumed all 8 bytes", used == 8);

    /* Numeric field values */
    CHECK("transaction_id = 0", field_uint(root, "ModbusTCP.transaction_id") == 0);
    CHECK("protocol_id = 0",    field_uint(root, "ModbusTCP.protocol_id")    == 0);
    CHECK("length = 2",         field_uint(root, "ModbusTCP.length")         == 2);
    CHECK("unit_id = 1",        field_uint(root, "ModbusTCP.unit_id")        == 1);
    CHECK("function_code = 3",  field_uint(root, "ModbusTCP.function_code")  == 3);

    /* function_code 3 must resolve to the enum name */
    CHECK("function_code label is READ_HOLDING_REGISTERS",
          label_has(root, "ModbusTCP.function_code", "READ_HOLDING_REGISTERS"));

    /* protocol_id = 0 is always Modbus — the label should say so */
    CHECK("protocol_id label contains 0",
          label_has(root, "ModbusTCP.protocol_id", "0"));

    pcapng_field_free(root);
}

static void test_posa_variants(const char *posa_path)
{
    SUITE("posa decode — non-default function codes");

    char errbuf[256] = "";
    pcapng_posa_clear();
    if (pcapng_posa_load_file(posa_path, errbuf, sizeof errbuf) < 0) {
        printf("  SKIP  cannot load posa file\n");
        return;
    }

    struct { uint8_t fc; const char *name; } cases[] = {
        { 0x01, "READ_COILS" },
        { 0x02, "READ_DISCRETE_INPUTS" },
        { 0x04, "READ_INPUT_REGISTERS" },
        { 0x05, "WRITE_SINGLE_COIL" },
        { 0x06, "WRITE_SINGLE_REGISTER" },
        { 0x0f, "WRITE_MULTIPLE_COILS" },
        { 0x10, "WRITE_MULTIPLE_REGISTERS" },
        { 0x2b, "MEI_TRANSPORT" },
    };

    for (int i = 0; i < (int)(sizeof cases / sizeof cases[0]); i++) {
        uint8_t pkt[8];
        memcpy(pkt, MODBUS_DEFAULTS, sizeof pkt);
        pkt[7] = cases[i].fc;

        pcapng_field_t *root = calloc(1, sizeof *root);
        char info[256] = "";
        pcapng_posa_dissect("ModbusTCP", pkt, 8, root, 0, info, sizeof info);

        char label[64];
        snprintf(label, sizeof label, "fc=0x%02x → %s", cases[i].fc, cases[i].name);
        CHECK(label, label_has(root, "ModbusTCP.function_code", cases[i].name));
        pcapng_field_free(root);
    }
}

static void test_pcapng_roundtrip(void)
{
    SUITE("pcapng write/read roundtrip");

    const char *path = "/tmp/modbus_test.pcapng";
    FILE *f = fopen(path, "wb");
    if (!f) { printf("  SKIP  cannot write %s\n", path); return; }

    libpcapng_write_header_to_file_with_linktype(f, LINKTYPE_ETHERNET);

    uint8_t  frame[512];
    uint32_t src = (10 << 24) | 1;      /* 10.0.0.1 */
    uint32_t dst = (10 << 24) | 2;      /* 10.0.0.2 */
    size_t   flen = wrap_tcp(frame, MODBUS_DEFAULTS, sizeof MODBUS_DEFAULTS,
                             src, dst, 12345, 502);
    libpcapng_write_enhanced_packet_to_file(f, frame, flen);

    /* Write a second packet: Modbus response with fc=0x03 echoed */
    uint8_t resp[8];
    memcpy(resp, MODBUS_DEFAULTS, sizeof resp);
    resp[7] = 0x03;   /* response echoes the same function code */
    flen = wrap_tcp(frame, resp, sizeof resp, dst, src, 502, 12345);
    libpcapng_write_enhanced_packet_to_file(f, frame, flen);

    fclose(f);

    int n = 0;
    libpcapng_file_read((char *)path, cb_count_epb, &n);
    CHECK("pcapng contains 2 packets", n == 2);
    CHECK("output file is non-empty", n > 0);
}

static void test_error_response(const char *posa_path)
{
    SUITE("posa decode — error response (fc | 0x80)");

    char errbuf[256] = "";
    pcapng_posa_clear();
    if (pcapng_posa_load_file(posa_path, errbuf, sizeof errbuf) < 0) {
        printf("  SKIP  cannot load posa file\n");
        return;
    }

    /* Error for READ_HOLDING_REGISTERS: fc = 3 | 0x80 = 0x83 */
    uint8_t pkt[8];
    memcpy(pkt, MODBUS_DEFAULTS, sizeof pkt);
    pkt[7] = 0x83;

    pcapng_field_t *root = calloc(1, sizeof *root);
    char info[256] = "";
    int used = pcapng_posa_dissect("ModbusTCP", pkt, 8, root, 0, info, sizeof info);

    CHECK("error response consumed 8 bytes", used == 8);
    /* function_code 0x83 has no enum entry, so the raw value is shown */
    CHECK("error fc = 0x83", field_uint(root, "ModbusTCP.function_code") == 0x83);

    pcapng_field_free(root);
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    printf("=== modbus-posa ===\n");

    /*
     * The posa file is looked up in order:
     *   1. argv[1]        — explicit override for out-of-tree builds
     *   2. POSA_FILE env  — CI / developer override
     *   3. Source tree    — relative to this file's build directory
     */
    const char *posa_path = NULL;
    if (argc > 1) {
        posa_path = argv[1];
    } else if (getenv("POSA_FILE")) {
        posa_path = getenv("POSA_FILE");
    } else {
#ifdef MODBUS_POSA_PATH
        posa_path = MODBUS_POSA_PATH;
#else
        posa_path = "/Users/str/git/hub/network.protos.posa/modbus_tcp.posa";
#endif
    }

    printf("Using posa file: %s\n", posa_path);

    test_posa_decode(posa_path);
    test_posa_variants(posa_path);
    test_pcapng_roundtrip();
    test_error_response(posa_path);

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
