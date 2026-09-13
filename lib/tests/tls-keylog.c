/*
 * tls-keylog.c — unit tests for pcapng_tls_keylog_* (parse path only;
 * no OpenSSL decryption required).
 *
 * Tests:
 *  - load_text(): valid entries are counted correctly
 *  - load_text(): invalid/comment lines are silently skipped
 *  - loaded(): reflects entry count after load and after clear
 *  - load_text() accumulates across multiple calls
 *  - ingest_dsb(): DSB body (4-byte type prefix + keylog text) is parsed
 *  - load_file(): reads from a temp file
 *
 * Build via cmake (TLS-Keylog ctest target).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <libpcapng/tls_keylog.h>

/* ── harness ──────────────────────────────────────────────────────────────── */

static int g_pass = 0, g_fail = 0;

#define SUITE(name) printf("\n[%s]\n", name)

#define CHECK(label, expr) do {                                         \
    if (expr) { g_pass++; printf("  PASS  %s\n", label); }            \
    else       { g_fail++; printf("  FAIL  %s  (%s:%d)\n",            \
                                  label, __FILE__, __LINE__); }        \
} while(0)

/* ── synthetic keylog data ────────────────────────────────────────────────── */

/* CLIENT_RANDOM: 32 bytes = 64 hex chars (8 groups of 8). */
#define CR1 "aabbccdd" "aabbccdd" "aabbccdd" "aabbccdd" \
            "aabbccdd" "aabbccdd" "aabbccdd" "aabbccdd"

/* Master secret (TLS 1.2): 48 bytes = 96 hex chars (12 groups of 8). */
#define MS1 "11223344" "11223344" "11223344" "11223344" \
            "11223344" "11223344" "11223344" "11223344" \
            "11223344" "11223344" "11223344" "11223344"

#define CR2 "deadbeef" "deadbeef" "deadbeef" "deadbeef" \
            "deadbeef" "deadbeef" "deadbeef" "deadbeef"

#define MS2 "cafebabe" "cafebabe" "cafebabe" "cafebabe" \
            "cafebabe" "cafebabe" "cafebabe" "cafebabe" \
            "cafebabe" "cafebabe" "cafebabe" "cafebabe"

/* TLS 1.3 traffic secret: 48 bytes = 96 hex chars (12 groups of 8). */
#define TS1 "0102030405060708" "0102030405060708" \
            "0102030405060708" "0102030405060708" \
            "0102030405060708" "0102030405060708" \
            "0102030405060708" "0102030405060708" \
            "0102030405060708" "0102030405060708" \
            "0102030405060708" "0102030405060708"

static const char *KEYLOG_VALID =
    "# TLS keylog file\n"
    "CLIENT_RANDOM " CR1 " " MS1 "\n"
    "CLIENT_RANDOM " CR2 " " MS2 "\n";

static const char *KEYLOG_WITH_GARBAGE =
    "# comment at start\n"
    "CLIENT_RANDOM " CR1 " " MS1 "\n"
    "INVALID_LABEL whatever\n"
    "   \n"             /* blank line */
    "CLIENT_RANDOM " CR2 " " MS2 "\n"
    "# trailing comment\n";

static const char *KEYLOG_TLS13 =
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET " CR1 " " TS1 "\n"
    "SERVER_HANDSHAKE_TRAFFIC_SECRET " CR1 " " TS1 "\n"
    "CLIENT_TRAFFIC_SECRET_0 "         CR1 " " TS1 "\n"
    "SERVER_TRAFFIC_SECRET_0 "         CR1 " " TS1 "\n";

/* ── tests ────────────────────────────────────────────────────────────────── */

static void test_basic_load(void)
{
    SUITE("load_text basic");

    pcapng_tls_keylog_clear();
    CHECK("initially not loaded", pcapng_tls_keylog_loaded() == 0);

    int n = pcapng_tls_keylog_load_text(KEYLOG_VALID);
    CHECK("load_text returns 2 for two entries", n == 2);
    CHECK("loaded() is non-zero after load", pcapng_tls_keylog_loaded() != 0);
}

static void test_garbage_skipped(void)
{
    SUITE("load_text skips garbage");

    pcapng_tls_keylog_clear();
    int n = pcapng_tls_keylog_load_text(KEYLOG_WITH_GARBAGE);
    /* valid lines: 2 CLIENT_RANDOM; INVALID_LABEL and comments are skipped */
    CHECK("only valid entries counted", n == 2);
    CHECK("loaded is non-zero", pcapng_tls_keylog_loaded() != 0);
}

static void test_tls13_labels(void)
{
    SUITE("load_text TLS 1.3 labels");

    pcapng_tls_keylog_clear();
    int n = pcapng_tls_keylog_load_text(KEYLOG_TLS13);
    /* 4 TLS 1.3 traffic-secret entries */
    CHECK("4 TLS 1.3 entries loaded", n == 4);
    CHECK("loaded is non-zero", pcapng_tls_keylog_loaded() != 0);
}

static void test_accumulate(void)
{
    SUITE("load_text accumulates");

    pcapng_tls_keylog_clear();
    int n1 = pcapng_tls_keylog_load_text(KEYLOG_VALID);
    int n2 = pcapng_tls_keylog_load_text(KEYLOG_TLS13);
    CHECK("first load returns 2",  n1 == 2);
    CHECK("second load returns 4", n2 == 4);
    /* loaded() is a boolean — non-zero means at least one entry is present */
    CHECK("loaded() reflects both loads", pcapng_tls_keylog_loaded() != 0);
}

static void test_clear(void)
{
    SUITE("clear");

    pcapng_tls_keylog_clear();
    pcapng_tls_keylog_load_text(KEYLOG_VALID);
    CHECK("loaded before clear", pcapng_tls_keylog_loaded() != 0);

    pcapng_tls_keylog_clear();
    CHECK("not loaded after clear", pcapng_tls_keylog_loaded() == 0);

    /* second clear is idempotent */
    pcapng_tls_keylog_clear();
    CHECK("double clear is safe", pcapng_tls_keylog_loaded() == 0);
}

static void test_empty_and_null(void)
{
    SUITE("edge cases");

    pcapng_tls_keylog_clear();

    int n = pcapng_tls_keylog_load_text("");
    CHECK("empty string returns 0", n == 0);

    n = pcapng_tls_keylog_load_text("# only comments\n# another\n");
    CHECK("only comments returns 0", n == 0);

    CHECK("loaded still 0 after no valid entries", pcapng_tls_keylog_loaded() == 0);
}

static void test_load_file(void)
{
    SUITE("load_file");

    const char *path = "/tmp/test_keylog.txt";
    FILE *f = fopen(path, "w");
    assert(f);
    fputs(KEYLOG_VALID, f);
    fclose(f);

    pcapng_tls_keylog_clear();
    int n = pcapng_tls_keylog_load_file(path);
    CHECK("load_file returns 2", n == 2);
    CHECK("loaded() after load_file", pcapng_tls_keylog_loaded() != 0);

    /* non-existent file */
    pcapng_tls_keylog_clear();
    n = pcapng_tls_keylog_load_file("/tmp/does_not_exist_keylog.txt");
    CHECK("load_file non-existent returns -1", n == -1);
    CHECK("loaded() still 0", pcapng_tls_keylog_loaded() == 0);
}

static void test_ingest_dsb(void)
{
    SUITE("ingest_dsb");

    /*
     * DSB body layout: 4-byte secrets_type (0x544c534b "TLSK") followed by
     * the raw keylog text.  ingest_dsb() skips the first 4 bytes.
     */
    const char *text = KEYLOG_VALID;
    size_t text_len  = strlen(text);

    uint8_t *dsb_body = malloc(4 + text_len);
    assert(dsb_body);

    /* secrets_type = 0x544c534b in little-endian (pcapng default) */
    dsb_body[0] = 0x4b; dsb_body[1] = 0x53; dsb_body[2] = 0x4c; dsb_body[3] = 0x54;
    memcpy(dsb_body + 4, text, text_len);

    pcapng_tls_keylog_clear();
    pcapng_tls_keylog_ingest_dsb(dsb_body, (uint32_t)(4 + text_len));
    CHECK("ingest_dsb populates store", pcapng_tls_keylog_loaded() != 0);

    free(dsb_body);

    /* minimal body (just the 4-byte type, no text) must not crash */
    pcapng_tls_keylog_clear();
    uint8_t hdr[4] = {0x4b, 0x53, 0x4c, 0x54};
    pcapng_tls_keylog_ingest_dsb(hdr, 4);
    CHECK("ingest_dsb empty text body does not crash", 1);
    CHECK("loaded() still 0 for empty text", pcapng_tls_keylog_loaded() == 0);
}

int main(void)
{
    printf("=== tls-keylog ===\n");

    test_basic_load();
    test_garbage_skipped();
    test_tls13_labels();
    test_accumulate();
    test_clear();
    test_empty_and_null();
    test_load_file();
    test_ingest_dsb();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
