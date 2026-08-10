/*
 * posa.c — decoder-language tests for the posa parser and dissector
 *
 * Covers the parts of the language the shell-based pcapsh suite cannot reach.
 * pcapsh walks a decoder's fields flatly, so it never evaluates `bits`,
 * `when`, `scope` or `repeat`; those live only in the library dissector, and
 * so do the bugs that used to hide in them.
 *
 * Every case here is a value that once rendered as a bare number while the
 * tree around it still looked correct — the failure mode worth a regression
 * test, because nothing about the output says it went wrong.
 *
 * Build via cmake (registered as the Posa ctest target), or manually:
 *   cc -I../include -o posa posa.c -lpcapng
 *   ./posa
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libpcapng/posa.h>
#include <libpcapng/dissect.h>

/* ── Minimal test harness ──────────────────────────────────────────────── */

static int g_tests  = 0;
static int g_passed = 0;
static int g_failed = 0;

#define SUITE(name)  printf("\n[%s]\n", (name))

#define CHECK(expr) do {                                                       \
    g_tests++;                                                                 \
    if (expr) {                                                                \
        g_passed++;                                                            \
        printf("  PASS  %s\n", #expr);                                         \
    } else {                                                                   \
        g_failed++;                                                            \
        printf("  FAIL  %s  (%s:%d)\n", #expr, __FILE__, __LINE__);            \
    }                                                                          \
} while(0)

/* Does any node with this abbrev carry `want` in its label? Labels read
   "Display: Name (value)", so asking for the name is how we tell a resolved
   enum from a bare number. */
static int label_has(pcapng_field_t *root, const char *abbrev, const char *want)
{
    pcapng_field_t *hits[16];
    int n, i;
    n = pcapng_field_collect(root, abbrev, hits, (int)(sizeof hits / sizeof hits[0]));
    for (i = 0; i < n; i++)
        if (strstr(hits[i]->label, want)) return 1;
    return 0;
}

static int decodes_to(const char *src, const char *proto,
                      const uint8_t *data, int len,
                      const char *abbrev, const char *want)
{
    char err[256] = "";
    pcapng_field_t *root;
    char info[256] = "";
    int ok;

    pcapng_posa_clear();
    if (pcapng_posa_load_text(src, err, sizeof err) < 0) {
        printf("      parse error: %s\n", err);
        return 0;
    }
    root = (pcapng_field_t *)calloc(1, sizeof *root);
    if (!root) return 0;
    pcapng_posa_dissect(proto, data, len, root, 0, info, sizeof info);
    ok = label_has(root, abbrev, want);
    if (!ok) printf("      '%s' did not resolve to '%s'\n", abbrev, want);
    pcapng_field_free(root);
    return ok;
}

int main(void)
{
    static const uint8_t ONE[]  = { 0x04 };
    static const uint8_t NAL[]  = { 0x65, 0x88 };          /* H.264 IDR slice   */
    static const uint8_t VINT[] = { 0x04, 0x05, 0x06, 0x44, 0x00, 0x01, 0x10 };

    printf("=== posa decoder-language tests ===\n");

    /* ── Enum spellings ──────────────────────────────────────────────────
       Only `NAME = value` used to resolve. `value = "Label"` — the spelling
       the shipped iec104, knxnetip, capwap and diameter decoders all use —
       parsed without complaint and produced nothing. */
    SUITE("enum spellings");

    CHECK(decodes_to(
        "Object<main> T\n    abbrev \"t\"\n    required uint8 a \"A\"\n        SETTINGS = 4\n",
        "T", ONE, 1, "t.a", "SETTINGS"));

    CHECK(decodes_to(
        "Object<main> T\n    abbrev \"t\"\n    required uint8 a \"A\"\n        4 = \"SETTINGS\"\n",
        "T", ONE, 1, "t.a", "SETTINGS"));

    CHECK(decodes_to(
        "Object<main> T\n    abbrev \"t\"\n    required uint8 a \"A\"\n        4 = SETTINGS\n",
        "T", ONE, 1, "t.a", "SETTINGS"));

    /* A name that is itself numeric on both sides must keep the legacy
       reading — name on the left — or older decoders change meaning. */
    CHECK(decodes_to(
        "Object<main> T\n    abbrev \"t\"\n    required uint8 a \"A\"\n        4 = 9\n",
        "T", ONE, 1, "t.a", "4"));

    /* ── Lookup tables ───────────────────────────────────────────────────
       `lookup` resolved for text fields only; on a numeric field it was
       parsed and then ignored. */
    SUITE("lookup tables");

    CHECK(decodes_to(
        "Lookup Tbl\n    4 = \"SETTINGS\"\n\n"
        "Object<main> T\n    abbrev \"t\"\n    required uint8 a lookup Tbl \"A\"\n",
        "T", ONE, 1, "t.a", "SETTINGS"));

    CHECK(decodes_to(
        "Lookup Tbl\n    4 = \"SETTINGS\"\n\n"
        "Object<main> T\n    abbrev \"t\"\n    required quic_varint a lookup Tbl \"A\"\n",
        "T", ONE, 1, "t.a", "SETTINGS"));

    /* A `bits` line has no room for the reference among its five positional
       arguments, so the table is named on the line below — the form capwap
       and the H.264/H.265 decoders use. This never resolved at all. */
    CHECK(decodes_to(
        "Lookup Nal\n    5 = \"IDR\"\n\n"
        "Object<main> T\n    abbrev \"t\"\n"
        "    required uint8 h hex \"Header\"\n"
        "    bits h nal_type 0 5 \"Type\"\n        lookup Nal\n",
        "T", NAL, 2, "t.nal_type", "IDR"));

    /* …and inline after the width, for symmetry. */
    CHECK(decodes_to(
        "Lookup Nal\n    5 = \"IDR\"\n\n"
        "Object<main> T\n    abbrev \"t\"\n"
        "    required uint8 h hex \"Header\"\n"
        "    bits h nal_type 0 5 lookup Nal \"Type\"\n",
        "T", NAL, 2, "t.nal_type", "IDR"));

    /* Inline enums on a bits field must still win over the table. */
    CHECK(decodes_to(
        "Lookup Nal\n    5 = \"FromTable\"\n\n"
        "Object<main> T\n    abbrev \"t\"\n"
        "    required uint8 h hex \"Header\"\n"
        "    bits h nal_type 0 5 \"Type\"\n        5 = \"Inline\"\n        lookup Nal\n",
        "T", NAL, 2, "t.nal_type", "Inline"));

    /* ── Variable-length integers driving structure ──────────────────────
       A varint whose width is guessed rather than read shifts every field
       after it, and the tree still renders. Check the value reaches `scope`,
       which is what bounds the records inside it. */
    SUITE("varint drives structure");

    CHECK(decodes_to(
        "Object<main> T\n    abbrev \"t\"\n"
        "    required quic_varint ftype \"Type\"\n"
        "        4 = \"SETTINGS\"\n"
        "    required quic_varint flen \"Length\"\n"
        "    scope flen\n"
        "        repeat until end as kv \"Settings\"\n"
        "            required quic_varint id \"Identifier\"\n"
        "            required quic_varint val \"Value\"\n",
        "T", VINT, (int)sizeof VINT, "t.val", "1024"));

    printf("\n=== Results: %d/%d passed", g_passed, g_tests);
    if (g_failed) printf(", %d FAILED", g_failed);
    printf(" ===\n");
    return g_failed ? 1 : 0;
}
