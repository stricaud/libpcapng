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

/* bind/recall spans packets, so it needs the decoders loaded once and several
   dissections run against a chosen conversation — not decodes_to()'s
   load-and-dissect-in-one. */
static int recall_shows(const char *src, const char *conv,
                        const uint8_t *bind_pkt, int bind_len,
                        const uint8_t *call_pkt, int call_len,
                        const char *abbrev, const char *want, int want_warning)
{
    char err[256] = "";
    pcapng_field_t *root;
    char info[256] = "";
    int ok, warned;

    pcapng_posa_clear();
    pcapng_posa_binds_clear();
    if (pcapng_posa_load_text(src, err, sizeof err) < 0) {
        printf("      parse error: %s\n", err);
        return 0;
    }
    pcapng_posa_set_conversation(conv);
    if (bind_pkt) {                       /* the packet that establishes it */
        root = (pcapng_field_t *)calloc(1, sizeof *root);
        if (!root) return 0;
        pcapng_posa_dissect("BindPdu", bind_pkt, bind_len, root, 0, info, sizeof info);
        pcapng_field_free(root);
    }
    root = (pcapng_field_t *)calloc(1, sizeof *root);
    if (!root) return 0;
    pcapng_posa_dissect("CallPdu", call_pkt, call_len, root, 0, info, sizeof info);
    ok = label_has(root, abbrev, want);
    warned = pcapng_posa_warning_count() > 0;
    pcapng_field_free(root);
    if (!ok) printf("      '%s' did not show '%s'\n", abbrev, want);
    if (warned != want_warning)
        printf("      warning count %d, wanted %s\n",
               pcapng_posa_warning_count(), want_warning ? "one" : "none");
    return ok && warned == want_warning;
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

    /* ── uuid ────────────────────────────────────────────────────────────
       DCE/RPC interface UUIDs are deliberately near-identical: LSARPC ends
       …789ab, SAMR …789ac, and SPOOLSS shares LSARPC's whole second half while
       differing in the first four bytes. Keying on any single 32- or 64-bit
       slice conflates at least two of them, which is why the type exists and
       why the mixed-endian layout has to be exactly right. */
    SUITE("uuid");
    {
        static const char *SRC =
            "Lookup If\n"
            "    \"12345778-1234-abcd-ef00-0123456789ab\" = \"LSARPC\"\n"
            "    \"12345778-1234-abcd-ef00-0123456789ac\" = \"SAMR\"\n"
            "    \"12345678-1234-abcd-ef00-0123456789ab\" = \"SPOOLSS\"\n\n"
            "Object<main> T\n    abbrev \"t\"\n"
            "    required uuid iface lookup If \"Interface\"\n";
        /* time_low, time_mid and time_hi little-endian; the rest big-endian. */
        static const uint8_t LSA[]  = { 0x78,0x57,0x34,0x12, 0x34,0x12, 0xcd,0xab,
                                        0xef,0x00, 0x01,0x23,0x45,0x67,0x89,0xab };
        static const uint8_t SAMR[] = { 0x78,0x57,0x34,0x12, 0x34,0x12, 0xcd,0xab,
                                        0xef,0x00, 0x01,0x23,0x45,0x67,0x89,0xac };
        static const uint8_t SPL[]  = { 0x78,0x56,0x34,0x12, 0x34,0x12, 0xcd,0xab,
                                        0xef,0x00, 0x01,0x23,0x45,0x67,0x89,0xab };
        CHECK(decodes_to(SRC, "T", LSA,  16, "t.iface", "LSARPC"));
        CHECK(decodes_to(SRC, "T", SAMR, 16, "t.iface", "SAMR"));
        CHECK(decodes_to(SRC, "T", SPL,  16, "t.iface", "SPOOLSS"));
        /* The canonical rendering itself — a big-endian read would print the
           first three groups reversed and match nothing. */
        CHECK(decodes_to(SRC, "T", LSA, 16, "t.iface",
                         "12345778-1234-abcd-ef00-0123456789ab"));
    }

    /* ── expressions ─────────────────────────────────────────────────────
       A length that has to be worked out rather than read. Without these the
       decoder can only reach what a header states, not what it implies — the
       DCE/RPC auth trailer at frag_length - auth_length - 8, or a record list
       that starts on the next 4-byte boundary. */
    SUITE("expressions");
    {
        static const uint8_t LEN[] = { 0x0a, 0x03, 0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x77, 0x99 };
        /* len=5 then five bytes puts us at 6; the aligned field starts at 8. */
        static const uint8_t ALN[] = { 0x05, 'a','b','c','d',0x00, 0x00,0x00,
                                       0x11,0x22,0x33,0x44 };

        /* arithmetic straight inside bytes[] — no intermediate field */
        CHECK(decodes_to(
            "Object<main> T\n    abbrev \"t\"\n"
            "    required uint8 total \"Total\"\n"
            "    required uint8 hdr \"Header\"\n"
            "    required bytes[total - hdr] body \"Body\"\n",
            "T", LEN, (int)sizeof LEN, "t.body", "7 bytes"));

        /* seek to the next 4-byte boundary, using the `offset` built-in */
        CHECK(decodes_to(
            "Object<main> T\n    abbrev \"t\"\n"
            "    required uint8 len \"Len\"\n"
            "    required str[len] name \"Name\"\n"
            "    seek (offset + 3) & ~3\n"
            "    required uint32 after hex \"Aligned\"\n",
            "T", ALN, (int)sizeof ALN, "t.after", "0x11223344"));

        /* `let` names a derived value so it shows in the tree and can be reused */
        CHECK(decodes_to(
            "Object<main> T\n    abbrev \"t\"\n"
            "    required uint8 total \"Total\"\n"
            "    required uint8 hdr \"Header\"\n"
            "    let payload_len = total - hdr \"Payload Length\"\n",
            "T", LEN, (int)sizeof LEN, "t.payload_len", "7"));

        /* C precedence, not left-to-right */
        CHECK(decodes_to(
            "Object<main> T\n    abbrev \"t\"\n"
            "    required uint8 a \"A\"\n"
            "    let m = a * 2 + 1 \"M\"\n",
            "T", LEN, (int)sizeof LEN, "t.m", "21"));
        CHECK(decodes_to(
            "Object<main> T\n    abbrev \"t\"\n"
            "    required uint8 a \"A\"\n"
            "    let m = (a + 1) * 2 \"M\"\n",
            "T", LEN, (int)sizeof LEN, "t.m", "22"));

        /* A name that was never parsed yields no field, rather than a zero
           standing in for a length nobody computed. */
        CHECK(!decodes_to(
            "Object<main> T\n    abbrev \"t\"\n"
            "    required uint8 a \"A\"\n"
            "    let bad = nosuchfield + 1 \"Bad\"\n",
            "T", LEN, (int)sizeof LEN, "t.bad", "1"));
    }

    /* ── bind / recall ───────────────────────────────────────────────────
       A value stated once and referred to later only by a small id — DCE/RPC
       agrees an interface in its BIND and afterwards names it by context id
       alone. The store is keyed by the flow, so the two must not bleed between
       conversations, and a capture that missed the BIND must say so rather than
       show a confident wrong answer. */
    SUITE("bind / recall");
    {
        static const char *SRC =
            "Object<main> BindPdu\n    abbrev \"b\"\n"
            "    required uint8 kind = 1 \"Kind\"\n"
            "    required uint8 ctx_id \"Context ID\"\n"
            "    required uint8 iface \"Interface\"\n"
            "        7 = \"SVCCTL\"\n"
            "    bind interface[ctx_id] = iface\n\n"
            "Object<main> CallPdu\n    abbrev \"c\"\n"
            "    required uint8 kind = 2 \"Kind\"\n"
            "    required uint8 ctx_id \"Context ID\"\n"
            "    required uint8 opnum \"Opnum\"\n"
            "    recall interface[ctx_id] as iface \"Interface\"\n";
        static const uint8_t BIND[] = { 1, 1, 7 };   /* ctx 1 is SVCCTL   */
        static const uint8_t CALL[] = { 2, 1, 12 };  /* call on ctx 1     */
        static const uint8_t CALL9[] = { 2, 9, 12 }; /* call on ctx 9     */
        static const char *A = "1:aaaaaaaaaaaaaaaaaaaaaaaaaaa=";
        static const char *B = "1:bbbbbbbbbbbbbbbbbbbbbbbbbbb=";

        /* bound earlier in this conversation — recalled, no warning */
        CHECK(recall_shows(SRC, A, BIND, 3, CALL, 3, "c.iface", "SVCCTL", 0));

        /* the same context id in a different conversation must not resolve */
        CHECK(recall_shows(SRC, A, NULL, 0, CALL, 3, "c.iface", "not bound", 1));

        /* a context id nobody bound, in a conversation that did bind others */
        CHECK(recall_shows(SRC, A, BIND, 3, CALL9, 3, "c.iface", "not bound", 1));

        /* and the store really is per-conversation: bind under A, ask under B */
        {
            char err[256] = "";
            pcapng_field_t *root;
            char info[256] = "";
            pcapng_posa_clear(); pcapng_posa_binds_clear();
            pcapng_posa_load_text(SRC, err, sizeof err);
            pcapng_posa_set_conversation(A);
            root = (pcapng_field_t *)calloc(1, sizeof *root);
            pcapng_posa_dissect("BindPdu", BIND, 3, root, 0, info, sizeof info);
            pcapng_field_free(root);
            pcapng_posa_set_conversation(B);
            root = (pcapng_field_t *)calloc(1, sizeof *root);
            pcapng_posa_dissect("CallPdu", CALL, 3, root, 0, info, sizeof info);
            CHECK(!label_has(root, "c.iface", "SVCCTL"));
            pcapng_field_free(root);
        }
    }

    printf("\n=== Results: %d/%d passed", g_passed, g_tests);
    if (g_failed) printf(", %d FAILED", g_failed);
    printf(" ===\n");
    return g_failed ? 1 : 0;
}
