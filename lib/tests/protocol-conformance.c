/*
 * protocol-conformance.c — one capture per protocol, every field checked.
 *
 * The other tests here prove the library can write a file and read it back.
 * This one proves the decoders still say the same thing about the same bytes:
 * that ModbusTCP.function_code is still 3 for a packet whose eighth byte is 3,
 * and that it is still labelled READ_HOLDING_REGISTERS. It is what a release
 * should be held to.
 *
 * Tests are data, not code. One .spec file per protocol under tests/protocols/
 * describes the bytes and what they must decode to, so adding a protocol is
 * writing a dozen lines, not writing C:
 *
 *     name     Modbus/TCP read holding registers
 *     packet   tcp 10.0.0.1:45000 > 10.0.0.2:502 000100000006010300000001
 *     proto    Modbus/TCP
 *     info~    READ_HOLDING_REGISTERS
 *     field    ModbusTCP.transaction_id  1
 *     field    ModbusTCP.function_code   3
 *     label~   ModbusTCP.function_code   READ_HOLDING_REGISTERS
 *
 * A caution about how the expected values get there. Recording whatever the
 * dissector currently prints turns a test into a description of today's
 * behaviour, bugs included — it will notice a change but cannot tell you the
 * change was wrong. The values in these files are meant to be read off the
 * protocol's own specification and the packet's own bytes. Where a value here
 * is merely what the decoder happened to produce, the spec says so.
 *
 *   ./protocol-conformance                 run every spec
 *   ./protocol-conformance modbus_tcp      run one, by file stem
 *   ./protocol-conformance --write DIR     also write each spec's capture as
 *                                          pcapng, for opening in Wireshark
 *
 * Build via cmake (registered as the Protocol-Conformance ctest target).
 */

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libpcapng/blocks.h>
#include <libpcapng/dissect.h>
#include <libpcapng/easyapi.h>
#include <libpcapng/linktypes.h>

#define MAX_PACKETS   16
#define MAX_CHECKS    64
#define MAX_FRAME     2048
#define LINE_MAX_     2048

static int g_pass, g_fail, g_files, g_xfail, g_xpass;
static const char *g_spec;          /* file being run, for failure messages */
static int g_lineno;

/*
 * A check marked `xfail` is one whose expectation is right and whose decoder is
 * wrong. Recording the decoder's current answer instead would bake the bug into
 * the suite and quietly bless it; leaving the check to fail would make every
 * release red for a defect already known. So the expectation stays honest, the
 * failure is tolerated, and the day someone fixes the decoder the check passes
 * unexpectedly — which is itself reported as a failure, because the marker has
 * outlived its reason and should be deleted.
 */
static const char *g_xfail_reason;      /* set for the check being run */

static void ok(const char *what)
{
    if (g_xfail_reason) {
        g_xpass++;
        printf("    XPASS %s\n", what);
        printf("          this is marked xfail (%s) but passes —\n", g_xfail_reason);
        printf("          the decoder was fixed; remove the xfail at %s:%d\n", g_spec, g_lineno);
        return;
    }
    g_pass++;
    printf("    ok    %s\n", what);
}

static void bad(const char *what, const char *got, const char *want)
{
    if (g_xfail_reason) {
        g_xfail++;
        printf("    xfail %s\n", what);
        printf("          %s\n", g_xfail_reason);
        printf("          (got \"%s\", want \"%s\") %s:%d\n", got, want, g_spec, g_lineno);
        return;
    }
    g_fail++;
    printf("    FAIL  %s\n", what);
    printf("          expected: %s\n", want);
    printf("          got:      %s\n", got);
    printf("          (%s:%d)\n", g_spec, g_lineno);
}

/* ── check kinds ──────────────────────────────────────────────────────────── */

typedef enum {
    CHK_PROTO,        /* d->proto exactly            */
    CHK_INFO,         /* d->info exactly             */
    CHK_INFO_SUB,     /* d->info contains            */
    CHK_FIELD,        /* field's numeric value        */
    CHK_STR,          /* field's string exactly       */
    CHK_STR_SUB,      /* field's string contains      */
    CHK_LABEL_SUB,    /* field's label contains       */
    CHK_PRESENT,      /* field exists                 */
    CHK_ABSENT        /* field does not exist         */
} chk_kind_t;

typedef struct {
    chk_kind_t kind;
    char       abbrev[96];
    char       want[256];
    uint64_t   want_num;
    int        lineno;
    char       xfail[160];      /* empty unless this check is known-broken */
} check_t;

typedef struct {
    uint8_t  frame[MAX_FRAME];
    size_t   len;
    check_t  checks[MAX_CHECKS];
    int      ncheck;
} packet_t;

typedef struct {
    char      name[160];
    uint16_t  linktype;
    packet_t  pkt[MAX_PACKETS];
    int       npkt;
} spec_t;

/* ── building frames ──────────────────────────────────────────────────────── */

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Hex with optional separators, so a long payload can be grouped for reading. */
static int hex_decode(const char *s, uint8_t *out, size_t max, size_t *outlen)
{
    size_t n = 0;
    while (*s) {
        int hi, lo;
        if (*s == ' ' || *s == ':' || *s == '-' || *s == '\t') { s++; continue; }
        hi = hexval((unsigned char)*s++);
        if (hi < 0 || !*s) return -1;
        lo = hexval((unsigned char)*s++);
        if (lo < 0) return -1;
        if (n >= max) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    *outlen = n;
    return 0;
}

static int parse_ipv4(const char *s, uint8_t out[4])
{
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255) return -1;
    out[0] = (uint8_t)a; out[1] = (uint8_t)b; out[2] = (uint8_t)c; out[3] = (uint8_t)d;
    return 0;
}

static uint16_t ip_checksum(const uint8_t *h, size_t n)
{
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < n; i += 2) sum += (uint32_t)((h[i] << 8) | h[i + 1]);
    if (i < n) sum += (uint32_t)(h[i] << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xffff);
}

/*
 * eth dst/src are fixed and locally administered: a spec is about the protocol
 * under test, and MAC addresses that vary per file would be noise. 0x02 has the
 * IG bit clear, so it is a valid source address.
 */
static size_t build_eth(uint8_t *f, uint16_t ethertype)
{
    memset(f, 0x00, 6);
    memset(f + 6, 0x02, 6);
    f[12] = (uint8_t)(ethertype >> 8);
    f[13] = (uint8_t)(ethertype & 0xff);
    return 14;
}

static size_t build_ipv4(uint8_t *f, uint8_t proto, const uint8_t s[4],
                         const uint8_t d[4], size_t payload_len)
{
    uint16_t total = (uint16_t)(20 + payload_len), ck;
    memset(f, 0, 20);
    f[0] = 0x45;
    f[2] = (uint8_t)(total >> 8); f[3] = (uint8_t)(total & 0xff);
    f[4] = 0x00; f[5] = 0x01;              /* id */
    f[8] = 64;                              /* ttl */
    f[9] = proto;
    memcpy(f + 12, s, 4);
    memcpy(f + 16, d, 4);
    ck = ip_checksum(f, 20);
    f[10] = (uint8_t)(ck >> 8); f[11] = (uint8_t)(ck & 0xff);
    return 20;
}

/*
 * packet <kind> <src> > <dst> <hex>
 *
 *   tcp 10.0.0.1:45000 > 10.0.0.2:502  <payload hex>
 *   udp 10.0.0.1:40000 > 10.0.0.2:53   <payload hex>
 *   ip4 10.0.0.1 > 10.0.0.2 proto 1    <payload hex>     (raw IP protocol)
 *   eth 0x0806                         <payload hex>     (raw ethertype)
 */
static int build_packet(const char *rest, packet_t *p, char *err, size_t errlen)
{
    char kind[16] = "", a[64] = "", arrow[4] = "", b[64] = "", tail[LINE_MAX_] = "";
    uint8_t payload[MAX_FRAME];
    size_t plen = 0, off = 0;

    if (sscanf(rest, "%15s", kind) != 1) {
        snprintf(err, errlen, "packet: missing kind");
        return -1;
    }

    if (!strcmp(kind, "eth")) {
        unsigned et;
        if (sscanf(rest, "%15s %x %[^\n]", kind, &et, tail) < 2) {
            snprintf(err, errlen, "packet eth: expected ETHERTYPE HEX");
            return -1;
        }
        if (hex_decode(tail, payload, sizeof payload, &plen) < 0) {
            snprintf(err, errlen, "packet eth: bad hex");
            return -1;
        }
        off = build_eth(p->frame, (uint16_t)et);
        if (off + plen > MAX_FRAME) { snprintf(err, errlen, "frame too long"); return -1; }
        memcpy(p->frame + off, payload, plen);
        p->len = off + plen;
        return 0;
    }

    if (!strcmp(kind, "tcp") || !strcmp(kind, "udp")) {
        uint8_t sip[4], dip[4];
        char sa[48], da[48];
        unsigned sport, dport;
        if (sscanf(rest, "%15s %63s %3s %63s %[^\n]", kind, a, arrow, b, tail) < 4) {
            snprintf(err, errlen, "packet %s: expected SRC:PORT > DST:PORT HEX", kind);
            return -1;
        }
        if (sscanf(a, "%47[^:]:%u", sa, &sport) != 2 ||
            sscanf(b, "%47[^:]:%u", da, &dport) != 2) {
            snprintf(err, errlen, "packet %s: addresses need :port", kind);
            return -1;
        }
        if (parse_ipv4(sa, sip) < 0 || parse_ipv4(da, dip) < 0) {
            snprintf(err, errlen, "packet %s: bad IPv4 address", kind);
            return -1;
        }
        if (hex_decode(tail, payload, sizeof payload, &plen) < 0) {
            snprintf(err, errlen, "packet %s: bad hex payload", kind);
            return -1;
        }

        off = build_eth(p->frame, 0x0800);
        if (!strcmp(kind, "tcp")) {
            uint8_t *t;
            off += build_ipv4(p->frame + off, 6, sip, dip, 20 + plen);
            t = p->frame + off;
            memset(t, 0, 20);
            t[0] = (uint8_t)(sport >> 8); t[1] = (uint8_t)(sport & 0xff);
            t[2] = (uint8_t)(dport >> 8); t[3] = (uint8_t)(dport & 0xff);
            t[12] = 0x50;                   /* data offset 5, no options */
            t[13] = 0x18;                   /* PSH|ACK: an established data segment */
            t[14] = 0xff; t[15] = 0xff;     /* window */
            off += 20;
        } else {
            uint8_t *u;
            off += build_ipv4(p->frame + off, 17, sip, dip, 8 + plen);
            u = p->frame + off;
            u[0] = (uint8_t)(sport >> 8); u[1] = (uint8_t)(sport & 0xff);
            u[2] = (uint8_t)(dport >> 8); u[3] = (uint8_t)(dport & 0xff);
            u[4] = (uint8_t)((8 + plen) >> 8); u[5] = (uint8_t)((8 + plen) & 0xff);
            u[6] = 0; u[7] = 0;             /* checksum 0 = not computed, legal for IPv4 */
            off += 8;
        }
        if (off + plen > MAX_FRAME) { snprintf(err, errlen, "frame too long"); return -1; }
        memcpy(p->frame + off, payload, plen);
        p->len = off + plen;
        return 0;
    }

    if (!strcmp(kind, "ip4")) {
        uint8_t sip[4], dip[4];
        unsigned proto;
        if (sscanf(rest, "%15s %63s %3s %63s proto %u %[^\n]",
                   kind, a, arrow, b, &proto, tail) < 5) {
            snprintf(err, errlen, "packet ip4: expected SRC > DST proto N HEX");
            return -1;
        }
        if (parse_ipv4(a, sip) < 0 || parse_ipv4(b, dip) < 0) {
            snprintf(err, errlen, "packet ip4: bad address");
            return -1;
        }
        if (hex_decode(tail, payload, sizeof payload, &plen) < 0) {
            snprintf(err, errlen, "packet ip4: bad hex");
            return -1;
        }
        off  = build_eth(p->frame, 0x0800);
        off += build_ipv4(p->frame + off, (uint8_t)proto, sip, dip, plen);
        if (off + plen > MAX_FRAME) { snprintf(err, errlen, "frame too long"); return -1; }
        memcpy(p->frame + off, payload, plen);
        p->len = off + plen;
        return 0;
    }

    snprintf(err, errlen, "packet: unknown kind '%s'", kind);
    return -1;
}

/* ── spec parsing ─────────────────────────────────────────────────────────── */

static char *trim(char *s)
{
    char *e;
    while (*s == ' ' || *s == '\t') s++;
    e = s + strlen(s);
    while (e > s && (e[-1]=='\n' || e[-1]=='\r' || e[-1]==' ' || e[-1]=='\t')) e--;
    *e = '\0';
    return s;
}

/* Set by an `xfail` line and consumed by the check that follows it. */
static char g_pending_xfail[160];

static int add_check(packet_t *p, chk_kind_t kind, const char *abbrev,
                     const char *want, int lineno, char *err, size_t errlen)
{
    check_t *c;
    if (p->ncheck >= MAX_CHECKS) { snprintf(err, errlen, "too many checks"); return -1; }
    c = &p->checks[p->ncheck++];
    memset(c, 0, sizeof *c);
    snprintf(c->xfail, sizeof c->xfail, "%s", g_pending_xfail);
    g_pending_xfail[0] = '\0';
    c->kind = kind;
    c->lineno = lineno;
    if (abbrev) snprintf(c->abbrev, sizeof c->abbrev, "%s", abbrev);
    if (want)   snprintf(c->want,   sizeof c->want,   "%s", want);
    if (kind == CHK_FIELD) c->want_num = strtoull(want, NULL, 0);
    return 0;
}

static int spec_load(const char *path, spec_t *sp, char *err, size_t errlen)
{
    FILE *fp = fopen(path, "r");
    char line[LINE_MAX_];
    int lineno = 0;

    if (!fp) { snprintf(err, errlen, "cannot open %s", path); return -1; }
    memset(sp, 0, sizeof *sp);
    sp->linktype = LINKTYPE_ETHERNET;

    while (fgets(line, sizeof line, fp)) {
        char *s, kw[32] = "";
        const char *rest;
        packet_t *cur;
        lineno++;
        s = trim(line);
        if (!*s || *s == '#') continue;

        sscanf(s, "%31s", kw);
        rest = s + strlen(kw);
        while (*rest == ' ' || *rest == '\t') rest++;

        if (!strcmp(kw, "name")) { snprintf(sp->name, sizeof sp->name, "%s", rest); continue; }
        if (!strcmp(kw, "linktype")) {
            if (!strcmp(rest, "ethernet"))   sp->linktype = LINKTYPE_ETHERNET;
            else if (!strcmp(rest, "raw"))   sp->linktype = LINKTYPE_RAW;
            else { snprintf(err, errlen, "%s:%d: unknown linktype", path, lineno); fclose(fp); return -1; }
            continue;
        }
        if (!strcmp(kw, "packet")) {
            if (sp->npkt >= MAX_PACKETS) { snprintf(err, errlen, "%s:%d: too many packets", path, lineno); fclose(fp); return -1; }
            cur = &sp->pkt[sp->npkt];
            memset(cur, 0, sizeof *cur);
            if (build_packet(rest, cur, err, errlen) < 0) {
                char tmp[256];
                snprintf(tmp, sizeof tmp, "%s:%d: %s", path, lineno, err);
                snprintf(err, errlen, "%s", tmp);
                fclose(fp);
                return -1;
            }
            sp->npkt++;
            continue;
        }

        if (sp->npkt == 0) {
            snprintf(err, errlen, "%s:%d: '%s' before any packet", path, lineno, kw);
            fclose(fp); return -1;
        }
        cur = &sp->pkt[sp->npkt - 1];

        {
            char abbrev[96] = "", want[256] = "";
            int rc = 0;
            if (!strcmp(kw, "xfail")) {
                if (!*rest) { snprintf(err, errlen, "%s:%d: xfail needs a reason", path, lineno);
                              fclose(fp); return -1; }
                snprintf(g_pending_xfail, sizeof g_pending_xfail, "%s", rest);
                continue;
            }
            if      (!strcmp(kw, "proto")) rc = add_check(cur, CHK_PROTO, NULL, rest, lineno, err, errlen);
            else if (!strcmp(kw, "info"))  rc = add_check(cur, CHK_INFO,  NULL, rest, lineno, err, errlen);
            else if (!strcmp(kw, "info~")) rc = add_check(cur, CHK_INFO_SUB, NULL, rest, lineno, err, errlen);
            else if (!strcmp(kw, "present")) rc = add_check(cur, CHK_PRESENT, rest, NULL, lineno, err, errlen);
            else if (!strcmp(kw, "absent"))  rc = add_check(cur, CHK_ABSENT,  rest, NULL, lineno, err, errlen);
            else if (!strcmp(kw, "field") || !strcmp(kw, "str") ||
                     !strcmp(kw, "str~")  || !strcmp(kw, "label~")) {
                if (sscanf(rest, "%95s %255[^\n]", abbrev, want) != 2) {
                    snprintf(err, errlen, "%s:%d: %s needs FIELD VALUE", path, lineno, kw);
                    fclose(fp); return -1;
                }
                trim(want);
                rc = add_check(cur,
                        !strcmp(kw, "field")  ? CHK_FIELD :
                        !strcmp(kw, "str")    ? CHK_STR   :
                        !strcmp(kw, "str~")   ? CHK_STR_SUB : CHK_LABEL_SUB,
                        abbrev, want, lineno, err, errlen);
            } else {
                snprintf(err, errlen, "%s:%d: unknown directive '%s'", path, lineno, kw);
                fclose(fp); return -1;
            }
            if (rc < 0) { fclose(fp); return -1; }
        }
    }
    fclose(fp);
    if (sp->npkt == 0) { snprintf(err, errlen, "%s: no packets", path); return -1; }
    return 0;
}

/* ── running ──────────────────────────────────────────────────────────────── */

static void run_check(const check_t *c, const pcapng_dissection_t *d)
{
    char what[512];
    pcapng_field_t *hits[8];
    int n = 0;

    g_lineno = c->lineno;
    g_xfail_reason = c->xfail[0] ? c->xfail : NULL;

    if (c->abbrev[0])
        n = pcapng_field_collect(d->root, c->abbrev, hits, 8);

    switch (c->kind) {
    case CHK_PROTO:
        snprintf(what, sizeof what, "protocol is %s", c->want);
        if (!strcmp(d->proto, c->want)) ok(what); else bad(what, d->proto, c->want);
        return;
    case CHK_INFO:
        snprintf(what, sizeof what, "info is \"%s\"", c->want);
        if (!strcmp(d->info, c->want)) ok(what); else bad(what, d->info, c->want);
        return;
    case CHK_INFO_SUB:
        snprintf(what, sizeof what, "info contains \"%s\"", c->want);
        if (strstr(d->info, c->want)) ok(what); else bad(what, d->info, c->want);
        return;
    case CHK_PRESENT:
        snprintf(what, sizeof what, "%s is present", c->abbrev);
        if (n > 0) ok(what); else bad(what, "not in the tree", "present");
        return;
    case CHK_ABSENT:
        snprintf(what, sizeof what, "%s is absent", c->abbrev);
        if (n == 0) ok(what);
        else { char got[128]; snprintf(got, sizeof got, "found %d node(s)", n); bad(what, got, "absent"); }
        return;
    default:
        break;
    }

    if (n <= 0) {
        snprintf(what, sizeof what, "%s == %s", c->abbrev, c->want);
        bad(what, "field not in the tree", c->want);
        return;
    }

    switch (c->kind) {
    case CHK_FIELD: {
        char got[64];
        snprintf(what, sizeof what, "%s == %s", c->abbrev, c->want);
        if (hits[0]->u == c->want_num) { ok(what); return; }
        snprintf(got, sizeof got, "%llu", (unsigned long long)hits[0]->u);
        bad(what, got, c->want);
        return;
    }
    case CHK_STR:
        snprintf(what, sizeof what, "%s is \"%s\"", c->abbrev, c->want);
        if (!strcmp(hits[0]->str, c->want)) ok(what); else bad(what, hits[0]->str, c->want);
        return;
    case CHK_STR_SUB:
        snprintf(what, sizeof what, "%s contains \"%s\"", c->abbrev, c->want);
        if (strstr(hits[0]->str, c->want)) ok(what); else bad(what, hits[0]->str, c->want);
        return;
    case CHK_LABEL_SUB: {
        int i;
        snprintf(what, sizeof what, "%s label contains \"%s\"", c->abbrev, c->want);
        /* Any node with this abbrev will do: a repeated field (a DNS answer,
           a Modbus register) legitimately appears more than once. */
        for (i = 0; i < n; i++)
            if (strstr(hits[i]->label, c->want)) { ok(what); return; }
        bad(what, hits[0]->label, c->want);
        return;
    }
    default:
        return;
    }
}

static void spec_run(const spec_t *sp, const char *stem, const char *write_dir)
{
    int i, j;

    printf("\n[%s] %s\n", stem, sp->name);
    g_files++;

    /* Each spec is its own capture, so sticky flow classification from the
       previous one cannot leak into this one. */
    pcapng_dissect_reset_flows();

    for (i = 0; i < sp->npkt; i++) {
        const packet_t *p = &sp->pkt[i];
        pcapng_dissection_t *d;

        if (sp->npkt > 1) printf("  packet %d\n", i + 1);
        d = pcapng_dissect(p->frame, (uint32_t)p->len, (uint32_t)p->len, sp->linktype);
        if (!d) {
            g_fail++;
            printf("    FAIL  dissection returned nothing\n");
            continue;
        }
        for (j = 0; j < p->ncheck; j++) run_check(&p->checks[j], d);
        pcapng_dissection_free(d);
    }

    if (write_dir) {
        char path[1024];
        FILE *fp;
        snprintf(path, sizeof path, "%s/%s.pcapng", write_dir, stem);
        fp = fopen(path, "wb");
        if (!fp) { printf("    (cannot write %s)\n", path); return; }
        libpcapng_write_header_to_file_with_linktype(fp, sp->linktype);
        for (i = 0; i < sp->npkt; i++) {
            uint8_t copy[MAX_FRAME];
            memcpy(copy, sp->pkt[i].frame, sp->pkt[i].len);
            libpcapng_write_enhanced_packet_to_file(fp, copy, sp->pkt[i].len);
        }
        fclose(fp);
        printf("    wrote %s\n", path);
    }
}

/* ── entry ────────────────────────────────────────────────────────────────── */

static int ends_with(const char *s, const char *suf)
{
    size_t a = strlen(s), b = strlen(suf);
    return a > b && !strcmp(s + a - b, suf);
}

int main(int argc, char **argv)
{
    const char *dir = getenv("PROTOCOL_SPEC_DIR");
    const char *write_dir = NULL, *only = NULL;
    char err[512] = "";
    DIR *dp;
    struct dirent *ent;
    char *names[512];
    int nnames = 0, i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--write") && i + 1 < argc) { write_dir = argv[++i]; continue; }
        if (!strcmp(argv[i], "--dir")   && i + 1 < argc) { dir = argv[++i]; continue; }
        only = argv[i];
    }
    if (!dir) dir = PROTOCOL_SPEC_DIR_DEFAULT;

    /* Decoders have to be loaded before the first dissection, not during it. */
    pcapng_dissect_ensure_protocols();

    dp = opendir(dir);
    if (!dp) {
        fprintf(stderr, "protocol-conformance: cannot open %s\n", dir);
        return 1;
    }
    while ((ent = readdir(dp)) && nnames < 512)
        if (ends_with(ent->d_name, ".spec")) names[nnames++] = strdup(ent->d_name);
    closedir(dp);

    /* Alphabetical, so a failure is always in the same place in the output. */
    for (i = 1; i < nnames; i++) {
        char *k = names[i];
        int j2 = i - 1;
        while (j2 >= 0 && strcmp(names[j2], k) > 0) { names[j2 + 1] = names[j2]; j2--; }
        names[j2 + 1] = k;
    }

    printf("=== protocol conformance ===\nspecs from %s\n", dir);

    for (i = 0; i < nnames; i++) {
        char path[1024], stem[256];
        spec_t sp;

        snprintf(stem, sizeof stem, "%s", names[i]);
        stem[strlen(stem) - 5] = '\0';                 /* drop ".spec" */
        if (only && strcmp(stem, only)) { free(names[i]); continue; }

        snprintf(path, sizeof path, "%s/%s", dir, names[i]);
        g_spec = path;
        if (spec_load(path, &sp, err, sizeof err) < 0) {
            g_fail++;
            printf("\n[%s]\n    FAIL  %s\n", stem, err);
            free(names[i]);
            continue;
        }
        spec_run(&sp, stem, write_dir);
        free(names[i]);
    }

    if (only && g_files == 0) {
        fprintf(stderr, "protocol-conformance: no spec named '%s'\n", only);
        return 1;
    }

    printf("\n%d spec(s), %d check(s) passed, %d failed", g_files, g_pass, g_fail);
    if (g_xfail) printf(", %d known-broken", g_xfail);
    if (g_xpass) printf(", %d NO LONGER BROKEN", g_xpass);
    printf("\n");
    /* An xfail that starts passing fails the run: the marker is now a lie. */
    return (g_fail || g_xpass) ? 1 : 0;
}
