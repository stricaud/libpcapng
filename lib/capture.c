/*
 * capture.c — live packet capture for libpcapng
 *
 * Platform backends:
 *   Linux : AF_PACKET + TPACKET_V3 ring buffer (true zero-copy)
 *   macOS : /dev/bpfN  (large read buffer, minimal copies)
 *
 * Filter engine:
 *   Wireshark-style display filter parser (recursive-descent) operating
 *   on raw packet bytes via a lightweight built-in dissector.  Unknown
 *   fields are routed to the registered pcapng_field_provider_t.
 *
 * License: MIT
 * Copyright (c) 2024 Sebastien Tricaud
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <regex.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include <sys/types.h>

/* Windows has no capture backend (see the platform stubs at the bottom of this
   file), so it needs none of the POSIX socket/mmap machinery — only the byte
   order + inet_ntop helpers the display-filter engine uses. */
#ifdef _WIN32
#  include <libpcapng/win_compat.h>
#else
#  include <sys/socket.h>
#  include <sys/mman.h>
#  include <sys/ioctl.h>
#  include <net/if.h>
#  include <ifaddrs.h>
#  include <poll.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <arpa/inet.h>
#  include <netinet/in.h>
#endif

#if defined(__linux__)
#  include <linux/if_packet.h>
#  include <linux/if_ether.h>
#  include <linux/sockios.h>
#  include <linux/net_tstamp.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#  include <net/bpf.h>
#  include <net/if_dl.h>
#endif

#include "libpcapng/capture.h"
#include "libpcapng/easyapi.h"
#include "libpcapng/linktypes.h"

/* ========================================================================
 * Constants
 * ======================================================================== */

#define CAP_DEFAULT_SNAPLEN     65535u
#define CAP_DEFAULT_TIMEOUT_MS  100
#define CAP_DEFAULT_BUF_SIZE    (16u * 1024u * 1024u)   /* 16 MB */

/* Linux TPACKET_V3: block and frame layout */
#define CAP_BLOCK_SIZE          (1u << 22)               /* 4 MB per block */
#define CAP_BLOCK_NR            4u                       /* 4 blocks = 16 MB */

/* BPF read-buffer size on macOS */
#define CAP_BPF_BUF_SIZE        (4u * 1024u * 1024u)    /* 4 MB */

/* Linktype for Ethernet (from linktypes.h) */
#ifndef LINKTYPE_ETHERNET
#define LINKTYPE_ETHERNET 1
#endif
#ifndef LINKTYPE_RAW
#define LINKTYPE_RAW 101
#endif

/* ========================================================================
 * Filter engine — internal types
 * (Ported from caracal/src/filter.c, adapted for raw-byte evaluation.)
 * ======================================================================== */

typedef enum { OP_EQ, OP_NE, OP_GT, OP_LT, OP_GE, OP_LE,
               OP_CONTAINS, OP_MATCHES } op_t;

typedef enum { N_AND, N_OR, N_NOT, N_EXISTS, N_CMP } ntype_t;

typedef struct fnode {
    ntype_t      type;
    struct fnode *a, *b;
    char          field[80];
    op_t          op;
    char          value[160];
} fnode_t;

typedef struct {
    fnode_t *root;
    int      match_all;
} cap_filter_t;

/* ---- Lexer ---- */

typedef enum { T_WORD, T_STR, T_LP, T_RP, T_LC, T_RC, T_AND, T_OR, T_NOT,
               T_EQ, T_NE, T_GT, T_LT, T_GE, T_LE, T_IN,
               T_CONTAINS, T_MATCHES, T_COMMA, T_BITAND, T_EOF } ttype_t;

typedef struct { ttype_t t; char s[160]; } tok_t;
typedef struct { const char *p; tok_t cur; char err[200]; } lex_t;

static int word_ch(int c)
{ return isalnum(c) || c == '.' || c == '_' || c == ':' || c == '-' || c == '/'; }

static void lex_next(lex_t *L)
{
    const char *p = L->p;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) { L->cur.t = T_EOF; L->cur.s[0] = '\0'; L->p = p; return; }

    switch (*p) {
    case '(': L->cur.t = T_LP;  L->p = p + 1; return;
    case ')': L->cur.t = T_RP;  L->p = p + 1; return;
    case '{': L->cur.t = T_LC;  L->p = p + 1; return;
    case '}': L->cur.t = T_RC;  L->p = p + 1; return;
    case ',': L->cur.t = T_COMMA; L->p = p + 1; return;
    case '&': if (p[1]=='&') { L->cur.t = T_AND;   L->p = p+2; return; }
              L->cur.t = T_BITAND; L->p = p+1; return;
    case '|': if (p[1]=='|') { L->cur.t = T_OR;  L->p = p+2; return; } break;
    case '=': if (p[1]=='=') { L->cur.t = T_EQ;  L->p = p+2; return; } break;
    case '!': if (p[1]=='=') { L->cur.t = T_NE;  L->p = p+2; return; }
              L->cur.t = T_NOT; L->p = p+1; return;
    case '>': if (p[1]=='=') { L->cur.t = T_GE; L->p = p+2; return; }
              L->cur.t = T_GT; L->p = p+1; return;
    case '<': if (p[1]=='=') { L->cur.t = T_LE; L->p = p+2; return; }
              L->cur.t = T_LT; L->p = p+1; return;
    case '"': {
        int n = 0; p++;
        while (*p && *p != '"' && n < (int)sizeof L->cur.s - 1) L->cur.s[n++] = *p++;
        L->cur.s[n] = '\0';
        if (*p == '"') p++;
        L->cur.t = T_STR; L->p = p; return;
    }
    default: break;
    }

    if (word_ch((unsigned char)*p)) {
        int n = 0;
        while (word_ch((unsigned char)*p) && n < (int)sizeof L->cur.s - 1)
            L->cur.s[n++] = *p++;
        /* slice suffix: proto[offset] or proto[offset:len] — absorb into token.
           Also absorbs &mask when directly adjacent: tcp[13]&0x02
           (single & only — && is the AND operator, never a mask) */
        if (*p == '[') {
            while (*p && *p != ']' && n < (int)sizeof L->cur.s - 1)
                L->cur.s[n++] = *p++;
            if (*p == ']' && n < (int)sizeof L->cur.s - 1)
                L->cur.s[n++] = *p++;
            if (*p == '&' && p[1] != '&') {
                L->cur.s[n++] = *p++;  /* & */
                while (word_ch((unsigned char)*p) && n < (int)sizeof L->cur.s - 1)
                    L->cur.s[n++] = *p++;
            }
        }
        /* function call: len(field) / upper(field) / lower(field)
           absorb as synthetic token "len:field", "upper:field", "lower:field" */
        if (*p == '(') {
            int is_func = (n == 3 && !memcmp(L->cur.s, "len",    3)) ||
                          (n == 5 && (!memcmp(L->cur.s, "upper",  5) ||
                                      !memcmp(L->cur.s, "lower",  5))) ||
                          (n == 6 &&  !memcmp(L->cur.s, "lookup", 6));
            if (is_func && n < (int)sizeof L->cur.s - 1) {
                L->cur.s[n++] = ':';
                p++;  /* skip '(' */
                while (*p && *p != ')' && n < (int)sizeof L->cur.s - 1)
                    L->cur.s[n++] = *p++;
                if (*p == ')') p++;
            }
        }
        L->cur.s[n] = '\0';
        L->p = p;
        /* keyword promotion */
        if (!strcmp(L->cur.s, "and"))     { L->cur.t = T_AND; return; }
        if (!strcmp(L->cur.s, "or"))      { L->cur.t = T_OR;  return; }
        if (!strcmp(L->cur.s, "not"))     { L->cur.t = T_NOT; return; }
        if (!strcmp(L->cur.s, "eq"))      { L->cur.t = T_EQ;  return; }
        if (!strcmp(L->cur.s, "ne"))      { L->cur.t = T_NE;  return; }
        if (!strcmp(L->cur.s, "gt"))      { L->cur.t = T_GT;  return; }
        if (!strcmp(L->cur.s, "lt"))      { L->cur.t = T_LT;  return; }
        if (!strcmp(L->cur.s, "ge"))      { L->cur.t = T_GE;  return; }
        if (!strcmp(L->cur.s, "le"))      { L->cur.t = T_LE;  return; }
        if (!strcmp(L->cur.s, "contains")) { L->cur.t = T_CONTAINS; return; }
        if (!strcmp(L->cur.s, "matches"))  { L->cur.t = T_MATCHES;  return; }
        if (!strcmp(L->cur.s, "in"))       { L->cur.t = T_IN; return; }
        L->cur.t = T_WORD; return;
    }
    snprintf(L->err, sizeof L->err, "unexpected character '%c'", *p);
    L->cur.t = T_EOF; L->p = p + 1;
}

/* ---- Parser (recursive descent) ---- */

static fnode_t *parse_or(lex_t *L);

static fnode_t *fnode_new(ntype_t t)
{
    fnode_t *n = calloc(1, sizeof *n);
    if (n) n->type = t;
    return n;
}

static void fnode_free(fnode_t *n)
{
    if (!n) return;
    fnode_free(n->a);
    fnode_free(n->b);
    free(n);
}

static fnode_t *parse_primary(lex_t *L)
{
    if (L->cur.t == T_LP) {
        lex_next(L);
        fnode_t *n = parse_or(L);
        if (L->cur.t == T_RP) lex_next(L);
        return n;
    }
    if (L->cur.t == T_NOT) {
        lex_next(L);
        fnode_t *n = fnode_new(N_NOT);
        if (!n) return NULL;
        n->a = parse_primary(L);
        return n;
    }
    if (L->cur.t == T_WORD || L->cur.t == T_STR) {
        char field[80];
        snprintf(field, sizeof field, "%s", L->cur.s);
        lex_next(L);

        /* named bitwise AND: tcp.flags & 0x02 — encode as "tcp.flags&0x02" */
        if (L->cur.t == T_BITAND) {
            lex_next(L);   /* consume '&' */
            if (L->cur.t == T_WORD || L->cur.t == T_STR) {
                char masked[120];
                snprintf(masked, sizeof masked, "%s&%s", field, L->cur.s);
                snprintf(field, sizeof field, "%s", masked);
                lex_next(L);
            }
        }

        /* existence test if no operator follows */
        ttype_t ot = L->cur.t;
        if (ot != T_EQ && ot != T_NE && ot != T_GT && ot != T_LT &&
            ot != T_GE && ot != T_LE && ot != T_IN &&
            ot != T_CONTAINS && ot != T_MATCHES) {
            fnode_t *n = fnode_new(N_EXISTS);
            if (!n) return NULL;
            snprintf(n->field, sizeof n->field, "%s", field);
            return n;
        }

        /* `field in { val1, val2, lo..hi, ... }` or `field in (...)` */
        if (ot == T_IN) {
            lex_next(L);   /* consume "in" */
            int use_braces = (L->cur.t == T_LC || L->cur.t == T_LP);
            ttype_t close_tok = (L->cur.t == T_LP) ? T_RP : T_RC;
            if (use_braces) lex_next(L);  /* consume '{' or '(' */
            fnode_t *root = NULL;
            while (L->cur.t == T_WORD || L->cur.t == T_STR) {
                const char *tok = L->cur.s;
                const char *dotdot = strstr(tok, "..");
                fnode_t *item = NULL;
                if (dotdot && dotdot > tok) {
                    /* range: lo..hi → (field >= lo) AND (field <= hi) */
                    char lo_s[80], hi_s[80];
                    int lo_len = (int)(dotdot - tok);
                    if (lo_len >= (int)sizeof lo_s) lo_len = (int)sizeof lo_s - 1;
                    memcpy(lo_s, tok, lo_len); lo_s[lo_len] = '\0';
                    snprintf(hi_s, sizeof hi_s, "%s", dotdot + 2);
                    fnode_t *ge = fnode_new(N_CMP), *le = fnode_new(N_CMP),
                            *an = fnode_new(N_AND);
                    if (!ge || !le || !an) {
                        fnode_free(ge); fnode_free(le); fnode_free(an);
                        fnode_free(root); return NULL;
                    }
                    snprintf(ge->field, sizeof ge->field, "%s", field);
                    ge->op = OP_GE;
                    snprintf(ge->value, sizeof ge->value, "%s", lo_s);
                    snprintf(le->field, sizeof le->field, "%s", field);
                    le->op = OP_LE;
                    snprintf(le->value, sizeof le->value, "%s", hi_s);
                    an->a = ge; an->b = le; item = an;
                } else {
                    fnode_t *cmp = fnode_new(N_CMP);
                    if (!cmp) { fnode_free(root); return NULL; }
                    snprintf(cmp->field, sizeof cmp->field, "%s", field);
                    cmp->op = OP_EQ;
                    snprintf(cmp->value, sizeof cmp->value, "%s", tok);
                    item = cmp;
                }
                lex_next(L);
                if (!root) { root = item; }
                else {
                    fnode_t *or = fnode_new(N_OR);
                    if (!or) { fnode_free(root); fnode_free(item); return NULL; }
                    or->a = root; or->b = item; root = or;
                }
                if (L->cur.t == T_COMMA) lex_next(L);  /* skip optional comma */
                if (!use_braces) break;   /* single-value form: stop after first */
            }
            if (use_braces && L->cur.t == close_tok) lex_next(L);  /* consume '}' or ')' */
            if (!root) { snprintf(L->err, sizeof L->err, "empty 'in' set"); return NULL; }
            return root;
        }

        op_t op;
        switch (ot) {
        case T_EQ:       op = OP_EQ;       break;
        case T_NE:       op = OP_NE;       break;
        case T_GT:       op = OP_GT;       break;
        case T_LT:       op = OP_LT;       break;
        case T_GE:       op = OP_GE;       break;
        case T_LE:       op = OP_LE;       break;
        case T_CONTAINS: op = OP_CONTAINS; break;
        case T_MATCHES:  op = OP_MATCHES;  break;
        default:         op = OP_EQ;       break;
        }
        lex_next(L);   /* consume operator */

        if (L->cur.t != T_WORD && L->cur.t != T_STR) {
            snprintf(L->err, sizeof L->err, "expected value after operator");
            return NULL;
        }
        fnode_t *n = fnode_new(N_CMP);
        if (!n) return NULL;
        snprintf(n->field, sizeof n->field, "%s", field);
        n->op = op;
        snprintf(n->value, sizeof n->value, "%s", L->cur.s);
        lex_next(L);
        return n;
    }
    snprintf(L->err, sizeof L->err, "unexpected token '%s'", L->cur.s);
    return NULL;
}

static fnode_t *parse_and(lex_t *L)
{
    fnode_t *a = parse_primary(L);
    while (L->cur.t == T_AND) {
        lex_next(L);
        fnode_t *b = parse_primary(L);
        fnode_t *n = fnode_new(N_AND);
        if (!n) { fnode_free(a); fnode_free(b); return NULL; }
        n->a = a; n->b = b; a = n;
    }
    return a;
}

static fnode_t *parse_or(lex_t *L)
{
    fnode_t *a = parse_and(L);
    while (L->cur.t == T_OR) {
        lex_next(L);
        fnode_t *b = parse_and(L);
        fnode_t *n = fnode_new(N_OR);
        if (!n) { fnode_free(a); fnode_free(b); return NULL; }
        n->a = a; n->b = b; a = n;
    }
    return a;
}

/* ========================================================================
 * TCP flow tracking for tcp.analysis.retransmission
 *
 * A directional flow table (src_ip, dst_ip, sport, dport, proto) tracks
 * the sequence-number high-water mark for each TCP half-connection.
 * A packet whose seq falls below the high-water mark is a retransmission.
 *
 * The table is updated for EVERY TCP packet that passes through pkt_ctx_init,
 * not only when the field appears in the filter expression — this ensures
 * the state remains accurate even when packets don't match the filter.
 *
 * pcapng_capture_t owns a flow table allocated at open time.
 * pcapng_capture_filter_match() (stateless) passes NULL → always returns 0.
 * Use pcapng_capture_filter_match_ex() with a pcapng_flow_table_t to do
 * stateful retransmission detection in scripts or one-shot evaluations.
 * ======================================================================== */

#define TCP_FLOW_MAX    4096u   /* power of 2, open-addressing; ~192 KB */
#define TCP_FLOW_PROBE  16u     /* max linear probe before eviction      */

typedef struct {
    /* Directional 5-tuple key */
    uint8_t  src[16];       /* IPv4 in first 4 bytes; full 16 for IPv6  */
    uint8_t  dst[16];
    uint16_t sport;
    uint16_t dport;
    uint8_t  is_ipv6;
    uint8_t  used;
    /* Sequence tracking */
    uint32_t isn;           /* initial sequence number (from SYN)        */
    uint32_t max_seq_end;   /* high-water mark: max(seq + payload_len)   */
    uint8_t  syn_seen;
    /* ACK + window tracking */
    uint32_t last_ack;      /* last ACK number sent from this direction  */
    uint8_t  last_ack_valid;/* 1 once any ACK has been recorded          */
    uint16_t last_win;      /* last window size advertised by this side  */
    uint8_t  zero_window;   /* this side last advertised window = 0      */
    uint32_t dup_ack_count; /* consecutive duplicate ACKs from this dir  */
    /* Bidirectional event flags */
    uint8_t  keep_alive_pending;     /* a keep-alive was received; expect ack  */
    uint8_t  zero_win_probe_pending; /* a zerowin probe was received; expect ack */
} tcp_flow_slot_t;

struct pcapng_flow_table {
    tcp_flow_slot_t slots[TCP_FLOW_MAX];
};

pcapng_flow_table_t *pcapng_flow_table_create(void)
{
    return calloc(1, sizeof(pcapng_flow_table_t));
}
void pcapng_flow_table_free(pcapng_flow_table_t *ft) { free(ft); }

static uint32_t flow_hash(const uint8_t *src, const uint8_t *dst,
                           uint16_t sport, uint16_t dport, int is_ipv6)
{
    uint32_t h = 2166136261u;
    int i, n = is_ipv6 ? 16 : 4;
    for (i = 0; i < n; i++) { h ^= src[i]; h *= 16777619u; }
    for (i = 0; i < n; i++) { h ^= dst[i]; h *= 16777619u; }
    h ^= (uint32_t)sport; h *= 16777619u;
    h ^= (uint32_t)dport; h *= 16777619u;
    return h & (TCP_FLOW_MAX - 1);
}

static tcp_flow_slot_t *flow_get(pcapng_flow_table_t *ft,
                                  const uint8_t *src, const uint8_t *dst,
                                  uint16_t sport, uint16_t dport, int is_ipv6)
{
    int n = is_ipv6 ? 16 : 4;
    uint32_t h = flow_hash(src, dst, sport, dport, is_ipv6);
    uint32_t i;
    for (i = 0; i < TCP_FLOW_PROBE; i++) {
        tcp_flow_slot_t *s = &ft->slots[(h + i) & (TCP_FLOW_MAX - 1)];
        if (!s->used) {
            memset(s, 0, sizeof *s);
            memcpy(s->src, src, n); memcpy(s->dst, dst, n);
            s->sport = sport; s->dport = dport;
            s->is_ipv6 = (uint8_t)is_ipv6; s->used = 1;
            return s;
        }
        if (s->is_ipv6 == (uint8_t)is_ipv6 &&
            memcmp(s->src, src, n) == 0 && memcmp(s->dst, dst, n) == 0 &&
            s->sport == sport && s->dport == dport)
            return s;
    }
    /* neighbourhood full — evict the primary slot */
    tcp_flow_slot_t *s = &ft->slots[h];
    memset(s, 0, sizeof *s);
    memcpy(s->src, src, n); memcpy(s->dst, dst, n);
    s->sport = sport; s->dport = dport;
    s->is_ipv6 = (uint8_t)is_ipv6; s->used = 1;
    return s;
}

/* ========================================================================
 * Filter alias table
 *
 * Two alias kinds:
 *   expression aliases — whole filter string substitution (key may contain spaces)
 *   field aliases      — field name expands to a comma-separated list of targets
 *                        with OR semantics (no spaces in key)
 * ======================================================================== */

#define CAP_MAX_ALIASES 256

typedef struct {
    char from[128];
    char to[512];
    int  is_field;  /* 0 = expression alias, 1 = field alias */
} cap_alias_t;

static cap_alias_t g_aliases[CAP_MAX_ALIASES];
static int         g_nalias = 0;

int pcapng_filter_alias_add(const char *from, const char *to)
{
    if (!from || !to || g_nalias >= CAP_MAX_ALIASES) return -1;
    cap_alias_t *a = &g_aliases[g_nalias++];
    snprintf(a->from, sizeof a->from, "%s", from);
    snprintf(a->to,   sizeof a->to,   "%s", to);
    a->is_field = (strchr(from, ' ') == NULL && strchr(from, '\t') == NULL);
    return 0;
}

int pcapng_filter_aliases_load(const char *path, char *errbuf)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (errbuf) snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                             "cannot open '%s': %s", path, strerror(errno));
        return -1;
    }
    char line[700];
    while (fgets(line, sizeof line, fp)) {
        /* strip newline */
        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        nl = strchr(line, '\r'); if (nl) *nl = '\0';
        /* skip blanks and comments */
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#') continue;
        /* locate '=' separator */
        char *eq = strchr(line, '=');
        if (!eq) continue;
        /* key: everything before '=', rtrimmed */
        char key[128];
        int klen = (int)(eq - line);
        while (klen > 0 && (line[klen-1] == ' ' || line[klen-1] == '\t')) klen--;
        if (klen <= 0 || klen >= (int)sizeof key) continue;
        memcpy(key, line, klen); key[klen] = '\0';
        /* value: everything after '=', ltrimmed */
        const char *vp = eq + 1;
        while (*vp == ' ' || *vp == '\t') vp++;
        char val[512];
        snprintf(val, sizeof val, "%s", vp);
        int vlen = (int)strlen(val);
        while (vlen > 0 && (val[vlen-1] == ' ' || val[vlen-1] == '\t')) vlen--;
        val[vlen] = '\0';
        if (!val[0]) continue;
        pcapng_filter_alias_add(key, val);
    }
    fclose(fp);
    return 0;
}

static cap_filter_t *filter_compile(const char *expr, char *errbuf, size_t esz)
{
    cap_filter_t *f = calloc(1, sizeof *f);
    if (!f) return NULL;

    if (!expr || !*expr || strspn(expr, " \t") == strlen(expr)) {
        f->match_all = 1;
        return f;
    }

    /* expression alias expansion: if the trimmed expression matches an alias
     * key (no spaces or spaces — whole string), substitute before parsing */
    const char *use_expr = expr;
    char alias_expanded[512];
    {
        /* trim leading/trailing whitespace for comparison */
        const char *s = expr;
        while (*s == ' ' || *s == '\t') s++;
        char trimmed[512];
        snprintf(trimmed, sizeof trimmed, "%s", s);
        int tlen = (int)strlen(trimmed);
        while (tlen > 0 && (trimmed[tlen-1] == ' ' || trimmed[tlen-1] == '\t')) tlen--;
        trimmed[tlen] = '\0';
        for (int i = 0; i < g_nalias; i++) {
            if (!g_aliases[i].is_field && !strcmp(trimmed, g_aliases[i].from)) {
                snprintf(alias_expanded, sizeof alias_expanded, "%s", g_aliases[i].to);
                use_expr = alias_expanded;
                break;
            }
        }
    }

    lex_t L;
    memset(&L, 0, sizeof L);
    L.p = use_expr;
    lex_next(&L);
    f->root = parse_or(&L);
    if (!f->root || L.cur.t != T_EOF) {
        if (errbuf) snprintf(errbuf, esz, "%s", L.err[0] ? L.err : "syntax error");
        fnode_free(f->root);
        free(f);
        return NULL;
    }
    return f;
}

static void filter_free(cap_filter_t *f)
{
    if (!f) return;
    fnode_free(f->root);
    free(f);
}

/* ========================================================================
 * Parsed-header context (built once per packet, drives filter eval)
 * ======================================================================== */

typedef struct {
    const uint8_t  *raw;
    uint32_t        rawlen;
    uint16_t        linktype;

    const uint8_t  *eth;
    uint16_t        ethertype;
    uint16_t        vlan_id;
    int             has_vlan;

    const uint8_t  *ip4;
    const uint8_t  *ip6;
    const uint8_t  *tcp;
    const uint8_t  *udp;
    const uint8_t  *icmp;
    const uint8_t  *icmp6;
    const uint8_t  *arp;

    /* Precomputed TCP analysis fields (require flow table; all 0 without one) */
    struct {
        uint8_t  retransmission;
        uint8_t  fast_retransmission;
        uint8_t  spurious_retransmission;
        uint8_t  duplicate_ack;
        uint32_t duplicate_ack_num;
        uint8_t  zero_window;
        uint8_t  zero_window_probe;
        uint8_t  zero_window_probe_ack;
        uint8_t  keep_alive;
        uint8_t  keep_alive_ack;
        uint8_t  window_update;
        uint8_t  out_of_order;
        uint32_t bytes_in_flight;
        uint8_t  lost_segment;
    } tcp_analysis;
} pkt_ctx_t;

/* Runs all tcp.analysis computations for this packet, writing into ctx->tcp_analysis.
 * Looks up both the forward (src→dst) and reverse (dst→src) flow slots so that
 * bidirectional fields (bytes_in_flight, fast_retransmission, …) are available.
 * Placed after pkt_ctx_t so it can reference ctx fields directly. */
static void tcp_run_analysis(pcapng_flow_table_t *ft, pkt_ctx_t *ctx)
{
    if (!ft || !ctx->tcp) return;

    uint8_t  flags    = ctx->tcp[13];
    uint16_t win      = (uint16_t)((ctx->tcp[14] << 8) | ctx->tcp[15]);
    uint32_t seq      = ((uint32_t)ctx->tcp[4]  << 24) | ((uint32_t)ctx->tcp[5]  << 16)
                      | ((uint32_t)ctx->tcp[6]  <<  8) |  (uint32_t)ctx->tcp[7];
    uint32_t ack_num  = ((uint32_t)ctx->tcp[8]  << 24) | ((uint32_t)ctx->tcp[9]  << 16)
                      | ((uint32_t)ctx->tcp[10] <<  8) |  (uint32_t)ctx->tcp[11];
    uint32_t tcp_hlen = (uint32_t)(ctx->tcp[12] >> 4) * 4;
    uint8_t  is_ack   = (flags & 0x10) ? 1 : 0;
    uint8_t  is_syn   = (flags & 0x02) ? 1 : 0;
    uint8_t  is_fin   = (flags & 0x01) ? 1 : 0;
    uint8_t  is_rst   = (flags & 0x04) ? 1 : 0;

    /* payload length */
    uint32_t data_len = 0;
    if (ctx->ip4) {
        uint32_t ip_tot  = (uint32_t)((ctx->ip4[2] << 8) | ctx->ip4[3]);
        uint32_t ip_hlen = (uint32_t)(ctx->ip4[0] & 0x0f) * 4;
        if (ip_tot > ip_hlen + tcp_hlen) data_len = ip_tot - ip_hlen - tcp_hlen;
    } else if (ctx->ip6) {
        uint32_t plen = (uint32_t)((ctx->ip6[4] << 8) | ctx->ip6[5]);
        if (plen > tcp_hlen) data_len = plen - tcp_hlen;
    }

    /* directional flow key */
    uint8_t src[16] = {0}, dst[16] = {0};
    int is_ipv6 = 0;
    if (ctx->ip4) {
        memcpy(src, ctx->ip4 + 12, 4); memcpy(dst, ctx->ip4 + 16, 4);
    } else if (ctx->ip6) {
        memcpy(src, ctx->ip6 +  8, 16); memcpy(dst, ctx->ip6 + 24, 16); is_ipv6 = 1;
    } else { return; }

    uint16_t sport = (uint16_t)((ctx->tcp[0] << 8) | ctx->tcp[1]);
    uint16_t dport = (uint16_t)((ctx->tcp[2] << 8) | ctx->tcp[3]);

    tcp_flow_slot_t *fwd = flow_get(ft, src, dst, sport, dport, is_ipv6);
    tcp_flow_slot_t *rev = flow_get(ft, dst, src, dport, sport, is_ipv6);
    if (!fwd || !rev) return;

    uint32_t seq_end   = seq + data_len + (is_fin ? 1u : 0u) + (is_syn ? 1u : 0u);
    int      has_data  = (data_len > 0 || is_fin) ? 1 : 0;
    int      is_pure_ack = (is_ack && !is_syn && !is_fin && !is_rst && data_len == 0) ? 1 : 0;

    /* RST — reset this direction's state and stop */
    if (is_rst) {
        fwd->syn_seen = 0; fwd->max_seq_end = 0;
        fwd->dup_ack_count = 0; fwd->zero_window = 0;
        fwd->keep_alive_pending = 0; fwd->zero_win_probe_pending = 0;
        return;
    }

    /* zero_window: this direction advertises window = 0 (not on SYN) */
    if (!is_syn) {
        ctx->tcp_analysis.zero_window = (win == 0) ? 1 : 0;
        fwd->zero_window = (win == 0) ? 1 : 0;
    }

    /* SYN / SYN-ACK */
    if (is_syn) {
        if (fwd->syn_seen && seq == fwd->isn) {
            ctx->tcp_analysis.retransmission = 1;
        } else {
            fwd->isn = seq; fwd->syn_seen = 1;
            fwd->max_seq_end = seq + 1;
        }
        if (is_ack) { fwd->last_ack = ack_num; fwd->last_ack_valid = 1; }
        fwd->last_win = win;
        return;
    }

    /* --- Established-phase analysis --- */

    /* zero_window_probe: 1 byte sent toward the side that said window=0 */
    if (data_len == 1 && rev->zero_window && fwd->syn_seen) {
        ctx->tcp_analysis.zero_window_probe = 1;
        fwd->zero_win_probe_pending = 1;
    }

    /* zero_window_probe_ack: pure ACK from the zero-window side after a probe */
    if (is_pure_ack && fwd->zero_window && rev->zero_win_probe_pending) {
        ctx->tcp_analysis.zero_window_probe_ack = 1;
        rev->zero_win_probe_pending = 0;
    }

    /* keep_alive: seq is one behind what the peer has acknowledged, len ≤ 1 */
    if (!is_fin && data_len <= 1 && fwd->syn_seen &&
        rev->last_ack_valid && seq == (uint32_t)(rev->last_ack - 1u)) {
        ctx->tcp_analysis.keep_alive = 1;
        rev->keep_alive_pending = 1;
    }

    /* keep_alive_ack: pure ACK in response to a keep-alive we received */
    if (is_pure_ack && fwd->keep_alive_pending) {
        ctx->tcp_analysis.keep_alive_ack = 1;
        fwd->keep_alive_pending = 0;
    }

    /* ACK number / window analysis */
    if (is_ack) {
        int ack_advanced = (!fwd->last_ack_valid ||
                            (int32_t)(ack_num - fwd->last_ack) > 0) ? 1 : 0;

        if (is_pure_ack &&
            !ctx->tcp_analysis.zero_window_probe_ack &&
            !ctx->tcp_analysis.keep_alive_ack) {
            if (fwd->last_ack_valid && !ack_advanced) {
                if (win == fwd->last_win) {
                    /* duplicate ACK */
                    fwd->dup_ack_count++;
                    ctx->tcp_analysis.duplicate_ack     = 1;
                    ctx->tcp_analysis.duplicate_ack_num = fwd->dup_ack_count;
                } else {
                    /* window update: same ack, different window */
                    ctx->tcp_analysis.window_update = 1;
                    fwd->dup_ack_count = 0;
                }
            } else {
                fwd->dup_ack_count = 0;
            }
        } else if (!is_pure_ack) {
            fwd->dup_ack_count = 0;
        }

        if (ack_advanced) { fwd->last_ack = ack_num; fwd->last_ack_valid = 1; }
        fwd->last_win = win;
    }

    /* Sequence-space analysis for data/FIN segments */
    if (has_data && fwd->syn_seen) {
        if ((int32_t)(seq - fwd->max_seq_end) < 0) {
            if ((int32_t)(seq_end - fwd->max_seq_end) <= 0) {
                /* all bytes previously seen → retransmission */
                ctx->tcp_analysis.retransmission = 1;
                /* spurious if peer already acked past this seq */
                if (rev->last_ack_valid && (int32_t)(seq - rev->last_ack) < 0)
                    ctx->tcp_analysis.spurious_retransmission = 1;
                /* fast if peer had sent ≥ 3 duplicate ACKs */
                if (rev->dup_ack_count >= 3)
                    ctx->tcp_analysis.fast_retransmission = 1;
            } else {
                /* straddles high-water mark → out-of-order (contains new data) */
                ctx->tcp_analysis.out_of_order = 1;
                fwd->max_seq_end = seq_end;
            }
        } else if ((int32_t)(seq - fwd->max_seq_end) > 0) {
            /* gap: seq jumped ahead → a segment before this is missing */
            ctx->tcp_analysis.lost_segment = 1;
            fwd->max_seq_end = seq_end;
        } else {
            fwd->max_seq_end = seq_end;
        }
    }

    /* bytes_in_flight: data sent by this direction not yet acknowledged by peer */
    if (fwd->syn_seen && rev->last_ack_valid) {
        int32_t bif = (int32_t)(fwd->max_seq_end - rev->last_ack);
        ctx->tcp_analysis.bytes_in_flight = (bif > 0) ? (uint32_t)bif : 0u;
    }
}

static void pkt_ctx_init(pkt_ctx_t *ctx,
                          const uint8_t *data, uint32_t len,
                          uint16_t linktype, pcapng_flow_table_t *ft)
{
    memset(ctx, 0, sizeof *ctx);
    ctx->raw     = data;
    ctx->rawlen  = len;
    ctx->linktype = linktype;

    const uint8_t *l3     = NULL;
    uint32_t       l3len  = 0;
    uint16_t       et     = 0;

    if (linktype == LINKTYPE_ETHERNET && len >= 14) {
        ctx->eth = data;
        et = (uint16_t)((data[12] << 8) | data[13]);

        l3    = data + 14;
        l3len = len  - 14;

        /* 802.1Q VLAN tag */
        if (et == 0x8100 && l3len >= 4) {
            ctx->has_vlan = 1;
            ctx->vlan_id  = (uint16_t)(((uint16_t)(l3[0] & 0x0f) << 8) | l3[1]);
            et     = (uint16_t)((l3[2] << 8) | l3[3]);
            l3    += 4;
            l3len -= 4;
        }
        ctx->ethertype = et;
    } else if (linktype == LINKTYPE_RAW && len >= 1 && (data[0] >> 4) == 4) {
        et    = 0x0800;   /* treat as IPv4 */
        l3    = data;
        l3len = len;
        ctx->ethertype = et;
    }

    if (!l3) return;

    if (et == 0x0800 && l3len >= 20 && (l3[0] >> 4) == 4) {
        /* IPv4 */
        ctx->ip4 = l3;
        uint8_t  ihl   = (uint8_t)((l3[0] & 0x0f) * 4);
        if (ihl < 20 || l3len < ihl) return;

        uint8_t        proto  = l3[9];
        const uint8_t *l4     = l3 + ihl;
        uint32_t       l4len  = l3len - ihl;

        if (proto == 6  && l4len >= 20) { ctx->tcp  = l4; }
        if (proto == 17 && l4len >=  8) { ctx->udp  = l4; }
        if (proto == 1  && l4len >=  4) { ctx->icmp = l4; }

    } else if (et == 0x86DD && l3len >= 40 && (l3[0] >> 4) == 6) {
        /* IPv6 */
        ctx->ip6 = l3;
        uint8_t        nxt   = l3[6];
        const uint8_t *l4    = l3 + 40;
        uint32_t       l4len = l3len - 40;

        if (nxt == 6  && l4len >= 20) { ctx->tcp   = l4; }
        if (nxt == 17 && l4len >=  8) { ctx->udp   = l4; }
        if (nxt == 58 && l4len >=  4) { ctx->icmp6 = l4; }

    } else if (et == 0x0806 && l3len >= 28) {
        /* ARP: htype(2) ptype(2) hlen(1) plen(1) oper(2) sha(6) spa(4) tha(6) tpa(4) */
        ctx->arp = l3;
    }

    /* Precompute TCP analysis fields (updates flow table state). */
    tcp_run_analysis(ft, ctx);
}

/* ========================================================================
 * Raw-field extraction
 *
 * fval_t holds one extracted field value; up to CAP_MAX_FVALS are returned
 * per call (alias expansion produces 2, otherwise 1).
 * ======================================================================== */

#define CAP_MAX_FVALS 4

typedef enum { FV_NONE, FV_UINT, FV_IPV4, FV_IPV6, FV_MAC, FV_STR, FV_BYTES } fvtype_t;

typedef struct {
    fvtype_t  type;
    union {
        uint64_t u;
        uint8_t  ipv4[4];
        uint8_t  ipv6[16];
        uint8_t  mac[6];
        char     str[64];
        struct { uint8_t data[8]; int len; } bytes;  /* slice notation result */
    };
} fval_t;

/* Forward declarations for helpers used inside raw_field_get */
static int parse_ipv4(const char *s, uint8_t out[4], int *cidr);
static int parse_mac(const char *s, uint8_t out[6]);

/* Populate out[] with field values; returns the count. */
static int raw_field_get(const pkt_ctx_t *ctx, const char *field,
                          fval_t *out, int maxout,
                          pcapng_field_provider_t provider_fn, void *provider_ctx)
{
    /* ── slice notation: proto[offset] or proto[offset:len] ──────────────────
     * Field strings like "tcp[13]", "tcp[0:2]", "tcp[13]&0x02" are produced
     * by the lexer as single T_WORD tokens.  Extract the layer, bounds-check,
     * assemble big-endian, apply optional bitmask, and return FV_UINT so the
     * standard comparison path handles all operators without special casing. */
    {
        char slice_proto[24];
        int  slice_off = 0, slice_len = 1;
        if (sscanf(field, "%23[^[][%d:%d]", slice_proto, &slice_off, &slice_len) >= 2 ||
            (slice_len = 1, sscanf(field, "%23[^[][%d]", slice_proto, &slice_off) == 2)) {
            if (slice_len >= 1 && slice_len <= 8 && maxout >= 1) {
                /* optional bitmask suffix: tcp[13]&0x02 */
                uint64_t mask = ~(uint64_t)0;
                const char *amp = strchr(field, '&');
                if (amp) mask = strtoull(amp + 1, NULL, 0);

                const uint8_t *base = NULL;
                if      (!strcmp(slice_proto, "frame"))                  base = ctx->raw;
                else if (!strcmp(slice_proto, "eth")    && ctx->eth)     base = ctx->eth;
                else if (!strcmp(slice_proto, "eth.dst") && ctx->eth)    base = ctx->eth;
                else if (!strcmp(slice_proto, "eth.src") && ctx->eth)    base = ctx->eth + 6;
                else if (!strcmp(slice_proto, "ip")     && ctx->ip4)     base = ctx->ip4;
                else if (!strcmp(slice_proto, "ip.src") && ctx->ip4)     base = ctx->ip4 + 12;
                else if (!strcmp(slice_proto, "ip.dst") && ctx->ip4)     base = ctx->ip4 + 16;
                else if (!strcmp(slice_proto, "ip6")    && ctx->ip6)     base = ctx->ip6;
                else if (!strcmp(slice_proto, "ip6.src") && ctx->ip6)    base = ctx->ip6 + 8;
                else if (!strcmp(slice_proto, "ip6.dst") && ctx->ip6)    base = ctx->ip6 + 24;
                else if (!strcmp(slice_proto, "tcp")    && ctx->tcp)     base = ctx->tcp;
                else if (!strcmp(slice_proto, "udp")    && ctx->udp)     base = ctx->udp;
                else if (!strcmp(slice_proto, "icmp")   && ctx->icmp)    base = ctx->icmp;
                else if (!strcmp(slice_proto, "icmpv6") && ctx->icmp6)   base = ctx->icmp6;
                if (base) {
                    uint32_t avail = ctx->rawlen - (uint32_t)(base - ctx->raw);
                    /* resolve negative offset from end */
                    int off = slice_off;
                    if (off < 0) {
                        off = (int)avail + off;
                        if (off < 0) return 0;
                    }
                    if ((uint32_t)(off + slice_len) <= avail) {
                        uint64_t lv = 0;
                        int i; for (i = 0; i < slice_len; i++)
                            lv = (lv << 8) | base[off + i];
                        fval_t *v = &out[0];
                        memset(v, 0, sizeof *v);
                        v->type = FV_UINT;
                        v->u    = lv & mask;
                        return 1;
                    }
                }
            }
            return 0;  /* slice field not resolved (layer absent or OOB) */
        }
    }

    /* ── function calls: len:FIELD, upper:FIELD, lower:FIELD ─────────────────
     * Lexer encodes len(tcp.payload) as the synthetic token "len:tcp.payload".
     * len() returns FV_UINT byte count; upper/lower transform FV_STR in place. */
    if (!strncmp(field, "len:", 4)) {
        const char *inner = field + 4;
        if (maxout < 1) return 0;
        fval_t *v = &out[0]; memset(v, 0, sizeof *v);
        /* named layer lengths */
        if (!strcmp(inner, "frame"))
            { v->type = FV_UINT; v->u = ctx->rawlen; return 1; }
        if (!strcmp(inner, "ip") && ctx->ip4)
            { v->type = FV_UINT; v->u = (uint32_t)((ctx->ip4[2]<<8)|ctx->ip4[3]); return 1; }
        if (!strcmp(inner, "ip.payload") && ctx->ip4) {
            uint32_t tot  = (uint32_t)((ctx->ip4[2]<<8)|ctx->ip4[3]);
            uint32_t hlen = (uint32_t)(ctx->ip4[0] & 0xf) * 4;
            v->type = FV_UINT; v->u = (tot > hlen) ? tot - hlen : 0; return 1;
        }
        if (!strcmp(inner, "tcp") && ctx->tcp)
            { v->type = FV_UINT; v->u = (uint32_t)(ctx->tcp[12] >> 4) * 4; return 1; }
        if (!strcmp(inner, "tcp.payload") && ctx->tcp && ctx->ip4) {
            uint32_t tot      = (uint32_t)((ctx->ip4[2]<<8)|ctx->ip4[3]);
            uint32_t ip_hlen  = (uint32_t)(ctx->ip4[0] & 0xf) * 4;
            uint32_t tcp_hlen = (uint32_t)(ctx->tcp[12] >> 4) * 4;
            uint32_t pl = (tot > ip_hlen + tcp_hlen) ? tot - ip_hlen - tcp_hlen : 0;
            v->type = FV_UINT; v->u = pl; return 1;
        }
        if (!strcmp(inner, "udp") && ctx->udp)
            { v->type = FV_UINT; v->u = (uint32_t)((ctx->udp[4]<<8)|ctx->udp[5]); return 1; }
        if (!strcmp(inner, "udp.payload") && ctx->udp) {
            uint32_t udp_len = (uint32_t)((ctx->udp[4]<<8)|ctx->udp[5]);
            v->type = FV_UINT; v->u = (udp_len >= 8) ? udp_len - 8 : 0; return 1;
        }
        /* fallback: resolve the inner field and return its string length */
        {
            fval_t iv[CAP_MAX_FVALS];
            if (raw_field_get(ctx, inner, iv, CAP_MAX_FVALS, provider_fn, provider_ctx) > 0
                    && iv[0].type == FV_STR) {
                v->type = FV_UINT; v->u = strlen(iv[0].str); return 1;
            }
        }
        return 0;
    }
    if (!strncmp(field, "upper:", 6) || !strncmp(field, "lower:", 6)) {
        int is_upper = (field[0] == 'u');
        const char *inner = field + 6;
        if (maxout < 1) return 0;
        fval_t iv[CAP_MAX_FVALS];
        if (raw_field_get(ctx, inner, iv, CAP_MAX_FVALS, provider_fn, provider_ctx) > 0
                && iv[0].type == FV_STR) {
            out[0] = iv[0];
            char *s = out[0].str;
            while (*s) {
                *s = is_upper ? (char)toupper((unsigned char)*s)
                              : (char)tolower((unsigned char)*s);
                s++;
            }
            return 1;
        }
        return 0;
    }
    /* lookup(SYMBOL) → asks the provider to resolve a POSA symbolic name.
     * Lexer encodes lookup(CREATED) as "lookup:CREATED".  Provider is called
     * with "__lookup__:CREATED"; it should return the numeric value ("0x41"). */
    if (!strncmp(field, "lookup:", 7)) {
        const char *sym = field + 7;
        if (maxout < 1 || !provider_fn) return 0;
        char lookup_key[200], val[160];
        snprintf(lookup_key, sizeof lookup_key, "__lookup__:%s", sym);
        if (provider_fn(lookup_key, ctx->raw, ctx->rawlen, val, sizeof val, provider_ctx)) {
            fval_t *v = &out[0]; memset(v, 0, sizeof *v);
            char *end;
            uint64_t n = strtoull(val, &end, 0);
            if (val[0] != '\0' && *end == '\0') {
                v->type = FV_UINT; v->u = n;
            } else {
                v->type = FV_STR;
                snprintf(v->str, sizeof v->str, "%s", val);
            }
            return 1;
        }
        return 0;
    }

    /* ── named-field bitmask: tcp.flags&0x02, ip.dsfield&0x3 ──────────────
     * Lexer emits "field&mask" only when there is no slice bracket, so this
     * won't conflict with the tcp[13]&0x02 slice path above. */
    {
        const char *amp2 = strchr(field, '&');
        if (amp2 && !strchr(field, '[')) {
            char base_field[80];
            int blen = (int)(amp2 - field);
            if (blen > 0 && blen < (int)sizeof base_field) {
                memcpy(base_field, field, blen);
                base_field[blen] = '\0';
                uint64_t mask2 = strtoull(amp2 + 1, NULL, 0);
                fval_t bv[1];
                if (raw_field_get(ctx, base_field, bv, 1, provider_fn, provider_ctx) > 0
                        && bv[0].type == FV_UINT && maxout >= 1) {
                    out[0].type = FV_UINT;
                    out[0].u    = bv[0].u & mask2;
                    return 1;
                }
            }
            return 0;
        }
    }

    /* ── alias expansion (like caracal's aliases()) ── */
    if (!strcmp(field, "ip.addr")) {
        int n = 0;
        n += raw_field_get(ctx, "ip.src", out + n, maxout - n, provider_fn, provider_ctx);
        n += raw_field_get(ctx, "ip.dst", out + n, maxout - n, provider_fn, provider_ctx);
        return n;
    }
    if (!strcmp(field, "tcp.port")) {
        int n = 0;
        n += raw_field_get(ctx, "tcp.srcport", out + n, maxout - n, provider_fn, provider_ctx);
        n += raw_field_get(ctx, "tcp.dstport", out + n, maxout - n, provider_fn, provider_ctx);
        return n;
    }
    if (!strcmp(field, "udp.port")) {
        int n = 0;
        n += raw_field_get(ctx, "udp.srcport", out + n, maxout - n, provider_fn, provider_ctx);
        n += raw_field_get(ctx, "udp.dstport", out + n, maxout - n, provider_fn, provider_ctx);
        return n;
    }
    if (!strcmp(field, "eth.addr")) {
        int n = 0;
        n += raw_field_get(ctx, "eth.src", out + n, maxout - n, provider_fn, provider_ctx);
        n += raw_field_get(ctx, "eth.dst", out + n, maxout - n, provider_fn, provider_ctx);
        return n;
    }
    /* ipv6.* aliases */
    if (!strncmp(field, "ipv6.", 5)) {
        char alt[80];
        snprintf(alt, sizeof alt, "ip6.%s", field + 5);
        return raw_field_get(ctx, alt, out, maxout, provider_fn, provider_ctx);
    }
    if (!strcmp(field, "ip6.addr") || !strcmp(field, "ipv6.addr")) {
        int n = 0;
        n += raw_field_get(ctx, "ip6.src", out + n, maxout - n, provider_fn, provider_ctx);
        n += raw_field_get(ctx, "ip6.dst", out + n, maxout - n, provider_fn, provider_ctx);
        return n;
    }

    if (maxout < 1) return 0;
    fval_t *v = &out[0];
    memset(v, 0, sizeof *v);

    /* ── Frame-level fields ── */
    if (!strcmp(field, "frame.len") || !strcmp(field, "frame.cap_len")) {
        v->type = FV_UINT; v->u = ctx->rawlen; return 1;
    }

    /* ── Ethernet ── */
    if (ctx->eth) {
        if (!strcmp(field, "eth.dst")) {
            v->type = FV_MAC; memcpy(v->mac, ctx->eth,     6); return 1;
        }
        if (!strcmp(field, "eth.src")) {
            v->type = FV_MAC; memcpy(v->mac, ctx->eth + 6, 6); return 1;
        }
        if (!strcmp(field, "eth.type")) {
            v->type = FV_UINT; v->u = ctx->ethertype; return 1;
        }
    }

    /* ── IPv4 ── */
    if (ctx->ip4) {
        if (!strcmp(field, "ip.src")) {
            v->type = FV_IPV4; memcpy(v->ipv4, ctx->ip4 + 12, 4); return 1;
        }
        if (!strcmp(field, "ip.dst")) {
            v->type = FV_IPV4; memcpy(v->ipv4, ctx->ip4 + 16, 4); return 1;
        }
        if (!strcmp(field, "ip.proto")) {
            v->type = FV_UINT; v->u = ctx->ip4[9]; return 1;
        }
        if (!strcmp(field, "ip.ttl")) {
            v->type = FV_UINT; v->u = ctx->ip4[8]; return 1;
        }
        if (!strcmp(field, "ip.len")) {
            v->type = FV_UINT;
            v->u = (uint32_t)((ctx->ip4[2] << 8) | ctx->ip4[3]); return 1;
        }
    }

    /* ── IPv6 ── */
    if (ctx->ip6) {
        if (!strcmp(field, "ip6.src")) {
            v->type = FV_IPV6; memcpy(v->ipv6, ctx->ip6 +  8, 16); return 1;
        }
        if (!strcmp(field, "ip6.dst")) {
            v->type = FV_IPV6; memcpy(v->ipv6, ctx->ip6 + 24, 16); return 1;
        }
        if (!strcmp(field, "ip6.nxt") || !strcmp(field, "ip6.proto")) {
            v->type = FV_UINT; v->u = ctx->ip6[6]; return 1;
        }
    }

    /* ── TCP ── */
    if (ctx->tcp) {
        if (!strcmp(field, "tcp.srcport")) {
            v->type = FV_UINT;
            v->u = (uint32_t)((ctx->tcp[0] << 8) | ctx->tcp[1]); return 1;
        }
        if (!strcmp(field, "tcp.dstport")) {
            v->type = FV_UINT;
            v->u = (uint32_t)((ctx->tcp[2] << 8) | ctx->tcp[3]); return 1;
        }
        if (!strcmp(field, "tcp.flags")) {
            v->type = FV_UINT; v->u = ctx->tcp[13]; return 1;
        }
        if (!strcmp(field, "tcp.flags.syn")) {
            v->type = FV_UINT; v->u = (ctx->tcp[13] & 0x02) ? 1 : 0; return 1;
        }
        if (!strcmp(field, "tcp.flags.ack")) {
            v->type = FV_UINT; v->u = (ctx->tcp[13] & 0x10) ? 1 : 0; return 1;
        }
        if (!strcmp(field, "tcp.flags.rst")) {
            v->type = FV_UINT; v->u = (ctx->tcp[13] & 0x04) ? 1 : 0; return 1;
        }
        if (!strcmp(field, "tcp.flags.fin")) {
            v->type = FV_UINT; v->u = (ctx->tcp[13] & 0x01) ? 1 : 0; return 1;
        }
        if (!strcmp(field, "tcp.seq")) {
            v->type = FV_UINT;
            v->u = ((uint32_t)ctx->tcp[4] << 24) | ((uint32_t)ctx->tcp[5] << 16) |
                   ((uint32_t)ctx->tcp[6] <<  8) |  (uint32_t)ctx->tcp[7]; return 1;
        }
        if (!strcmp(field, "tcp.ack")) {
            v->type = FV_UINT;
            v->u = ((uint32_t)ctx->tcp[8]  << 24) | ((uint32_t)ctx->tcp[9]  << 16) |
                   ((uint32_t)ctx->tcp[10] <<  8) |  (uint32_t)ctx->tcp[11]; return 1;
        }
        if (!strcmp(field, "tcp.window_size") || !strcmp(field, "tcp.window_size_value")) {
            v->type = FV_UINT;
            v->u = (uint32_t)((ctx->tcp[14] << 8) | ctx->tcp[15]); return 1;
        }
        if (!strcmp(field, "tcp.flags.psh")) {
            v->type = FV_UINT; v->u = (ctx->tcp[13] & 0x08) ? 1 : 0; return 1;
        }
        if (!strcmp(field, "tcp.flags.urg")) {
            v->type = FV_UINT; v->u = (ctx->tcp[13] & 0x20) ? 1 : 0; return 1;
        }
        /* tcp.analysis.* fields: precomputed by tcp_run_analysis via flow table.
         * All return 0 when no flow table is attached (stateless evaluation). */
        if (!strncmp(field, "tcp.analysis.", 13)) {
            const char *af = field + 13;
            v->type = FV_UINT;
            if (!strcmp(af, "retransmission"))
                { v->u = ctx->tcp_analysis.retransmission; return 1; }
            if (!strcmp(af, "fast_retransmission"))
                { v->u = ctx->tcp_analysis.fast_retransmission; return 1; }
            if (!strcmp(af, "spurious_retransmission"))
                { v->u = ctx->tcp_analysis.spurious_retransmission; return 1; }
            if (!strcmp(af, "duplicate_ack"))
                { v->u = ctx->tcp_analysis.duplicate_ack; return 1; }
            if (!strcmp(af, "duplicate_ack_num"))
                { v->u = ctx->tcp_analysis.duplicate_ack_num; return 1; }
            if (!strcmp(af, "zero_window"))
                { v->u = ctx->tcp_analysis.zero_window; return 1; }
            if (!strcmp(af, "zero_window_probe"))
                { v->u = ctx->tcp_analysis.zero_window_probe; return 1; }
            if (!strcmp(af, "zero_window_probe_ack"))
                { v->u = ctx->tcp_analysis.zero_window_probe_ack; return 1; }
            if (!strcmp(af, "keep_alive"))
                { v->u = ctx->tcp_analysis.keep_alive; return 1; }
            if (!strcmp(af, "keep_alive_ack"))
                { v->u = ctx->tcp_analysis.keep_alive_ack; return 1; }
            if (!strcmp(af, "window_update"))
                { v->u = ctx->tcp_analysis.window_update; return 1; }
            if (!strcmp(af, "out_of_order"))
                { v->u = ctx->tcp_analysis.out_of_order; return 1; }
            if (!strcmp(af, "bytes_in_flight"))
                { v->u = ctx->tcp_analysis.bytes_in_flight; return 1; }
            if (!strcmp(af, "lost_segment"))
                { v->u = ctx->tcp_analysis.lost_segment; return 1; }
        }
    }

    /* ── UDP ── */
    if (ctx->udp) {
        if (!strcmp(field, "udp.srcport")) {
            v->type = FV_UINT;
            v->u = (uint32_t)((ctx->udp[0] << 8) | ctx->udp[1]); return 1;
        }
        if (!strcmp(field, "udp.dstport")) {
            v->type = FV_UINT;
            v->u = (uint32_t)((ctx->udp[2] << 8) | ctx->udp[3]); return 1;
        }
        if (!strcmp(field, "udp.len")) {
            v->type = FV_UINT;
            v->u = (uint32_t)((ctx->udp[4] << 8) | ctx->udp[5]); return 1;
        }
    }

    /* ── ICMP ── */
    if (ctx->icmp) {
        if (!strcmp(field, "icmp.type")) {
            v->type = FV_UINT; v->u = ctx->icmp[0]; return 1;
        }
        if (!strcmp(field, "icmp.code")) {
            v->type = FV_UINT; v->u = ctx->icmp[1]; return 1;
        }
    }

    /* ── ICMPv6 ── */
    if (ctx->icmp6) {
        if (!strcmp(field, "icmpv6.type")) {
            v->type = FV_UINT; v->u = ctx->icmp6[0]; return 1;
        }
        if (!strcmp(field, "icmpv6.code")) {
            v->type = FV_UINT; v->u = ctx->icmp6[1]; return 1;
        }
    }

    /* ── ARP ── */
    if (ctx->arp) {
        if (!strcmp(field, "arp.opcode") || !strcmp(field, "arp.op")) {
            v->type = FV_UINT;
            v->u = (uint32_t)((ctx->arp[6] << 8) | ctx->arp[7]); return 1;
        }
        /* standard Ethernet ARP: htype=1 hlen=6 ptype=0x0800 plen=4 */
        if (!strcmp(field, "arp.src.proto_ipv4") && ctx->arp[4] == 6) {
            v->type = FV_IPV4; memcpy(v->ipv4, ctx->arp + 14, 4); return 1;
        }
        if (!strcmp(field, "arp.dst.proto_ipv4") && ctx->arp[4] == 6) {
            v->type = FV_IPV4; memcpy(v->ipv4, ctx->arp + 24, 4); return 1;
        }
        if (!strcmp(field, "arp.src.hw_mac") && ctx->arp[4] == 6) {
            v->type = FV_MAC; memcpy(v->mac, ctx->arp + 8,  6); return 1;
        }
        if (!strcmp(field, "arp.dst.hw_mac") && ctx->arp[4] == 6) {
            v->type = FV_MAC; memcpy(v->mac, ctx->arp + 18, 6); return 1;
        }
    }

    /* ── VLAN ── */
    if (!strcmp(field, "vlan.id")) {
        if (!ctx->has_vlan) return 0;
        v->type = FV_UINT; v->u = ctx->vlan_id; return 1;
    }
    if (!strcmp(field, "vlan")) {
        v->type = FV_UINT; v->u = ctx->has_vlan ? 1 : 0; return v->u ? 1 : 0;
    }

    /* ── Protocol existence ── */
    if (!strcmp(field, "ip"))      { v->type = FV_UINT; v->u = ctx->ip4   ? 1 : 0; return v->u ? 1 : 0; }
    if (!strcmp(field, "ip6") || !strcmp(field, "ipv6")) {
                                     v->type = FV_UINT; v->u = ctx->ip6   ? 1 : 0; return v->u ? 1 : 0; }
    if (!strcmp(field, "tcp"))     { v->type = FV_UINT; v->u = ctx->tcp   ? 1 : 0; return v->u ? 1 : 0; }
    if (!strcmp(field, "udp"))     { v->type = FV_UINT; v->u = ctx->udp   ? 1 : 0; return v->u ? 1 : 0; }
    if (!strcmp(field, "icmp"))    { v->type = FV_UINT; v->u = ctx->icmp  ? 1 : 0; return v->u ? 1 : 0; }
    if (!strcmp(field, "icmpv6"))  { v->type = FV_UINT; v->u = ctx->icmp6 ? 1 : 0; return v->u ? 1 : 0; }
    if (!strcmp(field, "arp"))     { v->type = FV_UINT; v->u = ctx->arp   ? 1 : 0; return v->u ? 1 : 0; }

    /* ── Registered field aliases (ECS or custom) ── */
    for (int _ai = 0; _ai < g_nalias; _ai++) {
        if (!g_aliases[_ai].is_field) continue;
        if (strcmp(field, g_aliases[_ai].from) != 0) continue;
        /* expand comma-separated target list with OR semantics */
        int _n = 0;
        char _targets[512];
        snprintf(_targets, sizeof _targets, "%s", g_aliases[_ai].to);
        char *_save = NULL, *_tok = strtok_r(_targets, ",", &_save);
        while (_tok && _n < maxout) {
            while (*_tok == ' ' || *_tok == '\t') _tok++;
            char *_end = _tok + strlen(_tok);
            while (_end > _tok && (_end[-1] == ' ' || _end[-1] == '\t')) _end--;
            *_end = '\0';
            if (*_tok)
                _n += raw_field_get(ctx, _tok, out + _n, maxout - _n, provider_fn, provider_ctx);
            _tok = strtok_r(NULL, ",", &_save);
        }
        return _n;
    }

    /* ── Custom field provider ── */
    if (provider_fn) {
        char val[160];
        if (provider_fn(field, ctx->raw, ctx->rawlen, val, sizeof val, provider_ctx)) {
            /* Infer the value type from the string so that POSA-defined fields get
             * the same comparison semantics as built-in fields: CIDR for IPv4,
             * byte-order comparison for MACs, and numeric ordering for integers.
             * Only falls back to FV_STR when the string doesn't match any typed
             * format — e.g. a DNS name or a human-readable label field. */
            uint8_t ipv4[4]; int cidr = 32;
            uint8_t mac[6];
            char *end;
            if (parse_ipv4(val, ipv4, &cidr) == 0 && cidr == 32) {
                v->type = FV_IPV4; memcpy(v->ipv4, ipv4, 4);
            } else if (parse_mac(val, mac) == 0) {
                v->type = FV_MAC; memcpy(v->mac, mac, 6);
            } else {
                uint64_t n = strtoull(val, &end, 0);
                if (val[0] != '\0' && *end == '\0') {
                    v->type = FV_UINT; v->u = n;
                } else {
                    v->type = FV_STR;
                    snprintf(v->str, sizeof v->str, "%s", val);
                }
            }
            return 1;
        }
    }

    return 0;  /* field not found */
}

/* ---- Comparison helpers (mirroring caracal's field_matches()) ---- */

static uint64_t to_num(const char *s)
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) return strtoull(s, NULL, 16);
    return strtoull(s, NULL, 10);
}

static int parse_ipv4(const char *s, uint8_t out[4], int *cidr)
{
    unsigned a, b, c, d;
    *cidr = 32;
    if (sscanf(s, "%u.%u.%u.%u/%d", &a, &b, &c, &d, cidr) >= 4 &&
        a <= 255 && b <= 255 && c <= 255 && d <= 255) {
        out[0] = (uint8_t)a; out[1] = (uint8_t)b;
        out[2] = (uint8_t)c; out[3] = (uint8_t)d;
        if (*cidr < 0)  *cidr = 0;
        if (*cidr > 32) *cidr = 32;
        return 0;
    }
    return -1;
}

static int parse_mac(const char *s, uint8_t out[6])
{
    unsigned m[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
        int i; for (i = 0; i < 6; i++) out[i] = (uint8_t)m[i];
        return 0;
    }
    return -1;
}

static int parse_ipv6_cidr(const char *s, uint8_t out[16], int *prefix)
{
    char addr[64];
    *prefix = 128;
    const char *slash = strchr(s, '/');
    if (slash) {
        int len = (int)(slash - s);
        if (len >= (int)sizeof addr) return -1;
        memcpy(addr, s, len); addr[len] = '\0';
        *prefix = atoi(slash + 1);
        if (*prefix < 0)   *prefix = 0;
        if (*prefix > 128) *prefix = 128;
    } else {
        snprintf(addr, sizeof addr, "%s", s);
    }
    return inet_pton(AF_INET6, addr, out) == 1 ? 0 : -1;
}

/* Convert a filter value string to a raw byte pattern for 'contains' searches:
 *   0xNNNN...  → big-endian bytes (pairs of hex digits)
 *   aa:bb:cc   → colon-separated hex bytes
 *   ASCII text → literal bytes */
static int parse_byte_pattern(const char *val, uint8_t *buf, int *outlen)
{
    if (val[0] == '0' && (val[1] == 'x' || val[1] == 'X')) {
        const char *p = val + 2; int n = 0;
        while (*p && n < 8) {
            if (!isxdigit((unsigned char)p[0])) break;
            char hex[3] = { p[0], isxdigit((unsigned char)p[1]) ? p[1] : '0', '\0' };
            if (isxdigit((unsigned char)p[1])) {
                buf[n++] = (uint8_t)strtoul(hex, NULL, 16); p += 2;
            } else {
                hex[1] = '\0';
                buf[n++] = (uint8_t)strtoul(hex, NULL, 16); p++;
            }
        }
        *outlen = n; return n > 0 ? 0 : -1;
    }
    if (strchr(val, ':')) {
        int n = 0; const char *p = val;
        while (*p && n < 64) {
            buf[n++] = (uint8_t)strtoul(p, NULL, 16);
            p = strchr(p, ':'); if (!p) break; p++;
        }
        *outlen = n; return n > 0 ? 0 : -1;
    }
    int n = (int)strlen(val); if (n > 64) n = 64;
    memcpy(buf, val, n); *outlen = n; return 0;
}

static int bytes_contains(const uint8_t *hay, uint32_t hlen,
                           const uint8_t *needle, int nlen)
{
    if (nlen <= 0 || (uint32_t)nlen > hlen) return 0;
    uint32_t i;
    for (i = 0; i <= hlen - (uint32_t)nlen; i++)
        if (memcmp(hay + i, needle, nlen) == 0) return 1;
    return 0;
}

static int cmp_sign(op_t op, long long c)
{
    switch (op) {
    case OP_EQ: return c == 0;
    case OP_NE: return c != 0;
    case OP_GT: return c >  0;
    case OP_LT: return c <  0;
    case OP_GE: return c >= 0;
    case OP_LE: return c <= 0;
    default:    return 0;
    }
}

static int fval_matches(const fval_t *fv, op_t op, const char *val)
{
    switch (fv->type) {
    case FV_UINT: {
        if (op == OP_CONTAINS || op == OP_MATCHES) return 0;
        uint64_t rhs = to_num(val);
        long long c  = (fv->u > rhs) - (fv->u < rhs);
        return cmp_sign(op, c);
    }
    case FV_IPV4: {
        uint8_t ip[4]; int cidr = 32;
        if (parse_ipv4(val, ip, &cidr) != 0) return 0;
        if (op == OP_EQ || op == OP_NE) {
            uint32_t a = ((uint32_t)fv->ipv4[0] << 24) | ((uint32_t)fv->ipv4[1] << 16) |
                         ((uint32_t)fv->ipv4[2] <<  8) |  (uint32_t)fv->ipv4[3];
            uint32_t b = ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
                         ((uint32_t)ip[2] <<  8) |  (uint32_t)ip[3];
            uint32_t mask = (cidr == 0) ? 0u
                          : (cidr >= 32 ? 0xffffffffu : ~((1u << (32 - cidr)) - 1));
            int eq = ((a & mask) == (b & mask));
            return (op == OP_EQ) ? eq : !eq;
        }
        return cmp_sign(op, (long long)memcmp(fv->ipv4, ip, 4));
    }
    case FV_IPV6: {
        uint8_t ip[16]; int prefix = 128;
        if (parse_ipv6_cidr(val, ip, &prefix) != 0) return 0;
        if (op == OP_EQ || op == OP_NE) {
            int full = prefix / 8, rem = prefix % 8, eq = 1, i;
            for (i = 0; i < full && eq; i++) eq = (fv->ipv6[i] == ip[i]);
            if (eq && rem) {
                uint8_t mask = (uint8_t)(0xff << (8 - rem)) & 0xff;
                eq = ((fv->ipv6[full] & mask) == (ip[full] & mask));
            }
            return (op == OP_EQ) ? eq : !eq;
        }
        return cmp_sign(op, (long long)memcmp(fv->ipv6, ip, 16));
    }
    case FV_MAC: {
        uint8_t m[6];
        if (parse_mac(val, m) != 0) return 0;
        return cmp_sign(op, (long long)memcmp(fv->mac, m, 6));
    }
    case FV_STR: {
        if (op == OP_CONTAINS) return strstr(fv->str, val) != NULL;
        if (op == OP_MATCHES) {
            regex_t re;
            if (regcomp(&re, val, REG_EXTENDED | REG_NOSUB) != 0) return 0;
            int r = (regexec(&re, fv->str, 0, NULL, 0) == 0);
            regfree(&re);
            return r;
        }
        return cmp_sign(op, (long long)strcmp(fv->str, val));
    }
    case FV_BYTES: {
        /* Extract big-endian integer from the slice bytes */
        uint64_t lv = 0;
        for (int i = 0; i < fv->bytes.len; i++)
            lv = (lv << 8) | fv->bytes.data[i];
        uint64_t rv = to_num(val);
        return cmp_sign(op, (lv > rv) - (lv < rv));
    }
    default: return 0;
    }
}

/* ---- Filter evaluator ---- */

static int filter_eval_node(const fnode_t *n, const pkt_ctx_t *ctx,
                             pcapng_field_provider_t pfn, void *pctx)
{
    if (!n) return 1;
    switch (n->type) {
    case N_AND:
        return filter_eval_node(n->a, ctx, pfn, pctx) &&
               filter_eval_node(n->b, ctx, pfn, pctx);
    case N_OR:
        return filter_eval_node(n->a, ctx, pfn, pctx) ||
               filter_eval_node(n->b, ctx, pfn, pctx);
    case N_NOT:
        return !filter_eval_node(n->a, ctx, pfn, pctx);
    case N_EXISTS: {
        fval_t hits[CAP_MAX_FVALS];
        return raw_field_get(ctx, n->field, hits, CAP_MAX_FVALS, pfn, pctx) > 0;
    }
    case N_CMP: {
        /* OP_CONTAINS on a named layer: byte-sequence search in raw bytes */
        if (n->op == OP_CONTAINS) {
            const uint8_t *base = NULL; uint32_t blen = 0;
            if      (!strcmp(n->field, "frame"))               { base = ctx->raw;  blen = ctx->rawlen; }
            else if (!strcmp(n->field, "eth")  && ctx->eth)    { base = ctx->eth;  blen = ctx->rawlen - (uint32_t)(ctx->eth  - ctx->raw); }
            else if (!strcmp(n->field, "ip")   && ctx->ip4)    { base = ctx->ip4;  blen = ctx->rawlen - (uint32_t)(ctx->ip4  - ctx->raw); }
            else if (!strcmp(n->field, "ip6")  && ctx->ip6)    { base = ctx->ip6;  blen = ctx->rawlen - (uint32_t)(ctx->ip6  - ctx->raw); }
            else if (!strcmp(n->field, "tcp")  && ctx->tcp)    { base = ctx->tcp;  blen = ctx->rawlen - (uint32_t)(ctx->tcp  - ctx->raw); }
            else if (!strcmp(n->field, "udp")  && ctx->udp)    { base = ctx->udp;  blen = ctx->rawlen - (uint32_t)(ctx->udp  - ctx->raw); }
            if (base) {
                uint8_t pat[64]; int plen = 0;
                return parse_byte_pattern(n->value, pat, &plen) == 0
                       && bytes_contains(base, blen, pat, plen);
            }
            /* fall through: provider-backed FV_STR fields use fval_matches */
        }
        fval_t hits[CAP_MAX_FVALS];
        int nh = raw_field_get(ctx, n->field, hits, CAP_MAX_FVALS, pfn, pctx);
        for (int i = 0; i < nh; i++)
            if (fval_matches(&hits[i], n->op, n->value)) return 1;
        return 0;
    }
    }
    return 0;
}

static int filter_eval(const cap_filter_t *f, const pkt_ctx_t *ctx,
                        pcapng_field_provider_t pfn, void *pctx)
{
    if (!f || f->match_all) return 1;
    return filter_eval_node(f->root, ctx, pfn, pctx);
}

int pcapng_capture_filter_match(const char *expr,
                                const uint8_t *data, uint32_t len,
                                uint16_t linktype,
                                char *errbuf)
{
    char ebuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
    cap_filter_t *f = filter_compile(expr, ebuf, sizeof ebuf);
    if (!f) {
        if (errbuf) snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE, "%s", ebuf);
        return -1;
    }
    pkt_ctx_t ctx;
    pkt_ctx_init(&ctx, data, len, linktype, NULL);  /* NULL = no flow state */
    int r = filter_eval(f, &ctx, NULL, NULL);
    filter_free(f);
    return r;
}

int pcapng_capture_filter_match_ex(const char *expr,
                                    const uint8_t *data, uint32_t len,
                                    uint16_t linktype,
                                    pcapng_flow_table_t *table,
                                    char *errbuf)
{
    char ebuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
    cap_filter_t *f = filter_compile(expr, ebuf, sizeof ebuf);
    if (!f) {
        if (errbuf) snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE, "%s", ebuf);
        return -1;
    }
    pkt_ctx_t ctx;
    pkt_ctx_init(&ctx, data, len, linktype, table);
    int r = filter_eval(f, &ctx, NULL, NULL);
    filter_free(f);
    return r;
}

/* ========================================================================
 * Capture handle
 * ======================================================================== */

struct pcapng_capture {
    char        device[64];
    uint32_t    snaplen;
    int         promisc;
    int         timeout_ms;
    size_t      buffer_size;

    cap_filter_t              *filter;
    pcapng_field_provider_t    field_fn;
    void                      *field_ctx;
    pcapng_flow_table_t       *flow_table;

    pcapng_capture_stats_t     stats;

    volatile int               breakflag;
    uint16_t                   linktype;

#if defined(__linux__)
    int          fd;
    void        *ring;
    size_t       ring_size;
    uint32_t     block_size;
    uint32_t     block_nr;
    uint32_t     block_idx;
#elif defined(__APPLE__) || defined(__FreeBSD__) || \
      defined(__OpenBSD__) || defined(__NetBSD__)
    int          fd;
    uint8_t     *bpf_buf;
    size_t       bpf_buf_size;
#else
    /* Unsupported platform (e.g. Windows): the stub backend never opens
       anything, but the platform-independent layer still tests cap->fd to
       decide whether to activate, so the member has to exist. */
    int          fd;
#endif
};

/* ---- Global SIGINT flag (shared across all handles in the process) ---- */
static volatile sig_atomic_t g_sigint = 0;
static void sigint_handler(int sig) { (void)sig; g_sigint = 1; }

static void install_sigint_handler(void)
{
#ifdef _WIN32
    /* No sigaction on Windows; the CRT's signal() is enough to set the flag. */
    signal(SIGINT, sigint_handler);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);
#endif
}

/* ========================================================================
 * Device enumeration
 * ======================================================================== */

#ifdef _WIN32

/* Windows has no capture backend, so there is nothing to enumerate. Report the
   empty list rather than a hard error: callers (carcal's interface chooser)
   show the message and carry on with file-based analysis. */
pcapng_device_t *pcapng_capture_list_devices(int *count, char *errbuf)
{
    if (errbuf) snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                         "live capture not supported on this platform");
    if (count) *count = 0;
    return NULL;
}

void pcapng_capture_free_devices(pcapng_device_t *devs)
{
    free(devs);
}

const char *pcapng_capture_default_device(char *errbuf)
{
    if (errbuf) snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                         "live capture not supported on this platform");
    return NULL;
}

#else /* !_WIN32 */

pcapng_device_t *pcapng_capture_list_devices(int *count, char *errbuf)
{
    struct ifaddrs *ifa_head = NULL, *ifa;
    if (getifaddrs(&ifa_head) != 0) {
        if (errbuf) snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                             "getifaddrs: %s", strerror(errno));
        if (count) *count = 0;
        return NULL;
    }

    /* Count unique interface names */
    int cap = 0;
    for (ifa = ifa_head; ifa; ifa = ifa->ifa_next)
        if (ifa->ifa_name) cap++;

    /* Allocate generous space (may over-count) */
    pcapng_device_t *devs = calloc((size_t)(cap + 1), sizeof *devs);
    if (!devs) {
        freeifaddrs(ifa_head);
        if (errbuf) snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE, "out of memory");
        if (count) *count = 0;
        return NULL;
    }

    int n = 0;
    for (ifa = ifa_head; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) continue;
        /* Deduplicate */
        int found = 0;
        for (int i = 0; i < n; i++)
            if (!strcmp(devs[i].name, ifa->ifa_name)) { found = 1; break; }
        if (found) continue;

        snprintf(devs[n].name, sizeof devs[n].name, "%s", ifa->ifa_name);
        devs[n].loopback = (ifa->ifa_flags & IFF_LOOPBACK) ? 1 : 0;
        n++;
    }

    freeifaddrs(ifa_head);
    if (count) *count = n;
    return devs;
}

void pcapng_capture_free_devices(pcapng_device_t *devs)
{
    free(devs);
}

const char *pcapng_capture_default_device(char *errbuf)
{
    static char name[64];
    int count = 0;
    pcapng_device_t *devs = pcapng_capture_list_devices(&count, errbuf);
    if (!devs) return NULL;

    const char *found = NULL;
    for (int i = 0; i < count; i++) {
        if (!devs[i].loopback) {
            snprintf(name, sizeof name, "%s", devs[i].name);
            found = name;
            break;
        }
    }
    if (!found && count > 0) {
        snprintf(name, sizeof name, "%s", devs[0].name);
        found = name;
    }
    free(devs);
    return found;
}

#endif /* !_WIN32 */

/* ========================================================================
 * Open / configure
 * ======================================================================== */

pcapng_capture_t *pcapng_capture_open(const char *device, char *errbuf)
{
    if (!device || !*device) {
        if (errbuf) snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                             "device name required");
        return NULL;
    }

    pcapng_capture_t *cap = calloc(1, sizeof *cap);
    if (!cap) {
        if (errbuf) snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE, "out of memory");
        return NULL;
    }

    snprintf(cap->device,  sizeof cap->device,  "%s", device);
    cap->snaplen    = CAP_DEFAULT_SNAPLEN;
    cap->promisc    = 1;
    cap->timeout_ms = CAP_DEFAULT_TIMEOUT_MS;
    cap->buffer_size = CAP_DEFAULT_BUF_SIZE;
    cap->linktype   = LINKTYPE_ETHERNET;

#if defined(__linux__)
    cap->fd      = -1;
    cap->ring    = MAP_FAILED;
    cap->block_size = CAP_BLOCK_SIZE;
    cap->block_nr   = CAP_BLOCK_NR;
#elif defined(__APPLE__) || defined(__FreeBSD__) || \
      defined(__OpenBSD__) || defined(__NetBSD__)
    cap->fd      = -1;
    cap->bpf_buf = NULL;
    cap->bpf_buf_size = CAP_BPF_BUF_SIZE;
#else
    cap->fd      = -1;   /* stub backend: never opened, but tested before use */
#endif

    cap->flow_table = pcapng_flow_table_create();
    return cap;
}

int pcapng_capture_set_snaplen(pcapng_capture_t *cap, uint32_t snaplen)
{
    if (!cap) return -1;
    cap->snaplen = snaplen ? snaplen : CAP_DEFAULT_SNAPLEN;
    return 0;
}

int pcapng_capture_set_promisc(pcapng_capture_t *cap, int on)
{
    if (!cap) return -1;
    cap->promisc = on;
    return 0;
}

int pcapng_capture_set_timeout(pcapng_capture_t *cap, int ms)
{
    if (!cap) return -1;
    cap->timeout_ms = (ms > 0) ? ms : CAP_DEFAULT_TIMEOUT_MS;
    return 0;
}

int pcapng_capture_set_buffer_size(pcapng_capture_t *cap, size_t bytes)
{
    if (!cap) return -1;
    if (bytes >= 4096) cap->buffer_size = bytes;
    return 0;
}

int pcapng_capture_set_filter(pcapng_capture_t *cap,
                               const char *expr, char *errbuf)
{
    if (!cap) return -1;
    filter_free(cap->filter);
    cap->filter = filter_compile(expr, errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE);
    return cap->filter ? 0 : -1;
}

void pcapng_capture_set_field_provider(pcapng_capture_t *cap,
                                        pcapng_field_provider_t fn, void *ctx)
{
    if (!cap) return;
    cap->field_fn  = fn;
    cap->field_ctx = ctx;
}

/* ========================================================================
 * Platform backends
 * ======================================================================== */

/* ────────────────────────────────────────────────────────────────────────
 * Linux: AF_PACKET + TPACKET_V3 (zero-copy ring buffer)
 * ────────────────────────────────────────────────────────────────────────*/
#if defined(__linux__)

static int linux_open(pcapng_capture_t *cap, char *errbuf)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                 "socket(AF_PACKET): %s  (need root or CAP_NET_RAW)", strerror(errno));
        return -1;
    }

    /* Select TPACKET_V3 */
    int ver = TPACKET_V3;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof ver) < 0) {
        snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                 "PACKET_VERSION: %s", strerror(errno));
        close(fd); return -1;
    }

    /* Compute frame size — must be a multiple of TPACKET_ALIGNMENT (16) */
    uint32_t frame_sz = (uint32_t)(sizeof(struct tpacket3_hdr) + cap->snaplen);
    frame_sz = (frame_sz + TPACKET_ALIGNMENT - 1) & ~(TPACKET_ALIGNMENT - 1u);

    /* Ensure at least 1 frame per block */
    uint32_t block_sz = cap->block_size;
    if (frame_sz > block_sz) block_sz = frame_sz * 4;
    /* block_size must be a multiple of page size */
    long pgsz = sysconf(_SC_PAGESIZE);
    if (pgsz < 4096) pgsz = 4096;
    block_sz = (uint32_t)(((uint64_t)block_sz + (uint64_t)(pgsz - 1)) &
                           ~(uint64_t)(pgsz - 1));

    uint32_t frames_per_block = block_sz / frame_sz;
    if (frames_per_block == 0) frames_per_block = 1;
    /* Recompute frame_sz so block_sz is an exact multiple */
    frame_sz = block_sz / frames_per_block;

    struct tpacket_req3 req;
    memset(&req, 0, sizeof req);
    req.tp_block_size       = block_sz;
    req.tp_block_nr         = cap->block_nr;
    req.tp_frame_size       = frame_sz;
    req.tp_frame_nr         = frames_per_block * cap->block_nr;
    req.tp_retire_blk_tov   = (uint32_t)cap->timeout_ms;
    req.tp_sizeof_priv      = 0;
    req.tp_feature_req_word = 0;

    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof req) < 0) {
        snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                 "PACKET_RX_RING: %s", strerror(errno));
        close(fd); return -1;
    }

    /* Map ring into userspace */
    size_t ring_size = (size_t)block_sz * cap->block_nr;
    void  *ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_LOCKED, fd, 0);
    if (ring == MAP_FAILED) {
        snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                 "mmap ring: %s", strerror(errno));
        close(fd); return -1;
    }

    /* Bind to interface */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof sll);
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = (int)if_nametoindex(cap->device);
    if (sll.sll_ifindex == 0) {
        snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                 "interface '%s' not found", cap->device);
        munmap(ring, ring_size); close(fd); return -1;
    }
    if (bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0) {
        snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                 "bind: %s", strerror(errno));
        munmap(ring, ring_size); close(fd); return -1;
    }

    /* Promiscuous mode */
    if (cap->promisc) {
        struct packet_mreq mr;
        memset(&mr, 0, sizeof mr);
        mr.mr_ifindex = sll.sll_ifindex;
        mr.mr_type    = PACKET_MR_PROMISC;
        setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr);
    }

    cap->fd         = fd;
    cap->ring       = ring;
    cap->ring_size  = ring_size;
    cap->block_size = block_sz;
    cap->linktype   = LINKTYPE_ETHERNET;

    return 0;
}

static void linux_close(pcapng_capture_t *cap)
{
    if (cap->ring != MAP_FAILED && cap->ring) {
        munmap(cap->ring, cap->ring_size);
        cap->ring = MAP_FAILED;
    }
    if (cap->fd >= 0) { close(cap->fd); cap->fd = -1; }
}

static int linux_get_stats(pcapng_capture_t *cap, pcapng_capture_stats_t *st)
{
    struct tpacket_stats_v3 ks;
    socklen_t len = sizeof ks;
    if (getsockopt(cap->fd, SOL_PACKET, PACKET_STATISTICS, &ks, &len) < 0) return -1;
    st->received = ks.tp_packets;
    st->dropped  = ks.tp_drops;
    st->passed   = cap->stats.passed;
    st->filtered = cap->stats.filtered;
    return 0;
}

/* Iterate one TPACKET_V3 block.  Returns packets processed. */
static int linux_process_block(pcapng_capture_t *cap,
                                pcapng_packet_cb cb, void *ud,
                                int max_pkts)
{
    uint8_t *bptr = (uint8_t *)cap->ring + (size_t)cap->block_idx * cap->block_size;
    struct tpacket_block_desc *bd = (struct tpacket_block_desc *)bptr;

    if (!(bd->hdr.bh1.block_status & TP_STATUS_USER)) return 0;

    int processed = 0;
    uint32_t nframes = bd->hdr.bh1.num_pkts;
    uint8_t *fptr    = bptr + bd->hdr.bh1.offset_to_first_pkt;

    for (uint32_t i = 0; i < nframes && (max_pkts <= 0 || processed < max_pkts); i++) {
        struct tpacket3_hdr *tp = (struct tpacket3_hdr *)fptr;

        const uint8_t *data   = fptr + tp->tp_mac;
        uint32_t       caplen = tp->tp_snaplen;
        uint32_t       origlen = tp->tp_len;

        if (caplen > cap->snaplen) caplen = cap->snaplen;

        pkt_ctx_t ctx;
        pkt_ctx_init(&ctx, data, caplen, cap->linktype, cap->flow_table);

        if (filter_eval(cap->filter, &ctx, cap->field_fn, cap->field_ctx)) {
            pcapng_packet_info_t info;
            info.data         = data;
            info.captured_len = caplen;
            info.original_len = origlen;
            info.timestamp_ns = (uint64_t)tp->tp_sec * 1000000000ULL + tp->tp_nsec;
            info.direction    = PCAPNG_CAP_DIR_UNKNOWN;
            cb(&info, ud);
            cap->stats.passed++;
        } else {
            cap->stats.filtered++;
        }
        processed++;

        if (tp->tp_next_offset == 0 || i + 1 >= nframes) break;
        fptr += tp->tp_next_offset;
    }

    /* Return block to kernel */
    bd->hdr.bh1.block_status = TP_STATUS_KERNEL;
    __sync_synchronize();
    cap->block_idx = (cap->block_idx + 1) % cap->block_nr;
    return processed;
}

static int linux_dispatch(pcapng_capture_t *cap,
                           int count, pcapng_packet_cb cb, void *ud)
{
    if (cap->fd < 0) return -1;

    struct pollfd pfd;
    pfd.fd     = cap->fd;
    pfd.events = POLLIN;

    int total = 0;
    while (!cap->breakflag && !g_sigint) {
        /* Drain all ready blocks first */
        int n;
        do {
            n = linux_process_block(cap, cb, ud,
                                    count > 0 ? count - total : -1);
            total += n;
            if (count > 0 && total >= count) return total;
        } while (n > 0);

        /* Wait for next block */
        int r = poll(&pfd, 1, cap->timeout_ms);
        if (r < 0 && errno == EINTR) continue;
        if (r == 0) break;   /* timeout → dispatch returns */
        if (r < 0)  return -1;
    }
    return total;
}

#endif /* __linux__ */

/* ────────────────────────────────────────────────────────────────────────
 * macOS / BSD: /dev/bpfN
 * ────────────────────────────────────────────────────────────────────────*/
#if defined(__APPLE__) || defined(__FreeBSD__) || \
    defined(__OpenBSD__) || defined(__NetBSD__)

static int bsd_open(pcapng_capture_t *cap, char *errbuf)
{
    int fd = -1;
    char path[32];
    for (int i = 0; i < 256; i++) {
        snprintf(path, sizeof path, "/dev/bpf%d", i);
        fd = open(path, O_RDWR);
        if (fd >= 0) break;
    }
    if (fd < 0) {
        snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                 "could not open /dev/bpfN: %s  (need root)", strerror(errno));
        return -1;
    }

    /* Buffer size must be set BEFORE binding the interface */
    u_int buf_len = (u_int)cap->bpf_buf_size;
    ioctl(fd, BIOCSBLEN, &buf_len);
    if (ioctl(fd, BIOCGBLEN, &buf_len) < 0) buf_len = CAP_BPF_BUF_SIZE;
    cap->bpf_buf_size = buf_len;

    /* Bind to interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strlcpy(ifr.ifr_name, cap->device, sizeof ifr.ifr_name);
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
        snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                 "BIOCSETIF '%s': %s", cap->device, strerror(errno));
        close(fd); return -1;
    }

    /* Immediate delivery (don't wait for buffer to fill) */
    u_int one = 1;
    ioctl(fd, BIOCIMMEDIATE, &one);

    /* Promiscuous mode */
    if (cap->promisc) ioctl(fd, BIOCPROMISC, NULL);

    /* Set read timeout */
    struct timeval tv;
    tv.tv_sec  = cap->timeout_ms / 1000;
    tv.tv_usec = (cap->timeout_ms % 1000) * 1000;
    ioctl(fd, BIOCSRTIMEOUT, &tv);

    /* Get link type */
    u_int dlt = DLT_EN10MB;
    ioctl(fd, BIOCGDLT, &dlt);
    cap->linktype = (dlt == DLT_EN10MB) ? LINKTYPE_ETHERNET
                  : (dlt == DLT_NULL)   ? LINKTYPE_RAW
                  : LINKTYPE_ETHERNET;

    /* Allocate read buffer */
    cap->bpf_buf = malloc(buf_len);
    if (!cap->bpf_buf) {
        snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE, "out of memory");
        close(fd); return -1;
    }

    cap->fd = fd;
    return 0;
}

static void bsd_close(pcapng_capture_t *cap)
{
    if (cap->fd >= 0) { close(cap->fd); cap->fd = -1; }
    free(cap->bpf_buf); cap->bpf_buf = NULL;
}

static int bsd_get_stats(pcapng_capture_t *cap, pcapng_capture_stats_t *st)
{
    struct bpf_stat bs;
    if (ioctl(cap->fd, BIOCGSTATS, &bs) < 0) return -1;
    st->received = bs.bs_recv;
    st->dropped  = bs.bs_drop;
    st->passed   = cap->stats.passed;
    st->filtered = cap->stats.filtered;
    return 0;
}

static int bsd_dispatch(pcapng_capture_t *cap,
                         int count, pcapng_packet_cb cb, void *ud)
{
    if (cap->fd < 0 || !cap->bpf_buf) return -1;

    ssize_t nread = read(cap->fd, cap->bpf_buf, cap->bpf_buf_size);
    if (nread < 0) {
        if (errno == EAGAIN || errno == EINTR) return 0;
        return -1;
    }
    if (nread == 0) return 0;

    int total = 0;
    uint8_t *p   = cap->bpf_buf;
    uint8_t *end = cap->bpf_buf + nread;

    while (p < end && (count <= 0 || total < count)) {
        if ((size_t)(end - p) < sizeof(struct bpf_hdr)) break;

        struct bpf_hdr *bh = (struct bpf_hdr *)p;
        uint8_t  *data   = p + bh->bh_hdrlen;
        uint32_t  caplen = bh->bh_caplen;
        uint32_t  origlen = bh->bh_datalen;

        if (caplen > cap->snaplen) caplen = cap->snaplen;

        pkt_ctx_t ctx;
        pkt_ctx_init(&ctx, data, caplen, cap->linktype, cap->flow_table);

        if (filter_eval(cap->filter, &ctx, cap->field_fn, cap->field_ctx)) {
            pcapng_packet_info_t info;
            info.data         = data;
            info.captured_len = caplen;
            info.original_len = origlen;
            info.timestamp_ns = (uint64_t)bh->bh_tstamp.tv_sec * 1000000000ULL
                              + (uint64_t)bh->bh_tstamp.tv_usec * 1000ULL;
            info.direction    = PCAPNG_CAP_DIR_UNKNOWN;
            cb(&info, ud);
            cap->stats.passed++;
        } else {
            cap->stats.filtered++;
        }
        total++;
        p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
    }

    return total;
}

#endif /* __APPLE__ || BSD */

/* ────────────────────────────────────────────────────────────────────────
 * Unsupported platform stub
 * ────────────────────────────────────────────────────────────────────────*/
#if !defined(__linux__) && !defined(__APPLE__) && !defined(__FreeBSD__) && \
    !defined(__OpenBSD__) && !defined(__NetBSD__)

static int   stub_open(pcapng_capture_t *cap, char *errbuf)
{
    snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
             "live capture not supported on this platform");
    (void)cap; return -1;
}
static void  stub_close(pcapng_capture_t *cap)      { (void)cap; }
static int   stub_get_stats(pcapng_capture_t *cap, pcapng_capture_stats_t *s)
{ (void)cap; (void)s; return -1; }
static int   stub_dispatch(pcapng_capture_t *cap, int c, pcapng_packet_cb cb, void *ud)
{ (void)cap; (void)c; (void)cb; (void)ud; return -1; }

#define linux_open      stub_open
#define linux_close     stub_close
#define linux_get_stats stub_get_stats
#define linux_dispatch  stub_dispatch
#define bsd_open        stub_open
#define bsd_close       stub_close
#define bsd_get_stats   stub_get_stats
#define bsd_dispatch    stub_dispatch

#endif

/* ========================================================================
 * Dispatch / loop — platform-independent layer
 * ======================================================================== */

/* Activate the underlying capture socket (called lazily on first loop/dispatch) */
static int cap_activate(pcapng_capture_t *cap, char *errbuf)
{
    if (!cap) return -1;

    char local_errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE] = {0};
    if (!errbuf) errbuf = local_errbuf;

#if defined(__linux__)
    return linux_open(cap, errbuf);
#elif defined(__APPLE__) || defined(__FreeBSD__) || \
      defined(__OpenBSD__) || defined(__NetBSD__)
    return bsd_open(cap, errbuf);
#else
    return stub_open(cap, errbuf);
#endif
}

int pcapng_capture_dispatch(pcapng_capture_t *cap, int count,
                             pcapng_packet_cb cb, void *userdata)
{
    if (!cap || !cb) return -1;

    /* Lazy activation */
    char errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
    if (
#if defined(__linux__)
        cap->fd < 0
#else
        cap->fd < 0
#endif
    ) {
        if (cap_activate(cap, errbuf) < 0) return -1;
    }

    install_sigint_handler();
    cap->breakflag = 0;

#if defined(__linux__)
    return linux_dispatch(cap, count, cb, userdata);
#elif defined(__APPLE__) || defined(__FreeBSD__) || \
      defined(__OpenBSD__) || defined(__NetBSD__)
    return bsd_dispatch(cap, count, cb, userdata);
#else
    return stub_dispatch(cap, count, cb, userdata);
#endif
}

int pcapng_capture_loop(pcapng_capture_t *cap, int count,
                         pcapng_packet_cb cb, void *userdata)
{
    if (!cap || !cb) return -1;

    /* Lazy activation */
    char errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
    if (cap->fd < 0) {
        if (cap_activate(cap, errbuf) < 0) return -1;
    }

    install_sigint_handler();
    cap->breakflag = 0;
    g_sigint = 0;

    int total = 0;

    while (!cap->breakflag && !g_sigint) {
#if defined(__linux__)
        int n = linux_dispatch(cap, count > 0 ? count - total : -1, cb, userdata);
#elif defined(__APPLE__) || defined(__FreeBSD__) || \
      defined(__OpenBSD__) || defined(__NetBSD__)
        int n = bsd_dispatch(cap, count > 0 ? count - total : -1, cb, userdata);
#else
        int n = stub_dispatch(cap, count > 0 ? count - total : -1, cb, userdata);
#endif
        if (n < 0) return -1;
        total += n;
        if (count > 0 && total >= count) break;
    }
    return total;
}

void pcapng_capture_break(pcapng_capture_t *cap)
{
    if (cap) cap->breakflag = 1;
}

int pcapng_capture_get_stats(pcapng_capture_t *cap,
                               pcapng_capture_stats_t *st)
{
    if (!cap || !st) return -1;
#if defined(__linux__)
    return linux_get_stats(cap, st);
#elif defined(__APPLE__) || defined(__FreeBSD__) || \
      defined(__OpenBSD__) || defined(__NetBSD__)
    return bsd_get_stats(cap, st);
#else
    return stub_get_stats(cap, st);
#endif
}

void pcapng_capture_close(pcapng_capture_t *cap)
{
    if (!cap) return;
#if defined(__linux__)
    linux_close(cap);
#elif defined(__APPLE__) || defined(__FreeBSD__) || \
      defined(__OpenBSD__) || defined(__NetBSD__)
    bsd_close(cap);
#else
    stub_close(cap);
#endif
    filter_free(cap->filter);
    pcapng_flow_table_free(cap->flow_table);
    free(cap);
}

/* ========================================================================
 * Convenience functions
 * ======================================================================== */

/* ---- to_file ---- */

typedef struct {
    FILE    *out;
    int      written;
} to_file_ctx_t;

static void to_file_cb(const pcapng_packet_info_t *pkt, void *ud)
{
    to_file_ctx_t *ctx = (to_file_ctx_t *)ud;
    /* timestamp in seconds for the easy-API */
    uint32_t ts_sec = (uint32_t)(pkt->timestamp_ns / 1000000000ULL);
    libpcapng_write_enhanced_packet_with_time_to_file(
        ctx->out,
        (unsigned char *)(uintptr_t)pkt->data,   /* cast away const */
        pkt->captured_len,
        ts_sec);
    ctx->written++;
}

int pcapng_capture_to_file(const char *device, const char *path,
                            const char *filter, int count, char *errbuf)
{
    char local_errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
    if (!errbuf) errbuf = local_errbuf;

    FILE *f = fopen(path, "wb");
    if (!f) {
        snprintf(errbuf, PCAPNG_CAPTURE_ERRBUF_SIZE,
                 "fopen '%s': %s", path, strerror(errno));
        return -1;
    }

    libpcapng_write_header_to_file_with_linktype(f, LINKTYPE_ETHERNET);

    pcapng_capture_t *cap = pcapng_capture_open(device, errbuf);
    if (!cap) { fclose(f); return -1; }

    if (filter && *filter) {
        if (pcapng_capture_set_filter(cap, filter, errbuf) < 0) {
            pcapng_capture_close(cap); fclose(f); return -1;
        }
    }

    to_file_ctx_t ctx = { f, 0 };
    int rc = pcapng_capture_loop(cap, count, to_file_cb, &ctx);

    pcapng_capture_stats_t st;
    if (pcapng_capture_get_stats(cap, &st) == 0) {
        fprintf(stderr, "%llu packets received, %llu dropped\n",
                (unsigned long long)st.received,
                (unsigned long long)st.dropped);
    }

    pcapng_capture_close(cap);
    fclose(f);
    return (rc < 0) ? -1 : ctx.written;
}

/* ---- print ---- */

static void print_cb(const pcapng_packet_info_t *pkt, void *ud)
{
    (void)ud;
    uint64_t ns   = pkt->timestamp_ns;
    uint64_t sec  = ns / 1000000000ULL;
    uint64_t usec = (ns % 1000000000ULL) / 1000ULL;

    /* Simple protocol detection for the one-liner */
    const char *proto = "DATA";
    if (pkt->captured_len >= 14) {
        uint16_t et = (uint16_t)((pkt->data[12] << 8) | pkt->data[13]);
        if (et == 0x0800 && pkt->captured_len >= 34) {
            uint8_t ip_proto = pkt->data[23];
            if (ip_proto == 6)  proto = "TCP";
            else if (ip_proto == 17) proto = "UDP";
            else if (ip_proto == 1)  proto = "ICMP";
            else                     proto = "IP";
        } else if (et == 0x86DD) proto = "IPv6";
        else if (et == 0x0806)   proto = "ARP";
    }

    printf("%llu.%06llu  %-6s  %u bytes\n",
           (unsigned long long)sec, (unsigned long long)usec,
           proto, pkt->original_len);
}

int pcapng_capture_print(const char *device, const char *filter,
                          int count, char *errbuf)
{
    char local_errbuf[PCAPNG_CAPTURE_ERRBUF_SIZE];
    if (!errbuf) errbuf = local_errbuf;

    pcapng_capture_t *cap = pcapng_capture_open(device, errbuf);
    if (!cap) return -1;

    if (filter && *filter) {
        if (pcapng_capture_set_filter(cap, filter, errbuf) < 0) {
            pcapng_capture_close(cap); return -1;
        }
    }

    printf("Capturing on %s%s%s — press Ctrl-C to stop\n",
           device,
           (filter && *filter) ? "  filter: " : "",
           (filter && *filter) ? filter        : "");

    int rc = pcapng_capture_loop(cap, count, print_cb, NULL);

    pcapng_capture_stats_t st;
    if (pcapng_capture_get_stats(cap, &st) == 0) {
        printf("\n%llu packets captured, %llu received, %llu dropped\n",
               (unsigned long long)cap->stats.passed,
               (unsigned long long)st.received,
               (unsigned long long)st.dropped);
    }

    pcapng_capture_close(cap);
    return rc;
}
