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

typedef enum { T_WORD, T_STR, T_LP, T_RP, T_AND, T_OR, T_NOT,
               T_EQ, T_NE, T_GT, T_LT, T_GE, T_LE, T_EOF } ttype_t;

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
    case '&': if (p[1]=='&') { L->cur.t = T_AND; L->p = p+2; return; } break;
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
        if (!strcmp(L->cur.s, "contains")){ L->cur.t = T_EQ; snprintf(L->cur.s, sizeof L->cur.s, "contains"); return; }
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

        /* existence test if no operator follows */
        ttype_t ot = L->cur.t;
        if (ot != T_EQ && ot != T_NE && ot != T_GT && ot != T_LT &&
            ot != T_GE && ot != T_LE) {
            fnode_t *n = fnode_new(N_EXISTS);
            if (!n) return NULL;
            snprintf(n->field, sizeof n->field, "%s", field);
            return n;
        }

        op_t op;
        switch (ot) {
        case T_EQ: op = OP_EQ; break;
        case T_NE: op = OP_NE; break;
        case T_GT: op = OP_GT; break;
        case T_LT: op = OP_LT; break;
        case T_GE: op = OP_GE; break;
        case T_LE: op = OP_LE; break;
        default:   op = OP_EQ; break;
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

static cap_filter_t *filter_compile(const char *expr, char *errbuf, size_t esz)
{
    cap_filter_t *f = calloc(1, sizeof *f);
    if (!f) return NULL;

    if (!expr || !*expr || strspn(expr, " \t") == strlen(expr)) {
        f->match_all = 1;
        return f;
    }

    lex_t L;
    memset(&L, 0, sizeof L);
    L.p = expr;
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

    const uint8_t  *ip4;
    const uint8_t  *ip6;
    const uint8_t  *tcp;
    const uint8_t  *udp;
    const uint8_t  *icmp;
} pkt_ctx_t;

static void pkt_ctx_init(pkt_ctx_t *ctx,
                          const uint8_t *data, uint32_t len,
                          uint16_t linktype)
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

        if (nxt == 6  && l4len >= 20) { ctx->tcp  = l4; }
        if (nxt == 17 && l4len >=  8) { ctx->udp  = l4; }
        if (nxt == 58 && l4len >=  4) { ctx->icmp = l4; }
    }
}

/* ========================================================================
 * Raw-field extraction
 *
 * fval_t holds one extracted field value; up to CAP_MAX_FVALS are returned
 * per call (alias expansion produces 2, otherwise 1).
 * ======================================================================== */

#define CAP_MAX_FVALS 4

typedef enum { FV_NONE, FV_UINT, FV_IPV4, FV_IPV6, FV_MAC, FV_STR } fvtype_t;

typedef struct {
    fvtype_t  type;
    union {
        uint64_t u;
        uint8_t  ipv4[4];
        uint8_t  ipv6[16];
        uint8_t  mac[6];
        char     str[64];
    };
} fval_t;

/* Populate out[] with field values; returns the count. */
static int raw_field_get(const pkt_ctx_t *ctx, const char *field,
                          fval_t *out, int maxout,
                          pcapng_field_provider_t provider_fn, void *provider_ctx)
{
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

    if (maxout < 1) return 0;
    fval_t *v = &out[0];
    memset(v, 0, sizeof *v);

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

    /* ── Protocol existence ── */
    if (!strcmp(field, "ip"))   { v->type = FV_UINT; v->u = ctx->ip4  ? 1 : 0; return v->u ? 1 : 0; }
    if (!strcmp(field, "ip6") || !strcmp(field, "ipv6")) {
                                  v->type = FV_UINT; v->u = ctx->ip6  ? 1 : 0; return v->u ? 1 : 0; }
    if (!strcmp(field, "tcp"))  { v->type = FV_UINT; v->u = ctx->tcp  ? 1 : 0; return v->u ? 1 : 0; }
    if (!strcmp(field, "udp"))  { v->type = FV_UINT; v->u = ctx->udp  ? 1 : 0; return v->u ? 1 : 0; }
    if (!strcmp(field, "icmp")) { v->type = FV_UINT; v->u = ctx->icmp ? 1 : 0; return v->u ? 1 : 0; }
    if (!strcmp(field, "arp"))  {
        v->type = FV_UINT;
        v->u = (ctx->ethertype == 0x0806) ? 1 : 0; return v->u ? 1 : 0;
    }

    /* ── Custom field provider ── */
    if (provider_fn) {
        char val[160];
        if (provider_fn(field, ctx->raw, ctx->rawlen, val, sizeof val, provider_ctx)) {
            v->type = FV_STR;
            snprintf(v->str, sizeof v->str, "%s", val);
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
        /* IPv6: string comparison only for now */
        char s[64];
        if (!inet_ntop(AF_INET6, fv->ipv6, s, sizeof s)) return 0;
        if (op == OP_CONTAINS || op == OP_MATCHES) return strstr(s, val) != NULL;
        return cmp_sign(op, (long long)strcmp(s, val));
    }
    case FV_MAC: {
        uint8_t m[6];
        if (parse_mac(val, m) != 0) return 0;
        return cmp_sign(op, (long long)memcmp(fv->mac, m, 6));
    }
    case FV_STR: {
        if (op == OP_CONTAINS || op == OP_MATCHES) return strstr(fv->str, val) != NULL;
        return cmp_sign(op, (long long)strcmp(fv->str, val));
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
        pkt_ctx_init(&ctx, data, caplen, cap->linktype);

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
        pkt_ctx_init(&ctx, data, caplen, cap->linktype);

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
