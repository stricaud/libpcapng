/* dfilter.c — a Wireshark/tshark-compatible display-filter engine.
 *
 * Evaluates a compiled expression against the pcapng_field_t tree produced by
 * pcapng_dissect(). Ported from carcal's filter.c; the field-tree layout is
 * shared, so this is the canonical engine for all libpcapng consumers.
 *
 * See dfilter.h for the supported grammar.
 *
 * License MIT
 */
#include <libpcapng/dfilter.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <regex.h>

/* ── operators ──────────────────────────────────────────────────────────── */
typedef enum { OP_EQ, OP_NE, OP_GT, OP_LT, OP_GE, OP_LE, OP_CONTAINS, OP_MATCHES } op_t;

/* ── AST ────────────────────────────────────────────────────────────────── */
typedef enum { N_AND, N_OR, N_NOT, N_EXISTS, N_CMP } ntype_t;
typedef struct node {
  ntype_t type;
  struct node *a, *b;          /* AND/OR: a,b ; NOT: a                        */
  char field[PCAPNG_FIELD_ABBREV_MAX];
  op_t op;
  char value[128];
  int  has_slice;              /* field[...] byte-slice comparison            */
  int  slice_off;
  int  slice_len;              /* -1 = to end of field                        */
} node_t;

struct pcapng_dfilter { node_t *root; int match_all; };

/* ── lexer ──────────────────────────────────────────────────────────────── */
typedef enum { T_WORD, T_STR, T_LP, T_RP, T_AND, T_OR, T_NOT,
               T_EQ, T_NE, T_GT, T_LT, T_GE, T_LE,
               T_LB, T_RB, T_LBRACE, T_RBRACE, T_COMMA, T_EOF } ttype_t;
typedef struct { ttype_t t; char s[128]; } tok_t;

typedef struct {
  const char *p;
  tok_t cur;
  char err[160];
} lex_t;

static int word_char(int c)
{ return isalnum(c) || c == '.' || c == '_' || c == ':' || c == '-' || c == '/'; }

static void lex_next(lex_t *L)
{
  const char *p = L->p;
  while (*p == ' ' || *p == '\t') p++;
  if (!*p) { L->cur.t = T_EOF; L->cur.s[0] = '\0'; L->p = p; return; }

  switch (*p) {
  case '(': L->cur.t = T_LP; L->p = p + 1; return;
  case ')': L->cur.t = T_RP; L->p = p + 1; return;
  case '[': L->cur.t = T_LB; L->p = p + 1; return;
  case ']': L->cur.t = T_RB; L->p = p + 1; return;
  case '{': L->cur.t = T_LBRACE; L->p = p + 1; return;
  case '}': L->cur.t = T_RBRACE; L->p = p + 1; return;
  case ',': L->cur.t = T_COMMA; L->p = p + 1; return;
  case '&': if (p[1] == '&') { L->cur.t = T_AND; L->p = p + 2; return; } break;
  case '|': if (p[1] == '|') { L->cur.t = T_OR;  L->p = p + 2; return; } break;
  case '=': if (p[1] == '=') { L->cur.t = T_EQ;  L->p = p + 2; return; } break;
  case '!': if (p[1] == '=') { L->cur.t = T_NE;  L->p = p + 2; return; }
            L->cur.t = T_NOT; L->p = p + 1; return;
  case '>': if (p[1] == '=') { L->cur.t = T_GE; L->p = p + 2; return; }
            L->cur.t = T_GT; L->p = p + 1; return;
  case '<': if (p[1] == '=') { L->cur.t = T_LE; L->p = p + 2; return; }
            L->cur.t = T_LT; L->p = p + 1; return;
  case '"': {
    int n = 0; p++;
    while (*p && *p != '"' && n < (int)sizeof L->cur.s - 1) L->cur.s[n++] = *p++;
    L->cur.s[n] = '\0';
    if (*p == '"') p++;
    L->cur.t = T_STR; L->p = p; return;
  }
  default: break;
  }

  if (word_char((unsigned char)*p)) {
    int n = 0;
    while (word_char((unsigned char)*p) && n < (int)sizeof L->cur.s - 1) L->cur.s[n++] = *p++;
    L->cur.s[n] = '\0';
    L->p = p;
    if      (!strcmp(L->cur.s, "and") || !strcmp(L->cur.s, "AND")) L->cur.t = T_AND;
    else if (!strcmp(L->cur.s, "or")  || !strcmp(L->cur.s, "OR"))  L->cur.t = T_OR;
    else if (!strcmp(L->cur.s, "not") || !strcmp(L->cur.s, "NOT")) L->cur.t = T_NOT;
    else L->cur.t = T_WORD;
    return;
  }
  /* unknown char — skip it */
  L->p = p + 1;
  lex_next(L);
}

/* word → comparison op, or -1 */
static int word_op(const char *s)
{
  if (!strcmp(s, "eq")) return OP_EQ;
  if (!strcmp(s, "ne")) return OP_NE;
  if (!strcmp(s, "gt")) return OP_GT;
  if (!strcmp(s, "lt")) return OP_LT;
  if (!strcmp(s, "ge")) return OP_GE;
  if (!strcmp(s, "le")) return OP_LE;
  if (!strcmp(s, "contains")) return OP_CONTAINS;
  if (!strcmp(s, "matches"))  return OP_MATCHES;
  return -1;
}

/* ── parser ─────────────────────────────────────────────────────────────── */
static node_t *parse_or(lex_t *L);

static node_t *mknode(ntype_t t) { node_t *n = calloc(1, sizeof *n); if (n) n->type = t; return n; }

static node_t *mkbin(ntype_t t, node_t *a, node_t *b)
{ node_t *n = mknode(t); if (n) { n->a = a; n->b = b; } return n; }

/* Build a comparison node, carrying an optional byte-slice. */
static node_t *mkcmp(const char *field, op_t op, const char *value,
                     int has_slice, int soff, int slen)
{
  node_t *n = mknode(N_CMP);
  if (!n) return NULL;
  snprintf(n->field, sizeof n->field, "%s", field);
  snprintf(n->value, sizeof n->value, "%s", value);
  n->op = op;
  n->has_slice = has_slice;
  n->slice_off = soff;
  n->slice_len = slen;
  return n;
}

/* Parse a Wireshark slice spec (the text between [ and ]):
     i   → off=i len=1        i:j → off=i len=j
     i-j → off=i len=j-i+1    :j  → off=0 len=j       i: → off=i len=-1 (end) */
static void parse_slice(const char *s, int *off, int *len)
{
  const char *colon = strchr(s, ':');
  const char *dash  = strchr(s, '-');
  if (colon) {
    *off = (colon == s) ? 0 : atoi(s);
    *len = (colon[1]) ? atoi(colon + 1) : -1;
  } else if (dash && dash != s) {
    int a = atoi(s), b = atoi(dash + 1);
    *off = a;
    *len = b - a + 1;
    if (*len < 0) *len = 0;
  } else {
    *off = atoi(s);
    *len = 1;
  }
}

/* Desugar one `in {}` element into a comparison / range subtree. */
static node_t *in_element(const char *field, const char *elem,
                          int has_slice, int soff, int slen)
{
  const char *range = strstr(elem, "..");
  if (range) {
    char lo[128];
    int n = (int)(range - elem);
    if (n > (int)sizeof lo - 1) n = sizeof lo - 1;
    memcpy(lo, elem, n); lo[n] = '\0';
    return mkbin(N_AND,
                 mkcmp(field, OP_GE, lo, has_slice, soff, slen),
                 mkcmp(field, OP_LE, range + 2, has_slice, soff, slen));
  }
  return mkcmp(field, OP_EQ, elem, has_slice, soff, slen);
}

static node_t *parse_primary(lex_t *L)
{
  char field[PCAPNG_FIELD_ABBREV_MAX];
  int has_slice = 0, soff = 0, slen = -1, op;

  if (L->cur.t == T_LP) {
    node_t *n;
    lex_next(L);
    n = parse_or(L);
    if (!n) return NULL;
    if (L->cur.t != T_RP) { snprintf(L->err, sizeof L->err, "expected ')'"); free(n); return NULL; }
    lex_next(L);
    return n;
  }
  if (L->cur.t != T_WORD) {
    snprintf(L->err, sizeof L->err, "expected a field name");
    return NULL;
  }
  snprintf(field, sizeof field, "%s", L->cur.s);
  lex_next(L);

  /* optional byte-slice: field[i:j] */
  if (L->cur.t == T_LB) {
    lex_next(L);
    if (L->cur.t != T_WORD) { snprintf(L->err, sizeof L->err, "expected a slice like [0:4]"); return NULL; }
    parse_slice(L->cur.s, &soff, &slen);
    has_slice = 1;
    lex_next(L);
    if (L->cur.t != T_RB) { snprintf(L->err, sizeof L->err, "expected ']'"); return NULL; }
    lex_next(L);
  }

  /* membership: field in { a, b, 1..5 } */
  if (L->cur.t == T_WORD && !strcmp(L->cur.s, "in")) {
    node_t *acc = NULL;
    lex_next(L);
    if (L->cur.t != T_LBRACE) { snprintf(L->err, sizeof L->err, "expected '{' after 'in'"); return NULL; }
    lex_next(L);
    while (L->cur.t == T_WORD || L->cur.t == T_STR) {
      node_t *e = in_element(field, L->cur.s, has_slice, soff, slen);
      acc = acc ? mkbin(N_OR, acc, e) : e;
      lex_next(L);
      if (L->cur.t == T_COMMA) { lex_next(L); continue; }
      break;
    }
    if (L->cur.t != T_RBRACE) { snprintf(L->err, sizeof L->err, "expected '}'"); return NULL; }
    lex_next(L);
    if (!acc) { snprintf(L->err, sizeof L->err, "empty set"); return NULL; }
    return acc;
  }

  op = -1;
  switch (L->cur.t) {
  case T_EQ: op = OP_EQ; break;
  case T_NE: op = OP_NE; break;
  case T_GT: op = OP_GT; break;
  case T_LT: op = OP_LT; break;
  case T_GE: op = OP_GE; break;
  case T_LE: op = OP_LE; break;
  case T_WORD: op = word_op(L->cur.s); break;
  default: break;
  }
  if (op >= 0) {
    node_t *n;
    lex_next(L);
    if (L->cur.t != T_WORD && L->cur.t != T_STR) {
      snprintf(L->err, sizeof L->err, "expected a value after operator");
      return NULL;
    }
    n = mkcmp(field, (op_t)op, L->cur.s, has_slice, soff, slen);
    lex_next(L);
    return n;
  }

  /* bare field → existence */
  {
    node_t *n = mknode(N_EXISTS);
    if (n) snprintf(n->field, sizeof n->field, "%s", field);
    return n;
  }
}

static node_t *parse_not(lex_t *L)
{
  if (L->cur.t == T_NOT) {
    node_t *n = mknode(N_NOT);
    lex_next(L);
    n->a = parse_not(L);
    if (!n->a) { free(n); return NULL; }
    return n;
  }
  return parse_primary(L);
}

static node_t *parse_and(lex_t *L)
{
  node_t *left = parse_not(L);
  while (left && L->cur.t == T_AND) {
    node_t *n = mknode(N_AND);
    lex_next(L);
    n->a = left;
    n->b = parse_not(L);
    if (!n->b) { return NULL; }   /* leak on error path is acceptable; err set */
    left = n;
  }
  return left;
}

static node_t *parse_or(lex_t *L)
{
  node_t *left = parse_and(L);
  while (left && L->cur.t == T_OR) {
    node_t *n = mknode(N_OR);
    lex_next(L);
    n->a = left;
    n->b = parse_and(L);
    if (!n->b) { return NULL; }
    left = n;
  }
  return left;
}

static void node_free(node_t *n)
{
  if (!n) return;
  node_free(n->a);
  node_free(n->b);
  free(n);
}

pcapng_dfilter_t *pcapng_dfilter_compile(const char *expr, char *errbuf, size_t errlen)
{
  pcapng_dfilter_t *f = calloc(1, sizeof *f);
  lex_t L;
  if (!f) return NULL;

  if (!expr || !*expr || strspn(expr, " \t") == strlen(expr)) {
    f->match_all = 1;
    return f;
  }

  memset(&L, 0, sizeof L);
  L.p = expr;
  lex_next(&L);
  f->root = parse_or(&L);
  if (!f->root || L.cur.t != T_EOF) {
    if (errbuf) snprintf(errbuf, errlen, "%s", L.err[0] ? L.err : "syntax error");
    node_free(f->root);
    free(f);
    return NULL;
  }
  return f;
}

/* ── alias expansion ────────────────────────────────────────────────────── */
static int aliases(const char *field, const char *out[4])
{
  if (!strcmp(field, "ip.addr"))   { out[0] = "ip.src";   out[1] = "ip.dst";   return 2; }
  if (!strcmp(field, "ipv6.addr")) { out[0] = "ipv6.src"; out[1] = "ipv6.dst"; return 2; }
  if (!strcmp(field, "tcp.port"))  { out[0] = "tcp.srcport"; out[1] = "tcp.dstport"; return 2; }
  if (!strcmp(field, "udp.port"))  { out[0] = "udp.srcport"; out[1] = "udp.dstport"; return 2; }
  if (!strcmp(field, "eth.addr"))  { out[0] = "eth.src";  out[1] = "eth.dst";  return 2; }
  out[0] = field;
  return 1;
}

/* ── value comparison ───────────────────────────────────────────────────── */
static uint64_t to_num(const char *s)
{
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) return strtoull(s, NULL, 16);
  return strtoull(s, NULL, 10);
}

static int parse_ipv4(const char *s, uint8_t out[4], int *cidr)
{
  unsigned a, b, c, d; int bits = 32;
  if (sscanf(s, "%u.%u.%u.%u/%d", &a, &b, &c, &d, &bits) >= 4) {
    if (a > 255 || b > 255 || c > 255 || d > 255) return -1;
    out[0] = (uint8_t)a; out[1] = (uint8_t)b; out[2] = (uint8_t)c; out[3] = (uint8_t)d;
    if (bits < 0) bits = 0; if (bits > 32) bits = 32;
    *cidr = bits;
    return 0;
  }
  return -1;
}

static int parse_mac(const char *s, uint8_t out[6])
{
  unsigned m[6];
  if (sscanf(s, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6) {
    int i; for (i = 0; i < 6; i++) out[i] = (uint8_t)m[i];
    return 0;
  }
  return -1;
}

static int cmp_op(op_t op, long long c)   /* c = memcmp/sign result */
{
  switch (op) {
  case OP_EQ: return c == 0;
  case OP_NE: return c != 0;
  case OP_GT: return c >  0;
  case OP_LT: return c <  0;
  case OP_GE: return c >= 0;
  case OP_LE: return c <= 0;
  default:    return c == 0;
  }
}

/* Parse "aa:bb:cc", "aabbcc", or "0x…" into bytes. Returns count, or -1. */
static int parse_hexbytes(const char *s, uint8_t *out, int max)
{
  int n = 0;
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
  if (strchr(s, ':')) {
    char buf[256], *tok, *save = NULL;
    snprintf(buf, sizeof buf, "%s", s);
    for (tok = strtok_r(buf, ":", &save); tok && n < max; tok = strtok_r(NULL, ":", &save))
      out[n++] = (uint8_t)strtoul(tok, NULL, 16);
    return n;
  }
  {
    int len = (int)strlen(s), i;
    if (len % 2) return -1;
    for (i = 0; i < len && n < max; i += 2) {
      char h[3] = { s[i], s[i + 1], 0 };
      if (!isxdigit((unsigned char)s[i]) || !isxdigit((unsigned char)s[i + 1])) return -1;
      out[n++] = (uint8_t)strtoul(h, NULL, 16);
    }
  }
  return n;
}

/* Textual value of a field, for regex `matches`. */
static void field_text(const pcapng_field_t *f, char *out, size_t sz)
{
  if (f->str[0]) { snprintf(out, sz, "%s", f->str); return; }
  if (f->vtype == PCAPNG_FT_UINT) { snprintf(out, sz, "%llu", (unsigned long long)f->u); return; }
  if (f->blen > 0) {
    size_t o = 0; int i;
    for (i = 0; i < f->blen && o + 2 < sz; i++) o += snprintf(out + o, sz - o, "%02x", f->bytes[i]);
    return;
  }
  out[0] = '\0';
}

/* Compare a byte-slice of the field (field[off:len]) against a hex value. */
static int slice_matches(const pcapng_field_t *f, const struct node *n)
{
  const uint8_t *fb = f->bytes;
  int fblen = f->blen, off = n->slice_off, len, wn, c, i;
  uint8_t want[64];
  if (fblen <= 0) return 0;                 /* only byte-valued fields sliceable */
  len = n->slice_len < 0 ? fblen - off : n->slice_len;
  if (off < 0 || len < 0 || off + len > fblen) return 0;
  wn = parse_hexbytes(n->value, want, (int)sizeof want);
  if (wn < 0) return 0;
  if (n->op == OP_CONTAINS) {
    for (i = 0; i + wn <= len; i++)
      if (memcmp(fb + off + i, want, wn) == 0) return 1;
    return 0;
  }
  if (n->op == OP_EQ || n->op == OP_NE) {
    int eq = (len == wn) && memcmp(fb + off, want, wn) == 0;
    return n->op == OP_EQ ? eq : !eq;
  }
  c = memcmp(fb + off, want, len < wn ? len : wn);
  if (c == 0) c = len - wn;
  return cmp_op(n->op, c);
}

static int regex_matches(const pcapng_field_t *f, const char *pat)
{
  char txt[512];
  regex_t re;
  int m;
  field_text(f, txt, sizeof txt);
  if (regcomp(&re, pat, REG_EXTENDED | REG_NOSUB) != 0) return 0;
  m = regexec(&re, txt, 0, NULL, 0) == 0;
  regfree(&re);
  return m;
}

static int field_matches(const pcapng_field_t *f, const struct node *n)
{
  op_t op = n->op;
  const char *val = n->value;
  if (n->has_slice) return slice_matches(f, n);
  if (op == OP_MATCHES) return regex_matches(f, val);
  switch (f->vtype) {
  case PCAPNG_FT_UINT: {
    uint64_t rhs = to_num(val);
    long long c = (f->u > rhs) - (f->u < rhs);
    if (op == OP_CONTAINS || op == OP_MATCHES) return 0;
    return cmp_op(op, c);
  }
  case PCAPNG_FT_IPV4: {
    uint8_t ip[4]; int cidr = 32;
    if (parse_ipv4(val, ip, &cidr) != 0) return 0;
    if (op == OP_EQ || op == OP_NE) {
      uint32_t a = ((uint32_t)f->bytes[0]<<24)|((uint32_t)f->bytes[1]<<16)|((uint32_t)f->bytes[2]<<8)|f->bytes[3];
      uint32_t b = ((uint32_t)ip[0]<<24)|((uint32_t)ip[1]<<16)|((uint32_t)ip[2]<<8)|ip[3];
      uint32_t mask = cidr == 0 ? 0 : (cidr >= 32 ? 0xffffffffu : ~((1u << (32 - cidr)) - 1));
      int eq = (a & mask) == (b & mask);
      return op == OP_EQ ? eq : !eq;
    }
    return cmp_op(op, memcmp(f->bytes, ip, 4));
  }
  case PCAPNG_FT_MAC: {
    uint8_t m[6];
    if (parse_mac(val, m) != 0) return 0;
    return cmp_op(op, memcmp(f->bytes, m, 6));
  }
  case PCAPNG_FT_STR:
  case PCAPNG_FT_IPV6: {
    if (op == OP_CONTAINS || op == OP_MATCHES) return strstr(f->str, val) != NULL;
    return cmp_op(op, strcmp(f->str, val));
  }
  case PCAPNG_FT_BYTES:
  default:
    return 0;
  }
}

static int eval(const node_t *n, pcapng_field_t *root)
{
  if (!n) return 1;
  switch (n->type) {
  case N_AND: return eval(n->a, root) && eval(n->b, root);
  case N_OR:  return eval(n->a, root) || eval(n->b, root);
  case N_NOT: return !eval(n->a, root);
  case N_EXISTS: {
    pcapng_field_t *hits[64];
    const char *al[4];
    int na = aliases(n->field, al), i, total = 0;
    for (i = 0; i < na; i++) total += pcapng_field_collect(root, al[i], hits, 64);
    return total > 0;
  }
  case N_CMP: {
    pcapng_field_t *hits[64];
    const char *al[4];
    int na = aliases(n->field, al), i, j, nh;
    for (i = 0; i < na; i++) {
      nh = pcapng_field_collect(root, al[i], hits, 64);
      for (j = 0; j < nh; j++)
        if (field_matches(hits[j], n)) return 1;   /* "any" semantics */
    }
    return 0;
  }
  }
  return 0;
}

int pcapng_dfilter_match(const pcapng_dfilter_t *f, pcapng_field_t *root)
{
  if (!f) return 1;
  if (f->match_all) return 1;
  return eval(f->root, root);
}

int pcapng_dfilter_is_match_all(const pcapng_dfilter_t *f)
{
  return !f || f->match_all;
}

void pcapng_dfilter_free(pcapng_dfilter_t *f)
{
  if (!f) return;
  node_free(f->root);
  free(f);
}
