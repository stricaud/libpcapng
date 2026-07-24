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
} node_t;

struct pcapng_dfilter { node_t *root; int match_all; };

/* ── lexer ──────────────────────────────────────────────────────────────── */
typedef enum { T_WORD, T_STR, T_LP, T_RP, T_AND, T_OR, T_NOT,
               T_EQ, T_NE, T_GT, T_LT, T_GE, T_LE, T_EOF } ttype_t;
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

static node_t *parse_primary(lex_t *L)
{
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
  {
    node_t *n = mknode(N_EXISTS);
    int op;
    snprintf(n->field, sizeof n->field, "%s", L->cur.s);
    lex_next(L);

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
      n->type = N_CMP;
      n->op = (op_t)op;
      lex_next(L);
      if (L->cur.t != T_WORD && L->cur.t != T_STR) {
        snprintf(L->err, sizeof L->err, "expected a value after operator");
        free(n);
        return NULL;
      }
      snprintf(n->value, sizeof n->value, "%s", L->cur.s);
      lex_next(L);
    }
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

static int field_matches(const pcapng_field_t *f, op_t op, const char *val)
{
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
        if (field_matches(hits[j], n->op, n->value)) return 1;   /* "any" semantics */
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
