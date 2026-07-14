/* posa.c — declarative packet decoders (.posa), part of libpcapng core.
 *
 * Parses .posa definitions and interprets them into a pcapng_field_t subtree,
 * so user-defined decoders are interchangeable with the built-in dissectors.
 * This file implements the base grammar; the extended constructs (layer, scope,
 * when, string-until, info, rule) build on the same structures.
 */
#include <libpcapng/posa.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#ifdef _WIN32
/* MinGW gets the real <dirent.h> through this; MSVC gets a minimal shim. */
#  include <libpcapng/win_compat.h>
#else
#  include <dirent.h>
#endif

/* ── registry ────────────────────────────────────────────────────────────── */
#define MAX_PROTOS 512
/* Allocated on demand: a proto carries its fields inline (each with its enum
   table), so a static array of them would cost hundreds of MB of BSS for a
   registry that usually holds a handful of decoders. */
static pcapng_posa_proto_t *g_protos[MAX_PROTOS];
/* The .posa text each protocol came from, kept verbatim so a front end can show
   and re-edit what the author actually wrote — pcapng_posa_to_text() can only
   reconstruct a normalized subset, and would silently drop comments, rules and
   the extended constructs. */
static char               *g_src[MAX_PROTOS];
static int                 g_nprotos;

static void src_set(int idx, const char *text)
{
  if (idx < 0 || idx >= MAX_PROTOS) return;
  free(g_src[idx]);
  g_src[idx] = NULL;
  if (text) {
    size_t n = strlen(text) + 1;
    g_src[idx] = malloc(n);
    if (g_src[idx]) memcpy(g_src[idx], text, n);
  }
}

const char *pcapng_posa_source(const char *name)
{
  int i;
  if (!name) return NULL;
  for (i = 0; i < g_nprotos; i++)
    if (g_protos[i] && !strcmp(g_protos[i]->name, name)) return g_src[i];
  return NULL;
}

#define MAX_BINDS 256
typedef struct { int ipproto; uint16_t port; char proto[PCAPNG_POSA_NAME_MAX]; int used; } bind_t;
static bind_t g_binds[MAX_BINDS];
static int    g_nbinds;

/* Binds below the transport layer, so a posa decoder can own an IP protocol
   (IGMP is protocol 2 — it has no port) or an ethertype. Same idea as the port
   table above, keyed differently. */
#define MAX_L3_BINDS 64
typedef struct { int key; char proto[PCAPNG_POSA_NAME_MAX]; int used; } l3bind_t;
static l3bind_t g_ipbinds[MAX_L3_BINDS];  static int g_nipbinds;
static l3bind_t g_ethbinds[MAX_L3_BINDS]; static int g_nethbinds;

/* Coloring declared by a `color <display filter> => <fg> <bg>` line. The colors
   are kept as opaque names: libpcapng has no notion of a display, it just
   carries what the .posa declared so the front end can apply it. */
#define MAX_COLORS 128
typedef struct {
  char expr[PCAPNG_POSA_COLOR_EXPR_MAX];
  char fg[PCAPNG_POSA_COLOR_NAME_MAX];
  char bg[PCAPNG_POSA_COLOR_NAME_MAX];
} posa_color_t;
static posa_color_t g_colors[MAX_COLORS];
static int          g_ncolors;

int pcapng_posa_count(void) { return g_nprotos; }
const pcapng_posa_proto_t *pcapng_posa_at(int i)
{ return (i >= 0 && i < g_nprotos) ? g_protos[i] : NULL; }
const pcapng_posa_proto_t *pcapng_posa_find(const char *name)
{
  int i;
  if (!name) return NULL;
  for (i = 0; i < g_nprotos; i++)
    if (g_protos[i] && !strcmp(g_protos[i]->name, name)) return g_protos[i];
  return NULL;
}
void pcapng_posa_clear(void)
{
  int i;
  for (i = 0; i < g_nprotos; i++) {
    free(g_src[i]);    g_src[i] = NULL;
    free(g_protos[i]); g_protos[i] = NULL;
  }
  g_nprotos = 0; g_nbinds = 0; g_ncolors = 0; g_nipbinds = 0; g_nethbinds = 0;
}

int pcapng_posa_color_count(void) { return g_ncolors; }

int pcapng_posa_color_get(int i, const char **expr, const char **fg, const char **bg)
{
  if (i < 0 || i >= g_ncolors) return -1;
  if (expr) *expr = g_colors[i].expr;
  if (fg)   *fg   = g_colors[i].fg;
  if (bg)   *bg   = g_colors[i].bg;
  return 0;
}

/* `color <display filter> => <fg> <bg>`
   The filter may contain spaces and '=' (e.g. "tcp.flags.reset == 1"), so split
   on the LAST "=>" and take exactly two names after it. */
static void parse_color(const char *rest)
{
  const char *arrow = NULL, *p;
  char fg[PCAPNG_POSA_COLOR_NAME_MAX] = "", bg[PCAPNG_POSA_COLOR_NAME_MAX] = "";
  size_t elen;

  for (p = rest; (p = strstr(p, "=>")) != NULL; p += 2) arrow = p;
  if (!arrow || g_ncolors >= MAX_COLORS) return;
  if (sscanf(arrow + 2, " %23s %23s", fg, bg) != 2) return;

  elen = (size_t)(arrow - rest);
  while (elen > 0 && (rest[elen - 1] == ' ' || rest[elen - 1] == '\t')) elen--;
  if (elen == 0 || elen >= PCAPNG_POSA_COLOR_EXPR_MAX) return;

  memcpy(g_colors[g_ncolors].expr, rest, elen);
  g_colors[g_ncolors].expr[elen] = '\0';
  snprintf(g_colors[g_ncolors].fg, sizeof g_colors[g_ncolors].fg, "%s", fg);
  snprintf(g_colors[g_ncolors].bg, sizeof g_colors[g_ncolors].bg, "%s", bg);
  g_ncolors++;
}

static const char *l3_lookup(const l3bind_t *t, int n, int key)
{
  int i;
  for (i = 0; i < n; i++) if (t[i].used && t[i].key == key) return t[i].proto;
  return NULL;
}
static void l3_add(l3bind_t *t, int *n, int key, const char *proto)
{
  int i;
  for (i = 0; i < *n; i++)
    if (t[i].used && t[i].key == key) { snprintf(t[i].proto, sizeof t[i].proto, "%s", proto); return; }
  if (*n < MAX_L3_BINDS) {
    t[*n].used = 1; t[*n].key = key;
    snprintf(t[*n].proto, sizeof t[*n].proto, "%s", proto);
    (*n)++;
  }
}
const char *pcapng_posa_bound_ipproto(int num)
{ return l3_lookup(g_ipbinds, g_nipbinds, num); }
const char *pcapng_posa_bound_ethertype(uint16_t type)
{ return l3_lookup(g_ethbinds, g_nethbinds, (int)type); }

const char *pcapng_posa_bound_port(int ipproto, uint16_t port)
{
  int i;
  for (i = 0; i < g_nbinds; i++)
    if (g_binds[i].used && g_binds[i].ipproto == ipproto && g_binds[i].port == port)
      return g_binds[i].proto;
  return NULL;
}
static void bind_add(int ipproto, uint16_t port, const char *proto)
{
  int i;
  for (i = 0; i < g_nbinds; i++)
    if (g_binds[i].used && g_binds[i].ipproto == ipproto && g_binds[i].port == port) {
      snprintf(g_binds[i].proto, sizeof g_binds[i].proto, "%s", proto); return; }
  if (g_nbinds < MAX_BINDS) {
    g_binds[g_nbinds].used = 1; g_binds[g_nbinds].ipproto = ipproto; g_binds[g_nbinds].port = port;
    snprintf(g_binds[g_nbinds].proto, sizeof g_binds[g_nbinds].proto, "%s", proto);
    g_nbinds++;
  }
}

/* ── pcapng_field_t builders (subtree construction) ──────────────────────── */
static pcapng_field_t *pf_add(pcapng_field_t *parent, const char *abbrev, pcapng_ftype_t vt)
{
  pcapng_field_t *f = calloc(1, sizeof *f);
  if (!f) return NULL;
  snprintf(f->abbrev, sizeof f->abbrev, "%s", abbrev ? abbrev : "");
  f->vtype = vt; f->parent = parent;
  if (parent) {
    if (parent->last_child) parent->last_child->next = f; else parent->children = f;
    parent->last_child = f;
  }
  return f;
}
static void pf_label(pcapng_field_t *f, const char *fmt, ...)
{ va_list ap; if (!f) return; va_start(ap, fmt); vsnprintf(f->label, sizeof f->label, fmt, ap); va_end(ap); }
static void pf_uint(pcapng_field_t *f, uint64_t v) { if (f) { f->vtype = PCAPNG_FT_UINT; f->u = v; } }
static void pf_str(pcapng_field_t *f, const char *s)
{ if (f) { f->vtype = PCAPNG_FT_STR; snprintf(f->str, sizeof f->str, "%s", s ? s : ""); } }
static void pf_ipv4(pcapng_field_t *f, const uint8_t ip[4])
{ if (!f) return; f->vtype = PCAPNG_FT_IPV4; memcpy(f->bytes, ip, 4); f->blen = 4;
  snprintf(f->str, sizeof f->str, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]); }
static void pf_ipv6(pcapng_field_t *f, const uint8_t ip[16])
{
  static const char hx[] = "0123456789abcdef";
  char *p; int i;
  if (!f) return;
  f->vtype = PCAPNG_FT_IPV6; memcpy(f->bytes, ip, 16); f->blen = 16;
  for (p = f->str, i = 0; i < 16; i += 2) {
    if (i) *p++ = ':';
    *p++ = hx[(ip[i] >> 4) & 0xf];     *p++ = hx[ip[i] & 0xf];
    *p++ = hx[(ip[i+1] >> 4) & 0xf];   *p++ = hx[ip[i+1] & 0xf];
  }
  *p = '\0';
}
static void pf_mac(pcapng_field_t *f, const uint8_t m[6])
{ if (!f) return; f->vtype = PCAPNG_FT_MAC; memcpy(f->bytes, m, 6); f->blen = 6;
  snprintf(f->str, sizeof f->str, "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); }
static void pf_bytes(pcapng_field_t *f, const uint8_t *b, int n)
{ int k; if (!f) return; f->vtype = PCAPNG_FT_BYTES; k = n < PCAPNG_FIELD_BYTES_MAX ? n : PCAPNG_FIELD_BYTES_MAX;
  if (k > 0) memcpy(f->bytes, b, (size_t)k); f->blen = k; }
static void pf_range(pcapng_field_t *f, int off, int len) { if (f) { f->off = off; f->len = len; } }

/* ── parsing helpers ─────────────────────────────────────────────────────── */
static uint64_t parse_num(const char *s)
{
  if (!s) return 0;
  while (*s == ' ' || *s == '\t') s++;
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) return (uint64_t)strtoull(s, NULL, 16);
  return (uint64_t)strtoull(s, NULL, 10);
}

static int parse_type(const char *tok, pcapng_posa_fld_t *f)
{
  if      (!strcmp(tok, "uint8"))      f->type = PCAPNG_POSA_U8;
  else if (!strcmp(tok, "uint16"))     f->type = PCAPNG_POSA_U16;
  else if (!strcmp(tok, "uint24"))     f->type = PCAPNG_POSA_U24;
  else if (!strcmp(tok, "uint32"))     f->type = PCAPNG_POSA_U32;
  else if (!strcmp(tok, "uint64"))     f->type = PCAPNG_POSA_U64;
  else if (!strcmp(tok, "le_uint16"))  f->type = PCAPNG_POSA_LE16;
  else if (!strcmp(tok, "le_uint32"))  f->type = PCAPNG_POSA_LE32;
  else if (!strcmp(tok, "le_uint64"))  f->type = PCAPNG_POSA_LE64;
  else if (!strcmp(tok, "mac"))        f->type = PCAPNG_POSA_MAC;
  else if (!strcmp(tok, "ip4"))        f->type = PCAPNG_POSA_IP4;
  else if (!strcmp(tok, "ip6"))        f->type = PCAPNG_POSA_IP6;
  else if (!strcmp(tok, "cstring"))    f->type = PCAPNG_POSA_CSTRING;
  else if (!strcmp(tok, "string"))     f->type = PCAPNG_POSA_CSTRING; /* until handled by caller */
  else if (!strcmp(tok, "payload"))    f->type = PCAPNG_POSA_PAYLOAD;
  else if (!strcmp(tok, "dnsname"))    f->type = PCAPNG_POSA_DNSNAME;
  else if (!strncmp(tok, "bytes<", 6)) { f->type = PCAPNG_POSA_BYTES_FIXED; f->nbytes = (size_t)parse_num(tok + 6); }
  else if (!strncmp(tok, "bytes[", 6)) {
    const char *e = strchr(tok + 6, ']');
    f->type = PCAPNG_POSA_BYTES_REF;
    snprintf(f->lenfield, sizeof f->lenfield, "%.*s", e ? (int)(e - (tok + 6)) : 0, tok + 6);
  } else if (!strncmp(tok, "str[", 4)) {
    const char *e = strchr(tok + 4, ']');
    f->type = PCAPNG_POSA_STR_REF;
    snprintf(f->lenfield, sizeof f->lenfield, "%.*s", e ? (int)(e - (tok + 4)) : 0, tok + 4);
  } else if (!strncmp(tok, "utf16[", 6)) {
    const char *e = strchr(tok + 6, ']');
    f->type = PCAPNG_POSA_UTF16;
    snprintf(f->lenfield, sizeof f->lenfield, "%.*s", e ? (int)(e - (tok + 6)) : 0, tok + 6);
  } else return -1;
  return 0;
}
static int is_type_tok(const char *t) { pcapng_posa_fld_t tmp; return parse_type(t, &tmp) == 0; }

/* Words that start a statement — anything else at the head of an indented line
   under a field is an enum name (which may contain spaces). */
static int is_kw(const char *t)
{
  static const char *kw[] = { "required","optional","when","scope","repeat","label","bits",
                              "layer","include","seek","info","col","abbrev","rule","color",
                              "protocol","Object","end", NULL };
  int i;
  if (!strncmp(t, "Object<", 7)) return 1;
  for (i = 0; kw[i]; i++) if (!strcmp(t, kw[i])) return 1;
  return is_type_tok(t);
}

static int tokenize(char *line, char *toks[], int max)
{
  int n = 0; char *p = line;
  while (*p && n < max) {
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) break;
    toks[n++] = p;
    while (*p && *p != ' ' && *p != '\t') p++;
    if (*p) *p++ = '\0';
  }
  return n;
}

/* Parse a `rule <what> == N => Proto` binding. Forms:
     tcp.port == 3389     udp.dstport == 69      (transport ports)
     ip.proto == 2        eth.type == 0x88cc     (below the transport layer) */
static void parse_rule(const char *rest)
{
  char t[16] = "", field[24] = "", num[24] = "";
  const char *arrow;
  char proto[PCAPNG_POSA_NAME_MAX] = "";
  if (sscanf(rest, "%15[a-z].%23[a-z] == %23s", t, field, num) != 3) return;
  arrow = strstr(rest, "=>");
  if (!arrow || sscanf(arrow + 2, " %63s", proto) != 1) return;
  { unsigned long v = (unsigned long)parse_num(num);   /* 0x… or decimal */
    if      (!strcmp(t, "tcp")) bind_add(6,  (uint16_t)v, proto);
    else if (!strcmp(t, "udp")) bind_add(17, (uint16_t)v, proto);
    else if (!strcmp(t, "ip")  && !strcmp(field, "proto")) l3_add(g_ipbinds, &g_nipbinds, (int)v, proto);
    else if (!strcmp(t, "eth") && !strcmp(field, "type"))  l3_add(g_ethbinds, &g_nethbinds, (int)v, proto);
  }
}

/* ── source parsing ──────────────────────────────────────────────────────── */
static pcapng_posa_fld_t *add_fld(pcapng_posa_proto_t *cur, pcapng_posa_ftype_t t)
{
  pcapng_posa_fld_t *f;
  if (cur->nflds >= PCAPNG_POSA_MAX_FLDS) return NULL;
  f = &cur->flds[cur->nflds++];
  memset(f, 0, sizeof *f);
  f->type = t; f->scope_len_field = -1;
  return f;
}

/* Unescape a quoted delimiter ("\r\n" etc.) into raw bytes. */
static void parse_delim(const char *tok, char *out, int *nout)
{
  int n = 0; const char *p = tok;
  if (*p == '"') p++;
  while (*p && *p != '"' && n < PCAPNG_POSA_DELIM_MAX) {
    if (*p == '\\' && p[1]) {
      p++;
      switch (*p) { case 'r': out[n++]='\r'; break; case 'n': out[n++]='\n'; break;
                    case 't': out[n++]='\t'; break; case '0': out[n++]='\0'; break;
                    default:  out[n++]=*p; }
      p++;
    } else out[n++] = *p++;
  }
  *nout = n;
}

/* Copy the first "..." of a line into out. Returns 1 if there was one. */
static int quoted(const char *s, char *out, size_t sz)
{
  const char *q1 = strchr(s, '"'), *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
  if (!q1 || !q2) return 0;
  snprintf(out, sz, "%.*s", (int)(q2 - q1 - 1), q1 + 1);
  return 1;
}

/* Comma-separated field names following a quoted string: `label "%s" a, b`. */
static int args_after_quote(const char *s, char args[][PCAPNG_POSA_NAME_MAX], int maxa)
{
  const char *q1 = strchr(s, '"'), *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
  const char *a; int na = 0;
  if (!q2) return 0;
  for (a = q2 + 1; *a && na < maxa; ) {
    const char *comma; int L;
    while (*a == ' ' || *a == '\t' || *a == ',') a++;
    if (!*a) break;
    comma = strchr(a, ',');
    L = comma ? (int)(comma - a) : (int)strlen(a);
    while (L > 0 && (a[L - 1] == ' ' || a[L - 1] == '\t')) L--;
    snprintf(args[na++], PCAPNG_POSA_NAME_MAX, "%.*s", L, a);
    if (!comma) break;
    a = comma + 1;
  }
  return na;
}

static void guard_from_toks(char **toks, int start, int nt, pcapng_posa_guard_t *g)
{
  int i = start;
  memset(g, 0, sizeof *g);
  if (i >= nt) return;
  snprintf(g->lhs, sizeof g->lhs, "%s", toks[i]); i++;
  if (i < nt && !strcmp(toks[i], "&")) { i++; if (i < nt) { g->mask = parse_num(toks[i]); i++; } }
  if (i < nt) {
    const char *op = toks[i]; i++;
    if      (!strcmp(op, "==")) g->op = PCAPNG_POSA_CMP_EQ;
    else if (!strcmp(op, "!=")) g->op = PCAPNG_POSA_CMP_NE;
    else if (!strcmp(op, "<"))  g->op = PCAPNG_POSA_CMP_LT;
    else if (!strcmp(op, ">"))  g->op = PCAPNG_POSA_CMP_GT;
    else if (!strcmp(op, ">=")) g->op = PCAPNG_POSA_CMP_GE;
    else if (!strcmp(op, "<=")) g->op = PCAPNG_POSA_CMP_LE;
    else { g->op = PCAPNG_POSA_CMP_NE; g->rhs = 0; return; }
    if (i < nt) g->rhs = parse_num(toks[i]);
  } else { g->op = PCAPNG_POSA_CMP_NE; g->rhs = 0; }   /* bare "when field:" → truthy */
}

static int parse_src(const char *src, char *errbuf, size_t errlen)
{
  const char *line = src;
  pcapng_posa_proto_t *cur = NULL;
  pcapng_posa_fld_t *lastfld = NULL;
  int added = 0, lineno = 0;
  int blk_indent[32], nblk = 0;               /* open scope/when block indents */

  while (*line) {
    char buf[1024], raw[1024], *toks[32], *hash, *tl;
    const char *eol = strchr(line, '\n');
    size_t llen = eol ? (size_t)(eol - line) : strlen(line);
    int nt, indent, ti, structural;

    lineno++;
    if (llen >= sizeof buf) llen = sizeof buf - 1;
    memcpy(buf, line, llen); buf[llen] = '\0';
    line = eol ? eol + 1 : line + strlen(line);
    hash = strchr(buf, '#'); if (hash) *hash = '\0';

    indent = 0; while (buf[indent] == ' ' || buf[indent] == '\t') indent++;
    tl = buf + indent;
    if (!*tl) continue;
    snprintf(raw, sizeof raw, "%s", tl);   /* tokenize() chops buf in place */

    /* rule <condition> => Proto  (parsed from raw text, before tokenizing) */
    if (!strncmp(tl, "rule", 4) && (tl[4] == ' ' || tl[4] == '\t')) {
      char *r = tl + 4; while (*r == ' ' || *r == '\t') r++;
      parse_rule(r);
      continue;
    }

    /* color <display filter> => <fg> <bg>  — how the front end should paint a
       matching packet. File-scoped like `rule`, not tied to the current proto. */
    if (!strncmp(tl, "color", 5) && (tl[5] == ' ' || tl[5] == '\t')) {
      char *r = tl + 5; while (*r == ' ' || *r == '\t') r++;
      parse_color(r);
      continue;
    }

    /* col "<Name>"  — the Protocol-column display name */
    if (cur && !strncmp(tl, "col", 3) && (tl[3] == ' ' || tl[3] == '"' || tl[3] == '\t')) {
      char *q1 = strchr(tl, '"'), *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
      if (q1 && q2) snprintf(cur->display, sizeof cur->display, "%.*s", (int)(q2 - q1 - 1), q1 + 1);
      continue;
    }

    /* abbrev "<prefix>"  — field/layer abbrev prefix (for display filters) */
    if (cur && !strncmp(tl, "abbrev", 6) && (tl[6] == ' ' || tl[6] == '"' || tl[6] == '\t')) {
      char *q1 = strchr(tl, '"'), *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
      if (q1 && q2) snprintf(cur->abbrev, sizeof cur->abbrev, "%.*s", (int)(q2 - q1 - 1), q1 + 1);
      continue;
    }

    /* info "<fmt>" arg, arg  (parsed from raw text — the fmt has spaces) */
    if (cur && !strncmp(tl, "info", 4) && (tl[4] == ' ' || tl[4] == '"' || tl[4] == '\t')) {
      if (quoted(tl, cur->info_fmt, sizeof cur->info_fmt))
        cur->info_nargs = args_after_quote(tl, cur->info_args, 8);
      continue;
    }

    nt = tokenize(buf, toks, 32);
    if (nt == 0) continue;

    if (!strncmp(toks[0], "Object<", 7) || !strcmp(toks[0], "protocol") || !strcmp(toks[0], "Object")) {
      char parent[PCAPNG_POSA_NAME_MAX] = "main";
      const char *name = NULL;
      /* close whatever blocks the previous object left open — an object whose
         last line is inside a scope/when/repeat must still end balanced, or
         `include` would splice its dangling blocks into its host */
      while (cur && nblk > 0) { add_fld(cur, PCAPNG_POSA_END); nblk--; }
      nblk = 0; lastfld = NULL;
      if (!strcmp(toks[0], "protocol")) { name = nt > 1 ? toks[1] : NULL; parent[0] = '\0'; }
      else {
        char *gt = strchr(toks[0], '>'); const char *pp = toks[0] + 7;
        if (gt) snprintf(parent, sizeof parent, "%.*s", (int)(gt - pp), pp);
        if (!strcmp(parent, "main")) parent[0] = '\0';
        name = nt > 1 ? toks[1] : NULL;
      }
      if (!name) { if (errbuf) snprintf(errbuf, errlen, "line %d: missing protocol name", lineno); return -1; }
      { int idx = -1, k;
        for (k = 0; k < g_nprotos; k++)                     /* redefinition replaces */
          if (g_protos[k] && !strcmp(g_protos[k]->name, name)) { idx = k; break; }
        if (idx < 0) {
          if (g_nprotos >= MAX_PROTOS) { if (errbuf) snprintf(errbuf, errlen, "too many protocols"); return -1; }
          idx = g_nprotos++;
          g_protos[idx] = calloc(1, sizeof *g_protos[idx]);
          if (!g_protos[idx]) { g_nprotos--; if (errbuf) snprintf(errbuf, errlen, "out of memory"); return -1; }
        }
        cur = g_protos[idx];
        memset(cur, 0, sizeof *cur);
        snprintf(cur->name, sizeof cur->name, "%s", name);
        snprintf(cur->parent, sizeof cur->parent, "%s", parent);
        { int k; for (k = 2; k < nt; k++) if (!strcmp(toks[k], "default")) cur->is_default = 1; }
        /* keep the whole file, not just this Object's lines: the `rule` and
           `color` lines that belong with it live at file scope */
        src_set(idx, src); }
      added++;
      continue;
    }
    if (!strcmp(toks[0], "end")) { cur = NULL; nblk = 0; lastfld = NULL; continue; }
    if (!cur) continue;

    /* enum line: NAME = value (attaches to the most recent value field). The
       name is display text and may contain spaces — "Membership Query = 0x11" —
       so it is taken from the raw line rather than from a single token. */
    if (lastfld && !is_kw(toks[0]) && strchr(raw, '=')) {
      const char *eq = strchr(raw, '=');
      int L = (int)(eq - raw);
      while (L > 0 && (raw[L - 1] == ' ' || raw[L - 1] == '\t')) L--;
      if (L > 0 && lastfld->nenums < PCAPNG_POSA_MAX_ENUMS) {
        pcapng_posa_enum_t *e = &lastfld->enums[lastfld->nenums++];
        snprintf(e->name, sizeof e->name, "%.*s", L, raw);
        e->val = parse_num(eq + 1);
      }
      continue;
    }

    /* everything below is a structural line — close deeper blocks first */
    structural = 1;
    if (structural) while (nblk > 0 && blk_indent[nblk - 1] >= indent) { add_fld(cur, PCAPNG_POSA_END); nblk--; }

    if (!strcmp(toks[0], "scope") && nt >= 2) {                 /* scope <field> */
      pcapng_posa_fld_t *f = add_fld(cur, PCAPNG_POSA_SCOPE);
      if (f) snprintf(f->lenfield, sizeof f->lenfield, "%s", toks[1]);
      if (nblk < 32) blk_indent[nblk++] = indent;
      lastfld = NULL;
      continue;
    }
    if (!strcmp(toks[0], "when") && nt >= 2) {                  /* when <cond>: */
      pcapng_posa_fld_t *f = add_fld(cur, PCAPNG_POSA_WHEN);
      char *last = toks[nt - 1]; int L = (int)strlen(last);     /* strip trailing ':' */
      if (L > 0 && last[L - 1] == ':') last[L - 1] = '\0';
      if (f) guard_from_toks(toks, 1, nt, &f->guard);
      if (nblk < 32) blk_indent[nblk++] = indent;
      lastfld = NULL;
      continue;
    }
    if (!strcmp(toks[0], "layer") && nt >= 3) {                 /* layer <name> <Proto> */
      pcapng_posa_fld_t *f = add_fld(cur, PCAPNG_POSA_LAYER);
      if (f) { snprintf(f->name, sizeof f->name, "%s", toks[1]);
               snprintf(f->sub, sizeof f->sub, "%s", toks[2]); }
      lastfld = NULL;
      continue;
    }
    /* include <Object> — inline an already-defined object's fields here. Unlike
       `layer`, this does not open a sub-protocol: the fields land in the current
       scope, so a `label` can name them and a `when` can test them. That is what
       lets the four DNS record sections share one RR definition. */
    if (!strcmp(toks[0], "include") && nt >= 2) {
      const pcapng_posa_proto_t *tpl = pcapng_posa_find(toks[1]);
      if (!tpl) {
        if (errbuf) snprintf(errbuf, errlen, "line %d: include: no such object '%s'", lineno, toks[1]);
        return -1;
      }
      { int k;
        for (k = 0; k < tpl->nflds && cur->nflds < PCAPNG_POSA_MAX_FLDS; k++)
          cur->flds[cur->nflds++] = tpl->flds[k]; }
      lastfld = NULL;
      continue;
    }
    /* else:  — the arm taken when the `when` above it, at the same indent, was not */
    if (!strcmp(toks[0], "else") || !strcmp(toks[0], "else:")) {
      add_fld(cur, PCAPNG_POSA_ELSE);
      if (nblk < 32) blk_indent[nblk++] = indent;
      lastfld = NULL;
      continue;
    }
    /* repeat <countfield> as <item> ["Section"]
       repeat until end as <item>          — until the enclosing scope runs out
       repeat until "<delim>" as <item>    — until those bytes come next, which is
                                             how an HTTP header block ends       */
    if (!strcmp(toks[0], "repeat") && nt >= 2) {
      pcapng_posa_fld_t *f = add_fld(cur, PCAPNG_POSA_REPEAT);
      if (f) {
        int ai;
        if (!strcmp(toks[1], "until")) {
          f->until_end = 1;
          if (nt > 2 && toks[2][0] == '"') { parse_delim(toks[2], f->delim, &f->ndelim); ai = 3; }
          else                             { ai = (nt > 2 && !strcmp(toks[2], "end")) ? 3 : 2; }
        } else {
          snprintf(f->lenfield, sizeof f->lenfield, "%s", toks[1]);
          ai = 2;
        }
        if (ai + 1 < nt && !strcmp(toks[ai], "as"))
          snprintf(f->name, sizeof f->name, "%s", toks[ai + 1]);
        if (!f->name[0]) snprintf(f->name, sizeof f->name, "item");
        /* the section title is the quoted string — but with `until "<delim>"` the
           first quoted string on the line is the delimiter, so skip past it */
        { const char *q = raw;
          if (f->ndelim > 0) {
            const char *q1 = strchr(raw, '"');
            const char *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
            q = q2 ? q2 + 1 : raw + strlen(raw);
          }
          quoted(q, f->disp, sizeof f->disp); }
      }
      if (nblk < 32) blk_indent[nblk++] = indent;
      lastfld = NULL;
      continue;
    }
    /* seek <offsetfield> — continue decoding at the offset that field holds,
       counted from the start of this object. SMB2 needs it: its variable blobs
       are placed by offset-from-header rather than laid out in field order. */
    if (!strcmp(toks[0], "seek") && nt >= 2) {
      pcapng_posa_fld_t *f = add_fld(cur, PCAPNG_POSA_SEEK);
      if (f) {
        if (toks[1][0] >= '0' && toks[1][0] <= '9') {   /* seek 0 — a literal offset */
          f->defnum = parse_num(toks[1]); f->until_end = 1;
        } else snprintf(f->lenfield, sizeof f->lenfield, "%s", toks[1]);
      }
      lastfld = NULL;
      continue;
    }
    /* bits <srcfield> <name> <shift> <width> ["Label"]   — enums may follow */
    if (!strcmp(toks[0], "bits") && nt >= 5) {
      pcapng_posa_fld_t *f = add_fld(cur, PCAPNG_POSA_BITS);
      if (f) {
        snprintf(f->src,  sizeof f->src,  "%s", toks[1]);
        snprintf(f->name, sizeof f->name, "%s", toks[2]);
        f->shift = (int)parse_num(toks[3]);
        f->width = (int)parse_num(toks[4]);
        if (f->width <= 0 || f->width > 64) f->width = 1;
        quoted(raw, f->disp, sizeof f->disp);
      }
      lastfld = f;
      continue;
    }
    /* label "<fmt>" arg, arg  — titles the subtree of the enclosing repeat item */
    if (!strcmp(toks[0], "label") && strchr(raw, '"')) {
      pcapng_posa_fld_t *f = add_fld(cur, PCAPNG_POSA_LABEL);
      if (f) {
        quoted(raw, f->disp, sizeof f->disp);
        f->nlargs = args_after_quote(raw, f->largs, PCAPNG_POSA_MAX_LARGS);
      }
      lastfld = NULL;
      continue;
    }

    /* field line:
       [required|optional] <type> <name> [until "delim"] [mask N] [= default] ["Label"] */
    ti = 0;
    if (!strcmp(toks[0], "required") || !strcmp(toks[0], "optional")) ti = 1;
    if (ti < nt && (is_type_tok(toks[ti]) || !strcmp(toks[ti], "string"))) {
      pcapng_posa_fld_t *f = add_fld(cur, PCAPNG_POSA_U8);
      if (!f) continue;
      parse_type(toks[ti], f);
      if (ti + 1 < nt) snprintf(f->name, sizeof f->name, "%s", toks[ti + 1]);
      if (!strcmp(toks[ti], "string") && ti + 3 < nt && !strcmp(toks[ti + 2], "until")) {
        /* the delimiter comes from the raw line, not from a token: HTTP splits on
           " ", and tokenize() would have torn that quoted space in half */
        const char *u = strstr(raw, "until");
        const char *q = u ? strchr(u, '"') : NULL;
        f->type = PCAPNG_POSA_STR_DELIM;
        if (q) parse_delim(q, f->delim, &f->ndelim);
      }
      { int k; for (k = ti + 2; k < nt; k++) if (!strcmp(toks[k], "=") && k + 1 < nt) {
          f->defnum = parse_num(toks[k + 1]); break; } }
      { int k; for (k = ti + 2; k < nt; k++) if (!strcmp(toks[k], "mask") && k + 1 < nt) {
          f->mask = parse_num(toks[k + 1]); break; } }
      { int k; for (k = ti + 1; k < nt; k++) if (!strcmp(toks[k], "hex")) { f->hex = 1; break; } }
      /* the label is the quoted string — but on a `string … until "\r\n"` line the
         first quoted string is the delimiter, so the label is the one after it */
      { const char *q = raw;
        if (f->type == PCAPNG_POSA_STR_DELIM) {
          const char *u = strstr(raw, "until");
          const char *q1 = u ? strchr(u, '"') : NULL;
          const char *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
          q = q2 ? q2 + 1 : raw + strlen(raw);
        }
        quoted(q, f->disp, sizeof f->disp); }
      lastfld = f;
      continue;
    }
  }
  while (cur && nblk > 0) { add_fld(cur, PCAPNG_POSA_END); nblk--; }   /* end of file */
  return added;
}

int pcapng_posa_load_file(const char *path, char *errbuf, size_t errlen)
{
  FILE *fp = fopen(path, "rb");
  long sz; char *src; int rc;
  if (!fp) { if (errbuf) snprintf(errbuf, errlen, "cannot open %s", path); return -1; }
  fseek(fp, 0, SEEK_END); sz = ftell(fp); fseek(fp, 0, SEEK_SET);
  if (sz < 0) { fclose(fp); return -1; }
  src = malloc((size_t)sz + 1);
  if (!src) { fclose(fp); return -1; }
  if (fread(src, 1, (size_t)sz, fp) != (size_t)sz) { free(src); fclose(fp); return -1; }
  src[sz] = '\0'; fclose(fp);
  rc = parse_src(src, errbuf, errlen);
  free(src);
  return rc;
}

int pcapng_posa_load_text(const char *src, char *errbuf, size_t errlen)
{ return src ? parse_src(src, errbuf, errlen) : -1; }

int pcapng_posa_load_dir(const char *dir)
{
  DIR *dp = opendir(dir); struct dirent *de; int total = 0;
  if (!dp) return -1;
  while ((de = readdir(dp))) {
    size_t n = strlen(de->d_name); char path[1200]; int rc;
    if (n < 6 || strcmp(de->d_name + n - 5, ".posa") != 0) continue;
    snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
    rc = pcapng_posa_load_file(path, NULL, 0);
    if (rc > 0) total += rc;
  }
  closedir(dp);
  return total;
}

/* ── interpreter ─────────────────────────────────────────────────────────── */
static const char *enum_name(const pcapng_posa_fld_t *f, uint64_t v)
{ int i; for (i = 0; i < f->nenums; i++) if (f->enums[i].val == v) return f->enums[i].name; return NULL; }

static int fld_fixed_size(const pcapng_posa_fld_t *f)
{
  switch (f->type) {
  case PCAPNG_POSA_U8:  return 1;
  case PCAPNG_POSA_U16: case PCAPNG_POSA_LE16: return 2;
  case PCAPNG_POSA_U24: return 3;
  case PCAPNG_POSA_U32: case PCAPNG_POSA_LE32: return 4;
  case PCAPNG_POSA_U64: case PCAPNG_POSA_LE64: return 8;
  case PCAPNG_POSA_MAC: return 6;
  case PCAPNG_POSA_IP4: return 4;
  case PCAPNG_POSA_IP6: return 16;
  case PCAPNG_POSA_BYTES_FIXED: return (int)f->nbytes;
  default: return -1;   /* variable-length, or consumes nothing (bits/label) */
  }
}
static uint64_t rd_be(const uint8_t *d, int n) { uint64_t v = 0; int i; for (i = 0; i < n; i++) v = (v << 8) | d[i]; return v; }
static uint64_t rd_le(const uint8_t *d, int n) { uint64_t v = 0; int i; for (i = n - 1; i >= 0; i--) v = (v << 8) | d[i]; return v; }

/* A field value parsed so far, for `scope`/`when`/`bits`/`label`/`info` to refer
   to by name. `val` is masked+display-ready, `raw` is what the wire held (bits
   carve their value out of the raw one). */
typedef struct {
  char     name[PCAPNG_POSA_NAME_MAX];
  uint64_t val, raw;
  int      start_off, end_off;
  char     disp[96];
} seen_t;

#define POSA_MAX_SEEN 128

static void seen_add(seen_t *seen, int *nseen, const char *name, uint64_t val, uint64_t raw,
                     int start_off, int end_off, const char *disp)
{
  seen_t *s;
  if (*nseen >= POSA_MAX_SEEN) return;
  s = &seen[(*nseen)++];
  snprintf(s->name, sizeof s->name, "%s", name);
  s->val = val; s->raw = raw; s->start_off = start_off; s->end_off = end_off;
  snprintf(s->disp, sizeof s->disp, "%s", disp ? disp : "");
}
/* Most recent wins: inside a `repeat`, iteration N's fields must shadow the ones
   an earlier iteration left behind. */
static const seen_t *seen_get(const seen_t *seen, int nseen, const char *name)
{ int i; for (i = nseen - 1; i >= 0; i--) if (!strcmp(seen[i].name, name)) return &seen[i]; return NULL; }

static int guard_ok(const pcapng_posa_guard_t *g, const seen_t *seen, int nseen, int off, int lim)
{
  uint64_t lv = 0;
  if (g->op == PCAPNG_POSA_CMP_NONE) return 1;
  if (!strcmp(g->lhs, "remaining"))    lv = (uint64_t)(lim - off);
  else { const seen_t *s = seen_get(seen, nseen, g->lhs); if (s) lv = s->val; }
  if (g->mask) lv &= g->mask;
  switch (g->op) {
  case PCAPNG_POSA_CMP_EQ: return lv == g->rhs;
  case PCAPNG_POSA_CMP_NE: return lv != g->rhs;
  case PCAPNG_POSA_CMP_LT: return lv <  g->rhs;
  case PCAPNG_POSA_CMP_GT: return lv >  g->rhs;
  case PCAPNG_POSA_CMP_GE: return lv >= g->rhs;
  case PCAPNG_POSA_CMP_LE: return lv <= g->rhs;
  default: return 1;
  }
}

/* Expand `"fmt" arg, arg` against the parsed fields. %s = display text, %u/%d =
   number, %x = hex.
   `pref` is consulted before `seen`, and holds the first value each repeated
   field took. A record label wants its own record's values (pref = NULL), but
   the packet's Info line wants the first record's — "Query 0x0 PTR
   _rdlink._tcp.local", not whichever question happened to come last. */
static void fmt_expand(const char *fmt, const char args[][PCAPNG_POSA_NAME_MAX], int nargs,
                       const seen_t *pref, int npref, const seen_t *seen, int nseen,
                       char *out, size_t outlen)
{
  const char *f = fmt; size_t o = 0; int ai = 0;
  if (!out || !outlen) return;
  while (*f && o < outlen - 1) {
    if (*f == '%' && f[1]) {
      char c = f[1];
      const seen_t *s = NULL;
      if (ai < nargs) {
        s = seen_get(pref, npref, args[ai]);
        if (!s) s = seen_get(seen, nseen, args[ai]);
      }
      ai++; f += 2;
      if (c == 's')            o += (size_t)snprintf(out + o, outlen - o, "%s", s ? s->disp : "");
      else if (c=='u'||c=='d') o += (size_t)snprintf(out + o, outlen - o, "%llu", s ? (unsigned long long)s->val : 0ULL);
      else if (c == 'x')       o += (size_t)snprintf(out + o, outlen - o, "%llx", s ? (unsigned long long)s->val : 0ULL);
      else if (c == '%')       out[o++] = '%';
    } else out[o++] = *f++;
  }
  out[o] = '\0';
  /* An arg that names a field this packet does not carry (a query has no answer
     records, a response no questions) expands to nothing — close the gap it
     leaves rather than showing "Response 0x0  AAAA". */
  { size_t r = 0, w = 0;
    while (out[r]) {
      if (out[r] == ' ' && (w == 0 || out[w - 1] == ' ')) { r++; continue; }
      out[w++] = out[r++];
    }
    while (w > 0 && out[w - 1] == ' ') w--;
    out[w] = '\0'; }
}

/* A DNS-style name at `off`: dotted text into `out`, return the offset just past
   the encoded name. A 0xc0 compression pointer is followed (bounded), but only
   the two pointer bytes are consumed here — that is what makes DNS records
   walkable at all, and it is why `dnsname` is a posa type rather than a
   composition of the primitive ones. */
static int dns_name_at(const uint8_t *d, int len, int off, char *out, int outsz)
{
  int op = 0, end = -1, hops = 0;
  out[0] = '\0';
  while (off >= 0 && off < len) {
    int lab = d[off];
    if ((lab & 0xc0) == 0xc0) {                 /* pointer */
      if (off + 1 >= len || ++hops > 16) break;
      if (end < 0) end = off + 2;
      off = ((lab & 0x3f) << 8) | d[off + 1];
      continue;
    }
    if (lab & 0xc0) break;                      /* reserved label type */
    off++;
    if (lab == 0) { if (end < 0) end = off; break; }   /* root ends the name */
    if (off + lab > len) break;
    if (op && op < outsz - 1) out[op++] = '.';
    { int k; for (k = 0; k < lab; k++) if (op < outsz - 1) out[op++] = (char)d[off + k]; }
    off += lab;
  }
  out[op] = '\0';
  return end < 0 ? off : end;
}

static int find_delim(const uint8_t *d, int off, int lim, const char *delim, int ndelim)
{
  int i;
  if (ndelim <= 0) return -1;
  for (i = off; i + ndelim <= lim; i++) if (!memcmp(d + i, delim, (size_t)ndelim)) return i;
  return -1;
}

/* An open scope/when/repeat block. `repeat` carries the extra state a loop needs:
   where to jump back to, how many iterations are left, and which subtree the
   current record's fields are being hung on. */
typedef struct {
  int type;                        /* SCOPE | WHEN | REPEAT                   */
  int prev_lim;
  /* REPEAT only */
  int fld_index;                   /* the `repeat` field — where an iteration restarts */
  int count, iter, until_end;
  int item_start, section_start, seen_base;
  pcapng_field_t *prev_node;       /* subtree to go back to when the loop ends */
  pcapng_field_t *section;         /* optional titled section, else prev_node  */
  pcapng_field_t *item;            /* this record's subtree                    */
  const pcapng_posa_fld_t *lbl;    /* `label "..."` for the record, if any     */
  char item_ab[PCAPNG_FIELD_ABBREV_MAX];
} blk_t;

#define POSA_MAX_ITER 4096         /* runaway guard for `repeat until end` */

/* The display name of a field: the `"Label"` if it declared one, else its name. */
static const char *fld_disp(const pcapng_posa_fld_t *f)
{ return f->disp[0] ? f->disp : f->name; }

/* `repeat until "<delim>"` stops when those bytes come next — an HTTP header
   block ends at the blank line, with no count and no length to go by. */
static int at_delim(const pcapng_posa_fld_t *f, const uint8_t *d, int off, int lim)
{
  if (f->ndelim <= 0) return 0;
  if (off + f->ndelim > lim) return 0;
  return memcmp(d + off, f->delim, (size_t)f->ndelim) == 0;
}

static int dissect_one(const pcapng_posa_proto_t *p, const uint8_t *data, int len,
                       pcapng_field_t *node, int abs_off, char *info, size_t infolen)
{
  int off = 0, i, nseen = 0, nfirst = 0, lim = len, skip = 0;
  seen_t seen[POSA_MAX_SEEN], first[POSA_MAX_SEEN];   /* live scope; first-of-each */
  char ab[PCAPNG_FIELD_ABBREV_MAX], child_info[192] = "";
  const char *prefix = p->abbrev[0] ? p->abbrev : p->name;
  pcapng_field_t *cur = node;      /* where fields land — a repeat item, or the proto */
  blk_t bstack[32]; int nb = 0;
  /* Has any `when` at this depth already run? `else:` is the arm for "none of
     them did", so the flag accumulates across a chain of `when`s and is cleared
     whenever a new block (or a fresh repeat iteration) opens beneath. */
  int taken[34] = {0};

  for (i = 0; i < p->nflds; i++) {
    const pcapng_posa_fld_t *f = &p->flds[i];
    int sz;
    pcapng_field_t *cf = NULL;

    /* skipping a false `when`/`else` (or an empty `repeat`): track nesting until END */
    if (skip) {
      if (f->type == PCAPNG_POSA_SCOPE || f->type == PCAPNG_POSA_WHEN ||
          f->type == PCAPNG_POSA_ELSE  || f->type == PCAPNG_POSA_REPEAT) skip++;
      else if (f->type == PCAPNG_POSA_END) skip--;
      continue;
    }

    if (f->type == PCAPNG_POSA_ELSE) {
      if (taken[nb] || nb >= 32) {
        skip = 1;                                     /* some `when` above it already ran */
      } else {
        taken[nb] = 1;                                /* this arm is the one that runs */
        bstack[nb].type = PCAPNG_POSA_WHEN; bstack[nb].prev_lim = lim; nb++;
        taken[nb] = 0;
      }
      continue;
    }
    if (f->type == PCAPNG_POSA_SCOPE) {
      const seen_t *s = seen_get(seen, nseen, f->lenfield);
      int nl = s ? s->end_off + (int)s->val : lim;
      if (nl > lim) nl = lim; if (nl < off) nl = off;
      if (nb < 32) { bstack[nb].type = PCAPNG_POSA_SCOPE; bstack[nb].prev_lim = lim; nb++;
                     taken[nb] = 0; }
      lim = nl;
      continue;
    }
    if (f->type == PCAPNG_POSA_WHEN) {
      int ok = guard_ok(&f->guard, seen, nseen, off, lim);
      if (ok) taken[nb] = 1;                          /* remembered for a following `else:` */
      if (ok) {
        if (nb < 32) { bstack[nb].type = PCAPNG_POSA_WHEN; bstack[nb].prev_lim = lim; nb++;
                       taken[nb] = 0; }
      } else skip = 1;
      continue;
    }
    if (f->type == PCAPNG_POSA_REPEAT) {
      const seen_t *s = f->until_end ? NULL : seen_get(seen, nseen, f->lenfield);
      int cnt = f->until_end ? -1 : (s ? (int)s->val : 0);
      blk_t *b;
      if (nb >= 32 || off >= lim || (!f->until_end && cnt <= 0) ||
          at_delim(f, data, off, lim)) { skip = 1; continue; }
      b = &bstack[nb++];
      b->type = PCAPNG_POSA_REPEAT; b->prev_lim = lim;
      b->fld_index = i; b->count = cnt; b->iter = 0; b->until_end = f->until_end;
      b->prev_node = cur; b->section = cur; b->lbl = NULL;
      b->section_start = off;
      snprintf(b->item_ab, sizeof b->item_ab, "%s.%s", prefix, f->name);
      if (f->disp[0]) {   /* a titled section groups the records: "Queries" */
        b->section = pf_add(cur, NULL, PCAPNG_FT_NONE);
        pf_label(b->section, "%s", f->disp);
      }
      b->item = pf_add(b->section, b->item_ab, PCAPNG_FT_NONE);
      pf_label(b->item, "%s", f->name);
      b->item_start = off; b->seen_base = nseen;
      taken[nb] = 0;
      cur = b->item;
      continue;
    }
    if (f->type == PCAPNG_POSA_LABEL) {   /* titles the record we are inside */
      if (nb > 0 && bstack[nb - 1].type == PCAPNG_POSA_REPEAT) bstack[nb - 1].lbl = f;
      continue;
    }
    if (f->type == PCAPNG_POSA_END) {
      blk_t *b;
      if (nb == 0) continue;
      b = &bstack[nb - 1];
      if (b->type != PCAPNG_POSA_REPEAT) {
        nb--;
        if (b->type == PCAPNG_POSA_SCOPE) off = lim;   /* skip what we did not decode */
        lim = b->prev_lim;
        continue;
      }
      /* close the record: size it, then title it from the fields it just parsed */
      pf_range(b->item, abs_off + b->item_start, off - b->item_start);
      if (b->lbl) {
        char t[192];
        fmt_expand(b->lbl->disp, b->lbl->largs, b->lbl->nlargs, NULL, 0, seen, nseen,
                   t, sizeof t);
        pf_label(b->item, "%s", t);
      }
      { int k;   /* remember this record's fields if they are the first of their name */
        for (k = b->seen_base; k < nseen; k++)
          if (!seen_get(first, nfirst, seen[k].name) && nfirst < POSA_MAX_SEEN)
            first[nfirst++] = seen[k]; }
      b->iter++;
      if (off > b->item_start && off < lim && b->iter < POSA_MAX_ITER &&
          !at_delim(&p->flds[b->fld_index], data, off, lim) &&
          (b->until_end || b->iter < b->count)) {
        /* next record: its fields replace this one's, so `seen` stays bounded no
           matter how many records the packet carries */
        nseen = b->seen_base;
        b->item = pf_add(b->section, b->item_ab, PCAPNG_FT_NONE);
        pf_label(b->item, "%s", p->flds[b->fld_index].name);
        b->item_start = off;
        taken[nb] = 0;                 /* each record decides its own when/else again */
        cur = b->item;
        i = b->fld_index;              /* the loop's i++ lands on the first body field */
        continue;
      }
      /* the loop is done — the last record's fields stay in scope, so an
         enclosing `label`/`info` can still name them */
      if (b->section != b->prev_node)
        pf_range(b->section, abs_off + b->section_start, off - b->section_start);
      cur = b->prev_node; lim = b->prev_lim; nb--;
      continue;
    }
    if (f->type == PCAPNG_POSA_LAYER) {
      int sublen = lim - off; char sinfo[192] = "";
      if (sublen > 0) {
        int used = pcapng_posa_dissect(f->sub, data + off, sublen, cur, abs_off + off, sinfo, sizeof sinfo);
        if (used > 0) off += used;
        if (sinfo[0]) snprintf(child_info, sizeof child_info, "%s", sinfo);
      }
      continue;
    }
    if (f->type == PCAPNG_POSA_SEEK) {   /* the protocol told us where to look */
      const seen_t *s = f->until_end ? NULL : seen_get(seen, nseen, f->lenfield);
      int to = f->until_end ? (int)f->defnum : (s ? (int)s->val : -1);
      if (to >= 0 && to <= lim) off = to;
      continue;
    }
    if (f->type == PCAPNG_POSA_BITS) {   /* carved out of another field: consumes nothing */
      const seen_t *s = seen_get(seen, nseen, f->src);
      uint64_t m = (f->width >= 64) ? ~0ULL : ((1ULL << f->width) - 1);
      uint64_t v = s ? (s->raw >> f->shift) & m : 0;
      const char *en = enum_name(f, v);
      char disp[96];
      snprintf(ab, sizeof ab, "%s.%s", prefix, f->name);
      cf = pf_add(cur, ab, PCAPNG_FT_UINT); pf_uint(cf, v);
      if (en) snprintf(disp, sizeof disp, "%s", en);
      else    snprintf(disp, sizeof disp, "%llu", (unsigned long long)v);
      pf_label(cf, "%s: %s", fld_disp(f), disp);
      if (s) pf_range(cf, abs_off + s->start_off, s->end_off - s->start_off);
      seen_add(seen, &nseen, f->name, v, v, s ? s->start_off : off, s ? s->end_off : off, disp);
      continue;
    }

    snprintf(ab, sizeof ab, "%s.%s", prefix, f->name);
    sz = fld_fixed_size(f);

    if (sz >= 0) {
      if (off + sz > lim) break;
      switch (f->type) {
      case PCAPNG_POSA_U8: case PCAPNG_POSA_U16: case PCAPNG_POSA_U24:
      case PCAPNG_POSA_U32: case PCAPNG_POSA_U64:
      case PCAPNG_POSA_LE16: case PCAPNG_POSA_LE32: case PCAPNG_POSA_LE64: {
        int le = (f->type == PCAPNG_POSA_LE16 || f->type == PCAPNG_POSA_LE32 || f->type == PCAPNG_POSA_LE64);
        uint64_t raw = le ? rd_le(data + off, sz) : rd_be(data + off, sz);
        uint64_t v = f->mask ? (raw & f->mask) : raw;
        const char *en = enum_name(f, v);
        char disp[96];
        cf = pf_add(cur, ab, PCAPNG_FT_UINT); pf_uint(cf, v);
        if (en) { pf_label(cf, "%s: %s (%llu)", fld_disp(f), en, (unsigned long long)v);
                  snprintf(disp, sizeof disp, "%s", en); }
        else if (f->hex) { pf_label(cf, "%s: 0x%0*llx", fld_disp(f), sz * 2, (unsigned long long)v);
                  snprintf(disp, sizeof disp, "0x%0*llx", sz * 2, (unsigned long long)v); }
        else    { pf_label(cf, "%s: %llu", fld_disp(f), (unsigned long long)v);
                  snprintf(disp, sizeof disp, "%llu", (unsigned long long)v); }
        seen_add(seen, &nseen, f->name, v, raw, off, off + sz, disp);
        break; }
      case PCAPNG_POSA_MAC:
        cf = pf_add(cur, ab, PCAPNG_FT_MAC); pf_mac(cf, data + off);
        pf_label(cf, "%s: %s", fld_disp(f), cf->str);
        seen_add(seen, &nseen, f->name, 0, 0, off, off + sz, cf->str); break;
      case PCAPNG_POSA_IP4:
        cf = pf_add(cur, ab, PCAPNG_FT_IPV4); pf_ipv4(cf, data + off);
        pf_label(cf, "%s: %s", fld_disp(f), cf->str);
        seen_add(seen, &nseen, f->name, 0, 0, off, off + sz, cf->str); break;
      case PCAPNG_POSA_IP6:
        cf = pf_add(cur, ab, PCAPNG_FT_IPV6); pf_ipv6(cf, data + off);
        pf_label(cf, "%s: %s", fld_disp(f), cf->str);
        seen_add(seen, &nseen, f->name, 0, 0, off, off + sz, cf->str); break;
      case PCAPNG_POSA_BYTES_FIXED:
        cf = pf_add(cur, ab, PCAPNG_FT_BYTES); pf_bytes(cf, data + off, sz);
        pf_label(cf, "%s: %d bytes", fld_disp(f), sz);
        seen_add(seen, &nseen, f->name, 0, 0, off, off + sz, ""); break;
      default: break;
      }
      if (cf) pf_range(cf, abs_off + off, sz);
      off += sz;
    } else if (f->type == PCAPNG_POSA_DNSNAME) {
      /* pointers may aim anywhere in the message, so resolve against `len`, not
         the enclosing scope's `lim` */
      int start = off; char nm[256];
      int end = dns_name_at(data, len, off, nm, sizeof nm);
      if (end <= start) end = start < lim ? start + 1 : lim;   /* never stall */
      off = end > lim ? lim : end;
      cf = pf_add(cur, ab, PCAPNG_FT_STR); pf_str(cf, nm);
      pf_label(cf, "%s: %s", fld_disp(f), nm[0] ? nm : "<Root>");
      pf_range(cf, abs_off + start, off - start);
      seen_add(seen, &nseen, f->name, 0, 0, start, off, nm[0] ? nm : "<Root>");
    } else if (f->type == PCAPNG_POSA_CSTRING) {
      int start = off, n = 0; char tmp[256];
      while (off < lim && data[off] != '\0' && n < (int)sizeof tmp - 1) tmp[n++] = (char)data[off++];
      tmp[n] = '\0';
      if (off < lim && data[off] == '\0') off++;
      cf = pf_add(cur, ab, PCAPNG_FT_STR); pf_str(cf, tmp);
      pf_label(cf, "%s: %s", fld_disp(f), tmp);
      pf_range(cf, abs_off + start, off - start);
      seen_add(seen, &nseen, f->name, (uint64_t)n, (uint64_t)n, start, off, tmp);
    } else if (f->type == PCAPNG_POSA_STR_DELIM) {
      /* consume up to (and past) the delimiter; if the delimiter is absent the
         field is empty (0 bytes) — an "optional" delimited token. */
      int start = off, d = find_delim(data, off, lim, f->delim, f->ndelim), n; char tmp[256];
      n = (d >= 0) ? d - start : 0;
      if (n > (int)sizeof tmp - 1) n = (int)sizeof tmp - 1;
      memcpy(tmp, data + start, (size_t)n); tmp[n] = '\0';
      if (d >= 0) off = d + f->ndelim;
      cf = pf_add(cur, ab, PCAPNG_FT_STR); pf_str(cf, tmp);
      pf_label(cf, "%s: %s", fld_disp(f), tmp);
      pf_range(cf, abs_off + start, off - start);
      seen_add(seen, &nseen, f->name, (uint64_t)n, (uint64_t)n, start, off, tmp);
    } else if (f->type == PCAPNG_POSA_UTF16) {
      /* UTF-16LE, as SMB2 carries every name. Rendered as the ASCII subset —
         enough to read a share or file name in the tree. */
      const seen_t *s = seen_get(seen, nseen, f->lenfield);
      int start = off, n = s ? (int)s->val : 0, k, o2 = 0;
      char tmp[256];
      if (n < 0) n = 0;
      if (off + n > lim) n = lim - off;
      if (n < 0) n = 0;
      for (k = 0; k + 1 < n && o2 < (int)sizeof tmp - 1; k += 2) {
        uint16_t wc = (uint16_t)(data[off + k] | (data[off + k + 1] << 8));
        tmp[o2++] = (wc >= 32 && wc < 127) ? (char)wc : (wc ? '.' : ' ');
      }
      tmp[o2] = '\0';
      while (o2 > 0 && tmp[o2 - 1] == ' ') tmp[--o2] = '\0';
      cf = pf_add(cur, ab, PCAPNG_FT_STR); pf_str(cf, tmp);
      pf_label(cf, "%s: %s", fld_disp(f), tmp);
      pf_range(cf, abs_off + start, n);
      seen_add(seen, &nseen, f->name, (uint64_t)n, (uint64_t)n, start, off + n, tmp);
      off += n;
    } else if (f->type == PCAPNG_POSA_BYTES_REF || f->type == PCAPNG_POSA_STR_REF) {
      const seen_t *s = seen_get(seen, nseen, f->lenfield);
      int start = off, n = s ? (int)s->val : 0;
      if (n < 0) n = 0;
      if (off + n > lim) n = lim - off;
      if (n < 0) n = 0;
      if (f->type == PCAPNG_POSA_STR_REF) {
        char tmp[256]; int k, o2 = 0;
        for (k = 0; k < n && o2 < (int)sizeof tmp - 1; k++) {
          uint8_t ch = data[off + k];
          tmp[o2++] = (ch >= 32 && ch < 127) ? (char)ch : '.';
        }
        tmp[o2] = '\0';
        cf = pf_add(cur, ab, PCAPNG_FT_STR); pf_str(cf, tmp);
        pf_label(cf, "%s: %s", fld_disp(f), tmp);
        seen_add(seen, &nseen, f->name, (uint64_t)n, (uint64_t)n, start, off + n, tmp);
      } else {
        cf = pf_add(cur, ab, PCAPNG_FT_BYTES); pf_bytes(cf, data + off, n);
        pf_label(cf, "%s: %d bytes", fld_disp(f), n);
        seen_add(seen, &nseen, f->name, (uint64_t)n, (uint64_t)n, start, off + n, "");
      }
      pf_range(cf, abs_off + off, n);
      off += n;
    } else if (f->type == PCAPNG_POSA_PAYLOAD) {
      int n = lim - off; if (n < 0) n = 0;
      cf = pf_add(cur, ab, PCAPNG_FT_BYTES); pf_bytes(cf, data + off, n);
      pf_label(cf, "%s: %d bytes", fld_disp(f), n);
      pf_range(cf, abs_off + off, n); off = lim;
    }
  }

  if (info && infolen) {
    /* the deepest layer that produced Info wins; else this proto's own info */
    if (child_info[0])       snprintf(info, infolen, "%s", child_info);
    else if (p->info_fmt[0])
      fmt_expand(p->info_fmt, p->info_args, p->info_nargs, first, nfirst, seen, nseen,
                 info, infolen);
  }
  return off;
}

/* Object<parent> dispatch: choose the sub-protocol whose first field matches. */
static const pcapng_posa_proto_t *resolve_group(const char *name, const uint8_t *data, int len)
{
  const pcapng_posa_proto_t *fallback = NULL;
  int i;
  for (i = 0; i < g_nprotos; i++) {
    const pcapng_posa_proto_t *p = g_protos[i]; int sz;
    if (!p) continue;
    if (strcmp(p->parent, name) != 0 || p->nflds == 0) continue;
    sz = fld_fixed_size(&p->flds[0]);
    if (sz <= 0 || sz > len) continue;
    { uint64_t v = (p->flds[0].type == PCAPNG_POSA_LE16 || p->flds[0].type == PCAPNG_POSA_LE32 ||
                    p->flds[0].type == PCAPNG_POSA_LE64) ? rd_le(data, sz) : rd_be(data, sz);
      if (v == p->flds[0].defnum) return p; }
  }
  for (i = 0; i < g_nprotos; i++) {          /* nothing matched: the group's default */
    const pcapng_posa_proto_t *p = g_protos[i];
    if (p && p->is_default && !strcmp(p->parent, name)) { fallback = p; break; }
  }
  return (pcapng_posa_proto_t *)fallback;
}

const pcapng_posa_proto_t *pcapng_posa_resolve(const char *name, const uint8_t *data, int len)
{
  const pcapng_posa_proto_t *p;
  if (!name) return NULL;
  p = pcapng_posa_find(name);
  if (p) return p;
  return resolve_group(name, data, len);
}

/* The Protocol-column name of the innermost decoder that ran: NetBIOS frames
   SMB2, and the packet is an "SMB2" — the deepest layer that names a column
   wins, the same way the deepest Info string already does. */
static char g_last_col[32];
const char *pcapng_posa_last_col(void) { return g_last_col[0] ? g_last_col : NULL; }
void pcapng_posa_reset_col(void) { g_last_col[0] = '\0'; }

int pcapng_posa_dissect(const char *proto_name, const uint8_t *data, int len,
                        pcapng_field_t *parent, int abs_off, char *info, size_t infolen)
{
  const pcapng_posa_proto_t *p = pcapng_posa_find(proto_name);
  pcapng_field_t *node; int used;
  if (!proto_name || !data || len <= 0) return 0;
  if (!p) { p = resolve_group(proto_name, data, len); if (!p) return 0; }
  node = pf_add(parent, p->abbrev[0] ? p->abbrev : p->name, PCAPNG_FT_NONE);
  pf_label(node, "%s", p->name);
  if (p->display[0]) snprintf(g_last_col, sizeof g_last_col, "%s", p->display);
  used = dissect_one(p, data, len, node, abs_off, info, infolen);   /* nests via `layer` */
  pf_range(node, abs_off, used > 0 ? used : len);
  return used > 0 ? used : len;
}

/* ── serialize back to editable .posa text ───────────────────────────────── */
int pcapng_posa_to_text(const pcapng_posa_proto_t *p, char *out, size_t sz)
{
  static const char *TN[] = { "uint8","uint16","uint32","uint64","le_uint16","le_uint32",
                              "le_uint64","mac","ip4","cstring","payload" };
  size_t o = 0; int i, j;
  if (!p || !out || sz == 0) return 0;
  o += (size_t)snprintf(out + o, sz - o, "# %s decoder (.posa) — regenerated by libpcapng\n", p->name);
  o += (size_t)snprintf(out + o, sz - o, "Object<%s> %s\n", p->parent[0] ? p->parent : "main", p->name);
  for (i = 0; i < p->nflds && o < sz; i++) {
    const pcapng_posa_fld_t *f = &p->flds[i]; char type[48];
    if (f->type == PCAPNG_POSA_BYTES_FIXED)    snprintf(type, sizeof type, "bytes<%zu>", f->nbytes);
    else if (f->type == PCAPNG_POSA_BYTES_REF) snprintf(type, sizeof type, "bytes[%s]", f->lenfield);
    else snprintf(type, sizeof type, "%s", (f->type >= 0 && f->type <= PCAPNG_POSA_PAYLOAD) ? TN[f->type] : "uint8");
    o += (size_t)snprintf(out + o, sz - o, "    required %s %s", type, f->name);
    if (f->nenums > 0 || f->type <= PCAPNG_POSA_U64)
      o += (size_t)snprintf(out + o, sz - o, " = %llu", (unsigned long long)f->defnum);
    o += (size_t)snprintf(out + o, sz - o, "\n");
    for (j = 0; j < f->nenums && o < sz; j++)
      o += (size_t)snprintf(out + o, sz - o, "        %s = %llu\n", f->enums[j].name, (unsigned long long)f->enums[j].val);
  }
  return (int)o;
}
