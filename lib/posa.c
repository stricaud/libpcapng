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
#include <dirent.h>

/* ── registry ────────────────────────────────────────────────────────────── */
#define MAX_PROTOS 512
static pcapng_posa_proto_t g_protos[MAX_PROTOS];
static int                 g_nprotos;

#define MAX_BINDS 256
typedef struct { int ipproto; uint16_t port; char proto[PCAPNG_POSA_NAME_MAX]; int used; } bind_t;
static bind_t g_binds[MAX_BINDS];
static int    g_nbinds;

int pcapng_posa_count(void) { return g_nprotos; }
const pcapng_posa_proto_t *pcapng_posa_at(int i)
{ return (i >= 0 && i < g_nprotos) ? &g_protos[i] : NULL; }
const pcapng_posa_proto_t *pcapng_posa_find(const char *name)
{
  int i;
  if (!name) return NULL;
  for (i = 0; i < g_nprotos; i++) if (!strcmp(g_protos[i].name, name)) return &g_protos[i];
  return NULL;
}
void pcapng_posa_clear(void) { g_nprotos = 0; g_nbinds = 0; }

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
  else if (!strcmp(tok, "uint32"))     f->type = PCAPNG_POSA_U32;
  else if (!strcmp(tok, "uint64"))     f->type = PCAPNG_POSA_U64;
  else if (!strcmp(tok, "le_uint16"))  f->type = PCAPNG_POSA_LE16;
  else if (!strcmp(tok, "le_uint32"))  f->type = PCAPNG_POSA_LE32;
  else if (!strcmp(tok, "le_uint64"))  f->type = PCAPNG_POSA_LE64;
  else if (!strcmp(tok, "mac"))        f->type = PCAPNG_POSA_MAC;
  else if (!strcmp(tok, "ip4"))        f->type = PCAPNG_POSA_IP4;
  else if (!strcmp(tok, "cstring"))    f->type = PCAPNG_POSA_CSTRING;
  else if (!strcmp(tok, "string"))     f->type = PCAPNG_POSA_CSTRING; /* until handled by caller */
  else if (!strcmp(tok, "payload"))    f->type = PCAPNG_POSA_PAYLOAD;
  else if (!strncmp(tok, "bytes<", 6)) { f->type = PCAPNG_POSA_BYTES_FIXED; f->nbytes = (size_t)parse_num(tok + 6); }
  else if (!strncmp(tok, "bytes[", 6)) {
    const char *e = strchr(tok + 6, ']');
    f->type = PCAPNG_POSA_BYTES_REF;
    snprintf(f->lenfield, sizeof f->lenfield, "%.*s", e ? (int)(e - (tok + 6)) : 0, tok + 6);
  } else return -1;
  return 0;
}
static int is_type_tok(const char *t) { pcapng_posa_fld_t tmp; return parse_type(t, &tmp) == 0; }

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

/* Parse "rule <tcp|udp>.port == N => Proto" into a port binding. */
static void parse_rule(const char *rest)
{
  char t[16] = "", field[24] = ""; unsigned port = 0; const char *arrow;
  char proto[PCAPNG_POSA_NAME_MAX] = "";
  /* forms: tcp.port == 3389   udp.dstport == 69 */
  if (sscanf(rest, "%15[a-z].%23[a-z] == %u", t, field, &port) == 3) {
    arrow = strstr(rest, "=>");
    if (arrow && sscanf(arrow + 2, " %63s", proto) == 1) {
      int ip = !strcmp(t, "tcp") ? 6 : !strcmp(t, "udp") ? 17 : 0;
      if (ip) bind_add(ip, (uint16_t)port, proto);
    }
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
    char buf[1024], *toks[32], *hash, *tl;
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

    /* rule <condition> => Proto  (parsed from raw text, before tokenizing) */
    if (!strncmp(tl, "rule", 4) && (tl[4] == ' ' || tl[4] == '\t')) {
      char *r = tl + 4; while (*r == ' ' || *r == '\t') r++;
      parse_rule(r);
      continue;
    }

    /* col "<Name>"  — the Protocol-column display name */
    if (cur && !strncmp(tl, "col", 3) && (tl[3] == ' ' || tl[3] == '"' || tl[3] == '\t')) {
      char *q1 = strchr(tl, '"'), *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
      if (q1 && q2) snprintf(cur->display, sizeof cur->display, "%.*s", (int)(q2 - q1 - 1), q1 + 1);
      continue;
    }

    /* info "<fmt>" arg, arg  (parsed from raw text — the fmt has spaces) */
    if (cur && !strncmp(tl, "info", 4) && (tl[4] == ' ' || tl[4] == '"' || tl[4] == '\t')) {
      char *q1 = strchr(tl, '"'), *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
      if (q1 && q2) {
        char *a; int na = 0;
        snprintf(cur->info_fmt, sizeof cur->info_fmt, "%.*s", (int)(q2 - q1 - 1), q1 + 1);
        a = q2 + 1;
        while (*a && na < 8) {
          char *comma;
          while (*a == ' ' || *a == '\t' || *a == ',') a++;
          if (!*a) break;
          comma = strchr(a, ',');
          { int L = comma ? (int)(comma - a) : (int)strlen(a);
            while (L > 0 && (a[L-1]==' '||a[L-1]=='\t')) L--;
            snprintf(cur->info_args[na++], PCAPNG_POSA_NAME_MAX, "%.*s", L, a); }
          if (!comma) break; a = comma + 1;
        }
        cur->info_nargs = na;
      }
      continue;
    }

    nt = tokenize(buf, toks, 32);
    if (nt == 0) continue;

    if (!strncmp(toks[0], "Object<", 7) || !strcmp(toks[0], "protocol") || !strcmp(toks[0], "Object")) {
      char parent[PCAPNG_POSA_NAME_MAX] = "main";
      const char *name = NULL;
      nblk = 0; lastfld = NULL;
      if (!strcmp(toks[0], "protocol")) { name = nt > 1 ? toks[1] : NULL; parent[0] = '\0'; }
      else {
        char *gt = strchr(toks[0], '>'); const char *pp = toks[0] + 7;
        if (gt) snprintf(parent, sizeof parent, "%.*s", (int)(gt - pp), pp);
        if (!strcmp(parent, "main")) parent[0] = '\0';
        name = nt > 1 ? toks[1] : NULL;
      }
      if (!name) { if (errbuf) snprintf(errbuf, errlen, "line %d: missing protocol name", lineno); return -1; }
      { pcapng_posa_proto_t *ex = (pcapng_posa_proto_t *)pcapng_posa_find(name);
        if (ex) cur = ex;
        else if (g_nprotos < MAX_PROTOS) cur = &g_protos[g_nprotos++];
        else { if (errbuf) snprintf(errbuf, errlen, "too many protocols"); return -1; } }
      memset(cur, 0, sizeof *cur);
      snprintf(cur->name, sizeof cur->name, "%s", name);
      snprintf(cur->parent, sizeof cur->parent, "%s", parent);
      added++;
      continue;
    }
    if (!strcmp(toks[0], "end")) { cur = NULL; nblk = 0; lastfld = NULL; continue; }
    if (!cur) continue;

    /* enum line: NAME = value (attaches to the most recent value field) */
    if (lastfld && nt >= 3 && !strcmp(toks[1], "=")) {
      if (lastfld->nenums < PCAPNG_POSA_MAX_ENUMS) {
        pcapng_posa_enum_t *e = &lastfld->enums[lastfld->nenums++];
        snprintf(e->name, sizeof e->name, "%s", toks[0]);
        e->val = parse_num(toks[2]);
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

    /* field line: [required|optional] <type> <name> [until "delim"] [= default] */
    ti = 0;
    if (!strcmp(toks[0], "required") || !strcmp(toks[0], "optional")) ti = 1;
    if (ti < nt && (is_type_tok(toks[ti]) || !strcmp(toks[ti], "string"))) {
      pcapng_posa_fld_t *f = add_fld(cur, PCAPNG_POSA_U8);
      if (!f) continue;
      parse_type(toks[ti], f);
      if (ti + 1 < nt) snprintf(f->name, sizeof f->name, "%s", toks[ti + 1]);
      if (!strcmp(toks[ti], "string") && ti + 3 < nt && !strcmp(toks[ti + 2], "until")) {
        f->type = PCAPNG_POSA_STR_DELIM;
        parse_delim(toks[ti + 3], f->delim, &f->ndelim);
      }
      { int k; for (k = ti + 2; k < nt; k++) if (!strcmp(toks[k], "=") && k + 1 < nt) {
          f->defnum = parse_num(toks[k + 1]); break; } }
      lastfld = f;
      continue;
    }
  }
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
  case PCAPNG_POSA_U32: case PCAPNG_POSA_LE32: return 4;
  case PCAPNG_POSA_U64: case PCAPNG_POSA_LE64: return 8;
  case PCAPNG_POSA_MAC: return 6;
  case PCAPNG_POSA_IP4: return 4;
  case PCAPNG_POSA_BYTES_FIXED: return (int)f->nbytes;
  default: return -1;
  }
}
static uint64_t rd_be(const uint8_t *d, int n) { uint64_t v = 0; int i; for (i = 0; i < n; i++) v = (v << 8) | d[i]; return v; }
static uint64_t rd_le(const uint8_t *d, int n) { uint64_t v = 0; int i; for (i = n - 1; i >= 0; i--) v = (v << 8) | d[i]; return v; }

typedef struct { char name[PCAPNG_POSA_NAME_MAX]; uint64_t val; int end_off; char disp[96]; } seen_t;

static void seen_add(seen_t *seen, int *nseen, const char *name, uint64_t val, int end_off, const char *disp)
{
  if (*nseen >= PCAPNG_POSA_MAX_FLDS) return;
  snprintf(seen[*nseen].name, sizeof seen[*nseen].name, "%s", name);
  seen[*nseen].val = val; seen[*nseen].end_off = end_off;
  snprintf(seen[*nseen].disp, sizeof seen[*nseen].disp, "%s", disp ? disp : "");
  (*nseen)++;
}
static const seen_t *seen_get(const seen_t *seen, int nseen, const char *name)
{ int i; for (i = 0; i < nseen; i++) if (!strcmp(seen[i].name, name)) return &seen[i]; return NULL; }

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

/* Build the Info string from `info "fmt" args`. %s = display, %u/%d = number. */
static void fmt_info(const pcapng_posa_proto_t *p, const seen_t *seen, int nseen, char *out, size_t outlen)
{
  const char *f = p->info_fmt; size_t o = 0; int ai = 0;
  if (!out || !outlen) return;
  while (*f && o < outlen - 1) {
    if (*f == '%' && f[1]) {
      char c = f[1]; const seen_t *s = (ai < p->info_nargs) ? seen_get(seen, nseen, p->info_args[ai]) : NULL;
      ai++; f += 2;
      if (c == 's')       o += (size_t)snprintf(out + o, outlen - o, "%s", s ? s->disp : "");
      else if (c=='u'||c=='d') o += (size_t)snprintf(out + o, outlen - o, "%llu", s ? (unsigned long long)s->val : 0ULL);
      else if (c == 'x')  o += (size_t)snprintf(out + o, outlen - o, "%llx", s ? (unsigned long long)s->val : 0ULL);
      else if (c == '%')  out[o++] = '%';
    } else out[o++] = *f++;
  }
  out[o] = '\0';
}

static int find_delim(const uint8_t *d, int off, int lim, const char *delim, int ndelim)
{
  int i;
  if (ndelim <= 0) return -1;
  for (i = off; i + ndelim <= lim; i++) if (!memcmp(d + i, delim, (size_t)ndelim)) return i;
  return -1;
}

static int dissect_one(const pcapng_posa_proto_t *p, const uint8_t *data, int len,
                       pcapng_field_t *node, int abs_off, char *info, size_t infolen)
{
  int off = 0, i, nseen = 0, lim = len, skip = 0;
  seen_t seen[PCAPNG_POSA_MAX_FLDS];
  char ab[PCAPNG_FIELD_ABBREV_MAX], child_info[192] = "";
  struct { int type; int prev_lim; } bstack[32]; int nb = 0;

  for (i = 0; i < p->nflds; i++) {
    const pcapng_posa_fld_t *f = &p->flds[i];
    int sz;
    pcapng_field_t *cf = NULL;

    /* skipping a false `when` block: track nesting until its END */
    if (skip) {
      if (f->type == PCAPNG_POSA_SCOPE || f->type == PCAPNG_POSA_WHEN) skip++;
      else if (f->type == PCAPNG_POSA_END) skip--;
      continue;
    }

    if (f->type == PCAPNG_POSA_SCOPE) {
      const seen_t *s = seen_get(seen, nseen, f->lenfield);
      int nl = s ? s->end_off + (int)s->val : lim;
      if (nl > lim) nl = lim; if (nl < off) nl = off;
      if (nb < 32) { bstack[nb].type = PCAPNG_POSA_SCOPE; bstack[nb].prev_lim = lim; nb++; }
      lim = nl;
      continue;
    }
    if (f->type == PCAPNG_POSA_WHEN) {
      if (guard_ok(&f->guard, seen, nseen, off, lim)) {
        if (nb < 32) { bstack[nb].type = PCAPNG_POSA_WHEN; bstack[nb].prev_lim = lim; nb++; }
      } else skip = 1;
      continue;
    }
    if (f->type == PCAPNG_POSA_END) {
      if (nb > 0) { nb--; if (bstack[nb].type == PCAPNG_POSA_SCOPE) off = lim; lim = bstack[nb].prev_lim; }
      continue;
    }
    if (f->type == PCAPNG_POSA_LAYER) {
      int sublen = lim - off; char sinfo[192] = "";
      if (sublen > 0) {
        int used = pcapng_posa_dissect(f->sub, data + off, sublen, node, abs_off + off, sinfo, sizeof sinfo);
        if (used > 0) off += used;
        if (sinfo[0]) snprintf(child_info, sizeof child_info, "%s", sinfo);
      }
      continue;
    }

    snprintf(ab, sizeof ab, "%s.%s", p->name, f->name);
    sz = fld_fixed_size(f);

    if (sz >= 0) {
      if (off + sz > lim) break;
      switch (f->type) {
      case PCAPNG_POSA_U8: case PCAPNG_POSA_U16: case PCAPNG_POSA_U32: case PCAPNG_POSA_U64:
      case PCAPNG_POSA_LE16: case PCAPNG_POSA_LE32: case PCAPNG_POSA_LE64: {
        int le = (f->type == PCAPNG_POSA_LE16 || f->type == PCAPNG_POSA_LE32 || f->type == PCAPNG_POSA_LE64);
        uint64_t v = le ? rd_le(data + off, sz) : rd_be(data + off, sz);
        const char *en = enum_name(f, v);
        char disp[96];
        cf = pf_add(node, ab, PCAPNG_FT_UINT); pf_uint(cf, v);
        if (en) { pf_label(cf, "%s: %s (%llu)", f->name, en, (unsigned long long)v);
                  snprintf(disp, sizeof disp, "%s", en); }
        else    { pf_label(cf, "%s: %llu", f->name, (unsigned long long)v);
                  snprintf(disp, sizeof disp, "%llu", (unsigned long long)v); }
        seen_add(seen, &nseen, f->name, v, off + sz, disp);
        break; }
      case PCAPNG_POSA_MAC:
        cf = pf_add(node, ab, PCAPNG_FT_MAC); pf_mac(cf, data + off);
        pf_label(cf, "%s: %s", f->name, cf->str);
        seen_add(seen, &nseen, f->name, 0, off + sz, cf->str); break;
      case PCAPNG_POSA_IP4:
        cf = pf_add(node, ab, PCAPNG_FT_IPV4); pf_ipv4(cf, data + off);
        pf_label(cf, "%s: %s", f->name, cf->str);
        seen_add(seen, &nseen, f->name, 0, off + sz, cf->str); break;
      case PCAPNG_POSA_BYTES_FIXED:
        cf = pf_add(node, ab, PCAPNG_FT_BYTES); pf_bytes(cf, data + off, sz);
        pf_label(cf, "%s: %d bytes", f->name, sz);
        seen_add(seen, &nseen, f->name, 0, off + sz, ""); break;
      default: break;
      }
      if (cf) pf_range(cf, abs_off + off, sz);
      off += sz;
    } else if (f->type == PCAPNG_POSA_CSTRING) {
      int start = off, n = 0; char tmp[256];
      while (off < lim && data[off] != '\0' && n < (int)sizeof tmp - 1) tmp[n++] = (char)data[off++];
      tmp[n] = '\0';
      if (off < lim && data[off] == '\0') off++;
      cf = pf_add(node, ab, PCAPNG_FT_STR); pf_str(cf, tmp);
      pf_label(cf, "%s: %s", f->name, tmp);
      pf_range(cf, abs_off + start, off - start);
      seen_add(seen, &nseen, f->name, (uint64_t)n, off, tmp);
    } else if (f->type == PCAPNG_POSA_STR_DELIM) {
      /* consume up to (and past) the delimiter; if the delimiter is absent the
         field is empty (0 bytes) — an "optional" delimited token. */
      int start = off, d = find_delim(data, off, lim, f->delim, f->ndelim), n; char tmp[256];
      n = (d >= 0) ? d - start : 0;
      if (n > (int)sizeof tmp - 1) n = (int)sizeof tmp - 1;
      memcpy(tmp, data + start, (size_t)n); tmp[n] = '\0';
      if (d >= 0) off = d + f->ndelim;
      cf = pf_add(node, ab, PCAPNG_FT_STR); pf_str(cf, tmp);
      pf_label(cf, "%s: %s", f->name, tmp);
      pf_range(cf, abs_off + start, off - start);
      seen_add(seen, &nseen, f->name, (uint64_t)n, off, tmp);
    } else if (f->type == PCAPNG_POSA_BYTES_REF) {
      const seen_t *s = seen_get(seen, nseen, f->lenfield);
      int n = s ? (int)s->val : 0;
      if (off + n > lim) n = lim - off; if (n < 0) n = 0;
      cf = pf_add(node, ab, PCAPNG_FT_BYTES); pf_bytes(cf, data + off, n);
      pf_label(cf, "%s: %d bytes", f->name, n);
      pf_range(cf, abs_off + off, n);
      seen_add(seen, &nseen, f->name, (uint64_t)n, off + n, ""); off += n;
    } else if (f->type == PCAPNG_POSA_PAYLOAD) {
      int n = lim - off; if (n < 0) n = 0;
      cf = pf_add(node, ab, PCAPNG_FT_BYTES); pf_bytes(cf, data + off, n);
      pf_label(cf, "%s: %d bytes", f->name, n);
      pf_range(cf, abs_off + off, n); off = lim;
    }
  }

  if (info && infolen) {
    /* the deepest layer that produced Info wins; else this proto's own info */
    if (child_info[0])       snprintf(info, infolen, "%s", child_info);
    else if (p->info_fmt[0]) fmt_info(p, seen, nseen, info, infolen);
  }
  return off;
}

/* Object<parent> dispatch: choose the sub-protocol whose first field matches. */
static const pcapng_posa_proto_t *resolve_group(const char *name, const uint8_t *data, int len)
{
  int i;
  for (i = 0; i < g_nprotos; i++) {
    const pcapng_posa_proto_t *p = &g_protos[i]; int sz;
    if (strcmp(p->parent, name) != 0 || p->nflds == 0) continue;
    sz = fld_fixed_size(&p->flds[0]);
    if (sz <= 0 || sz > len) continue;
    { uint64_t v = (p->flds[0].type == PCAPNG_POSA_LE16 || p->flds[0].type == PCAPNG_POSA_LE32 ||
                    p->flds[0].type == PCAPNG_POSA_LE64) ? rd_le(data, sz) : rd_be(data, sz);
      if (v == p->flds[0].defnum) return p; }
  }
  return NULL;
}

const pcapng_posa_proto_t *pcapng_posa_resolve(const char *name, const uint8_t *data, int len)
{
  const pcapng_posa_proto_t *p;
  if (!name) return NULL;
  p = pcapng_posa_find(name);
  if (p) return p;
  return resolve_group(name, data, len);
}

int pcapng_posa_dissect(const char *proto_name, const uint8_t *data, int len,
                        pcapng_field_t *parent, int abs_off, char *info, size_t infolen)
{
  const pcapng_posa_proto_t *p = pcapng_posa_find(proto_name);
  pcapng_field_t *node; int used;
  if (!proto_name || !data || len <= 0) return 0;
  if (!p) { p = resolve_group(proto_name, data, len); if (!p) return 0; }
  node = pf_add(parent, p->name, PCAPNG_FT_NONE);
  pf_label(node, "%s", p->name);
  used = dissect_one(p, data, len, node, abs_off, info, infolen);
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
