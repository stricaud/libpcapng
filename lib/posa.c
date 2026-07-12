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
static int parse_src(const char *src, char *errbuf, size_t errlen)
{
  const char *line = src;
  pcapng_posa_proto_t *cur = NULL;
  int added = 0, lineno = 0;

  while (*line) {
    char buf[1024], *toks[32], *hash;
    const char *eol = strchr(line, '\n');
    size_t llen = eol ? (size_t)(eol - line) : strlen(line);
    int nt;

    lineno++;
    if (llen >= sizeof buf) llen = sizeof buf - 1;
    memcpy(buf, line, llen); buf[llen] = '\0';
    line = eol ? eol + 1 : line + strlen(line);
    hash = strchr(buf, '#'); if (hash) *hash = '\0';

    nt = tokenize(buf, toks, 32);
    if (nt == 0) continue;

    if (!strcmp(toks[0], "rule")) {              /* rule <cond> => Proto */
      char *r = buf + 4; while (*r == ' ' || *r == '\t') r++;
      parse_rule(r);
      continue;
    }
    if (!strncmp(toks[0], "Object<", 7) || !strcmp(toks[0], "protocol") || !strcmp(toks[0], "Object")) {
      char parent[PCAPNG_POSA_NAME_MAX] = "main";
      const char *name = NULL;
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
    if (!strcmp(toks[0], "end")) { cur = NULL; continue; }
    if (!cur) continue;

    /* field line: [required|optional] <type> <name> [= default] */
    {
      int ti = 0;
      if (!strcmp(toks[0], "required") || !strcmp(toks[0], "optional")) ti = 1;
      if (ti < nt && is_type_tok(toks[ti])) {
        pcapng_posa_fld_t *f;
        if (cur->nflds >= PCAPNG_POSA_MAX_FLDS) continue;
        f = &cur->flds[cur->nflds];
        memset(f, 0, sizeof *f); f->scope_len_field = -1;
        parse_type(toks[ti], f);
        if (ti + 1 < nt) snprintf(f->name, sizeof f->name, "%s", toks[ti + 1]);
        { int k; for (k = ti + 2; k < nt; k++) if (!strcmp(toks[k], "=") && k + 1 < nt) {
            f->defnum = parse_num(toks[k + 1]); break; } }
        cur->nflds++;
        continue;
      }
    }
    /* enum line: NAME = value (attaches to the most recent field) */
    if (cur->nflds > 0 && nt >= 3 && !strcmp(toks[1], "=")) {
      pcapng_posa_fld_t *f = &cur->flds[cur->nflds - 1];
      if (f->nenums < PCAPNG_POSA_MAX_ENUMS) {
        pcapng_posa_enum_t *e = &f->enums[f->nenums++];
        snprintf(e->name, sizeof e->name, "%s", toks[0]);
        e->val = parse_num(toks[2]);
      }
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

typedef struct { char name[PCAPNG_POSA_NAME_MAX]; uint64_t val; } seen_t;

static int dissect_one(const pcapng_posa_proto_t *p, const uint8_t *data, int len,
                       pcapng_field_t *node, int abs_off)
{
  int off = 0, i, nseen = 0;
  seen_t seen[PCAPNG_POSA_MAX_FLDS];
  char ab[PCAPNG_FIELD_ABBREV_MAX];

  for (i = 0; i < p->nflds; i++) {
    const pcapng_posa_fld_t *f = &p->flds[i];
    int sz = fld_fixed_size(f);
    pcapng_field_t *cf = NULL;
    snprintf(ab, sizeof ab, "%s.%s", p->name, f->name);

    if (sz >= 0) {
      if (off + sz > len) break;
      switch (f->type) {
      case PCAPNG_POSA_U8: case PCAPNG_POSA_U16: case PCAPNG_POSA_U32: case PCAPNG_POSA_U64: {
        uint64_t v = rd_be(data + off, sz); const char *en;
        cf = pf_add(node, ab, PCAPNG_FT_UINT); pf_uint(cf, v);
        en = enum_name(f, v);
        if (en) pf_label(cf, "%s: %s (%llu)", f->name, en, (unsigned long long)v);
        else    pf_label(cf, "%s: %llu", f->name, (unsigned long long)v);
        if (nseen < PCAPNG_POSA_MAX_FLDS) { snprintf(seen[nseen].name, sizeof seen[nseen].name, "%s", f->name); seen[nseen].val = v; nseen++; }
        break; }
      case PCAPNG_POSA_LE16: case PCAPNG_POSA_LE32: case PCAPNG_POSA_LE64: {
        uint64_t v = rd_le(data + off, sz); const char *en = enum_name(f, v);
        cf = pf_add(node, ab, PCAPNG_FT_UINT); pf_uint(cf, v);
        if (en) pf_label(cf, "%s: %s (%llu)", f->name, en, (unsigned long long)v);
        else    pf_label(cf, "%s: %llu", f->name, (unsigned long long)v);
        if (nseen < PCAPNG_POSA_MAX_FLDS) { snprintf(seen[nseen].name, sizeof seen[nseen].name, "%s", f->name); seen[nseen].val = v; nseen++; }
        break; }
      case PCAPNG_POSA_MAC:
        cf = pf_add(node, ab, PCAPNG_FT_MAC); pf_mac(cf, data + off);
        pf_label(cf, "%s: %s", f->name, cf->str); break;
      case PCAPNG_POSA_IP4:
        cf = pf_add(node, ab, PCAPNG_FT_IPV4); pf_ipv4(cf, data + off);
        pf_label(cf, "%s: %s", f->name, cf->str); break;
      case PCAPNG_POSA_BYTES_FIXED:
        cf = pf_add(node, ab, PCAPNG_FT_BYTES); pf_bytes(cf, data + off, sz);
        pf_label(cf, "%s: %d bytes", f->name, sz); break;
      default: break;
      }
      if (cf) pf_range(cf, abs_off + off, sz);
      off += sz;
    } else if (f->type == PCAPNG_POSA_CSTRING) {
      int start = off, n = 0; char tmp[256];
      while (off < len && data[off] != '\0' && n < (int)sizeof tmp - 1) tmp[n++] = (char)data[off++];
      tmp[n] = '\0';
      if (off < len && data[off] == '\0') off++;
      cf = pf_add(node, ab, PCAPNG_FT_STR); pf_str(cf, tmp);
      pf_label(cf, "%s: %s", f->name, tmp);
      pf_range(cf, abs_off + start, off - start);
    } else if (f->type == PCAPNG_POSA_BYTES_REF) {
      int n = 0, j;
      for (j = 0; j < nseen; j++) if (!strcmp(seen[j].name, f->lenfield)) { n = (int)seen[j].val; break; }
      if (off + n > len) n = len - off; if (n < 0) n = 0;
      cf = pf_add(node, ab, PCAPNG_FT_BYTES); pf_bytes(cf, data + off, n);
      pf_label(cf, "%s: %d bytes", f->name, n);
      pf_range(cf, abs_off + off, n); off += n;
    } else if (f->type == PCAPNG_POSA_PAYLOAD) {
      int n = len - off; if (n < 0) n = 0;
      cf = pf_add(node, ab, PCAPNG_FT_BYTES); pf_bytes(cf, data + off, n);
      pf_label(cf, "%s: %d bytes", f->name, n);
      pf_range(cf, abs_off + off, n); off = len;
    }
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
  used = dissect_one(p, data, len, node, abs_off);
  pf_range(node, abs_off, used > 0 ? used : len);
  if (info && infolen) info[0] = '\0';           /* info string: Phase 4 */
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
