/* objects.c — carve transferred files out of reassembled traffic.
 *
 * Implements libpcapng/objects.h: feed captured packets, TCP streams are
 * reassembled (reassembly_tcp), and the chosen application protocol is parsed
 * to recover each object's bytes + metadata. This is the engine behind a
 * Wireshark-style "Export Objects" for HTTP and SMB2.
 */
#include <libpcapng/objects.h>
#include <libpcapng/reassembly_tcp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── link-layer constants (subset we locate TCP through) ─────────────────── */
#define LT_NULL      0
#define LT_ETHERNET  1
#define LT_RAW       101
#define LT_IPV4      228
#define LT_IPV6      229

static uint16_t be16(const uint8_t *p){ return (uint16_t)((p[0]<<8)|p[1]); }
static uint32_t be32(const uint8_t *p){
  return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static uint32_t fold16(const uint8_t *p){ return be32(p)^be32(p+4)^be32(p+8)^be32(p+12); }

/* Little-endian readers for SMB2. */
static uint16_t le16(const uint8_t *p){ return (uint16_t)(p[0]|(p[1]<<8)); }
static uint32_t le32(const uint8_t *p){
  return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint64_t le64(const uint8_t *p){ return (uint64_t)le32(p)|((uint64_t)le32(p+4)<<32); }

/* ── one located TCP segment ─────────────────────────────────────────────── */
typedef struct {
  uint32_t sip, dip; uint16_t sport, dport;
  uint32_t seq; uint8_t flags;
  const uint8_t *pl; int pll;
} seg_t;

static int locate_tcp(const uint8_t *d, int len, uint16_t linktype, seg_t *s)
{
  int off = 0; uint16_t et = 0; const uint8_t *ip; int iplen, ihl; uint8_t proto;
  const uint8_t *l4; int l4len, doff;

  switch (linktype) {
  case LT_ETHERNET:
    if (len < 14) return 0;
    et = be16(d + 12); off = 14;
    if (et == 0x8100) { if (len < 18) return 0; et = be16(d + 16); off = 18; }
    break;
  case LT_RAW: case LT_IPV4: case LT_IPV6:
    et = (len > 0 && (d[0] >> 4) == 6) ? 0x86DD : 0x0800; break;
  case LT_NULL: {
    uint32_t af;
    if (len < 4) return 0;
    af = (uint32_t)d[0]|((uint32_t)d[1]<<8)|((uint32_t)d[2]<<16)|((uint32_t)d[3]<<24);
    et = (af == 2) ? 0x0800 : (af==24||af==28||af==30) ? 0x86DD : 0; off = 4; break;
  }
  default:
    if (len > 0 && (d[0] >> 4) == 4) et = 0x0800; else return 0;
  }

  ip = d + off; iplen = len - off;
  if (et == 0x0800) {
    if (iplen < 20) return 0;
    ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > iplen) return 0;
    proto = ip[9];
    s->sip = be32(ip + 12); s->dip = be32(ip + 16);
    off += ihl;
  } else if (et == 0x86DD) {
    if (iplen < 40) return 0;
    proto = ip[6];
    s->sip = fold16(ip + 8); s->dip = fold16(ip + 24);
    off += 40;
  } else return 0;

  if (proto != 6) return 0;
  l4 = d + off; l4len = len - off;
  if (l4len < 20) return 0;
  doff = ((l4[12] >> 4) & 0x0f) * 4;
  if (doff < 20 || doff > l4len) return 0;
  s->sport = be16(l4); s->dport = be16(l4 + 2);
  s->seq = be32(l4 + 4); s->flags = l4[13];
  s->pl = l4 + doff; s->pll = l4len - doff;
  return 1;
}

/* ── reassembled bidirectional flow ──────────────────────────────────────── */
typedef struct {
  uint32_t lo_ip, hi_ip; uint16_t lo_port, hi_port;   /* canonical key */
  uint8_t *buf[2]; size_t len[2], cap[2];
  uint32_t sip[2], dip[2]; uint16_t sport[2], dport[2];
  int frame[2];
  int used;
} flow_t;

struct pcapng_object_extractor {
  pcapng_object_proto_t proto;
  pcapng_tcp_reasm_t *reasm;
  flow_t *flows; int nflows, cflows;
  int cur_frame;
  pcapng_object_t *objs; int nobjs, cobjs;
  uint8_t **owned; int nowned, cowned;   /* malloc'd object bodies to free */
};

static void endpoint_key(const seg_t *s, uint32_t *lo_ip, uint16_t *lo_port,
                         uint32_t *hi_ip, uint16_t *hi_port)
{
  int aless = (s->sip < s->dip) || (s->sip == s->dip && s->sport <= s->dport);
  if (aless) { *lo_ip=s->sip; *lo_port=s->sport; *hi_ip=s->dip; *hi_port=s->dport; }
  else       { *lo_ip=s->dip; *lo_port=s->dport; *hi_ip=s->sip; *hi_port=s->sport; }
}

static flow_t *flow_find(pcapng_object_extractor_t *ex, uint32_t lo_ip, uint16_t lo_port,
                         uint32_t hi_ip, uint16_t hi_port)
{
  int i;
  for (i = 0; i < ex->nflows; i++) {
    flow_t *f = &ex->flows[i];
    if (f->lo_ip==lo_ip && f->hi_ip==hi_ip && f->lo_port==lo_port && f->hi_port==hi_port)
      return f;
  }
  if (ex->nflows == ex->cflows) {
    int nc = ex->cflows ? ex->cflows * 2 : 16;
    flow_t *nf = realloc(ex->flows, (size_t)nc * sizeof *nf);
    if (!nf) return NULL;
    ex->flows = nf; ex->cflows = nc;
  }
  { flow_t *f = &ex->flows[ex->nflows++];
    memset(f, 0, sizeof *f);
    f->lo_ip=lo_ip; f->lo_port=lo_port; f->hi_ip=hi_ip; f->hi_port=hi_port;
    f->frame[0] = f->frame[1] = 0;
    return f; }
}

static void buf_append(flow_t *f, int dir, const uint8_t *data, size_t len)
{
  if (len == 0) return;
  if (f->len[dir] + len > f->cap[dir]) {
    size_t nc = f->cap[dir] ? f->cap[dir] : 4096;
    while (nc < f->len[dir] + len) nc *= 2;
    { uint8_t *nb = realloc(f->buf[dir], nc); if (!nb) return; f->buf[dir]=nb; f->cap[dir]=nc; }
  }
  memcpy(f->buf[dir] + f->len[dir], data, len);
  f->len[dir] += len;
}

/* reassembly callback: append newly in-order bytes to the flow's half-buffer */
static void reasm_cb(void *ud, uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport,
                     int dir, const uint8_t *data, size_t len,
                     const uint8_t *all, size_t all_len)
{
  pcapng_object_extractor_t *ex = ud;
  uint32_t lo_ip, hi_ip; uint16_t lo_port, hi_port;
  seg_t k; flow_t *f;
  (void)all; (void)all_len;
  k.sip=sip; k.dip=dip; k.sport=sport; k.dport=dport;
  endpoint_key(&k, &lo_ip, &lo_port, &hi_ip, &hi_port);
  f = flow_find(ex, lo_ip, lo_port, hi_ip, hi_port);
  if (!f) return;
  f->used = 1;
  if (f->len[dir] == 0 && f->frame[dir] == 0) f->frame[dir] = ex->cur_frame;
  f->sip[dir]=sip; f->sport[dir]=sport; f->dip[dir]=dip; f->dport[dir]=dport;
  buf_append(f, dir, data, len);
}

/* ── object list ─────────────────────────────────────────────────────────── */
static pcapng_object_t *obj_new(pcapng_object_extractor_t *ex)
{
  if (ex->nobjs == ex->cobjs) {
    int nc = ex->cobjs ? ex->cobjs * 2 : 16;
    pcapng_object_t *no = realloc(ex->objs, (size_t)nc * sizeof *no);
    if (!no) return NULL;
    ex->objs = no; ex->cobjs = nc;
  }
  { pcapng_object_t *o = &ex->objs[ex->nobjs++]; memset(o, 0, sizeof *o); return o; }
}

/* Hand a malloc'd body to the extractor (freed in _free) and attach to object. */
static void obj_take_body(pcapng_object_extractor_t *ex, pcapng_object_t *o,
                          uint8_t *body, size_t len)
{
  if (ex->nowned == ex->cowned) {
    int nc = ex->cowned ? ex->cowned * 2 : 16;
    ex->owned = realloc(ex->owned, (size_t)nc * sizeof *ex->owned);
    ex->cowned = nc;
  }
  ex->owned[ex->nowned++] = body;
  o->data = body; o->len = len;
}

static void ip_str(uint32_t ip, char *out, size_t n)
{ snprintf(out, n, "%u.%u.%u.%u", (ip>>24)&0xff,(ip>>16)&0xff,(ip>>8)&0xff,ip&0xff); }

/* ── small text helpers ──────────────────────────────────────────────────── */
static int mem_find(const uint8_t *h, int hl, const char *n)
{
  int nl = (int)strlen(n), i;
  for (i = 0; i + nl <= hl; i++) if (memcmp(h + i, n, (size_t)nl) == 0) return i;
  return -1;
}

/* Case-insensitive header lookup within a header block [h,hl). Copies the value
   (trimmed) into out. Returns 1 if found. */
static int header_get(const uint8_t *h, int hl, const char *name, char *out, size_t outsz)
{
  int nl = (int)strlen(name), i = 0;
  out[0] = '\0';
  while (i < hl) {
    int ls = i, le, j;
    while (i < hl && h[i] != '\n') i++;
    le = (i > ls && h[i-1] == '\r') ? i - 1 : i;
    if (i < hl) i++;
    if (le - ls > nl && h[ls + nl] == ':') {
      for (j = 0; j < nl; j++)
        if (tolower(h[ls + j]) != tolower((unsigned char)name[j])) break;
      if (j == nl) {
        int vs = ls + nl + 1, o = 0;
        while (vs < le && (h[vs]==' '||h[vs]=='\t')) vs++;
        while (vs < le && o < (int)outsz - 1) out[o++] = (char)h[vs++];
        while (o > 0 && (out[o-1]==' '||out[o-1]=='\t')) o--;
        out[o] = '\0';
        return 1;
      }
    }
  }
  return 0;
}

/* Sanitize a candidate filename (strip path separators / control chars). */
static void sanitize(char *s)
{
  char *p;
  for (p = s; *p; p++) if (*p=='/'||*p=='\\'||*p<32||*p==':') *p = '_';
  if (!s[0]) strcpy(s, "object");
}

/* Basename of an HTTP request URI (strip query, take last path element). */
static void uri_filename(const char *uri, char *out, size_t outsz)
{
  const char *q = strchr(uri, '?');
  int end = q ? (int)(q - uri) : (int)strlen(uri);
  int start = end;
  while (start > 0 && uri[start-1] != '/') start--;
  if (end - start <= 0) { snprintf(out, outsz, "index.html"); return; }
  snprintf(out, outsz, "%.*s", end - start, uri + start);
}

/* ── HTTP ────────────────────────────────────────────────────────────────── */
typedef struct { char uri[1024]; char host[256]; } http_req_t;

/* Parse the request half-stream into an ordered list of (uri, host). */
static int http_parse_requests(const uint8_t *b, int bl, http_req_t *reqs, int maxreq)
{
  int i = 0, n = 0;
  while (i < bl && n < maxreq) {
    int he, hl, sp1, sp2, cl;
    char lenbuf[32];
    /* request line: METHOD SP URI SP HTTP/1.x CRLF */
    int eol = i; while (eol < bl && b[eol] != '\n') eol++;
    if (eol >= bl) break;
    sp1 = i; while (sp1 < eol && b[sp1] != ' ') sp1++;
    sp2 = sp1 + 1; while (sp2 < eol && b[sp2] != ' ') sp2++;
    /* the token after the URI must be the HTTP version ("HTTP/1.x") */
    if (sp1 >= eol || sp2 >= eol || mem_find(b + sp2 + 1, eol - sp2 - 1, "HTTP/") == -1) {
      /* not a request line here; try to resync at next line */
      i = eol + 1; continue;
    }
    he = mem_find(b + i, bl - i, "\r\n\r\n");
    if (he < 0) break;
    hl = he;                                 /* header length from i */
    snprintf(reqs[n].uri, sizeof reqs[n].uri, "%.*s", sp2 - sp1 - 1, (const char *)(b + sp1 + 1));
    reqs[n].host[0] = '\0';
    header_get(b + i, hl, "Host", reqs[n].host, sizeof reqs[n].host);
    i += he + 4;
    /* skip a request body if Content-Length says so (POST/PUT) */
    if (header_get(b + (i - he - 4), hl, "Content-Length", lenbuf, sizeof lenbuf)) {
      cl = atoi(lenbuf); if (cl > 0 && i + cl <= bl) i += cl;
    }
    n++;
  }
  return n;
}

/* De-chunk an HTTP chunked body starting at b[0..bl). Returns malloc'd buffer
   (caller owns) and *outlen; *consumed = bytes used from the stream. */
static uint8_t *http_dechunk(const uint8_t *b, int bl, size_t *outlen, int *consumed)
{
  uint8_t *out = NULL; size_t olen = 0, ocap = 0; int i = 0;
  for (;;) {
    int eol = i, sz = 0, k;
    while (eol < bl && b[eol] != '\n') eol++;
    if (eol >= bl) break;
    for (k = i; k < eol; k++) {
      int c = b[k];
      if (c==';' || c=='\r') break;
      if (c>='0'&&c<='9') sz=sz*16+(c-'0');
      else if (c>='a'&&c<='f') sz=sz*16+(c-'a'+10);
      else if (c>='A'&&c<='F') sz=sz*16+(c-'A'+10);
      else break;
    }
    i = eol + 1;
    if (sz == 0) { /* trailer up to blank line */ break; }
    if (i + sz > bl) sz = bl - i;
    if (olen + (size_t)sz > ocap) { ocap = (ocap?ocap:1024); while (ocap < olen+sz) ocap*=2;
                                    out = realloc(out, ocap); }
    memcpy(out + olen, b + i, (size_t)sz); olen += sz;
    i += sz;
    if (i + 2 <= bl && b[i]=='\r' && b[i+1]=='\n') i += 2;   /* chunk trailing CRLF */
  }
  *outlen = olen; *consumed = i;
  return out;
}

static void http_extract(pcapng_object_extractor_t *ex, flow_t *f)
{
  int rdir = -1, qdir;
  const uint8_t *rb; int rl, i, ri = 0;
  http_req_t reqs[256]; int nreq = 0;

  /* response half starts with "HTTP/1."; the other half holds requests */
  if (f->len[0] >= 7 && memcmp(f->buf[0], "HTTP/1.", 7) == 0) rdir = 0;
  else if (f->len[1] >= 7 && memcmp(f->buf[1], "HTTP/1.", 7) == 0) rdir = 1;
  if (rdir < 0) return;
  qdir = rdir ^ 1;

  if (f->buf[qdir]) nreq = http_parse_requests(f->buf[qdir], (int)f->len[qdir], reqs, 256);

  rb = f->buf[rdir]; rl = (int)f->len[rdir];
  i = 0;
  while (i + 7 <= rl && memcmp(rb + i, "HTTP/1.", 7) == 0) {
    int he = mem_find(rb + i, rl - i, "\r\n\r\n");
    int hl, body, avail, consumed, complete = 1;
    char ctype[128] = "", clen[32] = "", te[64] = "", disp[256] = "";
    uint8_t *bodyp = NULL; size_t bodylen = 0; int owned = 0;
    pcapng_object_t *o;
    if (he < 0) break;
    hl = he;
    header_get(rb + i, hl, "Content-Type", ctype, sizeof ctype);
    header_get(rb + i, hl, "Content-Length", clen, sizeof clen);
    header_get(rb + i, hl, "Transfer-Encoding", te, sizeof te);
    header_get(rb + i, hl, "Content-Disposition", disp, sizeof disp);
    body = i + he + 4;
    avail = rl - body;
    if (avail < 0) avail = 0;

    if (te[0] && (strstr(te, "chunked") || strstr(te, "Chunked"))) {
      bodyp = http_dechunk(rb + body, avail, &bodylen, &consumed); owned = 1;
      i = body + consumed;
    } else if (clen[0]) {
      int cl = atoi(clen);
      if (cl < 0) cl = 0;
      bodylen = (avail >= cl) ? (size_t)cl : (size_t)avail;
      complete = (avail >= cl);
      bodyp = (uint8_t *)(rb + body);
      i = body + (int)bodylen;
    } else {
      /* no length: take until the next response or end of stream */
      int nxt = mem_find(rb + body, avail, "HTTP/1.");
      bodylen = (nxt >= 0) ? (size_t)nxt : (size_t)avail;
      bodyp = (uint8_t *)(rb + body);
      i = body + (int)bodylen;
    }

    if (bodylen > 0) {
      o = obj_new(ex);
      if (o) {
        char fn[256] = "";
        snprintf(o->proto, sizeof o->proto, "HTTP");
        o->frame = f->frame[rdir];
        o->complete = complete;
        snprintf(o->content_type, sizeof o->content_type, "%s", ctype);
        /* hostname: request Host header, else server IP */
        if (ri < nreq && reqs[ri].host[0]) snprintf(o->hostname, sizeof o->hostname, "%s", reqs[ri].host);
        else ip_str(f->sip[rdir], o->hostname, sizeof o->hostname);   /* rdir src = server */
        /* filename: Content-Disposition, else request URI basename */
        if (disp[0]) {
          const char *fnp = strstr(disp, "filename=");
          if (fnp) { fnp += 9; if (*fnp=='"') fnp++;
                     snprintf(fn, sizeof fn, "%s", fnp);
                     { char *q = strchr(fn, '"'); if (q) *q = '\0'; } }
        }
        if (!fn[0]) {
          if (ri < nreq) uri_filename(reqs[ri].uri, fn, sizeof fn);
          else snprintf(fn, sizeof fn, "%s-%d", o->hostname, o->frame);
        }
        sanitize(fn);
        snprintf(o->filename, sizeof o->filename, "%s", fn);
        if (owned) { obj_take_body(ex, o, bodyp, bodylen); }
        else { uint8_t *cp = malloc(bodylen ? bodylen : 1); if (cp) { memcpy(cp, bodyp, bodylen);
               obj_take_body(ex, o, cp, bodylen); } }
      } else if (owned) free(bodyp);
    } else if (owned) free(bodyp);
    ri++;
    if (i <= body && bodylen == 0) break;   /* no progress guard */
  }
}

/* ── SMB2 (implemented in the next step) ─────────────────────────────────── */
static void smb_extract(pcapng_object_extractor_t *ex, flow_t *f);

/* ── public API ──────────────────────────────────────────────────────────── */
pcapng_object_extractor_t *pcapng_object_extractor_new(pcapng_object_proto_t proto)
{
  pcapng_object_extractor_t *ex = calloc(1, sizeof *ex);
  if (!ex) return NULL;
  ex->proto = proto;
  ex->reasm = pcapng_tcp_reasm_new();
  if (!ex->reasm) { free(ex); return NULL; }
  return ex;
}

void pcapng_object_extractor_add_packet(pcapng_object_extractor_t *ex, int frame,
                                        const uint8_t *data, uint32_t caplen,
                                        uint16_t linktype)
{
  seg_t s;
  if (!ex || !locate_tcp(data, (int)caplen, linktype, &s)) return;
  ex->cur_frame = frame;
  pcapng_tcp_reasm_add(ex->reasm, s.sip, s.dip, s.sport, s.dport, s.seq, s.flags,
                       s.pll > 0 ? s.pl : NULL, (size_t)(s.pll > 0 ? s.pll : 0),
                       reasm_cb, ex);
}

void pcapng_object_extractor_finish(pcapng_object_extractor_t *ex)
{
  int i;
  if (!ex) return;
  for (i = 0; i < ex->nflows; i++) {
    flow_t *f = &ex->flows[i];
    if (!f->used) continue;
    if (ex->proto == PCAPNG_OBJ_HTTP) http_extract(ex, f);
    else if (ex->proto == PCAPNG_OBJ_SMB) smb_extract(ex, f);
  }
}

int pcapng_object_count(const pcapng_object_extractor_t *ex)
{ return ex ? ex->nobjs : 0; }

const pcapng_object_t *pcapng_object_at(const pcapng_object_extractor_t *ex, int i)
{ return (ex && i >= 0 && i < ex->nobjs) ? &ex->objs[i] : NULL; }

void pcapng_object_extractor_free(pcapng_object_extractor_t *ex)
{
  int i;
  if (!ex) return;
  if (ex->reasm) pcapng_tcp_reasm_free(ex->reasm);
  for (i = 0; i < ex->nflows; i++) { free(ex->flows[i].buf[0]); free(ex->flows[i].buf[1]); }
  free(ex->flows);
  for (i = 0; i < ex->nowned; i++) free(ex->owned[i]);
  free(ex->owned);
  free(ex->objs);
  free(ex);
}

/* ── SMB2 file carving ───────────────────────────────────────────────────── */
/* SMB2 reads a file as a series of READ responses; we correlate CREATE (name →
 * FileId) and READ (request FileId/offset → response data) by MessageId, then
 * reassemble each file by offset. SMB1 and encrypted SMB3 are not handled. */

typedef struct { uint64_t mid; char name[512]; } sm_create_t;
typedef struct { uint64_t mid; uint8_t fid[16]; uint64_t off; } sm_read_t;
typedef struct {
  uint8_t  fid[16];
  char     name[512];
  uint8_t *buf; size_t len, cap;   /* len = highest offset+length written */
  uint64_t eof;                    /* declared EndOfFile from CREATE response */
} sm_file_t;

typedef struct {
  sm_create_t *cr; int ncr, ccr;
  sm_read_t   *rd; int nrd, crd;
  sm_file_t   *fl; int nfl, cfl;
} smb_state_t;

static void utf16le_name(const uint8_t *p, int blen, char *out, size_t outsz)
{
  int i, o = 0;
  for (i = 0; i + 1 < blen && o < (int)outsz - 1; i += 2) {
    uint16_t u = (uint16_t)(p[i] | (p[i+1] << 8));
    out[o++] = (u >= 32 && u < 127) ? (char)u : (u == 0 ? 0 : '_');
  }
  out[o] = '\0';
}

static sm_file_t *smb_file_for(smb_state_t *st, const uint8_t *fid)
{
  int i;
  for (i = 0; i < st->nfl; i++) if (memcmp(st->fl[i].fid, fid, 16) == 0) return &st->fl[i];
  if (st->nfl == st->cfl) {
    int nc = st->cfl ? st->cfl * 2 : 8;
    st->fl = realloc(st->fl, (size_t)nc * sizeof *st->fl); st->cfl = nc;
  }
  { sm_file_t *f = &st->fl[st->nfl++]; memset(f, 0, sizeof *f);
    memcpy(f->fid, fid, 16); return f; }
}

static const char *smb_name_for_mid(smb_state_t *st, uint64_t mid)
{ int i; for (i = 0; i < st->ncr; i++) if (st->cr[i].mid == mid) return st->cr[i].name; return NULL; }

static sm_read_t *smb_read_for_mid(smb_state_t *st, uint64_t mid)
{ int i; for (i = 0; i < st->nrd; i++) if (st->rd[i].mid == mid) return &st->rd[i]; return NULL; }

/* Handle one SMB2 PDU (header + body within [hdr, hdr+len)). */
static void smb_pdu(smb_state_t *st, const uint8_t *hdr, int len)
{
  uint16_t cmd; uint32_t flags; uint64_t mid; const uint8_t *body; int bl, resp;
  if (len < 64 || memcmp(hdr, "\xFE" "SMB", 4) != 0) return;
  cmd   = le16(hdr + 12);
  flags = le32(hdr + 16);
  mid   = le64(hdr + 24);
  resp  = flags & 1;              /* SMB2_FLAGS_SERVER_TO_REDIR */
  body  = hdr + 64; bl = len - 64;

  if (cmd == 5) {                 /* CREATE */
    if (!resp) {
      if (bl >= 48) {
        uint16_t noff = le16(body + 44), nlen = le16(body + 46);
        if (noff + nlen <= len && nlen > 0 && st->ncr < 4096) {
          if (st->ncr == st->ccr) { int nc = st->ccr?st->ccr*2:16;
            st->cr = realloc(st->cr, (size_t)nc*sizeof *st->cr); st->ccr = nc; }
          st->cr[st->ncr].mid = mid;
          utf16le_name(hdr + noff, nlen, st->cr[st->ncr].name, sizeof st->cr[st->ncr].name);
          st->ncr++;
        }
      }
    } else if (bl >= 80) {        /* response: FileId at body+64, EndOfFile at body+48 */
      const char *nm = smb_name_for_mid(st, mid);
      sm_file_t *f = smb_file_for(st, body + 64);
      if (nm && !f->name[0]) snprintf(f->name, sizeof f->name, "%s", nm);
      f->eof = le64(body + 48);
    }
  } else if (cmd == 8) {          /* READ */
    if (!resp) {
      if (bl >= 32 && st->nrd < 8192) {
        if (st->nrd == st->crd) { int nc = st->crd?st->crd*2:16;
          st->rd = realloc(st->rd, (size_t)nc*sizeof *st->rd); st->crd = nc; }
        st->rd[st->nrd].mid = mid;
        memcpy(st->rd[st->nrd].fid, body + 16, 16);
        st->rd[st->nrd].off = le64(body + 8);
        st->nrd++;
      }
    } else if (bl >= 16) {        /* response: DataOffset(body+2), DataLength(body+4) */
      uint8_t  doff = body[2];
      uint32_t dlen = le32(body + 4);
      sm_read_t *r = smb_read_for_mid(st, mid);
      if (r && doff + (int)dlen <= len && dlen > 0) {
        sm_file_t *f = smb_file_for(st, r->fid);
        size_t end = (size_t)r->off + dlen;
        if (end > f->cap) { size_t nc = f->cap?f->cap:4096; while (nc<end) nc*=2;
                            f->buf = realloc(f->buf, nc); f->cap = nc; }
        memcpy(f->buf + r->off, hdr + doff, dlen);
        if (end > f->len) f->len = end;
      }
    }
  }
}

/* Walk NBSS-framed SMB2 messages (with compounding) in one half-stream. */
static void smb_parse_half(smb_state_t *st, const uint8_t *b, int bl)
{
  int i = 0;
  while (i + 4 <= bl) {
    int mlen, off;
    if (b[i] != 0x00) break;                       /* NBSS session message only */
    mlen = (b[i+1] << 16) | (b[i+2] << 8) | b[i+3];
    i += 4;
    if (mlen <= 0 || i + mlen > bl) break;
    off = 0;
    while (off + 64 <= mlen) {                      /* SMB2 compound chain */
      uint32_t next;
      if (memcmp(b + i + off, "\xFE" "SMB", 4) != 0) break;
      next = le32(b + i + off + 20);
      smb_pdu(st, b + i + off, next ? (int)next : (mlen - off));
      if (!next) break;
      off += (int)next;
    }
    i += mlen;
  }
}

static void smb_extract(pcapng_object_extractor_t *ex, flow_t *f)
{
  smb_state_t st; int rdir = -1, i;
  memset(&st, 0, sizeof st);

  /* Parse the request side first (so CREATE/READ requests register), then the
     response side. Identify request side = first PDU without the response flag
     (NBSS framing: 4-byte header, then the SMB2 header "\xFESMB"). */
  {
    int req = -1;
    for (i = 0; i < 2; i++) {
      const uint8_t *b = f->buf[i]; int bl = (int)f->len[i];
      if (bl >= 68 && b[0] == 0 && memcmp(b + 4, "\xFE" "SMB", 4) == 0) {
        if ((le32(b + 4 + 16) & 1) == 0) { req = i; }
        else if (rdir < 0) rdir = i;
      }
    }
    if (req >= 0)  smb_parse_half(&st, f->buf[req], (int)f->len[req]);
    if (rdir < 0) rdir = (req == 0) ? 1 : 0;
    smb_parse_half(&st, f->buf[rdir], (int)f->len[rdir]);
  }

  for (i = 0; i < st.nfl; i++) {
    sm_file_t *sf = &st.fl[i];
    pcapng_object_t *o;
    const char *base;
    uint8_t *cp;
    if (sf->len == 0) continue;
    o = obj_new(ex);
    if (!o) continue;
    snprintf(o->proto, sizeof o->proto, "SMB");
    o->frame = f->frame[rdir];
    ip_str(f->sip[rdir], o->hostname, sizeof o->hostname);   /* server */
    o->complete = (sf->eof > 0) ? (sf->len >= sf->eof) : 1;
    base = sf->name;
    { const char *p; for (p = sf->name; *p; p++) if (*p=='\\'||*p=='/') base = p + 1; }
    snprintf(o->filename, sizeof o->filename, "%s", base[0] ? base : "smbfile");
    { char tmp[256]; snprintf(tmp, sizeof tmp, "%s", o->filename);
      sanitize(tmp); snprintf(o->filename, sizeof o->filename, "%s", tmp); }
    cp = malloc(sf->len);
    if (cp) { memcpy(cp, sf->buf, sf->len); obj_take_body(ex, o, cp, sf->len); }
  }

  for (i = 0; i < st.nfl; i++) free(st.fl[i].buf);
  free(st.fl); free(st.cr); free(st.rd);
}
