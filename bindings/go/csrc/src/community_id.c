/* community_id.c — Community ID v1 (github.com/corelight/community-id-spec).
 *
 * id = "1:" + base64( SHA1( seed | addr_lo | addr_hi | proto | 0x00
 *                           [ | port_lo | port_hi ] ) )
 *
 * where the (addr,port) endpoints are ordered so the lower one comes first,
 * making the value independent of capture direction. SHA1 and base64 are the
 * only primitives needed, so both are kept here to avoid a crypto dependency. */
#include <libpcapng/community_id.h>
#include <string.h>

/* ── SHA1 (public-domain style, RFC 3174) ──────────────────────────────────── */
typedef struct { uint32_t h[5]; uint64_t len; uint8_t buf[64]; int n; } sha1_t;

static uint32_t rol(uint32_t v, int b) { return (v << b) | (v >> (32 - b)); }

static void sha1_block(sha1_t *s, const uint8_t *p)
{
  uint32_t w[80], a, b, c, d, e, f, k, t;
  int i;
  for (i = 0; i < 16; i++)
    w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
           ((uint32_t)p[i*4+2] << 8) | p[i*4+3];
  for (i = 16; i < 80; i++) w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
  a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3]; e = s->h[4];
  for (i = 0; i < 80; i++) {
    if      (i < 20) { f = (b & c) | (~b & d);          k = 0x5A827999; }
    else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
    else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
    else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
    t = rol(a, 5) + f + e + k + w[i];
    e = d; d = c; c = rol(b, 30); b = a; a = t;
  }
  s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e;
}

static void sha1_init(sha1_t *s)
{
  s->h[0] = 0x67452301; s->h[1] = 0xEFCDAB89; s->h[2] = 0x98BADCFE;
  s->h[3] = 0x10325476; s->h[4] = 0xC3D2E1F0; s->len = 0; s->n = 0;
}

static void sha1_update(sha1_t *s, const uint8_t *p, size_t len)
{
  s->len += len;
  while (len) {
    int c = 64 - s->n; if ((size_t)c > len) c = (int)len;
    memcpy(s->buf + s->n, p, (size_t)c);
    s->n += c; p += c; len -= (size_t)c;
    if (s->n == 64) { sha1_block(s, s->buf); s->n = 0; }
  }
}

static void sha1_final(sha1_t *s, uint8_t out[20])
{
  uint64_t bits = s->len * 8;
  uint8_t pad = 0x80;
  int i;
  sha1_update(s, &pad, 1);
  pad = 0x00;
  while (s->n != 56) sha1_update(s, &pad, 1);
  for (i = 7; i >= 0; i--) { uint8_t b = (uint8_t)(bits >> (i*8)); sha1_update(s, &b, 1); }
  for (i = 0; i < 5; i++) {
    out[i*4]   = (uint8_t)(s->h[i] >> 24); out[i*4+1] = (uint8_t)(s->h[i] >> 16);
    out[i*4+2] = (uint8_t)(s->h[i] >> 8);  out[i*4+3] = (uint8_t)(s->h[i]);
  }
}

/* ── base64 ─────────────────────────────────────────────────────────────────── */
static void b64(const uint8_t *in, int n, char *out)
{
  static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int i = 0, o = 0;
  while (i < n) {
    uint32_t v = (uint32_t)in[i++] << 16;
    int rem = n - i;                      /* bytes still to consume after the first */
    if (i < n) v |= (uint32_t)in[i++] << 8;
    if (i < n) v |= in[i++];
    out[o++] = t[(v >> 18) & 0x3F];
    out[o++] = t[(v >> 12) & 0x3F];
    out[o++] = rem >= 1 ? t[(v >> 6) & 0x3F] : '=';
    out[o++] = rem >= 2 ? t[v & 0x3F]        : '=';
  }
  out[o] = '\0';
}

void pcapng_community_id(uint8_t proto,
                        const uint8_t *saddr, const uint8_t *daddr, int addrlen,
                        uint16_t sport, uint16_t dport, uint16_t seed,
                        char *out, size_t outlen)
{
  const uint8_t *a1 = saddr, *a2 = daddr;
  uint16_t p1 = sport, p2 = dport;
  uint8_t msg[2 + 16 + 16 + 1 + 1 + 2 + 2], dg[20];
  char enc[32];
  int n = 0, cmp;

  if (!out || outlen < 4) { if (out && outlen) out[0] = '\0'; return; }
  if (addrlen != 4 && addrlen != 16) { out[0] = '\0'; return; }

  /* canonical order: smaller (addr,port) endpoint first → direction-independent */
  cmp = memcmp(saddr, daddr, (size_t)addrlen);
  if (cmp > 0 || (cmp == 0 && sport > dport)) {
    a1 = daddr; a2 = saddr; p1 = dport; p2 = sport;
  }

  msg[n++] = (uint8_t)(seed >> 8); msg[n++] = (uint8_t)seed;
  memcpy(msg + n, a1, (size_t)addrlen); n += addrlen;
  memcpy(msg + n, a2, (size_t)addrlen); n += addrlen;
  msg[n++] = proto;
  msg[n++] = 0;                                   /* padding byte */
  if (proto == 6 || proto == 17 || proto == 132 || proto == 33) { /* TCP/UDP/SCTP/DCCP */
    msg[n++] = (uint8_t)(p1 >> 8); msg[n++] = (uint8_t)p1;
    msg[n++] = (uint8_t)(p2 >> 8); msg[n++] = (uint8_t)p2;
  }

  { sha1_t s; sha1_init(&s); sha1_update(&s, msg, (size_t)n); sha1_final(&s, dg); }
  b64(dg, 20, enc);
  if (outlen < 3 + strlen(enc)) { out[0] = '\0'; return; }
  out[0] = '1'; out[1] = ':';
  memcpy(out + 2, enc, strlen(enc) + 1);
}
