/* reassembly_tcp.c — passive TCP stream reassembly.
 *
 * Flows are identified and direction-normalized with libpcapng's flow helper;
 * each half-stream buffers payload ordered by the observed TCP sequence numbers.
 * In-order segments are delivered immediately; a bounded set of out-of-order
 * segments is held and drained as the gaps fill. See reassembly_tcp.h.
 */
#include <libpcapng/reassembly_tcp.h>
#include <libpcapng/protocols/flow.h>

#include <stdlib.h>
#include <string.h>

#define HOLD_MAX     16            /* out-of-order segments held per half-stream */
#define BUF_CAP_MAX  (4u << 20)    /* cap cumulative buffer at 4 MiB             */

typedef struct { uint32_t seq; int len; uint8_t *data; } hold_t;

typedef struct {
  int      active;
  uint32_t src_ip, dst_ip;
  uint16_t src_port, dst_port;
  uint32_t next_seq;             /* next in-order sequence number expected */
  int      started;
  uint8_t *buf;
  int      buf_len, buf_cap;
  hold_t   holds[HOLD_MAX];
  int      nholds;
} half_t;

typedef struct {
  int      used;
  uint32_t a_ip, b_ip;
  uint16_t a_port, b_port;
  half_t   half[2];              /* [0] = A→B, [1] = B→A */
} flow_t;

struct pcapng_tcp_reasm {
  flow_t *flows;
  int     n, cap;
};

pcapng_tcp_reasm_t *pcapng_tcp_reasm_new(void)
{
  return calloc(1, sizeof(pcapng_tcp_reasm_t));
}

static void half_free(half_t *h)
{
  int i;
  free(h->buf);
  for (i = 0; i < h->nholds; i++) free(h->holds[i].data);
}

void pcapng_tcp_reasm_free(pcapng_tcp_reasm_t *r)
{
  int i;
  if (!r) return;
  for (i = 0; i < r->n; i++) {
    half_free(&r->flows[i].half[0]);
    half_free(&r->flows[i].half[1]);
  }
  free(r->flows);
  free(r);
}

static flow_t *flow_find(pcapng_tcp_reasm_t *r, uint32_t a_ip, uint16_t a_port,
                         uint32_t b_ip, uint16_t b_port)
{
  int i;
  for (i = 0; i < r->n; i++) {
    flow_t *f = &r->flows[i];
    if (f->used && f->a_ip == a_ip && f->a_port == a_port &&
        f->b_ip == b_ip && f->b_port == b_port)
      return f;
  }
  if (r->n == r->cap) {
    int nc = r->cap ? r->cap * 2 : 64;
    flow_t *nf = realloc(r->flows, (size_t)nc * sizeof *nf);
    if (!nf) return NULL;
    memset(nf + r->cap, 0, (size_t)(nc - r->cap) * sizeof *nf);
    r->flows = nf;
    r->cap = nc;
  }
  {
    flow_t *f = &r->flows[r->n++];
    memset(f, 0, sizeof *f);
    f->used = 1;
    f->a_ip = a_ip; f->a_port = a_port; f->b_ip = b_ip; f->b_port = b_port;
    return f;
  }
}

static void buf_append(half_t *h, const uint8_t *d, int n)
{
  if (n <= 0) return;
  if (h->buf_len + n > h->buf_cap) {
    int nc = h->buf_cap ? h->buf_cap : 4096;
    while (nc < h->buf_len + n && (unsigned)nc < BUF_CAP_MAX) nc *= 2;
    if ((unsigned)nc > BUF_CAP_MAX) nc = BUF_CAP_MAX;
    if (nc > h->buf_cap) {
      uint8_t *nb = realloc(h->buf, (size_t)nc);
      if (!nb) return;
      h->buf = nb; h->buf_cap = nc;
    }
  }
  if (h->buf_len + n > h->buf_cap) n = h->buf_cap - h->buf_len;  /* capped */
  if (n <= 0) return;
  memcpy(h->buf + h->buf_len, d, (size_t)n);
  h->buf_len += n;
}

static void drain_holds(half_t *h, pcapng_tcp_stream_cb cb, void *ud, int dir)
{
  int progressed = 1;
  while (progressed) {
    int i;
    progressed = 0;
    for (i = 0; i < h->nholds; i++) {
      hold_t *hd = &h->holds[i];
      if (hd->seq == h->next_seq) {
        buf_append(h, hd->data, hd->len);
        h->next_seq += (uint32_t)hd->len;
        if (cb)
          cb(ud, h->src_ip, h->src_port, h->dst_ip, h->dst_port,
             dir, hd->data, (size_t)hd->len, h->buf, (size_t)h->buf_len);
        free(hd->data);
        h->holds[i] = h->holds[--h->nholds];
        progressed = 1;
        break;
      }
      if ((int32_t)(hd->seq + hd->len - h->next_seq) <= 0) {  /* already consumed */
        free(hd->data);
        h->holds[i] = h->holds[--h->nholds];
        progressed = 1;
        break;
      }
    }
  }
}

static void hold_add(half_t *h, uint32_t seq, const uint8_t *d, int n)
{
  hold_t *hd;
  int i;
  for (i = 0; i < h->nholds; i++) if (h->holds[i].seq == seq) return;  /* dup */
  if (h->nholds == HOLD_MAX) {     /* evict the highest-seq hold */
    int worst = 0;
    for (i = 1; i < h->nholds; i++)
      if ((int32_t)(h->holds[i].seq - h->holds[worst].seq) > 0) worst = i;
    free(h->holds[worst].data);
    h->holds[worst] = h->holds[--h->nholds];
  }
  hd = &h->holds[h->nholds++];
  hd->seq = seq;
  hd->len = n;
  hd->data = malloc((size_t)n);
  if (hd->data) memcpy(hd->data, d, (size_t)n);
  else h->nholds--;
}

void pcapng_tcp_reasm_add(pcapng_tcp_reasm_t *r,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint32_t seq, uint8_t tcp_flags,
                          const uint8_t *payload, size_t payload_len,
                          pcapng_tcp_stream_cb cb, void *userdata)
{
  uint32_t a_ip, b_ip;
  uint16_t a_port, b_port;
  uint8_t from_a;
  flow_t *f;
  half_t *h;
  int dir, paylen = (int)payload_len;

  if (!r) return;

  from_a = libpcapng_normalize_flow_direction(src_ip, dst_ip, src_port, dst_port,
                                              &a_ip, &b_ip, &a_port, &b_port);
  f = flow_find(r, a_ip, a_port, b_ip, b_port);
  if (!f) return;
  dir = from_a ? 0 : 1;
  h = &f->half[dir];

  if (!h->active) {
    h->active = 1;
    h->src_ip = src_ip; h->dst_ip = dst_ip;
    h->src_port = src_port; h->dst_port = dst_port;
  }

  /* Anchor the stream origin: a SYN's sequence is the byte before the first
     data byte; otherwise the first segment seen anchors next_seq. */
  if (!h->started) {
    h->started = 1;
    h->next_seq = seq + ((tcp_flags & LIBPCAPNG_TCP_SYN) ? 1u : 0u);
  }

  if (paylen <= 0) return;  /* pure ACK / control */

  if (seq == h->next_seq) {
    buf_append(h, payload, paylen);
    h->next_seq += (uint32_t)paylen;
    if (cb) cb(userdata, h->src_ip, h->src_port, h->dst_ip, h->dst_port,
               dir, payload, (size_t)paylen, h->buf, (size_t)h->buf_len);
    drain_holds(h, cb, userdata, dir);
  } else if ((int32_t)(seq - h->next_seq) > 0) {
    hold_add(h, seq, payload, paylen);   /* future segment */
  } else {
    uint32_t already = h->next_seq - seq;  /* overlap / retransmission */
    if ((int)already < paylen) {
      const uint8_t *tail = payload + already;
      int tlen = paylen - (int)already;
      buf_append(h, tail, tlen);
      h->next_seq += (uint32_t)tlen;
      if (cb) cb(userdata, h->src_ip, h->src_port, h->dst_ip, h->dst_port,
                 dir, tail, (size_t)tlen, h->buf, (size_t)h->buf_len);
      drain_holds(h, cb, userdata, dir);
    }
  }
}
