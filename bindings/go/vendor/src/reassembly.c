#include <stdlib.h>
#include <string.h>

#include <libpcapng/reassembly.h>
#include <libpcapng/protocols/ipv4.h>

#define ETH_HDRLEN    14
#define ETHERTYPE_IP  0x0800

/* IP fragmentation field masks (16-bit frag_off word, network byte order):
 *   bit 15: Reserved
 *   bit 14: DF (Don't Fragment)
 *   bit 13: MF (More Fragments)
 *   bits 12-0: Fragment Offset in 8-byte units */
#define IP_MF       0x2000
#define IP_OFFMASK  0x1FFF

/* ── internal helpers ──────────────────────────────────────────────────────── */

static libpcapng_reasm_entry_t *entry_find(libpcapng_reasm_t *ctx,
    uint32_t src, uint32_t dst, uint8_t proto, uint16_t id)
{
    for (int i = 0; i < LIBPCAPNG_REASM_MAX_DATAGRAMS; i++) {
        libpcapng_reasm_entry_t *e = &ctx->table[i];
        if (e->used
            && e->src_ip == src && e->dst_ip == dst
            && e->proto  == proto && e->ip_id == id)
            return e;
    }
    return NULL;
}

static libpcapng_reasm_entry_t *entry_alloc(libpcapng_reasm_t *ctx,
    uint32_t src, uint32_t dst, uint8_t proto, uint16_t id)
{
    int slot = -1;
    uint32_t oldest_seq = UINT32_MAX;
    int oldest_slot = 0;

    for (int i = 0; i < LIBPCAPNG_REASM_MAX_DATAGRAMS; i++) {
        if (!ctx->table[i].used) { slot = i; break; }
        if (ctx->table[i].birth_seq < oldest_seq) {
            oldest_seq  = ctx->table[i].birth_seq;
            oldest_slot = i;
        }
    }
    if (slot < 0) slot = oldest_slot; /* evict oldest */

    libpcapng_reasm_entry_t *e = &ctx->table[slot];
    memset(e, 0, sizeof(*e));
    e->used      = 1;
    e->src_ip    = src;
    e->dst_ip    = dst;
    e->proto     = proto;
    e->ip_id     = id;
    e->birth_seq = ctx->seq++;
    return e;
}

/* ── public API ────────────────────────────────────────────────────────────── */

libpcapng_reasm_t *libpcapng_reasm_new(void)
{
    return calloc(1, sizeof(libpcapng_reasm_t));
}

void libpcapng_reasm_free(libpcapng_reasm_t *ctx)
{
    free(ctx);
}

int libpcapng_reasm_add(libpcapng_reasm_t *ctx,
                         const uint8_t *pkt, size_t pkt_len,
                         uint8_t **out, size_t *out_len)
{
    if (!ctx || !pkt || !out || !out_len) return -1;
    *out = NULL; *out_len = 0;

    /* ── locate the IPv4 header ── */
    const uint8_t *ip;
    size_t ip_avail;

    if (pkt_len >= 20 && (pkt[0] >> 4) == 4) {
        /* raw IPv4 datagram */
        ip = pkt; ip_avail = pkt_len;
    } else if (pkt_len >= (size_t)(ETH_HDRLEN + 20)) {
        uint16_t etype = (uint16_t)((pkt[12] << 8) | pkt[13]);
        if (etype != ETHERTYPE_IP) return -1;
        ip = pkt + ETH_HDRLEN; ip_avail = pkt_len - ETH_HDRLEN;
    } else {
        return -1;
    }

    if ((ip[0] >> 4) != 4) return -1;

    uint8_t  ihl       = (uint8_t)((ip[0] & 0x0f) * 4);
    if (ihl < 20 || ip_avail < ihl) return -1;

    uint16_t tot_len   = (uint16_t)((ip[2] << 8) | ip[3]);
    uint16_t ip_id     = (uint16_t)((ip[4] << 8) | ip[5]);
    uint16_t frag_word = (uint16_t)((ip[6] << 8) | ip[7]);
    uint16_t frag_off  = (uint16_t)((frag_word & IP_OFFMASK) * 8); /* bytes */
    int      mf        = (frag_word & IP_MF) != 0;
    uint8_t  proto     = ip[9];
    uint32_t src_ip    = (uint32_t)((ip[12] << 24) | (ip[13] << 16) |
                                    (ip[14] <<  8) |  ip[15]);
    uint32_t dst_ip    = (uint32_t)((ip[16] << 24) | (ip[17] << 16) |
                                    (ip[18] <<  8) |  ip[19]);

    /* not fragmented */
    if (!mf && frag_off == 0) return -1;

    uint16_t frag_data = (tot_len > ihl) ? (uint16_t)(tot_len - ihl) : 0;
    if ((uint32_t)frag_off + frag_data > LIBPCAPNG_REASM_MAX_PAYLOAD) return -1;

    /* ── find / create reassembly entry ── */
    libpcapng_reasm_entry_t *e = entry_find(ctx, src_ip, dst_ip, proto, ip_id);
    if (!e) e = entry_alloc(ctx, src_ip, dst_ip, proto, ip_id);

    /* save the first-fragment IP header (needed to reconstruct the output) */
    if (frag_off == 0 && !e->have_first) {
        memcpy(e->ip_hdr, ip, ihl);
        e->ip_hdr_len = ihl;
        e->have_first = 1;
    }

    /* copy payload into reassembly buffer, tracking new bytes */
    const uint8_t *payload = ip + ihl;
    for (uint16_t b = 0; b < frag_data; b++) {
        uint16_t pos = frag_off + b;
        if (!e->recvd[pos]) {
            e->buf[pos]  = payload[b];
            e->recvd[pos] = 1;
            e->bytes_recvd++;
        }
    }

    if (!mf) {
        e->have_last     = 1;
        e->total_data_len = frag_off + frag_data;
    }

    /* ── check for completion ── */
    if (!e->have_last || !e->have_first || e->bytes_recvd < e->total_data_len)
        return 0;

    /* ── build reassembled IPv4 datagram ── */
    uint16_t out_len_val = (uint16_t)(e->ip_hdr_len + e->total_data_len);
    uint8_t *result = malloc(out_len_val);
    if (!result) { e->used = 0; return -1; }

    memcpy(result, e->ip_hdr, e->ip_hdr_len);
    memcpy(result + e->ip_hdr_len, e->buf, e->total_data_len);

    /* fix total length */
    result[2] = (uint8_t)(out_len_val >> 8);
    result[3] = (uint8_t)(out_len_val & 0xff);
    /* clear fragment flags and offset */
    result[6] = 0;
    result[7] = 0;
    /* recalculate IP header checksum */
    result[10] = 0;
    result[11] = 0;
    uint16_t cksum = libpcapng_ip_checksum(result, e->ip_hdr_len);
    result[10] = (uint8_t)(cksum >> 8);
    result[11] = (uint8_t)(cksum & 0xff);

    *out     = result;
    *out_len = out_len_val;
    e->used  = 0;
    return 1;
}
