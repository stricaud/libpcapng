/* pcapsh_io.c — packet I/O, serialization, dissection, display, ls()
 * Included as part of the pcapsh unity build (see pcapsh.c). */
#include "pcapsh.h"

/* ─── DNS layer serializer ──────────────────────────────────────────────────── */

size_t serialize_dns_layer(layer_t *l, uint8_t *out, size_t max) {
    size_t n = 0;
    uint16_t id      = (uint16_t)get_u64(l, "id",      1);
    uint16_t flags   = (uint16_t)get_u64(l, "flags",   0);
    uint16_t qdcount = (uint16_t)get_u64(l, "qdcount", 0);
    uint16_t ancount = (uint16_t)get_u64(l, "ancount", 0);
    uint16_t nscount = (uint16_t)get_u64(l, "nscount", 0);
    uint16_t arcount = (uint16_t)get_u64(l, "arcount", 0);
    if (n+12 > max) return 0;
    out[n++]=(id>>8)&0xff;      out[n++]=id&0xff;
    out[n++]=(flags>>8)&0xff;   out[n++]=flags&0xff;
    out[n++]=(qdcount>>8)&0xff; out[n++]=qdcount&0xff;
    out[n++]=(ancount>>8)&0xff; out[n++]=ancount&0xff;
    out[n++]=(nscount>>8)&0xff; out[n++]=nscount&0xff;
    out[n++]=(arcount>>8)&0xff; out[n++]=arcount&0xff;
    const char *secs[] = { "_qd", "_an", "_ns", "_ar" };
    for (int i = 0; i < 4; i++) {
        field_t *f = find_field(l, secs[i]);
        if (f && f->type==FT_BYTES && f->raw && f->raw_len && n+f->raw_len <= max) {
            memcpy(out+n, f->raw, f->raw_len); n += f->raw_len;
        }
    }
    return n;
}

/* ─── Hex utilities ─────────────────────────────────────────────────────────── */

int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse hex dump string into bytes. Handles three formats:
 *   - Plain stream:        "4500003c..."
 *   - Space-separated:     "45 00 00 3c ..."
 *   - Wireshark multi-line:"0000   45 00 00 3c ...   E..<"
 * Returns number of bytes written. */
size_t fromhex_parse(const char *s, uint8_t *out, size_t max) {
    size_t n = 0;
    const char *p = s;
    while (*p && n < max) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (!*p) break;
        /* Wireshark-style line: 4 hex digits at column 0 followed by spaces = offset, skip it */
        if (hexval(p[0]) >= 0 && hexval(p[1]) >= 0 &&
            hexval(p[2]) >= 0 && hexval(p[3]) >= 0 &&
            (p[4] == ' ' || p[4] == '\t')) {
            p += 4;
            while (*p == ' ' || *p == '\t') p++;
        }
        while (*p && *p != '\n' && *p != '\r' && n < max) {
            if (p[0]==' ' && p[1]==' ' && p[2]==' ') break;
            if (*p == ' ' || *p == '\t') { p++; continue; }
            int hi = hexval(p[0]);
            int lo = hexval(p[1]);
            if (hi < 0 || lo < 0) break;
            out[n++] = (uint8_t)((hi << 4) | lo);
            p += 2;
        }
        while (*p && *p != '\n') p++;
    }
    return n;
}

/* ─── frompcapng ────────────────────────────────────────────────────────────── */

int frompcapng_cb(uint32_t block_counter, uint32_t block_type,
                         uint32_t block_total_length, unsigned char *data,
                         void *userdata)
{
    (void)block_counter;
    frompcapng_ctx_t *ctx = (frompcapng_ctx_t *)userdata;

    if (block_type != PCAPNG_ENHANCED_PACKET_BLOCK &&
        block_type != PCAPNG_SIMPLE_PACKET_BLOCK   &&
        block_type != PCAPNG_PACKET_BLOCK)
        return 0;

    ctx->seen++;
    if (ctx->seen != ctx->target) return 0;

    uint32_t cap_len = 0;
    uint32_t hdr_offset = 0;

    if (block_type == PCAPNG_ENHANCED_PACKET_BLOCK) {
        if (block_total_length < 8 + 20) return 0;
        pcapng_enhanced_packet_block_light_t *epb =
            (pcapng_enhanced_packet_block_light_t *)data;
        cap_len    = epb->captured_packet_length;
        hdr_offset = (uint32_t)sizeof(pcapng_enhanced_packet_block_light_t);
    } else if (block_type == PCAPNG_SIMPLE_PACKET_BLOCK) {
        if (block_total_length < 8 + 4) return 0;
        cap_len    = block_total_length - 16;
        hdr_offset = 4;
    } else {
        if (block_total_length < 8 + 20) return 0;
        cap_len    = *(uint32_t *)(data + 12);
        hdr_offset = 20;
    }

    if (cap_len > 65535) cap_len = 65535;
    size_t avail = block_total_length - 8 - hdr_offset;
    if (cap_len > avail) cap_len = (uint32_t)avail;

    memcpy(ctx->buf, data + hdr_offset, cap_len);
    ctx->buf_len = cap_len;
    return 0;
}

/* Read packet number 'pktnum' (1-based) from a pcapng file.
 * Returns a malloc'd buffer (caller must free), or NULL on error. */
uint8_t *frompcapng_read(const char *filename, uint32_t pktnum, size_t *out_len)
{
    *out_len = 0;
    if (!filename || pktnum == 0) return NULL;

    uint8_t *buf = malloc(65535);
    if (!buf) return NULL;

    frompcapng_ctx_t ctx = { .target = pktnum, .seen = 0, .buf = buf, .buf_len = 0 };
    libpcapng_file_read((char *)filename, frompcapng_cb, &ctx);

    if (ctx.buf_len == 0) {
        free(buf);
        if (ctx.seen < pktnum)
            fprintf(stderr, CBRED "frompcapng: file has %u packet(s), requested #%u\n" CR,
                    ctx.seen, pktnum);
        else
            fprintf(stderr, CBRED "frompcapng: packet #%u has zero bytes\n" CR, pktnum);
        return NULL;
    }

    *out_len = ctx.buf_len;
    return buf;
}

/* ─── replacepkt ────────────────────────────────────────────────────────────── */

/* Replace packet number 'pktnum' (1-based) in 'filename' with 'new_bytes'.
 * The file is updated in-place via a temp file + rename. */
int replacepkt_in_file(const char *filename, uint32_t pktnum,
                               const uint8_t *new_bytes, size_t new_len)
{
    FILE *src = fopen(filename, "rb");
    if (!src) { perror("replacepkt: open"); return -1; }

    char tmpname[520];
    snprintf(tmpname, sizeof(tmpname), "%s.pcapsh_tmp", filename);
    FILE *dst = fopen(tmpname, "wb");
    if (!dst) { perror("replacepkt: tmpfile"); fclose(src); return -1; }

    uint32_t pkt_seen = 0;
    int replaced = 0;
    uint8_t hdr[8];
    uint8_t *body = NULL;
    size_t body_alloc = 0;

    while (fread(hdr, 1, 8, src) == 8) {
        uint32_t block_type, block_total_length;
        memcpy(&block_type,         hdr,     4);
        memcpy(&block_total_length, hdr + 4, 4);

        if (block_total_length < 12) {
            fprintf(stderr, CBRED "replacepkt: corrupt block (type=0x%08x len=%u)\n" CR,
                    block_type, block_total_length);
            break;
        }

        size_t body_len = block_total_length - 8;
        if (body_len > body_alloc) {
            free(body);
            body = malloc(body_len);
            if (!body) { fprintf(stderr, CBRED "replacepkt: malloc failed\n" CR); break; }
            body_alloc = body_len;
        }
        if (fread(body, 1, body_len, src) != body_len) break;

        int is_pkt = (block_type == PCAPNG_ENHANCED_PACKET_BLOCK ||
                      block_type == PCAPNG_SIMPLE_PACKET_BLOCK   ||
                      block_type == PCAPNG_PACKET_BLOCK);
        if (is_pkt) pkt_seen++;

        if (is_pkt && pkt_seen == pktnum) {
            libpcapng_write_enhanced_packet_to_file(dst, (unsigned char *)new_bytes, new_len);
            replaced = 1;
        } else {
            fwrite(hdr,  1, 8,        dst);
            fwrite(body, 1, body_len, dst);
        }
    }

    free(body);
    fclose(src);
    fclose(dst);

    if (!replaced) {
        fprintf(stderr, CBRED "replacepkt: file has %u packet(s), requested #%u\n" CR,
                pkt_seen, pktnum);
        remove(tmpname);
        return -1;
    }

    if (rename(tmpname, filename) != 0) {
        perror("replacepkt: rename");
        remove(tmpname);
        return -1;
    }
    return 0;
}

/* ─── Dissect raw bytes according to a pdef ─────────────────────────────────── */

void dissect_pdef_layer(pdef_t *def, const uint8_t *data, size_t len) {
    if (!def || !data || len == 0) { printf("<empty>|\n"); return; }

    struct { char name[64]; uint64_t val; } pv[MAX_PFLDS];
    int npv = 0;

    printf(CBOLD "<%s " CR, def->pname);
    size_t off = 0;
    for (int i = 0; i < def->nflds; i++) {
        pfld_t *f = &def->flds[i];

        if (f->ftype != PFT_PAYLOAD && f->ftype != PFT_BYTES_REF && off >= len) {
            printf(CWHT "%s=?" CR " ", f->fname);
            continue;
        }

        uint64_t v = 0;
        size_t consumed = 0;
        switch (f->ftype) {
            case PFT_U8:
                v = data[off]; consumed = 1; break;
            case PFT_U16:
                if (off+2 <= len) v = ((uint64_t)data[off]<<8)|data[off+1];
                consumed = 2; break;
            case PFT_U32:
                if (off+4 <= len)
                    v = ((uint64_t)data[off]<<24)|((uint64_t)data[off+1]<<16)|
                        ((uint64_t)data[off+2]<<8)|data[off+3];
                consumed = 4; break;
            case PFT_U64:
                if (off+8 <= len) { for (int b=0;b<8;b++) v = (v<<8)|data[off+b]; }
                consumed = 8; break;
            case PFT_LE_U16:
                if (off+2 <= len) v = (uint64_t)data[off]|((uint64_t)data[off+1]<<8);
                consumed = 2; break;
            case PFT_LE_U32:
                if (off+4 <= len)
                    v = (uint64_t)data[off]|((uint64_t)data[off+1]<<8)|
                        ((uint64_t)data[off+2]<<16)|((uint64_t)data[off+3]<<24);
                consumed = 4; break;
            case PFT_LE_U64:
                if (off+8 <= len) { for (int b=0;b<8;b++) v |= ((uint64_t)data[off+b])<<(8*b); }
                consumed = 8; break;
            case PFT_IP4: {
                if (off+4 <= len) {
                    printf(CWHT "%s" CR "=%u.%u.%u.%u ",
                           f->fname, data[off], data[off+1], data[off+2], data[off+3]);
                    off += 4;
                }
                continue;
            }
            case PFT_MAC: {
                if (off+6 <= len) {
                    printf(CWHT "%s" CR "=%02x:%02x:%02x:%02x:%02x:%02x ",
                           f->fname,
                           data[off],data[off+1],data[off+2],
                           data[off+3],data[off+4],data[off+5]);
                    off += 6;
                }
                continue;
            }
            case PFT_BYTES: {
                size_t nb = f->nbytes < (len-off) ? f->nbytes : (len-off);
                printf(CWHT "%s" CR "=<bytes[%zu]> ", f->fname, nb);
                off += nb;
                continue;
            }
            case PFT_STR: {
                size_t avail_str = len - off;
                const char *sv = (const char *)(data + off);
                size_t sl = strnlen(sv, avail_str);
                int print_len = (sl > (size_t)INT_MAX) ? INT_MAX : (int)sl;
                printf(CWHT "%s" CR "='%.*s' ", f->fname, print_len, sv);
                off += sl + (sl < avail_str ? 1 : 0);
                if (off > len) off = len;
                continue;
            }
            case PFT_PAYLOAD: {
                size_t remaining = len - off;
                int is_text = (remaining > 0);
                for (size_t k = 0; k < remaining && is_text; k++)
                    if (!isprint((unsigned char)data[off+k]) &&
                        !isspace((unsigned char)data[off+k])) is_text = 0;
                int print_len = (remaining > (size_t)INT_MAX) ? INT_MAX : (int)remaining;
                if (is_text)
                    printf(CWHT "%s" CR "='%.*s' ", f->fname, print_len, (const char*)(data+off));
                else {
                    printf(CWHT "%s" CR "=<", f->fname);
                    for (size_t k = 0; k < remaining; k++) printf("%02x", data[off+k]);
                    printf("> ");
                }
                off = len;
                continue;
            }
            case PFT_BYTES_REF: {
                size_t blen = 0;
                if (f->lenfield[0]) {
                    for (int k = 0; k < npv; k++) {
                        if (!strcasecmp(pv[k].name, f->lenfield)) {
                            uint64_t raw = pv[k].val;
                            blen = (raw > 65535u) ? 65535u : (size_t)raw;
                            break;
                        }
                    }
                }
                size_t avail = len - off;
                if (blen > avail) blen = avail;
                int is_text = (blen > 0);
                for (size_t k = 0; k < blen && is_text; k++)
                    if (!isprint((unsigned char)data[off+k]) &&
                        !isspace((unsigned char)data[off+k])) is_text = 0;
                int print_len = (blen > (size_t)INT_MAX) ? INT_MAX : (int)blen;
                if (is_text)
                    printf(CWHT "%s" CR "='%.*s' ", f->fname, print_len, (const char*)(data+off));
                else {
                    printf(CWHT "%s" CR "=<", f->fname);
                    for (size_t k = 0; k < blen; k++) printf("%02x", data[off+k]);
                    printf("> ");
                }
                off += blen;
                if (off > len) off = len;
                continue;
            }
        }
        const char *ename = NULL;
        for (int j = 0; j < f->nevals; j++)
            if (f->evals[j].val == v) { ename = f->evals[j].name; break; }
        if (ename)
            printf(CWHT "%s" CR "=%s(%"PRIu64") ", f->fname, ename, v);
        else
            printf(CWHT "%s" CR "=%"PRIu64" ", f->fname, v);
        if (npv < MAX_PFLDS) {
            strncpy(pv[npv].name, f->fname, 63);
            pv[npv].val = v;
            npv++;
        }
        off += consumed;
        if (off > len) { off = len; break; }
    }
    printf("|\n");
    if (off < len)
        printf(CWHT "  +%zu trailing byte(s)\n" CR, len - off);
}

/* ─── Per-protocol show helpers ─────────────────────────────────────────────── */

size_t show_ether_layer(const uint8_t *d, size_t avail) {
    if (avail < 14) {
        fprintf(stderr, CBRED "show: Ether needs 14 bytes, got %zu\n" CR, avail);
        return 0;
    }
    printf(CBYEL "<Ether " CR
           CWHT "dst" CR "=%02x:%02x:%02x:%02x:%02x:%02x "
           CWHT "src" CR "=%02x:%02x:%02x:%02x:%02x:%02x "
           CWHT "type" CR "=0x%04x |\n",
           d[0],d[1],d[2],d[3],d[4],d[5],
           d[6],d[7],d[8],d[9],d[10],d[11],
           (unsigned)((d[12]<<8)|d[13]));
    return 14;
}

size_t show_ip_layer(const uint8_t *d, size_t avail) {
    if (avail < 20) {
        fprintf(stderr, CBRED "show: IP needs 20 bytes, got %zu\n" CR, avail);
        return 0;
    }
    size_t ihl = (size_t)((d[0] & 0x0f) * 4);
    if (ihl < 20) ihl = 20;
    uint8_t proto = d[9];
    const char *pname = (proto==6) ? "TCP" : (proto==17) ? "UDP" : (proto==1) ? "ICMP" : "?";
    printf(CBCYN "<IP " CR
           CWHT "src" CR "=%u.%u.%u.%u "
           CWHT "dst" CR "=%u.%u.%u.%u "
           CWHT "ttl" CR "=%u "
           CWHT "proto" CR "=%u(%s) "
           CWHT "len" CR "=%u |\n",
           d[12],d[13],d[14],d[15],
           d[16],d[17],d[18],d[19],
           d[8], proto, pname,
           (unsigned)((d[2]<<8)|d[3]));
    return ihl;
}

size_t show_tcp_layer(const uint8_t *d, size_t avail) {
    if (avail < 20) {
        fprintf(stderr, CBRED "show: TCP needs 20 bytes, got %zu\n" CR, avail);
        return 0;
    }
    size_t doff = (size_t)(((d[12] >> 4) & 0x0f) * 4);
    if (doff < 20) doff = 20;
    uint8_t fl = d[13];
    char fstr[8] = {0}; int fi = 0;
    if (fl & 0x02) fstr[fi++] = 'S';
    if (fl & 0x10) fstr[fi++] = 'A';
    if (fl & 0x08) fstr[fi++] = 'P';
    if (fl & 0x01) fstr[fi++] = 'F';
    if (fl & 0x04) fstr[fi++] = 'R';
    if (fl & 0x20) fstr[fi++] = 'U';
    if (!fi) { fstr[0]='0'; fi=1; }
    fstr[fi] = '\0';
    uint32_t seq = ((uint32_t)d[4]<<24)|((uint32_t)d[5]<<16)|((uint32_t)d[6]<<8)|d[7];
    uint32_t ack = ((uint32_t)d[8]<<24)|((uint32_t)d[9]<<16)|((uint32_t)d[10]<<8)|d[11];
    printf(CBGRN "<TCP " CR
           CWHT "sport" CR "=%u "
           CWHT "dport" CR "=%u "
           CWHT "seq" CR "=%u "
           CWHT "ack" CR "=%u "
           CWHT "flags" CR "=%s |\n",
           (unsigned)((d[0]<<8)|d[1]),
           (unsigned)((d[2]<<8)|d[3]),
           seq, ack, fstr);
    return doff;
}

size_t show_udp_layer(const uint8_t *d, size_t avail) {
    if (avail < 8) {
        fprintf(stderr, CBRED "show: UDP needs 8 bytes, got %zu\n" CR, avail);
        return 0;
    }
    printf(CBMAG "<UDP " CR
           CWHT "sport" CR "=%u "
           CWHT "dport" CR "=%u "
           CWHT "len" CR "=%u |\n",
           (unsigned)((d[0]<<8)|d[1]),
           (unsigned)((d[2]<<8)|d[3]),
           (unsigned)((d[4]<<8)|d[5]));
    return 8;
}

size_t show_icmp_layer(const uint8_t *d, size_t avail) {
    if (avail < 8) {
        fprintf(stderr, CBRED "show: ICMP needs 8 bytes, got %zu\n" CR, avail);
        return 0;
    }
    const char *tname = (d[0]==0) ? "Echo Reply" : (d[0]==8) ? "Echo Request" :
                        (d[0]==3) ? "Dest Unreachable" : (d[0]==11) ? "Time Exceeded" : "?";
    printf(CBRED "<ICMP " CR
           CWHT "type" CR "=%u(%s) "
           CWHT "code" CR "=%u "
           CWHT "id" CR "=%u "
           CWHT "seq" CR "=%u |\n",
           d[0], tname, d[1],
           (unsigned)((d[4]<<8)|d[5]),
           (unsigned)((d[6]<<8)|d[7]));
    return 8;
}

size_t show_dns_layer(const uint8_t *d, size_t avail) {
    if (avail < 12) {
        fprintf(stderr, CBRED "show: DNS needs 12 bytes, got %zu\n" CR, avail);
        return 0;
    }
    printf(CBCYN "<DNS " CR
           CWHT "id" CR "=%u "
           CWHT "flags" CR "=0x%04x "
           CWHT "qdcount" CR "=%u "
           CWHT "ancount" CR "=%u "
           CWHT "nscount" CR "=%u "
           CWHT "arcount" CR "=%u |\n",
           (unsigned)(((uint16_t)d[0]<<8)|d[1]),
           (unsigned)(((uint16_t)d[2]<<8)|d[3]),
           (unsigned)(((uint16_t)d[4]<<8)|d[5]),
           (unsigned)(((uint16_t)d[6]<<8)|d[7]),
           (unsigned)(((uint16_t)d[8]<<8)|d[9]),
           (unsigned)(((uint16_t)d[10]<<8)|d[11]));
    return avail;
}

/* Dispatch to a sub-protocol by reading the first field value. */
int dispatch_by_parent(const char *parent, const uint8_t *data, size_t len) {
    size_t field_width = 2;
    for (int i = 0; i < npdefs; i++) {
        if (pdefs[i].parent[0] && !strcasecmp(pdefs[i].parent, parent) && pdefs[i].nflds > 0) {
            switch (pdefs[i].flds[0].ftype) {
                case PFT_U8:  field_width = 1; break;
                case PFT_U32: field_width = 4; break;
                case PFT_U64: field_width = 8; break;
                default:      field_width = 2; break;
            }
            break;
        }
    }
    if (len < field_width) {
        fprintf(stderr, CBRED "show: '%s': truncated (%zu bytes)\n" CR, parent, len);
        return 0;
    }
    uint64_t v = 0;
    for (size_t b = 0; b < field_width; b++) v = (v << 8) | data[b];

    for (int i = 0; i < npdefs; i++) {
        pdef_t *sub = &pdefs[i];
        if (!sub->parent[0] || strcasecmp(sub->parent, parent) != 0) continue;
        if (sub->nflds == 0) continue;
        if (sub->flds[0].defnum == v) {
            dissect_pdef_layer(sub, data, len);
            return 1;
        }
    }
    fprintf(stderr, CBRED "show: '%s': no sub-protocol matches value %"PRIu64"\n" CR, parent, v);
    return 0;
}

int has_sub_protocols(const char *name) {
    for (int i = 0; i < npdefs; i++)
        if (pdefs[i].parent[0] && !strcasecmp(pdefs[i].parent, name)) return 1;
    return 0;
}

/* Dispatch a single named layer; returns bytes consumed (0 = error). */
size_t show_layer_by_name(const char *proto, const uint8_t *d, size_t avail) {
    if (!strcasecmp(proto,"Ether") || !strcasecmp(proto,"Ethernet")) return show_ether_layer(d, avail);
    if (!strcasecmp(proto,"IP")    || !strcasecmp(proto,"IPv4"))      return show_ip_layer(d, avail);
    if (!strcasecmp(proto,"TCP"))                                      return show_tcp_layer(d, avail);
    if (!strcasecmp(proto,"UDP"))                                      return show_udp_layer(d, avail);
    if (!strcasecmp(proto,"ICMP"))                                     return show_icmp_layer(d, avail);
    if (!strcasecmp(proto,"DNS"))                                      return show_dns_layer(d, avail);
    pdef_t *def = find_pdef_by_name(proto);
    if (def) { dissect_pdef_layer(def, d, avail); return avail; }
    if (has_sub_protocols(proto)) {
        dispatch_by_parent(proto, d, avail);
        return avail;
    }
    fprintf(stderr, CBRED "show: unknown protocol '%s' — use ls() to see all\n" CR, proto);
    return 0;
}

/* ─── Raw bytes builder ─────────────────────────────────────────────────────── */

size_t pkt_to_raw_ex(layer_t *pkt, uint8_t *buf, size_t bufsz, int keep_eth);
size_t pkt_to_raw(layer_t *pkt, uint8_t *buf, size_t bufsz) {
    return pkt_to_raw_ex(pkt, buf, bufsz, 0);
}
size_t pkt_to_raw_ex(layer_t *pkt, uint8_t *buf, size_t bufsz, int keep_eth) {
    layer_t *l_ether = NULL, *l_ip = NULL, *l_tcp = NULL;
    layer_t *l_udp = NULL, *l_icmp = NULL, *l_raw = NULL;
    for (layer_t *l = pkt; l; l = l->next) {
        switch (l->proto) {
            case PROTO_ETHER: l_ether = l; break;
            case PROTO_IP:    l_ip    = l; break;
            case PROTO_TCP:   l_tcp   = l; break;
            case PROTO_UDP:   l_udp   = l; break;
            case PROTO_ICMP:  l_icmp  = l; break;
            case PROTO_RAW:   l_raw   = l; break;
        }
    }

    static const uint8_t ZEROS[6] = {0x02,0x00,0x00,0x00,0x00,0x01};
    static const uint8_t BCAST[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

    uint8_t src_mac[6], dst_mac[6];
    get_mac(l_ether ? l_ether : NULL, "src", ZEROS, src_mac);
    get_mac(l_ether ? l_ether : NULL, "dst", BCAST, dst_mac);
    if (!l_ether) {
        memcpy(src_mac, ZEROS, 6);
        memcpy(dst_mac, BCAST, 6);
    }

    uint8_t pay_combined[8192]; size_t pay_len = 0;
    for (layer_t *lx = pkt; lx; lx = lx->next) {
        if (lx->proto == PROTO_DNS) {
            if (pay_len < sizeof(pay_combined))
                pay_len += serialize_dns_layer(lx, pay_combined+pay_len, sizeof(pay_combined)-pay_len);
            continue;
        }
        if (lx->proto < PROTO_DYNAMIC_BASE) continue;
        pdef_t *def = find_pdef_by_id(lx->proto);
        if (def && pay_len < sizeof(pay_combined))
            pay_len += serialize_pdef_layer(def, lx, pay_combined+pay_len, sizeof(pay_combined)-pay_len);
    }
    if (l_raw) {
        field_t *rf = find_field(l_raw, "load");
        if (rf && rf->type==FT_BYTES && rf->raw) {
            size_t cp = rf->raw_len < sizeof(pay_combined)-pay_len ? rf->raw_len : sizeof(pay_combined)-pay_len;
            memcpy(pay_combined+pay_len, rf->raw, cp); pay_len += cp;
        } else if (rf && rf->type==FT_STR) {
            size_t sl = strlen(rf->s);
            sl = sl < sizeof(pay_combined)-pay_len ? sl : sizeof(pay_combined)-pay_len;
            memcpy(pay_combined+pay_len, rf->s, sl); pay_len += sl;
        }
    }
    uint8_t *payload = pay_len ? pay_combined : NULL;
    size_t   plen    = pay_len;

    size_t frame_len = 0;
    int    prepended_eth = 0;

    if (l_tcp && l_ip) {
        field_t *flg = find_field(l_tcp, "flags");
        uint8_t tf = 0x02;
        if (flg && !flg->is_auto) {
            if (flg->type==FT_STR && flg->s[0]) tf = parse_tcp_flags(flg->s);
            else if (flg->type==FT_U64) tf = (uint8_t)flg->n;
        }

        uint32_t sip   = get_ip4(l_ip, "src", "127.0.0.1");
        uint32_t dip   = get_ip4(l_ip, "dst", "127.0.0.1");
        uint16_t sport = (uint16_t)get_u64(l_tcp, "sport",  20);
        uint16_t dport = (uint16_t)get_u64(l_tcp, "dport",  80);
        uint32_t seq_n = (uint32_t)get_u64(l_tcp, "seq",     0);
        uint32_t ack_n = (uint32_t)get_u64(l_tcp, "ack",     0);
        uint16_t win   = (uint16_t)get_u64(l_tcp, "window", 65535);
        uint8_t  ttl   = (uint8_t) get_u64(l_ip,  "ttl",    64);

        /* IP id: use the layer value only when explicitly set */
        field_t *id_f   = find_field(l_ip, "id");
        int      has_id = id_f && !id_f->is_auto && id_f->type == FT_U64;
        uint16_t ip_id  = has_id ? (uint16_t)id_f->n : (uint16_t)(rand() & 0xffff);

        /* TCP options: MSS and SACK_PERM */
        uint8_t opts[40]; int optlen = 0;
        uint16_t mss       = (uint16_t)get_u64(l_tcp, "mss",       0);
        int      sack_perm = (int)     get_u64(l_tcp, "sack_perm", 0);
        if (mss) {
            opts[optlen++] = 0x02; opts[optlen++] = 0x04;
            opts[optlen++] = (uint8_t)(mss >> 8); opts[optlen++] = (uint8_t)mss;
        }
        if (sack_perm) {
            opts[optlen++] = 0x01; opts[optlen++] = 0x01; /* NOP NOP */
            opts[optlen++] = 0x04; opts[optlen++] = 0x02; /* SACK_PERM */
        }
        while (optlen & 3) opts[optlen++] = 0x01; /* NOP pad to 4-byte boundary */

        /* Build Ethernet + IP + TCP frame in buf */
        size_t tcp_seg_len = 20 + optlen + plen;
        size_t ip_total    = 20 + tcp_seg_len;
        size_t off = 0;

        /* Ethernet */
        memcpy(buf+off, dst_mac, 6); off += 6;
        memcpy(buf+off, src_mac, 6); off += 6;
        buf[off++] = 0x08; buf[off++] = 0x00;

        /* IPv4 */
        struct libpcapng_ipv4_hdr *iph = (struct libpcapng_ipv4_hdr *)(buf+off);
        libpcapng_fill_ipv4_header(iph, sip, dip, (uint16_t)ip_total, IPPROTO_TCP);
        iph->ttl = ttl;
        iph->id  = htons(ip_id);
        /* IP flags: DF=2, MF=1 → frag_off bits */
        uint8_t ip_flags = (uint8_t)get_u64(l_ip, "flags", 0);
        uint16_t frag_word = 0;
        if (ip_flags & 2) frag_word |= 0x4000; /* DF */
        if (ip_flags & 1) frag_word |= 0x2000; /* MF */
        iph->frag_off = htons(frag_word);
        iph->checksum = 0;
        iph->checksum = libpcapng_ip_checksum(iph, 20);
        off += 20;

        /* TCP header */
        struct tcp_hdr *tcph = (struct tcp_hdr *)(buf+off);
        libpcapng_fill_tcp_header(tcph, sport, dport, seq_n, ack_n, tf, win);
        tcph->doff = (uint8_t)((20 + optlen) / 4);
        off += 20;

        /* TCP options */
        if (optlen) { memcpy(buf+off, opts, optlen); off += optlen; }

        /* Payload */
        if (payload && plen) { memcpy(buf+off, payload, plen); off += plen; }

        /* TCP checksum over pseudo-header + full TCP segment (header+opts+payload) */
        tcph->checksum = 0;
        uint32_t chk = 0;
        chk += (sip >> 16) & 0xffff; chk += sip & 0xffff;
        chk += (dip >> 16) & 0xffff; chk += dip & 0xffff;
        chk += htons(IPPROTO_TCP);
        chk += htons((uint16_t)tcp_seg_len);
        const uint8_t *seg = buf + 14 + 20;
        for (size_t i = 0; i + 1 < tcp_seg_len; i += 2)
            chk += (uint32_t)((seg[i] << 8) | seg[i+1]);
        if (tcp_seg_len & 1) chk += (uint32_t)(seg[tcp_seg_len-1] << 8);
        while (chk >> 16) chk = (chk & 0xffff) + (chk >> 16);
        tcph->checksum = htons(~chk & 0xffff);

        frame_len = off;
        prepended_eth = 1;
    } else if (l_udp && l_ip) {
        uint32_t sip = get_ip4(l_ip, "src", "127.0.0.1");
        uint32_t dip = get_ip4(l_ip, "dst", "127.0.0.1");
        libpcapng_udp_packet_build(src_mac, dst_mac, sip, dip,
            (uint16_t)get_u64(l_udp,"sport",53),
            (uint16_t)get_u64(l_udp,"dport",53),
            payload, plen, buf, &frame_len);
        prepended_eth = 1;
    } else if (l_icmp && l_ip) {
        uint32_t sip = get_ip4(l_ip, "src", "127.0.0.1");
        uint32_t dip = get_ip4(l_ip, "dst", "127.0.0.1");
        libpcapng_icmp_packet_build(src_mac, dst_mac, sip, dip,
            (uint8_t)get_u64(l_icmp,"type",8),
            (uint8_t)get_u64(l_icmp,"code",0),
            (uint16_t)get_u64(l_icmp,"id",0),
            (uint16_t)get_u64(l_icmp,"seq",0),
            payload, plen, buf, &frame_len);
        prepended_eth = 1;
    } else if (l_ip) {
        size_t ip_payload = plen;
        size_t ip_total   = 20 + ip_payload;
        struct libpcapng_eth_hdr *eth = (struct libpcapng_eth_hdr *)buf;
        memcpy(eth->dst, dst_mac, 6);
        memcpy(eth->src, src_mac, 6);
        eth->ethertype = htons(0x0800);
        struct libpcapng_ipv4_hdr *iph = (struct libpcapng_ipv4_hdr *)(buf + 14);
        uint32_t sip = get_ip4(l_ip, "src", "127.0.0.1");
        uint32_t dip = get_ip4(l_ip, "dst", "127.0.0.1");
        libpcapng_fill_ipv4_header(iph, sip, dip, (uint16_t)ip_total,
                                   (uint8_t)get_u64(l_ip,"proto",0));
        iph->ttl = (uint8_t)get_u64(l_ip,"ttl",64);
        iph->checksum = 0;
        iph->checksum = libpcapng_ip_checksum(iph, 20);
        if (payload && ip_payload) memcpy(buf + 34, payload, ip_payload);
        frame_len = 14 + ip_total;
        prepended_eth = 1;
    } else if (l_ether) {
        struct libpcapng_eth_hdr *eth = (struct libpcapng_eth_hdr *)buf;
        memcpy(eth->dst, dst_mac, 6);
        memcpy(eth->src, src_mac, 6);
        uint16_t et = (uint16_t)get_u64(l_ether,"type",0x800);
        eth->ethertype = htons(et);
        if (payload && plen) memcpy(buf + 14, payload, plen);
        frame_len = 14 + plen;
    } else if (payload) {
        if (plen <= bufsz) { memcpy(buf, payload, plen); frame_len = plen; }
    }

    if (!keep_eth && prepended_eth && !l_ether && frame_len >= 14) {
        memmove(buf, buf + 14, frame_len - 14);
        frame_len -= 14;
    }
    return frame_len;
}

/* ─── Pretty printer ────────────────────────────────────────────────────────── */

void print_field(const field_t *f, int proto) {
    printf(" " CCYN "%s" CR "=", f->name);
    if (f->is_auto) { printf(CDIM "auto" CR); return; }
    switch (f->type) {
        case FT_U64:
            if (strcmp(f->name,"chksum")==0 || strcmp(f->name,"type")==0)
                printf(CGRN "0x%04llx" CR, (unsigned long long)f->n);
            else if (strcmp(f->name,"flags")==0 && proto==PROTO_IP)
                printf(CBYEL "0x%x" CR, (unsigned)f->n);
            else
                printf(CGRN "%llu" CR, (unsigned long long)f->n);
            break;
        case FT_STR:
            if (strcmp(f->name,"flags")==0 && proto==PROTO_TCP)
                printf(CBYEL "%s" CR, f->s);
            else
                printf(CMAG "'%s'" CR, f->s);
            break;
        case FT_IP4:
            printf(CYEL "%s" CR, f->s[0] ? f->s : "0.0.0.0");
            break;
        case FT_MAC:
            printf(CYEL "%s" CR, f->s[0] ? f->s : "00:00:00:00:00:00");
            break;
        case FT_BYTES: {
            printf(CMAG "'");
            size_t show = f->raw_len < 48 ? f->raw_len : 48;
            for (size_t i = 0; i < show; i++) {
                unsigned char c = f->raw[i];
                if (isprint(c) && c != '\'') putchar(c);
                else printf("\\x%02x", (unsigned)c);
            }
            if (f->raw_len > 48) printf("...");
            printf("'" CR);
            break;
        }
    }
}

void print_pkt(layer_t *pkt) {
    for (layer_t *l = pkt; l; l = l->next) {
        printf(CWHT "<" CR "%s%s" CR, proto_color(l->proto), proto_name(l->proto));
        for (int i = 0; i < l->nflds; i++) {
            if (l->flds[i].name[0] == '_') continue;
            print_field(&l->flds[i], l->proto);
        }
        if (l->next) printf(" " CWHT "|" CR);
    }
    for (layer_t *l = pkt; l; l = l->next)
        printf(CWHT ">" CR);
    printf("\n");
}

/* ─── Hexdump ───────────────────────────────────────────────────────────────── */

void do_hexdump(const uint8_t *data, size_t len) {
    const char *cols[] = { CGRN, CCYN, CYEL, CMAG, CWHT };
    int ncols = 5;
    for (size_t i = 0; i < len; i += 16) {
        printf(CDIM "%04zx" CR "  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                int ci = (int)((i + j) / 6) % ncols;
                printf("%s%02X " CR, cols[ci], (unsigned)data[i + j]);
            } else {
                printf("   ");
            }
            if (j == 7) printf(" ");
        }
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t b = data[i + j];
            printf(CWHT "%c" CR, isprint(b) ? b : '.');
        }
        printf("\n");
    }
}

/* ─── ls() field listing ────────────────────────────────────────────────────── */

static const proto_field_info_t ip_fields[] = {
    {"version", "IP version",               FT_U64,  1,      4, NULL},
    {"ihl",     "Header length (32b words)", FT_U64,  1,      5, NULL},
    {"tos",     "Type of service",           FT_U64,  1,      0, NULL},
    {"len",     "Total length",              FT_U64,  2,      0, "(auto)"},
    {"id",      "Identification",            FT_U64,  2,      1, NULL},
    {"flags",   "Flags (DF=2, MF=1)",        FT_U64,  1,      0, NULL},
    {"frag",    "Fragment offset",           FT_U64,  2,      0, NULL},
    {"ttl",     "Time to live",              FT_U64,  1,     64, NULL},
    {"proto",   "Protocol number",           FT_U64,  1,      0, "(auto)"},
    {"chksum",  "Header checksum",           FT_U64,  2,      0, "(auto)"},
    {"src",     "Source IP",                 FT_IP4,  0,      0, "0.0.0.0"},
    {"dst",     "Destination IP",            FT_IP4,  0,      0, "0.0.0.0"},
    {NULL,NULL,0}
};
static const proto_field_info_t tcp_fields[] = {
    {"sport",   "Source port",              FT_U64,  2,      0, NULL},
    {"dport",   "Destination port",         FT_U64,  2,      0, NULL},
    {"seq",     "Sequence number",          FT_U64,  4,      0, NULL},
    {"ack",     "Acknowledgement number",   FT_U64,  4,      0, NULL},
    {"dataofs", "Data offset (32b words)",  FT_U64,  1,      5, NULL},
    {"flags",   "Control flags (F S R P A U)", FT_STR, 0,   0, ""},
    {"window",  "Window size",              FT_U64,  2,   8192, NULL},
    {"chksum",  "Checksum",                 FT_U64,  2,      0, "(auto)"},
    {"urgptr",  "Urgent pointer",           FT_U64,  2,      0, NULL},
    {"mss",     "Max segment size option",  FT_U64,  2,      0, "0=none"},
    {"sack_perm","SACK permitted option",   FT_U64,  1,      0, "0=none"},
    {NULL,NULL,0}
};
static const proto_field_info_t udp_fields[] = {
    {"sport",   "Source port",              FT_U64,  2,      0, NULL},
    {"dport",   "Destination port",         FT_U64,  2,      0, NULL},
    {"len",     "Length",                   FT_U64,  2,      0, "(auto)"},
    {"chksum",  "Checksum",                 FT_U64,  2,      0, "(auto)"},
    {NULL,NULL,0}
};
static const proto_field_info_t ether_fields[] = {
    {"dst",     "Destination MAC",          FT_MAC,  0,      0, "ff:ff:ff:ff:ff:ff"},
    {"src",     "Source MAC",               FT_MAC,  0,      0, "00:00:00:00:00:00"},
    {"type",    "EtherType (2048=IPv4)",     FT_U64,  2, 0x0800, NULL},
    {NULL,NULL,0}
};
static const proto_field_info_t icmp_fields[] = {
    {"type",    "ICMP type (8=echo req)",   FT_U64,  1,      8, NULL},
    {"code",    "ICMP code",                FT_U64,  1,      0, NULL},
    {"chksum",  "Checksum",                 FT_U64,  2,      0, "(auto)"},
    {"id",      "Identifier",               FT_U64,  2,      0, NULL},
    {"seq",     "Sequence number",          FT_U64,  2,      0, NULL},
    {NULL,NULL,0}
};
static const proto_field_info_t raw_fields[] = {
    {"load",    "Raw bytes payload",        FT_BYTES, 0,     0, NULL},
    {NULL,NULL,0}
};
static const proto_field_info_t dns_fields[] = {
    {"id",      "Transaction ID",               FT_U64,  2, 0, NULL},
    {"flags",   "Flags word",                   FT_U64,  2, 0, NULL},
    {"qr",      "Query(0)/Response(1)",         FT_U64,  1, 0, NULL},
    {"opcode",  "Opcode (0=QUERY)",             FT_U64,  1, 0, NULL},
    {"aa",      "Authoritative answer",         FT_U64,  1, 0, NULL},
    {"tc",      "Truncated",                    FT_U64,  1, 0, NULL},
    {"rd",      "Recursion desired",            FT_U64,  1, 1, NULL},
    {"ra",      "Recursion available",          FT_U64,  1, 0, NULL},
    {"rcode",   "Response code",                FT_U64,  1, 0, NULL},
    {"qdcount", "Question count",               FT_U64,  2, 0, NULL},
    {"ancount", "Answer RR count",              FT_U64,  2, 0, NULL},
    {"nscount", "Authority RR count",           FT_U64,  2, 0, NULL},
    {"arcount", "Additional RR count",          FT_U64,  2, 0, NULL},
    {"qd",      "Question  DNSQR(...)",         FT_BYTES, 0, 0, NULL},
    {"an",      "Answer    DNSRR(...)",         FT_BYTES, 0, 0, NULL},
    {"ns",      "Authority DNSRR(...)",         FT_BYTES, 0, 0, NULL},
    {"ar",      "Additional DNSRR(...)",        FT_BYTES, 0, 0, NULL},
    {NULL,NULL,0}
};

static const proto_info_t protos[] = {
    {"IP",    PROTO_IP,    ip_fields},
    {"TCP",   PROTO_TCP,   tcp_fields},
    {"UDP",   PROTO_UDP,   udp_fields},
    {"Ether", PROTO_ETHER, ether_fields},
    {"ICMP",  PROTO_ICMP,  icmp_fields},
    {"Raw",   PROTO_RAW,   raw_fields},
    {"DNS",   PROTO_DNS,   dns_fields},
    {NULL, 0, NULL}
};

void do_ls(const char *proto_arg) {
    int found = 0;
    for (int i = 0; protos[i].name; i++) {
        if (proto_arg && strcasecmp(protos[i].name, proto_arg) != 0) continue;
        found++;
        printf("%s%s" CR " fields:\n", proto_color(protos[i].proto), protos[i].name);
        for (const proto_field_info_t *f = protos[i].fields; f->name; f++) {
            char typestr[16];
            switch (f->type) {
                case FT_IP4:   strcpy(typestr, "ip4");   break;
                case FT_MAC:   strcpy(typestr, "mac");   break;
                case FT_STR:   strcpy(typestr, "str");   break;
                case FT_BYTES: strcpy(typestr, "bytes"); break;
                default:
                    switch (f->nbytes) {
                        case 1:  strcpy(typestr, "uint8");  break;
                        case 2:  strcpy(typestr, "uint16"); break;
                        case 4:  strcpy(typestr, "uint32"); break;
                        default: strcpy(typestr, "uint64"); break;
                    }
            }
            char defbuf[32] = "";
            if (f->defstr) {
                snprintf(defbuf, sizeof(defbuf), "%s", f->defstr);
            } else if (f->type == FT_U64 && f->nbytes) {
                snprintf(defbuf, sizeof(defbuf), "%llu", (unsigned long long)f->defval);
            }
            printf("  " CCYN "%-12s" CR " %-8s %-12s %s\n", f->name, typestr, defbuf, f->desc);
        }
        if (!proto_arg) printf("\n");
    }
    for (int i = 0; i < npdefs; i++) {
        pdef_t *d = &pdefs[i];
        if (proto_arg && strcasecmp(d->pname, proto_arg) != 0) continue;
        found++;
        printf("%s%s" CR " fields:\n", proto_color(d->proto_id), d->pname);
        if (d->parent[0])
            printf("  " CDIM "(sub-protocol of %s)" CR "\n", d->parent);
        for (int j = 0; j < d->nflds; j++) {
            pfld_t *f = &d->flds[j];
            char typebuf[80];
            if (f->ftype==PFT_BYTES)     snprintf(typebuf,sizeof(typebuf),"bytes<%zu>",f->nbytes);
            else if (f->ftype==PFT_BYTES_REF && f->lenfield[0])
                                         snprintf(typebuf,sizeof(typebuf),"bytes[%s]",f->lenfield);
            else strncpy(typebuf, pftype_name(f->ftype), sizeof(typebuf)-1);
            printf("  " CCYN "%-12s" CR " %-12s", f->fname, typebuf);
            if (f->nevals > 0) {
                printf(" [");
                for (int k = 0; k < f->nevals; k++)
                    printf("%s%s=0x%llx", k?", ":"", f->evals[k].name,
                           (unsigned long long)f->evals[k].val);
                printf("]");
            }
            printf("\n");
        }
        if (!proto_arg) printf("\n");
    }
    if (proto_arg && !found) {
        fprintf(stderr, CBRED "Unknown protocol: %s\n" CR, proto_arg);
        int nsugg = 0;
        fprintf(stderr, CDIM "Did you mean:" CR);
        for (int i = 0; protos[i].name; i++)
            if (strcasestr(protos[i].name, proto_arg)) {
                fprintf(stderr, " %s%s" CR, proto_color(protos[i].proto), protos[i].name);
                nsugg++;
            }
        for (int i = 0; i < npdefs; i++)
            if (strcasestr(pdefs[i].pname, proto_arg)) {
                fprintf(stderr, " %s%s" CR, proto_color(pdefs[i].proto_id), pdefs[i].pname);
                nsugg++;
            }
        if (!nsugg) fprintf(stderr, " (none)");
        fprintf(stderr, "\n");
        return;
    }

    if (proto_arg && has_sub_protocols(proto_arg)) {
        printf(CBOLD "%s" CR " sub-protocols:\n", proto_arg);
        for (int i = 0; i < npdefs; i++) {
            if (pdefs[i].parent[0] && !strcasecmp(pdefs[i].parent, proto_arg)) {
                pdef_t *sub = &pdefs[i];
                printf("  " CCYN "%-20s" CR, sub->pname);
                if (sub->nflds > 0)
                    printf(" (first field %s = %llu)", sub->flds[0].fname,
                           (unsigned long long)sub->flds[0].defnum);
                printf("\n");
            }
        }
    }
}
