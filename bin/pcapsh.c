/* pcapsh.c — interactive packet shell for libpcapng
 *
 * Scapy-like REPL: build, inspect, and write packets interactively.
 *
 * Examples:
 *   IP()
 *   Ether()/IP()/TCP()
 *   IP()/TCP()/"GET / HTTP/1.0\r\n\r\n"
 *   a = Ether(src="aa:bb:cc:dd:ee:ff")/IP(dst="8.8.8.8")/UDP()
 *   hexdump(a)
 *   raw(a)
 *   wrpcap("out.pcapng", a)
 *   ls(IP)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>

#include "linenoise/linenoise.h"
#include <libpcapng/libpcapng.h>

/* ─── ANSI colors ───────────────────────────────────────────────────────────── */
#define CR    "\033[0m"
#define CBOLD "\033[1m"
#define CDIM  "\033[2m"
#define CRED  "\033[31m"
#define CGRN  "\033[32m"
#define CYEL  "\033[33m"
#define CBLU  "\033[34m"
#define CMAG  "\033[35m"
#define CCYN  "\033[36m"
#define CWHT  "\033[37m"
#define CBGRN "\033[1;32m"
#define CBYEL "\033[1;33m"
#define CBCYN "\033[1;36m"
#define CBRED "\033[1;31m"
#define CBMAG "\033[1;35m"
#define CBBLU "\033[1;34m"

/* ─── Protocol IDs ──────────────────────────────────────────────────────────── */
#define PROTO_NONE  0
#define PROTO_ETHER 1
#define PROTO_IP    2
#define PROTO_TCP   3
#define PROTO_UDP   4
#define PROTO_ICMP  5
#define PROTO_RAW   6
#define PROTO_DNS   7
#define PROTO_ARP   8

/* ─── Field types ───────────────────────────────────────────────────────────── */
typedef enum { FT_U64 = 1, FT_STR, FT_IP4, FT_MAC, FT_BYTES } ftype_t;

#define MAX_RAWFIELD 4096

typedef struct {
    char    name[32];
    ftype_t type;
    int     is_auto;    /* value is computed (checksum, len) */
    uint64_t n;
    char     s[256];
    uint8_t  mac[6];
    uint8_t *raw;
    size_t   raw_len;
} field_t;

/* ─── Packet layer ──────────────────────────────────────────────────────────── */
#define MAX_FIELDS 28

typedef struct layer {
    int     proto;
    field_t flds[MAX_FIELDS];
    int     nflds;
    struct  layer *next;
} layer_t;

/* ─── TCP Session tracking ──────────────────────────────────────────────────── */
#define MAX_SESSIONS 64

typedef struct {
    char     name[64];
    uint32_t client_ip;  /* host byte order */
    uint32_t server_ip;  /* host byte order */
    uint16_t sport;
    uint16_t dport;
    uint32_t cli_seq;    /* next seq from client */
    uint32_t srv_seq;    /* next seq from server */
    uint8_t  client_mac[6];
    uint8_t  server_mac[6];
} sess_t;

static sess_t sessions[MAX_SESSIONS];
static int    nsessions = 0;

static void ip_to_mac(uint32_t ip_host, uint8_t mac[6]) {
    mac[0] = 0x02; mac[1] = 0x00;
    mac[2] = (ip_host >> 24) & 0xff;
    mac[3] = (ip_host >> 16) & 0xff;
    mac[4] = (ip_host >> 8)  & 0xff;
    mac[5] =  ip_host        & 0xff;
}

static void ip_str(uint32_t ip_host, char *buf, size_t sz) {
    struct in_addr a; a.s_addr = htonl(ip_host);
    strncpy(buf, inet_ntoa(a), sz - 1);
    buf[sz - 1] = '\0';
}

static sess_t *sess_find(const char *name) {
    for (int i = 0; i < nsessions; i++)
        if (strcmp(sessions[i].name, name) == 0) return &sessions[i];
    return NULL;
}

static sess_t *sess_new(const char *client_ip_str, const char *server_ip_str,
                        uint16_t sport, uint16_t dport) {
    if (nsessions >= MAX_SESSIONS) return NULL;
    sess_t *s = &sessions[nsessions++];
    memset(s, 0, sizeof(*s));
    s->client_ip = ntohl(inet_addr(client_ip_str));
    s->server_ip = ntohl(inet_addr(server_ip_str));
    s->sport = sport;
    s->dport = dport;
    s->cli_seq = 0x10000000u + (s->client_ip ^ ((uint32_t)sport << 16));
    s->srv_seq = 0x20000000u + (s->server_ip ^ ((uint32_t)dport << 16));
    ip_to_mac(s->client_ip, s->client_mac);
    ip_to_mac(s->server_ip, s->server_mac);
    return s;
}

/* ─── Variable storage ──────────────────────────────────────────────────────── */
#define MAX_VARS 256

typedef struct {
    char    name[64];
    int     used;
    layer_t *pkt;
    uint8_t *raw;
    size_t   raw_len;
    int      is_raw;
    int      is_session;  /* variable holds a TCPSession reference */
} var_t;

static var_t vars[MAX_VARS];
static int   nvars = 0;

/* ─── Field helpers ─────────────────────────────────────────────────────────── */

static field_t *find_field(layer_t *l, const char *name) {
    if (!l) return NULL;
    for (int i = 0; i < l->nflds; i++)
        if (strcmp(l->flds[i].name, name) == 0)
            return &l->flds[i];
    return NULL;
}

static field_t *get_or_add(layer_t *l, const char *name) {
    field_t *f = find_field(l, name);
    if (!f) {
        if (l->nflds >= MAX_FIELDS) return NULL;
        f = &l->flds[l->nflds++];
        memset(f, 0, sizeof(*f));
        strncpy(f->name, name, 31);
    }
    return f;
}

static void set_u64(layer_t *l, const char *n, uint64_t v) {
    field_t *f = get_or_add(l, n);
    if (!f) return;
    f->type = FT_U64; f->n = v; f->is_auto = 0;
}

static void set_auto(layer_t *l, const char *n, ftype_t t) {
    field_t *f = get_or_add(l, n);
    if (!f) return;
    f->type = t; f->is_auto = 1;
}

static void set_ip4(layer_t *l, const char *n, const char *ip) {
    field_t *f = get_or_add(l, n);
    if (!f) return;
    f->type = FT_IP4;
    f->n    = ntohl(inet_addr(ip));
    strncpy(f->s, ip, 255);
    f->is_auto = 0;
}

static void set_mac(layer_t *l, const char *n, const char *mac) {
    field_t *f = get_or_add(l, n);
    if (!f) return;
    f->type = FT_MAC;
    libpcapng_mac_str_to_bytes(mac, f->mac);
    strncpy(f->s, mac, 255);
    f->is_auto = 0;
}

static void set_str(layer_t *l, const char *n, const char *s) {
    field_t *f = get_or_add(l, n);
    if (!f) return;
    f->type = FT_STR;
    strncpy(f->s, s, 255);
    f->is_auto = 0;
}

static void set_bytes(layer_t *l, const char *n, const uint8_t *data, size_t len) {
    field_t *f = get_or_add(l, n);
    if (!f) return;
    f->type = FT_BYTES;
    if (f->raw) free(f->raw);
    f->raw = malloc(len);
    if (f->raw) { memcpy(f->raw, data, len); f->raw_len = len; }
    f->is_auto = 0;
}

static uint64_t get_u64(layer_t *l, const char *n, uint64_t def) {
    field_t *f = find_field(l, n);
    return (f && !f->is_auto) ? f->n : def;
}

static const char *get_str(layer_t *l, const char *n, const char *def) {
    field_t *f = find_field(l, n);
    return f ? f->s : def;
}

static uint32_t get_ip4(layer_t *l, const char *n, const char *def) {
    field_t *f = find_field(l, n);
    if (f && f->type == FT_IP4 && !f->is_auto) return (uint32_t)f->n;
    return ntohl(inet_addr(def));
}

static void get_mac(layer_t *l, const char *n, const uint8_t def[6], uint8_t out[6]) {
    field_t *f = find_field(l, n);
    if (f && f->type == FT_MAC && !f->is_auto) { memcpy(out, f->mac, 6); return; }
    memcpy(out, def, 6);
}

/* ─── Layer constructors ────────────────────────────────────────────────────── */

static layer_t *new_layer(int proto) {
    layer_t *l = calloc(1, sizeof(layer_t));
    if (l) l->proto = proto;
    return l;
}

static layer_t *make_ether(void) {
    layer_t *l = new_layer(PROTO_ETHER);
    set_mac(l, "dst", "ff:ff:ff:ff:ff:ff");
    set_mac(l, "src", "00:00:00:00:00:00");
    set_auto(l, "type", FT_U64);
    return l;
}

static layer_t *make_ip(void) {
    layer_t *l = new_layer(PROTO_IP);
    set_u64(l, "version", 4);
    set_u64(l, "ihl", 5);
    set_u64(l, "tos", 0);
    set_auto(l, "len", FT_U64);
    set_u64(l, "id", 1);
    set_u64(l, "flags", 0);
    set_u64(l, "frag", 0);
    set_u64(l, "ttl", 64);
    set_auto(l, "proto", FT_U64);
    set_auto(l, "chksum", FT_U64);
    set_ip4(l, "src", "127.0.0.1");
    set_ip4(l, "dst", "127.0.0.1");
    return l;
}

static layer_t *make_tcp(void) {
    layer_t *l = new_layer(PROTO_TCP);
    set_u64(l, "sport", 20);
    set_u64(l, "dport", 80);
    set_u64(l, "seq", 0);
    set_u64(l, "ack", 0);
    set_u64(l, "dataofs", 5);
    set_str(l, "flags", "S");
    set_u64(l, "window", 8192);
    set_auto(l, "chksum", FT_U64);
    set_u64(l, "urgptr", 0);
    return l;
}

static layer_t *make_udp(void) {
    layer_t *l = new_layer(PROTO_UDP);
    set_u64(l, "sport", 53);
    set_u64(l, "dport", 53);
    set_auto(l, "len", FT_U64);
    set_auto(l, "chksum", FT_U64);
    return l;
}

static layer_t *make_icmp(void) {
    layer_t *l = new_layer(PROTO_ICMP);
    set_u64(l, "type", 8);
    set_u64(l, "code", 0);
    set_auto(l, "chksum", FT_U64);
    set_u64(l, "id", 0);
    set_u64(l, "seq", 0);
    return l;
}

static layer_t *make_raw_layer(const uint8_t *data, size_t len) {
    layer_t *l = new_layer(PROTO_RAW);
    set_bytes(l, "load", data, len);
    return l;
}

static void free_layer(layer_t *l) {
    if (!l) return;
    free_layer(l->next);
    for (int i = 0; i < l->nflds; i++)
        if (l->flds[i].raw) free(l->flds[i].raw);
    free(l);
}

static layer_t *clone_chain(layer_t *l) {
    if (!l) return NULL;
    layer_t *c = malloc(sizeof(layer_t));
    memcpy(c, l, sizeof(layer_t));
    for (int i = 0; i < c->nflds; i++) {
        if (c->flds[i].raw && c->flds[i].raw_len) {
            c->flds[i].raw = malloc(c->flds[i].raw_len);
            if (c->flds[i].raw)
                memcpy(c->flds[i].raw, l->flds[i].raw, l->flds[i].raw_len);
        }
    }
    c->next = clone_chain(l->next);
    return c;
}

static layer_t *chain_append(layer_t *a, layer_t *b) {
    if (!a) return b;
    layer_t *t = a;
    while (t->next) t = t->next;
    t->next = b;
    return a;
}

/* ─── TCP flags ─────────────────────────────────────────────────────────────── */

static uint8_t parse_tcp_flags(const char *s) {
    uint8_t f = 0;
    for (; *s; s++) switch (*s) {
        case 'F': f |= 0x01; break;
        case 'S': f |= 0x02; break;
        case 'R': f |= 0x04; break;
        case 'P': f |= 0x08; break;
        case 'A': f |= 0x10; break;
        case 'U': f |= 0x20; break;
    }
    return f;
}

/* ─── Dynamic protocol system (posa-like definitions) ──────────────────────── */

#define PROTO_DYNAMIC_BASE 100
#define MAX_PDEFS   64
#define MAX_PFLDS   64
#define MAX_PEVALS  32

typedef enum {
    PFT_U8, PFT_U16, PFT_U32, PFT_U64,
    PFT_LE_U16, PFT_LE_U32, PFT_LE_U64,  /* little-endian integers (for SMB, RDP, etc.) */
    PFT_BYTES, PFT_MAC, PFT_IP4, PFT_STR
} pftype_t;

typedef struct { char name[64]; uint64_t val; } peval_t;

typedef struct {
    char     fname[64];
    pftype_t ftype;
    uint64_t defnum;
    char     defstr[256];
    size_t   nbytes;
    peval_t  evals[MAX_PEVALS];
    int      nevals;
} pfld_t;

typedef struct {
    char   pname[64];
    int    proto_id;
    pfld_t flds[MAX_PFLDS];
    int    nflds;
} pdef_t;

static pdef_t pdefs[MAX_PDEFS];
static int    npdefs = 0;

static pdef_t *find_pdef_by_name(const char *name) {
    for (int i = 0; i < npdefs; i++)
        if (strcasecmp(pdefs[i].pname, name) == 0) return &pdefs[i];
    return NULL;
}

static pdef_t *find_pdef_by_id(int id) {
    for (int i = 0; i < npdefs; i++)
        if (pdefs[i].proto_id == id) return &pdefs[i];
    return NULL;
}

static pftype_t parse_posa_type(const char *s, size_t *nbytes_out) {
    if (!strcasecmp(s,"uint8")||!strcasecmp(s,"int8"))   return PFT_U8;
    if (!strcasecmp(s,"uint16")||!strcasecmp(s,"int16")) return PFT_U16;
    if (!strcasecmp(s,"uint32")||!strcasecmp(s,"int32")) return PFT_U32;
    if (!strcasecmp(s,"uint64")||!strcasecmp(s,"int64")) return PFT_U64;
    if (!strcasecmp(s,"le_uint16")||!strcasecmp(s,"uint16le")) return PFT_LE_U16;
    if (!strcasecmp(s,"le_uint32")||!strcasecmp(s,"uint32le")) return PFT_LE_U32;
    if (!strcasecmp(s,"le_uint64")||!strcasecmp(s,"uint64le")) return PFT_LE_U64;
    if (!strcasecmp(s,"mac"))    return PFT_MAC;
    if (!strcasecmp(s,"ip4")||!strcasecmp(s,"ip")) return PFT_IP4;
    if (!strcasecmp(s,"string")) return PFT_STR;
    if (!strncasecmp(s,"bytes<",6)||!strncasecmp(s,"byte<",5)) {
        const char *lt = strchr(s,'<');
        if (lt) *nbytes_out = (size_t)atoi(lt+1);
        return PFT_BYTES;
    }
    if (!strncasecmp(s,"enum<",5)) {
        const char *inner = s+5;
        if (!strncasecmp(inner,"uint8",5)||!strncasecmp(inner,"int8",4)) return PFT_U8;
        if (!strncasecmp(inner,"uint32",6)||!strncasecmp(inner,"int32",6)) return PFT_U32;
        return PFT_U16;
    }
    if (!strcasecmp(s,"enum")) return PFT_U16;
    return PFT_U16;
}

/* Parse posa-format text; returns number of new protocols registered. */
static int parse_posa_src(const char *src) {
    pdef_t *cur = NULL;
    pfld_t *lastfld = NULL;
    int added = 0;
    char line[1024];
    const char *p = src;
    while (*p) {
        int li = 0;
        while (*p && *p != '\n' && li < 1023) line[li++] = *p++;
        if (*p == '\n') p++;
        line[li] = '\0';
        while (li > 0 && (line[li-1]==' '||line[li-1]=='\r'||line[li-1]=='\t')) line[--li]='\0';
        char *s = line;
        while (*s==' '||*s=='\t') s++;
        if (!*s || *s=='#') continue;
        int indent = (int)(s - line);

        if (!strncasecmp(s,"Object",6)) {
            if (npdefs >= MAX_PDEFS) continue;
            cur = &pdefs[npdefs];
            memset(cur, 0, sizeof(*cur));
            cur->proto_id = PROTO_DYNAMIC_BASE + npdefs;
            lastfld = NULL;
            const char *q = s + 6;
            if (*q == '<') { while (*q && *q != '>') q++; if (*q) q++; }
            while (*q==' '||*q=='\t') q++;
            int ni = 0;
            while (*q && *q!=' ' && *q!='\t' && ni<63) cur->pname[ni++] = *q++;
            cur->pname[ni] = '\0';
            if (cur->pname[0]) { npdefs++; added++; }
            continue;
        }

        if (!strncasecmp(s,"required",8)||!strncasecmp(s,"optional",8)||!strncasecmp(s,"list",4)) {
            if (!cur || cur->nflds >= MAX_PFLDS) continue;
            pfld_t *f = &cur->flds[cur->nflds];
            memset(f, 0, sizeof(*f));
            while (*s && *s!=' ' && *s!='\t') s++;
            while (*s==' '||*s=='\t') s++;
            char typestr[64]; int ti=0;
            while (*s && *s!=' ' && *s!='\t' && ti<63) typestr[ti++]=*s++;
            typestr[ti]='\0';
            while (*s==' '||*s=='\t') s++;
            if (!strcasecmp(typestr,"object")) { lastfld=NULL; continue; }
            int fi=0;
            while (*s && *s!=' ' && *s!='\t' && *s!='=' && fi<63) f->fname[fi++]=*s++;
            f->fname[fi]='\0';
            while (*s==' '||*s=='\t') s++;
            size_t nb = 0;
            f->ftype = parse_posa_type(typestr, &nb);
            f->nbytes = nb;
            if (*s == '=') {
                s++; while (*s==' '||*s=='\t') s++;
                if (!strncmp(s,"0x",2)||!strncmp(s,"0X",2)) f->defnum = strtoull(s,NULL,16);
                else if (isdigit((unsigned char)*s))          f->defnum = strtoull(s,NULL,10);
                else if (*s) {
                    strncpy(f->defstr, s, 255);
                    if (f->ftype==PFT_IP4) f->defnum = ntohl(inet_addr(f->defstr));
                }
            }
            if (f->ftype==PFT_IP4 && !f->defstr[0]) strcpy(f->defstr,"0.0.0.0");
            if (f->ftype==PFT_MAC && !f->defstr[0]) strcpy(f->defstr,"00:00:00:00:00:00");
            lastfld = f;
            cur->nflds++;
            continue;
        }

        /* indented ENUMNAME = 0xVALUE lines become named values for the last field */
        if (indent >= 4 && lastfld && *s != '#') {
            char ename[64]; int ei=0;
            const char *t = s;
            while (*t && *t!=' ' && *t!='\t' && *t!='=' && ei<63) ename[ei++]=*t++;
            ename[ei]='\0';
            while (*t==' '||*t=='\t') t++;
            if (*t=='=' && t[1]!='=') {
                t++; while (*t==' '||*t=='\t') t++;
                if (lastfld->nevals < MAX_PEVALS) {
                    peval_t *ev = &lastfld->evals[lastfld->nevals++];
                    strncpy(ev->name, ename, 63);
                    ev->val = (!strncmp(t,"0x",2)||!strncmp(t,"0X",2))
                              ? strtoull(t,NULL,16) : strtoull(t,NULL,10);
                }
            }
        }
    }
    return added;
}

static int parse_posa_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 0; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    if (sz <= 0) { fclose(f); return 0; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return 0; }
    size_t rd = fread(buf, 1, (size_t)sz, f); fclose(f);
    buf[rd] = '\0';
    int n = parse_posa_src(buf); free(buf);
    return n;
}

/* Serialize a dynamic protocol layer into wire bytes (big-endian fields). */
static size_t serialize_pdef_layer(pdef_t *def, layer_t *l, uint8_t *out, size_t max) {
    size_t off = 0;
    for (int i = 0; i < def->nflds && off < max; i++) {
        pfld_t *f = &def->flds[i];
        uint64_t v = get_u64(l, f->fname, f->defnum);
        switch (f->ftype) {
            case PFT_U8:
                if (off+1 <= max) out[off++] = (uint8_t)v;
                break;
            case PFT_U16:
                if (off+2 <= max) { uint16_t x=htons((uint16_t)v); memcpy(out+off,&x,2); off+=2; }
                break;
            case PFT_U32:
                if (off+4 <= max) { uint32_t x=htonl((uint32_t)v); memcpy(out+off,&x,4); off+=4; }
                break;
            case PFT_U64:
                if (off+8 <= max) {
                    uint64_t vv = v;
                    for (int b=7;b>=0;b--) { out[off+b]=(uint8_t)(vv&0xff); vv>>=8; }
                    off+=8;
                }
                break;
            case PFT_LE_U16:
                if (off+2 <= max) {
                    uint16_t x = (uint16_t)v;
                    out[off]   = (uint8_t)(x & 0xff);
                    out[off+1] = (uint8_t)((x >> 8) & 0xff);
                    off += 2;
                }
                break;
            case PFT_LE_U32:
                if (off+4 <= max) {
                    uint32_t x = (uint32_t)v;
                    out[off]   = (uint8_t)(x & 0xff);
                    out[off+1] = (uint8_t)((x >> 8) & 0xff);
                    out[off+2] = (uint8_t)((x >> 16) & 0xff);
                    out[off+3] = (uint8_t)((x >> 24) & 0xff);
                    off += 4;
                }
                break;
            case PFT_LE_U64:
                if (off+8 <= max) {
                    uint64_t x = v;
                    for (int b = 0; b < 8; b++) { out[off+b] = (uint8_t)(x & 0xff); x >>= 8; }
                    off += 8;
                }
                break;
            case PFT_IP4: {
                uint32_t ip = htonl((uint32_t)v);
                if (off+4 <= max) { memcpy(out+off,&ip,4); off+=4; }
                break;
            }
            case PFT_MAC: {
                field_t *lf = find_field(l, f->fname);
                uint8_t mac[6] = {0};
                if (lf && lf->type==FT_MAC) memcpy(mac,lf->mac,6);
                else if (lf && lf->s[0]) libpcapng_mac_str_to_bytes(lf->s, mac);
                else libpcapng_mac_str_to_bytes(f->defstr, mac);
                if (off+6 <= max) { memcpy(out+off,mac,6); off+=6; }
                break;
            }
            case PFT_STR: {
                field_t *lf = find_field(l, f->fname);
                const char *sv = (lf && lf->s[0]) ? lf->s : f->defstr;
                size_t sl = strlen(sv)+1;
                if (off+sl <= max) { memcpy(out+off,sv,sl); off+=sl; }
                break;
            }
            case PFT_BYTES: {
                size_t nb = f->nbytes;
                if (off+nb > max) break;
                field_t *lf = find_field(l, f->fname);
                if (lf && lf->type==FT_BYTES && lf->raw) {
                    size_t cp = lf->raw_len < nb ? lf->raw_len : nb;
                    memcpy(out+off, lf->raw, cp);
                    if (cp < nb) memset(out+off+cp, 0, nb-cp);
                } else memset(out+off, 0, nb);
                off += nb;
                break;
            }
        }
    }
    return off;
}

/* Construct a layer with default field values from a pdef. */
static layer_t *make_dynamic_layer(pdef_t *def) {
    layer_t *l = new_layer(def->proto_id);
    if (!l) return NULL;
    for (int i = 0; i < def->nflds; i++) {
        pfld_t *f = &def->flds[i];
        switch (f->ftype) {
            case PFT_U8: case PFT_U16: case PFT_U32: case PFT_U64:
        case PFT_LE_U16: case PFT_LE_U32: case PFT_LE_U64:
                set_u64(l, f->fname, f->defnum); break;
            case PFT_IP4: set_ip4(l, f->fname, f->defstr[0]?f->defstr:"0.0.0.0"); break;
            case PFT_MAC: set_mac(l, f->fname, f->defstr[0]?f->defstr:"00:00:00:00:00:00"); break;
            case PFT_STR: set_str(l, f->fname, f->defstr); break;
            case PFT_BYTES:
                if (f->nbytes) {
                    uint8_t *z = calloc(1, f->nbytes);
                    if (z) { set_bytes(l, f->fname, z, f->nbytes); free(z); }
                }
                break;
        }
    }
    return l;
}

/* After parse_arglist, resolve any ident strings that match enum names. */
static void resolve_dynamic_enums(pdef_t *def, layer_t *l) {
    for (int i = 0; i < def->nflds; i++) {
        pfld_t *f = &def->flds[i];
        if (!f->nevals) continue;
        field_t *lf = find_field(l, f->fname);
        if (!lf || lf->type != FT_STR) continue;
        for (int j = 0; j < f->nevals; j++) {
            if (strcasecmp(lf->s, f->evals[j].name) == 0) {
                lf->type = FT_U64;
                lf->n    = f->evals[j].val;
                lf->s[0] = '\0';
                break;
            }
        }
    }
}

static const char *pftype_name(pftype_t t) {
    switch(t) {
        case PFT_U8:     return "uint8";
        case PFT_U16:    return "uint16";
        case PFT_U32:    return "uint32";
        case PFT_U64:    return "uint64";
        case PFT_LE_U16: return "le_uint16";
        case PFT_LE_U32: return "le_uint32";
        case PFT_LE_U64: return "le_uint64";
        case PFT_BYTES:  return "bytes";
        case PFT_MAC:    return "mac";
        case PFT_IP4:    return "ip4";
        case PFT_STR:    return "string";
        default:         return "?";
    }
}

/* Built-in protocol definitions (posa format). */
static const char BUILTIN_POSA[] =
"Object<main> ARP\n"
"    required uint16 htype = 1\n"
"        ETHERNET = 1\n"
"    required uint16 ptype = 0x0800\n"
"        IPV4 = 0x0800\n"
"    required uint8  hlen = 6\n"
"    required uint8  plen = 4\n"
"    required uint16 op = 1\n"
"        REQUEST = 1\n"
"        REPLY = 2\n"
"    required mac sha = 00:00:00:00:00:00\n"
"    required ip4 spa = 0.0.0.0\n"
"    required mac tha = 00:00:00:00:00:00\n"
"    required ip4 tpa = 0.0.0.0\n"
"\n"
"Object<main> DNS\n"
"    required uint16 id = 0x0001\n"
"    required uint16 flags = 0x0100\n"
"        RESPONSE = 0x8000\n"
"        STANDARD_QUERY = 0x0100\n"
"        RD = 0x0100\n"
"    required uint16 qdcount = 1\n"
"    required uint16 ancount = 0\n"
"    required uint16 nscount = 0\n"
"    required uint16 arcount = 0\n"
"\n"
"Object<main> NTP\n"
"    required uint8 li_vn_mode = 0x1b\n"
"        CLIENT = 0x1b\n"
"        SERVER = 0x1c\n"
"    required uint8  stratum = 0\n"
"    required uint8  poll = 4\n"
"    required uint8  precision = 0xfa\n"
"    required uint32 root_delay = 0\n"
"    required uint32 root_dispersion = 0\n"
"    required uint32 ref_id = 0\n"
"    required uint32 ref_ts_s = 0\n"
"    required uint32 ref_ts_f = 0\n"
"    required uint32 orig_ts_s = 0\n"
"    required uint32 orig_ts_f = 0\n"
"    required uint32 recv_ts_s = 0\n"
"    required uint32 recv_ts_f = 0\n"
"    required uint32 tx_ts_s = 0\n"
"    required uint32 tx_ts_f = 0\n"
"\n"
"Object<main> DHCP\n"
"    required uint8  op = 1\n"
"        BOOTREQUEST = 1\n"
"        BOOTREPLY = 2\n"
"    required uint8  htype = 1\n"
"    required uint8  hlen = 6\n"
"    required uint8  hops = 0\n"
"    required uint32 xid = 0\n"
"    required uint16 secs = 0\n"
"    required uint16 flags = 0\n"
"    required ip4    ciaddr = 0.0.0.0\n"
"    required ip4    yiaddr = 0.0.0.0\n"
"    required ip4    siaddr = 0.0.0.0\n"
"    required ip4    giaddr = 0.0.0.0\n"
"    required bytes<16> chaddr\n"
"    required bytes<64> sname\n"
"    required bytes<128> file\n"
"\n"
"Object<main> GRE\n"
"    required uint16 flags_ver = 0\n"
"    required uint16 proto = 0x0800\n"
"        IPV4 = 0x0800\n"
"        IPV6 = 0x86DD\n"
"        MPLS = 0x8847\n"
"\n"
"Object<main> VXLAN\n"
"    required uint8  flags = 0x08\n"
"    required bytes<3> reserved1\n"
"    required bytes<3> vni\n"
"    required uint8  reserved2 = 0\n"
"\n"
"Object<main> RADIUS\n"
"    required uint8  code = 1\n"
"        ACCESS_REQUEST = 1\n"
"        ACCESS_ACCEPT = 2\n"
"        ACCESS_REJECT = 3\n"
"        ACCOUNTING_REQUEST = 4\n"
"        ACCOUNTING_RESPONSE = 5\n"
"    required uint8  identifier = 0\n"
"    required uint16 length = 20\n"
"    required bytes<16> authenticator\n"
"\n"
"Object<main> SYSLOG\n"
"    required uint8  severity = 6\n"
"        EMERGENCY = 0\n"
"        ALERT = 1\n"
"        CRITICAL = 2\n"
"        ERROR = 3\n"
"        WARNING = 4\n"
"        NOTICE = 5\n"
"        INFO = 6\n"
"        DEBUG = 7\n"
"    required uint8  facility = 1\n"
"    required string message\n"
"\n"
"Object<main> NBT\n"
"    required uint8  type = 0\n"
"        SESSION_MESSAGE = 0\n"
"        SESSION_REQUEST = 0x81\n"
"        POSITIVE_SESSION_RESPONSE = 0x82\n"
"        NEGATIVE_SESSION_RESPONSE = 0x83\n"
"        RETARGET_SESSION_RESPONSE = 0x84\n"
"        SESSION_KEEPALIVE = 0x85\n"
"    required uint8  flags = 0\n"
"    required uint16 length = 0\n"
"\n"
"Object<main> SMB2\n"
"    required uint32    magic = 0xFE534D42\n"
"    required le_uint16 structure_size = 64\n"
"    required le_uint16 credit_charge = 0\n"
"    required le_uint32 status = 0\n"
"    required le_uint16 command = 0\n"
"        NEGOTIATE = 0\n"
"        SESSION_SETUP = 1\n"
"        LOGOFF = 2\n"
"        TREE_CONNECT = 3\n"
"        TREE_DISCONNECT = 4\n"
"        CREATE = 5\n"
"        CLOSE = 6\n"
"        FLUSH = 7\n"
"        READ = 8\n"
"        WRITE = 9\n"
"        IOCTL = 11\n"
"        CANCEL = 12\n"
"        ECHO = 13\n"
"        QUERY_DIRECTORY = 14\n"
"        QUERY_INFO = 16\n"
"        SET_INFO = 17\n"
"    required le_uint16 credit_request = 0\n"
"    required le_uint32 flags = 0\n"
"    required le_uint32 next_command = 0\n"
"    required le_uint64 message_id = 0\n"
"    required le_uint32 process_id = 0\n"
"    required le_uint32 tree_id = 0\n"
"    required le_uint64 session_id = 0\n"
"    required bytes<16> signature\n"
"\n"
"Object<main> DCERPC\n"
"    required uint8     ver_major = 5\n"
"    required uint8     ver_minor = 0\n"
"    required uint8     type = 0\n"
"        REQUEST = 0\n"
"        RESPONSE = 2\n"
"        FAULT = 3\n"
"        BIND = 11\n"
"        BIND_ACK = 12\n"
"        BIND_NAK = 13\n"
"        ALTER_CONTEXT = 14\n"
"        ALTER_CONTEXT_RESP = 15\n"
"        AUTH3 = 16\n"
"    required uint8     flags = 0x03\n"
"    required le_uint32 data_rep = 0x10000000\n"
"    required le_uint16 frag_len = 0\n"
"    required le_uint16 auth_len = 0\n"
"    required le_uint32 call_id = 1\n"
"\n"
"Object<main> LDAP\n"
"    required uint8  seq_tag = 0x30\n"
"    required uint8  seq_len = 0\n"
"    required uint8  msgid_tag = 0x02\n"
"    required uint8  msgid_len = 0x01\n"
"    required uint8  message_id = 1\n"
"    required uint8  op_tag = 0x60\n"
"        BIND_REQUEST = 0x60\n"
"        BIND_RESPONSE = 0x61\n"
"        UNBIND_REQUEST = 0x42\n"
"        SEARCH_REQUEST = 0x63\n"
"        SEARCH_RESULT_ENTRY = 0x64\n"
"        SEARCH_RESULT_DONE = 0x65\n"
"        MODIFY_REQUEST = 0x66\n"
"        MODIFY_RESPONSE = 0x67\n"
"        ADD_REQUEST = 0x68\n"
"        ADD_RESPONSE = 0x69\n"
"        DEL_REQUEST = 0x4A\n"
"        DEL_RESPONSE = 0x6B\n"
"    required uint8  op_len = 0\n"
"\n";

/* ─── Raw bytes builder ─────────────────────────────────────────────────────── */
#define MAX_PKT_BYTES 65535

static size_t pkt_to_raw_ex(layer_t *pkt, uint8_t *buf, size_t bufsz, int keep_eth);
static size_t pkt_to_raw(layer_t *pkt, uint8_t *buf, size_t bufsz) {
    return pkt_to_raw_ex(pkt, buf, bufsz, 0);
}
static size_t pkt_to_raw_ex(layer_t *pkt, uint8_t *buf, size_t bufsz, int keep_eth) {
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

    static const uint8_t ZEROS[6]   = {0x02,0x00,0x00,0x00,0x00,0x01};
    static const uint8_t BCAST[6]   = {0xff,0xff,0xff,0xff,0xff,0xff};

    uint8_t src_mac[6], dst_mac[6];
    get_mac(l_ether ? l_ether : NULL, "src", ZEROS, src_mac);
    get_mac(l_ether ? l_ether : NULL, "dst", BCAST, dst_mac);
    if (!l_ether) {
        memcpy(src_mac, ZEROS, 6);
        memcpy(dst_mac, BCAST, 6);
    }

    /* Collect payload: dynamic protocol layers first, then Raw layer bytes. */
    uint8_t pay_combined[8192]; size_t pay_len = 0;
    for (layer_t *lx = pkt; lx; lx = lx->next) {
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
    int    prepended_eth = 0;  /* set when we synthesize an Ethernet header */

    /* TCP flags: support both string ("SA") and numeric (0x12) forms. */
    /* libpcapng builders expect HOST byte order for IPs (call htonl internally). */
    if (l_tcp && l_ip) {
        field_t *flg = find_field(l_tcp, "flags");
        uint8_t tf = 0x02; /* default SYN */
        if (flg && !flg->is_auto) {
            if (flg->type==FT_STR && flg->s[0]) tf = parse_tcp_flags(flg->s);
            else if (flg->type==FT_U64) tf = (uint8_t)flg->n;
        }
        uint32_t sip = get_ip4(l_ip, "src", "127.0.0.1");
        uint32_t dip = get_ip4(l_ip, "dst", "127.0.0.1");
        libpcapng_tcp_packet_build(src_mac, dst_mac, sip, dip,
            (uint16_t)get_u64(l_tcp,"sport",20),
            (uint16_t)get_u64(l_tcp,"dport",80),
            (uint32_t)get_u64(l_tcp,"seq",0),
            (uint32_t)get_u64(l_tcp,"ack",0),
            tf,
            payload, plen, buf, &frame_len);
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
        /* IP-only frame — synthesize Ethernet header */
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
        /* bare dynamic-protocol or raw-only layer with no network encapsulation */
        if (plen <= bufsz) { memcpy(buf, payload, plen); frame_len = plen; }
    }

    /* Strip synthesized Ethernet header when no Ether layer was in the packet */
    if (!keep_eth && prepended_eth && !l_ether && frame_len >= 14) {
        memmove(buf, buf + 14, frame_len - 14);
        frame_len -= 14;
    }
    return frame_len;
}

/* ─── Pretty printer ────────────────────────────────────────────────────────── */

static const char *proto_name(int p) {
    switch (p) {
        case PROTO_ETHER: return "Ether";
        case PROTO_IP:    return "IP";
        case PROTO_TCP:   return "TCP";
        case PROTO_UDP:   return "UDP";
        case PROTO_ICMP:  return "ICMP";
        case PROTO_RAW:   return "Raw";
        default: {
            pdef_t *d = find_pdef_by_id(p);
            return d ? d->pname : "???";
        }
    }
}

static const char *proto_color(int p) {
    static const char *dc[] = {CBYEL,CBGRN,CBMAG,CBCYN,CBRED,CBLU,CWHT};
    switch (p) {
        case PROTO_ETHER: return CBYEL;
        case PROTO_IP:    return CBCYN;
        case PROTO_TCP:   return CBGRN;
        case PROTO_UDP:   return CBMAG;
        case PROTO_ICMP:  return CBRED;
        case PROTO_RAW:   return CWHT;
        default:          return dc[p % 7];
    }
}

static void print_field(const field_t *f, int proto) {
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

static void print_pkt(layer_t *pkt) {
    for (layer_t *l = pkt; l; l = l->next) {
        printf(CWHT "<" CR "%s%s" CR, proto_color(l->proto), proto_name(l->proto));
        for (int i = 0; i < l->nflds; i++)
            print_field(&l->flds[i], l->proto);
        if (l->next) printf(" " CWHT "|" CR);
    }
    /* close brackets */
    for (layer_t *l = pkt; l; l = l->next)
        printf(CWHT ">" CR);
    printf("\n");
}

/* ─── Hexdump ───────────────────────────────────────────────────────────────── */

static void do_hexdump(const uint8_t *data, size_t len) {
    /* color bands by rough layer heuristic */
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

typedef struct { const char *name; const char *desc; ftype_t type; } proto_field_info_t;

static const proto_field_info_t ip_fields[] = {
    {"version","IP version (4)",FT_U64},{"ihl","Header length in 32-bit words",FT_U64},
    {"tos","Type of service",FT_U64},{"len","Total length (auto)",FT_U64},
    {"id","Identification",FT_U64},{"flags","Flags (0=DF,etc.)",FT_U64},
    {"frag","Fragment offset",FT_U64},{"ttl","Time to live",FT_U64},
    {"proto","Protocol number (auto)",FT_U64},{"chksum","Header checksum (auto)",FT_U64},
    {"src","Source IP",FT_IP4},{"dst","Destination IP",FT_IP4},{NULL,NULL,0}
};
static const proto_field_info_t tcp_fields[] = {
    {"sport","Source port",FT_U64},{"dport","Destination port",FT_U64},
    {"seq","Sequence number",FT_U64},{"ack","Acknowledgement number",FT_U64},
    {"dataofs","Data offset in 32-bit words",FT_U64},
    {"flags","Control flags (F S R P A U)",FT_STR},
    {"window","Window size",FT_U64},{"chksum","Checksum (auto)",FT_U64},
    {"urgptr","Urgent pointer",FT_U64},{NULL,NULL,0}
};
static const proto_field_info_t udp_fields[] = {
    {"sport","Source port",FT_U64},{"dport","Destination port",FT_U64},
    {"len","Length (auto)",FT_U64},{"chksum","Checksum (auto)",FT_U64},{NULL,NULL,0}
};
static const proto_field_info_t ether_fields[] = {
    {"dst","Destination MAC",FT_MAC},{"src","Source MAC",FT_MAC},
    {"type","EtherType (auto: 0x800=IP)",FT_U64},{NULL,NULL,0}
};
static const proto_field_info_t icmp_fields[] = {
    {"type","ICMP type (8=echo request)",FT_U64},{"code","ICMP code",FT_U64},
    {"chksum","Checksum (auto)",FT_U64},{"id","Identifier",FT_U64},
    {"seq","Sequence number",FT_U64},{NULL,NULL,0}
};
static const proto_field_info_t raw_fields[] = {
    {"load","Raw bytes payload",FT_BYTES},{NULL,NULL,0}
};

typedef struct { const char *name; int proto; const proto_field_info_t *fields; } proto_info_t;

static const proto_info_t protos[] = {
    {"IP",    PROTO_IP,    ip_fields},
    {"TCP",   PROTO_TCP,   tcp_fields},
    {"UDP",   PROTO_UDP,   udp_fields},
    {"Ether", PROTO_ETHER, ether_fields},
    {"ICMP",  PROTO_ICMP,  icmp_fields},
    {"Raw",   PROTO_RAW,   raw_fields},
    {NULL, 0, NULL}
};

static void do_ls(const char *proto_arg) {
    for (int i = 0; protos[i].name; i++) {
        if (proto_arg && strcasecmp(protos[i].name, proto_arg) != 0) continue;
        printf("%s%s" CR " fields:\n", proto_color(protos[i].proto), protos[i].name);
        for (const proto_field_info_t *f = protos[i].fields; f->name; f++) {
            const char *tname = (f->type==FT_IP4)?"ip4":
                                (f->type==FT_MAC)?"mac":
                                (f->type==FT_STR)?"str":"int";
            printf("  " CCYN "%-12s" CR " %-6s %s\n", f->name, tname, f->desc);
        }
        if (!proto_arg) printf("\n");
    }
    for (int i = 0; i < npdefs; i++) {
        pdef_t *d = &pdefs[i];
        if (proto_arg && strcasecmp(d->pname, proto_arg) != 0) continue;
        printf("%s%s" CR " fields:\n", proto_color(d->proto_id), d->pname);
        for (int j = 0; j < d->nflds; j++) {
            pfld_t *f = &d->flds[j];
            char typebuf[32];
            if (f->ftype==PFT_BYTES) snprintf(typebuf,sizeof(typebuf),"bytes<%zu>",f->nbytes);
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
}

/* ─── Variable management ───────────────────────────────────────────────────── */

static var_t *var_find(const char *name) {
    for (int i = 0; i < nvars; i++)
        if (vars[i].used && strcmp(vars[i].name, name) == 0)
            return &vars[i];
    return NULL;
}

static var_t *var_set_pkt(const char *name, layer_t *pkt) {
    var_t *v = var_find(name);
    if (!v) {
        if (nvars >= MAX_VARS) { fprintf(stderr, "too many variables\n"); return NULL; }
        v = &vars[nvars++];
        memset(v, 0, sizeof(*v));
        strncpy(v->name, name, 63);
    } else {
        if (v->pkt) free_layer(v->pkt);
        if (v->raw) free(v->raw);
    }
    v->used   = 1;
    v->pkt    = pkt;
    v->raw    = NULL;
    v->raw_len= 0;
    v->is_raw = 0;
    return v;
}

static var_t *var_set_session(const char *varname, sess_t *sess) {
    strncpy(sess->name, varname, 63);
    var_t *v = var_find(varname);
    if (!v) {
        if (nvars >= MAX_VARS) { fprintf(stderr, "too many variables\n"); return NULL; }
        v = &vars[nvars++];
        memset(v, 0, sizeof(*v));
        strncpy(v->name, varname, 63);
    } else {
        if (v->pkt) free_layer(v->pkt);
        if (v->raw) free(v->raw);
    }
    v->used = 1; v->pkt = NULL; v->raw = NULL; v->raw_len = 0;
    v->is_raw = 0; v->is_session = 1;
    return v;
}

static var_t *var_set_raw(const char *name, const uint8_t *data, size_t len) {
    var_t *v = var_find(name);
    if (!v) {
        if (nvars >= MAX_VARS) { fprintf(stderr, "too many variables\n"); return NULL; }
        v = &vars[nvars++];
        memset(v, 0, sizeof(*v));
        strncpy(v->name, name, 63);
    } else {
        if (v->pkt) free_layer(v->pkt);
        if (v->raw) free(v->raw);
    }
    v->used   = 1;
    v->pkt    = NULL;
    v->raw    = malloc(len);
    if (v->raw) memcpy(v->raw, data, len);
    v->raw_len= len;
    v->is_raw = 1;
    return v;
}

/* ─── Tokenizer ─────────────────────────────────────────────────────────────── */

typedef enum {
    T_EOF, T_IDENT, T_NUM, T_STR,
    T_LPAREN, T_RPAREN, T_COMMA, T_EQ, T_SLASH, T_DOT
} TT;

typedef struct {
    TT       type;
    char     s[512];
    uint64_t n;
    size_t   slen;    /* for binary strings */
} Tok;

typedef struct {
    const char *src;
    int         pos;
    Tok         cur;
    char        err[256];
} Lex;

static void lex_adv(Lex *L) {
    /* skip spaces (not newline) */
    while (L->src[L->pos] == ' ' || L->src[L->pos] == '\t') L->pos++;

    char c = L->src[L->pos];
    if (!c) { L->cur.type = T_EOF; return; }

    if (c == '#') { while (L->src[L->pos]) L->pos++; L->cur.type = T_EOF; return; }

    if (c == '"' || c == '\'') {
        char q = c; L->pos++;
        int i = 0;
        while (L->src[L->pos] && L->src[L->pos] != q) {
            if (L->src[L->pos] == '\\') {
                L->pos++;
                switch (L->src[L->pos]) {
                    case 'n':  L->cur.s[i++]='\n'; break;
                    case 'r':  L->cur.s[i++]='\r'; break;
                    case 't':  L->cur.s[i++]='\t'; break;
                    case '\\': L->cur.s[i++]='\\'; break;
                    case '\'': L->cur.s[i++]='\''; break;
                    case '"':  L->cur.s[i++]='"';  break;
                    case 'x': {
                        L->pos++;
                        char h[3] = {L->src[L->pos], L->src[L->pos+1], 0};
                        if (isxdigit(h[0]) && isxdigit(h[1]))
                            { L->cur.s[i++]=(char)strtol(h,NULL,16); L->pos++; }
                        else
                            { L->cur.s[i++]='x'; L->pos--; }
                        break;
                    }
                    default: L->cur.s[i++]=L->src[L->pos]; break;
                }
            } else {
                L->cur.s[i++] = L->src[L->pos];
            }
            L->pos++;
            if (i >= 510) break;
        }
        L->cur.s[i] = '\0';
        if (L->src[L->pos] == q) L->pos++;
        L->cur.slen = (size_t)i;
        L->cur.type = T_STR;
        return;
    }

    if (isdigit(c)) {
        if (c == '0' && (L->src[L->pos+1]=='x' || L->src[L->pos+1]=='X')) {
            L->pos += 2;
            char *e; L->cur.n = strtoull(L->src+L->pos, &e, 16);
            snprintf(L->cur.s,511,"0x%llx",(unsigned long long)L->cur.n);
            L->pos = (int)(e - L->src);
        } else {
            char *e; L->cur.n = strtoull(L->src+L->pos, &e, 10);
            snprintf(L->cur.s,511,"%llu",(unsigned long long)L->cur.n);
            L->pos = (int)(e - L->src);
        }
        L->cur.type = T_NUM; return;
    }

    if (isalpha(c) || c == '_') {
        int i = 0;
        while (isalnum(L->src[L->pos]) || L->src[L->pos]=='_')
            L->cur.s[i++] = L->src[L->pos++];
        L->cur.s[i] = '\0';
        L->cur.type = T_IDENT; return;
    }

    L->pos++;
    switch (c) {
        case '(': L->cur.type = T_LPAREN; break;
        case ')': L->cur.type = T_RPAREN; break;
        case ',': L->cur.type = T_COMMA;  break;
        case '=': L->cur.type = T_EQ;     break;
        case '/': L->cur.type = T_SLASH;  break;
        case '.': L->cur.type = T_DOT;    break;
        default:
            snprintf(L->err,255,"unexpected '%c'",c);
            L->cur.type = T_EOF; break;
    }
}

static void lex_init(Lex *L, const char *src) {
    L->src = src; L->pos = 0; L->err[0] = '\0';
    lex_adv(L);
}

/* ─── apply a named/positional arg to a layer ───────────────────────────────── */

static void apply_field(layer_t *l, const char *name, Lex *L) {
    if (L->cur.type == T_NUM) {
        set_u64(l, name, L->cur.n);
        lex_adv(L);
    } else if (L->cur.type == T_STR) {
        const char *val = L->cur.s;
        size_t slen = L->cur.slen;
        /* detect IP */
        struct in_addr addr;
        if (inet_aton(val, &addr)) {
            set_ip4(l, name, val);
        } else if (strlen(val) == 17 && val[2] == ':' && val[5] == ':') {
            set_mac(l, name, val);
        } else if (slen != strlen(val)) {
            /* binary string (has embedded NULs or \x escapes) */
            set_bytes(l, name, (const uint8_t*)val, slen);
        } else {
            set_str(l, name, val);
        }
        lex_adv(L);
    } else if (L->cur.type == T_IDENT) {
        /* variable reference (e.g. flags=SYN not supported yet, treat as str) */
        set_str(l, name, L->cur.s);
        lex_adv(L);
    }
}

/* ─── parse arglist into a layer ────────────────────────────────────────────── */

static void parse_arglist(Lex *L, layer_t *lay) {
    while (L->cur.type != T_RPAREN && L->cur.type != T_EOF) {
        if (L->cur.type == T_IDENT) {
            char name[64];
            strncpy(name, L->cur.s, 63);
            lex_adv(L);
            if (L->cur.type == T_EQ) {
                lex_adv(L);
                apply_field(lay, name, L);
            } else {
                /* positional ident (e.g. IP(src)) - skip silently */
            }
        } else {
            lex_adv(L); /* skip unknown positional */
        }
        if (L->cur.type == T_COMMA) lex_adv(L);
    }
}

/* ─── Forward declarations ───────────────────────────────────────────────────── */
typedef struct eval_result {
    layer_t *pkt;
    uint8_t *raw;
    size_t   raw_len;
    int      is_raw;
    int      is_none;
    sess_t  *sess;  /* non-NULL if result is a TCPSession reference */
} EvalResult;

static EvalResult eval_expr(Lex *L);

/* ─── TCP Session packet builders ───────────────────────────────────────────── */

static layer_t *sess_build_pkt(sess_t *s, int from_client,
                               uint32_t seq, uint32_t ack,
                               const char *flags,
                               const uint8_t *data, size_t dlen) {
    uint32_t sip = from_client ? s->client_ip : s->server_ip;
    uint32_t dip = from_client ? s->server_ip : s->client_ip;
    uint16_t sp  = from_client ? s->sport     : s->dport;
    uint16_t dp  = from_client ? s->dport     : s->sport;
    uint8_t *smac = from_client ? s->client_mac : s->server_mac;
    uint8_t *dmac = from_client ? s->server_mac : s->client_mac;

    char smac_s[20], dmac_s[20], sip_s[20], dip_s[20];
    snprintf(smac_s, sizeof(smac_s), "%02x:%02x:%02x:%02x:%02x:%02x",
             smac[0],smac[1],smac[2],smac[3],smac[4],smac[5]);
    snprintf(dmac_s, sizeof(dmac_s), "%02x:%02x:%02x:%02x:%02x:%02x",
             dmac[0],dmac[1],dmac[2],dmac[3],dmac[4],dmac[5]);

    struct in_addr sa, da;
    sa.s_addr = htonl(sip); strncpy(sip_s, inet_ntoa(sa), 19);
    da.s_addr = htonl(dip); strncpy(dip_s, inet_ntoa(da), 19);

    layer_t *eth = make_ether();
    set_mac(eth, "src", smac_s); set_mac(eth, "dst", dmac_s);
    set_u64(eth, "type", 0x0800);

    layer_t *ip = make_ip();
    set_ip4(ip, "src", sip_s); set_ip4(ip, "dst", dip_s);

    layer_t *tcp = make_tcp();
    set_u64(tcp, "sport", sp); set_u64(tcp, "dport", dp);
    set_u64(tcp, "seq", seq);  set_u64(tcp, "ack", ack);
    set_str(tcp, "flags", flags);

    layer_t *chain = chain_append(eth, chain_append(ip, tcp));
    if (data && dlen) chain_append(chain, make_raw_layer(data, dlen));
    return chain;
}

static layer_t *do_syn(sess_t *s) {
    layer_t *p = sess_build_pkt(s, 1, s->cli_seq, 0, "S", NULL, 0);
    s->cli_seq++;
    return p;
}
static layer_t *do_syn_ack(sess_t *s) {
    layer_t *p = sess_build_pkt(s, 0, s->srv_seq, s->cli_seq, "SA", NULL, 0);
    s->srv_seq++;
    return p;
}
static layer_t *do_tcp_ack(sess_t *s) {
    return sess_build_pkt(s, 1, s->cli_seq, s->srv_seq, "A", NULL, 0);
}
static layer_t *do_client_send(sess_t *s, const uint8_t *data, size_t dlen) {
    layer_t *p = sess_build_pkt(s, 1, s->cli_seq, s->srv_seq, "PA", data, dlen);
    s->cli_seq += (uint32_t)dlen;
    return p;
}
static layer_t *do_server_send(sess_t *s, const uint8_t *data, size_t dlen) {
    layer_t *p = sess_build_pkt(s, 0, s->srv_seq, s->cli_seq, "PA", data, dlen);
    s->srv_seq += (uint32_t)dlen;
    return p;
}
static layer_t *do_client_fin(sess_t *s) {
    layer_t *p = sess_build_pkt(s, 1, s->cli_seq, s->srv_seq, "FA", NULL, 0);
    s->cli_seq++;
    return p;
}
static layer_t *do_server_fin_ack(sess_t *s) {
    layer_t *p = sess_build_pkt(s, 0, s->srv_seq, s->cli_seq, "FA", NULL, 0);
    s->srv_seq++;
    return p;
}

/* ─── Evaluate a primary (call, variable, string literal) ───────────────────── */

static EvalResult eval_primary(Lex *L) {
    EvalResult r = {NULL, NULL, 0, 0, 0};

    if (L->cur.type == T_STR) {
        /* raw string layer */
        r.pkt = make_raw_layer((uint8_t*)L->cur.s, L->cur.slen);
        lex_adv(L);
        return r;
    }

    if (L->cur.type != T_IDENT) {
        if (L->err[0]) fprintf(stderr, CBRED "Error: %s\n" CR, L->err);
        r.is_none = 1; return r;
    }

    char name[64];
    strncpy(name, L->cur.s, 63);
    lex_adv(L);

    /* ── function call ── */
    if (L->cur.type == T_LPAREN) {
        lex_adv(L); /* consume ( */

        /* Protocol constructors */
        layer_t *lay = NULL;
        if      (!strcmp(name,"IP"))    lay = make_ip();
        else if (!strcmp(name,"TCP"))   lay = make_tcp();
        else if (!strcmp(name,"UDP"))   lay = make_udp();
        else if (!strcmp(name,"Ether")) lay = make_ether();
        else if (!strcmp(name,"ICMP"))  lay = make_icmp();
        else if (!strcmp(name,"Raw")) {
            /* Raw(load="...") or Raw("...") */
            if (L->cur.type == T_STR) {
                lay = make_raw_layer((uint8_t*)L->cur.s, L->cur.slen);
                lex_adv(L);
                if (L->cur.type == T_RPAREN) lex_adv(L);
                r.pkt = lay; return r;
            }
            lay = new_layer(PROTO_RAW);
        }

        /* Dynamic protocol constructors (posa-defined) */
        if (!lay) {
            pdef_t *def = find_pdef_by_name(name);
            if (def) lay = make_dynamic_layer(def);
        }

        /* utility functions */
        if (!lay) {
            /* hexdump(x) */
            if (!strcmp(name,"hexdump")) {
                EvalResult arg = eval_expr(L);
                if (L->cur.type == T_RPAREN) lex_adv(L);
                if (arg.pkt) {
                    uint8_t *buf = malloc(MAX_PKT_BYTES);
                    if (!buf) { free_layer(arg.pkt); r.is_none=1; return r; }
                    size_t len = pkt_to_raw(arg.pkt, buf, MAX_PKT_BYTES);
                    free_layer(arg.pkt);
                    do_hexdump(buf, len);
                    free(buf);
                } else if (arg.raw) {
                    do_hexdump(arg.raw, arg.raw_len);
                    free(arg.raw);
                }
                r.is_none = 1; return r;
            }
            /* raw(x) */
            if (!strcmp(name,"raw")) {
                EvalResult arg = eval_expr(L);
                if (L->cur.type == T_RPAREN) lex_adv(L);
                uint8_t *out = NULL; size_t olen = 0;
                if (arg.pkt) {
                    uint8_t *buf = malloc(MAX_PKT_BYTES);
                    if (!buf) { free_layer(arg.pkt); r.is_none=1; return r; }
                    olen = pkt_to_raw(arg.pkt, buf, MAX_PKT_BYTES);
                    free_layer(arg.pkt);
                    out = malloc(olen);
                    if (out) memcpy(out, buf, olen);
                    free(buf);
                } else if (arg.raw) {
                    out = arg.raw; olen = arg.raw_len; arg.raw = NULL;
                }
                if (out) {
                    printf(CMAG "'");
                    for (size_t i = 0; i < olen; i++) {
                        uint8_t b = out[i];
                        if (b == '\'') printf("\\'");
                        else if (isprint(b)) putchar(b);
                        else printf("\\x%02x", (unsigned)b);
                    }
                    printf("'" CR "\n");
                    r.raw = out; r.raw_len = olen; r.is_raw = 1;
                } else { r.is_none = 1; }
                return r;
            }
            /* ls([proto]) */
            if (!strcmp(name,"ls")) {
                char proto_arg[64] = "";
                if (L->cur.type == T_IDENT) { strncpy(proto_arg, L->cur.s, 63); lex_adv(L); }
                else if (L->cur.type == T_STR) { strncpy(proto_arg, L->cur.s, 63); lex_adv(L); }
                if (L->cur.type == T_RPAREN) lex_adv(L);
                do_ls(proto_arg[0] ? proto_arg : NULL);
                r.is_none = 1; return r;
            }
            /* wrpcap("file", pkt) — appends if file already exists */
            if (!strcmp(name,"wrpcap")) {
                char filename[256] = "";
                if (L->cur.type == T_STR) { strncpy(filename, L->cur.s, 255); lex_adv(L); }
                if (L->cur.type == T_COMMA) lex_adv(L);
                EvalResult arg = eval_expr(L);
                if (L->cur.type == T_RPAREN) lex_adv(L);
                if (filename[0] && (arg.pkt || arg.raw)) {
                    struct stat _st; int exists = (stat(filename, &_st) == 0);
                    FILE *fp = fopen(filename, exists ? "ab" : "wb");
                    if (!fp) { perror("wrpcap"); r.is_none=1; return r; }
                    /* always LINKTYPE_ETHERNET; keep Ethernet header even for IP-only packets */
                    if (!exists) libpcapng_write_header_to_file_with_linktype(fp, LINKTYPE_ETHERNET);
                    uint8_t *buf = malloc(MAX_PKT_BYTES); size_t len = 0;
                    if (!buf) { if (arg.pkt) free_layer(arg.pkt); if (arg.raw) free(arg.raw); fclose(fp); r.is_none=1; return r; }
                    if (arg.pkt) {
                        len = pkt_to_raw_ex(arg.pkt, buf, MAX_PKT_BYTES, 1);
                        free_layer(arg.pkt);
                    } else if (arg.raw) {
                        len = arg.raw_len < MAX_PKT_BYTES ? arg.raw_len : MAX_PKT_BYTES;
                        memcpy(buf, arg.raw, len);
                        free(arg.raw);
                    }
                    libpcapng_write_enhanced_packet_to_file(fp, buf, len);
                    free(buf);
                    fclose(fp);
                    printf(CGRN "%s %zu bytes to %s\n" CR, exists ? "Appended" : "Wrote", len, filename);
                }
                r.is_none = 1; return r;
            }
            /* load("file.posa") — load protocol definitions */
            if (!strcmp(name,"load")) {
                char path[512] = "";
                if (L->cur.type == T_STR) { strncpy(path, L->cur.s, 511); lex_adv(L); }
                if (L->cur.type == T_RPAREN) lex_adv(L);
                if (path[0]) {
                    int n = parse_posa_file(path);
                    printf(CGRN "Loaded %d protocol(s) from %s\n" CR, n, path);
                }
                r.is_none = 1; return r;
            }
            /* help() */
            if (!strcmp(name,"help")) {
                if (L->cur.type == T_RPAREN) lex_adv(L);
                printf(CBOLD "pcapsh — libpcapng interactive packet shell\n" CR
                       "\n"
                       CBYEL "Built-in protocols:\n" CR
                       "  " CBCYN "IP" CR "([src,dst,ttl,proto,...])   "
                       CBGRN "TCP" CR "([sport,dport,seq,ack,flags,...])\n"
                       "  " CBMAG "UDP" CR "([sport,dport,...])          "
                       CBYEL "Ether" CR "([src,dst,type,...])\n"
                       "  " CBRED "ICMP" CR "([type,code,id,seq,...])     "
                       CWHT "Raw" CR "(load='bytes')\n"
                       "\n"
                       CBYEL "Dynamic protocols (posa-defined):\n" CR
                       "  " CBCYN "ARP DNS NTP DHCP GRE VXLAN RADIUS SYSLOG" CR "\n"
                       "  " CBCYN "NBT SMB2 DCERPC LDAP" CR "\n"
                       "  Plus any loaded via load() — use ls() to see all\n"
                       "\n"
                       CBYEL "Operators:\n" CR
                       "  " CCYN "/" CR "         stack layers:  IP()/UDP()/DNS()\n"
                       "  " CCYN "=" CR "         assign:        a = Ether()/IP()/TCP()\n"
                       "\n"
                       CBYEL "Functions:\n" CR
                       "  " CCYN "hexdump" CR "(pkt)              hex dump bytes\n"
                       "  " CCYN "raw" CR "(pkt)                  raw bytes string\n"
                       "  " CCYN "ls" CR "([Proto])               list protocol fields\n"
                       "  " CCYN "wrpcap" CR "(\"file\",pkt)        write/append pcapng\n"
                       "  " CCYN "load" CR "(\"file.posa\")         load protocol defs\n"
                       "  " CCYN "help" CR "()                    this message\n"
                       "  " CCYN "exit" CR "() / " CCYN "quit" CR "()        exit\n"
                       "\n"
                       CBYEL "TCP Session functions:\n" CR
                       "  " CCYN "s = TCPSession" CR "(\"1.2.3.4\",\"5.6.7.8\",sport,dport)\n"
                       "  " CCYN "syn" CR "(s)             SYN from client\n"
                       "  " CCYN "syn_ack" CR "(s)         SYN-ACK from server\n"
                       "  " CCYN "tcp_ack" CR "(s)         ACK from client\n"
                       "  " CCYN "client_send" CR "(s,\"data\")  PSH+ACK from client\n"
                       "  " CCYN "server_send" CR "(s,\"data\")  PSH+ACK from server\n"
                       "  " CCYN "client_fin" CR "(s)      FIN+ACK from client\n"
                       "  " CCYN "server_fin_ack" CR "(s)  FIN+ACK from server\n"
                       "\n"
                       CBYEL "TCP flags:\n" CR
                       "  String: TCP(flags=\"SA\")  [F=FIN S=SYN R=RST P=PSH A=ACK U=URG]\n"
                       "  Numeric: TCP(flags=0x12)  [0x02=SYN 0x10=ACK 0x01=FIN]\n"
                       "\n"
                       CBYEL "Examples:\n" CR
                       "  IP(dst=\"8.8.8.8\")/UDP(dport=53)/DNS(id=0x1234)\n"
                       "  Ether(type=0x0806)/ARP(op=REQUEST,spa=\"192.168.1.1\")\n"
                       "  IP()/TCP()/NBT()/SMB2(command=READ)\n"
                       "  s = TCPSession(\"10.0.0.1\",\"10.0.0.2\",54321,80)\n"
                       "  wrpcap(\"http.pcapng\", syn(s))\n"
                       "  wrpcap(\"http.pcapng\", syn_ack(s))\n"
                       "  wrpcap(\"http.pcapng\", client_send(s,\"GET / HTTP/1.0\\r\\n\\r\\n\"))\n"
                       "  load(\"myproto.posa\")  ls(SMB2)\n"
                       "\n");
                r.is_none = 1; return r;
            }
            /* exit() / quit() */
            if (!strcmp(name,"exit") || !strcmp(name,"quit")) {
                if (L->cur.type == T_RPAREN) lex_adv(L);
                linenoiseHistorySave(".pcapsh_history");
                exit(0);
            }
            /* TCPSession(client_ip, server_ip, sport, dport) */
            if (!strcmp(name,"TCPSession")) {
                char cip[64]="127.0.0.1", sip[64]="127.0.0.2";
                uint16_t sport=12345, dport=80;
                int argn = 0;
                while (L->cur.type != T_RPAREN && L->cur.type != T_EOF) {
                    if (L->cur.type == T_STR) {
                        if      (argn==0) strncpy(cip, L->cur.s, 63);
                        else if (argn==1) strncpy(sip, L->cur.s, 63);
                        lex_adv(L);
                    } else if (L->cur.type == T_NUM) {
                        if      (argn==2) sport = (uint16_t)L->cur.n;
                        else if (argn==3) dport = (uint16_t)L->cur.n;
                        lex_adv(L);
                    } else lex_adv(L);
                    argn++;
                    if (L->cur.type == T_COMMA) lex_adv(L);
                }
                if (L->cur.type == T_RPAREN) lex_adv(L);
                r.sess = sess_new(cip, sip, sport, dport);
                return r;
            }
            /* syn/syn_ack/tcp_ack/client_fin/server_fin_ack(session) */
            if (!strcmp(name,"syn")      || !strcmp(name,"syn_ack") ||
                !strcmp(name,"tcp_ack")  || !strcmp(name,"client_fin") ||
                !strcmp(name,"server_fin_ack")) {
                EvalResult arg = eval_expr(L);
                if (L->cur.type == T_RPAREN) lex_adv(L);
                if (!arg.sess) {
                    fprintf(stderr, CBRED "%s() requires a TCPSession\n" CR, name);
                    r.is_none = 1; return r;
                }
                if      (!strcmp(name,"syn"))           r.pkt = do_syn(arg.sess);
                else if (!strcmp(name,"syn_ack"))        r.pkt = do_syn_ack(arg.sess);
                else if (!strcmp(name,"tcp_ack"))        r.pkt = do_tcp_ack(arg.sess);
                else if (!strcmp(name,"client_fin"))     r.pkt = do_client_fin(arg.sess);
                else if (!strcmp(name,"server_fin_ack")) r.pkt = do_server_fin_ack(arg.sess);
                return r;
            }
            /* client_send(session, "data") / server_send(session, "data") */
            if (!strcmp(name,"client_send") || !strcmp(name,"server_send")) {
                EvalResult arg = eval_expr(L);
                const uint8_t *data = NULL; size_t dlen = 0;
                static uint8_t dbuf[8192];
                if (L->cur.type == T_COMMA) lex_adv(L);
                if (L->cur.type == T_STR) {
                    dlen = L->cur.slen < sizeof(dbuf) ? L->cur.slen : sizeof(dbuf);
                    memcpy(dbuf, L->cur.s, dlen); data = dbuf;
                    lex_adv(L);
                }
                if (L->cur.type == T_RPAREN) lex_adv(L);
                if (!arg.sess) {
                    fprintf(stderr, CBRED "%s() requires a TCPSession\n" CR, name);
                    r.is_none = 1; return r;
                }
                r.pkt = !strcmp(name,"client_send")
                    ? do_client_send(arg.sess, data, dlen)
                    : do_server_send(arg.sess, data, dlen);
                return r;
            }
            fprintf(stderr, CBRED "Unknown function: %s\n" CR, name);
            while (L->cur.type != T_RPAREN && L->cur.type != T_EOF) lex_adv(L);
            if (L->cur.type == T_RPAREN) lex_adv(L);
            r.is_none = 1; return r;
        }

        /* parse args into layer */
        parse_arglist(L, lay);
        /* for dynamic protocols, resolve any ident strings as enum names */
        if (lay->proto >= PROTO_DYNAMIC_BASE) {
            pdef_t *def = find_pdef_by_id(lay->proto);
            if (def) resolve_dynamic_enums(def, lay);
        }
        if (L->cur.type == T_RPAREN) lex_adv(L);
        r.pkt = lay;
        return r;
    }

    /* ── variable reference ── */
    var_t *v = var_find(name);
    if (v) {
        if (v->is_session) {
            r.sess = sess_find(v->name);
            return r;
        }
        if (v->is_raw && v->raw) {
            r.raw = malloc(v->raw_len);
            if (r.raw) { memcpy(r.raw, v->raw, v->raw_len); r.raw_len = v->raw_len; }
            r.is_raw = 1;
        } else if (v->pkt) {
            r.pkt = clone_chain(v->pkt);
        }
        return r;
    }

    /* ── bareword: treat as string layer (e.g. "Raw") ── */
    fprintf(stderr, CBRED "Undefined: %s\n" CR, name);
    r.is_none = 1;
    return r;
}

/* ─── Evaluate a chain (A / B / C) ──────────────────────────────────────────── */

static EvalResult eval_chain(Lex *L) {
    EvalResult r = eval_primary(L);
    while (L->cur.type == T_SLASH) {
        lex_adv(L); /* consume / */
        EvalResult rhs = eval_primary(L);
        if (rhs.pkt) {
            if (r.pkt) chain_append(r.pkt, rhs.pkt);
            else r.pkt = rhs.pkt;
        }
    }
    return r;
}

/* ─── Evaluate a full expression (possibly an assignment) ───────────────────── */

static EvalResult eval_expr(Lex *L) {
    /* peek: is it IDENT = ? */
    if (L->cur.type == T_IDENT) {
        /* We need one-token look-ahead. Save state. */
        const char *saved_src = L->src;
        int saved_pos = L->pos;
        Tok saved_cur = L->cur;

        char varname[64];
        strncpy(varname, L->cur.s, 63);
        lex_adv(L);

        if (L->cur.type == T_EQ) {
            /* Assignment: varname = chain */
            lex_adv(L);
            EvalResult r = eval_chain(L);
            if (!r.is_none) {
                if (r.sess) {
                    var_set_session(varname, r.sess);
                    char csip[20], ssip[20];
                    ip_str(r.sess->client_ip, csip, sizeof(csip));
                    ip_str(r.sess->server_ip, ssip, sizeof(ssip));
                    printf(CGRN "%s" CR " = " CCYN "TCPSession" CR
                           "(%s:%u → %s:%u)\n",
                           varname, csip, r.sess->sport, ssip, r.sess->dport);
                } else if (r.pkt) {
                    var_set_pkt(varname, clone_chain(r.pkt));
                    printf(CGRN "%s" CR " = ", varname);
                    print_pkt(r.pkt);
                } else if (r.raw) {
                    var_set_raw(varname, r.raw, r.raw_len);
                    printf(CGRN "%s" CR " = " CMAG "(%zu bytes)" CR "\n", varname, r.raw_len);
                }
            }
            /* free the chain held by r — var owns the clone */
            if (r.pkt) { free_layer(r.pkt); r.pkt = NULL; }
            r.is_none = 1;  /* suppress re-print in main loop */
            return r;
        }
        /* Not an assignment: restore and parse as chain */
        L->src = saved_src;
        L->pos = saved_pos;
        L->cur = saved_cur;
    }
    return eval_chain(L);
}

/* ─── Completion callback ────────────────────────────────────────────────────── */

static void completion_cb(const char *buf, linenoiseCompletions *lc) {
    static const char *keywords[] = {
        "IP(","TCP(","UDP(","Ether(","ICMP(","Raw(",
        "hexdump(","raw(","ls(","wrpcap(","load(","help()","exit()","quit()",
        "TCPSession(","syn(","syn_ack(","tcp_ack(","client_send(","server_send(",
        "client_fin(","server_fin_ack(",
        NULL
    };
    size_t n = strlen(buf);
    /* find the start of the current token (last word boundary) */
    const char *start = buf + n;
    while (start > buf && (isalnum(*(start-1)) || *(start-1)=='_')) start--;
    size_t pfxlen = n - (size_t)(start - buf);
    const char *pfx = start;

    for (int i = 0; keywords[i]; i++) {
        if (strncasecmp(pfx, keywords[i], pfxlen) == 0) {
            char comp[512];
            size_t before = (size_t)(start - buf);
            memcpy(comp, buf, before);
            strncpy(comp + before, keywords[i], sizeof(comp) - before - 1);
            comp[sizeof(comp)-1] = '\0';
            linenoiseAddCompletion(lc, comp);
        }
    }
    /* complete dynamic protocol names */
    for (int i = 0; i < npdefs; i++) {
        char kw[70]; snprintf(kw, sizeof(kw), "%s(", pdefs[i].pname);
        if (strncasecmp(pfx, kw, pfxlen) == 0) {
            char comp[512];
            size_t before = (size_t)(start - buf);
            memcpy(comp, buf, before);
            strncpy(comp+before, kw, sizeof(comp)-before-1);
            comp[sizeof(comp)-1]='\0';
            linenoiseAddCompletion(lc, comp);
        }
    }
    /* also complete variable names */
    for (int i = 0; i < nvars; i++) {
        if (!vars[i].used) continue;
        if (strncmp(pfx, vars[i].name, pfxlen) == 0) {
            char comp[512];
            size_t before = (size_t)(start - buf);
            memcpy(comp, buf, before);
            strncpy(comp + before, vars[i].name, sizeof(comp) - before - 1);
            comp[sizeof(comp)-1] = '\0';
            linenoiseAddCompletion(lc, comp);
        }
    }
}

/* ─── Line evaluator (shared by REPL and script mode) ───────────────────────── */

static void eval_line(const char *src) {
    Lex L;
    lex_init(&L, src);
    while (L.cur.type != T_EOF) {
        EvalResult r = eval_expr(&L);
        if (!r.is_none) {
            if (r.pkt)      { print_pkt(r.pkt); free_layer(r.pkt); }
            else if (r.raw) { free(r.raw); }
        }
        /* skip semicolons / trailing junk between statements */
        while (L.cur.type != T_EOF &&
               L.cur.type != T_IDENT &&
               L.cur.type != T_NUM   &&
               L.cur.type != T_STR)
            lex_adv(&L);
    }
}

/* ─── Script execution ───────────────────────────────────────────────────────── */

static int run_script(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, CBRED "pcapsh: cannot open script '%s': %s\n" CR, path, strerror(errno)); return 1; }

    char line[4096];
    int  lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        /* strip trailing CR/LF */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1]=='\n'||line[len-1]=='\r')) line[--len]='\0';

        /* skip blank lines and comments */
        char *p = line;
        while (*p==' '||*p=='\t') p++;
        if (!*p || *p=='#') continue;

        eval_line(line);
    }
    fclose(f);
    return 0;
}

/* ─── REPL ───────────────────────────────────────────────────────────────────── */

static void banner(void) {
    printf(CBOLD CBCYN
           "  ____                   ____  _   _ \n"
           " |  _ \\ ___ __ _ _ __  / ___|| | | |\n"
           " | |_) / __/ _` | '_ \\ \\___ \\| |_| |\n"
           " |  __/ (_| (_| | |_) | ___) |  _  |\n"
           " |_|   \\___\\__,_| .__/ |____/|_| |_|\n"
           "                |_|   " CR
           CWHT "libpcapng interactive shell" CR "\n"
           CDIM "Type help() for usage, exit() or Ctrl-D to quit.\n" CR "\n");
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options] [script.pcapsh]\n"
        "       %s [options]           (interactive mode)\n"
        "\n"
        "Options:\n"
        "  -p, --proto FILE.posa   load protocol definitions from FILE.posa\n"
        "  -e EXPR                 evaluate EXPR and exit\n"
        "  -h, --help              show this help\n"
        "\n"
        "Script files (.pcapsh) are executed non-interactively.\n"
        ".posa files define custom protocols (see ~/.pcapsh_protos.posa).\n",
        prog, prog);
}

int main(int argc, char **argv) {
    /* register built-in protocol definitions */
    parse_posa_src(BUILTIN_POSA);

    /* auto-load ~/.pcapsh_protos.posa if it exists */
    {
        const char *home = getenv("HOME");
        if (home) {
            char p[512]; snprintf(p, sizeof(p), "%s/.pcapsh_protos.posa", home);
            struct stat _s; if (stat(p, &_s) == 0) parse_posa_file(p);
        }
    }

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* ── parse arguments ── */
    const char *script_file  = NULL;
    const char *eval_expr_s  = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i],"-h") || !strcmp(argv[i],"--help")) {
            usage(argv[0]); return 0;
        }
        if ((!strcmp(argv[i],"-p")||!strcmp(argv[i],"--proto")) && i+1 < argc) {
            int n = parse_posa_file(argv[++i]);
            fprintf(stderr, "Loaded %d protocol(s) from %s\n", n, argv[i]);
            continue;
        }
        if (!strcmp(argv[i],"-e") && i+1 < argc) {
            eval_expr_s = argv[++i];
            continue;
        }
        /* bare .posa file */
        size_t slen = strlen(argv[i]);
        if (slen > 5 && !strcmp(argv[i]+slen-5, ".posa")) {
            int n = parse_posa_file(argv[i]);
            fprintf(stderr, "Loaded %d protocol(s) from %s\n", n, argv[i]);
            continue;
        }
        /* anything else is a script file (first one wins) */
        if (!script_file && argv[i][0] != '-') {
            script_file = argv[i];
        }
    }

    /* ── -e one-liner mode ── */
    if (eval_expr_s) {
        eval_line(eval_expr_s);
        return 0;
    }

    /* ── script mode ── */
    if (script_file) {
        return run_script(script_file);
    }

    /* ── interactive REPL ── */
    banner();

    linenoiseSetCompletionCallback(completion_cb);
    linenoiseHistorySetMaxLen(500);
    linenoiseHistoryLoad(".pcapsh_history");

    const char *prompt = CBCYN "pcapsh" CR CWHT " >>> " CR;

    char *line;
    while ((line = linenoise(prompt)) != NULL) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') { linenoiseFree(line); continue; }

        linenoiseHistoryAdd(line);
        eval_line(line);
        linenoiseFree(line);
    }

    linenoiseHistorySave(".pcapsh_history");
    printf("\n");
    return 0;
}
