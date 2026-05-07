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
#include <inttypes.h>
#include <limits.h>
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

/* ─── Protocol registry ─────────────────────────────────────────────────────── */
typedef struct { int id; char name[64]; const char *color; } proto_reg_t;

#define MAX_PROTO_REG 128
static proto_reg_t proto_reg[MAX_PROTO_REG];
static int         nproto_reg = 0;

static void proto_register(int id, const char *name, const char *color) {
    for (int i = 0; i < nproto_reg; i++)
        if (proto_reg[i].id == id) {
            strncpy(proto_reg[i].name, name, 63);
            proto_reg[i].color = color;
            return;
        }
    if (nproto_reg >= MAX_PROTO_REG) return;
    proto_reg[nproto_reg].id = id;
    strncpy(proto_reg[nproto_reg].name, name, 63);
    proto_reg[nproto_reg].color = color;
    nproto_reg++;
}

static const char *proto_name(int p) {
    for (int i = 0; i < nproto_reg; i++)
        if (proto_reg[i].id == p) return proto_reg[i].name;
    return "???";
}

static const char *proto_color(int p) {
    static const char *dc[] = {CBYEL,CBGRN,CBMAG,CBCYN,CBRED,CBLU,CWHT};
    for (int i = 0; i < nproto_reg; i++)
        if (proto_reg[i].id == p) return proto_reg[i].color;
    return dc[p % 7];
}

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
    int64_t  numval;      /* numeric value (for loop variables) */
    int      is_num;
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
    PFT_BYTES, PFT_MAC, PFT_IP4, PFT_STR,
    PFT_PAYLOAD,   /* rest of packet — variable length, must be last field       */
    PFT_BYTES_REF  /* bytes[fieldname] — length read from a named integer field  */
} pftype_t;

typedef struct { char name[64]; uint64_t val; } peval_t;

typedef struct {
    char     fname[64];
    pftype_t ftype;
    uint64_t defnum;
    char     defstr[256];
    size_t   nbytes;
    char     lenfield[64]; /* PFT_BYTES_REF: name of field that holds the byte count */
    peval_t  evals[MAX_PEVALS];
    int      nevals;
} pfld_t;

typedef struct {
    char   pname[64];
    char   parent[64]; /* Object<parent> type; empty or "main" for top-level */
    int    proto_id;
    pfld_t flds[MAX_PFLDS];
    int    nflds;
} pdef_t;

static pdef_t pdefs[MAX_PDEFS];
static int    npdefs = 0;

static pdef_t *find_pdef_by_name(const char *name) {
    /* return last match so inline/later definitions override earlier ones */
    pdef_t *found = NULL;
    for (int i = 0; i < npdefs; i++)
        if (strcasecmp(pdefs[i].pname, name) == 0) found = &pdefs[i];
    return found;
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
    if (!strcasecmp(s,"string")||!strcasecmp(s,"cstring")) return PFT_STR;
    if (!strcasecmp(s,"payload")||!strcasecmp(s,"bytes_eod")) return PFT_PAYLOAD;
    if (!strncasecmp(s,"bytes<",6)||!strncasecmp(s,"byte<",5)) {
        const char *lt = strchr(s,'<');
        if (lt) *nbytes_out = (size_t)atoi(lt+1);
        return PFT_BYTES;
    }
    /* bytes[fieldname] — handled in parse_posa_src, returns sentinel here */
    if (!strncasecmp(s,"bytes[",6)) return PFT_BYTES_REF;
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
            /* parse optional <parent> type — store if not "main" or empty */
            if (*q == '<') {
                q++;
                int pi = 0;
                while (*q && *q != '>' && pi < 63) cur->parent[pi++] = *q++;
                cur->parent[pi] = '\0';
                if (*q == '>') q++;
                if (!strcasecmp(cur->parent, "main")) cur->parent[0] = '\0';
            }
            while (*q==' '||*q=='\t') q++;
            int ni = 0;
            while (*q && *q!=' ' && *q!='\t' && ni<63) cur->pname[ni++] = *q++;
            cur->pname[ni] = '\0';
            if (cur->pname[0]) {
                npdefs++; added++;
                /* auto-register for name/color lookup */
                static const char *dc[] = {CBYEL,CBGRN,CBMAG,CBCYN,CBRED,CBLU,CWHT};
                proto_register(cur->proto_id, cur->pname, dc[cur->proto_id % 7]);
            }
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
            /* bytes[fieldname] — extract the referenced field name */
            if (f->ftype == PFT_BYTES_REF) {
                const char *lb = strchr(typestr, '[');
                const char *rb = lb ? strchr(lb, ']') : NULL;
                if (lb && rb && rb > lb+1) {
                    size_t nlen = (size_t)(rb - lb - 1);
                    if (nlen >= 64) nlen = 63;
                    strncpy(f->lenfield, lb+1, nlen);
                    f->lenfield[nlen] = '\0';
                }
            }
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
    /* pre-pass: auto-fill length fields for every BYTES_REF field */
    for (int i = 0; i < def->nflds; i++) {
        pfld_t *rf = &def->flds[i];
        if (rf->ftype != PFT_BYTES_REF || !rf->lenfield[0]) continue;
        field_t *data_lf = find_field(l, rf->fname);
        size_t dlen = 0;
        if (data_lf && data_lf->type==FT_BYTES && data_lf->raw) dlen = data_lf->raw_len;
        else if (data_lf && data_lf->type==FT_STR)              dlen = strlen(data_lf->s);
        field_t *len_lf = find_field(l, rf->lenfield);
        if (len_lf) len_lf->n = (uint64_t)dlen;
    }
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
            case PFT_PAYLOAD:
            case PFT_BYTES_REF: {
                field_t *lf = find_field(l, f->fname);
                if (lf && lf->type==FT_BYTES && lf->raw && lf->raw_len) {
                    size_t cp = lf->raw_len;
                    if (off+cp <= max) { memcpy(out+off, lf->raw, cp); off += cp; }
                } else if (lf && lf->type==FT_STR && lf->s[0]) {
                    size_t sl = strlen(lf->s);
                    if (off+sl <= max) { memcpy(out+off, lf->s, sl); off += sl; }
                }
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
            case PFT_PAYLOAD:
            case PFT_BYTES_REF:
                /* start empty — user sets via fieldname="data" or \xNN escapes */
                set_bytes(l, f->fname, (const uint8_t*)"", 0);
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
        case PFT_BYTES:     return "bytes";
        case PFT_MAC:       return "mac";
        case PFT_IP4:       return "ip4";
        case PFT_STR:       return "cstring";
        case PFT_PAYLOAD:   return "payload";
        case PFT_BYTES_REF: return "bytes[N]";
        default:            return "?";
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

/* Default content written to ~/.pcapsh_protos.posa on first run. */
static const char DEFAULT_USER_POSA[] =
"# ~/.pcapsh_protos.posa — user protocol definitions\n"
"# Loaded automatically at startup. Add your own protocols below.\n"
"# Protocol syntax reference: https://github.com/stricaud/libpcapng/blob/main/bin/pcapsh.md\n"
"\n"
"# ── TFTP (RFC 1350) ─────────────────────────────────────────────────────────\n"
"# Sub-protocols are tagged Object<TFTP> so that show(\"IP/UDP/TFTP\", data)\n"
"# automatically dispatches on the opcode field.  Each sub-protocol can still\n"
"# be used directly: show(\"IP/UDP/TFTP_ACK\", data).\n"
"Object<TFTP> TFTP_RRQ\n"
"    required uint16  opcode   = 1\n"
"        RRQ = 1\n"
"    required cstring filename = \n"
"    required cstring mode     = octet\n"
"\n"
"Object<TFTP> TFTP_WRQ\n"
"    required uint16  opcode   = 2\n"
"        WRQ = 2\n"
"    required cstring filename = \n"
"    required cstring mode     = octet\n"
"\n"
"Object<TFTP> TFTP_DATA\n"
"    required uint16  opcode = 3\n"
"        DATA = 3\n"
"    required uint16  block  = 1\n"
"    required payload data\n"
"\n"
"Object<TFTP> TFTP_ACK\n"
"    required uint16 opcode = 4\n"
"        ACK = 4\n"
"    required uint16 block  = 0\n"
"\n"
"Object<TFTP> TFTP_ERROR\n"
"    required uint16  opcode = 5\n"
"        ERROR = 5\n"
"    required uint16  code   = 0\n"
"        ERR_UNDEFINED        = 0\n"
"        ERR_FILE_NOT_FOUND   = 1\n"
"        ERR_ACCESS_VIOLATION = 2\n"
"        ERR_DISK_FULL        = 3\n"
"        ERR_ILLEGAL_OP       = 4\n"
"        ERR_UNKNOWN_TID      = 5\n"
"        ERR_FILE_EXISTS      = 6\n"
"        ERR_NO_SUCH_USER     = 7\n"
"    required cstring msg\n"
"\n"
"# ── Telnet (RFC 854) ─────────────────────────────────────────────────────────\n"
"# Represents a single IAC command triple (IAC + verb + option).\n"
"# Data bytes between IAC sequences are raw payload and not covered here.\n"
"Object<main> Telnet\n"
"    required uint8 iac = 0xFF\n"
"    required uint8 command = 0xFD\n"
"        SE   = 0xF0\n"
"        SB   = 0xFA\n"
"        WILL = 0xFB\n"
"        WONT = 0xFC\n"
"        DO   = 0xFD\n"
"        DONT = 0xFE\n"
"        IAC  = 0xFF\n"
"    required uint8 option = 0\n"
"        ECHO                 = 1\n"
"        SUPPRESS_GO_AHEAD    = 3\n"
"        STATUS               = 5\n"
"        TIMING_MARK          = 6\n"
"        TERMINAL_TYPE        = 24\n"
"        WINDOW_SIZE          = 31\n"
"        TERMINAL_SPEED       = 32\n"
"        REMOTE_FLOW_CONTROL  = 33\n"
"        LINEMODE             = 34\n"
"        NEW_ENVIRON          = 39\n"
"\n";

/* ─── DNS layer serializer ──────────────────────────────────────────────────── */
static size_t serialize_dns_layer(layer_t *l, uint8_t *out, size_t max) {
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

/* ─── fromhex / show utilities ──────────────────────────────────────────────── */

static int hexval(char c) {
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
static size_t fromhex_parse(const char *s, uint8_t *out, size_t max) {
    size_t n = 0;
    const char *p = s;
    while (*p && n < max) {
        /* skip leading whitespace / newlines */
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (!*p) break;
        /* Wireshark-style line: 4 hex digits at column 0 followed by spaces = offset, skip it */
        if (hexval(p[0]) >= 0 && hexval(p[1]) >= 0 &&
            hexval(p[2]) >= 0 && hexval(p[3]) >= 0 &&
            (p[4] == ' ' || p[4] == '\t')) {
            p += 4; /* skip offset */
            while (*p == ' ' || *p == '\t') p++;
        }
        /* read hex bytes on this line:
         * stop when we see 3+ consecutive spaces (Wireshark ASCII column) or end of line */
        while (*p && *p != '\n' && *p != '\r' && n < max) {
            /* 3+ spaces = ASCII column separator — stop this line */
            if (p[0]==' ' && p[1]==' ' && p[2]==' ') break;
            /* skip spaces (byte separators and group separators) */
            if (*p == ' ' || *p == '\t') { p++; continue; }
            int hi = hexval(p[0]);
            int lo = hexval(p[1]);
            if (hi < 0 || lo < 0) break; /* non-hex char — stop this line (ASCII column) */
            out[n++] = (uint8_t)((hi << 4) | lo);
            p += 2;
        }
        /* skip to end of line */
        while (*p && *p != '\n') p++;
    }
    return n;
}

/* ─── frompcapng helper ──────────────────────────────────────────────────────── */

typedef struct {
    uint32_t  target;    /* 1-based packet number to extract */
    uint32_t  seen;      /* packet blocks seen so far */
    uint8_t  *buf;       /* output buffer (pre-allocated, 65535 bytes) */
    size_t    buf_len;   /* bytes written */
} frompcapng_ctx_t;

static int frompcapng_cb(uint32_t block_counter, uint32_t block_type,
                         uint32_t block_total_length, unsigned char *data,
                         void *userdata)
{
    frompcapng_ctx_t *ctx = (frompcapng_ctx_t *)userdata;

    /* count Enhanced Packet Blocks, Simple Packet Blocks, and legacy Packet Blocks */
    if (block_type != PCAPNG_ENHANCED_PACKET_BLOCK &&
        block_type != PCAPNG_SIMPLE_PACKET_BLOCK   &&
        block_type != PCAPNG_PACKET_BLOCK)
        return 0;

    ctx->seen++;
    if (ctx->seen != ctx->target)
        return 0;

    /* Extract packet data from the block.
     * The 'data' buffer starts immediately after the 8-byte type+length header.
     * EPB:  interface_id(4) + ts_high(4) + ts_low(4) + cap_len(4) + orig_len(4) = 20 bytes
     * SPB:  orig_len(4) = 4 bytes header
     * PKT (legacy): iface(2) + drops(2) + ts_high(4) + ts_low(4) + cap_len(4) + orig_len(4) = 20 bytes */
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
        /* cap_len = block_total_length - 16 (type4 + len4 + orig_len4 + trailing_len4) */
        cap_len    = block_total_length - 16;
        hdr_offset = 4; /* skip orig_len only */
    } else { /* PCAPNG_PACKET_BLOCK */
        if (block_total_length < 8 + 20) return 0;
        /* interface_id(2)+drops(2)+ts_high(4)+ts_low(4)+cap_len(4)+orig_len(4) = 20 */
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
 * Returns a malloc'd buffer of the raw packet bytes (caller must free), or NULL on error.
 * *out_len is set to the number of bytes. */
static uint8_t *frompcapng_read(const char *filename, uint32_t pktnum, size_t *out_len)
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

/* ─── replacepkt helper ──────────────────────────────────────────────────────── */

/* Replace packet number 'pktnum' (1-based) in 'filename' with 'new_bytes'.
 * All other blocks (SHB, IDB, non-target EPBs) are copied verbatim.
 * The file is updated in-place via a temp file + rename. */
static int replacepkt_in_file(const char *filename, uint32_t pktnum,
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

/* Dissect raw bytes according to a pdef and print the fields. */
static void dissect_pdef_layer(pdef_t *def, const uint8_t *data, size_t len) {
    /* paranoia: reject obviously invalid inputs */
    if (!def || !data || len == 0) {
        printf("<empty>|\n");
        return;
    }

    /* accumulate parsed integer values so BYTES_REF can look up length fields */
    struct { char name[64]; uint64_t val; } pv[MAX_PFLDS];
    int npv = 0;

    printf(CBOLD "<%s " CR, def->pname);
    size_t off = 0;
    for (int i = 0; i < def->nflds; i++) {
        pfld_t *f = &def->flds[i];

        /* PAYLOAD and BYTES_REF can start even at off==len (empty) */
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
                if (off+8 <= len) {
                    for (int b=0;b<8;b++) v = (v<<8)|data[off+b];
                }
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
                if (off+8 <= len) {
                    for (int b=0;b<8;b++) v |= ((uint64_t)data[off+b])<<(8*b);
                }
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
                /* avail_str >= 1 guaranteed by the off >= len guard above */
                size_t avail_str = len - off;
                const char *sv = (const char *)(data + off);
                size_t sl = strnlen(sv, avail_str);
                /* sl == avail_str → no NUL found; don't advance past the buffer end */
                int print_len = (sl > (size_t)INT_MAX) ? INT_MAX : (int)sl;
                printf(CWHT "%s" CR "='%.*s' ", f->fname, print_len, sv);
                off += sl + (sl < avail_str ? 1 : 0);
                if (off > len) off = len;  /* defensive clamp — should never fire */
                continue;
            }
            case PFT_PAYLOAD: {
                size_t remaining = len - off;
                /* print as ASCII if fully printable, else hex */
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
                /* look up length from the previously parsed integer field */
                size_t blen = 0;
                if (f->lenfield[0]) {
                    for (int k = 0; k < npv; k++) {
                        if (!strcasecmp(pv[k].name, f->lenfield)) {
                            uint64_t raw = pv[k].val;
                            /* cap at 64 KiB before converting to size_t — a packet
                               can't carry more and an evil length field must not
                               cause a size_t wrap or a giant allocation */
                            blen = (raw > 65535u) ? 65535u : (size_t)raw;
                            break;
                        }
                    }
                }
                size_t avail = len - off;
                if (blen > avail) blen = avail;  /* never read past data end */
                /* print as ASCII if fully printable, else hex */
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
                if (off > len) off = len;  /* defensive clamp */
                continue;
            }
        }
        /* integer field — look up enum name and store in parsed-values table */
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
        if (off > len) { off = len; break; }  /* defensive: fixed-width field overran */
    }
    printf("|\n");
    if (off < len)
        printf(CWHT "  +%zu trailing byte(s)\n" CR, len - off);
}

/* ─── Per-protocol show helpers (print fields, return bytes consumed) ────────── */

static size_t show_ether_layer(const uint8_t *d, size_t avail) {
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

static size_t show_ip_layer(const uint8_t *d, size_t avail) {
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

static size_t show_tcp_layer(const uint8_t *d, size_t avail) {
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

static size_t show_udp_layer(const uint8_t *d, size_t avail) {
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

static size_t show_icmp_layer(const uint8_t *d, size_t avail) {
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

static size_t show_dns_layer(const uint8_t *d, size_t avail) {
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

/* Dispatch to a sub-protocol by reading the first field value and matching it
   against the default of the first field in every Object<parent> sub-protocol. */
static int dispatch_by_parent(const char *parent, const uint8_t *data, size_t len) {
    /* find any sub-protocol to learn the first-field byte width */
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

/* Check if 'name' is used as a parent type by any registered sub-protocol. */
static int has_sub_protocols(const char *name) {
    for (int i = 0; i < npdefs; i++)
        if (pdefs[i].parent[0] && !strcasecmp(pdefs[i].parent, name)) return 1;
    return 0;
}

/* Dispatch a single named layer; returns bytes consumed (0 = error). */
static size_t show_layer_by_name(const char *proto, const uint8_t *d, size_t avail) {
    if (!strcasecmp(proto,"Ether") || !strcasecmp(proto,"Ethernet")) return show_ether_layer(d, avail);
    if (!strcasecmp(proto,"IP")    || !strcasecmp(proto,"IPv4"))      return show_ip_layer(d, avail);
    if (!strcasecmp(proto,"TCP"))                                      return show_tcp_layer(d, avail);
    if (!strcasecmp(proto,"UDP"))                                      return show_udp_layer(d, avail);
    if (!strcasecmp(proto,"ICMP"))                                     return show_icmp_layer(d, avail);
    if (!strcasecmp(proto,"DNS"))                                      return show_dns_layer(d, avail);
    pdef_t *def = find_pdef_by_name(proto);
    if (def) { dissect_pdef_layer(def, d, avail); return avail; }
    /* not a direct protocol — try parent-type dispatch (Object<proto> sub-protocols) */
    if (has_sub_protocols(proto)) {
        dispatch_by_parent(proto, d, avail);
        return avail;
    }
    fprintf(stderr, CBRED "show: unknown protocol '%s' — use ls() to see all\n" CR, proto);
    return 0;
}

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

    /* Collect payload: built-in application layers, dynamic posa layers, then Raw. */
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
        for (int i = 0; i < l->nflds; i++) {
            if (l->flds[i].name[0] == '_') continue; /* hidden internal field */
            print_field(&l->flds[i], l->proto);
        }
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
static const proto_field_info_t dns_fields[] = {
    {"id",      "Transaction ID",        FT_U64},
    {"flags",   "Flags word (or use qr/rd/aa/tc/ra/rcode)",FT_U64},
    {"qr",      "Query(0)/Response(1)",  FT_U64},
    {"opcode",  "Opcode (0=QUERY)",      FT_U64},
    {"aa",      "Authoritative answer",  FT_U64},
    {"tc",      "Truncated",             FT_U64},
    {"rd",      "Recursion desired",     FT_U64},
    {"ra",      "Recursion available",   FT_U64},
    {"rcode",   "Response code",         FT_U64},
    {"qdcount", "Question count",        FT_U64},
    {"ancount", "Answer RR count",       FT_U64},
    {"nscount", "Authority RR count",    FT_U64},
    {"arcount", "Additional RR count",   FT_U64},
    {"qd",      "Question  DNSQR(...)",  FT_BYTES},
    {"an",      "Answer    DNSRR(...)",  FT_BYTES},
    {"ns",      "Authority DNSRR(...)",  FT_BYTES},
    {"ar",      "Additional DNSRR(...)", FT_BYTES},
    {NULL,NULL,0}
};

typedef struct { const char *name; int proto; const proto_field_info_t *fields; } proto_info_t;

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
    /* if proto_arg names a parent type, list its sub-protocols */
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

static var_t *var_set_num(const char *name, int64_t val) {
    var_t *v = var_find(name);
    if (!v) {
        if (nvars >= MAX_VARS) { fprintf(stderr, "too many variables\n"); return NULL; }
        v = &vars[nvars++];
        memset(v, 0, sizeof(*v));
        strncpy(v->name, name, 63);
    } else {
        if (v->pkt) { free_layer(v->pkt); v->pkt = NULL; }
        if (v->raw) { free(v->raw);       v->raw = NULL; }
    }
    v->used   = 1;
    v->numval = val;
    v->is_num = 1;
    v->is_raw = 0;
    return v;
}

/* ─── Tokenizer ─────────────────────────────────────────────────────────────── */

typedef enum {
    T_EOF, T_IDENT, T_NUM, T_STR,
    T_LPAREN, T_RPAREN, T_COMMA, T_EQ, T_SLASH, T_DOT,
    T_VAR   /* $ident — loop/numeric variable reference */
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

    if (c == '$') {
        L->pos++; /* skip past '$' */
        int i = 0;
        while (isalnum((unsigned char)L->src[L->pos]) || L->src[L->pos]=='_')
            L->cur.s[i++] = L->src[L->pos++];
        L->cur.s[i] = '\0';
        L->cur.type = T_VAR; return;
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
    } else if (L->cur.type == T_VAR) {
        /* $varname — look up numeric variable and use its value */
        var_t *v = var_find(L->cur.s);
        if (v && v->is_num) set_u64(l, name, (uint64_t)(int64_t)v->numval);
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
    sess_t  *sess;
    uint64_t num;
    int      is_num;
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

/* ─── DNS wire-format helpers ───────────────────────────────────────────────── */

static uint16_t dns_qtype_from_str(const char *s) {
    if (!strcasecmp(s,"A"))     return 1;
    if (!strcasecmp(s,"NS"))    return 2;
    if (!strcasecmp(s,"CNAME")) return 5;
    if (!strcasecmp(s,"SOA"))   return 6;
    if (!strcasecmp(s,"PTR"))   return 12;
    if (!strcasecmp(s,"MX"))    return 15;
    if (!strcasecmp(s,"AAAA"))  return 28;
    if (!strcasecmp(s,"ANY"))   return 255;
    return 1;
}

/* Encode dotted domain name into DNS label wire format; returns bytes written. */
static size_t dns_encode_name(const char *name, uint8_t *out, size_t max) {
    size_t off = 0;
    if (!name || !*name) { if (off < max) out[off++] = 0; return off; }
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t llen = dot ? (size_t)(dot - name) : strlen(name);
        if (!llen) { name++; continue; }
        if (off + 1 + llen + 1 > max) break;
        out[off++] = (uint8_t)llen;
        memcpy(out + off, name, llen); off += llen;
        if (!dot) break;
        name = dot + 1;
    }
    if (off < max) out[off++] = 0;
    return off;
}

/* ─── Evaluate a primary (call, variable, string literal) ───────────────────── */

static EvalResult eval_primary(Lex *L) {
    EvalResult r = {0};

    if (L->cur.type == T_NUM) {
        r.num = L->cur.n; r.is_num = 1;
        lex_adv(L); return r;
    }

    if (L->cur.type == T_STR) {
        /* raw string layer */
        r.pkt = make_raw_layer((uint8_t*)L->cur.s, L->cur.slen);
        lex_adv(L);
        return r;
    }

    if (L->cur.type == T_VAR) {
        /* $varname — look up numeric (loop) variable */
        var_t *v = var_find(L->cur.s);
        lex_adv(L);
        if (!v || !v->is_num) {
            fprintf(stderr, CBRED "pcapsh: undefined variable '$%s'\n" CR,
                    v ? v->name : "?");
            r.is_none = 1; return r;
        }
        r.num = (uint64_t)(int64_t)v->numval;
        r.is_num = 1;
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
            /* fromhex("hex string or Wireshark dump") — parse hex into raw bytes */
            if (!strcmp(name,"fromhex")) {
                char hexstr[65536] = "";
                if (L->cur.type == T_STR) { strncpy(hexstr, L->cur.s, sizeof(hexstr)-1); lex_adv(L); }
                if (L->cur.type == T_RPAREN) lex_adv(L);
                if (!hexstr[0]) { r.is_none = 1; return r; }
                uint8_t *buf = malloc(32768);
                if (!buf) { r.is_none = 1; return r; }
                size_t n = fromhex_parse(hexstr, buf, 32768);
                if (n == 0) {
                    fprintf(stderr, CBRED "fromhex: no bytes parsed\n" CR);
                    free(buf); r.is_none = 1; return r;
                }
                printf(CMAG "<raw %zu bytes>" CR "\n", n);
                r.raw = buf; r.raw_len = n; r.is_raw = 1;
                return r;
            }
            /* frompcapng("file.pcapng", packet_number=N) — extract raw bytes from pcapng */
            if (!strcmp(name,"frompcapng")) {
                char filename[512] = "";
                uint32_t pktnum = 1;
                if (L->cur.type == T_STR) { strncpy(filename, L->cur.s, 511); lex_adv(L); }
                if (L->cur.type == T_COMMA) lex_adv(L);
                /* accept positional expr or keyword packet_number=expr ($var, literal, ...) */
                if (L->cur.type == T_IDENT && !strcmp(L->cur.s, "packet_number")) {
                    lex_adv(L); /* skip "packet_number" */
                    if (L->cur.type == T_EQ) lex_adv(L);
                }
                if (L->cur.type != T_RPAREN && L->cur.type != T_EOF) {
                    EvalResult nr = eval_primary(L);
                    if (nr.is_num) pktnum = (uint32_t)(int64_t)(int64_t)nr.num;
                }
                if (L->cur.type == T_RPAREN) lex_adv(L);
                if (!filename[0]) {
                    fprintf(stderr, CBRED "frompcapng: filename required\n" CR);
                    r.is_none = 1; return r;
                }
                size_t n = 0;
                uint8_t *buf = frompcapng_read(filename, pktnum, &n);
                if (!buf) { r.is_none = 1; return r; }
                printf(CMAG "<raw %zu bytes from %s packet #%u>" CR "\n", n, filename, pktnum);
                r.raw = buf; r.raw_len = n; r.is_raw = 1;
                return r;
            }
            /* replacepkt("file.pcapng", N, new_pkt) — replace packet N in-place */
            if (!strcmp(name,"replacepkt")) {
                char filename[512] = "";
                uint32_t pktnum = 1;
                if (L->cur.type == T_STR) { strncpy(filename, L->cur.s, 511); lex_adv(L); }
                if (L->cur.type == T_COMMA) lex_adv(L);
                if (L->cur.type != T_RPAREN && L->cur.type != T_EOF) {
                    EvalResult nr = eval_primary(L);
                    if (nr.is_num) pktnum = (uint32_t)(int64_t)nr.num;
                }
                if (L->cur.type == T_COMMA) lex_adv(L);
                EvalResult arg = eval_expr(L);
                if (L->cur.type == T_RPAREN) lex_adv(L);
                if (!filename[0]) {
                    fprintf(stderr, CBRED "replacepkt: filename required\n" CR);
                    if (arg.pkt) free_layer(arg.pkt);
                    if (arg.raw) free(arg.raw);
                    r.is_none = 1; return r;
                }
                if (!arg.pkt && !arg.raw) {
                    fprintf(stderr, CBRED "replacepkt: packet required as third argument\n" CR);
                    r.is_none = 1; return r;
                }
                uint8_t *buf = malloc(MAX_PKT_BYTES); size_t len = 0;
                if (!buf) {
                    if (arg.pkt) free_layer(arg.pkt);
                    if (arg.raw) free(arg.raw);
                    r.is_none = 1; return r;
                }
                if (arg.pkt) {
                    len = pkt_to_raw_ex(arg.pkt, buf, MAX_PKT_BYTES, 1);
                    free_layer(arg.pkt);
                } else {
                    len = arg.raw_len < MAX_PKT_BYTES ? arg.raw_len : MAX_PKT_BYTES;
                    memcpy(buf, arg.raw, len);
                    free(arg.raw);
                }
                if (replacepkt_in_file(filename, pktnum, buf, len) == 0)
                    printf(CGRN "Replaced packet #%u in %s (%zu bytes)\n" CR,
                           pktnum, filename, len);
                free(buf);
                r.is_none = 1; return r;
            }
            /* show("IP/UDP/DNS", raw) — dissect raw bytes through a protocol stack */
            if (!strcmp(name,"show")) {
                char proto_arg[128] = "";
                if (L->cur.type == T_STR) { strncpy(proto_arg, L->cur.s, 127); lex_adv(L); }
                else if (L->cur.type == T_IDENT) { strncpy(proto_arg, L->cur.s, 127); lex_adv(L); }
                if (L->cur.type == T_COMMA) lex_adv(L);
                EvalResult data_r = eval_expr(L);
                if (L->cur.type == T_RPAREN) lex_adv(L);
                const uint8_t *bytes = NULL; size_t blen = 0;
                uint8_t *tmp = NULL;
                if (data_r.raw) { bytes = data_r.raw; blen = data_r.raw_len; }
                else if (data_r.pkt) {
                    tmp = malloc(MAX_PKT_BYTES);
                    if (tmp) { blen = pkt_to_raw(data_r.pkt, tmp, MAX_PKT_BYTES); bytes = tmp; }
                    free_layer(data_r.pkt); data_r.pkt = NULL;
                }
                if (!bytes || !blen) {
                    fprintf(stderr, CBRED "show: no data\n" CR);
                    if (tmp) free(tmp);
                    r.is_none = 1; return r;
                }
                /* split proto_arg on '/' and walk the stack */
                char stack_buf[128];
                strncpy(stack_buf, proto_arg, 127);
                char *layers[16]; int nlayers = 0;
                char *tok = strtok(stack_buf, "/");
                while (tok && nlayers < 16) { layers[nlayers++] = tok; tok = strtok(NULL, "/"); }
                size_t offset = 0;
                for (int li = 0; li < nlayers; li++) {
                    if (offset >= blen) {
                        fprintf(stderr, CBRED "show: no bytes left for '%s'\n" CR, layers[li]);
                        break;
                    }
                    size_t consumed = show_layer_by_name(layers[li], bytes + offset, blen - offset);
                    if (consumed == 0) break; /* error already printed */
                    offset += consumed;
                }
                if (data_r.raw) free(data_r.raw);
                if (tmp) free(tmp);
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
                       CBYEL "DNS (native):\n" CR
                       "  " CCYN "DNS" CR "(id,qr,opcode,aa,tc,rd,ra,rcode,flags,qdcount,...\n"
                       "       qd=DNSQR(...), an=DNSRR(...), ns=..., ar=...)\n"
                       "  " CCYN "DNSQR" CR "(qname=\"host.example.com\", qtype=A, qclass=IN)\n"
                       "  " CCYN "DNSRR" CR "(rrname=\"host.example.com\", type=A, ttl=60, rdata=\"1.2.3.4\")\n"
                       "  " CCYN "RandShort" CR "()  random uint16\n"
                       "  qtype/type: A NS CNAME SOA PTR MX AAAA ANY (or integer)\n"
                       "\n"
                       CBYEL "Dynamic protocols (posa-defined):\n" CR
                       "  " CBCYN "ARP NTP DHCP GRE VXLAN RADIUS SYSLOG" CR "\n"
                       "  " CBCYN "NBT SMB2 DCERPC LDAP" CR "\n"
                       "  Plus any loaded via load() — use ls() to see all\n"
                       "\n"
                       CBYEL "Inline protocol definition:\n" CR
                       "  " CCYN "protocol" CR " MyProto\n"
                       "      required uint8  type = 0\n"
                       "          DATA = 1  CTRL = 2\n"
                       "      required uint16 length = 0\n"
                       "      required uint32 sequence = 0\n"
                       "  " CCYN "end" CR "\n"
                       "  Types: uint8 uint16 uint32 uint64 le_uint16 le_uint32 le_uint64\n"
                       "         mac ip4 cstring payload bytes<N> bytes[lenfield]\n"
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
                       "  " CCYN "fromhex" CR "(\"hex\")             parse hex dump → raw bytes\n"
                       "  " CCYN "frompcapng" CR "(\"file\",N)       read packet #N from pcapng → raw bytes\n"
                       "  " CCYN "replacepkt" CR "(\"file\",N,pkt)   replace packet #N in pcapng in-place\n"
                       "  " CCYN "show" CR "(\"IP/UDP/Proto\", raw)  dissect stacked layers\n"
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
                       "  IP(dst=\"8.8.8.8\")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=\"example.com\"))\n"
                       "  DNS(qr=1,an=DNSRR(rrname=\"x.com\",ttl=60,rdata=\"1.2.3.4\"),ancount=1)\n"
                       "  Ether(type=0x0806)/ARP(op=REQUEST,spa=\"192.168.1.1\")\n"
                       "  IP()/TCP()/NBT()/SMB2(command=READ)\n"
                       "  s = TCPSession(\"10.0.0.1\",\"10.0.0.2\",54321,80)\n"
                       "  wrpcap(\"http.pcapng\", syn(s))\n"
                       "  wrpcap(\"http.pcapng\", syn_ack(s))\n"
                       "  wrpcap(\"http.pcapng\", client_send(s,\"GET / HTTP/1.0\\r\\n\\r\\n\"))\n"
                       "  load(\"myproto.posa\")  ls(SMB2)\n"
                       "  show(\"IP/UDP/DNS\", fromhex(\"45 00 ...\"))\n"
                       "  show(\"IP/TCP/MyProto\", fromhex(\"45 00 ...\"))\n"
                       "\n");
                r.is_none = 1; return r;
            }
            /* exit() / quit() */
            if (!strcmp(name,"exit") || !strcmp(name,"quit")) {
                if (L->cur.type == T_RPAREN) lex_adv(L);
                linenoiseHistorySave(".pcapsh_history");
                exit(0);
            }
            /* RandShort() — random uint16 */
            if (!strcmp(name,"RandShort")) {
                if (L->cur.type == T_RPAREN) lex_adv(L);
                r.num = (uint64_t)(rand() & 0xffff); r.is_num = 1;
                return r;
            }
            /* DNSQR(qname="...", qtype=A, qclass=IN)
             * Returns raw bytes: encoded_name + qtype(BE16) + qclass(BE16) */
            if (!strcmp(name,"DNSQR")) {
                char qname[256] = ""; uint16_t qtype = 1, qclass = 1;
                while (L->cur.type != T_RPAREN && L->cur.type != T_EOF) {
                    if (L->cur.type == T_IDENT) {
                        char an[64]; strncpy(an, L->cur.s, 63); lex_adv(L);
                        if (L->cur.type == T_EQ) {
                            lex_adv(L);
                            if (!strcmp(an,"qname") && L->cur.type == T_STR)
                                { strncpy(qname, L->cur.s, 255); lex_adv(L); }
                            else if (!strcmp(an,"qtype")) {
                                if (L->cur.type==T_STR || L->cur.type==T_IDENT)
                                    { qtype = dns_qtype_from_str(L->cur.s); lex_adv(L); }
                                else if (L->cur.type==T_NUM)
                                    { qtype = (uint16_t)L->cur.n; lex_adv(L); }
                            } else if (!strcmp(an,"qclass")) {
                                if (L->cur.type==T_NUM) { qclass = (uint16_t)L->cur.n; lex_adv(L); }
                                else lex_adv(L);
                            } else lex_adv(L);
                        }
                    } else if (L->cur.type == T_STR) {
                        strncpy(qname, L->cur.s, 255); lex_adv(L);
                    } else lex_adv(L);
                    if (L->cur.type == T_COMMA) lex_adv(L);
                }
                if (L->cur.type == T_RPAREN) lex_adv(L);
                uint8_t buf[512]; size_t blen = 0;
                blen += dns_encode_name(qname, buf+blen, sizeof(buf)-blen);
                buf[blen++] = (qtype>>8)&0xff;  buf[blen++] = qtype&0xff;
                buf[blen++] = (qclass>>8)&0xff; buf[blen++] = qclass&0xff;
                r.raw = malloc(blen);
                if (r.raw) { memcpy(r.raw, buf, blen); r.raw_len = blen; }
                return r;
            }
            /* DNSRR(rrname="...", type=A, rclass=IN, ttl=0, rdata="1.2.3.4")
             * Returns raw bytes: encoded_name + type + class + ttl + rdlen + rdata */
            if (!strcmp(name,"DNSRR")) {
                char rrname[256] = "", rdata_s[256] = "";
                uint16_t type = 1, rclass = 1; uint32_t ttl = 0;
                while (L->cur.type != T_RPAREN && L->cur.type != T_EOF) {
                    if (L->cur.type == T_IDENT) {
                        char an[64]; strncpy(an, L->cur.s, 63); lex_adv(L);
                        if (L->cur.type == T_EQ) {
                            lex_adv(L);
                            if (!strcmp(an,"rrname") && L->cur.type==T_STR)
                                { strncpy(rrname, L->cur.s, 255); lex_adv(L); }
                            else if (!strcmp(an,"rdata") && L->cur.type==T_STR)
                                { strncpy(rdata_s, L->cur.s, 255); lex_adv(L); }
                            else if (!strcmp(an,"type")) {
                                if (L->cur.type==T_STR||L->cur.type==T_IDENT)
                                    { type = dns_qtype_from_str(L->cur.s); lex_adv(L); }
                                else if (L->cur.type==T_NUM)
                                    { type = (uint16_t)L->cur.n; lex_adv(L); }
                            } else if (!strcmp(an,"rclass")||!strcmp(an,"rdclass")) {
                                if (L->cur.type==T_NUM) { rclass=(uint16_t)L->cur.n; lex_adv(L); }
                                else lex_adv(L);
                            } else if (!strcmp(an,"ttl") && L->cur.type==T_NUM)
                                { ttl=(uint32_t)L->cur.n; lex_adv(L); }
                            else lex_adv(L);
                        }
                    } else if (L->cur.type==T_STR) {
                        strncpy(rrname, L->cur.s, 255); lex_adv(L);
                    } else lex_adv(L);
                    if (L->cur.type==T_COMMA) lex_adv(L);
                }
                if (L->cur.type==T_RPAREN) lex_adv(L);
                uint8_t rdata_b[256]; size_t rdlen = 0;
                if (type==1 && rdata_s[0]) {
                    struct in_addr a; a.s_addr = 0;
                    if (inet_aton(rdata_s, &a)) { memcpy(rdata_b, &a.s_addr, 4); rdlen = 4; }
                } else if ((type==5||type==2||type==12) && rdata_s[0]) {
                    rdlen = dns_encode_name(rdata_s, rdata_b, sizeof(rdata_b));
                } else if (rdata_s[0]) {
                    rdlen = strlen(rdata_s);
                    if (rdlen > sizeof(rdata_b)) rdlen = sizeof(rdata_b);
                    memcpy(rdata_b, rdata_s, rdlen);
                }
                uint8_t buf[512]; size_t blen = 0;
                blen += dns_encode_name(rrname, buf+blen, sizeof(buf)-blen);
                buf[blen++]=(type>>8)&0xff;   buf[blen++]=type&0xff;
                buf[blen++]=(rclass>>8)&0xff; buf[blen++]=rclass&0xff;
                buf[blen++]=(ttl>>24)&0xff;   buf[blen++]=(ttl>>16)&0xff;
                buf[blen++]=(ttl>>8)&0xff;    buf[blen++]=ttl&0xff;
                buf[blen++]=(rdlen>>8)&0xff;  buf[blen++]=rdlen&0xff;
                if (rdlen) { memcpy(buf+blen, rdata_b, rdlen); blen += rdlen; }
                r.raw = malloc(blen);
                if (r.raw) { memcpy(r.raw, buf, blen); r.raw_len = blen; }
                return r;
            }
            /* DNS(id, qr, opcode, aa, tc, rd, ra, rcode, flags,
             *     qdcount, ancount, nscount, arcount,
             *     qd=DNSQR(...), an=DNSRR(...), ns=DNSRR(...), ar=DNSRR(...))
             * Builds a complete DNS message as a Raw layer. */
            if (!strcmp(name,"DNS")) {
                uint16_t id = (uint16_t)(rand() & 0xffff);
                uint8_t  qr=0, opcode=0, aa=0, tc=0, rd=0, ra=0, rcode=0;
                uint16_t qdcount=0, ancount=0, nscount=0, arcount=0;
                uint16_t flags_ov=0; int flags_set=0;
                int qdcnt_set=0, ancnt_set=0, nscnt_set=0, arcnt_set=0;
                uint8_t qd_b[2048]; size_t qd_l=0;
                uint8_t an_b[2048]; size_t an_l=0;
                uint8_t ns_b[2048]; size_t ns_l=0;
                uint8_t ar_b[2048]; size_t ar_l=0;
                while (L->cur.type != T_RPAREN && L->cur.type != T_EOF) {
                    if (L->cur.type == T_IDENT) {
                        char an[64]; strncpy(an, L->cur.s, 63); lex_adv(L);
                        if (L->cur.type == T_EQ) {
                            lex_adv(L);
                            if (!strcmp(an,"qd")||!strcmp(an,"an")||
                                !strcmp(an,"ns")||!strcmp(an,"ar")) {
                                EvalResult sub = eval_expr(L);
                                if (sub.raw) {
                                    uint8_t *dst; size_t *dl; size_t dsz;
                                    if      (!strcmp(an,"qd")){ dst=qd_b; dl=&qd_l; dsz=sizeof(qd_b); if(!qdcnt_set) qdcount++; }
                                    else if (!strcmp(an,"an")){ dst=an_b; dl=&an_l; dsz=sizeof(an_b); if(!ancnt_set) ancount++; }
                                    else if (!strcmp(an,"ns")){ dst=ns_b; dl=&ns_l; dsz=sizeof(ns_b); if(!nscnt_set) nscount++; }
                                    else                       { dst=ar_b; dl=&ar_l; dsz=sizeof(ar_b); if(!arcnt_set) arcount++; }
                                    size_t cp = sub.raw_len < dsz-*dl ? sub.raw_len : dsz-*dl;
                                    memcpy(dst+*dl, sub.raw, cp); *dl += cp; free(sub.raw);
                                }
                                if (sub.pkt) free_layer(sub.pkt);
                            } else {
                                EvalResult sub = eval_expr(L);
                                uint64_t v = sub.is_num ? sub.num : 0;
                                if (!sub.is_num && sub.raw && sub.raw_len<=8) {
                                    for (size_t bi=0; bi<sub.raw_len; bi++) v=(v<<8)|sub.raw[bi];
                                    free(sub.raw);
                                }
                                if (sub.pkt) free_layer(sub.pkt);
                                if      (!strcmp(an,"id"))      id=(uint16_t)v;
                                else if (!strcmp(an,"qr"))      qr=(uint8_t)(v&1);
                                else if (!strcmp(an,"opcode"))  opcode=(uint8_t)(v&0xf);
                                else if (!strcmp(an,"aa"))      aa=(uint8_t)(v&1);
                                else if (!strcmp(an,"tc"))      tc=(uint8_t)(v&1);
                                else if (!strcmp(an,"rd"))      rd=(uint8_t)(v&1);
                                else if (!strcmp(an,"ra"))      ra=(uint8_t)(v&1);
                                else if (!strcmp(an,"rcode"))   rcode=(uint8_t)(v&0xf);
                                else if (!strcmp(an,"flags"))   { flags_ov=(uint16_t)v; flags_set=1; }
                                else if (!strcmp(an,"qdcount")) { qdcount=(uint16_t)v; qdcnt_set=1; }
                                else if (!strcmp(an,"ancount")) { ancount=(uint16_t)v; ancnt_set=1; }
                                else if (!strcmp(an,"nscount")) { nscount=(uint16_t)v; nscnt_set=1; }
                                else if (!strcmp(an,"arcount")) { arcount=(uint16_t)v; arcnt_set=1; }
                            }
                        }
                    } else lex_adv(L);
                    if (L->cur.type==T_COMMA) lex_adv(L);
                }
                if (L->cur.type==T_RPAREN) lex_adv(L);
                uint16_t fl = flags_set ? flags_ov
                    : (uint16_t)((qr<<15)|(opcode<<11)|(aa<<10)|(tc<<9)|(rd<<8)|(ra<<7)|(rcode&0xf));
                layer_t *dns_l = new_layer(PROTO_DNS);
                set_u64(dns_l, "id",      id);
                set_u64(dns_l, "flags",   fl);
                set_u64(dns_l, "qdcount", qdcount);
                set_u64(dns_l, "ancount", ancount);
                set_u64(dns_l, "nscount", nscount);
                set_u64(dns_l, "arcount", arcount);
                if (qd_l) set_bytes(dns_l, "_qd", qd_b, qd_l);
                if (an_l) set_bytes(dns_l, "_an", an_b, an_l);
                if (ns_l) set_bytes(dns_l, "_ns", ns_b, ns_l);
                if (ar_l) set_bytes(dns_l, "_ar", ar_b, ar_l);
                r.pkt = dns_l;
                return r;
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
        /* for dynamic protocols: resolve enum names and auto-fill length fields */
        if (lay->proto >= PROTO_DYNAMIC_BASE) {
            pdef_t *def = find_pdef_by_id(lay->proto);
            if (def) {
                resolve_dynamic_enums(def, lay);
                /* auto-fill bytes[lenfield] length fields so display matches wire */
                for (int _i = 0; _i < def->nflds; _i++) {
                    pfld_t *rf = &def->flds[_i];
                    if (rf->ftype != PFT_BYTES_REF || !rf->lenfield[0]) continue;
                    field_t *data_lf = find_field(lay, rf->fname);
                    size_t dlen = 0;
                    if (data_lf && data_lf->type==FT_BYTES && data_lf->raw) dlen = data_lf->raw_len;
                    else if (data_lf && data_lf->type==FT_STR) dlen = strlen(data_lf->s);
                    field_t *len_lf = find_field(lay, rf->lenfield);
                    if (len_lf) len_lf->n = (uint64_t)dlen;
                }
            }
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
        "DNS(","DNSQR(","DNSRR(","RandShort()",
        "hexdump(","raw(","ls(","wrpcap(","load(","fromhex(","frompcapng(","replacepkt(","show(",
        "help()","exit()","quit()",
        "TCPSession(","syn(","syn_ack(","tcp_ack(","client_send(","server_send(",
        "client_fin(","server_fin_ack(",
        "protocol ",
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

/* ─── For-loop support ───────────────────────────────────────────────────────── */

static void eval_line(const char *src); /* forward declaration */

/* Parse: for $varname in range([start,] stop [, step]):
 * Returns 1 on success, 0 if the line is not a for-loop header. */
static int parse_for_header(const char *line,
                            char *varname,       /* out: variable name (no $) */
                            int64_t *start_out,
                            int64_t *stop_out,
                            int64_t *step_out)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "for", 3) != 0) return 0;
    p += 3;
    if (*p != ' ' && *p != '\t') return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '$') return 0;
    p++;
    int i = 0;
    while ((isalnum((unsigned char)*p) || *p == '_') && i < 63)
        varname[i++] = *p++;
    varname[i] = '\0';
    if (i == 0) return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "in", 2) != 0) return 0;
    p += 2;
    if (*p != ' ' && *p != '\t') return 0;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "range", 5) != 0) return 0;
    p += 5;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '(') return 0;
    p++;
    int64_t args[3]; int nargs = 0;
    while (nargs < 3) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == ')') break;
        char *end;
        args[nargs++] = strtoll(p, &end, 10);
        if (end == p) return 0;
        p = end;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == ',') { p++; continue; }
        if (*p == ')') break;
        return 0;
    }
    if (*p != ')') return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != ':') return 0;
    if (nargs == 0) return 0;
    if (nargs == 1) { *start_out = 1; *stop_out = args[0] + 1; *step_out = 1; }
    else if (nargs == 2) { *start_out = args[0]; *stop_out = args[1]; *step_out = 1; }
    else                 { *start_out = args[0]; *stop_out = args[1]; *step_out = args[2]; }
    if (*step_out == 0) return 0;
    return 1;
}

/* Execute the body string (newline-separated lines) for each value in the range,
 * setting $varname to each value before evaluating the body. */
static void run_for_body(const char *varname, int64_t start, int64_t stop, int64_t step,
                         const char *body)
{
    /* iterate while (step>0 ? i < stop : i > stop) */
    int64_t i = start;
    while ((step > 0 && i < stop) || (step < 0 && i > stop)) {
        var_set_num(varname, i);
        /* execute each line of the body */
        char buf[4096];
        const char *p = body;
        while (*p) {
            const char *nl = strchr(p, '\n');
            size_t len = nl ? (size_t)(nl - p) : strlen(p);
            if (len >= sizeof(buf)) len = sizeof(buf) - 1;
            memcpy(buf, p, len); buf[len] = '\0';
            /* skip blank/comment lines */
            char *q = buf; while (*q == ' ' || *q == '\t') q++;
            if (*q && *q != '#') eval_line(buf);
            p += len + (nl ? 1 : 0);
            if (!nl) break;
        }
        i += step;
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
        while (L.cur.type != T_EOF  &&
               L.cur.type != T_IDENT &&
               L.cur.type != T_VAR  &&
               L.cur.type != T_NUM  &&
               L.cur.type != T_STR)
            lex_adv(&L);
    }
}

/* ─── Inline protocol definition (protocol NAME ... end) ─────────────────────── */

static void eval_protocol_block(const char *name, const char *body) {
    char posa[16384];
    snprintf(posa, sizeof(posa), "Object<main> %s\n%s", name, body);
    int n_before = npdefs;
    int n = parse_posa_src(posa);
    if (n > 0) {
        pdef_t *def = &pdefs[n_before];
        printf(CGRN "Protocol '%s' defined" CR " (%d field%s). "
               "Use " CCYN "%s()" CR " and " CCYN "ls(%s)" CR ".\n",
               name, def->nflds, def->nflds == 1 ? "" : "s", name, name);
    } else {
        fprintf(stderr, CBRED "Protocol '%s': no fields parsed — check syntax.\n" CR, name);
    }
}

/* ─── Script execution ───────────────────────────────────────────────────────── */

static int run_script(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, CBRED "pcapsh: cannot open script '%s': %s\n" CR, path, strerror(errno)); return 1; }

    char line[4096];
    char proto_name[64]   = {0};
    char proto_body[8192] = {0};
    int  in_proto = 0;

    char for_var[64]        = {0};
    char for_body[65536]    = {0};
    int64_t for_start = 0, for_stop = 0, for_step = 1;
    int  in_for = 0;

    while (fgets(line, sizeof(line), f)) {
        /* strip trailing CR/LF */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1]=='\n'||line[len-1]=='\r')) line[--len]='\0';

        char *p = line;
        while (*p==' '||*p=='\t') p++;

        if (in_proto) {
            if (strcmp(p, "end") == 0) {
                eval_protocol_block(proto_name, proto_body);
                in_proto = 0; proto_name[0] = 0; proto_body[0] = 0;
            } else {
                strncat(proto_body, line, sizeof(proto_body) - strlen(proto_body) - 2);
                strncat(proto_body, "\n", sizeof(proto_body) - strlen(proto_body) - 1);
            }
            continue;
        }

        if (in_for) {
            /* body lines must be indented; a non-empty, non-indented line ends the loop */
            int indented = (line[0] == ' ' || line[0] == '\t');
            if (!indented && *p && *p != '#') {
                /* flush and execute the loop, then fall through to process this line */
                run_for_body(for_var, for_start, for_stop, for_step, for_body);
                in_for = 0; for_var[0] = 0; for_body[0] = 0;
                /* fall through — process 'line' normally below */
            } else {
                if (*p && *p != '#') {
                    strncat(for_body, line, sizeof(for_body) - strlen(for_body) - 2);
                    strncat(for_body, "\n", sizeof(for_body) - strlen(for_body) - 1);
                }
                continue;
            }
        }

        if (!*p || *p=='#') continue;

        if (strncmp(p, "protocol ", 9) == 0) {
            in_proto = 1;
            p += 9; while (*p==' '||*p=='\t') p++;
            strncpy(proto_name, p, 63); proto_name[63] = 0;
            char *hash = strchr(proto_name, '#'); if (hash) *hash = 0;
            len = strlen(proto_name);
            while (len > 0 && (proto_name[len-1]==' '||proto_name[len-1]=='\t')) proto_name[--len]=0;
            continue;
        }

        char tmp_var[64]; int64_t ts, te, tstep;
        if (parse_for_header(p, tmp_var, &ts, &te, &tstep)) {
            in_for = 1;
            strncpy(for_var, tmp_var, 63); for_var[63] = 0;
            for_start = ts; for_stop = te; for_step = tstep;
            for_body[0] = 0;
            continue;
        }

        eval_line(line);
    }
    if (in_proto)
        fprintf(stderr, CBRED "pcapsh: unterminated 'protocol %s' block (missing 'end')\n" CR, proto_name);
    if (in_for)
        run_for_body(for_var, for_start, for_stop, for_step, for_body);
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
    /* register built-in protocols in the name/color registry */
    proto_register(PROTO_ETHER, "Ether", CBYEL);
    proto_register(PROTO_IP,    "IP",    CBCYN);
    proto_register(PROTO_TCP,   "TCP",   CBGRN);
    proto_register(PROTO_UDP,   "UDP",   CBMAG);
    proto_register(PROTO_ICMP,  "ICMP",  CBRED);
    proto_register(PROTO_RAW,   "Raw",   CWHT);
    proto_register(PROTO_DNS,   "DNS",   CBCYN);

    /* register built-in posa-defined protocols */
    parse_posa_src(BUILTIN_POSA);

    /* auto-load ~/.pcapsh_protos.posa; create with defaults if missing */
    {
        const char *home = getenv("HOME");
        if (home) {
            char p[512]; snprintf(p, sizeof(p), "%s/.pcapsh_protos.posa", home);
            struct stat _s;
            if (stat(p, &_s) != 0) {
                /* file does not exist — seed it with TFTP + Telnet examples */
                FILE *fp = fopen(p, "w");
                if (fp) {
                    fputs(DEFAULT_USER_POSA, fp);
                    fclose(fp);
                    fprintf(stderr, CGRN "Created %s with example protocols (TFTP, Telnet).\n" CR, p);
                }
            }
            parse_posa_file(p);
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

    const char *prompt      = CBCYN "pcapsh" CR CWHT " >>> " CR;
    const char *cont_prompt = CCYN  "...   " CR CWHT " ... " CR;

    char proto_name[64]   = {0};
    char proto_body[8192] = {0};
    int  in_proto = 0;

    char for_var[64]     = {0};
    char for_body[65536] = {0};
    int64_t for_start = 0, for_stop = 0, for_step = 1;
    int  in_for = 0;

    char *line;
    int continue_mode = 0; /* show cont_prompt when collecting multi-line constructs */
    while ((line = linenoise(continue_mode ? cont_prompt : prompt)) != NULL) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        if (in_proto) {
            if (strcmp(p, "end") == 0) {
                linenoiseHistoryAdd(line);
                eval_protocol_block(proto_name, proto_body);
                in_proto = 0; proto_name[0] = 0; proto_body[0] = 0;
                continue_mode = 0;
            } else {
                strncat(proto_body, line, sizeof(proto_body) - strlen(proto_body) - 2);
                strncat(proto_body, "\n", sizeof(proto_body) - strlen(proto_body) - 1);
            }
            linenoiseFree(line);
            continue;
        }

        if (in_for) {
            if (*p == '\0') {
                /* blank line — end of loop body, execute */
                linenoiseHistoryAdd(line);
                run_for_body(for_var, for_start, for_stop, for_step, for_body);
                in_for = 0; for_var[0] = 0; for_body[0] = 0;
                continue_mode = 0;
            } else {
                linenoiseHistoryAdd(line);
                strncat(for_body, line, sizeof(for_body) - strlen(for_body) - 2);
                strncat(for_body, "\n", sizeof(for_body) - strlen(for_body) - 1);
            }
            linenoiseFree(line);
            continue;
        }

        if (*p == '\0' || *p == '#') { linenoiseFree(line); continue; }

        if (strncmp(p, "protocol ", 9) == 0) {
            in_proto = 1; continue_mode = 1;
            p += 9; while (*p==' '||*p=='\t') p++;
            strncpy(proto_name, p, 63); proto_name[63] = 0;
            char *hash = strchr(proto_name, '#'); if (hash) *hash = 0;
            size_t nl = strlen(proto_name);
            while (nl > 0 && (proto_name[nl-1]==' '||proto_name[nl-1]=='\t')) proto_name[--nl]=0;
            linenoiseHistoryAdd(line);
            linenoiseFree(line);
            continue;
        }

        char tmp_var[64]; int64_t ts, te, tstep;
        if (parse_for_header(p, tmp_var, &ts, &te, &tstep)) {
            in_for = 1; continue_mode = 1;
            strncpy(for_var, tmp_var, 63); for_var[63] = 0;
            for_start = ts; for_stop = te; for_step = tstep;
            for_body[0] = 0;
            linenoiseHistoryAdd(line);
            linenoiseFree(line);
            continue;
        }

        linenoiseHistoryAdd(line);
        eval_line(line);
        linenoiseFree(line);
    }

    linenoiseHistorySave(".pcapsh_history");
    printf("\n");
    return 0;
}
