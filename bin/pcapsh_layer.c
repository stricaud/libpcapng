/* pcapsh_layer.c — layer/field operations, session management, protocol registry
 * Included as part of the pcapsh unity build (see pcapsh.c). */
#include "pcapsh.h"

/* ─── Protocol registry ─────────────────────────────────────────────────────── */

void proto_register(int id, const char *name, const char *color) {
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

const char *proto_name(int p) {
    for (int i = 0; i < nproto_reg; i++)
        if (proto_reg[i].id == p) return proto_reg[i].name;
    return "???";
}

const char *proto_color(int p) {
    static const char *dc[] = {CBYEL,CBGRN,CBMAG,CBCYN,CBRED,CBLU,CWHT};
    for (int i = 0; i < nproto_reg; i++)
        if (proto_reg[i].id == p) return proto_reg[i].color;
    return dc[p % 7];
}

/* ─── Networking utilities ──────────────────────────────────────────────────── */

void ip_to_mac(uint32_t ip_host, uint8_t mac[6]) {
    mac[0] = 0x02; mac[1] = 0x00;
    mac[2] = (ip_host >> 24) & 0xff;
    mac[3] = (ip_host >> 16) & 0xff;
    mac[4] = (ip_host >> 8)  & 0xff;
    mac[5] =  ip_host        & 0xff;
}

void ip_str(uint32_t ip_host, char *buf, size_t sz) {
    struct in_addr a; a.s_addr = htonl(ip_host);
    strncpy(buf, inet_ntoa(a), sz - 1);
    buf[sz - 1] = '\0';
}

/* ─── Session management ────────────────────────────────────────────────────── */

sess_t *sess_find(const char *name) {
    for (int i = 0; i < nsessions; i++)
        if (strcmp(sessions[i].name, name) == 0) return &sessions[i];
    return NULL;
}

sess_t *sess_new(const char *client_ip_str, const char *server_ip_str,
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

/* ─── Field helpers ─────────────────────────────────────────────────────────── */

field_t *find_field(layer_t *l, const char *name) {
    if (!l) return NULL;
    for (int i = 0; i < l->nflds; i++)
        if (strcmp(l->flds[i].name, name) == 0)
            return &l->flds[i];
    return NULL;
}

field_t *get_or_add(layer_t *l, const char *name) {
    field_t *f = find_field(l, name);
    if (!f) {
        if (l->nflds >= MAX_FIELDS) return NULL;
        f = &l->flds[l->nflds++];
        memset(f, 0, sizeof(*f));
        strncpy(f->name, name, 31);
    }
    return f;
}

void set_u64(layer_t *l, const char *n, uint64_t v) {
    field_t *f = get_or_add(l, n);
    if (!f) return;
    f->type = FT_U64; f->n = v; f->is_auto = 0;
}

void set_auto(layer_t *l, const char *n, ftype_t t) {
    field_t *f = get_or_add(l, n);
    if (!f) return;
    f->type = t; f->is_auto = 1;
}

void set_ip4(layer_t *l, const char *n, const char *ip) {
    field_t *f = get_or_add(l, n);
    if (!f) return;
    f->type = FT_IP4;
    f->n    = ntohl(inet_addr(ip));
    strncpy(f->s, ip, 255);
    f->is_auto = 0;
}

void set_mac(layer_t *l, const char *n, const char *mac) {
    field_t *f = get_or_add(l, n);
    if (!f) return;
    f->type = FT_MAC;
    libpcapng_mac_str_to_bytes(mac, f->mac);
    strncpy(f->s, mac, 255);
    f->is_auto = 0;
}

void set_str(layer_t *l, const char *n, const char *s) {
    field_t *f = get_or_add(l, n);
    if (!f) return;
    f->type = FT_STR;
    strncpy(f->s, s, 255);
    f->is_auto = 0;
}

void set_bytes(layer_t *l, const char *n, const uint8_t *data, size_t len) {
    field_t *f = get_or_add(l, n);
    if (!f) return;
    f->type = FT_BYTES;
    if (f->raw) free(f->raw);
    f->raw = malloc(len);
    if (f->raw) { memcpy(f->raw, data, len); f->raw_len = len; }
    f->is_auto = 0;
}

uint64_t get_u64(layer_t *l, const char *n, uint64_t def) {
    field_t *f = find_field(l, n);
    return (f && !f->is_auto) ? f->n : def;
}

const char *get_str(layer_t *l, const char *n, const char *def) {
    field_t *f = find_field(l, n);
    return f ? f->s : def;
}

uint32_t get_ip4(layer_t *l, const char *n, const char *def) {
    field_t *f = find_field(l, n);
    if (f && f->type == FT_IP4 && !f->is_auto) return (uint32_t)f->n;
    return ntohl(inet_addr(def));
}

void get_mac(layer_t *l, const char *n, const uint8_t def[6], uint8_t out[6]) {
    field_t *f = find_field(l, n);
    if (f && f->type == FT_MAC && !f->is_auto) { memcpy(out, f->mac, 6); return; }
    memcpy(out, def, 6);
}

/* ─── Layer constructors ────────────────────────────────────────────────────── */

layer_t *new_layer(int proto) {
    layer_t *l = calloc(1, sizeof(layer_t));
    if (l) l->proto = proto;
    return l;
}

layer_t *make_ether(void) {
    layer_t *l = new_layer(PROTO_ETHER);
    set_mac(l, "dst", "ff:ff:ff:ff:ff:ff");
    set_mac(l, "src", "00:00:00:00:00:00");
    set_auto(l, "type", FT_U64);
    return l;
}

layer_t *make_ip(void) {
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

layer_t *make_tcp(void) {
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

layer_t *make_udp(void) {
    layer_t *l = new_layer(PROTO_UDP);
    set_u64(l, "sport", 53);
    set_u64(l, "dport", 53);
    set_auto(l, "len", FT_U64);
    set_auto(l, "chksum", FT_U64);
    return l;
}

layer_t *make_icmp(void) {
    layer_t *l = new_layer(PROTO_ICMP);
    set_u64(l, "type", 8);
    set_u64(l, "code", 0);
    set_auto(l, "chksum", FT_U64);
    set_u64(l, "id", 0);
    set_u64(l, "seq", 0);
    return l;
}

layer_t *make_tls_layer(void) {
    layer_t *l = new_layer(PROTO_TLS);
    return l;
}

layer_t *make_raw_layer(const uint8_t *data, size_t len) {
    layer_t *l = new_layer(PROTO_RAW);
    set_bytes(l, "load", data, len);
    return l;
}

void free_layer(layer_t *l) {
    if (!l) return;
    free_layer(l->next);
    for (int i = 0; i < l->nflds; i++)
        if (l->flds[i].raw) free(l->flds[i].raw);
    free(l);
}

layer_t *clone_chain(layer_t *l) {
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

layer_t *chain_append(layer_t *a, layer_t *b) {
    if (!a) return b;
    layer_t *t = a;
    while (t->next) t = t->next;
    t->next = b;
    return a;
}

/* ─── TCP flags ─────────────────────────────────────────────────────────────── */

uint8_t parse_tcp_flags(const char *s) {
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
