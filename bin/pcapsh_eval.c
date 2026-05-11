/* pcapsh_eval.c — variable storage, lexer, evaluator, TCP session builders
 * Included as part of the pcapsh unity build (see pcapsh.c). */
#include "pcapsh.h"
#include <libpcapng/protocols/ssl.h>
#include <libpcapng/protocols/ssh.h>

int g_tls_used = 0; /* set when any TLS_* function or TLS() layer is used */

/* ─── Automatic TCP seq/ack tracking table ──────────────────────────────────── */
#define TCP_AUTOTRACK_MAX 64

typedef struct {
    uint32_t a_ip,  b_ip;    /* a = SYN sender, b = responder */
    uint16_t a_port, b_port;
    uint32_t a_seq, b_seq;   /* next seq to emit from each side */
    int      active;
} tcp_autotrack_t;

static tcp_autotrack_t tcp_autotrack[TCP_AUTOTRACK_MAX];

static tcp_autotrack_t *autotrack_find(uint32_t src, uint16_t sport,
                                       uint32_t dst, uint16_t dport,
                                       int *from_a)
{
    for (int i = 0; i < TCP_AUTOTRACK_MAX; i++) {
        if (!tcp_autotrack[i].active) continue;
        tcp_autotrack_t *e = &tcp_autotrack[i];
        if (e->a_ip==src && e->a_port==sport && e->b_ip==dst && e->b_port==dport)
            { *from_a=1; return e; }
        if (e->b_ip==src && e->b_port==sport && e->a_ip==dst && e->a_port==dport)
            { *from_a=0; return e; }
    }
    return NULL;
}

static tcp_autotrack_t *autotrack_new(uint32_t src, uint16_t sport,
                                      uint32_t dst, uint16_t dport)
{
    for (int i = 0; i < TCP_AUTOTRACK_MAX; i++) {
        if (!tcp_autotrack[i].active) {
            tcp_autotrack_t *e = &tcp_autotrack[i];
            memset(e, 0, sizeof(*e));
            e->active=1; e->a_ip=src; e->a_port=sport; e->b_ip=dst; e->b_port=dport;
            return e;
        }
    }
    return NULL;
}

/* Called from wrpcap() before serialization.
 * For each TCP field (seq, ack): if is_auto=1, fill from session table;
 * if is_auto=0 (user wrote explicit value), keep it and sync the tracker. */
static void tcp_autotrack_fixup(layer_t *chain)
{
    layer_t *ip_lay=NULL, *tcp_lay=NULL;
    for (layer_t *l=chain; l; l=l->next) {
        if (l->proto==PROTO_IP  && !ip_lay)  ip_lay=l;
        if (l->proto==PROTO_TCP && !tcp_lay) tcp_lay=l;
    }
    if (!tcp_lay) return;

    field_t *f_sport = find_field(tcp_lay,"sport");
    field_t *f_dport = find_field(tcp_lay,"dport");
    field_t *f_seq   = find_field(tcp_lay,"seq");
    field_t *f_ack   = find_field(tcp_lay,"ack");
    field_t *f_flags = find_field(tcp_lay,"flags");
    if (!f_sport || !f_dport || !f_seq || !f_ack) return;

    uint32_t src_ip = (ip_lay && find_field(ip_lay,"src")) ? (uint32_t)find_field(ip_lay,"src")->n : 0;
    uint32_t dst_ip = (ip_lay && find_field(ip_lay,"dst")) ? (uint32_t)find_field(ip_lay,"dst")->n : 0;
    uint16_t sport  = (uint16_t)f_sport->n;
    uint16_t dport  = (uint16_t)f_dport->n;

    int has_syn=0, has_ack=0, has_fin=0, has_rst=0;
    if (f_flags && f_flags->type==FT_STR) {
        for (const char *p=f_flags->s; *p; p++) {
            if (*p=='S'||*p=='s') has_syn=1;
            if (*p=='A'||*p=='a') has_ack=1;
            if (*p=='F'||*p=='f') has_fin=1;
            if (*p=='R'||*p=='r') has_rst=1;
        }
    }
    if (has_rst) return;

    /* Sum payload bytes in all raw layers after TCP */
    size_t data_len=0; int past=0;
    for (layer_t *l=chain; l; l=l->next) {
        if (l==tcp_lay) { past=1; continue; }
        if (!past) continue;
        if (l->proto==PROTO_RAW) {
            field_t *rf=find_field(l,"load");
            if (rf && rf->raw) data_len+=rf->raw_len;
        }
    }

    int from_a=1;
    tcp_autotrack_t *e = autotrack_find(src_ip,sport,dst_ip,dport,&from_a);

    if (!e) {
        /* First time we see this 4-tuple — create entry on SYN, ignore others */
        if (!has_syn) return;
        e = autotrack_new(src_ip,sport,dst_ip,dport);
        if (!e) return;
        /* Seed initial seq from user's explicit value or a fixed default */
        uint32_t init = f_seq->is_auto ? 0xdeadbe00u : (uint32_t)f_seq->n;
        if (f_seq->is_auto) { f_seq->n=init; f_seq->is_auto=0; }
        e->a_seq = init + 1; /* SYN consumes 1 */
        e->b_seq = 0;
        return;
    }

    uint32_t *my_seq   = from_a ? &e->a_seq : &e->b_seq;
    uint32_t *peer_seq = from_a ? &e->b_seq : &e->a_seq;

    /* Resolve seq: auto → fill from table; explicit → sync table from packet */
    if (f_seq->is_auto) { f_seq->n=*my_seq; f_seq->is_auto=0; }
    else                { *my_seq=(uint32_t)f_seq->n; }

    /* Resolve ack */
    if (has_ack) {
        if (f_ack->is_auto) { f_ack->n=*peer_seq; f_ack->is_auto=0; }
        else                { *peer_seq=(uint32_t)f_ack->n; }
    }

    /* Advance my_seq by what this packet consumed in sequence space */
    *my_seq = (uint32_t)f_seq->n + (uint32_t)data_len + has_fin + has_syn;
}

void pcapsh_eval_reset(void) {
    memset(tcp_autotrack, 0, sizeof(tcp_autotrack));
    g_tls_used = 0;
}

/* ─── Variable storage ──────────────────────────────────────────────────────── */

var_t *var_find(const char *name) {
    for (int i = 0; i < nvars; i++)
        if (vars[i].used && strcmp(vars[i].name, name) == 0)
            return &vars[i];
    return NULL;
}

var_t *var_set_pkt(const char *name, layer_t *pkt) {
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

var_t *var_set_session(const char *varname, sess_t *sess) {
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

var_t *var_set_raw(const char *name, const uint8_t *data, size_t len) {
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

var_t *var_set_num(const char *name, int64_t val) {
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

void lex_adv(Lex *L) {
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
            if (i >= 8190) break;
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
            snprintf(L->cur.s,8191,"0x%llx",(unsigned long long)L->cur.n);
            L->pos = (int)(e - L->src);
        } else {
            char *e; L->cur.n = strtoull(L->src+L->pos, &e, 10);
            snprintf(L->cur.s,8191,"%llu",(unsigned long long)L->cur.n);
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
        case '+': L->cur.type = T_PLUS;   break;
        case '-': L->cur.type = T_MINUS;  break;
        case '*': L->cur.type = T_STAR;   break;
        default:
            snprintf(L->err,255,"unexpected '%c'",c);
            L->cur.type = T_EOF; break;
    }
}

void lex_init(Lex *L, const char *src) {
    L->src = src; L->pos = 0; L->err[0] = '\0';
    lex_adv(L);
}

/* ─── apply a named/positional arg to a layer ───────────────────────────────── */

/* Read one numeric atom (T_NUM or T_VAR) and return its value.
 * Returns 0 and leaves L unchanged if the current token is neither. */
static int read_num_atom(Lex *L, int64_t *out) {
    if (L->cur.type == T_NUM) {
        *out = (int64_t)L->cur.n;
        lex_adv(L);
        return 1;
    }
    if (L->cur.type == T_VAR) {
        var_t *v = var_find(L->cur.s);
        *out = (v && v->is_num) ? (int64_t)v->numval : 0;
        lex_adv(L);
        return 1;
    }
    return 0;
}

void apply_field(layer_t *l, const char *name, Lex *L) {
    int64_t atom;
    if (read_num_atom(L, &atom)) {
        /* evaluate optional arithmetic chain: expr = atom [op atom]* */
        /* precedence: first collect all * terms, then + / - */
        int64_t product = atom;
        while (L->cur.type == T_STAR) {
            lex_adv(L);
            int64_t rhs; if (!read_num_atom(L, &rhs)) break;
            product *= rhs;
        }
        int64_t result = product;
        while (L->cur.type == T_PLUS || L->cur.type == T_MINUS) {
            TT op = L->cur.type;
            lex_adv(L);
            int64_t rhs; if (!read_num_atom(L, &rhs)) break;
            /* consume any following * for the right-hand term */
            while (L->cur.type == T_STAR) {
                lex_adv(L);
                int64_t f; if (!read_num_atom(L, &f)) break;
                rhs *= f;
            }
            result = (op == T_PLUS) ? result + rhs : result - rhs;
        }
        set_u64(l, name, (uint64_t)result);
    } else if (L->cur.type == T_STR) {
        const char *val = L->cur.s;
        size_t slen = L->cur.slen;
        struct in_addr addr;
        if (inet_aton(val, &addr)) {
            set_ip4(l, name, val);
        } else if (strlen(val) == 17 && val[2] == ':' && val[5] == ':') {
            set_mac(l, name, val);
        } else if (slen != strlen(val)) {
            set_bytes(l, name, (const uint8_t*)val, slen);
        } else {
            set_str(l, name, val);
        }
        lex_adv(L);
    } else if (L->cur.type == T_IDENT) {
        set_str(l, name, L->cur.s);
        lex_adv(L);
    }
}

/* ─── parse arglist into a layer ────────────────────────────────────────────── */

void parse_arglist(Lex *L, layer_t *lay) {
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

EvalResult eval_expr(Lex *L);

/* ─── TCP Session packet builders ───────────────────────────────────────────── */

layer_t *sess_build_pkt(sess_t *s, int from_client,
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

layer_t *do_syn(sess_t *s) {
    layer_t *p = sess_build_pkt(s, 1, s->cli_seq, 0, "S", NULL, 0);
    s->cli_seq++;
    return p;
}
layer_t *do_syn_ack(sess_t *s) {
    layer_t *p = sess_build_pkt(s, 0, s->srv_seq, s->cli_seq, "SA", NULL, 0);
    s->srv_seq++;
    return p;
}
layer_t *do_tcp_ack(sess_t *s) {
    return sess_build_pkt(s, 1, s->cli_seq, s->srv_seq, "A", NULL, 0);
}
layer_t *do_client_send(sess_t *s, const uint8_t *data, size_t dlen) {
    layer_t *p = sess_build_pkt(s, 1, s->cli_seq, s->srv_seq, "PA", data, dlen);
    s->cli_seq += (uint32_t)dlen;
    return p;
}
layer_t *do_server_send(sess_t *s, const uint8_t *data, size_t dlen) {
    layer_t *p = sess_build_pkt(s, 0, s->srv_seq, s->cli_seq, "PA", data, dlen);
    s->srv_seq += (uint32_t)dlen;
    return p;
}
layer_t *do_client_fin(sess_t *s) {
    layer_t *p = sess_build_pkt(s, 1, s->cli_seq, s->srv_seq, "FA", NULL, 0);
    s->cli_seq++;
    return p;
}
layer_t *do_server_fin_ack(sess_t *s) {
    layer_t *p = sess_build_pkt(s, 0, s->srv_seq, s->cli_seq, "FA", NULL, 0);
    s->srv_seq++;
    return p;
}

/* ─── DNS wire-format helpers ───────────────────────────────────────────────── */

uint16_t dns_qtype_from_str(const char *s) {
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
size_t dns_encode_name(const char *name, uint8_t *out, size_t max) {
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

EvalResult eval_primary(Lex *L) {
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
        else if (!strcmp(name,"TLS"))   { lay = make_tls_layer(); g_tls_used = 1; }
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
                if (!g_packet_cb)
                    printf(CMAG "<raw %zu bytes>" CR "\n", n);
                r.raw = buf; r.raw_len = n; r.is_raw = 1;
                return r;
            }
            /* TLS handshake record builders */
            if (!strcmp(name,"TLS_CLIENT_HELLO")) {
                /* Optional: TLS_CLIENT_HELLO(sni="hostname") */
                char sni[256] = "";
                while (L->cur.type != T_RPAREN && L->cur.type != T_EOF) {
                    if (L->cur.type == T_IDENT && !strcmp(L->cur.s, "sni")) {
                        lex_adv(L);
                        if (L->cur.type == T_EQ) lex_adv(L);
                        if (L->cur.type == T_STR) {
                            strncpy(sni, L->cur.s, sizeof(sni)-1);
                            lex_adv(L);
                        }
                    } else {
                        lex_adv(L);
                    }
                    if (L->cur.type == T_COMMA) lex_adv(L);
                }
                if (L->cur.type == T_RPAREN) lex_adv(L);
                uint8_t *buf = malloc(1024);
                if (!buf) { r.is_none = 1; return r; }
                size_t n = sni[0] ? tls_build_client_hello_sni(buf, 1024, sni)
                                  : tls_build_client_hello(buf, 1024);
                r.raw = buf; r.raw_len = n; r.is_raw = 1;
                g_tls_used = 1;
                return r;
            }
            if (!strcmp(name,"TLS_SERVER_HELLO")) {
                if (L->cur.type == T_RPAREN) lex_adv(L);
                uint8_t *buf = malloc(1024);
                if (!buf) { r.is_none = 1; return r; }
                size_t n = tls_build_server_hello(buf, 1024);
                r.raw = buf; r.raw_len = n; r.is_raw = 1;
                return r;
            }
            if (!strcmp(name,"TLS_CERTIFICATE")) {
                /* Optional: TLS_CERTIFICATE(cn="Common Name") */
                char cn[256] = "";
                while (L->cur.type != T_RPAREN && L->cur.type != T_EOF) {
                    if (L->cur.type == T_IDENT && !strcmp(L->cur.s, "cn")) {
                        lex_adv(L);
                        if (L->cur.type == T_EQ) lex_adv(L);
                        if (L->cur.type == T_STR) {
                            strncpy(cn, L->cur.s, sizeof(cn)-1);
                            lex_adv(L);
                        }
                    } else {
                        lex_adv(L);
                    }
                    if (L->cur.type == T_COMMA) lex_adv(L);
                }
                if (L->cur.type == T_RPAREN) lex_adv(L);
                uint8_t *buf = malloc(4096);
                if (!buf) { r.is_none = 1; return r; }
                size_t n = cn[0] ? tls_build_certificate_with_cn(buf, 4096, cn)
                                 : tls_build_certificate(buf, 4096, NULL, 0);
                r.raw = buf; r.raw_len = n; r.is_raw = 1;
                return r;
            }
            if (!strcmp(name,"TLS_CHANGE_CIPHER_SPEC")) {
                if (L->cur.type == T_RPAREN) lex_adv(L);
                uint8_t *buf = malloc(64);
                if (!buf) { r.is_none = 1; return r; }
                size_t n = tls_build_change_cipher_spec(buf, 64);
                r.raw = buf; r.raw_len = n; r.is_raw = 1;
                return r;
            }
            if (!strcmp(name,"TLS_FINISHED")) {
                if (L->cur.type == T_RPAREN) lex_adv(L);
                uint8_t *buf = malloc(256);
                if (!buf) { r.is_none = 1; return r; }
                size_t n = tls_build_finished(buf, 256);
                r.raw = buf; r.raw_len = n; r.is_raw = 1;
                return r;
            }
            /* SSH binary packet builders */
            if (!strcmp(name,"SSH_KEXINIT")) {
                /* Optional: SSH_KEXINIT(side="server")  default: client */
                int is_server = 0;
                while (L->cur.type != T_RPAREN && L->cur.type != T_EOF) {
                    if (L->cur.type == T_IDENT && !strcmp(L->cur.s, "side")) {
                        lex_adv(L);
                        if (L->cur.type == T_EQ) lex_adv(L);
                        if (L->cur.type == T_STR) {
                            if (!strcmp(L->cur.s, "server")) is_server = 1;
                            lex_adv(L);
                        }
                    } else {
                        lex_adv(L);
                    }
                    if (L->cur.type == T_COMMA) lex_adv(L);
                }
                if (L->cur.type == T_RPAREN) lex_adv(L);
                uint8_t *buf = malloc(2048);
                if (!buf) { r.is_none = 1; return r; }
                size_t n = ssh_build_kexinit(buf, 2048, is_server);
                r.raw = buf; r.raw_len = n; r.is_raw = 1;
                return r;
            }
            if (!strcmp(name,"SSH_NEWKEYS")) {
                if (L->cur.type == T_RPAREN) lex_adv(L);
                uint8_t *buf = malloc(32);
                if (!buf) { r.is_none = 1; return r; }
                size_t n = ssh_build_newkeys(buf, 32);
                r.raw = buf; r.raw_len = n; r.is_raw = 1;
                return r;
            }

            /* frompcapng("file.pcapng", packet_number=N) — extract raw bytes from pcapng */
            if (!strcmp(name,"frompcapng")) {
                char filename[MAXPATH] = "";
                uint32_t pktnum = 1;
                if (L->cur.type == T_STR) { strncpy(filename, L->cur.s, sizeof(filename)-1); lex_adv(L); }
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
                if (!g_packet_cb)
                    printf(CMAG "<raw %zu bytes from %s packet #%u>" CR "\n", n, filename, pktnum);
                r.raw = buf; r.raw_len = n; r.is_raw = 1;
                return r;
            }
            /* replacepkt("file.pcapng", N, new_pkt) — replace packet N in-place */
            if (!strcmp(name,"replacepkt")) {
                char filename[MAXPATH] = "";
                uint32_t pktnum = 1;
                if (L->cur.type == T_STR) { strncpy(filename, L->cur.s, sizeof(filename)-1); lex_adv(L); }
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
                char filename[MAXPATH] = "";
                if (L->cur.type == T_STR) {
                    if (wrpcap_override[0])
                        strncpy(filename, wrpcap_override, sizeof(filename)-1);
                    else
                        strncpy(filename, L->cur.s, sizeof(filename)-1);
                    lex_adv(L);
                }
                if (L->cur.type == T_COMMA) lex_adv(L);
                EvalResult arg = eval_expr(L);
                if (L->cur.type == T_RPAREN) lex_adv(L);
                if ((filename[0] || g_packet_cb) && (arg.pkt || arg.raw)) {
                    uint8_t *buf = malloc(MAX_PKT_BYTES); size_t len = 0;
                    if (!buf) { if (arg.pkt) free_layer(arg.pkt); if (arg.raw) free(arg.raw); r.is_none=1; return r; }
                    if (arg.pkt) {
                        tcp_autotrack_fixup(arg.pkt);
                        len = pkt_to_raw_ex(arg.pkt, buf, MAX_PKT_BYTES, 1);
                        free_layer(arg.pkt);
                    } else if (arg.raw) {
                        len = arg.raw_len < MAX_PKT_BYTES ? arg.raw_len : MAX_PKT_BYTES;
                        memcpy(buf, arg.raw, len);
                        free(arg.raw);
                    }
                    if (g_packet_cb) {
                        /* embedded / Python mode: deliver raw bytes via callback */
                        g_packet_cb(buf, len, g_packet_cb_userdata);
                    } else {
                        /* CLI mode: write to pcapng file */
                        struct stat _st; int exists = (stat(filename, &_st) == 0);
                        FILE *fp = fopen(filename, exists ? "ab" : "wb");
                        if (!fp) { perror("wrpcap"); free(buf); r.is_none=1; return r; }
                        if (!exists) libpcapng_write_header_to_file_with_linktype(fp, LINKTYPE_ETHERNET);
                        libpcapng_write_enhanced_packet_to_file(fp, buf, len);
                        fclose(fp);
                        printf(CGRN "%s %zu bytes to %s\n" CR, exists ? "Appended" : "Wrote", len, filename);
                    }
                    free(buf);
                }
                r.is_none = 1; return r;
            }
            /* load("file.posa") — load protocol definitions */
            if (!strcmp(name,"load")) {
                char path[MAXPATH] = "";
                if (L->cur.type == T_STR) { strncpy(path, L->cur.s, sizeof(path)-1); lex_adv(L); }
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
                       CBYEL "TLS helpers:\n" CR
                       "  " CCYN "TLS_CLIENT_HELLO" CR "([sni=\"host\"])   "
                       CCYN "TLS_SERVER_HELLO" CR "()\n"
                       "  " CCYN "TLS_CERTIFICATE" CR "([cn=\"Common Name\"])   "
                       CCYN "TLS_CHANGE_CIPHER_SPEC" CR "()\n"
                       "  " CCYN "TLS_FINISHED" CR "()\n"
                       "\n"
                       CBYEL "SSH helpers (binary packet framing, RFC 4253):\n" CR
                       "  " CCYN "SSH_KEXINIT" CR "([side=\"server\"])   "
                       CCYN "SSH_NEWKEYS" CR "()\n"
                       "  Banner (plain text, use string literal): "
                       "\"SSH-2.0-OpenSSH_9.5\\r\\n\"\n"
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
            /* client_send(session, data) / server_send(session, data)
             * data may be a string literal OR any expression returning bytes
             * (e.g. raw(SOCKS5_HELLO()), raw(BGP(type=4)), etc.) */
            if (!strcmp(name,"client_send") || !strcmp(name,"server_send")) {
                EvalResult arg = eval_expr(L);
                const uint8_t *data = NULL; size_t dlen = 0;
                static uint8_t dbuf[8192];
                if (L->cur.type == T_COMMA) lex_adv(L);
                if (L->cur.type == T_STR) {
                    dlen = L->cur.slen < sizeof(dbuf) ? L->cur.slen : sizeof(dbuf);
                    memcpy(dbuf, L->cur.s, dlen); data = dbuf;
                    lex_adv(L);
                } else if (L->cur.type != T_RPAREN && L->cur.type != T_EOF) {
                    EvalResult darg = eval_expr(L);
                    if (darg.is_raw && darg.raw) {
                        dlen = darg.raw_len < sizeof(dbuf) ? darg.raw_len : sizeof(dbuf);
                        memcpy(dbuf, darg.raw, dlen); data = dbuf;
                        free(darg.raw);
                    } else if (darg.pkt) {
                        dlen = pkt_to_raw(darg.pkt, dbuf, sizeof(dbuf));
                        if (dlen) data = dbuf;
                        free_layer(darg.pkt);
                    }
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

EvalResult eval_chain(Lex *L) {
    EvalResult r = eval_primary(L);
    while (L->cur.type == T_SLASH) {
        lex_adv(L); /* consume / */
        EvalResult rhs = eval_primary(L);
        if (rhs.pkt) {
            if (r.pkt) chain_append(r.pkt, rhs.pkt);
            else r.pkt = rhs.pkt;
        } else if (rhs.is_raw && rhs.raw && rhs.raw_len) {
            layer_t *raw_lay = make_raw_layer(rhs.raw, rhs.raw_len);
            if (r.pkt) chain_append(r.pkt, raw_lay);
            else r.pkt = raw_lay;
        }
    }
    return r;
}

/* ─── Evaluate a full expression (possibly an assignment) ───────────────────── */

EvalResult eval_expr(Lex *L) {
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
