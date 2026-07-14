/* pcapsh.h — shared types, constants, and global declarations for pcapsh
 *
 * All sub-modules (pcapsh_layer.c, pcapsh_posa.c, pcapsh_io.c,
 * pcapsh_eval.c, pcapsh_main.c) are compiled as a unity build via pcapsh.c.
 * This header provides type definitions and extern declarations so that IDEs
 * can resolve symbols when browsing sub-module files directly.
 */
#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#ifdef _WIN32
/* win_compat.h provides arpa/inet.h, dirent.h, gettimeofday, strcasecmp. */
#  include <libpcapng/win_compat.h>
#  include <sys/stat.h>
#  include <io.h>           /* _access */
#  ifndef F_OK
#    define F_OK 0
#  endif
#  ifndef R_OK
#    define R_OK 4
#  endif
#  ifndef access
#    define access(p, m) _access((p), (m))
#  endif
#else
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <sys/stat.h>
#  include <dirent.h>
#endif

#include "linenoise/linenoise.h"
#include <libpcapng/libpcapng.h>

#ifndef MAXPATH
#  ifdef PATH_MAX
#    define MAXPATH PATH_MAX
#  else
#    define MAXPATH 4096
#  endif
#endif

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
#define PROTO_TLS   9

/* ─── Layer field types ─────────────────────────────────────────────────────── */
typedef enum { FT_U64 = 1, FT_STR, FT_IP4, FT_MAC, FT_BYTES } ftype_t;

#define MAX_RAWFIELD 4096

typedef struct {
    char     name[32];
    ftype_t  type;
    int      is_auto;
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

/* ─── TCP session ───────────────────────────────────────────────────────────── */
#define MAX_SESSIONS 64

typedef struct {
    char     name[64];
    uint32_t client_ip;
    uint32_t server_ip;
    uint16_t sport;
    uint16_t dport;
    uint32_t cli_seq;
    uint32_t srv_seq;
    uint8_t  client_mac[6];
    uint8_t  server_mac[6];
} sess_t;

/* ─── Protocol registry ─────────────────────────────────────────────────────── */
typedef struct { int id; char name[64]; const char *color; } proto_reg_t;

#define MAX_PROTO_REG 128

/* ─── Variable storage ──────────────────────────────────────────────────────── */
#define MAX_VARS 256

typedef struct {
    char    name[64];
    int     used;
    layer_t *pkt;
    uint8_t *raw;
    size_t   raw_len;
    int      is_raw;
    int      is_session;
    int64_t  numval;
    int      is_num;
} var_t;

/* ─── Dynamic protocol system ───────────────────────────────────────────────── */
#define PROTO_DYNAMIC_BASE 100
#define MAX_PDEFS   256
#define MAX_PFLDS   64
#define MAX_PEVALS  32

typedef enum {
    PFT_U8, PFT_U16, PFT_U32, PFT_U64,
    PFT_LE_U16, PFT_LE_U32, PFT_LE_U64,
    PFT_BYTES, PFT_MAC, PFT_IP4, PFT_STR,
    PFT_PAYLOAD,
    PFT_BYTES_REF
} pftype_t;

typedef struct { char name[64]; uint64_t val; } peval_t;

typedef struct {
    char     fname[64];
    pftype_t ftype;
    uint64_t defnum;
    char     defstr[256];
    size_t   nbytes;
    char     lenfield[64];
    peval_t  evals[MAX_PEVALS];
    int      nevals;
} pfld_t;

typedef struct {
    char   pname[64];
    char   parent[64];
    int    proto_id;
    pfld_t flds[MAX_PFLDS];
    int    nflds;
} pdef_t;

/* ─── frompcapng context ────────────────────────────────────────────────────── */
typedef struct {
    uint32_t  target;
    uint32_t  seen;
    uint8_t  *buf;
    size_t    buf_len;
} frompcapng_ctx_t;

/* ─── Packet serialization ──────────────────────────────────────────────────── */
#define MAX_PKT_BYTES 65535

/* ─── ls() field info ───────────────────────────────────────────────────────── */
typedef struct {
    const char *name;
    const char *desc;
    ftype_t     type;
    uint8_t     nbytes;
    uint64_t    defval;
    const char *defstr;
} proto_field_info_t;

typedef struct { const char *name; int proto; const proto_field_info_t *fields; } proto_info_t;

/* ─── Tokenizer ─────────────────────────────────────────────────────────────── */
typedef enum {
    T_EOF, T_IDENT, T_NUM, T_STR,
    T_LPAREN, T_RPAREN, T_COMMA, T_EQ, T_SLASH, T_DOT,
    T_VAR,
    T_PLUS, T_MINUS, T_STAR
} TT;

typedef struct {
    TT       type;
    char     s[8192];
    uint64_t n;
    size_t   slen;
} Tok;

typedef struct {
    const char *src;
    int         pos;
    Tok         cur;
    char        err[256];
} Lex;

/* ─── Evaluator result ──────────────────────────────────────────────────────── */
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

/* ─── Embedded / callback API ───────────────────────────────────────────────── */
typedef void (*pcapsh_packet_cb)(const uint8_t *buf, size_t len, void *userdata);

/* ─── Global state (defined in pcapsh.c) ───────────────────────────────────── */
extern sess_t           sessions[MAX_SESSIONS];
extern int              nsessions;
extern proto_reg_t      proto_reg[MAX_PROTO_REG];
extern int              nproto_reg;
extern var_t            vars[MAX_VARS];
extern int              nvars;
extern pdef_t           pdefs[MAX_PDEFS];
extern int              npdefs;
extern char             wrpcap_override[MAXPATH];
extern pcapsh_packet_cb g_packet_cb;
extern void            *g_packet_cb_userdata;

/* ─── pcapsh_layer.c ────────────────────────────────────────────────────────── */
void        proto_register(int id, const char *name, const char *color);
const char *proto_name(int p);
const char *proto_color(int p);
void        ip_to_mac(uint32_t ip_host, uint8_t mac[6]);
void        ip_str(uint32_t ip_host, char *buf, size_t sz);
sess_t     *sess_find(const char *name);
sess_t     *sess_new(const char *client_ip_str, const char *server_ip_str,
                     uint16_t sport, uint16_t dport);
field_t    *find_field(layer_t *l, const char *name);
field_t    *get_or_add(layer_t *l, const char *name);
void        set_u64(layer_t *l, const char *n, uint64_t v);
void        set_auto(layer_t *l, const char *n, ftype_t t);
void        set_ip4(layer_t *l, const char *n, const char *ip);
void        set_mac(layer_t *l, const char *n, const char *mac);
void        set_str(layer_t *l, const char *n, const char *s);
void        set_bytes(layer_t *l, const char *n, const uint8_t *data, size_t len);
uint64_t    get_u64(layer_t *l, const char *n, uint64_t def);
const char *get_str(layer_t *l, const char *n, const char *def);
uint32_t    get_ip4(layer_t *l, const char *n, const char *def);
void        get_mac(layer_t *l, const char *n, const uint8_t def[6], uint8_t out[6]);
layer_t    *new_layer(int proto);
layer_t    *make_ether(void);
layer_t    *make_ip(void);
layer_t    *make_tcp(void);
layer_t    *make_udp(void);
layer_t    *make_icmp(void);
layer_t    *make_tls_layer(void);
layer_t    *make_raw_layer(const uint8_t *data, size_t len);
void        free_layer(layer_t *l);
layer_t    *clone_chain(layer_t *l);
layer_t    *chain_append(layer_t *a, layer_t *b);
uint8_t     parse_tcp_flags(const char *s);

/* ─── pcapsh_posa.c ─────────────────────────────────────────────────────────── */
extern const char BUILTIN_POSA[];
extern const char DEFAULT_USER_POSA[];
pdef_t     *find_pdef_by_name(const char *name);
pdef_t     *find_pdef_by_id(int id);
int         parse_posa_src(const char *src);
int         parse_posa_file(const char *path);
int         load_protos_dir(const char *dir);
size_t      serialize_pdef_layer(pdef_t *def, layer_t *l, uint8_t *out, size_t max);
layer_t    *make_dynamic_layer(pdef_t *def);
void        resolve_dynamic_enums(pdef_t *def, layer_t *l);
const char *pftype_name(pftype_t t);

/* ─── pcapsh_io.c ───────────────────────────────────────────────────────────── */
size_t   fromhex_parse(const char *s, uint8_t *out, size_t max);
uint8_t *frompcapng_read(const char *filename, uint32_t pktnum, size_t *out_len);
int      replacepkt_in_file(const char *filename, uint32_t pktnum,
                             const uint8_t *newpkt, size_t newlen);
size_t   show_layer_by_name(const char *proto, const uint8_t *d, size_t avail);
size_t   pkt_to_raw(layer_t *pkt, uint8_t *buf, size_t bufsz);
size_t   pkt_to_raw_ex(layer_t *pkt, uint8_t *buf, size_t bufsz, int keep_eth);
void     print_pkt(layer_t *pkt);
void     do_hexdump(const uint8_t *data, size_t len);
void     do_ls(const char *proto_arg);

/* ─── pcapsh_eval.c ─────────────────────────────────────────────────────────── */
var_t      *var_find(const char *name);
var_t      *var_set_num(const char *name, int64_t val);
void        lex_adv(Lex *L);
void        lex_init(Lex *L, const char *src);
EvalResult  eval_expr(Lex *L);
void        pcapsh_eval_reset(void);

/* ─── pcapsh_main.c ─────────────────────────────────────────────────────────── */
void pcapsh_init(void);
void pcapsh_reset(void);
int  run_script(const char *path);
int  run_script_from_buffer(const char *src, size_t len);
void eval_line(const char *src);
