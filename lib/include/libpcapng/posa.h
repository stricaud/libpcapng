#ifndef LIBPCAPNG_POSA_H
#define LIBPCAPNG_POSA_H

#include <stdint.h>
#include <stddef.h>
#include <libpcapng/dissect.h>   /* pcapng_field_t */

#ifdef __cplusplus
extern "C" {
#endif

/* ── posa: declarative packet decoders (.posa) ───────────────────────────────
 *
 * A .posa file describes how to decode a protocol as a sequence of typed
 * fields, and (with the extended grammar) layered sub-protocols, conditional
 * layout, delimiter fields, length scopes, a derived Info string, and the
 * display-filter/port rules that bind it. The engine interprets a decoder and
 * attaches a pcapng_field_t subtree — the same tree the built-in dissectors
 * produce — so posa and built-in decoders are interchangeable.
 *
 * Base grammar:
 *     protocol NAME                 # or  Object<parent> NAME
 *         required uint16 opcode = 1
 *             RRQ = 1               # enum constants (indented under a field)
 *         required cstring filename
 *         required payload data
 *
 * Field types: uint8/16/32/64, le_uint16/32/64, mac, ip4, ip6, cstring, string,
 * payload, bytes<N>, bytes[lenfield], str[lenfield], dnsname. Extended
 * constructs (layer/scope/when/repeat/bits/label/string-until/info/rule) are
 * documented in the tutorial.
 *
 * Record-structured protocols (DNS and friends) need three things the base
 * grammar cannot express, so the extended grammar adds them:
 *
 *     repeat <countfield> as <item>     # N records, one subtree each
 *     repeat until end as <item>        # records until the enclosing scope ends
 *         label "%s: type %s" name, type   # how to title this record's subtree
 *         required dnsname name         # a name, following 0xc0 compression
 *         bits flags qr 15 1 "Response" # a bitfield carved out of `flags`
 */

typedef enum {
  PCAPNG_POSA_U8, PCAPNG_POSA_U16, PCAPNG_POSA_U32, PCAPNG_POSA_U64,
  PCAPNG_POSA_LE16, PCAPNG_POSA_LE32, PCAPNG_POSA_LE64,
  PCAPNG_POSA_MAC, PCAPNG_POSA_IP4, PCAPNG_POSA_CSTRING, PCAPNG_POSA_PAYLOAD,
  PCAPNG_POSA_BYTES_FIXED,   /* bytes<N>          */
  PCAPNG_POSA_STR_FIXED,     /* str<N> — fixed-length text (e.g. a PNG chunk type) */
  PCAPNG_POSA_BYTES_REF,     /* bytes[lenfield]   */
  PCAPNG_POSA_STR_DELIM,     /* string ... until "delim"   (extended) */
  PCAPNG_POSA_LAYER,         /* layer <name> <Proto>       (extended) */
  PCAPNG_POSA_SCOPE,         /* scope <field> { ... }      (extended) */
  PCAPNG_POSA_WHEN,          /* when <cond>: { ... }       (extended) */
  PCAPNG_POSA_END,           /* marks end of a scope/when/repeat block (internal) */
  PCAPNG_POSA_IP6,           /* ip6                        (extended) */
  PCAPNG_POSA_STR_REF,       /* str[lenfield]              (extended) */
  PCAPNG_POSA_DNSNAME,       /* dnsname — DNS label sequence, 0xc0-compressed */
  PCAPNG_POSA_REPEAT,        /* repeat <count|until end> as <item> { ... }    */
  PCAPNG_POSA_BITS,          /* bits <src> <name> <shift> <width>             */
  PCAPNG_POSA_LABEL,         /* label "<fmt>" args — titles the enclosing item */
  PCAPNG_POSA_U24,           /* uint24 — 3-byte big-endian (NetBIOS framing)  */
  PCAPNG_POSA_UTF16,         /* utf16[lenfield] — UTF-16LE text (SMB2 names)  */
  PCAPNG_POSA_SEEK,          /* seek <offsetfield|number> — jump to an offset carried
                                by the protocol itself (SMB2 places its blobs
                                by offset-from-header, not in field order)    */
  PCAPNG_POSA_ELSE           /* else: — the arm taken when the `when` above it
                                at the same indent was not (DHCP: decode the
                                options we know, show the rest as bytes)      */
} pcapng_posa_ftype_t;

#define PCAPNG_POSA_NAME_MAX   64
#define PCAPNG_POSA_MAX_FLDS   512   /* SMB2 dispatches ~20 commands in one object */
#define PCAPNG_POSA_MAX_ENUMS  32
#define PCAPNG_POSA_DELIM_MAX  16
#define PCAPNG_POSA_LABEL_MAX  96
#define PCAPNG_POSA_MAX_LARGS   6

typedef struct { char name[PCAPNG_POSA_NAME_MAX]; uint64_t val; } pcapng_posa_enum_t;

/* A conditional guard: parse the field only when <field> <op> [mask] value. */
typedef enum { PCAPNG_POSA_CMP_NONE = 0, PCAPNG_POSA_CMP_EQ, PCAPNG_POSA_CMP_NE,
               PCAPNG_POSA_CMP_LT, PCAPNG_POSA_CMP_GT, PCAPNG_POSA_CMP_GE,
               PCAPNG_POSA_CMP_LE } pcapng_posa_cmp_t;
typedef struct {
  pcapng_posa_cmp_t op;                 /* NONE = always */
  char     lhs[PCAPNG_POSA_NAME_MAX];   /* field name, or "remaining" */
  uint64_t mask;                        /* 0 = no mask */
  uint64_t rhs;
} pcapng_posa_guard_t;

typedef struct {
  char                name[PCAPNG_POSA_NAME_MAX];
  pcapng_posa_ftype_t type;
  uint64_t            defnum;
  size_t              nbytes;                       /* BYTES_FIXED             */
  char                lenfield[PCAPNG_POSA_NAME_MAX];/* BYTES_REF/STR_REF, and
                                                        REPEAT: the count field */
  char                delim[PCAPNG_POSA_DELIM_MAX]; int ndelim; /* STR_DELIM   */
  char                sub[PCAPNG_POSA_NAME_MAX];     /* LAYER: sub-proto name  */
  pcapng_posa_enum_t  enums[PCAPNG_POSA_MAX_ENUMS];
  int                 nenums;
  pcapng_posa_guard_t guard;                         /* when <cond>:           */
  int                 scope_len_field;               /* >=0: this field opens a
                                                        scope bounded by field #*/
  /* display text: `required uint16 qtype "Type"` shows as `Type: PTR (12)`.
     Empty → the field name is used, as before. */
  char                disp[PCAPNG_POSA_LABEL_MAX];
  uint64_t            mask;                          /* `mask 0x7fff` — value shown
                                                        and matched after masking */
  int                 hex;                           /* `hex` — show the value as 0x… */
  /* BITS: value = (<src> >> shift) & ((1 << width) - 1) */
  char                src[PCAPNG_POSA_NAME_MAX];
  int                 shift, width;
  /* REPEAT: `until end` instead of a count; LABEL: fmt lives in .disp */
  int                 until_end;
  char                largs[PCAPNG_POSA_MAX_LARGS][PCAPNG_POSA_NAME_MAX];
  int                 nlargs;
} pcapng_posa_fld_t;

typedef struct {
  char               name[PCAPNG_POSA_NAME_MAX];
  char               parent[PCAPNG_POSA_NAME_MAX];   /* Object<parent>; "" if top */
  char               display[32];                    /* col "..." — Protocol column */
  char               abbrev[32];                     /* abbrev "..." — field/layer abbrev prefix */
  pcapng_posa_fld_t  flds[PCAPNG_POSA_MAX_FLDS];
  int                nflds;
  char               info_fmt[192];                  /* info "..." fmt ("" = none) */
  char               info_args[8][PCAPNG_POSA_NAME_MAX];
  int                info_nargs;
  int                is_default;                     /* `Object<G> X default` — the
                                                        member of group G to use when
                                                        no other one's first field
                                                        matches (an HTTP request has
                                                        no magic; a response does) */
} pcapng_posa_proto_t;

/* Load .posa definitions into the global registry. Redefining a protocol by
   name replaces it. Returns number of protocols added, or -1 on error. */
int  pcapng_posa_load_file(const char *path, char *errbuf, size_t errlen);
int  pcapng_posa_load_dir(const char *dir);
int  pcapng_posa_load_text(const char *src, char *errbuf, size_t errlen);  /* parse from memory */
void pcapng_posa_clear(void);

int  pcapng_posa_count(void);
const pcapng_posa_proto_t *pcapng_posa_at(int index);
const pcapng_posa_proto_t *pcapng_posa_find(const char *name);
/* Resolve a name to a concrete protocol, or — if it names an Object<parent>
   group — the sub-protocol whose first field matches `data`. NULL if neither. */
const pcapng_posa_proto_t *pcapng_posa_resolve(const char *name, const uint8_t *data, int len);

/* Dissect `data` as the named protocol, attaching a subtree to `parent` and
   (optionally) writing the derived Info string. Returns bytes consumed. */
int  pcapng_posa_dissect(const char *proto, const uint8_t *data, int len,
                         pcapng_field_t *parent, int abs_off, char *info, size_t infolen);

/* The `col "..."` of the innermost decoder the last dissect reached (NULL if
   none declared one): NetBIOS frames SMB2, and the packet should read "SMB2".
   Reset before a dissect, read after it. */
void        pcapng_posa_reset_col(void);
const char *pcapng_posa_last_col(void);

/* Bindings declared by `rule` lines. A decoder can claim a transport port, an IP
   protocol number (`rule ip.proto == 2 => IGMP`) or an ethertype
   (`rule eth.type == 0x88cc => LLDP`). Return the bound protocol name, or NULL. */
const char *pcapng_posa_bound_port(int ip_proto, uint16_t port);
const char *pcapng_posa_bound_ipproto(int ip_proto_num);
const char *pcapng_posa_bound_ethertype(uint16_t ethertype);

/* ── Coloring declared by a `color <display filter> => <fg> <bg>` line ───────
 *
 *     color tcp.flags.reset == 1 => yellow red
 *     color rdp                  => black lightcyan
 *
 * libpcapng only carries the declaration — it has no display of its own, so the
 * colors stay opaque names and the front end decides what they mean (carcal maps
 * them onto libcaca's ANSI palette). This is how a .posa ships its own coloring
 * alongside its decoder, with no code change in the analyzer. */
#define PCAPNG_POSA_COLOR_EXPR_MAX 192
#define PCAPNG_POSA_COLOR_NAME_MAX  24
int pcapng_posa_color_count(void);
/* Borrowed pointers into the loaded posa set; invalidated by pcapng_posa_clear. */
int pcapng_posa_color_get(int i, const char **expr, const char **fg, const char **bg);

/* Regenerate editable .posa source for a protocol. Returns bytes written.
   This is a reconstruction from the parsed form; prefer pcapng_posa_source()
   when it has the original text, so comments and extended constructs survive
   a view/edit round-trip. */
int  pcapng_posa_to_text(const pcapng_posa_proto_t *p, char *out, size_t sz);

/* The exact source text this protocol was parsed from (borrowed, NULL if it was
   built without one). Invalidated by pcapng_posa_clear() or by redefining the
   protocol. */
const char *pcapng_posa_source(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* LIBPCAPNG_POSA_H */
