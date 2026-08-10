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
  PCAPNG_POSA_ELSE,          /* else: — the arm taken when the `when` above it
                                at the same indent was not (DHCP: decode the
                                options we know, show the rest as bytes)      */
  PCAPNG_POSA_KVBLOCK,       /* kvblock <name> [sep "..."] ["Label"]
                                Parse a MIME-style "Key: Value\r\n" header block
                                into named child fields. sub[] holds the separator
                                (default ": "); delim/ndelim hold the end sentinel
                                (default "\r\n\r\n"). Each header becomes a child
                                field at <proto>.<name>.<normalized_key>, enabling
                                display filters like sip.headers.content_type.   */
  PCAPNG_POSA_QUIC_VARINT,   /* quic_varint — RFC 9000 §16 variable-length integer.
                                The top two bits of the first octet give the total
                                width (1, 2, 4 or 8 octets); the remaining 62 bits
                                are the value, big-endian. Used by QUIC and by
                                every field of HTTP/3.                           */
  PCAPNG_POSA_BIND,          /* bind <table>[<key>] = <value> — remember a value
                                for the rest of this *conversation*, keyed by the
                                Community ID of the flow. What one PDU states and
                                a later one only refers to: DCE/RPC agrees an
                                interface once in its BIND and afterwards names it
                                only by a small context id.               */
  PCAPNG_POSA_RECALL,        /* recall <table>[<key>] as <name> ["Label"] — read
                                back what `bind` stored. A miss is reported, not
                                fatal: the field still appears, saying it was
                                never bound, and a warning is recorded.   */
  PCAPNG_POSA_LET,           /* let <name> = <expr> ["Label"] — a value computed
                                from fields already parsed rather than read from
                                the wire. Consumes no bytes, and is written with
                                no type in front for exactly that reason. The
                                name is then used like any other field's:
                                bytes[x], scope x, seek x, when x > 0.
                                The same arithmetic can be written directly in a
                                length or offset position, which is usually
                                shorter: bytes[total - hdr], seek (offset+3)&~3. */
  PCAPNG_POSA_UUID,          /* uuid — a 16-byte DCE/RPC UUID (Microsoft GUID),
                                rendered canonically as
                                xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx. The first
                                three groups are little-endian on the wire and
                                the last two big-endian; getting that wrong is
                                the classic GUID bug. Because the value reaches
                                the tree as text, string-keyed enums and Lookup
                                tables resolve against it directly.           */
  PCAPNG_POSA_LEB128         /* leb128 — seven value bits per octet, least
                                significant group first, high bit set on every
                                octet but the last (protobuf, DWARF, Thrift
                                compact).                                        */
} pcapng_posa_ftype_t;

#define PCAPNG_POSA_NAME_MAX   64
#define PCAPNG_POSA_MAX_FLDS   512   /* SMB2 dispatches ~20 commands in one object */
#define PCAPNG_POSA_MAX_ENUMS  32
#define PCAPNG_POSA_DELIM_MAX  16
#define PCAPNG_POSA_LABEL_MAX  96
#define PCAPNG_POSA_MAX_LARGS   6
#define PCAPNG_POSA_EXPR_MAX  128

typedef struct {
  char     name[PCAPNG_POSA_NAME_MAX]; /* display label: "OK", "Ringing", … */
  uint64_t val;                         /* numeric key (uint fields)          */
  char     key[PCAPNG_POSA_NAME_MAX];  /* string key — set when LHS is "…"   */
} pcapng_posa_enum_t;

/* Lookup table: a named collection of string or numeric enum entries, declared
 * with `Lookup NAME` and referenced from any field with `lookup NAME`.
 * Decouples large value-to-label tables (SIP status codes, SMTP reply codes,
 * HTTP methods, …) from the field that uses them, enabling sharing and keeping
 * protocol objects clean. */
#define PCAPNG_POSA_LOOKUP_MAX_ENUMS 128
#define PCAPNG_POSA_MAX_LOOKUPS       64
typedef struct {
  char               name[PCAPNG_POSA_NAME_MAX];
  pcapng_posa_enum_t enums[PCAPNG_POSA_LOOKUP_MAX_ENUMS];
  int                nenums;
} pcapng_posa_lookup_t;

/* A conditional guard: parse the field only when <field> [& mask] <op> value.
   Supports compound conditions joined by `and`/`or`:
     when command == 5 and response == 0:
     when flags & 0x01 == 0 or flags & 0x02 == 0x02: */
typedef enum { PCAPNG_POSA_CMP_NONE = 0, PCAPNG_POSA_CMP_EQ, PCAPNG_POSA_CMP_NE,
               PCAPNG_POSA_CMP_LT, PCAPNG_POSA_CMP_GT, PCAPNG_POSA_CMP_GE,
               PCAPNG_POSA_CMP_LE } pcapng_posa_cmp_t;
typedef struct {
  pcapng_posa_cmp_t op;                 /* NONE = always */
  char     lhs[PCAPNG_POSA_NAME_MAX];   /* field name, or "remaining" */
  uint64_t mask;                        /* 0 = no mask */
  uint64_t rhs;
  /* optional second condition: `when A and B:` or `when A or B:` */
  pcapng_posa_cmp_t op2;
  char     lhs2[PCAPNG_POSA_NAME_MAX];
  uint64_t mask2;
  uint64_t rhs2;
  int      logic2;                      /* 0 = AND (default), 1 = OR */
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
  /* `matches <N>` — a constraint, not a default. If the wire value differs the
     whole dissection is abandoned and the caller falls through to the next
     candidate decoder. This is what lets a `weak rule` be safe: the signature
     gets the decoder a hearing, and the magic number decides whether it keeps
     it. Distinct from `= N`, which is only a default (hsrp's `priority = 100`
     is a sensible starting value, not something to reject a packet over). */
  int                 has_match;
  uint64_t            match_val;
  /* BITS: value = (<src> >> shift) & ((1 << width) - 1) */
  char                src[PCAPNG_POSA_NAME_MAX];
  int                 shift, width;
  /* REPEAT: `until end` instead of a count; LABEL: fmt lives in .disp */
  int                 until_end;
  /* REPEAT: `repeat <field>-2 as x` — an adjustment applied to the count the
     field carries. Formats that store "objects + 2" (NoteWorthy Composer does)
     are otherwise not walkable, since the loop would run past the records. */
  int                 count_bias;
  char                largs[PCAPNG_POSA_MAX_LARGS][PCAPNG_POSA_NAME_MAX];
  int                 nlargs;
  /* `lookup NAME` — reference to a named Lookup table for value-to-label
     resolution; "" means use inline enums only. */
  char                lookup_name[PCAPNG_POSA_NAME_MAX];
  /* LET: the expression source, evaluated against the fields parsed so far
     plus the built-ins `offset` and `remaining`. */
  char                expr[PCAPNG_POSA_EXPR_MAX];
  /* BIND/RECALL: `sub` holds the table name, `lenfield` the key field, and
     `src` the value field (BIND only). */
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
  char               prefixes[8][16];                /* `starts "GET " "POST "…` — select
                                                        this member of group G only when the
                                                        payload begins with one of these
                                                        literals (content-based dispatch,
                                                        for text protocols with no magic) */
  int                nprefix;
  int                prefix_len[8];                   /* byte length of each prefix         */
} pcapng_posa_proto_t;

/* Load .posa definitions into the global registry. Redefining a protocol by
   name replaces it. Returns number of protocols added, or -1 on error. */
int  pcapng_posa_load_file(const char *path, char *errbuf, size_t errlen);
int  pcapng_posa_load_dir(const char *dir);
int  pcapng_posa_load_text(const char *src, char *errbuf, size_t errlen);  /* parse from memory */
void pcapng_posa_clear(void);

/* ── Conversation memory (`bind` / `recall`) ─────────────────────────────────
 * A decoder can remember a value for the life of a flow and read it back in a
 * later packet. The key is the flow's Community ID, so it is the same in both
 * directions and matches what the rest of the library, Zeek and Suricata use.
 *
 * The host sets the current conversation before dissecting; passing NULL (or
 * never calling it) simply means `bind` stores nothing and `recall` always
 * misses, which is what happens for a decoder run on a bare buffer. */
void pcapng_posa_set_conversation(const char *community_id);
void pcapng_posa_binds_clear(void);
int  pcapng_posa_bind_count(void);

/* Warnings raised by the last dissect — today, a `recall` that found nothing.
 * They are informational: the dissection completes either way. Returns the
 * number available; index 0 is the oldest. */
int         pcapng_posa_warning_count(void);
const char *pcapng_posa_warning_at(int index);

int  pcapng_posa_count(void);
const pcapng_posa_proto_t *pcapng_posa_at(int index);
const pcapng_posa_proto_t *pcapng_posa_find(const char *name);

int pcapng_posa_lookup_count(void);
const pcapng_posa_lookup_t *pcapng_posa_find_lookup(const char *name);
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
/* Decoder claimed by a `rule content "…"` signature the payload starts with.
   ip_proto is the transport (6/17); tried after port binding fails. */
const char *pcapng_posa_bound_content(int ip_proto, const uint8_t *data, int len);

/* Signatures declared `weak rule …`: suggestive rather than conclusive, and so
 * consulted only after both the strong signatures and the port bindings have
 * failed. A two-octet prefix that a lot of unrelated traffic also begins with
 * belongs here — it should never outrank the real binding of a connection. */
const char *pcapng_posa_bound_content_weak(int ip_proto, const uint8_t *data, int len);

/* Weak rules are on by default. Turning them off leaves only signatures strong
 * enough to stand on their own, which is what a capture full of unrelated
 * traffic wants. */
void pcapng_posa_weak_rules_enable(int on);
int  pcapng_posa_weak_rules_enabled(void);
/* Decoder claimed by a `rule ip4.addr/src/dst in A.B.C.D/N => Proto` CIDR rule.
   src and dst are 4-byte IPv4 addresses in network byte order (may be NULL). */
const char *pcapng_posa_bound_ip4cidr(const uint8_t *src, const uint8_t *dst);

/* Expand a field-synonym alias (`alias <name> => <field> …`). Writes up to
   `max` target abbrevs into `out` and returns the count, or 0 if `field` is not
   a synonym alias. Targets are OR'd together by the caller (as `tcp.port` is). */
int pcapng_posa_alias_expand(const char *field, const char **out, int max);

/* The display-filter expression of a macro alias (`alias <name> => <expr>`), or
   NULL if `name` is not a macro. The caller compiles the string in place. */
const char *pcapng_posa_alias_macro(const char *name);

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
