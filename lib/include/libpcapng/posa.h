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
 * Field types: uint8/16/32/64, le_uint16/32/64, mac, ip4, cstring, string,
 * payload, bytes<N>, bytes[lenfield]. Extended constructs (layer/scope/when/
 * string-until/info/rule) are documented in the tutorial.
 */

typedef enum {
  PCAPNG_POSA_U8, PCAPNG_POSA_U16, PCAPNG_POSA_U32, PCAPNG_POSA_U64,
  PCAPNG_POSA_LE16, PCAPNG_POSA_LE32, PCAPNG_POSA_LE64,
  PCAPNG_POSA_MAC, PCAPNG_POSA_IP4, PCAPNG_POSA_CSTRING, PCAPNG_POSA_PAYLOAD,
  PCAPNG_POSA_BYTES_FIXED,   /* bytes<N>          */
  PCAPNG_POSA_BYTES_REF,     /* bytes[lenfield]   */
  PCAPNG_POSA_STR_DELIM,     /* string ... until "delim"   (extended) */
  PCAPNG_POSA_LAYER,         /* layer <name> <Proto>       (extended) */
  PCAPNG_POSA_SCOPE,         /* scope <field> { ... }      (extended) */
  PCAPNG_POSA_WHEN,          /* when <cond>: { ... }       (extended) */
  PCAPNG_POSA_END            /* marks end of a scope/when block (internal) */
} pcapng_posa_ftype_t;

#define PCAPNG_POSA_NAME_MAX   64
#define PCAPNG_POSA_MAX_FLDS   96
#define PCAPNG_POSA_MAX_ENUMS  32
#define PCAPNG_POSA_DELIM_MAX  16

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
  char                lenfield[PCAPNG_POSA_NAME_MAX];/* BYTES_REF              */
  char                delim[PCAPNG_POSA_DELIM_MAX]; int ndelim; /* STR_DELIM   */
  char                sub[PCAPNG_POSA_NAME_MAX];     /* LAYER: sub-proto name  */
  pcapng_posa_enum_t  enums[PCAPNG_POSA_MAX_ENUMS];
  int                 nenums;
  pcapng_posa_guard_t guard;                         /* when <cond>:           */
  int                 scope_len_field;               /* >=0: this field opens a
                                                        scope bounded by field #*/
} pcapng_posa_fld_t;

typedef struct {
  char               name[PCAPNG_POSA_NAME_MAX];
  char               parent[PCAPNG_POSA_NAME_MAX];   /* Object<parent>; "" if top */
  char               display[32];                    /* col "..." — Protocol column */
  pcapng_posa_fld_t  flds[PCAPNG_POSA_MAX_FLDS];
  int                nflds;
  char               info_fmt[192];                  /* info "..." fmt ("" = none) */
  char               info_args[8][PCAPNG_POSA_NAME_MAX];
  int                info_nargs;
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

/* Port binding declared by a `rule <tcp|udp>.port == N => Proto` line. Returns
   the bound protocol name for (ip_proto 6/17, port), or NULL. */
const char *pcapng_posa_bound_port(int ip_proto, uint16_t port);

/* Regenerate editable .posa source for a protocol. Returns bytes written. */
int  pcapng_posa_to_text(const pcapng_posa_proto_t *p, char *out, size_t sz);

#ifdef __cplusplus
}
#endif

#endif /* LIBPCAPNG_POSA_H */
