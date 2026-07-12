#ifndef _LIBPCAPNG_DISSECT_H_
#define _LIBPCAPNG_DISSECT_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Generic packet dissection → a field tree ────────────────────────────────
 *
 * pcapng_dissect() turns captured bytes into a tree of protocol layers and
 * fields. Each field carries a Wireshark-style abbrev ("ip.src", "tcp.dstport")
 * for filtering, a human label for display, a typed value, and — crucially — its
 * absolute byte offset/length within the packet (so a UI can highlight exactly
 * the bytes of the selected field). This is the single dissection engine shared
 * by tools built on libpcapng. */

typedef enum {
  PCAPNG_FT_NONE = 0,   /* structural node (a protocol layer), no value        */
  PCAPNG_FT_UINT,       /* unsigned integer                                    */
  PCAPNG_FT_STR,        /* text                                                */
  PCAPNG_FT_IPV4,       /* 4 raw bytes in .bytes, dotted-quad in .str          */
  PCAPNG_FT_IPV6,       /* 16 raw bytes in .bytes                              */
  PCAPNG_FT_MAC,        /* 6 raw bytes in .bytes                               */
  PCAPNG_FT_BYTES       /* opaque bytes (first 16 kept in .bytes)              */
} pcapng_ftype_t;

#define PCAPNG_FIELD_ABBREV_MAX 64
#define PCAPNG_FIELD_LABEL_MAX  192
#define PCAPNG_FIELD_STR_MAX    160
#define PCAPNG_FIELD_BYTES_MAX  16

typedef struct pcapng_field {
  char           abbrev[PCAPNG_FIELD_ABBREV_MAX]; /* "" for structural-only    */
  char           label[PCAPNG_FIELD_LABEL_MAX];
  pcapng_ftype_t vtype;
  uint64_t       u;                                /* PCAPNG_FT_UINT           */
  char           str[PCAPNG_FIELD_STR_MAX];        /* STR / formatted ip / mac */
  uint8_t        bytes[PCAPNG_FIELD_BYTES_MAX];
  int            blen;
  int            off;                              /* absolute byte offset     */
  int            len;                              /* byte length              */

  struct pcapng_field *parent;
  struct pcapng_field *children;
  struct pcapng_field *last_child;
  struct pcapng_field *next;                       /* next sibling             */
} pcapng_field_t;

typedef struct {
  pcapng_field_t *root;        /* children = the protocol layers, in order      */
  char proto[16];              /* deepest recognised protocol (summary column)  */
  char src[48];                /* source address (summary column)               */
  char dst[48];                /* destination address (summary column)          */
  char info[160];              /* one-line info (summary column)                */
} pcapng_dissection_t;

/* Link-layer types understood by the dissector (subset of DLT/LINKTYPE_*). */
#ifndef PCAPNG_LINKTYPE_ETHERNET
#define PCAPNG_LINKTYPE_NULL      0
#define PCAPNG_LINKTYPE_ETHERNET  1
#define PCAPNG_LINKTYPE_RAW       101
#define PCAPNG_LINKTYPE_LINUX_SLL 113
#define PCAPNG_LINKTYPE_IPV4      228
#define PCAPNG_LINKTYPE_IPV6      229
#endif

/* Dissect a packet. `origlen` is the on-wire length (for the Frame node);
   pass caplen if unknown. Caller frees the result with pcapng_dissection_free.
   Never returns NULL for valid input except on allocation failure. */
pcapng_dissection_t *pcapng_dissect(const uint8_t *data, uint32_t caplen,
                                    uint32_t origlen, uint16_t linktype);
void pcapng_dissection_free(pcapng_dissection_t *d);

/* The protocol abbrevs this dissector can produce (for listing decoders). The
   returned array is static; *count is set to its length. */
const char *const *pcapng_dissect_protocols(int *count);

/* Tree helpers. */
int             pcapng_field_count(const pcapng_field_t *parent);
pcapng_field_t *pcapng_field_child_at(const pcapng_field_t *parent, int index);
/* Collect every node whose abbrev == `abbrev`; returns the count (up to max). */
int             pcapng_field_collect(pcapng_field_t *root, const char *abbrev,
                                     pcapng_field_t **out, int max);
void            pcapng_field_free(pcapng_field_t *root);

#ifdef __cplusplus
}
#endif

#endif /* _LIBPCAPNG_DISSECT_H_ */
