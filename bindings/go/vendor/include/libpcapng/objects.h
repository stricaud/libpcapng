#ifndef LIBPCAPNG_OBJECTS_H
#define LIBPCAPNG_OBJECTS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Object (file) extraction ────────────────────────────────────────────────
 *
 * Carves transferred files out of passively captured, unencrypted traffic —
 * the equivalent of Wireshark's "File > Export Objects". TCP streams are
 * reassembled (via reassembly_tcp) and the application protocol is parsed to
 * recover each object's bytes plus metadata (host, content type, filename).
 *
 * Supported today: HTTP (requests/responses, de-chunked) and SMB2 (files read
 * over READ responses). The API is protocol-agnostic; feed packets in capture
 * order, call finish(), then iterate the objects.
 */

typedef enum {
  PCAPNG_OBJ_HTTP = 1,
  PCAPNG_OBJ_SMB  = 2
} pcapng_object_proto_t;

typedef struct {
  char        proto[8];         /* "HTTP" / "SMB"                              */
  int         frame;            /* 1-based packet number the object ends in    */
  char        hostname[256];    /* HTTP Host: / SMB server, or an IP           */
  char        content_type[128];/* HTTP Content-Type (empty for SMB)           */
  char        filename[256];    /* derived from URI / SMB path                 */
  const uint8_t *data;          /* object bytes (owned by the extractor)       */
  size_t      len;
  int         complete;         /* 1 if the full declared length was captured  */
} pcapng_object_t;

typedef struct pcapng_object_extractor pcapng_object_extractor_t;

/* Create an extractor for the given protocol (PCAPNG_OBJ_HTTP / _SMB). */
pcapng_object_extractor_t *pcapng_object_extractor_new(pcapng_object_proto_t proto);
void pcapng_object_extractor_free(pcapng_object_extractor_t *ex);

/* Feed one captured packet (raw link-layer bytes, host order not required).
 * `frame` is the 1-based packet number. Non-TCP packets are ignored. Packets
 * should be supplied in capture order. */
void pcapng_object_extractor_add_packet(pcapng_object_extractor_t *ex, int frame,
                                        const uint8_t *data, uint32_t caplen,
                                        uint16_t linktype);

/* Parse the accumulated streams into objects. Call once, after all packets. */
void pcapng_object_extractor_finish(pcapng_object_extractor_t *ex);

int  pcapng_object_count(const pcapng_object_extractor_t *ex);
const pcapng_object_t *pcapng_object_at(const pcapng_object_extractor_t *ex, int i);

#ifdef __cplusplus
}
#endif

#endif /* LIBPCAPNG_OBJECTS_H */
