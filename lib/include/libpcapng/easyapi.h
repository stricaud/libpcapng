/*
 * License MIT
 * Copyright (c) 2022 Sebastien Tricaud
 */
#ifndef _LIBPCAPNG_EASYAPI_H_
#define _LIBPCAPNG_EASYAPI_H_

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int libpcapng_write_header_to_file(FILE *outfile);
int libpcapng_write_header_to_file_with_linktype(FILE *outfile, uint16_t linktype);
int libpcapng_write_header_with_comment_to_file(FILE *outfile, uint16_t linktype, const char *comment);
/* The packet is read, never written — so a caller holding const bytes, which
   is every capture callback, needs no cast to hand them over. */
int libpcapng_write_enhanced_packet_to_file(FILE *outfile, const unsigned char *packet, size_t packet_size);
/* Timestamped in nanoseconds since the UNIX epoch — the unit every reader
   here reports, so a round trip needs no conversion. What lands in the file
   is microseconds, the format's default resolution, so the sub-microsecond
   part is truncated. */
int libpcapng_write_enhanced_packet_with_time_ns_to_file(FILE *outfile, const unsigned char *packet, size_t packet_size, uint64_t timestamp_ns);
/* The same, in whole seconds. Kept for existing callers; new code should use
   the _ns form, which can express a packet rate above one per second. */
int libpcapng_write_enhanced_packet_with_time_to_file(FILE *outfile, const unsigned char *packet, size_t packet_size, uint32_t timestamp);

#ifdef __cplusplus
}
#endif

#endif	/* _LIBPCAPNG_EASYAPI_H_ */

