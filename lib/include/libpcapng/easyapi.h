/*
 * License MIT
 * Copyright (c) 2022 Sebastien Tricaud
 */
#ifndef _LIBPCAPNG_EASYAPI_H_
#define _LIBPCAPNG_EASYAPI_H_

#ifdef __cplusplus
extern "C" {
#endif

int libpcapng_write_header_to_file(FILE *outfile);
int libpcapng_write_enhanced_packet_to_file(FILE *outfile, unsigned char *packet, size_t packet_size);
int libpcapng_write_enhanced_packet_with_time_to_file(FILE *outfile, unsigned char *packet, size_t packet_size, uint32_t timestamp);

#ifdef __cplusplus
}
#endif

#endif	/* _LIBPCAPNG_EASYAPI_H_ */

