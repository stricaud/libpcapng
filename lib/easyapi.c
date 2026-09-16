/*
 * License MIT
 * Copyright (c) 2022 Sebastien Tricaud
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libpcapng/libpcapng.h>

#include <libpcapng/easyapi.h>

int libpcapng_write_header_to_file(FILE *outfile)
{
	unsigned char *buffer;
	size_t buffer_size;

	buffer_size = libpcapng_section_header_block_size();
	buffer = (unsigned char *)malloc(buffer_size);
	memset(buffer, '\0', buffer_size);
	libpcapng_section_header_block_write(buffer);
	fwrite(buffer, buffer_size, 1, outfile);
	free(buffer);

	buffer_size = libpcapng_interface_description_block_size();
	buffer = (unsigned char *)malloc(buffer_size);
	memset(buffer, '\0', buffer_size);
	libpcapng_interface_description_block_write(0, buffer);
	fwrite(buffer, buffer_size, 1, outfile);
	free(buffer);

	return 0;
}

int libpcapng_write_header_to_file_with_linktype(FILE *outfile, uint16_t linktype)
{
	unsigned char *buffer;
	size_t buffer_size;

	buffer_size = libpcapng_section_header_block_size();
	buffer = (unsigned char *)malloc(buffer_size);
	memset(buffer, '\0', buffer_size);
	libpcapng_section_header_block_write(buffer);
	fwrite(buffer, buffer_size, 1, outfile);
	free(buffer);

	buffer_size = libpcapng_interface_description_block_size();
	buffer = (unsigned char *)malloc(buffer_size);
	memset(buffer, '\0', buffer_size);
	libpcapng_interface_description_block_write_with_linktype(0, buffer, linktype);
	fwrite(buffer, buffer_size, 1, outfile);
	free(buffer);

	return 0;
}

int libpcapng_write_header_with_comment_to_file(FILE *outfile, uint16_t linktype, const char *comment)
{
	unsigned char *buffer;
	size_t buffer_size;

	if (comment && *comment) {
		pcapng_option_t opts[2];
		opts[0].type   = PCAPNG_OPT_COMMENT;
		opts[0].length = (uint16_t)strlen(comment);
		opts[0].value  = comment;
		opts[1].type   = PCAPNG_OPT_ENDOFOPT;
		opts[1].length = 0;
		opts[1].value  = NULL;

		buffer_size = libpcapng_section_header_block_size_with_options(opts, 1);
		buffer = (unsigned char *)malloc(buffer_size);
		memset(buffer, '\0', buffer_size);
		libpcapng_section_header_block_write_with_options(opts, 1, buffer);
		fwrite(buffer, buffer_size, 1, outfile);
		free(buffer);
	} else {
		buffer_size = libpcapng_section_header_block_size();
		buffer = (unsigned char *)malloc(buffer_size);
		memset(buffer, '\0', buffer_size);
		libpcapng_section_header_block_write(buffer);
		fwrite(buffer, buffer_size, 1, outfile);
		free(buffer);
	}

	buffer_size = libpcapng_interface_description_block_size();
	buffer = (unsigned char *)malloc(buffer_size);
	memset(buffer, '\0', buffer_size);
	libpcapng_interface_description_block_write_with_linktype(0, buffer, linktype);
	fwrite(buffer, buffer_size, 1, outfile);
	free(buffer);

	return 0;
}

int libpcapng_write_enhanced_packet_to_file(FILE *outfile, const unsigned char *packet, size_t packet_size)
{
	unsigned char *buffer;
	size_t buffer_size;

	buffer_size = libpcapng_enhanced_packet_block_size(packet_size);
	buffer = (unsigned char *)malloc(buffer_size);
	memset(buffer, '\0', buffer_size);
	libpcapng_enhanced_packet_block_write(packet, packet_size, buffer);
	fwrite(buffer, buffer_size, 1, outfile);
	free(buffer);

	return 0;
}

int libpcapng_write_enhanced_packet_with_time_to_file(FILE *outfile, const unsigned char *packet, size_t packet_size, uint32_t timestamp)
{
	unsigned char *buffer;
	size_t buffer_size;

	uint64_t timestamp_in_micros = timestamp * (uint64_t) 1000000;
	uint64_t timestamp_high_shift = timestamp_in_micros >> 32;
	uint32_t timestamp_high = (uint32_t) timestamp_high_shift;
	uint32_t timestamp_low = timestamp_in_micros & 0xFFFFFFFF;

	buffer_size = libpcapng_enhanced_packet_block_size(packet_size);
	buffer = (unsigned char *)malloc(buffer_size);
	libpcapng_enhanced_packet_block_write_time(packet, packet_size, timestamp_high, timestamp_low, buffer);
	fwrite(buffer, buffer_size, 1, outfile);
	free(buffer);

  return 0;
}
