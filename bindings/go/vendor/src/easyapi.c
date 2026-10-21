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

int libpcapng_write_enhanced_packet_with_time_ns_to_file(FILE *outfile, const unsigned char *packet, size_t packet_size, uint64_t timestamp_ns)
{
	unsigned char *buffer;
	size_t buffer_size;

	/* Nanoseconds in, because nanoseconds are what every reader in this
	 * library reports: pcapng_packet_t::timestamp_ns, Python's
	 * pkt.timestamp_ns, Go's Packet.TimestampNs. A writer that took some
	 * other unit would mean every round trip had a conversion in it, and a
	 * forgotten conversion in a timestamp is not something a test notices.
	 *
	 * The interface description this easy API writes carries no if_tsresol
	 * option, so the format's default applies and the block's two words are
	 * *microseconds* since the epoch. The sub-microsecond part is therefore
	 * dropped here — truncated deliberately, which is visible in the file,
	 * rather than reinterpreted, which would not be. */
	uint64_t timestamp_in_micros = timestamp_ns / 1000;
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

int libpcapng_write_enhanced_packet_with_time_to_file(FILE *outfile, const unsigned char *packet, size_t packet_size, uint32_t timestamp)
{
	/* Whole seconds, kept for callers written against it. */
	return libpcapng_write_enhanced_packet_with_time_ns_to_file(
		outfile, packet, packet_size, (uint64_t)timestamp * 1000000000ULL);
}
