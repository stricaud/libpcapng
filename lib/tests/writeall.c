/*
 * License MIT
 * Copyright (c) 2021 Devo Inc.
 * Copyright (c) 2022 Sebastien Tricaud
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libpcapng/blocks.h>

int main(int argc, char **argv)
{
	FILE *fp;
	unsigned char *buffer;
	size_t buffer_size;

 	unsigned char *pkt = "\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x0c\xea\xac\x10\x00\x2a\xc0\xa8\x01\x03\x46\x11\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x20\x00\xdb\x9b\x00\x00";
	size_t pkt_len = 40;

	size_t retval;

	unsigned char *custom = "helo";

	fp = fopen("out.pcapng", "wb");

	buffer_size = libpcapng_section_header_block_size();
	buffer = malloc(buffer_size);
	libpcapng_section_header_block_write(buffer);
	fwrite(buffer, buffer_size, 1, fp);
	free(buffer);

	buffer_size = libpcapng_interface_description_block_size();
	buffer = malloc(buffer_size);
	libpcapng_interface_description_block_write(0, buffer);
	fwrite(buffer, buffer_size, 1, fp);
	free(buffer);

	/* Write an Enhanced Packet */
	buffer_size = libpcapng_enhanced_packet_block_size(pkt_len);
	buffer = malloc(buffer_size);
	libpcapng_enhanced_packet_block_write(pkt, pkt_len, buffer);
	fwrite(buffer, buffer_size, 1, fp);
	free(buffer);

	/* Write a Custom Block */
	buffer_size = libpcapng_custom_data_block_size(3);
	buffer = malloc(buffer_size);
	libpcapng_custom_data_block_write(123, custom, 3, buffer);
	fwrite(buffer, buffer_size, 1, fp);
	free(buffer);

	fflush(fp);
	fclose(fp);

	return 0;
}
