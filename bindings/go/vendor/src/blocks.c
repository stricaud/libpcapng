/*
 * License MIT
 * Copyright (c) 2021 Devo Inc.
 * Copyright (c) 2022 Sebastien Tricaud
 */
#ifdef _WIN32
/* MinGW gets the real <sys/time.h> through this; MSVC gets a gettimeofday shim. */
#  include <libpcapng/win_compat.h>
#else
#  include <sys/time.h>
#endif
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libpcapng/libpcapng.h>
#include <libpcapng/linktypes.h>

#include <libpcapng/blocks.h>

size_t libpcapng_section_header_block_write(unsigned char *outbuf)
{
	size_t block_total_length;
	uint32_t *final_length;
	pcapng_section_header_block_t *shb;

	block_total_length = libpcapng_section_header_block_size();

	shb = (pcapng_section_header_block_t *)outbuf;
	shb->block_type = PCAPNG_SECTION_HEADER_BLOCK;
	shb->block_total_length = block_total_length;
	shb->magic = PCAPNG_BYTE_ORDER_MAGIC;
	shb->major_version = PCAPNG_VERSION_MAJOR;
	shb->minor_version = PCAPNG_VERSION_MINOR;
	shb->section_length = (uint64_t)-1;

	final_length = (uint32_t *)(outbuf+block_total_length - BLOCK_TOTAL_LENGTH_SIZE);
	*final_length = block_total_length;

	return block_total_length;
}

size_t libpcapng_section_header_block_size(void)
{
	return sizeof(pcapng_section_header_block_t) + BLOCK_TOTAL_LENGTH_SIZE;
}

pcapng_section_header_block_light_t *libpcapng_section_header_block_read(unsigned char *inbuf, size_t inbuf_len)
{
	pcapng_section_header_block_t *raw;
	pcapng_section_header_block_light_t *shb;

	shb = (pcapng_section_header_block_light_t *)malloc(sizeof(*shb));
	if (!shb) return NULL;

	raw = (pcapng_section_header_block_t *)inbuf;
	shb->magic          = raw->magic;
	shb->major_version  = raw->major_version;
	shb->minor_version  = raw->minor_version;
	shb->section_length = raw->section_length;

	return shb;
}

size_t libpcapng_interface_description_block_write(uint32_t snaplen, unsigned char *outbuf)
{
	size_t block_total_length;
	uint32_t *final_length;
	pcapng_interface_description_block_t *idb;

	block_total_length = libpcapng_interface_description_block_size();

	idb = (pcapng_interface_description_block_t *)outbuf;
	idb->block_type = PCAPNG_INTERFACE_DESCRIPTION_BLOCK;
	idb->block_total_length = block_total_length;
	idb->linktype = LINKTYPE_RAW;
	idb->reserved = 0;
	idb->snaplen = snaplen;

	final_length = (uint32_t *)(outbuf + block_total_length - BLOCK_TOTAL_LENGTH_SIZE);
	*final_length = block_total_length;

	return block_total_length;
}

size_t libpcapng_interface_description_block_write_with_linktype(uint32_t snaplen, unsigned char *outbuf, uint16_t linktype)
{
	size_t block_total_length;
	uint32_t *final_length;
	pcapng_interface_description_block_t *idb;

	block_total_length = libpcapng_interface_description_block_size();

	idb = (pcapng_interface_description_block_t *)outbuf;
	idb->block_type = PCAPNG_INTERFACE_DESCRIPTION_BLOCK;
	idb->block_total_length = block_total_length;
	idb->linktype = linktype;
	idb->reserved = 0;
	idb->snaplen = snaplen;

	final_length = (uint32_t *)(outbuf + block_total_length - BLOCK_TOTAL_LENGTH_SIZE);
	*final_length = block_total_length;

	return block_total_length;
}

size_t libpcapng_interface_description_block_size(void)
{
	return sizeof(pcapng_interface_description_block_t) + BLOCK_TOTAL_LENGTH_SIZE;
}

pcapng_interface_description_block_light_t *libpcapng_interface_description_block_read(unsigned char *inbuf, size_t inbuf_len)
{
	pcapng_interface_description_block_t *idb;
	pcapng_interface_description_block_light_t *light;

	idb = (pcapng_interface_description_block_t *)inbuf;
	light = (pcapng_interface_description_block_light_t *)malloc(sizeof(*light));
	if (!light) return NULL;

	light->linktype = idb->linktype;
	light->reserved = idb->reserved;
	light->snaplen  = idb->snaplen;

	return light;
}

size_t libpcapng_enhanced_packet_block_write_time(const unsigned char *packet, const size_t packet_len, uint32_t timestamp_high, uint32_t timestamp_low, unsigned char *outbuf)
{
	size_t block_total_length;
	uint32_t *final_length;
	pcapng_enhanced_packet_block_t *epb;

	block_total_length = libpcapng_enhanced_packet_block_size(packet_len);

	epb = (pcapng_enhanced_packet_block_t *)outbuf;
	epb->block_type = PCAPNG_ENHANCED_PACKET_BLOCK;
	epb->block_total_length = block_total_length;
	epb->interface_id = 0;

	epb->timestamp_high = timestamp_high;
	epb->timestamp_low = timestamp_low;

	epb->captured_packet_length = packet_len;
	epb->original_packet_length = packet_len;

	memcpy(outbuf + sizeof(pcapng_enhanced_packet_block_t), packet, packet_len);

	final_length = (uint32_t *)  (outbuf + block_total_length - BLOCK_TOTAL_LENGTH_SIZE);
	*final_length = block_total_length;

	return block_total_length;
}

size_t libpcapng_enhanced_packet_block_write(const unsigned char *packet, const size_t packet_len, unsigned char *outbuf)
{
	struct timeval tv;
	uint64_t ms_tv = 0;
	uint32_t timestamp_high;
	uint32_t timestamp_low;

	gettimeofday(&tv, NULL);
	ms_tv = (uint64_t) (tv.tv_sec) * (uint64_t) 1e6 + (uint64_t) (tv.tv_usec);

	timestamp_high = (uint32_t) (ms_tv >> 32);
	timestamp_low = (uint32_t) ms_tv;

	return libpcapng_enhanced_packet_block_write_time(packet, packet_len, timestamp_high, timestamp_low, outbuf);
}

size_t libpcapng_enhanced_packet_block_size(const size_t packet_len)
{
	uint32_t padded_len;
	uint32_t padding;

	PADDING(packet_len, &padded_len, sizeof(uint32_t));
	padding = padded_len - packet_len;

	return sizeof(pcapng_enhanced_packet_block_t) + packet_len + padding + BLOCK_TOTAL_LENGTH_SIZE;
}

pcapng_enhanced_packet_block_light_t *libpcapng_enhanced_packet_block_read(unsigned char *inbuf, size_t inbuf_len)
{

}

size_t libpcapng_custom_data_block_write(const uint32_t pen, const unsigned char *data, const size_t data_len, unsigned char *outbuf)
{
	size_t block_total_length;
	uint32_t *final_length;
	pcapng_custom_data_block_t *cb;

	block_total_length = libpcapng_custom_data_block_size(data_len);

	memset(outbuf, 0, block_total_length);
	cb = (pcapng_custom_data_block_t *)outbuf;
	cb->block_type = PCAPNG_CUSTOM_DATA_BLOCK;
	cb->block_total_length = block_total_length;
	cb->pen = pen;

	memcpy(outbuf + sizeof(pcapng_custom_data_block_t), data, data_len);

	final_length = (uint32_t *) (outbuf + block_total_length - BLOCK_TOTAL_LENGTH_SIZE);
	*final_length = block_total_length;

#ifdef DEBUG
	uint32_t i;
	printf("Custom Packet Hex output:\n");
	for (i = 0; i < data_len; i++) {
	  printf("%02X", data[i]);
	}
	printf("\n");
#endif // DEBUG

	return block_total_length;
}

size_t libpcapng_custom_data_block_size(const size_t data_len)
{
	uint32_t padded_len;
	uint32_t padding;

	PADDING(data_len, &padded_len, sizeof(uint32_t));
	padding = padded_len - data_len;

	return sizeof(pcapng_custom_data_block_t) + data_len + padding + BLOCK_TOTAL_LENGTH_SIZE;
}

uint32_t libpcapng_custom_data_block_start_offset(void)
{
  return sizeof(pcapng_custom_data_block_light_t);
}

uint32_t libpcapng_custom_data_block_data_length(uint32_t block_total_length)
{
  uint32_t retlen = block_total_length;
  retlen -= BLOCK_TOTAL_LENGTH_SIZE; // The First one.
  retlen -= sizeof(uint32_t); // The block type
  retlen -= libpcapng_custom_data_block_start_offset();
  retlen -= BLOCK_TOTAL_LENGTH_SIZE; // The last one.

  return retlen;
}

pcapng_custom_data_block_light_t *libpcapng_custom_data_block_read(unsigned char *inbuf, size_t inbuf_len)
{

	return NULL;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Options TLV helpers
 * ══════════════════════════════════════════════════════════════════════════*/

size_t libpcapng_options_size(const pcapng_option_t *opts, size_t nopt)
{
	size_t total = 0;
	uint32_t padded;

	for (size_t i = 0; i < nopt; i++) {
		PADDING(opts[i].length, &padded, 4);
		total += 4 + padded;  /* type(2) + len(2) + padded value */
	}
	total += 4;  /* opt_endofopt */
	return total;
}

size_t libpcapng_options_write(const pcapng_option_t *opts, size_t nopt, unsigned char *outbuf)
{
	size_t pos = 0;
	uint32_t padded;

	for (size_t i = 0; i < nopt; i++) {
		uint16_t t = opts[i].type;
		uint16_t l = opts[i].length;
		PADDING(l, &padded, 4);

		memcpy(outbuf + pos, &t, 2);  pos += 2;
		memcpy(outbuf + pos, &l, 2);  pos += 2;
		if (l > 0 && opts[i].value) {
			memcpy(outbuf + pos, opts[i].value, l);
			pos += l;
			if (padded > l) {
				memset(outbuf + pos, 0, padded - l);
				pos += padded - l;
			}
		}
	}
	/* opt_endofopt */
	memset(outbuf + pos, 0, 4);
	pos += 4;
	return pos;
}

/* ══════════════════════════════════════════════════════════════════════════
 * SHB with options
 * ══════════════════════════════════════════════════════════════════════════*/

size_t libpcapng_section_header_block_size_with_options(const pcapng_option_t *opts, size_t nopt)
{
	return libpcapng_section_header_block_size()
	       + (nopt > 0 ? libpcapng_options_size(opts, nopt) : 0);
}

size_t libpcapng_section_header_block_write_with_options(const pcapng_option_t *opts, size_t nopt, unsigned char *outbuf)
{
	size_t block_total_length = libpcapng_section_header_block_size_with_options(opts, nopt);
	pcapng_section_header_block_t *shb;
	uint32_t *final_length;
	size_t pos;

	shb = (pcapng_section_header_block_t *)outbuf;
	shb->block_type = PCAPNG_SECTION_HEADER_BLOCK;
	shb->block_total_length = block_total_length;
	shb->magic = PCAPNG_BYTE_ORDER_MAGIC;
	shb->major_version = PCAPNG_VERSION_MAJOR;
	shb->minor_version = PCAPNG_VERSION_MINOR;
	shb->section_length = (uint64_t)-1;

	pos = sizeof(pcapng_section_header_block_t);
	if (nopt > 0)
		pos += libpcapng_options_write(opts, nopt, outbuf + pos);

	final_length = (uint32_t *)(outbuf + block_total_length - BLOCK_TOTAL_LENGTH_SIZE);
	*final_length = block_total_length;

	return block_total_length;
}

/* ══════════════════════════════════════════════════════════════════════════
 * IDB with options
 * ══════════════════════════════════════════════════════════════════════════*/

size_t libpcapng_interface_description_block_size_with_options(const pcapng_option_t *opts, size_t nopt)
{
	return libpcapng_interface_description_block_size()
	       + (nopt > 0 ? libpcapng_options_size(opts, nopt) : 0);
}

size_t libpcapng_interface_description_block_write_with_options(uint32_t snaplen, uint16_t linktype, const pcapng_option_t *opts, size_t nopt, unsigned char *outbuf)
{
	size_t block_total_length = libpcapng_interface_description_block_size_with_options(opts, nopt);
	pcapng_interface_description_block_t *idb;
	uint32_t *final_length;
	size_t pos;

	idb = (pcapng_interface_description_block_t *)outbuf;
	idb->block_type = PCAPNG_INTERFACE_DESCRIPTION_BLOCK;
	idb->block_total_length = block_total_length;
	idb->linktype = linktype;
	idb->reserved = 0;
	idb->snaplen = snaplen;

	pos = sizeof(pcapng_interface_description_block_t);
	if (nopt > 0)
		pos += libpcapng_options_write(opts, nopt, outbuf + pos);

	final_length = (uint32_t *)(outbuf + block_total_length - BLOCK_TOTAL_LENGTH_SIZE);
	*final_length = block_total_length;

	return block_total_length;
}

/* ══════════════════════════════════════════════════════════════════════════
 * EPB full (interface_id, original_len, options)
 * ══════════════════════════════════════════════════════════════════════════*/

size_t libpcapng_enhanced_packet_block_size_with_options(size_t packet_len, const pcapng_option_t *opts, size_t nopt)
{
	return libpcapng_enhanced_packet_block_size(packet_len)
	       + (nopt > 0 ? libpcapng_options_size(opts, nopt) : 0);
}

size_t libpcapng_enhanced_packet_block_write_full(
	const unsigned char *packet, size_t captured_len,
	uint32_t original_len, uint32_t interface_id,
	uint32_t ts_hi, uint32_t ts_lo,
	const pcapng_option_t *opts, size_t nopt,
	unsigned char *outbuf)
{
	size_t block_total_length = libpcapng_enhanced_packet_block_size_with_options(captured_len, opts, nopt);
	pcapng_enhanced_packet_block_t *epb;
	uint32_t *final_length;
	uint32_t padded;
	size_t pos;

	PADDING(captured_len, &padded, sizeof(uint32_t));

	memset(outbuf, 0, block_total_length);

	epb = (pcapng_enhanced_packet_block_t *)outbuf;
	epb->block_type = PCAPNG_ENHANCED_PACKET_BLOCK;
	epb->block_total_length = block_total_length;
	epb->interface_id = interface_id;
	epb->timestamp_high = ts_hi;
	epb->timestamp_low  = ts_lo;
	epb->captured_packet_length = captured_len;
	epb->original_packet_length = original_len;

	if (captured_len > 0 && packet)
		memcpy(outbuf + sizeof(pcapng_enhanced_packet_block_t), packet, captured_len);

	pos = sizeof(pcapng_enhanced_packet_block_t) + padded;
	if (nopt > 0)
		pos += libpcapng_options_write(opts, nopt, outbuf + pos);

	final_length = (uint32_t *)(outbuf + block_total_length - BLOCK_TOTAL_LENGTH_SIZE);
	*final_length = block_total_length;

	return block_total_length;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Simple Packet Block (spec §4.4)
 * ══════════════════════════════════════════════════════════════════════════*/

size_t libpcapng_simple_packet_block_size(size_t packet_len)
{
	uint32_t padded;
	uint32_t padding;

	PADDING(packet_len, &padded, sizeof(uint32_t));
	padding = padded - packet_len;

	return sizeof(pcapng_simple_packet_block_t) + packet_len + padding + BLOCK_TOTAL_LENGTH_SIZE;
}

size_t libpcapng_simple_packet_block_write(const unsigned char *packet, size_t packet_len, uint32_t original_packet_length, unsigned char *outbuf)
{
	size_t block_total_length = libpcapng_simple_packet_block_size(packet_len);
	pcapng_simple_packet_block_t *spb;
	uint32_t *final_length;
	uint32_t padded;

	PADDING(packet_len, &padded, sizeof(uint32_t));

	memset(outbuf, 0, block_total_length);

	spb = (pcapng_simple_packet_block_t *)outbuf;
	spb->block_type = PCAPNG_SIMPLE_PACKET_BLOCK;
	spb->block_total_length = block_total_length;
	spb->original_packet_length = original_packet_length;

	if (packet_len > 0 && packet)
		memcpy(outbuf + sizeof(pcapng_simple_packet_block_t), packet, packet_len);

	final_length = (uint32_t *)(outbuf + block_total_length - BLOCK_TOTAL_LENGTH_SIZE);
	*final_length = block_total_length;

	return block_total_length;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Name Resolution Block (spec §4.5)
 * ══════════════════════════════════════════════════════════════════════════*/

/*
 * NRB record size: record header (4) + addr_len + name_len+1 (null-terminated),
 * all padded to 4-byte boundary.
 */
size_t libpcapng_nrb_record_size(size_t addr_len, size_t name_len)
{
	uint32_t padded;
	size_t data_len = addr_len + name_len + 1;  /* +1 for NUL terminator */
	PADDING(data_len, &padded, 4);
	return 4 + padded;
}

size_t libpcapng_nrb_record_write(uint16_t record_type, const void *addr, size_t addr_len, const char *name, unsigned char *outbuf)
{
	size_t name_len = name ? strlen(name) : 0;
	size_t data_len = addr_len + name_len + 1;
	uint32_t padded;
	pcapng_nrb_record_t *rec;
	size_t pos;

	PADDING(data_len, &padded, 4);
	memset(outbuf, 0, 4 + padded);

	rec = (pcapng_nrb_record_t *)outbuf;
	rec->record_type   = record_type;
	rec->record_length = (uint16_t)data_len;

	pos = sizeof(pcapng_nrb_record_t);
	if (addr_len > 0 && addr)
		memcpy(outbuf + pos, addr, addr_len);
	pos += addr_len;
	if (name_len > 0)
		memcpy(outbuf + pos, name, name_len);
	/* NUL terminator and padding are already zeroed by memset */

	return 4 + padded;
}

size_t libpcapng_name_resolution_block_size(const unsigned char *records_buf, size_t records_len, const pcapng_option_t *opts, size_t nopt)
{
	uint32_t padded;
	PADDING(records_len, &padded, 4);
	return sizeof(pcapng_name_resolution_block_t)
	       + padded
	       + (nopt > 0 ? libpcapng_options_size(opts, nopt) : 0)
	       + BLOCK_TOTAL_LENGTH_SIZE;
}

size_t libpcapng_name_resolution_block_write(const unsigned char *records_buf, size_t records_len, const pcapng_option_t *opts, size_t nopt, unsigned char *outbuf)
{
	size_t block_total_length = libpcapng_name_resolution_block_size(records_buf, records_len, opts, nopt);
	pcapng_name_resolution_block_t *nrb;
	uint32_t *final_length;
	uint32_t padded;
	size_t pos;

	PADDING(records_len, &padded, 4);
	memset(outbuf, 0, block_total_length);

	nrb = (pcapng_name_resolution_block_t *)outbuf;
	nrb->block_type = PCAPNG_NAME_RESOLUTION_BLOCK;
	nrb->block_total_length = block_total_length;

	pos = sizeof(pcapng_name_resolution_block_t);
	if (records_len > 0 && records_buf)
		memcpy(outbuf + pos, records_buf, records_len);
	pos += padded;

	if (nopt > 0)
		pos += libpcapng_options_write(opts, nopt, outbuf + pos);

	final_length = (uint32_t *)(outbuf + block_total_length - BLOCK_TOTAL_LENGTH_SIZE);
	*final_length = block_total_length;

	return block_total_length;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Interface Statistics Block (spec §4.6)
 * ══════════════════════════════════════════════════════════════════════════*/

size_t libpcapng_interface_statistics_block_size(const pcapng_option_t *opts, size_t nopt)
{
	return sizeof(pcapng_interface_statistics_block_t)
	       + (nopt > 0 ? libpcapng_options_size(opts, nopt) : 0)
	       + BLOCK_TOTAL_LENGTH_SIZE;
}

size_t libpcapng_interface_statistics_block_write(uint32_t interface_id, uint32_t ts_hi, uint32_t ts_lo, const pcapng_option_t *opts, size_t nopt, unsigned char *outbuf)
{
	size_t block_total_length = libpcapng_interface_statistics_block_size(opts, nopt);
	pcapng_interface_statistics_block_t *isb;
	uint32_t *final_length;
	size_t pos;

	isb = (pcapng_interface_statistics_block_t *)outbuf;
	isb->block_type = PCAPNG_INTERFACE_STATISTICS_BLOCK;
	isb->block_total_length = block_total_length;
	isb->interface_id = interface_id;
	isb->timestamp_high = ts_hi;
	isb->timestamp_low  = ts_lo;

	pos = sizeof(pcapng_interface_statistics_block_t);
	if (nopt > 0)
		pos += libpcapng_options_write(opts, nopt, outbuf + pos);

	final_length = (uint32_t *)(outbuf + block_total_length - BLOCK_TOTAL_LENGTH_SIZE);
	*final_length = block_total_length;

	return block_total_length;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Decryption Secrets Block (spec §4.7)
 * ══════════════════════════════════════════════════════════════════════════*/

size_t libpcapng_decryption_secrets_block_size(size_t secrets_len)
{
	uint32_t padded;
	PADDING(secrets_len, &padded, sizeof(uint32_t));
	return sizeof(pcapng_decryption_secrets_block_t) + padded + BLOCK_TOTAL_LENGTH_SIZE;
}

size_t libpcapng_decryption_secrets_block_write(uint32_t secrets_type, const unsigned char *secrets, size_t secrets_len, unsigned char *outbuf)
{
	size_t block_total_length = libpcapng_decryption_secrets_block_size(secrets_len);
	pcapng_decryption_secrets_block_t *dsb;
	uint32_t *final_length;
	uint32_t padded;

	PADDING(secrets_len, &padded, sizeof(uint32_t));
	memset(outbuf, 0, block_total_length);

	dsb = (pcapng_decryption_secrets_block_t *)outbuf;
	dsb->block_type = PCAPNG_DECRYPTION_SECRETS_BLOCK;
	dsb->block_total_length = block_total_length;
	dsb->secrets_type   = secrets_type;
	dsb->secrets_length = secrets_len;

	if (secrets_len > 0 && secrets)
		memcpy(outbuf + sizeof(pcapng_decryption_secrets_block_t), secrets, secrets_len);

	final_length = (uint32_t *)(outbuf + block_total_length - BLOCK_TOTAL_LENGTH_SIZE);
	*final_length = block_total_length;

	return block_total_length;
}
