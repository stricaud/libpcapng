/*
 * License MIT
 * Copyright (c) 2021 Devo Inc.
 * Copyright (c) 2022 Sebastien Tricaud
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libpcapng/blocks.h>

#include <libpcapng/io.h>

/* ── Classic pcap helpers ────────────────────────────────────────────────── */

/*
 * Classic pcap magic values (native-endian after memcpy into uint32_t):
 *   0xa1b2c3d4  microsecond LE file on LE host  (or BE file on BE host)
 *   0xd4c3b2a1  microsecond BE file on LE host  (or LE file on BE host)
 *   0xa1b23c4d  nanosecond  LE file on LE host
 *   0x4d3cb2a1  nanosecond  BE file on LE host
 */
#define PCAP_MAGIC_NATIVE   0xa1b2c3d4u
#define PCAP_MAGIC_SWAPPED  0xd4c3b2a1u
#define PCAP_MAGIC_NS_NAT   0xa1b23c4du
#define PCAP_MAGIC_NS_SWP   0x4d3cb2a1u

static uint16_t _pcap_swap16(uint16_t v) {
    return (uint16_t)((v >> 8) | (v << 8));
}
static uint32_t _pcap_swap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) <<  8) |
           ((v & 0x00FF0000u) >>  8) | ((v & 0xFF000000u) >> 24);
}
static uint32_t _pcap_u32(const unsigned char *p, int swap) {
    uint32_t v; memcpy(&v, p, 4); return swap ? _pcap_swap32(v) : v;
}
static uint16_t _pcap_u16(const unsigned char *p, int swap) {
    uint16_t v; memcpy(&v, p, 2); return swap ? _pcap_swap16(v) : v;
}

/* Returns 1 if buf starts with a classic pcap magic; sets *need_swap. */
static int _pcap_classic_magic(const unsigned char *buf, size_t buf_len, int *need_swap)
{
    uint32_t magic;
    if (buf_len < 4) return 0;
    memcpy(&magic, buf, 4);
    if (magic == PCAP_MAGIC_NATIVE  || magic == PCAP_MAGIC_NS_NAT) { *need_swap = 0; return 1; }
    if (magic == PCAP_MAGIC_SWAPPED || magic == PCAP_MAGIC_NS_SWP) { *need_swap = 1; return 1; }
    return 0;
}

/*
 * Emit a synthetic IDB callback and then one EPB callback per packet.
 * Used by both the file and the memory readers.
 */
static void _pcap_emit_idb(uint32_t linktype, uint32_t snaplen,
                            foreach_pcapng_block_cb cb, void *userdata)
{
    /* IDB body: linktype(2) reserved(2) snaplen(4) trailing_btl(4) */
    unsigned char idb[12];
    uint16_t lt16 = (uint16_t)(linktype & 0xffffu), rsv = 0;
    uint32_t idb_btl = 20; /* 4+4+2+2+4+4 */
    memcpy(idb + 0, &lt16,    2);
    memcpy(idb + 2, &rsv,     2);
    memcpy(idb + 4, &snaplen, 4);
    memcpy(idb + 8, &idb_btl, 4);
    cb(0, PCAPNG_INTERFACE_DESCRIPTION_BLOCK, idb_btl, idb, userdata);
}

static int _pcap_emit_epb(uint32_t ts_sec, uint32_t ts_usec,
                           const unsigned char *pkt, uint32_t incl_len, uint32_t orig_len,
                           uint64_t counter, foreach_pcapng_block_cb cb, void *userdata)
{
    /* EPB body: iface_id(4) ts_hi(4) ts_lo(4) cap_len(4) orig_len(4)
     *           pkt_data(incl_len) pad trailing_btl(4) */
    uint32_t pad     = (4 - (incl_len % 4)) % 4;
    uint32_t epb_btl = 8 + 20 + incl_len + pad + 4;
    uint32_t data_sz = epb_btl - 8;

    unsigned char *epb = (unsigned char *)malloc(data_sz);
    if (!epb) return -1;

    uint32_t iface = 0;
    memcpy(epb +  0, &iface,    4);
    memcpy(epb +  4, &ts_sec,   4);
    memcpy(epb +  8, &ts_usec,  4);
    memcpy(epb + 12, &incl_len, 4);
    memcpy(epb + 16, &orig_len, 4);
    memcpy(epb + 20, pkt,       incl_len);
    memset(epb + 20 + incl_len, 0, pad);
    memcpy(epb + 20 + incl_len + pad, &epb_btl, 4);

    cb((uint32_t)counter, PCAPNG_ENHANCED_PACKET_BLOCK, epb_btl, epb, userdata);
    free(epb);
    return 0;
}

/* ── Classic pcap from memory ────────────────────────────────────────────── */

static int _mem_read_classic_pcap(const unsigned char *buf, size_t buf_len,
                                   foreach_pcapng_block_cb cb, void *userdata)
{
    if (buf_len < 24) return -1;
    int swap;
    if (!_pcap_classic_magic(buf, buf_len, &swap)) return -1;

    uint32_t snaplen  = _pcap_u32(buf + 16, swap);
    uint32_t linktype = _pcap_u32(buf + 20, swap);
    _pcap_emit_idb(linktype, snaplen, cb, userdata);

    size_t   off = 24;
    uint64_t ctr = 1;
    while (off + 16 <= buf_len) {
        uint32_t ts_sec   = _pcap_u32(buf + off +  0, swap);
        uint32_t ts_usec  = _pcap_u32(buf + off +  4, swap);
        uint32_t incl_len = _pcap_u32(buf + off +  8, swap);
        uint32_t orig_len = _pcap_u32(buf + off + 12, swap);
        off += 16;
        if (incl_len > 65535 || off + incl_len > buf_len) break;
        _pcap_emit_epb(ts_sec, ts_usec, buf + off, incl_len, orig_len, ctr, cb, userdata);
        off += incl_len;
        ctr++;
    }
    return 0;
}

/* ── pcapng from memory ──────────────────────────────────────────────────── */

static int _mem_read_pcapng(const unsigned char *buf, size_t buf_len,
                             foreach_pcapng_block_cb cb, void *userdata)
{
    size_t   off = 0;
    uint64_t ctr = 1;
    while (off + 8 <= buf_len) {
        uint32_t block_type, block_total_length;
        memcpy(&block_type,         buf + off,     4);
        memcpy(&block_total_length, buf + off + 4, 4);
        if (block_total_length < 12 || off + block_total_length > buf_len) break;
        cb((uint32_t)ctr, block_type, block_total_length,
           (unsigned char *)(buf + off + 8), userdata);
        off += block_total_length;
        ctr++;
    }
    return 0;
}

/* ── Classic pcap from FILE* ─────────────────────────────────────────────── */

static int _fp_read_classic_pcap(FILE *fp, foreach_pcapng_block_cb cb, void *userdata)
{
    unsigned char global_hdr[24];
    if (fread(global_hdr, 1, 24, fp) != 24) return -1;

    int swap;
    if (!_pcap_classic_magic(global_hdr, 24, &swap)) return -1;

    uint32_t snaplen  = _pcap_u32(global_hdr + 16, swap);
    uint32_t linktype = _pcap_u32(global_hdr + 20, swap);
    _pcap_emit_idb(linktype, snaplen, cb, userdata);

    uint8_t  pkt_hdr[16];
    uint64_t ctr = 1;
    unsigned char *pkt_buf = NULL;
    uint32_t      pkt_buf_cap = 0;

    while (fread(pkt_hdr, 1, 16, fp) == 16) {
        uint32_t ts_sec   = _pcap_u32(pkt_hdr +  0, swap);
        uint32_t ts_usec  = _pcap_u32(pkt_hdr +  4, swap);
        uint32_t incl_len = _pcap_u32(pkt_hdr +  8, swap);
        uint32_t orig_len = _pcap_u32(pkt_hdr + 12, swap);
        if (incl_len > 65535) break;
        if (incl_len > pkt_buf_cap) {
            free(pkt_buf);
            pkt_buf = (unsigned char *)malloc(incl_len);
            if (!pkt_buf) return -1;
            pkt_buf_cap = incl_len;
        }
        if (fread(pkt_buf, 1, incl_len, fp) != incl_len) break;
        _pcap_emit_epb(ts_sec, ts_usec, pkt_buf, incl_len, orig_len, ctr, cb, userdata);
        ctr++;
    }
    free(pkt_buf);
    return 0;
}

int foreach_pcapng_block(uint32_t block_counter, uint32_t block_type, uint32_t block_total_length, unsigned char *data, void *userdata)
{

	switch (block_type) {
	case PCAPNG_SECTION_HEADER_BLOCK: {
		/* printf("Section Header Block\n"); */
		pcapng_section_header_block_light_t *shb;
		shb = libpcapng_section_header_block_read(data, block_total_length);
	}
		break;
	case PCAPNG_CUSTOM_DATA_BLOCK: {
		/* printf("Custom Data Block\n"); */
		pcapng_custom_data_block_light_t *cb;
		cb = libpcapng_custom_data_block_read(data, block_total_length);
	}
		break;
	case PCAPNG_ENHANCED_PACKET_BLOCK: {
		/* printf("PCAPNG_ENHANCED_PACKET_BLOCK\n"); */
		pcapng_enhanced_packet_block_light_t *epb;
		epb = libpcapng_enhanced_packet_block_read(data, block_total_length);
	}
		break;
	case PCAPNG_INTERFACE_DESCRIPTION_BLOCK:
		printf("Interface Description Block\n");
		break;
	default:
		fprintf(stderr, "Block type %x not handled yet!\n", block_type);
		break;
	}

	return 0;
}

int libpcapng_mem_read(unsigned char *buf, size_t buf_len,
                       foreach_pcapng_block_cb pcapng_block_cb, void *userdata)
{
    int swap;
    if (!pcapng_block_cb) { fprintf(stderr, "No Block Callback set!\n"); return -1; }
    if (_pcap_classic_magic(buf, buf_len, &swap))
        return _mem_read_classic_pcap(buf, buf_len, pcapng_block_cb, userdata);
    return _mem_read_pcapng(buf, buf_len, pcapng_block_cb, userdata);
}

int libpcapng_fp_read(FILE *fp, foreach_pcapng_block_cb pcapng_block_cb, void *userdata)
{
	uint64_t block_counter = 1;
	uint32_t block_info[2]; // [0] = block_type [1] = block_total_length
	size_t read_length;

	unsigned char data[65535]; // A packet is not greater than snaplen
	uint32_t block_total_length = 0;

	if (!pcapng_block_cb) {
	  fprintf(stderr, "No Block Callback set!\n");
	  return -1;
	}

	/* Detect classic pcap by peeking at the first 4 magic bytes. */
	{
		unsigned char magic_buf[4];
		if (fread(magic_buf, 1, 4, fp) != 4) return -1;
		int swap;
		if (_pcap_classic_magic(magic_buf, 4, &swap)) {
			fseek(fp, 0, SEEK_SET);
			return _fp_read_classic_pcap(fp, pcapng_block_cb, userdata);
		}
		/* Not classic pcap; seek back and continue with pcapng parsing. */
		fseek(fp, 0, SEEK_SET);
	}

	read_length = fread(&block_info, 1, PCAPNG_BLOCK_TYPE_AND_SIZE_LENGTH, fp);
	if (read_length != PCAPNG_BLOCK_TYPE_AND_SIZE_LENGTH) {
		fprintf(stderr, "Could not read expected data: got %lu expected %u. Stopping.\n", read_length, PCAPNG_BLOCK_TYPE_AND_SIZE_LENGTH);
		return -1;
	}
	block_total_length = block_info[1];
	while (read_length > 0) {
		if (block_total_length - PCAPNG_BLOCK_TYPE_AND_SIZE_LENGTH > sizeof(data)) {
			fprintf(stderr, "Block size %u exceeds buffer. Stopping.\n", block_total_length);
			return -1;
		}
		read_length = fread(&data, 1, block_total_length - PCAPNG_BLOCK_TYPE_AND_SIZE_LENGTH, fp);
		if (read_length != block_info[1] - PCAPNG_BLOCK_TYPE_AND_SIZE_LENGTH) {
			fprintf(stderr, "Could not read expected (%u) block_size; Got %lu. Stopping.\n", block_info[1], read_length);
			return -1;
		}

		pcapng_block_cb(block_counter, block_info[0], block_info[1], (unsigned char *)data, (void *)userdata);

		read_length = fread(&block_info, 1, PCAPNG_BLOCK_TYPE_AND_SIZE_LENGTH, fp);
		if (read_length == 0) {
			break;
		}
		if (read_length != PCAPNG_BLOCK_TYPE_AND_SIZE_LENGTH) {
			fprintf(stderr, "Could not read expected (%d) data; Got %lu. Stopping.\n", PCAPNG_BLOCK_TYPE_AND_SIZE_LENGTH, read_length);
			return -1;
		}
		block_total_length = block_info[1];

		block_counter++;
	}
	return 0;
}

int libpcapng_file_read(char *filename, foreach_pcapng_block_cb pcapng_block_cb, void *userdata)
{
	FILE *fp;

	fp = fopen(filename, "rb");
	if (!fp) {
		fprintf(stderr, "Cannot read file '%s'\n", filename);
		return -1;
	}

	libpcapng_fp_read(fp, pcapng_block_cb, userdata);

	fclose(fp);

	return 0;
}

int libpcapng_file_read_debug(char *filename)
{
  return libpcapng_file_read(filename, foreach_pcapng_block, NULL);
}

int libpcapng_padded_count(unsigned char *data, uint32_t data_len)
{
	int retpad = 0;
	int i;

	/*
	 * Count only trailing *consecutive* zero bytes (pcapng alignment
	 * padding is at most 3 bytes).  The previous implementation counted
	 * every zero byte among the last four positions, which incorrectly
	 * stripped payload bytes whose values happened to be 0x00.
	 */
	for (i = (int)data_len - 1; i >= 0 && retpad < 3; i--) {
		if (data[i] == 0)
			retpad++;
		else
			break;
	}

	return retpad;
}
