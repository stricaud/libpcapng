/*
 * License MIT
 * Copyright (c) 2021 Devo Inc.
 * Copyright (c) 2022 Sebastien Tricaud
 */
#ifndef _LIBPCAPNG_BLOCKS_H_
#define _LIBPCAPNG_BLOCKS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define BLOCK_TOTAL_LENGTH_SIZE 4

#define PCAPNG_INTERFACE_DESCRIPTION_BLOCK         0x00000001
#define PCAPNG_PACKET_BLOCK                        0x00000002
#define PCAPNG_SIMPLE_PACKET_BLOCK                 0x00000003
#define PCAPNG_NAME_RESOLUTION_BLOCK               0x00000004
#define PCAPNG_INTERFACE_STATISTICS_BLOCK          0x00000005
#define PCAPNG_ENHANCED_PACKET_BLOCK               0x00000006
#define PCAPNG_IRIG_TIMESTAMP_BLOCK                0x00000007
#define PCAPNG_ARINC_429_AFDX_ENCAP_BLOCK          0x00000008
#define PCAPNG_SYSTEMD_JOURNAL_EXPORT_BLOCK        0x00000009
#define PCAPNG_DECRYPTION_SECRETS_BLOCK            0x0000000A
#define PCAPNG_HONE_PROJECT_MACHINE_INFO_BLOCK     0x00000101
#define PCAPNG_HONE_PROJECT_CONNECTION_EVENT_BLOCK 0x00000102
#define PCAPNG_SYSDIG_MACHINE_INFO_BLOCK           0x00000201
#define PCAPNG_SYSDIG_PROCESS_INFO_V1_BLOCK        0x00000202
#define PCAPNG_SYSDIG_FD_LIST_BLOCK                0x00000203
#define PCAPNG_SYSDIG_EVENT_BLOCK                  0x00000204
#define PCAPNG_SYSDIG_INTERFACE_LIST_BLOCK         0x00000205
#define PCAPNG_SYSDIG_USER_LIST_BLOCK              0x00000206
#define PCAPNG_SYSDIG_PROCESS_INFO_V2_BLOCK        0x00000207
#define PCAPNG_SYSDIG_EVENT_WITH_FLAGS_BLOCK       0x00000208
#define PCAPNG_SYSDIG_PROCESS_INFO_V3_BLOCK        0x00000209
#define PCAPNG_SYSDIG_PROCESS_INFO_V4_BLOCK        0x00000210
#define PCAPNG_SYSDIG_PROCESS_INFO_V5_BLOCK        0x00000211
#define PCAPNG_SYSDIG_PROCESS_INFO_V6_BLOCK        0x00000212
#define PCAPNG_SYSDIG_PROCESS_INFO_V7_BLOCK        0x00000213
#define PCAPNG_CUSTOM_DATA_BLOCK                   0x00000BAD
#define PCAPNG_CUSTOM_DATA_BLOCK_NOCOPY            0x40000BAD
#define PCAPNG_SECTION_HEADER_BLOCK                0x0A0D0D0A

/* DSB secret type codes */
#define PCAPNG_TLS_KEY_LOG          0x544c534b  /* "TLSK" */
#define PCAPNG_WIREGUARD_KEY_LOG    0x57474b4c  /* "WGKL" */
#define PCAPNG_ZIGBEE_NWK_KEY       0x5a4e574b  /* "ZNWK" */
#define PCAPNG_ZIGBEE_APS_KEY       0x5a415053  /* "ZAPS" */
#define PCAPNG_SSH_KEY_LOG          0x5353484b  /* "SSHK" */
#define PCAPNG_OPC_UA_KEY_LOG       0x55414b4c  /* "UAKL" */
#define PCAPNG_ESP_SA               0x45535053  /* "ESPS" */

/* NRB record types (spec §4.5) */
#define PCAPNG_NRB_RECORD_END       0x0000
#define PCAPNG_NRB_RECORD_IPV4      0x0001
#define PCAPNG_NRB_RECORD_IPV6      0x0002
#define PCAPNG_NRB_RECORD_EUI48     0x0003
#define PCAPNG_NRB_RECORD_EUI64     0x0004

/* Common option codes (all blocks) */
#define PCAPNG_OPT_ENDOFOPT         0
#define PCAPNG_OPT_COMMENT          1
#define PCAPNG_OPT_CUSTOM_2988      2988
#define PCAPNG_OPT_CUSTOM_2989      2989
#define PCAPNG_OPT_CUSTOM_19372     19372
#define PCAPNG_OPT_CUSTOM_19373     19373

/* SHB option codes (spec §4.1) */
#define PCAPNG_OPT_SHB_HARDWARE     2
#define PCAPNG_OPT_SHB_OS           3
#define PCAPNG_OPT_SHB_USERAPPL     4

/* IDB option codes (spec §4.2) */
#define PCAPNG_OPT_IDB_NAME         2
#define PCAPNG_OPT_IDB_DESCRIPTION  3
#define PCAPNG_OPT_IDB_IPV4ADDR     4
#define PCAPNG_OPT_IDB_IPV6ADDR     5
#define PCAPNG_OPT_IDB_MACADDR      6
#define PCAPNG_OPT_IDB_EUIADDR      7
#define PCAPNG_OPT_IDB_SPEED        8
#define PCAPNG_OPT_IDB_TSRESOL      9
#define PCAPNG_OPT_IDB_TZONE        10
#define PCAPNG_OPT_IDB_FILTER       11
#define PCAPNG_OPT_IDB_OS           12
#define PCAPNG_OPT_IDB_FCSLEN       13
#define PCAPNG_OPT_IDB_TSOFFSET     14
#define PCAPNG_OPT_IDB_HARDWARE     15
#define PCAPNG_OPT_IDB_TXSPEED      16
#define PCAPNG_OPT_IDB_RXSPEED      17
#define PCAPNG_OPT_IDB_IANA_TZNAME  18

/* EPB option codes (spec §4.3) */
#define PCAPNG_OPT_EPB_FLAGS        2
#define PCAPNG_OPT_EPB_HASH         3
#define PCAPNG_OPT_EPB_DROPCOUNT    4
#define PCAPNG_OPT_EPB_PACKETID     5
#define PCAPNG_OPT_EPB_QUEUE        6
#define PCAPNG_OPT_EPB_VERDICT      7
#define PCAPNG_OPT_EPB_PROCESSID    8

/* EPB flags word bit fields (spec §4.3.1) */
#define PCAPNG_EPB_FLAG_DIR_MASK        0x00000003u
#define PCAPNG_EPB_FLAG_DIR_UNKNOWN     0x00000000u
#define PCAPNG_EPB_FLAG_DIR_INBOUND     0x00000001u
#define PCAPNG_EPB_FLAG_DIR_OUTBOUND    0x00000002u
#define PCAPNG_EPB_FLAG_RECV_MASK       0x0000001Cu
#define PCAPNG_EPB_FLAG_RECV_UNSPEC     0x00000000u
#define PCAPNG_EPB_FLAG_RECV_UNICAST    0x00000004u
#define PCAPNG_EPB_FLAG_RECV_MULTICAST  0x00000008u
#define PCAPNG_EPB_FLAG_RECV_BROADCAST  0x0000000Cu
#define PCAPNG_EPB_FLAG_RECV_PROMISC    0x00000010u
#define PCAPNG_EPB_FLAG_FCS_LEN_MASK    0x000001E0u
#define PCAPNG_EPB_FLAG_FCS_LEN_SHIFT   5
#define PCAPNG_EPB_FLAG_CKSUM_NOT_READY 0x00000200u
#define PCAPNG_EPB_FLAG_CKSUM_VALID     0x00000400u
#define PCAPNG_EPB_FLAG_TCP_SEG_OFFLOAD 0x00000800u
#define PCAPNG_EPB_FLAG_LL_ERR_SYMBOL   0x80000000u
#define PCAPNG_EPB_FLAG_LL_ERR_PREAMBLE 0x40000000u
#define PCAPNG_EPB_FLAG_LL_ERR_SFD      0x20000000u
#define PCAPNG_EPB_FLAG_LL_ERR_UNALIGN  0x10000000u
#define PCAPNG_EPB_FLAG_LL_ERR_IFG      0x08000000u
#define PCAPNG_EPB_FLAG_LL_ERR_SHORT    0x04000000u
#define PCAPNG_EPB_FLAG_LL_ERR_LONG     0x02000000u
#define PCAPNG_EPB_FLAG_LL_ERR_CRC      0x01000000u

/* NRB option codes (spec §4.5) */
#define PCAPNG_OPT_NS_DNSNAME       2
#define PCAPNG_OPT_NS_DNSIP4ADDR    3
#define PCAPNG_OPT_NS_DNSIP6ADDR    4

/* ISB option codes (spec §4.6) */
#define PCAPNG_OPT_ISB_STARTTIME    2
#define PCAPNG_OPT_ISB_ENDTIME      3
#define PCAPNG_OPT_ISB_IFRECV       4
#define PCAPNG_OPT_ISB_IFDROP       5
#define PCAPNG_OPT_ISB_FILTERACCEPT 6
#define PCAPNG_OPT_ISB_OSDROP       7
#define PCAPNG_OPT_ISB_USRDELIV     8

/*
 * Option helper — used to pass option lists to block-write functions.
 * Not a wire-format struct; value is a pointer to the option's data bytes.
 */
typedef struct {
    uint16_t    type;
    uint16_t    length;
    const void *value;
} pcapng_option_t;

struct _pcapng_custom_data_block_t {
	uint32_t block_type;
	uint32_t block_total_length;
	uint32_t pen;
} __attribute__((packed));
typedef struct _pcapng_custom_data_block_t pcapng_custom_data_block_t;

struct _pcapng_custom_data_block_light_t {
	uint32_t pen;
} __attribute__((packed));
typedef struct _pcapng_custom_data_block_light_t pcapng_custom_data_block_light_t;

struct _pcapng_section_header_block_t {
	uint32_t block_type;
	uint32_t block_total_length;
	uint32_t magic;
	uint16_t major_version;
	uint16_t minor_version;
	uint64_t section_length;
} __attribute__((packed));
typedef struct _pcapng_section_header_block_t pcapng_section_header_block_t;

struct _pcapng_section_header_block_light_t {
	uint32_t magic;
	uint16_t major_version;
	uint16_t minor_version;
	uint64_t section_length;
} __attribute__((packed));
typedef struct _pcapng_section_header_block_light_t pcapng_section_header_block_light_t;

struct _pcapng_interface_description_block_t {
	uint32_t block_type;
	uint32_t block_total_length;
	uint16_t linktype;
	uint16_t reserved;
	uint32_t snaplen;
} __attribute__((packed));
typedef struct _pcapng_interface_description_block_t pcapng_interface_description_block_t;

struct _pcapng_interface_description_block_light_t {
	uint16_t linktype;
	uint16_t reserved;
	uint32_t snaplen;
} __attribute__((packed));
typedef struct _pcapng_interface_description_block_light_t pcapng_interface_description_block_light_t;

struct _pcapng_enhanced_packet_block_t {
	uint32_t block_type;
	uint32_t block_total_length;
	uint32_t interface_id;
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	uint32_t captured_packet_length;
	uint32_t original_packet_length;
} __attribute__((packed));
typedef struct _pcapng_enhanced_packet_block_t pcapng_enhanced_packet_block_t;

struct _pcapng_enhanced_packet_block_light_t {
	uint32_t interface_id;
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	uint32_t captured_packet_length;
	uint32_t original_packet_length;
} __attribute__((packed));
typedef struct _pcapng_enhanced_packet_block_light_t pcapng_enhanced_packet_block_light_t;

/* Simple Packet Block (spec §4.4) */
struct _pcapng_simple_packet_block_t {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t original_packet_length;
} __attribute__((packed));
typedef struct _pcapng_simple_packet_block_t pcapng_simple_packet_block_t;

/* Name Resolution Block (spec §4.5) */
struct _pcapng_name_resolution_block_t {
    uint32_t block_type;
    uint32_t block_total_length;
} __attribute__((packed));
typedef struct _pcapng_name_resolution_block_t pcapng_name_resolution_block_t;

/* NRB record header (type + length precede each record) */
struct _pcapng_nrb_record_t {
    uint16_t record_type;
    uint16_t record_length;
} __attribute__((packed));
typedef struct _pcapng_nrb_record_t pcapng_nrb_record_t;

/* Interface Statistics Block (spec §4.6) */
struct _pcapng_interface_statistics_block_t {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
} __attribute__((packed));
typedef struct _pcapng_interface_statistics_block_t pcapng_interface_statistics_block_t;

/* Decryption Secrets Block (spec §4.7) */
struct _pcapng_decryption_secrets_block_t {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t secrets_type;
    uint32_t secrets_length;
} __attribute__((packed));
typedef struct _pcapng_decryption_secrets_block_t pcapng_decryption_secrets_block_t;

/* ── Options helpers ─────────────────────────────────────────────────────── */
size_t libpcapng_options_size(const pcapng_option_t *opts, size_t nopt);
size_t libpcapng_options_write(const pcapng_option_t *opts, size_t nopt, unsigned char *outbuf);

/* ── SHB ─────────────────────────────────────────────────────────────────── */
size_t libpcapng_section_header_block_write(unsigned char *outbuf);
size_t libpcapng_section_header_block_size(void);
size_t libpcapng_section_header_block_size_with_options(const pcapng_option_t *opts, size_t nopt);
size_t libpcapng_section_header_block_write_with_options(const pcapng_option_t *opts, size_t nopt, unsigned char *outbuf);
pcapng_section_header_block_light_t *libpcapng_section_header_block_read(unsigned char *inbuf, size_t inbuf_len);

/* ── IDB ─────────────────────────────────────────────────────────────────── */
size_t libpcapng_interface_description_block_write(uint32_t snaplen, unsigned char *outbuf);
size_t libpcapng_interface_description_block_write_with_linktype(uint32_t snaplen, unsigned char *outbuf, uint16_t linktype);
size_t libpcapng_interface_description_block_size(void);
size_t libpcapng_interface_description_block_size_with_options(const pcapng_option_t *opts, size_t nopt);
size_t libpcapng_interface_description_block_write_with_options(uint32_t snaplen, uint16_t linktype, const pcapng_option_t *opts, size_t nopt, unsigned char *outbuf);
pcapng_interface_description_block_light_t *libpcapng_interface_description_block_read(unsigned char *inbuf, size_t inbuf_len);

/* ── EPB ─────────────────────────────────────────────────────────────────── */
size_t libpcapng_enhanced_packet_block_write_time(const unsigned char *packet, const size_t packet_len, uint32_t timestamp_high, uint32_t timestamp_low, unsigned char *outbuf);
size_t libpcapng_enhanced_packet_block_write(const unsigned char *packet, const size_t packet_len, unsigned char *outbuf);
size_t libpcapng_enhanced_packet_block_size(const size_t packet_len);
size_t libpcapng_enhanced_packet_block_size_with_options(size_t packet_len, const pcapng_option_t *opts, size_t nopt);
size_t libpcapng_enhanced_packet_block_write_full(const unsigned char *packet, size_t captured_len, uint32_t original_len, uint32_t interface_id, uint32_t ts_hi, uint32_t ts_lo, const pcapng_option_t *opts, size_t nopt, unsigned char *outbuf);
pcapng_enhanced_packet_block_light_t *libpcapng_enhanced_packet_block_read(unsigned char *inbuf, size_t inbuf_len);

/* ── SPB ─────────────────────────────────────────────────────────────────── */
size_t libpcapng_simple_packet_block_size(size_t packet_len);
size_t libpcapng_simple_packet_block_write(const unsigned char *packet, size_t packet_len, uint32_t original_packet_length, unsigned char *outbuf);

/* ── NRB ─────────────────────────────────────────────────────────────────── */
size_t libpcapng_nrb_record_size(size_t addr_len, size_t name_len);
size_t libpcapng_nrb_record_write(uint16_t record_type, const void *addr, size_t addr_len, const char *name, unsigned char *outbuf);
size_t libpcapng_name_resolution_block_size(const unsigned char *records_buf, size_t records_len, const pcapng_option_t *opts, size_t nopt);
size_t libpcapng_name_resolution_block_write(const unsigned char *records_buf, size_t records_len, const pcapng_option_t *opts, size_t nopt, unsigned char *outbuf);

/* ── ISB ─────────────────────────────────────────────────────────────────── */
size_t libpcapng_interface_statistics_block_size(const pcapng_option_t *opts, size_t nopt);
size_t libpcapng_interface_statistics_block_write(uint32_t interface_id, uint32_t ts_hi, uint32_t ts_lo, const pcapng_option_t *opts, size_t nopt, unsigned char *outbuf);

/* ── DSB ─────────────────────────────────────────────────────────────────── */
size_t libpcapng_decryption_secrets_block_size(size_t secrets_len);
size_t libpcapng_decryption_secrets_block_write(uint32_t secrets_type, const unsigned char *secrets, size_t secrets_len, unsigned char *outbuf);

/* ── Custom block ────────────────────────────────────────────────────────── */
size_t libpcapng_custom_data_block_write(const uint32_t pen, const unsigned char *data, const size_t data_len, unsigned char *outbuf);
size_t libpcapng_custom_data_block_size(const size_t data_len);
pcapng_custom_data_block_light_t *libpcapng_custom_data_block_read(unsigned char *inbuf, size_t inbuf_len);
uint32_t libpcapng_custom_data_block_start_offset(void);
uint32_t libpcapng_custom_data_block_data_length(uint32_t block_total_length);

#ifdef __cplusplus
}
#endif

#endif	/* _LIBPCAPNG_BLOCKS_H_ */
