/*
 * wire_layout.c — compile-time guards on the on-the-wire struct layouts.
 *
 * These structs are overlaid directly on captured bytes, so their packing is
 * part of the format, not an optimisation. GCC/Clang get it from
 * __attribute__((packed)); MSVC from #pragma pack (see packed.h). If either
 * mechanism ever fails to apply, the compiler silently pads the struct and
 * every field past the first misaligned member reads the wrong offset —
 * corrupting dissection rather than failing.
 *
 * So we assert every size here. A build where packing did not take effect stops
 * with an error instead of shipping a subtly wrong dissector. The expected
 * values are the format's own byte counts (Ethernet is 14 bytes on the wire,
 * an X.224 connection-confirm PDU is 7, ...), not whatever a given compiler
 * happens to produce.
 *
 * Portable static assert: a negative-sized array is a hard error everywhere,
 * and unlike _Static_assert it needs no C11 mode from MSVC.
 */
/* The public headers expect the includer to have pulled these in already. */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include <libpcapng/libpcapng.h>
#include <libpcapng/blocks.h>
#include <libpcapng/protocols/rdp.h>
#include <libpcapng/protocols/bootp.h>

#define PCAPNG_ASSERT_SIZE(type, want) \
    typedef char pcapng_wire_size_##type[(sizeof(struct type) == (want)) ? 1 : -1]

PCAPNG_ASSERT_SIZE(_pcapng_custom_data_block_light_t, 4);
PCAPNG_ASSERT_SIZE(_pcapng_custom_data_block_t, 12);
PCAPNG_ASSERT_SIZE(_pcapng_decryption_secrets_block_t, 16);
PCAPNG_ASSERT_SIZE(_pcapng_enhanced_packet_block_light_t, 20);
PCAPNG_ASSERT_SIZE(_pcapng_enhanced_packet_block_t, 28);
PCAPNG_ASSERT_SIZE(_pcapng_interface_description_block_light_t, 8);
PCAPNG_ASSERT_SIZE(_pcapng_interface_description_block_t, 16);
PCAPNG_ASSERT_SIZE(_pcapng_interface_statistics_block_t, 20);
PCAPNG_ASSERT_SIZE(_pcapng_name_resolution_block_t, 8);
PCAPNG_ASSERT_SIZE(_pcapng_nrb_record_t, 4);
PCAPNG_ASSERT_SIZE(_pcapng_section_header_block_light_t, 16);
PCAPNG_ASSERT_SIZE(_pcapng_section_header_block_t, 24);
PCAPNG_ASSERT_SIZE(_pcapng_simple_packet_block_t, 12);
PCAPNG_ASSERT_SIZE(libpcapng_bootp_hdr, 236);
PCAPNG_ASSERT_SIZE(libpcapng_dns_hdr, 12);
PCAPNG_ASSERT_SIZE(libpcapng_eth_hdr, 14);
PCAPNG_ASSERT_SIZE(libpcapng_icmp_hdr, 8);
PCAPNG_ASSERT_SIZE(libpcapng_ipv4_hdr, 20);
PCAPNG_ASSERT_SIZE(libpcapng_ntp_hdr, 48);
PCAPNG_ASSERT_SIZE(libpcapng_rdp_neg_req, 8);
PCAPNG_ASSERT_SIZE(libpcapng_rdp_neg_rsp, 8);
PCAPNG_ASSERT_SIZE(libpcapng_tpkt_hdr, 4);
PCAPNG_ASSERT_SIZE(libpcapng_udp_hdr, 8);
PCAPNG_ASSERT_SIZE(libpcapng_x224_cc_hdr, 7);
PCAPNG_ASSERT_SIZE(libpcapng_x224_cr_hdr, 7);
PCAPNG_ASSERT_SIZE(libpcapng_x224_dt_hdr, 3);
