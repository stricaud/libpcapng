#pragma once
#include <stdint.h>
#include <libpcapng/io.h>
#include <libpcapng/capture.h>

/* C trampolines that call into Go. The Go //export functions are defined in
   cbexport.go and registered via the same uintptr handle passed as userdata. */

int  cBlockCallback(uint32_t counter, uint32_t block_type, uint32_t block_total_length,
                    unsigned char *data, void *userdata);

void cPacketCallback(const pcapng_packet_info_t *pkt, void *userdata);
