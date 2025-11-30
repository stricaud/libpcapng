/*
 * License MIT
 * Copyright (c) 2021 Devo Inc.
 * Copyright (c) 2022 Sebastien Tricaud
 */
#ifndef _LIBPCAPNG_H_
#define _LIBPCAPNG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define SWAP32(x) ((((x) & 0x000000ff) << 24) | (((x) & 0x0000ff00) << 8) | (((x) & 0x00ff0000) >>  8) | (((x) & 0xff000000) >> 24))
#define PADDING(x, aligned_ptr, size) do {\
		*aligned_ptr = (x % size) == 0 ? x : (x / size + 1) * size; \
	} while(0)

#define PCAPNG_VERSION_MAJOR 1
#define PCAPNG_VERSION_MINOR 0

#define PCAPNG_BYTE_ORDER_MAGIC 0x1A2B3C4D

#include "blocks.h"
#include "easyapi.h"
#include "io.h"
#include "linktypes.h"

#include "protocols/ethernet.h"
#include "protocols/ipv4.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/dns.h"
#include "protocols/icmp.h"
  
#ifdef __cplusplus
}
#endif

#endif // _LIBPCAPNG_H_
