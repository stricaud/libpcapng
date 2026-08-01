// Package pcapng provides Go bindings for libpcapng: a fast pcap/pcapng
// reader/writer with a built-in packet dissector and display-filter engine.
//
// CGo notes: all exported types that wrap a C pointer have a Close() or Free()
// method that must be called to release the underlying C memory.
package pcapng

/*
#cgo CFLAGS: -I${SRCDIR}/vendor/include -DNDEBUG
#cgo linux LDFLAGS: -lm
#cgo darwin LDFLAGS: -lresolv -lm
#cgo windows LDFLAGS: -lws2_32

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <libpcapng/libpcapng.h>
#include "callbacks.h"
*/
import "C"

// Block type constants — values that appear in the block_type field of raw
// pcapng blocks delivered to a BlockCallback.
const (
	BlockTypeSectionHeader         = C.PCAPNG_SECTION_HEADER_BLOCK
	BlockTypeInterfaceDescription  = C.PCAPNG_INTERFACE_DESCRIPTION_BLOCK
	BlockTypeEnhancedPacket        = C.PCAPNG_ENHANCED_PACKET_BLOCK
	BlockTypeSimplePacket          = C.PCAPNG_SIMPLE_PACKET_BLOCK
	BlockTypeNameResolution        = C.PCAPNG_NAME_RESOLUTION_BLOCK
	BlockTypeInterfaceStatistics   = C.PCAPNG_INTERFACE_STATISTICS_BLOCK
	BlockTypeDecryptionSecrets     = C.PCAPNG_DECRYPTION_SECRETS_BLOCK
)

// Link-layer type constants passed to Dissect.
const (
	LinktypeNull      = C.PCAPNG_LINKTYPE_NULL
	LinktypeEthernet  = C.PCAPNG_LINKTYPE_ETHERNET
	LinktypeRaw       = C.PCAPNG_LINKTYPE_RAW
	LinktypeLinuxSLL  = C.PCAPNG_LINKTYPE_LINUX_SLL
	LinktypeIPv4      = C.PCAPNG_LINKTYPE_IPV4
	LinktypeIPv6      = C.PCAPNG_LINKTYPE_IPV6
)
