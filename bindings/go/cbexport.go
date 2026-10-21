package pcapng

// This file contains ONLY //export functions. CGo requires that a file using
// //export not define C functions in its preamble, so all CGo types are
// accessed via the separate pcapng.go preamble.

/*
#include <stdint.h>
#include <libpcapng/capture.h>
#include <libpcapng/reader.h>
*/
import "C"
import "unsafe"

//export goBlockCallback
func goBlockCallback(handle C.uintptr_t, counter C.uint32_t, blockType C.uint32_t,
	blockLen C.uint32_t, data *C.uchar) {
	fn := cbLoad(uintptr(handle))
	if fn == nil {
		return
	}
	// ReadFile stores a BlockCallback, which is a *named* type: asserting the
	// unnamed `func(uint32, uint32, []byte)` never matched and panicked on
	// the first block of every file. Both spellings are accepted so a caller
	// passing a bare function literal works too.
	var cb BlockCallback
	switch f := fn.(type) {
	case BlockCallback:
		cb = f
	case func(counter, blockType uint32, data []byte):
		cb = f
	default:
		return
	}
	// Copy the block bytes — the C pointer is only valid during this call.
	cb(uint32(counter), uint32(blockType),
		C.GoBytes(unsafe.Pointer(data), C.int(blockLen)))
}

//export goPacketCallback
func goPacketCallback(handle C.uintptr_t, pkt *C.pcapng_packet_info_t) {
	fn := cbLoad(uintptr(handle))
	if fn == nil {
		return
	}
	cb := fn.(PacketHandler)
	info := &PacketInfo{
		// Zero-copy from the kernel ring buffer — the C contract says the pointer
		// is valid only for the duration of this callback, so we must copy.
		Data:        C.GoBytes(unsafe.Pointer(pkt.data), C.int(pkt.captured_len)),
		CapturedLen: uint32(pkt.captured_len),
		OriginalLen: uint32(pkt.original_len),
		TimestampNs: uint64(pkt.timestamp_ns),
		Direction:   Direction(pkt.direction),
	}
	cb(info)
}

//export goReadPacketCallback
func goReadPacketCallback(handle C.uintptr_t, pkt *C.pcapng_packet_t) C.int {
	fn := cbLoad(uintptr(handle))
	if fn == nil {
		return 0
	}
	var cb PacketCallback
	switch f := fn.(type) {
	case PacketCallback:
		cb = f
	case func(*Packet) bool:
		cb = f
	default:
		return 0
	}
	p := &Packet{
		Index: uint64(pkt.index),
		// Copied: the C contract says the pointer is good for this call only.
		Data:         C.GoBytes(unsafe.Pointer(pkt.data), C.int(pkt.captured_len)),
		CapturedLen:  uint32(pkt.captured_len),
		OriginalLen:  uint32(pkt.original_len),
		InterfaceID:  uint32(pkt.interface_id),
		Linktype:     uint16(pkt.linktype),
		TimestampNs:  uint64(pkt.timestamp_ns),
		HasTimestamp: pkt.has_timestamp != 0,
		BlockType:    uint32(pkt.block_type),
	}
	if !cb(p) {
		return 1 // stop reading
	}
	return 0
}
