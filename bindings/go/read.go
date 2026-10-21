package pcapng

/*
#include <stdlib.h>
#include <stdint.h>
#include <libpcapng/reader.h>
#include <libpcapng/dissect.h>
#include "callbacks.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Packet is one packet from a capture file, as ReadPackets delivers it.
//
// This is the layer that was missing. ReadFile hands back raw *blocks* —
// including the 8-byte block header — which leaves the caller to work out
// where the frame starts inside an Enhanced Packet Block, to find the
// link-layer type by tracking Interface Description Blocks, and to scale the
// timestamp by the interface's declared resolution. That arithmetic is the
// library's job, and getting it wrong is quiet: dissecting from four bytes
// off produces a confident, wrong answer rather than an error.
type Packet struct {
	// Index is the 1-based position among the packets (not among blocks).
	Index uint64
	// Data is the frame itself, copied: the C buffer is valid only for the
	// duration of the callback.
	Data []byte
	// CapturedLen is len(Data); OriginalLen is the length on the wire, which
	// is larger when the capture used a snaplen.
	CapturedLen uint32
	OriginalLen uint32
	// InterfaceID is which IDB this packet belongs to, and Linktype is that
	// interface's link-layer type — already resolved, so it can be passed
	// straight to Dissect.
	InterfaceID uint32
	Linktype    uint16
	// TimestampNs is nanoseconds since the UNIX epoch, already scaled by the
	// interface's if_tsresol. HasTimestamp is false for a Simple Packet
	// Block, which carries none; TimestampNs is then 0 rather than a guess.
	TimestampNs  uint64
	HasTimestamp bool
	BlockType    uint32
}

// Truncated reports whether the capture kept less than the wire length.
func (p *Packet) Truncated() bool { return p.CapturedLen < p.OriginalLen }

// PacketCallback is called once per packet. Return false to stop reading.
type PacketCallback func(pkt *Packet) bool

// ReadPackets reads every packet from a pcap or pcapng file, calling cb for
// each. It returns how many were delivered.
//
//	pcapng.EnsureProtocols()
//	n, err := pcapng.ReadPackets("capture.pcapng", func(p *pcapng.Packet) bool {
//	    d, _ := pcapng.Dissect(p.Data, p.Linktype)
//	    fmt.Println(d.Protocol, d.Src, "->", d.Dst, d.Info)
//	    return true
//	})
//
// Both legacy .pcap and .pcapng are supported; the format is detected.
func ReadPackets(path string, cb PacketCallback) (int64, error) {
	cs := C.CString(path)
	defer C.free(unsafe.Pointer(cs))

	h := cbStore(cb)
	defer cbDelete(h)

	n := C.pcapng_read_packets(cs,
		C.pcapng_read_packet_cb(C.cReadPacketCallback),
		C.cHandleToPtr(C.uintptr_t(h)))
	if n < 0 {
		return 0, fmt.Errorf("pcapng: ReadPackets(%q) failed (rc=%d)", path, int64(n))
	}
	return int64(n), nil
}

// EnsureProtocols loads the bundled protocol decoders.
//
// Most of libpcapng's protocol support is POSA definitions compiled into the
// library, held in a registry populated on demand. Until this is called,
// Dissect reports only what the built-in C dissectors recognise — a bare
// `tcp` where there was an HTTP request — and a filter naming a field such as
// http.uri matches nothing, because that field does not exist yet.
//
// Call it once at startup, before dissecting and before compiling a filter.
// It is idempotent.
func EnsureProtocols() {
	C.pcapng_dissect_ensure_protocols()
}
