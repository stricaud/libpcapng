package pcapng

/*
#include <stdio.h>
#include <stdlib.h>
#include <libpcapng/easyapi.h>
*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"
)

// Writer writes packets to a pcapng file.
type Writer struct {
	fp   *C.FILE
	path string
}

// NewWriter creates or truncates path and writes a pcapng Section Header Block
// and Interface Description Block with link-type Ethernet.
func NewWriter(path string) (*Writer, error) {
	return NewWriterWithLinktype(path, uint16(LinktypeEthernet))
}

// NewWriterWithLinktype is like NewWriter but uses the given link-layer type.
func NewWriterWithLinktype(path string, linktype uint16) (*Writer, error) {
	cs := C.CString(path)
	defer C.free(unsafe.Pointer(cs))
	mode := C.CString("wb")
	defer C.free(unsafe.Pointer(mode))

	fp := C.fopen(cs, mode)
	if fp == nil {
		return nil, fmt.Errorf("pcapng: cannot open %q for writing: %w", path, os.ErrPermission)
	}
	if C.libpcapng_write_header_to_file_with_linktype(fp, C.uint16_t(linktype)) < 0 {
		C.fclose(fp)
		return nil, fmt.Errorf("pcapng: failed to write pcapng header to %q", path)
	}
	return &Writer{fp: fp, path: path}, nil
}

// WritePacket appends an Enhanced Packet Block for data with a zero timestamp.
func (w *Writer) WritePacket(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	rc := C.libpcapng_write_enhanced_packet_to_file(w.fp,
		(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	if rc < 0 {
		return fmt.Errorf("pcapng: WritePacket to %q failed", w.path)
	}
	return nil
}

// WritePacketWithTime appends an Enhanced Packet Block with the given
// Unix timestamp in seconds.
func (w *Writer) WritePacketWithTime(data []byte, timestamp uint32) error {
	if len(data) == 0 {
		return nil
	}
	rc := C.libpcapng_write_enhanced_packet_with_time_to_file(w.fp,
		(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)),
		C.uint32_t(timestamp))
	if rc < 0 {
		return fmt.Errorf("pcapng: WritePacketWithTime to %q failed", w.path)
	}
	return nil
}

// Close flushes and closes the underlying file.
func (w *Writer) Close() error {
	if w == nil || w.fp == nil {
		return nil
	}
	C.fclose(w.fp)
	w.fp = nil
	return nil
}
