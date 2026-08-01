package pcapng

/*
#include <stddef.h>
#include <stdlib.h>
#include <libpcapng/io.h>
#include "callbacks.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// BlockCallback is called for every block in a pcap/pcapng file.
//
// counter is a monotonically-increasing index (first block = 0).
// blockType identifies the block kind (use the BlockType* constants).
// data is a copy of the raw block bytes (including the 8-byte type+length header).
type BlockCallback func(counter, blockType uint32, data []byte)

// ReadFile reads every block from the pcap or pcapng file at path and calls
// cb for each one. Both legacy .pcap and .pcapng formats are supported.
func ReadFile(path string, cb BlockCallback) error {
	cs := C.CString(path)
	defer C.free(unsafe.Pointer(cs))

	h := cbStore(cb)
	defer cbDelete(h)

	rc := C.libpcapng_file_read(cs, C.foreach_pcapng_block_cb(C.cBlockCallback),
		unsafe.Pointer(h))
	if rc < 0 {
		return fmt.Errorf("pcapng: ReadFile(%q) failed (rc=%d)", path, rc)
	}
	return nil
}

// ReadMemory reads every block from the in-memory buffer buf and calls cb for
// each one.
func ReadMemory(buf []byte, cb BlockCallback) error {
	if len(buf) == 0 {
		return nil
	}
	h := cbStore(cb)
	defer cbDelete(h)

	rc := C.libpcapng_mem_read((*C.uchar)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)),
		C.foreach_pcapng_block_cb(C.cBlockCallback), unsafe.Pointer(h))
	if rc < 0 {
		return fmt.Errorf("pcapng: ReadMemory failed (rc=%d)", rc)
	}
	return nil
}
