package pcapng

/*
#include <stdlib.h>
#include <string.h>
#include <libpcapng/capture.h>
#include "callbacks.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

// Direction mirrors PCAPNG_CAP_DIR_*.
type Direction int

const (
	DirUnknown  Direction = C.PCAPNG_CAP_DIR_UNKNOWN
	DirInbound  Direction = C.PCAPNG_CAP_DIR_INBOUND
	DirOutbound Direction = C.PCAPNG_CAP_DIR_OUTBOUND
)

// PacketInfo holds the metadata and a copy of one captured packet's bytes.
// The bytes are safe to retain past the callback — they are a Go-owned copy.
type PacketInfo struct {
	Data        []byte
	CapturedLen uint32
	OriginalLen uint32
	TimestampNs uint64
	Direction   Direction
}

// PacketHandler is called for each packet delivered during Loop or Dispatch.
type PacketHandler func(*PacketInfo)

// CaptureStats holds packet counters from the kernel.
type CaptureStats struct {
	Received uint64
	Dropped  uint64
	Passed   uint64
	Filtered uint64
}

// Device describes one network interface visible to the capture engine.
type Device struct {
	Name        string
	Description string
	Loopback    bool
}

// ListDevices enumerates available network interfaces.
func ListDevices() ([]Device, error) {
	var errbuf [C.PCAPNG_CAPTURE_ERRBUF_SIZE]C.char
	var count C.int
	devs := C.pcapng_capture_list_devices(&count, &errbuf[0])
	if devs == nil {
		return nil, errors.New(C.GoString(&errbuf[0]))
	}
	defer C.pcapng_capture_free_devices(devs)

	result := make([]Device, int(count))
	for i := range result {
		d := (*C.pcapng_device_t)(unsafe.Pointer(uintptr(unsafe.Pointer(devs)) +
			uintptr(i)*C.sizeof_pcapng_device_t))
		result[i] = Device{
			Name:        C.GoString(&d.name[0]),
			Description: C.GoString(&d.description[0]),
			Loopback:    d.loopback != 0,
		}
	}
	return result, nil
}

// DefaultDevice returns the name of the first suitable non-loopback interface.
func DefaultDevice() (string, error) {
	var errbuf [C.PCAPNG_CAPTURE_ERRBUF_SIZE]C.char
	cs := C.pcapng_capture_default_device(&errbuf[0])
	if cs == nil {
		return "", errors.New(C.GoString(&errbuf[0]))
	}
	return C.GoString(cs), nil
}

// Capture is a live packet capture handle. Create one with Open, configure it
// with the Set* methods, start capture with Loop or Dispatch, and release
// resources with Close.
type Capture struct {
	cc *C.pcapng_capture_t
}

// Open creates a capture handle for device (e.g. "eth0", "en0").
func Open(device string) (*Capture, error) {
	var errbuf [C.PCAPNG_CAPTURE_ERRBUF_SIZE]C.char
	cs := C.CString(device)
	defer C.free(unsafe.Pointer(cs))

	cc := C.pcapng_capture_open(cs, &errbuf[0])
	if cc == nil {
		return nil, fmt.Errorf("pcapng: open %q: %s", device, C.GoString(&errbuf[0]))
	}
	return &Capture{cc: cc}, nil
}

// SetSnaplen sets the maximum bytes captured per packet (default 65535).
func (c *Capture) SetSnaplen(snaplen uint32) error {
	if C.pcapng_capture_set_snaplen(c.cc, C.uint32_t(snaplen)) < 0 {
		return errors.New("pcapng: SetSnaplen failed")
	}
	return nil
}

// SetPromisc enables or disables promiscuous mode (default: enabled).
func (c *Capture) SetPromisc(on bool) error {
	v := C.int(0)
	if on {
		v = 1
	}
	if C.pcapng_capture_set_promisc(c.cc, v) < 0 {
		return errors.New("pcapng: SetPromisc failed")
	}
	return nil
}

// SetTimeout sets the packet-delivery timeout in milliseconds (default 100).
func (c *Capture) SetTimeout(ms int) error {
	if C.pcapng_capture_set_timeout(c.cc, C.int(ms)) < 0 {
		return errors.New("pcapng: SetTimeout failed")
	}
	return nil
}

// SetBufferSize sets the total ring-buffer / read-buffer size in bytes (default 16 MiB).
func (c *Capture) SetBufferSize(bytes int) error {
	if C.pcapng_capture_set_buffer_size(c.cc, C.size_t(bytes)) < 0 {
		return errors.New("pcapng: SetBufferSize failed")
	}
	return nil
}

// SetFilter compiles and attaches a Wireshark-compatible display filter expression.
// An empty string removes any existing filter.
func (c *Capture) SetFilter(expr string) error {
	var errbuf [C.PCAPNG_CAPTURE_ERRBUF_SIZE]C.char
	cs := C.CString(expr)
	defer C.free(unsafe.Pointer(cs))

	if C.pcapng_capture_set_filter(c.cc, cs, &errbuf[0]) < 0 {
		return fmt.Errorf("pcapng: SetFilter: %s", C.GoString(&errbuf[0]))
	}
	return nil
}

// Loop captures packets and delivers them to fn until count packets have been
// delivered (count <= 0 = unlimited), Break is called, SIGINT is received, or
// a fatal error occurs. Returns the number of packets delivered.
func (c *Capture) Loop(count int, fn PacketHandler) (int, error) {
	h := cbStore(fn)
	defer cbDelete(h)

	n := C.pcapng_capture_loop(c.cc, C.int(count),
		C.pcapng_packet_cb(C.cPacketCallback), unsafe.Pointer(h))
	if n < 0 {
		return 0, errors.New("pcapng: Loop: capture error")
	}
	return int(n), nil
}

// Dispatch processes one batch of currently-available packets. count <= 0
// means "all available". Suitable for embedding in an event loop.
// Returns the number of packets processed (0 if none arrived).
func (c *Capture) Dispatch(count int, fn PacketHandler) (int, error) {
	h := cbStore(fn)
	defer cbDelete(h)

	n := C.pcapng_capture_dispatch(c.cc, C.int(count),
		C.pcapng_packet_cb(C.cPacketCallback), unsafe.Pointer(h))
	if n < 0 {
		return 0, errors.New("pcapng: Dispatch: capture error")
	}
	return int(n), nil
}

// Break signals the capture loop to stop cleanly. Safe to call from a goroutine.
func (c *Capture) Break() {
	C.pcapng_capture_break(c.cc)
}

// Stats returns packet counters from the kernel.
func (c *Capture) Stats() (CaptureStats, error) {
	var cs C.pcapng_capture_stats_t
	if C.pcapng_capture_get_stats(c.cc, &cs) < 0 {
		return CaptureStats{}, errors.New("pcapng: Stats failed")
	}
	return CaptureStats{
		Received: uint64(cs.received),
		Dropped:  uint64(cs.dropped),
		Passed:   uint64(cs.passed),
		Filtered: uint64(cs.filtered),
	}, nil
}

// Close releases the capture handle and all associated kernel resources.
func (c *Capture) Close() {
	if c != nil && c.cc != nil {
		C.pcapng_capture_close(c.cc)
		c.cc = nil
	}
}

// CaptureToFile is a convenience function that opens device, optionally
// applies filter (may be ""), and writes captured packets to path in pcapng
// format. count == 0 runs until SIGINT.
func CaptureToFile(device, path, filter string, count int) (int, error) {
	var errbuf [C.PCAPNG_CAPTURE_ERRBUF_SIZE]C.char
	cdev := C.CString(device)
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cdev))
	defer C.free(unsafe.Pointer(cpath))

	var cfilt *C.char
	if filter != "" {
		cfilt = C.CString(filter)
		defer C.free(unsafe.Pointer(cfilt))
	}

	n := C.pcapng_capture_to_file(cdev, cpath, cfilt, C.int(count), &errbuf[0])
	if n < 0 {
		return 0, fmt.Errorf("pcapng: CaptureToFile: %s", C.GoString(&errbuf[0]))
	}
	return int(n), nil
}
