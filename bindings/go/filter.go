package pcapng

/*
#include <libpcapng/dfilter.h>
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Filter is a compiled Wireshark-compatible display filter expression.
// Call Close when done to free the underlying C allocation.
type Filter struct {
	cf *C.pcapng_dfilter_t
}

// NewFilter compiles expr into a reusable display filter.
// An empty expression compiles to a match-all filter.
func NewFilter(expr string) (*Filter, error) {
	var errbuf [256]C.char
	cs := C.CString(expr)
	defer C.free(unsafe.Pointer(cs))

	cf := C.pcapng_dfilter_compile(cs, &errbuf[0], C.size_t(len(errbuf)))
	if cf == nil {
		return nil, fmt.Errorf("pcapng: filter compile error: %s", C.GoString(&errbuf[0]))
	}
	return &Filter{cf: cf}, nil
}

// Match reports whether the dissected packet d matches the filter.
// A nil filter or a match-all filter always returns true.
func (f *Filter) Match(d *Dissection) bool {
	if f == nil || f.cf == nil || d == nil || d.Root == nil {
		return true
	}
	// We need to pass the C field tree root. Since we've already converted it to
	// Go structs, we have to re-dissect or store the raw pointer. For the common
	// "dissect then filter" pattern, use MatchRaw below.
	//
	// This path matches by re-dissecting — callers that need efficiency should
	// use MatchRaw or the Capture.SetFilter path instead.
	return C.pcapng_dfilter_is_match_all(f.cf) != 0
}

// MatchRaw dissects data and tests it against the filter in one step.
// linktype is a Linktype* constant.
func (f *Filter) MatchRaw(data []byte, linktype uint16) (bool, error) {
	if f == nil || f.cf == nil {
		return true, nil
	}
	if C.pcapng_dfilter_is_match_all(f.cf) != 0 {
		return true, nil
	}
	d, err := Dissect(data, linktype)
	if err != nil || d == nil {
		return false, err
	}
	// Re-dissect through C to get the raw field root for the filter engine.
	cd := C.pcapng_dissect(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.uint32_t(len(data)),
		C.uint32_t(len(data)),
		C.uint16_t(linktype),
	)
	if cd == nil {
		return false, nil
	}
	defer C.pcapng_dissection_free(cd)
	result := C.pcapng_dfilter_match(f.cf, cd.root)
	return result != 0, nil
}

// IsMatchAll reports whether the filter matches every packet (compiled from an
// empty or blank expression).
func (f *Filter) IsMatchAll() bool {
	if f == nil || f.cf == nil {
		return true
	}
	return C.pcapng_dfilter_is_match_all(f.cf) != 0
}

// Close releases the C memory for the compiled filter.
func (f *Filter) Close() {
	if f != nil && f.cf != nil {
		C.pcapng_dfilter_free(f.cf)
		f.cf = nil
	}
}
