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
//
// This is the call to use when more than one filter is involved, or when the
// dissection is wanted for its own sake as well: dissecting a packet costs
// microseconds and matching a compiled filter against the result costs
// nanoseconds, so a program with thirty filters should dissect once and match
// thirty times.
//
//	pcapng.EnsureProtocols()
//	d, _ := pcapng.Dissect(frame, pcapng.LinktypeEthernet)
//	if want.Match(d) { ... }
//
// A nil filter, or one compiled from an empty expression, matches everything.
// A nil dissection, or one whose Close has already been called, matches
// nothing — except against a match-all filter.
func (f *Filter) Match(d *Dissection) bool {
	if f == nil || f.cf == nil {
		return true
	}
	if C.pcapng_dfilter_is_match_all(f.cf) != 0 {
		return true
	}
	if d == nil || d.cd == nil || d.cd.root == nil {
		return false
	}
	return C.pcapng_dfilter_match(f.cf, d.cd.root) != 0
}

// MatchRaw dissects data and tests it against the filter in one step.
// linktype is a Linktype* constant.
//
// Convenient for a single filter over raw bytes. With more than one filter,
// prefer Dissect followed by Match: this dissects on every call.
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
	defer d.Close()
	return f.Match(d), nil
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
