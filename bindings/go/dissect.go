package pcapng

/*
#include <libpcapng/dissect.h>
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"
)

// FieldType mirrors pcapng_ftype_t.
type FieldType int

const (
	FieldTypeNone   FieldType = C.PCAPNG_FT_NONE
	FieldTypeUint   FieldType = C.PCAPNG_FT_UINT
	FieldTypeString FieldType = C.PCAPNG_FT_STR
	FieldTypeIPv4   FieldType = C.PCAPNG_FT_IPV4
	FieldTypeIPv6   FieldType = C.PCAPNG_FT_IPV6
	FieldTypeMAC    FieldType = C.PCAPNG_FT_MAC
	FieldTypeBytes  FieldType = C.PCAPNG_FT_BYTES
)

// Field is one node in a dissected packet's field tree.
type Field struct {
	Abbrev   string    // e.g. "ip.src", "tcp.dstport"
	Label    string    // human-readable label
	Type     FieldType
	Uint     uint64    // valid when Type == FieldTypeUint
	Str      string    // valid when Type is String / IPv4 / IPv6 / MAC
	Bytes    []byte    // raw bytes (first 16 for FieldTypeBytes; full for IPv6/MAC)
	Offset   int       // byte offset within the original packet
	Len      int       // byte length of this field
	Children []*Field
}

// Dissection is the result of dissecting one packet.
type Dissection struct {
	Root     *Field
	Protocol string // deepest recognised protocol name
	Src      string // source address summary
	Dst      string // destination address summary
	Info     string // one-line info column
}

// Dissect dissects data as a packet with the given link-layer type (use the
// Linktype* constants; LinktypeEthernet is the most common).
func Dissect(data []byte, linktype uint16) (*Dissection, error) {
	return DissectFull(data, uint32(len(data)), uint32(len(data)), linktype)
}

// DissectFull is like Dissect but lets you supply separate captured/original
// lengths for truncated packets.
func DissectFull(data []byte, caplen, origlen uint32, linktype uint16) (*Dissection, error) {
	if len(data) == 0 {
		return &Dissection{Root: &Field{}}, nil
	}
	cd := C.pcapng_dissect(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.uint32_t(caplen),
		C.uint32_t(origlen),
		C.uint16_t(linktype),
	)
	if cd == nil {
		return nil, nil
	}
	defer C.pcapng_dissection_free(cd)

	d := &Dissection{
		Protocol: C.GoString(&cd.proto[0]),
		Src:      C.GoString(&cd.src[0]),
		Dst:      C.GoString(&cd.dst[0]),
		Info:     C.GoString(&cd.info[0]),
	}
	if cd.root != nil {
		d.Root = convertField(cd.root)
	}
	return d, nil
}

// FindFields returns all fields in the dissection tree whose Abbrev matches.
func (d *Dissection) FindFields(abbrev string) []*Field {
	var results []*Field
	if d.Root != nil {
		walkFields(d.Root, abbrev, &results)
	}
	return results
}

func walkFields(f *Field, abbrev string, out *[]*Field) {
	if f.Abbrev == abbrev {
		*out = append(*out, f)
	}
	for _, c := range f.Children {
		walkFields(c, abbrev, out)
	}
}

// ResetFlows clears the sticky flow-classification table. Call before
// dissecting a new capture in file order so flows from the previous capture
// don't bleed across.
func ResetFlows() {
	C.pcapng_dissect_reset_flows()
}

// SetVerifyChecksums enables or disables IP/TCP/UDP checksum validation
// (disabled by default, like Wireshark).
func SetVerifyChecksums(on bool) {
	if on {
		C.pcapng_dissect_set_verify_checksums(1)
	} else {
		C.pcapng_dissect_set_verify_checksums(0)
	}
}

// convertField recursively converts a C pcapng_field_t tree into Go structs.
func convertField(cf *C.pcapng_field_t) *Field {
	if cf == nil {
		return nil
	}
	f := &Field{
		Abbrev: C.GoString(&cf.abbrev[0]),
		Label:  C.GoString(&cf.label[0]),
		Type:   FieldType(cf.vtype),
		Uint:   uint64(cf.u),
		Str:    C.GoString(&cf.str[0]),
		Offset: int(cf.off),
		Len:    int(cf.len),
	}
	blen := int(cf.blen)
	if blen > 0 {
		f.Bytes = C.GoBytes(unsafe.Pointer(&cf.bytes[0]), C.int(blen))
	}
	// Walk siblings (children of cf's parent are linked via next).
	for child := cf.children; child != nil; child = child.next {
		f.Children = append(f.Children, convertField(child))
	}
	return f
}
