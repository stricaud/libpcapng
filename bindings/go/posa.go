package pcapng

// posa — Go access to libpcapng's declarative decoders (.posa files).
//
// A .posa file describes a protocol (or a file format) as a sequence of typed
// fields; the engine turns bytes into the same field tree a hand-written C
// dissector produces. Two things are exposed here:
//
//   - the parsed *declaration* (PosaProto / PosaField), which is what a tool
//     needs to draw or document a format without any sample bytes, and
//   - PosaDissect, which runs a decoder over an arbitrary buffer and returns a
//     field tree whose nodes carry absolute offsets — so a hex view can colour
//     the exact bytes a field owns.
//
// See doc/posa.md for the language itself.

/*
#include <stdlib.h>
#include <string.h>
#include <libpcapng/posa.h>
#include <libpcapng/dissect.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

// PosaFieldType mirrors pcapng_posa_ftype_t: the declared type of a field, or
// one of the structural markers (scope/when/repeat/end) that carry nesting.
type PosaFieldType int

const (
	PosaU8          PosaFieldType = C.PCAPNG_POSA_U8
	PosaU16         PosaFieldType = C.PCAPNG_POSA_U16
	PosaU32         PosaFieldType = C.PCAPNG_POSA_U32
	PosaU64         PosaFieldType = C.PCAPNG_POSA_U64
	PosaLE16        PosaFieldType = C.PCAPNG_POSA_LE16
	PosaLE32        PosaFieldType = C.PCAPNG_POSA_LE32
	PosaLE64        PosaFieldType = C.PCAPNG_POSA_LE64
	PosaMAC         PosaFieldType = C.PCAPNG_POSA_MAC
	PosaIP4         PosaFieldType = C.PCAPNG_POSA_IP4
	PosaCString     PosaFieldType = C.PCAPNG_POSA_CSTRING
	PosaPayload     PosaFieldType = C.PCAPNG_POSA_PAYLOAD
	PosaBytesFixed  PosaFieldType = C.PCAPNG_POSA_BYTES_FIXED
	PosaStrFixed    PosaFieldType = C.PCAPNG_POSA_STR_FIXED
	PosaBytesRef    PosaFieldType = C.PCAPNG_POSA_BYTES_REF
	PosaStrDelim    PosaFieldType = C.PCAPNG_POSA_STR_DELIM
	PosaLayer       PosaFieldType = C.PCAPNG_POSA_LAYER
	PosaScope       PosaFieldType = C.PCAPNG_POSA_SCOPE
	PosaWhen        PosaFieldType = C.PCAPNG_POSA_WHEN
	PosaEnd         PosaFieldType = C.PCAPNG_POSA_END
	PosaIP6         PosaFieldType = C.PCAPNG_POSA_IP6
	PosaStrRef      PosaFieldType = C.PCAPNG_POSA_STR_REF
	PosaDNSName     PosaFieldType = C.PCAPNG_POSA_DNSNAME
	PosaRepeat      PosaFieldType = C.PCAPNG_POSA_REPEAT
	PosaBits        PosaFieldType = C.PCAPNG_POSA_BITS
	PosaLabel       PosaFieldType = C.PCAPNG_POSA_LABEL
	PosaU24         PosaFieldType = C.PCAPNG_POSA_U24
	PosaUTF16       PosaFieldType = C.PCAPNG_POSA_UTF16
	PosaSeek        PosaFieldType = C.PCAPNG_POSA_SEEK
	PosaElse        PosaFieldType = C.PCAPNG_POSA_ELSE
	PosaKVBlock     PosaFieldType = C.PCAPNG_POSA_KVBLOCK
)

// String gives the .posa keyword a field type is written with.
func (t PosaFieldType) String() string {
	switch t {
	case PosaU8:
		return "uint8"
	case PosaU16:
		return "uint16"
	case PosaU24:
		return "uint24"
	case PosaU32:
		return "uint32"
	case PosaU64:
		return "uint64"
	case PosaLE16:
		return "le_uint16"
	case PosaLE32:
		return "le_uint32"
	case PosaLE64:
		return "le_uint64"
	case PosaMAC:
		return "mac"
	case PosaIP4:
		return "ip4"
	case PosaIP6:
		return "ip6"
	case PosaCString:
		return "cstring"
	case PosaPayload:
		return "payload"
	case PosaBytesFixed:
		return "bytes"
	case PosaStrFixed:
		return "str"
	case PosaBytesRef:
		return "bytes[]"
	case PosaStrRef:
		return "str[]"
	case PosaUTF16:
		return "utf16[]"
	case PosaStrDelim:
		return "string"
	case PosaDNSName:
		return "dnsname"
	case PosaKVBlock:
		return "kvblock"
	case PosaLayer:
		return "layer"
	case PosaScope:
		return "scope"
	case PosaWhen:
		return "when"
	case PosaElse:
		return "else"
	case PosaRepeat:
		return "repeat"
	case PosaBits:
		return "bits"
	case PosaLabel:
		return "label"
	case PosaSeek:
		return "seek"
	case PosaEnd:
		return "end"
	}
	return "?"
}

// FixedSize is the number of bytes a field of this type always consumes, and
// ok=false for the types whose length is only known at decode time
// (payload, cstring, bytes[len], delimited strings, …) or that consume nothing
// (bits, label, and the structural markers).
func (t PosaFieldType) FixedSize() (n int, ok bool) {
	switch t {
	case PosaU8:
		return 1, true
	case PosaU16, PosaLE16:
		return 2, true
	case PosaU24:
		return 3, true
	case PosaU32, PosaLE32, PosaIP4:
		return 4, true
	case PosaU64, PosaLE64:
		return 8, true
	case PosaMAC:
		return 6, true
	case PosaIP6:
		return 16, true
	}
	return 0, false
}

// Structural reports whether the field is a block marker rather than data:
// scope/when/else/repeat open a block, end closes one.
func (t PosaFieldType) Structural() bool {
	switch t {
	case PosaScope, PosaWhen, PosaElse, PosaRepeat, PosaEnd:
		return true
	}
	return false
}

// PosaCmp mirrors pcapng_posa_cmp_t, the comparison of a `when` guard.
type PosaCmp int

const (
	PosaCmpNone PosaCmp = C.PCAPNG_POSA_CMP_NONE
	PosaCmpEQ   PosaCmp = C.PCAPNG_POSA_CMP_EQ
	PosaCmpNE   PosaCmp = C.PCAPNG_POSA_CMP_NE
	PosaCmpLT   PosaCmp = C.PCAPNG_POSA_CMP_LT
	PosaCmpGT   PosaCmp = C.PCAPNG_POSA_CMP_GT
	PosaCmpGE   PosaCmp = C.PCAPNG_POSA_CMP_GE
	PosaCmpLE   PosaCmp = C.PCAPNG_POSA_CMP_LE
)

// String gives the operator as it is written in a .posa file.
func (c PosaCmp) String() string {
	switch c {
	case PosaCmpEQ:
		return "=="
	case PosaCmpNE:
		return "!="
	case PosaCmpLT:
		return "<"
	case PosaCmpGT:
		return ">"
	case PosaCmpGE:
		return ">="
	case PosaCmpLE:
		return "<="
	}
	return ""
}

// PosaEnum is one `NAME = value` line under a field. Key is set instead of Val
// for string-keyed enums (`"404" = "Not Found"`).
type PosaEnum struct {
	Name string
	Val  uint64
	Key  string
}

// PosaGuard is the condition of a `when <lhs> [& mask] <op> <rhs>:` block.
// Op == PosaCmpNone means the block is unconditional.
type PosaGuard struct {
	Op   PosaCmp
	LHS  string // a field name, or "remaining"
	Mask uint64 // 0: no mask
	RHS  uint64
}

// PosaField is one declared line of a decoder: a data field, or a structural
// marker whose Type reports which block it opens or closes.
type PosaField struct {
	Name     string
	Type     PosaFieldType
	Default  uint64 // `= N`; also the dispatch magic on a group member's first field
	NBytes   int    // bytes<N> / str<N>
	LenField string // bytes[len]/str[len]/utf16[len]; on repeat, the count field
	Delim    string // `until "…"`, and the kvblock end sentinel
	Sub      string // layer: sub-protocol name; kvblock: key/value separator
	Enums    []PosaEnum
	Guard    PosaGuard
	ScopeLen int    // >= 0: index of the field bounding this scope
	Display  string // the "Label" shown in the tree; also a label/info format
	Mask     uint64 // `mask 0x7fff`
	Hex      bool   // `hex`
	Src      string // bits: the field the value is carved out of
	Shift    int    // bits: shift
	Width    int    // bits: width
	UntilEnd bool   // repeat until end
	Args     []string
}

// Size is the byte width of a fixed-size field (bytes<N>/str<N> included), and
// ok=false when the length depends on the data.
func (f *PosaField) Size() (n int, ok bool) {
	switch f.Type {
	case PosaBytesFixed, PosaStrFixed:
		return f.NBytes, true
	}
	return f.Type.FixedSize()
}

// PosaProto is a decoder as declared by one `Object<…> NAME` block.
type PosaProto struct {
	Name      string
	Parent    string // Object<parent>; "" (or "main") at top level
	Display   string // col "…" — the Protocol column
	Abbrev    string // abbrev "…" — the field-name prefix
	Fields    []PosaField
	InfoFmt   string
	InfoArgs  []string
	IsDefault bool     // the group member used when no magic matched
	Prefixes  []string // `starts "GET " "POST "` — content dispatch
}

// PosaLoadFile loads the .posa definitions in path into the global registry,
// returning how many protocols it added. Redefining a protocol replaces it.
func PosaLoadFile(path string) (int, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var errbuf [256]C.char
	n := C.pcapng_posa_load_file(cpath, &errbuf[0], C.size_t(len(errbuf)))
	if n < 0 {
		msg := C.GoString(&errbuf[0])
		if msg == "" {
			msg = "cannot load " + path
		}
		return 0, errors.New(msg)
	}
	return int(n), nil
}

// PosaLoadDir loads every .posa file in dir, returning the number added.
func PosaLoadDir(dir string) int {
	cdir := C.CString(dir)
	defer C.free(unsafe.Pointer(cdir))
	return int(C.pcapng_posa_load_dir(cdir))
}

// PosaLoadText parses decoders from a string, as if it were a .posa file.
func PosaLoadText(src string) (int, error) {
	csrc := C.CString(src)
	defer C.free(unsafe.Pointer(csrc))
	var errbuf [256]C.char
	n := C.pcapng_posa_load_text(csrc, &errbuf[0], C.size_t(len(errbuf)))
	if n < 0 {
		msg := C.GoString(&errbuf[0])
		if msg == "" {
			msg = "cannot parse posa source"
		}
		return 0, errors.New(msg)
	}
	return int(n), nil
}

// PosaClear empties the registry.
func PosaClear() { C.pcapng_posa_clear() }

// PosaCount is the number of loaded decoders.
func PosaCount() int { return int(C.pcapng_posa_count()) }

// PosaAt returns the decoder at index, or nil when index is out of range.
func PosaAt(index int) *PosaProto {
	return convPosaProto(C.pcapng_posa_at(C.int(index)))
}

// PosaFind returns the decoder with this name, or nil.
func PosaFind(name string) *PosaProto {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	return convPosaProto(C.pcapng_posa_find(cname))
}

// PosaProtos returns every loaded decoder, in registry order.
func PosaProtos() []*PosaProto {
	n := PosaCount()
	out := make([]*PosaProto, 0, n)
	for i := 0; i < n; i++ {
		if p := PosaAt(i); p != nil {
			out = append(out, p)
		}
	}
	return out
}

// PosaResolve maps a name to a concrete decoder — following an Object<group>
// to the member whose magic matches data. Returns nil if neither applies.
func PosaResolve(name string, data []byte) *PosaProto {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var p *C.uint8_t
	if len(data) > 0 {
		p = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	return convPosaProto(C.pcapng_posa_resolve(cname, p, C.int(len(data))))
}

// PosaSource is the exact text a decoder was parsed from ("" when it was built
// without one, e.g. from PosaLoadText on a stripped buffer).
func PosaSource(name string) string {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	return C.GoString(C.pcapng_posa_source(cname))
}

// PosaDissection is the result of running a decoder over a buffer.
type PosaDissection struct {
	Fields   []*Field // top-level fields, in wire order
	Info     string   // the decoder's info "…" line
	Col      string   // the innermost col "…" reached
	Consumed int      // bytes the decoder consumed
}

// PosaDissect decodes data with the named decoder. absOff is added to every
// field offset, so a payload dissected out of a larger buffer reports offsets
// in that buffer's terms. It returns nil when the decoder is unknown or
// nothing decoded.
func PosaDissect(proto string, data []byte, absOff int) *PosaDissection {
	cproto := C.CString(proto)
	defer C.free(unsafe.Pointer(cproto))

	root := (*C.pcapng_field_t)(C.calloc(1, C.sizeof_pcapng_field_t))
	if root == nil {
		return nil
	}
	defer C.pcapng_field_free(root)

	var dp *C.uint8_t
	if len(data) > 0 {
		dp = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}
	var info [192]C.char
	C.pcapng_posa_reset_col()
	consumed := C.pcapng_posa_dissect(cproto, dp, C.int(len(data)), root,
		C.int(absOff), &info[0], C.size_t(len(info)))

	var fields []*Field
	for c := root.children; c != nil; c = c.next {
		fields = append(fields, convertField(c))
	}
	if consumed <= 0 && len(fields) == 0 {
		return nil
	}
	return &PosaDissection{
		Fields:   fields,
		Info:     C.GoString(&info[0]),
		Col:      C.GoString(C.pcapng_posa_last_col()),
		Consumed: int(consumed),
	}
}

// PosaBoundPort returns the decoder claimed by a `rule <proto>.port == N` line
// for this transport (6 TCP, 17 UDP) and port, or "".
func PosaBoundPort(ipProto int, port uint16) string {
	return C.GoString(C.pcapng_posa_bound_port(C.int(ipProto), C.uint16_t(port)))
}

// PosaBoundIPProto returns the decoder claimed by `rule ip.proto == N`, or "".
func PosaBoundIPProto(num int) string {
	return C.GoString(C.pcapng_posa_bound_ipproto(C.int(num)))
}

// PosaBoundEthertype returns the decoder claimed by `rule eth.type == N`, or "".
func PosaBoundEthertype(et uint16) string {
	return C.GoString(C.pcapng_posa_bound_ethertype(C.uint16_t(et)))
}

// PosaColor is one `color <display filter> => <fg> <bg>` declaration. The names
// stay opaque: libpcapng has no display of its own, so the front end decides
// what "lightcyan" means.
type PosaColor struct {
	Expr string
	FG   string
	BG   string
}

// PosaColors returns the coloring rules declared by the loaded decoders.
func PosaColors() []PosaColor {
	n := int(C.pcapng_posa_color_count())
	out := make([]PosaColor, 0, n)
	for i := 0; i < n; i++ {
		var expr, fg, bg *C.char
		if C.pcapng_posa_color_get(C.int(i), &expr, &fg, &bg) != 0 {
			out = append(out, PosaColor{C.GoString(expr), C.GoString(fg), C.GoString(bg)})
		}
	}
	return out
}

// ── C → Go conversion ───────────────────────────────────────────────────────

// cstr copies a NUL-terminated C char array given its first element.
func cstr(p *C.char) string { return C.GoString(p) }

func convPosaProto(cp *C.pcapng_posa_proto_t) *PosaProto {
	if cp == nil {
		return nil
	}
	p := &PosaProto{
		Name:      cstr(&cp.name[0]),
		Parent:    cstr(&cp.parent[0]),
		Display:   cstr(&cp.display[0]),
		Abbrev:    cstr(&cp.abbrev[0]),
		InfoFmt:   cstr(&cp.info_fmt[0]),
		IsDefault: cp.is_default != 0,
	}
	for i := 0; i < int(cp.info_nargs); i++ {
		p.InfoArgs = append(p.InfoArgs, cstr(&cp.info_args[i][0]))
	}
	for i := 0; i < int(cp.nprefix); i++ {
		// `starts "\xc0"` may hold NUL bytes: take the recorded length, not the
		// C string.
		p.Prefixes = append(p.Prefixes,
			C.GoStringN(&cp.prefixes[i][0], C.int(cp.prefix_len[i])))
	}
	n := int(cp.nflds)
	p.Fields = make([]PosaField, 0, n)
	for i := 0; i < n; i++ {
		p.Fields = append(p.Fields, convPosaField(&cp.flds[i]))
	}
	return p
}

func convPosaField(cf *C.pcapng_posa_fld_t) PosaField {
	f := PosaField{
		Name:     cstr(&cf.name[0]),
		Type:     PosaFieldType(cf._type),
		Default:  uint64(cf.defnum),
		NBytes:   int(cf.nbytes),
		LenField: cstr(&cf.lenfield[0]),
		Sub:      cstr(&cf.sub[0]),
		ScopeLen: int(cf.scope_len_field),
		Display:  cstr(&cf.disp[0]),
		Mask:     uint64(cf.mask),
		Hex:      cf.hex != 0,
		Src:      cstr(&cf.src[0]),
		Shift:    int(cf.shift),
		Width:    int(cf.width),
		UntilEnd: cf.until_end != 0,
		Guard: PosaGuard{
			Op:   PosaCmp(cf.guard.op),
			LHS:  cstr(&cf.guard.lhs[0]),
			Mask: uint64(cf.guard.mask),
			RHS:  uint64(cf.guard.rhs),
		},
	}
	if nd := int(cf.ndelim); nd > 0 {
		f.Delim = C.GoStringN(&cf.delim[0], C.int(nd))
	}
	for i := 0; i < int(cf.nenums); i++ {
		f.Enums = append(f.Enums, PosaEnum{
			Name: cstr(&cf.enums[i].name[0]),
			Val:  uint64(cf.enums[i].val),
			Key:  cstr(&cf.enums[i].key[0]),
		})
	}
	for i := 0; i < int(cf.nlargs); i++ {
		f.Args = append(f.Args, cstr(&cf.largs[i][0]))
	}
	return f
}
