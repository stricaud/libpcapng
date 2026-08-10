package pcapng

import "testing"

// The Go constants mirror pcapng_posa_ftype_t by hand, so a type added to the
// C header is invisible here until someone adds it. Check the four most
// recently added ones resolve and name themselves.
func TestPosaFieldTypeMirror(t *testing.T) {
	for _, c := range []struct {
		got  PosaFieldType
		want string
	}{
		{PosaQuicVarint, "quic_varint"},
		{PosaLEB128, "leb128"},
		{PosaUUID, "uuid"},
		{PosaLet, "let"},
		{PosaU24, "uint24"},
	} {
		if c.got.String() != c.want {
			t.Errorf("%d.String() = %q, want %q", c.got, c.got.String(), c.want)
		}
	}
}
