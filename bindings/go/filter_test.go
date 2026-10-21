package pcapng

// Filter.Match, and the bug it had.
//
// Match used to ignore its argument and return pcapng_dfilter_is_match_all(),
// which means every filter with anything in it returned false, on every
// packet, for ever. Nothing errored; a program using it simply saw no traffic.
// The fix was to keep the C field tree alive behind the Dissection so the
// filter engine has a tree to walk, which is also what makes "dissect once,
// match many" true rather than aspirational.
//
// So the test that matters is a filter that must match and a filter that must
// not, through Match, against one dissection.

import "testing"

func TestFilterMatchUsesTheDissection(t *testing.T) {
	EnsureProtocols()

	d, err := Dissect(httpFrame(), LinktypeEthernet)
	if err != nil || d == nil {
		t.Fatalf("Dissect: %v", err)
	}
	defer d.Close()

	for _, tc := range []struct {
		expr string
		want bool
	}{
		{`http.uri == "/index.html"`, true},
		{`http.uri contains "/index"`, true},
		{`http.method == "GET"`, true},
		{`tcp.dstport == 80`, true},
		{`ip.src == 203.0.113.0/24`, true},
		{`http and not ip.src == 10.0.0.0/8`, true},
		{`http.uri == "/admin"`, false},
		{`tcp.dstport == 443`, false},
		{`dns`, false},
		{`ip.src == 10.0.0.0/8`, false},
	} {
		f, err := NewFilter(tc.expr)
		if err != nil {
			t.Errorf("NewFilter(%q): %v", tc.expr, err)
			continue
		}
		if got := f.Match(d); got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.expr, got, tc.want)
		}
		// The same answer the slow way, as a cross-check.
		if got, err := f.MatchRaw(httpFrame(), LinktypeEthernet); err != nil || got != tc.want {
			t.Errorf("MatchRaw(%q) = %v, %v; want %v", tc.expr, got, err, tc.want)
		}
		f.Close()
	}
}

func TestFilterMatchAll(t *testing.T) {
	d, err := Dissect(httpFrame(), LinktypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	f, err := NewFilter("")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if !f.IsMatchAll() {
		t.Error("an empty expression does not report itself as match-all")
	}
	if !f.Match(d) {
		t.Error("a match-all filter did not match")
	}
	if !f.Match(nil) {
		t.Error("a match-all filter should match even a nil dissection")
	}

	real, err := NewFilter("tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer real.Close()
	if real.IsMatchAll() {
		t.Error("a real filter claims to match everything")
	}
	// A packet that is not there matches nothing, rather than everything —
	// the old behaviour of returning true for a nil dissection turned a
	// dissection failure into a match.
	if real.Match(nil) {
		t.Error("a real filter matched a nil dissection")
	}
}

func TestFilterCompileError(t *testing.T) {
	// A typo in the syntax fails where it is written, not silently on every
	// packet for the rest of the run.
	if f, err := NewFilter(`http.uri contains`); err == nil {
		f.Close()
		t.Error("an incomplete expression compiled")
	}
}

func TestDissectionCloseIsIdempotent(t *testing.T) {
	d, err := Dissect(httpFrame(), LinktypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	d.Close() // must not double-free

	// The Go-side fields are copies, so they survive the C tree.
	if d.Protocol != "HTTP" || len(d.Root.Children) == 0 {
		t.Error("the Go field tree did not survive Close")
	}
	f, err := NewFilter("tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f.Match(d) {
		t.Error("matching a closed dissection should be false, not a crash")
	}
}
