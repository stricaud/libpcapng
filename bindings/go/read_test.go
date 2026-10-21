package pcapng

// ReadPackets, and why it exists.
//
// Before it, the only reader was ReadFile, which hands back whole blocks —
// header included. Callers then had to find the frame inside an Enhanced
// Packet Block themselves, and the README told them to take data[24:], which
// is four bytes short: the EPB body is 8 bytes of block header plus 20 bytes
// of fixed fields, so the frame starts at 28. Dissecting from four bytes off
// does not fail. It produces a confident, wrong answer — the demo printed
// Ethernet addresses lifted out of the middle of an IP header. A length check
// sails straight past that, so the check that matters here is comparing the
// delivered bytes against the bytes that went in.

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Two frames with distinct, recognisable contents.
var (
	frameA = seq(0x10, 48)
	frameB = seq(0xA0, 32)
)

func seq(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// writePcapng writes the smallest valid pcapng holding the given frames: SHB,
// one IDB, then an EPB each.
func writePcapng(t *testing.T, path string, linktype uint16, frames [][]byte) {
	t.Helper()

	block := func(btype uint32, body []byte) []byte {
		pad := (4 - len(body)%4) % 4
		total := uint32(12 + len(body) + pad)
		out := binary.LittleEndian.AppendUint32(nil, btype)
		out = binary.LittleEndian.AppendUint32(out, total)
		out = append(out, body...)
		out = append(out, make([]byte, pad)...)
		return binary.LittleEndian.AppendUint32(out, total)
	}

	shb := binary.LittleEndian.AppendUint32(nil, 0x1A2B3C4D)
	shb = binary.LittleEndian.AppendUint16(shb, 1)
	shb = binary.LittleEndian.AppendUint16(shb, 0)
	shb = binary.LittleEndian.AppendUint64(shb, ^uint64(0)) // section length: unknown
	data := block(0x0A0D0D0A, shb)

	idb := binary.LittleEndian.AppendUint16(nil, linktype)
	idb = binary.LittleEndian.AppendUint16(idb, 0)
	idb = binary.LittleEndian.AppendUint32(idb, 65535)
	data = append(data, block(1, idb)...)

	// Default if_tsresol is microseconds, so the ticks are µs since the epoch.
	const ticks = uint64(1700000000)*1000000 + 500000
	for _, f := range frames {
		epb := binary.LittleEndian.AppendUint32(nil, 0) // interface id
		epb = binary.LittleEndian.AppendUint32(epb, uint32(ticks>>32))
		epb = binary.LittleEndian.AppendUint32(epb, uint32(ticks&0xFFFFFFFF))
		epb = binary.LittleEndian.AppendUint32(epb, uint32(len(f)))
		epb = binary.LittleEndian.AppendUint32(epb, uint32(len(f)))
		epb = append(epb, f...)
		data = append(data, block(6, epb)...)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeClassicPcap writes a legacy .pcap, where the library synthesises each
// block and frees it when the callback returns — the case where a binding that
// merely kept the C pointer would hand back freed memory.
func writeClassicPcap(t *testing.T, path string, linktype uint16, frames [][]byte) {
	t.Helper()

	hdr := binary.LittleEndian.AppendUint32(nil, 0xA1B2C3D4)
	hdr = binary.LittleEndian.AppendUint16(hdr, 2)
	hdr = binary.LittleEndian.AppendUint16(hdr, 4)
	hdr = binary.LittleEndian.AppendUint32(hdr, 0) // thiszone
	hdr = binary.LittleEndian.AppendUint32(hdr, 0) // sigfigs
	hdr = binary.LittleEndian.AppendUint32(hdr, 65535)
	hdr = binary.LittleEndian.AppendUint32(hdr, uint32(linktype))

	data := hdr
	for i, f := range frames {
		data = binary.LittleEndian.AppendUint32(data, uint32(1700000000+i))
		data = binary.LittleEndian.AppendUint32(data, 500000)
		data = binary.LittleEndian.AppendUint32(data, uint32(len(f)))
		data = binary.LittleEndian.AppendUint32(data, uint32(len(f)))
		data = append(data, f...)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadPackets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(*testing.T, string, uint16, [][]byte)
	}{
		{"pcapng", writePcapng},
		{"classic pcap", writeClassicPcap},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c.cap")
			tc.write(t, path, 101, [][]byte{frameA, frameB})

			var got []*Packet
			n, err := ReadPackets(path, func(p *Packet) bool {
				got = append(got, p)
				return true
			})
			if err != nil {
				t.Fatal(err)
			}
			if n != 2 || len(got) != 2 {
				t.Fatalf("ReadPackets = %d, collected %d, want 2 and 2", n, len(got))
			}

			// The assertion this file exists for: the delivered bytes are the
			// frame, not the frame shifted by a header.
			if !bytes.Equal(got[0].Data, frameA) {
				t.Errorf("first frame = % x, want % x", got[0].Data, frameA)
			}
			if !bytes.Equal(got[1].Data, frameB) {
				t.Errorf("second frame = % x, want % x", got[1].Data, frameB)
			}

			if got[0].Index != 1 || got[1].Index != 2 {
				t.Errorf("indices = %d, %d, want 1-based and in order",
					got[0].Index, got[1].Index)
			}
			for i, p := range got {
				if p.Linktype != 101 {
					t.Errorf("packet %d: linktype = %d, want the IDB's 101", i, p.Linktype)
				}
				if p.CapturedLen != uint32(len(p.Data)) {
					t.Errorf("packet %d: captured_len = %d, len(Data) = %d",
						i, p.CapturedLen, len(p.Data))
				}
				if p.Truncated() {
					t.Errorf("packet %d: claims truncation with caplen == origlen", i)
				}
			}

			// if_tsresol defaults to microseconds; the binding scales to ns.
			if want := uint64(1700000000)*1e9 + 500*1e6; got[0].TimestampNs != want {
				t.Errorf("timestamp = %d ns, want %d", got[0].TimestampNs, want)
			}
			if !got[0].HasTimestamp {
				t.Error("HasTimestamp is false for a packet that carries one")
			}
		})
	}
}

func TestReadPacketsStops(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.pcapng")
	writePcapng(t, path, 1, [][]byte{frameA, frameB, frameA})

	seen := 0
	n, err := ReadPackets(path, func(p *Packet) bool {
		seen++
		return false // stop after the first
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Errorf("callback ran %d times after returning false, want 1", seen)
	}
	if n != 1 {
		t.Errorf("ReadPackets = %d, want 1 delivered before the stop", n)
	}
}

func TestReadPacketsMissingFile(t *testing.T) {
	// An absent file is an error, not an empty read: a typo in a path should
	// not look like a capture with nothing in it.
	n, err := ReadPackets(filepath.Join(t.TempDir(), "nope.pcapng"), func(*Packet) bool {
		t.Error("callback ran for a file that is not there")
		return true
	})
	if err == nil {
		t.Errorf("ReadPackets on a missing file returned %d and no error", n)
	}
}

// The reason ReadPackets exists: feeding Dissect straight from it, and having
// the result be the actual protocol rather than whatever lives 4 bytes early.
func TestReadPacketsFeedsDissect(t *testing.T) {
	EnsureProtocols()

	path := filepath.Join(t.TempDir(), "http.pcapng")
	writePcapng(t, path, LinktypeEthernet, [][]byte{httpFrame()})

	want, err := NewFilter(`http.uri == "/index.html"`)
	if err != nil {
		t.Fatal(err)
	}
	defer want.Close()

	matched := 0
	if _, err := ReadPackets(path, func(p *Packet) bool {
		d, err := Dissect(p.Data, p.Linktype)
		if err != nil || d == nil {
			t.Fatalf("Dissect: %v", err)
		}
		if d.Protocol != "HTTP" {
			t.Errorf("protocol = %q, want HTTP (is EnsureProtocols taking effect?)", d.Protocol)
		}
		if d.Src != "203.0.113.9" || d.Dst != "10.0.0.5" {
			t.Errorf("%s -> %s, want 203.0.113.9 -> 10.0.0.5", d.Src, d.Dst)
		}
		if want.Match(d) {
			matched++
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if matched != 1 {
		t.Errorf("filter matched %d packets, want 1", matched)
	}
}

// httpFrame builds Ethernet/IPv4/TCP carrying one HTTP request.
func httpFrame() []byte {
	req := []byte("GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n")

	tcp := binary.BigEndian.AppendUint16(nil, 54321)
	tcp = binary.BigEndian.AppendUint16(tcp, 80)
	tcp = binary.BigEndian.AppendUint32(tcp, 1000)
	tcp = binary.BigEndian.AppendUint32(tcp, 2000)
	tcp = append(tcp, 0x50, 0x18) // 5 words of header, ACK|PSH
	tcp = binary.BigEndian.AppendUint16(tcp, 8192)
	tcp = append(tcp, 0, 0, 0, 0) // checksum, urgent pointer
	tcp = append(tcp, req...)

	ip := []byte{0x45, 0x00}
	ip = binary.BigEndian.AppendUint16(ip, uint16(20+len(tcp)))
	ip = append(ip, 0x00, 0x01, 0x00, 0x00, 0x40, 6, 0, 0)
	ip = append(ip, 203, 0, 113, 9)
	ip = append(ip, 10, 0, 0, 5)
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip))
	ip = append(ip, tcp...)

	eth := []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00}
	return append(eth, ip...)
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// The writer and the reader share one unit, so this round trip should be exact
// to the microsecond the file stores. It used to take whole seconds, which
// meant a capture written through this API had every packet arriving at the
// same instant.
func TestWriteAndReadBackTimestamps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.pcapng")

	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	const base = uint64(1700000000)*1e9 + 123456789
	for i, f := range [][]byte{frameA, frameB} {
		if err := w.WritePacketWithTime(f, base+uint64(i)*1500); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var got []*Packet
	if _, err := ReadPackets(path, func(p *Packet) bool {
		got = append(got, p)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("read back %d packets, want 2", len(got))
	}
	if !bytes.Equal(got[0].Data, frameA) || !bytes.Equal(got[1].Data, frameB) {
		t.Error("the frames did not survive the round trip")
	}
	// The file stores microseconds, so the nanosecond remainder is truncated —
	// deliberately, and only that much.
	for i, p := range got {
		want := (base + uint64(i)*1500) / 1000 * 1000
		if p.TimestampNs != want {
			t.Errorf("packet %d: timestamp = %d ns, want %d", i, p.TimestampNs, want)
		}
	}
	if got[1].TimestampNs <= got[0].TimestampNs {
		t.Error("sub-second spacing was lost: both packets have the same time")
	}
}
