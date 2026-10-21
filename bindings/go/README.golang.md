# libpcapng Go bindings

Go bindings for [libpcapng](https://github.com/stricaud/libpcapng) — a fast pcap/pcapng
reader/writer with a built-in packet dissector and Wireshark-compatible display-filter engine.

## Install

```
go get github.com/stricaud/libpcapng/bindings/go
```

Requires CGo and a C compiler (`gcc` or `clang`). No other dependencies — the C library
is compiled automatically as part of `go build`.

## Quick start

### Read a pcap or pcapng file

```go
package main

import (
    "fmt"
    pcapng "github.com/stricaud/libpcapng/bindings/go"
)

func main() {
    n, err := pcapng.ReadPackets("capture.pcapng", func(p *pcapng.Packet) bool {
        fmt.Printf("%d: %d bytes on the wire, %d captured\n",
            p.Index, p.OriginalLen, p.CapturedLen)
        return true // false stops the read
    })
    if err != nil {
        panic(err)
    }
    fmt.Printf("%d packets\n", n)
}
```

`ReadPackets` hands you the frame itself, with the link-layer type already
resolved from the interface the packet belongs to and the timestamp already
scaled by that interface's resolution. Both `.pcap` and `.pcapng` work; the
format is detected.

If you want the file's block structure rather than its packets — options,
name-resolution blocks, decryption secrets — use `ReadFile`, which delivers
whole blocks including the 8-byte block header.

### Dissect packets

```go
pcapng.EnsureProtocols() // once, at startup

n, err := pcapng.ReadPackets("capture.pcapng", func(p *pcapng.Packet) bool {
    d, _ := pcapng.Dissect(p.Data, p.Linktype)
    if d != nil {
        fmt.Printf("%4d  %-6s %-15s -> %-15s  %s\n",
            p.Index, d.Protocol, d.Src, d.Dst, d.Info)
    }
    return true
})
```

`EnsureProtocols` loads the bundled POSA protocol definitions. Without it you
get only the built-in C dissectors — a bare `TCP` where there was an HTTP
request — and a filter naming a field such as `http.uri` matches nothing,
because the field does not exist yet. It is idempotent.

### Apply a display filter

```go
pcapng.EnsureProtocols()

f, err := pcapng.NewFilter("tcp.dstport == 443 and ip.src == 10.0.0.0/8")
if err != nil {
    panic(err) // a typo fails here, not silently on every packet
}
defer f.Close()

_, err = pcapng.ReadPackets("capture.pcapng", func(p *pcapng.Packet) bool {
    d, _ := pcapng.Dissect(p.Data, p.Linktype)
    if d != nil && f.Match(d) {
        fmt.Printf("packet %d matches\n", p.Index)
    }
    return true
})
```

Dissect once and match many: dissecting costs microseconds, matching a
compiled filter against the result costs nanoseconds. `f.MatchRaw(data,
linktype)` is there for when you have only the bytes, but it dissects
internally, so with more than one filter prefer `Dissect` + `Match`.

### Walk the field tree

```go
d, _ := pcapng.Dissect(pktBytes, pcapng.LinktypeEthernet)
if d == nil {
    return
}

// Find all fields with a specific abbreviation (Wireshark-style).
for _, field := range d.FindFields("ip.src") {
    fmt.Println("IP src:", field.Str)
}

// Or walk the full tree.
var walk func(f *pcapng.Field, depth int)
walk = func(f *pcapng.Field, depth int) {
    indent := strings.Repeat("  ", depth)
    fmt.Printf("%s%s: %s\n", indent, f.Abbrev, f.Str)
    for _, child := range f.Children {
        walk(child, depth+1)
    }
}
walk(d.Root, 0)
```

### Write a pcapng file

```go
w, err := pcapng.NewWriter("output.pcapng")
if err != nil {
    panic(err)
}
defer w.Close()

rawEthernetFrame := []byte{ /* ... */ }
w.WritePacket(rawEthernetFrame)
w.WritePacketWithTime(rawEthernetFrame, uint64(time.Now().UnixNano()))
```

Timestamps are nanoseconds since the epoch — the same unit `ReadPackets` gives
back in `Packet.TimestampNs`, so a round trip needs no conversion. The file
stores microseconds, the format's default resolution, so anything finer than a
microsecond is truncated.

### Live capture

```go
cap, err := pcapng.Open("en0")
if err != nil {
    panic(err)   // needs root / CAP_NET_RAW
}
defer cap.Close()

cap.SetFilter("tcp.port == 80 or tcp.port == 443")

cap.Loop(0, func(pkt *pcapng.PacketInfo) {
    d, _ := pcapng.Dissect(pkt.Data, pcapng.LinktypeEthernet)
    if d != nil {
        fmt.Printf("%s → %s  %s\n", d.Src, d.Dst, d.Info)
    }
})
```

## API overview

| Symbol | Description |
|--------|-------------|
| `ReadPackets(path, cb)` | Read every **packet**: frame, resolved linktype, scaled timestamp |
| `EnsureProtocols()` | Load the bundled POSA protocol decoders (call once, before dissecting) |
| `(*Packet).Truncated()` | Was the frame cut short by the capture's snaplen? |
| `ReadFile(path, cb)` | Read every **block** from a pcap/pcapng file, header included |
| `ReadMemory(buf, cb)` | Read blocks from an in-memory buffer |
| `Dissect(data, linktype)` | Dissect raw packet bytes into a field tree |
| `DissectFull(data, caplen, origlen, linktype)` | Dissect with separate captured/original lengths |
| `ResetFlows()` | Clear the sticky flow-classification table between captures |
| `SetVerifyChecksums(bool)` | Enable/disable IP/TCP/UDP checksum validation |
| `NewFilter(expr)` | Compile a Wireshark-compatible display filter |
| `(*Filter).Match(d)` | Match a compiled filter against an existing dissection |
| `(*Filter).MatchRaw(data, linktype)` | Dissect + filter in one step |
| `ListDevices()` | Enumerate network interfaces |
| `DefaultDevice()` | Name of the first usable non-loopback interface |
| `Open(device)` | Create a live capture handle |
| `(*Capture).SetFilter(expr)` | Attach a display filter to a live capture |
| `(*Capture).Loop(count, fn)` | Capture packets until count or SIGINT |
| `(*Capture).Dispatch(count, fn)` | Process one batch (for event loops) |
| `(*Capture).Break()` | Stop the capture loop |
| `CaptureToFile(dev, path, filter, count)` | One-shot: capture to file |
| `NewWriter(path)` | Create a pcapng file writer (Ethernet link type) |
| `(*Writer).WritePacketWithTime(frame, ns)` | Append a packet timestamped in nanoseconds |
| `NewWriterWithLinktype(path, lt)` | Create a writer with explicit link type |

## Versioning & publishing

Go packages don't require manual registration. As soon as a tag of the form
`bindings/go/vX.Y.Z` is pushed to GitHub, the package becomes available at:

```
https://pkg.go.dev/github.com/stricaud/libpcapng/bindings/go
```

To publish a new version:

```bash
# from the repo root
git tag bindings/go/v0.2.0
git push origin bindings/go/v0.2.0
```

The Go module proxy ([proxy.golang.org](https://proxy.golang.org)) will fetch and cache
the new version automatically within a few minutes of the tag being pushed.

## Updating the bundled C sources

The C library sources are carried in `csrc/`, which is why `go get` needs
nothing installed. After updating the parent library, re-run the sync script:

```bash
cd bindings/go
./scripts/sync-sources.sh
```

Then commit the updated `csrc/` directory alongside any API changes.
`ctest -R Vendor-Sync` fails if the copy has drifted from `lib/`.

The directory is deliberately **not** called `vendor`: the module zip format
drops any directory with that name, so the published module arrived with no C
sources in it and would not compile — while building perfectly from a
checkout, where the directory is sitting right there. If you rename it, do not
rename it to that.

## License

MIT — same as libpcapng.
