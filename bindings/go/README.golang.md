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
    err := pcapng.ReadFile("capture.pcapng", func(counter, blockType uint32, data []byte) {
        if blockType == pcapng.BlockTypeEnhancedPacket {
            fmt.Printf("block %d: %d bytes\n", counter, len(data))
        }
    })
    if err != nil {
        panic(err)
    }
}
```

### Dissect packets

```go
err := pcapng.ReadFile("capture.pcapng", func(counter, blockType uint32, data []byte) {
    if blockType != pcapng.BlockTypeEnhancedPacket {
        return
    }
    // The EPB body starts at offset 24 (8-byte block header + 16-byte EPB fixed fields).
    // For real use, parse the EPB header to get captured_len and the packet payload offset.
    d, _ := pcapng.Dissect(data[24:], pcapng.LinktypeEthernet)
    if d != nil {
        fmt.Printf("[%s] %s → %s  %s\n", d.Protocol, d.Src, d.Dst, d.Info)
    }
})
```

### Apply a display filter

```go
f, err := pcapng.NewFilter("tcp.dstport == 443 and ip.src == 10.0.0.0/8")
if err != nil {
    panic(err)
}
defer f.Close()

err = pcapng.ReadFile("capture.pcapng", func(counter, blockType uint32, data []byte) {
    if blockType != pcapng.BlockTypeEnhancedPacket {
        return
    }
    payload := data[24:]
    matched, _ := f.MatchRaw(payload, pcapng.LinktypeEthernet)
    if matched {
        fmt.Printf("packet %d matches\n", counter)
    }
})
```

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
w.WritePacketWithTime(rawEthernetFrame, uint32(time.Now().Unix()))
```

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
| `ReadFile(path, cb)` | Read every block from a pcap/pcapng file |
| `ReadMemory(buf, cb)` | Read blocks from an in-memory buffer |
| `Dissect(data, linktype)` | Dissect raw packet bytes into a field tree |
| `DissectFull(data, caplen, origlen, linktype)` | Dissect with separate captured/original lengths |
| `ResetFlows()` | Clear the sticky flow-classification table between captures |
| `SetVerifyChecksums(bool)` | Enable/disable IP/TCP/UDP checksum validation |
| `NewFilter(expr)` | Compile a Wireshark-compatible display filter |
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

## Updating vendored C sources

The C library sources are vendored under `vendor/`. After updating the parent
library, re-run the sync script:

```bash
cd bindings/go
./scripts/sync-sources.sh
```

Then commit the updated `vendor/` directory alongside any API changes.

## License

MIT — same as libpcapng.
