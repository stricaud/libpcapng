# pycapng

Python library for reading, writing, and capturing network traffic in the
[pcapng](https://github.com/pcapng/pcapng) file format.

```
pip install pycapng
```

- **Read** pcapng and legacy pcap files packet by packet
- **Dissect** packets into Wireshark-style protocol layers and named fields
- **Filter** with Wireshark display-filter syntax, compiled once and matched many times
- **Write** pcapng files with hand-crafted Ethernet/IP/TCP/UDP/ICMP/DNS/DHCP/NTP/TLS packets
- **Capture** live traffic with a Wireshark-style display filter (Linux / macOS)
- **Reassemble** fragmented IP packets
- **Script** packet flows with the built-in pcapsh engine

---

## Reading a pcapng file

```python
import pycapng

for pkt in pycapng.read_packets("capture.pcapng"):
    print(f"{pkt.index}: {pkt.captured_len}/{pkt.original_len} bytes "
          f"at {pkt.timestamp_ns} ns, linktype {pkt.linktype}")
```

`read_packets` returns a list; `foreach_packet(path, cb)` streams instead, and
stops early if the callback returns `False`. Both hand you the frame itself,
with the link-layer type already resolved from the interface the packet belongs
to and the timestamp already scaled by that interface's resolution. Legacy
`.pcap` files work too — the format is detected.

```python
def each(pkt):
    print(pkt.index, len(pkt.data), "bytes")
    return True          # False stops the read

n = pycapng.foreach_packet("capture.pcapng", each)
```

`read_packets_mem(buf)` does the same for a capture you already have in memory.

---

## Dissecting packets

```python
import pycapng

pycapng.ensure_protocols()          # once, at startup

for pkt in pycapng.read_packets("capture.pcapng"):
    d = pycapng.dissect(pkt.data, pkt.linktype)
    print(f"{d.proto:6} {d.src:15} -> {d.dst:15} {d.info}")
```

```
HTTP   203.0.113.9     -> 10.0.0.5         GET /index.html HTTP/1.1
DNS    203.0.113.9     -> 8.8.8.8          Query 0x1234 A example.com
TLS    203.0.113.9     -> 10.0.0.5         Handshake Client Hello
```

`ensure_protocols()` loads the bundled protocol decoders. Most of libpcapng's
protocol knowledge is [POSA](https://github.com/stricaud/libpcapng/blob/main/doc/posa.md)
definitions compiled into the library and registered on demand, so **until you
call it** an HTTP request dissects as plain `TCP` and a filter naming
`http.uri` matches nothing — with no error either way. It is idempotent.

### The fields

```python
d = pycapng.dissect(pkt.data, pkt.linktype)

[f["abbrev"] for f in d.fields]
# ['frame', 'eth', 'ip', 'tcp', 'http']   — the layers, each with its children

d.flat()["http.uri"]        # '/index.html'
d.flat()["tcp.dstport"]     # 80  (an int, not a string)
```

`d.fields` is the tree, one entry per protocol layer; `d.flat()` is every field
in it collapsed to `{abbrev: value}`, which is what you want when you are after
one value and do not care where it sits.

### Display filters

```python
pycapng.ensure_protocols()

want = pycapng.Filter('http.uri contains "/cgi-bin/" and ip.src == 10.0.0.0/8')

for pkt in pycapng.read_packets("capture.pcapng"):
    d = pycapng.dissect(pkt.data, pkt.linktype)
    if want.matches(d):
        print(d.src, "->", d.dst, d.info)
```

A filter is compiled once and matched many times: dissecting costs
microseconds, matching a compiled filter against the result costs nanoseconds,
so thirty filters should mean one dissection and thirty tree walks, not thirty
dissections. `Filter("")` matches everything, which `is_match_all()` reports.

A filter that will not compile raises `ValueError` where it is written, rather
than quietly matching nothing for the rest of the run. An unknown *field* name
is not caught that way — field names come into existence during dissection, so
`Filter("htttp.uri")` compiles and matches nothing. Worth a second look when a
filter you expect to fire does not.

---

## Writing packets

Every `Build*` helper returns a complete **Ethernet** frame, which is why each
one takes a pair of MAC addresses, and why that is what a file opened for
writing declares.

```python
import pycapng

p = pycapng.PcapNG()
p.OpenFile("out.pcapng", "w")
...
p.CloseFile()
```

Writing something else — bare IP datagrams, SLL, CAN — means saying so, since
a file whose interface disagrees with its packets is not an error that any
reader reports; it just decodes from the wrong offset:

```python
p.OpenFileLinkType("out.pcapng", "w", pycapng.LINKTYPE_RAW)
```

Before 0.19.6, `OpenFile` declared `LINKTYPE_RAW` and the builders' Ethernet
frames landed in a file that claimed to hold raw IP.

### Raw bytes

```python
raw = bytes([0x45, 0x00, 0x00, 0x28])   # any bytes
p.WritePacket(raw)
p.WritePacket(raw, comment="the one that started it")
```

### TCP

```python
p.WriteTcpPacket(
    src_mac="02:00:00:00:00:01", dst_mac="02:00:00:00:00:02",
    src_ip="192.168.1.10",       dst_ip="93.184.216.34",
    src_port=54321,              dst_port=80,
    flags=0x02,   # SYN; the default is 0x18, PSH|ACK
    data=b"",
)
```

`seqnum` and `ack` default to 0.

### Build a packet without writing it

```python
syn = p.BuildTcpPacket(
    src_mac="02:00:00:00:00:01", dst_mac="02:00:00:00:00:02",
    src_ip="10.0.0.1", dst_ip="10.0.0.2",
    src_port=1234, dst_port=443,
    flags=0x02, data=b"",
)
# syn is bytes — inspect it, dissect it, modify it, write it later
p.WritePacket(syn)
```

### UDP / ICMP

```python
pkt = p.BuildUdpPacket(
    src_mac="02:00:00:00:00:01", dst_mac="02:00:00:00:00:02",
    src_ip="10.0.0.1", dst_ip="8.8.8.8",
    src_port=12345, dst_port=53,
    data=b"\x00\x01...",   # your DNS query bytes
)

icmp = p.BuildIcmpPacket(
    src_mac="02:00:00:00:00:01", dst_mac="02:00:00:00:00:02",
    src_ip="10.0.0.1", dst_ip="10.0.0.2",
    icmp_type=8, icmp_code=0,      # Echo Request
    identifier=1, sequence=1,
    data=b"hello",
)
```

### Application-layer helpers

```python
CLIENT, SERVER = "02:00:00:00:00:01", "02:00:00:00:00:02"

# DNS
query = p.BuildDnsQuery(
    src_mac=CLIENT, dst_mac=SERVER,
    src_ip="10.0.0.1", dst_ip="8.8.8.8",
    src_port=51000, dst_port=53,
    transaction_id=0x1234, domain="example.com",   # qtype="A", qclass="IN"
)
response = p.BuildDNSResponse(
    src_mac=SERVER, dst_mac=CLIENT,
    src_ip="8.8.8.8", dst_ip="10.0.0.1",
    src_port=53, dst_port=51000,
    transaction_id=0x1234, domain="example.com",
    qtype="A", response_ip="93.184.216.34",
)

# DHCP
discover = p.BuildDhcpDiscover(
    src_mac=CLIENT, src_ip="0.0.0.0",
    src_port=68, dst_port=67, xid=0x1234,
)
offer = p.BuildDhcpOffer(
    src_mac=SERVER, dst_mac=CLIENT,
    src_ip="192.168.1.1", offered_ip="192.168.1.100",
    xid=0x1234, src_port=67, dst_port=68,
)

# NTP
req = p.BuildNtpRequest(src_mac=CLIENT, dst_mac=SERVER,
                        src_ip="10.0.0.1", dst_ip="10.0.0.2",
                        src_port=50000, dst_port=123)
resp = p.BuildNtpReply(src_mac=SERVER, dst_mac=CLIENT,
                       src_ip="10.0.0.2", dst_ip="10.0.0.1",
                       src_port=123, dst_port=50000, ntp_request=req)

# TLS handshake (produces realistic-looking bytes for testing)
ch = p.BuildTlsClientHello(src_mac=CLIENT, dst_mac=SERVER,
                           src_ip="10.0.0.1", dst_ip="10.0.0.2",
                           src_port=54322, dst_port=443)
sh = p.BuildTlsServerHello(src_mac=SERVER, dst_mac=CLIENT,
                           src_ip="10.0.0.2", dst_ip="10.0.0.1",
                           src_port=443, dst_port=54322)
app = p.BuildTlsApplicationData(src_mac=CLIENT, dst_mac=SERVER,
                                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                                src_port=54322, dst_port=443,
                                tls_appdata=b"GET / HTTP/1.1\r\n")
```

### Write with a timestamp

```python
import time

p.WritePacketTime(raw_bytes, time.time_ns())   # nanoseconds since the epoch
```

Nanoseconds, because that is the unit `read_packets()` gives back in
`pkt.timestamp_ns`, so writing and reading use one unit. The file stores
microseconds — the format's default resolution — so anything finer than a
microsecond is truncated.

---

## Live capture

Requires **root** or `CAP_NET_RAW` on Linux, **root** or the network entitlement
on macOS.

### Simple callback loop

```python
import pycapng

with pycapng.Capture("eth0") as cap:
    cap.set_filter("tcp.dstport == 443")
    cap.loop(0, lambda pkt: print(f"{pkt.captured_len} bytes"))
```

### Full example

```python
import pycapng, signal

cap = pycapng.Capture(pycapng.capture_default_device())
cap.set_snaplen(65535)
cap.set_promisc(True)
cap.set_timeout(100)                        # ms between ring deliveries
cap.set_filter("ip and not arp")

signal.signal(signal.SIGINT, lambda *_: cap.break_loop())

def on_packet(pkt: pycapng.PacketInfo) -> None:
    ts = pkt.timestamp_ns // 1_000_000_000
    print(f"[{ts}] {pkt.direction}  {pkt.captured_len}/{pkt.original_len} bytes")

cap.loop(0, on_packet)

stats = cap.get_stats()
print(f"received={stats.received}  dropped={stats.dropped}")
cap.close()
```

### Display filter syntax

The filter language is a subset of Wireshark's display filter syntax.

| Example | Meaning |
|---|---|
| `tcp` | any TCP packet |
| `tcp.dstport == 443` | TCP to port 443 |
| `ip.src == 192.168.0.0/16` | source in subnet |
| `tcp.flags.syn and not tcp.flags.ack` | SYN-only |
| `udp.port == 53` | DNS (src or dst) |
| `ip.addr == 10.0.0.1` | any direction to/from IP |
| `tcp and not (tcp.dstport == 80 or tcp.dstport == 443)` | non-web TCP |
| `eth.addr == aa:bb:cc:dd:ee:ff` | by MAC (src or dst) |

Built-in fields: `eth.{src,dst,type,addr}` · `ip.{src,dst,proto,ttl,len,addr}` ·
`ip6.{src,dst}` · `tcp.{srcport,dstport,flags,flags.syn/ack/rst/fin,port}` ·
`udp.{srcport,dstport,port}` · `icmp.{type,code}`

### Capture directly to a pcapng file

```python
# one-liner: capture 500 TLS packets and save to a file
pycapng.capture_to_file("eth0", "tls.pcapng",
                         filter="tcp.dstport == 443", count=500)
```

### List available interfaces

```python
for dev in pycapng.capture_list_devices():
    print(dev["name"], "(loopback)" if dev["loopback"] else "")

iface = pycapng.capture_default_device()
```

---

## IP fragment reassembly

```python
import pycapng

r = pycapng.Reassembler()
p = pycapng.PcapNG()
p.OpenFile("fragments.pcapng", "r")

def on_packet(data: bytes, ts: int) -> None:
    complete = r.add(data)
    if complete:
        print(f"reassembled datagram: {len(complete)} bytes")

p.ForeachPacket(on_packet)
```

---

## pcapsh script engine

The `pycapng.pcapsh` submodule exposes a scripting engine for building and
replaying packet flows declaratively.

```python
from pycapng import pcapsh

engine = pcapsh.PcapSH()
engine.RunScript("my_flow.pcapsh", "out.pcapng")
```

TLS record builders are also available as standalone functions:

```python
from pycapng.pcapsh import (
    tls_client_hello, tls_server_hello,
    tls_certificate, tls_finished,
    tls_application_data,
)
```

---

## C library

pycapng is the Python interface to [libpcapng](https://github.com/stricaud/libpcapng),
a C library that also ships a standalone command-line tool (`pcapsh`) and a
full C API.  See the repository for C usage, build instructions, and the
[capture API reference](docs/capture.md).
