# pycapng

Python library for reading, writing, and capturing network traffic in the
[pcapng](https://github.com/pcapng/pcapng) file format.

```
pip install pycapng
```

- **Read** pcapng files packet by packet
- **Write** pcapng files with hand-crafted Ethernet/IP/TCP/UDP/ICMP/DNS/DHCP/NTP/TLS packets
- **Capture** live traffic with a Wireshark-style display filter (Linux / macOS)
- **Reassemble** fragmented IP packets
- **Script** packet flows with the built-in pcapsh engine

---

## Reading a pcapng file

```python
import pycapng

p = pycapng.PcapNG()
p.OpenFile("capture.pcapng", "r")

def on_packet(data: bytes, ts: int) -> None:
    print(f"packet {len(data)} bytes  ts={ts}")

p.ForeachPacket(on_packet)
p.CloseFile()
```

---

## Writing packets

### Raw bytes

```python
import pycapng

p = pycapng.PcapNG()
p.OpenFile("out.pcapng", "w")

raw = bytes([0x45, 0x00, 0x00, 0x28])   # any bytes
p.WritePacket(raw)

p.CloseFile()
```

### TCP

```python
p.WriteTcpPacket(
    src_ip="192.168.1.10", dst_ip="93.184.216.34",
    src_port=54321,        dst_port=80,
    payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    flags=0x02,   # SYN
)
```

### Build a packet without writing it

```python
syn = p.BuildTcpPacket(
    src_ip="10.0.0.1", dst_ip="10.0.0.2",
    src_port=1234, dst_port=443,
    payload=b"", flags=0x02,
)
# syn is bytes — inspect it, modify it, write it later
p.WritePacket(syn)
```

### UDP / ICMP

```python
pkt = p.BuildUdpPacket(
    src_ip="10.0.0.1", dst_ip="8.8.8.8",
    src_port=12345, dst_port=53,
    payload=b"\x00\x01...",   # your DNS query bytes
)

icmp = p.BuildIcmpPacket(
    src_ip="10.0.0.1", dst_ip="10.0.0.2",
    icmp_type=8, icmp_code=0,   # Echo Request
    payload=b"hello",
)
```

### Application-layer helpers

```python
# DNS
query    = p.BuildDnsQuery("example.com")
response = p.BuildDNSResponse("example.com", "93.184.216.34")

# DHCP
discover = p.BuildDhcpDiscover()
offer    = p.BuildDhcpOffer(client_mac="aa:bb:cc:dd:ee:ff",
                             offered_ip="192.168.1.100")

# NTP
req  = p.BuildNtpRequest()
resp = p.BuildNtpReply()

# TLS handshake (produces realistic-looking bytes for testing)
ch = p.BuildTlsClientHello()
sh = p.BuildTlsServerHello()
ct = p.BuildTlsCertificate()
fin = p.BuildTlsFinished()
app = p.BuildTlsApplicationData(b"GET / HTTP/1.1\r\n")
```

### Write with a timestamp

```python
import time

p.WritePacketTime(raw_bytes, int(time.time() * 1e9))   # nanoseconds
```

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
