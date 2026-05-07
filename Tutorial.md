# pcapsh Tutorial

This tutorial walks through building network packets with `pcapsh`, from the very first
packet to defining your own protocol and writing multi-packet captures that Wireshark
can open and dissect.

---

## Prerequisites

Build pcapsh from source:

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target pcapsh
```

Start the shell:

```
./build/bin/pcapsh
```

You should see the banner and the `pcapsh >>>` prompt.

---

## Part 1 — Your first packet

Type this at the prompt:

```
pcapsh >>> IP()
```

You'll see the default IP packet printed with all its fields:

```
<IP version=4 ihl=5 tos=0 len=auto id=1 flags=0x0 frag=0 ttl=64 proto=auto chksum=auto src=127.0.0.1 dst=127.0.0.1>
```

Fields marked `auto` are computed at serialization time (length, checksum, protocol
number). Every protocol comes with sensible defaults — you only need to set the fields
you care about.

Now set the destination:

```
pcapsh >>> IP(dst="8.8.8.8")
<IP ... src=127.0.0.1 dst=8.8.8.8>
```

To see the raw bytes, use `hexdump()`:

```
pcapsh >>> hexdump(IP(dst="8.8.8.8")/ICMP(type=8, id=1, seq=1))
0000  45 00 00 1c 41 A7 00 00  40 01 94 ...
```

Or `raw()` for an escaped byte string (same format as Scapy):

```
pcapsh >>> raw(IP(dst="8.8.8.8")/ICMP(type=8, id=1, seq=1))
'E\x00\x00\x1c...'
```

---

## Part 2 — Stacking layers

Layers are stacked with `/`, just like Scapy. This mirrors the real network stack:
Ethernet carries IP, IP carries TCP, and so on.

```
pcapsh >>> Ether()/IP()/TCP()
<Ether dst=ff:ff:ff:ff:ff:ff src=00:00:00:00:00:00 type=auto | <IP ... | <TCP ...>>>
```

A string after `/` becomes a raw payload:

```
pcapsh >>> IP(dst="1.2.3.4")/TCP(dport=80,flags="PA")/"GET / HTTP/1.0\r\n\r\n"
<IP ... | <TCP ... | <Raw load='GET / HTTP/1.0\r\n\r\n'>>>
```

Save packets to variables:

```
pcapsh >>> a = Ether(src="aa:bb:cc:dd:ee:ff")/IP(src="10.0.0.1",dst="10.0.0.2")/TCP(dport=443,flags="S")
pcapsh >>> a
<Ether ... | <IP ... | <TCP ...>>>
pcapsh >>> hexdump(a)
```

---

## Part 3 — Writing a capture file

`wrpcap("file.pcapng", pkt)` writes a packet to a pcapng file. If the file exists,
the packet is appended. Every pcapng file pcapsh writes is valid — open it directly
in Wireshark or feed it to tshark.

```
pcapsh >>> wrpcap("first.pcapng", IP(src="10.0.0.1",dst="8.8.8.8")/ICMP(type=8,id=1,seq=1))
Wrote 42 bytes to first.pcapng
pcapsh >>> wrpcap("first.pcapng", IP(src="8.8.8.8",dst="10.0.0.1")/ICMP(type=0,id=1,seq=1))
Wrote 42 bytes to first.pcapng
```

Open `first.pcapng` in Wireshark: two ICMP packets, request then reply.

Verify with tshark:

```
$ tshark -r first.pcapng
1   0.000000  10.0.0.1 → 8.8.8.8    ICMP 42 Echo (ping) request
2   0.000000  8.8.8.8  → 10.0.0.1   ICMP 42 Echo (ping) reply
```

---

## Part 4 — Working with DNS

DNS is a first-class native protocol with named fields. Build a query:

```
pcapsh >>> DNS()
<DNS id=16807 flags=0 qdcount=0 ancount=0 nscount=0 arcount=0>
```

Add a question with `DNSQR()`:

```
pcapsh >>> DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com"))
<DNS id=4660 flags=256 qdcount=1 ancount=0 nscount=0 arcount=0>
```

`rd=1` sets the "recursion desired" bit (flag 0x0100 = 256). `qdcount` is auto-incremented
when you provide `qd=`. Stack it under UDP/IP and write it out:

```
pcapsh >>> q = IP(src="192.168.1.10",dst="8.8.8.8")/UDP(sport=54321,dport=53)/DNS(id=0x1234,rd=1,qd=DNSQR(qname="example.com"))
pcapsh >>> wrpcap("dns.pcapng", q)
```

Build a response with `DNSRR()`:

```
pcapsh >>> r = IP(src="8.8.8.8",dst="192.168.1.10")/UDP(sport=53,dport=54321)/DNS(id=0x1234,qr=1,rd=1,ra=1,qd=DNSQR(qname="example.com"),an=DNSRR(rrname="example.com",type=A,ttl=300,rdata="93.184.216.34"),qdcount=1,ancount=1)
pcapsh >>> wrpcap("dns.pcapng", r)
```

Open `dns.pcapng` in Wireshark: a complete DNS query/response pair, fully dissected.

`DNSQR` supports query types: `A NS CNAME SOA PTR MX AAAA ANY`. Use them by name:

```
pcapsh >>> DNS(rd=1, qd=DNSQR(qname="gmail.com", qtype=MX))
pcapsh >>> DNS(rd=1, qd=DNSQR(qname="4.3.2.1.in-addr.arpa", qtype=PTR))
```

Use `RandShort()` for a random transaction ID:

```
pcapsh >>> DNS(id=RandShort(), rd=1, qd=DNSQR(qname="example.com"))
```

---

## Part 5 — TCP session tracking

Building a realistic TCP session by hand means tracking sequence numbers, ACK values,
and MAC addresses. pcapsh does this automatically with `TCPSession`.

```
pcapsh >>> s = TCPSession("192.168.1.100", "93.184.216.34", 54321, 80)
```

This creates a session object. MACs are derived from IPs automatically. Call the
session functions in order:

```
pcapsh >>> wrpcap("http.pcapng", syn(s))
pcapsh >>> wrpcap("http.pcapng", syn_ack(s))
pcapsh >>> wrpcap("http.pcapng", tcp_ack(s))
pcapsh >>> wrpcap("http.pcapng", client_send(s, "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"))
pcapsh >>> wrpcap("http.pcapng", server_send(s, "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
pcapsh >>> wrpcap("http.pcapng", client_fin(s))
pcapsh >>> wrpcap("http.pcapng", server_fin_ack(s))
```

Open `http.pcapng` in Wireshark and follow the TCP stream — you'll see the full HTTP
exchange with correct sequence numbers throughout.

You can run multiple sessions simultaneously and interleave them into one capture:

```
pcapsh >>> web  = TCPSession("10.0.0.1", "1.2.3.4",   49152, 80)
pcapsh >>> db   = TCPSession("10.0.0.1", "10.0.0.10", 49153, 5432)
pcapsh >>> wrpcap("multi.pcapng", syn(web))
pcapsh >>> wrpcap("multi.pcapng", syn(db))
pcapsh >>> wrpcap("multi.pcapng", syn_ack(web))
pcapsh >>> wrpcap("multi.pcapng", syn_ack(db))
```

---

## Part 6 — Script files

Anything you type in the REPL can go in a script file (`.pcapsh` extension):

```sh
# http_session.pcapsh
s = TCPSession("192.168.1.100", "93.184.216.34", 54321, 80)
wrpcap("http.pcapng", syn(s))
wrpcap("http.pcapng", syn_ack(s))
wrpcap("http.pcapng", tcp_ack(s))
wrpcap("http.pcapng", client_send(s, "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"))
wrpcap("http.pcapng", server_send(s, "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
wrpcap("http.pcapng", client_fin(s))
wrpcap("http.pcapng", server_fin_ack(s))
```

Run it non-interactively:

```
./build/bin/pcapsh http_session.pcapsh
```

Or evaluate a one-liner:

```
./build/bin/pcapsh -e 'hexdump(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="example.com")))'
```

---

## Part 7 — Discovering what's available

`ls()` lists all protocols and their fields. `ls(Proto)` shows one protocol in detail:

```
pcapsh >>> ls()          # all protocols
pcapsh >>> ls(IP)        # IP fields
pcapsh >>> ls(DNS)       # DNS fields with descriptions
pcapsh >>> ls(SMB2)      # SMB2 with enum values
```

`help()` gives a compact usage summary with examples.

Tab-completion works in the REPL: press Tab after typing a few letters to complete
protocol names and function names.

---

## Part 8 — Built-in application protocols

pcapsh includes several protocols beyond the basics. They all work the same way:
construct, inspect, stack, write.

**ARP** — Layer 2 address resolution:

```
pcapsh >>> Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=REQUEST, spa="10.0.0.1", tpa="10.0.0.254")
pcapsh >>> Ether(dst="aa:bb:cc:dd:ee:ff")/ARP(op=REPLY, sha="00:11:22:33:44:55", spa="10.0.0.254", tha="aa:bb:cc:dd:ee:ff", tpa="10.0.0.1")
```

**NTP** — Network time protocol:

```
pcapsh >>> IP(dst="129.6.15.28")/UDP(sport=12345,dport=123)/NTP(li_vn_mode=CLIENT)
```

**DHCP** — Dynamic host configuration:

```
pcapsh >>> Ether(src="aa:bb:cc:dd:ee:ff",dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/DHCP(op=BOOTREQUEST,xid=0x12345678)
```

**SMB2** over NBT/TCP:

```
pcapsh >>> s = TCPSession("10.0.0.1", "10.0.0.2", 49152, 445)
pcapsh >>> wrpcap("smb2.pcapng", syn(s))
pcapsh >>> wrpcap("smb2.pcapng", syn_ack(s))
pcapsh >>> wrpcap("smb2.pcapng", tcp_ack(s))
pcapsh >>> wrpcap("smb2.pcapng", client_send(s, "\x00\x00\x00\x40\xfeSMB\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
```

Enum values can always be used by name: `SMB2(command=READ)`, `RADIUS(code=ACCESS_ACCEPT)`,
`SYSLOG(severity=WARNING)`, `DCERPC(type=BIND)`. Use `ls(Proto)` to see available names.

---

## Part 9 — Defining your own protocol

This is where pcapsh becomes a protocol development tool. Define any protocol directly
in the REPL or in a script using the `protocol ... end` block.

### In the REPL

```
pcapsh >>> protocol MyProto
...   >>> required uint8  type = 0
...   >>>     DATA = 1
...   >>>     CTRL = 2
...   >>> required uint16 length = 0
...   >>> required uint32 sequence = 0
...   >>> end
Protocol 'MyProto' defined (3 fields). Use MyProto() and ls(MyProto).
```

The shell switches to a continuation prompt (`...`) while the block is open. When you
type `end`, the protocol is registered immediately and ready to use.

```
pcapsh >>> MyProto()
<MyProto type=0x0000 length=0 sequence=0>

pcapsh >>> MyProto(type=DATA, length=12, sequence=1)
<MyProto type=0x0001 length=12 sequence=1>

pcapsh >>> hexdump(IP(src="10.0.0.1",dst="10.0.0.2")/UDP(dport=9000)/MyProto(type=DATA, length=8, sequence=42))
0000  45 00 00 23 ...  CA FE ...  01 00 00 2A
```

```
pcapsh >>> ls(MyProto)
MyProto fields:
  type        uint8   [DATA=0x1, CTRL=0x2]
  length      uint16
  sequence    uint32
```

### In a script file

The block works identically in scripts — no special syntax needed:

```sh
# my_protocol_test.pcapsh

protocol Beacon
    required uint32 magic = 0xBEAC04
    required uint8  version = 1
    required uint8  hop_count = 0
    required uint16 ttl = 64
    required ip4    origin = 0.0.0.0
    required ip4    target = 0.0.0.0
end

# Build a beacon packet
pkt = Ether()/IP(src="10.1.0.1",dst="224.0.0.1")/UDP(sport=5353,dport=5353)/Beacon(origin="10.1.0.1",target="0.0.0.0")
hexdump(pkt)
wrpcap("beacon.pcapng", pkt)
```

```
./build/bin/pcapsh my_protocol_test.pcapsh
```

### Field types

All posa field types are available:

| Type              | Size     | Notes |
|-------------------|----------|-------|
| `uint8`           | 1 byte   | big-endian |
| `uint16`          | 2 bytes  | big-endian |
| `uint32`          | 4 bytes  | big-endian |
| `uint64`          | 8 bytes  | big-endian |
| `le_uint16`       | 2 bytes  | little-endian (Windows protocols) |
| `le_uint32`       | 4 bytes  | little-endian |
| `le_uint64`       | 8 bytes  | little-endian |
| `mac`             | 6 bytes  | default `00:00:00:00:00:00` |
| `ip4`             | 4 bytes  | default `0.0.0.0` |
| `cstring`         | variable | null-terminated string |
| `payload`         | variable | rest of packet bytes (must be last field) |
| `bytes[lenfield]` | variable | length taken from a previously parsed integer field |
| `bytes<N>`        | N bytes  | fixed width, zero-padded |

### Enum values

Add named constants under any integer field (indented 4+ spaces):

```
protocol Status
    required uint8 code = 0
        OK      = 0
        ERR     = 1
        RETRY   = 2
        NACK    = 3
    required uint16 reason = 0
end
```

Use them by name when constructing:

```
pcapsh >>> Status(code=ERR, reason=404)
```

### Example: a TLV framing protocol

```
protocol TLV
    required uint8  tag = 0
        PADDING   = 0
        HEARTBEAT = 1
        DATA      = 2
        EOF       = 255
    required uint8  flags = 0
    required uint16 length = 0
    required uint32 sequence = 0
end
```

```
pcapsh >>> hexdump(IP()/UDP(dport=9000)/TLV(tag=DATA,length=4,sequence=1))
pcapsh >>> wrpcap("tlv.pcapng", IP(src="10.0.0.1",dst="10.0.0.2")/UDP(dport=9000)/TLV(tag=HEARTBEAT,sequence=100))
```

### Example: a proprietary Windows protocol (little-endian)

```
protocol WinMsg
    required le_uint32 magic = 0x574D5347
    required le_uint16 version = 1
    required le_uint16 flags = 0
        COMPRESSED = 0x0001
        ENCRYPTED  = 0x0002
    required le_uint32 payload_len = 0
    required le_uint32 checksum = 0
    required bytes<16> session_id
end
```

```
pcapsh >>> WinMsg(version=2, flags=COMPRESSED, payload_len=128)
pcapsh >>> hexdump(IP()/TCP(dport=8443,flags="PA",seq=1,ack=1)/WinMsg(flags=ENCRYPTED,payload_len=256))
```

### Example: network sensor beacon with MAC address field

```
protocol SensorBeacon
    required mac     sensor_mac = 00:00:00:00:00:00
    required ip4     sensor_ip  = 0.0.0.0
    required uint32  uptime_sec = 0
    required uint16  battery_mv = 3300
    required uint8   signal_dbm = 0
    required uint8   seq = 0
end
```

```
pcapsh >>> SensorBeacon(sensor_mac="aa:bb:cc:dd:ee:ff", sensor_ip="192.168.1.50", battery_mv=3150, seq=1)
pcapsh >>> wrpcap("sensors.pcapng", IP(src="192.168.1.50",dst="255.255.255.255")/UDP(dport=6666)/SensorBeacon(sensor_mac="aa:bb:cc:dd:ee:ff",sensor_ip="192.168.1.50",uptime_sec=86400,seq=1))
```

---

## Part 10 — Persistent protocol library

Protocols you define in the REPL are gone when you exit. To make them permanent,
save them to `~/.pcapsh_protos.posa`:

```
# ~/.pcapsh_protos.posa

Object<main> TLV
    required uint8  tag = 0
        HEARTBEAT = 1
        DATA      = 2
    required uint8  flags = 0
    required uint16 length = 0
    required uint32 sequence = 0

Object<main> SensorBeacon
    required mac    sensor_mac = 00:00:00:00:00:00
    required ip4    sensor_ip  = 0.0.0.0
    required uint32 uptime_sec = 0
    required uint16 battery_mv = 3300
    required uint8  signal_dbm = 0
    required uint8  seq = 0
```

pcapsh loads this file automatically at startup. You can also load any `.posa` file
on demand:

```
pcapsh >>> load("myprotos.posa")
pcapsh -p myprotos.posa
```

The format for `.posa` files is the same as the `protocol ... end` block, but using
the posa `Object<main> NAME` header instead of `protocol NAME` / `end`.

### Grouping sub-protocols with `Object<parent>`

Use `Object<parent>` to group related sub-protocols under a common dispatch name.
pcapsh then dispatches `show("…/PARENT", data)` automatically by reading the first
field and matching it to each sub-protocol's default value:

```
# Two message types that share a "Msg" namespace
Object<Msg> Msg_Hello
    required uint8 type = 1
    required uint16 seq = 0

Object<Msg> Msg_Bye
    required uint8 type = 2
    required uint16 code = 0
```

```
pcapsh >>> show("Msg", fromhex("01 00 07"))   # → <Msg_Hello type=1 seq=7 |
pcapsh >>> show("Msg", fromhex("02 00 01"))   # → <Msg_Bye   type=2 code=1 |
pcapsh >>> ls(Msg)
Msg sub-protocols:
  Msg_Hello            (first field type = 1)
  Msg_Bye              (first field type = 2)
```

The nesting can be arbitrary: `Object<Msg_Hello>` would group sub-types of `Msg_Hello`.
Sub-protocols can still be named directly: `show("Msg_Hello", data)` always works.

---

## Part 11 — Complete example: custom protocol simulation

Let's put it all together. We'll define a simple sensor network protocol, build packets
representing a real scenario, and write a capture file for analysis.

Save this as `sensor_sim.pcapsh`:

```sh
# sensor_sim.pcapsh — simulated IoT sensor mesh

# Define the protocol
protocol SensorMsg
    required uint8  msg_type = 0
        REGISTER = 0
        READING  = 1
        ALERT    = 2
        ACK      = 3
    required uint8  sensor_id = 0
    required uint16 seq = 0
    required uint32 value = 0
    required uint16 battery_mv = 3300
end

# Sensor registers with gateway
wrpcap("sensor.pcapng", IP(src="192.168.1.10",dst="192.168.1.1")/UDP(sport=5000,dport=5000)/SensorMsg(msg_type=REGISTER,sensor_id=1,seq=1))
wrpcap("sensor.pcapng", IP(src="192.168.1.1",dst="192.168.1.10")/UDP(sport=5000,dport=5000)/SensorMsg(msg_type=ACK,sensor_id=1,seq=1))

# Sensor sends readings
wrpcap("sensor.pcapng", IP(src="192.168.1.10",dst="192.168.1.1")/UDP(sport=5000,dport=5000)/SensorMsg(msg_type=READING,sensor_id=1,seq=2,value=2450,battery_mv=3300))
wrpcap("sensor.pcapng", IP(src="192.168.1.10",dst="192.168.1.1")/UDP(sport=5000,dport=5000)/SensorMsg(msg_type=READING,sensor_id=1,seq=3,value=2480,battery_mv=3290))
wrpcap("sensor.pcapng", IP(src="192.168.1.10",dst="192.168.1.1")/UDP(sport=5000,dport=5000)/SensorMsg(msg_type=READING,sensor_id=1,seq=4,value=2510,battery_mv=3280))

# Sensor triggers an alert
wrpcap("sensor.pcapng", IP(src="192.168.1.10",dst="192.168.1.1")/UDP(sport=5000,dport=5000)/SensorMsg(msg_type=ALERT,sensor_id=1,seq=5,value=9999,battery_mv=3270))
wrpcap("sensor.pcapng", IP(src="192.168.1.1",dst="192.168.1.10")/UDP(sport=5000,dport=5000)/SensorMsg(msg_type=ACK,sensor_id=1,seq=5))
```

Run it:

```
./build/bin/pcapsh sensor_sim.pcapsh
```

Open `sensor.pcapng` in Wireshark. You'll see 7 UDP packets. Wireshark won't know
the SensorMsg layer — but if you add a custom Lua dissector, or just use the raw bytes,
you can verify every field by comparing to the hexdump:

```
./build/bin/pcapsh -e 'hexdump(IP()/UDP(dport=5000)/SensorMsg(msg_type=READING,sensor_id=1,seq=2,value=2450,battery_mv=3300))'
```

---

## Part 12 — Parsing Wireshark hex dumps

`fromhex()` and `show()` let you paste captured bytes straight into pcapsh for inspection,
without writing a full dissector.

### fromhex() — three input formats

```
# plain hex stream (e.g. from tshark -T fields -e data.data)
d = fromhex("0001010000010000000000000000")

# space-separated bytes
d = fromhex("00 01 01 00 00 01 00 00 00 00 00 00")

# Wireshark full hex dump (with offset column and ASCII column — paste as-is)
d = fromhex("0000   45 00 00 34 00 01 00 00  40 11 f6 c4 c0 a8 01 05   E..4....@.......
0010   08 08 08 08 c3 a8 00 35  00 20 41 a1 12 34 01 00   .......5. A..4..
0020   00 01 00 00 00 00 00 00                            ........")
```

### show() — walk a protocol stack

Specify the layers with `/`. Each layer is printed and its header consumed before the next:

```
show("IP/UDP/DNS", d)
# <IP src=192.168.1.5 dst=8.8.8.8 ttl=64 proto=17(UDP) len=52 |
# <UDP sport=50088 dport=53 len=32 |
# <DNS id=4660 flags=0x0100 qdcount=1 ancount=0 nscount=0 arcount=0 |
```

IP's header length comes from the actual IHL field in the bytes, so IP options are handled
correctly. TCP's data-offset field works the same way.

If you only have the payload (no IP/UDP prefix), omit those layers:

```
d_dns_only = fromhex("00 01 01 00 00 01 00 00 00 00 00 00")
show("DNS", d_dns_only)
# <DNS id=1 flags=0x0100 qdcount=1 ancount=0 nscount=0 arcount=0 |
```

### show() with a custom inline protocol

Define the layout first, then place it last in the stack:

```
protocol IoTReading
    required uint8  sensor_type = 0
        TEMP     = 1
        HUMIDITY = 2
        PRESSURE = 3
    required uint16 value = 0
    required uint8  battery_pct = 0
    required uint32 timestamp = 0
end

# Payload-only bytes (no transport headers)
show("IoTReading", fromhex("01 01 0e 5a 00 67 04 d9"))
# <IoTReading sensor_type=TEMP(1) value=270 battery_pct=103 timestamp=1241 |

# Full IP/UDP capture with custom payload
show("IP/UDP/IoTReading", fromhex("45 00 00 24 ... 01 01 0e 5a 00 67 04 d9"))
```

### Full workflow: capture → inspect → replay

```
# 1. Paste a Wireshark hex dump — full packet including IP/TCP headers
payload = fromhex("45 00 00 30 00 01 40 00 40 06 00 00 0a 00 00 01 0a 00 00 02
                   c3 a8 1f 90 00 00 00 01 00 00 00 00 50 18 20 00 00 00 00 00
                   ef be ad de 03 00 02 00 80 00 00 00")

# 2. Define the application-layer protocol
protocol WinHdr
    required le_uint32 magic = 0
    required le_uint16 version = 0
    required le_uint16 flags = 0
        COMPRESSED = 1
        ENCRYPTED  = 2
    required le_uint32 length = 0
end

# 3. Inspect the full stack — IP and TCP headers are skipped automatically
show("IP/TCP/WinHdr", payload)
# <IP src=10.0.0.1 dst=10.0.0.2 ttl=64 proto=6(TCP) len=48 |
# <TCP sport=50088 dport=8080 seq=1 ack=0 flags=AP |
# <WinHdr magic=3735928559 version=3 flags=ENCRYPTED(2) length=128 |

# 4. Build a modified variant and write it to a pcapng
s = TCPSession("10.0.0.1", "10.0.0.2", 54321, 8080)
wrpcap("replay.pcapng", syn(s))
wrpcap("replay.pcapng", syn_ack(s))
wrpcap("replay.pcapng", tcp_ack(s))
wrpcap("replay.pcapng", client_send(s, WinHdr(flags=COMPRESSED, length=64)))
```

---

## Part 13 — Reading pcapng files and looping

`frompcapng()` extracts a single packet's raw bytes from a pcapng file by 1-based packet
number. The result is identical to `fromhex()` output — pipe it straight into `show()`,
`hexdump()`, or `raw()`.

```
# Get packet 1 (the first packet)
show("Ether/IP/UDP", frompcapng("capture.pcapng", 1))

# Keyword form is also accepted
show("Ether/IP/TCP", frompcapng("capture.pcapng", packet_number=3))
```

### for $i in range(N): — loop over packets

pcapsh has a Python-style for-loop. Loop variables use a `$` prefix. `range(N)` starts at
**1** (not 0) and runs N times, matching `frompcapng`'s 1-based packet numbering.

```
# Inspect every packet in a capture (packets 1 through 100)
for $i in range(100):
    show("Ether/IP", frompcapng("capture.pcapng", $i))
```

`range(start, stop)` and `range(start, stop, step)` work like Python — exclusive stop:

```
# Packets 5 through 9
for $i in range(5, 10):
    hexdump(frompcapng("capture.pcapng", $i))

# Reverse: packets 10 down to 1
for $i in range(10, 0, -1):
    show("Ether/IP/TCP", frompcapng("capture.pcapng", $i))
```

`$i` works in protocol field arguments too:

```
# Write 10 ICMP echo requests with incrementing sequence numbers
for $i in range(10):
    wrpcap("pings.pcapng", IP(dst="8.8.8.8")/ICMP(type=8,seq=$i))
```

### Full analysis workflow

```
# 1. Capture or copy a pcapng file — e.g. exported from Wireshark
# 2. Inspect a specific packet
show("Ether/IP/UDP/DNS", frompcapng("dns_traffic.pcapng", 1))

# 3. Loop over all packets with a custom protocol dissector
protocol DNSMsg
    required uint16 txid = 0
    required uint16 flags = 0
end

for $i in range(50):
    show("Ether/IP/UDP/DNSMsg", frompcapng("dns_traffic.pcapng", $i))
```

In script mode the loop body ends at the first non-indented line (same as Python).
In the interactive REPL a blank line ends the body.

---

## Recap

| Task | Expression |
|------|-----------|
| Build a packet | `IP(dst="8.8.8.8")/TCP(dport=443,flags="S")` |
| Inspect fields | `ls(DNS)`, `ls(SMB2)` |
| Hex dump | `hexdump(IP()/UDP()/DNS(rd=1,qd=DNSQR(qname="x.com")))` |
| Write to pcapng | `wrpcap("out.pcapng", pkt)` |
| TCP session | `s = TCPSession("1.2.3.4","5.6.7.8",4444,80)` then `syn(s)`, `client_send(s,"data")` |
| DNS query | `DNS(id=RandShort(),rd=1,qd=DNSQR(qname="example.com"))` |
| DNS response | `DNS(qr=1,rd=1,ra=1,an=DNSRR(rrname="x.com",type=A,ttl=300,rdata="1.2.3.4"),ancount=1)` |
| Define protocol | `protocol Foo` / `required uint16 x = 0` / `end` |
| Load from file | `load("myprotos.posa")` or `pcapsh -p file.posa` |
| Run a script | `pcapsh script.pcapsh` |
| One-liner | `pcapsh -e 'hexdump(IP()/TCP())'` |
| Parse hex dump | `show("IP/UDP/DNS", fromhex("..."))` |
| Inspect custom | `show("IP/TCP/MyProto", fromhex("..."))` |
| Payload only | `show("MyProto", fromhex("01 00 64"))` |
| Read from pcapng | `frompcapng("file.pcapng", N)` or `frompcapng("file.pcapng", packet_number=N)` |
| Loop N times | `for $i in range(N):` (1-based; body indented) |
| Loop slice | `for $i in range(start, stop):` or `for $i in range(start, stop, step):` |

Full field reference: see [bin/pcapsh.md](bin/pcapsh.md).
