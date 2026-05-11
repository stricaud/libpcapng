# pcapsh — Interactive Packet Shell

`pcapsh` is a Scapy-inspired interactive shell and scripting language for building, inspecting,
and writing network packets using libpcapng. Packets are described with a concise expression
syntax; the output is always a valid pcapng file that tshark, Wireshark, and tcpdump can read.

---

## Running pcapsh

```
pcapsh                        # interactive REPL
pcapsh script.pcapsh          # run a script file non-interactively
pcapsh -e "EXPR"              # evaluate one expression and exit
pcapsh -p extra.posa          # load additional protocol definitions
pcapsh my.posa script.pcapsh  # load posa then run script
```

In script mode there is no banner or prompt. Comments (`#`) and blank lines are ignored.
`exit()` and `quit()` in a script file terminate immediately.

---

## Expression Syntax

### Packet construction

Stack layers with `/`:

```
IP()
Ether()/IP()/TCP()
IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="example.com"))
IP(src="10.0.0.1")/TCP(dport=443,flags="S")
```

### Assignment

```
a = IP()/TCP()
b = Ether(src="aa:bb:cc:dd:ee:ff")/IP(dst="1.2.3.4")/UDP()
```

### String payload

A quoted string after `/` becomes a Raw layer:

```
IP()/TCP()/"GET / HTTP/1.0\r\n\r\n"
IP()/UDP(dport=514)/SYSLOG()/"<34>Oct 11 22:14:15 mymachine su: 'su root' failed"
```

### Comments

```
# this is a comment
a = IP()   # inline comment
```

### Escape sequences in strings

Inside quoted strings: `\r` → CR, `\n` → LF, `\t` → tab, `\xNN` → hex byte, `\\` → backslash.

### Arithmetic in field values

Numeric field values accept `+`, `-`, and `*` expressions. Operands can be integer
literals, hex literals, or `$variables`:

```
UDP(sport=49000+7)              # → sport=49007
TCP(seq=1+$i*68)                # → seq varies with loop variable
UDP(sport=0xC000+3)             # → sport=49155
IP(id=0x100*2+1)                # → id=513
```

Operator precedence follows standard rules: `*` binds tighter than `+`/`-`.
Division inside field values is not supported (the `/` character is reserved for
layer stacking).

---

## Scripting

### Variables

Variables are assigned with `=`. A variable can hold a packet, raw bytes, a
TCPSession, or a numeric value. In scripts, numeric variables are most commonly
set by for-loop counters.

```
a = Ether()/IP()/TCP()        # packet variable
n = 42                        # numeric variable
wrpcap("out.pcapng", a)
hexdump(a)
```

### For-loops

```
for $varname in range(stop):
    BODY_LINE
    BODY_LINE
```

- `$varname` is set to **1, 2, … stop** (inclusive) on each iteration.
- Body lines must be indented with at least one space or tab.
- An empty line or an un-indented line ends the loop body.

**range variants:**

| Form | Values |
|------|--------|
| `range(N)` | 1, 2, … N |
| `range(start, stop)` | start, start+1, … stop-1 |
| `range(start, stop, step)` | start, start+step, … while < stop |

**Notes:**
- `$varname` substitutes **only into numeric fields** — it cannot be interpolated
  into string fields such as IP addresses or MAC addresses.
- Combine with arithmetic to avoid low well-known port numbers:
  `sport=49000+$i` instead of `sport=$i`.

**Examples:**

```
# 20 NTP requests from ports 49152-49171
for $i in range(20):
    wrpcap("ntp.pcapng", Ether()/IP()/UDP(sport=49151+$i,dport=123)/NTP(li_vn_mode=CLIENT))

# DNS queries with varying transaction IDs
for $i in range(10):
    wrpcap("dns.pcapng", IP()/UDP(dport=53)/DNS(id=$i,rd=1,qd=DNSQR(qname="example.com")))

# Explicit start and step
for $i in range(1, 100, 10):
    wrpcap("out.pcapng", UDP(sport=5000+$i,dport=9000))
```

### Inline protocol definition

Define a protocol directly inside a script or the REPL without a separate `.posa` file:

```
protocol NAME
    required TYPE fieldname = default
        ENUM_NAME = value
    required TYPE field2 = default
end
```

The protocol is immediately available as `NAME(...)` and visible in `ls()`.

```
protocol MyHdr
    required uint8  version = 1
    required uint8  flags = 0
        FLAG_URGENT = 0x01
        FLAG_RETRY  = 0x02
    required uint16 length = 0
    required uint32 session_id = 0
end

hexdump(IP()/UDP(dport=9000)/MyHdr(flags=FLAG_URGENT, session_id=0xdeadbeef))
wrpcap("custom.pcapng", Ether()/IP()/UDP(dport=9000)/MyHdr(version=2))
```

---

## Built-in Protocols

All built-in protocols are implemented natively in C with proper checksum and length
computation. The protocol registry lets you add new protocols (via posa) or inspect the
full list with `ls()` — no switch statements to maintain.

### Ether

```
Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55", type=0x0800)
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| dst   | mac  | ff:ff:ff:ff:ff:ff | destination MAC |
| src   | mac  | 00:00:00:00:00:00 | source MAC |
| type  | int  | auto | 0x0800=IP, 0x0806=ARP, 0x86DD=IPv6 |

### IP

```
IP(src="192.168.1.1", dst="8.8.8.8", ttl=64)
```

| Field  | Type | Default   | Notes |
|--------|------|-----------|-------|
| src    | ip4  | 127.0.0.1 | source IP |
| dst    | ip4  | 127.0.0.1 | destination IP |
| ttl    | int  | 64        | time to live |
| proto  | int  | auto      | 6=TCP, 17=UDP, 1=ICMP |
| id     | int  | 1         | identification |
| flags  | int  | 0         | 0x02=DF, 0x01=MF |
| frag   | int  | 0         | fragment offset |
| tos    | int  | 0         | type of service |
| len    | int  | auto      | total length |
| chksum | int  | auto      | header checksum |

### TCP

```
TCP(sport=12345, dport=80, seq=100, ack=0, flags="S")
TCP(flags="PA")    # PSH+ACK
TCP(flags=0x12)    # SYN+ACK numeric
```

| Field   | Type | Default | Notes |
|---------|------|---------|-------|
| sport   | int  | 20      | source port |
| dport   | int  | 80      | destination port |
| seq     | int  | 0       | sequence number |
| ack     | int  | 0       | acknowledgement number |
| flags   | str  | S       | F=FIN S=SYN R=RST P=PSH A=ACK U=URG |
| window  | int  | 8192    | window size |
| dataofs | int  | 5       | header length in 32-bit words |
| chksum  | int  | auto    | checksum |
| urgptr  | int  | 0       | urgent pointer |

### UDP

```
UDP(sport=5000, dport=53)
```

| Field  | Type | Default | Notes |
|--------|------|---------|-------|
| sport  | int  | 53      | source port |
| dport  | int  | 53      | destination port |
| len    | int  | auto    | length |
| chksum | int  | auto    | checksum |

### ICMP

```
ICMP(type=8, code=0, id=1, seq=1)
ICMP(type=0)   # echo reply
```

| Field  | Type | Default | Notes |
|--------|------|---------|-------|
| type   | int  | 8       | 8=echo request, 0=echo reply |
| code   | int  | 0       | |
| id     | int  | 0       | identifier |
| seq    | int  | 0       | sequence number |
| chksum | int  | auto    | checksum |

### Raw

```
Raw(load="hello\r\n")
IP()/TCP()/"binary\x00payload"
```

---

## DNS (Native)

DNS is a first-class built-in protocol with named fields and proper wire-format encoding.
`DNS()` displays field names just like any other protocol, and serializes correctly when
stacked under UDP or TCP.

### DNS()

```
DNS()
DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com"))
DNS(qr=1, id=0xabcd, an=DNSRR(rrname="example.com", type=1, ttl=300, rdata="93.184.216.34"), ancount=1)
```

| Field   | Type | Default | Notes |
|---------|------|---------|-------|
| id      | int  | random  | transaction ID; use `RandShort()` for random |
| flags   | int  | 0       | raw flags word (overrides individual bits) |
| qr      | bit  | 0       | 0=query, 1=response |
| opcode  | int  | 0       | 0=QUERY, 1=IQUERY, 2=STATUS |
| aa      | bit  | 0       | authoritative answer |
| tc      | bit  | 0       | truncated |
| rd      | bit  | 0       | recursion desired |
| ra      | bit  | 0       | recursion available (server sets) |
| rcode   | int  | 0       | 0=NOERROR, 1=FORMERR, 2=SERVFAIL, 3=NXDOMAIN |
| qdcount | int  | 0       | question count (auto-incremented when qd= is set) |
| ancount | int  | 0       | answer RR count |
| nscount | int  | 0       | authority RR count |
| arcount | int  | 0       | additional RR count |
| qd      | —    | —       | question section — takes a DNSQR(...) |
| an      | —    | —       | answer section — takes a DNSRR(...) |
| ns      | —    | —       | authority section — takes a DNSRR(...) |
| ar      | —    | —       | additional section — takes a DNSRR(...) |

### DNSQR()

Encodes a DNS question record in wire format.

```
DNSQR(qname="example.com")
DNSQR(qname="mail.google.com", qtype=MX, qclass=IN)
DNSQR(qname="1.2.3.4.in-addr.arpa", qtype=PTR)
```

| Arg    | Default | Notes |
|--------|---------|-------|
| qname  | ""      | dotted domain name — encoded as DNS labels |
| qtype  | A       | A=1, NS=2, CNAME=5, SOA=6, PTR=12, MX=15, AAAA=28, ANY=255 |
| qclass | IN (1)  | IN=1 |

### DNSRR()

Encodes a DNS resource record in wire format.

```
DNSRR(rrname="example.com", type=A, ttl=300, rdata="1.2.3.4")
DNSRR(rrname="www.example.com", type=CNAME, ttl=3600, rdata="example.com")
DNSRR(rrname="example.com", type=MX, ttl=3600, rdata="mail.example.com")
DNSRR(rrname="example.com", type=NS, ttl=172800, rdata="ns1.example.com")
```

| Arg    | Default | Notes |
|--------|---------|-------|
| rrname | ""      | owner name |
| type   | A (1)   | record type — same names as DNSQR qtype |
| rclass | IN (1)  | |
| ttl    | 0       | time to live in seconds |
| rdata  | ""      | for A: dotted IPv4; for CNAME/NS/MX/PTR: dotted domain name |

### RandShort()

Returns a random uint16, useful for DNS transaction IDs.

```
DNS(id=RandShort(), rd=1, qd=DNSQR(qname="example.com"))
```

### DNS Examples

**Standard recursive query:**
```
IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=5353,dport=53)/DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com"))
```

**DNS query for MX record:**
```
IP(dst="8.8.8.8")/UDP(dport=53)/DNS(id=RandShort(), rd=1, qd=DNSQR(qname="gmail.com", qtype=MX))
```

**DNS response with A record:**
```
IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53, dport=5353)/DNS(id=0x1234, qr=1, rd=1, ra=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", type=A, ttl=300, rdata="93.184.216.34"), qdcount=1, ancount=1)
```

**NXDOMAIN response:**
```
IP(src="8.8.8.8", dst="192.168.1.10")/UDP(sport=53, dport=5353)/DNS(id=0x5678, qr=1, rd=1, ra=1, rcode=3)
```

**Full query + response pair written to pcapng:**
```
# dns_exchange.pcapsh
wrpcap("dns.pcapng", IP(src="192.168.1.10",dst="8.8.8.8")/UDP(sport=54321,dport=53)/DNS(id=0x1111,rd=1,qd=DNSQR(qname="example.com")))
wrpcap("dns.pcapng", IP(src="8.8.8.8",dst="192.168.1.10")/UDP(sport=53,dport=54321)/DNS(id=0x1111,qr=1,rd=1,ra=1,qd=DNSQR(qname="example.com"),an=DNSRR(rrname="example.com",type=A,ttl=300,rdata="93.184.216.34"),qdcount=1,ancount=1))
```

---

## Dynamic Protocols (posa-defined)

These are loaded from the built-in definitions and from `~/.pcapsh_protos.posa`.
Use `ls()` to list all available protocols; use `ls(PROTO)` for field details.

### ARP

```
Ether(type=0x0806)/ARP(op=REQUEST, spa="192.168.1.1", tpa="192.168.1.254")
Ether()/ARP(op=REPLY, sha="aa:bb:cc:dd:ee:ff", spa="192.168.1.1", tha="bb:cc:dd:ee:ff:00", tpa="192.168.1.2")
```

| Field | Type   | Default           | Enums |
|-------|--------|-------------------|-------|
| htype | uint16 | 1                 | ETHERNET=1 |
| ptype | uint16 | 0x0800            | IPV4=0x0800 |
| hlen  | uint8  | 6                 | |
| plen  | uint8  | 4                 | |
| op    | uint16 | 1                 | REQUEST=1, REPLY=2 |
| sha   | mac    | 00:00:00:00:00:00 | sender MAC |
| spa   | ip4    | 0.0.0.0           | sender IP |
| tha   | mac    | 00:00:00:00:00:00 | target MAC |
| tpa   | ip4    | 0.0.0.0           | target IP |

### NTP

```
IP(src="10.0.0.1", dst="pool.ntp.org")/UDP(sport=12345, dport=123)/NTP(li_vn_mode=CLIENT)
IP(src="pool.ntp.org", dst="10.0.0.1")/UDP(sport=123, dport=12345)/NTP(li_vn_mode=SERVER, stratum=1)
```

| Field           | Type   | Default | Enums |
|-----------------|--------|---------|-------|
| li_vn_mode      | uint8  | 0x1b    | CLIENT=0x1b, SERVER=0x1c |
| stratum         | uint8  | 0       | |
| poll            | uint8  | 4       | |
| precision       | uint8  | 0xfa    | |
| root_delay      | uint32 | 0       | |
| root_dispersion | uint32 | 0       | |
| ref_id          | uint32 | 0       | |
| ref_ts_s/f      | uint32 | 0       | reference timestamp (seconds / fraction) |
| orig_ts_s/f     | uint32 | 0       | originate timestamp |
| recv_ts_s/f     | uint32 | 0       | receive timestamp |
| tx_ts_s/f       | uint32 | 0       | transmit timestamp |

### DHCP

```
IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/DHCP(op=BOOTREQUEST,xid=0x12345678)
```

| Field  | Type       | Default   | Enums |
|--------|------------|-----------|-------|
| op     | uint8      | 1         | BOOTREQUEST=1, BOOTREPLY=2 |
| htype  | uint8      | 1         | |
| hlen   | uint8      | 6         | |
| hops   | uint8      | 0         | |
| xid    | uint32     | 0         | transaction ID |
| secs   | uint16     | 0         | |
| flags  | uint16     | 0         | |
| ciaddr | ip4        | 0.0.0.0   | client IP |
| yiaddr | ip4        | 0.0.0.0   | your (assigned) IP |
| siaddr | ip4        | 0.0.0.0   | server IP |
| giaddr | ip4        | 0.0.0.0   | relay agent IP |
| chaddr | bytes<16>  | zeros     | client hardware address |
| sname  | bytes<64>  | zeros     | server host name |
| file   | bytes<128> | zeros     | boot file name |

### GRE

```
IP(proto=47)/GRE(proto=IPV4)/IP(dst="10.0.0.1")/TCP()
```

| Field     | Type   | Default | Enums |
|-----------|--------|---------|-------|
| flags_ver | uint16 | 0       | |
| proto     | uint16 | 0x0800  | IPV4=0x0800, IPV6=0x86DD, MPLS=0x8847 |

### VXLAN

```
IP(src="10.0.0.1",dst="10.0.0.2")/UDP(dport=4789)/VXLAN()/Ether()/IP()/TCP()
```

| Field     | Type     | Default | Notes |
|-----------|----------|---------|-------|
| flags     | uint8    | 0x08    | I-bit set |
| reserved1 | bytes<3> | zeros   | |
| vni       | bytes<3> | zeros   | virtual network identifier |
| reserved2 | uint8    | 0       | |

### RADIUS

```
IP(src="10.0.0.1",dst="10.0.0.2")/UDP(sport=49152,dport=1812)/RADIUS(code=ACCESS_REQUEST, identifier=1, length=20)
```

| Field         | Type      | Default | Enums |
|---------------|-----------|---------|-------|
| code          | uint8     | 1       | ACCESS_REQUEST=1, ACCESS_ACCEPT=2, ACCESS_REJECT=3, ACCOUNTING_REQUEST=4, ACCOUNTING_RESPONSE=5 |
| identifier    | uint8     | 0       | |
| length        | uint16    | 20      | |
| authenticator | bytes<16> | zeros   | |

### SYSLOG

> **Note:** The `SYSLOG()` object emits only the PRI byte (one byte encoding facility
> and severity). It does **not** produce a complete RFC 3164 or RFC 5424 message body
> (no timestamp, hostname, or message text), so Wireshark will report
> *"Message conforms to neither RFC 5424 nor RFC 3164"*.
>
> For RFC 3164-compliant output, use a raw string payload instead:
>
> ```
> # facility=4 (auth), severity=INFO=6 → PRI = 4*8+6 = 38
> IP(src="10.0.0.1",dst="10.0.0.2")/UDP(dport=514)/"<38>May 11 10:00:01 host tag: message"
> ```
>
> The `SYSLOG()` object is useful when you only need to mark the protocol for
> custom dissectors or tooling that does not validate the message body:
>
> ```
> IP(src="10.0.0.1",dst="10.0.0.2")/UDP(dport=514)/SYSLOG(severity=WARNING, facility=1)
> ```

| Field    | Type   | Default | Enums |
|----------|--------|---------|-------|
| severity | uint8  | 6       | EMERGENCY=0, ALERT=1, CRITICAL=2, ERROR=3, WARNING=4, NOTICE=5, INFO=6, DEBUG=7 |
| facility | uint8  | 1       | User=1, Mail=2, Daemon=3, Auth=4, Syslog=5, LPR=6, News=7 |
| message  | string | ""      | (not included in wire output — use raw string for full RFC 3164 body) |

**RFC 3164 PRI calculation:** `PRI = facility × 8 + severity`

| Facility | Code | Severity | Code |
|----------|------|----------|------|
| kernel   | 0    | EMERGENCY | 0  |
| user     | 1    | ALERT     | 1  |
| mail     | 2    | CRITICAL  | 2  |
| daemon   | 3    | ERROR     | 3  |
| auth     | 4    | WARNING   | 4  |
| syslog   | 5    | NOTICE    | 5  |
| lpr      | 6    | INFO      | 6  |
| news     | 7    | DEBUG     | 7  |

### NBT (NetBIOS Session Service)

```
IP()/TCP(dport=139)/NBT(type=SESSION_MESSAGE, length=72)
```

| Field  | Type   | Default | Enums |
|--------|--------|---------|-------|
| type   | uint8  | 0       | SESSION_MESSAGE=0, SESSION_REQUEST=0x81, POSITIVE_SESSION_RESPONSE=0x82, NEGATIVE_SESSION_RESPONSE=0x83, SESSION_KEEPALIVE=0x85 |
| flags  | uint8  | 0       | |
| length | uint16 | 0       | payload length |

### SMB2

SMB2 uses **little-endian** integers for most fields.

```
IP()/TCP(dport=445)/NBT()/SMB2(command=NEGOTIATE)
IP()/TCP(dport=445)/NBT()/SMB2(command=READ, tree_id=1, session_id=0x100)
```

| Field          | Type      | Default    | Notes |
|----------------|-----------|------------|-------|
| magic          | uint32    | 0xFE534D42 | big-endian magic `\xFESMB` |
| structure_size | le_uint16 | 64         | always 64 |
| credit_charge  | le_uint16 | 0          | |
| status         | le_uint32 | 0          | NTSTATUS |
| command        | le_uint16 | 0          | NEGOTIATE=0, SESSION_SETUP=1, LOGOFF=2, TREE_CONNECT=3, TREE_DISCONNECT=4, CREATE=5, CLOSE=6, FLUSH=7, READ=8, WRITE=9, IOCTL=11, CANCEL=12, ECHO=13, QUERY_DIRECTORY=14, QUERY_INFO=16, SET_INFO=17 |
| credit_request | le_uint16 | 0          | |
| flags          | le_uint32 | 0          | |
| next_command   | le_uint32 | 0          | chained requests |
| message_id     | le_uint64 | 0          | |
| process_id     | le_uint32 | 0          | |
| tree_id        | le_uint32 | 0          | |
| session_id     | le_uint64 | 0          | |
| signature      | bytes<16> | zeros      | |

### DCERPC

```
IP()/TCP(dport=135)/DCERPC(type=BIND, call_id=1)
IP()/TCP(dport=135)/DCERPC(type=REQUEST, frag_len=72, call_id=1)
```

| Field     | Type      | Default    | Notes |
|-----------|-----------|------------|-------|
| ver_major | uint8     | 5          | |
| ver_minor | uint8     | 0          | |
| type      | uint8     | 0          | REQUEST=0, RESPONSE=2, FAULT=3, BIND=11, BIND_ACK=12, BIND_NAK=13, ALTER_CONTEXT=14, AUTH3=16 |
| flags     | uint8     | 0x03       | 0x01=FIRST_FRAG, 0x02=LAST_FRAG |
| data_rep  | le_uint32 | 0x10000000 | LE+IEEE+ASCII |
| frag_len  | le_uint16 | 0          | total fragment length |
| auth_len  | le_uint16 | 0          | |
| call_id   | le_uint32 | 1          | |

### LDAP

Simplified 7-byte BER header for basic LDAP operation framing:

```
IP()/TCP(dport=389)/LDAP(op_tag=SEARCH_REQUEST)
IP()/TCP(dport=636)/LDAP(op_tag=BIND_REQUEST, message_id=1)
```

| Field      | Type  | Default | Notes |
|------------|-------|---------|-------|
| seq_tag    | uint8 | 0x30    | SEQUENCE |
| seq_len    | uint8 | 0       | sequence length |
| msgid_tag  | uint8 | 0x02    | INTEGER |
| msgid_len  | uint8 | 0x01    | |
| message_id | uint8 | 1       | |
| op_tag     | uint8 | 0x60    | BIND_REQUEST=0x60, BIND_RESPONSE=0x61, UNBIND_REQUEST=0x42, SEARCH_REQUEST=0x63, SEARCH_RESULT_ENTRY=0x64, SEARCH_RESULT_DONE=0x65, MODIFY_REQUEST=0x66, MODIFY_RESPONSE=0x67, ADD_REQUEST=0x68, ADD_RESPONSE=0x69, DEL_REQUEST=0x4A, DEL_RESPONSE=0x6B |
| op_len     | uint8 | 0       | operation length |

### NBNS (NetBIOS Name Service)

NetBIOS Name Service — RFC 1001/1002, **UDP port 137**.
This is the layer-3 name resolution protocol used in Windows networks (distinct from
NBT Session Service on TCP 139, which is the `NBT` built-in).

```
# Name query broadcast (who has FILESERVER?)
Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="10.0.1.1",dst="10.0.1.255")/UDP(sport=137,dport=137)/NBNS(trans_id=0x1234,flags=NAME_QUERY_REQUEST,qdcount=1)

# Name registration (workstation announces itself)
Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="10.0.1.5",dst="10.0.1.255")/UDP(sport=137,dport=137)/NBNS(flags=NAME_REGISTRATION_REQUEST,qdcount=1,arcount=1)

# Positive query response
Ether()/IP(src="10.0.0.1",dst="10.0.1.1")/UDP(sport=137,dport=137)/NBNS(trans_id=0x1234,flags=NAME_QUERY_RESPONSE_POS,ancount=1)
```

| Field    | Type   | Default | Notes |
|----------|--------|---------|-------|
| trans_id | uint16 | 0       | echoed in responses |
| flags    | uint16 | 0x0110  | see enum table below |
| qdcount  | uint16 | 1       | question count |
| ancount  | uint16 | 0       | answer records |
| nscount  | uint16 | 0       | authority records |
| arcount  | uint16 | 0       | additional records |
| queries  | payload| —       | NetBIOS-encoded names and resource records |

**flags enum values:**

| Constant | Value | Description |
|----------|-------|-------------|
| NAME_QUERY_REQUEST | 0x0110 | R=0, RD=1, B=1 — broadcast query |
| NAME_QUERY_UNICAST | 0x0100 | R=0, RD=1 — unicast query to WINS |
| NAME_QUERY_RESPONSE_POS | 0x8500 | R=1, AA=1, RD=1, RA=1 — positive |
| NAME_QUERY_RESPONSE_NEG | 0x8506 | R=1, AA=1, RA=1, RCODE=6 — negative |
| NAME_REGISTRATION_REQUEST | 0x2910 | R=0, OPCODE=5, RD=1, B=1 |
| NAME_REGISTRATION_RESPONSE | 0xAD10 | R=1, OPCODE=5, AA=1, RD=1 |
| NAME_RELEASE_REQUEST | 0x3000 | R=0, OPCODE=6, B=1 |
| NAME_RELEASE_RESPONSE | 0xB800 | R=1, OPCODE=6, AA=1 |
| NAME_WACK | 0xBC10 | R=1, OPCODE=7, AA=1, RD=1, B=1 |
| NAME_REFRESH_REQUEST | 0x4108 | R=0, OPCODE=8, RD=1, B=1 |

### KRB5 (Kerberos 5)

Kerberos 5 — RFC 4120, **TCP or UDP port 88**.

The `KRB5` object models the fixed-position ASN.1 DER bytes that appear at the start
of every Kerberos PDU: the 4-byte TCP record mark, APPLICATION tag, outer length, SEQUENCE
wrapper, `pvno` (always 5), and `msg-type`. The variable body (PA-DATA, KDC-REQ-BODY,
EncryptedData, error fields, etc.) is captured in the trailing `payload body` field.

Total fixed header size: **18 bytes**.

On **TCP**, each KRB5 PDU is preceded by a 4-byte big-endian length (`record_mark`).
On **UDP**, set `record_mark=0` — it occupies no wire space and can be ignored.

```
# AS-REQ (client → KDC, TCP)
IP(src="10.0.1.1",dst="10.0.0.1")/TCP(dport=88,flags="PA",seq=1,ack=1)/KRB5(app_tag=AS_REQ,msg_type=AS_REQUEST)

# KRB-ERROR PREAUTH_REQUIRED (KDC → client)
IP(src="10.0.0.1",dst="10.0.1.1")/TCP(sport=88,flags="PA",seq=1,ack=19)/KRB5(app_tag=KRB_ERROR,msg_type=KRB_ERROR_VAL)

# TGS-REP (KDC → client)
IP(src="10.0.0.1",dst="10.0.1.1")/TCP(sport=88,flags="PA")/KRB5(app_tag=TGS_REP,msg_type=TGS_REPLY)
```

| Field      | Type   | Default | Notes |
|------------|--------|---------|-------|
| record_mark | uint32 | 0      | TCP: big-endian PDU length; set 0 for UDP or test packets |
| app_tag    | uint8  | 0x6a   | ASN.1 APPLICATION tag (see enum below) |
| body_len   | uint8  | 0      | outer BER/DER length (0 = acceptable for test packets) |
| seq_tag    | uint8  | 0x30   | SEQUENCE wrapper tag |
| seq_len    | uint8  | 0      | |
| ctx1_tag   | uint8  | 0xa1   | CONTEXT [1] — pvno |
| ctx1_len   | uint8  | 0x03   | |
| pvno_tag   | uint8  | 0x02   | UNIVERSAL INTEGER |
| pvno_len   | uint8  | 0x01   | |
| pvno       | uint8  | 5      | Kerberos protocol version (always 5) |
| ctx2_tag   | uint8  | 0xa2   | CONTEXT [2] — msg-type |
| ctx2_len   | uint8  | 0x03   | |
| mtype_tag  | uint8  | 0x02   | UNIVERSAL INTEGER |
| mtype_len  | uint8  | 0x01   | |
| msg_type   | uint8  | 10     | message type (see enum below) |
| body       | payload| —      | PA-DATA, KDC-REQ-BODY, EncryptedData, etc. |

**app_tag enum values:**

| Constant | Value | Description |
|----------|-------|-------------|
| AS_REQ   | 0x6a  | [APPLICATION 10] Authentication Service Request |
| AS_REP   | 0x6b  | [APPLICATION 11] Authentication Service Reply |
| TGS_REQ  | 0x6c  | [APPLICATION 12] Ticket-Granting Service Request |
| TGS_REP  | 0x6d  | [APPLICATION 13] Ticket-Granting Service Reply |
| AP_REQ   | 0x6e  | [APPLICATION 14] Application Request |
| AP_REP   | 0x6f  | [APPLICATION 15] Application Reply |
| KRB_SAFE | 0x74  | [APPLICATION 20] Integrity-protected message |
| KRB_PRIV | 0x75  | [APPLICATION 21] Encrypted message |
| KRB_CRED | 0x76  | [APPLICATION 22] Credential forwarding |
| KRB_ERROR | 0x7e | [APPLICATION 30] Error reply |

**msg_type enum values:**

| Constant | Value | Description |
|----------|-------|-------------|
| AS_REQUEST | 10 | Authentication Service Request |
| AS_REPLY | 11 | Authentication Service Reply |
| TGS_REQUEST | 12 | Ticket-Granting Service Request |
| TGS_REPLY | 13 | Ticket-Granting Service Reply |
| AP_REQUEST | 14 | Application authentication request |
| AP_REPLY | 15 | Application authentication reply |
| KRB_SAFE_VAL | 20 | Integrity-protected application message |
| KRB_PRIV_VAL | 21 | Encrypted application message |
| KRB_CRED_VAL | 22 | Credential forwarding message |
| KRB_ERROR_VAL | 30 | Error from KDC or application server |

**TCP seq/ack accounting:** each `KRB5()` header serializes to exactly **18 bytes**, so
the next segment's seq/ack advances by 18 per data packet.

---

## TLS (Native)

pcapsh includes built-in TLS 1.2 functions that generate proper TLS handshake and
application-data records. The default cipher is `TLS_NULL_WITH_NULL_NULL` (0x0000) —
no encryption — so Wireshark dissects the inner protocol (LDAP, HTTP, etc.) directly
without needing a key file.

### TLS handshake functions

Each function returns raw bytes that can be stacked directly under a TCP layer:

```
Ether()/IP()/TCP(flags="PA")/TLS_CLIENT_HELLO()
Ether()/IP()/TCP(flags="PA")/TLS_SERVER_HELLO()
Ether()/IP()/TCP(flags="PA")/TLS_CERTIFICATE()
Ether()/IP()/TCP(flags="PA")/TLS_CHANGE_CIPHER_SPEC()
Ether()/IP()/TCP(flags="PA")/TLS_FINISHED()
```

| Function | TLS record type | tcp.len | Notes |
|----------|----------------|---------|-------|
| `TLS_CLIENT_HELLO()` | Handshake (22) | 50 | TLS 1.2, cipher 0x0000, fixed 32-byte client random |
| `TLS_SERVER_HELLO()` | Handshake (22) | 47 | TLS 1.2, cipher 0x0000, fixed 32-byte server random |
| `TLS_CERTIFICATE()`  | Handshake (22) | 12 | Empty certificate list (valid for NULL cipher) |
| `TLS_CHANGE_CIPHER_SPEC()` | ChangeCipherSpec (20) | 6 | Single byte 0x01 |
| `TLS_FINISHED()` | Handshake (22) | 21 | 12-byte verify_data (0xaa × 12) |

### TLS() — application data layer

`TLS()` wraps the payload of whatever comes after it in a TLS Application Data record
(type=0x17, version=TLS 1.2). Use it to enclose an inner protocol inside a TLS stream:

```
Ether()/IP()/TCP(flags="PA")/TLS()/LDAP(op_tag=BIND_REQUEST, message_id=1)
Ether()/IP()/TCP(flags="PA")/TLS()/"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
```

The inner payload is wrapped as-is (NULL cipher — no encryption). Wireshark decodes the
inner content directly without requiring a key file.

### Typical LDAPS session skeleton

```
# TCP handshake
wrpcap("ldaps.pcapng", Ether(src=C,dst=S)/IP(src=ci,dst=si)/TCP(sport=sp,dport=636,seq=csn,flags="S",...))
wrpcap("ldaps.pcapng", Ether(src=S,dst=C)/IP(src=si,dst=ci)/TCP(sport=636,dport=sp,seq=ssn,ack=csn+1,flags="SA",...))
wrpcap("ldaps.pcapng", Ether(src=C,dst=S)/IP(src=ci,dst=si)/TCP(sport=sp,dport=636,seq=csn+1,ack=ssn+1,flags="A"))
# TLS handshake
wrpcap("ldaps.pcapng", .../TCP(seq=csn+1,ack=ssn+1,flags="PA")/TLS_CLIENT_HELLO())   # +50 bytes
wrpcap("ldaps.pcapng", .../TCP(seq=ssn+1,ack=csn+51,flags="PA")/TLS_SERVER_HELLO())  # +47 bytes
wrpcap("ldaps.pcapng", .../TCP(seq=ssn+48,ack=csn+51,flags="PA")/TLS_CERTIFICATE())  # +12 bytes
wrpcap("ldaps.pcapng", .../TCP(seq=csn+51,ack=ssn+60,flags="PA")/TLS_CHANGE_CIPHER_SPEC())  # +6 bytes
wrpcap("ldaps.pcapng", .../TCP(seq=csn+57,ack=ssn+60,flags="PA")/TLS_FINISHED())     # +21 bytes
wrpcap("ldaps.pcapng", .../TCP(seq=ssn+60,ack=csn+78,flags="PA")/TLS_CHANGE_CIPHER_SPEC())  # +6 bytes
wrpcap("ldaps.pcapng", .../TCP(seq=ssn+66,ack=csn+78,flags="PA")/TLS_FINISHED())     # +21 bytes
# LDAP over TLS
wrpcap("ldaps.pcapng", .../TCP(seq=csn+78,ack=ssn+87,flags="PA")/TLS()/LDAP(op_tag=BIND_REQUEST,message_id=1))
```

### Session key output (-s flag)

Running pcapsh with `-s` prints NSS Key Log format to stderr after the script completes.
Since the default cipher is NULL (no encryption), Wireshark decodes the Application Data
payload without a key — the output is informational:

```
pcapsh -s my_tls_session.pcapsh
```

Output (to stderr):
```
# TLS Session Keys (NSS Key Log format)
# Load in Wireshark: Edit > Preferences > Protocols > TLS
# > (Pre)-Master-Secret Log filename
# NOTE: This capture uses TLS_NULL_WITH_NULL_NULL (no encryption).
# Wireshark decodes Application Data directly — no key file needed.
CLIENT_RANDOM 1111...1111 0000...0000
```

The CLIENT_RANDOM is fixed at 32 bytes of `0x11` for reproducibility.

### Full LDAPS DirSync example

See `ldap-controls-dirsync-01.pcapsh` for a complete 18-packet session:
TCP handshake → TLS handshake → LDAP Bind → DirSync SearchRequest → Unbind → TCP close.

```
pcapsh ldap-controls-dirsync-01.pcapsh -o dirsync.pcapng
tshark -r dirsync.pcapng    # shows 18 clean packets, LDAP decoded inside TLS AppData
```

---

## Functions Reference

### hexdump(pkt)

Print a colorized hex dump of the packet bytes.

```
hexdump(IP()/TCP())
hexdump(Ether()/IP()/UDP(dport=53)/DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com")))
a = Ether()/IP()/TCP()/"GET / HTTP/1.0\r\n\r\n"
hexdump(a)
```

### raw(pkt)

Print packet bytes as an escaped string (same format as Scapy's `raw()`).

```
raw(IP()/TCP())
raw(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com")))
```

### ls([Proto])

List fields of one or all protocols.

```
ls()         # list all protocols
ls(IP)       # list IP fields
ls(DNS)      # list DNS fields
ls(SMB2)     # list SMB2 fields with enum values
ls(ARP)
```

### wrpcap("file.pcapng", pkt)

Write (or append) a packet to a pcapng file. Always uses LINKTYPE_ETHERNET so Wireshark
and tshark dissect all layers correctly.

- If the file **does not exist**: creates a new pcapng file with full header.
- If the file **already exists**: appends the packet as a new Enhanced Packet Block.

```
wrpcap("out.pcapng", IP()/TCP())
wrpcap("out.pcapng", Ether()/IP()/UDP(dport=53)/DNS(id=0x1234,rd=1,qd=DNSQR(qname="example.com")))
wrpcap("out.pcapng", a)    # append second packet
```

### frompcapng("file.pcapng", N)

Read packet number N from an existing pcapng file as raw bytes. The result can be
passed to `show()`, `hexdump()`, `wrpcap()`, or `raw()`.

- Packet numbering is **1-based**.
- Returns the raw Ethernet frame (link-layer bytes, no pcapng framing).

```
# Read packet 1 and dissect it
d = frompcapng("capture.pcapng", 1)
show("Ether/IP/TCP", d)

# Read packet 3 and hexdump it
hexdump(frompcapng("capture.pcapng", 3))

# Copy a packet from one file and write it to another
d = frompcapng("original.pcapng", 5)
wrpcap("copy.pcapng", d)
```

### replacepkt("file.pcapng", N, pkt)

Replace packet number N in an existing pcapng file with a new packet, **in-place**.
The file must already exist and contain at least N packets.

```
# Replace packet 2 with a modified version
replacepkt("out.pcapng", 2, Ether()/IP(dst="10.0.0.99")/TCP(dport=8080,flags="S"))
```

### fromhex("hex string")

Parse a hex string into raw bytes. Accepts three formats:

**Plain hex stream** (no separators):
```
d = fromhex("0001010000010000000000000000")
```

**Space-separated bytes**:
```
d = fromhex("00 01 01 00 00 01 00 00 00 00 00 00")
```

**Wireshark hex dump** (one or more lines, with or without the ASCII column):
```
d = fromhex("0000   45 00 00 28 00 00 40 00  40 11 f0 56 c0 a8 01 01   E..(..@.@..V....
0010   08 08 08 08 e6 16 00 35  00 14 d1 e0 00 01 01 00   .......5........
0020   00 01 00 00 00 00 00 00                            ........")
```

`fromhex` returns a raw bytes value that can be passed to `show()`, `hexdump()`, or `wrpcap()`.

### show("Stack", raw_data)

Dissect raw bytes through a `/`-separated protocol stack. Each named layer is printed and
its header bytes consumed before the next layer is dissected.

Built-in layers: `Ether`, `IP`, `TCP`, `UDP`, `ICMP`, `DNS`  
Any posa-defined or inline-defined protocol (ARP, NTP, SMB2, DHCP, … or your own) can appear
anywhere in the stack.

```
# Single layer — dissect from byte 0
show("DNS", fromhex("00 01 01 00 00 01 00 00 00 00 00 00"))
# → <DNS id=1 flags=0x0100 qdcount=1 ancount=0 nscount=0 arcount=0 |

# Stack — each layer printed and skipped automatically
show("IP/UDP/DNS", fromhex("45 00 00 34 ... 00 01 01 00 00 01 ..."))
# → <IP src=192.168.1.5 dst=8.8.8.8 ttl=64 proto=17(UDP) len=52 |
# → <UDP sport=50088 dport=53 len=32 |
# → <DNS id=1 flags=0x0100 qdcount=1 ancount=0 nscount=0 arcount=0 |

# Ether/IP/TCP with a custom payload protocol
show("Ether/IP/TCP/MyProto", fromhex("ff ff ... ef be ad de 03 00 ..."))

# Posa builtins work as stack layers too
show("IP/UDP/NTP", fromhex("45 00 ..."))
show("ARP", fromhex("00 01 08 00 06 04 00 01 ..."))
```

IP headers use the actual IHL field for their length; TCP headers use the data-offset field,
so options (timestamps, SACK, etc.) are skipped correctly.

### load("file.posa")

Load additional protocol definitions at runtime.

```
load("myprotos.posa")
load("/etc/pcapsh/enterprise.posa")
```

### help()

Print usage summary.

### exit() / quit()

Exit the shell (saves readline history in interactive mode).

---

## TCP Session System

The session system tracks TCP state (seq, ack, MACs) automatically so `wrpcap` stays
simple — just pass it whatever packet the session function returns.

### Creating a session

```
s = TCPSession("client_ip", "server_ip", client_port, server_port)
```

- MACs are derived deterministically from IPs: `02:00:IP1:IP2:IP3:IP4`
- Initial sequence numbers are pseudo-random based on IP+port

### Session functions

| Function                 | Direction     | Flags | Advances |
|--------------------------|---------------|-------|----------|
| `syn(s)`                 | client→server | S     | cli_seq += 1 |
| `syn_ack(s)`             | server→client | SA    | srv_seq += 1 |
| `tcp_ack(s)`             | client→server | A     | — |
| `client_send(s, "data")` | client→server | PA    | cli_seq += len(data) |
| `server_send(s, "data")` | server→client | PA    | srv_seq += len(data) |
| `client_fin(s)`          | client→server | FA    | cli_seq += 1 |
| `server_fin_ack(s)`      | server→client | FA    | srv_seq += 1 |

### Full HTTP session example

```
s = TCPSession("192.168.1.100", "93.184.216.34", 54321, 80)
wrpcap("http.pcapng", syn(s))
wrpcap("http.pcapng", syn_ack(s))
wrpcap("http.pcapng", tcp_ack(s))
wrpcap("http.pcapng", client_send(s, "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"))
wrpcap("http.pcapng", server_send(s, "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
wrpcap("http.pcapng", client_fin(s))
wrpcap("http.pcapng", server_fin_ack(s))
```

### Multiple simultaneous sessions

```
web  = TCPSession("10.0.0.1", "1.2.3.4", 49152, 80)
smtp = TCPSession("10.0.0.1", "5.6.7.8", 49153, 25)
wrpcap("multi.pcapng", syn(web))
wrpcap("multi.pcapng", syn(smtp))
wrpcap("multi.pcapng", syn_ack(web))
wrpcap("multi.pcapng", syn_ack(smtp))
```

---

## Adding Custom Protocols via ~/.pcapsh_protos.posa

Any protocol defined in `~/.pcapsh_protos.posa` is automatically available in every pcapsh
session. You can also load files on demand with `load("file.posa")` or `-p file.posa`.

All posa-defined protocols are automatically registered in the protocol registry — they
show up in `ls()` with their name, color, and fields without any code changes.

### posa format

```
Object<main> PROTOCOLNAME
    required TYPE fieldname = default_value
        ENUM_NAME = value
        ENUM_NAME2 = value2
    required TYPE field2 = default_value
```

### Field types

| Type          | Size    | Byte order        | Notes |
|---------------|---------|-------------------|-------|
| `uint8`       | 1 byte  | —                 | |
| `uint16`      | 2 bytes | big-endian        | |
| `uint32`      | 4 bytes | big-endian        | |
| `uint64`      | 8 bytes | big-endian        | |
| `le_uint16`   | 2 bytes | **little-endian** | for Windows protocols |
| `le_uint32`   | 4 bytes | **little-endian** | |
| `le_uint64`   | 8 bytes | **little-endian** | |
| `mac`         | 6 bytes | —                 | default: "00:00:00:00:00:00" |
| `ip4`         | 4 bytes | network           | default: "0.0.0.0" |
| `string`      | variable| —                 | null-terminated |
| `bytes<N>`    | N bytes | —                 | fixed-width, zero-padded |
| `enum<uint8>` | 1 byte  | —                 | uint8-backed enum |
| `enum<uint16>`| 2 bytes | big-endian        | |
| `enum<uint32>`| 4 bytes | big-endian        | |

### Example: simple TLV header

```
Object<main> MyTLV
    required uint8  type = 0
        DATA      = 1
        CONTROL   = 2
        KEEPALIVE = 3
    required uint8  flags = 0
    required uint16 length = 0
    required uint32 sequence = 0
```

Usage:

```
IP()/UDP(dport=9000)/MyTLV(type=DATA, sequence=42)
hexdump(IP()/UDP(dport=9000)/MyTLV(type=CONTROL))
```

### Example: proprietary protocol with little-endian fields

```
Object<main> MyWinProto
    required le_uint32 magic = 0xDEADBEEF
    required le_uint16 version = 1
    required le_uint16 flags = 0
        FLAG_COMPRESSED = 0x0001
        FLAG_ENCRYPTED  = 0x0002
    required le_uint32 length = 0
    required le_uint32 checksum = 0
    required bytes<16> session_id
```

### Example: custom tunnel encapsulation

```
Object<main> MyTunnel
    required uint32 magic = 0x4D594E4C
    required uint8  version = 1
    required uint8  type = 0
        DATA    = 0
        CONTROL = 1
    required uint16 payload_len = 0
    required uint32 src_node = 0
    required uint32 dst_node = 0
```

Usage in a script:

```
load("myprotos.posa")
a = IP(src="10.0.0.1",dst="10.0.0.2")/UDP(dport=8472)/MyTunnel(type=DATA, src_node=1, dst_node=2)
wrpcap("tunnel.pcapng", a)
```

### Using enums

Enum names can be used directly when setting a field:

```
ARP(op=REQUEST)
ARP(op=REPLY)
RADIUS(code=ACCESS_ACCEPT)
SMB2(command=READ)
DCERPC(type=BIND)
NTP(li_vn_mode=CLIENT)
SYSLOG(severity=WARNING)
MyTLV(type=DATA)
```

---

## Script Examples

### DNS query and response exchange

```
# dns_exchange.pcapsh — write a full DNS query/response to a pcapng file
wrpcap("dns.pcapng", IP(src="192.168.1.10",dst="8.8.8.8")/UDP(sport=54321,dport=53)/DNS(id=0x1111,rd=1,qd=DNSQR(qname="example.com")))
wrpcap("dns.pcapng", IP(src="8.8.8.8",dst="192.168.1.10")/UDP(sport=53,dport=54321)/DNS(id=0x1111,qr=1,rd=1,ra=1,qd=DNSQR(qname="example.com"),an=DNSRR(rrname="example.com",type=A,ttl=300,rdata="93.184.216.34"),qdcount=1,ancount=1))
```

### DNS MX query

```
# dns_mx.pcapsh
wrpcap("dns_mx.pcapng", IP(dst="8.8.8.8")/UDP(dport=53)/DNS(id=RandShort(),rd=1,qd=DNSQR(qname="gmail.com",qtype=MX)))
```

### ARP scan simulation

```
# arp_scan.pcapsh — ARP requests for a /28 subnet
wrpcap("arp_scan.pcapng", Ether(type=0x0806)/ARP(op=REQUEST, spa="10.0.0.100", tpa="10.0.0.1"))
wrpcap("arp_scan.pcapng", Ether(type=0x0806)/ARP(op=REQUEST, spa="10.0.0.100", tpa="10.0.0.2"))
wrpcap("arp_scan.pcapng", Ether(type=0x0806)/ARP(op=REQUEST, spa="10.0.0.100", tpa="10.0.0.3"))
wrpcap("arp_scan.pcapng", Ether(type=0x0806)/ARP(op=REPLY, sha="aa:bb:cc:dd:ee:01", spa="10.0.0.1", tha="02:00:0a:00:00:64", tpa="10.0.0.100"))
```

### Full HTTP session

```
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

### ICMP ping sequence

```
# icmp_ping.pcapsh
wrpcap("ping.pcapng", IP(src="10.0.0.1",dst="10.0.0.2")/ICMP(type=8,id=1,seq=1)/"Hello!")
wrpcap("ping.pcapng", IP(src="10.0.0.2",dst="10.0.0.1")/ICMP(type=0,id=1,seq=1)/"Hello!")
wrpcap("ping.pcapng", IP(src="10.0.0.1",dst="10.0.0.2")/ICMP(type=8,id=1,seq=2)/"Hello!")
wrpcap("ping.pcapng", IP(src="10.0.0.2",dst="10.0.0.1")/ICMP(type=0,id=1,seq=2)/"Hello!")
```

### NTP client request

```
# ntp.pcapsh
wrpcap("ntp.pcapng", IP(src="10.0.0.1",dst="129.6.15.28")/UDP(sport=12345,dport=123)/NTP(li_vn_mode=CLIENT))
wrpcap("ntp.pcapng", IP(src="129.6.15.28",dst="10.0.0.1")/UDP(sport=123,dport=12345)/NTP(li_vn_mode=SERVER,stratum=1))
```

### DHCP discover / offer

```
# dhcp.pcapsh
wrpcap("dhcp.pcapng", Ether(src="aa:bb:cc:dd:ee:ff",dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/DHCP(op=BOOTREQUEST,xid=0xdeadbeef))
wrpcap("dhcp.pcapng", Ether(src="00:11:22:33:44:55",dst="aa:bb:cc:dd:ee:ff")/IP(src="192.168.1.1",dst="255.255.255.255")/UDP(sport=67,dport=68)/DHCP(op=BOOTREPLY,xid=0xdeadbeef,yiaddr="192.168.1.100",siaddr="192.168.1.1"))
```

### SMB2 negotiate over NBT/TCP

```
# smb2_negotiate.pcapsh
s = TCPSession("10.0.0.1", "10.0.0.2", 49152, 445)
wrpcap("smb2.pcapng", syn(s))
wrpcap("smb2.pcapng", syn_ack(s))
wrpcap("smb2.pcapng", tcp_ack(s))
wrpcap("smb2.pcapng", client_send(s, "\x00\x00\x00\x24\xfeSMB\x40\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
wrpcap("smb2.pcapng", server_fin_ack(s))
```

### Kerberos AS exchange (PREAUTH_REQUIRED → retry)

```
# krb5_auth.pcapsh — KDC returns error, client retries with pre-auth data
# KRB5 header = 18 bytes, so seq/ack advances by 18 per data packet
wrpcap("krb5.pcapng", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1")/TCP(sport=52001,dport=88,flags="S",seq=0))
wrpcap("krb5.pcapng", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1")/TCP(sport=88,dport=52001,flags="SA",seq=0,ack=1))
wrpcap("krb5.pcapng", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1")/TCP(sport=52001,dport=88,flags="A",seq=1,ack=1))
# initial AS-REQ (no pre-auth)
wrpcap("krb5.pcapng", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1")/TCP(sport=52001,dport=88,flags="PA",seq=1,ack=1)/KRB5(app_tag=AS_REQ,msg_type=AS_REQUEST))
# KDC replies PREAUTH_REQUIRED
wrpcap("krb5.pcapng", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1")/TCP(sport=88,dport=52001,flags="PA",seq=1,ack=19)/KRB5(app_tag=KRB_ERROR,msg_type=KRB_ERROR_VAL))
# client retries with pre-auth data
wrpcap("krb5.pcapng", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1")/TCP(sport=52001,dport=88,flags="PA",seq=19,ack=19)/KRB5(app_tag=AS_REQ,msg_type=AS_REQUEST))
wrpcap("krb5.pcapng", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1")/TCP(sport=88,dport=52001,flags="PA",seq=19,ack=37)/KRB5(app_tag=AS_REP,msg_type=AS_REPLY))
# TGS exchange
wrpcap("krb5.pcapng", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1")/TCP(sport=52001,dport=88,flags="PA",seq=37,ack=37)/KRB5(app_tag=TGS_REQ,msg_type=TGS_REQUEST))
wrpcap("krb5.pcapng", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1")/TCP(sport=88,dport=52001,flags="PA",seq=37,ack=55)/KRB5(app_tag=TGS_REP,msg_type=TGS_REPLY))
wrpcap("krb5.pcapng", Ether(src="02:00:00:01:00:01",dst="02:00:00:00:00:01")/IP(src="10.0.1.1",dst="10.0.0.1")/TCP(sport=52001,dport=88,flags="FA",seq=55,ack=55))
wrpcap("krb5.pcapng", Ether(src="02:00:00:00:00:01",dst="02:00:00:01:00:01")/IP(src="10.0.0.1",dst="10.0.1.1")/TCP(sport=88,dport=52001,flags="FA",seq=55,ack=56))
```

### NBNS name query broadcast

```
# nbns.pcapsh
wrpcap("nbns.pcapng", Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="10.0.1.1",dst="10.0.1.255",ttl=1)/UDP(sport=137,dport=137)/NBNS(trans_id=0x1234,flags=NAME_QUERY_REQUEST,qdcount=1))
wrpcap("nbns.pcapng", Ether(src="00:11:22:33:44:55")/IP(src="10.0.0.10",dst="10.0.1.1")/UDP(sport=137,dport=137)/NBNS(trans_id=0x1234,flags=NAME_QUERY_RESPONSE_POS,ancount=1))
```

### NTP with for-loop and arithmetic (avoid well-known port conflicts)

```
# ntp_20_hosts.pcapsh
# sport=49151+$i gives ports 49152-49171 (safe ephemeral range)
for $i in range(20):
    wrpcap("ntp.pcapng", Ether()/IP(src="10.0.1.1",dst="10.0.0.2")/UDP(sport=49151+$i,dport=123)/NTP(li_vn_mode=CLIENT,stratum=0))
    wrpcap("ntp.pcapng", Ether()/IP(src="10.0.0.2",dst="10.0.1.1")/UDP(sport=123,dport=49151+$i)/NTP(li_vn_mode=SERVER,stratum=1))
```

### RFC 3164 syslog messages

```
# syslog_rfc3164.pcapsh
# PRI = facility*8 + severity (auth=4, info=6 → <38>; notice=5 → <37>; warning=4 → <36>)
wrpcap("syslog.pcapng", Ether()/IP(src="10.0.0.1",dst="10.0.0.254")/UDP(sport=514,dport=514)/"<38>May 11 10:00:01 dc01 sshd[1234]: Accepted publickey for admin")
wrpcap("syslog.pcapng", Ether()/IP(src="10.0.0.1",dst="10.0.0.254")/UDP(sport=514,dport=514)/"<37>May 11 10:00:02 dc01 kernel: eth0: link up 1Gbps")
wrpcap("syslog.pcapng", Ether()/IP(src="10.0.0.1",dst="10.0.0.254")/UDP(sport=514,dport=514)/"<36>May 11 10:00:03 dc01 named[567]: error parsing dns query")
```

### GRE tunnel

```
# gre_tunnel.pcapsh
wrpcap("gre.pcapng", Ether()/IP(src="10.0.0.1",dst="10.0.0.2",proto=47)/GRE(proto=IPV4)/IP(src="192.168.1.1",dst="192.168.2.1")/TCP(dport=80,flags="S"))
```

### VXLAN overlay

```
# vxlan.pcapsh
wrpcap("vxlan.pcapng", Ether()/IP(src="10.0.0.1",dst="10.0.0.2")/UDP(dport=4789)/VXLAN()/IP(src="172.16.0.1",dst="172.16.0.2")/TCP(dport=8080,flags="S"))
```

### RADIUS access request

```
# radius.pcapsh
wrpcap("radius.pcapng", IP(src="10.0.0.1",dst="10.0.0.2")/UDP(sport=49152,dport=1812)/RADIUS(code=ACCESS_REQUEST,identifier=1,length=20))
wrpcap("radius.pcapng", IP(src="10.0.0.2",dst="10.0.0.1")/UDP(sport=1812,dport=49152)/RADIUS(code=ACCESS_ACCEPT,identifier=1,length=20))
```

### DCERPC bind over TCP

```
# dcerpc.pcapsh
s = TCPSession("10.0.0.1", "10.0.0.2", 49200, 135)
wrpcap("dcerpc.pcapng", syn(s))
wrpcap("dcerpc.pcapng", syn_ack(s))
wrpcap("dcerpc.pcapng", tcp_ack(s))
wrpcap("dcerpc.pcapng", client_send(s, "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00"))
wrpcap("dcerpc.pcapng", server_fin_ack(s))
```

---

## Parsing Wireshark Hex Dumps

`fromhex()` + `show()` let you paste Wireshark bytes directly into pcapsh and dissect them
against any protocol — built-in or custom-defined.

### Dissecting a known protocol (DNS)

In Wireshark, right-click any packet → **Copy → …as Hex Dump**. Paste the result into
`fromhex()` and tell `show()` which layers to walk through with `/`:

```
# DNS query captured in Wireshark (IP+UDP+DNS, 40 bytes)
d = fromhex("0000   45 00 00 34 00 01 00 00  40 11 f6 c4 c0 a8 01 05   E..4....@.......
0010   08 08 08 08 c3 a8 00 35  00 20 41 a1 12 34 01 00   .......5. A..4..
0020   00 01 00 00 00 00 00 00                            ........")
show("IP/UDP/DNS", d)
# → <IP src=192.168.1.5 dst=8.8.8.8 ttl=64 proto=17(UDP) len=52 |
# → <UDP sport=50088 dport=53 len=32 |
# → <DNS id=4660 flags=0x0100 qdcount=1 ancount=0 nscount=0 arcount=0 |
```

The stack tells `show()` exactly which headers to skip: `IP` reads the IHL field to know its
own length, `UDP` is always 8 bytes, then `DNS` gets whatever remains.

### Dissecting a custom inline protocol

Define the protocol in pcapsh, then paste the hex bytes directly:

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

# Paste hex from Wireshark (or any capture tool) — just the payload bytes
d = fromhex("01 01 0e 5a 00 67 04 d9")
show("IoTReading", d)
# → <IoTReading sensor_type=TEMP(1) value=270 battery_pct=103 timestamp=1241 |
```

### Space-separated format

If you copy just the hex column from Wireshark (without offsets or ASCII):

```
d = fromhex("00 01 01 00 00 01 00 00 00 00 00 00")
show("DNS", d)
# → <DNS id=1 flags=0x0100 qdcount=1 ancount=0 nscount=0 arcount=0 |
```

### Plain hex stream

Useful when you have hex from a scripted `tshark -T fields -e data.data` output:

```
d = fromhex("0001010000010000000000000000")
show("DNS", d)
```

### Combine with wrpcap to replay captures

Parse bytes from Wireshark, tweak a field, and write a modified packet:

```
protocol WinHdr
    required le_uint32 magic = 0xDEADBEEF
    required le_uint16 version = 0
    required le_uint16 flags = 0
        COMPRESSED = 1
        ENCRYPTED  = 2
    required le_uint32 length = 0
end

# Bytes from Wireshark capture
d = fromhex("ef be ad de 03 00 02 00 80 00 00 00")
show("WinHdr", d)
# → <WinHdr magic=3735928559 version=3 flags=ENCRYPTED(2) length=128 |

# Build a modified version and write it
s = TCPSession("10.0.0.1", "10.0.0.2", 54321, 8080)
wrpcap("replay.pcapng", syn(s))
wrpcap("replay.pcapng", syn_ack(s))
wrpcap("replay.pcapng", tcp_ack(s))
wrpcap("replay.pcapng", client_send(s, "payload data here"))
```

---

## Inspecting Packets

```
# print packet structure
IP(dst="8.8.8.8")/UDP(dport=53)/DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com"))
DNS(qr=1, an=DNSRR(rrname="example.com", type=A, ttl=300, rdata="1.2.3.4"), ancount=1)

# hex dump
hexdump(Ether()/IP()/TCP()/"GET / HTTP/1.0\r\n\r\n")
hexdump(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(id=0x1234,rd=1,qd=DNSQR(qname="example.com")))
hexdump(SMB2(command=READ))

# raw bytes (escaped string, same as Scapy)
raw(IP()/TCP())
raw(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="google.com")))

# list all protocol fields
ls()
ls(IP)
ls(DNS)
ls(SMB2)
ls(DCERPC)
```

---

## Tips

- **Wireshark/tshark**: open any `.pcapng` file produced by `wrpcap` — all layers dissect correctly.
- **Multiple sessions in one file**: call `wrpcap` with the same filename from different sessions; packets interleave in write order.
- **DNS auto-count**: when you pass `qd=DNSQR(...)`, `qdcount` is incremented automatically (unless you set it explicitly).
- **DNS flags shorthand**: use individual bits (`rd=1`, `qr=1`, `aa=1`) or the raw `flags=0x8180` word — mutually exclusive.
- **Tab completion**: in interactive mode, press Tab to complete protocol names, function names, and variable names.
- **History**: the REPL saves history to `.pcapsh_history` in the current directory.
- **Script + interactive**: run your script first to build the pcapng file, then open it with Wireshark.
- **ANSI colors**: the REPL uses colors for protocol display; pipe through `cat` for plain text if needed.
- **Protocol registry**: adding a posa protocol auto-registers it for name/color lookup — no code changes required.
- **For-loop sport arithmetic**: `sport=$i` hits well-known ports (Echo=7, Discard=9, Daytime=13, Chargen=19, …). Always offset: `sport=49000+$i`.
- **ARP Ether type**: `Ether()` defaults to `type=0x0800` (IPv4). ARP frames require `type=0x0806` explicitly — Wireshark will try to parse ARP bytes as IPv4 otherwise.
- **SMB2 NEGOTIATE body**: the `SMB2(command=NEGOTIATE)` header alone (64 bytes) is not RFC-compliant — Wireshark marks it malformed because the NEGOTIATE command body (36 bytes for request, 65 for response) is missing. For clean captures, start SMB2 sessions at SESSION_SETUP.
- **KRB5 TCP seq accounting**: each `KRB5()` object serializes to exactly 18 bytes. Advance seq/ack by 18 per data exchange: SYN(seq=0) → data starts at seq=1, next ack=1+18=19, etc.
- **Syslog RFC compliance**: the `SYSLOG()` built-in emits only the PRI byte. Use a raw string payload for RFC 3164-compliant output: `UDP(dport=514)/"<38>May 11 10:00:01 host tag: msg"`.
- **Reading existing captures**: `frompcapng("file.pcapng", N)` extracts packet N as raw bytes for `show()`, `hexdump()`, or `wrpcap()`. Packet numbers are 1-based.
- **In-place packet editing**: `replacepkt("file.pcapng", N, newpkt)` replaces packet N without rewriting the whole file.
