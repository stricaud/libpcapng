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
IP(dst="8.8.8.8")/UDP(dport=53)/DNS(id=0x1234)
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
```

### Comments

```
# this is a comment
a = IP()   # inline comment
```

### Escape sequences in strings

Inside quoted strings: `\r` → CR, `\n` → LF, `\t` → tab, `\xNN` → hex byte, `\\` → backslash.

```
client_send(s, "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
```

---

## Built-in Protocols

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

| Field  | Type | Default | Notes |
|--------|------|---------|-------|
| src    | ip4  | 127.0.0.1 | source IP |
| dst    | ip4  | 127.0.0.1 | destination IP |
| ttl    | int  | 64 | time to live |
| proto  | int  | auto | 6=TCP, 17=UDP, 1=ICMP |
| id     | int  | 1 | identification |
| flags  | int  | 0 | 0x02=DF, 0x01=MF |
| frag   | int  | 0 | fragment offset |
| tos    | int  | 0 | type of service |
| len    | int  | auto | total length |
| chksum | int  | auto | header checksum |

### TCP

```
TCP(sport=12345, dport=80, seq=100, ack=0, flags="S")
TCP(flags="PA")   # PSH+ACK
TCP(flags=0x12)   # SYN+ACK numeric
```

| Field   | Type | Default | Notes |
|---------|------|---------|-------|
| sport   | int  | 20 | source port |
| dport   | int  | 80 | destination port |
| seq     | int  | 0 | sequence number |
| ack     | int  | 0 | acknowledgement number |
| flags   | str  | S | F=FIN S=SYN R=RST P=PSH A=ACK U=URG |
| window  | int  | 8192 | window size |
| dataofs | int  | 5 | header length in 32-bit words |
| chksum  | int  | auto | checksum |
| urgptr  | int  | 0 | urgent pointer |

### UDP

```
UDP(sport=5000, dport=53)
```

| Field  | Type | Default | Notes |
|--------|------|---------|-------|
| sport  | int  | 53 | source port |
| dport  | int  | 53 | destination port |
| len    | int  | auto | length |
| chksum | int  | auto | checksum |

### ICMP

```
ICMP(type=8, code=0, id=1, seq=1)
```

| Field  | Type | Default | Notes |
|--------|------|---------|-------|
| type   | int  | 8 | 8=echo request, 0=echo reply |
| code   | int  | 0 | |
| id     | int  | 0 | identifier |
| seq    | int  | 0 | sequence number |
| chksum | int  | auto | checksum |

### Raw

```
Raw(load="hello\r\n")
IP()/TCP()/"binary payload"
```

---

## Dynamic Protocols (posa-defined)

These are loaded from the built-in definitions and from `~/.pcapsh_protos.posa`.

### ARP

```
Ether(type=0x0806)/ARP(op=REQUEST, spa="192.168.1.1", tpa="192.168.1.254")
Ether()/ARP(op=REPLY, sha="aa:bb:cc:dd:ee:ff", spa="192.168.1.1")
```

| Field | Type   | Default            | Enums |
|-------|--------|--------------------|-------|
| htype | uint16 | 1                  | ETHERNET=1 |
| ptype | uint16 | 0x0800             | IPV4=0x0800 |
| hlen  | uint8  | 6                  | |
| plen  | uint8  | 4                  | |
| op    | uint16 | 1                  | REQUEST=1, REPLY=2 |
| sha   | mac    | 00:00:00:00:00:00  | sender MAC |
| spa   | ip4    | 0.0.0.0            | sender IP |
| tha   | mac    | 00:00:00:00:00:00  | target MAC |
| tpa   | ip4    | 0.0.0.0            | target IP |

### DNS

```
IP()/UDP(dport=53)/DNS(id=0xabcd, flags=STANDARD_QUERY, qdcount=1)
```

| Field   | Type   | Default | Enums |
|---------|--------|---------|-------|
| id      | uint16 | 0x0001  | |
| flags   | uint16 | 0x0100  | RESPONSE=0x8000, STANDARD_QUERY=0x0100, RD=0x0100 |
| qdcount | uint16 | 1       | question count |
| ancount | uint16 | 0       | answer count |
| nscount | uint16 | 0       | authority count |
| arcount | uint16 | 0       | additional count |

### NTP

```
IP()/UDP(sport=123, dport=123)/NTP(li_vn_mode=CLIENT)
IP()/UDP(sport=123, dport=123)/NTP(li_vn_mode=SERVER)
```

| Field           | Type   | Default |
|-----------------|--------|---------|
| li_vn_mode      | uint8  | 0x1b (CLIENT=0x1b, SERVER=0x1c) |
| stratum         | uint8  | 0       |
| poll            | uint8  | 4       |
| precision       | uint8  | 0xfa    |
| root_delay      | uint32 | 0       |
| root_dispersion | uint32 | 0       |
| ref_id          | uint32 | 0       |
| ref_ts_s/f      | uint32 | 0       |
| orig_ts_s/f     | uint32 | 0       |
| recv_ts_s/f     | uint32 | 0       |
| tx_ts_s/f       | uint32 | 0       |

### DHCP

```
IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68,dport=67)/DHCP(op=BOOTREQUEST,xid=0x12345678)
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
| yiaddr | ip4        | 0.0.0.0   | your IP |
| siaddr | ip4        | 0.0.0.0   | server IP |
| giaddr | ip4        | 0.0.0.0   | gateway IP |
| chaddr | bytes<16>  | zeros     | client hardware address |
| sname  | bytes<64>  | zeros     | server name |
| file   | bytes<128> | zeros     | boot file |

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
IP()/UDP(dport=4789)/VXLAN()
```

| Field     | Type      | Default |
|-----------|-----------|---------|
| flags     | uint8     | 0x08    |
| reserved1 | bytes<3>  | zeros   |
| vni       | bytes<3>  | zeros   |
| reserved2 | uint8     | 0       |

### RADIUS

```
IP()/UDP(sport=1812,dport=1812)/RADIUS(code=ACCESS_REQUEST, identifier=1, length=20)
```

| Field         | Type      | Default | Enums |
|---------------|-----------|---------|-------|
| code          | uint8     | 1       | ACCESS_REQUEST=1, ACCESS_ACCEPT=2, ACCESS_REJECT=3, ACCOUNTING_REQUEST=4, ACCOUNTING_RESPONSE=5 |
| identifier    | uint8     | 0       | |
| length        | uint16    | 20      | |
| authenticator | bytes<16> | zeros   | |

### SYSLOG

```
IP()/UDP(dport=514)/SYSLOG(severity=WARNING, facility=1)
```

| Field    | Type   | Default | Enums |
|----------|--------|---------|-------|
| severity | uint8  | 6       | EMERGENCY=0, ALERT=1, CRITICAL=2, ERROR=3, WARNING=4, NOTICE=5, INFO=6, DEBUG=7 |
| facility | uint8  | 1       | |
| message  | string | ""      | |

### NBT (NetBIOS Session Service)

```
IP()/TCP(dport=139)/NBT(type=SESSION_MESSAGE, length=72)
```

| Field  | Type   | Default | Enums |
|--------|--------|---------|-------|
| type   | uint8  | 0       | SESSION_MESSAGE=0, SESSION_REQUEST=0x81, POSITIVE_SESSION_RESPONSE=0x82, NEGATIVE_SESSION_RESPONSE=0x83, SESSION_KEEPALIVE=0x85 |
| flags  | uint8  | 0       | |
| length | uint16 | 0       | payload length (big-endian) |

### SMB2

SMB2 uses **little-endian** (LE) integers for most fields.

```
IP()/TCP(dport=445)/NBT()/SMB2(command=NEGOTIATE)
IP()/TCP(dport=445)/NBT()/SMB2(command=READ, tree_id=1, session_id=0x100)
```

| Field          | Type      | Default      | Notes |
|----------------|-----------|--------------|-------|
| magic          | uint32    | 0xFE534D42   | big-endian magic \xFESMB |
| structure_size | le_uint16 | 64           | always 64 |
| credit_charge  | le_uint16 | 0            | |
| status         | le_uint32 | 0            | NTSTATUS |
| command        | le_uint16 | 0            | NEGOTIATE=0, SESSION_SETUP=1, LOGOFF=2, TREE_CONNECT=3, TREE_DISCONNECT=4, CREATE=5, CLOSE=6, FLUSH=7, READ=8, WRITE=9, IOCTL=11, CANCEL=12, ECHO=13, QUERY_DIRECTORY=14, QUERY_INFO=16, SET_INFO=17 |
| credit_request | le_uint16 | 0            | |
| flags          | le_uint32 | 0            | |
| next_command   | le_uint32 | 0            | chained requests |
| message_id     | le_uint64 | 0            | |
| process_id     | le_uint32 | 0            | |
| tree_id        | le_uint32 | 0            | |
| session_id     | le_uint64 | 0            | |
| signature      | bytes<16> | zeros        | |

### DCERPC

```
IP()/TCP(dport=135)/DCERPC(type=BIND, call_id=1)
IP()/TCP(dport=135)/DCERPC(type=REQUEST, frag_len=72, call_id=1)
```

| Field     | Type      | Default    | Notes |
|-----------|-----------|------------|-------|
| ver_major | uint8     | 5          | always 5 |
| ver_minor | uint8     | 0          | |
| type      | uint8     | 0          | REQUEST=0, RESPONSE=2, FAULT=3, BIND=11, BIND_ACK=12, BIND_NAK=13, ALTER_CONTEXT=14, AUTH3=16 |
| flags     | uint8     | 0x03       | 0x01=FIRST_FRAG, 0x02=LAST_FRAG |
| data_rep  | le_uint32 | 0x10000000 | LE+IEEE+ASCII |
| frag_len  | le_uint16 | 0          | total fragment length |
| auth_len  | le_uint16 | 0          | |
| call_id   | le_uint32 | 1          | |

### LDAP

Simplified 7-byte BER header (for basic LDAP op framing):

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

---

## Functions Reference

### hexdump(pkt)

Print a colorized hex dump of the packet bytes.

```
hexdump(IP()/TCP())
hexdump(SMB2(command=READ))
a = Ether()/IP()/UDP()/DNS()
hexdump(a)
```

### raw(pkt)

Print packet bytes as an escaped string (same output format as Scapy).

```
raw(IP()/TCP())
```

### ls([Proto])

List fields of one or all protocols.

```
ls()          # list all protocols
ls(IP)        # list IP fields
ls(SMB2)      # list SMB2 fields with enum values
ls(DNS)
```

### wrpcap("file.pcapng", pkt)

Write (or append) a packet to a pcapng file. Always uses LINKTYPE_ETHERNET so tshark
dissects all layers correctly.

- If the file **does not exist**: creates a new pcapng file with full header.
- If the file **already exists**: appends the packet as a new Enhanced Packet Block.

```
wrpcap("out.pcapng", IP()/TCP())
wrpcap("out.pcapng", a)         # append second packet
```

### load("file.posa")

Load additional protocol definitions at runtime.

```
load("~/myprotos.posa")
load("/etc/pcapsh/enterprise.posa")
```

### help()

Print usage summary.

### exit() / quit()

Exit the shell (saves history in interactive mode).

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

| Function             | Direction    | Flags | Advances |
|----------------------|-------------|-------|----------|
| `syn(s)`             | client→server | S   | cli_seq += 1 |
| `syn_ack(s)`         | server→client | SA  | srv_seq += 1 |
| `tcp_ack(s)`         | client→server | A   | — |
| `client_send(s, "data")` | client→server | PA | cli_seq += len(data) |
| `server_send(s, "data")` | server→client | PA | srv_seq += len(data) |
| `client_fin(s)`      | client→server | FA  | cli_seq += 1 |
| `server_fin_ack(s)`  | server→client | FA  | srv_seq += 1 |

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

### posa format

```
Object<main> PROTOCOLNAME
    required TYPE fieldname = default_value
        ENUM_NAME = value
        ENUM_NAME2 = value2
    required TYPE field2 = default_value
```

### Field types

| Type        | Size    | Byte order | Notes |
|-------------|---------|------------|-------|
| `uint8`     | 1 byte  | —          | |
| `uint16`    | 2 bytes | big-endian | |
| `uint32`    | 4 bytes | big-endian | |
| `uint64`    | 8 bytes | big-endian | |
| `le_uint16` | 2 bytes | **little-endian** | for Windows protocols |
| `le_uint32` | 4 bytes | **little-endian** | |
| `le_uint64` | 8 bytes | **little-endian** | |
| `mac`       | 6 bytes | —          | default: "00:00:00:00:00:00" |
| `ip4`       | 4 bytes | network    | default: "0.0.0.0" |
| `string`    | variable | —         | null-terminated |
| `bytes<N>`  | N bytes | —          | fixed-width, zero-padded |
| `enum<uint8>` | 1 byte | —        | uint8-backed enum |
| `enum<uint16>` | 2 bytes | big-endian | uint16-backed enum |
| `enum<uint32>` | 4 bytes | big-endian | |

### Example: simple TLV header

```
Object<main> MyTLV
    required uint8  type = 0
        DATA    = 1
        CONTROL = 2
        KEEPALIVE = 3
    required uint8  flags = 0
    required uint16 length = 0
    required uint32 sequence = 0
```

Usage:

```
IP()/UDP(dport=9000)/MyTLV(type=DATA, sequence=42)
```

### Example: a proprietary protocol with little-endian fields

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

### Example: extending SYSLOG with structured data

```
Object<main> SyslogRFC5424
    required uint8  facility_severity = 0x86
    required string version = "1"
    required string timestamp
    required string hostname
    required string app_name
    required string proc_id = "-"
    required string msg_id = "-"
```

### Example: custom encapsulation

```
Object<main> MyTunnel
    required uint32 magic = 0x4D594E4C
        MYNET_MAGIC = 0x4D594E4C
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
s = TCPSession("10.0.0.1", "10.0.0.2", 5000, 5000)
wrpcap("tunnel.pcapng", syn(s))
wrpcap("tunnel.pcapng", syn_ack(s))
wrpcap("tunnel.pcapng", tcp_ack(s))
wrpcap("tunnel.pcapng", client_send(s, "..."))
```

Or stack the tunnel protocol explicitly:

```
a = Ether()/IP()/UDP(dport=8472)/MyTunnel(type=DATA, src_node=1, dst_node=2)
wrpcap("tunnel.pcapng", a)
```

### Using enums

Enum names can be used directly when setting a field:

```
MyTLV(type=DATA)             # uses enum name
MyTLV(type=1)                # same using numeric value
ARP(op=REQUEST)
RADIUS(code=ACCESS_ACCEPT)
SMB2(command=READ)
DCERPC(type=BIND)
```

---

## Script Examples

### ARP scan simulation

```
# arp_scan.pcapsh — simulate ARP requests for 192.168.1.1 through 192.168.1.5
targets = "192.168.1.1"
wrpcap("arp_scan.pcapng", Ether(type=0x0806)/ARP(op=REQUEST, spa="10.0.0.100", tpa="192.168.1.1"))
wrpcap("arp_scan.pcapng", Ether(type=0x0806)/ARP(op=REQUEST, spa="10.0.0.100", tpa="192.168.1.2"))
wrpcap("arp_scan.pcapng", Ether(type=0x0806)/ARP(op=REQUEST, spa="10.0.0.100", tpa="192.168.1.3"))
```

### DNS query + response

```
# dns.pcapsh
s = TCPSession("10.0.0.1", "8.8.8.8", 53200, 53)
wrpcap("dns.pcapng", syn(s))
wrpcap("dns.pcapng", syn_ack(s))
wrpcap("dns.pcapng", tcp_ack(s))
wrpcap("dns.pcapng", client_send(s, "\x00\x1c\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"))
wrpcap("dns.pcapng", client_fin(s))
wrpcap("dns.pcapng", server_fin_ack(s))
```

### SMB2 session setup skeleton

```
# smb2.pcapsh — bare SMB2 negotiate over NBT/TCP
s = TCPSession("10.0.0.1", "10.0.0.2", 49152, 445)
wrpcap("smb2.pcapng", syn(s))
wrpcap("smb2.pcapng", syn_ack(s))
wrpcap("smb2.pcapng", tcp_ack(s))

# negotiate request: NBT session message + SMB2 NEGOTIATE header
req = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=49152,dport=445,flags="PA",seq=1,ack=1)/NBT(type=SESSION_MESSAGE)/SMB2(command=NEGOTIATE,message_id=1,credit_request=1)
wrpcap("smb2.pcapng", req)
```

### NTP client request

```
# ntp.pcapsh
wrpcap("ntp.pcapng", IP(src="10.0.0.1",dst="pool.ntp.org")/UDP(sport=12345,dport=123)/NTP(li_vn_mode=CLIENT))
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

## Inspecting Packets

```
# print packet structure
IP(dst="8.8.8.8")/UDP(dport=53)/DNS()

# hex dump
hexdump(Ether()/IP()/TCP()/"GET / HTTP/1.0\r\n\r\n")
hexdump(SMB2(command=READ))

# raw bytes (escaped string)
raw(IP()/TCP())

# list all protocol fields
ls()
ls(IP)
ls(SMB2)
ls(DCERPC)
```

---

## Tips

- **Wireshark/tshark**: open any `.pcapng` file produced by `wrpcap` — all layers dissect correctly.
- **Multiple sessions in one file**: call `wrpcap` with the same filename from different sessions; packets interleave in write order.
- **Script + interactive**: run your script first to set up state, then continue interactively with the resulting pcapng file.
- **ANSI colors**: the REPL uses colors for protocol display; script mode prints colors too (pipe to `cat` if you want plain text).
- **Tab completion**: in interactive mode, press Tab to complete protocol names, function names, and variable names.
- **History**: the REPL saves history to `.pcapsh_history` in the current directory.
