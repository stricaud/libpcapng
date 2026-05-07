# Tutorial 2 — Writing a TFTP Protocol Definition with pcapsh and posa

This tutorial follows the same arc as the
[Zeek/Spicy TFTP tutorial](https://docs.zeek.org/projects/spicy/en/latest/tutorial/index.html):
start with one packet type, build toward the complete protocol, use enums, and test against real
bytes. The difference is the tool: Spicy is a streaming *parser* that integrates with Zeek;
pcapsh + posa is a packet *builder and inspector* that outputs pcapng files. Both tools define
protocol structure as typed fields — the concepts map closely, the syntax is different.

Prerequisites: pcapsh built and on your PATH (`make && make install` from the repo root), or
run directly as `./build/bin/pcapsh`.

---

## Part 1 — Parsing one packet type

In Spicy you start with a `module` declaration and a single `unit` type. In posa you start with
an `Object<main>` block. The inline `protocol … end` syntax in pcapsh translates directly to
the posa format.

TFTP's simplest packet is the **ACK** — two fields, four bytes:

```
protocol TFTP
    required uint16 opcode = 4
    required uint16 block  = 0
end
```

Enter this in the pcapsh REPL or save it to a `.pcapsh` script:

```
pcapsh >>> protocol TFTP
...    ...     required uint16 opcode = 4
...    ...     required uint16 block  = 0
...    ... end
Protocol 'TFTP' defined (2 fields). Use TFTP() and ls(TFTP).
```

Construct a default instance and inspect it:

```
pcapsh >>> TFTP()
<TFTP opcode=4 block=0>

pcapsh >>> hexdump(TFTP())
0000   00 04 00 00                                        ....

pcapsh >>> raw(TFTP())
'\x00\x04\x00\x00'
```

The two big-endian uint16 fields serialize to four bytes — matching RFC 1350 exactly. Compare
with the Spicy equivalent test:

```bash
# Spicy:
printf '\000\004\000\001' | spicy-driver -d tftp.spicy

# pcapsh equivalent — dissect four bytes as TFTP:
pcapsh -e 'show("TFTP", fromhex("00 04 00 01"))'
# → <TFTP opcode=4 block=1 |
```

---

## Part 2 — Testing the parser

Spicy uses `spicy-driver` to feed raw bytes into a grammar and check the output. In pcapsh the
equivalent is `show()` with `fromhex()`.

### Feed raw bytes

```
pcapsh >>> show("TFTP", fromhex("00 04 00 07"))
<TFTP opcode=4 block=7 |
```

### Feed a Wireshark hex dump

Right-click any TFTP packet in Wireshark → **Copy → …as Hex Dump**, then paste:

```
pcapsh >>> show("IP/UDP/TFTP", fromhex("0000   45 00 00 1c 00 01 40 00  40 11 f6 e8 c0 a8 01 01
0010   c0 a8 01 02 00 45 00 45  00 08 00 00 00 04 00 03   .E.E........
0020   "))
<IP src=192.168.1.1 dst=192.168.1.2 ttl=64 proto=17(UDP) len=28 |
<UDP sport=69 dport=69 len=8 |
<TFTP opcode=4 block=3 |
```

The `/`-separated stack tells pcapsh exactly which headers to skip before reaching the TFTP
payload. IP reads its own IHL field; UDP is always 8 bytes.

### Build and inspect in one step

```
pcapsh >>> hexdump(IP(dst="192.168.1.2")/UDP(sport=1234,dport=69)/TFTP())
0000   45 00 00 1c ...
```

---

## Part 3 — Using enums

Spicy uses `type Opcode = enum { RRQ=1, … }` and the `&convert` attribute to turn a uint16
into a named value. In posa, enums are declared as indented name/value lines directly under the
field:

```
protocol TFTP
    required uint16 opcode = 4
        RRQ   = 1
        WRQ   = 2
        DATA  = 3
        ACK   = 4
        ERROR = 5
    required uint16 block = 0
end
```

Now enum names work as constructors and appear in `show()` output:

```
pcapsh >>> TFTP(opcode=ACK, block=5)
<TFTP opcode=4 block=5>

pcapsh >>> show("TFTP", fromhex("00 04 00 05"))
<TFTP opcode=ACK(4) block=5 |

pcapsh >>> show("TFTP", fromhex("00 01 00 00"))
<TFTP opcode=RRQ(1) block=0 |
```

When constructing, the enum name resolves to its numeric value. When dissecting with `show()`,
the numeric value is annotated with its name — the same behaviour Spicy achieves with `&convert`.

---

## Part 4 — Multiple packet types with automatic dispatch

In Spicy a single `Packet` unit has a `switch(self.opcode)` that dispatches to sub-units at
parse time. posa achieves the same with **`Object<parent>`** — tagging each sub-protocol with
its parent name enables automatic opcode-based dispatch in `show()`.

The key idea: declare each packet shape as `Object<TFTP>` instead of `Object<main>`. pcapsh
then dispatches `show("…/TFTP", data)` to the matching sub-protocol by reading the first field
and comparing it to each sub-protocol's default value.

| Concept | Spicy | pcapsh/posa |
|---------|-------|-------------|
| Dispatch | `switch(self.opcode)` in grammar | `Object<parent>` grouping + first-field match |
| Variable-length fields | `bytes &until=b"\x00"` | `cstring` (null-terminated), `payload` (rest of packet) |
| Sub-units | named types referenced in switch | `Object<TFTP>` sub-protocols |

### Define each packet shape as `Object<TFTP>`

In `.posa` format (or via `load()`):

```
Object<TFTP> TFTP_RRQ
    required uint16  opcode   = 1
        RRQ = 1
    required cstring filename
    required cstring mode

Object<TFTP> TFTP_WRQ
    required uint16  opcode   = 2
        WRQ = 2
    required cstring filename
    required cstring mode

Object<TFTP> TFTP_DATA
    required uint16  opcode = 3
        DATA = 3
    required uint16  block  = 1
    required payload data

Object<TFTP> TFTP_ACK
    required uint16 opcode = 4
        ACK = 4
    required uint16 block  = 0

Object<TFTP> TFTP_ERROR
    required uint16  opcode = 5
        ERROR = 5
    required uint16  code   = 0
        ERR_UNDEFINED        = 0
        ERR_FILE_NOT_FOUND   = 1
        ERR_ACCESS_VIOLATION = 2
        ERR_DISK_FULL        = 3
        ERR_ILLEGAL_OP       = 4
        ERR_UNKNOWN_TID      = 5
        ERR_FILE_EXISTS      = 6
        ERR_NO_SUCH_USER     = 7
    required cstring msg
```

### Automatic dispatch — same as Spicy

```
# Spicy:  spicy-driver dispatches automatically on opcode
# pcapsh: Object<TFTP> grouping gives the same behaviour

pcapsh >>> show("TFTP", fromhex("00 04 00 07"))
<TFTP_ACK opcode=ACK(4) block=7 |

pcapsh >>> show("TFTP", fromhex("00 03 00 01 48 65 6c 6c 6f"))
<TFTP_DATA opcode=DATA(3) block=1 data='Hello' |

pcapsh >>> show("TFTP", fromhex("00 05 00 01 46 69 6c 65 20 6e 6f 74 20 66 6f 75 6e 64 00"))
<TFTP_ERROR opcode=ERROR(5) code=ERR_FILE_NOT_FOUND(1) msg='File not found' |
```

The same works stacked under IP/UDP:

```
pcapsh >>> show("IP/UDP/TFTP", fromhex("45 00 00 20 ... 00 04 00 07"))
<IP src=192.168.1.1 dst=192.168.1.2 … |
<UDP sport=69 dport=69 … |
<TFTP_ACK opcode=ACK(4) block=7 |
```

`ls(TFTP)` shows all sub-protocols and their dispatch values:

```
pcapsh >>> ls(TFTP)
TFTP sub-protocols:
  TFTP_RRQ             (first field opcode = 1)
  TFTP_WRQ             (first field opcode = 2)
  TFTP_DATA            (first field opcode = 3)
  TFTP_ACK             (first field opcode = 4)
  TFTP_ERROR           (first field opcode = 5)
```

Direct sub-protocol names still work alongside dispatch:

```
pcapsh >>> show("IP/UDP/TFTP_ACK", fromhex("… 00 04 00 07"))
```

### Build a complete TFTP exchange

```
# tftp_exchange.pcapsh
s = TCPSession("192.168.1.1", "192.168.1.2", 1069, 69)

# UDP exchange — pcapsh session helpers are TCP-only, so build raw UDP packets:
wrpcap("/tmp/tftp.pcapng", IP(src="192.168.1.1",dst="192.168.1.2")/UDP(sport=1069,dport=69)/TFTP_RRQ(opcode=RRQ))
wrpcap("/tmp/tftp.pcapng", IP(src="192.168.1.2",dst="192.168.1.1")/UDP(sport=69,dport=1069)/TFTP_DATA(opcode=DATA,block=1))
wrpcap("/tmp/tftp.pcapng", IP(src="192.168.1.1",dst="192.168.1.2")/UDP(sport=1069,dport=69)/TFTP_ACK(opcode=ACK,block=1))
wrpcap("/tmp/tftp.pcapng", IP(src="192.168.1.2",dst="192.168.1.1")/UDP(sport=69,dport=1069)/TFTP_DATA(opcode=DATA,block=2))
wrpcap("/tmp/tftp.pcapng", IP(src="192.168.1.1",dst="192.168.1.2")/UDP(sport=1069,dport=69)/TFTP_ACK(opcode=ACK,block=2))
```

```bash
pcapsh tftp_exchange.pcapsh
# → Wrote N bytes to /tmp/tftp.pcapng   (×5)
tshark -r /tmp/tftp.pcapng
```

Open `/tmp/tftp.pcapng` in Wireshark — all five packets appear with correct TFTP dissection
because the layer types and port 69 are standard.

---

## Part 5 — Complete protocol definition

Spicy ends with a single unified grammar file. The posa equivalent is what lives in
`~/.pcapsh_protos.posa` — auto-loaded at every pcapsh startup.

The file is created automatically on first run with TFTP and Telnet definitions. The full TFTP
block uses `Object<TFTP>` so that `show("TFTP", …)` dispatches automatically:

```
# ── TFTP (RFC 1350) ─────────────────────────────────────────────────────────
Object<TFTP> TFTP_RRQ
    required uint16  opcode   = 1
        RRQ = 1
    required cstring filename
    required cstring mode

Object<TFTP> TFTP_WRQ
    required uint16  opcode   = 2
        WRQ = 2
    required cstring filename
    required cstring mode

Object<TFTP> TFTP_DATA
    required uint16  opcode = 3
        DATA = 3
    required uint16  block  = 1
    required payload data

Object<TFTP> TFTP_ACK
    required uint16 opcode = 4
        ACK = 4
    required uint16 block  = 0

Object<TFTP> TFTP_ERROR
    required uint16  opcode = 5
        ERROR = 5
    required uint16  code   = 0
        ERR_UNDEFINED        = 0
        ERR_FILE_NOT_FOUND   = 1
        ERR_ACCESS_VIOLATION = 2
        ERR_DISK_FULL        = 3
        ERR_ILLEGAL_OP       = 4
        ERR_UNKNOWN_TID      = 5
        ERR_FILE_EXISTS      = 6
        ERR_NO_SUCH_USER     = 7
    required cstring msg
```

After startup every pcapsh session has `TFTP_ACK`, `TFTP_DATA`, `TFTP_ERROR`, `TFTP_RRQ`, and
`TFTP_WRQ` available, plus automatic dispatch through the `TFTP` parent name:

```
pcapsh >>> ls(TFTP_ACK)
TFTP_ACK fields:
  (sub-protocol of TFTP)
  opcode  uint16  [ACK=0x4]
  block   uint16

pcapsh >>> TFTP_ACK(block=42)
<TFTP_ACK opcode=4 block=42>

pcapsh >>> show("TFTP", fromhex("00 05 00 01"))
<TFTP_ERROR opcode=ERROR(5) code=ERR_FILE_NOT_FOUND(1) msg='' |

pcapsh >>> ls(TFTP)
TFTP sub-protocols:
  TFTP_RRQ             (first field opcode = 1)
  TFTP_WRQ             (first field opcode = 2)
  TFTP_DATA            (first field opcode = 3)
  TFTP_ACK             (first field opcode = 4)
  TFTP_ERROR           (first field opcode = 5)
```

---

## Differences from Spicy — summary

| Feature | Spicy | pcapsh/posa |
|---------|-------|-------------|
| Field types | rich type system incl. `bytes &until`, bitfields, vectors | fixed-width integers, mac, ip4, cstring, payload, bytes\<N\>, bytes[field] |
| Runtime dispatch | `switch(self.field)` in grammar | `Object<parent>` grouping — `show("TFTP", …)` dispatches on first field |
| Variable-length fields | `bytes &eod`, `bytes &until=b"\x00"` | `cstring` (null-terminated), `payload` (rest of packet), `bytes[lenfield]` |
| Null-terminated strings | `bytes &until=b"\x00"` | `cstring` field |
| Packet construction | not a goal — Spicy is parser-only | first-class: `TFTP_ACK(block=5)`, stacking with `/` |
| Output format | Zeek logs, `spicy-driver` stdout | pcapng files readable by Wireshark/tshark |
| Integration | Zeek network monitor | standalone shell + pcapng writer |

The tools are complementary: use pcapsh to build and replay test traffic, open the resulting
pcapng in Wireshark, then write a Spicy analyzer against the same protocol structure.

---

## Inline definition vs `.posa` file

The inline `protocol … end` block (REPL or script) and the `.posa` file format are the same
language. The only difference is lifecycle:

```
# Inline — lives for this session only
protocol TFTP_ACK
    required uint16 opcode = 4
        ACK = 4
    required uint16 block = 0
end

# Persistent — add the Object<TFTP> form to ~/.pcapsh_protos.posa
# so the full dispatch group is available in every future session.
# Object<TFTP> (not Object<main>) tags each type as a TFTP sub-protocol
# and enables show("…/TFTP", data) to dispatch automatically on opcode.
Object<TFTP> TFTP_ACK
    required uint16 opcode = 4
        ACK = 4
    required uint16 block = 0
```

This mirrors the Spicy workflow where you develop in a `.spicy` file and eventually integrate
the grammar into a Zeek package.

---

## Quick reference

```bash
# Run one-liner — direct sub-protocol
pcapsh -e 'show("TFTP_ACK", fromhex("00 04 00 07"))'

# Run one-liner — automatic dispatch (requires Object<TFTP> definitions loaded)
pcapsh -e 'show("IP/UDP/TFTP", fromhex("45 00 00 20 00 01 40 00 40 11 00 00 c0 a8 01 01 c0 a8 01 02 00 45 00 45 00 0c 00 00 00 04 00 07"))'

# Run a script
pcapsh tftp_exchange.pcapsh

# Interactive REPL with inline definition
pcapsh
>>> protocol TFTP_ACK
...     required uint16 opcode = 4
...         ACK = 4
...     required uint16 block = 0
... end
>>> TFTP_ACK(block=3)
>>> show("TFTP_ACK", fromhex("00 04 00 03"))

# Interactive REPL with automatic dispatch (after loading Object<TFTP> definitions)
>>> load("bin/tests/tftp_protos.posa")
>>> show("IP/UDP/TFTP", fromhex("..."))   # dispatches to TFTP_ACK, TFTP_DATA, etc.
>>> ls(TFTP)                              # lists all sub-protocols and their dispatch keys
>>> wrpcap("/tmp/out.pcapng", IP()/UDP(dport=69)/TFTP_ACK(block=1))

# Loop over every packet in a captured TFTP exchange
# range(N) starts at 1 — packet_number=1 is the first packet
for $i in range(20):
    show("IP/UDP/TFTP", frompcapng("tftp_session.pcapng", $i))
```

Full field and function reference: [bin/pcapsh.md](bin/pcapsh.md)  
posa syntax reference: [https://github.com/stricaud/libpcapng](https://github.com/stricaud/libpcapng)
