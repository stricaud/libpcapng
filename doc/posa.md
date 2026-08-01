# posa:�  declarative packet decoders

A `.posa` file describes how to decode a protocol. libpcapng interprets it and
builds the same field tree a hand-written C dissector would, so a posa decoder is
not a second-class citizen: it appears in the details pane, its fields work in
display filters, its bytes highlight in the hex pane, it names the Protocol and
Info columns, and it can ship its own coloring rules.

Nothing is compiled. You drop a file in the `protos/` directory (or write one in
carcal's editor: **Analyze ▸ Decoders ▸ Enter**, `^S` to save) and the protocol
is decoded on the next packet. DNS, IGMP, SMB2, HTTP, TLS and DHCP are all posa
files — read them next to this document; they are the worked examples.

---

## 1. A first decoder

```posa
Object<main> TFTP_RRQ
    abbrev "tftp"
    col "TFTP"

    required uint16  opcode = 1 "Opcode"
        RRQ = 1
    required cstring filename "Filename"
    required cstring mode "Mode"

    info "Read request: %s" filename

rule udp.port == 69 => TFTP_RRQ
```

* `Object<main> NAME` starts a decoder. `main` means "top level"; any other
  parent makes it a member of a group (§7).
* `abbrev "tftp"` prefixes every field name, so filters read `tftp.opcode == 1`.
  Without it fields are named after the object.
* `col "TFTP"` is the Protocol column. `info "…"` is the Info column (§8).
* `rule` binds it (§9).
* Indented `NAME = value` lines under a field are its enum labels (§4). For tables larger than 32 entries declare a `Lookup NAME` and reference it with `lookup NAME` on the field line.

Field lines are:

```
[type] <name> [until "<delim>"] [mask N] [hex] [= default] ["Label"]
```

`"Label"` is the display text in the tree (`Opcode: RRQ (1)`); without it the
field's name is used. Fields are required by default — decoding stops when there
are not enough bytes for a field. Add the `optional` keyword to fields that may
legitimately be absent; they are silently skipped when bytes run out.

The legacy `required` keyword is accepted and has the same effect as no keyword.
New files should omit it.

---

## 2. Types

| Type | Bytes | Notes |
|---|---|---|
| `uint8` `uint16` `uint24` `uint32` `uint64` | 1/2/3/4/8 | big-endian |
| `le_uint16` `le_uint32` `le_uint64` | 2/4/8 | little-endian (SMB2 is all little-endian) |
| `mac` | 6 | `aa:bb:cc:dd:ee:ff` |
| `ip4` | 4 | dotted quad |
| `ip6` | 16 | |
| `bytes<N>` | N | fixed-size opaque bytes |
| `bytes[lenfield]` | value of `lenfield` | opaque bytes, length taken from a field |
| `str[lenfield]` | value of `lenfield` | text, length from a field |
| `utf16[lenfield]` | value of `lenfield` | UTF-16LE text (SMB2 file and share names) |
| `cstring` | until `\0` | NUL-terminated text |
| `string … until "<delim>"` | until the delimiter | delimited text (HTTP lines) |
| `kvblock <name> [sep "<sep>"]` | until `\r\n\r\n` | MIME-style header block (see §3) |
| `dnsname` | one encoded name | DNS labels, following `0xc0` compression pointers |
| `payload` | all that is left | the rest of the enclosing scope |

Modifiers:

* `mask 0x7fff` — the value is masked before it is shown, matched against enums,
  and used by `when`. mDNS packs a flag into the top bit of the DNS class; the
  class is `class mask 0x7fff` and the flag is a `bits` field (§5).
* `hex` — show the number as `0x…` rather than decimal.
* `= N` — a default. On the **first** field of a group member it is also the
  magic used to dispatch (§7).

```posa
required le_uint32 flags hex "Flags"
required uint16 qclass mask 0x7fff "Class"
required utf16[name_length] filename "Filename"
```

---

## 3. Structure

Blocks are opened by a keyword and closed by **indentation** — there are no
braces. Anything indented under `when`, `scope` or `repeat` is inside it.

### `when <cond>:` / `else:`

```posa
when command == 5:
    when response == 0:
        required le_uint16 structure_size "Structure Size"
    when response == 1:
        required le_uint16 create_action "Create Action"
```

The condition is `<field> [& mask] <op> <value>`, with `op` one of
`== != < > <= >=`. The left side is a field parsed earlier, or the word
`remaining` (bytes left in the current scope). A bare `when field:` is true when
the field is non-zero.

`else:` runs when **no** `when` above it, at the same indent, ran. DHCP uses it
to give an option it does not decode its raw value anyway:

```posa
when opt_code == 53:
    required uint8 msg_type "DHCP Message Type"
when opt_code == 1:
    required ip4 opt_ip "Subnet Mask"
else:
    required payload opt_value "Value"
```

### `scope <lenfield>`

Bounds the fields inside it to `lenfield` bytes, counted from where that field
ended. When the block closes, decoding continues **at the end of the scope**
whether or not everything inside was decoded. This is what keeps a walk aligned
across records you have never heard of:

```posa
required uint16 rdlength "Data length"
scope rdlength
    when type == 1:
        required ip4 rdata "Address"
    # an unknown RR type decodes nothing, and the next record still starts right
```

### `repeat`

```posa
repeat <countfield> as <item> ["Section title"]     # exactly N records
repeat until end as <item> ["Section title"]        # until the enclosing scope runs out
repeat until "<delim>" as <item> ["Section title"]  # until those bytes come next
```

Each iteration becomes its own subtree, named `<abbrev>.<item>` so you can filter
on it. With a section title the records are grouped under one node.

```posa
repeat questions as query "Queries"
    label "%s: type %s, class %s" qname, qtype, qclass
    required dnsname qname "Name"
    required uint16 qtype "Type"
    required uint16 qclass mask 0x7fff "Class"
```

* `repeat <countfield>` — a count in the packet (DNS `Questions: 5`, SMB2's
  dialect count, IGMPv3's group-record count).
* `repeat until end` — no count anywhere: TLS records, DHCP options, TXT strings.
  It stops at the end of the enclosing `scope` (or of the packet).
* `repeat until "<delim>"` — stops when the delimiter comes next. An HTTP header
  block ends at a blank line, so its headers are `repeat until "\r\n"`.

Records can nest: an IGMPv3 report repeats group records, and each group record
repeats its source addresses.

### `kvblock` — MIME-style key: value header blocks

Many text protocols share the same header format: lines of `Key: Value\r\n`,
terminated by a blank line (`\r\n\r\n`). Pre-declaring every possible header name
is fragile — field order varies, extensions add new names, and the list grows
without bound.

`kvblock` parses the entire block in one shot, emitting a child field for each
line it finds:

```posa
Object<SIP> SIP_RESPONSE
    abbrev "sip"

    string version     until " "    "SIP-Version"
    string status_code until " "    "Status-Code"
    string reason      until "\r\n" "Reason-Phrase"

    kvblock headers "Headers"

    payload body "Message Body"

    info "%s %s [%s]" status_code, reason, call_id
```

Each `Key: Value\r\n` line becomes a child field:
- Header `Via: SIP/2.0/UDP 10.0.0.1:5060` → field abbrev `sip.headers.via`, value `SIP/2.0/UDP 10.0.0.1:5060`
- Header `Content-Type: application/sdp` → `sip.headers.content_type`
- Header `Call-ID: abc123@host` → `sip.headers.call_id`

Key normalization: lowercase, hyphens and spaces replaced by underscore.

The child fields are also added to the `seen` table under their normalized name,
so `info` can reference them directly:
```posa
info "%s %s [%s]" status_code, reason, call_id
#                                       ^^^^^^^ from kvblock headers
```

The block end sentinel defaults to `"\r\n\r\n"` (blank line). A custom
key-value separator can be supplied with `sep "..."` (default `": "`):

```posa
kvblock headers sep "= " "Parameters"   # "Key= Value\r\n" format
```

Wireshark-style aliases connect the kvblock child fields to human-friendly names:

```posa
alias sip.Via          => sip.headers.via
alias sip.Content-Type => sip.headers.content_type
alias sip.Call-ID      => sip.headers.call_id
```

### `label "<fmt>" arg, arg`

Titles the record of the `repeat` it sits in, from the fields that record just
parsed (`%s` display text, `%u`/`%d` number, `%x` hex):

```
Queries
  _airplay._tcp.local: type PTR, class IN
```

An argument naming a field this record does not have expands to nothing, and the
gap it leaves is closed — so one label can serve a record whose shape varies.

---

## 4. Enums

Indented `NAME = value` lines under a numeric field label it. The name is display
text and **may contain spaces**:

```posa
uint8 type "Type"
    Membership Query = 0x11
    IGMPv3 Membership Report = 0x22
```

shows as `Type: IGMPv3 Membership Report (34)`, and `%s` in a `label`/`info`
gives the name rather than the number.

Enum values are normally **numbers** (decimal, hex, or `0b` binary):

```posa
uint8 type "Type"
    Membership Query = 0x11
    IGMPv3 Membership Report = 0x22
```

For text-protocol fields — SIP status codes, HTTP methods, SMTP replies, any
field where the wire value is ASCII — use **string-keyed enums**: quote the key
on the left and the label on the right:

```posa
string status_code until " " "Status-Code"
    "200" = "OK"
    "404" = "Not Found"
    "503" = "Service Unavailable"
```

The runtime matches the field's string value against the quoted key and shows
`Status-Code: OK (200)` in the tree. The raw value `200` is stored in the seen
table so `info` and `when` comparisons still work with the original wire text.

Identity enums (`"OK" = "OK"` where key and label are identical) are valid but
pointless — omit them.

The per-field enum array holds up to **32 entries**. When a protocol has more
(SIP has 46 status codes), declare a **Lookup table** instead:

```posa
Lookup SipStatusCodes
    "100" = "Trying"
    "180" = "Ringing"
    "200" = "OK"
    "404" = "Not Found"
    # … up to 128 entries …

string status_code until " " lookup SipStatusCodes "Status-Code"
```

`Lookup NAME` declares a named table at file scope (outside any Object). A field
references it with `lookup NAME` on its field line. The runtime checks the inline
enums first, then the lookup table. Lookup tables hold up to **128 entries** and
can be referenced from multiple fields.

---

## 5. `bits` — flags inside a field

```posa
required le_uint32 flags hex "Flags"
    bits flags response 0 1 "Direction"
        Request = 0
        Response = 1
    bits flags async 1 1 "Async command"
```

`bits <srcfield> <name> <shift> <width> ["Label"]` carves a value out of a field
already parsed: `(src >> shift) & ((1 << width) - 1)`. It consumes no bytes, it
highlights the source field's bytes, it takes enums, and it can be used by `when`
— which is how SMB2 picks a request body from a response body, and how DNS shows
the mDNS cache-flush and QU bits.

`bits` reads the **raw** value, before any `mask`, so masking a field and
carving a flag out of the bit you masked away both work at once.

---

## 6. `seek` — fields that are not in field order

```posa
required le_uint16 path_offset "Path Offset"
required le_uint16 path_length "Path Length"
seek path_offset
required utf16[path_length] path "Tree"
```

`seek <offsetfield>` continues at the offset that field holds, counted from the
start of the current object. SMB2 puts its variable parts (share paths, file
names, security blobs) at an offset from the SMB2 header rather than laying them
out in order; without `seek` they could not be reached at all.

`seek <number>` seeks to a literal offset. HTTP uses `seek 0` to rewind over the
4-byte magic it was dispatched on and re-read the status line as text.

---

## 7. Composition: `layer`, `Object<group>`, `include`

**`layer <name> <Proto>`** decodes a sub-protocol at the current offset, as its
own subtree. Offsets inside it are relative to where it starts — which is exactly
what a `dnsname` or a `seek` needs:

```posa
Object<main> NBSS
    required uint8 msg_type "Message Type"
    required uint24 length "Length"
    scope length
        layer smb SMB
```

**`Object<GROUP> NAME`** makes the object a member of a group. Dissecting the
group name picks the member whose **first field's value** equals its `= default`
— the magic. `Object<GROUP> NAME default` marks the member to use when nothing
matched:

```posa
Object<SMB> SMB2
    required uint32 protocol_id = 0xFE534D42 hex "Protocol ID"
Object<SMB> SMB1
    required uint32 protocol_id = 0xFF534D42 hex "Protocol ID"
```

An HTTP response starts with the magic `HTTP`; a request starts with a method, so
`HTTP_REQUEST` is the group's `default`.

**`include <Object>`** inlines another object's fields *here*, in the current
scope — unlike `layer` it does not create a sub-protocol, so a `label` can name
the included fields and a `when` can test them. DNS defines a resource record
once and includes it in the answer, authority and additional sections:

```posa
repeat answers as answer "Answers"
    label "%s: type %s, class %s, %s" name, type, class, rdata
    include RR
```

The included object must be defined before the file that includes it (same file,
earlier).

---

## 8. The Info column

```posa
info "%s 0x%x %s %s %s %s" qr, id, qtype, qname, type, rdata
```

Arguments are field names; `%s` is display text, `%u`/`%d` a number, `%x` hex. A
field the packet does not carry expands to nothing and the gap closes, so one
format can serve both directions of a protocol — a DNS query has questions and no
records, a response usually the reverse, and the same line reads
`Query 0x0 PTR _rdlink._tcp.local` or `Response 0x0 PTR Skywalker._airplay._tcp.local`.

Inside a `repeat`, `info` sees the **first** record's values (Wireshark's habit);
`label` sees its own record's. The innermost `layer` that sets `info` wins, and
so does the innermost `col`: NetBIOS frames SMB2, and the packet reads `SMB2`.

---

## 9. Binding: `rule`

Rules tell the dissector which decoder to apply to a payload. A rule bound by a
`.posa` file is tried **before** the built-in C dissectors, so a decoder takes
over a protocol without touching the library. In carcal you can also bind at
runtime: **Analyze ▸ Decode As…**.

### Port and protocol rules

```posa
rule tcp.port == 445    => NBSS      # src OR dst port
rule tcp.dstport == 69  => TFTP      # destination port only
rule udp.port == 53     => DNS
rule ip.proto == 2      => IGMP      # IP protocol number — IGMP has no port
rule eth.type == 0x88cc => LLDP      # ethertype
```

`tcp.port` and `udp.port` match when **either** the source or destination port
equals the value. Use `tcp.srcport` / `tcp.dstport` (or the UDP equivalents) to
restrict to one direction.

### Content signatures — protocol without a fixed port

```posa
rule tcp.content "\x16\x03"         => TLS
rule tcp.content "HTTP/1."          => HTTP
rule tcp.content "GET "             => HTTP
rule udp.content "\xff\xfe\xfd"     => DTLS
rule content     "SSH-"             => SSH
```

`rule [tcp.|udp.]content "<bytes>" => Proto` matches when the application
payload **starts** with the given bytes, regardless of port. This is the primary
tool for protocols that run on non-standard ports.

* `tcp.content` — only TCP payloads
* `udp.content` — only UDP payloads
* `content` (no prefix) — any transport

Content rules are tried **after** port rules, so a connection on the registered
port is handled by the port rule and content scanning is skipped; a connection on
an arbitrary port falls through to content detection.

Byte strings use `\xNN` escapes and literal text:

```posa
rule tcp.content "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" => BGP
rule tcp.content "AMQP"    => AMQP
rule tcp.content "SSH-"    => SSH
```

**Offset variant** — `content@N` checks at byte offset N from the start of the
payload, not byte 0. STUN's magic cookie is at offset 4:

```posa
rule udp.content@4 "\x21\x12\xa4\x42" => STUN
rule tcp.content@4 "\xfeSMB"          => NBSS
```

### IPv4 CIDR rules — protocol identified by host address

When a protocol has no usable content signature and no fixed port, you can bind
by the remote host's IP address using CIDR notation:

```posa
rule ip4.addr in 149.154.160.0/20 => TELEGRAM   # src OR dst in block
rule ip4.src  in 91.108.4.0/22    => TELEGRAM   # source only
rule ip4.dst  in 10.0.0.0/8       => INTERNAL   # destination only
```

Three field variants:
* `ip4.addr` — matches if **either** the source or destination IP falls inside the block
* `ip4.src`  — matches on source IP only
* `ip4.dst`  — matches on destination IP only

Multiple CIDR rules for the same protocol name are OR'd together; the first match
wins. The same syntax works in display filters:

```
ip.addr == 149.154.160.0/20
ip.addr in { 149.154.160.0/20 91.108.4.0/22 91.108.8.0/22 }
```

IP CIDR rules are checked **after** content rules and **before** port rules.

### Group member dispatch with `starts`

Inside an `Object<GROUP>` member, `starts` restricts that member to payloads
whose content begins with one of the given prefixes. It acts like a per-member
content filter within the group's dispatch:

```posa
Object<HTTP> HTTP_REQUEST
    abbrev "http"
    starts "GET " "POST " "PUT " "HEAD " "DELETE " "OPTIONS " "TRACE " "CONNECT " "PATCH "

    required string method until " " "Method"
    …
```

Without `starts`, the group would try to parse every payload that matched the
group's port rule as a request — `starts` prevents mid-stream TCP segments
(which look like raw binary) from being mis-decoded as a request line.

Combine `starts` with a magic-field default for groups that have a byte-level
marker: the `HTTP_RESPONSE` member checks for the 4-byte `HTTP` ASCII magic,
while the `HTTP_REQUEST` member uses `starts` for the method keywords.

---

## 10. Filter aliases: `alias`

```posa
alias http.request        => http.method
alias http.request.method => http.method
alias http.request.uri    => http.uri
```

`alias <name> => <target>` declares a filter synonym. The alias name works
anywhere a field name does in a display filter, and the comparison operator
distributes across all targets if a list is given:

```posa
alias tcp.port => tcp.srcport tcp.dstport
# tcp.port == 80  ≡  tcp.srcport == 80 or tcp.dstport == 80
```

**Expression macros** — when the right-hand side is a full filter expression,
the alias name expands to that expression:

```posa
alias http.error => http.response.code >= 400
# http.error  ≡  http.response.code >= 400
```

Macros let you name multi-field conditions and reuse them in color rules or
`rdpcap` filters without repeating the expression. A `.posa` file typically
declares Wireshark-compatible aliases so that filters written against Wireshark
field names work unchanged:

```posa
alias http.request.line   => http.method   # Wireshark compat
alias http.response.code  => http.status_code
alias tls.handshake.type  => tls.handshake_type
```

---

## 11. Coloring

```posa
color dns.rcode > 0 => yellow red
color dns           => white blue
```

`color <display filter> => <fg> <bg>`, first match wins, consulted before the
front end's generic rules. libpcapng carries the names; carcal maps them onto its
palette. A decoder therefore ships its own look.

---

## 12. Worked example: DHCP options end to end

```posa
repeat until end as option "Options"
    label "%s: %s%s%s" opt_code, msg_type, opt_ip, opt_text
    required uint8 opt_code "Option"
        DHCP Message Type = 53
        Host Name = 12
        End = 255
    when opt_code > 0:                 # Pad (0) has no length byte
        when opt_code < 255:           # End (255) has none either
            required uint8 opt_len "Length"
            scope opt_len
                when opt_code == 53:
                    required uint8 msg_type "DHCP Message Type"
                        Discover = 1
                        Offer = 2
                when opt_code == 12:
                    required str[opt_len] opt_text "Host Name"
                else:
                    required payload opt_value "Value"
```

produces

```
Options
  DHCP Message Type: Discover
    Option: DHCP Message Type (53)
    Length: 1
    DHCP Message Type: Discover (1)
  Host Name: laptop1
    Option: Host Name (12)
    Length: 7
    Host Name: laptop1
  Client Identifier:
    Option: Client Identifier (61)
    Length: 3
    Value: 3 bytes
```

---

## 13. Worked example: protocol on a non-standard port

Suppose you have an internal binary RPC protocol that runs on port 9000 in
production but on a random ephemeral port during local testing. With port rules
alone the test traffic goes unrecognised. The content approach decodes it on any
port:

```posa
# myrpc.posa — binary RPC with a 4-byte magic header
Object<main> MyRPC
    abbrev "myrpc"
    col "MyRPC"

    required uint32 magic = 0xDEADBEEF hex "Magic"
    required uint8  version "Version"
    required uint8  msg_type "Message Type"
        Request  = 1
        Response = 2
        Error    = 3
    required uint16 request_id "Request ID"
    required uint32 payload_length "Payload Length"
    required payload body "Body"

    info "%s id=%u" msg_type, request_id

# Primary binding — production port
rule tcp.port == 9000 => MyRPC

# Content signature — any port, any direction.
# The 4-byte magic at offset 0 identifies the protocol unambiguously.
rule tcp.content "\xde\xad\xbe\xef" => MyRPC

color myrpc.msg_type == 3 => yellow red    # errors
color myrpc               => white darkblue
```

After dropping this file in the protos directory (no rebuild required), every
TCP connection whose payload opens with `0xDEADBEEF` is decoded as MyRPC —
regardless of port. The port rule still takes precedence on port 9000, so that
path costs no content scan.

When the magic alone is not distinctive enough (many protocols share common
prefixes), add `content@N` to match at a non-zero offset, or combine a
magic-field default with `starts` inside a group.

---

## 14. Limits and gotchas

* **Indentation defines blocks.** A field indented under a `when` is inside it; a
  line at the same indent as the `when` closes it. Mixed tabs and spaces will
  bite you.
* **Enum names may contain spaces; field names may not.**
* `scope` needs a **length field**, and measures from the end of that field.
* A `repeat` that would consume zero bytes stops, rather than spinning; there is
  also a hard cap of 4096 iterations per loop.
* A field's abbrev is `<abbrev>.<name>`. Two fields with the same name in
  different branches share one abbrev — usually what you want (`smb2.filename`),
  occasionally not.
* A `seek` can only go where a field or a literal points; there is no arithmetic.
* No checksum validation, no reassembly across packets, no decryption. A decoder
  sees one packet's bytes.
* `pcapng_posa_to_text()` reconstructs a *normalized* subset of a decoder and is
  lossy; the original text is kept and is what carcal shows you when you edit.

## 15. Where the files live

* carcal loads every `*.posa` in its protos directory at startup — the one it was
  built with, or `$CARCAL_PROTOS_DIR` if you set it. Port bindings can also be
  added there in `decoders.rules`.
* libpcapng embeds a couple of decoders (RDP) so the library decodes them with no
  files at all.
* A protocol redefined by name **replaces** the earlier one — drop your own
  `dns.posa` in `protos/` and it wins over the shipped one.

## 16. API

```c
#include <libpcapng/posa.h>

pcapng_posa_load_file("protos/dns.posa", err, sizeof err);
pcapng_posa_load_dir("protos");
pcapng_posa_load_text(src, err, sizeof err);

int n = pcapng_posa_count();
const pcapng_posa_proto_t *p = pcapng_posa_find("DNS");
const char *src = pcapng_posa_source("DNS");   /* the text it was parsed from */

pcapng_posa_dissect("DNS", data, len, parent, abs_off, info, sizeof info);
```

Decoders bound by `rule` are applied automatically by `pcapng_dissect()` — you
only call `pcapng_posa_dissect()` to decode something explicitly.
