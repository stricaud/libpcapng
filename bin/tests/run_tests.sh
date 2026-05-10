#!/usr/bin/env bash
# run_tests.sh — run pcapsh tests and validate output

set -uo pipefail

PCAPSH=${PCAPSH:-./build/bin/pcapsh}
PASS=0
FAIL=0
ERRORS=()

ok()   { echo "  PASS: $1"; ((PASS++)); }
fail() { echo "  FAIL: $1"; ((FAIL++)); ERRORS+=("$1"); }

check() {
    local desc="$1"; local expr="$2"; local expected="$3"
    local out
    out=$("$PCAPSH" -e "$expr" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
    if echo "$out" | grep -q "$expected"; then
        ok "$desc"
    else
        fail "$desc — expected '$expected', got: $out"
    fi
}

check_absent() {
    local desc="$1"; local expr="$2"; local absent="$3"
    local out
    out=$("$PCAPSH" -e "$expr" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
    if echo "$out" | grep -q "$absent"; then
        fail "$desc — '$absent' should NOT appear in: $out"
    else
        ok "$desc"
    fi
}

echo "=== pcapsh test suite ==="
echo ""

# ── Protocol display ──────────────────────────────────────────────────────────
echo "-- Protocol display --"
check "DNS() shows named fields"    'DNS()'     '<DNS '
check "DNS() has id field"          'DNS()'     'id='
check "DNS() has flags field"       'DNS()'     'flags='
check "DNS() has qdcount field"     'DNS()'     'qdcount='
check_absent "DNS() hides _qd"      'DNS(qd=DNSQR(qname="x.com"))' '_qd='
check "IP() shows named fields"     'IP()'      '<IP '
check "TCP() shows named fields"    'TCP()'     '<TCP '
check "UDP() shows named fields"    'UDP()'     '<UDP '
check "ICMP() shows named fields"   'ICMP()'    '<ICMP '
check "Ether() shows named fields"  'Ether()'   '<Ether '
check "ARP() shows named fields"    'ARP()'     '<ARP '
check "NTP() shows named fields"    'NTP()'     '<NTP '
check "SMB2() shows named fields"   'SMB2()'    '<SMB2 '

# ── DNS flag bits ─────────────────────────────────────────────────────────────
echo ""
echo "-- DNS flag bits --"
check "DNS rd=1 gives flags=256"    'DNS(rd=1)'                  'flags=256'
check "DNS qr=1 gives flags=32768"  'DNS(qr=1)'                  'flags=32768'
check "DNS explicit flags override" 'DNS(flags=0x8180)'          'flags=33152'
check "DNS rcode=3 (NXDOMAIN)"      'DNS(qr=1,rcode=3)'          'flags=32771'

# ── DNS record counts ─────────────────────────────────────────────────────────
echo ""
echo "-- DNS record counts --"
check "DNSQR auto-increments qdcount" 'DNS(rd=1,qd=DNSQR(qname="a.com"))' 'qdcount=1'
check "DNSRR sets ancount=1"          'DNS(qr=1,an=DNSRR(rrname="a.com",type=A,ttl=60,rdata="1.2.3.4"),ancount=1)' 'ancount=1'
check "Explicit qdcount respected"    'DNS(rd=1,qdcount=2)'                'qdcount=2'

# ── Wire format (raw bytes) ───────────────────────────────────────────────────
echo ""
echo "-- DNS wire format --"
# DNS query raw bytes: check for 'example' label \x07example
check "DNS qname label encoding" \
    'raw(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(id=0x1234,rd=1,qd=DNSQR(qname="example.com")))' \
    'example'
# Check rd=1 bit appears as \x01\x00 in flags position
check "DNS rd=1 wire flags byte" \
    'raw(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(id=0x0001,rd=1,qd=DNSQR(qname="x.com")))' \
    '\\x01\\x00'

# ── DNSQR qtypes ─────────────────────────────────────────────────────────────
echo ""
echo "-- DNSQR qtype encoding --"
check "DNSQR qtype=A"    'raw(IP()/UDP(dport=53)/DNS(qd=DNSQR(qname="a.com",qtype=A)))'    '\\x00\\x01\\x00\\x01'
check "DNSQR qtype=MX"   'raw(IP()/UDP(dport=53)/DNS(qd=DNSQR(qname="a.com",qtype=MX)))'   '\\x00\\x0f\\x00\\x01'
check "DNSQR qtype=AAAA" 'raw(IP()/UDP(dport=53)/DNS(qd=DNSQR(qname="a.com",qtype=AAAA)))' '\\x00\\x1c\\x00\\x01'
check "DNSQR qtype=PTR"  'raw(IP()/UDP(dport=53)/DNS(qd=DNSQR(qname="a.com",qtype=PTR)))'  '\\x00\\x0c\\x00\\x01'
check "DNSQR qtype=ANY"  'raw(IP()/UDP(dport=53)/DNS(qd=DNSQR(qname="a.com",qtype=ANY)))'  '\\x00\\xff\\x00\\x01'

# ── RandShort ─────────────────────────────────────────────────────────────────
echo ""
echo "-- RandShort --"
check "RandShort() produces numeric id" 'DNS(id=RandShort())' 'id='

# ── ls() ─────────────────────────────────────────────────────────────────────
echo ""
echo "-- ls() field listing --"
check "ls(DNS) shows id field"      'ls(DNS)'   'id'
check "ls(DNS) shows flags field"   'ls(DNS)'   'flags'
check "ls(DNS) shows qd field"      'ls(DNS)'   'qd'
check "ls(IP) shows src field"      'ls(IP)'    'src'
check "ls(TCP) shows flags field"   'ls(TCP)'   'flags'
check "ls(SMB2) shows command"      'ls(SMB2)'  'command'
check "ls(ARP) shows op field"      'ls(ARP)'   'op'

# ── ARP enums ─────────────────────────────────────────────────────────────────
echo ""
echo "-- ARP enum values --"
check "ARP op=REQUEST gives op=1"  'ARP(op=REQUEST)' 'op=1'
check "ARP op=REPLY gives op=2"    'ARP(op=REPLY)'   'op=2'

# ── SMB2 enums ────────────────────────────────────────────────────────────────
echo ""
echo "-- SMB2 enum values --"
check "SMB2 NEGOTIATE=0"   'SMB2(command=NEGOTIATE)' 'command=0'
check "SMB2 READ=8"        'SMB2(command=READ)'      'command=8'
check "SMB2 WRITE=9"       'SMB2(command=WRITE)'     'command=9'

# ── RADIUS enums ──────────────────────────────────────────────────────────────
echo ""
echo "-- RADIUS enum values --"
check "RADIUS ACCESS_REQUEST=1"  'RADIUS(code=ACCESS_REQUEST)'  'code=1'
check "RADIUS ACCESS_ACCEPT=2"   'RADIUS(code=ACCESS_ACCEPT)'   'code=2'
check "RADIUS ACCESS_REJECT=3"   'RADIUS(code=ACCESS_REJECT)'   'code=3'

# ── NTP enums ─────────────────────────────────────────────────────────────────
echo ""
echo "-- NTP enum values --"
check "NTP CLIENT=0x1b"  'NTP(li_vn_mode=CLIENT)' 'li_vn_mode=27'
check "NTP SERVER=0x1c"  'NTP(li_vn_mode=SERVER)' 'li_vn_mode=28'

# ── Layer stacking ────────────────────────────────────────────────────────────
echo ""
echo "-- Layer stacking --"
check "IP/TCP stacks"            'IP()/TCP()'              '<IP '
check "IP/UDP/DNS stacks"        'IP()/UDP()/DNS()'        '<DNS '
check "Ether/IP/TCP stacks"      'Ether()/IP()/TCP()'      '<Ether '
check "IP/TCP with payload"      'IP()/TCP()/"hello"'      '<Raw '
check "DNS in chain shows named" 'IP()/UDP()/DNS(rd=1)'    'flags=256'

# ── wrpcap creates file ───────────────────────────────────────────────────────
echo ""
echo "-- wrpcap file creation --"
rm -f /tmp/pcapsh_test_out.pcapng
"$PCAPSH" -e 'wrpcap("/tmp/pcapsh_test_out.pcapng", IP()/TCP())' 2>&1 > /dev/null
if [[ -f /tmp/pcapsh_test_out.pcapng ]]; then
    ok "wrpcap creates pcapng file"
    # Check pcapng magic bytes: 0a0d0d0a
    magic=$(xxd /tmp/pcapsh_test_out.pcapng | head -1 | awk '{print $2$3}')
    if [[ "$magic" == "0a0d0d0a" ]]; then
        ok "pcapng file has correct magic"
    else
        fail "pcapng magic incorrect: $magic"
    fi
else
    fail "wrpcap did not create file"
fi

# ── wrpcap appends ────────────────────────────────────────────────────────────
rm -f /tmp/pcapsh_test_append.pcapng
"$PCAPSH" -e 'wrpcap("/tmp/pcapsh_test_append.pcapng", IP()/TCP())' 2>&1 > /dev/null
size1=$(wc -c < /tmp/pcapsh_test_append.pcapng)
"$PCAPSH" -e 'wrpcap("/tmp/pcapsh_test_append.pcapng", IP()/UDP())' 2>&1 > /dev/null
size2=$(wc -c < /tmp/pcapsh_test_append.pcapng)
if [[ $size2 -gt $size1 ]]; then
    ok "wrpcap appends to existing file"
else
    fail "wrpcap did not append (size unchanged: $size1)"
fi

# ── Script file execution ─────────────────────────────────────────────────────
echo ""
echo "-- Script execution --"
SCRIPT=$(mktemp /tmp/pcapsh_test_XXXXXX.pcapsh)
cat > "$SCRIPT" <<'EOF'
a = IP(dst="1.2.3.4")/TCP(dport=443,flags="S")
hexdump(a)
wrpcap("/tmp/pcapsh_script_out.pcapng", a)
EOF
rm -f /tmp/pcapsh_script_out.pcapng
"$PCAPSH" "$SCRIPT" 2>&1 > /dev/null
if [[ -f /tmp/pcapsh_script_out.pcapng ]]; then
    ok "script file executes and creates pcapng"
else
    fail "script file did not create pcapng"
fi
rm -f "$SCRIPT"

# ── Full DNS exchange via script ──────────────────────────────────────────────
echo ""
echo "-- DNS exchange script --"
rm -f /tmp/pcapsh_dns_exchange.pcapng
"$PCAPSH" bin/tests/test_dns.pcapsh 2>&1 > /dev/null || true
if [[ -f /tmp/test_dns.pcapng ]]; then
    ok "DNS exchange script creates pcapng"
else
    fail "DNS exchange script did not create /tmp/test_dns.pcapng"
fi

# ── TCP session script ────────────────────────────────────────────────────────
echo ""
echo "-- TCP session script --"
rm -f /tmp/test_http.pcapng
"$PCAPSH" bin/tests/test_tcp_session.pcapsh 2>&1 > /dev/null || true
if [[ -f /tmp/test_http.pcapng ]]; then
    ok "TCP session script creates http.pcapng"
else
    fail "TCP session script did not create /tmp/test_http.pcapng"
fi

# ── Inline protocol definition ────────────────────────────────────────────────
echo ""
echo "-- Inline protocol definition --"

# Basic protocol definition and use
check_inline() {
    local desc="$1"; local script="$2"; local expected="$3"
    local out
    out=$(printf '%s\n' "$script" | "$PCAPSH" /dev/stdin 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
    if echo "$out" | grep -q "$expected"; then
        ok "$desc"
    else
        fail "$desc — expected '$expected', got: $out"
    fi
}

check_inline "protocol block defines protocol" \
    "$(printf 'protocol Ping\n    required uint8 seq = 0\nend\nPing()')" \
    "Protocol 'Ping' defined"

check_inline "defined protocol is usable" \
    "$(printf 'protocol Ping\n    required uint8 seq = 0\nend\nPing(seq=42)')" \
    "seq=42"

check_inline "defined protocol shows in ls()" \
    "$(printf 'protocol Ping\n    required uint8 seq = 0\nend\nls(Ping)')" \
    "seq"

check_inline "enum values resolve in inline protocol" \
    "$(printf 'protocol Status\n    required uint8 code = 0\n        OK = 0\n        ERR = 1\nend\nStatus(code=ERR)')" \
    "code=1"

check_inline "le_uint32 field serializes little-endian" \
    "$(printf 'protocol WinH\n    required le_uint32 x = 0x01020304\nend\nraw(IP()/UDP()/WinH())')" \
    '\\x04\\x03\\x02\\x01'

check_inline "ip4 field in inline protocol" \
    "$(printf 'protocol Beacon\n    required ip4 addr = 0.0.0.0\nend\nBeacon(addr="1.2.3.4")')" \
    "addr=1.2.3.4"

check_inline "mac field in inline protocol" \
    "$(printf 'protocol Sensor\n    required mac id = 00:00:00:00:00:00\nend\nSensor(id="aa:bb:cc:dd:ee:ff")')" \
    "id=aa:bb:cc:dd:ee:ff"

check_inline "inline protocol stacks under IP/UDP" \
    "$(printf 'protocol P\n    required uint16 x = 0xBEEF\nend\nraw(IP()/UDP(dport=9)/P())')" \
    '\\xbe\\xef'

# Run the full inline protocol script
rm -f /tmp/test_inline.pcapng
"$PCAPSH" bin/tests/test_inline_protocol.pcapsh 2>&1 > /dev/null || true
if [[ -f /tmp/test_inline.pcapng ]]; then
    ok "inline protocol script creates pcapng"
else
    fail "inline protocol script did not create /tmp/test_inline.pcapng"
fi

# ── fromhex / show ────────────────────────────────────────────────────────────
echo ""
echo "-- fromhex / show --"
check "fromhex plain hex stream"       'fromhex("0001010000010000000000000000")' '<raw 14 bytes>'
check "fromhex space-separated"        'fromhex("00 01 01 00 00 01 00 00 00 00 00 00")' '<raw 12 bytes>'
check "show DNS from hex header"       'show("DNS", fromhex("00 01 01 00 00 01 00 00 00 00 00 00"))' '<DNS '
check "show DNS id field"              'show("DNS", fromhex("12 34 01 00 00 01 00 00 00 00 00 00"))' 'id=4660'
check "show DNS flags field"           'show("DNS", fromhex("00 01 01 00 00 01 00 00 00 00 00 00"))' 'flags=0x0100'
check "show DNS qdcount=1"             'show("DNS", fromhex("00 01 01 00 00 01 00 00 00 00 00 00"))' 'qdcount=1'

check_inline "show custom protocol field" \
    "$(printf 'protocol Sensor\n    required uint8 type = 0\n        TEMP = 1\nend\nshow("Sensor", fromhex("01"))')" \
    'type=TEMP'

check_inline "show custom protocol numeric" \
    "$(printf 'protocol Counter\n    required uint16 n = 0\nend\nshow("Counter", fromhex("00 64"))')" \
    'n=100'

check_inline "show wireshark-style dump" \
    "$(printf 'protocol H\n    required uint8 a = 0\n    required uint8 b = 0\nend\nshow("H", fromhex("0000   42 07            B."))')" \
    'a=66'

# ── show() stacked protocol dissection ────────────────────────────────────────
echo ""
echo "-- show() stacked dissection --"
# IP/UDP/DNS: 20+8+12 = 40 bytes
check "show IP/UDP/DNS prints IP layer" \
    'show("IP/UDP/DNS", fromhex("45 00 00 34 00 01 00 00 40 11 00 00 c0 a8 01 05 08 08 08 08 c3 a8 00 35 00 20 00 00 12 34 01 00 00 01 00 00 00 00 00 00"))' \
    '<IP '
check "show IP/UDP/DNS prints UDP layer" \
    'show("IP/UDP/DNS", fromhex("45 00 00 34 00 01 00 00 40 11 00 00 c0 a8 01 05 08 08 08 08 c3 a8 00 35 00 20 00 00 12 34 01 00 00 01 00 00 00 00 00 00"))' \
    'dport=53'
check "show IP/UDP/DNS prints DNS layer" \
    'show("IP/UDP/DNS", fromhex("45 00 00 34 00 01 00 00 40 11 00 00 c0 a8 01 05 08 08 08 08 c3 a8 00 35 00 20 00 00 12 34 01 00 00 01 00 00 00 00 00 00"))' \
    '<DNS '
check "show Ether/IP/TCP prints Ether layer" \
    'show("Ether/IP/TCP", fromhex("ff ff ff ff ff ff 00 11 22 33 44 55 08 00 45 00 00 28 00 01 00 00 40 06 00 00 c0 a8 01 01 c0 a8 01 02 00 50 1f 90 00 00 00 01 00 00 00 00 50 02 20 00 00 00 00 00"))' \
    '<Ether '
check "show Ether/IP/TCP prints TCP layer" \
    'show("Ether/IP/TCP", fromhex("ff ff ff ff ff ff 00 11 22 33 44 55 08 00 45 00 00 28 00 01 00 00 40 06 00 00 c0 a8 01 01 c0 a8 01 02 00 50 1f 90 00 00 00 01 00 00 00 00 50 02 20 00 00 00 00 00"))' \
    '<TCP '
check "show ARP (posa builtin) parses op" \
    'show("ARP", fromhex("00 01 08 00 06 04 00 01 aa bb cc dd ee ff c0 a8 01 01 00 00 00 00 00 00 c0 a8 01 02"))' \
    'op=REQUEST'
check "show IP/UDP/NTP (posa builtin stacked)" \
    'show("IP/UDP/NTP", fromhex("45 00 00 4c 00 01 40 00 40 11 00 00 c0 a8 01 01 c0 a8 01 02 c3 a8 00 7b 00 38 00 00 1b 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"))' \
    'li_vn_mode=CLIENT'
check_inline "show IP/TCP/custom protocol" \
    "$(printf 'protocol Hdr\n    required uint8 type = 0\n    required uint16 len = 0\nend\nshow("IP/TCP/Hdr", fromhex("45 00 00 2f 00 01 40 00 40 06 00 00 0a 00 00 01 0a 00 00 02 00 50 1f 90 00 00 00 01 00 00 00 00 50 18 20 00 00 00 00 00 07 00 40"))')" \
    'type=7'

# ── TFTP Object<TFTP> dispatch ───────────────────────────────────────────────
echo ""
echo "-- TFTP Object<TFTP> dispatch --"

TFTP_OUT=$("$PCAPSH" bin/tests/test_tftp.pcapsh 2>&1 | sed 's/\x1b\[[0-9;]*m//g')

check_tftp() {
    local desc="$1"; local expected="$2"
    if echo "$TFTP_OUT" | grep -q "$expected"; then
        ok "$desc"
    else
        fail "$desc — expected '$expected'"
    fi
}

if "$PCAPSH" bin/tests/test_tftp.pcapsh > /dev/null 2>&1; then
    ok "TFTP test script exits cleanly"
else
    fail "TFTP test script exited with error"
fi

# bare TFTP dispatch
check_tftp "TFTP dispatch: ACK opcode=4 block=7"          "TFTP_ACK opcode=ACK(4) block=7"
check_tftp "TFTP dispatch: DATA opcode=3 payload"         "TFTP_DATA opcode=DATA(3) block=1 data='Hello'"
check_tftp "TFTP dispatch: RRQ opcode=1 filename"         "TFTP_RRQ opcode=RRQ(1) filename='test.txt'"
check_tftp "TFTP dispatch: WRQ opcode=2 filename"         "TFTP_WRQ opcode=WRQ(2) filename='upload.txt'"
check_tftp "TFTP dispatch: ERROR opcode=5 named code"     "TFTP_ERROR opcode=ERROR(5) code=ERR_FILE_NOT_FOUND"
check_tftp "TFTP dispatch: ERROR message field"           "msg='File not found'"

# stacked IP/UDP/TFTP dispatch
check_tftp "IP/UDP/TFTP dispatch to ACK"                  "TFTP_ACK opcode=ACK(4) block=7"
check_tftp "IP/UDP/TFTP dispatch to DATA with payload"    "TFTP_DATA opcode=DATA(3) block=1 data='Hello'"
check_tftp "IP/UDP/TFTP dispatch to ERROR with code"      "TFTP_ERROR opcode=ERROR(5) code=ERR_FILE_NOT_FOUND"
check_tftp "IP/UDP/TFTP dispatch to RRQ with filename"    "TFTP_RRQ opcode=RRQ(1) filename='test.txt'"

# direct sub-protocol name still works
check_tftp "TFTP_ACK direct (no dispatch) block=3"        "TFTP_ACK opcode=ACK(4) block=3"

# ── cstring / bytes[N] / payload security ────────────────────────────────────
echo ""
echo "-- cstring / bytes[N] / payload security --"

# Run the dedicated security script once and grep the combined output.
SECURITY_OUT=$("$PCAPSH" bin/tests/test_cstring_security.pcapsh 2>&1 | sed 's/\x1b\[[0-9;]*m//g')

check_out() {
    local desc="$1"; local expected="$2"
    if echo "$SECURITY_OUT" | grep -q "$expected"; then
        ok "$desc"
    else
        fail "$desc — expected '$expected'"
    fi
}

# Script must exit cleanly
if "$PCAPSH" bin/tests/test_cstring_security.pcapsh > /dev/null 2>&1; then
    ok "cstring security script exits cleanly"
else
    fail "cstring security script exited with error"
fi

# cstring: normal null-terminated string
check_out "cstring: reads up to null terminator"         "msg='hello'"
check_out "cstring: field after null terminator parsed"  "after=66"

# cstring: no null terminator in data (evil/truncated packet)
check_out "cstring: no null — displays available bytes"  "msg='ABC'"
check_out "cstring: no null — subsequent field shows ?"  "after=?"

# cstring: empty string (null byte is the first byte of the field)
check_out "cstring: empty string shown correctly"        "msg=''"
check_out "cstring: empty string — field after parsed"   "after=85"

# cstring: two consecutive cstring fields
check_out "cstring: consecutive — first field correct"   "first='AB'"
check_out "cstring: consecutive — second field correct"  "second='CDE'"

# bytes[N]: normal length field
check_out "bytes[N]: normal length reads correct bytes"  "value='ABC'"

# bytes[N]: attacker-controlled 0xffff length against 3-byte packet
check_out "bytes[N]: evil length field preserved"        "length=65535"
check_out "bytes[N]: evil length clamped to avail bytes" "value='ABC'"

# bytes[N]: zero length — field after the empty value is still reachable
check_out "bytes[N]: zero length — after field parsed"   "after=85"

# payload: printable bytes shown as a string
check_out "payload: text content shown as string"        "data='HTTP"

# payload: non-printable bytes shown as hex
check_out "payload: binary content shown as hex"         "data=<"

# payload: no data after the header byte — no crash
check_out "payload: empty — type field still shown"      "type=3"

# ── for-loop and frompcapng ────────────────────────────────────────────────────
echo ""
echo "-- for-loop / frompcapng --"

rm -f /tmp/pcapsh_forloop.pcapng
LOOP_OUT=$("$PCAPSH" bin/tests/test_forloop.pcapsh 2>&1 | sed 's/\x1b\[[0-9;]*m//g')

check_loop() {
    local desc="$1"; local expected="$2"
    if echo "$LOOP_OUT" | grep -q "$expected"; then
        ok "$desc"
    else
        fail "$desc — expected '$expected'"
    fi
}
check_loop_absent() {
    local desc="$1"; local absent="$2"
    if echo "$LOOP_OUT" | grep -q "$absent"; then
        fail "$desc — '$absent' should NOT appear"
    else
        ok "$desc"
    fi
}

# Script must exit cleanly
if "$PCAPSH" bin/tests/test_forloop.pcapsh > /dev/null 2>&1; then
    ok "for-loop script exits cleanly"
else
    fail "for-loop script exited with error"
fi

# range(3) starts at 1: all three packets appear
check_loop "range(3): packet 1 shown (src=10.1.1.1)"     "src=10.1.1.1"
check_loop "range(3): packet 2 shown (src=10.1.1.2)"     "src=10.1.1.2"
check_loop "range(3): packet 3 shown (src=10.1.1.3)"     "src=10.1.1.3"
check_loop "range(3): dport=1001 from packet 1"          "dport=1001"
check_loop "range(3): dport=1002 from packet 2"          "dport=1002"
check_loop "range(3): dport=1003 from packet 3"          "dport=1003"

# range(2, 4): only packets 2 and 3 (exclusive stop — packet 1 absent)
check_loop        "range(2,4): packet 2 present"          "10.1.1.2"
check_loop        "range(2,4): packet 3 present"          "10.1.1.3"

# range(3, 0, -1): reverse — all three appear but 3 comes before 1
check_loop "range(3,0,-1): reverse shows packet #3 line" "packet #3"
check_loop "range(3,0,-1): reverse shows packet #1 line" "packet #1"

# $var in protocol field: dport=$i → dport=1, 2, 3
check_loop "\$i in field: dport=1 (range starts at 1)"   "dport=1 "
check_loop "\$i in field: dport=2"                        "dport=2 "
check_loop "\$i in field: dport=3"                        "dport=3 "
check_loop_absent "\$i in field: dport=0 never appears"   "dport=0 "

# ── replacepkt ────────────────────────────────────────────────────────────────
echo ""
echo "-- replacepkt --"

rm -f /tmp/pcapsh_replacepkt.pcapng
"$PCAPSH" << 'PCAPSH_EOF' > /dev/null 2>&1
wrpcap("/tmp/pcapsh_replacepkt.pcapng", IP(src="1.1.1.1",dst="1.1.1.1")/UDP(dport=111))
wrpcap("/tmp/pcapsh_replacepkt.pcapng", IP(src="2.2.2.2",dst="2.2.2.2")/UDP(dport=222))
wrpcap("/tmp/pcapsh_replacepkt.pcapng", IP(src="3.3.3.3",dst="3.3.3.3")/UDP(dport=333))
PCAPSH_EOF

REPLACE_OUT=$("$PCAPSH" << 'PCAPSH_EOF' 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
replacepkt("/tmp/pcapsh_replacepkt.pcapng", 2, IP(src="9.9.9.9",dst="8.8.8.8")/UDP(dport=9999))
show("Ether/IP/UDP", frompcapng("/tmp/pcapsh_replacepkt.pcapng", 1))
show("Ether/IP/UDP", frompcapng("/tmp/pcapsh_replacepkt.pcapng", 2))
show("Ether/IP/UDP", frompcapng("/tmp/pcapsh_replacepkt.pcapng", 3))
PCAPSH_EOF
)

check_replace() {
    local desc="$1"; local expected="$2"
    if echo "$REPLACE_OUT" | grep -q "$expected"; then
        ok "$desc"
    else
        fail "$desc — expected '$expected'"
    fi
}
check_replace_absent() {
    local desc="$1"; local absent="$2"
    if echo "$REPLACE_OUT" | grep -q "$absent"; then
        fail "$desc — '$absent' should NOT appear"
    else
        ok "$desc"
    fi
}

check_replace        "replacepkt: success message"                  "Replaced packet #2"
check_replace        "replacepkt: packet 1 unchanged (src=1.1.1.1)" "src=1.1.1.1"
check_replace        "replacepkt: packet 2 replaced (src=9.9.9.9)"  "src=9.9.9.9"
check_replace        "replacepkt: packet 2 replaced (dport=9999)"   "dport=9999"
check_replace        "replacepkt: packet 3 unchanged (src=3.3.3.3)" "src=3.3.3.3"
check_replace_absent "replacepkt: old packet 2 src=2.2.2.2 gone"    "src=2.2.2.2"
check_replace_absent "replacepkt: old packet 2 dport=222 gone"      "dport=222 "

# error case: out-of-range packet number
ERR_OUT=$("$PCAPSH" << 'PCAPSH_EOF' 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
replacepkt("/tmp/pcapsh_replacepkt.pcapng", 99, IP()/UDP())
PCAPSH_EOF
)
if echo "$ERR_OUT" | grep -q "file has.*packet"; then
    ok "replacepkt: out-of-range gives informative error"
else
    fail "replacepkt: out-of-range error message missing"
fi

# ── Wireshark sample captures — real packet bytes ────────────────────────────
echo ""
echo "-- Wireshark sample captures --"

WS_OUT=$("$PCAPSH" bin/tests/test_wireshark_samples.pcapsh 2>&1 | sed 's/\x1b\[[0-9;]*m//g')

check_ws() {
    local desc="$1"; local expected="$2"
    if echo "$WS_OUT" | grep -q "$expected"; then
        ok "$desc"
    else
        fail "$desc — expected '$expected' in output"
    fi
}

# BFD
check_ws "BFD: detect_mult=5"             "detect_mult=5"
check_ws "BFD: my_discriminator=1"        "my_discriminator=1"
check_ws "BFD: desired_min_tx=1000000"    "desired_min_tx=1000000"
check_ws "BFD: diag enum DIAG_NO_DIAG"   "DIAG_NO_DIAG"

# OSPF
check_ws "OSPF: version=2"                "version=2"
check_ws "OSPF: type=HELLO"               "type=HELLO"
check_ws "OSPF: router_id=192.168.170.8"  "router_id=192.168.170.8"
check_ws "OSPF: area_id=0.0.0.1"          "area_id=0.0.0.1"

# EIGRP
check_ws "EIGRP: opcode=HELLO"            "opcode=HELLO"
check_ws "EIGRP: as_number=100"           "as_number=100"
check_ws "EIGRP: version=2"              "version=2"

# IGMP
check_ws "IGMP: type=MEMBERSHIP_QUERY"   "type=MEMBERSHIP_QUERY"
check_ws "IGMP: max_resp_time=100"       "max_resp_time=100"

# RSVP
check_ws "RSVP: msg_type=PATH"           "msg_type=PATH"
check_ws "RSVP: send_ttl=254"            "send_ttl=254"
check_ws "RSVP: rsvp_length=136"         "rsvp_length=136"

# PTPv2
check_ws "PTPv2: ts_msg_type=PDELAY_REQ" "ts_msg_type=PDELAY_REQ"
check_ws "PTPv2: version=2"              "PTPv2 ts_msg_type=PDELAY_REQ(2) version=2"
check_ws "PTPv2: message_len=54"         "message_len=54"
check_ws "PTPv2: seq_id=1118"            "seq_id=1118"

# CDP
check_ws "CDP: version=1"               "CDP version=1"
check_ws "CDP: ttl=180"                 "ttl=180"

# LACP
check_ws "LACP: subtype=LACP"           "subtype=LACP"
check_ws "LACP: actor_key=32768"        "actor_key=32768"
check_ws "LACP: actor_port=18"          "actor_port=18"

# DCCP
check_ws "DCCP: sport=32772"            "sport=32772"
check_ws "DCCP: dport=5001"             "dport=5001"

# DHCPv6
check_ws "DHCPv6: msg_type=SOLICIT"     "msg_type=SOLICIT"

# BGP
check_ws "BGP: type=KEEPALIVE"          "type=KEEPALIVE"
check_ws "BGP: length=19"              "length=19"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
if [[ ${#ERRORS[@]} -gt 0 ]]; then
    echo "Failed tests:"
    for e in "${ERRORS[@]}"; do echo "  - $e"; done
    exit 1
fi
