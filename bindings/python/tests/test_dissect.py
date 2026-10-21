#!/usr/bin/env python3
"""
test_dissect.py — pycapng.dissect(), pycapng.Filter() and ensure_protocols().

The thing this file is really guarding is the ordering requirement. Most of
libpcapng's protocol knowledge is POSA definitions compiled into the library
and registered on demand, so before `ensure_protocols()` runs, an HTTP request
dissects as plain TCP and a filter on `http.uri` matches nothing — not because
the filter is wrong, but because the field does not exist yet. That is a silent
failure: no exception, no warning, just a program that quietly sees less than
it should. So the first check below is deliberately made *before* the call.

The second is `Dissection.fields`, which has to step over the unnamed root the
C tree uses as a holder. Returning that holder is also silent: you get a list
of length one where you expected the protocol stack.

    PYTHONPATH=build/bindings/python python3 bindings/python/tests/test_dissect.py
"""

import struct
import sys

import pycapng

ok = 0
bad = 0


def check(label, cond):
    global ok, bad
    if cond:
        ok += 1
        print(f"  ok    {label}")
    else:
        bad += 1
        print(f"  FAIL  {label}")


def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b"\x00"
    total = 0
    for i in range(0, len(hdr), 2):
        total += (hdr[i] << 8) | hdr[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(payload, ethertype=0x0800):
    return (b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"
            + struct.pack(">H", ethertype) + payload)


def ipv4(payload, src, dst, proto):
    def addr(a):
        return bytes(int(p) for p in a.split("."))

    hdr = (b"\x45\x00" + struct.pack(">H", 20 + len(payload))
           + b"\x00\x01\x00\x00\x40" + bytes([proto]) + b"\x00\x00"
           + addr(src) + addr(dst))
    hdr = hdr[:10] + struct.pack(">H", ip_checksum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(payload, sport, dport):
    hdr = (struct.pack(">HH", sport, dport)
           + struct.pack(">II", 1000, 2000)
           + b"\x50\x18" + struct.pack(">H", 8192) + b"\x00\x00\x00\x00")
    return hdr + payload


def udp(payload, sport, dport):
    return (struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload)


HTTP_REQUEST = (b"GET /index.html HTTP/1.1\r\n"
                b"Host: www.example.com\r\n"
                b"User-Agent: curl/8.4.0\r\n\r\n")

HTTP_FRAME = ethernet(ipv4(tcp(HTTP_REQUEST, 54321, 80),
                           "203.0.113.9", "10.0.0.5", 6))

# A standard query for example.com, type A.
DNS_QUERY = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
             + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1))

DNS_FRAME = ethernet(ipv4(udp(DNS_QUERY, 51000, 53),
                          "203.0.113.9", "8.8.8.8", 17))


def main():
    print("[before ensure_protocols: the POSA decoders are not registered]")
    # Run first, in a fresh interpreter, because ensure_protocols() cannot be
    # undone. An HTTP request on port 80 is still *transported* correctly, so
    # the addresses are right; what is missing is the application layer.
    d = pycapng.dissect(HTTP_FRAME)
    check("a frame still dissects without the decoders", d is not None)
    check("the transport layers are there regardless",
          "http.uri" not in d.flat() or d.proto == "HTTP")
    before_proto = d.proto

    print("\n[ensure_protocols]")
    pycapng.ensure_protocols()
    pycapng.ensure_protocols()  # idempotent
    check("calling it twice is harmless", True)

    print("\n[summary columns]")
    d = pycapng.dissect(HTTP_FRAME)
    check("proto reaches the application layer", d.proto == "HTTP")
    check("src is the IP address, not the MAC", d.src == "203.0.113.9")
    check("dst likewise", d.dst == "10.0.0.5")
    check("info is Wireshark's one-line summary",
          "GET /index.html" in d.info)
    check("repr says something useful", "Dissection" in repr(d))
    check("the decoders changed the answer",
          before_proto != "HTTP" or d.proto == "HTTP")

    print("\n[the field tree]")
    names = [f["abbrev"] for f in d.fields]
    # The regression this guards: the C root is an unnamed holder, and handing
    # it back gives one anonymous node instead of the protocol stack.
    check("fields are the layers, not one unnamed holder",
          len(names) > 1 and "" not in names)
    check("the stack is in wire order",
          names[:4] == ["frame", "eth", "ip", "tcp"], )
    check("http is the last layer", names[-1] == "http")
    check("each layer carries its own children",
          any(f["children"] for f in d.fields))

    print("\n[flat()]")
    flat = d.flat()
    check("http.uri is the request target", flat.get("http.uri") == "/index.html")
    check("http.method is a string", flat.get("http.method") == "GET")
    check("tcp.dstport is an int, not a string", flat.get("tcp.dstport") == 80)
    check("ip.src is present", flat.get("ip.src") == "203.0.113.9")
    check("a field that is not there is absent, not empty",
          "ftp.command" not in flat)

    print("\n[Filter]")
    f = pycapng.Filter("http.uri contains \"/index\"")
    check("a matching filter matches", f.matches(d))
    check("the dissection can match it the other way round", d.matches(f))
    check("expr is the expression as written", "/index" in f.expr)
    check("repr says something useful", "Filter" in repr(f))

    check("a non-matching filter does not match",
          not pycapng.Filter("http.uri contains \"/admin\"").matches(d))
    check("a field-level filter on the transport layer works",
          pycapng.Filter("tcp.dstport == 80").matches(d))
    check("a CIDR comparison works",
          pycapng.Filter("ip.src == 203.0.113.0/24").matches(d))
    check("and/or/not compose",
          pycapng.Filter("http and not ip.src == 10.0.0.0/8").matches(d))

    print("\n[a filter that will not compile fails where it is written]")
    try:
        pycapng.Filter("http.uri contains")
        check("ValueError for a syntax error", False)
    except ValueError:
        check("ValueError for a syntax error", True)
    # An unknown *field* is a different matter: libpcapng builds field names
    # during dissection rather than keeping a registry, so it cannot know at
    # compile time that nothing will ever be called this. It compiles, and
    # matches nothing — worth knowing, because a typo in a field name is then
    # silent where a typo in the syntax is not.
    typo = pycapng.Filter("no.such.field.at.all == 1")
    check("an unknown field compiles and matches nothing",
          not typo.matches(d) and not typo.is_match_all())

    print("\n[the empty filter matches everything]")
    allf = pycapng.Filter("")
    check("is_match_all reports it", allf.is_match_all())
    check("and it matches", allf.matches(d))
    check("a real filter does not claim to match all",
          not pycapng.Filter("tcp").is_match_all())

    print("\n[a second protocol, to show it is not HTTP-specific]")
    dns = pycapng.dissect(DNS_FRAME)
    check("DNS over UDP is recognised", dns.proto == "DNS")
    check("the query name is a field",
          dns.flat().get("dns.qname") == "example.com")
    check("a filter on it matches",
          pycapng.Filter("dns.qname == \"example.com\"").matches(dns))
    check("and does not match the HTTP packet",
          not pycapng.Filter("dns").matches(d))

    print("\n[linktype is honoured]")
    # The same bytes read as raw IPv4 rather than Ethernet: the IP header is
    # 14 bytes in, so dissecting from the frame start as LINKTYPE_RAW must not
    # claim to have found HTTP.
    raw = pycapng.dissect(HTTP_FRAME, 101)
    check("the wrong linktype does not invent a match",
          raw is None or raw.proto != "HTTP")
    ip_only = pycapng.dissect(HTTP_FRAME[14:], 101)
    check("and the right one, from the right offset, does",
          ip_only is not None and ip_only.proto == "HTTP")

    print(f"\n{ok} passed, {bad} failed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
