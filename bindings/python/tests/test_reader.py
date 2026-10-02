#!/usr/bin/env python3
"""
test_reader.py — pycapng.read_packets() and the lifetime of what it hands back.

The C reader points `data` into its own buffer and says so: the pointer is
valid for the duration of the callback only. For a classic .pcap the library
synthesises each block and frees it on return, so a CapturedPacket that merely
held that pointer would hand back freed memory the moment anything read it
after the walk. That is not a hypothetical — the binding did exactly that, and
the symptom was a frame of the right length and the wrong bytes, which a length
check sails straight past.

So the test that matters is reading .data *after* the walk has finished, from a
classic .pcap, and comparing it against the bytes that went in.

    PYTHONPATH=build/bindings/python python3 bindings/python/tests/test_reader.py
"""

import struct
import sys
import tempfile
from pathlib import Path

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


# Two frames with distinct, recognisable contents.
FRAME_A = bytes(range(0x10, 0x10 + 48))
FRAME_B = bytes(range(0xA0, 0xA0 + 32))


def write_classic_pcap(path, linktype, frames):
    """A classic .pcap — the case where the library synthesises and frees blocks."""
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", 1700000000 + i, 500000, len(f), len(f)) + f
    path.write_bytes(bytes(out))


def write_pcapng(path, linktype, frames):
    def block(btype, body):
        padded = body + b"\x00" * ((4 - len(body) % 4) % 4)
        total = 12 + len(padded)
        return struct.pack("<II", btype, total) + padded + struct.pack("<I", total)

    data = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    data += block(1, struct.pack("<HHI", linktype, 0, 65535))
    for f in frames:
        ticks = 1700000000 * 1000000 + 500000
        data += block(6, struct.pack("<IIIII", 0, ticks >> 32,
                                     ticks & 0xFFFFFFFF, len(f), len(f)) + f)
    path.write_bytes(data)


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        for name, writer in (("classic .pcap", write_classic_pcap),
                             ("pcapng", write_pcapng)):
            print(f"\n[{name}]")
            path = tmp / "c.cap"
            writer(path, 101, [FRAME_A, FRAME_B])

            # The whole list is materialised first; every .data read below
            # happens after the walk, and after the library has freed whatever
            # it was pointing at.
            pkts = pycapng.read_packets(str(path))

            check("both packets read", len(pkts) == 2)
            check("indices are 1-based and in order",
                  [p.index for p in pkts] == [1, 2])
            check("linktype resolved from the interface",
                  all(p.linktype == 101 for p in pkts))
            check("lengths survive", [len(p.data) for p in pkts] == [48, 32])
            # The assertion this file exists for.
            check("first frame's bytes are intact after the walk",
                  pkts[0].data == FRAME_A)
            check("second frame's bytes are intact after the walk",
                  pkts[1].data == FRAME_B)
            check("captured_len agrees with the bytes",
                  all(p.captured_len == len(p.data) for p in pkts))
            check("timestamp is the one written",
                  pkts[0].timestamp_ns == 1700000000 * 10**9 + 500 * 10**6)
            check("nothing claims to be truncated",
                  not any(p.truncated for p in pkts))
            check("repr says something useful", "CapturedPacket" in repr(pkts[0]))

        print("\n[from memory]")
        path = tmp / "m.pcapng"
        write_pcapng(path, 1, [FRAME_A])
        pkts = pycapng.read_packets_mem(path.read_bytes())
        check("read_packets_mem agrees", len(pkts) == 1 and pkts[0].data == FRAME_A)

        print("\n[streaming]")
        path = tmp / "s.pcapng"
        write_pcapng(path, 1, [FRAME_A, FRAME_B])
        # Kept past the end of the callback on purpose: the same lifetime trap.
        kept = []
        n = pycapng.foreach_packet(str(path), lambda p: kept.append(p) or True)
        check("every packet delivered", n == 2 and len(kept) == 2)
        check("bytes kept past the callback are intact",
              kept[0].data == FRAME_A and kept[1].data == FRAME_B)

        stopped = []
        def first_only(p):
            stopped.append(p)
            return False                      # stop the walk
        check("returning False stops the walk",
              pycapng.foreach_packet(str(path), first_only) == 1)

        def boom(p):
            raise ValueError("from the callback")
        try:
            pycapng.foreach_packet(str(path), boom)
            check("an exception in the callback propagates", False)
        except ValueError:
            check("an exception in the callback propagates", True)

        print("\n[block predicates]")
        check("is_epb needs the type and the length",
              pycapng.is_epb(6, b"\x00" * 20) and not pycapng.is_epb(6, b"\x00" * 19)
              and not pycapng.is_epb(3, b"\x00" * 64))
        check("is_idb", pycapng.is_idb(1, b"\x00" * 8) and not pycapng.is_idb(1, b"\x00" * 7))
        check("is_spb", pycapng.is_spb(3, b"\x00" * 4) and not pycapng.is_spb(3, b"\x00" * 3))
        check("has_packet covers epb, spb and the obsolete block",
              pycapng.has_packet(6, b"\x00" * 20) and pycapng.has_packet(3, b"\x00" * 4)
              and pycapng.has_packet(2, b"\x00" * 20)
              and not pycapng.has_packet(0x0A0D0D0A, b"\x00" * 64))

        print("\n[a missing file is an error, not an empty list]")
        try:
            pycapng.read_packets(str(tmp / "nope.pcapng"))
            check("read_packets raises for a file that is not there", False)
        except RuntimeError:
            check("read_packets raises for a file that is not there", True)

    print(f"\n{ok} passed, {bad} failed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
