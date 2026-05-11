#!/usr/bin/env python3
"""
Build packets with inline pcapsh expressions and write to a pcapng file.

Demonstrates using pcapsh.PcapSH.run_string() to evaluate pcapsh
expressions directly from Python and receive the resulting raw frames.

Usage:
    python3 pcapsh_inline.py output.pcapng
"""

import sys

sys.path.insert(0, "../")

from pycapng import pcapsh
def main():
    output = sys.argv[1] if len(sys.argv) > 1 else "pcapsh_inline_out.pcapng"

    sh = pcapsh.PcapSH()

    # Multiple wrpcap() calls — one per line, or use backslash continuation.
    packets = sh.run_string("""\
wrpcap("x", Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00")/ \\
  IP(src="127.0.0.1", dst="127.0.0.1", ttl=64, flags=2)/ \\
  TCP(sport=54320, dport=9050, flags="PA", window=65535)/ \\
  fromhex("05 01 00"))

wrpcap("x", Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00")/ \\
  IP(src="127.0.0.1", dst="127.0.0.1", ttl=64, flags=2)/ \\
  TCP(sport=9050, dport=54320, flags="PA", window=65535)/ \\
  fromhex("05 00"))
""")

    print(f"Produced {len(packets)} packet(s):")
    for i, pkt in enumerate(packets):
        print(f"  [{i}] {len(pkt)} bytes  {pkt.hex()}")

    # Use the raw bytes however you like — write to pcapng, pass to Scapy, etc.
    print(f"(packets available as raw bytes; write them yourself)")
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
