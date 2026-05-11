#!/usr/bin/env python3
"""
Run a .pcapsh script and write the resulting packets to a pcapng file.

Usage:
    python3 pcapsh_run_script.py input.pcapsh output.pcapng
"""

import sys
import struct
import time

sys.path.insert(0, "../")          # find libpcapng/ package from source tree

from libpcapng import pcapsh


def write_pcapng(path: str, raw_frames: list[bytes]) -> None:
    """Write raw Ethernet frames to a minimal pcapng file."""
    LINKTYPE_ETHERNET = 1

    def pad4(n: int) -> int:
        return (n + 3) & ~3

    with open(path, "wb") as f:
        # Section Header Block
        body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        block_len = 12 + len(body)
        f.write(struct.pack("<II", 0x0A0D0D0A, block_len) + body + struct.pack("<I", block_len))

        # Interface Description Block
        body = struct.pack("<HHI", LINKTYPE_ETHERNET, 0, 65535)
        block_len = 12 + len(body)
        f.write(struct.pack("<II", 0x00000001, block_len) + body + struct.pack("<I", block_len))

        # Enhanced Packet Blocks
        ts = int(time.time() * 1e6)
        for frame in raw_frames:
            padded = frame + b"\x00" * (pad4(len(frame)) - len(frame))
            body = struct.pack("<IIIII", 0, ts >> 32 & 0xFFFFFFFF, ts & 0xFFFFFFFF,
                               len(frame), len(frame)) + padded
            block_len = 12 + len(body)
            f.write(struct.pack("<II", 0x00000006, block_len) + body + struct.pack("<I", block_len))
            ts += 100_000  # 100 ms between packets


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} input.pcapsh output.pcapng", file=sys.stderr)
        sys.exit(1)

    script_path = sys.argv[1]
    output_path = sys.argv[2]

    sh = pcapsh.PcapSH()
    packets = sh.run_script(script_path)
    print(f"Script produced {len(packets)} packet(s).")

    write_pcapng(output_path, packets)
    print(f"Wrote {output_path}")


if __name__ == "__main__":
    main()
