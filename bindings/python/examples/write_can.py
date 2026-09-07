#!/usr/bin/env python3
"""
CAN-bus pcapng example.

  1. Define SocketCAN frame layout once as a pcapsh protocol
  2. Build frames with named fields — no raw struct.pack
  3. Write with explicit timestamps, SHB comment, and per-packet comments

Usage:
    python write_can.py [output.pcapng]
"""

import time
import sys

import pycapng
from pycapng import pcapsh

OUTFILE = sys.argv[1] if len(sys.argv) > 1 else "can_example.pcapng"

# ── Define the SocketCAN frame layout as a pcapsh protocol ───────────────────
#
# Linux LINKTYPE_CAN_SOCKETCAN wire layout (16 bytes):
#   can_id(4 LE)  dlc(1)  pad(3)  data(8)
#
# Bit 31 of can_id = EFF (extended frame format, 29-bit ID).

SOCKETCAN_PROTO = """
protocol SocketCAN
    required le_uint32 can_id  = 0
        EFF_FLAG = 0x80000000
        RTR_FLAG = 0x40000000
        ERR_FLAG = 0x20000000
    required uint8     dlc     = 0
    required bytes<3>  pad     = 00:00:00
    required bytes<8>  data    = 00:00:00:00:00:00:00:00
end
"""

# Build frames using named fields — the protocol definition turns magic bytes
# into self-documenting field assignments.
sh = pcapsh.PcapSH()
frames = sh.run_string(SOCKETCAN_PROTO + """
wrpcap("x", SocketCAN(can_id=0x7FF,           dlc=8, data=01:02:03:04:05:06:07:08))
wrpcap("x", SocketCAN(can_id=0x123,           dlc=2, data=AB:CD:00:00:00:00:00:00))
wrpcap("x", SocketCAN(can_id=0x98DAF101,      dlc=3, data=02:10:03:00:00:00:00:00))
""")
# frame index:              0 = std 0x7FF   1 = std 0x123   2 = ext 0x18DAF101

# ── Write the pcapng file ─────────────────────────────────────────────────────

ng = pycapng.PcapNG()
ng.OpenFileLinkTypeComment(
    OUTFILE, "w",
    pycapng.LINKTYPE_CAN_SOCKETCAN,
    "OBD-II capture — engine ECU diagnostics session",
)

base_ts = int(time.time())

ng.WritePacketTime(frames[0], base_ts)
ng.WritePacketTime(frames[1], base_ts + 1)
ng.WritePacket(frames[2], "UDS DiagnosticSessionControl — extended session")

ng.CloseFile()

print(f"Wrote {OUTFILE}  ({len(frames)} packets)")
print("Open in Wireshark: Edit → Capture File Properties shows the SHB comment.")
