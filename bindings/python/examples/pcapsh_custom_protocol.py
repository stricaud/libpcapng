#!/usr/bin/env python3
"""
Custom protocol definition — inline pcapsh protocol block.

Defines a simple IoT sensor telemetry protocol entirely inside the script,
then generates a realistic session: sensor boot, periodic readings, an alarm,
and shutdown.  All packets are written to a pcapng file.

Protocol layout (SensorReport, carried over UDP port 7777):
    version        uint8   — always 1
    type           uint8   — message type (HELLO/DATA/ALARM/BYE)
    sensor_id      uint16  — unique sensor identifier
    uptime_s       uint32  — seconds since boot
    temperature    uint16  — temperature in 0.1 °C units (e.g. 235 = 23.5 °C)
    humidity       uint16  — relative humidity in 0.1 % units (e.g. 654 = 65.4 %)
    battery_pct    uint8   — remaining battery (0–100)

Usage:
    python3 pcapsh_custom_protocol.py [output.pcapng]
"""

import os
import sys

_HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_HERE, ".."))

import pycapng
from pycapng import pcapsh

# Network topology
SENSOR_MAC  = "02:00:00:aa:bb:01"
GATEWAY_MAC = "02:00:00:00:00:01"
SENSOR_IP   = "10.0.0.10"
GATEWAY_IP  = "10.0.0.1"
SENSOR_ID   = 1
DPORT       = 7777

SCRIPT = """\
# ── Custom protocol definition ────────────────────────────────────────────────
protocol SensorReport
    required uint8  version     = 1
    required uint8  type        = 0
        HELLO = 1
        DATA  = 2
        ALARM = 3
        BYE   = 4
    required uint16 sensor_id   = 0
    required uint32 uptime_s    = 0
    required uint16 temperature = 0
    required uint16 humidity    = 0
    required uint8  battery_pct = 100
end

# ── Helper macro: wrap SensorReport in Ether/IP/UDP ──────────────────────────
# (pcapsh does not have macros, so we spell out the stack each time)

# ── 1. Sensor boot — HELLO ───────────────────────────────────────────────────
wrpcap("x", Ether(src="02:00:00:aa:bb:01", dst="02:00:00:00:00:01")/ \\
  IP(src="10.0.0.10", dst="10.0.0.1", ttl=64)/ \\
  UDP(sport=49152, dport=7777)/ \\
  SensorReport(type=HELLO, sensor_id=1, uptime_s=0, \\
               temperature=220, humidity=500, battery_pct=100))

# ── 2. Periodic DATA readings (every 30 s, 8 samples) ────────────────────────
# Temperature rises from 22.0 °C to 29.5 °C; humidity drops; battery drains.
wrpcap("x", Ether(src="02:00:00:aa:bb:01", dst="02:00:00:00:00:01")/ \\
  IP(src="10.0.0.10", dst="10.0.0.1", ttl=64)/ \\
  UDP(sport=49152, dport=7777)/ \\
  SensorReport(type=DATA, sensor_id=1, uptime_s=30, \\
               temperature=225, humidity=490, battery_pct=99))

wrpcap("x", Ether(src="02:00:00:aa:bb:01", dst="02:00:00:00:00:01")/ \\
  IP(src="10.0.0.10", dst="10.0.0.1", ttl=64)/ \\
  UDP(sport=49152, dport=7777)/ \\
  SensorReport(type=DATA, sensor_id=1, uptime_s=60, \\
               temperature=241, humidity=478, battery_pct=99))

wrpcap("x", Ether(src="02:00:00:aa:bb:01", dst="02:00:00:00:00:01")/ \\
  IP(src="10.0.0.10", dst="10.0.0.1", ttl=64)/ \\
  UDP(sport=49152, dport=7777)/ \\
  SensorReport(type=DATA, sensor_id=1, uptime_s=90, \\
               temperature=258, humidity=461, battery_pct=98))

wrpcap("x", Ether(src="02:00:00:aa:bb:01", dst="02:00:00:00:00:01")/ \\
  IP(src="10.0.0.10", dst="10.0.0.1", ttl=64)/ \\
  UDP(sport=49152, dport=7777)/ \\
  SensorReport(type=DATA, sensor_id=1, uptime_s=120, \\
               temperature=272, humidity=449, battery_pct=98))

wrpcap("x", Ether(src="02:00:00:aa:bb:01", dst="02:00:00:00:00:01")/ \\
  IP(src="10.0.0.10", dst="10.0.0.1", ttl=64)/ \\
  UDP(sport=49152, dport=7777)/ \\
  SensorReport(type=DATA, sensor_id=1, uptime_s=150, \\
               temperature=281, humidity=440, battery_pct=97))

wrpcap("x", Ether(src="02:00:00:aa:bb:01", dst="02:00:00:00:00:01")/ \\
  IP(src="10.0.0.10", dst="10.0.0.1", ttl=64)/ \\
  UDP(sport=49152, dport=7777)/ \\
  SensorReport(type=DATA, sensor_id=1, uptime_s=180, \\
               temperature=289, humidity=435, battery_pct=97))

wrpcap("x", Ether(src="02:00:00:aa:bb:01", dst="02:00:00:00:00:01")/ \\
  IP(src="10.0.0.10", dst="10.0.0.1", ttl=64)/ \\
  UDP(sport=49152, dport=7777)/ \\
  SensorReport(type=DATA, sensor_id=1, uptime_s=210, \\
               temperature=294, humidity=430, battery_pct=96))

wrpcap("x", Ether(src="02:00:00:aa:bb:01", dst="02:00:00:00:00:01")/ \\
  IP(src="10.0.0.10", dst="10.0.0.1", ttl=64)/ \\
  UDP(sport=49152, dport=7777)/ \\
  SensorReport(type=DATA, sensor_id=1, uptime_s=240, \\
               temperature=295, humidity=428, battery_pct=96))

# ── 3. Temperature exceeds 29.0 °C threshold — ALARM ─────────────────────────
wrpcap("x", Ether(src="02:00:00:aa:bb:01", dst="02:00:00:00:00:01")/ \\
  IP(src="10.0.0.10", dst="10.0.0.1", ttl=64)/ \\
  UDP(sport=49152, dport=7777)/ \\
  SensorReport(type=ALARM, sensor_id=1, uptime_s=270, \\
               temperature=301, humidity=425, battery_pct=95))

# Gateway ACKs the alarm (gateway → sensor, ICMP echo used as a stand-in)
wrpcap("x", Ether(src="02:00:00:00:00:01", dst="02:00:00:aa:bb:01")/ \\
  IP(src="10.0.0.1", dst="10.0.0.10", ttl=64)/ \\
  ICMP(type=0, code=0))

# ── 4. Sensor shutdown — BYE ─────────────────────────────────────────────────
wrpcap("x", Ether(src="02:00:00:aa:bb:01", dst="02:00:00:00:00:01")/ \\
  IP(src="10.0.0.10", dst="10.0.0.1", ttl=64)/ \\
  UDP(sport=49152, dport=7777)/ \\
  SensorReport(type=BYE, sensor_id=1, uptime_s=300, \\
               temperature=298, humidity=427, battery_pct=95))
"""


def decode_report(payload: bytes) -> str:
    """Parse a SensorReport payload and return a human-readable string."""
    if len(payload) < 12:
        return f"<short: {len(payload)} bytes>"
    version      = payload[0]
    msg_type     = payload[1]
    sensor_id    = int.from_bytes(payload[2:4],  "big")
    uptime_s     = int.from_bytes(payload[4:8],  "big")
    temperature  = int.from_bytes(payload[8:10], "big")
    humidity     = int.from_bytes(payload[10:12],"big")
    battery_pct  = payload[12] if len(payload) > 12 else 0
    type_names   = {1: "HELLO", 2: "DATA", 3: "ALARM", 4: "BYE"}
    type_str     = type_names.get(msg_type, f"?{msg_type}")
    return (f"v{version} {type_str:<5}  sensor={sensor_id}"
            f"  uptime={uptime_s:>4}s"
            f"  temp={temperature/10:>5.1f}°C"
            f"  hum={humidity/10:>5.1f}%"
            f"  batt={battery_pct}%")


def on_packet(frame: bytes) -> None:
    """Called for each packet as it is produced."""
    # Minimal Ethernet(14) + IP(20) + UDP(8) header skip
    ETH, IP_MIN, UDP = 14, 20, 8
    if len(frame) < ETH + IP_MIN + UDP + 1:
        return
    # Check EtherType = IPv4 (0x0800)
    if frame[12:14] != b"\x08\x00":
        print(f"  [non-IPv4 frame  {len(frame):>4} bytes]")
        return
    ip_ihl    = (frame[14] & 0x0F) * 4
    proto     = frame[14 + 9]
    udp_start = ETH + ip_ihl
    # Only decode UDP SensorReport frames
    if proto == 17 and len(frame) > udp_start + UDP:
        dport   = int.from_bytes(frame[udp_start + 2:udp_start + 4], "big")
        payload = frame[udp_start + UDP:]
        if dport == DPORT:
            print(f"  SensorReport  {decode_report(payload)}")
            return
    print(f"  [frame  {len(frame):>4} bytes  proto={proto}]")


def main() -> None:
    output = sys.argv[1] if len(sys.argv) > 1 else "custom_protocol_out.pcapng"

    sh = pcapsh.PcapSH()

    print("Generating sensor session …")
    packets = sh.run_string(SCRIPT, on_packet=on_packet)

    writer = pycapng.PcapNG()
    writer.OpenFileLinkType(output, "w", pycapng.LINKTYPE_ETHERNET)
    for pkt in packets:
        writer.WritePacket(pkt, "")
    writer.CloseFile()

    print(f"\n{len(packets)} packet(s) written to {output}")


if __name__ == "__main__":
    main()
