#!/usr/bin/env python3
"""live_capture.py — demonstrate pycapng live packet capture.

Requires root / CAP_NET_RAW (Linux) or root / network entitlement (macOS).

Usage:
    sudo python3 live_capture.py [interface] [filter]

    sudo python3 live_capture.py eth0 "tcp.dstport == 443"
    sudo python3 live_capture.py en0  "not arp"

If no interface is given the default non-loopback interface is used.
"""

import sys
import time
import datetime
import pycapng

# ── helpers ────────────────────────────────────────────────────────────────

def direction_str(d):
    return {pycapng.CAP_DIR_INBOUND: "in", pycapng.CAP_DIR_OUTBOUND: "out"}.get(d, "??")


def ts_to_str(ns):
    """Convert nanosecond UNIX timestamp to human-readable string."""
    sec = ns // 1_000_000_000
    frac = ns % 1_000_000_000
    dt = datetime.datetime.fromtimestamp(sec, tz=datetime.timezone.utc)
    return dt.strftime("%H:%M:%S") + f".{frac:09d}"


# ── 1. List available interfaces ───────────────────────────────────────────

print("Available interfaces:")
for dev in pycapng.capture_list_devices():
    lo = " (loopback)" if dev["loopback"] else ""
    print(f"  {dev['name']}{lo}")
print()

# ── 2. Choose interface and optional filter ─────────────────────────────────

iface  = sys.argv[1] if len(sys.argv) > 1 else pycapng.capture_default_device()
fexpr  = sys.argv[2] if len(sys.argv) > 2 else None

if iface is None:
    print("No usable interface found.", file=sys.stderr)
    sys.exit(1)

print(f"Capturing on: {iface}")
if fexpr:
    print(f"Filter:       {fexpr}")
print("Press Ctrl-C to stop.\n")

# ── 3. Open capture handle and configure ───────────────────────────────────

cap = pycapng.Capture(iface)
cap.set_snaplen(65535)
cap.set_promisc(True)
cap.set_timeout(100)          # ms between kernel ring deliveries

if fexpr:
    cap.set_filter(fexpr)

# ── 4. Optional POSA / custom field provider ───────────────────────────────
# Register a provider that exposes a synthetic "capture.time_str" field
# usable in display filters (not really useful here but shows the API).

def my_field_provider(field, data):
    """Expose capture.len as the captured frame length in decimal."""
    if field == "capture.len":
        return str(len(data))
    return None

cap.set_field_provider(my_field_provider)

# ── 5. Packet callback ─────────────────────────────────────────────────────

packet_count = [0]
byte_count   = [0]
start_time   = [time.monotonic()]

def on_packet(pkt):
    packet_count[0] += 1
    byte_count[0]   += pkt.captured_len

    ts  = ts_to_str(pkt.timestamp_ns)
    trunc = "*" if pkt.captured_len < pkt.original_len else " "
    print(f"[{packet_count[0]:6d}] {ts} {direction_str(pkt.direction):3s} "
          f"{pkt.captured_len:5d}{trunc}/{pkt.original_len} bytes")

# ── 6. Blocking loop (releases GIL — other threads can run) ────────────────

try:
    cap.loop(0, on_packet)          # 0 = run until Ctrl-C
except KeyboardInterrupt:
    cap.break_loop()
    print()

# ── 7. Statistics ──────────────────────────────────────────────────────────

elapsed = time.monotonic() - start_time[0]
stats   = cap.get_stats()

print(f"\n{'─' * 50}")
print(f"  Elapsed:   {elapsed:.2f}s")
print(f"  Received:  {stats.received}  (kernel ring)")
print(f"  Dropped:   {stats.dropped}   (ring full)")
print(f"  Filtered:  {stats.filtered}  (display filter)")
print(f"  Passed:    {stats.passed}")
print(f"  Bytes:     {byte_count[0]}")
if elapsed > 0:
    print(f"  Rate:      {packet_count[0]/elapsed:.1f} pkt/s  "
          f"{byte_count[0]*8/elapsed/1e6:.2f} Mbit/s")
cap.close()

# ── 8. Context-manager form (shown but not run) ────────────────────────────
# with pycapng.Capture(iface) as c:
#     c.set_filter("tcp.dstport == 443 or tcp.srcport == 443")
#     c.loop(200, on_packet)

# ── 9. One-liner convenience: save 100 packets to a pcapng file ────────────
# pycapng.capture_to_file(iface, "/tmp/capture.pcapng",
#                         filter="tcp", count=100)

# ── 10. One-liner: print summaries to stdout ───────────────────────────────
# pycapng.capture_print(iface, filter="udp.port == 53", count=50)
