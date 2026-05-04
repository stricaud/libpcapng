#!/usr/bin/env python3
"""
RDP traffic simulation examples using pycapng.

Usage:
    python write_rdp.py <output.pcapng>

Generates four scenario sections into a single pcapng file:
  1. Default login (jdoe / WORKGROUP, TLS, 1920x1080)
  2. Admin login  (administrator / CORP, custom resolution)
  3. Clipboard file transfer
  4. Raw mode (no TLS – Wireshark decodes RDP fully)
"""

import sys
import pycapng

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} output.pcapng")
    sys.exit(1)

pcapng = pycapng.PcapNG()
pcapng.OpenFileLinkType(sys.argv[1], "w", pycapng.LINKTYPE_ETHERNET)

C_MAC   = "02:00:00:00:00:01"
S_MAC   = "02:00:00:00:00:02"
C_IP    = "192.168.1.100"
S_IP    = "192.168.1.10"
C_PORT  = 54321
RDP_PORT = 3389

# ── Scenario 1: Default login (jdoe, TLS) ────────────────────────────────────
#
# SimulateRdpLogin writes the full connection sequence directly into the file:
#   TCP 3-way handshake
#   X.224 CR / CC  ← Wireshark decodes as RDP negotiation
#   TLS handshake  (when use_tls=1)
#   MCS Connect Initial / Response
#   Channel joins, Client Info (credentials), Demand/Confirm Active,
#   Synchronize, Control PDUs
#
pcapng.SimulateRdpLogin(
    C_MAC, S_MAC, C_IP, S_IP, C_PORT, RDP_PORT,
    username="jdoe",
    domain="WORKGROUP",
    password="Password123",
    user_id=1004,           # default MCS user channel; change to override
    desktop_width=1920,
    desktop_height=1080,
    use_tls=1,
)

# Keyboard: scan codes for W-I-N-K-E-Y (0x11 = W, etc.)
for keycode in [0x11, 0x17, 0x31, 0x25, 0x12, 0x15]:  # w-i-n-k-e-y
    pcapng.SimulateRdpKeyboard(C_MAC, S_MAC, C_IP, S_IP, C_PORT, RDP_PORT,
                               keycode=keycode, use_tls=1)

# Mouse: move to (960, 540) and click
pcapng.SimulateRdpMouse(C_MAC, S_MAC, C_IP, S_IP, C_PORT, RDP_PORT,
                        x=960, y=540, click=1, use_tls=1)

# Clipboard transfer: paste a path
pcapng.SimulateRdpClipboard(C_MAC, S_MAC, C_IP, S_IP, C_PORT, RDP_PORT,
                             data=b"C:\\Users\\jdoe\\Documents\\report.docx",
                             use_tls=1)

pcapng.SimulateRdpLogout(C_MAC, S_MAC, C_IP, S_IP, C_PORT, RDP_PORT, use_tls=1)

# ── Scenario 2: Admin login (different IPs, custom resolution) ───────────────
pcapng.SimulateRdpLogin(
    "0a:00:00:00:00:01", "0a:00:00:00:00:02",
    "10.0.0.50", "10.0.0.5", 49152, RDP_PORT,
    username="administrator",
    domain="CORP",
    password="Admin@2024!",
    user_id=1007,
    desktop_width=2560,
    desktop_height=1440,
    use_tls=1,
)

pcapng.SimulateRdpLogout("0a:00:00:00:00:01", "0a:00:00:00:00:02",
                         "10.0.0.50", "10.0.0.5", 49152, RDP_PORT, use_tls=1)

# ── Scenario 3: No-TLS (classic RDP – Wireshark decodes all PDUs) ────────────
pcapng.SimulateRdpLogin(
    "02:aa:bb:cc:dd:01", "02:aa:bb:cc:dd:02",
    "172.16.0.100", "172.16.0.1", 51000, RDP_PORT,
    username="testuser",
    domain="WORKGROUP",
    password="test",
    user_id=1004,
    desktop_width=1280,
    desktop_height=720,
    use_tls=0,              # ← raw RDP, no TLS wrapping
)

for keycode in [0x23, 0x12, 0x26, 0x26, 0x18]:  # h-e-l-l-o scan codes
    pcapng.SimulateRdpKeyboard("02:aa:bb:cc:dd:01", "02:aa:bb:cc:dd:02",
                               "172.16.0.100", "172.16.0.1", 51000, RDP_PORT,
                               keycode=keycode, use_tls=0)

pcapng.SimulateRdpLogout("02:aa:bb:cc:dd:01", "02:aa:bb:cc:dd:02",
                         "172.16.0.100", "172.16.0.1", 51000, RDP_PORT, use_tls=0)

# ── Low-level: build individual packets without session state ─────────────────
# Use unique IPs/ports to avoid colliding with the scenario 1 TCP flow above.
SA_C_MAC  = "02:de:ad:00:00:01"
SA_S_MAC  = "02:de:ad:00:00:02"
SA_C_IP   = "10.99.0.1"
SA_S_IP   = "10.99.0.2"
SA_C_PORT = 60001

frame = pcapng.BuildRdpConnectionRequest(
    SA_C_MAC, SA_S_MAC, SA_C_IP, SA_S_IP, SA_C_PORT, RDP_PORT,
    username="standalone",
    domain="EXAMPLE",
    requested_protocol=pycapng.RDP_PROTO_SSL,
    use_tls=1,
)
pcapng.WritePacket(frame, "standalone X.224 CR")

frame = pcapng.BuildRdpConnectionConfirm(
    SA_S_MAC, SA_C_MAC, SA_S_IP, SA_C_IP, RDP_PORT, SA_C_PORT,
    selected_protocol=pycapng.RDP_PROTO_SSL,
)
pcapng.WritePacket(frame, "standalone X.224 CC")

pcapng.CloseFile()
print(f"Wrote RDP simulation to {sys.argv[1]}")
print("Open in Wireshark: it will decode X.224 CR/CC as RDP negotiation on port 3389.")
