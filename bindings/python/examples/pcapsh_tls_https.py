#!/usr/bin/env python3
"""
Simulate a TLS 1.2 HTTPS session with a self-signed certificate.

The certificate is generated here in Python (via openssl subprocess) and
injected into the TLS Certificate record using pcapsh.tls_certificate().
The resulting pcapng uses TLS_NULL_WITH_NULL_NULL so Wireshark decodes
HTTP content directly — no key file needed.

Usage:
    python3 pcapsh_tls_https.py [output.pcapng]
"""

import subprocess
import struct
import sys
import time
import tempfile
import os

sys.path.insert(0, "../")

from libpcapng import pcapsh


# ── Certificate generation ────────────────────────────────────────────────────

def generate_self_signed_cert_der(cn: str = "example.com") -> bytes:
    """Generate a minimal self-signed RSA certificate; return DER bytes."""
    with tempfile.TemporaryDirectory() as d:
        key_path  = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "365", "-nodes",
            "-subj", f"/CN={cn}",
        ], check=True, capture_output=True)
        der = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-outform", "DER"],
            check=True, capture_output=True,
        ).stdout
    return der


# ── Minimal pcapng writer ─────────────────────────────────────────────────────

def write_pcapng(path: str, frames: list[bytes]) -> None:
    LINKTYPE_ETHERNET = 1

    def pad4(n): return (n + 3) & ~3

    with open(path, "wb") as f:
        shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        blen = 12 + len(shb_body)
        f.write(struct.pack("<II", 0x0A0D0D0A, blen) + shb_body + struct.pack("<I", blen))

        idb_body = struct.pack("<HHI", LINKTYPE_ETHERNET, 0, 65535)
        blen = 12 + len(idb_body)
        f.write(struct.pack("<II", 0x00000001, blen) + idb_body + struct.pack("<I", blen))

        ts = int(time.time() * 1e6)
        for frame in frames:
            padded = frame + b"\x00" * (pad4(len(frame)) - len(frame))
            epb_body = struct.pack("<IIIII",
                0, ts >> 32 & 0xFFFFFFFF, ts & 0xFFFFFFFF,
                len(frame), len(frame)) + padded
            blen = 12 + len(epb_body)
            f.write(struct.pack("<II", 0x00000006, blen) + epb_body + struct.pack("<I", blen))
            ts += 50_000  # 50 ms between packets


# ── HTTPS session builder ─────────────────────────────────────────────────────

def build_https_session(cert_der: bytes) -> list[bytes]:
    """
    Build a minimal HTTPS/TLS 1.2 session:
      1–3   TCP handshake    (SYN / SYN-ACK / ACK)
      4     TLS ClientHello
      5     TLS ServerHello
      6     TLS Certificate  ← your self-signed cert
      7     TLS CCS + Finished (server)
      8     TLS CCS + Finished (client)
      9     HTTP GET (TLS ApplicationData)
      10    HTTP 200 OK (TLS ApplicationData)
      11–13 TCP teardown
    """
    sh = pcapsh.PcapSH()

    CLIENT_MAC = "aa:bb:cc:00:01:02"
    SERVER_MAC = "aa:bb:cc:00:03:04"
    CLIENT_IP  = "192.168.1.10"
    SERVER_IP  = "93.184.216.34"   # example.com
    CPORT      = 54321
    SPORT      = 443

    def ether(src, dst):
        return f'Ether(src="{src}", dst="{dst}")'

    def ip(src, dst, ttl=64):
        return f'IP(src="{src}", dst="{dst}", ttl={ttl}, flags=2)'

    def tcp(sport, dport, flags, window=65535):
        return f'TCP(sport={sport}, dport={dport}, flags="{flags}", window={window})'

    def frame(e, i, t, payload=""):
        chain = f"{e}/{i}/{t}"
        if payload:
            chain += f"/{payload}"
        return chain

    # Build TLS record bytes in Python and pass as fromhex() to pcapsh.
    # Each TLS record is a raw payload on top of TCP.
    def to_fromhex(data: bytes) -> str:
        return 'fromhex("' + data.hex() + '")'

    cert_record = pcapsh.tls_certificate(cert_der)
    client_hello = pcapsh.tls_client_hello("example.com")
    server_hello = pcapsh.tls_server_hello()
    srv_ccs      = pcapsh.tls_change_cipher_spec()
    srv_finished = pcapsh.tls_finished()
    cli_ccs      = pcapsh.tls_change_cipher_spec()
    cli_finished = pcapsh.tls_finished()
    http_req     = pcapsh.tls_application_data(
        b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
    http_resp    = pcapsh.tls_application_data(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!")

    OUT = "https_example.pcapng"

    def wrpcap(src_e, dst_e, src_i, dst_i, sport, dport, flags, payload=""):
        e = f'Ether(src="{src_e}", dst="{dst_e}")'
        i = f'IP(src="{src_i}", dst="{dst_i}", ttl=64, flags=2)'
        t = f'TCP(sport={sport}, dport={dport}, flags="{flags}", window=65535)'
        chain = f'{e}/{i}/{t}'
        if payload:
            chain += f'/{payload}'
        return f'wrpcap("{OUT}", {chain})'

    lines = [
        # ── TCP handshake ──
        wrpcap(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CPORT, SPORT, "S"),
        wrpcap(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, SPORT, CPORT, "SA"),
        wrpcap(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CPORT, SPORT, "A"),
        # ── TLS handshake ──
        wrpcap(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CPORT, SPORT, "PA",
               to_fromhex(client_hello)),
        wrpcap(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, SPORT, CPORT, "PA",
               to_fromhex(server_hello)),
        wrpcap(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, SPORT, CPORT, "PA",
               to_fromhex(cert_record)),
        wrpcap(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, SPORT, CPORT, "PA",
               to_fromhex(srv_ccs + srv_finished)),
        wrpcap(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CPORT, SPORT, "PA",
               to_fromhex(cli_ccs + cli_finished)),
        # ── HTTP request / response ──
        wrpcap(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CPORT, SPORT, "PA",
               to_fromhex(http_req)),
        wrpcap(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, SPORT, CPORT, "PA",
               to_fromhex(http_resp)),
        # ── TCP teardown ──
        wrpcap(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CPORT, SPORT, "FA"),
        wrpcap(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, SPORT, CPORT, "FA"),
        wrpcap(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CPORT, SPORT, "A"),
    ]

    return sh.run_string("\n".join(lines))


def main():
    output = sys.argv[1] if len(sys.argv) > 1 else "https_example.pcapng"

    print("Generating self-signed certificate for example.com …")
    cert_der = generate_self_signed_cert_der("example.com")
    print(f"  Certificate DER: {len(cert_der)} bytes")

    print("Building HTTPS session …")
    packets = build_https_session(cert_der)
    print(f"  Generated {len(packets)} packet(s)")

    write_pcapng(output, packets)
    print(f"Wrote {output}")
    print("  Open in Wireshark — HTTP content is visible directly (TLS_NULL cipher).")


if __name__ == "__main__":
    main()
