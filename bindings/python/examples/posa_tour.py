#!/usr/bin/env python3
"""
posa_tour.py — capture, discover, dissect, craft: a guided tour of libpcapng.

Five stages, each one building on the last:

  1. capture   pull frames off the wire (or replay a file), save them as pcapng
  2. discover  ask posa which decoder claims each frame
  3. dissect   hand a claimed payload to its decoder and print the field tree
  4. author    write a posa decoder for a protocol nothing understands yet
  5. craft     build packets from that same decoder and write them for Wireshark

The arc is deliberate. Stage 2 finds traffic posa already knows (Modbus/TCP on
port 502) next to traffic it does not (a made-up HeartBeat protocol on port
9999) — which is exactly the moment you would reach for stage 4. And the
decoder you write there is the same file stage 5 builds packets from: one
definition, read and write.

Run the whole tour with no privileges at all:

    python3 posa_tour.py

It generates its own demo traffic when it cannot capture. To capture for real:

    sudo python3 posa_tour.py --iface en0 --filter "tcp.port == 502" --count 20

Or replay a capture you already have:

    python3 posa_tour.py --read mycapture.pcapng

Single stages, once you know your way around:

    python3 posa_tour.py --stage discover --read mycapture.pcapng
"""

import argparse
import os
import struct
import sys
import tempfile

import pycapng
from pycapng import pcapsh


# ══════════════════════════════════════════════════════════════════════════════
# The decoder we will write in stage 4 and build packets from in stage 5.
#
# This is the whole point of posa: a protocol is a text file, not C code. The
# engine that reads it is the same one behind every decoder libpcapng ships.
#
#   Object<main> NAME   opens a decoder. `main` means it stands on its own
#                       rather than being a variant inside a group.
#   abbrev "hb"         the prefix for its field names in filters: hb.node_id
#   col "HeartBeat"     what the protocol column shows
#   uint16 x ...        a field: type, name, ["Display Name"], defaults(value)
#   indented NAME = n   an enumerated value for the field above it
#   info "..." a, b     the one-line summary, printf-style over named fields
#   rule tcp.port ...   which packets to hand to this decoder
#
# `defaults(...)` earns its keep twice over: dissection uses it for
# documentation, and packet crafting uses it as the value a field takes when
# you do not set one. Stage 5 leans on that.
# ══════════════════════════════════════════════════════════════════════════════

HEARTBEAT_POSA = """\
# heartbeat.posa — a made-up device heartbeat, carried over UDP port 9999.
#
# Wire layout (10 bytes, big-endian):
#   0      version      uint8    always 1
#   1      msg_type     uint8    HELLO / BEAT / BYE
#   2-3    node_id      uint16   which device is talking
#   4-7    uptime_s     uint32   seconds since it booted
#   8-9    temp_c10     uint16   temperature in tenths of a degree

Object<main> HeartBeat
    abbrev "hb"
    col "HeartBeat"

    uint8  version  ["Version"] defaults(1)
    uint8  msg_type ["Message Type"] defaults(2)
        HELLO = 1
        BEAT  = 2
        BYE   = 3
    uint16 node_id  ["Node ID"] defaults(7)
    uint32 uptime_s ["Uptime (s)"] defaults(0)
    uint16 temp_c10 ["Temperature (0.1 C)"] defaults(200)

    info "%s node=%u up=%us" msg_type, node_id, uptime_s

rule udp.port == 9999 => HeartBeat
"""

HEARTBEAT_PORT = 9999


# ══════════════════════════════════════════════════════════════════════════════
# Frame parsing
#
# libpcapng's C dissector walks Ethernet/IP/TCP/UDP for you, but that full
# field tree is not exposed to Python yet — posa_dissect() takes a payload and
# a decoder name. So we peel the headers off ourselves. Ten lines, and it makes
# plain what a decoder is actually handed.
# ══════════════════════════════════════════════════════════════════════════════

ETH_HDR = 14
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# EtherTypes that mean "this really is an Ethernet frame", used to notice when
# a capture is not Ethernet at all.
KNOWN_ETHERTYPES = {0x0800, 0x0806, 0x86DD, 0x8100, 0x88A8}


def parse_frame(frame: bytes) -> dict:
    """Peel Ethernet/IPv4/TCP|UDP off a frame.

    Returns a dict describing each layer found and, in `payload`, whatever is
    left once the transport header ends. Fields that do not apply are None, so
    a caller can tell "no IP layer" from "IP but no ports".
    """
    out = {"ethertype": None, "ip_proto": None, "src": None, "dst": None,
           "sport": None, "dport": None, "payload": b"", "summary": ""}

    if len(frame) < ETH_HDR:
        out["summary"] = f"runt frame, {len(frame)} bytes"
        return out

    out["ethertype"] = struct.unpack("!H", frame[12:14])[0]
    if out["ethertype"] != 0x0800:                       # not IPv4 — stop here
        out["summary"] = f"ethertype 0x{out['ethertype']:04x}"
        return out

    ip = frame[ETH_HDR:]
    if len(ip) < 20:
        out["summary"] = "truncated IPv4 header"
        return out

    ihl = (ip[0] & 0x0F) * 4
    out["ip_proto"] = ip[9]
    out["src"] = ".".join(str(b) for b in ip[12:16])
    out["dst"] = ".".join(str(b) for b in ip[16:20])

    # total_length bounds the payload: trailing padding a NIC added is not data.
    total_len = struct.unpack("!H", ip[2:4])[0]
    ip = ip[:total_len] if 20 <= total_len <= len(ip) else ip
    l4 = ip[ihl:]

    if out["ip_proto"] == IPPROTO_TCP and len(l4) >= 20:
        out["sport"], out["dport"] = struct.unpack("!HH", l4[0:4])
        data_off = (l4[12] >> 4) * 4                     # in 32-bit words
        out["payload"] = l4[data_off:]
        out["summary"] = f"TCP {out['src']}:{out['sport']} -> {out['dst']}:{out['dport']}"
    elif out["ip_proto"] == IPPROTO_UDP and len(l4) >= 8:
        out["sport"], out["dport"] = struct.unpack("!HH", l4[0:4])
        udp_len = struct.unpack("!H", l4[4:6])[0]
        out["payload"] = l4[8:udp_len] if 8 <= udp_len <= len(l4) else l4[8:]
        out["summary"] = f"UDP {out['src']}:{out['sport']} -> {out['dst']}:{out['dport']}"
    else:
        out["payload"] = l4
        out["summary"] = f"IP proto {out['ip_proto']} {out['src']} -> {out['dst']}"

    return out


def hexdump(data: bytes, indent: str = "    ", limit: int = 64) -> str:
    """Classic offset / hex / ASCII dump, truncated to `limit` bytes."""
    lines, shown = [], data[:limit]
    for off in range(0, len(shown), 16):
        chunk = shown[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{indent}{off:04x}  {hexpart}  {text}")
    if len(data) > limit:
        lines.append(f"{indent}      ... {len(data) - limit} more bytes")
    return "\n".join(lines)


def banner(n: int, title: str) -> None:
    print(f"\n{'═' * 78}\n  STAGE {n}  {title}\n{'═' * 78}")


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 1 — capture
# ══════════════════════════════════════════════════════════════════════════════

def stage_capture(args, sh) -> list[bytes]:
    """Get frames from somewhere: the wire, a file, or a generator."""
    banner(1, "CAPTURE — get frames")

    if args.read:
        print(f"Reading {args.read}\n")
        frames = read_pcapng(args.read)
        print(f"  {len(frames)} packet(s) read")
        return frames

    if args.iface:
        return capture_live(args)

    print("No --iface and no --read, so the tour generates its own traffic.")
    print("Re-run with `sudo python3 posa_tour.py --iface <dev>` to use the wire.\n")
    frames = generate_demo_traffic(sh)
    print(f"  {len(frames)} packet(s) generated")
    return frames


def capture_live(args) -> list[bytes]:
    """Live capture. Needs root (or CAP_NET_RAW on Linux)."""
    print("Interfaces libpcapng can see:")
    for dev in pycapng.capture_list_devices():
        print(f"    {dev['name']}{'  (loopback)' if dev['loopback'] else ''}")

    iface = args.iface if args.iface != "auto" else pycapng.capture_default_device()
    if not iface:
        sys.exit("no usable interface found")

    print(f"\nCapturing {args.count} packet(s) on {iface}")
    if args.filter:
        print(f"Filter: {args.filter}")
        # Worth knowing: this filter understands posa field names too, so
        # `ModbusTCP.function_code == 3` works here and not just in Wireshark.
    print("Waiting for traffic — Ctrl-C to stop early.\n")

    cap = pycapng.Capture(iface)
    cap.set_snaplen(65535)
    cap.set_promisc(True)
    cap.set_timeout(100)                 # ms the kernel may batch before delivery
    if args.filter:
        cap.set_filter(args.filter)      # raises on a bad expression

    frames: list[bytes] = []

    def on_packet(pkt):
        # pkt.data is a view into the kernel ring and is only valid for the
        # duration of this call — bytes() copies it before we keep it.
        frames.append(bytes(pkt.data))
        trunc = "*" if pkt.captured_len < pkt.original_len else " "
        print(f"  [{len(frames):4d}] {pkt.captured_len:5d}{trunc} bytes")

    try:
        cap.loop(args.count, on_packet)
    except KeyboardInterrupt:
        cap.break_loop()

    stats = cap.get_stats()
    cap.close()
    print(f"\n  received={stats.received} dropped={stats.dropped} "
          f"filtered={stats.filtered} passed={stats.passed}")
    return frames


def read_pcapng(path: str) -> list[bytes]:
    """Pull the raw frames out of a pcapng file.

    ForeachPacket hands back the Enhanced Packet Block's fixed header followed
    by exactly captured_len bytes of frame:
        interface_id(4) ts_high(4) ts_low(4) captured_len(4) original_len(4)
    all little-endian, so the frame starts at offset 20.
    """
    EPB_HDR = 20
    frames: list[bytes] = []

    def each_block(counter, btype, total_len, data):
        if btype != pycapng.ENHANCED_PACKET_BLOCK or len(data) < EPB_HDR:
            return
        _iface, _hi, _lo, caplen, _orig = struct.unpack("<IIIII", data[:EPB_HDR])
        frames.append(data[EPB_HDR:EPB_HDR + caplen])

    f = pycapng.PcapNG()
    f.OpenFile(path, "r")
    f.ForeachPacket(each_block)
    f.CloseFile()
    return frames


def run_pcapsh(sh, script: str, **kw) -> list[bytes]:
    """Run a pcapsh script, keeping its output in step with ours.

    pcapsh prints from C, through a stdio buffer Python knows nothing about.
    Without the flush, anything ls() or an error prints surfaces whenever that
    buffer happens to drain — usually at exit, pages away from the call.
    """
    sys.stdout.flush()
    frames = sh.run_string(script, **kw)
    sys.stdout.flush()
    return frames


def generate_demo_traffic(sh) -> list[bytes]:
    """Synthesise a small mixed capture so the tour runs without privileges.

    Two Modbus/TCP packets (a protocol posa already ships a decoder for) and
    three HeartBeat packets (one it has never heard of). Stage 2 will tell them
    apart, which is what motivates stage 4.

    `/` stacks layers, and fromhex() drops raw bytes in as a payload. One
    statement per line: pcapsh continues a line only when it ends in a
    backslash, so a stray newline mid-expression would split the packet in two.
    """
    return run_pcapsh(sh, """
# ── Modbus/TCP: read one holding register, and the reply ────────────────────
wrpcap("x", Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="10.0.0.10", dst="10.0.0.20")/TCP(sport=45000, dport=502, flags="PA")/fromhex("000100000006010300000001"))
wrpcap("x", Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")/IP(src="10.0.0.20", dst="10.0.0.10")/TCP(sport=502, dport=45000, flags="PA")/fromhex("0001000000050103021234"))

# ── HeartBeat: three UDP datagrams nothing can decode yet ───────────────────
wrpcap("x", Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:01")/IP(src="10.0.0.30", dst="10.0.0.1")/UDP(sport=41000, dport=9999)/fromhex("0101002a0000000000d2"))
wrpcap("x", Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:01")/IP(src="10.0.0.30", dst="10.0.0.1")/UDP(sport=41000, dport=9999)/fromhex("0102002a00000e1000e6"))
wrpcap("x", Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:01")/IP(src="10.0.0.30", dst="10.0.0.1")/UDP(sport=41000, dport=9999)/fromhex("0103002a0001c20000f5"))
""")


def save_pcapng(frames: list[bytes], path: str, comment: str = "") -> None:
    """Write frames out as pcapng — openable in Wireshark, and re-readable here.

    The link type is stamped once, in the Interface Description Block, and
    everything downstream trusts it. LINKTYPE_ETHERNET is right for a NIC and
    wrong for loopback or a tunnel, which carry their own link layers.
    """
    out = pycapng.PcapNG()
    out.OpenFileLinkType(path, "w", pycapng.LINKTYPE_ETHERNET)
    for frame in frames:
        out.WritePacket(frame, comment)
    out.CloseFile()
    print(f"\n  wrote {len(frames)} packet(s) to {path}")


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 2 — discover
# ══════════════════════════════════════════════════════════════════════════════

def identify(info: dict):
    """Ask posa which decoder claims this frame, and say how it decided.

    These four calls answer the `rule` lines decoders declare. Order matters:
    a port binding is definite, a content signature is strong evidence, and a
    weak signature is a couple of suggestive bytes worth trying only once the
    others have come up empty.

        rule tcp.port == 502    => ModbusTCP     posa_bound_port
        rule ip.proto == 51     => AH            posa_bound_ipproto
        rule eth.type == 0x8847 => MPLS          posa_bound_ethertype
        rule tcp.content "SSH-" => SSH           posa_bound_content
    """
    proto, payload = info["ip_proto"], info["payload"]

    for port in (info["dport"], info["sport"]):
        if port is not None:
            name = pycapng.posa_bound_port(proto, port)
            if name:
                return name, f"rule {'tcp' if proto == IPPROTO_TCP else 'udp'}.port == {port}"

    if payload:
        name = pycapng.posa_bound_content(proto, payload)
        if name:
            return name, "payload signature"

    if proto is not None:
        name = pycapng.posa_bound_ipproto(proto)
        if name:
            return name, f"rule ip.proto == {proto}"

    if info["ethertype"] is not None:
        name = pycapng.posa_bound_ethertype(info["ethertype"])
        if name:
            return name, f"rule eth.type == 0x{info['ethertype']:04x}"

    if payload:
        name = pycapng.posa_bound_content(proto, payload, weak=True)
        if name:
            return name, "weak signature (suggestive only)"

    return None, "no rule matched"


def stage_discover(frames: list[bytes]) -> list[tuple]:
    """Label every frame with the decoder that claims it."""
    banner(2, "DISCOVER — which decoder claims each frame?")

    # The decoders bundled into the library only reach the registry when
    # something asks for them. Dissecting a packet does it implicitly; here we
    # need the registry populated *before* anything is dissected, because the
    # port and signature lookups read it directly.
    count = pycapng.posa_load_builtin()
    print(f"{count} decoders loaded (every .posa bundled into the library)\n")

    if frames and not any(len(f) >= ETH_HDR and
                          struct.unpack("!H", f[12:14])[0] in KNOWN_ETHERTYPES
                          for f in frames):
        print("  None of these frames start with an Ethernet header. This tour")
        print("  assumes LINKTYPE_ETHERNET — a loopback or tunnel interface")
        print("  (lo0, gif0, utun*) uses a different link layer, so the header")
        print("  peeling below will not find anything. Capture on a real NIC.\n")

    results = []
    for i, frame in enumerate(frames, 1):
        info = parse_frame(frame)
        name, how = identify(info)
        results.append((i, frame, info, name))

        label = name if name else "— unknown —"
        print(f"  [{i:3d}] {info['summary']:<44} {label}")
        print(f"        {len(info['payload']):3d} payload bytes   ({how})")

    unknown = sum(1 for r in results if r[3] is None)
    if unknown:
        print(f"\n  {unknown} frame(s) nothing claims. That is what stage 4 is for.")
    return results


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 3 — dissect
# ══════════════════════════════════════════════════════════════════════════════

def print_tree(nodes: list, indent: str = "      ") -> None:
    """Print the field tree posa_dissect() returns.

    Every node carries `offset` and `length` — the exact bytes it covers — which
    is what lets a hex pane highlight a field you click in the tree.
    """
    for node in nodes:
        span = f"@{node['offset']}+{node['length']}"
        print(f"{indent}{span:<9} {node['label']}")
        if node["children"]:
            print_tree(node["children"], indent + "  ")


def dissect_one(proto: str, payload: bytes, label: str) -> bool:
    """Run one decoder over one payload and print what it made of it."""
    result = pycapng.posa_dissect(proto, payload)
    if result is None:
        print(f"  {label}: {proto} decoded nothing")
        return False

    print(f"  {label}  ->  {proto}")
    print(f"      column: {result['col']}")
    print(f"      info:   {result['info']}")
    print(f"      consumed {result['consumed']} of {len(payload)} bytes")
    print_tree(result["fields"])
    print()
    return True


def stage_dissect(results: list[tuple]) -> None:
    """Hand each claimed payload to its decoder."""
    banner(3, "DISSECT — decode the payloads posa recognised")

    seen = set()
    decoded = 0
    for idx, _frame, info, name in results:
        if name is None or not info["payload"]:
            continue
        # One example per protocol keeps the output readable.
        if name in seen:
            continue
        seen.add(name)
        decoded += dissect_one(name, info["payload"], f"packet {idx}")

    if not decoded:
        print("  Nothing to dissect — no frame matched a decoder.")


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 4 — author a decoder
# ══════════════════════════════════════════════════════════════════════════════

def stage_author(results: list[tuple], posa_path: str, sh) -> None:
    """Write a decoder for the traffic nothing claimed, then use it."""
    banner(4, "AUTHOR — write a posa decoder for the unknown traffic")

    unknown = [(i, info) for i, _f, info, name in results
               if name is None and info["payload"]]
    if not unknown:
        print("  Every frame carrying a payload was already claimed — there is")
        print("  nothing here to reverse-engineer. Loading the HeartBeat decoder")
        print("  anyway, so stage 5 has something to build packets from.\n")
    else:
        idx, info = unknown[0]
        print(f"Packet {idx} is {info['summary']}, and no rule claims it.")
        print(f"Here are its {len(info['payload'])} payload bytes:\n")
        print(hexdump(info["payload"]))
        print("""
Read the bytes and the structure suggests itself:

    01                 a version, and it is 1 in every packet
    01 / 02 / 03       a small enumeration that changes per packet
    00 2a              two bytes that never change — an identifier, 42
    00 00 00 00        a counter that climbs: 0, 3600, 115200
    00 d2              a value that drifts: 210, 230, 245

Written as posa, that is:""")

    print("\n" + "\n".join(f"    {line}" for line in HEARTBEAT_POSA.splitlines()))

    # Two ways in. pycapng.posa_load_text() parses a decoder straight from a
    # string — what you want while you are still guessing at the layout, since
    # there is no file to keep rewriting. PcapSH.load_posa() reads a file and
    # registers it in two places at once: the dissector registry *and* the
    # packet builder, which is what lets stage 5 craft with it.
    #
    # Load it once, through the builder, and both get it. Loading the same
    # decoder twice is not an error but the second load adds nothing new, so
    # the builder would never see it.
    with open(posa_path, "w") as fh:
        fh.write(HEARTBEAT_POSA)
    n = sh.load_posa(posa_path)
    print(f"\n  saved to {posa_path}, loaded {n} decoder")

    for warning in pycapng.posa_warnings():
        print(f"  warning: {warning}")

    # The `rule udp.port == 9999` line is live the moment the decoder loads:
    # the same lookup that came up empty in stage 2 now answers.
    print(f"\n  posa_bound_port(17, {HEARTBEAT_PORT}) -> "
          f"{pycapng.posa_bound_port(IPPROTO_UDP, HEARTBEAT_PORT)}")

    print("\nAnd the frames that were unreadable a moment ago:\n")
    for idx, info in unknown:
        dissect_one("HeartBeat", info["payload"], f"packet {idx}")


# ══════════════════════════════════════════════════════════════════════════════
# STAGE 5 — craft
# ══════════════════════════════════════════════════════════════════════════════

def stage_craft(posa_path: str, out_path: str, sh) -> None:
    """Build packets from the decoder written in stage 4.

    The same .posa file that told the dissector how to *read* HeartBeat tells
    the builder how to *write* it. Fields you do not mention take the value
    their `defaults(...)` declares, so a bare HeartBeat() is a complete, valid
    packet and you only spell out what you want to differ.
    """
    banner(5, "CRAFT — build packets from the same decoder")

    # Stage 4 already loaded this decoder through the same PcapSH; load_posa()
    # here is for the `--stage craft` path, where stage 4 never ran. A decoder
    # already present is simply left alone.
    sh.load_posa(posa_path)

    # pcapsh has an ls(HeartBeat) that tabulates a protocol's fields and their
    # defaults. It is worth knowing about, but it prints from C: piped to a
    # file its output arrives whenever the stdio buffer drains, out of step
    # with everything Python printed. So the defaults are shown below by
    # dissecting packet 1, which uses every one of them.
    script = """
# 1. Every field left at its default: version=1, msg_type=BEAT, node_id=7, uptime_s=0, temp_c10=200.
wrpcap("x", Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:01")/IP(src="10.0.0.30", dst="10.0.0.1")/UDP(sport=41000, dport=9999)/HeartBeat())

# 2. Override some of them. An enumerated field takes the name, not the number.
wrpcap("x", Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:01")/IP(src="10.0.0.30", dst="10.0.0.1")/UDP(sport=41000, dport=9999)/HeartBeat(msg_type=HELLO, node_id=1234, temp_c10=195))

# 3. A node that has been up a day and is running warm.
wrpcap("x", Ether(src="02:00:00:00:00:04", dst="02:00:00:00:00:01")/IP(src="10.0.0.31", dst="10.0.0.1")/UDP(sport=41001, dport=9999)/HeartBeat(msg_type=BEAT, node_id=1235, uptime_s=86400, temp_c10=488))

# 4. Saying goodbye.
wrpcap("x", Ether(src="02:00:00:00:00:04", dst="02:00:00:00:00:01")/IP(src="10.0.0.31", dst="10.0.0.1")/UDP(sport=41001, dport=9999)/HeartBeat(msg_type=BYE, node_id=1235, uptime_s=86401, temp_c10=486))
"""
    frames = run_pcapsh(sh, script)

    print("\nPacket 1 was built as a bare HeartBeat() — every field here is the")
    print("value its defaults(...) declares:\n")
    first = parse_frame(frames[0])
    result = pycapng.posa_dissect("HeartBeat", first["payload"])
    print_tree(result["fields"], indent="    ")

    print("\nAll four, read back through the decoder that built them:\n")
    for i, frame in enumerate(frames, 1):
        info = parse_frame(frame)
        result = pycapng.posa_dissect("HeartBeat", info["payload"])
        print(f"  [{i}] {info['payload'].hex()}   {result['info'] if result else '?'}")

    save_pcapng(frames, out_path, comment="built by posa_tour.py")

    print(f"\n  Open it in Wireshark:   wireshark {out_path}")
    print("  It will show plain UDP — Wireshark has never heard of HeartBeat.")
    print("  Point pcapsh at the decoder and the same file reads properly:")
    print("")
    print("      $ pcapsh")
    print(f'      > load("{posa_path}")')
    print(f'      > rdpcap("{out_path}")')
    print(f'      > rdpcap("{out_path}", "hb.msg_type == BYE")')
    print("")
    print("  The `abbrev \"hb\"` line is what names those filter fields. To make")
    print("  the decoder permanent — for pcapngtool and every other tool built")
    print("  on the library — drop the .posa into bin/protos/ and rebuild: they")
    print("  are embedded at build time.")


# ══════════════════════════════════════════════════════════════════════════════

STAGES = ("capture", "discover", "dissect", "author", "craft", "all")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="A guided tour of libpcapng: capture, discover, dissect, craft.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  posa_tour.py                                    the whole tour, no privileges needed
  sudo posa_tour.py --iface en0 --count 50        capture for real
  sudo posa_tour.py --iface auto --filter "tcp.port == 502"
  posa_tour.py --read mycapture.pcapng            replay a file you already have
  posa_tour.py --stage discover --read x.pcapng   one stage on its own""")
    ap.add_argument("--stage", choices=STAGES, default="all",
                    help="run one stage instead of the whole tour")
    ap.add_argument("--iface", metavar="DEV",
                    help="capture live from this interface ('auto' for the default); needs root")
    ap.add_argument("--read", metavar="FILE",
                    help="replay a pcapng file instead of capturing")
    ap.add_argument("--filter", metavar="EXPR",
                    help="display filter for live capture, e.g. 'tcp.port == 502'")
    ap.add_argument("--count", type=int, default=20,
                    help="packets to capture before stopping (default 20)")
    ap.add_argument("--outdir", default=tempfile.gettempdir(),
                    help="where to write the pcapng and .posa files")
    args = ap.parse_args()

    if not hasattr(pycapng, "posa_load_builtin"):
        sys.exit("This pycapng predates posa_load_builtin(); rebuild and "
                 "reinstall the Python bindings.")

    captured_path = os.path.join(args.outdir, "posa_tour_captured.pcapng")
    crafted_path = os.path.join(args.outdir, "posa_tour_crafted.pcapng")
    posa_path = os.path.join(args.outdir, "heartbeat.posa")

    # One PcapSH for the whole tour. It is both the packet builder and the way
    # a .posa file reaches the builder, so stages 4 and 5 have to share it.
    sh = pcapsh.PcapSH()

    want = args.stage

    # Stages 2-4 all need frames, so a single-stage run still has to capture.
    if want in ("capture", "discover", "dissect", "author", "all"):
        frames = stage_capture(args, sh)
        if not frames:
            sys.exit("no packets — nothing to work with")
        if want in ("capture", "all"):
            save_pcapng(frames, captured_path)
        if want == "capture":
            return
    else:
        frames = []

    if want in ("discover", "dissect", "author", "all"):
        results = stage_discover(frames)
        if want == "discover":
            return

    if want in ("dissect", "all"):
        stage_dissect(results)
        if want == "dissect":
            return

    if want in ("author", "all"):
        stage_author(results, posa_path, sh)
        if want == "author":
            return

    if want in ("craft", "all"):
        if not os.path.exists(posa_path):
            # `--stage craft` on its own: write the decoder out first.
            with open(posa_path, "w") as fh:
                fh.write(HEARTBEAT_POSA)
        stage_craft(posa_path, crafted_path, sh)

    if want == "all":
        print(f"\n{'═' * 78}")
        print("  Tour complete. What you have now:")
        print(f"    {captured_path}   the frames stage 1 collected")
        print(f"    {posa_path}   the decoder you wrote in stage 4")
        print(f"    {crafted_path}    packets built from it in stage 5")
        print(f"{'═' * 78}")


if __name__ == "__main__":
    main()
