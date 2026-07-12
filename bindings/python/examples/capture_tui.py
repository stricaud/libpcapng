#!/usr/bin/env python3
"""capture_tui.py — Wireshark-style terminal packet capture viewer.

Layout:
  ┌──────────────────────────────────────────────────────────┐
  │  No.     Time          Dir   Len   Proto   Info          │  ← header
  ├──────────────────────────────────────────────────────────┤
  │     1  12:34:56.001   ←      74   TCP     1.2.3.4:443   │
  │     2  12:34:56.002   →    1480   TCP     10.0.0.1:80   │  ← auto-scroll
  │  ▶  3  12:34:56.003   ←      64   ARP     who has …     │  ← selected row
  ├── Packet Detail (hex) ───────────────────────────────────┤
  │  0000  45 00 00 3c …  E..<…                              │
  └──────────────────────────────────────────────────────────┘
  [↑↓] Select  [F] Follow/Freeze  [q] Quit   rcv:… drop:…

Requires root / CAP_NET_RAW (Linux) or root / network entitlement (macOS).

Usage:
    sudo python3 capture_tui.py [interface] [filter]

    sudo python3 capture_tui.py eth0
    sudo python3 capture_tui.py en0  "tcp.dstport == 443"
"""

import sys
import curses
import datetime
import queue
import threading

try:
    import pycapng
except ImportError:
    sys.exit("pycapng not found — build with: cmake --build build --target pycapng")


# ── protocol dissection (pure Python, no external deps) ───────────────────

def _mac(b):
    return ":".join(f"{x:02x}" for x in b)

def _ip4(b):
    return ".".join(str(x) for x in b)

def _ip6(b):
    return ":".join(f"{b[i]<<8|b[i+1]:04x}" for i in range(0, 16, 2))

_TCP_FLAGS = [("SYN",0x02),("ACK",0x10),("RST",0x04),("FIN",0x01),("PSH",0x08),("URG",0x20)]

def dissect(data):
    """Return (proto_label, info_string) for a raw Ethernet frame."""
    if len(data) < 14:
        return "?", "short frame"

    et  = (data[12] << 8) | data[13]
    off = 14

    # 802.1Q VLAN tag
    if et == 0x8100 and len(data) >= 18:
        et  = (data[16] << 8) | data[17]
        off = 18

    if et == 0x0806:
        return "ARP", f"{_mac(data[6:12])} → {_mac(data[0:6])}"

    if et == 0x0800 and len(data) >= off + 20:
        ihl  = (data[off] & 0x0f) * 4
        prot = data[off + 9]
        s4   = _ip4(data[off+12:off+16])
        d4   = _ip4(data[off+16:off+20])
        l4   = off + ihl

        if prot == 6 and len(data) >= l4 + 20:
            sp = (data[l4] << 8) | data[l4+1]
            dp = (data[l4+2] << 8) | data[l4+3]
            fl = data[l4+13]
            fs = "".join(n for n, b in _TCP_FLAGS if fl & b) or f"0x{fl:02x}"
            return "TCP", f"{s4}:{sp} → {d4}:{dp} [{fs}]"

        if prot == 17 and len(data) >= l4 + 4:
            sp = (data[l4] << 8) | data[l4+1]
            dp = (data[l4+2] << 8) | data[l4+3]
            return "UDP", f"{s4}:{sp} → {d4}:{dp}"

        if prot == 1 and len(data) >= l4 + 2:
            t  = data[l4]
            nm = {0:"Echo Reply",8:"Echo Req",3:"Unreachable",11:"TTL Exceeded",5:"Redirect"}
            return "ICMP", f"{s4} → {d4}  {nm.get(t, f'type={t}')}"

        pnames = {6:"TCP",17:"UDP",1:"ICMP",89:"OSPF",47:"GRE",50:"ESP",51:"AH"}
        return "IPv4", f"{s4} → {d4}  ({pnames.get(prot, f'proto={prot}')})"

    if et == 0x86DD and len(data) >= off + 40:
        nxt = data[off + 6]
        s6  = _ip6(data[off+8:off+24])
        d6  = _ip6(data[off+24:off+40])
        l4  = off + 40

        if nxt == 6 and len(data) >= l4 + 20:
            sp = (data[l4] << 8) | data[l4+1]
            dp = (data[l4+2] << 8) | data[l4+3]
            fl = data[l4+13]
            fs = "".join(n for n, b in _TCP_FLAGS if fl & b) or f"0x{fl:02x}"
            return "TCP6", f"{s6}:{sp} → {d6}:{dp} [{fs}]"

        if nxt == 17 and len(data) >= l4 + 4:
            sp = (data[l4] << 8) | data[l4+1]
            dp = (data[l4+2] << 8) | data[l4+3]
            return "UDP6", f"{s6}:{sp} → {d6}:{dp}"

        if nxt == 58 and len(data) >= l4 + 2:
            t  = data[l4]
            nm = {128:"Echo Req",129:"Echo Reply",133:"RS",134:"RA",135:"NS",136:"NA"}
            return "ICMPv6", f"{s6} → {d6}  {nm.get(t, f'type={t}')}"

        pnames = {6:"TCP",17:"UDP",58:"ICMPv6",59:"NoNext",60:"DestOpts"}
        return "IPv6", f"{s6} → {d6}  ({pnames.get(nxt, f'nxt={nxt}')})"

    return f"0x{et:04x}", f"{_mac(data[6:12])} → {_mac(data[0:6])}"


def hex_dump_lines(data):
    """Return list of 'OOOO  HH HH …  ASCII' strings for data."""
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hx    = " ".join(f"{b:02x}" for b in chunk)
        asc   = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"  {i:04x}  {hx:<47}  {asc}")
    return rows


def ts_str(ns):
    s  = ns // 1_000_000_000
    us = (ns % 1_000_000_000) // 1_000
    dt = datetime.datetime.fromtimestamp(s, tz=datetime.timezone.utc)
    return dt.strftime("%H:%M:%S") + f".{us:06d}"


# ── color pairs ───────────────────────────────────────────────────────────

CP_HEADER   = 1
CP_SELECTED = 2
CP_TCP      = 3
CP_UDP      = 4
CP_ICMP     = 5
CP_ARP      = 6
CP_OTHER    = 7
CP_STATUS   = 8
CP_DIVIDER  = 9

def _setup_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(CP_HEADER,   curses.COLOR_BLACK,  curses.COLOR_CYAN)
    curses.init_pair(CP_SELECTED, curses.COLOR_BLACK,  curses.COLOR_WHITE)
    curses.init_pair(CP_TCP,      curses.COLOR_WHITE,  -1)
    curses.init_pair(CP_UDP,      curses.COLOR_CYAN,   -1)
    curses.init_pair(CP_ICMP,     curses.COLOR_YELLOW, -1)
    curses.init_pair(CP_ARP,      curses.COLOR_GREEN,  -1)
    curses.init_pair(CP_OTHER,    curses.COLOR_WHITE,  -1)
    curses.init_pair(CP_STATUS,   curses.COLOR_BLACK,  curses.COLOR_BLUE)
    curses.init_pair(CP_DIVIDER,  curses.COLOR_CYAN,   -1)

def _proto_cp(proto):
    p = proto.upper()
    if p.startswith("TCP"):  return CP_TCP
    if p.startswith("UDP"):  return CP_UDP
    if p.startswith("ICMP"): return CP_ICMP
    if p == "ARP":           return CP_ARP
    return CP_OTHER


# ── packet record ─────────────────────────────────────────────────────────

class Rec:
    __slots__ = ("num","data","ts_ns","orig_len","direction","proto","info")
    def __init__(self, num, pkt):
        self.num       = num
        self.data      = bytes(pkt.data)
        self.ts_ns     = pkt.timestamp_ns
        self.orig_len  = pkt.original_len
        self.direction = pkt.direction
        self.proto, self.info = dissect(self.data)


# ── safe addstr (avoids writing to bottom-right corner) ───────────────────

def _addstr(win, y, x, s, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    s = s[:w - x]
    try:
        if attr:
            win.addstr(y, x, s, attr)
        else:
            win.addstr(y, x, s)
    except curses.error:
        pass


# ── TUI main ──────────────────────────────────────────────────────────────

def run_tui(stdscr, iface, fexpr):
    _setup_colors()
    curses.curs_set(0)
    stdscr.timeout(80)   # ms between getch() timeouts (= UI refresh rate)

    packets   = []       # list[Rec], appended by pump_queue()
    pkt_q     = queue.Queue()
    counter   = [0]

    selected  = 0        # index into packets[] of the highlighted row
    follow    = True     # auto-scroll to newest packet
    list_top  = 0        # index of first visible row in packet list
    hex_top   = 0        # first visible row in hex pane

    # ── open capture + start background thread ────────────────────────────
    cap = pycapng.Capture(iface)
    cap.set_snaplen(65535)
    cap.set_promisc(True)
    cap.set_timeout(80)
    if fexpr:
        cap.set_filter(fexpr)

    def _cap_thread():
        try:
            cap.loop(0, lambda pkt: pkt_q.put(pkt))
        except Exception:
            pass

    threading.Thread(target=_cap_thread, daemon=True).start()

    def pump():
        while True:
            try:
                pkt = pkt_q.get_nowait()
            except queue.Empty:
                break
            counter[0] += 1
            packets.append(Rec(counter[0], pkt))

    # ── layout constants ──────────────────────────────────────────────────
    #   row 0            : column header
    #   rows 1..list_h   : packet list
    #   row list_h+1     : divider
    #   rows list_h+2..  : hex pane
    #   last row         : status bar

    def layout(h):
        list_h = max(3, (h - 4) * 6 // 10)   # ~60 % for packet list
        hex_h  = max(2, h - list_h - 3)       # remaining rows
        return list_h, hex_h

    # ── drawing ───────────────────────────────────────────────────────────

    def draw_col_header(w):
        hdr = f"  {'No.':>6}  {'Time':15}  {'←→':2}  {'Len':>5}  {'Proto':<7}  Info"
        _addstr(stdscr, 0, 0,
                hdr[:w].ljust(w),
                curses.color_pair(CP_HEADER) | curses.A_BOLD)

    def draw_divider(y, w):
        label = " Packet Detail "
        try:
            stdscr.hline(y, 0, curses.ACS_HLINE, w)
            stdscr.addstr(y, 2, label, curses.color_pair(CP_DIVIDER) | curses.A_BOLD)
        except curses.error:
            pass

    def draw_pkt_row(y, rec, is_sel, w):
        arrow = "←" if rec.direction == pycapng.CAP_DIR_INBOUND  else \
                "→" if rec.direction == pycapng.CAP_DIR_OUTBOUND else " "
        row = (f"  {rec.num:>6}  {ts_str(rec.ts_ns):15}  {arrow:2}  "
               f"{len(rec.data):>5}  {rec.proto:<7}  {rec.info}")
        row = row[:w].ljust(w)
        if is_sel:
            attr = curses.color_pair(CP_SELECTED) | curses.A_BOLD
        else:
            attr = curses.color_pair(_proto_cp(rec.proto))
        _addstr(stdscr, y, 0, row, attr)

    def draw_hex_pane(y0, hex_h, w, rec):
        if rec is None:
            _addstr(stdscr, y0, 0, "  (no packet selected)", curses.A_DIM)
            return
        lines = hex_dump_lines(rec.data)
        for i in range(hex_h):
            li = hex_top + i
            text = lines[li] if li < len(lines) else ""
            _addstr(stdscr, y0 + i, 0, text[:w].ljust(w))

    def draw_status(y, w):
        try:
            s = cap.get_stats()
            stats = f"  rcv:{s.received}  drop:{s.dropped}  filter:{s.filtered}"
        except Exception:
            stats = ""
        mode = "▶ FOLLOW" if follow else "■ FROZEN"
        bar  = f" [↑↓] Select  [F] {mode}  [End] Jump to latest  [q] Quit{stats}"
        _addstr(stdscr, y, 0, bar[:w].ljust(w), curses.color_pair(CP_STATUS))

    # ── main event loop ───────────────────────────────────────────────────
    while True:
        h, w     = stdscr.getmaxyx()
        list_h, hex_h = layout(h)

        pump()

        # Clamp selected to valid range.
        if packets:
            selected = max(0, min(selected, len(packets) - 1))

        if follow and packets:
            # Pin to the newest packet and directly compute list_top so the
            # last packet always appears at the bottom of the visible area.
            # (A reactive scroll adjustment only fires when selected falls
            # outside the visible range, so it can leave the newest packet
            # somewhere in the middle once the list exceeds the view height.)
            selected  = len(packets) - 1
            list_top  = max(0, selected - list_h + 1)
            hex_top   = 0
        else:
            # Scroll list_top reactively to keep selected visible.
            if selected < list_top:
                list_top = selected
            elif selected >= list_top + list_h:
                list_top = selected - list_h + 1

        # ── draw ──────────────────────────────────────────────────────────
        stdscr.erase()
        draw_col_header(w)

        for row in range(list_h):
            idx = list_top + row
            if idx >= len(packets):
                break
            draw_pkt_row(1 + row, packets[idx], idx == selected, w)

        div_y = list_h + 1
        draw_divider(div_y, w)

        sel_rec = packets[selected] if packets else None
        draw_hex_pane(div_y + 1, hex_h, w, sel_rec)

        draw_status(h - 1, w)
        stdscr.refresh()

        # ── keyboard ──────────────────────────────────────────────────────
        key = stdscr.getch()

        if key in (ord('q'), ord('Q'), 27):        # quit
            break

        elif key == curses.KEY_DOWN:
            follow   = False
            selected = min(selected + 1, len(packets) - 1) if packets else 0

        elif key == curses.KEY_UP:
            follow   = False
            selected = max(selected - 1, 0)

        elif key == curses.KEY_NPAGE:              # Page Down
            follow   = False
            selected = min(selected + list_h, len(packets) - 1) if packets else 0

        elif key == curses.KEY_PPAGE:              # Page Up
            follow   = False
            selected = max(selected - list_h, 0)

        elif key == curses.KEY_HOME:
            follow   = False
            selected = 0

        elif key == curses.KEY_END:                # jump to latest + re-follow
            follow   = True

        elif key in (ord('f'), ord('F')):          # toggle follow
            follow = not follow

        # j/k scroll the hex pane
        elif key in (ord('j'),) and sel_rec:
            max_top = max(0, len(hex_dump_lines(sel_rec.data)) - hex_h)
            hex_top = min(hex_top + 1, max_top)

        elif key in (ord('k'),):
            hex_top = max(hex_top - 1, 0)

    cap.break_loop()
    cap.close()


# ── entry point ───────────────────────────────────────────────────────────

def main():
    iface = sys.argv[1] if len(sys.argv) > 1 else pycapng.capture_default_device()
    fexpr = sys.argv[2] if len(sys.argv) > 2 else None

    if iface is None:
        sys.exit("No suitable interface found. Pass the interface name as the first argument.")

    print(f"Opening {iface}…", flush=True)
    try:
        curses.wrapper(run_tui, iface, fexpr)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
