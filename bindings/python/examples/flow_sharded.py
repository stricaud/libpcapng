#!/usr/bin/env python3
"""
flow_sharded.py — the pipeline pattern from Python: shard by flow, keep order.

The C tool does this with threads (see bin/pipeline.c). Python cannot: the
posa/dissect bindings hold the GIL for the whole call, so eight Python threads
dissecting take turns rather than running at once. That is not a defect to work
around — it is what makes `pycapng.posa_dissect` safe to call from threads at
all — but it does mean real parallelism in Python needs processes.

Which suits the model perfectly. Flow-pinned sharding wants each worker to have
its own per-flow state, and separate processes have that by construction: no
shared decoder registry, no shared flow table, nothing to synchronise.

The two rules are the same as in C:

  1. Pin flows.  pycapng.flow_hash(frame) is direction-independent, so
     hash % nworkers sends both halves of a connection to one worker. Split a
     flow and each worker sees half a conversation — the TLS ClientHello goes
     to one and its encrypted records to another.

  2. Keep order. Order is not recovered at the end, it is never given up: each
     packet carries the index it had in the file, workers return
     (index, result) pairs, and the parent sorts once. A worker that finishes
     early cannot jump the queue.

Run:
    python3 flow_sharded.py capture.pcapng [workers]
"""

import multiprocessing as mp
import struct
import sys
from collections import Counter

import pycapng

EPB_HDR = 20        # interface_id, ts_high, ts_low, captured_len, original_len


# ── reading ──────────────────────────────────────────────────────────────────

def read_frames(path):
    """Every frame in the file, in file order, with its link type.

    The link type lives in the Interface Description Block, which always
    precedes the packets citing it, so it is picked up on the way past.
    """
    frames, linktypes = [], []

    def each_block(counter, btype, total_len, data):
        if btype == pycapng.INTERFACE_DESCRIPTION_BLOCK and len(data) >= 2:
            linktypes.append(struct.unpack("<H", data[:2])[0])
        elif btype == pycapng.ENHANCED_PACKET_BLOCK and len(data) >= EPB_HDR:
            iface, _hi, _lo, caplen, _orig = struct.unpack("<IIIII", data[:EPB_HDR])
            lt = linktypes[iface] if iface < len(linktypes) else 1
            frames.append((data[EPB_HDR:EPB_HDR + caplen], lt))

    f = pycapng.PcapNG()
    f.OpenFile(path, "r")
    f.ForeachPacket(each_block)
    f.CloseFile()
    return frames


# ── the work, one worker's share ─────────────────────────────────────────────

def process_shard(args):
    """Runs in a separate process. Gets whole flows, never half of one.

    Returns (index, protocol) pairs so the parent can restore file order
    without trusting the order results happen to come back in.
    """
    shard, = args,
    # Each process has its own registry. Loading it here rather than letting
    # the first dissection do it lazily keeps the cost out of the timed work
    # and matches what the C side does before starting threads.
    pycapng.posa_load_builtin()

    out = []
    for index, frame, linktype in shard:
        info = parse_frame(frame, linktype)
        proto = "other"
        if info and info["payload"]:
            name = which_decoder(info)
            if name:
                result = pycapng.posa_dissect(name, info["payload"])
                if result:
                    proto = result["col"] or name
        out.append((index, proto))
    return out


def which_decoder(info):
    """Which decoder claims this payload, in the order the C dissector asks.

    Order matters and is not obvious. A payload signature beats a port, because
    the bytes know better than the port number does — plaintext HTTP on 443 is
    HTTP, not a mangled TLS record. Ports come next. Weak signatures, which are
    a couple of suggestive octets, are asked only once both have come up empty,
    so a guess never outranks a binding that actually knew.

    Asking the port first, as an obvious first attempt would, gets ordinary
    HTTP on port 80 wrong: several decoders bind that port, and only one of
    them is the one whose bytes are on the wire.
    """
    proto, payload = info["proto"], info["payload"]

    name = pycapng.posa_bound_content(proto, payload)
    if name:
        return name
    name = pycapng.posa_bound_port(proto, info["dport"]) \
        or pycapng.posa_bound_port(proto, info["sport"])
    if name:
        return name
    return pycapng.posa_bound_content(proto, payload, weak=True)


def parse_frame(frame, linktype):
    """Peel Ethernet/IPv4/TCP|UDP. Enough to find the payload and its ports."""
    if linktype != 1 or len(frame) < 34:
        return None
    if frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    total = struct.unpack("!H", ip[2:4])[0]
    if 20 <= total <= len(ip):
        ip = ip[:total]
    l4 = ip[ihl:]
    if proto == 6 and len(l4) >= 20:
        sport, dport = struct.unpack("!HH", l4[0:4])
        payload = l4[(l4[12] >> 4) * 4:]
    elif proto == 17 and len(l4) >= 8:
        sport, dport = struct.unpack("!HH", l4[0:4])
        ulen = struct.unpack("!H", l4[4:6])[0]
        payload = l4[8:ulen] if 8 <= ulen <= len(l4) else l4[8:]
    else:
        return None
    return {"proto": proto, "sport": sport, "dport": dport, "payload": payload}


# ── sharding ─────────────────────────────────────────────────────────────────

def shard_by_flow(frames, nworkers):
    """Split the capture so each worker gets whole flows.

    flow_hash is the same function the C pipeline uses, and it hashes both
    directions of a connection to the same value — so a request and its reply
    always land in the same shard. A frame with no flow (ARP, a runt) has no
    per-flow state to keep coherent, so it goes wherever its index sends it.
    """
    shards = [[] for _ in range(nworkers)]
    unflowed = 0
    for index, (frame, linktype) in enumerate(frames):
        h = pycapng.flow_hash(frame, linktype, pycapng.FLOW_TUPLE)
        if h == 0:
            unflowed += 1
            h = index
        shards[h % nworkers].append((index, frame, linktype))
    return shards, unflowed


def main():
    if len(sys.argv) < 2:
        sys.exit(f"usage: {sys.argv[0]} CAPTURE.pcapng [workers]")
    path = sys.argv[1]
    nworkers = int(sys.argv[2]) if len(sys.argv) > 2 else mp.cpu_count()

    pycapng.posa_load_builtin()
    frames = read_frames(path)
    print(f"{len(frames)} packet(s) from {path}, {nworkers} worker(s)")

    shards, unflowed = shard_by_flow(frames, nworkers)
    print("  shard sizes:", [len(s) for s in shards],
          f"({unflowed} frame(s) carried no flow)")

    # Each flow lands in exactly one shard, so no worker ever sees a
    # conversation another worker is also looking at.
    if nworkers > 1:
        with mp.Pool(nworkers) as pool:
            chunks = pool.map(process_shard, shards)
    else:
        chunks = [process_shard(s) for s in shards]

    # Order restored from the indices the packets carried all along.
    results = sorted((pair for chunk in chunks for pair in chunk))

    print("\n  first few, in file order:")
    for index, proto in results[:10]:
        print(f"    {index + 1:6d}  {proto}")

    print("\n  totals:")
    for proto, n in Counter(p for _, p in results).most_common():
        print(f"    {proto:-<14} {n}")


if __name__ == "__main__":
    main()
