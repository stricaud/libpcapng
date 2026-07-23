// Dependency-free smoke test: build a minimal classic-pcap buffer in memory
// (Ethernet / IPv4 / UDP), parse it through the WASM bindings, and assert the
// basic API works. Exits non-zero on failure so CI catches regressions.
import createLibpcapng from "../dist/libpcapng.mjs";

function assert(cond, msg) {
  if (!cond) {
    console.error("FAIL:", msg);
    process.exit(1);
  }
}

// ── hand-craft a one-packet classic pcap (little-endian) ────────────────────
function u8(...bytes) {
  return Uint8Array.from(bytes);
}
const eth = u8(
  0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // dst mac
  0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // src mac
  0x08, 0x00,                         // ethertype IPv4
);
const ip = u8(
  0x45, 0x00, 0x00, 0x22,             // ver/ihl, tos, total length (34)
  0x00, 0x01, 0x00, 0x00,             // id, flags/frag
  0x40, 0x11, 0x00, 0x00,             // ttl, proto=UDP(17), checksum
  0x0a, 0x00, 0x00, 0x01,             // src 10.0.0.1
  0x0a, 0x00, 0x00, 0x02,             // dst 10.0.0.2
);
const udp = u8(
  0x30, 0x39, 0x00, 0x35,             // src port 12345, dst port 53
  0x00, 0x0a, 0x00, 0x00,             // length 10, checksum
  0x68, 0x69,                         // payload "hi"
);
const pkt = new Uint8Array([...eth, ...ip, ...udp]);

const hdr = new Uint8Array(24 + 16 + pkt.length);
const dv = new DataView(hdr.buffer);
dv.setUint32(0, 0xa1b2c3d4, true);   // magic (microsecond)
dv.setUint16(4, 2, true);            // version major
dv.setUint16(6, 4, true);            // version minor
dv.setUint32(20, 1, true);           // network = LINKTYPE_ETHERNET
dv.setUint32(24, 1700000000, true);  // ts_sec
dv.setUint32(28, 0, true);           // ts_usec
dv.setUint32(32, pkt.length, true);  // incl_len
dv.setUint32(36, pkt.length, true);  // orig_len
hdr.set(pkt, 40);

// ── run the bindings ────────────────────────────────────────────────────────
const M = await createLibpcapng();

const n = M.loadCapture(hdr);
assert(n === 1, `expected 1 packet, got ${n}`);

const sums = M.getSummaries();
assert(sums.length === 1, "summaries length");
assert(sums[0].src === "10.0.0.1", `src = ${sums[0].src}`);
assert(sums[0].dst === "10.0.0.2", `dst = ${sums[0].dst}`);
assert(sums[0].proto.length > 0, `proto empty`); // UDP or DNS (port 53)

const layers = M.getDetail(0);
assert(Array.isArray(layers) && layers.length >= 3, "detail layers");

const bytes = M.getPacketBytes(0);
assert(bytes.length === pkt.length, "packet bytes length");

assert(M.listProtocols().length > 0, "listProtocols non-empty");

console.log(`OK: ${n} packet, ${layers.length} layers, ${bytes.length} bytes, ` +
            `${M.listProtocols().length} protocol abbrevs, ` +
            `posa: ${M.listPosa().map((p) => p.name).join(",")}`);
