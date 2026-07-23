# libpcapng — JavaScript / WebAssembly bindings

Read-only capture analysis in the browser (or Node), powered by the same C
dissection engine as the rest of libpcapng, compiled to WebAssembly with
Emscripten.

Parse `.pcap` / `.pcapng` buffers **entirely in memory** — nothing is uploaded
anywhere — list packets with Wireshark-style summary columns, dissect any
packet into a field tree with byte offsets, and load your own declarative
(posa) dissectors at runtime.

> **No live capture.** `lib/capture.c` (OS-level BPF / packet sockets) is
> deliberately excluded from this build — it cannot run in a browser and is not
> needed to analyse saved captures.

## Building

Requires [Emscripten](https://emscripten.org/docs/getting_started/downloads.html).

```sh
cd bindings/js
./build.sh            # emcc on PATH, or: EMSDK=~/emsdk ./build.sh
```

Output: **`dist/libpcapng.mjs`** — a self-contained ES module (the `.wasm` is
embedded via `SINGLE_FILE`, so it works from any path, including a GitHub Pages
sub-directory). Prebuilt modules are also published as artifacts by the
`js-bindings` GitHub Actions workflow and attached to `js-v*` releases.

## Usage

```js
import createLibpcapng from "./libpcapng.mjs";

const M = await createLibpcapng();

// bytes: a Uint8Array of a .pcap or .pcapng file (e.g. from <input type=file>)
const count = M.loadCapture(bytes);

for (const p of M.getSummaries()) {
  // { no, time, src, dst, proto, length, info }
  console.log(`#${p.no} ${p.src} → ${p.dst} ${p.proto}  ${p.info}`);
}

// Full dissection of one packet: an array of protocol layers.
const layers = M.getDetail(0);
// each node: { abbrev, label, value, off, len, children: [...] }
// `off`/`len` are absolute byte offsets — use them to highlight the hex view.

const rawBytes = M.getPacketBytes(0);  // Uint8Array
```

### Loading a file in the browser

```js
const buf = new Uint8Array(await file.arrayBuffer());  // file: a File object
M.loadCapture(buf);
```

## API

| Function | Returns | Description |
| --- | --- | --- |
| `loadCapture(u8)` | `number` | Parse a `Uint8Array` (`.pcap`/`.pcapng`). Returns packet count. Replaces any previously loaded capture. |
| `getPacketCount()` | `number` | Number of packets in the loaded capture. |
| `getSummaries()` | `Array` | Packet list: `{no, time, src, dst, proto, length, info}`. `time` is seconds relative to the first packet. |
| `getDetail(i)` | `Array \| null` | Protocol layers of packet `i`, each a field node (see below). |
| `getPacketBytes(i)` | `Uint8Array \| null` | Raw captured bytes of packet `i`. |
| `loadPosaText(src)` | `{ok, added, error}` | Load one or more declarative dissectors from `.posa` text. Redefining a protocol by name replaces it. |
| `listPosa()` | `Array` | Loaded posa dissectors: `{name, display, abbrev}`. |
| `listProtocols()` | `Array<string>` | Field abbrevs the built-in C dissector can emit. |

### Field node

```ts
interface Field {
  abbrev: string;   // Wireshark-style, e.g. "ip.src", "tcp.dstport" ("" = structural)
  label: string;    // human-readable, e.g. "Source Address: 10.0.0.1"
  value: string;    // formatted value ("" for structural nodes)
  off: number;      // absolute byte offset within the packet
  len: number;      // byte length
  children: Field[];
}
```

## Declarative dissectors (posa)

The engine ships with built-in decoders (RDP negotiation, TPKT, COTP). You can
add more at runtime from `.posa` text — handy for a UI that lets users define
and persist their own dissectors:

```js
const res = M.loadPosaText(myPosaSource);
if (!res.ok) console.error(res.error);
console.log(M.listPosa());   // now includes the new protocol(s)
```

## Testing

```sh
node test/smoke.mjs
```
