#!/usr/bin/env bash
#
# Build the libpcapng JavaScript / WebAssembly bindings with Emscripten.
#
# Output: dist/libpcapng.mjs  — an ES module exporting a default factory
#                               `createLibpcapng()` -> Promise<Module>.
# The .wasm is embedded (SINGLE_FILE) so the module is self-contained and
# works from any path, including a GitHub Pages sub-directory.
#
# Usage:
#   ./build.sh                       # needs emcc on PATH, or EMSDK set
#   EMSDK=~/emsdk ./build.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"        # libpcapng repository root
LIB="$ROOT/lib"
OUT="$HERE/dist"

# Bring emcc onto PATH if it isn't already (local dev convenience).
if ! command -v emcc >/dev/null 2>&1; then
  if [ -n "${EMSDK:-}" ] && [ -f "$EMSDK/emsdk_env.sh" ]; then
    # shellcheck disable=SC1091
    source "$EMSDK/emsdk_env.sh" >/dev/null 2>&1
  elif [ -f "$HOME/emsdk/emsdk_env.sh" ]; then
    # shellcheck disable=SC1091
    source "$HOME/emsdk/emsdk_env.sh" >/dev/null 2>&1
  fi
fi
command -v emcc >/dev/null 2>&1 || {
  echo "error: emcc not found. Install Emscripten (https://emscripten.org) or set EMSDK." >&2
  exit 1
}

mkdir -p "$OUT"

# Dissection / read-only sources only. capture.c is deliberately excluded:
# it performs OS-level live capture (BPF / packet sockets) unavailable in a
# browser and not needed to analyse saved captures.
SOURCES=(
  "$LIB/blocks.c"
  "$LIB/io.c"
  "$LIB/objects.c"
  "$LIB/dissect.c"
  "$LIB/posa.c"
  "$LIB/wire_layout.c"
  "$LIB/easyapi.c"
  "$LIB/reassembly.c"
  "$LIB/reassembly_tcp.c"
)
for f in "$LIB"/protocols/*.c; do SOURCES+=("$f"); done

echo "emcc: $(emcc --version | head -1)"
echo "building ${#SOURCES[@]} C sources + embind binding -> $OUT/libpcapng.mjs"

emcc \
  -O3 \
  -I"$LIB/include" \
  "${SOURCES[@]}" \
  "$HERE/pcapng_wasm.cpp" \
  -lembind \
  -s MODULARIZE=1 \
  -s EXPORT_ES6=1 \
  -s EXPORT_NAME=createLibpcapng \
  -s ENVIRONMENT=web,worker,node \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s STACK_SIZE=8388608 \
  -s SINGLE_FILE=1 \
  -o "$OUT/libpcapng.mjs"

echo "done: $OUT/libpcapng.mjs ($(wc -c < "$OUT/libpcapng.mjs") bytes)"
