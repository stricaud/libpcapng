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
#   ./build.sh                       # needs em++ on PATH, or EMSDK set
#   EMSDK=~/emsdk ./build.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"        # libpcapng repository root
LIB="$ROOT/lib"
OUT="$HERE/dist"

# Bring em++ onto PATH if it is not already (local dev convenience).
if ! command -v em++ >/dev/null 2>&1; then
  if [ -n "${EMSDK:-}" ] && [ -f "$EMSDK/emsdk_env.sh" ]; then
    # shellcheck disable=SC1091
    source "$EMSDK/emsdk_env.sh" >/dev/null 2>&1
  elif [ -f "$HOME/emsdk/emsdk_env.sh" ]; then
    # shellcheck disable=SC1091
    source "$HOME/emsdk/emsdk_env.sh" >/dev/null 2>&1
  fi
fi
command -v em++ >/dev/null 2>&1 || {
  echo "error: em++ not found. Install Emscripten (https://emscripten.org) or set EMSDK." >&2
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
  "$LIB/dfilter.c"
  "$LIB/posa.c"
  "$LIB/community_id.c"
  "$LIB/flow_hash.c"
  "$LIB/wire_layout.c"
  "$LIB/easyapi.c"
  "$LIB/reassembly.c"
  "$LIB/reassembly_tcp.c"
  # dissect.c calls into the keylog store for TLS session keys embedded in a
  # capture (DSB blocks). Decryption itself needs HAVE_OPENSSL, which this
  # build does not set, but the symbols must still resolve.
  "$LIB/tls_keylog.c"
)
for f in "$LIB"/protocols/*.c; do SOURCES+=("$f"); done

echo "em++: $(em++ --version | head -1)"
echo "building ${#SOURCES[@]} C sources + embind binding -> $OUT/libpcapng.mjs"

# Compile per language, then link with em++.
#
# One command cannot do this: handing the whole mixed set to emcc compiles the
# C++ as C and the link comes up short of operator new/delete and std::string;
# handing it to em++ compiles the C as C++, where `void *` no longer converts
# implicitly and objects.c fails on every realloc(). So each source is compiled
# by the driver for its own language, and only the link is C++.
OBJDIR="$(mktemp -d)"
trap 'rm -rf "$OBJDIR"' EXIT
OBJECTS=()

for f in "${SOURCES[@]}"; do
  # Flatten the path into the object name so lib/x.c and lib/protocols/x.c
  # could never collide.
  rel="${f#$ROOT/}"
  obj="$OBJDIR/${rel//\//_}.o"
  emcc -O3 -I"$LIB/include" -c "$f" -o "$obj"
  OBJECTS+=("$obj")
done

em++ -O3 -I"$LIB/include" -c "$HERE/pcapng_wasm.cpp" -o "$OBJDIR/pcapng_wasm.o"
OBJECTS+=("$OBJDIR/pcapng_wasm.o")

em++ \
  -O3 \
  "${OBJECTS[@]}" \
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
