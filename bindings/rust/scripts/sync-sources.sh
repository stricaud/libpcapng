#!/usr/bin/env bash
# Vendor C sources into libpcapng-sys/vendor before `cargo publish`.
# Must match the LIBPCAPNG_SOURCES list in lib/CMakeLists.txt.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
SYS="$SCRIPT_DIR/../pcapng-sys"

VENDOR_SRC="$SYS/vendor/src"
VENDOR_INC="$SYS/vendor/include"

mkdir -p "$VENDOR_SRC/protocols"
mkdir -p "$VENDOR_INC"

# C sources
cp "$ROOT/lib/"*.c                    "$VENDOR_SRC/"
cp "$ROOT/lib/protocols/"*.c          "$VENDOR_SRC/protocols/"

# Headers (full tree)
cp -R "$ROOT/lib/include/libpcapng"   "$VENDOR_INC/"

echo "Vendored into $SYS/vendor/"
