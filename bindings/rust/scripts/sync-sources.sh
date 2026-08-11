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

# dissect.c does #include "builtin_protos.h" — the .posa decoders embedded as C
# string literals. In the normal build it sits beside dissect.c in lib/; in the
# vendored tree there is no such sibling, so it has to be on the include path
# cc-rs is given. Without it `cargo publish` fails when it builds the packaged
# tarball to verify it. (bindings/go/scripts/sync-sources.sh copies it too.)
cp "$ROOT/lib/builtin_protos.h"       "$VENDOR_INC/"

echo "Vendored into $SYS/vendor/"
