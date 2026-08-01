#!/usr/bin/env bash
# sync-sources.sh — copy libpcapng C sources from the repo root into the
# Go binding's vendor/ directory.
#
# Run this script whenever the C library sources change and before publishing
# a new version of the Go module.
#
# Usage:  ./scripts/sync-sources.sh  (from bindings/go/)
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
GO_DIR="$SCRIPT_DIR/.."
REPO_ROOT="$GO_DIR/../.."
LIB="$REPO_ROOT/lib"
VEND="$GO_DIR/vendor"

# Verify we can find the library sources.
if [[ ! -f "$LIB/blocks.c" ]]; then
    echo "error: cannot find $LIB/blocks.c" >&2
    echo "       Run this script from within the libpcapng repository." >&2
    exit 1
fi

mkdir -p "$VEND/src/protocols"
mkdir -p "$VEND/include/libpcapng/protocols"

TOP_SRCS=(
    blocks.c easyapi.c io.c dissect.c dfilter.c objects.c posa.c
    reassembly.c reassembly_tcp.c capture.c wire_layout.c community_id.c
)
PROTO_SRCS=(
    ethernet.c ipv4.c tcp.c udp.c dns.c icmp.c flow.c dhcp.c ntp.c
    ssl.c ssh.c http2.c http2_hpack.c http2_stream.c tls_stream.c
    tcp_mss.c asn1.c rdp.c
)

for f in "${TOP_SRCS[@]}"; do
    cp -v "$LIB/$f" "$VEND/src/$f"
done

for f in "${PROTO_SRCS[@]}"; do
    cp -v "$LIB/protocols/$f" "$VEND/src/protocols/$f"
done

# Headers (public) + internal generated header
cp -v "$LIB/include/libpcapng/"*.h "$VEND/include/libpcapng/"
cp -v "$LIB/include/libpcapng/protocols/"*.h "$VEND/include/libpcapng/protocols/" 2>/dev/null || true
cp -v "$LIB/builtin_protos.h" "$VEND/include/"

# Remove editor backups
find "$VEND" -name "*~" -delete

echo ""
echo "vendor/ synced from $LIB"
echo "$(find "$VEND" -name '*.c' | wc -l | tr -d ' ') C files, $(find "$VEND" -name '*.h' | wc -l | tr -d ' ') headers"
