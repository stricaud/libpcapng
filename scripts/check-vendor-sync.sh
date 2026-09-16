#!/usr/bin/env bash
#
# check-vendor-sync.sh — the vendored C sources must match lib/.
#
# The Go and Rust bindings each carry a copy of the library's C sources. That
# is not a design choice anyone made for fun: cgo and cc-rs compile C that is
# inside the published module, so `go get` and `cargo add` have to work for
# someone who has never heard of libpcapng and has nothing installed. Neither
# ecosystem has a good way to depend on a system C library.
#
# The cost of that is two copies that can drift, silently, because nothing
# builds them during ordinary development. They drifted: at the point this
# script was written both trees were missing the per-thread storage that makes
# dissection safe across threads, both were missing flow_hash.c and
# tls_keylog.c entirely, and capture.c was 715 lines behind. Everything still
# compiled and every test passed, because no test looked.
#
# So this looks. Run it, or let ctest run it:
#
#     ctest -R Vendor-Sync
#
# When it fails, the fix is never to edit a vendored file — it is regenerated
# and any edit there is lost on the next sync. Fix lib/, then:
#
#     bash bindings/go/scripts/sync-sources.sh
#     bash bindings/rust/scripts/sync-sources.sh
#
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$ROOT/lib"
fail=0

# Sources the bindings deliberately do not carry. surgery.c is the file-surgery
# API (filter/merge/split/anonymize); neither binding exposes it, so neither
# compiles it. Anything else absent from a vendor tree is an oversight.
SKIP_GO="surgery.c"
SKIP_RUST=""

check_tree() {
    local name="$1" vsrc="$2" skip="$3"
    local stale=0 missing=0 orphan=0 f b

    if [[ ! -d "$vsrc" ]]; then
        echo "  $name: no vendor tree at $vsrc — skipped"
        return 0
    fi

    # Every vendored file must be byte-identical to the one it came from.
    for f in "$vsrc"/*.c "$vsrc"/protocols/*.c; do
        [[ -e "$f" ]] || continue
        b="${f#"$vsrc"/}"
        if [[ ! -f "$LIB/$b" ]]; then
            echo "  STALE   $name/$b — no such file in lib/ any more"
            orphan=$((orphan + 1)); continue
        fi
        if ! cmp -s "$LIB/$b" "$f"; then
            echo "  STALE   $name/$b — differs from lib/$b"
            stale=$((stale + 1))
        fi
    done

    # And every library source must be vendored, unless deliberately skipped.
    for f in "$LIB"/*.c "$LIB"/protocols/*.c; do
        b="${f#"$LIB"/}"
        [[ " $skip " == *" $b "* ]] && continue
        if [[ ! -f "$vsrc/$b" ]]; then
            echo "  MISSING $name/$b — in lib/ but never vendored"
            missing=$((missing + 1))
        fi
    done

    if (( stale || missing || orphan )); then
        echo "  $name: $stale stale, $missing missing, $orphan orphaned"
        fail=1
    else
        echo "  $name: in sync"
    fi
}

echo "=== vendored source sync ==="
check_tree "go"   "$ROOT/bindings/go/vendor/src"              "$SKIP_GO"
check_tree "rust" "$ROOT/bindings/rust/pcapng-sys/vendor/src" "$SKIP_RUST"

# cgo only compiles .c files sitting in the package directory, so each vendored
# source needs a one-line bridge there that #includes it. Vendoring a file
# without adding its bridge leaves it present, uncompiled, and missing at link
# time — which is how flow_hash.c and tls_keylog.c came to be shipped but not
# built.
echo "=== cgo bridges ==="
GO_PKG="$ROOT/bindings/go"
if [[ -d "$GO_PKG/vendor/src" ]]; then
    nobridge=0
    for f in "$GO_PKG"/vendor/src/*.c; do
        [[ -e "$f" ]] || continue
        b="$(basename "$f" .c)"
        if [[ ! -f "$GO_PKG/cgo_$b.c" ]]; then
            echo "  MISSING bindings/go/cgo_$b.c — vendored but never compiled"
            nobridge=$((nobridge + 1))
        fi
    done
    for f in "$GO_PKG"/vendor/src/protocols/*.c; do
        [[ -e "$f" ]] || continue
        b="$(basename "$f" .c)"
        if [[ ! -f "$GO_PKG/cgo_proto_$b.c" ]]; then
            echo "  MISSING bindings/go/cgo_proto_$b.c — vendored but never compiled"
            nobridge=$((nobridge + 1))
        fi
    done
    if (( nobridge )); then
        echo "  go: $nobridge source(s) with no cgo bridge"
        fail=1
    else
        echo "  go: every vendored source has a bridge"
    fi
fi

# builtin_protos.h is generated from bin/protos, not copied from lib/, so it
# drifts on its own schedule — a submodule update that is not followed by a
# regeneration leaves a binding decoding last month's protocols.
echo "=== embedded protocol definitions ==="
gen="$(mktemp)"
trap 'rm -f "$gen"' EXIT
if python3 "$ROOT/bindings/python/embed_protos.py" "$ROOT/bin/protos" "$gen" >/dev/null 2>&1; then
    for h in "$LIB/builtin_protos.h" \
             "$ROOT/bindings/go/vendor/include/builtin_protos.h" \
             "$ROOT/bindings/rust/pcapng-sys/vendor/include/builtin_protos.h"; do
        [[ -f "$h" ]] || continue
        if cmp -s "$gen" "$h"; then
            echo "  in sync: ${h#"$ROOT"/}"
        else
            echo "  STALE:   ${h#"$ROOT"/} — regenerate with bindings/python/embed_protos.py"
            fail=1
        fi
    done
else
    echo "  (python3 unavailable — skipped)"
fi

if (( fail )); then
    echo
    echo "Fix lib/ — never a vendored copy, it is overwritten — then run:"
    echo "    bash bindings/go/scripts/sync-sources.sh"
    echo "    bash bindings/rust/scripts/sync-sources.sh"
    echo "    python3 bindings/python/embed_protos.py bin/protos lib/builtin_protos.h"
    echo "and for a newly vendored source, add its one-line bridge:"
    echo "    printf '#include \"vendor/src/NAME.c\"\\n' > bindings/go/cgo_NAME.c"
    exit 1
fi
echo
echo "vendored sources match lib/"
