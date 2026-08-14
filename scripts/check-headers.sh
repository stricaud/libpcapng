#!/usr/bin/env bash
#
# Every public header must compile on its own.
#
# A header that uses FILE or size_t without including <stdio.h> or <stddef.h>
# still builds wherever its includer pulled those in first — and Apple's libc
# leaks them almost everywhere, glibc does not. The breakage then shows up only
# on Linux, in whichever consumer includes the header first.
#
# Caveat: this only catches what the *host* compiler catches. A header that
# gets size_t from a sibling libpcapng header passes here and would pass on
# glibc too, so a clean run is necessary, not sufficient.
#
#     ./scripts/check-headers.sh          # CC=gcc to check another libc
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
INC="$ROOT/lib/include"
CC="${CC:-cc}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail=0
count=0

while IFS= read -r hdr; do
    rel="${hdr#"$INC"/}"
    count=$((count + 1))
    printf '#include <%s>\nint main(void) { return 0; }\n' "$rel" > "$tmp/t.c"
    if ! err="$("$CC" -fsyntax-only -I"$INC" "$tmp/t.c" 2>&1)"; then
        fail=$((fail + 1))
        echo "FAIL  $rel"
        echo "$err" | sed 's/^/        /' | head -6
    fi
done < <(find "$INC" -name '*.h' | sort)

echo ""
if [ "$fail" -eq 0 ]; then
    echo "=== $count public headers, all self-contained ==="
else
    echo "=== $count public headers, $fail NOT self-contained ==="
    echo "Add the include the header itself needs — do not rely on the includer."
fi
exit $((fail > 0))
