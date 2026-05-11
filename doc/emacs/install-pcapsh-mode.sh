#!/usr/bin/env bash
# install-pcapsh-mode.sh — install pcapsh-mode.el for the current user
#
# What this script does:
#   1. Copies pcapsh-mode.el to ~/.emacs.d/pcapsh-mode.el
#   2. Appends a `require` form to ~/.emacs.d/init.el (or ~/.emacs)
#      if not already present, so the mode loads automatically for
#      every file ending in .pcapsh.
#
# Run with:
#   bash install-pcapsh-mode.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/pcapsh-mode.el"

# ── 1. Locate/create the Emacs lisp directory ────────────────────────────────

EMACS_D="${HOME}/.emacs.d"
mkdir -p "$EMACS_D"

DEST="$EMACS_D/pcapsh-mode.el"
cp "$SRC" "$DEST"
echo "Installed: $DEST"

# ── 2. Locate the user init file ─────────────────────────────────────────────

if   [ -f "$HOME/.emacs.d/init.el" ]; then
    INIT="$HOME/.emacs.d/init.el"
elif [ -f "$HOME/.emacs" ]; then
    INIT="$HOME/.emacs"
else
    # Create a minimal init.el
    INIT="$HOME/.emacs.d/init.el"
    touch "$INIT"
fi
echo "Init file: $INIT"

# ── 3. Inject the load snippet (idempotent) ───────────────────────────────────

MARKER=";; pcapsh-mode"

if grep -qF "$MARKER" "$INIT" 2>/dev/null; then
    echo "pcapsh-mode is already configured in $INIT — nothing to do."
else
    cat >> "$INIT" <<'ELISP'

;; pcapsh-mode — syntax highlighting and indentation for .pcapsh files
(add-to-list 'load-path (expand-file-name "~/.emacs.d"))
(autoload 'pcapsh-mode "pcapsh-mode" "Major mode for pcapsh scripts." t)
(add-to-list 'auto-mode-alist '("\\.pcapsh\\'" . pcapsh-mode))
ELISP
    echo "Appended pcapsh-mode configuration to $INIT"
fi

# ── 4. Byte-compile (optional, silently skip if emacs is absent) ──────────────

if command -v emacs >/dev/null 2>&1; then
    echo "Byte-compiling pcapsh-mode.el …"
    emacs --batch --eval "(byte-compile-file \"$DEST\")" 2>/dev/null && \
        echo "Byte-compiled: ${DEST}c" || \
        echo "Byte-compilation failed (mode still works from source)."
else
    echo "emacs not found in PATH — skipping byte-compilation."
fi

echo ""
echo "Done. Open any .pcapsh file in Emacs and pcapsh-mode will activate."
echo "To change the indentation step, add to your init file:"
echo "  (setq pcapsh-indent-offset 2)"
