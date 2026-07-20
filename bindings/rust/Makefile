# Convenience targets for the libpcapng Rust bindings (pcapng-sys + libpcapng).
# Run from this directory: `make <target>` (e.g. `make crate-publish`).
#
# ── FIRST-TIME SETUP (once per machine) ────────────────────────────────────
#   Publishing to crates.io needs an account + an auth token:
#     1. Sign in at https://crates.io  ("Log in with GitHub").
#     2. Verify your email  (Account Settings → Profile) — publishing is
#        BLOCKED until an email is confirmed.
#     3. Create a token     (Account Settings → API Tokens → New Token).
#     4. Store it locally:  `cargo login`   (paste the token when prompted).
#   After that, `make crate-publish` just works.
#
# Publishes are PERMANENT: a version can be yanked but never re-uploaded or
# deleted. Use `make crate-publish-dry` first, and bump the version (in
# Cargo.toml [workspace.package]) if you need to re-release.

SHELL := /bin/bash
SYNC  := scripts/sync-sources.sh

.DEFAULT_GOAL := help

.PHONY: help build test fmt lint vendor crate-package crate-publish-dry \
        crate-publish crate-check-names clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-22s\033[0m %s\n",$$1,$$2}'

build: ## Build both crates (against the in-repo C sources)
	cargo build

test: ## Run the test suite
	cargo test

fmt: ## Format source files
	cargo fmt

lint: ## Clippy (warnings only)
	cargo clippy --workspace --examples

vendor: ## Copy C sources into pcapng-sys/vendor (needed for publishing)
	bash $(SYNC)

# These targets vendor the C sources, run cargo, then ALWAYS remove vendor/ via
# a shell trap (so a failure can't leave a stale copy behind that would shadow
# the live lib/ tree). Kept as single shell recipes because macOS make (3.81)
# has no .ONESHELL. --allow-dirty: vendor/ is generated at publish time and is
# gitignored, so it always reads as uncommitted; the tarball is pinned by the
# `include` list in Cargo.toml regardless of tree state.

crate-package: ## Build the -sys tarball in isolation (no upload)
	@trap 'rm -rf pcapng-sys/vendor' EXIT; \
	 bash $(SYNC) >/dev/null && \
	 cargo package -p pcapng-sys --allow-dirty

crate-publish-dry: ## Dry-run publish of pcapng-sys (libpcapng can't dry-run until sys is on crates.io)
	@trap 'rm -rf pcapng-sys/vendor' EXIT; \
	 bash $(SYNC) >/dev/null && \
	 cargo publish -p pcapng-sys --dry-run --allow-dirty; \
	 echo ">> note: 'libpcapng' has no dry-run here — it resolves pcapng-sys"; \
	 echo ">>       from the crates.io index, which only exists after a real publish."

crate-publish: ## Publish BOTH crates to crates.io (needs `cargo login` first — see top of file)
	@command -v cargo >/dev/null || { echo "cargo not found"; exit 1; }
	@trap 'rm -rf pcapng-sys/vendor' EXIT; \
	 echo ">> vendoring C sources into pcapng-sys/vendor ..."; \
	 bash $(SYNC) >/dev/null && \
	 echo ">> publishing pcapng-sys (the -sys crate must go first) ..." && \
	 cargo publish -p pcapng-sys --allow-dirty && \
	 echo ">> waiting 30s for crates.io to index pcapng-sys ..." && \
	 sleep 30 && \
	 echo ">> publishing libpcapng ..." && \
	 cargo publish -p libpcapng --allow-dirty && \
	 echo ">> done. Published pcapng-sys and libpcapng."

crate-check-names: ## Check whether the crate names are already taken on crates.io
	@for c in pcapng-sys libpcapng; do \
	  code=$$(curl -s -o /dev/null -w '%{http_code}' \
	    -A 'libpcapng-make/1.0 (name availability check)' \
	    "https://crates.io/api/v1/crates/$$c"); \
	  if [ "$$code" = "200" ]; then echo "  $$c: TAKEN"; \
	  elif [ "$$code" = "404" ]; then echo "  $$c: available"; \
	  else echo "  $$c: unknown (HTTP $$code)"; fi; \
	done

clean: ## Remove build artifacts and vendored sources
	cargo clean
	@$(MAKE) --no-print-directory _unvendor

.PHONY: _unvendor
_unvendor:
	@rm -rf pcapng-sys/vendor
