#!/usr/bin/env bash
#
# Build bigbang and put it on PATH.
#
#   ./install.sh              build and install
#   ./install.sh --debug      debug build (faster to compile, slower to run)
#   BIGBANG_BIN_DIR=~/bin ./install.sh
#
# Installs a copy, not a symlink, so the binary keeps working after this checkout moves
# or the target/ directory is cleaned.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${BIGBANG_BIN_DIR:-$HOME/.local/bin}"
PROFILE=release

for arg in "$@"; do
  case "$arg" in
    --debug) PROFILE=debug ;;
    -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '   \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '   \033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

say "Build"
command -v cargo >/dev/null || die "cargo not found — install Rust from https://rustup.rs"
if [ "$PROFILE" = release ]; then
  ( cd "$REPO/bigbang-rs" && cargo build --release ) || die "cargo build failed"
else
  ( cd "$REPO/bigbang-rs" && cargo build ) || die "cargo build failed"
fi
SRC="$REPO/bigbang-rs/target/$PROFILE/bigbang"
[ -x "$SRC" ] || die "expected a binary at $SRC"
ok "$SRC ($(du -h "$SRC" | cut -f1))"

say "Test"
# The suite is fast enough that skipping it saves nothing worth having, and it covers the
# parts that decide a deployment's behaviour — skipIf, retries, vault crypto, role matching.
( cd "$REPO/bigbang-rs" && cargo test --quiet ) || die "tests failed — not installing"
ok "tests pass"

say "Install"
mkdir -p "$BIN_DIR"
install -m 0755 "$SRC" "$BIN_DIR/bigbang"
ok "$BIN_DIR/bigbang"

say "PATH"
case ":$PATH:" in
  *":$BIN_DIR:"*) ok "$BIN_DIR is on PATH" ;;
  *)
    warn "$BIN_DIR is NOT on PATH. Add this to your shell profile:"
    printf '\n       export PATH="%s:$PATH"\n\n' "$BIN_DIR"
    ;;
esac

say "Verify"
# Running the installed binary is the only check that proves the whole chain: built,
# copied, executable, and able to start. An install reported without it is a guess.
out="$("$BIN_DIR/bigbang" --version 2>&1 | head -1)" || die "installed binary does not run"
ok "$out"

# And then: is the copy we just installed the one the shell will actually run? An earlier
# PATH entry holding an older bigbang is the worst kind of install success — everything
# reports fine while every command runs last week's binary. This caught a stale copy in
# ~/.cargo/bin the first time it ran.
hash -r 2>/dev/null || true
RESOLVED="$(command -v bigbang || true)"
if [ -z "$RESOLVED" ]; then
  warn "bigbang is not on PATH yet — see the note above"
elif [ "$RESOLVED" -ef "$BIN_DIR/bigbang" ]; then
  ok "bigbang resolves to the copy just installed"
else
  printf '   \033[31m✗\033[0m %s\n' "another bigbang shadows this install" >&2
  printf '       your shell runs: %s\n' "$RESOLVED" >&2
  printf '       just installed:  %s\n' "$BIN_DIR/bigbang" >&2
  printf '\n       Remove the other one, or install over it:\n' >&2
  printf '         rm %s\n' "$RESOLVED" >&2
  printf '         BIGBANG_BIN_DIR=%s ./install.sh\n\n' "$(dirname "$RESOLVED")" >&2
  exit 1
fi

say "Ready"
echo "   bigbang shell                    interactive: load a profile once, then work"
echo "   bigbang recipe list --profile P"
echo "   bigbang recipe execute --id R --profile P --dry-run"
