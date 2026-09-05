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
DEFAULT_BIN_DIR="$HOME/.local/bin"
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
# Install where the shell already finds bigbang, so the command you type is the binary just
# built. Only when there is no bigbang yet does the default directory get used.
EXISTING="$(command -v bigbang 2>/dev/null || true)"
if [ -n "${BIGBANG_BIN_DIR:-}" ]; then
  TARGET_DIR="$BIGBANG_BIN_DIR"
elif [ -n "$EXISTING" ]; then
  TARGET_DIR="$(cd "$(dirname "$EXISTING")" && pwd)"
else
  TARGET_DIR="$DEFAULT_BIN_DIR"
fi
mkdir -p "$TARGET_DIR"
install -m 0755 "$SRC" "$TARGET_DIR/bigbang"
ok "$TARGET_DIR/bigbang"

# There is one bigbang: the one just built. Any other copy sitting on PATH is a leftover that
# would shadow this one depending on directory order, so overwrite them all with the same
# binary rather than leaving the user to discover which one their shell picked.
replaced=0
seen=""
IFS=':' read -r -a path_dirs <<< "$PATH"
for dir in "${path_dirs[@]}"; do
  [ -n "$dir" ] || continue
  # PATH commonly repeats a directory; visiting one twice would report the same file twice.
  resolved_dir="$(cd "$dir" 2>/dev/null && pwd)" || continue
  case ":$seen:" in *":$resolved_dir:"*) continue ;; esac
  seen="$seen:$resolved_dir"

  candidate="$resolved_dir/bigbang"
  [ -f "$candidate" ] || continue
  [ "$candidate" -ef "$TARGET_DIR/bigbang" ] && continue
  # Only touch it if it actually differs, so a re-run is quiet and honest.
  cmp -s "$SRC" "$candidate" && continue
  install -m 0755 "$SRC" "$candidate" 2>/dev/null && { ok "replaced older copy at $candidate"; replaced=$((replaced+1)); } \
    || warn "could not replace $candidate (permissions?) — remove it manually"
done
[ "$replaced" = 0 ] || ok "$replaced other cop$([ "$replaced" = 1 ] && echo y || echo ies) brought up to date"

say "PATH"
case ":$PATH:" in
  *":$TARGET_DIR:"*) ok "$TARGET_DIR is on PATH" ;;
  *)
    warn "$TARGET_DIR is NOT on PATH. Add this to your shell profile:"
    printf '\n       export PATH="%s:$PATH"\n\n' "$TARGET_DIR"
    ;;
esac

say "Verify"
# Run what the shell will actually run, not the file we happened to write.
hash -r 2>/dev/null || true
RESOLVED="$(command -v bigbang || true)"
if [ -z "$RESOLVED" ]; then
  out="$("$TARGET_DIR/bigbang" --version 2>&1 | head -1)" || die "the installed binary does not run"
  ok "$out (from $TARGET_DIR — not yet on PATH, see above)"
else
  out="$(bigbang --version 2>&1 | head -1)" || die "bigbang is on PATH but does not run"
  ok "$out  →  $RESOLVED"
fi

say "Ready"
echo "   bigbang shell                    interactive: load a profile once, then work"
echo "   bigbang recipe list --profile P"
echo "   bigbang recipe execute --id R --profile P --dry-run"
