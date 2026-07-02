#!/usr/bin/env bash

# Verifies the two properties the EXTRAS=ccache embed handling relies
# on, under the exact sloppiness/extrafiles config the build uses
# (config/extra/with-ccache.mk):
#
#   1. HIT on repeat: with sloppiness=incbin, a TU using an
#      FD_IMPORT-style macro-expanded .incbin IS cached (without the
#      sloppiness flag, ccache >= 4.9 marks such TUs
#      unsupported_code_directive and never caches them -- safe but
#      pointless).
#   2. MISS on embed change: changing the .incbin'd file's content
#      must produce a different object, because CCACHE_EXTRAFILES
#      hashes the file content into the key.  If this fails, ccache
#      serves stale embedded bytes -- the exact FD_IMPORT staleness
#      bug this setup exists to prevent.
#
# Property 2 without property 1 means the canary is passing vacuously
# (nothing was cached), so both are asserted.
#
# Usage: contrib/ccache/test-embed-canary.sh [cc]   (default: gcc)

set -euo pipefail

CC="${1:-gcc}"
CCACHE="${CCACHE:-ccache}"

command -v "$CCACHE" >/dev/null || { echo "SKIP: no $CCACHE in PATH"; exit 0; }
command -v "$CC"     >/dev/null || { echo "SKIP: no $CC in PATH";     exit 0; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

# FD_IMPORT-shaped: .incbin arrives via macro expansion, path is a
# string literal (mirrors src/util/fd_util_base.h FD_IMPORT).
cat > embed.c <<'EOF'
#define IMPORT(name, path) \
  __asm__( ".section .rodata\n" #name ":\n.incbin \"" path "\"\n.previous\n" ); \
  extern const unsigned char name[];
IMPORT( canary_payload, "payload.bin" )
EOF

# Isolated cache + the same correctness knobs as with-ccache.mk.
export CCACHE_DIR="$tmp/cache"
export CCACHE_SLOPPINESS=incbin
export CCACHE_EXTRAFILES="$tmp/payload.bin"
unset CCACHE_DISABLE CCACHE_RECACHE || true

stat_hits() { $CCACHE -s | sed -nE 's/^ *Hits: *([0-9]+).*/\1/p' | head -1; }

printf 'AAAA_CANARY_V1' > payload.bin
$CCACHE "$CC" -c embed.c -o embed1.o      # miss, populates
$CCACHE "$CC" -c embed.c -o embed1b.o     # must hit

hits="$(stat_hits)"
if [[ "${hits:-0}" -lt 1 ]]; then
  echo "FAIL: repeat compile of an .incbin TU did not hit the cache."
  echo "      sloppiness=incbin is not taking effect (ccache too old,"
  echo "      or config overridden) -- embed TUs are silently uncacheable."
  exit 1
fi

printf 'BBBB_CANARY_V2' > payload.bin
$CCACHE "$CC" -c embed.c -o embed2.o      # must miss: extrafiles changed

if cmp -s embed1.o embed2.o; then
  echo "FAIL: ccache served a stale object after the .incbin'd file changed."
  echo "      CCACHE_EXTRAFILES is not being honored -- the FD_IMPORT"
  echo "      staleness protection is broken.  Do not use this ccache setup."
  exit 1
fi

if ! strings embed2.o | grep -q 'BBBB_CANARY_V2'; then
  echo "FAIL: second object does not contain the new embedded bytes."
  exit 1
fi

echo "OK: embed TUs cache on repeat AND re-key on embed change."
