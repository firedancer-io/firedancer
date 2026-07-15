#!/usr/bin/env bash

# Re-imports the blst subset used by Firedancer: the two-object build
# upstream's build.sh performs (src/server.c unity build +
# build/assembly.S, which #includes the pre-generated per-arch .s
# bodies from build/elf/).  The src/asm/*.pl generators, non-ELF
# platforms, and non-C bindings are not imported.

set -euo pipefail

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"

readonly BLST_TAG="v0.3.13"
readonly BLST_URL="https://github.com/supranational/blst"

tmp="$( mktemp -d "${TMPDIR:-/tmp}/fd-blst-vendor.XXXXXX" )"
trap 'rm -rf "$tmp"' EXIT

git clone --depth=1 --branch "$BLST_TAG" "$BLST_URL" "$tmp/blst"

cp "$tmp/blst/LICENSE" LICENSE
mkdir -p src build/elf bindings
cp "$tmp/blst/src/"*.c "$tmp/blst/src/"*.h src/
cp "$tmp/blst/build/assembly.S" build/
cp "$tmp/blst/build/elf/"*-x86_64.s build/elf/
cp "$tmp/blst/build/elf/"*-armv8.S build/elf/
cp "$tmp/blst/bindings/blst.h" "$tmp/blst/bindings/blst_aux.h" bindings/

echo "[+] Vendored blst files from $BLST_TAG"
