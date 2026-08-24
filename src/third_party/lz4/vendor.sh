#!/usr/bin/env bash

# Re-imports the lz4 subset used by Firedancer: the core block API
# (lz4.c) used by fd_checkpt/fd_wksp/vinyl.  Only lib/ is
# BSD-2-licensed; programs/ is GPL and must never be imported.

set -euo pipefail

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"

readonly LZ4_TAG="v1.10.0"
readonly LZ4_URL="https://github.com/lz4/lz4"

tmp="$( mktemp -d "${TMPDIR:-/tmp}/fd-lz4-vendor.XXXXXX" )"
trap 'rm -rf "$tmp"' EXIT

git clone --depth=1 --branch "$LZ4_TAG" "$LZ4_URL" "$tmp/lz4"

cp "$tmp/lz4/lib/LICENSE" LICENSE
mkdir -p lib
cp "$tmp/lz4/lib/lz4.c" "$tmp/lz4/lib/lz4.h" lib/

echo "[+] Vendored lz4 files from $LZ4_TAG"
