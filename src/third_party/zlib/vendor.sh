#!/usr/bin/env bash

# Re-imports the compress-only zlib subset used by fd_gzip_pack (gzip
# encoding of GUI assets at build time).  The inflate side, gz* file
# API, and build system are not imported.

set -euo pipefail

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"

readonly ZLIB_TAG="v1.3.1"
readonly ZLIB_URL="https://github.com/madler/zlib"

readonly -a ZLIB_FILES=(
  zlib.h
  zconf.h
  deflate.c
  deflate.h
  trees.c
  trees.h
  adler32.c
  crc32.c
  crc32.h
  zutil.c
  zutil.h
)

tmp="$( mktemp -d "${TMPDIR:-/tmp}/fd-zlib-vendor.XXXXXX" )"
trap 'rm -rf "$tmp"' EXIT

git clone --depth=1 --branch "$ZLIB_TAG" "$ZLIB_URL" "$tmp/zlib"

cp "$tmp/zlib/LICENSE" LICENSE
for f in "${ZLIB_FILES[@]}"; do
  cp "$tmp/zlib/$f" "$f"
done

echo "[+] Vendored zlib files from $ZLIB_TAG"
