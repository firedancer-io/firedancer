#!/usr/bin/env bash

# Re-imports the zstd subset used by Firedancer:
# lib/{common,compress,decompress,dictBuilder} + public headers.
# dictBuilder is present only for librocksdb.a's ZDICT_* references
# (dev-mode); legacy/, deprecated/, and the build/ tree are not
# imported.  No build-time codegen exists in zstd.

set -euo pipefail

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"

readonly ZSTD_TAG="v1.5.7"
readonly ZSTD_URL="https://github.com/facebook/zstd"

tmp="$( mktemp -d "${TMPDIR:-/tmp}/fd-zstd-vendor.XXXXXX" )"
trap 'rm -rf "$tmp"' EXIT

git clone --depth=1 --branch "$ZSTD_TAG" "$ZSTD_URL" "$tmp/zstd"

cp "$tmp/zstd/LICENSE" LICENSE
mkdir -p lib/common lib/compress lib/decompress lib/dictBuilder
cp "$tmp/zstd/lib/zstd.h" "$tmp/zstd/lib/zstd_errors.h" "$tmp/zstd/lib/zdict.h" lib/
cp "$tmp/zstd/lib/common/"*.c "$tmp/zstd/lib/common/"*.h lib/common/
cp "$tmp/zstd/lib/compress/"*.c "$tmp/zstd/lib/compress/"*.h lib/compress/
cp "$tmp/zstd/lib/decompress/"*.c "$tmp/zstd/lib/decompress/"*.h \
   "$tmp/zstd/lib/decompress/huf_decompress_amd64.S" lib/decompress/
cp "$tmp/zstd/lib/dictBuilder/"*.c "$tmp/zstd/lib/dictBuilder/"*.h lib/dictBuilder/
# single-threaded build: zstdmt is never compiled (see Local.mk)
rm lib/compress/zstdmt_compress.c

echo "[+] Vendored zstd files from $ZSTD_TAG"
