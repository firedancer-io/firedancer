#!/usr/bin/env bash

set -euo pipefail

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"

readonly BZIP2_TAG="bzip2-1.0.8"
readonly BZIP2_URL="https://github.com/libarchive/bzip2/archive/refs/tags/${BZIP2_TAG}.tar.gz"

readonly -a BZIP2_FILES=(
  blocksort.c
  bzlib.c
  bzlib.h
  bzlib_private.h
  compress.c
  crctable.c
  decompress.c
  huffman.c
  randtable.c
)

tmp="$( mktemp -d "${TMPDIR:-/tmp}/fd-bzip2-vendor.XXXXXX" )"
trap 'rm -rf "$tmp"' EXIT

archive="${tmp}/${BZIP2_TAG}.tar.gz"
src_parent="${tmp}/src"

mkdir -p "$src_parent"

curl -fL "$BZIP2_URL" -o "$archive"
tar -xzf "$archive" -C "$src_parent"

src_dir="$( find "$src_parent" -mindepth 1 -maxdepth 1 -type d -print -quit )"
if [[ -z "$src_dir" ]]; then
  echo "error: could not find extracted bzip2 source directory" >&2
  exit 1
fi

(
  cd "$src_dir"
  sha256sum -c <<'EOF'
4e48cd2ccff44699e67a7c949b0e9576c05b8dcbe20f863475c4fcc8db11a409  blocksort.c
d06cf1bd991df1f2dc8ef4f7713d186eb636767111cbd4807ef5fc4a54ca6838  bzlib.c
6ac62e811669598ee30c9e1c379b9e627f6ff17a5a3dc1e0b4fa8b8ea75e580d  bzlib.h
c0cda4f35ee1f2d54c9beacd524f8d28e0dbf8494aca30d854af3f143af4341b  bzlib_private.h
75995bd6e8c5f1e1dad05178f3cf53137df99ce860a1984324f78591f28deed3  compress.c
2fb7a564629386456e731f431a5cf4f5026747bace4cd10be8f5ecf082066a92  crctable.c
31a89f8bf408ef0e4acae83e8be60a8eb4edece6c866d6e32b8f7e557ca54bc6  decompress.c
bdeb45f3f535546a672811b68aa87cc58fd395b28ecebc34fa3566a656a4d1d1  huffman.c
407054ca6f54cd737dbc26ceb6b7874b55a0fcff86c2eb23cbec2fbdbb884815  randtable.c
EOF
)

for file in "${BZIP2_FILES[@]}"; do
  cp "$src_dir/$file" "$file"
done

echo "[+] Vendored libbz2 files from ${BZIP2_TAG}"
