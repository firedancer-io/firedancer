#!/usr/bin/env bash

set -euo pipefail

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"

readonly CJSON_TAG="v1.7.19"
readonly CJSON_URL="https://github.com/DaveGamble/cJSON/archive/refs/tags/${CJSON_TAG}.tar.gz"

readonly -a CJSON_FILES=(
  cJSON.c
  cJSON.h
)

tmp="$( mktemp -d "${TMPDIR:-/tmp}/fd-cjson-vendor.XXXXXX" )"
trap 'rm -rf "$tmp"' EXIT

archive="${tmp}/${CJSON_TAG}.tar.gz"
src_parent="${tmp}/src"

mkdir -p "$src_parent"

curl -fL "$CJSON_URL" -o "$archive"
tar -xzf "$archive" -C "$src_parent"

src_dir="$( find "$src_parent" -mindepth 1 -maxdepth 1 -type d -print -quit )"
if [[ -z "$src_dir" ]]; then
  echo "error: could not find extracted cJSON source directory" >&2
  exit 1
fi

(
  cd "$src_dir"
  sha256sum -c <<'EOF'
298581a04a36c0165da4b0aade235c23088cb2faa58651d720ea2f3706ed0b0d  cJSON.c
25b0145150d500498e4d209cec69c18c42cf818bffcc54690be3b895a2a16dee  cJSON.h
EOF
)

for file in "${CJSON_FILES[@]}"; do
  cp "$src_dir/$file" "$file"
done

repo_root="$( git rev-parse --show-toplevel )"
vendor_dir="$( git rev-parse --show-prefix )"
git -C "$repo_root" apply --directory="$vendor_dir" "${vendor_dir}cJSON.patch"

echo "[+] Vendored cJSON files from ${CJSON_TAG}"
