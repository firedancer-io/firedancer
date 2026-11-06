#!/usr/bin/env bash
set -euo pipefail

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"

readonly PICOHTTP_COMMIT="54413dc68acd3aca70317d3c0a8c1d45819c9de2"
tmp="$( mktemp -d "${TMPDIR:-/tmp}/fd-picohttpparser-vendor.XXXXXX" )"
trap 'rm -rf "$tmp"' EXIT

for file in picohttpparser.c picohttpparser.h; do
  curl -fsSL "https://raw.githubusercontent.com/h2o/picohttpparser/${PICOHTTP_COMMIT}/${file}" -o "$tmp/$file"
done

(
  cd "$tmp"
  sha256sum -c <<'SHA256'
8aacb701e60a3a5c600f51845d9554463773eafed88f9c4f47472ed5dac6a942  picohttpparser.c
f19173fc3a60881d0e5f36fc5872d686b3ad288b8a439c6dc20bbaccec519d5d  picohttpparser.h
SHA256
)

cp "$tmp/picohttpparser.c" "$tmp/picohttpparser.h" .
