#!/usr/bin/env bash
set -euo pipefail

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"

readonly PICOHTTP_COMMIT="66534e6a48d67a3d9ddfeb5bd2c922f498d314ae"
tmp="$( mktemp -d "${TMPDIR:-/tmp}/fd-picohttpparser-vendor.XXXXXX" )"
trap 'rm -rf "$tmp"' EXIT

for file in picohttpparser.c picohttpparser.h; do
  curl -fsSL "https://raw.githubusercontent.com/h2o/picohttpparser/${PICOHTTP_COMMIT}/${file}" -o "$tmp/$file"
done

(
  cd "$tmp"
  sha256sum -c <<'SHA256'
177196a72fb3b480de80485a17b5509578f3e2c1e4343dcb1f2b2cf94255065a  picohttpparser.c
0113b9f8c6237f7163d99b320a2390983b27c6d56e32700682b73302e183b347  picohttpparser.h
SHA256
)

cp "$tmp/picohttpparser.c" "$tmp/picohttpparser.h" .
