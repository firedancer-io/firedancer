#!/usr/bin/env bash

# Re-imports the DynASM x86/x64 subset from LuaJIT used by Firedancer:
# C headers (dasm_proto.h, dasm_x86.h) and Lua preprocessor modules
# (dynasm.lua, dasm_x86.lua, dasm_x64.lua).

set -euo pipefail

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"

readonly LUAJIT_COMMIT="24c20c94e7db195b640854619577441f9b4bc6be"
readonly LUAJIT_URL="https://github.com/LuaJIT/LuaJIT/archive/${LUAJIT_COMMIT}.tar.gz"

tmp="$( mktemp -d "${TMPDIR:-/tmp}/fd-luajit-vendor.XXXXXX" )"
trap 'rm -rf "$tmp"' EXIT

archive="${tmp}/${LUAJIT_COMMIT}.tar.gz"
src_parent="${tmp}/src"

mkdir -p "$src_parent"

curl -fL "$LUAJIT_URL" -o "$archive"
tar -xzf "$archive" -C "$src_parent"

src_dir="$( find "$src_parent" -mindepth 1 -maxdepth 1 -type d -print -quit )"
if [[ -z "$src_dir" ]]; then
  echo "error: could not find extracted luajit source directory" >&2
  exit 1
fi

(
  cd "$src_dir"
  sha256sum -c <<'EOF'
6ce9bcf6b3413dc3f1e65fd9ee19d5fb7c2699cb144a6df7dbc3e75b9c8dab43  dynasm/dasm_proto.h
bcde2830be490ae7cc46e1ad4c0ab0e6935e87a11bfa48710d08b53662fae7b9  dynasm/dasm_x86.h
8d162770544aee5dd66b1cae9f94faccc5ae82d7225f43c708acb4279175c727  dynasm/dasm_x64.lua
52b44ad1cf29a13c372fea516841bc2fe576c221b00378834d91fc37907967ff  dynasm/dynasm.lua
9554085064e870e4a0222ca80aed48233c6370f00cff4eee6939ce737945a2c5  dynasm/dasm_x86.lua
EOF
)

cp "$src_dir/COPYRIGHT" LICENSE
cp "$src_dir/dynasm/dasm_proto.h" dasm_proto.h
cp "$src_dir/dynasm/dasm_x86.h" dasm_x86.h

mkdir -p dynasm
cp "$src_dir/dynasm/dasm_x64.lua" dynasm/dasm_x64.lua
cp "$src_dir/dynasm/dynasm.lua" dynasm/dynasm.lua
cp "$src_dir/dynasm/dasm_x86.lua" dynasm/dasm_x86.lua
cp "$src_dir/dynasm/dasm_x86.lua" dynasm/dynasm_x86.lua

echo "[+] Vendored luajit files from ${LUAJIT_COMMIT}"
