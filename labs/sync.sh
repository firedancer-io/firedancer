#!/bin/sh

set -eux

# Clean up on exit.
trap "git -C ../third_party/solana checkout HEAD -- Cargo.toml" EXIT

# TODO Check if upstream Cargo.toml has changes to avoid stepping over user

# Purge existing auto-generated files.
rm -rf ./cargo
mkdir -p ./solana
find ./solana -name 'BUILD.bazel' -print \
  | grep 'cargo/BUILD.bazel$' \
  | xargs --no-run-if-empty rm -v

# Replace workspace Cargo file with our custom one.
rm -f ../third_party/solana/Cargo.toml
ln ./Cargo.toml ../third_party/solana/Cargo.toml

# Run cargo-raze to generate Bazel targets
cargo raze \
  --manifest-path ../third_party/solana/Cargo.toml \
  --output ../labs/cargo

# Move generated dependency alias files
# from in-tree to ./labs/solana/.../cargo/BUILD.bazel
find ../third_party/solana -name 'BUILD.bazel' -print \
  | grep 'cargo/BUILD.bazel$' \
  | while read -r LINE; do
  alias_dir="$(dirname "$LINE")"
  crate_path=$(dirname "$(realpath --relative-to ../third_party/solana "$alias_dir")")
  mkdir -p ./solana/"$crate_path"
  rm -rf ./solana/"$crate_path"/cargo
  mv ../third_party/solana/"$crate_path"/cargo ./solana/"$crate_path"/cargo
done
