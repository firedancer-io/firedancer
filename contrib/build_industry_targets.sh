#!/usr/bin/env bash

# This scripts creates a bundle containing all of the industry targets that exist in this repo (Firedancer and Solana Labs Client ones)
# For the Firedancer targets, it invokes `make industry-test`.
# For the Labs Client targets, it builds the ffi/rust project and captures all the debug artifacts matching "libdiff_.*\.so".

set -exo pipefail

INDUSTRY_TARGETS=build/industry-bundle-stage/targets

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"/..

FD_INDUSTRY_ARTIFACTS=build/linux/clang/icelake/industry-test
MACHINE=linux_clang_icelake \
  EXTRAS='shared fuzz' \
  make -j shared

for fd_target in $(find ./build/linux/clang/icelake/shared -type f -executable -name 'industry_*.so'); do
  NAME=$(basename $fd_target | sed 's/industry_\(.*\)\.so/\1/')
  mkdir -p "$INDUSTRY_TARGETS/$NAME"
  cp "$fd_target" "$INDUSTRY_TARGETS/$NAME/firedancer.so"
done

pushd ffi/rust
cargo build
popd

for lab_target in $(find ffi/rust/target/debug -maxdepth 1 -name 'libdiff*.so'); do
  NAME=$(basename $lab_target | sed 's/libdiff_\(.*\)\.so/\1/')
  mkdir -p "$INDUSTRY_TARGETS/$NAME"
  cp "$lab_target" "$INDUSTRY_TARGETS/$NAME/labs.so"
done

# make an archive
pushd $INDUSTRY_TARGETS/..
zip -r bundle targets/
popd

echo $(du -h build/industry-bundle-stage/bundle.zip)
