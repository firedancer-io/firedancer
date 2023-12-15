#!/bin/bash

set -eux

if [[ -d ffi/rust/firedancer-diff/fuzz ]]; then
    # mix the fuzz targets with the highend fuzz
    TARGET_DIR=./build/linux/clang/combi/highend/fuzz-test
    RUST_FUZZ_OUT_DIR=./ffi/rust/firedancer-diff/fuzz/target/release
    pushd ffi/rust/firedancer-diff/fuzz
    RUSTFLAGS=-Zsanitizer=address cargo build -Zbuild-std --target x86_64-unknown-linux-gnu --release
    cargo build --release
    popd

    ARTIFACTS=$(find ./ffi/rust/firedancer-diff/fuzz/target/release -maxdepth 1 -executable -type f)
    for ARTIFACT in $ARTIFACTS; do
        mkdir -p "${TARGET_DIR}/$(basename $ARTIFACT)"
        cp $ARTIFACT "${TARGET_DIR}/$(basename $ARTIFACT)/"
    done
else
    echo "ignoring rust fuzz since directory does not exist"
fi
