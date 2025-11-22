#!/bin/bash

set -exuo pipefail

cd "$(dirname "$0")/../.."
PREFIX=opt/cross/wasi
mkdir -p "$PREFIX"
cd "$PREFIX"

sdk () {
  git clone --recurse-submodules https://github.com/WebAssembly/wasi-sdk.git --depth 1
  (
    cd wasi-sdk
    cmake -G Ninja -B build/toolchain -S . -DWASI_SDK_BUILD_TOOLCHAIN=ON -DCMAKE_INSTALL_PREFIX=build/install
    cmake --build build/toolchain --target install
  )
}

sysroot () {
  (
    cd wasi-sdk
    cmake -G Ninja -B build/sysroot -S . \
      -DCMAKE_INSTALL_PREFIX=../ \
      -DCMAKE_TOOLCHAIN_FILE=build/install/share/cmake/wasi-sdk.cmake \
      -DCMAKE_C_COMPILER_WORKS=ON \
      -DCMAKE_CXX_COMPILER_WORKS=ON \
      -DWASI_SDK_TARGETS=wasm64-wasi
    cmake --build build/sysroot --target install
  )
}

if [[ ! -d "opt/wasi-sdk" ]]; then
  sdk
fi
sysroot

echo "DONE!"
