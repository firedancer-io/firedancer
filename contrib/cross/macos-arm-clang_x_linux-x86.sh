#!/bin/bash

set -exuo pipefail

cd "$(dirname "$0")/../.."
FIND_RPMS=$(realpath contrib/cross/find_rpms.py)
PREFIX=opt/cross/macos-arm-clang_x_linux-x86
mkdir -p "$PREFIX"
cd "$PREFIX"

macos_pkgs () {
  local REQUIRED_FORMULAE=( rpm llvm lld coreutils findutils git make cmake )

  echo "[~] Checking for required brew formulae"

  local MISSING_FORMULAE=( )
  for formula in "${REQUIRED_FORMULAE[@]}"; do
    if ! brew ls --versions "$formula" >/dev/null 2>&1; then
      MISSING_FORMULAE+=( "$formula" )
    fi
  done

  if [[ ${#MISSING_FORMULAE[@]} -eq 0 ]]; then
    echo "[~] OK: brew formulae required for build are installed"
    return 0
  fi

  PACKAGE_INSTALL_CMD=( brew install "${MISSING_FORMULAE[@]}" )
  "${PACKAGE_INSTALL_CMD[@]}"
}

sysroot () {
  mkdir -p usr/bin usr/lib usr/lib64 dl/rpm usr/local/include usr/local/lib usr/local/lib64
  rm -f bin lib lib64
  ln -sf usr/bin bin
  ln -sf usr/lib lib
  ln -sf usr/lib64 lib64

  # Mirror configuration
  ARCH=x86_64
  FEDORA_VERSION=43

  # Target packages
  PACKAGES=(
    # Build environment
    clang-libs # C17 headers
    glibc
    glibc-devel # libc headers
    gcc # crtBeginS.o
    gcc-c++ # /usr/lib/gcc/x86_64-redhat-linux/15/libstdc++.so
    libgcc
    libstdc++
    libstdc++-devel
    # Project dependencies
    kernel-headers
    liburing-devel liburing
    bzip2-devel bzip2-static
    lz4-devel lz4-static
    libzstd-devel libzstd-static
    snappy-devel snappy
    rocksdb-devel rocksdb
  )

  # Resolve packages
  PACKAGE_URLS=( $(python3 "$FIND_RPMS" --arch "$ARCH" --fedora-version "$FEDORA_VERSION" "${PACKAGES[@]}") )

  # Create sysroot

  install_rpm () {
    local url="$1"
    pkg=$(basename "$url")
    pkg_path="./dl/rpm/${pkg}"
    echo "Installing $url"
    if [[ ! -f "$pkg_path" ]]; then curl -sS -L -o "$pkg_path" "$url"; fi
    rpm2archive "$pkg_path" | tar -Px
  }

  for url in "${PACKAGE_URLS[@]}"; do
    install_rpm "$url"
  done
}

deps_cmake () {
  LLVM_PREFIX="$(brew --prefix llvm)"
  cat > ./toolchain.cmake << EOF

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_C_COMPILER $LLVM_PREFIX/bin/clang "--sysroot $(realpath .)" "-nostdinc" "-isystem $(realpath ./usr/include)" "-isystem $(realpath ./usr/lib/clang/21/include)")
set(CMAKE_AR $LLVM_PREFIX/bin/llvm-ar)
set(CMAKE_RANLIB $LLVM_PREFIX/bin/llvm-ranlib)
set(CLANG_TARGET_TRIPLE x86_64-linux-gnu)
set(CMAKE_C_COMPILER_TARGET x86_64-linux-gnu)
set(CMAKE_CXX_COMPILER_TARGET x86_64-linux-gnu)
set(CMAKE_ASM_COMPILER_TARGET x86_64-linux-gnu)
set(CMAKE_SYSTEM_PROCESSOR amd64)
set(CMAKE_C_COMPILER_WORKS ON)

set(CMAKE_FIND_ROOT_PATH $(realpath .))
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

EOF
}

deps_secp256k1 () {
  (
    cd dl
    rm -rf secp256k1
    git clone https://github.com/bitcoin-core/secp256k1
    cd secp256k1
    git checkout v0.7.0

    cmake -B build \
      -DCMAKE_TOOLCHAIN_FILE=../../toolchain.cmake \
      -DCMAKE_INSTALL_PREFIX:PATH="$(realpath ../../usr/local)" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
      -DSECP256K1_BUILD_TESTS=OFF \
      -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
      -DSECP256K1_BUILD_BENCHMARK=OFF \
      -DSECP256K1_DISABLE_SHARED=ON \
      -DBUILD_SHARED_LIBS=OFF \
      -DSECP256K1_ENABLE_MODULE_ECDH=OFF \
      -DSECP256K1_ENABLE_MODULE_RECOVERY=ON \
      -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=OFF \
      -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=OFF \
      -DSECP256K1_ENABLE_MODULE_ECDH=OFF \
      -DSECP256K1_ENABLE_MODULE_MUSIG=OFF \
      -DSECP256K1_ENABLE_MODULE_ELLSWIFT=OFF \
      .
    make -C build
    make -C build install
  )
}

deps () {
  deps_cmake
  deps_secp256k1
}

macos_pkgs
sysroot
deps

echo "DONE!"
