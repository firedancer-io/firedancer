#!/bin/bash

set -exuo pipefail

cd "$(dirname "$0")/../.."
FIND_RPMS=$(realpath contrib/cross/find_rpms.py)
PREFIX=opt/cross/macos-arm-clang_x_linux-x86
mkdir -p "$PREFIX"
cd "$PREFIX"

macos_pkgs () {
  local REQUIRED_FORMULAE=( rpm llvm@21 lld coreutils findutils grep git make )

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
    libgcc
    # Project dependencies
    kernel-headers
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

macos_pkgs
sysroot

echo "DONE!"
