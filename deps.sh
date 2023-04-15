#!/usr/bin/env bash

set -euo pipefail

# Change into Firedancer root directory
cd "$(dirname "${BASH_SOURCE[0]}")"

# Fix pkg-config path and environment
# shellcheck source=./activate-opt
source activate-opt

# Load distro information
source /etc/os-release || echo "[!] Failed to get OS info from /etc/os-release"

# Figure out how to escalate privileges
SUDO=""
if [[ ! "$(id -u)" -eq "0" ]]; then
  SUDO="sudo "
fi

# Install prefix
PREFIX="$(pwd)/opt"

help () {
cat <<EOF

  Usage: $0 [cmd] [args...]

  If cmd is ommitted, default is 'install'.

  Commands are:

    help
    - Prints this message

    check
    - Runs system requirement checks for dep build/install
    - Exits with code 0 on success

    nuke
    - Get rid of dependency checkouts
    - Get rid of all third party dependency files
    - Same as 'rm -rf $(pwd)/opt'

    fetch
    - Fetches dependencies from Git repos into $(pwd)/opt/git

    install
    - Runs 'fetch'
    - Runs 'check'
    - Builds dependencies
    - Installs all project dependencies into prefix $(pwd)/opt

EOF
  exit 0
}

nuke () {
  rm -rf ./opt
  echo "[-] Nuked $(pwd)/opt"
  exit 0
}

fetch_repo () {
  # Skip if dir already exists
  if [[ -d ./opt/git/"$1" ]]; then
    echo "[~] Skipping $1 fetch as \"$(pwd)/opt/git/$1\" already exists"
    echo
    return 0
  fi

  echo "[+] Cloning $1 from $2"
  git clone "$2" "./opt/git/$1"
  echo
}

checkout_repo () {
  echo "[~] Checking out $1 $2"
  (
    cd ./opt/git/"$1"
    git -c advice.detachedHead=false checkout "$2"
  )
  echo
}

fetch () {
  mkdir -pv ./opt/git

  fetch_repo zlib https://github.com/madler/zlib
  fetch_repo zstd https://github.com/facebook/zstd
  fetch_repo elfutils git://sourceware.org/git/elfutils.git
  fetch_repo libbpf https://github.com/libbpf/libbpf
  fetch_repo openssl https://github.com/quictls/openssl
  fetch_repo libseccomp https://github.com/seccomp/libseccomp.git

  checkout_repo zlib "v1.2.13"
  checkout_repo zstd "v1.5.4"
  checkout_repo elfutils "elfutils-0.189"
  checkout_repo libbpf "v1.1.0"
  checkout_repo openssl "OpenSSL_1_1_1t-quic1"
  checkout_repo libseccomp "release-2.5"
}

check_fedora_pkgs () {
  local REQUIRED_RPMS=( perl autoconf gettext-devel automake flex bison gperf )

  echo "[~] Checking for required RPM packages"

  local MISSING_RPMS=( )
  for rpm in ${REQUIRED_RPMS[@]}; do
    if ! rpm -q "$rpm" >/dev/null; then
      MISSING_RPMS+=( "$rpm" )
    fi
  done

  if [[ ${#MISSING_RPMS[@]} -eq 0 ]]; then
    echo "[~] OK: RPM packages required for build are installed"
    return 0
  fi

  echo "[!] Found missing packages"
  echo "[?] This is fixed by the following command:"
  echo "        ${SUDO}dnf install -y ${MISSING_RPMS[@]}"
  read -r -p "[?] Install missing packages with superuser privileges? (y/N) " choice
  case "$choice" in
    y|Y)
      echo "[+] Installing missing RPMs"
      ${SUDO}dnf install -y "${MISSING_RPMS[@]}"
      echo "[+] Installed missing RPMs"
      ;;
    *)
      echo "[-] Skipping package install"
      ;;
  esac
}

check_debian_pkgs () {
  local REQUIRED_DEBS=( perl autoconf gettext automake autopoint flex bison build-essential pkg-config )

  echo "[~] Checking for required DEB packages"

  local MISSING_DEBS=( )
  for deb in ${REQUIRED_DEBS[@]}; do
    if ! dpkg -s "$deb" >/dev/null 2>/dev/null; then
      MISSING_DEBS+=( "$deb" )
    fi
  done

  if [[ ${#MISSING_DEBS[@]} -eq 0 ]]; then
    echo "[~] OK: DEB packages required for build are installed"
    return 0
  fi

  echo "[!] Found missing packages"
  echo "[?] This is fixed by the following command:"
  echo "        ${SUDO}apt-get install -y ${MISSING_DEBS[@]}"
  read -r -p "[?] Install missing packages with superuser privileges? (y/N) " choice
  case "$choice" in
    y|Y)
      echo "[+] Installing missing DEBs"
      ${SUDO}apt-get install -y "${MISSING_DEBS[@]}"
      echo "[+] Installed missing DEBs"
      ;;
    *)
      echo "[-] Skipping package install"
      ;;
  esac
}

check_alpine_pkgs () {
  local REQUIRED_APKS=( perl autoconf gettext automake flex bison build-base pkgconf )

  echo "[~] Checking for required APK packages"

  local MISSING_APKS=( )
  for deb in ${REQUIRED_APKS[@]}; do
    if ! apk info -e "$deb" >/dev/null; then
      MISSING_APKS+=( "$deb" )
    fi
  done

  if [[ ${#MISSING_APKS[@]} -eq 0 ]]; then
    echo "[~] OK: APK packages required for build are installed"
    return 0
  fi

  echo "[!] Found missing packages"
  echo "[?] This is fixed by the following command:"
  echo "        ${SUDO}apk add ${MISSING_APKS[@]}"
  read -r -p "[?] Install missing packages with superuser privileges? (y/N) " choice
  case "$choice" in
    y|Y)
      echo "[+] Installing missing APKs"
      ${SUDO}apk add "${MISSING_APKS[@]}"
      echo "[+] Installed missing APKs"
      ;;
    *)
      echo "[-] Skipping package install"
      ;;
  esac
}

check () {
  DISTRO="${ID_LIKE:-${ID:-}}"
  case "$DISTRO" in
    fedora)
      check_fedora_pkgs
      ;;
    debian)
      check_debian_pkgs
      ;;
    alpine)
      check_alpine_pkgs
      ;;
    *)
      echo "Unsupported distro $DISTRO. Your mileage may vary."
      ;;
  esac
}

install_zlib () {
  if pkg-config --exists zlib; then
    echo "[~] zlib already installed at $(pkg-config --path zlib), skipping installation"
    return 0
  fi

  cd ./opt/git/zlib

  echo "[+] Configuring zlib"
  ./configure \
    --prefix="$PREFIX"
  echo "[+] Configured zlib"

  echo "[+] Building zlib"
  make -j --output-sync=target libz.a
  echo "[+] Successfully built zlib"

  echo "[+] Installing zlib to $PREFIX"
  make install -j
  echo "[+] Successfully installed zlib"
}

install_zstd () {
  if pkg-config --exists libzstd; then
    echo "[~] zstd already installed at $(pkg-config --path libzstd), skipping installation"
    return 0
  fi

  cd ./opt/git/zstd/lib

  echo "[+] Installing zstd to $PREFIX"
  make -j DESTDIR="$PREFIX" PREFIX="" install-pc install-static install-includes
  echo "[+] Successfully installed zstd"
}

install_elfutils () {
  if pkg-config --exists libelf; then
    echo "[~] libelf already installed at $(pkg-config --path libelf), skipping installation"
    return 0
  fi

  cd ./opt/git/elfutils

  echo "[+] Generating elfutils configure script"
  autoreconf -i -f
  echo "[+] Generated elfutils configure script"

  echo "[+] Configuring elfutils"
  ./configure \
    --prefix="$PREFIX" \
    --enable-maintainer-mode \
    --disable-debuginfod \
    --disable-libdebuginfod \
    --without-curl \
    --without-microhttpd \
    --without-sqlite3 \
    --without-libarchive \
    --without-tests
  echo "[+] Configured elfutils"

  echo "[+] Building elfutils"
  make -j --output-sync=target
  echo "[+] Successfully built elfutils"

  echo "[+] Installing elfutils to $PREFIX"
  make install -j
  echo "[+] Successfully installed elfutils"
}

install_libbpf () {
  if pkg-config --exists libbpf; then
    echo "[~] libbpf already installed at $(pkg-config --path libbpf), skipping installation"
    return 0
  fi

  cd ./opt/git/libbpf
  git apply ../../../contrib/libbpf-fix-pedantic-compile.patch

  cd src

  echo "[+] Installing libbpf to $PREFIX"
  make -j install PREFIX="$PREFIX" LIBDIR="$PREFIX/lib"
  echo "[+] Successfully installed libbpf"
}

install_openssl () {
  if pkg-config --exists openssl; then
    echo "[~] openssl already installed at $(pkg-config --path openssl), skipping installation"
    return 0
  fi

  cd ./opt/git/openssl

  echo "[+] Configuring OpenSSL"
  ./config \
    --prefix="$PREFIX" \
    enable-quic
  echo "[+] Configured OpenSSL"

  echo "[+] Building OpenSSL"
  make -j --output-sync=target
  echo "[+] Successfully built OpenSSL"

  echo "[+] Installing OpenSSL to $PREFIX"
  make install_sw -j
  echo "[+] Successfully installed OpenSSL"

  echo "[~] Installed all dependencies"
}

install_libseccomp () {
  if pkg-config --exists libseccomp; then
    echo "[~] libseccomp already installed at $(pkg-config --path libseccomp), skipping installation"
    return 0
  fi

  cd ./opt/git/libseccomp

  echo "[+] Configuring libseccomp"
  ./autogen.sh
  ./configure \
    --prefix="$PREFIX"
  echo "[+] Configured libseccomp"

  echo "[+] Building libseccomp"
  make -j --output-sync=target
  echo "[+] Successfully built libseccomp"

  echo "[+] Installing libseccomp to $PREFIX"
  make install
  echo "[+] Successfully installed libseccomp"

  echo "[~] Installed all dependencies"
}

install () {
  ( install_zlib       )
  ( install_zstd       )
  ( install_elfutils   )
  ( install_libbpf     )
  ( install_openssl    )
  ( install_libseccomp )

  echo "[~] Done! To wire up $(pwd)/opt with make, run:"
  echo "    source activate-opt"
  echo
}

if [[ $# -eq 0 ]]; then
  echo "[~] This will fetch, build, and install Firedancer's dependencies into $(pwd)/opt"
  echo "[~] For help, run: $0 help"
  echo
  echo "[~] Running $0 install"

  read -r -p "[?] Continue? (y/N) " choice
  case "$choice" in
    y|Y)
      echo
      fetch
      check
      install
      ;;
    *)
      echo "[!] Stopping." >&2
      exit 1
  esac
fi

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help|help)
      help
      ;;
    nuke)
      shift
      nuke
      ;;
    fetch)
      shift
      fetch
      ;;
    check)
      shift
      check
      ;;
    install)
      shift
      fetch
      check
      install
      ;;
    *)
      echo "Unknown command: $1" >&2
      exit 1
      ;;
  esac
done
