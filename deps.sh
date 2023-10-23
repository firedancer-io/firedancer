#!/usr/bin/env bash

# Change into Firedancer root directory
cd "$(dirname "${BASH_SOURCE[0]}")"

set -euo pipefail

# Load OS information
OS="$(uname -s)"
case "$OS" in
  Darwin)
    MAKE=( make -j )
    ID=macos
    ;;
  Linux)
    MAKE=( make -j )
    # Load distro information
    if [[ -f /etc/os-release ]]; then
      source /etc/os-release
    fi
    ;;
  *)
    echo "[!] Unsupported OS $OS"
    ;;
esac

# Figure out how to escalate privileges
SUDO=""
if [[ ! "$(id -u)" -eq "0" ]]; then
  SUDO="sudo"
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

checkout_repo () {
  # Skip if dir already exists
  if [[ -d ./opt/git/"$1" ]]; then
    echo "[~] Skipping $1 fetch as \"$(pwd)/opt/git/$1\" already exists"
  else
    echo "[+] Cloning $1 from $2"
    git -c advice.detachedHead=false clone "$2" "./opt/git/$1" --branch "$3" --depth=1
    echo
  fi

  # Skip if tag already correct
  if [[ "$(git -C ./opt/git/"$1" describe --tags --abbrev=0)" == "$3" ]]; then
    return
  fi

  echo "[~] Checking out $1 $3"
  (
    cd ./opt/git/"$1"
    git fetch origin "$3" --depth=1
    git -c advice.detachedHead=false checkout "$3"
  )
  echo
}

checkout_gnuweb () {
  # Skip if dir already exists
  if [[ -d ./opt/gnuweb/"$1" ]]; then
    echo "[~] Skipping $1 fetch as \"$(pwd)/opt/gnuweb/$1\" already exists"
  else
    echo "[+] Cloning $1 from $2/$3.tar.gz"
    curl -o - -L "$2/$3.tar.gz" | gunzip | tar xf - -C ./opt/gnuweb
    mv ./opt/gnuweb/$3 ./opt/gnuweb/$1
    echo
  fi
}

fetch () {
  mkdir -pv ./opt/git

  checkout_repo zlib      https://github.com/madler/zlib            "v1.2.13"
  checkout_repo bzip2     https://sourceware.org/git/bzip2.git      "bzip2-1.0.8"
  checkout_repo zstd      https://github.com/facebook/zstd          "v1.5.4"
  checkout_repo openssl   https://github.com/quictls/openssl.git    "openssl-3.1.4-quic1"
  checkout_repo rocksdb   https://github.com/facebook/rocksdb       "v7.10.2"
  checkout_repo secp256k1 https://github.com/bitcoin-core/secp256k1 "v0.3.2"
  checkout_repo snappy    https://github.com/google/snappy          "1.1.10"
  checkout_repo libff     https://github.com/firedancer-io/libff.git "develop"

  mkdir -pv ./opt/gnuweb
  checkout_gnuweb libmicrohttpd https://ftp.gnu.org/gnu/libmicrohttpd/ "libmicrohttpd-0.9.77"
}

check_fedora_pkgs () {
  local REQUIRED_RPMS=( perl autoconf gettext-devel automake flex bison cmake clang )

  echo "[~] Checking for required RPM packages"

  local MISSING_RPMS=( )
  for rpm in "${REQUIRED_RPMS[@]}"; do
    if ! rpm -q "$rpm" >/dev/null; then
      MISSING_RPMS+=( "$rpm" )
    fi
  done

  if [[ "${#MISSING_RPMS[@]}" -eq 0 ]]; then
    echo "[~] OK: RPM packages required for build are installed"
    return 0
  fi

  if [[ -z "${SUDO}" ]]; then
    PACKAGE_INSTALL_CMD=( dnf install -y ${MISSING_RPMS[*]} )
  else
    PACKAGE_INSTALL_CMD=( "${SUDO}" dnf install -y ${MISSING_RPMS[*]} )
  fi
}

check_debian_pkgs () {
  local REQUIRED_DEBS=( perl autoconf gettext automake autopoint flex bison build-essential gcc-multilib )

  echo "[~] Checking for required DEB packages"

  local MISSING_DEBS=( )
  for deb in "${REQUIRED_DEBS[@]}"; do
    if ! dpkg -s "$deb" >/dev/null 2>/dev/null; then
      MISSING_DEBS+=( "$deb" )
    fi
  done

  if [[ ${#MISSING_DEBS[@]} -eq 0 ]]; then
    echo "[~] OK: DEB packages required for build are installed"
    return 0
  fi

  if [[ -z "${SUDO}" ]]; then
    PACKAGE_INSTALL_CMD=( apt-get install -y ${MISSING_DEBS[*]} )
  else
    PACKAGE_INSTALL_CMD=( "${SUDO}" apt-get install -y ${MISSING_DEBS[*]} )
  fi
}

check_alpine_pkgs () {
  local REQUIRED_APKS=( perl autoconf gettext automake flex bison build-base linux-headers )

  echo "[~] Checking for required APK packages"

  local MISSING_APKS=( )
  for deb in "${REQUIRED_APKS[@]}"; do
    if ! apk info -e "$deb" >/dev/null; then
      MISSING_APKS+=( "$deb" )
    fi
  done

  if [[ ${#MISSING_APKS[@]} -eq 0 ]]; then
    echo "[~] OK: APK packages required for build are installed"
    return 0
  fi

  if [[ -z "${SUDO}" ]]; then
    PACKAGE_INSTALL_CMD=( apk add ${MISSING_APKS[*]} )
  else
    PACKAGE_INSTALL_CMD=( "${SUDO}" apk add ${MISSING_APKS[*]} )
  fi
}

check_macos_pkgs () {
  local REQUIRED_FORMULAE=( perl autoconf gettext automake flex bison )

  echo "[~] Checking for required brew formulae"

  local MISSING_FORMULAE=( )
  for formula in "${REQUIRED_FORMULAE[@]}"; do
    if [[ ! -d "/usr/local/Cellar/$formula" ]]; then
      MISSING_FORMULAE+=( "$formula" )
    fi
  done

  if [[ ${#MISSING_FORMULAE[@]} -eq 0 ]]; then
    echo "[~] OK: brew formulae required for build are installed"
    return 0
  fi

  PACKAGE_INSTALL_CMD=( brew install ${MISSING_FORMULAE[*]} )
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
    macos)
      check_macos_pkgs
      ;;
    *)
      echo "Unsupported distro $DISTRO. Your mileage may vary."
      ;;
  esac

  if [[ ! -z "${PACKAGE_INSTALL_CMD[@]}" ]]; then
    echo "[!] Found missing system packages"
    echo "[?] This is fixed by the following command:"
    echo "        ${PACKAGE_INSTALL_CMD[@]}"
    if [[ "$FD_AUTO_INSTALL_PACKAGES" == "1" ]]; then
      choice=y
    else
      read -r -p "[?] Install missing system packages? (y/N) " choice
    fi
    case "$choice" in
      y|Y)
        echo "[+] Installing missing packages"
        "${PACKAGE_INSTALL_CMD[@]}"
        echo "[+] Finished installing missing packages"
        ;;
      *)
        echo "[-] Skipping formula install"
        ;;
    esac
  fi
}

install_zlib () {
  cd ./opt/git/zlib

  echo "[+] Configuring zlib"
  ./configure \
    --prefix="$PREFIX"
  echo "[+] Configured zlib"

  echo "[+] Building zlib"
  "${MAKE[@]}" libz.a
  echo "[+] Successfully built zlib"

  echo "[+] Installing zlib to $PREFIX"
  make install -j
  echo "[+] Successfully installed zlib"
}

install_bzip2 () {
  cd ./opt/git/bzip2

  echo "[+] Installing bzip2 to $PREFIX"
  "${MAKE[@]}" PREFIX="$PREFIX" install
  echo "[+] Successfully installed bzip2"
}

install_zstd () {
  cd ./opt/git/zstd/lib

  echo "[+] Installing zstd to $PREFIX"
  "${MAKE[@]}" DESTDIR="$PREFIX" PREFIX="" install-pc install-static install-includes install-shared
  echo "[+] Successfully installed zstd"
}

install_secp256k1 () {
  cd ./opt/git/secp256k1

  echo "[+] Configuring secp256k1"
  rm -rf build
  mkdir build
  cd build
  cmake .. \
    -G"Unix Makefiles" \
    -DCMAKE_INSTALL_PREFIX:PATH="$PREFIX" \
    -DCMAKE_INSTALL_LIBDIR="lib" \
    -DCMAKE_BUILD_TYPE=Release \
    -DSECP256K1_BUILD_TESTS=OFF \
    -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
    -DSECP256K1_BUILD_BENCHMARK=OFF \
    -DSECP256K1_DISABLE_SHARED=OFF \
    -DBUILD_SHARED_LIBS=OFF \
    -DSECP256K1_ENABLE_MODULE_RECOVERY=ON \
    -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=OFF \
    -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=OFF \
    -DSECP256K1_ENABLE_MODULE_ECDH=OFF

  echo "[+] Building secp256k1"
  "${MAKE[@]}"
  echo "[+] Successfully built secp256k1"

  echo "[+] Installing secp256k1 to $PREFIX"
  make install
  echo "[+] Successfully installed secp256k1"
}

install_openssl () {
  cd ./opt/git/openssl

  echo "[+] Configuring OpenSSL"
  ./config \
    -static \
    -fPIC \
    --prefix="$PREFIX" \
    --libdir=lib \
    enable-quic \
    enable-pic \
    no-engine \
    no-static-engine \
    no-weak-ssl-ciphers \
    no-autoload-config \
    no-tls1 \
    no-tls1-method \
    no-tls1_1 \
    no-tls1_1-method \
    no-tls1_2 \
    no-tls1_2-method \
    enable-tls1_3 \
    no-shared \
    no-legacy \
    no-tests \
    no-ui-console \
    no-sctp \
    no-ssl3 \
    no-aria \
    no-bf \
    no-blake2 \
    no-camellia \
    no-cast \
    no-cmac \
    no-cmp \
    no-cms \
    no-comp \
    no-ct \
    no-des \
    no-dh \
    no-dsa \
    no-dtls \
    no-dtls1-method \
    no-dtls1_2-method \
    no-ecdsa \
    no-fips \
    no-gost \
    no-idea \
    no-ktls \
    no-md4 \
    no-nextprotoneg \
    no-ocb \
    no-ocsp \
    no-rc2 \
    no-rc4 \
    no-rc5 \
    no-rmd160 \
    no-scrypt \
    no-seed \
    no-siphash \
    no-siv \
    no-sm3 \
    no-sm4 \
    no-srp \
    no-srtp \
    no-sock \
    no-ts \
    no-whirlpool
  echo "[+] Configured OpenSSL"

  echo "[+] Building OpenSSL"
  "${MAKE[@]}" build_libs
  echo "[+] Successfully built OpenSSL"

  echo "[+] Installing OpenSSL to $PREFIX"
  "${MAKE[@]}" install_dev
  echo "[+] Successfully installed OpenSSL"
}

install_rocksdb () {
  cd ./opt/git/rocksdb
  mkdir -p build
  cd build
  cmake .. \
    -G"Unix Makefiles" \
    -DCMAKE_INSTALL_PREFIX:PATH="$PREFIX" \
    -DCMAKE_INSTALL_LIBDIR="lib" \
    -DCMAKE_BUILD_TYPE=Release \
    -DROCKSDB_BUILD_SHARED=ON \
    -DWITH_GFLAGS=OFF \
    -DWITH_LIBURING=OFF \
    -DWITH_BZ2=OFF \
    -DWITH_SNAPPY=ON \
    -DWITH_ZLIB=ON \
    -DWITH_ZSTD=ON \
    -DWITH_ALL_TESTS=OFF \
    -DWITH_BENCHMARK_TOOLS=OFF \
    -DWITH_CORE_TOOLS=OFF \
    -DWITH_RUNTIME_DEBUG=OFF \
    -DWITH_TESTS=OFF \
    -DWITH_TOOLS=OFF \
    -DWITH_TRACE_TOOLS=OFF \
    -DZLIB_ROOT="$PREFIX" \
    -DBZIP2_LIBRARIES="$PREFIX/lib/libbz2.a" \
    -DBZIP2_INCLUDE_DIR="$PREFIX/include" \
    -Dzstd_ROOT_DIR="$PREFIX" \
    -DSnappy_LIBRARIES="$PREFIX/lib" \
    -DSnappy_INCLUDE_DIRS="$PREFIX/include"

  local NJOBS
  NJOBS=$(( $(nproc) / 2 ))
  NJOBS=$((NJOBS>0 ? NJOBS : 1))
  make -j $NJOBS
  make install
}

install_libmicrohttpd () {
  cd ./opt/gnuweb/libmicrohttpd/
  ./configure \
    --prefix="$PREFIX" \
    --disable-https \
    --disable-curl  \
    --disable-dauth
  ${MAKE} install

  echo "[+] Successfully installed libmicrohttpd"
}

install_snappy () {
  cd ./opt/git/snappy

  echo "[+] Configuring snappy"
  mkdir -p build
  cd build
  cmake .. \
    -G"Unix Makefiles" \
    -DCMAKE_INSTALL_PREFIX:PATH="" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DSNAPPY_BUILD_TESTS=OFF \
    -DSNAPPY_BUILD_BENCHMARKS=OFF
  echo "[+] Configured snappy"

  echo "[+] Building snappy"
  make -j
  echo "[+] Successfully built snappy"

  echo "[+] Installing snappy to $PREFIX"
  make install DESTDIR="$PREFIX"
  echo "[+] Successfully installed snappy"
}

install_libff () {
  cd ./opt/git/libff
  git submodule init
  git submodule update
  mkdir -p build
  cd build
  cmake .. \
    -G"Unix Makefiles" \
    -DCMAKE_INSTALL_PREFIX:PATH="$PREFIX" \
    -DCMAKE_INSTALL_LIBDIR="lib"
  local NJOBS
  NJOBS=$(( $(nproc) / 2 ))
  NJOBS=$((NJOBS>0 ? NJOBS : 1))
  make -j $NJOBS
  make install
}

install () {
  CC="$(command -v gcc)"
  cc="$CC"
  export CC
  export cc
  ( install_zlib      )
  ( install_bzip2     )
  ( install_zstd      )
  ( install_secp256k1 )
  ( install_snappy    )
  ( install_rocksdb   )
  ( install_openssl   )
  ( install_libmicrohttpd )
  ( install_libff     )

  # Remove cmake and pkgconfig files, so we don't accidentally
  # depend on them.
  rm -rf ./opt/lib/cmake ./opt/lib/pkgconfig ./opt/lib64/pkgconfig

  # Merge lib64 with lib
  if [[ -d ./opt/lib64 ]]; then
    find ./opt/lib64/ -mindepth 1 -exec mv -t ./opt/lib/ {} +
    rm -rf ./opt/lib64
  fi

  # Remove cmake and pkgconfig files, so we don't accidentally
  # depend on them.
  rm -rf ./opt/lib/cmake ./opt/lib/pkgconfig

  echo "[~] Done!"
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
