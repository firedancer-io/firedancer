#!/usr/bin/env bash

set -euo pipefail

# Change into Firedancer root directory
cd "$(dirname "${BASH_SOURCE[0]}")"

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

MSAN=0
_CC="${CC:=gcc}"
_CXX="${CXX:=g++}"
EXTRA_CFLAGS="-g3"
EXTRA_CXXFLAGS=""
if [[ "$(uname -m)" == x86_64 ]]; then
  EXTRA_CFLAGS+=" -fno-omit-frame-pointer -fcf-protection=return"
  EXTRA_CXXFLAGS+=" -fno-omit-frame-pointer -fcf-protection=return"
fi
EXTRA_LDFLAGS=""

help () {
cat <<EOF

  Usage: $0 [cmd] [args...]

  If cmd is omitted, default is 'install'.

  Commands are:

    help
    - Prints this message

    check
    - Runs system requirement checks for dep build/install
    - Exits with code 0 on success

    nuke
    - Get rid of dependency checkouts
    - Get rid of all third party dependency files
    - Same as 'rm -rf $PREFIX'

    fetch
    - Fetches dependencies from Git repos into $PREFIX/git

    install
    - Builds dependencies
    - Installs all project dependencies into prefix $PREFIX

EOF
  exit 0
}

nuke () {
  rm -rf "$PREFIX"
  echo "[-] Nuked $PREFIX"
  exit 0
}

checkout_repo () {
  if [[ -d "$PREFIX/git/$1" ]]; then
    if [[ -n "$3" ]]; then
      # Tag-based repo: skip if already on the right tag
      if [[ "$(git -C "$PREFIX/git/$1" describe --tags --abbrev=0 2>/dev/null)" == "$3" ]]; then
        echo "[~] Skipping $1 fetch (already at $3)"
        return
      fi
      echo "[~] Updating $1 to $3"
      (
        cd "$PREFIX/git/$1"
        git fetch origin "$3" --tags --depth=1
        git -c advice.detachedHead=false checkout "$3"
      )
    elif [[ -n "$4" ]]; then
      # Commit-hash repo: skip if already on the right commit
      if [[ "$(git -C "$PREFIX/git/$1" rev-parse HEAD)" == "$(git -C "$PREFIX/git/$1" rev-parse "$4" 2>/dev/null)" ]]; then
        echo "[~] Skipping $1 fetch (already at $4)"
        return
      fi
      echo "[~] Updating $1 to $4"
      (
        cd "$PREFIX/git/$1"
        git fetch origin
        git -c advice.detachedHead=false checkout "$4"
      )
    else
      echo "[~] Skipping $1 fetch as \"$PREFIX/git/$1\" already exists"
    fi
  elif [[ -z "$3" ]]; then
    echo "[+] Cloning $1 from $2"
    git -c advice.detachedHead=false clone "$2" "$PREFIX/git/$1" && cd "$PREFIX/git/$1" && git reset --hard "$4"
  else
    echo "[+] Cloning $1 from $2"
    git -c advice.detachedHead=false clone "$2" "$PREFIX/git/$1" --branch "$3" --depth=1
  fi
  echo
}

fetch () {
  git submodule update --init

  mkdir -pv "$PREFIX/git"
}

check_fedora_pkgs () {
  local REQUIRED_RPMS=(
    curl               # download rustup
    diffutils          # build system
    make               # build system
    pkgconf            # build system
    gcc                # compiler
    gcc-c++            # compiler

    cmake              # Agave (RocksDB)
    clang-devel        # Agave (bindgen)
    systemd-devel      # Agave
    perl               # Agave (OpenSSL)
    protobuf-compiler  # Agave, solfuzz
  )

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
    PACKAGE_INSTALL_CMD=( dnf install -y --skip-broken ${MISSING_RPMS[*]} )
  else
    PACKAGE_INSTALL_CMD=( "${SUDO}" dnf install -y --skip-broken ${MISSING_RPMS[*]} )
  fi
}

check_debian_pkgs () {
  local REQUIRED_DEBS=(
    curl               # download rustup
    diffutils          # build system
    build-essential    # C/C++ compiler
    pkgconf            # build system

    cmake              # Agave (protobuf-src)
    libclang-dev       # Agave (bindgen)
    libudev-dev        # Agave
    protobuf-compiler  # Agave
  )

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
  local REQUIRED_APKS=(
    build-base       # C/C++ compiler
    curl             # download rustup
    linux-headers    # base dependency
    grep             # build system
    make             # build system
    perl             # OpenSSL
  )

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
  local REQUIRED_FORMULAE=( perl autoconf gettext automake flex bison protobuf coreutils )

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

  PACKAGE_INSTALL_CMD=( brew install ${MISSING_FORMULAE[*]} )
}

check_arch_pkgs () {
  local REQUIRED_PKGS=(
    base-devel        # C/C++ compiler, make, etc.
    curl              # download rustup
    cmake             # Agave (protobuf-src)
    clang             # Agave (bindgen)
    perl              # Agave (OpenSSL)
    protobuf          # Agave, solfuzz
    systemd-libs      # Agave
  )

  echo "[~] Checking for required Arch Linux packages"

  local MISSING_PKGS=( )
  for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! pacman -Q "$pkg" &>/dev/null; then
      MISSING_PKGS+=( "$pkg" )
    fi
  done

  if [[ ${#MISSING_PKGS[@]} -eq 0 ]]; then
    echo "[~] OK: Arch Linux packages required for build are installed"
    return 0
  fi

  if [[ -z "${SUDO}" ]]; then
    PACKAGE_INSTALL_CMD=( pacman -S --needed --noconfirm ${MISSING_PKGS[*]} )
  else
    PACKAGE_INSTALL_CMD=( "${SUDO}" pacman -S --needed --noconfirm ${MISSING_PKGS[*]} )
  fi
}

check () {
  DISTRO="${ID_LIKE:-${ID:-}}"
  for word in $DISTRO ; do
    case "$word" in
      fedora|debian|alpine|macos|arch)
        check_${word}_pkgs
        ;;
      rhel|centos)
        ;;
      *)
        echo "Unsupported distro $DISTRO. Your mileage may vary."
        ;;
    esac
  done

  if [[ ! -z "${PACKAGE_INSTALL_CMD[@]}" ]]; then
    echo "[!] Found missing system packages"
    echo "[?] This is fixed by the following command:"
    echo "        ${PACKAGE_INSTALL_CMD[@]}"
    if [[ "${FD_AUTO_INSTALL_PACKAGES:-}" == "1" ]]; then
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
        echo "[-] Skipping package install"
        ;;
    esac
  fi

  if [[ ! -x "$(command -v cargo)" ]]; then
    echo "[!] cargo is not in PATH"
    source "$HOME/.cargo/env" || true
  fi
  if [[ ! -x "$(command -v cargo)" ]]; then
    if [[ "${FD_AUTO_INSTALL_PACKAGES:-}" == "1" ]]; then
      choice=y
    else
      read -r -p "[?] Install rustup? (y/N) " choice
    fi
    case "$choice" in
      y|Y)
        echo "[+] Installing rustup"
        # Keep this in sync with agave/rust-toolchain.toml
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.95.0 --profile minimal
        source "$HOME/.cargo/env"
        ;;
      *)
        echo "[-] Skipping rustup install"
        ;;
    esac
  fi
}

install () {
  CC="$(command -v $_CC)"
  cc="$CC"
  export CC
  export cc

  CXX="$(command -v $_CXX)"
  cxx="$CXX"
  export CXX
  export cxx

  mkdir -p "$PREFIX/include" "$PREFIX/lib"

  # Merge lib64 with lib
  if [[ -d "$PREFIX/lib64" ]]; then
    find "$PREFIX/lib64/" -mindepth 1 -exec mv -t "$PREFIX/lib/" {} +
    rm -rf "$PREFIX/lib64"
  fi

  # Remove cmake and pkgconfig files, so we don't accidentally
  # depend on them.
  rm -rf "$PREFIX/lib/cmake" "$PREFIX/lib/pkgconfig"

  echo "[~] Done!"
}

ACTION=0
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help|help)
      help
      ;;
    "+msan")
      shift
      MSAN=1
      PREFIX="$(pwd)/opt-msan"
      _CC=clang
      EXTRA_CFLAGS+=" -fsanitize=memory"
      ;;
    nuke)
      shift
      nuke
      ACTION=1
      ;;
    fetch)
      shift
      fetch
      ACTION=1
      ;;
    check)
      shift
      check
      ACTION=1
      ;;
    install)
      shift
      install
      ACTION=1
      ;;
    *)
      echo "Unknown command: $1" >&2
      exit 1
      ;;
  esac
done

if [[ $ACTION == 0 ]]; then
  echo "[~] This will fetch, build, and install Firedancer's dependencies into $PREFIX"
  echo "[~] For help, run: $0 help"
  echo
  echo "[~] Running $0 fetch check install"

  if [[ "${FD_AUTO_INSTALL_PACKAGES:-}" == "1" ]]; then
    choice=y
  else
    read -r -p "[?] Continue? (y/N) " choice
  fi
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
