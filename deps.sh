#!/usr/bin/env bash

set -euo pipefail

# Change into Firedancer root directory
cd "$(dirname "${BASH_SOURCE[0]}")"

# Load OS information
OS="$(uname -s)"
case "$OS" in
  Darwin)
    ID=macos
    ;;
  Linux)
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

help () {
cat <<EOF

  Usage: $0 [cmd] [args...]

  Commands are:

    help
    - Prints this message

    check
    - Runs system requirement checks for the build
    - Installs missing system packages and rustup

    fetch
    - Check out Agave submodule

EOF
  exit 0
}

fetch () {
  git submodule update --init
}

check_fedora_pkgs () {
  local REQUIRED_RPMS=(
    make               # build system
    gcc                # C compiler

    curl               # Agave (rustup)
    cmake              # Agave (RocksDB)
    clang-devel        # Agave (bindgen)
    systemd-devel      # Agave (hidapi)
    pkgconf            # Agave (hidapi)
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
    build-essential    # C compiler

    curl               # Agave (rustup)
    cmake              # Agave (protobuf-src)
    libclang-dev       # Agave (bindgen)
    pkgconf            # Agave (hidapi)
    libudev-dev        # Agave (hidapi)
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
    build-base       # C compiler
    linux-headers    # base dependency
    grep             # build system
    make             # build system

    curl             # Agave (download rustup)
  )

  echo "[~] Checking for required APK packages"

  local MISSING_APKS=( )
  for apk in "${REQUIRED_APKS[@]}"; do
    if ! apk info -e "$apk" >/dev/null; then
      MISSING_APKS+=( "$apk" )
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
  local REQUIRED_FORMULAE=(
    coreutils   # build system
  )

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
    base-devel        # C compiler, make, etc.

    curl              # Agave (rustup)
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

ACTION=0
while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help|help)
      help
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
      ACTION=1
      ;;
    *)
      echo "Unknown command: $1" >&2
      exit 1
      ;;
  esac
done

if [[ $ACTION == 0 ]]; then
  echo "[~] This will fetch, build, and install Firedancer's dependencies"
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
