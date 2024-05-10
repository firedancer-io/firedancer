#!/usr/bin/env bash

set -euo pipefail

# Install prefix
cd ../../..
PREFIX="$(pwd)/opt"

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
  mkdir -pv ./opt/gnuweb
  checkout_gnuweb libmicrohttpd https://ftp.gnu.org/gnu/libmicrohttpd/ "libmicrohttpd-0.9.77"
}

install_libmicrohttpd () {
  cd ./opt/gnuweb/libmicrohttpd/
  ./configure \
    --prefix="$PREFIX" \
    --disable-https \
    --disable-curl  \
    --disable-dauth \
    --with-pic
  make -j
  make install

  echo "[+] Successfully installed libmicrohttpd"
}

install () {
  CC="$(command -v gcc)"
  cc="$CC"
  export CC
  export cc

  ( install_libmicrohttpd )

  echo "[~] Done!"
}

ACTION=0
while [[ $# -gt 0 ]]; do
  case $1 in
    fetch)
      shift
      fetch
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
  fetch
  install
fi
