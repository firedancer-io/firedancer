#!/usr/bin/env bash

set -e

cd "$(dirname "$0")"
PREFIX="$(pwd)/opt"
DIST="$(pwd)/dist"

if [[ ! -d "doxygen" ]]; then
  echo "[+] Downloading Doxygen"
  git clone --depth=1 https://github.com/doxygen/doxygen
  echo "[+] Doxygen download finished"
else
  echo "[~] Doxygen repo already checked out"
fi

if [[ ! -f "opt/bin/doxygen" ]]; then
  echo "[+] Building Doxygen"
  rm -rf opt
  rm -rf doxygen/build
  mkdir opt
  (
    cd doxygen
    cmake -B build \
      -DCMAKE_INSTALL_PREFIX:PATH="$PREFIX" \
      -DCMAKE_C_FLAGS_RELEASE="-O1" \
      -Duse_sys_sqlite3=ON \
      -Duse_libclang=ON
    cmake --build build -j
    cmake --build build -- install
  )
  echo "[+] Finished building Doxygen"
else
  echo "[~] Doxygen already built"
fi

echo "[+] Running Doxygen"
rm -rf "$DIST"
(
  cd ../..
  OUTPUT_DIRECTORY="$DIST" \
  ./contrib/doxygen/opt/bin/doxygen ./contrib/doxygen/Doxyfile
)
echo "[+] Done"
