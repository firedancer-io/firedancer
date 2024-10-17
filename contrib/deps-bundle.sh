#!/usr/bin/env bash

set -e

# deps-bundle.sh pack a redistributable bundle of build dependencies.
#
# This offers an alternative to building dependencies from source,
# such that only a recent compiler and linker is required (and no other
# tools like perl or bison).  Also requires the Zstandard compression
# tool and GNU tar.
#
# To start, first create the a dependency prefix at ./opt using deps.sh.
# Then, run this script to create deps-bundle.tar.zst which contains
# only static libraries and includes.
#
# The resulting bundle is in the order of 13 MB compressed (as of June
# 2023, including OpenSSL and RocksDB).

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"/..

if [ -n "$MSAN" ]; then
    bundle="deps-bundle-msan.tar.zst"
    prefix="opt-msan"
else
    bundle="deps-bundle.tar.zst"
    prefix="opt"
fi

rm -f "$bundle"

tar -Izstd -cf "$bundle" "./$prefix"/{include,lib} 

echo "[+] Created $bundle"

# Now you can commit this file to blob storage such as Git LFS.
