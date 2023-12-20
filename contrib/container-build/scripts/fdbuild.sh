#!/bin/bash
set -xeo pipefail

GITDIR=/build/src
source "$HOME/.cargo/env"

git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git $GITDIR
cd "$GITDIR"

# Currently needed to build and install openssl build libs that support QUIC
./deps.sh install

# Do the thing
MACHINE=linux_gcc_x86_64 make -j fdctl solana

cp -v build/linux/gcc/x86_64/bin/* /build/out
echo "You can find build output in $HOME/build/out"
