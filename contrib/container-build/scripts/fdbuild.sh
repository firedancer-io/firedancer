#!/bin/bash
set -xeo pipefail

GITDIR=/build/src
source "$HOME/.cargo/env"

git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git $GITDIR
cd "$GITDIR"

# Allow for a tag, release, or branch
[ -n "$2" ] && git checkout "$2"

# Currently needed to build and install openssl build libs that support QUIC
./deps.sh install

# Do the thing
MACHINE=$1 make -j fdctl solana

cd build
for dir in $(find . -name bin -type d)
  do mkdir -p /build/out/$dir
    cp $dir/* /build/out/$dir/
done

echo "You can find build output in ~/build"
