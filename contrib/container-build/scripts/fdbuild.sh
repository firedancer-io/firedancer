#!/bin/bash
set -eo pipefail

GITDIR=/build/src
. "$HOME/.cargo/env"

git clone --recurse-submodules https://github.com/firedancer-io/firedancer.git $GITDIR
cd "$GITDIR"

# Allow for a tag, release, or branch
[ -n "$3" ] && git checkout "$3"

# Currently needed to build and install openssl build libs that support QUIC
./deps.sh install

# Do the thing
MACHINE=$1 make -j fdctl solana

cd build
for dir in $(find . -name bin -type d)
  do mkdir -p /build/out/"$2"/"$dir"
    cp "$dir"/* /build/out/"$2"/"$dir"/
done

echo "You can find build output in ~/build"
