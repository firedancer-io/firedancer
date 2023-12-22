#!/usr/bin/env bash

# This scripts creates a bundle containing all of the industry targets that exist in this repo (Firedancer and Solana Labs Client ones)
# For the Firedancer targets, it invokes `make industry-test`.
# For the Labs Client targets, it builds the ffi/rust project and captures all the debug artifacts matching "libdiff_.*\.so".

set -exuo pipefail

OBJDIR=$1
LIBDIR="$OBJDIR/lib"
BUNDLE="industry-bundle.zip"

INDUSTRY_TARGETS="$OBJDIR/industry-bundle-stage/targets"

cd -- "$( dirname -- "${BASH_SOURCE[0]}" )"/..

for fd_target in $(find $LIBDIR -type f -executable -name 'industry_*.so'); do
  NAME=$(basename $fd_target | sed 's/industry_\(.*\)\.so/\1/')
  mkdir -p "$INDUSTRY_TARGETS/$NAME"
  cp "$fd_target" "$INDUSTRY_TARGETS/$NAME/firedancer.so"
done

# make an archive
pushd $INDUSTRY_TARGETS/..
zip -r ../$BUNDLE targets/
popd

echo $(du -h "$OBJDIR/industry-bundle.zip")
