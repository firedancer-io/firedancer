#!/bin/bash
set -xeuo

# Abort if our local tree is unclean
if [ ! "$(git status --porcelain | wc -l)" -eq "0" ]; then
    echo "Current checkout unclean: commit or stash changes before publishing"
    exit 1
fi

# Check we have checked out the tag with the same version as the firedancer-sys package.
# e.g. if the firedancer-sys package has version 0.5.2, git tag firedancer-sys-0.5.2
# point to the current HEAD.
CRATE_VERSION=$(awk '/version/ { gsub(/"/, "", $3); print $3; exit}' Cargo.toml)
GIT_TAG=firedancer-sys-$CRATE_VERSION
if [ -z "$( git tag --list "$GIT_TAG" )" ]; then
  echo "Current checkout has incorrect tag: expecting $GIT_TAG"
  exit 1
fi

rm -rf "${PWD}/staging"
mkdir -p "${PWD}/staging"
cd "${PWD}/staging"
ln -s ../../../../Makefile Makefile
ln -s ../../../../config config
ln -s ../../../../src src

cd "${PWD}"
# Need to allow dirty because of the symlinks we created
cargo package --allow-dirty
rm -rf "${PWD}/staging"
