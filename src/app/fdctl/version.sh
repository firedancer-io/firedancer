#!/bin/sh

# This script generates the version.h and version.env files.

set -ex

if [ ! -d solana ] || [ ! -f solana/Cargo.toml ]; then
  echo 'Agave submodule not checked out.  Please run `git submodule update --init`' >&2
  exit 1
fi

SOLANA_VERSION="$(grep '^version = ' solana/Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')"
SOLANA_VERSION_MAJOR="$(echo "$SOLANA_VERSION" | cut -d. -f1)"
SOLANA_VERSION_MINOR="$(echo "$SOLANA_VERSION" | cut -d. -f2)"
SOLANA_VERSION_PATCH="$(echo "$SOLANA_VERSION" | cut -d. -f3)"
VERSION_COMMIT="$(git rev-parse HEAD)"

if [ -z "$SOLANA_VERSION_MAJOR"  ]; then echo "Failed to detect SOLANA_VERSION_MAJOR"  >&2; exit 1; fi
if [ -z "$SOLANA_VERSION_MINOR"  ]; then echo "Failed to detect SOLANA_VERSION_MINOR"  >&2; exit 1; fi
if [ -z "$SOLANA_VERSION_PATCH"  ]; then echo "Failed to detect SOLANA_VERSION_PATCH"  >&2; exit 1; fi
if [ -z "$VERSION_COMMIT" ]; then echo "Failed to detect SOLANA_VERSION_COMMIT" >&2; exit 1; fi

FIREDANCER_VERSION_BASE="$(cat src/app/fdctl/version.txt)"
FIREDANCER_VERSION_MAJOR="$(echo "$FIREDANCER_VERSION_BASE" | cut -d. -f1)"
FIREDANCER_VERSION_MINOR="$(echo "$FIREDANCER_VERSION_BASE" | cut -d. -f2)"
FIREDANCER_VERSION_PATCH="$(printf %d%02d%02d "$SOLANA_VERSION_MAJOR" "$SOLANA_VERSION_MINOR" "$SOLANA_VERSION_PATCH")"

cat > src/app/fdctl/version.env << EOF
export FIREDANCER_VERSION_MAJOR=$FIREDANCER_VERSION_MAJOR
export FIREDANCER_VERSION_MINOR=$FIREDANCER_VERSION_MINOR
export FIREDANCER_VERSION_PATCH=$FIREDANCER_VERSION_PATCH
export FIREDANCER_CI_COMMIT=$VERSION_COMMIT
EOF

cat > src/app/fdctl/version.h << EOF
#ifndef HEADER_fd_src_app_fdctl_version_h
#define HEADER_fd_src_app_fdctl_version_h

#define FD_VERSION_MAJOR (${FIREDANCER_VERSION_MAJOR}U)
#define FD_VERSION_MINOR (${FIREDANCER_VERSION_MINOR}U)
#define FD_VERSION_PATCH (${FIREDANCER_VERSION_PATCH}U)
#define FD_GIT_COMMIT "$VERSION_COMMIT"

#endif /* HEADER_fd_src_app_fdctl_version_h */
EOF
