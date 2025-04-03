#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 0.410.20113"
  exit 1
fi

VERSION="$1"
TAG="v$VERSION"
OWNER="firedancer-io"
REPO="firedancer"
DEB_NAME="firedancer-tools_x86_64.deb"
URL="https://github.com/${OWNER}/${REPO}/releases/download/${TAG}/${DEB_NAME}"

TMP_DIR=$(mktemp -d)
DEB_PATH="${TMP_DIR}/${DEB_NAME}"

echo "📥 Downloading .deb from: $URL"
curl -sSLf -o "${DEB_PATH}" "$URL"

echo "📦 Installing $DEB_NAME"
sudo dpkg -i "${DEB_PATH}"

echo "✅ Firedancer tools v$VERSION installed successfully!"
