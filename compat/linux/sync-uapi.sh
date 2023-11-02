#!/usr/bin/env bash

set -eu -o pipefail

# This script fetches a Linux kernel tarball and extracts the kernel
# uapi headers.

LINUX_VERSION="6.5.9"
LINUX_PREFIX="linux-${LINUX_VERSION}"
LINUX_TARBALL="${LINUX_PREFIX}.tar.xz"
DIST_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/${LINUX_TARBALL}"
DIST_SHA="c6662f64713f56bf30e009c32eac15536fad5fd1c02e8a3daf62a0dc2f058fd5"
DEST_DIR=compat/linux/include

UAPI_FILES=(
  include/uapi/linux/bpf.h
  include/uapi/linux/bpf_common.h
  include/uapi/linux/netlink.h
  include/uapi/linux/rtnetlink.h
  include/uapi/linux/neighbour.h
  include/uapi/linux/if_addr.h
  include/uapi/linux/if_link.h
  include/uapi/linux/if_packet.h
  include/uapi/linux/if_xdp.h
)

# Download tarball

mkdir -p build/dist
if [[ ! -f build/dist/"${LINUX_TARBALL}" ]] \
   || ! sha256sum -c <<< "${DIST_SHA}  build/dist/${LINUX_TARBALL}"
then
  echo "Fetching ${LINUX_TARBALL}"
  curl -L "${DIST_URL}" -o build/dist/"${LINUX_TARBALL}"
else
  echo "Using cached ${LINUX_TARBALL}"
fi

# Git sanity checks to prevent data loss

if [[ ! -z "$(git clean -n -f ${DEST_DIR})" ]]; then
  echo "FAIL: Found uncommitted files in ${DEST_DIR}" >&2
  git clean -n -f ${DEST_DIR} >&2
  exit 1
fi
if [[ ! -z "$(git status --porcelain ${DEST_DIR})" ]]; then
  echo "FAIL: Found staged changes in ${DEST_DIR}" >&2
  exit 1
fi

# Untar

rm -rf build/dist/"${LINUX_PREFIX}"
tar xpf build/dist/"${LINUX_TARBALL}" \
  -C build/dist \
  "${UAPI_FILES[@]/#/linux-${LINUX_VERSION}/}"

# Copy headers

mkdir -p "${DEST_DIR}"
mv build/dist/linux-"${LINUX_VERSION}"/include/uapi/linux "${DEST_DIR}/linux"

# Create commit

git add "${DEST_DIR}"
if git diff --staged --exit-code "${DEST_DIR}" >/dev/null; then
  echo "No changes to commit"
  exit 0
fi
git commit \
  -m "compat/linux: import Linux ${LINUX_VERSION} uapi" \
  --author "Linux Contributors <git@vger.kernel.org>"
