#!/bin/bash -f

set -e

# Pull the latest code
cd $FD_NIGHTLY_REPO_DIR
git checkout $FD_NIGHTLY_BRANCH
git pull origin $FD_NIGHTLY_BRANCH
export FD_NIGHTLY_COMMIT=$(git rev-parse HEAD)

# Set up environment
PATH=/opt/rh/gcc-toolset-12/root/usr/bin:$PATH
export PATH
PKG_CONFIG_PATH=/usr/lib64/pkgconfig:$PKG_CONFIG_PATH

make distclean && make clean
./deps.sh nuke
FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh +dev fetch check install
source ~/.cargo/env
make -j

# Run the tests
make run-runtime-test-nightly > ~/nightly_run.txt
