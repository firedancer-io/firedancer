#!/bin/bash

# bash strict mode
set -euo pipefail
IFS=$'\n\t'
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "${SCRIPT_DIR}/../../"

# create test configuration for fddev
TMPDIR=$(mktemp -d)
cat > ${TMPDIR}/config.toml <<EOM
[development]
    sudo = true
    sandbox = true
    [development.netns]
        enabled = true
[tiles.quic]
    interface = "veth_test_xdp_0"
[layout]
    affinity = "0-9"
    verify_tile_count = 2
    bank_tile_count = 2
EOM
export FIREDANCER_CONFIG_TOML=${TMPDIR}/config.toml

# acquire and initialize everything to build
echo y | ./deps.sh
git submodule init
git submodule update

# Make absolutely sure we're working with a clean build directory
# TODO: make clean does not delete everything in the build directory
rm -rf build

# build
./contrib/make-j

# start fddev, send a single transaction, and if everything works return 0
FDDEV=./build/native/gcc/bin/fddev
TEST_QUIC_TXN=$(find -name test_quic_txn -type f -executable)
set +e
# TODO: this is flakey run give it multiple chances
for i in {1..10}; do
    sudo /home/runner/firedancer-opts/build/native/gcc/bin/fd_shmem_cfg fini || true
    timeout --preserve-status 5 ${FDDEV} &
    FDDEV_PID=$!
    sleep 4
    sudo nsenter --net=/var/run/netns/veth_test_xdp_1 ${TEST_QUIC_TXN}
    RETVAL=$?
    wait $FDDEV_PID
    if [ $RETVAL -eq 0 ]; then
        exit 0
    fi
done

exit 1
