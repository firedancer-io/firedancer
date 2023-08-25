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

# start fddev, send a single transaction, and if everything works return 0
FDDEV=./build/native/gcc/bin/fddev
TEST_QUIC_TXN=./build/native/gcc/unit-test/test_quic_txn
# TODO: For some reason /tmp does not work on the github runner for --log-path
timeout --preserve-status 15 $FDDEV configure init all --log-path ~/log
timeout --preserve-status 15 $FDDEV --log-path ~/log &
FDDEV_PID=$!
sleep 4
sudo nsenter --net=/var/run/netns/veth_test_xdp_1 ${TEST_QUIC_TXN}
RETVAL=$?
sudo kill $FDDEV_PID
exit $RETVAL
