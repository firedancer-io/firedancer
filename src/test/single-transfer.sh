#!/bin/bash

# bash strict mode
set -xeuo pipefail
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "${SCRIPT_DIR}/../../"

cleanup() {
    # TODO: We grep instead of using 'sudo ausearch -c fddev' because ausearch returns 'no matches'
    # when it should not.
    sudo grep -n fddev /var/log/audit/audit.log
}
trap cleanup EXIT INT TERM

# start fddev, send a single transfer to the locally running RPC endpoint, and if everything works return 0
FDDEV=./build/native/gcc/bin/fddev

# TODO: For some reason /tmp does not work on the github runner for --log-path
timeout --preserve-status --kill-after=20 15 $FDDEV configure init all --log-path ./log
timeout --preserve-status --kill-after=20 15 $FDDEV --no-configure --log-path ./log &
FDDEV_PID=$!
sleep 2
timeout --preserve-status --kill-after=20 15 ./solana/target/release/solana transfer -u http://127.0.0.1:8899 -k /home/$USER/.firedancer/fd1/faucet.json $($FDDEV keys pubkey /home/$USER/.firedancer/fd1/faucet.json)  0.01
RETVAL=$?
sudo kill $FDDEV_PID
exit $RETVAL
