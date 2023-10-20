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

# start fddev, send a single transaction, and if everything works return 0
FDDEV=./build/native/clang/bin/fddev

# TODO: For some reason /tmp does not work on the github runner for --log-path
timeout --preserve-status --kill-after=20 15 $FDDEV configure init all --netns --log-path ./log
timeout --preserve-status --kill-after=20 15 $FDDEV --no-configure --netns --log-path ./log &
FDDEV_PID=$!
timeout --preserve-status --kill-after=20 15 $FDDEV txn --netns --log-path ./log2
RETVAL=$?
sudo kill $FDDEV_PID
exit $RETVAL
