#!/bin/bash

# bash strict mode
set -xeuo pipefail
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "${SCRIPT_DIR}/../../"

# start fddev, send a single transaction, and if everything works return 0
FDDEV=./build/native/gcc/bin/fddev
# TODO: For some reason /tmp does not work on the github runner for --log-path
timeout --preserve-status --kill-after=20 15 $FDDEV configure init all --netns --log-path ~/log
timeout --preserve-status --kill-after=20 15 $FDDEV --no-configure --netns --log-path ~/log &
FDDEV_PID=$!
timeout --preserve-status --kill-after=20 15 $FDDEV txn --netns --log-path ~/log2
RETVAL=$?
sudo kill $FDDEV_PID
exit $RETVAL
