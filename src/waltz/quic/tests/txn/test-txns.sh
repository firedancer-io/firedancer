#!/bin/bash
# bash strict mode
set -euo pipefail
IFS=$'\n\t'
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "${SCRIPT_DIR}"
rm -f /tmp/test-transactions.log
TX_FILE=${2:-tx}

cat $TX_FILE | \
    sudo nsenter --net=/var/run/netns/veth_test_xdp_1 ./build/native/gcc/unit-test/test_quic_txns

# echo filename: $TX_FILE
# sudo nsenter --net=/var/run/netns/veth_test_xdp_1 gdb --args ./build/native/gcc/unit-test/test_quic_txns
