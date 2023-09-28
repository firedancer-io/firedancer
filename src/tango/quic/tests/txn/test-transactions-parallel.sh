#!/bin/bash
# bash strict mode
set -euo pipefail
IFS=$'\n\t'
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "${SCRIPT_DIR}"
rm -f /tmp/run-*
NUM_TRANSACTIONS=${1:-8102}
TX_FILE=${2:-all.txns}
NUM_JOBS=${3:-64}
set +e
#head -n $NUM_TRANSACTIONS $TX_FILE | parallel -j $NUM_JOBS "sudo nsenter --net=/var/run/netns/veth_test_xdp_1 /home/llamb/code/firedancer-playground/test_quic_txn/target/debug/test_quic_txn --payload-base64-encoded {} > /tmp/run-{#} 2>&1"
head -n $NUM_TRANSACTIONS $TX_FILE | parallel -j $NUM_JOBS "sudo nsenter --net=/var/run/netns/veth_test_xdp_1 ./build/native/gcc/unit-test/test_quic_txn --payload-base64-encoded {} > /tmp/run-{#} 2>&1"
set -e
echo " $(grep -E 'rc 1|rc 2|rc 3' /tmp/run* | wc -l) / $NUM_TRANSACTIONS successfully transmitted by clients ($NUM_JOBS at a time)"
