#!/bin/bash
# bash strict mode
set -euo pipefail
IFS=$'\n\t'
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "${SCRIPT_DIR}"
rm -f /tmp/test-transactions.log
NUM_TRANSACTIONS=${1:-1000}
TX_FILE=${2:-tx}
head -n $NUM_TRANSACTIONS $TX_FILE | while read line; do
    echo $line
    sudo nsenter --net=/var/run/netns/veth_test_xdp_1 fddeva txn --payload-base64-encoded $line 2>&1 | tee -a /tmp/test-transactions.log
done
echo " $(grep -E 'rc 1|rc 2|rc 3' /tmp/test-transactions.log | wc -l) / $NUM_TRANSACTIONS successfully transmitted by clients"
