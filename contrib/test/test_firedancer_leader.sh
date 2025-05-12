#!/bin/bash

set -euxo pipefail

IFS=$'\n\t'
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
FD_DIR="$SCRIPT_DIR/../.."
OBJDIR=${OBJDIR:-build/native/${CC}}
AGAVE_PATH=${AGAVE_PATH:='./agave/target/release'}

cd ../test-ledger/

cleanup() {
  sudo killall -9 -q firedancer-dev || true
#   $FD_DIR/$OBJDIR/bin/firedancer-dev configure fini all --config firedancer-dev.toml
}
trap cleanup EXIT SIGINT SIGTERM

sudo killall -9 -q firedancer-dev || true

# if fd_frank_ledger is not on path then use the one in the home directory
if ! command -v firedancer-dev > /dev/null; then
  PATH="$FD_DIR/$OBJDIR/bin":$PATH
fi

_PRIMARY_INTERFACE=$(ip route show default | awk '/default/ {print $5}')
PRIMARY_IP=$(ip addr show $_PRIMARY_INTERFACE | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)

while [ $($AGAVE_PATH/solana -u localhost epoch-info --output json | jq .blockHeight) -le 150 ]; do
  sleep 1
done

FULL_SNAPSHOT=$(wget -c -nc -S --trust-server-names http://$PRIMARY_IP:8899/snapshot.tar.bz2 |& grep 'location:' | cut -d/ -f2)
SHRED_VERS=`grep shred_version: validator.log | sed -e 's@.*shred_version: \([0-9]*\).*@\1@'`

sudo rm -f /tmp/localnet.funk
sudo rm -f /tmp/localnet.blockstore
sudo rm -f firedancer-dev.log

echo "
[layout]
    verify_tile_count = 16
[gossip]
    entrypoints = [\"$PRIMARY_IP:8001\"]
    port = 8700
[tiles]
    [tiles.repair]
        repair_intake_listen_port = 8701
        repair_serve_listen_port = 8702
    [tiles.replay]
        capture = \"firedancer-dev.solcap\"
        snapshot = \"$FULL_SNAPSHOT\"
        cluster_version = \"2.0.14\"
    [tiles.gui]
        enabled = false
        gui_listen_address = \"64.130.51.169\"
        gui_listen_port = 8080
[consensus]
    expected_shred_version = $SHRED_VERS
    vote = true
[paths]
    identity_key = \"fd-identity-keypair.json\"
    vote_account = \"fd-vote-keypair.json\"
[blockstore]
    shred_max = 16777216
    block_max = 4096
    idx_max = 1024
    txn_max = 1024
    alloc_max = 10737418240
    file = \"/tmp/localnet.blockstore\"
[funk]
    max_account_records = 10000000
    heap_size_gib = 32
    max_database_transactions = 1024
[log]
    path = \"firedancer-dev.log\"
    level_stderr = \"INFO\"
    level_logfile = \"NOTICE\"
    level_flush = \"ERR\"
[rpc]
    port = 8123
    extended_tx_metadata_storage = true
" > firedancer-dev.toml

sudo $FD_DIR/$OBJDIR/bin/firedancer-dev configure init kill --config $(readlink -f firedancer-dev.toml)
sudo $FD_DIR/$OBJDIR/bin/firedancer-dev configure init hugetlbfs --config $(readlink -f firedancer-dev.toml)
sudo $FD_DIR/$OBJDIR/bin/firedancer-dev configure init ethtool-channels --config $(readlink -f firedancer-dev.toml)
sudo $FD_DIR/$OBJDIR/bin/firedancer-dev configure init ethtool-gro ethtool-loopback --config $(readlink -f firedancer-dev.toml)
sudo $FD_DIR/$OBJDIR/bin/firedancer-dev configure init keys --config $(readlink -f firedancer-dev.toml)

sudo gdb -iex="set debuginfod enabled on" -ex=r --args $FD_DIR/$OBJDIR/bin/firedancer-dev dev --no-configure --log-path $(readlink -f firedancer-dev.log) --config $(readlink -f firedancer-dev.toml)
