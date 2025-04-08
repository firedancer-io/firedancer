#!/bin/bash

set -euxo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

#TMPDIR=$(find $HOME -maxdepth 1 -type d -regex ".*tmp-.*")
TMPDIR=../test-ledger
cd ../test-ledger

SHRED_VERSION=1234

cleanup() {
  sudo killall -9 -q firedancer-dev || true
  sudo $FD_DIR/build/native/$CC/bin/firedancer-dev configure fini all --config $TMPDIR/firedancer-dev.toml >/dev/null 2>&1 || true
}

trap cleanup EXIT SIGINT SIGTERM

FD_DIR="$SCRIPT_DIR/../.."

sudo killall -9 -q firedancer-dev || true

# if fd_frank_ledger is not on path then use the one in the home directory
if ! command -v firedancer-dev > /dev/null; then
  PATH="$FD_DIR/build/native/$CC/bin":$PATH
fi

_PRIMARY_INTERFACE=bond0
PRIMARY_IP=$(ip addr show $_PRIMARY_INTERFACE | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)

echo "
name = \"fd1\"
[layout]
    affinity = \"1-61\"
    bank_tile_count = 20
    verify_tile_count = 20
    shred_tile_count = 4
[gossip]
    entrypoints = [\"$PRIMARY_IP:8001\"]
    port = 8700
[tiles]
    [tiles.repair]
        repair_intake_listen_port = 8701
        repair_serve_listen_port = 8702
    [tiles.replay]
        # capture = \"firedancer_dev.solcap\"
        blockstore_publish = true
        genesis = \"genesis.bin\"
        funk_sz_gb = 32
        funk_rec_max = 10000000
        funk_txn_max = 1024
        cluster_version = 2004
    #[tiles.net]
        #interface = \"$_PRIMARY_INTERFACE\"
        #xdp_mode = \"drv\"
[log]
    path = \"firedancer_dev_leader.log\"
    level_stderr = \"INFO\"
    level_flush = \"ERR\"
[development]
    topology = \"firedancer\"
    [development.bench]
        larger_max_cost_per_block = true
        larger_shred_limits_per_block = true
[consensus]
    vote = true
    identity_path = \"validator-keypair.json\"
    vote_account_path = \"vote-account-keypair.json\"
    expected_shred_version = $SHRED_VERSION
" > firedancer-dev.toml

sudo $FD_DIR/build/native/$CC/bin/firedancer-dev configure init kill --config $(readlink -f firedancer-dev.toml)
sudo $FD_DIR/build/native/$CC/bin/firedancer-dev configure init hugetlbfs --config $(readlink -f firedancer-dev.toml)
sudo $FD_DIR/build/native/$CC/bin/firedancer-dev configure init ethtool-channels --config $(readlink -f firedancer-dev.toml)
sudo $FD_DIR/build/native/$CC/bin/firedancer-dev configure init ethtool-gro ethtool-loopback --config $(readlink -f firedancer-dev.toml)
sudo $FD_DIR/build/native/$CC/bin/firedancer-dev configure init keys --config $(readlink -f firedancer-dev.toml)

sudo gdb -iex="set debuginfod enabled on" -ex=r --args $FD_DIR/build/native/$CC/bin/firedancer-dev dev --no-configure --log-path $(readlink -f firedancer-dev.log) --config $(readlink -f firedancer-dev.toml)
