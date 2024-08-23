#!/bin/bash

set -euxo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

TMPDIR=$(find $HOME -maxdepth 1 -type d -regex ".*tmp-.*")
cd $TMPDIR

SHRED_VERSION=1234

cleanup() {
  sudo killall -9 -q fddev || true
  sudo $FD_DIR/build/native/$CC/bin/fddev configure fini all --config $TMPDIR/fddev.toml >/dev/null 2>&1 || true
}

trap cleanup EXIT SIGINT SIGTERM

FD_DIR="$SCRIPT_DIR/../.."

sudo killall -9 -q fddev || true

# if fd_frank_ledger is not on path then use the one in the home directory
if ! command -v fddev > /dev/null; then
  PATH="$FD_DIR/build/native/$CC/bin":$PATH
fi

_PRIMARY_INTERFACE=enp75s0f0
PRIMARY_IP=$(ip addr show $_PRIMARY_INTERFACE | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)

echo "
name = \"fd1\"
[layout]
    affinity = \"1-38\"
    bank_tile_count = 1
    verify_tile_count = 16
    shred_tile_count = 2
[gossip]
    port = 8700
[tiles]
    [tiles.gossip]
        entrypoints = [\"$PRIMARY_IP\"]
        peer_ports = [8001]
        gossip_listen_port = 8700
    
    [tiles.repair]
        repair_intake_listen_port = 8701
        repair_serve_listen_port = 8702
    [tiles.replay]
        capture = \"fddev.solcap\"
        blockstore_publish = true
        genesis = \"genesis.bin\"
        tpool_thread_count = 8
        funk_sz_gb = 32
        funk_rec_max = 10000000
        funk_txn_max = 1024
        cluster_version = 2004
    [tiles.net]
        interface = \"$_PRIMARY_INTERFACE\"
[log]
    path = \"fddev_leader.log\"
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
" > fddev.toml

sudo $FD_DIR/build/native/$CC/bin/fddev configure init kill --config $(readlink -f fddev.toml)
sudo $FD_DIR/build/native/$CC/bin/fddev configure init hugetlbfs --config $(readlink -f fddev.toml)
sudo $FD_DIR/build/native/$CC/bin/fddev configure init ethtool-channels --config $(readlink -f fddev.toml)
sudo $FD_DIR/build/native/$CC/bin/fddev configure init ethtool-gro --config $(readlink -f fddev.toml)
sudo $FD_DIR/build/native/$CC/bin/fddev configure init keys --config $(readlink -f fddev.toml)

sudo gdb -iex="set debuginfod enabled on" -ex=r --args $FD_DIR/build/native/$CC/bin/fddev dev --no-configure --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) --no-solana --no-sandbox --no-clone
