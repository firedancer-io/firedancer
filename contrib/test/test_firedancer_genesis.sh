#!/bin/bash

set -euxo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd ../test-ledger/

cleanup() {
  sudo killall -9 -q fddev || true
  fddev configure fini all >/dev/null 2>&1 || true
}

trap cleanup EXIT SIGINT SIGTERM

FD_DIR="$SCRIPT_DIR/../.."

sudo killall -9 -q fddev || true

# if fd_frank_ledger is not on path then use the one in the home directory
if ! command -v fddev > /dev/null; then
  PATH="$FD_DIR/build/native/$CC/bin":$PATH
fi

_PRIMARY_INTERFACE=$(ip route show default | awk '/default/ {print $5}')
PRIMARY_IP=$(ip addr show $_PRIMARY_INTERFACE | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)

echo "
name = \"fd1test\"
[layout]
    affinity = \"1-37\"
    bank_tile_count = 1
    verify_tile_count = 16
    shred_tile_count = 1
[gossip]
    entrypoints = [\"$PRIMARY_IP:8001\"]
    port = 8700
[tiles]
    [tiles.repair]
        repair_intake_listen_port = 8701
        repair_serve_listen_port = 8702
    [tiles.replay]
        capture = \"fddev.solcap\"
        blockstore_publish = true
        blockstore_checkpt = \"fddev-blockstore.checkpt\"
        genesis = \"genesis.bin\"
        tpool_thread_count = 8
        funk_sz_gb = 32
        funk_rec_max = 10000000
        funk_txn_max = 1024
        cluster_version = 2004
[log]
    path = \"fddev.log\"
    level_stderr = \"INFO\"
    level_flush = \"ERR\"
[development]
    topology = \"firedancer\"
[consensus]
    vote = true
    identity_path = \"fd-identity-keypair.json\"
    vote_account_path = \"fd-vote-keypair.json\"
" > fddev.toml

sudo $FD_DIR/build/native/$CC/bin/fddev configure init kill --config $(readlink -f fddev.toml)
sudo $FD_DIR/build/native/$CC/bin/fddev configure init hugetlbfs --config $(readlink -f fddev.toml)
sudo $FD_DIR/build/native/$CC/bin/fddev configure init ethtool-channels --config $(readlink -f fddev.toml)
sudo $FD_DIR/build/native/$CC/bin/fddev configure init ethtool-gro ethtool-loopback --config $(readlink -f fddev.toml)
sudo $FD_DIR/build/native/$CC/bin/fddev configure init keys --config $(readlink -f fddev.toml)

sudo gdb -iex="set debuginfod enabled on" -ex=r --args $FD_DIR/build/native/$CC/bin/fddev dev --no-configure --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) --no-solana --no-sandbox --no-clone
