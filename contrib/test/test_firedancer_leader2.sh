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

while [ $(solana -u localhost epoch-info --output json | jq .blockHeight) -le 150 ]; do
  sleep 1
done

# FULL_SNAPSHOT=$(wget -c -nc -S --trust-server-names http://$PRIMARY_IP:8899/snapshot.tar.bz2 |& grep 'location:' | cut -d/ -f2)

echo "
name = \"fd1\"
[layout]
    affinity = \"1-60\"
    quic_tile_count = 1
    bank_tile_count = 6
    verify_tile_count = 30
    shred_tile_count = 1
[gossip]
    port = 8700
[tiles]
    [tiles.pack]
        max_pending_transactions = 4096
    [tiles.gossip]
        entrypoints = [\"$PRIMARY_IP\"]
        peer_ports = [8001]
        gossip_listen_port = 8700
    [tiles.repair]
        repair_intake_listen_port = 8701
        repair_serve_listen_port = 8702
    [tiles.replay]
        # capture = \"fddev.solcap\"
        # blockstore_checkpt = \"fddev-blockstore.checkpt\"
        blockstore_publish = true
        snapshot = \"$(ls snapshot-* | head -n1)\"
        tpool_thread_count = 7
        funk_sz_gb = 16
        funk_rec_max = 10000000
        funk_txn_max = 1024
        cluster_version = 1180
    [tiles.shred]
        max_pending_shred_sets = 16384
[log]
    path = \"fddev.log\"
    level_stderr = \"INFO\"
    level_flush = \"ERR\"
[development]
    topology = \"firedancer\"
[consensus]
    expected_shred_version = 3232
    vote = true
    identity_path = \"validator-keypair.json\"
    vote_account_path = \"vote-account-keypair.json\"
[development]
    [development.bench]
        larger_max_cost_per_block = true
        larger_shred_limits_per_block = true

" > fddev.toml

sudo $FD_DIR/build/native/$CC/bin/fddev configure init kill --config $(readlink -f fddev.toml)
sudo $FD_DIR/build/native/$CC/bin/fddev configure init hugetlbfs --config $(readlink -f fddev.toml)
sudo $FD_DIR/build/native/$CC/bin/fddev configure init keys --config $(readlink -f fddev.toml)

sudo gdb -iex="set debuginfod enabled on" -ex=r --args $FD_DIR/build/native/$CC/bin/fddev dev --no-configure --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) --no-solana --no-sandbox --no-clone
