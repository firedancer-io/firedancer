#!/bin/bash

set -euxo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd ../test-ledger/

FD_DIR="$SCRIPT_DIR/../.."

OBJDIR=${OBJDIR:-build/native/${CC}}

cleanup() {
  sudo killall -9 -q fddev || true
#   $FD_DIR/$OBJDIR/bin/fddev configure fini all --config fddev.toml
}
trap cleanup EXIT SIGINT SIGTERM

sudo killall -9 -q fddev || true

# if fd_frank_ledger is not on path then use the one in the home directory
if ! command -v fddev > /dev/null; then
  PATH="$FD_DIR/$OBJDIR/bin":$PATH
fi

_PRIMARY_INTERFACE=$(ip route show default | awk '/default/ {print $5}')
PRIMARY_IP=$(ip addr show $_PRIMARY_INTERFACE | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)

while [ $(solana -u localhost epoch-info --output json | jq .blockHeight) -le 150 ]; do
  sleep 1
done

FULL_SNAPSHOT=$(wget -c -nc -S --trust-server-names http://$PRIMARY_IP:8899/snapshot.tar.bz2 |& grep 'location:' | cut -d/ -f2)
SHRED_VERS=`grep shred_version: validator.log | sed -e 's@.*shred_version: \([0-9]*\).*@\1@'`

sudo rm -f /tmp/localnet.funk
sudo rm -f /tmp/localnet.blockstore

echo "
name = \"fd1\"
[layout]
    affinity = \"auto\"
    bank_tile_count = 1
    verify_tile_count = 16
    shred_tile_count = 1
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
        snapshot = \"$FULL_SNAPSHOT\"
        tpool_thread_count = 8
        funk_sz_gb = 32
        funk_rec_max = 10000000
        funk_txn_max = 1024
        funk_file = \"/tmp/localnet.funk\"
        cluster_version = \"2.0.14\"
    [tiles.pack]
        use_consumed_cus = false
[consensus]
    expected_shred_version = $SHRED_VERS
    vote = true
    identity_path = \"fd-identity-keypair.json\"
    vote_account_path = \"fd-vote-keypair.json\"
[blockstore]
    shred_max = 1024
    block_max = 300
    idx_max = 1024
    txn_max = 1024
    alloc_max = 10737418240
    file = \"/tmp/localnet.blockstore\"
[development]
    sandbox = false
    no_agave = true
    no_clone = true
[log]
    path = \"fddev.log\"
    level_stderr = \"INFO\"
    level_logfile = \"NOTICE\"
    level_flush = \"ERR\"
[rpc]
    port = 8123
    extended_tx_metadata_storage = true
" > fddev.toml

sudo $FD_DIR/$OBJDIR/bin/fddev configure init kill --config $(readlink -f fddev.toml)
sudo $FD_DIR/$OBJDIR/bin/fddev configure init hugetlbfs --config $(readlink -f fddev.toml)
sudo $FD_DIR/$OBJDIR/bin/fddev configure init ethtool-channels --config $(readlink -f fddev.toml)
sudo $FD_DIR/$OBJDIR/bin/fddev configure init ethtool-gro --config $(readlink -f fddev.toml)
sudo $FD_DIR/$OBJDIR/bin/fddev configure init keys --config $(readlink -f fddev.toml)

sudo gdb -iex="set debuginfod enabled on" -ex=r --args $FD_DIR/$OBJDIR/bin/fddev dev --no-configure --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) --no-solana --no-sandbox --no-clone
