#!/bin/bash

set -euxo pipefail

IFS=$'\n\t'
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
FD_DIR="$SCRIPT_DIR/../.."
OBJDIR=${OBJDIR:-build/native/${CC}}
KEY_PATH=${KEY_PATH:="/home/${USER}/keys"}
AGAVE_URL="64.130.55.36"

make -j firedancer-dev
cd ../test-ledger/

cleanup() {
  sudo killall -9 -q firedancer-dev || true
#  $FD_DIR/$OBJDIR/bin/firedancer-dev configure fini all --config firedancer-dev.toml
}
trap cleanup EXIT SIGINT SIGTERM

sudo killall -9 -q firedancer-dev || true

while [ $(solana -u http://${AGAVE_URL}:8899 epoch-info --output json | jq .blockHeight) -le 120 ]; do
  sleep 1
done

sudo rm -f firedancer-dev.log
# clear snapshot cache always
sudo rm -rf /home/${USER}/.firedancer/fd2/snapshots/*

echo "
[gossip]
    entrypoints = [\"${AGAVE_URL}:8001\"]
    port = 8700
[tiles]
    [tiles.repair]
        slot_max = 1024
    [tiles.gui]
        enabled = false
    [tiles.rpc]
        enabled = false
    [tiles.shred]
        shred_listen_port = 8004
[snapshots]
    incremental_snapshots = false
[paths]
    identity_key = \"$KEY_PATH/fd-identity.json\"
    vote_account = \"$KEY_PATH/fd-vote.json\"
    base = \"/home/${USER}/.firedancer/fd2\"
[funk]
    max_account_records = 10000000
    heap_size_gib = 32
    max_database_transactions = 1024
[log]
    path = \"firedancer-dev.log\"
" > firedancer-dev.toml

sudo gdb -iex="set debuginfod enabled on" -ex=r --args $FD_DIR/$OBJDIR/bin/firedancer-dev dev --config $(readlink -f firedancer-dev.toml) --no-clone --no-sandbox
