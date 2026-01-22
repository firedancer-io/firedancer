#!/bin/bash

set -euxo pipefail

IFS=$'\n\t'
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
FD_DIR="$SCRIPT_DIR/../.."
OBJDIR=${OBJDIR:-build/native/${CC}}
AGAVE_PATH=${AGAVE_PATH:='./agave/target/release'}

make -j firedancer-dev

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

#while [ $($AGAVE_PATH/solana -u localhost epoch-info --output json | jq .blockHeight) -le 150 ]; do
  #sleep 1
#done

sudo rm -f firedancer-dev.log
# clear snapshot cache always
sudo rm -rf /home/${USER}/.firedancer/fd2/snapshots/*

echo "
[gossip]
    entrypoints = [\"64.130.55.36:8001\"]
    port = 8700
[tiles]
    [tiles.repair]
        slot_max = 1024
    [tiles.gui]
        enabled = false
    [tiles.rpc]
        enabled = false
[snapshots]
    incremental_snapshots = false
[paths]
    identity_key = \"/home/emwang/em-testnet-keys/fd-identity.json\"
    vote_account = \"/home/emwang/em-testnet-keys/fd-vote.json\"
    base = \"/home/${USER}/.firedancer/fd2\"
[funk]
    max_account_records = 10000000
    heap_size_gib = 32
    max_database_transactions = 1024
[log]
    path = \"firedancer-dev.log\"
" > firedancer-dev.toml

sudo gdb -iex="set debuginfod enabled on" -ex=r --args $FD_DIR/$OBJDIR/bin/firedancer-dev dev --config $(readlink -f firedancer-dev.toml) --no-clone --no-sandbox
