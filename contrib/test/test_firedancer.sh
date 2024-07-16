#!/bin/bash

set -euxo pipefail
IFS=$'\n\t'

PRIMARY_IP=$(ip -o -4 addr show scope global | awk '{ print $4 }' | cut -d/ -f1)

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# create temporary files in the user's home directory because it's likely to be on a large disk
TMPDIR=$(mktemp --directory --tmpdir="/tmp" tmp-test-tvu-fddev.XXXXXX)
cd $TMPDIR

cleanup() {
  sudo killall -9 -q agave-validator || true
  sudo killall -9 -q fddev || true
  fddev configure fini all >/dev/null 2>&1 || true
  rm -rf "$TMPDIR"
}

trap cleanup EXIT SIGINT SIGTERM

SOLANA_BIN_DIR="$HOME/code/solana/target/release"
FD_DIR="$SCRIPT_DIR/../.."

sudo killall -9 -q fddev || true
sudo killall -9 -q agave-validator || true

# if solana is not on path then use the one in the home directory
if ! command -v solana > /dev/null; then
  PATH=$SOLANA_BIN_DIR:$PATH
fi

# if fd_frank_ledger is not on path then use the one in the home directory
if ! command -v fddev > /dev/null; then
  PATH="$FD_DIR/build/native/$CC/bin":$PATH
fi

echo "Creating mint and stake authority keys..."
solana-keygen new --no-bip39-passphrase --force -o faucet-keypair.json > /dev/null
solana-keygen new --no-bip39-passphrase --force -o authority.json > /dev/null

# Create bootstrap validator keys
echo "Creating keys for Validator"
solana-keygen new --no-bip39-passphrase --force -o validator-keypair.json > id.seed
solana-keygen new --no-bip39-passphrase --force -o vote-account-keypair.json > vote.seed
solana-keygen new --no-bip39-passphrase --force -o stake-account-keypair.json > stake.seed
cd ..
# Genesis
echo "Running Genesis..."

GENESIS_OUTPUT=$(solana-genesis \
    --cluster-type mainnet-beta \
    --ledger $TMPDIR \
    --bootstrap-validator $TMPDIR/validator-keypair.json $TMPDIR/vote-account-keypair.json $TMPDIR/stake-account-keypair.json \
    --bootstrap-stake-authorized-pubkey $TMPDIR/validator-keypair.json \
    --bootstrap-validator-lamports 11000000000000000 \
    --bootstrap-validator-stake-lamports 10000000000000000 \
    --faucet-pubkey $TMPDIR/faucet-keypair.json --faucet-lamports 1000000000000000000 \
    --slots-per-epoch 200 \
    --hashes-per-tick 128 \
    --ticks-per-slot 64)

# Start validator
echo "Starting Bootstarp Validator..."

# Start the bootstrap validator
GENESIS_HASH=$(echo $GENESIS_OUTPUT | grep -o -P '(?<=Genesis hash:).*(?=Shred version:)' | xargs)
SHRED_VERSION=$(echo $GENESIS_OUTPUT | grep -o -P '(?<=Shred version:).*(?=Ticks per slot:)' | xargs)

RUST_LOG=trace taskset -c 40,41 agave-validator \
    --identity $TMPDIR/validator-keypair.json \
    --ledger $TMPDIR \
    --limit-ledger-size 100000000 \
    --no-genesis-fetch \
    --no-snapshot-fetch \
    --no-poh-speed-test \
    --no-os-network-limits-test \
    --vote-account $(solana-keygen pubkey $TMPDIR/vote-account-keypair.json) \
    --expected-shred-version $SHRED_VERSION \
    --expected-genesis-hash $GENESIS_HASH \
    --no-wait-for-vote-to-start-leader \
    --no-incremental-snapshots \
    --full-snapshot-interval-slots 100 \
    --maximum-full-snapshots-to-retain 10 \
    --rpc-port 8899 \
    --gossip-port 8001 \
    --gossip-host $PRIMARY_IP \
    --dynamic-port-range 8100-10000 \
    --full-rpc-api \
    --allow-private-addr \
    --rpc-faucet-address 127.0.0.1:9900 \
    --log $TMPDIR/validator.log &

sleep 10
cd $TMPDIR

RPC_URL="http://localhost:8899/"

solana-keygen new --no-bip39-passphrase --silent --outfile fd-identity-keypair.json
solana-keygen new --no-bip39-passphrase --silent --outfile fd-stake-keypair.json
solana-keygen new --no-bip39-passphrase --silent --outfile fd-vote-keypair.json
solana-keygen new --no-bip39-passphrase --silent --outfile fd-withdrawer-keypair.json

solana -u $RPC_URL --keypair faucet-keypair.json transfer --allow-unfunded-recipient fd-identity-keypair.json 4000000
solana -u $RPC_URL --keypair fd-identity-keypair.json create-vote-account fd-vote-keypair.json fd-identity-keypair.json fd-withdrawer-keypair.json
solana -u $RPC_URL --keypair fd-identity-keypair.json create-stake-account fd-stake-keypair.json 3000000
solana -u $RPC_URL --keypair fd-identity-keypair.json delegate-stake fd-stake-keypair.json fd-vote-keypair.json

solana -u $RPC_URL --keypair fd-identity-keypair.json vote-account fd-vote-keypair.json
solana -u $RPC_URL --keypair fd-identity-keypair.json stake-account fd-stake-keypair.json

while [ $(solana -u localhost epoch-info --output json | jq .blockHeight) -le 150 ]; do
  sleep 1
done

_PRIMARY_INTERFACE=$(ip route show default | awk '/default/ {print $5}')
PRIMARY_IP=$(ip addr show $_PRIMARY_INTERFACE | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
FULL_SNAPSHOT=$(wget -c -nc -S --trust-server-names http://$PRIMARY_IP:8899/snapshot.tar.bz2 |& grep 'location:' | cut -d/ -f2)

echo "
name = \"fd1test\"
[layout]
    affinity = \"1-32\"
    bank_tile_count = 1
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
        blockstore_checkpt = \"fddev-blockstore.checkpt\"
        snapshot = \"$FULL_SNAPSHOT\"
        tpool_thread_count = 8
        funk_sz_gb = 32
        funk_rec_max = 10000000
        funk_txn_max = 1024
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
sudo $FD_DIR/build/native/$CC/bin/fddev configure init ethtool-gro --config $(readlink -f fddev.toml)
sudo $FD_DIR/build/native/$CC/bin/fddev configure init keys --config $(readlink -f fddev.toml)

sudo $FD_DIR/build/native/$CC/bin/fddev dev --no-configure --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) --no-solana --no-sandbox --no-clone &
sleep 120

grep -q "result: match" $(readlink -f fddev.log)
if grep -q "result: mismatch" $(readlink -f fddev.log); then
  echo "*** BANK HASH MISMATCH ***"
fi

if grep -q "block invalid" $(readlink -f fddev.log); then
  echo "*** INVALID BLOCK ***"
fi
