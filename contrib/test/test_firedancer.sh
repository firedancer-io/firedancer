#!/bin/bash

set -euxo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# create temporary files in the user's home directory because it's likely to be on a large disk
TMPDIR=$(mktemp --directory --tmpdir="$HOME" tmp-test-tvu-fddev.XXXXXX)
cd $TMPDIR

cleanup() {
  sudo killall -9 -q solana-validator || true
  sudo killall -9 -q fddev || true
  fddev configure fini all >/dev/null 2>&1 || true
  rm -rf "$TMPDIR"
}

trap cleanup EXIT SIGINT SIGTERM

SOLANA_BIN_DIR="$HOME/code/solana/target/release"
FD_DIR="$SCRIPT_DIR/../.."

sudo killall -9 -q fddev || true
sudo killall -9 -q solana-validator || true

# if solana is not on path then use the one in the home directory
if ! command -v solana > /dev/null; then
  PATH=$SOLANA_BIN_DIR:$PATH
fi

# if fd_frank_ledger is not on path then use the one in the home directory
if ! command -v fddev > /dev/null; then
  PATH="$FD_DIR/build/native/gcc/bin":$PATH
fi

#fddev configure fini all >/dev/null 2>&1

echo "Creating mint and stake authority keys..."
solana-keygen new --no-bip39-passphrase -o faucet.json > /dev/null
solana-keygen new --no-bip39-passphrase -o authority.json > /dev/null

# Create bootstrap validator keys
echo "Creating keys for Validator"
solana-keygen new --no-bip39-passphrase -o id.json > id.seed
solana-keygen new --no-bip39-passphrase -o vote.json > vote.seed
solana-keygen new --no-bip39-passphrase -o stake.json > stake.seed

# Genesis
echo "Running Genesis..."

GENESIS_OUTPUT=$(solana-genesis \
    --cluster-type mainnet-beta \
    --ledger ledger \
    --bootstrap-validator id.json vote.json stake.json \
    --bootstrap-stake-authorized-pubkey id.json \
    --bootstrap-validator-lamports 2399348000000000 \
    --bootstrap-validator-stake-lamports 32282880 \
    --faucet-pubkey faucet.json --faucet-lamports 5000000000000000)

# Start the bootstrap validator
GENESIS_HASH=$(echo $GENESIS_OUTPUT | grep -o -P '(?<=Genesis hash:).*(?=Shred version:)' | xargs)
SHRED_VERSION=$(echo $GENESIS_OUTPUT | grep -o -P '(?<=Shred version:).*(?=Ticks per slot:)' | xargs)
_PRIMARY_INTERFACE=$(ip route show default | awk '/default/ {print $5}')
PRIMARY_IP=$(ip addr show $_PRIMARY_INTERFACE | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)

fd_shmem_cfg query

RUST_LOG=trace taskset -c 40,41 solana-validator \
    --identity id.json \
    --ledger ledger \
    --limit-ledger-size 100000000 \
    --no-genesis-fetch \
    --no-snapshot-fetch \
    --no-poh-speed-test \
    --no-os-network-limits-test \
    --vote-account $(solana-keygen pubkey vote.json) \
    --expected-shred-version $SHRED_VERSION \
    --expected-genesis-hash $GENESIS_HASH \
    --no-wait-for-vote-to-start-leader \
    --incremental-snapshots \
    --full-snapshot-interval-slots 100 \
    --incremental-snapshot-interval-slots 50 \
    --rpc-port 8899 \
    --gossip-port 8001 \
    --gossip-host $PRIMARY_IP \
    --full-rpc-api \
    --allow-private-addr \
    --log validator.log &

sleep 55
while [ $(solana -u localhost epoch-info --output json | jq .blockHeight) -le 150 ]; do
  sleep 1
done

FULL_SNAPSHOT=$(wget -c -nc -S --trust-server-names http://$PRIMARY_IP:8899/snapshot.tar.bz2 |& grep 'location:' | cut -d/ -f2)

SNAPSHOT_SLOT=$(echo "$FULL_SNAPSHOT" | cut -d- -f2)

echo "
[gossip]
    port = 8700
[tiles]
    [tiles.gossip]
        peer_ip_addr = \"$PRIMARY_IP\"
        peer_port = 8001
        gossip_listen_port = 8700
    [tiles.repair]
        repair_intake_listen_port = 8701
        repair_serve_listen_port = 8702
    [tiles.replay]
        snapshot = \"$FULL_SNAPSHOT\"
    [tiles.store]
        snapshot_slot = $SNAPSHOT_SLOT
[log]
  path = \"fddev.log\"
  level_stderr = \"NOTICE\"
[development]
    topology = \"firedancer\"
" > fddev.toml

fddev --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) --no-solana --no-sandbox --no-clone &
sleep 120

grep -q "bank_hash" $(readlink -f fddev.log)
if grep -q "Bank hash mismatch" $(readlink -f fddev.log); then
  echo "*** BANK HASH MISMATCH ***"
fi
