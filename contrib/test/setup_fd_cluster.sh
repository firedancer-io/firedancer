#!/bin/bash
set -euxo pipefail
IFS=$'\n\t'

PRIMARY_IP=$(ip -o -4 addr show scope global | awk '{ print $4 }' | cut -d/ -f1)
RPC_URL="http://$PRIMARY_IP:8899/"

mkdir ../test-ledger
cd ../test-ledger

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

GENESIS_OUTPUT=$(./agave/target/release/solana-genesis \
    --cluster-type mainnet-beta \
    --ledger test-ledger \
    --bootstrap-validator test-ledger/validator-keypair.json test-ledger/vote-account-keypair.json test-ledger/stake-account-keypair.json \
    --bootstrap-stake-authorized-pubkey test-ledger/validator-keypair.json \
    --bootstrap-validator-lamports 11000000000000000 \
    --bootstrap-validator-stake-lamports 1000000000000000 \
    --faucet-pubkey test-ledger/faucet-keypair.json --faucet-lamports 1000000000000000000 \
    --slots-per-epoch 200 \
    --hashes-per-tick 128 \
    --ticks-per-slot 64)

# Start validator
echo "Starting Bootstarp Validator..."

# Start the bootstrap validator
GENESIS_HASH=$(echo $GENESIS_OUTPUT | grep -o -P '(?<=Genesis hash:).*(?=Shred version:)' | xargs)
SHRED_VERSION=$(echo $GENESIS_OUTPUT | grep -o -P '(?<=Shred version:).*(?=Ticks per slot:)' | xargs)
_PRIMARY_INTERFACE=$(ip route show default | awk '/default/ {print $5}')

RUST_LOG=debug ./agave/target/release/agave-validator \
    --identity test-ledger/validator-keypair.json \
    --ledger test-ledger \
    --limit-ledger-size 100000000 \
    --no-genesis-fetch \
    --no-snapshot-fetch \
    --no-poh-speed-test \
    --no-os-network-limits-test \
    --vote-account $(solana-keygen pubkey test-ledger/vote-account-keypair.json) \
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
    --log test-ledger/validator.log