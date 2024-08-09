#!/bin/bash

set -euxo pipefail
IFS=$'\n\t'

TMPDIR=$(mktemp --directory --tmpdir="$HOME" tmp-test-tvu-fddev.XXXXXX)
cd $TMPDIR

echo "Creating mint and stake authority keys..."
solana-keygen new --no-bip39-passphrase --force -o faucet-keypair.json > /dev/null
solana-keygen new --no-bip39-passphrase --force -o authority.json > /dev/null

# Create bootstrap validator keys
echo "Creating keys for Validator"
solana-keygen new --no-bip39-passphrase --force -o validator-keypair.json > id.seed
solana-keygen new --no-bip39-passphrase --force -o vote-account-keypair.json > vote.seed
solana-keygen new --no-bip39-passphrase --force -o stake-account-keypair.json > stake.seed
cd ..

echo "Running Genesis..."

GENESIS_OUTPUT=$(solana-genesis \
    --cluster-type mainnet-beta \
    --ledger $TMPDIR \
    --bootstrap-validator $TMPDIR/validator-keypair.json $TMPDIR/vote-account-keypair.json $TMPDIR/stake-account-keypair.json \
    --bootstrap-stake-authorized-pubkey $TMPDIR/validator-keypair.json \
    --bootstrap-validator-lamports 11000000000000000 \
    --bootstrap-validator-stake-lamports 1000000000000000 \
    --faucet-pubkey $TMPDIR/faucet-keypair.json --faucet-lamports 1000000000000000000 \
    --slots-per-epoch 200 \
    --hashes-per-tick 1024 \
    --ticks-per-slot 64)
