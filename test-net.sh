#!/bin/bash
set -euxo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd test-ledger

PRIMARY_IP=$(ip -o -4 addr show scope global | awk '{ print $4 }' | cut -d/ -f1)
RPC_URL="http://$PRIMARY_IP:8899/"


solana-keygen new --no-bip39-passphrase --silent --outfile fd-identity-keypair.json
solana-keygen new --no-bip39-passphrase --silent --outfile fd-stake-keypair.json
solana-keygen new --no-bip39-passphrase --silent --outfile fd-vote-keypair.json
solana-keygen new --no-bip39-passphrase --silent --outfile fd-withdrawer-keypair.json

solana -u $RPC_URL --keypair faucet-keypair.json transfer --allow-unfunded-recipient fd-identity-keypair.json 2000000
solana -u $RPC_URL --keypair fd-identity-keypair.json create-vote-account fd-vote-keypair.json fd-identity-keypair.json fd-withdrawer-keypair.json
solana -u $RPC_URL --keypair fd-identity-keypair.json create-stake-account fd-stake-keypair.json 300000
solana -u $RPC_URL --keypair fd-identity-keypair.json delegate-stake fd-stake-keypair.json fd-vote-keypair.json

solana -u $RPC_URL --keypair fd-identity-keypair.json vote-account fd-vote-keypair.json
solana -u $RPC_URL --keypair fd-identity-keypair.json stake-account fd-stake-keypair.json
