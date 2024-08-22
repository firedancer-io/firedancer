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

upgradeableLoader=BPFLoaderUpgradeab1e11111111111111111111111

fetch_program() {
  declare name=$1
  declare version=$2
  declare address=$3
  declare loader=$4

  declare so=spl_$name-$version.so

  if [[ $loader == "$upgradeableLoader" ]]; then
    genesis_args+=(--upgradeable-program "$address" "$loader" "$so" none)
  else
    genesis_args+=(--bpf-program "$address" "$loader" "$so")
  fi

  if [[ -r $so ]]; then
    return
  fi

  if [[ -r ~/.cache/solana-spl/$so ]]; then
    cp ~/.cache/solana-spl/"$so" "$so"
  else
    echo "Downloading $name $version"
    so_name="spl_${name//-/_}.so"
    (
      set -x
      curl -L --retry 5 --retry-delay 2 --retry-connrefused \
        -o "$so" \
        "https://github.com/solana-labs/solana-program-library/releases/download/$name-v$version/$so_name"
    )

    mkdir -p ~/.cache/solana-spl
    cp "$so" ~/.cache/solana-spl/"$so"
  fi

}

fetch_program token 3.5.0 TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA BPFLoader2111111111111111111111111111111111
fetch_program token-2022 1.0.0 TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb BPFLoaderUpgradeab1e11111111111111111111111
fetch_program memo  1.0.0 Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo BPFLoader1111111111111111111111111111111111
fetch_program memo  3.0.0 MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr BPFLoader2111111111111111111111111111111111
fetch_program associated-token-account 1.1.2 ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL BPFLoader2111111111111111111111111111111111
fetch_program feature-proposal 1.0.0 Feat1YXHhH6t1juaWF74WLcfv4XoNocjXA6sPWHNgAse BPFLoader2111111111111111111111111111111111
solana program dump GigabithNd6HmU4nRFPHXAkBK9nAtvNuHnSavWi3G7Zj -ut nanotoken.so
genesis_args+=(--upgradeable-program NanoToken1111111111111111111111111111111111 BPFLoaderUpgradeab1e11111111111111111111111 nanotoken.so none)

echo "${genesis_args[@]}"

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
    --ticks-per-slot 64 \
    ${genesis_args[@]})

# Start validator
echo "Starting Bootstrap Validator..."

# Start the bootstrap validator
GENESIS_HASH=$(echo $GENESIS_OUTPUT | grep -o -P '(?<=Genesis hash:).*(?=Shred version:)' | xargs)
SHRED_VERSION=$(echo $GENESIS_OUTPUT | grep -o -P '(?<=Shred version:).*(?=Ticks per slot:)' | xargs)
_PRIMARY_INTERFACE=$(ip route show default | awk '/default/ {print $5}')

RUST_LOG=debug ./agave/target/release/agave-validator \
    --identity test-ledger/validator-keypair.json \
    --ledger test-ledger \
    --limit-ledger-size 1000000000 \
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
    --enable-rpc-transaction-history \
    --tpu-enable-udp \
    --log test-ledger/validator.log
    # --tpu-disable-quic \
    # --public-tpu-address 127.0.0.1:9010 \
