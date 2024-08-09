#!/bin/bash

set -euxo pipefail
IFS=$'\n\t'

#TMPDIR=$(mktemp --directory --tmpdir="$HOME" tmp-test-tvu-fddev.XXXXXX)
TMPDIR=$(pwd)/../test-ledger
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
solana program dump GjyKyRCSygSaszrjJFu43jkAshFc1sWs45HqKEDXhvwx -ut nanotoken.so
solana program dump noop8ytexvkpCuqbf6FB89BSuNemHtPRqaNC31GWivW -ut noop.so

genesis_args+=(--upgradeable-program NoopToken1111111111111111111111111111111111 BPFLoaderUpgradeab1e11111111111111111111111 noop.so none)
genesis_args+=(--upgradeable-program GjyKyRCSygSaszrjJFu43jkAshFc1sWs45HqKEDXhvwx BPFLoaderUpgradeab1e11111111111111111111111 nanotoken.so none)

echo "${genesis_args[@]}"

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
    --ticks-per-slot 64 \
    ${genesis_args[@]})
