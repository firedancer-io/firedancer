#!/bin/bash

# Check if the network parameter is provided
if [ -z "$1" ]; then
  echo "Usage: source set_network_env.sh <network>"
  return 1
fi

# Get the network parameter
network=$1

case $network in
  "mainnet")
    export BUCKET_ENDPOINT="gs://mainnet-beta-ledger-us-ny5"
    export GENESIS_FILE="https://api.mainnet-beta.solana.com/genesis.tar.bz2"
    # Keep the historical default used by offline_replay.toml (MiB).
    export HEAP_SIZE_MIB=4096
    export BACKTEST_FUNK_PAGES=600
    export INDEX_MAX=1200000000
    export AGAVE_TAG=v3.0.6
    ;;
  "testnet")
    export BUCKET_ENDPOINT="gs://testnet-ledger-us-sv15"
    export GENESIS_FILE="https://api.testnet.solana.com/genesis.tar.bz2"
    export HEAP_SIZE_MIB=4096
    export BACKTEST_FUNK_PAGES=50
    export INDEX_MAX=200000000
    export AGAVE_TAG=v3.1.1
    ;;
  "devnet")
    export BUCKET_ENDPOINT="gs://solana-devnet-ledger-us-ny5"
    export GENESIS_FILE="https://api.devnet.solana.com/genesis.tar.bz2"
    export HEAP_SIZE_MIB=4096
    export BACKTEST_FUNK_PAGES=400
    export INDEX_MAX=300000000
    export AGAVE_TAG=v3.0.6
    ;;
  *)
    echo "Unknown network: $network"
    return 1
    ;;
esac

# Backward compatibility for existing callers that still read HEAP_SIZE.
# Preserve any caller-provided HEAP_SIZE override.
if [ -z "${HEAP_SIZE:-}" ]; then
  export HEAP_SIZE="$HEAP_SIZE_MIB"
else
  # Ensure legacy HEAP_SIZE overrides are reflected in the new variable.
  export HEAP_SIZE_MIB="$HEAP_SIZE"
  export HEAP_SIZE
fi
