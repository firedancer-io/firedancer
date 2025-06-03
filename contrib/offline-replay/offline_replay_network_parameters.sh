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
    export FUNK_PAGES=900
    export BACKTEST_FUNK_PAGES=900
    export INDEX_MAX=1000000000
    export PAGES=250
    export AGAVE_TAG=v2.1.21
    export FD_CLUSTER_VERSION=2.1.21
    ;;
  "testnet")
    export BUCKET_ENDPOINT="gs://testnet-ledger-us-sv15"
    export GENESIS_FILE="https://api.testnet.solana.com/genesis.tar.bz2"
    export FUNK_PAGES=500
    export BACKTEST_FUNK_PAGES=200
    export INDEX_MAX=200000000
    export PAGES=250
    export AGAVE_TAG=v2.2.14
    export FD_CLUSTER_VERSION=2.2.14
    ;;
  "devnet")
    export BUCKET_ENDPOINT="gs://solana-devnet-ledger-us-ny5"
    export GENESIS_FILE="https://api.devnet.solana.com/genesis.tar.bz2"
    export FUNK_PAGES=500
    export BACKTEST_FUNK_PAGES=500
    export INDEX_MAX=200000000
    export PAGES=250
    export AGAVE_TAG=v2.2.14
    export FD_CLUSTER_VERSION=2.2.14
    ;;
  *)
    echo "Unknown network: $network"
    return 1
    ;;
esac

export ALLOC_HUGE_PAGES=300
export ALLOC_GIGANTIC_PAGES=250

export HEAP_SIZE=200
export IDENTITY_KEY_PATH="/data/offline-replay-keys/fd-identity-keypair.json"
export VOTE_ACCOUNT_PATH="/data/offline-replay-keys/fd-vote-keypair.json"
