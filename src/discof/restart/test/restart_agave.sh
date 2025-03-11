#!/usr/bin/env sh

PRIMARY_IP=147.75.87.225
GOSSIP_PORT=8001
SHRED_VERSION=16013

# We need the ledger-local directory from running Agave normally before crashing it
LEDGER=./ledger-local
VOTE_ACCT=fd-vote-keypair.json
IDENTITY=fd-identity-keypair.json

WEN_RESTART_COORDINATOR=6tr7Acuwy5PiEEQMyyDphTeEoY2MAz4nncjEvcZAcERo
WEN_RESTART_PROTOBUF_LOG=./restart/restart_progress
rm $WEN_RESTART_PROTOBUF_LOG

# FIXME: this currently requires a special fork of Agave release v2.0.3

RUST_LOG=info agave/target/debug/agave-validator \
    --identity $IDENTITY \
    --ledger $LEDGER \
    --expected-shred-version $SHRED_VERSION \
    --vote-account $(solana-keygen pubkey $VOTE_ACCT) \
    --gossip-host $PRIMARY_IP \
    --gossip-port $GOSSIP_PORT \
    --log $LEDGER/restart.log \
    --no-os-network-limits-test \
    --wen-restart $WEN_RESTART_PROTOBUF_LOG \
    --wen-restart-coordinator $WEN_RESTART_COORDINATOR
