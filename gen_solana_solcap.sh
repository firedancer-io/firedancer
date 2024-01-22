#!/bin/bash

BASE_DIR=$1
SLOT=$2

cd $BASE_DIR/solana
cargo build --release --package solana-ledger-tool
RUST_LOG=trace ./target/release/solana-ledger-tool verify --halt-at-slot $SLOT -l $LEDGER --write-bank-file
cd $BASE_DIR/firedancer-private
make -j
build/native/gcc/bin/fd_solcap_import $LEDGER/bank_hash_details/$SLOT-*.json ref$SLOT.solcap
