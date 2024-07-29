#!/bin/bash

txn_firedancer_repo="$REPO_ROOT/firedancer"
txn_fd_ledger_dump="$txn_firedancer_repo/dump"
txn_fd_dump_txn_out="$REPO_ROOT/txn_pb"
txn_fd_conformance_out="$REPO_ROOT/conformance_out"
txn_solana_conformance_repo="$REPO_ROOT/solana-conformance"
txn_solfuzz_agave_repo="$REPO_ROOT/solfuzz-agave"

# Get the transaction protobufs
cd $txn_firedancer_repo || exit

txn_snap_root_path=$(find dump -maxdepth 2 -name "snapshot-*" -type f -print0 | xargs -0 ls -t | head -n 1)
txn_rocksdb_path=$(echo "$txn_snap_root_path" | sed 's|/snapshot-.*|/rocksdb|')
txn_mismatch_slot=$(echo "$txn_snap_root_path" | awk -F'/' '{print $2}' | awk -F'-' '{print $2}')
txn_protobuf_end_slot=$((txn_mismatch_slot + 1))

rm -rf $txn_fd_dump_txn_out && mkdir -p $txn_fd_dump_txn_out

build/native/gcc/bin/fd_ledger --cmd replay \
                               --rocksdb $txn_rocksdb_path \
                               --index-max $INDEX_MAX \
                               --end-slot $txn_protobuf_end_slot \
                               --funk-only 1 \
                               --txn-max 100 \
                               --page-cnt $PAGES \
                               --funk-page-cnt $FUNK_PAGES \
                               --verify-acc-hash 1 \
                               --snapshot $txn_snap_root_path \
                               --slot-history 5000 \
                               --allocator wksp \
                               --on-demand-block-ingest 1 \
                               --dump-txn-to-pb 1 \
                               --dump-proto-start-slot $txn_mismatch_slot \
                               --dump-proto-output-dir $txn_fd_dump_txn_out \
                               --tile-cpus 5-21 2>&1

# Run against solana-conformance
cd $txn_solana_conformance_repo
rm -rf $txn_fd_conformance_out && mkdir -p $txn_fd_conformance_out

source test_suite_env/bin/activate
HARNESS_TYPE=TxnHarness solana-test-suite run-tests --input-dir $txn_fd_dump_txn_out \
                                                    --solana-target $txn_solfuzz_agave_repo/target/debug/libsolfuzz_agave.so \
                                                    --target $txn_firedancer_repo/build/native/gcc/lib/libfd_exec_sol_compat.so \
                                                    --output-dir $txn_fd_conformance_out \
                                                    --consensus-mode \
                                                    --failures-only \
                                                    --save-failures
