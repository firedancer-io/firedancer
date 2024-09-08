#!/bin/bash

instr_firedancer_repo="$REPO_ROOT/firedancer"
instr_fd_ledger_dump="$instr_firedancer_repo/dump"
instr_fd_dump_instr_out="$REPO_ROOT/insn_pb"
instr_fd_conformance_out="$REPO_ROOT/conformance_out"
instr_solana_conformance_repo="$REPO_ROOT/solana-conformance"
instr_solfuzz_agave_repo="$REPO_ROOT/solfuzz-agave"

# Get the instruction protobufs
cd $instr_firedancer_repo || exit

instr_snap_root_path=$(find dump -maxdepth 2 -name "snapshot-*" -type f -print0 | xargs -0 ls -t | head -n 1)
instr_rocksdb_path=$(echo "$instr_snap_root_path" | sed 's|/snapshot-.*|/rocksdb|')
instr_mismatch_slot=$(echo "$instr_snap_root_path" | awk -F'/' '{print $2}' | awk -F'-' '{print $2}')
instr_protobuf_end_slot=$((instr_mismatch_slot + 1))

rm -rf $instr_fd_dump_instr_out && mkdir -p $instr_fd_dump_instr_out

build/native/gcc/bin/fd_ledger --cmd replay \
                            --rocksdb $instr_rocksdb_path \
                            --index-max $INDEX_MAX \
                            --end-slot $instr_protobuf_end_slot \
                            --cluster-version $FIREDANCER_CLUSTER_VERSION \
                            --funk-only 1 \
                            --txn-max 100 \
                            --page-cnt $PAGES \
                            --funk-page-cnt $FUNK_PAGES \
                            --verify-acc-hash 1 \
                            --snapshot $instr_snap_root_path \
                            --slot-history 5000 \
                            --allocator wksp \
                            --on-demand-block-ingest 1 \
                            --dump-insn-to-pb 1 \
                            --dump-proto-start-slot $instr_mismatch_slot \
                            --dump-proto-output-dir $instr_fd_dump_instr_out \
                            --tile-cpus 5-21 2>&1

# Run against solana-conformance
cd $instr_solana_conformance_repo
rm -rf $instr_fd_conformance_out && mkdir -p $instr_fd_conformance_out

source test_suite_env/bin/activate
solana-test-suite run-tests --input-dir $instr_fd_dump_instr_out \
                            --solana-target $instr_solfuzz_agave_repo/target/debug/libsolfuzz_agave.so \
                            --target $instr_firedancer_repo/build/native/gcc/lib/libfd_exec_sol_compat.so \
                            --output-dir $instr_fd_conformance_out \
                            --consensus-mode \
                            --failures-only \
                            --save-failures
