#!/bin/bash

# This script can be used to produce a solcap file for a given ledger for both firedancer
# and solana. It can also be used to produce a diff between the two solcap files.

solcap_firedancer_repo="$REPO_ROOT/firedancer"

cd $solcap_firedancer_repo || exit

solcap_fd_solcap_import="build/native/gcc/bin/fd_solcap_import"
solcap_fd_solcap_diff="build/native/gcc/bin/fd_solcap_diff"

solcap_snap_root_path=$(find dump -maxdepth 2 -name "snapshot-*" -type f -print0 | xargs -0 ls -t | head -n 1)
solcap_rocksdb_path=$(echo "$solcap_snap_root_path" | sed 's|/snapshot-.*|/rocksdb|')
solcap_bank_hash_details_path=$(echo "$solcap_snap_root_path" | sed 's|/snapshot-.*|/ledger_tool/bank_hash_details/|')
solcap_dump_path=$(echo "$solcap_snap_root_path" | sed 's|/snapshot-.*|/|')
solcap_mismatch_slot=$(echo "$solcap_snap_root_path" | awk -F'/' '{print $2}' | awk -F'-' '{print $2}')
solcap_end_slot=$((solcap_mismatch_slot + 1))


# produce firedancer solcap
# this would usually be enough since we have copy-txn-status set to 1
# but there is a bug in rocksdb minify so we also need to create the solana solcap below
build/native/gcc/bin/fd_ledger --cmd replay \
                               --rocksdb $solcap_rocksdb_path \
                               --index-max $INDEX_MAX \
                               --end-slot $solcap_end_slot \
                               --cluster-version $FIREDANCER_CLUSTER_VERSION \
                               --funk-only 1 \
                               --txn-max 100 \
                               --page-cnt $PAGES \
                               --funk-page-cnt $FUNK_PAGES \
                               --verify-acc-hash 1 \
                               --snapshot $solcap_snap_root_path \
                               --slot-history 5000 \
                               --allocator wksp \
                               --on-demand-block-ingest 1 \
                               --tile-cpus 5-21 \
                               --capture-txns 1 \
                               --copy-txn-status 1 \
                               --capture-solcap fd.solcap

# produce solana solcap 
cd $solcap_dump_path
$SOLANA_LEDGER_TOOL verify --ledger . --halt-at-slot $solcap_end_slot
cd $solcap_firedancer_repo || exit
$solcap_fd_solcap_import $solcap_bank_hash_details_path solana.solcap

## Get the solcap Diff
set -x
echo -e "[~] solcap diff \n"
$solcap_fd_solcap_diff fd.solcap solana.solcap -v 4
set +x

