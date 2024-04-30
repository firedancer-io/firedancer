#!/bin/bash

# This script minimizes both the snapshot and rocksdb from a ledger, from $LEDGER to $LEDGER_MIN

BENCH_SLOT_MAINNET=0
BENCH_EPOCH_MAINNET=0
BENCH_SLOT_TESTNET=213932256
BENCH_EPOCH_TESTNET=508
BENCH_SLOT_INTERNAL=0
BENCH_EPOCH_INTERNAL=0

minf_fd_frank_minimize_tool="$FIREDANCER/build/native/gcc/bin/fd_frank_ledger"
minf_rocksdb_min=""
minf_rocksdb_max=""
minf_edge=""

rocksdb_bounds() {
  local rooted_bounds="$($SOLANA_LEDGER_TOOL bounds -l $LEDGER |& grep "rooted slots")"
  minf_rocksdb_min="$(echo $rooted_bounds | awk '{print $(NF-2)}')"
  minf_rocksdb_max="$(echo $rooted_bounds | awk '{print $(NF)}')"
  echo "[~] rocksdb_bounds=$minf_rocksdb_min-$minf_rocksdb_max"

  if [[ -z $minf_rocksdb_min || -z $minf_rocksdb_max ]]; then
    echo "[-] error could not get rocksdb bounds"
    exit 1
  fi
}

calculate_edge() {
  if [[ "$NETWORK" == "mainnet" ]]; then
    bench_slot="$BENCH_SLOT_MAINNET"
  elif [[ "$NETWORK" == "testnet" ]]; then
    bench_slot="$BENCH_SLOT_TESTNET"
  elif [[ "$NETWORK" == "internal" ]]; then
    bench_slot="$BENCH_SLOT_INTERNAL"
  fi

  # calculate epoch boundary based on edge
  # get the slot number from the original (oldest modified) snapshot in LEDGER
  local snapshot_slot=$(find $LEDGER -maxdepth 1 -name 'snapshot-*.tar.zst' -print0 | xargs -0 ls -tr | head -n 1 | xargs -I {} basename {} | grep -oP 'snapshot-\K\d+')
  if [[ -z "$snapshot_slot" ]]; then
    echo "[-] No snapshot found in $LEDGER"
    exit 1
  fi
  echo "[~] bench_slot=$bench_slot,snapshot_slot=$snapshot_slot,slots_in_epoch=$SLOTS_IN_EPOCH"
  minf_edge=$(echo "($bench_slot + ((($snapshot_slot - $bench_slot) / $SLOTS_IN_EPOCH) + 1) * $SLOTS_IN_EPOCH)" | bc)
  echo "[~] edge=$minf_edge"
}

minimize_snapshot_frank() {
  local in_dir=$1
  local out_dir=$2
  local start_slot=$3
  local end_slot=$4

  echo "[~] running minimize_snapshot_frank"
  rm -rf "$out_dir"
  mkdir -p "$out_dir"

  if [ ! -f "$in_dir/rocksdb/CURRENT" ]; then
    echo "[-] rocksdb not found in $in_dir/rocksdb"
    exit 1
  fi
  set -x
  "$minf_fd_frank_minimize_tool" --cmd minify --rocksdb "$in_dir/rocksdb" --minidb "$out_dir/rocksdb" --startslot $start_slot --endslot $end_slot --pages $GIGANTIC_PAGES --indexmax $INDEX_MAX
  set +x
  cd "$in_dir" || exit
  cp gen* "$out_dir"

  minimized_snapshot=$(find "$in_dir" -maxdepth 1 -name 'snapshot-*.tar.zst' -print0 | xargs -0 ls -t | head -n 1)
  cp "$minimized_snapshot" "$out_dir"

  num_snapshot=$(find "$in_dir" -maxdepth 1 -name 'snapshot-*.tar.zst' -print0 | xargs -0 ls -t | wc -l)
  if [[ $num_snapshot -gt 1 ]]; then
    rm -rf $minimized_snapshot
  fi
}

minimize_snapshot_solana() {
  local in_dir=$1
  local out_dir=$2
  local start_slot=$3
  local end_slot=$4

  echo "[~] running minimize_snapshot_solana"

  # Check if minimization if possible
  local snapshot_slot=$(find $in_dir -maxdepth 1 -name 'snapshot-*.tar.zst' -print0 | xargs -0 ls -tr | head -n 1 | xargs -I {} basename {} | grep -oP 'snapshot-\K\d+')
  if [[ -z "$snapshot_slot" ]]; then
    echo "[-] no snapshot found in $in_dir"
    exit 1
  fi
  if [[ $start_slot -lt $snapshot_slot ]]; then
    echo "[~] skipping snapshot minimization, start_slot=$start_slot must be greater than snapshot_slot=$snapshot_slot"
    return
  fi

  rm -rf "$out_dir"
  cd "$in_dir" || exit

  #    rm -rf ledger_tool
  #    if [[ "$IS_VERIFY" == "true" ]]; then
  #        set -x
  #        "$SOLANA_LEDGER_TOOL"  verify -l . --halt-at-slot $end_slot  >& validator1.log
  #        set +x
  #    fi
  #    set -x
  #    "$SOLANA_LEDGER_TOOL"  create-snapshot -l . $start_slot
  #    set +x

  rm -rf ledger_tool
  if [[ "$IS_VERIFY" == "true" ]]; then
    "$SOLANA_LEDGER_TOOL" verify -l . --halt-at-slot $end_slot |& tee validator2.log
  fi
  set -x
  "$SOLANA_LEDGER_TOOL" create-snapshot -l . $start_slot --minimized --ending-slot $end_slot
  set +x

  rm -rf ledger_tool
  if [[ "$IS_VERIFY" == "true" ]]; then
    set -x
    "$SOLANA_LEDGER_TOOL" verify -l . --halt-at-slot $end_slot |& tee validator3.log
    set +x
    echo "[~] checking hash consistency across $in_dir..."
    check_hash_consistency "$in_dir"
  fi

  minimize_snapshot_frank $in_dir $out_dir $start_slot $end_slot

  if [[ "$IS_VERIFY" == "true" ]]; then
    cd "$out_dir" || exit
    set -x
    "$SOLANA_LEDGER_TOOL" verify -l . |& tee validator4.log
    set +x
    echo "[~] checking hash consistency across $in_dir and $out_dir..."
    check_hash_consistency "$in_dir" "$out_dir"
  fi
}

if [[ "$MODE" == "edge" ]]; then
  rocksdb_bounds
  calculate_edge
  edge_start_slot=$(echo "$minf_edge - $EDGE_OFFSET" | bc)
  edge_end_slot=$(echo "$minf_edge + $EDGE_OFFSET" | bc)
  echo "[~] rocksdb_min=$minf_rocksdb_min, edge_min=$edge_start_slot, edge_max=$edge_end_slot, rocksdb_max=$minf_rocksdb_max"

  if [[ $minf_rocksdb_min -gt $edge_start_slot || $minf_rocksdb_max -lt $edge_end_slot ]]; then
    echo "[-] edge $minf_edge is not within the bounds $minf_rocksdb_min-$minf_rocksdb_max. try a smaller offset."
    exit 1
  fi

  echo "[~] minimizing snapshot with edge=$minf_edge, edge_start_slot=$edge_start_slot, edge_end_slot=$edge_end_slot, ledger=$LEDGER, ledger_min=$LEDGER_MIN"
  minimize_snapshot_solana $LEDGER $LEDGER_MIN $edge_start_slot $edge_end_slot

elif [[ "$MODE" == "exact" ]]; then
  rocksdb_bounds
  if [ $START_SLOT -lt $minf_rocksdb_min ] || [ $END_SLOT -gt $minf_rocksdb_max ]; then
    echo "[-] error: [start_slot=$START_SLOT, end_slot=$END_SLOT] must be within [rocksdb_min=$minf_rocksdb_min, rocksdb_max=$minf_rocksdb_max]"
    exit 1
  fi

  echo "[~] minimizing snapshot with exact start_slot=$START_SLOT, end_slot=$END_SLOT, ledger=$LEDGER, ledger_min=$LEDGER_MIN"
  minimize_snapshot_solana $LEDGER $LEDGER_MIN $START_SLOT $END_SLOT

else
  echo "[-] invalid mode=$MODE. options: edge, exact"
  exit 1
fi
