#!/bin/bash

# find_rooted_slot verifies that a slot_number is in the blockstore,
# if not it iterates in the specified direction to find the next one that is
find_rooted_slot() {
  local slot_number=$1
  local direction=$2

  echo "[~] finding rooted slot for $slot_number in direction $direction" >&2

  while true; do
    output=$($SOLANA_LEDGER_TOOL slot $slot_number -l $LEDGER 2>&1)

    if [[ "$output" == *"is_full: true"* ]]; then
      parent_slot="${BASH_REMATCH[1]}"
      echo "[~] found rooted slot at $slot_number with parent slot $parent_slot" >&2
      echo $slot_number
      return 0
    elif [[ "$output" == *"is_full: false"* ]]; then
      echo "[~] slot $slot_number has no parent, skipping..." >&2
    else
      echo "[-] no information for slot $slot_number, skipping... $output" >&2
    fi

    if [[ "$direction" == "+" ]]; then
      ((slot_number++))
    elif [[ "$direction" == "-" ]]; then
      ((slot_number--))
    fi
  done
  echo "[~] found rooted slot at $slot_number from $slot_number in direction $direction" >&2
}

# set_default_slots finds an appropriate start and end slot based on the snapshot and rocksdb bounds
set_default_slots() {
  local rooted_bounds="$($SOLANA_LEDGER_TOOL bounds -l $LEDGER |& grep "rooted slots")"

  local snapshot_slot=$(find $LEDGER -maxdepth 1 -name 'snapshot-*.tar.zst' -print0 | xargs -0 ls -tr | head -n 1 | xargs -I {} basename {} | grep -oP 'snapshot-\K\d+')
  if [[ -z "$snapshot_slot" ]]; then
    echo "[-] no snapshot found in $in_dir"
    exit 1
  fi

  local rocksdb_min="$(echo $rooted_bounds | awk '{print $(NF-2)}')"
  local rocksdb_max="$(echo $rooted_bounds | awk '{print $(NF)}')"
  echo "[~] rocksdb_bounds=$rocksdb_min-$rocksdb_max"

  if [[ -z $rocksdb_min || -z $rocksdb_max ]]; then
    echo "[-] error could not get rocksdb bounds"
    exit 1
  fi
  if [[ $snapshot_slot -gt $rocksdb_max ]]; then
    echo "[-] error: snapshot slot $snapshot_slot is greater than rocksdb_max $rocksdb_max"
    exit 1
  fi

  if [ -z "$START_SLOT" ] || [ -z "$END_SLOT" ]; then
    START_SLOT=$(($rocksdb_min > $snapshot_slot ? $rocksdb_min : $snapshot_slot))
    END_SLOT=$rocksdb_max
    echo "[~] Setting initial default START_SLOT=$START_SLOT, END_SLOT=$END_SLOT"
  else
    if [ $START_SLOT -lt $rocksdb_min ] || [ $END_SLOT -gt $rocksdb_max ]; then
      echo "[-] error: [START_SLOT=$START_SLOT, END_SLOT=$END_SLOT] must be within [rocksdb_min=$rocksdb_min, rocksdb_max=$rocksdb_max]"
      exit 1
    fi
  fi

  local rooted_start_slot=$(find_rooted_slot $START_SLOT "+")
  local rooted_end_slot=$(find_rooted_slot $END_SLOT "-")
  START_SLOT=$rooted_start_slot
  END_SLOT=$rooted_end_slot
  echo "[~] Setting final default rooted START_SLOT=$START_SLOT, END_SLOT=$END_SLOT"
}

export -f set_default_slots find_rooted_slot
