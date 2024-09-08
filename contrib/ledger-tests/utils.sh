#!/bin/bash

is_rooted_slot() {
  local slot_number=$1
  local output=$($SOLANA_LEDGER_TOOL slot $slot_number -l $LEDGER 2>&1)

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
  return 1  
}

# find_rooted_slot verifies that a slot_number is in the blockstore,
# if not it iterates in the specified direction to find the next one that is
find_rooted_slot() {
  local slot_number=$1
  local direction=$2

  echo "[~] finding rooted slot for $slot_number in direction $direction" >&2

  while true; do    
    is_rooted=$(is_rooted_slot $slot_number)
    status=$?    
    if [ $status -eq 0 ]; then
      # it is indeed rooted
      echo $is_rooted
      return 0
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

get_closest_hourly() {
    local slot=$1
    local network=$2

    local closest_hourly_url=""
    local closest_hourly_slot=-1

    if [[ $network == "mainnet" ]]; then
        bucket="gs://mainnet-beta-ledger-europe-fr2"
    elif [[ $network == "testnet" ]]; then
        bucket="gs://testnet-ledger-us-sv15"
    else
        echo "[-] error: unknown network $network"
        exit 1
    fi

    local directories=$(gsutil ls $bucket | sort -n -t / -k 4 | tail -n 3)

    for dir in $directories; do
        local dir_number=$(basename $dir)

        if (( dir_number <= slot )); then
            local snapshots=$(gsutil ls "${dir}hourly" | sort -n -t - -k 3)
            local base_snapshot=$(gsutil ls "${dir}snapshot*.tar.zst")
            snapshots="${base_snapshot} ${snapshots}"

            for snapshot in $snapshots; do
                local snapshot_number=$(basename $snapshot | cut -d '-' -f 2)

                if (( snapshot_number <= slot && snapshot_number > closest_hourly_slot )); then
                    closest_hourly_slot=$snapshot_number
                    closest_hourly_url=$snapshot
                fi
            done
        fi
    done

    echo $closest_hourly_url
}

slot_to_epoch() {
    local slot=$1
    local network=$2

    if [[ $network == "mainnet" ]]; then
        bench_slot=0
        bench_epoch=0
    elif [[ $network == "testnet" ]]; then
        bench_slot=213932256
        bench_epoch=508
    else
        echo "[-] error: unknown network $network"
        exit 1
    fi

    local epoch=$(( (slot - bench_slot) / 432000 + bench_epoch ))
    echo $epoch
}

export -f set_default_slots find_rooted_slot is_rooted_slot get_closest_hourly slot_to_epoch
