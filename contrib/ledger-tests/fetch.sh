#!/bin/bash

# Download ledger from mainnet/testnet or copies a ledger from a self hosted development cluster
# Dumps everything in $LEDGER

MAINNET_GS_LEDGER_US="gs://mainnet-beta-ledger-us-ny5"
MAINNET_GS_LEDGER_EU="gs://mainnet-beta-ledger-europe-fr2"
MAINNET_GS_LEDGER_ASIA="gs://mainnet-beta-ledger-asia-sg1"
MAINNET_GS_GENESIS="https://api.mainnet-beta.solana.com/genesis.tar.bz2"
TESTNET_GS_LEDGER="gs://testnet-ledger-us-sv15"
TESTNET_GS_GENESIS="https://api.testnet.solana.com/genesis.tar.bz2"

mainnet_gs_ledger=""

get_endpoint_by_location() {
  local country=$(curl -s https://ipinfo.io | jq -r '.country')
  case $country in
  "JP" | "KR" | "IN" | "ID" | "HK" | "SG")
    mainnet_gs_ledger=$MAINNET_GS_LEDGER_ASIA
    ;;
  "US" | "CA" | "MX" | "BR" | "AR" | "CL")
    mainnet_gs_ledger=$MAINNET_GS_LEDGER_US
    ;;
  "FR" | "DE" | "GB" | "IT" | "ES" | "NL")
    mainnet_gs_ledger=$MAINNET_GS_LEDGER_EU
    ;;
  *)
    mainnet_gs_ledger=$MAINNET_GS_LEDGER_US
    ;;
  esac
}

check_gs() {
  local ledger_url=$1
  if ! gsutil ls $ledger_url &>/dev/null; then
    echo "[-] error accessing $ledger_url. check permissions or if the bucket URL is correct."
    exit 1
  fi
}

download_ext_rocksdb() {
  local ledger_url=$1
  local genesis_url=$2

  cd "$LEDGER" || exit

  LATEST_SNAPSHOT="$(gcloud storage ls $ledger_url | sort -n -t / -k 4 | tail -1)"
  LATEST_SNAPSHOT_SLOT=$(echo "$LATEST_SNAPSHOT" | sed 's#.*/\([0-9]\+\)/#\1#')

  gcloud storage cp "$ledger_url/$LATEST_SNAPSHOT_SLOT/rocksdb.tar.zst" .
  if [ ! -f rocksdb.tar.zst ]; then
    echo "[-] error rocksdb.tar.zst not found. $ledger_url/$LATEST_SNAPSHOT_SLOT/rocksdb.tar.zst might not be present"
    exit 1
  fi
  unzstd <rocksdb.tar.zst | tar xvf -
  wget $genesis_url
}

download_ext_snapshot() {
  local ledger_url=$1

  local fetch_snapshot=""
  cd "$LEDGER" || exit

  set +x

  is_rooted_slot $((LATEST_SNAPSHOT_SLOT + 1))
  local is_rooted_status=$?
  local full_snapshot="false"

  if [[ $LATEST_SNAPSHOT_SLOT -ge $MIN_SNAPSHOT_SLOT && $is_rooted_status -eq 0 ]]; then
    echo "[~] getting the latest full snapshot"
    fetch_snapshot=${LATEST_SNAPSHOT}snapshot-${LATEST_SNAPSHOT_SLOT}-*.tar.zst
    local snapshot_in_gs=$(gsutil ls $fetch_snapshot 2>&1)
    if ! echo "$snapshot_in_gs" | grep -q -e "No such file or directory" -e "matched no objects"; then
      full_snapshot="true"
    fi
  fi

  if [[ $full_snapshot == "false" ]]; then
    echo "[~] getting the latest hourly snapshot"
    local fetch_hourly_snapshots="$(gcloud storage ls $ledger_url/$LATEST_SNAPSHOT_SLOT/hourly | sort -n -t / -k 4)"
    for fetch_snap in $(echo $fetch_hourly_snapshots); do
      local fetch_hourly_slot=$(echo $fetch_snap | awk -F '/' '{print $NF}' | awk -F '-' '{print $2}')
      if [[ $fetch_hourly_slot -gt $MIN_SNAPSHOT_SLOT ]]; then
        is_rooted_slot $((fetch_hourly_slot + 1))
        is_rooted_status=$?
        if [ $is_rooted_status -eq 0 ]; then
          echo "[~] getting hourly snapshot, using $fetch_snap"
          fetch_snapshot=$fetch_snap
          break
        else
          echo "[~] hourly snapshot $fetch_hourly_slot is not rooted"
          continue
        fi
      fi
    done
  fi

  if [[ -z $fetch_snapshot ]]; then
    echo "[-] error no more snapshots to download"
    exit 1
  fi

  gcloud storage cp "$fetch_snapshot" .
  set -x
}

rocksdb_bounds() {
  local rooted_bounds="$($SOLANA_LEDGER_TOOL bounds -l $LEDGER |& grep "rooted slots")"
  MIN_SNAPSHOT_SLOT="$(echo $rooted_bounds | awk '{print $(NF-2)}')"
  MAX_SNAPSHOT_SLOT="$(echo $rooted_bounds | awk '{print $(NF)}')"
  echo "[~] rocksdb_bounds=$MIN_SNAPSHOT_SLOT-$MAX_SNAPSHOT_SLOT"

  if [[ -z $MIN_SNAPSHOT_SLOT || -z $MAX_SNAPSHOT_SLOT ]]; then
    echo "[-] error could not get rocksdb bounds"
    exit 1
  fi
}

echo "[~] running fetch script to download recent rocksdb and snapshots"

if [ ! -d "$LEDGER" ]; then
  echo "[-] error $LEDGER does not exist"
  exit 1
fi

if [[ -d "$LEDGER/rocksdb" && -z $MIN_SNAPSHOT_SLOT ]]; then
  echo "[-] error $LEDGER/rocksdb already exists"
  exit 1
fi

if [[ "$NETWORK" == "mainnet" ]]; then
  get_endpoint_by_location
  check_gs $mainnet_gs_ledger
  if [[ -z $MIN_SNAPSHOT_SLOT ]]; then
    download_ext_rocksdb $mainnet_gs_ledger $MAINNET_GS_GENESIS
    rocksdb_bounds
  fi
  download_ext_snapshot $mainnet_gs_ledger
elif [[ "$NETWORK" == "testnet" ]]; then
  check_gs $TESTNET_GS_LEDGER
  if [[ -z $MIN_SNAPSHOT_SLOT ]]; then
    download_ext_rocksdb $TESTNET_GS_LEDGER $TESTNET_GS_GENESIS
    rocksdb_bounds
  fi
  download_ext_snapshot $TESTNET_GS_LEDGER
elif [[ "$NETWORK" == "internal" ]]; then
  cp "$LEDGER_INT"/genesis.bin "$LEDGER"
  cp "$LEDGER_INT"/genesis.tar.bz2 "$LEDGER"
  cp -r "$LEDGER_INT"/rocksdb/ "$LEDGER"
  cp "$LEDGER_INT/snapshot-*.tar.zst" "$LEDGER"
fi
