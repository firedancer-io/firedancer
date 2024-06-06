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
fetch_latest_snapshot=""
fetch_latest_snapshot_slot=""
fetch_min_snapshot_slot=""
fetch_max_snapshot_slot=""

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
  if ! /bin/gsutil ls $ledger_url &>/dev/null; then
    echo "[-] error accessing $ledger_url. check permissions or if the bucket URL is correct."
    exit 1
  fi
}

download_ext_rocksdb() {
  local ledger_url=$1
  local genesis_url=$2

  cd "$LEDGER" || exit

  fetch_latest_snapshot="$(gcloud storage ls $ledger_url | sort -n -t / -k 4 | tail -1)"
  fetch_latest_snapshot_slot=$(echo "$fetch_latest_snapshot" | sed 's#.*/\([0-9]\+\)/#\1#')
  echo "[~] latest_snapshot=$fetch_latest_snapshot, latest_snapshot_slot=$fetch_latest_snapshot_slot"

  /bin/gsutil cp "$ledger_url/$fetch_latest_snapshot_slot/rocksdb.tar.zst" .
  if [ ! -f rocksdb.tar.zst ]; then
    echo "[-] error rocksdb.tar.zst not found. $ledger_url/$fetch_latest_snapshot_slot/rocksdb.tar.zst might not be present"
    exit 1
  fi
  unzstd <rocksdb.tar.zst | tar xvf -
  wget $genesis_url
}

download_ext_snapshot() {
  local ledger_url=$1
  local fetch_latest_snapshot_slot=$2
  local fetch_min_snapshot_slot=$3

  fetch_snapshot=""
  cd "$LEDGER" || exit

  # find a snapshot that is within the rocksdb_bounds
  set +x
  if [[ $fetch_latest_snapshot_slot -lt $fetch_min_snapshot_slot ]]; then
    local fetch_hourly_snapshots="$(gcloud storage ls $ledger_url/$fetch_latest_snapshot_slot/hourly | sort -n -t / -k 4)"
    for fetch_snap in $(echo $fetch_hourly_snapshots); do
      if [[ $(echo $fetch_snap | awk -F '/' '{print $NF}' | awk -F '-' '{print $2}') -gt $fetch_min_snapshot_slot ]]; then
        echo "[~] Found hourly snapshot, using $fetch_snap"
        fetch_snapshot=$fetch_snap
        break
      fi
    done
  fi
  if [[ -z $fetch_snapshot ]]; then
    echo "[~] Could not find hourly snapshot within rocksdb bounds, getting the latest snapshot instead $fetch_snapshot"
    fetch_snapshot=${fetch_latest_snapshot}snapshot-${fetch_latest_snapshot_slot}-*.tar.zst
  fi

  /bin/gsutil cp "$fetch_snapshot" .
  set -x
}

rocksdb_bounds() {
  local rooted_bounds="$($SOLANA_LEDGER_TOOL bounds -l $LEDGER |& grep "rooted slots")"
  fetch_min_snapshot_slot="$(echo $rooted_bounds | awk '{print $(NF-2)}')"
  fetch_max_snapshot_slot="$(echo $rooted_bounds | awk '{print $(NF)}')"
  echo "[~] rocksdb_bounds=$fetch_min_snapshot_slot-$fetch_max_snapshot_slot"

  if [[ -z $fetch_min_snapshot_slot || -z $fetch_max_snapshot_slot ]]; then
    echo "[-] error could not get rocksdb bounds"
    exit 1
  fi
}

echo "[~] running fetch script to download recent rocksdb and snapshots"

if [ ! -d "$LEDGER" ]; then
  echo "[-] error $LEDGER does not exist"
  exit 1
fi

if [ -d "$LEDGER/rocksdb" ]; then
  echo "[-] error $LEDGER/rocksdb already exists"
  exit 1
fi

if [[ "$NETWORK" == "mainnet" ]]; then
  get_endpoint_by_location
  check_gs $mainnet_gs_ledger
  download_ext_rocksdb $mainnet_gs_ledger $MAINNET_GS_GENESIS
  rocksdb_bounds
  download_ext_snapshot $mainnet_gs_ledger $fetch_latest_snapshot_slot $fetch_min_snapshot_slot
elif [[ "$NETWORK" == "testnet" ]]; then
  check_gs $TESTNET_GS_LEDGER
  download_ext_rocksdb $TESTNET_GS_LEDGER $TESTNET_GS_GENESIS
  rocksdb_bounds
  download_ext_snapshot $TESTNET_GS_LEDGER $fetch_latest_snapshot_slot $fetch_min_snapshot_slot
elif [[ "$NETWORK" == "internal" ]]; then
  cp "$LEDGER_INT"/genesis.bin "$LEDGER"
  cp "$LEDGER_INT"/genesis.tar.bz2 "$LEDGER"
  cp -r "$LEDGER_INT"/rocksdb/ "$LEDGER"
  cp "$LEDGER_INT/snapshot-*.tar.zst" "$LEDGER"
fi
