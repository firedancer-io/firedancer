#!/bin/bash

# This script does a replay of a ledger and compares the result bank hashes to the original ledger
# It also uploads a minimized ledger of one block around the mismatch slot if specified

rep_fd_ledger_dump="$FIREDANCER/dump"
rep_temp_ledger_upload="$FIREDANCER/.ledger-min"
rep_run_ledger_tests="src/flamenco/runtime/tests/run_ledger_tests.sh"

if [ -z "$ROOT_DIR" ]; then
  ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
fi

rm -rf "$rep_fd_ledger_dump"
mkdir -p "$rep_fd_ledger_dump"
cp -r "$LEDGER_MIN" "$rep_fd_ledger_dump"

rep_snapshot=$(find "$LEDGER_MIN" -type f -name "snapshot-*" | head -n 1)
rep_snapshot_basename=$(basename "$rep_snapshot")
rep_ledger_min_basename=$(basename "$LEDGER_MIN")

# For --mode edge, set the value of START_SLOT and END_SLOT
if [ -z "$START_SLOT" ] || [ -z "$END_SLOT" ]; then
  START_SLOT=$(echo "$rep_snapshot_basename" | sed -E 's/.*snapshot-([0-9]+)-.*/\1/')
  END_SLOT=$((START_SLOT + (2 * EDGE_OFFSET)))
fi

cd "$FIREDANCER" || exit
set -x
replay_output=$("$rep_run_ledger_tests" -l "$rep_ledger_min_basename" -s "$rep_snapshot_basename" -e "$END_SLOT" -p $GIGANTIC_PAGES -m $INDEX_MAX 2>&1)
set +x
echo "$replay_output"

rep_mismatch_slot=$(echo "$replay_output" | grep -oP "Bank hash mismatch! slot=\K\d+")
rep_mismatch_msg=$(echo "$replay_output" | grep -o "Bank hash mismatch!.*")

if [ -z "$rep_mismatch_slot" ]; then
  echo "[+] ledger test success"

  # This is used in `ledger_conformance all --mode exact --repetitions multiple`
  # It is simply ignored in other cases
  # Signifies that the end of the ledger has been reached
  START_SLOT=$((END_SLOT + 1))
else
  echo "[-] ledger test failed"
  echo "[-] mismatch_slot: $rep_mismatch_slot"
  echo "[-] mismatch_msg: $rep_mismatch_msg"

  if [ -n "$UPLOAD_URL" ]; then
    # Minimize to one block around the mismatch block by locating the mismatch slot
    # And then calling minify with the exact bounds [bhm-1, bhm+1]
    rep_mismatch_start=$((rep_mismatch_slot - 1))
    if [ "$rep_mismatch_start" -lt "$START_SLOT" ]; then
      rep_mismatch_start=$START_SLOT
    fi
    rep_mismatch_end=$((rep_mismatch_slot + 1))
    if [ "$rep_mismatch_end" -gt "$END_SLOT" ]; then
      rep_mismatch_end=$END_SLOT
    fi
    rm -rf "$rep_temp_ledger_upload"
    mkdir -p "$rep_temp_ledger_upload"
    set -x
    NETWORK=$NETWORK \
      MODE=exact \
      LEDGER=$LEDGER_MIN \
      LEDGER_MIN=$rep_temp_ledger_upload \
      IS_VERIFY=false \
      SLOTS_IN_EPOCH=$SLOTS_IN_EPOCH \
      START_SLOT=$rep_mismatch_start \
      END_SLOT=$rep_mismatch_end \
      SOLANA_LEDGER_TOOL=$SOLANA_LEDGER_TOOL \
      FIREDANCER=$FIREDANCER \
      $ROOT_DIR/minify.sh
    rep_minify_status=$?
    set +x
    if [ $rep_minify_status -ne 0 ]; then
      echo "[-] failed to minify ledger around mismatch slot $rep_mismatch_slot for upload"
      exit 1
    fi

    # Upload the ledger to gcloud storage
    # Bucket key activation is already handled by the run_ledger_tests script
    echo "[~] Compressing $rep_temp_ledger_upload to $FIREDANCER/$NETWORK-$rep_mismatch_slot.tar.gz"
    tar -czvf $FIREDANCER/$NETWORK-$rep_mismatch_slot.tar.gz $rep_temp_ledger_upload
    echo "[~] Uploading $FIREDANCER/$NETWORK-$rep_mismatch_slot.tar.gz to $UPLOAD_URL"
    /bin/gsutil cp -r "$FIREDANCER/$NETWORK-$rep_mismatch_slot.tar.gz" $UPLOAD_URL
  fi
  
  # Set new values of START_SLOT for the next iteration; END_SLOT does not change
  # this is used for `ledger_conformance all --mode exact --repetitions multiple` and ignored in other cases
  START_SLOT=$((rep_mismatch_slot + 1))
fi
