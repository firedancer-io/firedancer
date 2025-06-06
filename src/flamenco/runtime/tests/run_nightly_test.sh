#!/bin/bash -f

LOG="/tmp/ledger_log$$"
TRASH_HASH=""
THREAD_MEM_BOUND="--thread-mem-bound 0"

while [[ $# -gt 0 ]]; do
  case $1 in
    -l|--ledger)
       LEDGER="$2"
       shift
       shift
       ;;
    -s|--snapshot)
       SNAPSHOT="--snapshot dump/$LEDGER/$2"
       shift
       shift
       ;;
    -e|--end_slot)
       END_SLOT="--end-slot $2"
       shift
       shift
       ;;
    -p|--pages)
       PAGES="--page-cnt $2"
       shift
       shift
       ;;
    -y|--funk-pages)
       FUNK_PAGES="--funk-page-cnt $2"
       shift
       shift
       ;;
    -m|--indexmax)
       INDEX_MAX="--index-max $2"
       shift
       shift
       ;;
    -t|--trash)
       TRASH_HASH="--trash-hash $2"
       shift
       shift
       ;;
    -c|--cluster-version)
        CLUSTER_VERSION="--cluster-version $2"
        shift
        ;;
    -*|--*)
       echo "unknown option $1"
       exit 1
       ;;
    *)
       POSITION_ARGS+=("$1")
       shift
       ;;
  esac
done

CHECKPT_PATH=/data/nightly-mismatches/${LEDGER}_mismatch

allocated_pages=$($FD_NIGHTLY_REPO_DIR/"$OBJDIR"/bin/fd_shmem_cfg query)
gigantic_pages=$(echo "$allocated_pages" | grep "gigantic pages:" -A 1 | grep -oP '\d+(?= total)')
huge_pages=$(echo "$allocated_pages" | grep "huge pages:" -A 1 | grep -oP '\d+(?= total)')


if [ "$gigantic_pages" -eq 0 ] && [ "$huge_pages" -eq 0 ]; then
    echo "No gigantic or huge pages configured, Configuring..."
    sudo $FD_NIGHTLY_REPO_DIR/"$OBJDIR"/bin/fd_shmem_cfg alloc 175 gigantic 0 alloc 300 huge 0
else
    echo "Currently allocated gigantic pages: $gigantic_pages"
    echo "Currently allocated huge pages: $huge_pages"
fi

START_SLACK_MESSAGE="ALERT: Starting Run for Ledger \`$LEDGER\` using Commit \`$FD_NIGHTLY_COMMIT\` on Branch \`$FD_NIGHTLY_BRANCH\`"
start_json_payload=$(cat <<EOF
{
    "text": "$START_SLACK_MESSAGE"
}
EOF
)
curl -X POST -H 'Content-type: application/json' --data "$start_json_payload" $SLACK_WEBHOOK_URL

set -x
  "$OBJDIR"/bin/fd_ledger \
    --reset 1 \
    --cmd replay \
    --rocksdb dump/$LEDGER/rocksdb \
    $TRASH_HASH \
    $INDEX_MAX \
    $END_SLOT \
    --funk-only 1 \
    --txn-max 100 \
    $PAGES \
    $FUNK_PAGES \
    $SNAPSHOT \
    $THREAD_MEM_BOUND \
    $CLUSTER_VERSION \
    --checkpt-mismatch 1 \
    --checkpt-path $CHECKPT_PATH \
    --slot-history 5000 \
    --copy-txn-status 0 \
    --allocator wksp \
    --on-demand-block-ingest 1 \
    --tile-cpus 5-21 >& $LOG

status=$?

if [ $status -eq 0 ]; then
    END_SLACK_MESSAGE="Ledger \`$LEDGER\` Completed using Commit \`$FD_NIGHTLY_COMMIT\` on Branch \`$FD_NIGHTLY_BRANCH\`"
else
    END_SLACK_MESSAGE="@here ALERT: Ledger \`$LEDGER\` Failed using Commit \`$FD_NIGHTLY_COMMIT\` on Branch \`$FD_NIGHTLY_BRANCH\`"
fi

START_SLOT=$(basename $SNAPSHOT | cut -d '-' -f 2)

MISMATCHED=$(grep "Bank hash mismatch!" "$LOG" | tail -n 1)
REPLAY_COMPLETED=$(grep "replay completed" "$LOG" | tail -n 1)

if [[ -n "$REPLAY_COMPLETED" ]]; then
    REPLAY_COMPLETED_LINE=$(grep "replay completed" "$LOG" | tail -n 1)
    REPLAY_INFO="${REPLAY_COMPLETED_LINE#*replay completed - }"
    END_SLACK_MESSAGE+=$'\n'" - Ledger \`$LOG\` Starting at Slot \`$START_SLOT\` Passed: $REPLAY_INFO"
elif [[ -n "$MISMATCHED" ]]; then
    MISMATCH_SLOT=$(grep "Bank hash mismatch!" "$LOG" | tail -n 1 | awk -F'slot=' '{print $2}' | awk '{print $1}')
    END_SLACK_MESSAGE+=$'\n'" - Ledger \`$LEDGER\` Starting at Slot \`$START_SLOT\` Mismatched at Slot \`$MISMATCH_SLOT\`, Log at: \`$LOG\`, Checkpoint at: \`$CHECKPT_PATH\`"
else
    END_SLACK_MESSAGE+=$'\n'" - Ledger \`$LEDGER\` Failed, Log at: \`$LOG\`"
fi

json_payload=$(cat <<EOF
{
    "text": "$END_SLACK_MESSAGE",
    "link_names": 1
}
EOF
)
curl -X POST -H 'Content-type: application/json' --data "$json_payload" $SLACK_WEBHOOK_URL

sleep 300
