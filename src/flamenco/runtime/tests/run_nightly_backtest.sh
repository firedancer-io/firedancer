#!/bin/bash -f

send_slack_message() {
    MESSAGE=$1
    json_payload=$(cat <<EOF
{
    "text": "$MESSAGE",
    "link_names": 1
}
EOF
)
    curl -X POST -H 'Content-type: application/json' --data "$json_payload" $SLACK_WEBHOOK_URL
}

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
       SNAPSHOT="dump/$LEDGER/$2"
       shift
       shift
       ;;
    -e|--end_slot)
       END_SLOT="$2"
       shift
       shift
       ;;

    -y|--funk-pages)
       FUNK_PAGES="$2"
       shift
       shift
       ;;
    -m|--indexmax)
       INDEX_MAX="$2"
       shift
       shift
       ;;
    -t|--trash)
       TRASH_HASH="--trash-hash $2"
       shift
       shift
       ;;
    -c|--cluster-version)
        CLUSTER_VERSION="$2"
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
send_slack_message "$START_SLACK_MESSAGE"

echo "
[layout]
    affinity = \"auto\"
    bank_tile_count = 1
    shred_tile_count = 4
    exec_tile_count = 4
[tiles]
    [tiles.archiver]
        enabled = true
        end_slot = $END_SLOT
        archiver_path = \"dump/$LEDGER/rocksdb\"
    [tiles.replay]
        snapshot = \"$SNAPSHOT\"
        cluster_version = \"$CLUSTER_VERSION\"
        enable_features = [ \"$ONE_OFFS\" ]
        heap_size_gib = 50
    [tiles.gui]
        enabled = false
[funk]
    heap_size_gib = $FUNK_PAGES
    max_account_records = $INDEX_MAX
    max_database_transactions = 1024
[runtime]
    max_love_slots = 128
    max_fork_width = 32
[consensus]
    vote = false
[development]
    sandbox = false
    no_agave = true
    no_clone = true
[log]
    level_stderr = \"INFO\"
    path = \"$LOG\"
" > dump/${LEDGER}_backtest.toml

$OBJDIR/bin/firedancer-dev configure init all --config dump/${LEDGER}_backtest.toml &> /dev/null

set -x
  sudo $OBJDIR/bin/firedancer-dev backtest --config dump/${LEDGER}_backtest.toml &> /dev/null

{ set +x; } &> /dev/null

if grep -q "Backtest playback done." $LOG && ! grep -q "Bank hash mismatch!" $LOG;
then
    status=0
else
    status=1
fi

START_SLOT=$(basename $SNAPSHOT | cut -d '-' -f 2)

if [ $status -eq 0 ]; then
    END_SLACK_MESSAGE="Ledger \`$LEDGER\` Completed using Commit \`$FD_NIGHTLY_COMMIT\` on Branch \`$FD_NIGHTLY_BRANCH\`"
else
    END_SLACK_MESSAGE="@here ALERT: Ledger \`$LEDGER\` Failed using Commit \`$FD_NIGHTLY_COMMIT\` on Branch \`$FD_NIGHTLY_BRANCH\`"

    MISMATCH_LOG=$(grep "mismatch!" "$LOG" | tail -n 1)
    if [ -z "$MISMATCH_LOG" ]; then
        MISMATCH_SLOT=$(awk '/\[Replay\]/ {getline; if ($1 == "slot:") slot=$2} END {print slot}' "$LOG")
        END_SLACK_MESSAGE+=$'\n'" - Ledger \`$LEDGER\` Failed, Log at: \`$LOG\`"

    else
        MISMATCH_SLOT=$(echo "$MISMATCH_LOG" | awk -F 'slot=' '{print $2}' | awk '{print $1}')
        END_SLACK_MESSAGE+=$'\n'" - Ledger \`$LEDGER\` Starting at Slot \`$START_SLOT\` Mismatched at Slot \`$MISMATCH_SLOT\`, Log at: \`$LOG\`"
    fi
fi

send_slack_message "$END_SLACK_MESSAGE"

$OBJDIR/bin/firedancer-dev configure fini all --config dump/${LEDGER}_backtest.toml &> /dev/null
