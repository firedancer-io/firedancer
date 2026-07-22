#!/bin/bash
#
# Continuous offline-replay backtest harness. Watches a Solana ledger
# archive bucket for new ledgers, replays the newest one with
# `firedancer-dev backtest`, and uploads a minimized reproduction ledger
# whenever a bank hash mismatch or crash occurs.
#
# See README.md in this directory for a full description, the required
# environment variables, and operational notes.
#
# NOTE: several variables (e.g. LEDGER_REPLAY_SNAPSHOT) intentionally hold
# unquoted globs that must expand at use sites, so quoting is deliberately
# loose in those places.

OBJDIR=${OBJDIR:-build/native/gcc}   # relative to FIREDANCER_REPO
LOG_DIR=${LOG_DIR:-/data/offline-replay/logs}

# All harness output (builds, downloads, git operations, step markers) is
# logged under $LOG_DIR: idle polling goes to harness.log, and each ledger
# run is rotated into its own <network>_offline_replay_<slot>_harness.log.
HARNESS_LOG=$LOG_DIR/harness.log

#---------------------------------------------------------------------------
# Slack helpers
#---------------------------------------------------------------------------

post_to_slack() {
    local webhook_url=$1
    local message=$2
    local json_payload
    json_payload=$(cat <<EOF
{
    "text": "$message",
    "link_names": 1
}
EOF
)
    curl -sS -o /dev/null -X POST -H 'Content-type: application/json' --data "$json_payload" $webhook_url
}

send_slack_message()          { post_to_slack "$SLACK_WEBHOOK_URL" "$1"; }
send_mismatch_slack_message() { post_to_slack "$SLACK_MISMATCH_WEBHOOK_URL" "$1"; }
send_slack_debug_message()    { post_to_slack "$SLACK_DEBUG_WEBHOOK_URL" "$1"; }

# Timestamped marker separating steps in the harness log.
log_step() {
    echo ""
    echo "=== [$(date '+%Y-%m-%d %H:%M:%S')] $1 ==="
}

# Alert and stop: called when producing or uploading a minimization artifact
# fails; continuing would announce (or replay past) a broken reproduction.
fail_minimization() {
    send_slack_message "@here $1. Exiting; minimized reproduction is incomplete."
    exit 1
}

#---------------------------------------------------------------------------
# Rooted-slot queries (via agave-ledger-tool)
#---------------------------------------------------------------------------

# True if $1 is in the ledger's rooted chain. (is_full alone would also
# match fully-shredded slots on abandoned forks, which create-snapshot
# rejects.)
slot_is_rooted() {
    local output
    output=$($AGAVE_LEDGER_TOOL slot $1 -l $LEDGER_DIR)
    [[ "$output" == *"(root)"* ]]
}

# Print the nearest rooted slot at or below $1. Rooted slots are normally at
# most a few slots apart, so give up (non-zero exit) after 512 steps rather
# than walking forever on a bogus starting slot.
find_rooted_slot_at_or_below() {
    local slot=$1
    local floor=$((slot-512))
    while ! slot_is_rooted $slot; do
        slot=$((slot-1))
        if [ "$slot" -le 0 ] || [ "$slot" -le "$floor" ]; then
            send_slack_message "@here No rooted slot found at or below \`$1\`. Exiting."
            return 1
        fi
    done
    echo $slot
}

# Print the nearest rooted slot at or above $1. Gives up (non-zero exit)
# after 512 steps.
find_rooted_slot_at_or_above() {
    local slot=$1
    local ceiling=$((slot+512))
    while ! slot_is_rooted $slot; do
        slot=$((slot+1))
        if [ "$slot" -ge "$ceiling" ]; then
            send_slack_message "@here No rooted slot found at or above \`$1\`. Exiting."
            return 1
        fi
    done
    echo $slot
}

#---------------------------------------------------------------------------
# Ledger discovery and download
#---------------------------------------------------------------------------

# Sets NEWEST_BUCKET_SLOT (highest slot directory in the bucket) and
# LATEST_RUN_BUCKET_SLOT (last slot this harness processed).
find_newest_bucket_slot() {
    local newest_bucket
    newest_bucket=$(gcloud storage ls $BUCKET_ENDPOINT --billing-project=$BILLING_PROJECT | sort -n -t / -k 4 | tail -n 1)
    NEWEST_BUCKET_SLOT=$(echo $newest_bucket | awk -F'/' '{print $(NF-1)}')
    LATEST_RUN_BUCKET_SLOT=$(cat $LATEST_RUN_BUCKET_SLOT_FILE)
}

# Determine the agave-ledger-tool version that produced this ledger from the
# version.txt that lives alongside the ledger in its bucket, e.g.
#   gs://testnet-ledger-us-sv15/410883856/version.txt
#   -> "agave-ledger-tool 4.1.0-beta.1 (src:8e81e22a; feat:3b4f0ba8, client:Agave)"
# Falls back to the pre-existing AGAVE_TAG if version.txt cannot be read.
determine_agave_tag() {
    local version_txt agave_version
    version_txt=$(gcloud storage cat ${BUCKET_ENDPOINT}/${NEWEST_BUCKET_SLOT}/version.txt --billing-project=$BILLING_PROJECT 2>/dev/null)
    agave_version=$(echo "$version_txt" | awk '{print $2}')
    if [ -n "$agave_version" ]; then
        export AGAVE_TAG="v${agave_version}"
        echo "Using AGAVE_TAG=$AGAVE_TAG (from ${BUCKET_ENDPOINT}/${NEWEST_BUCKET_SLOT}/version.txt)"
    else
        echo "Could not read version.txt for slot $NEWEST_BUCKET_SLOT; falling back to AGAVE_TAG=$AGAVE_TAG"
    fi
    send_slack_message "Using agave tag \`$AGAVE_TAG\` for ledger \`$NEWEST_BUCKET_SLOT\` (from version.txt)"
}

# Check out $AGAVE_TAG and build agave-ledger-tool; sets AGAVE_LEDGER_TOOL to
# the built binary. Versions >= 3.1.0 moved the tool into the dev-bins
# workspace.
build_agave_ledger_tool() {
    cd $AGAVE_REPO
    git pull
    git checkout $AGAVE_TAG

    local agave_version
    agave_version=$(echo "$AGAVE_TAG" | sed 's/^v//')
    if [ "$(printf '%s\n' "$agave_version" "3.1.0" | sort -V | head -n1)" = "3.1.0" ]; then
        cargo clean
        cargo build --manifest-path dev-bins/Cargo.toml -p agave-ledger-tool --release
        AGAVE_LEDGER_TOOL="${AGAVE_REPO}/dev-bins/target/release/agave-ledger-tool"
    else
        cargo clean
        cargo build --release
        AGAVE_LEDGER_TOOL="${AGAVE_REPO}/target/release/agave-ledger-tool"
    fi
}

# Sets up LOG, TEMP_LOG, LEDGER_DIR, OLD_SNAPSHOTS_DIR and SOLANA_BUCKET_PATH
# for this ledger, downloads genesis, and leaves the cwd in LEDGER_DIR.
prepare_ledger_dir() {
    mkdir -p $LOG_DIR
    LOG=$LOG_DIR/${NETWORK}_offline_replay_${NEWEST_BUCKET_SLOT}.log
    TEMP_LOG=$LOG_DIR/${NETWORK}_offline_replay_${NEWEST_BUCKET_SLOT}_temp.log
    send_slack_message "Log File: \`$LOG\`"
    echo "" > $LOG && chmod 777 $LOG

    LEDGER_DIR=${FIREDANCER_REPO}/dump/${NETWORK}-${NEWEST_BUCKET_SLOT}
    send_slack_message "Ledger Directory: \`$LEDGER_DIR\`"
    OLD_SNAPSHOTS_DIR=${LEDGER_DIR}/old_snapshots
    SOLANA_BUCKET_PATH=${BUCKET_ENDPOINT}/${NEWEST_BUCKET_SLOT}

    mkdir -p $LEDGER_DIR
    mkdir -p $OLD_SNAPSHOTS_DIR
    cd $LEDGER_DIR

    # Only extract genesis.bin: the tarball also bundles a stub rocksdb/ that
    # would shadow the real ledger if extracted.
    wget -q -O genesis.tar.bz2 $GENESIS_FILE
    tar -xjf genesis.tar.bz2 genesis.bin
}

# Download and extract the ledger's rocksdb archive into $LEDGER_DIR/rocksdb.
# The archive can lag the bucket-directory creation, so poll hourly until it
# appears; retry failed downloads every 5 minutes. Expects cwd = LEDGER_DIR.
download_rocksdb() {
    send_slack_message "Downloading rocksdb from \`$SOLANA_BUCKET_PATH\` to \`$LEDGER_DIR/rocksdb\`"

    if [ -e "$LEDGER_DIR/rocksdb" ]; then
        send_slack_message "Rocksdb already exists at \`$LEDGER_DIR/rocksdb\`"
        return
    fi

    while true; do
        if gcloud storage ls ${SOLANA_BUCKET_PATH}/rocksdb.tar.zst --billing-project=$BILLING_PROJECT | grep -q 'rocksdb.tar.zst'; then
            send_slack_message "Rocksdb found. Starting to copy..."
            break
        else
            send_slack_message "Rocksdb not found. Checking again in 1 hour."
            sleep 3600
        fi
    done

    until gcloud storage cp ${SOLANA_BUCKET_PATH}/rocksdb.tar.zst . --billing-project=$BILLING_PROJECT; do
        send_slack_message "rocksdb download failed for \`$SOLANA_BUCKET_PATH\`. Retrying in 5 minutes."
        sleep 300
    done

    rm -rf rocksdb_extract_tmp && mkdir rocksdb_extract_tmp
    if ! tar --zstd -xf rocksdb.tar.zst -C rocksdb_extract_tmp; then
        send_slack_message "@here rocksdb extraction failed for \`$SOLANA_BUCKET_PATH\`. Exiting."
        exit 1
    fi
    mv rocksdb_extract_tmp/rocksdb $LEDGER_DIR/rocksdb
    rm -rf rocksdb_extract_tmp rocksdb.tar.zst
    send_slack_message "Downloaded rocksdb to \`$LEDGER_DIR/rocksdb\`"
}

# Compute the rocksdb rooted bounds and pick the replay start snapshot: the
# lowest-slot rooted snapshot (base or hourly) within those bounds. Sets
# ROCKSDB_ROOTED_MIN/MAX, CLOSEST_HOURLY_SLOT/URL/FILENAME.
# Expects cwd = LEDGER_DIR.
select_replay_snapshot() {
    gcloud storage cp ${SOLANA_BUCKET_PATH}/bounds.txt . --billing-project=$BILLING_PROJECT

    local bounds
    bounds=$( $AGAVE_LEDGER_TOOL bounds -l $LEDGER_DIR --force-update-to-open )
    ROCKSDB_ROOTED_MIN=$(echo "$bounds" | grep "rooted" | awk '{print $6}')
    ROCKSDB_ROOTED_MAX=$(echo "$bounds" | grep "rooted" | awk '{print $8}')
    echo "RocksDB Bounds: $ROCKSDB_ROOTED_MIN - $ROCKSDB_ROOTED_MAX"

    local hourly_snapshot_dir=${SOLANA_BUCKET_PATH}/hourly
    echo "Hourly Snapshot Directory: $hourly_snapshot_dir"

    local base_snapshot hourly_snapshots
    base_snapshot=$(gcloud storage ls "${SOLANA_BUCKET_PATH}/snapshot*.tar.zst" --billing-project=$BILLING_PROJECT | sort -n -t - -k 3)
    hourly_snapshots=$(gcloud storage ls "${hourly_snapshot_dir}" --billing-project=$BILLING_PROJECT | sort -n -t - -k 3)

    # Reset the selection for this ledger: these are globals, and stale
    # values from a previous ledger must not leak into this one.
    CLOSEST_HOURLY_SLOT=${ROCKSDB_ROOTED_MAX}
    CLOSEST_HOURLY_URL=
    CLOSEST_HOURLY_FILENAME=

    local snapshot snapshot_slot
    for snapshot in ${base_snapshot} ${hourly_snapshots}; do
        echo "Checking Snapshot: $snapshot"
        snapshot_slot=$(basename $snapshot | cut -d '-' -f 2)
        if slot_is_rooted $snapshot_slot && \
           (( snapshot_slot >= ROCKSDB_ROOTED_MIN && snapshot_slot < CLOSEST_HOURLY_SLOT )); then
            CLOSEST_HOURLY_SLOT=$snapshot_slot
            CLOSEST_HOURLY_URL=$snapshot
            CLOSEST_HOURLY_FILENAME=$(basename $CLOSEST_HOURLY_URL)
            echo "Snapshot $snapshot is rooted and within bounds"
        fi
    done

    if [ -z "$CLOSEST_HOURLY_URL" ]; then
        send_slack_message "@here No rooted snapshot found within rocksdb bounds for ledger \`$NEWEST_BUCKET_SLOT\`. Exiting."
        exit 1
    fi
}

# Download the selected snapshot into LEDGER_DIR (skipped if already there).
# Expects cwd = LEDGER_DIR.
download_replay_snapshot() {
    send_slack_message "Downloading Closest Hourly Snapshot \`$CLOSEST_HOURLY_SLOT\` from \`$SOLANA_BUCKET_PATH\`"
    echo "$LEDGER_DIR/$CLOSEST_HOURLY_FILENAME"
    # Drop resume snapshots left by an interrupted prior run: the snapshot
    # loader picks the latest archive in the directory, which would silently
    # diverge from LEDGER_REPLAY_SNAPSHOT below.
    find "$LEDGER_DIR" -maxdepth 1 -type f \( -name 'snapshot-*.tar*' -o -name 'incremental-snapshot-*.tar*' \) ! -name "$CLOSEST_HOURLY_FILENAME" -delete
    if [ -e "$LEDGER_DIR/$CLOSEST_HOURLY_FILENAME" ]; then
        send_slack_message "Hourly snapshot already exists at \`$LEDGER_DIR/$CLOSEST_HOURLY_FILENAME\`"
    else
        rm -f $LEDGER_DIR/snapshot*.tar.zst
        local snapshot_tmp="$LEDGER_DIR/$CLOSEST_HOURLY_FILENAME.tmp"
        rm -f "$snapshot_tmp"
        gcloud storage cp "$CLOSEST_HOURLY_URL" "$snapshot_tmp" --billing-project="$BILLING_PROJECT" || {
            send_slack_message "@here snapshot download failed for \`$CLOSEST_HOURLY_URL\`. Exiting."
            exit 1
        }
        mv "$snapshot_tmp" "$LEDGER_DIR/$CLOSEST_HOURLY_FILENAME"
        send_slack_message "Downloaded hourly snapshot to \`$LEDGER_DIR/$CLOSEST_HOURLY_FILENAME\`"
    fi
}

#---------------------------------------------------------------------------
# Firedancer build and backtest
#---------------------------------------------------------------------------

# Build the latest Firedancer on $FD_BRANCH from scratch. Sets FD_COMMIT and
# leaves the cwd in FIREDANCER_REPO.
build_firedancer() {
    cd $FIREDANCER_REPO
    git pull
    git checkout $FD_BRANCH
    git pull origin $FD_BRANCH
    export FD_COMMIT=$(git rev-parse HEAD)

    PATH=/opt/rh/gcc-toolset-12/root/usr/bin:$PATH
    export PATH
    PKG_CONFIG_PATH=/usr/lib64/pkgconfig:$PKG_CONFIG_PATH

    make distclean && make clean
    ./deps.sh nuke
    git submodule update --init --recursive --force
    echo "y" | FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh +dev
    EXTRAS=offline-replay make -j
}

# Convert the downloaded rocksdb into a shredcap capture covering the replay
# range; the backtest ingests the capture (single streamable file) while the
# rocksdb directory is kept for agave-ledger-tool and fd_ledger during
# minimization. Skipped if the capture already exists. Expects
# build_firedancer to have run (needs fd_blockstore2shredcap) and cwd =
# FIREDANCER_REPO (OBJDIR is relative).
convert_rocksdb_to_shredcap() {
    SHREDCAP_FILE=$LEDGER_DIR/shreds.pcapng.zst
    if [ -e "$SHREDCAP_FILE" ]; then
        send_slack_message "Shredcap already exists at \`$SHREDCAP_FILE\`"
        return
    fi

    # fd_blockstore2shredcap refuses to overwrite; write to a temp name and
    # move so an interrupted conversion never leaves a plausible-looking file.
    rm -f $SHREDCAP_FILE.tmp
    $OBJDIR/bin/fd_blockstore2shredcap \
        --rocksdb $LEDGER_DIR/rocksdb \
        --out $SHREDCAP_FILE.tmp \
        --start-slot $CLOSEST_HOURLY_SLOT \
        --end-slot $ROCKSDB_ROOTED_MAX \
        --zstd || {
        send_slack_message "@here rocksdb to shredcap conversion failed for \`$LEDGER_DIR\`. Exiting."
        exit 1
    }
    mv $SHREDCAP_FILE.tmp $SHREDCAP_FILE
    send_slack_message "Converted rocksdb to shredcap at \`$SHREDCAP_FILE\`"
}

# Copy the offline_replay.toml template into LEDGER_DIR and fill in its
# {placeholder} values for this run.
render_backtest_config() {
    cp $FIREDANCER_REPO/contrib/offline-replay/offline_replay.toml $LEDGER_DIR

    # `configure fini all` (end of ledger, or any manual run) unlinks
    # genesis.bin via the dev genesis stage; cheap re-extract so every pass
    # is guaranteed to have it (eg. the gui identifies the cluster from it).
    tar -xjf $LEDGER_DIR/genesis.tar.bz2 -C $LEDGER_DIR genesis.bin

    # Pin {user} to the actual runtime user: without it firedancer guesses
    # from SUDO_USER/LOGNAME, which is wrong when run via sudo/su and makes
    # firedancer-dev exit immediately with a uid mismatch.
    local run_user
    run_user=$(id -un)

    sed -i "s#{user}#${run_user}#g"            "$LEDGER_DIR/offline_replay.toml"
    sed -i "s#{ledger}#${LEDGER_DIR}#g"        "$LEDGER_DIR/offline_replay.toml"
    sed -i "s#{end_slot}#${ROCKSDB_ROOTED_MAX}#g" "$LEDGER_DIR/offline_replay.toml"
    sed -i "s#{index_max}#${INDEX_MAX}#g"      "$LEDGER_DIR/offline_replay.toml"
    sed -i "s#{log}#${TEMP_LOG}#g"             "$LEDGER_DIR/offline_replay.toml"

    echo "toml at: $LEDGER_DIR/offline_replay.toml"
}

# Run one backtest pass over the ledger. Sets status=0 if playback completed
# with no bank hash mismatch, status=1 otherwise. Backtest output goes to
# TEMP_LOG, which is appended to LOG afterwards. Expects cwd = FIREDANCER_REPO
# (OBJDIR is relative).
run_backtest() {
    # configure output is small and shows startup problems (permissions, uid
    # mismatches, hugepages) that the backtest itself silently dies on.
    $OBJDIR/bin/firedancer-dev configure init all --config $LEDGER_DIR/offline_replay.toml

    $OBJDIR/bin/firedancer-dev configure fini cpuset --config $LEDGER_DIR/offline_replay.toml

    rm -rf $TEMP_LOG && touch $TEMP_LOG && chmod 777 $TEMP_LOG

    chmod -R 0700 $LEDGER_DIR

    set -x
        $OBJDIR/bin/firedancer-dev backtest --config $LEDGER_DIR/offline_replay.toml &> /dev/null

    rm -rf $LEDGER_DIR/accounts.db

    if grep -q "Backtest playback done." $TEMP_LOG && ! grep -q "Bank hash mismatch!" $TEMP_LOG;
    then
        status=0
    else
        status=1
    fi
    echo "status: $status"

    cat $TEMP_LOG >> $LOG

    { set +x; } &> /dev/null
}

#---------------------------------------------------------------------------
# Mismatch/failure minimization
#---------------------------------------------------------------------------

# Called when a backtest pass failed. Figures out the bad slot, creates a
# minimized reproduction ledger around it, uploads it to
# gs://firedancer-ci-resources/, and points LEDGER_REPLAY_SNAPSHOT at a new
# snapshot just past the bad slot so the replay loop can resume from there.
# Exits the script after more than 5 mismatches or 5 failures.
# Expects cwd = FIREDANCER_REPO; leaves cwd in LEDGER_DIR.
handle_replay_failure() {
    log_step "Backtest pass failed; minimizing"

    # Classify the failure from TEMP_LOG, which holds only the current pass
    # (LOG accumulates every pass, so grepping it could misattribute an
    # earlier pass's mismatch to this one).  BAD_SLOT is the slot the
    # minimized reproduction is built around.
    BAD_SLOT=0
    MISMATCH_LINE=$(grep "mismatch!" "$TEMP_LOG" | tail -n 1)

    if [ -z "$MISMATCH_LINE" ]; then
        # No mismatch line: the run crashed/failed some other way.  The
        # crash slot is the next populated slot after the last one that
        # replayed cleanly; slot numbers can be skipped, so query the ledger
        # for it rather than assuming last+1.
        CURRENT_FAILURE_COUNT=$((CURRENT_FAILURE_COUNT + 1))
        LAST_CLEAN_SLOT=$(grep "Bank hash matches! slot=" "$TEMP_LOG" | tail -n 1 | grep -oP 'slot=\K[0-9]+')
        if [ -n "$LAST_CLEAN_SLOT" ]; then
            BAD_SLOT=$(find_rooted_slot_at_or_above $((LAST_CLEAN_SLOT+1))) || exit 1
        fi
        send_slack_message "@here Failure occurred on slot: \`$BAD_SLOT\`. Minimizing failure"
    else
        CURRENT_MISMATCH_COUNT=$((CURRENT_MISMATCH_COUNT + 1))
        BAD_SLOT=$(tail -n 100 "$TEMP_LOG" | awk '/Bank hash mismatch/ {match($0, /slot=[0-9]+/, a); if (a[0]) slot=substr(a[0],6)} END {print slot}')
        send_slack_message "@here Mismatch occurred on slot: \`$BAD_SLOT\`. Minimizing mismatch"
    fi

    # If the slot could not be parsed out of the log, there is nothing to
    # minimize — bail out instead of searching from a garbage slot number.
    if ! [[ "$BAD_SLOT" =~ ^[0-9]+$ ]] || [ "$BAD_SLOT" -le 0 ]; then
        send_slack_message "@here Could not determine the failing slot from \`$TEMP_LOG\` (got \`$BAD_SLOT\`). Exiting; investigate manually."
        exit 1
    fi

    if [ "$CURRENT_MISMATCH_COUNT" -gt 5 ] || [ "$CURRENT_FAILURE_COUNT" -gt 5 ]; then
        send_slack_message "Mismatch count: \`$CURRENT_MISMATCH_COUNT\`"
        send_slack_message "Failure count: \`$CURRENT_FAILURE_COUNT\`"
        send_slack_message "Exiting script due to high mismatch or failure count"
        exit 1
    fi

    # Keep a copy of the snapshot this pass replayed from.
    cp $LEDGER_REPLAY_SNAPSHOT $OLD_SNAPSHOTS_DIR

    # Bracket the bad slot with rooted slots:
    #   MINIMIZED_START_SLOT - nearest rooted slot before the bad slot (the
    #                          minimized snapshot is created here), clamped to
    #                          the snapshot slot this pass replayed from
    #   PREVIOUS_ROOTED_SLOT - the rooted slot before that (start of the
    #                          minified rocksdb range)
    #   NEXT_ROOTED_SLOT     - nearest rooted slot after the bad slot (replay
    #                          resumes from a snapshot created here)
    MINIMIZED_START_SLOT=$(find_rooted_slot_at_or_below $((BAD_SLOT-1))) || exit 1
    echo "Found minimized rooted slot: $MINIMIZED_START_SLOT"
    if [ "$MINIMIZED_START_SLOT" -lt "$REPLAY_SNAPSHOT_SLOT_NUMBER" ]; then
        MINIMIZED_START_SLOT=$REPLAY_SNAPSHOT_SLOT_NUMBER
    fi
    echo "Minimized start slot: $MINIMIZED_START_SLOT"

    PREVIOUS_ROOTED_SLOT=$(find_rooted_slot_at_or_below $((MINIMIZED_START_SLOT-1))) || exit 1
    echo "Found previous rooted slot: $PREVIOUS_ROOTED_SLOT"

    NEXT_ROOTED_SLOT=$(find_rooted_slot_at_or_above $((BAD_SLOT+1))) || exit 1
    echo "Found next rooted slot: $NEXT_ROOTED_SLOT"

    # Create a full snapshot at PREVIOUS_ROOTED_SLOT (replacing the one we
    # replayed from) unless it would land at or before that snapshot's slot.
    if [ "$PREVIOUS_ROOTED_SLOT" -gt "$REPLAY_SNAPSHOT_SLOT_NUMBER" ]; then
        echo "Creating new snapshot at $PREVIOUS_ROOTED_SLOT"
        $AGAVE_LEDGER_TOOL create-snapshot $PREVIOUS_ROOTED_SLOT -l $LEDGER_DIR --enable-capitalization-change \
            || fail_minimization "create-snapshot at slot \`$PREVIOUS_ROOTED_SLOT\` failed"
        sleep 10
        rm $LEDGER_DIR/ledger_tool -rf
        rm $LEDGER_REPLAY_SNAPSHOT
    fi
    if [ "$PREVIOUS_ROOTED_SLOT" -lt "$REPLAY_SNAPSHOT_SLOT_NUMBER" ]; then
        PREVIOUS_ROOTED_SLOT=$REPLAY_SNAPSHOT_SLOT_NUMBER
    fi
    echo "Minified rocksdb start slot: $PREVIOUS_ROOTED_SLOT"

    # Create a full snapshot at the rooted slot right after the bad slot;
    # replay resumes from this one.
    echo "Creating new snapshot at $NEXT_ROOTED_SLOT"
    $AGAVE_LEDGER_TOOL create-snapshot $NEXT_ROOTED_SLOT -l $LEDGER_DIR --enable-capitalization-change \
        || fail_minimization "create-snapshot at slot \`$NEXT_ROOTED_SLOT\` failed"
    sleep 10
    rm $LEDGER_DIR/ledger_tool -rf

    echo "New (right after) snapshot created at $NEXT_ROOTED_SLOT"
    for NEXT_REPLAY_SNAPSHOT_FILE in $LEDGER_DIR/snapshot-${NEXT_ROOTED_SLOT}*; do
        send_slack_message "New (right after) snapshot created at \`$NEXT_REPLAY_SNAPSHOT_FILE\`"
    done

    # Assemble a self-contained minimized ledger: genesis + minified rocksdb
    # + minimized snapshot, covering PREVIOUS_ROOTED_SLOT through
    # NEXT_ROOTED_SLOT+32.
    MISMATCH_DIR=$LEDGER_DIR/$NETWORK-${BAD_SLOT}
    mkdir -p $MISMATCH_DIR
    cp "$LEDGER_DIR/genesis.tar.bz2" "$MISMATCH_DIR"
    tar -xjf "$MISMATCH_DIR/genesis.tar.bz2" -C "$MISMATCH_DIR" genesis.bin \
        || fail_minimization "extracting genesis.bin for minimized ledger failed"

    MINIMIZED_END_SLOT=$((NEXT_ROOTED_SLOT+32))
    send_slack_message "Minifying rocksdb for mismatch"
    "$OBJDIR"/bin/fd_ledger \
        --cmd minify \
        --rocksdb $LEDGER_DIR/rocksdb \
        --minified-rocksdb $MISMATCH_DIR/rocksdb \
        --start-slot $PREVIOUS_ROOTED_SLOT \
        --end-slot $MINIMIZED_END_SLOT >> $LOG 2>&1 \
        || fail_minimization "fd_ledger minify failed (see \`$LOG\`)"
    sleep 10

    # Park the resume snapshot in old_snapshots so create-snapshot below
    # starts from the PREVIOUS_ROOTED_SLOT snapshot, not this newer one.
    mv $LEDGER_DIR/snapshot-${NEXT_ROOTED_SLOT}* $OLD_SNAPSHOTS_DIR
    echo "Creating minimized snapshot for mismatch"
    $AGAVE_LEDGER_TOOL create-snapshot $MINIMIZED_START_SLOT $MISMATCH_DIR -l $LEDGER_DIR --minimized --ending-slot $MINIMIZED_END_SLOT --enable-capitalization-change \
        || fail_minimization "minimized create-snapshot at slot \`$MINIMIZED_START_SLOT\` failed"
    sleep 10
    rm $LEDGER_DIR/ledger_tool -rf
    mv $LEDGER_DIR/snapshot-${PREVIOUS_ROOTED_SLOT}* $OLD_SNAPSHOTS_DIR

    for MISMATCH_SNAPSHOT_FILE in $MISMATCH_DIR/snapshot-${MINIMIZED_START_SLOT}*; do
        send_slack_message "Minimized snapshot created at \`$MISMATCH_SNAPSHOT_FILE\`"
    done

    # Bring the resume snapshot back and use it for the next replay pass.
    mv $OLD_SNAPSHOTS_DIR/snapshot-${NEXT_ROOTED_SLOT}* $LEDGER_DIR
    LEDGER_REPLAY_SNAPSHOT=$LEDGER_DIR/snapshot-${NEXT_ROOTED_SLOT}*

    # Tar up the minimized ledger and upload it for CI/debugging.
    MISMATCH_TAR=$MISMATCH_DIR.tar.gz
    cd $LEDGER_DIR
    tar -czvf $(basename $MISMATCH_TAR) $(basename $MISMATCH_DIR) \
        || fail_minimization "tar of minimized ledger \`$(basename $MISMATCH_DIR)\` failed"
    gsutil cp $MISMATCH_TAR gs://firedancer-ci-resources/$(basename $MISMATCH_TAR) \
        || fail_minimization "upload of minimized ledger \`$(basename $MISMATCH_TAR)\` failed"
    send_slack_message "Minimized ledger uploaded to gs://firedancer-ci-resources/$(basename $MISMATCH_TAR)"
    send_mismatch_slack_message "Mismatch ledger uploaded to gs://firedancer-ci-resources/$(basename $MISMATCH_TAR)"

    # Upload the (compressed) replay log next to the minimized ledger so the
    # failure can be inspected without access to this machine.
    MISMATCH_LOG_GZ=$(basename $MISMATCH_DIR).log.gz
    gzip -c "$LOG" > $MISMATCH_LOG_GZ \
        || fail_minimization "compressing replay log \`$LOG\` failed"
    gsutil cp $MISMATCH_LOG_GZ gs://firedancer-ci-resources/$MISMATCH_LOG_GZ \
        || fail_minimization "upload of replay log \`$MISMATCH_LOG_GZ\` failed"
    send_slack_message "Replay log uploaded to gs://firedancer-ci-resources/$MISMATCH_LOG_GZ"
    send_mismatch_slack_message "Replay log uploaded to gs://firedancer-ci-resources/$MISMATCH_LOG_GZ"

    local ledger_name repro_end_slot
    ledger_name=$(basename $MISMATCH_DIR)
    repro_end_slot=$((NEXT_ROOTED_SLOT+5))
    send_slack_message "Command to reproduce mismatch: \`\`\`src/flamenco/runtime/tests/run_ledger_backtest.sh -l $ledger_name -m 2000000 -e $repro_end_slot\`\`\`"
}

#---------------------------------------------------------------------------
# Per-ledger replay loop
#---------------------------------------------------------------------------

# Replay the ledger, minimizing and resuming past each mismatch/failure,
# until a pass completes cleanly.
replay_until_clean() {
    DONE=0
    LEDGER_REPLAY_SNAPSHOT=$LEDGER_DIR/$CLOSEST_HOURLY_FILENAME

    while [ $DONE -eq 0 ]; do
        cd $FIREDANCER_REPO
        log_step "Backtest pass starting (replay snapshot: $LEDGER_REPLAY_SNAPSHOT)"
        send_slack_message "Starting ledger replay with commit \`$FD_COMMIT\`"
        send_slack_message "View progress for ledger replay at http://$(hostname -f) with metrics at http://$(hostname -f):7999/metrics"
        set +e

        render_backtest_config
        run_backtest

        # Let the workspace teardown settle before classifying the pass.
        sleep 10
        # LEDGER_REPLAY_SNAPSHOT may hold a glob after a resume; it expands here.
        REPLAY_SNAPSHOT_SLOT_NUMBER=$(basename $LEDGER_REPLAY_SNAPSHOT | grep -oP 'snapshot-\K\d+')

        # An empty backtest log means firedancer-dev never started (bad
        # config, permissions, ...) — that is an infrastructure problem, not
        # a ledger mismatch, so there is nothing to minimize.
        if [ "$status" -ne 0 ] && [ ! -s "$TEMP_LOG" ]; then
            send_slack_message "@here Backtest produced no log output; firedancer-dev likely failed at startup. See the configure output in the harness log. Exiting."
            exit 1
        fi

        if [ "$status" -eq 0 ]; then
            DONE=1
            echo "Ledger replay successful"
            send_slack_message "Ledger Replay Successful for Ledger \`$NEWEST_BUCKET_SLOT\`"
        else
            handle_replay_failure
        fi
    done
}

# Full pipeline for one newly-uploaded ledger.
process_new_ledger() {
    CURRENT_MISMATCH_COUNT=0
    CURRENT_FAILURE_COUNT=0

    # Rotate the harness log: this ledger run gets its own file (pruned with
    # the other logs after 30 days).
    HARNESS_RUN_LOG=$LOG_DIR/${NETWORK}_offline_replay_${NEWEST_BUCKET_SLOT}_harness.log
    exec >> $HARNESS_RUN_LOG 2>&1
    log_step "Processing new ledger $NEWEST_BUCKET_SLOT"

    log_step "Determining agave tag"
    determine_agave_tag
    log_step "Building agave-ledger-tool $AGAVE_TAG"
    build_agave_ledger_tool

    send_slack_message "Bucket Slot \`$NEWEST_BUCKET_SLOT\` is greater than the last run bucket slot \`$LATEST_RUN_BUCKET_SLOT\`"

    log_step "Preparing ledger directory and downloading genesis"
    prepare_ledger_dir
    log_step "Downloading rocksdb"
    download_rocksdb
    log_step "Selecting replay snapshot"
    select_replay_snapshot
    log_step "Downloading replay snapshot"
    download_replay_snapshot
    log_step "Building Firedancer ($FD_BRANCH)"
    build_firedancer
    log_step "Converting rocksdb to shredcap"
    convert_rocksdb_to_shredcap
    log_step "Replaying ledger"
    replay_until_clean
    log_step "Cleaning up"

    # Tear down configure state once per ledger (not per pass: retry passes
    # reuse it, and the dev genesis stage's fini unlinks genesis.bin).
    $OBJDIR/bin/firedancer-dev configure fini all --config $LEDGER_DIR/offline_replay.toml

    # Keep rocksdb and minimized ledgers for debugging whenever anything went
    # wrong; only a fully clean run is cleaned up. Replay logs stay in
    # $LOG_DIR either way (pruned after 30 days by the main loop).
    if [ "$CURRENT_MISMATCH_COUNT" -eq 0 ] && [ "$CURRENT_FAILURE_COUNT" -eq 0 ]; then
        rm -rf "$LEDGER_DIR"
        rm -rf "$TEMP_LOG"
    fi

    echo "$NEWEST_BUCKET_SLOT" > $LATEST_RUN_BUCKET_SLOT_FILE
    echo "Updated latest bucket slot to $NEWEST_BUCKET_SLOT"

    log_step "Finished ledger $NEWEST_BUCKET_SLOT"
    exec >> $HARNESS_LOG 2>&1
}

#---------------------------------------------------------------------------
# Main loop: poll the bucket hourly for new ledgers
#---------------------------------------------------------------------------

main() {
    mkdir -p $LOG_DIR
    echo "Harness output logging to $HARNESS_LOG"
    exec >> $HARNESS_LOG 2>&1
    log_step "Harness started on $(hostname) (pid $$)"

    source $NETWORK_PARAMETERS_FILE $NETWORK
    echo "Updated network parameters"

    # AGAVE_TAG is determined per-ledger from each ledger's version.txt in
    # determine_agave_tag(). Whatever is exported here is only used as a
    # fallback if a given ledger's version.txt cannot be read.
    echo "Initial AGAVE_TAG=$AGAVE_TAG (will be overridden per-ledger from version.txt)"

    send_slack_message "Starting $NETWORK-offline-replay run on \`$(hostname)\` in \`$(pwd)\`"
    CURRENT_MISMATCH_COUNT=0
    CURRENT_FAILURE_COUNT=0

    while true; do
        source $NETWORK_PARAMETERS_FILE $NETWORK
        echo "Updated network parameters"

        # Prune replay logs older than 30 days.
        find $LOG_DIR -maxdepth 1 -name "*_offline_replay_*" -mtime +30 -delete 2> /dev/null

        find_newest_bucket_slot
        log_step "Poll: newest bucket slot $NEWEST_BUCKET_SLOT, last processed $LATEST_RUN_BUCKET_SLOT"
        send_slack_message "Most Recent Bucket Slot in $NETWORK: \`$NEWEST_BUCKET_SLOT\`"

        if [ "$NEWEST_BUCKET_SLOT" -gt "$LATEST_RUN_BUCKET_SLOT" ]; then
            process_new_ledger
        fi

        echo "Sleeping for 1 hour"
        sleep 3600
    done
}

main
