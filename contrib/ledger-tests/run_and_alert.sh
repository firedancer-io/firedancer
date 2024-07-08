#!/bin/bash

# REMOVE THESE BEFORE COMMITTING
# The following environment variables are used for configuration and should be removed before committing:

# 1. NETWORK
# Description: Specifies the Solana network to source the ledger from.
# Example: `mainnet`

# 2. FIREDANCER_DIR
# Description: Absolute directory path pointing to the Firedancer repository.
# Example: `/home/fd_user/firedancer`

# 3. SOLANA_DIR
# Description: Absolute directory path for the Solana build. This is where the Solana binaries are located after being built.
# Example: `/home/fd_user/solana/target/release/`

# 4. LEDGER_DIR
# Description: Absolute directory path for where the full ledger will be downloaded into. This can be any arbitrary path. 

# 5. LEDGER_MIN_DIR
# Description: Absolute directory path for where the minimal ledger will be downloaded into. This can be any arbitrary path.

# 6. REPO_BRANCH
# Description: Specifies the Git branch to be checked out and used. This is typically the main or a specific feature branch.
# Example: `main`

# 7. PATCH_DIR
# Description: Directory path where patch files are stored. These patches are applied to the repository before running the nightly test.
# Example: `/home/fd_user/patches`

# 8. SLACK_WEBHOOK_URL
# Description: Webhook URL for sending alerts to Slack. This URL is used to post alerts to a specified Slack channel.
# Example: `https://hooks.slack.com/...`

# 9. LOG_FILE
# Description: Path to the log file from the ledger conformance run.

# 10. UPLOAD_URL
# Description: URL for uploading the mismatch ledger.
# Example: `gs://...`

# 11. GCLOUD_KEY_FILE
# Description: Path to the Google Cloud key file used for authentication.

# -----------------------------------------------------------------------------
# Cleanup previous run

rm -rf $LEDGER_DIR && mkdir $LEDGER_DIR
rm -rf $LEDGER_MIN_DIR && mkdir $LEDGER_MIN_DIR

# -----------------------------------------------------------------------------
# Setup
START_TIME=$(date +%s)

cd $FIREDANCER_DIR
rm -rf $NETWORK-*.tar.gz
git checkout $REPO_BRANCH
git pull origin $REPO_BRANCH
PATCH_FILES=""

for patch in "$PATCH_DIR"/*.diff;
do
  if [ -f "$patch" ]; then
    git apply "$patch"
    PATCH_FILES+="$(basename "$patch") "
  fi
done

GIT_COMMIT=$(git rev-parse HEAD)

PATH=/opt/rh/gcc-toolset-13/root/usr/bin:$PATH
export PATH
PKG_CONFIG_PATH=/usr/lib64/pkgconfig:$PKG_CONFIG_PATH

make distclean && make clean
./deps.sh nuke
echo "y" | FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh +dev
make -j

prlimit --pid=$$ --nofile=1048576
prlimit --pid=$$ --memlock=unlimited

gcloud auth activate-service-account --key-file=$GCLOUD_KEY_FILE

# -----------------------------------------------------------------------------
# Run

slack_alert() {
    local alert_message=$1
    local ledger_min_basename=$(basename "$LEDGER_MIN_DIR")
    local metadata=$FIREDANCER_DIR/dump/$ledger_min_basename/metadata

    local mismatch_slot=$(echo "$alert_message" | grep -oP 'mismatch_slot: \K\d+')
    local replay_start_slot=$(grep 'replay_start_slot=' $metadata | cut -d'=' -f2)
    local replay_time=$(grep 'replay_time=' $metadata | cut -d'=' -f2)
    local replay_slots_before_mismatch=$((mismatch_slot - replay_start_slot))
    
    curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"Network: $NETWORK \nCommit: $GIT_COMMIT \nPatches: $PATCH_FILES \nAlert: $alert_message \nURL: $UPLOAD_URL/$NETWORK-$mismatch_slot.tar.gz \nSlots Replayed: $replay_slots_before_mismatch \nReplay Time: $replay_time's \"}" $SLACK_WEBHOOK_URL
}

alert_success() {
    local end_info=$1
    local end_slot=$(echo "$end_info" | grep -oE '[0-9]{9}' | tail -n 1)
    local ledger_min_basename=$(basename "$LEDGER_MIN_DIR")
    local metadata=$FIREDANCER_DIR/dump/$ledger_min_basename/metadata

    local alert_message="Ledger Test Success"
    local replay_start_slot=$(grep 'replay_start_slot=' $metadata | cut -d'=' -f2)
    local replay_time=$(grep 'replay_time=' $metadata | cut -d'=' -f2)
    local replay_slots_before_success=$((end_slot - replay_start_slot))

    curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"Network: $NETWORK \nCommit: $GIT_COMMIT \nPatches: $PATCH_FILES \nAlert: $alert_message \nSlots Replayed: $replay_slots_before_success \nReplay Time: $replay_time's \"}" $SLACK_WEBHOOK_URL
}

cd $FIREDANCER_DIR/contrib/ledger-tests

if [[ "$NETWORK" == "mainnet" ]]; then
    $FIREDANCER_DIR/contrib/ledger-tests/ledger_conformance.sh all \
        --network mainnet \
        --repetitions multiple \
        --ledger $LEDGER_DIR \
        --ledger-min $LEDGER_MIN_DIR \
        --solana-build-dir $SOLANA_DIR \
        --firedancer-root-dir $FIREDANCER_DIR \
        --upload $UPLOAD_URL &>$LOG_FILE &
elif [[ "$NETWORK" == "testnet" ]]; then
    $FIREDANCER_DIR/contrib/ledger-tests/ledger_conformance.sh all \
        --network testnet \
        --repetitions once \
        --ledger $LEDGER_DIR \
        --ledger-min $LEDGER_MIN_DIR \
        --solana-build-dir $SOLANA_DIR \
        --firedancer-root-dir $FIREDANCER_DIR \
        --upload $UPLOAD_URL &>$LOG_FILE &
fi

CURRENT_COUNT=0
PREV_COUNT=0

while true; do
    # Check for End of Ledger Test
    if grep -q 'ledger test success' "$LOG_FILE"; then
        CUR_LOGFILE_LINE_COUNT=$(wc -l < "$LOG_FILE")
        sleep 30
        NEW_LOGFILE_LINE_COUNT=$(wc -l < "$LOG_FILE")
        if [[ $CUR_LOGFILE_LINE_COUNT -eq $NEW_LOGFILE_LINE_COUNT ]]; then
            if tail -n 2 "$LOG_FILE" | head -n 1 | grep -q 'ERR'; then
                break
	        fi
            
            END_INFO=$(sed -n '$!{h;d;}; x; $p' "$LOG_FILE")
            alert_success "$END_INFO"
            break
        fi
    fi

    # Check for new mismatches
    CURRENT_COUNT=$(grep -c -E 'mismatch_(slot|msg):' "$LOG_FILE")

    if [[ $CURRENT_COUNT -gt $PREV_COUNT ]]; then
        MISMATCH_INFO=$(grep -E 'mismatch_(slot|msg):' "$LOG_FILE" | tail -n 2)
        slack_alert "$MISMATCH_INFO"
    fi

    PREV_COUNT=$CURRENT_COUNT
    sleep 60
done
