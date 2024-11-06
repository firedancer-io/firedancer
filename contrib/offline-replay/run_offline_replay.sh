#!/bin/bash

OBJDIR=${OBJDIR:-build/native/gcc}

source $NETWORK_PARAMETERS_FILE $NETWORK
echo "Updated network parameters"
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

send_slack_message "Starting $NETWORK-offline-replay run on \`$(hostname)\` in \`$(pwd)\` with agave tag \`$AGAVE_TAG\` and firedancer cluster version \`$FD_CLUSTER_VERSION\`"
CURRENT_MISMATCH_COUNT=0    
CURRENT_FAILURE_COUNT=0

allocated_pages=$($FIREDANCER_REPO/"$OBJDIR"/bin/fd_shmem_cfg query)
gigantic_pages=$(echo "$allocated_pages" | grep "gigantic pages:" -A 1 | grep -oP '\d+(?= total)')
huge_pages=$(echo "$allocated_pages" | grep "huge pages:" -A 1 | grep -oP '\d+(?= total)')

if [ "$gigantic_pages" -eq 0 ] && [ "$huge_pages" -eq 0 ]; then
    echo "No gigantic or huge pages configured, Configuring..."
    sudo $FIREDANCER_REPO/"$OBJDIR"/bin/fd_shmem_cfg alloc $ALLOC_GIGANTIC_PAGES gigantic 0 alloc $ALLOC_HUGE_PAGES huge 0
else
    echo "Currently allocated gigantic pages: $gigantic_pages"
    echo "Currently allocated huge pages: $huge_pages"
fi

while true; do
    source $NETWORK_PARAMETERS_FILE $NETWORK
    echo "Updated network parameters"
    NEWEST_BUCKET=$(gcloud storage ls $BUCKET_ENDPOINT | sort -n -t / -k 4 | tail -n 1)
    NEWEST_BUCKET_SLOT=$(echo $NEWEST_BUCKET | awk -F'/' '{print $(NF-1)}')
    LATEST_RUN_BUCKET_SLOT=$(cat $LATEST_RUN_BUCKET_SLOT_FILE)

    send_slack_message "Most Recent Bucket Slot in $NETWORK: \`$NEWEST_BUCKET_SLOT\`"

    if [ "$NEWEST_BUCKET_SLOT" -gt "$LATEST_RUN_BUCKET_SLOT" ]; then
        CURRENT_MISMATCH_COUNT=0
        CURRENT_FAILURE_COUNT=0
        cd $AGAVE_REPO
        git pull
        git checkout $AGAVE_TAG
        cargo build --release

        send_slack_message "Bucket Slot \`$NEWEST_BUCKET_SLOT\` is greater than the last run bucket slot \`$LATEST_RUN_BUCKET_SLOT\`"

        LOG=/home/kbhargava/${NETWORK}_offline_replay_${NEWEST_BUCKET_SLOT}.log
        send_slack_message "Log File: \`$LOG\`"
        echo "" > $LOG
        LEDGER_DIR=${FIREDANCER_REPO}/dump/${NETWORK}-${NEWEST_BUCKET_SLOT}
        send_slack_message "Ledger Directory: \`$LEDGER_DIR\`"
        OLD_SNAPSHOTS_DIR=${LEDGER_DIR}/old_snapshots

        mkdir -p $LEDGER_DIR
        mkdir -p $OLD_SNAPSHOTS_DIR
        cd $LEDGER_DIR
        wget $GENESIS_FILE

        SOLANA_BUCKET_PATH=${BUCKET_ENDPOINT}/${NEWEST_BUCKET_SLOT}
        send_slack_message "Downloading rocksdb from \`$SOLANA_BUCKET_PATH\` to \`$LEDGER_DIR/rocksdb\`"
        
        if [ -e "$LEDGER_DIR/rocksdb" ]; then
            send_slack_message "Rocksdb already exists at \`$LEDGER_DIR/rocksdb\`"
        else
            while true; do
                if gcloud storage ls ${SOLANA_BUCKET_PATH}/rocksdb.tar.zst | grep -q 'rocksdb.tar.zst'; then
                    send_slack_message "Rocksdb found. Starting to copy..."
                    break
                else
                    send_slack_message "Rocksdb not found. Checking again in 1 hour."
                    sleep 3600
                fi
            done
            gcloud storage cp ${SOLANA_BUCKET_PATH}/rocksdb.tar.zst .
            zstd -d rocksdb.tar.zst && sleep 5 && rm -rf rocksdb.tar.zst
            tar -xf rocksdb.tar && sleep 5 && rm -rf rocksdb.tar
            send_slack_message "Downloaded rocksdb to \`$LEDGER_DIR/rocksdb\`"
        fi

        output=$( $AGAVE_LEDGER_TOOL bounds -l $LEDGER_DIR )
        ROCKSDB_ROOTED_MIN=$(echo "$output" | grep "rooted" | awk '{print $6}')
        ROCKSDB_ROOTED_MAX=$(echo "$output" | grep "rooted" | awk '{print $8}')
        echo "RocksDB Bounds: $ROCKSDB_ROOTED_MIN - $ROCKSDB_ROOTED_MAX"
        
        HOURLY_SNAPSHOT_DIR=${SOLANA_BUCKET_PATH}/hourly
        echo "Hourly Snapshot Directory: $HOURLY_SNAPSHOT_DIR"

        BASE_SNAPSHOT=$(gcloud storage ls "${SOLANA_BUCKET_PATH}/snapshot*.tar.zst" | sort -n -t - -k 3)

        HOURLY_SNAPSHOTS=$(gcloud storage ls "${HOURLY_SNAPSHOT_DIR}" | sort -n -t - -k 3)
        SNAPSHOTS="${BASE_SNAPSHOT} ${HOURLY_SNAPSHOTS}"

        CLOSEST_HOURLY_SLOT=${ROCKSDB_ROOTED_MAX}

        for snapshot in $SNAPSHOTS; do
            echo "Checking Snapshot: $snapshot"
            SNAPSHOT_NUMBER=$(basename $snapshot | cut -d '-' -f 2)
            CHECK_SNAPSHOT_ROOTED=$($AGAVE_LEDGER_TOOL slot $SNAPSHOT_NUMBER -l $LEDGER_DIR )

            if [[ "$CHECK_SNAPSHOT_ROOTED" == *"is_full: true"* ]]; then
                IS_SNAPSHOT_ROOTED=1
            else
                IS_SNAPSHOT_ROOTED=0
            fi

            if (( SNAPSHOT_NUMBER >= ROCKSDB_ROOTED_MIN && SNAPSHOT_NUMBER < CLOSEST_HOURLY_SLOT && IS_SNAPSHOT_ROOTED == 1 )); then
                CLOSEST_HOURLY_SLOT=$SNAPSHOT_NUMBER
                CLOSEST_HOURLY_URL=$snapshot
                CLOSEST_HOURLY_FILENAME=$(basename $CLOSEST_HOURLY_URL)
                echo "Snapshot $snapshot is rooted and within bounds"
            fi
        done

        send_slack_message "Downloading Closest Hourly Snapshot \`$CLOSEST_HOURLY_SLOT\` from \`$SOLANA_BUCKET_PATH\`"
        echo "$LEDGER_DIR/$CLOSEST_HOURLY_FILENAME"
        if [ -e "$LEDGER_DIR/$CLOSEST_HOURLY_FILENAME" ]; then
            send_slack_message "Hourly snapshot already exists at \`$LEDGER_DIR/$CLOSEST_HOURLY_FILENAME\`"
        else
            rm -f $LEDGER_DIR/snapshot*.tar.zst
            gcloud storage cp ${CLOSEST_HOURLY_URL} .
            send_slack_message "Downloaded hourly snapshot to \`$LEDGER_DIR/$CLOSEST_HOURLY_FILENAME\`"
        fi

        # Now we have downloaded the rocksdb and closest hourly snapshot
        # Time to start replaying the ledger
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
        echo "y" | FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh +dev
        EXTRAS=offline-replay make -j

        DONE=0
        LEDGER_REPLAY_SNAPSHOT=$LEDGER_DIR/$CLOSEST_HOURLY_FILENAME

        while [ $DONE -eq 0 ]; do
            cd $FIREDANCER_REPO
            send_slack_message "Starting ledger replay with commit \`$FD_COMMIT\` and cluster version \`$FD_CLUSTER_VERSION\`"
            set +e
            set -x
            "$OBJDIR"/bin/fd_ledger \
                --reset 1 \
                --cmd replay \
                --rocksdb $LEDGER_DIR/rocksdb \
                --index-max $INDEX_MAX \
                --end-slot $ROCKSDB_ROOTED_MAX \
                --funk-only 1 \
                --cluster-version $FD_CLUSTER_VERSION \
                --txn-max 100 \
                --page-cnt $PAGES \
                --funk-page-cnt $FUNK_PAGES \
                --snapshot $LEDGER_REPLAY_SNAPSHOT \
                --slot-history 5000 \
                --copy-txn-status 0 \
                --allocator wksp \
                --on-demand-block-ingest 1 \
                --tile-cpus 5-21 >> $LOG 2>&1
            status=$?

            if [ "$status" -eq 0 ]; then
                DONE=1
                echo "Ledger replay successful"
                REPLAY_COMPLETED_LINE=$(grep "replay completed" "$LOG" | tail -n 1)
                REPLAY_INFO="${REPLAY_COMPLETED_LINE#*replay completed - }"

                send_slack_message "Ledger Replay Successful"
                send_slack_message "Replay Statistics: \`$REPLAY_INFO\`"
            else
                DONE=0
                BH_MISMATCH=$(grep "Bank hash mismatch!" "$LOG" | tail -n 1)
                CURRENT_MISMATCH_COUNT=$((CURRENT_MISMATCH_COUNT + 1))

                if [ -z "$BH_MISMATCH" ]; then
                    CURRENT_FAILURE_COUNT=$((CURRENT_FAILURE_COUNT + 1))
                    send_slack_message "Ledger Replay Failure. Check logs for more details"
                    DONE=1
                    exit 0
                else
                    MISMATCH_SLOT=$(echo "$BH_MISMATCH" | awk -F 'slot=' '{print $2}' | awk '{print $1}')
                    send_slack_message "@here Mismatch occurred on slot: \`$MISMATCH_SLOT\`. Minimizing mismatch"

                    # move older snapshot to old_snapshots
                    cp $LEDGER_REPLAY_SNAPSHOT $OLD_SNAPSHOTS_DIR
                    # check most recent rooted slot
                    FOUND_MINIMIZED_START_SLOT=0
                    MINIMIZED_START_SLOT=$((MISMATCH_SLOT-1))
                    while [ $FOUND_MINIMIZED_START_SLOT -eq 0 ]; do
                        ROOTED=$($AGAVE_LEDGER_TOOL slot $MINIMIZED_START_SLOT -l $LEDGER_DIR )
                          if [[ "$ROOTED" == *"is_full: true"* ]]; then
                            FOUND_MINIMIZED_START_SLOT=1
                        else
                            MINIMIZED_START_SLOT=$((MINIMIZED_START_SLOT-1))
                        fi
                    done
                    echo "Found minimized rooted slot: $MINIMIZED_START_SLOT"

                    FOUND_PREVIOUS_ROOTED_SLOT=0
                    PREVIOUS_ROOTED_SLOT=$((MINIMIZED_START_SLOT-1))

                    while [ $FOUND_PREVIOUS_ROOTED_SLOT -eq 0 ]; do
                        ROOTED=$($AGAVE_LEDGER_TOOL slot $PREVIOUS_ROOTED_SLOT -l $LEDGER_DIR )
                          if [[ "$ROOTED" == *"is_full: true"* ]]; then
                            FOUND_PREVIOUS_ROOTED_SLOT=1
                        else
                            PREVIOUS_ROOTED_SLOT=$((PREVIOUS_ROOTED_SLOT-1))
                        fi
                    done
                    echo "Found previous rooted slot: $PREVIOUS_ROOTED_SLOT"

                    FOUND_NEXT_ROOTED_SLOT=0
                    NEXT_ROOTED_SLOT=$((MISMATCH_SLOT+1))

                    while [ $FOUND_NEXT_ROOTED_SLOT -eq 0 ]; do
                        ROOTED=$($AGAVE_LEDGER_TOOL slot $NEXT_ROOTED_SLOT -l $LEDGER_DIR )
                          if [[ "$ROOTED" == *"is_full: true"* ]]; then
                            FOUND_NEXT_ROOTED_SLOT=1
                        else
                            NEXT_ROOTED_SLOT=$((NEXT_ROOTED_SLOT+1))
                        fi
                    done
                    echo "Found next rooted slot: $NEXT_ROOTED_SLOT"

                    # create new snapshot at that slot
                    $AGAVE_LEDGER_TOOL create-snapshot $PREVIOUS_ROOTED_SLOT -l $LEDGER_DIR
                    rm $LEDGER_DIR/ledger_tool -rf
                    # delete old snapshot (LEADER_REPLAY_SNAPSHOT)
                    rm $LEDGER_REPLAY_SNAPSHOT
                    # create a new base snapshot for rooted slot right after the mismatch slot
                    $AGAVE_LEDGER_TOOL create-snapshot $NEXT_ROOTED_SLOT -l $LEDGER_DIR
                    rm $LEDGER_DIR/ledger_tool -rf
                    # set LEDGER_REPLAY_SNAPSHOT to new snapshot
                    LEDGER_REPLAY_SNAPSHOT=$LEDGER_DIR/snapshot-${NEXT_ROOTED_SLOT}*
                    echo "New snapshot created at $LEDGER_REPLAY_SNAPSHOT"
                    # minify a rocksdb for the minimized snapshot
                    
                    
                    # create a minimized snapshot for the mismatch slot using the new snapshot
                    MISMATCH_DIR=$LEDGER_DIR/$NETWORK-${MISMATCH_SLOT}
                    mkdir -p $MISMATCH_DIR
                    cp $LEDGER_DIR/genesis.tar.bz2 $MISMATCH_DIR
                    # mv $LEDGER_DIR/snapshot-${PREVIOUS_ROOTED_SLOT}* $MISMATCH_DIR

                    MINIMIZED_END_SLOT=$((NEXT_ROOTED_SLOT+32))

                    send_slack_message "Minifying rocksdb for mismatch"
                    "$OBJDIR"/bin/fd_ledger \
                        --reset 1 \
                        --cmd minify \
                        --rocksdb $LEDGER_DIR/rocksdb \
                        --minified-rocksdb $MISMATCH_DIR/rocksdb \
                        --start-slot $PREVIOUS_ROOTED_SLOT \
                        --end-slot $MINIMIZED_END_SLOT \
                        --page-cnt $FUNK_PAGES \
                        --copy-txn-status 1 >> $LOG 2>&1
                    status=$?

                    mv $LEDGER_DIR/snapshot-${NEXT_ROOTED_SLOT}* $OLD_SNAPSHOTS_DIR
                    echo "Creating minimized snapshot for mismatch"
                    $AGAVE_LEDGER_TOOL create-snapshot $MINIMIZED_START_SLOT $MISMATCH_DIR -l $LEDGER_DIR --minimized --ending-slot $MINIMIZED_END_SLOT
                    rm $LEDGER_DIR/ledger_tool -rf
                    mv $LEDGER_DIR/snapshot-${PREVIOUS_ROOTED_SLOT}* $OLD_SNAPSHOTS_DIR


                    MISMATCH_SNAPSHOT=$MISMATCH_DIR/snapshot-${MINIMIZED_START_SLOT}*
                    for MISMATCH_SNAPSHOT_FILE in $MISMATCH_SNAPSHOT; do
                        send_slack_message "Minimized snapshot created at \`$MISMATCH_SNAPSHOT_FILE\`"
                    done
                    mv $OLD_SNAPSHOTS_DIR/snapshot-${NEXT_ROOTED_SLOT}* $LEDGER_DIR

                    MISMATCH_TAR=$MISMATCH_DIR.tar.gz
                    cd $LEDGER_DIR
                    tar -czvf $(basename $MISMATCH_TAR) $(basename $MISMATCH_DIR)
                    gsutil cp $MISMATCH_TAR gs://firedancer-ci-resources/$(basename $MISMATCH_TAR)
                    send_slack_message "Minimized ledger uploaded to gs://firedancer-ci-resources/$(basename $MISMATCH_TAR)"
                fi
            fi
        done
        rm -rf $LEDGER_DIR/old_snapshots
        rm -rf $LEDGER_DIR/snapshot*.tar.zst
        # currently keeping rocksdb and minimized ledgers for debugging purposes
        if [ "$CURRENT_MISMATCH_COUNT" -eq 0 ] && [ "$CURRENT_FAILURE_COUNT" -eq 0 ]; then
            # delete everything including rocksdb and mismatch directories
            rm -rf "$LEDGER_DIR"
            rm -rf "$LOG"
        fi
        echo "$NEWEST_BUCKET_SLOT" > $LATEST_RUN_BUCKET_SLOT_FILE
        echo "Updated latest bucket slot to $NEWEST_BUCKET_SLOT"
    fi
    
    echo "Sleeping for 1 hour"
    sleep 3600
done
