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

send_mismatch_slack_message() {
    MESSAGE=$1
    json_payload=$(cat <<EOF
{
    "text": "$MESSAGE",
    "link_names": 1
}
EOF
)
    curl -X POST -H 'Content-type: application/json' --data "$json_payload" $SLACK_MISMATCH_WEBHOOK_URL
}

send_slack_debug_message() {
    MESSAGE=$1
    json_payload=$(cat <<EOF
{
    "text": "$MESSAGE",
    "link_names": 1
}
EOF
)
    curl -X POST -H 'Content-type: application/json' --data "$json_payload" $SLACK_DEBUG_WEBHOOK_URL
}

send_slack_message "Starting $NETWORK-offline-replay run on \`$(hostname)\` in \`$(pwd)\` with agave tag \`$AGAVE_TAG\`"
CURRENT_MISMATCH_COUNT=0
CURRENT_FAILURE_COUNT=0

while true; do
    source $NETWORK_PARAMETERS_FILE $NETWORK
    echo "Updated network parameters"
    NEWEST_BUCKET=$(gcloud storage ls $BUCKET_ENDPOINT --billing-project=$BILLING_PROJECT | sort -n -t / -k 4 | tail -n 1)
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
        TEMP_LOG=/home/kbhargava/${NETWORK}_offline_replay_${NEWEST_BUCKET_SLOT}_temp.log
        send_slack_message "Log File: \`$LOG\`"
        echo "" > $LOG && chmod 777 $LOG
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
                if gcloud storage ls ${SOLANA_BUCKET_PATH}/rocksdb.tar.zst --billing-project=$BILLING_PROJECT | grep -q 'rocksdb.tar.zst'; then
                    send_slack_message "Rocksdb found. Starting to copy..."
                    break
                else
                    send_slack_message "Rocksdb not found. Checking again in 1 hour."
                    sleep 3600
                fi
            done
            gcloud storage cp ${SOLANA_BUCKET_PATH}/rocksdb.tar.zst . --billing-project=$BILLING_PROJECT
            zstd -d rocksdb.tar.zst && sleep 5 && rm -rf rocksdb.tar.zst
            tar -xf rocksdb.tar && sleep 5 && rm -rf rocksdb.tar
            send_slack_message "Downloaded rocksdb to \`$LEDGER_DIR/rocksdb\`"
        fi
        gcloud storage cp ${SOLANA_BUCKET_PATH}/bounds.txt . --billing-project=$BILLING_PROJECT

        output=$( $AGAVE_LEDGER_TOOL bounds -l $LEDGER_DIR --force-update-to-open )
        ROCKSDB_ROOTED_MIN=$(echo "$output" | grep "rooted" | awk '{print $6}')
        ROCKSDB_ROOTED_MAX=$(echo "$output" | grep "rooted" | awk '{print $8}')
        echo "RocksDB Bounds: $ROCKSDB_ROOTED_MIN - $ROCKSDB_ROOTED_MAX"

        HOURLY_SNAPSHOT_DIR=${SOLANA_BUCKET_PATH}/hourly
        echo "Hourly Snapshot Directory: $HOURLY_SNAPSHOT_DIR"

        BASE_SNAPSHOT=$(gcloud storage ls "${SOLANA_BUCKET_PATH}/snapshot*.tar.zst" --billing-project=$BILLING_PROJECT | sort -n -t - -k 3)

        HOURLY_SNAPSHOTS=$(gcloud storage ls "${HOURLY_SNAPSHOT_DIR}" --billing-project=$BILLING_PROJECT | sort -n -t - -k 3)
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
            gcloud storage cp ${CLOSEST_HOURLY_URL} . --billing-project=$BILLING_PROJECT
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
        git submodule update --init --recursive --force
        echo "y" | FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh +dev
        EXTRAS=offline-replay make -j

        DONE=0
        LEDGER_REPLAY_SNAPSHOT=$LEDGER_DIR/$CLOSEST_HOURLY_FILENAME

        while [ $DONE -eq 0 ]; do
            cd $FIREDANCER_REPO
            send_slack_message "Starting ledger replay with commit \`$FD_COMMIT\`"
            set +e

            cp $FIREDANCER_REPO/contrib/offline-replay/offline_replay.toml $LEDGER_DIR

            export ledger=$LEDGER_DIR
            echo "ledger: $ledger"
            export end_slot=$ROCKSDB_ROOTED_MAX
            export funk_pages=$BACKTEST_FUNK_PAGES
            export index_max=$INDEX_MAX
            export heap_size=$HEAP_SIZE
            export log=$TEMP_LOG

            sed -i "s#{ledger}#${ledger}#g" "$LEDGER_DIR/offline_replay.toml"
            sed -i "s#{end_slot}#${end_slot}#g" "$LEDGER_DIR/offline_replay.toml"
            sed -i "s#{funk_pages}#${funk_pages}#g" "$LEDGER_DIR/offline_replay.toml"
            sed -i "s#{index_max}#${index_max}#g" "$LEDGER_DIR/offline_replay.toml"
            sed -i "s#{heap_size}#${heap_size}#g" "$LEDGER_DIR/offline_replay.toml"
            sed -i "s#{log}#${log}#g" "$LEDGER_DIR/offline_replay.toml"

            echo "toml at: $LEDGER_DIR/offline_replay.toml"

            $OBJDIR/bin/firedancer-dev configure init all --config $LEDGER_DIR/offline_replay.toml &> /dev/null

            rm -rf $TEMP_LOG && touch $TEMP_LOG && chmod 777 $TEMP_LOG

            chmod -R 0700 $LEDGER_DIR

            set -x
                $OBJDIR/bin/firedancer-dev backtest --config $LEDGER_DIR/offline_replay.toml &> /dev/null

            if grep -q "Backtest playback done." $TEMP_LOG && ! grep -q "Bank hash mismatch!" $TEMP_LOG;
            then
                status=0
            else
                status=1
            fi
            echo "status: $status"

            cat $TEMP_LOG >> $LOG

            { set +x; } &> /dev/null
            $OBJDIR/bin/firedancer-dev configure fini all --config $LEDGER_DIR/offline_replay.toml &> /dev/null

            sleep 10
            REPLAY_SNAPSHOT_SLOT_NUMBER=$(basename $LEDGER_REPLAY_SNAPSHOT | grep -oP 'snapshot-\K\d+')

            if [ "$status" -eq 0 ]; then
                DONE=1
                echo "Ledger replay successful"
                # REPLAY_COMPLETED_LINE=$(grep "replay completed" "$LOG" | tail -n 1)
                # REPLAY_INFO="${REPLAY_COMPLETED_LINE#*replay completed - }"
                # TXN_SPAD_INFO=$(grep "mem_wmark" "$LOG" | sed -E 's/.*(spad.*)/\1/')

                send_slack_message "Ledger Replay Successful for Ledger \`$NEWEST_BUCKET_SLOT\`"
                # send_slack_message "Replay Statistics: \`$REPLAY_INFO\`"
                # send_slack_debug_message "Memory Statistics:\n\`\`\`$TXN_SPAD_INFO\`\`\`"
            else
                DONE=0
                MISMATCH_SLOT=0
                MISMATCH_LOG=$(grep "mismatch!" "$LOG" | tail -n 1)

                if [ -z "$MISMATCH_LOG" ]; then
                    CURRENT_FAILURE_COUNT=$((CURRENT_FAILURE_COUNT + 1))
                    MISMATCH_SLOT=$(tail -n 100 "$LOG" | awk '/\[Replay\]/ {getline; if ($1 == "slot:") slot=$2; getline; if ($1 == "bank") last_bank_slot=slot} END {print last_bank_slot}')
                    send_slack_message "@here Failure occurred on slot: \`$MISMATCH_SLOT\`. Minimizing failure"
                else
                    CURRENT_MISMATCH_COUNT=$((CURRENT_MISMATCH_COUNT + 1))
                    MISMATCH_SLOT=$(tail -n 100 "$LOG" | awk '/Bank hash mismatch/ {match($0, /slot=[0-9]+/, a); if (a[0]) slot=substr(a[0],6)} END {print slot}')
                    send_slack_message "@here Mismatch occurred on slot: \`$MISMATCH_SLOT\`. Minimizing mismatch"
                fi

                # if mismatch count or failure count is greater than 5, stop the script
                if [ "$CURRENT_MISMATCH_COUNT" -gt 5 ] || [ "$CURRENT_FAILURE_COUNT" -gt 5 ]; then
                    send_slack_message "Mismatch count: \`$CURRENT_MISMATCH_COUNT\`"
                    send_slack_message "Failure count: \`$CURRENT_FAILURE_COUNT\`"
                    send_slack_message "Exiting script due to high mismatch or failure count"
                    exit 1
                fi

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
                if [ "$MINIMIZED_START_SLOT" -lt "$REPLAY_SNAPSHOT_SLOT_NUMBER" ]; then
                    MINIMIZED_START_SLOT=$REPLAY_SNAPSHOT_SLOT_NUMBER
                fi
                echo "Minimized start slot: $MINIMIZED_START_SLOT"

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
                if [ "$PREVIOUS_ROOTED_SLOT" -gt "$REPLAY_SNAPSHOT_SLOT_NUMBER" ]; then
                    echo "Creating new snapshot at $PREVIOUS_ROOTED_SLOT"
                    $AGAVE_LEDGER_TOOL create-snapshot $PREVIOUS_ROOTED_SLOT -l $LEDGER_DIR
                    sleep 10
                    rm $LEDGER_DIR/ledger_tool -rf
                    # delete old snapshot (LEADER_REPLAY_SNAPSHOT)
                    rm $LEDGER_REPLAY_SNAPSHOT
                fi
                if [ "$PREVIOUS_ROOTED_SLOT" -lt "$REPLAY_SNAPSHOT_SLOT_NUMBER" ]; then
                    PREVIOUS_ROOTED_SLOT=$REPLAY_SNAPSHOT_SLOT_NUMBER
                fi
                echo "Minimized start slot: $PREVIOUS_ROOTED_SLOT"

                # create a new base snapshot for rooted slot right after the mismatch slot
                echo "Creating new snapshot at $NEXT_ROOTED_SLOT"
                $AGAVE_LEDGER_TOOL create-snapshot $NEXT_ROOTED_SLOT -l $LEDGER_DIR
                sleep 10
                rm $LEDGER_DIR/ledger_tool -rf

                echo "New (right after) snapshot created at $NEXT_ROOTED_SLOT"
                NEXT_REPLAY_SNAPSHOT=$LEDGER_DIR/snapshot-${NEXT_ROOTED_SLOT}*
                for NEXT_REPLAY_SNAPSHOT_FILE in $NEXT_REPLAY_SNAPSHOT; do
                    send_slack_message "New (right after) snapshot created at \`$NEXT_REPLAY_SNAPSHOT_FILE\`"
                done

                # create a minimized snapshot for the mismatch slot using the new snapshot
                MISMATCH_DIR=$LEDGER_DIR/$NETWORK-${MISMATCH_SLOT}
                mkdir -p $MISMATCH_DIR
                cp $LEDGER_DIR/genesis.tar.bz2 $MISMATCH_DIR
                # mv $LEDGER_DIR/snapshot-${PREVIOUS_ROOTED_SLOT}* $MISMATCH_DIR

                # minify a rocksdb for the minimized snapshot
                MINIMIZED_END_SLOT=$((NEXT_ROOTED_SLOT+32))
                send_slack_message "Minifying rocksdb for mismatch"
                "$OBJDIR"/bin/fd_ledger \
                    --reset 1 \
                    --cmd minify \
                    --rocksdb $LEDGER_DIR/rocksdb \
                    --minified-rocksdb $MISMATCH_DIR/rocksdb \
                    --start-slot $PREVIOUS_ROOTED_SLOT \
                    --end-slot $MINIMIZED_END_SLOT \
                    --page-cnt $PAGES \
                    --copy-txn-status 0 >> $LOG 2>&1
                status=$?
                sleep 10

                mv $LEDGER_DIR/snapshot-${NEXT_ROOTED_SLOT}* $OLD_SNAPSHOTS_DIR
                echo "Creating minimized snapshot for mismatch"
                $AGAVE_LEDGER_TOOL create-snapshot $MINIMIZED_START_SLOT $MISMATCH_DIR -l $LEDGER_DIR --minimized --ending-slot $MINIMIZED_END_SLOT
                sleep 10
                rm $LEDGER_DIR/ledger_tool -rf
                mv $LEDGER_DIR/snapshot-${PREVIOUS_ROOTED_SLOT}* $OLD_SNAPSHOTS_DIR


                MISMATCH_SNAPSHOT=$MISMATCH_DIR/snapshot-${MINIMIZED_START_SLOT}*
                for MISMATCH_SNAPSHOT_FILE in $MISMATCH_SNAPSHOT; do
                    send_slack_message "Minimized snapshot created at \`$MISMATCH_SNAPSHOT_FILE\`"
                done
                mv $OLD_SNAPSHOTS_DIR/snapshot-${NEXT_ROOTED_SLOT}* $LEDGER_DIR

                # set LEDGER_REPLAY_SNAPSHOT to new snapshot
                LEDGER_REPLAY_SNAPSHOT=$LEDGER_DIR/snapshot-${NEXT_ROOTED_SLOT}*

                MISMATCH_TAR=$MISMATCH_DIR.tar.gz
                cd $LEDGER_DIR
                tar -czvf $(basename $MISMATCH_TAR) $(basename $MISMATCH_DIR)
                gsutil cp $MISMATCH_TAR gs://firedancer-ci-resources/$(basename $MISMATCH_TAR)
                send_slack_message "Minimized ledger uploaded to gs://firedancer-ci-resources/$(basename $MISMATCH_TAR)"
                send_mismatch_slack_message "Mismatch ledger uploaded to gs://firedancer-ci-resources/$(basename $MISMATCH_TAR)"

                ledger_name=$(basename $MISMATCH_DIR)
                end_slot=$((NEXT_ROOTED_SLOT+5))
                send_slack_message "Command to reproduce mismatch: \`\`\`src/flamenco/runtime/tests/run_ledger_backtest.sh -l $ledger_name -y 10 -m 2000000 -e $end_slot\`\`\`"

            fi
        done
        # currently keeping rocksdb and minimized ledgers for debugging purposes
        if [ "$CURRENT_MISMATCH_COUNT" -eq 0 ] && [ "$CURRENT_FAILURE_COUNT" -eq 0 ]; then
            # delete everything including rocksdb and mismatch directories
            cp "$LOG" /tmp/
            rm -rf "$LEDGER_DIR"
            rm -rf "$LOG"
            rm -rf "$TEMP_LOG"
            rm -rf $LEDGER_DIR/old_snapshots
            rm -rf $LEDGER_DIR/snapshot*.tar.zst
        fi
        echo "$NEWEST_BUCKET_SLOT" > $LATEST_RUN_BUCKET_SLOT_FILE
        echo "Updated latest bucket slot to $NEWEST_BUCKET_SLOT"
    fi

    echo "Sleeping for 1 hour"
    sleep 3600
done
