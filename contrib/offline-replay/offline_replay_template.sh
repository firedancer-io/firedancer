#!/bin/bash

# Firedancer Repo
export FIREDANCER_REPO="/path/to/firedancer"
export FD_BRANCH="main"

# Agave Repo
export AGAVE_REPO="/path/to/agave"
export AGAVE_LEDGER_TOOL="${AGAVE_REPO}/target/release/agave-ledger-tool"

# Network Specific Parameters
export NETWORK="mainnet"
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# For Testing Purposes (comment out if not testing)
# export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Latest Bucket Slot File
export LATEST_RUN_BUCKET_SLOT_FILE="/path/to/newest_bucket_slot.txt"

# Offline Replay Parameters File
export NETWORK_PARAMETERS_FILE="/path/to/offline_replay_network_parameters.sh"
chmod +x $NETWORK_PARAMETERS_FILE

# Offline Replay Script
OFFLINE_REPLAY_SCRIPT="/path/to/run_offline_replay.sh"
chmod +x $OFFLINE_REPLAY_SCRIPT

# Run Script
$OFFLINE_REPLAY_SCRIPT
