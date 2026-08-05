#!/bin/bash

# Deployed as /usr/local/bin/offline_replay.sh with the Slack webhook
# URLs filled in. Keep the two in sync when either changes.

# Firedancer Repo
export FIREDANCER_REPO="/home/svc_firedancer/repos/firedancer"
export FD_BRANCH="main"

# Agave Repo
export AGAVE_REPO="/home/svc_firedancer/repos/agave"

# Network Specific Parameters
export NETWORK="mainnet"
export BILLING_PROJECT="billing-project-id"
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
export SLACK_MISMATCH_WEBHOOK_URL=https://hooks.slack.com/services/...

# For Testing Purposes (comment out if not testing)
# export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
# export SLACK_MISMATCH_WEBHOOK_URL=https://hooks.slack.com/services/...

# Debugging Slack Webhook
export SLACK_DEBUG_WEBHOOK_URL=https://hooks.slack.com/services/...

# Latest Bucket Slot File
export LATEST_RUN_BUCKET_SLOT_FILE="/home/svc_firedancer/newest_bucket_slot.txt"

# Shared log directory (readable by the whole team)
export LOG_DIR="/data/offline-replay/logs"

# Offline Replay Parameters File
export NETWORK_PARAMETERS_FILE="/home/svc_firedancer/repos/firedancer/contrib/offline-replay/offline_replay_network_parameters.sh"

# Offline Replay Script
OFFLINE_REPLAY_SCRIPT="/home/svc_firedancer/repos/firedancer/contrib/offline-replay/run_offline_replay_backtest.sh"

# Run Script
$OFFLINE_REPLAY_SCRIPT
