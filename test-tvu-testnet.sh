#!/bin/bash
set -euxo pipefail
shopt -s extglob
IFS=$'\n\t'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# create temporary files in the user's home directory because it's likely to be on a large disk
TMPDIR=$(mktemp --directory --tmpdir="$HOME" tmp-test-tvu-testnet.XXXXXX)
cd $TMPDIR

cleanup() {
  sudo killall fddev || true
  fddev configure fini all >/dev/null 2>&1 || true
  rm -rf "$TMPDIR"
}

trap cleanup EXIT SIGINT SIGTERM
sudo killall fddev || true

# if fddev is not on path then use the one in the home directory
if ! command -v fddev > /dev/null; then
  PATH="$SCRIPT_DIR/build/native/gcc/bin":$PATH
fi

ENTRYPOINT=entrypoint3.testnet.solana.com

echo "[tiles.tvu]
  gossip_peer_addr = \"$(dig +short $ENTRYPOINT):8001\"
  snapshot = \"http://$ENTRYPOINT:8899/snapshot.tar.bz2\"
  incremental_snapshot = \"http://$ENTRYPOINT:8899/incremental-snapshot.tar.bz2\"
  page_cnt = 250
  validate_snapshot = \"true\"
  check_hash = \"true\"
  solcap_path = \"fddev.solcap\"
  solcap_txns = \"true\"
[log]
  path = \"fddev.log\"
  level_stderr = \"NOTICE\"
  level_logfile = \"NOTICE\"
" > fddev.toml

cp "$SCRIPT_DIR/shenanigans.sh" .

# JOB_URL is potentially set by the github workflow
# This will be written to a file so that we can link the files in the google cloud bucket back to the github run.
# example: export JOB_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/"
if [ -n "$JOB_URL" ]; then
  echo "$JOB_URL" > github_job_url.txt
fi

fddev --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) &
FDDEV_PID=$!

CAUGHT_UP=0
set +x
for i in $(seq 1 600); do
  if grep -q "caught up: 1" $(readlink -f fddev.log); then
    CAUGHT_UP=1
    break
  fi
  sleep 1
done
set -x

if grep -q "Bank hash mismatch" $(readlink -f fddev.log); then
  BAD_SLOT=$( grep "Bank hash mismatch" fddev.log | awk 'NR==1 {for (i=1; i<=NF; i++) if ($i == "slot:") {gsub(/[^0-9]/, "", $(i+1)); print $(i+1); exit}}' )
  echo "*** BANK HASH MISMATCH $BAD_SLOT ***"
  mkdir -p $BAD_SLOT
  cp fddev.log fddev.solcap github_job_url.txt $BAD_SLOT
  mv $BAD_SLOT ~/bad-slots
fi

if grep -P "ERR.*incremental accounts_hash [^ ]+ != [^ ]+$" $(readlink -f fddev.log); then
  echo "*** INCREMENTAL ACCOUNTS_HASH MISMATCH ***"
  NEW_DIR=incremental-accounts-hash-mismatch-$(TZ='America/Chicago' date "+%Y-%m-%d-%H:%M:%S")
  mkdir -p $NEW_DIR
  cp -r !($NEW_DIR) $NEW_DIR
  mv $NEW_DIR ~/bad-slots
  exit 1
fi

if [ $CAUGHT_UP -eq 0 ]; then
  echo "fddev failed to catch up"
  exit 1
fi

# TODO: LML once we figure out what's breaking incremental snapshots on testnet do this instead of the above which just checks for block execution
#echo "[tiles.tvu]
#  gossip_peer_addr = \"$(dig +short $ENTRYPOINT):8001\"
#  snapshot = \"$(echo snapshot*)\"
#  incremental_snapshot = \"http://$ENTRYPOINT:8899/incremental-snapshot.tar.bz2\"
#  page_cnt = 250
#  validate_snapshot = \"true\"
#  check_hash = \"true\"
#" > fddev.toml
#
#cp "$SCRIPT_DIR/shenanigans.sh" .
#
#timeout 300 fddev --no-sandbox --no-solana-labs --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) || true
#
#grep -q "caught up: 1" $(readlink -f fddev.log)
#if grep -q "Bank hash mismatch" $(readlink -f fddev.log); then
#  echo "*** BANK HASH MISMATCH ***"
#fi
