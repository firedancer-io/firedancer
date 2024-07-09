#!/bin/bash
set -euxo pipefail
shopt -s extglob
IFS=$'\n\t'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
FD_DIR="$SCRIPT_DIR"

# create temporary files in the user's home directory because it's likely to be on a large disk
TMPDIR=$(mktemp --directory --tmpdir="$HOME" tmp-test-firedancer-mainnet.XXXXXX)
mkdir -p $TMPDIR
cd $TMPDIR

cleanup() {
  sudo killall fddev || true
  fddev configure fini all >/dev/null 2>&1 || true
  rm -rf "$TMPDIR"
}

download_snapshot() {
  local url=$1
  local num_tries=${2:-10}
  local s
  for _ in $(seq 1 $num_tries); do
    s=$(curl -s --max-redirs 0 $url)
    if ! wget -nc -q --trust-server-names $url; then
      sleep 1
    else
      echo "${s:1}"
      return 0
    fi
  done

  echo "failed after $num_tries tries to wget $url"
  return 1
}

is_ip() {
  if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    return 0  # True, it's an IP
  else
    return 1  # False, it's not an IP
  fi
}

trap cleanup EXIT SIGINT SIGTERM
sudo killall fddev || true

# if fddev is not on path then use the one in the home directory
if ! command -v fddev > /dev/null; then
  PATH="$FD_DIR/build/native/gcc/bin":$PATH
fi

DEFAULT_ENTRYPOINT=entrypoint2.mainnet-beta.solana.com
DEFAULT_ENTRYPOINT_PORT=8001

if [ -z "${ENTRYPOINT-}" ]; then
  ENTRYPOINT=$DEFAULT_ENTRYPOINT
  ENTRYPOINT_PORT=$DEFAULT_ENTRYPOINT_PORT
fi

snapshot=$(download_snapshot http://$ENTRYPOINT:8899/snapshot.tar.bz2)
incremental=$(download_snapshot http://$ENTRYPOINT:8899/incremental-snapshot.tar.bz2)

if ! is_ip "$ENTRYPOINT"; then
  ENTRYPOINT=$(dig +short "$ENTRYPOINT")
fi

echo "
[layout]
    affinity = \"1-32\"
    bank_tile_count = 1
[gossip]
    port = 8820
[tiles]
    [tiles.gossip]
        entrypoints = [\"$(dig +short $DEFAULT_ENTRYPOINT)\"]
        peer_ports = [$DEFAULT_ENTRYPOINT_PORT]
        gossip_listen_port = 8820
    [tiles.repair]
        repair_intake_listen_port = 8821
        repair_serve_listen_port = 8822
    [tiles.replay]
        snapshot = \"$snapshot\"
        incremental = \"$incremental\"
        tpool_thread_count = 13
        blockstore_checkpt = \"blockstore_checkpoint\"
        funk_sz_gb = 600
        funk_txn_max = 1024
        funk_rec_max = 600000000
[consensus]
    expected_shred_version = 50093
    vote_account_path = \"/home/$USER/.firedancer/fd1/vote-account.json\"
[log]
  path = \"fddev.log\"
  level_stderr = \"NOTICE\"
[development]
    topology = \"firedancer\"
" > fddev.toml

# JOB_URL is potentially set by the github workflow
# This will be written to a file so that we can link the files in the google cloud bucket back to the github run.
# example: export JOB_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/"
if [ -n "${JOB_URL-}" ]; then
  echo "$JOB_URL" > github_job_url.txt
fi

fddev configure fini all
fddev --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) --no-sandbox --no-clone --no-solana-labs &
FDDEV_PID=$!
disown $FDDEV_PID

CAUGHT_UP=0
mkdir -p ~/upload-to-gcs
set +x
# Run for 3 days (very optimistic)
for i in $(seq 1 259200); do
  # if we have a bank hash mismatch, then fail
  if grep -q "Bank hash mismatch" fddev.log; then
    BAD_SLOT=$(grep -o "Bank hash mismatch on slot.*" fddev.log | awk '{print $6}' | cut -d. -f1)
    echo "*** BANK HASH MISMATCH $BAD_SLOT ***"
    NEW_DIR=$BAD_SLOT-bank-hash-mismatch-$(TZ='America/Chicago' date "+%Y-%m-%d-%H:%M:%S")
    mkdir -p $NEW_DIR
    cp -r !($NEW_DIR) $NEW_DIR
    mv $NEW_DIR ~/upload-to-gcs
    break
  fi

  if ! kill -0 $FDDEV_PID 2>/dev/null; then
    echo "*** FDDEV CRASH ***"
    mkdir -p ~/crashes
    NEW_DIR=$CURRENT_SLOT-crash-$(TZ='America/Chicago' date "+%Y-%m-%d-%H:%M:%S")
    mkdir -p $NEW_DIR
    cp -r !($NEW_DIR) $NEW_DIR
    mv $NEW_DIR ~/crashes
    break
  fi

  CURRENT_SLOT=$(solana -u m epoch-info --output json | jq .absoluteSlot)
  # if we have an incremental accounts hash mismatch, then fail
  if grep -P "ERR.*incremental accounts_hash [^ ]+ != [^ ]+$" fddev.log; then
    echo "*** INCREMENTAL ACCOUNTS_HASH MISMATCH ***"
    NEW_DIR=$CURRENT_SLOT-incremental-accounts-hash-mismatch-$(TZ='America/Chicago' date "+%Y-%m-%d-%H:%M:%S")
    mkdir -p $NEW_DIR
    cp -r !($NEW_DIR) $NEW_DIR
    mv $NEW_DIR ~/upload-to-gcs
    break
  fi

  if grep -q "caught up: 1" fddev.log; then
    CAUGHT_UP=1
  fi

  if grep -q "^ERR" fddev.log; then
    echo "*** ERROR ENCOUNTERED ***"
    mkdir -p ~/errors
    NEW_DIR=$CURRENT_SLOT-error-$(TZ='America/Chicago' date "+%Y-%m-%d-%H:%M:%S")
    mkdir -p $NEW_DIR
    cp -r !($NEW_DIR) $NEW_DIR
    mv $NEW_DIR ~/errors
    break
  fi

  # if we have not caught up after one hour, then fail
  if [ $CAUGHT_UP -eq 0 ]; then
    if [ $i -eq 3600 ]; then
      echo "fddev failed to catch up"
      exit 1
    fi
  fi

  sleep 1
done
set -x

exit 0
