#!/bin/bash
set -euxo pipefail
shopt -s extglob
IFS=$'\n\t'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
FD_DIR="$SCRIPT_DIR/../.."

# create temporary files in the user's home directory because it's likely to be on a large disk
TMPDIR=$(mktemp --directory --tmpdir="$HOME" tmp-test-firedancer-mainnet.XXXXXX)
mkdir -p $TMPDIR
cd $TMPDIR

cleanup() {
  sudo killall fddev || true
  fddev configure fini all >/dev/null 2>&1 || true
  # rm -rf "$TMPDIR"
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

if [ -z "${ENTRYPOINT-}" ]; then
  ENTRYPOINT=entrypoint2.mainnet-beta.solana.com
  ENTRYPOINT_PORT=8001
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
        entrypoints = [\"$ENTRYPOINT\"]
        peer_ports = [$ENTRYPOINT_PORT]
        gossip_listen_port = 8820
    [tiles.repair]
        repair_intake_listen_port = 8821
        repair_serve_listen_port = 8822
    [tiles.replay]
        snapshot = \"$snapshot\"
        incremental = \"$incremental\"
        tpool_thread_count = 13
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
fddev --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) --no-sandbox --no-clone --no-agave
