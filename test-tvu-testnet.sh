#!/bin/bash
set -euxo pipefail
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

timeout 600 wget --quiet --trust-server-names http://entrypoint3.testnet.solana.com:8899/snapshot.tar.bz2

ENTRYPOINT=entrypoint3.testnet.solana.com

echo "[tiles.tvu]
  gossip_peer_addr = \"$(dig +short $ENTRYPOINT):8001\"
  snapshot = \"$(echo snapshot*)\"
  incremental_snapshot = \"http://$ENTRYPOINT:8899/incremental-snapshot.tar.bz2\"
  page_cnt = 250
  validate_snapshot = \"true\"
  check_hash = \"true\"
  solcap_path = \"fddev.solcap\"
" > fddev.toml

cp "$SCRIPT_DIR/shenanigans.sh" .

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
  echo "*** BANK HASH MISMATCH ***"
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
