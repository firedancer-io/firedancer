#!/bin/bash
set -euxo pipefail
shopt -s extglob
IFS=$'\n\t'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
FD_DIR="$SCRIPT_DIR"

sudo killall fddev || true

sudo ./build/native/gcc/bin/fd_shmem_cfg fini
sudo ./build/native/gcc/bin/fd_shmem_cfg init 0700 chali ""



# create temporary files in the user's home directory because it's likely to be on a large disk
TMPDIR=/data/chali/tmp-test-tvu-mainnet
rm -rf $TMPDIR
mkdir -p $TMPDIR
cd $TMPDIR

cleanup() {
  sudo killall fddev || true
  #rm -rf "$TMPDIR"
}

download_snapshot() {
  local url=$1
  local num_tries=${2:-10}
  local s
  for i in $(seq 1 $num_tries); do
    s=$(curl -s --max-redirs 0 $url)
    if ! wget -q --trust-server-names $url; then
      sleep 1
    else
      echo "${s:1}"
      return 0
    fi
  done

  echo "failed after $num_tries tries to wget $url"
  return 1
}

trap cleanup EXIT SIGINT SIGTERM

# if fddev is not on path then use the one in the home directory
if ! command -v fddev > /dev/null; then
  PATH="$FD_DIR/build/native/gcc/bin":$PATH
fi

sudo fddev configure fini all >/dev/null 2>&1 || true
chown -R chali:chali /mnt/.fd
rm -rf ~/.firedancer

if [ -z "${ENTRYPOINT-}" ]; then
  ENTRYPOINT="202.8.8.7"
fi

snapshot=$(download_snapshot https://api.mainnet-beta.solana.com/snapshot.tar.bz2)

fd_ledger --cmd ingest --funk-page-cnt 600 --index-max 600000000 --txns-max 1024 --funk-only 1 --checkpt-funk mainnet-funk.checkpt --snapshot /data/chali/snapshot-268486844-Gt61ivJFVwngS3pgCxN3FBzS6AhGAEsvTuDeY4VzaaNH.tar.zst

incremental=$(download_snapshot https://api.mainnet-beta.solana.com/incremental-snapshot.tar.bz2)

echo "
[gossip]
    port = 9010
[tiles]
    [tiles.gossip]
        entrypoints = [\"$ENTRYPOINT\"]
        peer_ports = [8000]
        gossip_listen_port = 9110
    [tiles.repair]
        repair_intake_listen_port = 9111
        repair_serve_listen_port = 9112
    [tiles.replay]
        snapshot = \"wksp:mainnet-funk.checkpt\"
        incremental = \"$incremental\"
        tpool_thread_count = 10
        funk_sz_gb = 600
        funk_txn_max = 1024
        funk_rec_max = 600000000
[consensus]
    expected_shred_version = 50093
[log]
  path = \"fddev.log\"
  level_stderr = \"NOTICE\"
[development]
    topology = \"firedancer\"
" > fddev.toml

fddev --log-path $(readlink -f fddev.log) --config $(readlink -f fddev.toml) --no-sandbox --no-clone --no-solana-labs
