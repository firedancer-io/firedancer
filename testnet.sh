#!/bin/bash
set -euxo pipefail
shopt -s extglob
IFS=$'\n\t'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
FD_DIR="$SCRIPT_DIR"

sudo killall fddev || true

make -j
EXTRAS=no-solana make -j fddev

sudo ./build/native/gcc/bin/fd_shmem_cfg fini || true
sudo ./build/native/gcc/bin/fd_shmem_cfg init 0700 chali ""

# create temporary files in the user's home directory because it's likely to be on a large disk
TMPDIR=/data/chali/tmp-test-tvu-testnet
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
  ENTRYPOINT="147.75.84.157"
fi

snapshot=$(download_snapshot http://entrypoint3.testnet.solana.com:8899/snapshot.tar.bz2)

fd_ledger --cmd ingest --funk-page-cnt 140 --index-max 100000000 --txns-max 1024 --funk-only 1 --checkpt-funk funk.checkpt --snapshot 

incremental=$(download_snapshot http://entrypoint3.testnet.solana.com:8899/incremental-snapshot.tar.bz2)

echo "
[gossip]
    port = 9010
[tiles]
    [tiles.gossip]
        entrypoints = [\"$ENTRYPOINT\"]
        peer_ports = [8000]
        gossip_listen_port = 9010
    [tiles.repair]
        repair_intake_listen_port = 9011
        repair_serve_listen_port = 9012
    [tiles.replay]
        snapshot = \"wksp:funk.checkpt\"
        incremental = \"$incremental\"
        tpool_thread_count = 10
        funk_sz_gb = 140
        funk_txn_max = 1024
        funk_rec_max = 100000000
[consensus]
    expected_shred_version = 35459
[log]
  path = \"fddev.log\"
  level_stderr = \"NOTICE\"
[development]
    topology = \"firedancer\"
" > testnet.toml

fddev --log-path $(readlink -f fddev.log) --config $(readlink -f testnet.toml) --no-sandbox --no-clone --no-solana-labs
