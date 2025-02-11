#!/bin/bash

cleanup() {
  sudo killall fddev || true
  sudo $FD_DIR/$OBJDIR/bin/fddev configure fini all  || true
  exit $status
}

trap cleanup EXIT SIGINT SIGTERM
sudo killall fddev || true

DUMP_DIR=${DUMP_DIR:="./dump"}
LOG="/tmp/ledger_log$$"

DATA_DIR=${DATA_DIR:="/data/svc_firedancer"}

TOML=$DATA_DIR/fd_shredcap.toml

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
FD_DIR="$SCRIPT_DIR/../.."
OBJDIR=${OBJDIR:-build/native/${CC}}

# check to make sure theres 120 GB of space in the data directory
if [ "$(df -k --output=avail $DATA_DIR | tail -n1)" -lt 120000000 ]; then
  echo "Not enough space in $DATA_DIR"
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case $1 in
    -d|--dump-dir)
       DUMP_DIR="$2"
       shift
       shift
       ;;
    -*|--*)
       echo "unknown option $1"
       exit 1
       ;;
    *)
       POSITION_ARGS+=("$1")
       shift
       ;;
  esac
done


AGAVE_PATH=${AGAVE_PATH:='./agave/target/release'}
$AGAVE_PATH/solana-keygen new --no-bip39-passphrase --silent --force --outfile fd-identity-keypair.json
$AGAVE_PATH/solana-keygen new --no-bip39-passphrase --silent --force --outfile fd-vote-keypair.json

echo "Log File: $LOG"

DUMP=$(realpath $DUMP_DIR)
mkdir -p $DUMP

LEDGER="testnet-317018409-shred-cap"

if [[ ! -e $DUMP/$LEDGER ]]; then
  echo "Downloading gs://firedancer-ci-resources/$LEDGER.tar.gz"
  if [ "`gcloud auth list |& grep  firedancer-scratch | wc -l`" == "0" ]; then
    if [ "`gcloud auth list |& grep  firedancer-ci | wc -l`" == "0" ]; then
      if [ -f /etc/firedancer-scratch-bucket-key.json ]; then
        gcloud auth activate-service-account --key-file /etc/firedancer-scratch-bucket-key.json
      fi
      if [ -f /etc/firedancer-ci-78fff3e07c8b.json ]; then
        gcloud auth activate-service-account --key-file /etc/firedancer-ci-78fff3e07c8b.json
      fi
    fi
  fi
  gcloud storage cat gs://firedancer-ci-resources/$LEDGER.tar.gz | tee $DUMP/$LEDGER.tar.gz | tar zxf - -C $DUMP
fi


# ls in $DUMP/$LEDGER for snapshot* and set that to SNAPSHOT
SNAPSHOT=$(ls $DUMP/$LEDGER/snapshot*.tar.zst | head -n1)
INCREMENTAL=$(ls $DUMP/$LEDGER/incremental* | head -n1)
SHREDCAP=$(ls $DUMP/$LEDGER/*shredcap | head -n1)

echo "
[layout]
    affinity = \"auto\"
    bank_tile_count = 1
    shred_tile_count = 1
[gossip]
[blockstore]
    shred_max = 1048576
    block_max = 8192
    txn_max = 1048576
    idx_max = 8192
    alloc_max = 1073741824
    file = \"$DATA_DIR/shredcap_testnet.blockstore\"
[tiles]
    [tiles.shred]
        max_pending_shred_sets = 16384
    [tiles.replay]
        snapshot = \"$SNAPSHOT\"
        incremental = \"$INCREMENTAL\"
        tpool_thread_count = 10
        funk_sz_gb = 100
        funk_rec_max = 150000000
        funk_txn_max = 2000
        funk_file = \"$DATA_DIR/shredcap_testnet.funk\"
    [tiles.pack]
        use_consumed_cus = false
    [tiles.store_int]
        shred_cap_replay = \"$SHREDCAP\"
        shred_cap_end_slot = 317018450
[consensus]
    vote = false
    expected_shred_version = 64475
    identity_path = \"fd-identity-keypair.json\"
    vote_account_path = \"fd-vote-keypair.json\"
[log]
    path = \"$LOG\"
    level_stderr = \"INFO\"
    level_logfile = \"NOTICE\"
" > $TOML

sudo $FD_DIR/$OBJDIR/bin/fddev configure fini all
sudo $FD_DIR/$OBJDIR/bin/fddev configure init all

set -x

timeout 6m $FD_DIR/$OBJDIR/bin/fddev dev \
  --config "$(readlink -f "$TOML")" \
  --no-sandbox \
  --no-clone \
  --no-agave

status=$?

rm -rf fd-identity-keypair.json
rm -rf fd-vote-keypair.json

last_line=$(tail -n 1 $LOG)
echo "Last Log Line: $last_line"
if [[ $last_line == *"Finished simulation to slot"* ]]; then
  status=0
  echo "Simulation Completed Successfully"
else
  status=1
  echo "Simulation Failed"
fi
exit $status
