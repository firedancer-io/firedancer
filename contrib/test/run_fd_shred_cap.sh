#!/bin/bash

DUMP_DIR=${DUMP_DIR:="./dump"}
LOG="/tmp/ledger_log$$"

DATA_DIR=${DATA_DIR:="/data/svc_firedancer"}

rm -rf $DATA_DIR/shredcap_testnet.blockstore
rm -rf $DATA_DIR/shredcap_testnet.funk

TOML=$DATA_DIR/fd_shredcap.toml

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
FD_DIR="$SCRIPT_DIR/../.."
OBJDIR=${OBJDIR:-build/native/${CC}}

cleanup() {
  sudo killall firedancer-dev || true
  sudo $FD_DIR/$OBJDIR/bin/firedancer-dev configure fini all --config "$(readlink -f "$TOML")"  || true
  exit $status
}

trap cleanup EXIT SIGINT SIGTERM
sudo killall firedancer-dev || true

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
    execrp_tile_count = 8
[funk]
    max_account_records = 150000000
    heap_size_gib = 100
    max_database_transactions = 2000
[tiles]
    [tiles.shred]
        max_pending_shred_sets = 16384
    [tiles.replay]
        snapshot = \"$SNAPSHOT\"
        incremental = \"$INCREMENTAL\"
    [tiles.store_int]
        shred_cap_replay = \"$SHREDCAP\"
        shred_cap_end_slot = 317018450
[consensus]
    vote = false
    expected_shred_version = 64475
[paths]
    identity_key = \"$(pwd)/fd-identity-keypair.json\"
    vote_account = \"$(pwd)/fd-vote-keypair.json\"
[log]
    path = \"$LOG\"
    level_stderr = \"INFO\"
    level_logfile = \"NOTICE\"
" > $TOML

sudo $FD_DIR/$OBJDIR/bin/firedancer-dev configure fini all
sudo $FD_DIR/$OBJDIR/bin/firedancer-dev configure init all

set -x

timeout 6m $FD_DIR/$OBJDIR/bin/firedancer-dev dev \
  --config "$(readlink -f "$TOML")"

status=$?

rm -rf fd-identity-keypair.json
rm -rf fd-vote-keypair.json

simulation_finished=$(grep "Finished simulation" $LOG)
echo "Simulation Finished Line: $simulation_finished"
if [[ $simulation_finished == *"Finished simulation to slot"* ]]; then
  status=0
  echo "Simulation Completed Successfully"
else
  status=1
  echo "Simulation Failed"
fi
exit $status
