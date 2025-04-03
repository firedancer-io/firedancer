#!/bin/bash

DUMP_DIR=${DUMP_DIR:="./dump"}
LOG="/tmp/ledger_log$$"

DATA_DIR=${DATA_DIR:="/data/ibhatt/"}

rm -rf $DATA_DIR/shredcap_testnet.blockstore
rm -rf $DATA_DIR/shredcap_testnet.funk

TOML=$DATA_DIR/fd_shredcap.toml

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
FD_DIR="$SCRIPT_DIR/../.."
OBJDIR=${OBJDIR:-build/native/${CC}}

cleanup() {
  sudo killall fddev || true
  sudo $FD_DIR/$OBJDIR/bin/fddev configure fini all   --config "$(readlink -f "$TOML")"  || true
  exit $status
}

trap cleanup EXIT SIGINT SIGTERM
sudo killall fddev || true

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
    exec_tile_count = 8
[gossip]
[blockstore]
    shred_max = 16777216
    block_max = 16384
    txn_max = 1048576
    idx_max = 8192
    alloc_max = 10737418240
    file = \"/data/ibhatt/default.blockstore\"
[tiles]
    [tiles.shred]
        max_pending_shred_sets = 16384
    [tiles.replay]
        snapshot = \"/data/ibhatt/dump/mainnet-586-no-rent/snapshot-253151900-HVhfam8TtRFVwFto5fWkhgR4mbBJmUxcnxeKZoW5MrSD.tar.zst\"
        tpool_thread_count = 8
        funk_sz_gb = 40
        funk_rec_max = 5000000
        funk_txn_max = 2000
        funk_file = \"/data/ibhatt/shredcap.funk\"
        replay_end_slot = 253152090
        replay_type = \"rocksdb\"
    [tiles.pack]
        use_consumed_cus = false
    [tiles.metric]
        prometheus_listen_address = \"0.0.0.0\"
        prometheus_listen_port = 7999
    [tiles.store_int]
        rocksdb = \"/data/ibhatt/dump/mainnet-586-no-rent/rocksdb\"
[consensus]
    vote = false
    expected_shred_version = 64475
    identity_path = \"/data/ibhatt/testnet/validator-1.json\"
[log]
    path = \"/data/ibhatt/fddev.log\"
    level_stderr = \"INFO\"
    level_logfile = \"NOTICE\"
" > $TOML

sudo $FD_DIR/$OBJDIR/bin/fddev configure fini all
sudo $FD_DIR/$OBJDIR/bin/fddev configure init all

set -x

sudo gdb -nx -iex="set debuginfod enabled on" -ex=r --args $FD_DIR/$OBJDIR/bin/fddev dev \
  --config "$(readlink -f "$TOML")" \
  --no-sandbox \
  --no-clone \
  --no-agave

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
