#!/bin/bash -f

echo_notice() {
  echo -e "\033[34m$1\033[0m"
}

echo_error() {
  echo -e "\033[31m$1$2\033[0m"
}

POSITION_ARGS=()
OBJDIR=${OBJDIR:-build/native/gcc}

LEDGER=""
SNAPSHOT=""
RESTORE_ARCHIVE=""
END_SLOT="1010"
FUNK_PAGES="16"
INDEX_MAX="5000000"
TRASH_HASH=""
LOG="/tmp/ledger_log$$"
TILE_CPUS="--tile-cpus 5-15"
THREAD_MEM_BOUND="--thread-mem-bound 0"
CLUSTER_VERSION=""
DUMP_DIR=${DUMP_DIR:="./dump"}
ONE_OFFS=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -d|--dump-dir)
       DUMP_DIR="$2"
       shift
       shift
       ;;
    -l|--ledger)
       LEDGER="$2"
       shift
       shift
       ;;
    -s|--snapshot)
       SNAPSHOT="$LEDGER/$2"
       shift
       shift
       ;;
    -a|--restore-archive)
       RESTORE_ARCHIVE="$LEDGER/$2"
       shift
       shift
       ;;
    -c|--cluster-version)
       CLUSTER_VERSION="$2"
       shift
       shift
       ;;
    -e|--end_slot)
       END_SLOT="$2"
       shift
       shift
       ;;
    -y|--funk-pages)
       FUNK_PAGES="$2"
       shift
       shift
       ;;
    -m|--indexmax)
       INDEX_MAX="$2"
       shift
       shift
       ;;
    -t|--trash)
       TRASH_HASH="--trash-hash $2"
       shift
       shift
       ;;
    -o|--one-offs)
       ONE_OFFS="$2"
       shift
       ;;
    --zst)
        ZST=1
        shift
        ;;
    --tile-cpus)
        TILE_CPUS="--tile-cpus $2"
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

export LLVM_PROFILE_FILE=$OBJDIR/cov/raw/ledger_test_$LEDGER.profraw
mkdir -p $OBJDIR/cov/raw

DUMP=$(realpath $DUMP_DIR)
mkdir -p $DUMP

if [[ ! -e $DUMP/$LEDGER && SKIP_INGEST -eq 0 ]]; then
  if [[ -n "$ZST" ]]; then
    echo "Downloading gs://firedancer-ci-resources/$LEDGER.tar.zst"
  else
    echo "Downloading gs://firedancer-ci-resources/$LEDGER.tar.gz"
  fi
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
  if [[ -n "$ZST" ]]; then
    gcloud storage cat gs://firedancer-ci-resources/$LEDGER.tar.zst | zstd -d --stdout | tee $DUMP/$LEDGER.tar.zst | tar xf - -C $DUMP
  else
    gcloud storage cat gs://firedancer-ci-resources/$LEDGER.tar.gz | tee $DUMP/$LEDGER.tar.gz | tar zxf - -C $DUMP
  fi
fi

if [[ "" != "$SNAPSHOT" ]]; then
  SNAPSHOT="$DUMP/$SNAPSHOT"
fi

if [[ "" != "$RESTORE_ARCHIVE" ]]; then
  RESTORE_ARCHIVE="--restore-archive $DUMP/$RESTORE_ARCHIVE"
fi

if [[ "" == "$SNAPSHOT" && "" == "$RESTORE_ARCHIVE" ]]; then
  SNAPSHOT="--genesis $DUMP/$LEDGER/genesis.bin"
fi

echo_notice "Starting on-demand ingest and replay"
echo "
[layout]
     affinity = \"auto\"
     bank_tile_count = 1
     shred_tile_count = 4
     exec_tile_count = 4
 [tiles]
     [tiles.archiver]
         enabled = true
         end_slot = $END_SLOT
         archiver_path = \"$DUMP/$LEDGER/rocksdb\"
     [tiles.replay]
         snapshot = \"$SNAPSHOT\"
         funk_sz_gb = $FUNK_PAGES
         funk_txn_max = 1024
         funk_rec_max = $INDEX_MAX
         cluster_version = \"$CLUSTER_VERSION\"
         enable_features = [ \"$ONE_OFFS\" ]
         funk_file = \"$DUMP/$LEDGER/backtest.funk\"
     [tiles.gui]
         enabled = false
 [blockstore]
     shred_max = 16777216
     block_max = 8192
     txn_max = 1048576
     alloc_max = 10737418240
     file = \"$DUMP/$LEDGER/backtest.blockstore\"
 [consensus]
     vote = false
 [development]
     sandbox = false
     no_agave = true
     no_clone = true
 [log]
     level_stderr = \"INFO\"
     path = \"$LOG\"
 [paths]
     identity_key = \"$DUMP_DIR/identity.json\"
     vote_account = \"$DUMP_DIR/vote.json\"
" > $DUMP_DIR/${LEDGER}_backtest.toml

if [ ! -f $DUMP_DIR/identity.json ]; then
$OBJDIR/bin/firedancer-dev keys new identity --config ${DUMP_DIR}/${LEDGER}_backtest.toml
fi
if [ ! -f $DUMP_DIR/vote.json ]; then
$OBJDIR/bin/firedancer-dev keys new vote --config ${DUMP_DIR}/${LEDGER}_backtest.toml
fi

echo "Running backtest for $LEDGER"
sudo $OBJDIR/bin/firedancer-dev configure init all --config ${DUMP_DIR}/${LEDGER}_backtest.toml &> /dev/null

sudo rm -rf $DUMP/$LEDGER/backtest.blockstore $DUMP/$LEDGER/backtest.funk &> /dev/null

set -x
  sudo $OBJDIR/bin/firedancer-dev backtest --config ${DUMP_DIR}/${LEDGER}_backtest.toml &> /dev/null

{ set +x; } &> /dev/null

sudo rm -rf $DUMP/$LEDGER/backtest.blockstore $DUMP/$LEDGER/backtest.funk &> /dev/null

echo_notice "Finished on-demand ingest and replay\n"

echo "Log for ledger $LEDGER at $LOG"

if grep -q "Rocksdb playback done." $LOG && ! grep -q "Bank hash mismatch!" $LOG;
then
  exit 0
  #   rm $LOG
else
  if [ -n "$TRASH_HASH" ]; then
    echo "inverted test passed"
    # rm $LOG
    exit 0
  fi

  tail -40 $LOG
  echo_error "backtest test failed: $*"
  echo $LOG

  exit 1
fi
