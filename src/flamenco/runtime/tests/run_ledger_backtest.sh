#!/bin/bash -f

source contrib/test/ledger_common.sh

POSITION_ARGS=()
OBJDIR=${OBJDIR:-build/native/gcc}

LEDGER=""
RESTORE_ARCHIVE=""
END_SLOT="1010"
FUNK_PAGES="16"
INDEX_MAX="5000000"
TRASH_HASH=""
LOG="/tmp/ledger_log$$"
TILE_CPUS="--tile-cpus 5-15"
THREAD_MEM_BOUND="--thread-mem-bound 0"
INGEST_MODE="shredcap"
DUMP_DIR=${DUMP_DIR:="./dump"}
ONE_OFFS=""
HUGE_TLBFS_MOUNT_PATH=${HUGE_TLBFS_MOUNT_PATH:="/mnt/.fd"}
HAS_INCREMENTAL="false"
REDOWNLOAD=1
SKIP_CHECKSUM=1
DEBUG=( )
WATCH=( )
LOG_LEVEL_STDERR=NOTICE
DISABLE_LTHASH_VERIFICATION=true

DOWNLOAD_ONLY=${DOWNLOAD_ONLY:-"false"}

if [[ -n "$CI" ]]; then
  SKIP_CHECKSUM=0
  WATCH=( "--no-watch" )
  LOG_LEVEL_STDERR=INFO
fi

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
    -a|--restore-archive)
       RESTORE_ARCHIVE="$LEDGER/$2"
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
    -i|--ingest-mode)
       INGEST_MODE="$2"
       shift
       shift
       ;;
    --zst)
        ZST=1
        shift
        ;;
    -g|--genesis)
        GENESIS=1
        shift
        ;;
    --tile-cpus)
        TILE_CPUS="--tile-cpus $2"
        shift
        shift
        ;;
    -v|--has-incremental)
        HAS_INCREMENTAL="$2"
        shift
        ;;
    -nr|--no-redownload)
        REDOWNLOAD=0
        shift
        ;;
    --debug)
        DEBUG=( gdb -q -x contrib/debug.gdb --args )
        shift
        ;;
    --skip-checksum)
        SKIP_CHECKSUM=1
        shift
        ;;
    --log)
        LOG="$2"
        shift
        shift
        ;;
    -lt|--lthash-verification)
        DISABLE_LTHASH_VERIFICATION=false
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

FORMATTED_ONE_OFFS=$(echo "$ONE_OFFS" | sed -E 's/([^,]+)/"\1"/g')

export LLVM_PROFILE_FILE=$OBJDIR/cov/raw/ledger_test_$LEDGER.profraw
mkdir -p $OBJDIR/cov/raw

DUMP=$(realpath $DUMP_DIR)
mkdir -p $DUMP

download_and_extract_ledger() {
  if [[ ! -e $DUMP/$LEDGER && SKIP_INGEST -eq 0 ]]; then
    if [[ -e $DUMP/$LEDGER.pending ]]; then
      echo "Cleaning up previous interrupted download..."
      rm -rf $DUMP/$LEDGER.pending
    fi

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

    mkdir -p $DUMP/$LEDGER.pending

    if [[ -n "$ZST" ]]; then
      if gcloud storage cat gs://firedancer-ci-resources/$LEDGER.tar.zst | zstd -d --stdout | tee $DUMP/$LEDGER.tar.zst | tar xf - -C $DUMP/$LEDGER.pending --strip-components=1; then
        rm -rf $DUMP/$LEDGER
        mv $DUMP/$LEDGER.pending $DUMP/$LEDGER
        echo "Download completed successfully"
      else
        echo "Download failed, cleaning up..."
        rm -rf $DUMP/$LEDGER.pending
        exit 1
      fi
    else
      if gcloud storage cat gs://firedancer-ci-resources/$LEDGER.tar.gz | tee $DUMP/$LEDGER.tar.gz | tar zxf - -C $DUMP/$LEDGER.pending --strip-components=1; then
        rm -rf $DUMP/$LEDGER
        mv $DUMP/$LEDGER.pending $DUMP/$LEDGER
        echo "Download completed successfully"
      else
        echo "Download failed, cleaning up..."
        rm -rf $DUMP/$LEDGER.pending
        exit 1
      fi
    fi
  fi
}

if [[ ! -e $DUMP/$LEDGER && SKIP_INGEST -eq 0 ]]; then
  if [[ -e $DUMP/$LEDGER.pending ]]; then
    echo "Found incomplete download, cleaning up and retrying..."
    rm -rf $DUMP/$LEDGER.pending
  fi
  download_and_extract_ledger
  if [[ $SKIP_CHECKSUM -eq 0 ]]; then
    create_checksum
  fi
else
  if [[ $SKIP_CHECKSUM -eq 0 ]]; then
    check_ledger_checksum_and_redownload
  fi
fi

if [[ "$DOWNLOAD_ONLY" == "true" ]]; then
  exit 0
fi

chmod -R 0700 $DUMP/$LEDGER

echo_notice "Starting on-demand ingest and replay"
if [[ -n "$GENESIS" ]]; then
  HAS_INCREMENTAL="false"
fi
echo "
[snapshots]
    incremental_snapshots = $HAS_INCREMENTAL
    [snapshots.sources]
        servers = []
        [snapshots.sources.gossip]
            allow_any = false
            allow_list = []
[layout]
    shred_tile_count = 4
    snapla_tile_count = 1
    verify_tile_count = 2
    exec_tile_count = 6
[tiles]
    [tiles.archiver]
        enabled = true
        end_slot = $END_SLOT
        rocksdb_path = \"$DUMP/$LEDGER/rocksdb\"
        shredcap_path = \"$DUMP/$LEDGER/shreds.pcapng.zst\"
        ingest_mode = \"$INGEST_MODE\"
    [tiles.replay]
        enable_features = [ $FORMATTED_ONE_OFFS ]
    [tiles.gui]
        enabled = false
    [tiles.rpc]
        enabled = false
[store]
    max_completed_shred_sets = 32768
[funk]
    heap_size_gib = $FUNK_PAGES
    max_account_records = $INDEX_MAX
    max_database_transactions = 64
[runtime]
    max_live_slots = 32
    max_fork_width = 4
[log]
    level_stderr = \"$LOG_LEVEL_STDERR\"
    path = \"$LOG\"
[paths]
    snapshots = \"$DUMP/$LEDGER\"
[development]
    [development.snapshots]
        disable_lthash_verification = $DISABLE_LTHASH_VERIFICATION" > $DUMP_DIR/${LEDGER}_backtest.toml

if [[ -z "$GENESIS" ]]; then
  echo "[gossip]
    entrypoints = [ \"0.0.0.0:1\" ]" >> $DUMP_DIR/${LEDGER}_backtest.toml
else
  echo "[paths]
    genesis = \"$DUMP/$LEDGER/genesis.bin\""  >> $DUMP_DIR/${LEDGER}_backtest.toml
fi


if [[ "$INGEST_MODE" == "shredcap" ]]; then
  if [[ ! -e $DUMP/$LEDGER/shreds.pcapng.zst ]]; then
    $OBJDIR/bin/fd_blockstore2shredcap --rocksdb $DUMP/$LEDGER/rocksdb --out $DUMP/$LEDGER/shreds.pcapng.zst --zstd
  fi
  echo "Converted rocksdb to shredcap"
fi

echo "Running backtest for $LEDGER"

sudo rm -rf $DUMP/$LEDGER/backtest.blockstore $DUMP/$LEDGER/backtest.funk &> /dev/null

sudo killall firedancer-dev &> /dev/null || true

set -x
"${DEBUG[@]}" $OBJDIR/bin/firedancer-dev backtest --config ${DUMP_DIR}/${LEDGER}_backtest.toml "${WATCH[@]}"&> /dev/null
{ status=$?; set +x; } &> /dev/null

sudo rm -rf $DUMP/$LEDGER/backtest.blockstore $DUMP/$LEDGER/backtest.funk &> /dev/null

echo "Log for ledger $LEDGER at $LOG"

# check that the ledger is not corrupted after a run
if [[ $SKIP_CHECKSUM -eq 0 ]]; then
  check_ledger_checksum
fi

if [ "$status" -eq 0 ]; then
  echo_notice "Finished on-demand ingest and replay\n"
  exit 0
fi

tail -n 10 $LOG
echo "Failed with status: $status"

exit $status
