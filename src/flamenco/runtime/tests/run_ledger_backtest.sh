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
INGEST_MODE="rocksdb"
CLUSTER_VERSION=""
DUMP_DIR=${DUMP_DIR:="./dump"}
ONE_OFFS=""
HUGE_TLBFS_MOUNT_PATH=${HUGE_TLBFS_MOUNT_PATH:="/mnt/.fd"}
HUGE_TLBFS_ALLOW_HUGEPAGE_INCREASE=${HUGE_TLBFS_ALLOW_HUGEPAGE_INCREASE:="true"}
HAS_INCREMENTAL="false"
REDOWNLOAD=1

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
    -h|--hugetlbfs-mount-path)
        HUGE_TLBFS_MOUNT_PATH="$2"
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
}

if [[ ! -e $DUMP/$LEDGER && SKIP_INGEST -eq 0 ]]; then
  download_and_extract_ledger
  create_checksum
else
  check_ledger_checksum_and_redownload
fi

chmod -R 0700 $DUMP/$LEDGER

echo_notice "Starting on-demand ingest and replay"
if [[ -n "$GENESIS" ]]; then
  HAS_INCREMENTAL="false"
fi
echo "
[snapshots]
    incremental_snapshots = $HAS_INCREMENTAL
    download = false
    minimum_download_speed_mib = 0
    maximum_local_snapshot_age = 0
    maximum_download_retry_abort = 0
[layout]
    affinity = \"auto\"
    bank_tile_count = 1
    shred_tile_count = 4
    exec_tile_count = 4
[tiles]
    [tiles.archiver]
        enabled = true
        end_slot = $END_SLOT
        rocksdb_path = \"$DUMP/$LEDGER/rocksdb\"
        shredcap_path = \"$DUMP/$LEDGER/slices.bin\"
        bank_hash_path = \"$DUMP/$LEDGER/bank_hashes.bin\"
        ingest_mode = \"$INGEST_MODE\"
    [tiles.replay]
        cluster_version = \"$CLUSTER_VERSION\"
        heap_size_gib = 50
        enable_features = [ $FORMATTED_ONE_OFFS ] " > $DUMP_DIR/${LEDGER}_backtest.toml
if [[ -n "$GENESIS" ]]; then
  echo -n "        genesis = \"$DUMP/$LEDGER/genesis.bin\""  >> $DUMP_DIR/${LEDGER}_backtest.toml
fi
echo "
    [tiles.gui]
        enabled = false
[store]
    max_completed_shred_sets = 32768
[funk]
    heap_size_gib = $FUNK_PAGES
    max_account_records = $INDEX_MAX
    max_database_transactions = 64
[runtime]
    max_total_banks = 4
    max_fork_width = 4
[development]
    sandbox = true
    no_agave = true
    no_clone = false
[log]
    level_stderr = \"INFO\"
    path = \"$LOG\"
[paths]
    snapshots = \"$DUMP/$LEDGER\"
[hugetlbfs]
    mount_path = \"$HUGE_TLBFS_MOUNT_PATH\"
    allow_hugepage_increase = $HUGE_TLBFS_ALLOW_HUGEPAGE_INCREASE
" >> $DUMP_DIR/${LEDGER}_backtest.toml

echo "Running backtest for $LEDGER"

sudo rm -rf $DUMP/$LEDGER/backtest.blockstore $DUMP/$LEDGER/backtest.funk &> /dev/null

set -x
sudo $OBJDIR/bin/firedancer-dev backtest --config ${DUMP_DIR}/${LEDGER}_backtest.toml &> /dev/null
{ status=$?; set +x; } &> /dev/null

if [ "$status" -eq 139 ]; then
  echo "Backtest crashed with a segmentation fault!" &> /dev/null
fi

sudo rm -rf $DUMP/$LEDGER/backtest.blockstore $DUMP/$LEDGER/backtest.funk &> /dev/null

echo_notice "Finished on-demand ingest and replay\n"

echo "Log for ledger $LEDGER at $LOG"

# check that the ledger is not corrupted after a run
check_ledger_checksum

if grep -q "Backtest playback done." $LOG && ! grep -q "Bank hash mismatch!" $LOG;
then
  exit 0
  #   rm $LOG
else
  if [ -n "$TRASH_HASH" ]; then
    echo "inverted test passed"
    # rm $LOG
    exit 0
  fi

  echo "LAST 40 LINES OF LOG:"
  tail -40 $LOG
  echo_error "backtest test failed: $*"
  echo $LOG

  exit 1
fi
