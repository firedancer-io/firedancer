#!/bin/bash -f

source contrib/test/ledger_common.sh

POSITION_ARGS=()
OBJDIR=${OBJDIR:-$(make --silent --no-print-directory objdir 2>/dev/null || true)}
: "${OBJDIR:?cannot determine OBJDIR (make objdir failed)}"

LEDGER=""
RESTORE_ARCHIVE=""
END_SLOT="0"
INDEX_MAX="5000000"
LOG="/tmp/ledger_log$$"
INGEST_MODE="shredcap"
DUMP_DIR=${DUMP_DIR:="./dump"}
ONE_OFFS=""
HUGE_TLBFS_MOUNT_PATH=${HUGE_TLBFS_MOUNT_PATH:="/mnt/.fd"}
DEBUG=( )
WATCH=( )
LOG_LEVEL_STDERR=NOTICE
EXECRP_TILE_COUNT="10"
SNAPDC_TILE_COUNT=""
ROOT_DISTANCE="2"
MAX_LIVE_SLOTS="32"
ALPENGLOW="false"
SHRED_VERSION=""
DOWNLOAD_ONLY=${DOWNLOAD_ONLY:-"false"}

if [[ -n "$CI" ]]; then
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
    -m|--indexmax)
       INDEX_MAX="$2"
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
    --debug)
        DEBUG=( gdb -q -x contrib/debug.gdb --args )
        shift
        ;;
    --log)
        LOG="$2"
        shift
        shift
        ;;
    --exec)
        EXECRP_TILE_COUNT="$2"
        shift
        shift
        ;;
    --snapdc)
        SNAPDC_TILE_COUNT="$2"
        shift
        shift
        ;;
    --root-distance)
        ROOT_DISTANCE="$2"
        shift
        shift
        ;;
    --max-live-slots)
        MAX_LIVE_SLOTS="$2"
        shift
        shift
        ;;
    --alpenglow)
        ALPENGLOW="true"
        shift
        ;;
    --shred-version)
        SHRED_VERSION="$2"
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

FORMATTED_ONE_OFFS=$(echo "$ONE_OFFS" | sed -E 's/([^,]+)/"\1"/g')

export LLVM_PROFILE_FILE=$OBJDIR/cov/raw/ledger_test_$LEDGER.profraw
mkdir -p $OBJDIR/cov/raw

DUMP=$(realpath $DUMP_DIR)
mkdir -p $DUMP

download_and_extract_ledger() {
  local ext=tar.gz unpack="tar zxf -"
  [[ -n "${ZST:-}" ]] && ext=tar.zst unpack="zstd -d --stdout | tar xf -"
  echo "Downloading gs://firedancer-ci-resources/$LEDGER.$ext"
  if ! gcloud auth list 2>&1 | grep -q "firedancer-\(scratch\|ci\)"; then
    for key in /etc/firedancer-scratch-bucket-key.json /etc/firedancer-ci-78fff3e07c8b.json; do
      [[ -f $key ]] && gcloud auth activate-service-account --key-file "$key"
    done
  fi
  rm -rf "$DUMP/$LEDGER.pending" "$DUMP/$LEDGER"
  mkdir -p "$DUMP/$LEDGER.pending"
  if ! gcloud storage cat "gs://firedancer-ci-resources/$LEDGER.$ext" | eval "$unpack" -C "$DUMP/$LEDGER.pending" --strip-components=1; then
    echo "Download failed, cleaning up..."; rm -rf "$DUMP/$LEDGER.pending"; exit 1
  fi
  ( cd "$DUMP/$LEDGER.pending" && find . -type f -printf '%P %s\n' | sort ) > "$DUMP/$LEDGER.manifest"
  mv "$DUMP/$LEDGER.pending" "$DUMP/$LEDGER"
}

ledger_ok() {
  [[ -f $DUMP/$LEDGER.manifest ]] || return 0
  while read -r f sz; do [[ $(stat -c %s "$DUMP/$LEDGER/$f" 2>/dev/null) == "$sz" ]] || return 1; done < "$DUMP/$LEDGER.manifest"
}

if [[ SKIP_INGEST -eq 0 ]] && { [[ ! -e $DUMP/$LEDGER ]] || ! ledger_ok; }; then
  download_and_extract_ledger
fi

if [[ "$DOWNLOAD_ONLY" == "true" ]]; then
  exit 0
fi

if [[ "$INGEST_MODE" != "shredcap" ]]; then
  echo "ingest mode '$INGEST_MODE' is not supported: firedancer-dev only ingests shredcap captures (RocksDB ingest lives in blockstore2shredcap)"
  exit 1
fi

convert_rocksdb_to_shredcap() {
  local zst_tmp=$DUMP/$LEDGER/shreds.pcapng.zst.tmp
  rm -f "$zst_tmp"
  if ! contrib/blockstore/blockstore2shredcap --rocksdb $DUMP/$LEDGER/rocksdb --out "$zst_tmp" --zstd; then
    rm -f "$zst_tmp"
    return 1
  fi
  mv "$zst_tmp" $DUMP/$LEDGER/shreds.pcapng.zst
  echo "Converted rocksdb to shredcap"
}

LEDGER_INPUT="$DUMP/$LEDGER/shreds.pcapng.zst"
if [[ ! -e $DUMP/$LEDGER/shreds.pcapng.zst && ! -e $DUMP/$LEDGER/rocksdb ]]; then
  LEDGER_INPUT=""
elif [[ ! -e $DUMP/$LEDGER/shreds.pcapng.zst ]]; then
  if ! make -B -C contrib/blockstore blockstore2shredcap; then
    echo "failed to build contrib/blockstore/blockstore2shredcap"
    exit 1
  fi

  if ! convert_rocksdb_to_shredcap; then
    # A cached ledger may have a corrupt rocksdb (eg. damaged by a converter
    # version that deleted unopened column families); re-download once.
    echo "conversion failed; re-downloading ledger and retrying"
    download_and_extract_ledger
    if ! convert_rocksdb_to_shredcap; then
      echo "rocksdb to shredcap conversion failed"
      exit 1
    fi
  fi
fi

chmod -R 0700 $DUMP/$LEDGER

CONFIG_FILE="$DUMP_DIR/${LEDGER}_backtest.toml"
cat <<EOF > ${CONFIG_FILE}
telemetry = false
[snapshots]
    max_full_snapshots_to_keep = 5
    max_incremental_snapshots_to_keep = 5
    [snapshots.sources]
        servers = []
        [snapshots.sources.gossip]
            allow_any = false
            allow_list = []
[layout]
    execrp_tile_count = $EXECRP_TILE_COUNT
${SNAPDC_TILE_COUNT:+    snapdc_tile_count = $SNAPDC_TILE_COUNT}
[tiles]
    [tiles.replay]
        enable_features = [ $FORMATTED_ONE_OFFS ]
    [tiles.gui]
        enabled = false
    [tiles.rpc]
        enabled = false
[runtime]
    max_live_slots = $MAX_LIVE_SLOTS
    max_fork_width = 4
[log]
    level_stderr = "$LOG_LEVEL_STDERR"
    path = "$LOG"
[paths]
    snapshots = "$DUMP/$LEDGER"
    accounts = "$DUMP/accounts.db"
    genesis = "$DUMP/$LEDGER/genesis.bin"
[development]
    fixed_fec_sets = false
    alpenglow = $ALPENGLOW
    [development.genesis]
        validate_genesis_hash = false
    [development.ledger_input]
        path = "$LEDGER_INPUT"
        end_slot = $END_SLOT
    [development.backtest]
        root_distance = $ROOT_DISTANCE
EOF

if [[ "$INDEX_MAX" -lt "1000000" ]]; then
  INDEX_MAX=1000000
fi
cat <<EOF >> ${CONFIG_FILE}
[accounts]
    max_accounts = $INDEX_MAX
    cache_size_gib = 3
EOF

if [[ -z "$GENESIS" ]]; then
  echo "[gossip]
    entrypoints = [ \"0.0.0.0:1\" ]" >> $DUMP_DIR/${LEDGER}_backtest.toml
fi

# alpenglow ledgers require an expected_shred_verion
if [[ -n "$SHRED_VERSION" ]]; then
  echo "[consensus]
    expected_shred_version = $SHRED_VERSION" >> $DUMP_DIR/${LEDGER}_backtest.toml
fi

echo_notice "Running backtest for $LEDGER"

sudo killall firedancer-dev &> /dev/null || true
rm -f $DUMP/accounts.db

set -x
if [[ -n "$CI" ]]; then
  "${DEBUG[@]}" $OBJDIR/bin/firedancer-dev backtest --config ${DUMP_DIR}/${LEDGER}_backtest.toml "${WATCH[@]}" &> /dev/null
  { status=$?; set +x; } &> /dev/null
else
  "${DEBUG[@]}" $OBJDIR/bin/firedancer-dev backtest --config ${DUMP_DIR}/${LEDGER}_backtest.toml "${WATCH[@]}"
  { status=$?; set +x; }
fi

echo "Log for ledger $LEDGER at $LOG"

rm -rf $DUMP/accounts.db

if [ "$status" -eq 0 ]; then
  snapshot_load_time=$(grep "loaded" $LOG | grep -o "from snapshot in [0-9.]*" | grep -o "[0-9.]*")
  echo "Snapshot load time for $LEDGER: $snapshot_load_time seconds"
  elapsed_time=$(grep "Backtest playback done." $LOG | grep -o "elapsed: [0-9.]*" | grep -o "[0-9.]*")
  echo "Replay time for $LEDGER: $elapsed_time seconds"

  while IFS= read -r epoch_line; do
    epoch_num=$(echo "$epoch_line" | grep -o "starting epoch [0-9]*" | grep -o "[0-9]*")
    epoch_time_sec=$(echo "$epoch_line" | grep -o "took [0-9.]*" | grep -o "[0-9.]*")
    echo "Epoch $epoch_num boundary time for $LEDGER: ${epoch_time_sec} seconds"
  done < <(grep "starting epoch .* took " "$LOG")

  echo_notice "Finished backtest for ledger $LEDGER\n"
  exit 0
fi

tail -n 10 $LOG
echo "Failed with status: $status"

exit $status
