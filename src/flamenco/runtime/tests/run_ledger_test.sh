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
END_SLOT="--end-slot 1010"
PAGES="--page-cnt 30"
FUNK_PAGES="--funk-page-cnt 16"
INDEX_MAX="--index-max 5000000"
TRASH_HASH=""
LOG="/tmp/ledger_log$$"
TILE_CPUS="--tile-cpus 5-21"
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
       CLUSTER_VERSION="--cluster-version $2"
       shift
       shift
       ;;
    -e|--end_slot)
       END_SLOT="--end-slot $2"
       shift
       shift
       ;;
    -p|--pages)
       PAGES="--page-cnt $2"
       shift
       shift
       ;;
    -y|--funk-pages)
       FUNK_PAGES="--funk-page-cnt $2"
       shift
       shift
       ;;
    -m|--indexmax)
       INDEX_MAX="--index-max $2"
       shift
       shift
       ;;
    -t|--trash)
       TRASH_HASH="--trash-hash $2"
       shift
       shift
       ;;
    -o|--one-offs)
       ONE_OFFS="--one-off-features $2"
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
  SNAPSHOT="--snapshot $DUMP/$SNAPSHOT"
fi

if [[ "" != "$RESTORE_ARCHIVE" ]]; then
  RESTORE_ARCHIVE="--restore-archive $DUMP/$RESTORE_ARCHIVE"
fi

if [[ "" == "$SNAPSHOT" && "" == "$RESTORE_ARCHIVE" ]]; then
  SNAPSHOT="--genesis $DUMP/$LEDGER/genesis.bin"
fi

echo_notice "Starting on-demand ingest and replay"
set -x
  "$OBJDIR"/bin/fd_ledger \
    --cmd replay \
    --verify-acc-hash 1 \
    --rocksdb $DUMP/$LEDGER/rocksdb \
    $RESTORE_ARCHIVE \
    $TRASH_HASH \
    $INDEX_MAX \
    $END_SLOT \
    $CLUSTER_VERSION \
    $PAGES \
    $FUNK_PAGES \
    $SNAPSHOT \
    $ONE_OFFS \
    --allocator wksp \
    $TILE_CPUS >& $LOG

status=$?
{ set +x; } &> /dev/null
echo_notice "Finished on-demand ingest and replay\n"

fd_log_file=$(grep "Log at" $LOG)
echo "Log for ledger $LEDGER at $fd_log_file"


if [ $status -ne 0 ] || grep -q "Bank hash mismatch" $LOG;
then
  if [ -n "$TRASH_HASH" ]; then
    echo "inverted test passed"
    exit 0
  fi
  tail -40 $LOG
  echo_error "ledger test failed: $*"
  echo $LOG

  exit $status
fi

rm $LOG
