#!/bin/bash -f

# We determine these values by
#  1) Checkout https://github.com/firedancer-io/solana.git
#  2) switch to the debug branch
#  3) build using podman (podman build --no-cache -t solana-builder2 -f Dockerfile -v `pwd`:/solana:rw  .)
#  4) ./target/debug/solana-test-validator --reset
#         Do stuff
#  5) grep 'bank frozen:' test-ledger/validator.log | grep 'solana_runtime::bank'

# we could ALWAYS run it with logging except when I run this from the command line, I want less noise...

# sudo build/native/gcc/bin/fd_shmem_cfg fini

# sudo build/native/gcc/bin/fd_shmem_cfg init 0777 jsiegel ""
# sudo build/native/gcc/bin/fd_shmem_cfg alloc 225 gigantic 0
# sudo build/native/gcc/bin/fd_shmem_cfg alloc 512 huge 0

# sudo build/linux/clang/x86_64/bin/fd_shmem_cfg fini
# sudo build/linux/clang/x86_64/bin/fd_shmem_cfg init 0777 jsiegel ""
# sudo build/linux/clang/x86_64/bin/fd_shmem_cfg alloc 64 gigantic 0
# sudo build/linux/clang/x86_64/bin/fd_shmem_cfg alloc 32 huge 0

echo_notice() {
  echo -e "\033[34m$1\033[0m"
}

echo_error() {
  echo -e "\033[31m$1$2\033[0m"
}

LEDGER="v18-small"
SNAPSHOT=""
INC_SNAPSHOT=""
END_SLOT="--end-slot 1010"
FUNK_PAGES="--funk-page-cnt 20"
PAGES="--page-cnt 20"
PRUNED_PAGES="--pruned-page-cnt 20"
IMAX="--index-max 1000000"
PRUNED_IMAX="--pruned-index-max 1000000"
START="--start-slot 241819853"
HISTORY="--slot-history 5000"
TRASHHASH=""
EXPECTED="0"
LOG="/tmp/ledger_log$$"
TXN_STATUS="--copy-txn-status 0"
SKIP_INGEST=0
CHECKPT="test_ledger_backup"
CHECKPT_PATH=""
CHECKPT_FREQ=""
SOLCAP=""
ON_DEMAND=1
WITH_COVERAGE=0
PRUNE_FAILURE=0
TILE_CPUS="--tile-cpus 5-21"

POSITION_ARGS=()
OBJDIR=${OBJDIR:-build/native/gcc}

while [[ $# -gt 0 ]]; do
  case $1 in
    -l|--ledger)
       LEDGER="$2"
       shift
       shift
       ;;
    -c|--with_coverage)
       WITH_COVERAGE="$2"
       shift
       shift
       ;;
    -p|--pages)
       PAGES="--page-cnt $2"
       shift
       shift
       ;;
    -P|--pruned-page-cnt)
       PRUNED_PAGES="--pruned-page-cnt $2"
       shift
       shift
       ;;
    -y|--funk-pages)
       FUNK_PAGES="--funk-page-cnt $2"
       shift
       shift
       ;;
    -t|--trash)
       TRASHHASH="--trash-hash $2"
       shift
       shift
       ;;
    -X|--expected)
       EXPECTED="$2"
       shift
       shift
       ;;
    -m|--indexmax)
       IMAX="--index-max $2"
       shift
       shift
       ;;
    -M|--indexmax-pruned)
       PRUNED_IMAX="--pruned-index-max $2"
       shift
       shift
       ;;
    -e|--end_slot)
       END_SLOT="--end-slot $2"
       shift
       shift
       ;;
    -b|--start)
       START="--start-slot=$2"
       shift
       shift
       ;;
    -s|--snapshot)
       SNAPSHOT=" --verify-acc-hash 1 --snapshot dump/$LEDGER/$2"
       shift
       shift
       ;;
    --snapshot-no-verify)
       SNAPSHOT=" --verify-acc-hash 0 --snapshot dump/$LEDGER/$2"
       shift
       shift
       ;;
    -i|--incremental)
       INC_SNAPSHOT="--incremental dump/$LEDGER/$2"
       shift
       shift
       ;;
    -h|--slothistory)
       HISTORY="--slot-history $2"
       shift
       shift
       ;;
    -tx|--txnstatus)
       TXN_STATUS="--copy-txn-status $2"
       shift
       shift
       ;;
    -l|--log)
       LOG="$2"
       shift
       shift
       ;;
    --noreplay)
        NOREPLAY=1
        shift
        ;;
    --zst)
        ZST=1
        shift
        ;;
    -pf|--prune-failure)
       PRUNE_FAILURE="$2"
       shift
       shift
       ;;
    -S|--skipingest)
        SKIP_INGEST=1
        shift
        ;;
    -C|--checkpoint)
        CHECKPT="$2"
        shift
        ;;
    -cp|--checkpt-path)
        CHECKPT_PATH="--checkpt-path $2"
        shift
        ;;
    -cf|--checkpt-freq)
        CHECKPT_FREQ="--checkpt-freq $2"
        shift
        ;;
    -c|--capture)
        SOLCAP="--capture-solcap $2"
        shift
        shift
        ;;
    -L|--log)
        LOG="$2"
        shift
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

if [[ ! -e dump/$CHECKPT && SKIP_INGEST -eq 1 ]]; then
  mkdir -p dump
  echo "Downloading gs://firedancer-ci-resources/$CHECKPT.zst"
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

  gcloud storage cat gs://firedancer-ci-resources/$CHECKPT.zst | zstd -d > ./dump/$CHECKPT
fi

if [[ ! -e dump/$LEDGER && SKIP_INGEST -eq 0 ]]; then
  mkdir -p dump
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
    gcloud storage cat gs://firedancer-ci-resources/$LEDGER.tar.zst | zstd -d --stdout | tar xf - -C ./dump
  else
    gcloud storage cat gs://firedancer-ci-resources/$LEDGER.tar.gz | tar zxf - -C ./dump
  fi
  # curl -o - -L -q https://github.com/firedancer-io/firedancer-testbins/raw/main/$LEDGER.tar.gz | tar zxf - -C ./dump
fi

if [ "" == "$SNAPSHOT" ]; then
  SNAPSHOT="--genesis dump/$LEDGER/genesis.bin"
fi

# If on demand, ingest and replay in a single pass
if [[ $ON_DEMAND = 1 ]]; then
  echo_notice "Starting on-demand ingest and replay"
  set -x
  "$OBJDIR"/bin/fd_ledger \
    --reset 1 \
    --cmd replay \
    --rocksdb dump/$LEDGER/rocksdb \
    $TRASHHASH \
    $IMAX \
    $END_SLOT \
    $CHECKPT_PATH \
    $CHECKPT_FREQ \
    --funk-only 1 \
    --txn-max 100 \
    $PAGES \
    $FUNK_PAGES \
    $SNAPSHOT \
    $SOLCAP \
    $INC_SNAPSHOT \
    $HISTORY \
    $TXN_STATUS \
    --allocator wksp \
    --on-demand-block-ingest 1 \
    $TILE_CPUS >& $LOG

  status=$?
  { set +x; } &> /dev/null
  echo_notice "Finished on-demand ingest and replay\n"
fi

# If not on demand and not skipping ingest, ingest first
if [[ $SKIP_INGEST = 0 && $ON_DEMAND = 0 ]]; then
  echo_notice "Non on-demand ingest is deprecated!!"
  echo_notice "Starting ingest to checkpoint"
  set -x
  "$OBJDIR"/bin/fd_ledger \
    --reset true \
    --cmd ingest \
    --rocksdb dump/$LEDGER/rocksdb \
    $TRASHHASH \
    $IMAX \
    $END_SLOT \
    --txn-max 100 \
    --checkpt dump/test_ledger_backup \
    $PAGES \
    $SNAPSHOT \
    $INC_SNAPSHOT \
    $HISTORY \
    $TXN_STATUS
  { set +x; } &> /dev/null
  echo_notice "Finished ingest to checkpoint\n"
  status=$?

  if [ $status -ne 0 ]
  then
    echo_error 'ledger ingest failed:' $status
    exit $status
  fi

  if [[ -n "$NOREPLAY" ]]; then
    echo_notice "No replay enabed"
    exit 0
  fi
fi


ARGS=" --restore dump/$CHECKPT \
  --cmd replay \
  $PAGES \
  --validate true \
  --abort-on-mismatch 1 \
  $SOLCAP \
  $END_SLOT \
  $IMAX \
  $CHECKPT_PATH \
  $CHECKPT_FREQ \
  --funk-only 1 \
  --log-level-logfile 2 \
  --log-level-stderr 2 \
  --allocator wksp \
  $TILE_CPUS" \

if [ -e dump/$LEDGER/capitalization.csv ]
then
  ARGS="$ARGS --cap dump/$LEDGER/capitalization.csv"
fi

if [[ $ON_DEMAND = 0 ]]; then
  echo_notice "Starting replay from checkpoint"
  set -x
  "$OBJDIR"/bin/fd_ledger $ARGS >& $LOG
  { set +x; } &> /dev/null
  status=$?
  echo_notice "Finished replay from checkpoint\n"
fi

fd_log_file=$(grep "Log at" $LOG)
echo "Log for ledger $LEDGER at $fd_log_file"

if [ $status -ne 0 ] || grep -q "Bank hash mismatch" $LOG;
then
  if [ "$status" -eq "$EXPECTED" ]; then
    echo "inverted test passed"
    exit 0
  fi
  tail -40 $LOG
  echo_error 'ledger test failed:'
  echo $LOG

  # create prune here
  mismatch_slot=$(grep "Bank hash mismatch!" "$LOG" | tail -n 1 | awk -F'slot=' '{print $2}' | awk '{print $1}')
  prune_start_slot=$((mismatch_slot - 100))
  prune_end_slot=$((mismatch_slot + 100))

  if [[ $PRUNE_FAILURE = 1 ]]; then
    RESTORE_PATH=${CHECKPT_PATH#* }
    PRUNE_PATH=${CHECKPT_PATH#* }_pruned

    echo_notice "Starting prune on failed slots"
    set -x
    "$OBJDIR"/bin/fd_ledger \
      --reset 1 \
      --cmd prune \
      --rocksdb dump/$LEDGER/rocksdb \
      $TRASHHASH \
      $IMAX \
      --start-slot $prune_start_slot \
      --end-slot $prune_end_slot \
      --funk-restore $RESTORE_PATH \
      --checkpt-funk $PRUNE_PATH \
      --funk-only 1 \
      --txn-max 100 \
      $PAGES \
      $FUNK_PAGES \
      $PRUNED_PAGES \
      $PRUNED_IMAX \
      $SOLCAP \
      $INC_SNAPSHOT \
      $HISTORY \
      $TXN_STATUS \
      --allocator wksp \
      --on-demand-block-ingest 1 \
      --tile-cpus 5-21 >& $LOG

      prune_status=$?

      if [ $prune_status -eq 0 ]; then
        gsutil cp ${PRUNE_PATH} gs://firedancer-ci-resources${PRUNE_PATH}
      else
        echo_error 'ledger prune failed:' $prune_status
      fi
    fi

  exit $status
fi

rm $LOG
