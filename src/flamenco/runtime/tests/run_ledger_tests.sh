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
PAGES="--page-cnt 20"
IMAX="--index-max 1000000"
START="--start-slot 241819853"
HISTORY="--slot-history 5000"
TRASHHASH=""
EXPECTED="0"
LOG="/tmp/ledger_log$$"
TXN_STATUS="--copy-txn-status 0"
SKIP_INGEST=0
CHECKPT="test_ledger_backup"
SOLCAP=""
ON_DEMAND=1

POSITION_ARGS=()
OBJDIR=${OBJDIR:-build/native/gcc}

while [[ $# -gt 0 ]]; do
  case $1 in
    -l|--ledger)
       LEDGER="$2"
       shift
       shift
       ;;
    -p|--pages)
       PAGES="--page-cnt $2"
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
    -S|--skipingest)
        SKIP_INGEST=1
        shift
        ;;
    -C|--checkpoint)
        CHECKPT="$2"
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
    gcloud storage cat gs://firedancer-ci-resources/$LEDGER.tar.zst | zstd -d | tar xf - -C ./dump
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
    --txn-max 100 \
    $PAGES \
    $SNAPSHOT \
    $SOLCAP \
    $INC_SNAPSHOT \
    $HISTORY \
    $TXN_STATUS \
    --allocator wksp \
    --on-demand-block-ingest 1 \
    --tile-cpus 5-21 >& $LOG

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
  --log-level-logfile 2 \
  --log-level-stderr 2 \
  --allocator wksp \
  --tile-cpus 5-21" \

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

if [ $status -ne 0 ] || grep -q "Bank hash mismatch" $LOG;
then
  if [ "$status" -eq "$EXPECTED" ]; then
    echo "inverted test passed"
    exit 0
  fi
  tail -40 $LOG
  echo_error 'ledger test failed:'
  echo $LOG
  exit $status
fi

rm $LOG
