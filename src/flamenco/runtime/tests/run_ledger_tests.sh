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

# this assumes the test_runtime has already been built

LEDGER="v18-small"
SNAPSHOT=""
INC_SNAPSHOT=""
END_SLOT="--end-slot 1010"
PAGES="--page-cnt 20"
IMAX="--indexmax 100000"
START="--start 241819853"
HISTORY="--slothistory 5000"
END=""
TRASHHASH=""
EXPECTED="0"
LOG="/tmp/ledger_log$$"
TXN_STATUS="--txnstatus false"
SKIP_INGEST=0
CHECKPT="test_ledger_backup"
SOLCAP=""

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
       TRASHHASH="--trashhash $2"
       shift
       shift
       ;;
    -X|--expected)
       EXPECTED="$2"
       shift
       shift
       ;;
    -m|--indexmax)
       IMAX="--indexmax $2"
       shift
       shift
       ;;
    -e|--end_slot)
       END_SLOT="--end-slot $2"
       END="--endslot $2"
       shift
       shift
       ;;
    -b|--start)
       START="--start=$2"
       shift
       shift
       ;;
    -s|--snapshot)
       SNAPSHOT=" --verifyacchash true --snapshotfile dump/$LEDGER/$2"
       shift
       shift
       ;;
    -i|--incremental)
       INC_SNAPSHOT="--incremental dump/$LEDGER/$2"
       shift
       shift
       ;;
    -h|--slothistory)
       HISTORY="--slothistory $2"
       shift
       shift
       ;;
    -t|--txnstatus)
       TXN_STATUS="--txnstatus $2"
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
        SOLCAP="--capture $2"
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

if [[ $SKIP_INGEST = 0 ]]; then
  set -x
  "$OBJDIR"/bin/fd_frank_ledger \
    --reset true \
    --cmd ingest \
    --rocksdb dump/$LEDGER/rocksdb \
    $TRASHHASH \
    $IMAX \
    $END \
    --txnmax 100 \
    --backup dump/test_ledger_backup \
    $PAGES \
    $SNAPSHOT \
    $INC_SNAPSHOT \
    $HISTORY \
    $TXN_STATUS

  status=$?

  if [ $status -ne 0 ]
  then
    if [ "$status" -eq "$EXPECTED" ]; then
      echo "inverted test passed"
      exit 0
    fi
    echo 'ledger test failed: $status'
    exit $status
  fi

  if [[ -n "$NOREPLAY" ]]; then
    exit 0
  fi
fi

ARGS=" --load dump/$CHECKPT \
  --cmd replay \
  $PAGES \
  --validate true \
  --abort-on-mismatch 1 \
  $SOLCAP \
  $END_SLOT \
  --log-level-logfile 2 \
  --log-level-stderr 2 \
  --allocator wksp \
  --tile-cpus 5-21"

if [ -e dump/$LEDGER/capitalization.csv ]
then
  ARGS="$ARGS --cap dump/$LEDGER/capitalization.csv"
fi

set -x
"$OBJDIR"/unit-test/test_runtime $ARGS >& $LOG

status=$?

if [ $status -ne 0 ] || grep -q "Bank hash mismatch" $LOG;
then
  if [ "$status" -eq "$EXPECTED" ]; then
    echo "inverted test passed"
    exit 0
  fi
  tail -40 $LOG
  echo 'ledger test failed:'
  echo $LOG
  exit $status
fi

rm $LOG
