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

# sudo build/linux/clang/icelake/bin/fd_shmem_cfg fini
# sudo build/linux/clang/icelake/bin/fd_shmem_cfg init 0777 jsiegel ""
# sudo build/linux/clang/icelake/bin/fd_shmem_cfg alloc 64 gigantic 0
# sudo build/linux/clang/icelake/bin/fd_shmem_cfg alloc 32 huge 0

# this assumes the test_runtime has already been built

LEDGER="v18-small"
SNAPSHOT=""
INC_SNAPSHOT=""
END_SLOT="--end-slot 1010"
PAGES="--page-cnt 5"
IMAX="--indexmax 100000"
START="--start 241819853"
HISTORY="--slothistory 3000"
END=""
TRASHHASH=""
EXPECTED="0"
LOG="/tmp/ledger_log$$"

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
    -l|--log)
       LOG="$2"
       shift
       shift
       ;;
    --noreplay)
        NOREPLAY=1
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

if [ ! -e dump/$LEDGER ]; then
  mkdir -p dump
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
  gsutil cat gs://firedancer-ci-resources/$LEDGER.tar.gz | tar zxf - -C ./dump
  # curl -o - -L -q https://github.com/firedancer-io/firedancer-testbins/raw/main/$LEDGER.tar.gz | tar zxf - -C ./dump
fi

if [ "" == "$SNAPSHOT" ]; then
  SNAPSHOT="--genesis dump/$LEDGER/genesis.bin"
fi

set -x

"$OBJDIR"/bin/fd_frank_ledger \
  --reset true \
  --cmd ingest \
  --rocksdb dump/$LEDGER/rocksdb \
  $TRASHHASH \
  $IMAX \
  $END \
  --txnmax 100 \
  --backup test_ledger_backup \
  $PAGES \
  $SNAPSHOT \
  $INC_SNAPSHOT \
  $HISTORY

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

ARGS=" --load test_ledger_backup \
  --cmd replay \
  $PAGES \
  --validate true \
  --abort-on-mismatch 1 \
  --capture test.solcap \
  $END_SLOT \
  --log-level-logfile 2 \
  --log-level-stderr 2 \
  --allocator libc"

if [ -e dump/$LEDGER/capitalization.csv ]
then
  ARGS="$ARGS --cap dump/$LEDGER/capitalization.csv"
fi

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


