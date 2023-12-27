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

# this assumes the test_runtime has already been built

LEDGER="v1176-big"
SNAPSHOT=""
INC_SNAPSHOT=""
END_SLOT="--end-slot 1010"
PAGES="--pages 5"
IMAX="--indexmax 100000"
START="--start 241819853"
END=""

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
       PAGES="--pages $2"
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
       SNAPSHOT="--snapshotfile dump/$LEDGER/$2"
       shift
       shift
       ;;
    -i|--incremental)
       INC_SNAPSHOT="--incremental dump/$LEDGER/$2"
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

if [ ! -e dump/$LEDGER ]; then
  mkdir -p dump
  curl -o - -L -q https://github.com/firedancer-io/firedancer-testbins/raw/main/$LEDGER.tar.gz | tar zxf - -C ./dump
fi

if [ "" == "$SNAPSHOT" ]; then
  SNAPSHOT="--genesis dump/$LEDGER/genesis.bin"
fi

set -x

"$OBJDIR"/bin/fd_frank_ledger \
  --reset true \
  --cmd ingest \
  --rocksdb dump/$LEDGER/rocksdb \
  $IMAX \
  $END \
  --txnmax 100 \
  --backup test_ledger_backup \
  $PAGES \
  $SNAPSHOT \
  $INC_SNAPSHOT

status=$?

if [ $status -ne 0 ]
then
  echo 'ledger test failed:'
  exit $status
fi

log=/tmp/ledger_log$$

ARGS=" --load test_ledger_backup \
  --cmd replay \
  $PAGES \
  --validate true \
  --abort-on-mismatch 1 \
  --capture test.solcap \
  $END_SLOT \
  --log-level-logfile 0 \
  --log-level-stderr 0 \
  --allocator libc"

if [ -e dump/$LEDGER/capitalization.csv ]
then
  ARGS="$ARGS --cap dump/$LEDGER/capitalization.csv"
fi

"$OBJDIR"/unit-test/test_runtime $ARGS >& $log

status=$?

if [ $status -ne 0 ]
then
  tail -20 $log
  echo 'ledger test failed:'
  echo $log
  exit $status
fi

rm $log
