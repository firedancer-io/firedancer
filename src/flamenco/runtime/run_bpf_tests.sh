#!/bin/bash -f

# this assumes the test_runtime has already been built

LEDGER="v13-contract-ledger"
POSITION_ARGS=()
OBJDIR=${OBJDIR:-build/native/gcc}

while [[ $# -gt 0 ]]; do
  case $1 in
    -l|--ledger)
       LEDGER="$2"
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

if [ ! -e $LEDGER ]; then
  curl -o - -L -q https://github.com/firedancer-io/firedancer-testbins/raw/main/$LEDGER.tar.gz | tar zxf -
fi

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

set -x

"$OBJDIR"/bin/fd_frank_ledger --rocksdb $LEDGER/rocksdb --genesis $LEDGER/genesis.bin --cmd ingest --indexmax 10000 --txnmax 100 --backup test_ledger_backup --gaddrout gaddr --pages 1

status=$?

if [ $status -ne 0 ]
then
  echo 'ledger test failed:'
  exit $status
fi

log=/tmp/ledger_log$$

"$OBJDIR"/unit-test/test_runtime \
  --load test_ledger_backup \
  --cmd replay \
  --gaddr `cat gaddr` \
  --pages 1 \
  --validate true \
  --abort-on-mismatch 1 \
  --capture test.solcap >& $log

status=$?

if [ $status -ne 0 ]
then
  tail -20 $log
  echo 'ledger test failed:'
  echo $log
  exit $status
fi

rm $log

echo 'bpf tests passed'
