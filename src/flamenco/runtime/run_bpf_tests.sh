#!/bin/bash -f

# this assumes the test_runtime has already been built

LEDGER="v14-contract-ledger"
VERBOSE=NO
POSITION_ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -l|--ledger)
       LEDGER="$2"
       shift
       shift
       ;;
    -v|--verbose)
       VERBOSE=YES
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

# sudo build/linux/gcc/x86_64/bin/fd_shmem_cfg fini

# sudo build/linux/gcc/x86_64/bin/fd_shmem_cfg init 0777 jsiegel ""
# sudo build/linux/gcc/x86_64/bin/fd_shmem_cfg alloc 64 gigantic 0
# sudo build/linux/gcc/x86_64/bin/fd_shmem_cfg alloc 512 huge 0

set -x

if [ $VERBOSE == "YES" ]; then
  set -x
fi

build/linux/gcc/x86_64/bin/fd_frank_ledger --rocksdb $LEDGER/rocksdb --genesis $LEDGER/genesis.bin --cmd ingest --indexmax 10000 --txnmax 100 --backup test_ledger_backup --network main --log_level 99

build/linux/gcc/x86_64/unit-test/test_runtime --load test_ledger_backup --cmd replay --end-slot 22 --confirm_hash J1SVLicejnC67wzPpP3W3c7XqtSPj6JPSDDDuufsn2GQ    --confirm_signature 2  --confirm_last_block HyqLfiMCsXYwDTujyDLKwrTCDmkFtCoid5ehH6PDdzjt --validate true  --network main --log_level 99

status=$?

if [ $status -ne 0 ]
then
  echo 'ledger test failed'
  exit $status
fi

echo 'all tests passed'
