#!/bin/bash -f

# this assumes the test_runtime has already been built

LEDGER="v13-contract-ledger"
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

# bank frozen: 21 hash: 7A1Zi63guF7kMWeoYPZmhKdg2H9Hvoc2DAQ2S1QFXtH parent_hash: 6zPf6DeMhrpiSBhqahu9qEkqgVNiPhhzTejKB85FiAmB  accounts_delta: 4ptz3mgFYHfsfiBUfPaCtM5TwPXvu8Ctxe346sTiq74x signature_count: 2 last_blockhash: HyqLfiMCsXYwDTujyDLKwrTCDmkFtCoid5ehH6PDdzjt capitalization: 503000502311969156

build/native/gcc/bin/fd_frank_ledger --rocksdb $LEDGER/rocksdb --genesis $LEDGER/genesis.bin --cmd ingest --indexmax 10000 --txnmax 100 --backup test_ledger_backup  main  --net v13

build/native/gcc/unit-test/test_runtime --load test_ledger_backup --cmd replay --end-slot 22 --confirm_hash 7A1Zi63guF7kMWeoYPZmhKdg2H9Hvoc2DAQ2S1QFXtH    --confirm_signature 2  --confirm_last_block HyqLfiMCsXYwDTujyDLKwrTCDmkFtCoid5ehH6PDdzjt --validate true  --net v13 >& /tmp/bpf_log$$

status=$?

if [ $status -ne 0 ]
then
  tail -20 /tmp/bpf_log$$
  echo 'bpf test failed'
  echo /tmp/bpf_log$$
  exit $status
fi

echo 'bpf tests passed'
