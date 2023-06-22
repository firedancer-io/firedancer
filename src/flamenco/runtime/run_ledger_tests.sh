#!/bin/bash -f

# this assumes the test_runtime has already been built

if [ ! -e test-ledger-4 ]; then
  wget -q https://github.com/firedancer-io/firedancer-testbins/raw/main/test-ledger-4.tar.gz -O - | tar zxf -
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

# set -x

if [ -e /mnt/.fd/.gigantic/test_ledger_wksp ]; then
    build/linux/gcc/x86_64/bin/fd_wksp_ctl delete test_ledger_wksp
fi
build/linux/gcc/x86_64/bin/fd_wksp_ctl new test_ledger_wksp 5 gigantic 0 0666

build/linux/gcc/x86_64/bin/fd_frank_ledger --wksp test_ledger_wksp --reset true --rocksdb test-ledger-4/rocksdb --genesis test-ledger-4/genesis.bin --cmd ingest --gaddrout testgaddr --indexmax 10000 --txnmax 100 --backup test_ledger_backup

build/linux/gcc/x86_64/unit-test/test_runtime --wksp test_ledger_wksp --gaddr `cat testgaddr` --cmd replay --end-slot 25 --confirm_hash AsHedZaZkabNtB8XBiKWQkKwaeLy2y4Hrqm6MkQALT5h --confirm_parent CvgPeR54qpVRZGBuiQztGXecxSXREPfTF8wALujK4WdE --confirm_account_delta 7PL6JZgcNy5vkPSc6JsMHET9dvpvsFMWR734VtCG29xN  --confirm_signature 2  --confirm_last_block G4YL2SieHDGNZGjiwBsJESK7jMDfazg33ievuCwbkjrv --validate true

status=$?

build/linux/gcc/x86_64/bin/fd_wksp_ctl delete test_ledger_wksp
rm -f testfunk testgaddr

if [ $status -ne 0 ]
then
  echo 'ledger test failed'
  exit $status
fi

build/linux/gcc/x86_64/unit-test/test_native_programs --filter 'vote|system|config' >& native.log
status=$?
if [ $status -ne 0 ]
then
  echo 'native test failed'
  grep "Failed" native.log | tail -20
  exit $status
fi

grep "Progress" native.log

echo 'all tests passed'
