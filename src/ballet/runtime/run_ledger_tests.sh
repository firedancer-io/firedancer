#!/bin/bash -f

# this assumes the test_runtime has already been built

if [ ! -e test-ledger-4 ]; then
  wget -q https://github.com/firedancer-io/firedancer-testbins/raw/main/test-ledger-4.tar.gz -O - | tar zxf -
fi

# we could ALWAYS run it with logging except when I run this from the command line, I want less noise...

build/linux/gcc/x86_64/unit-test/test_runtime --ledger test-ledger-4 --db /tmp/funk$$ --cmd replay --accounts test-ledger-4/accounts/ --pages 15 --index-max 120000000 --start-slot 0 --end-slot 25  --confirm_hash AsHedZaZkabNtB8XBiKWQkKwaeLy2y4Hrqm6MkQALT5h --confirm_parent CvgPeR54qpVRZGBuiQztGXecxSXREPfTF8wALujK4WdE --confirm_account_delta 7PL6JZgcNy5vkPSc6JsMHET9dvpvsFMWR734VtCG29xN  --confirm_signature 2  --confirm_last_block G4YL2SieHDGNZGjiwBsJESK7jMDfazg33ievuCwbkjrv

status=$?

if [ $status -ne 0 ]; then
  /bin/rm -f /tmp/funk$$
  build/linux/gcc/x86_64/unit-test/test_runtime --ledger test-ledger-4 --db /tmp/funk$$ --cmd replay --accounts test-ledger-4/accounts/ --pages 15 --index-max 120000000 --start-slot 0 --end-slot 25  --confirm_hash AsHedZaZkabNtB8XBiKWQkKwaeLy2y4Hrqm6MkQALT5h --confirm_parent CvgPeR54qpVRZGBuiQztGXecxSXREPfTF8wALujK4WdE --confirm_account_delta 7PL6JZgcNy5vkPSc6JsMHET9dvpvsFMWR734VtCG29xN  --confirm_signature 2  --confirm_last_block G4YL2SieHDGNZGjiwBsJESK7jMDfazg33ievuCwbkjrv  --log_level 5
fi

/bin/rm -f /tmp/funk$$
exit $status
