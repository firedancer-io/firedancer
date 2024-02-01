#!/bin/bash

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

LEDGER="empty-ledger"
SNAPSHOT=""
INC_SNAPSHOT=""
PAGES="--pages 100"

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

if [ ! -e dump/$snapshots ]; then
  mkdir -p dump/snapshots
  cd dump/snapshots
  wget --trust-server-names http://entrypoint2.testnet.solana.com/snapshot.tar.bz2&
  wget --trust-server-names http://entrypoint2.testnet.solana.com/incremental-snapshot.tar.bz2&
  wait
  cd ../..
fi


if [ "" == "$SNAPSHOT" ]; then
  SNAPSHOT="--genesis dump/$LEDGER/genesis.bin"
fi

set -x

"$OBJDIR"/bin/fd_frank_ledger \
  --reset true \
  --cmd ingest \
   --verifyacchash true \
  --txnmax 100 \
  --backup test_ledger_backup \
  $PAGES \
  --snapshotfile dump/snapshots/snapshot-*

status=$?

if [ $status -ne 0 ]
then
  echo 'ledger test failed:'
  exit $status
fi

rm $log
