#!/bin/bash

# FIXME This whole file should just really be a firedancer-dev
#       invocation with parallelism natively implemented in C.

set -ex

DIR="$( dirname -- "${BASH_SOURCE[0]}"; )";   # Get the directory name
DIR="$( realpath -e -- "$DIR"; )";    # Resolve its full path if need be
cd $DIR/../..

OBJDIR=${OBJDIR:-build/native/gcc}
NUM_PROCESSES=${NUM_PROCESSES:-12}
PAGE_SZ=gigantic
PAGE_CNT=$(( 7 * $NUM_PROCESSES ))

if [ "$LOG_PATH" == "" ]; then
  LOG_PATH="`mktemp -d`"
else
  rm    -rf $LOG_PATH
  mkdir -pv $LOG_PATH
fi

mkdir -p dump

GIT_REF=${GIT_REF:-$(cat contrib/test/test-vectors-commit-sha.txt)}

echo $GIT_REF

if [ ! -d dump/test-vectors ]; then
  cd dump
  git clone -q --depth=1 https://github.com/firedancer-io/test-vectors.git
  cd test-vectors
else
  cd dump/test-vectors
fi

if ! git checkout -q $GIT_REF; then
  git remote update
  git checkout -q FETCH_HEAD
fi
cd ../..

WKSP=run-test-vectors
# If workspace already exists, reset it (and hope that it has the correct size)
if ./$OBJDIR/bin/fd_wksp_ctl query $WKSP --log-path '' >/dev/null 2>/dev/null; then
  ./$OBJDIR/bin/fd_wksp_ctl reset $WKSP --log-path ''
else
  ./$OBJDIR/bin/fd_wksp_ctl new run-test-vectors $PAGE_CNT $PAGE_SZ 0 0644 --log-path ''
fi

SOL_COMPAT=( "$OBJDIR/unit-test/test_sol_compat" "--wksp" "$WKSP" --tile-cpus "f,0-$(( $NUM_PROCESSES - 1 ))" )

export FD_LOG_PATH=$LOG_PATH/solfuzz.log
${SOL_COMPAT[@]} \
  dump/test-vectors/block/fixtures \
  dump/test-vectors/syscall/fixtures \
  dump/test-vectors/vm_interp/fixtures \
  dump/test-vectors/txn/fixtures \
  dump/test-vectors/elf_loader/fixtures \
  dump/test-vectors/instr/fixtures

echo Test vectors success
