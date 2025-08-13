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
PAGE_CNT=$(( 6 * $NUM_PROCESSES ))

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
  git fetch -q --depth=1 origin $GIT_REF
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

SOL_COMPAT=( "$OBJDIR/unit-test/test_sol_compat" "--wksp" "$WKSP" )

export FD_LOG_PATH=$LOG_PATH/test_exec_block
find dump/test-vectors/block/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ${SOL_COMPAT[@]}

export FD_LOG_PATH=$LOG_PATH/test_exec_syscall
find dump/test-vectors/syscall/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ${SOL_COMPAT[@]}

export FD_LOG_PATH=$LOG_PATH/test_exec_interp
find dump/test-vectors/vm_interp/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ${SOL_COMPAT[@]}

export FD_LOG_PATH=$LOG_PATH/test_exec_txn
find dump/test-vectors/txn/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES ${SOL_COMPAT[@]}

zstd -df dump/test-vectors/elf_loader/fixtures/*.zst
export FD_LOG_PATH=$LOG_PATH/test_elf_loader
find dump/test-vectors/elf_loader/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ${SOL_COMPAT[@]}

export FD_LOG_PATH=$LOG_PATH/test_exec_instr
find dump/test-vectors/instr/fixtures -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ${SOL_COMPAT[@]}

echo Test vectors success
