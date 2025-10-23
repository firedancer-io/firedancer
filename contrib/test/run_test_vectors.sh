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
REPO_URL="https://github.com/firedancer-io/test-vectors.git"

echo $GIT_REF

# Prepare local repo and enter it
if [ ! -f dump/test-vectors/README.md ]; then
  cd dump
  git clone -q --no-tags --depth=1 "$REPO_URL" test-vectors
  cd test-vectors
else
  cd dump/test-vectors
fi

if ! git checkout -q $GIT_REF; then
  git remote update
  git checkout -q $GIT_REF
fi
cd ../..

SOL_COMPAT=( "$OBJDIR/unit-test/test_sol_compat" --tile-cpus "f,0-$(( $NUM_PROCESSES - 1 ))" )

export FD_LOG_PATH=$LOG_PATH/solfuzz.log
${SOL_COMPAT[@]} \
  dump/test-vectors/block/fixtures \
  dump/test-vectors/syscall/fixtures \
  dump/test-vectors/vm_interp/fixtures \
  dump/test-vectors/txn/fixtures \
  dump/test-vectors/elf_loader/fixtures \
  dump/test-vectors/instr/fixtures

echo Test vectors success
