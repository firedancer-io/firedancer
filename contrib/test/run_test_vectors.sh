#!/bin/bash

set -ex

DIR="$( dirname -- "${BASH_SOURCE[0]}"; )";   # Get the directory name
DIR="$( realpath -e -- "$DIR"; )";    # Resolve its full path if need be
cd $DIR/../..

OBJDIR=${OBJDIR:-build/native/gcc}
NUM_PROCESSES=${NUM_PROCESSES:-12}

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

git fetch -q --depth=1 origin $GIT_REF
git checkout -q $GIT_REF
cd ../..

LOG=$LOG_PATH/test_exec_block
find dump/test-vectors/block/fixtures/* -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG --wksp-page-sz 1073741824

LOG=$LOG_PATH/test_exec_syscall
find dump/test-vectors/syscall/fixtures/* -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG --wksp-page-sz 1073741824

LOG=$LOG_PATH/test_exec_interp
find dump/test-vectors/vm_interp/fixtures/* -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG --wksp-page-sz 1073741824

LOG=$LOG_PATH/test_exec_txn
find dump/test-vectors/txn/fixtures/* -type f -name '*.fix' | xargs -P $NUM_PROCESSES ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG --wksp-page-sz 1073741824

zstd -df dump/test-vectors/elf_loader/fixtures/*.zst
LOG=$LOG_PATH/test_elf_loader
find dump/test-vectors/elf_loader/fixtures/* -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG --wksp-page-sz 1073741824

LOG=$LOG_PATH/test_exec_instr
find dump/test-vectors/instr/fixtures/* -type f -name '*.fix' | xargs -P $NUM_PROCESSES -n 1000 ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG --wksp-page-sz 1073741824

echo Test vectors success
