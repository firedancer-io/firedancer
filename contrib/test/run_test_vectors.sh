#!/bin/bash

set -ex

DIR="$( dirname -- "${BASH_SOURCE[0]}"; )";   # Get the directory name
DIR="$( realpath -e -- "$DIR"; )";    # Resolve its full path if need be
cd $DIR/../..

OBJDIR=${OBJDIR:-build/native/gcc}

if [ "$LOG_PATH" == "" ]; then
  LOG_PATH="`mktemp -d`"
else
  rm    -rf $LOG_PATH
  mkdir -pv $LOG_PATH
fi

mkdir -p dump

GIT_REF=${GIT_REF:-$(cat contrib/test/test-vectors-fixtures/test-vectors-commit-sha.txt)}

echo $GIT_REF

if [ ! -d dump/test-vectors ]; then
  pushd dump
  git clone --depth=1 -q https://github.com/firedancer-io/test-vectors.git
  cd test-vectors
  git fetch --depth=1 -q origin $GIT_REF
  git checkout -q $GIT_REF
  popd
else
  pushd dump/test-vectors
  git fetch --depth=1 -q origin $GIT_REF
  git checkout -q $GIT_REF
  popd
fi

LOG=$LOG_PATH/test_exec_syscall
cat contrib/test/test-vectors-fixtures/syscall-fixtures/*.list | xargs -P 4 -n 1000 ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG

LOG=$LOG_PATH/test_exec_interp
cat contrib/test/test-vectors-fixtures/vm_interp-fixtures.list | xargs -P 4 -n 1000 ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG

LOG=$LOG_PATH/test_exec_precompiles
cat contrib/test/test-vectors-fixtures/precompile-fixtures/*.list | xargs -P 4 -n 1000 ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG

LOG=$LOG_PATH/test_exec_txn
cat contrib/test/test-vectors-fixtures/txn-fixtures/*.list | xargs -P 4 ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG

zstd -df dump/test-vectors/elf_loader/fixtures/*.zst
LOG=$LOG_PATH/test_elf_loader
cat contrib/test/test-vectors-fixtures/elf-loader-fixtures.list | xargs -P 4 -n 1000 ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG

LOG=$LOG_PATH/test_exec_instr
cat contrib/test/test-vectors-fixtures/instr-fixtures/*.list | xargs -P 4 -n 1000 ./$OBJDIR/unit-test/test_exec_instr --log-path $LOG

LOG=$LOG_PATH/test_vm_validate
xargs -P 4 -n 1000 -a contrib/test/test-vectors-fixtures/vm_validate-fixtures.list ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG

echo Test vectors success
