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

if [ ! -d dump/test-vectors ]; then
  cd dump
  git clone --depth=1 -q https://github.com/firedancer-io/test-vectors.git
  cd ..
else
  cd dump/test-vectors
  git pull -q
  cd ../..
fi

LOG=$LOG_PATH/test_exec_syscall
cat contrib/test/syscall-fixtures.list | xargs ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG

# LOG=$LOG_PATH/test_exec_precompiles
# cat contrib/test/precompile-fixtures.list | xargs ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG

zstd -df dump/test-vectors/elf_loader/fixtures/*.zst
LOG=$LOG_PATH/test_elf_loader
cat contrib/test/elf-loader-fixtures.list | xargs ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG

LOG=$LOG_PATH/test_exec_instr
cat contrib/test/instr-fixtures.list | xargs ./$OBJDIR/unit-test/test_exec_instr --log-path $LOG

LOG=$LOG_PATH/test_vm_validate
xargs -a contrib/test/vm_validate-fixtures.list ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG

echo Test vectors success
