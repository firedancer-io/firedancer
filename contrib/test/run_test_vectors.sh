#!/bin/bash

#set -x

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

# find dump/test-vectors/instr/fixtures -type f -name '*.fix' -exec ./$OBJDIR/unit-test/test_exec_instr --log-path $LOG_PATH/test_exec_instr --log-level-stderr 4 {} +
./$OBJDIR/unit-test/test_exec_instr --log-path $LOG_PATH/test_exec_instr --log-level-stderr 4 `cat contrib/test/test-vectors.list`

zstd -df dump/test-vectors/elf_loader/fixtures/*.zst
# find dump/test-vectors/elf_loader/fixtures -type f -name '*.fix' -exec ./$OBJDIR/unit-test/test_elf_loader --log-path $LOG_PATH/test_elf_loader --log-level-stderr 4 {} +
./$OBJDIR/unit-test/test_elf_loader --log-path $LOG_PATH/test_elf_loader --log-level-stderr 4 `cat contrib/test/elf-vectors.list`

num_exec_instr_tests_raw=`find dump/test-vectors/instr/fixtures -type f -name '*.fix' | wc -l`
num_elf_tests_raw=`find dump/test-vectors/elf_loader/fixtures -type f -name '*.fix' | wc -l`
num_exec_instr_tests="`cat contrib/test/test-vectors.list | wc -l`"
num_elf_tests="`cat contrib/test/elf-vectors.list | wc -l`"
total_tests=$((num_exec_instr_tests + num_elf_tests))
total_tests_missing=$((num_exec_instr_tests_raw + num_elf_tests_raw - total_tests))

failed=`grep -wR FAIL $LOG_PATH | wc -l`
passed=`grep -wR OK $LOG_PATH | wc -l`

echo "Total test cases: $total_tests"
echo "Total test cases not run: $total_tests_missing"
echo "Total passed: $passed"
echo "Total failed: $failed"

if [ "$failed" != "0" ] || [ $passed -ne $total_tests ];
then
  echo 'test vector execution failed'
  grep -wR FAIL $LOG_PATH
  echo $LOG_PATH
  exit 1
else
  echo 'test vector execution passed'
  exit 0
fi
