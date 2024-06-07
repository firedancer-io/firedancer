#!/bin/bash -f

# this assumes fd_ledger has already been built

set -xe

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

find dump/test-vectors/instr/fixtures -type f -name '*.fix' -exec ./$OBJDIR/unit-test/test_exec_instr --log-path $LOG_PATH/test_exec_instr --log-level-stderr 4 {} + 
find dump/test-vectors/elf_loader/fixtures -type f -name '*.fix' -exec ./$OBJDIR/unit-test/test_elf_loader --log-path $LOG_PATH/test_elf_loader --log-level-stderr 4 {} + 

total_tests=`find dump/test-vectors/instr/fixtures -type f -name '*.fix' | wc -l`
failed=`grep -wR FAIL $LOG_PATH | wc -l`
passed=`grep -wR OK $LOG_PATH | wc -l`

echo "Total test cases: $total_tests"
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

TESTS=dump/test-vectors/syscall/fixtures
LOG=$LOG_PATH/test_exec_syscalls
find $TESTS -type f -name '*.fix' -exec ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG {} +
if [ "$?" != "0" ]
then
  echo "Test vector execution failed: $LOG"
  exit 1
fi

TESTS=dump/test-vectors/precompile/fixtures
LOG=$LOG_PATH/test_exec_precompiles
find $TESTS -type f -name '*.fix' -exec ./$OBJDIR/unit-test/test_exec_sol_compat --log-path $LOG {} +
if [ "$?" != "0" ]
then
  echo "Test vector execution failed: $LOG"
  exit 1
fi
