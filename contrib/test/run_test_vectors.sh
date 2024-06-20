#!/bin/bash


set -x

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
if [ $? -ne 0 ]; then
  tail -n 100 $LOG_PATH/test_exec_instr
  exit 1
fi;
zstd -df dump/test-vectors/elf_loader/fixtures/*.zst
find dump/test-vectors/elf_loader/fixtures -type f -name '*.fix' -exec ./$OBJDIR/unit-test/test_elf_loader --log-path $LOG_PATH/test_elf_loader --log-level-stderr 4 {} + 
if [ $? -ne 0 ]; then
  tail -n 100 $LOG_PATH/test_elf_loader
  exit 1
fi;

num_exec_instr_tests=`find dump/test-vectors/instr/fixtures -type f -name '*.fix' | wc -l`
num_elf_tests=`find dump/test-vectors/elf_loader/fixtures -type f -name '*.fix' | wc -l`
total_tests=$((num_exec_instr_tests + num_elf_tests))

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
