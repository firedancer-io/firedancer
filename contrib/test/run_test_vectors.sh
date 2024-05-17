#!/bin/bash -f

# this assumes fd_ledger has already been built

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

find dump/test-vectors/instr/fixtures -type f -name '*.fix' -exec ./$OBJDIR/unit-test/test_exec_instr {} + > $LOG_PATH/test_vectors_exec 2>&1
failed=`grep -w FAIL $LOG_PATH/test_vectors_exec | wc -l`
echo "Total failed: $failed"

if [ "$failed" != "0" ]
then
  echo 'test vector execution failed'
  grep -w FAIL $LOG_PATH/test_vectors_exec
  echo $LOG_PATH
  exit 1
else
  echo 'test vector execution passed'
  exit 0
fi
