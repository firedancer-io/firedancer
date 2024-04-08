#!/bin/bash -f

# this assumes the test_runtime has already been built

OBJDIR=${OBJDIR:-build/native/gcc}

# Running this twice, but whatever
"$OBJDIR"/unit-test/test_native_programs >& native.log

status=$?

if [ $status -ne 0 ]
then
  echo 'native test failed'
  grep "not_ignored" native.log | tail -20
  exit $status
fi

grep "Progress" native.log

echo 'native tests passed'
