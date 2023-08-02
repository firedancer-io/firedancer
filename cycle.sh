#!/bin/bash -f

set -x

rm -rf build
make clean >& /dev/null
make -j >& /dev/null
make run-runtime-test
