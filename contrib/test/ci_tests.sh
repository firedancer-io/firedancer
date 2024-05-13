#!/bin/bash

# ci_tests.sh builds and runs the tests that are required on every CI
# commit.  May optionally export coverage data.
#
# WARNING: Running this script will destroy your build directory.

set -eo pipefail
cd "$(dirname "$0")/../.."

if [[ -z "$MACHINES" ]]; then
  echo "\$MACHINES not set" >&2
  exit 1
fi

for extra in $EXTRAS; do
  if [[ $extra == "llvm-cov" ]]; then
    HAS_LLVM_COV=1
  fi
done
export EXTRAS

set -x

# Build and run tests for all machines
OBJDIRS=( )
for MACHINE in ${MACHINES[*]}; do
  export MACHINE
  OBJDIR="$(make help | grep OBJDIR | awk '{print $4}')"
  OBJDIRS+=( "${OBJDIR}" )
  make clean --silent >/dev/null
  contrib/make-j all integration-test
  if [[ "$NOTEST" != 1 ]]; then
    make run-unit-test
    if [[ "$EXTRAS" != *"ubsan"* && "$EXTRAS" != *"asan"* ]]; then
      make run-integration-test
    fi
    make run-fuzz-test
    make run-script-test
    make run-test-vectors
    if [[ "$HAS_LLVM_COV" == 1 ]]; then
      make "${OBJDIR}/cov/cov.lcov"
    fi
  fi
  for ledger in $EXTRA_RUN_TARGETS; do
    make $ledger
  done
  export -n MACHINE
done

# Export coverage report
if [[ "$COV_REPORT" == 1 ]]; then
  make dist-cov-report OBJDIRS="${OBJDIRS[*]}"
  contrib/test/find_uncovered_fuzz_canaries.py build/cov/cov.lcov || true
fi
