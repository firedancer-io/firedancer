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
  elif [[ $extra == "fuzz" ]]; then
    HAS_FUZZ=1
  fi
done
export EXTRAS

set -x

# Build and run tests for all machines
OBJDIRS=( )
for MACHINE in "${MACHINES[*]}"; do
  # TODO hacky
  OBJDIR="build/$(echo "$MACHINE" | tr "_" "/")"
  OBJDIRS+=( "${OBJDIR}" )

  export MACHINE
  make clean --silent >/dev/null
  contrib/make-j
  if [[ "$NOTEST" != 1 ]]; then
    make run-unit-test
    if [[ "$HAS_FUZZ" == 1 ]]; then
      make run-fuzz-test
    fi
    make run-script-test
    if [[ "$HAS_LLVM_COV" == 1 ]]; then
      make "${OBJDIR}/cov/cov.profdata"
    fi
  fi
  export -n EXTRAS
done

# Export coverage report
if [[ "$COV_REPORT" == 1 ]]; then
  make dist-cov-report OBJDIRS="${OBJDIRS[*]}"
  contrib/test/find_uncovered_fuzz_canaries.py buld/cov/cov.lcov
fi
