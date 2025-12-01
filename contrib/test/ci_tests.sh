#!/bin/bash

# ci_tests.sh builds and runs the tests that are required on every CI
# commit.  May optionally export coverage data.
# NOTE: Use EXTRAS=fuzz-stubs to build stubbed binaries for fuzz tests.
#
# WARNING: Running this script will destroy your build directory.

set -eo pipefail
cd "$(dirname "$0")/../.."

if [[ -z "$MACHINES" ]]; then
  echo "\$MACHINES not set" >&2
  exit 1
fi

if [[ -z "$TARGETS" ]]; then
  TARGETS="all integration-test fdctl"
fi

for extra in $EXTRAS; do
  if [[ $extra == "llvm-cov" ]]; then
    HAS_LLVM_COV=1
  fi
done
export EXTRAS

export FD_LOG_LEVEL_STDERR=3

set -x

# Build and run tests for all machines
OBJDIRS=( )
for MACHINE in ${MACHINES[*]}; do
  export MACHINE
  OBJDIR="$(make help | grep OBJDIR | awk '{print $4}')"
  OBJDIRS+=( "${OBJDIR}" )
  make clean --silent >/dev/null
  contrib/make-j $TARGETS >/dev/null
  if [[ "$NOTEST" != 1 ]]; then
    make run-unit-test
    make run-fuzz-test
    make run-script-test
    # make run-test-vectors
    if [[ "$HAS_LLVM_COV" == 1 ]]; then
      make "${OBJDIR}/cov/cov.lcov"
    fi
  fi
  for ledger in $EXTRA_RUN_TARGETS; do
    make $ledger
  done
  export -n MACHINE
done

if [[ "$RACESAN" == 1 ]]; then
  rm -rf build/racesan
  MACHINE=native CC=clang EXTRAS="$EXTRAS racesan" BUILDDIR=racesan contrib/make-j unit-test >/dev/null
  mkdir -p build/racesan/cov/raw
  for test in $(find build/racesan/unit-test -type f -executable -name '*racesan*'); do
    LLVM_PROFILE_FILE="build/racesan/cov/raw/$(basename "$test").profraw"
    export LLVM_PROFILE_FILE
    "$test" --page-cnt 2 --page-sz gigantic --log-path '' >/dev/null
    unset LLVM_PROFILE_FILE
    if [[ "$HAS_LLVM_COV" == 1 ]]; then
      MACHINE=native CC=clang EXTRAS="$EXTRAS racesan" BUILDDIR=racesan make "build/racesan/cov/cov.lcov"
    fi
  done
  OBJDIRS+=( "build/racesan" )
fi

# Export coverage report
if [[ "$COV_REPORT" == 1 ]]; then
  make dist-cov-report OBJDIRS="${OBJDIRS[*]}"
  contrib/test/find_uncovered_fuzz_canaries.py build/cov/cov.lcov || true
fi
