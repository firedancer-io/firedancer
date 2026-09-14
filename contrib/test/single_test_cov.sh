#!/usr/bin/env bash

# This script quickly generates a coverage report for a single test.
# Requires Clang, LLVM, and Lcov.
#
# Usage:
#
#  make -j BUILDDIR=clang-cov CC=clang EXTRAS=llvm-cov all
#  ./contrib/test/single_test_cov.sh build/clang-cov/unit-test/test_xxx ... test-arguments ...

set -euo pipefail

if (( $# == 0 )); then
  echo "usage: $0 <test-binary> [test-arguments ...]" >&2
  exit 2
fi

BINARY="$1"

rm -f default.profraw default.profdata
test_status=0
LLVM_PROFILE_FILE=default.profraw "$@" || test_status=$?

print_error() {
  echo -e "\033[0;31mERR\033[0m $1"
}

if [[ ! -f "default.profraw" ]]; then
  print_error "No default.profraw file generated. Make sure binary is compiled with coverage instrumentation."
  print_error "Compile with: make -j BUILDDIR=clang-cov CC=clang EXTRAS=llvm-cov all"
  exit 1
fi

llvm-profdata merge -sparse default.profraw -o default.profdata
if [[ "${CLANKER:-0}" == "1" ]]; then exit "$test_status"; fi

llvm-cov export "$BINARY" -instr-profile=default.profdata -format=lcov > default.lcov

rm -rf report

mkdir -p ./report
genhtml default.lcov \
  --output-directory ./report \
  --title "Coverage Report" \
  --num-spaces 1 \
  --legend \
  --branch-coverage \
  --quiet

exit "$test_status"
