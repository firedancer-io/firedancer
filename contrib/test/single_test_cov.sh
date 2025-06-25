#!/usr/bin/env bash

# This script quickly generates a coverage report for a single test.
# Requires Clang, LLVM, and Lcov.
#
# Usage:
#
#  make -j BUILDDIR=clang-cov CC=clang EXTRAS=llvm-cov
#  ./contrib/test/single_test_cov.sh build/clang-cov/unit-test/test_xxx ... test-arguments ...

BINARY="$1"
COMMAND="$@"

rm -f default.profraw
LLVM_PROFILE_FILE=default.profraw eval "$COMMAND"

print_error() {
  echo -e "\033[0;31mERR\033[0m $1"
}

if [[ ! -f "default.profraw" ]]; then
  print_error "No default.profraw file generated. Make sure binary is compiled with coverage instrumentation."
  print_error "Compile with: make -j BUILDDIR=clang-cov CC=clang EXTRAS=llvm-cov"
  exit 1
fi

set -e

llvm-profdata merge -sparse default.profraw -o default.profdata

llvm-cov export "$BINARY" -instr-profile=default.profdata -format=lcov > default.lcov

rm -rf report

mkdir -p ./report
genhtml default.lcov \
  --output-directory ./report \
  --title "Coverage Report" \
  --num-spaces 1 \
  --legend \
  --highlight \
  --branch-coverage
