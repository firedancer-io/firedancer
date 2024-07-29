#!/bin/bash

set -ex

# Usage: ./run_tests.sh -i <input-dir> -p <num-processes>

OBJDIR=${OBJDIR:-build/native/gcc}

INPUT_DIR=""
NUM_PROCESSES=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -i|--input-dir)
       INPUT_DIR="-i $2"
       shift
       shift
       ;;
    -p|--num-processes)
       NUM_PROCESSES="-p $2"
       shift
       shift
       ;;
    -*|--*)
       echo "unknown option $1"
       exit 1
       ;;
    *)
       POSITION_ARGS+=("$1")
       shift
       ;;
  esac
done

# Build / update solfuzz-agave and solana-conformance
REPO_ROOT=./dump SETUP_LITE=true ./contrib/ledger-tests/setup.sh

source dump/solana-conformance/test_suite_env/bin/activate
HARNESS_TYPE="TxnHarness" solana-test-suite run-tests -s dump/solfuzz-agave/target/debug/libsolfuzz_agave.so -t $OBJDIR/lib/libfd_exec_sol_compat.so -f $INPUT_DIR $NUM_PROCESSES --consensus-mode --failures-only --save-failures
