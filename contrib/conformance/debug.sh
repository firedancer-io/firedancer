#!/bin/bash

set -ex

# Usage: ./debug.sh -t <agave/fd> -i <input_file>

OBJDIR=${OBJDIR:-build/native/gcc}

INPUT_FILE=""
TARGET="fd"

while [[ $# -gt 0 ]]; do
  case $1 in
    -i|--input)
       INPUT_FILE="-i $2"
       shift
       shift
       ;;
    -t|--target)
       TARGET="$2"
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

TARGET_SHARED_OBJ_FILE=""
case $TARGET in
    agave)
        TARGET_SHARED_OBJ_FILE="-t dump/solfuzz-agave/target/debug/libsolfuzz_agave.so"
        DEBUGGER="rust-gdb"
        ;;
    fd)
        TARGET_SHARED_OBJ_FILE="-t $OBJDIR/lib/libfd_exec_sol_compat.so"
        DEBUGGER="gdb"
        ;;
    *)
        echo "unknown target $TARGET"
        exit 1
        ;;
esac

# Build / update solfuzz-agave and solana-conformance
REPO_ROOT=./dump SETUP_LITE=true ./contrib/ledger-tests/setup.sh

source dump/solana-conformance/test_suite_env/bin/activate
HARNESS_TYPE="TxnHarness" $DEBUGGER --args python3.11 -m test_suite.test_suite exec-instr $TARGET_SHARED_OBJ_FILE $INPUT_FILE
