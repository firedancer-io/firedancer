#!/bin/bash

# WARNING: These tests will destroy your system configuration.

export OBJDIR
export LLVM_PROFILE_FILE

set -xeuo pipefail

cd "$(dirname "$0")/../.."
src/app/fddev/tests/test_single_transfer.sh
# This test appears to be broken
#src/app/fddev/tests/test_single_txn.sh
