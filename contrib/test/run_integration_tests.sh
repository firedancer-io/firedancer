#!/bin/bash

# WARNING: These tests will destroy your system configuration.

export OBJDIR
export LLVM_PROFILE_FILE

set -xeuo pipefail

cd "$(dirname "$0")/../.."

# TODO add fddev integration tests here

# Broken because genesis creation is unreliable
#src/app/fddev/tests/test_single_transfer.sh
# Broken because 'fddev txn' is unreliable
#src/app/fddev/tests/test_single_txn.sh
