#!/usr/bin/bash
# This script is used to dump the a SyscallContext during CPIs executed on a ledger.
# Run this from the root of the firedancer repository
# Must have a "dump/vm_cpi_state" directory in the root of the firedancer repository

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
set -e

# Apply the patch and build the project
git apply $SCRIPT_DIR/dump_cpi.patch
make -j  bin lib

# Run the replay command 
build/native/gcc/bin/fd_ledger --cmd replay --verify-acc-hash 1 --rocksdb dump/mainnet-265330432/rocksdb --index-max 5000000 --end-slot 265330433 --cluster-version 1190 --page-cnt 30 --funk-page-cnt 16 --snapshot dump/mainnet-265330432/snapshot-265330431-BMvcRhxNoRtkZ5KLEKhhXM6GiWdTgdkoGLMe86xY4rF.tar.zst --allocator wksp --tile-cpus 5-21

# Revert the patch and clean the project
git apply -R contrib/tool/dump_cpi.patch
make -j  clean

set +e