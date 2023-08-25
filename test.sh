#!/usr/bin/env bash

# test.sh indirects test execution through Make.
# This ensures that we select the correct build dir for the current
# environment ($CC, $MACHINE, etc).
# Make then executes config/test.sh.

exec make run-unit-test TEST_OPTS="$*"

SHMEM_PATH="${FD_SHMEM_PATH:-/mnt/.fd}"
