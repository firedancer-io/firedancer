#!/usr/bin/env bash
# run_integration_tests.sh is like run_unit_tests.sh except that tests
# are not run concurrently, only one integration test will currently run
# at a time.
#
# WARNING: These tests might change your system configuration.

set -eou pipefail

# Defaults

TESTS=
VERBOSE=0

if [[ -z "$TESTS" && -z "${RECURSE_GUARD:-}" ]]; then
  # No tests given, so indirect test execution through Make and retry.
  # This ensures that we select the correct build dir for the current
  # environment ($CC, $MACHINE, etc).
  # Make then re-executes this file with the proper parameters.

  export RECURSE_GUARD=1
  exec make run-integration-test TEST_OPTS="$*"
fi

# Ensure we schedule at most one job at a time
AVAILABLE_JOBS=1

# Clean up process tree on exit
trap 'exit' INT QUIT TERM

runner () {
  local pid="$BASHPID"
  local prog="$1"
  local log="$2"
  local logfull="${log%.log}-full.log"
  shift 2

  # Create coverage dir, in case it's used
  local covdir; covdir="$(dirname "$prog")/../cov/raw"
  mkdir -p "$covdir"
  # Set up coverage file (no-op for non-instrumented binary)
  local LLVM_PROFILE_FILE
  LLVM_PROFILE_FILE="$covdir/$(basename "$prog").profraw"

  set +e
  local elapsed
  elapsed="$({                 \
    time                       \
    LLVM_PROFILE_FILE="$LLVM_PROFILE_FILE" \
    "sudo"                     \
      "$prog"                  \
      "$@"                     \
      --log-path "$logfull"    \
      --log-level-stderr 3     \
      >/dev/null               \
      2>"$log"                 \
    ; } \
    2>&1 >/dev/null \
    | grep real \
    | awk '{print $2}'
  )"
  local ret="$?"

  local rcpath; rcpath="$(rc_path "$pid")"
  {
    echo "$ret"
    echo "$elapsed"
  } > "$rcpath"
}

dispatch () {
  local prog="$1"
  local progname="${prog##*/}"
  shift 1

  if [[ ! -f "$prog" ]]; then
    return 0
  fi

  # Create log dir
  local logdir
  logdir="$(dirname "$(dirname "$prog")")/log/$progname"
  mkdir -p "$logdir"
  local log; log="$logdir/$(date -u +%Y%m%d-%H%M%S).log"

  if [[ "$VERBOSE" == 1 ]]; then
    echo "test.sh: NUMA $numa_idx: $progname" >&2
  fi

  # Dispatch
  runner "$prog" "$log" "$@"
}

dispatch "$OBJDIR"/unit-test/test_fddev
dispatch "$OBJDIR"/unit-test/test_firedancer_dev --testnet
