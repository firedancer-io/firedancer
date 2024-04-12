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

# Read command-line args

while [[ $# -gt 0 ]]; do

  FLAG="$1"
  shift 1

  case "$FLAG" in
    "--tests")
      TESTS="$1"
      shift 1
      ;;
    "-v")
      VERBOSE=1
      ;;
    *)
      echo "Unknown flag: $FLAG" >&2
      exit 1
      ;;
  esac

done

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

# Track list of PIDs of child processes
declare -A PIDS=()
# Remember unit name of each PID
declare -A PID2UNIT=()
# Remember logfile name of each PID
declare -A PID2LOG=()

# Read in list of automatic integration tests to schedule as jobs
declare -a TEST_LIST=()

if [[ -s "$TESTS" ]]; then
  while read -r line; do
    if [[ "$line" =~ ^[[:space:]]*# ]]; then
      continue
    fi
    TEST_LIST+=( "$line" )
  done < <(grep -v '^#' "$TESTS")
fi

echo "test.sh: Scheduling ${#TEST_LIST[@]} tests in sequence" >&2

rc_path () {
  echo "/tmp/.pid-$1.rc"
}

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

# dispatch numa_idx cpu_idx cmdline...
#   Fork task
dispatch () {
  # Craft command line args
  local prog="$1"
  local progname="${prog##*/}"
  shift 1

  # Create log dir
  local logdir
  logdir="$(dirname "$(dirname "$prog")")/log/$progname"
  mkdir -p "$logdir"
  local log; log="$logdir/$(date -u +%Y%m%d-%H%M%S).log"

  if [[ "$VERBOSE" == 1 ]]; then
    echo "test.sh: NUMA $numa_idx: $progname" >&2
  fi

  # Dispatch
  runner "$prog" "$log" "$@" &
  local pid="$!"

  # Remember PID
  PIDS["$pid"]=$pid
  PID2UNIT["$pid"]="$progname"
  PID2LOG["$pid"]="$log"
}

# sow
#   schedule tasks until max concurrency reached
sow () {
  if [[ "${#TEST_LIST[@]}" -eq 0 ]]; then return; fi
  if [[ "${AVAILABLE_JOBS}" -eq 0 ]]; then return; fi

  # Found a free CPU!
  local test="${TEST_LIST[0]}"
  TEST_LIST=( "${TEST_LIST[@]:1}" )
  AVAILABLE_JOBS="$(( AVAILABLE_JOBS - 1 ))"
  dispatch "$test"
}

FAIL_CNT=0

# reap
#   wait for a job to finish
reap () {
  wait -n "${PIDS[@]}"
  # Clean up finished jobs
  for pid in "${PIDS[@]}"; do
    if [[ ! -d "/proc/$pid" ]]; then
      # Job finished
      local rcfile; rcfile="$(rc_path "$pid")"
      local rc
      local elapsed
      {
        IFS= read -r rc
        IFS= read -r elapsed
      } < "$rcfile"
      local unit="${PID2UNIT["$pid"]}"
      local log="${PID2LOG["$pid"]}"
      local logfull="${log%.log}-full.log"
      unset PIDS["$pid"]
      unset PID2UNIT["$pid"]
      unset PID2LOG["$pid"]
      AVAILABLE_JOBS="$(( AVAILABLE_JOBS + 1 ))"
      if [[ "$rc" -ne 0 ]]; then
        FAIL_CNT="$(( FAIL_CNT + 1 ))"
        printf "\033[0;31mFAIL\033[0m%12s   %s (exit %d): %s\n" "$elapsed" "$unit" "$rc" "$logfull" >&2
        grep -sv "Log at" "$log" | sed -e "$(printf "s/^/%19s%-20s /" '' "$unit")" || true >&2
      else
        printf "\033[0;32mOK  \033[0m%12s   %s\n"               "$elapsed" "$unit" >&2
      fi
    fi
  done
}

while [[ "${#TEST_LIST[@]}" -gt 0 ]]; do
  sow
  reap
done
while [[ "${#PIDS[@]}" -gt 0 ]]; do
  reap
done

if [[ "$FAIL_CNT" -gt 0 ]]; then
  echo -e "\033[0;31mFAIL\033[0m ($FAIL_CNT failure)" >&2
  exit 1
else
  echo -e "\033[0;32mPASS\033[0m" >&2
  exit 0
fi

# TODO add fddev integration tests here

# Broken because genesis creation is unreliable
#src/app/fddev/tests/test_single_transfer.sh
# Broken because 'fddev txn' is unreliable
#src/app/fddev/tests/test_single_txn.sh
