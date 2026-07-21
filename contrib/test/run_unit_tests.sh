#!/usr/bin/env bash
# run_unit_tests.sh is a poor man's NUMA-aware greedy test scheduler.

set -euo pipefail

# Defaults

JOBS=0
NUMA_IDX=0
PAGE_SZ=gigantic
JOB_MEM=$((1*(1<<30)))  # 1GiB default per-test workspace
PAGE_CNT=
TESTS=
VERBOSE=0

# Most unit tests fit in a single 1 GiB gigantic page.  The scheduler
# therefore reserves one page per running job by default so that it can
# fill every available CPU.  The handful of tests below allocate a
# larger anonymous workspace; they are passed their own --page-cnt and
# the scheduler accounts for those extra gigantic pages so the in-flight
# set never over-subscribes the hugetlbfs reservation (an over-subscribed
# test hard-fails when fd_wksp_new_anonymous cannot acquire its pages).
#
# Tests are always run with --page-sz gigantic, so the count here is the
# number of 1 GiB pages needed to hold each test's default workspace
# footprint (ceil(default_page_cnt * default_page_sz / 1 GiB)).
# Keep this list in sync with the sources;
# contrib/test/gen_unit_test_pages.sh regenerates it.
declare -A TEST_GIGANTIC_PAGES=(
  [test_vinyl_req]=8
  [test_vat_refresh_vote_accounts]=6
  [test_vm_syscalls]=5
  [test_vm_syscall_hash]=5
  [test_vm_syscall_curve]=5
  [test_vm_interp]=5
  [test_bpf_loader_program]=5
  [test_tower_tile]=4
  [test_log_collector]=4
  [test_ssmanifest_parser]=2
  [test_replay_tile]=2
  [test_repair_tile]=2
  [test_quic_streams]=2
  [test_quic_server]=2
  [test_quic_retx]=2
  [test_quic_pkt_meta_lifecycle]=2
  [test_quic_keep_alive]=2
  [test_quic_hs]=2
  [test_quic_conn]=2
  [test_quic_conformance]=2
  [test_quic_concurrency]=2
  [test_quic_bw]=2
  [test_progcache]=2
  [test_groove_volume]=2
)

# Read command-line args

while [[ $# -gt 0 ]]; do

  FLAG="$1"
  shift 1

  case "$FLAG" in
    "--tests")
      TESTS="$1"
      shift 1
      ;;
    "-j")
      if [[ $# -ge 1 ]] && [[ "$1" =~ ^[0-9]+$ ]]; then
        JOBS="$1"
        shift 1
      else
        JOBS=0
      fi
      ;;
    "--numa-idx")
      NUMA_IDX="$1"
      shift 1
      ;;
    "--page-sz")
      PAGE_SZ="$1"
      shift 1
      ;;
    "--page-cnt")
      PAGE_CNT="$1"
      shift 1
      ;;
    "--job-mem")
      JOB_MEM="$1"
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
  exec make run-unit-test TEST_OPTS="$*"
fi

# Parse command-line args

# Usage: parse_list arr '0-3,5'
# Sets:    arr=( 0 1 2 3 5 )
parse_list () {
  local -n out=$1
  local frags
  declare -a frags
  IFS=',' read -ra frags <<< "$2"
  for frag in "${frags[@]}"; do
    if [[ "$frag" =~ ^[0-9]+$ ]]; then
      out+=( "$frag" )
    elif [[ "$frag" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      local start="${BASH_REMATCH[1]}"
      local end="${BASH_REMATCH[2]}"
      for (( i = start; i <= end; i++ )); do
        out+=( "$i" )
      done
    else
      echo "Invalid list range: $frag" >&2
      exit 1
    fi
  done
}

# NUMAS holds the list of NUMA nodes to use
parse_list NUMAS "$NUMA_IDX"

# Derive PAGE_CNT
if [[ -z "$PAGE_CNT" ]]; then
  case "$PAGE_SZ" in
    normal)   PAGE_CNT=$(( (JOB_MEM+     0xfff)/    0x1000 )) ;;
    huge)     PAGE_CNT=$(( (JOB_MEM+  0x1fffff)/  0x200000 )) ;;
    gigantic) PAGE_CNT=$(( (JOB_MEM+0x3fffffff)/0x40000000 )) ;;
    *)
      echo "Unknown page size: $PAGE_SZ" >&2
      exit 1
      ;;
  esac
fi

# Count and map available CPUs per NUMA
declare -a NUMA_CPUS
for numa in "${NUMAS[@]}"; do
  cpulist="$(cat /sys/devices/system/node/node"$numa"/cpulist)"
  declare -a "NUMA_CPUMAP_$numa"
  declare -n cpus="NUMA_CPUMAP_$numa"
  parse_list cpus "$cpulist"
  NUMA_CPUS[$numa]="${#cpus[@]}"
done

# Set CPU-slot parallelism per NUMA node.  A job occupies one CPU, so
# the number of concurrent jobs on a node is bounded by its CPU count.
# Memory is a separate budget (NUMA_PAGES below): the scheduler only
# dispatches a test onto a free CPU if that node still has enough free
# gigantic pages for the test's workspace.  This decouples concurrency
# from per-test memory so the common case (most tests need 1 page) fills
# every CPU, while the few large tests are admitted as pages allow.
declare -a NUMA_SLOTS
if [[ "$JOBS" == 0 ]]; then
  # Running with max job count.  Use all CPUs available for NUMAs.
  for numa in "${NUMAS[@]}"; do
    NUMA_SLOTS[$numa]="${NUMA_CPUS[$numa]}"
  done
else
  # Otherwise, distribute CPU slots evenly across NUMAs.
  # Note: This is not a very good scheduler
  for numa in "${NUMAS[@]}"; do
    NUMA_SLOTS[$numa]="$(( JOBS / ${#NUMAS[@]} ))"
  done
  # Distribute remainder
  for (( i = 0; i < JOBS % ${#NUMAS[@]}; i++ )); do
    NUMA_SLOTS[$i]="$(( NUMA_SLOTS[i] + 1 ))"
  done
fi

# Determine the per-NUMA gigantic page budget for admission control.
# Note: This is far from ideal and racy when multiple jobs share the
#       same runner.
echo "test.sh: $PAGE_CNT $PAGE_SZ pages per job (default)" >&2
declare -a NUMA_PAGES
MAX_TEST_PAGES=1
for pages in "${TEST_GIGANTIC_PAGES[@]}"; do
  if [[ "$pages" -gt "$MAX_TEST_PAGES" ]]; then MAX_TEST_PAGES="$pages"; fi
done
for numa in "${NUMAS[@]}"; do
  case "$PAGE_SZ" in
    gigantic)
      free_pages=$(cat /sys/devices/system/node/node"$numa"/hugepages/hugepages-1048576kB/free_hugepages)
      ;;
    huge)
      free_pages=$(cat /sys/devices/system/node/node"$numa"/hugepages/hugepages-2048kB/free_hugepages)
      ;;
    normal)
      free_pages=$(grep MemFree /sys/devices/system/node/node"$numa"/meminfo | awk '{print $4}')
      free_pages=$(( free_pages / 4 ))
      ;;
  esac
  NUMA_PAGES[$numa]="$free_pages"
  # The largest single test must fit, or it can never be scheduled.
  if [[ "$free_pages" -lt "$MAX_TEST_PAGES" ]]; then
    echo "test.sh: $free_pages free $PAGE_SZ pages on NUMA $numa, but the largest test needs $MAX_TEST_PAGES" >&2
    echo "test.sh: Not enough memory!" >&2
    exit 1
  fi
  echo "test.sh: NUMA $numa: ${NUMA_SLOTS[$numa]} CPU slots, $free_pages free $PAGE_SZ pages" >&2
done

# Ensure we have at least one CPU slot.
JOBS=0
for numa in "${NUMAS[@]}"; do
  JOBS=$(( JOBS + NUMA_SLOTS[numa] ))
done
if [[ "$JOBS" -eq 0 ]]; then
  echo "test.sh: No CPUs available!" >&2
  exit 1
fi

# Clean up process tree on exit
trap 'exit' INT QUIT TERM

# Track list of PIDs of child processes
declare -A PIDS

# Remember to which NUMA each PID was scheduled to
declare -A PID2NUMA
# Remember which CPU each PID was scheduled to
declare -A PID2CPU
declare -A CPU2PID
# Remember unit name of each PID
declare -A PID2UNIT
# Remember logfile name of each PID
declare -A PID2LOG
# Remember how many gigantic pages each PID reserved
declare -A PID2PAGES

# NUMA_SLOTS holds the number of free CPU slots per node and NUMA_PAGES
# the number of free gigantic pages per node.  When a job spawns, the
# node's slot count is decremented by one and its page count by the
# test's page need; both are restored when the job is reaped.

# test_pages <progname>
#   Echo the number of gigantic pages a test reserves (its --page-cnt).
test_pages () {
  echo "${TEST_GIGANTIC_PAGES[$1]:-$PAGE_CNT}"
}

# Read in list of automatic unit tests to schedule as jobs
declare -a TEST_LIST
while read -r line; do
  if [[ "$line" =~ ^[[:space:]]*# ]]; then
    continue
  fi
  TEST_LIST+=( "$line" )
done < <(grep -v '^#' "$TESTS")
echo "test.sh: Scheduling ${#TEST_LIST[@]} tests with $JOBS workers" >&2

rc_path () {
  echo "/tmp/.pid-$1.rc"
}

runner () {
  local pid="$BASHPID"
  local numa_idx="$1"
  local cpu_idx="$2"
  local prog="$3"
  local log="$4"
  local page_cnt="$5"
  local logfull="${log%.log}-full.log"
  shift 5

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
    taskset -c "$cpu_idx"      \
      "$prog"                  \
      "--numa-idx" "$numa_idx" \
      "--page-cnt" "$page_cnt" \
      "--page-sz" "$PAGE_SZ"   \
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

# dispatch numa_idx cpu_idx prog page_cnt cmdline...
#   Fork task
dispatch () {
  # Craft command line args
  local numa_idx="$1"
  local cpu="$2"
  local prog="$3"
  local page_cnt="$4"
  local progname="${prog##*/}"
  shift 4

  # Create log dir
  local logdir
  logdir="$(dirname "$(dirname "$prog")")/log/$progname"
  mkdir -p "$logdir"
  local log; log="$logdir/$(date -u +%Y%m%d-%H%M%S).log"

  if [[ "$VERBOSE" == 1 ]]; then
    echo "test.sh: NUMA $numa_idx: $progname ($page_cnt $PAGE_SZ pages)" >&2
  fi

  # Dispatch
  runner "$numa_idx" "$cpu" "$prog" "$log" "$page_cnt" "$@" &
  local pid="$!"

  # Remember PID
  PIDS["$pid"]=$pid
  PID2NUMA["$pid"]="$numa_idx"
  PID2CPU["$pid"]="$cpu"
  CPU2PID[$cpu]="$pid"
  PID2UNIT["$pid"]="$progname"
  PID2LOG["$pid"]="$log"
  PID2PAGES["$pid"]="$page_cnt"
}

# sow
#   schedule tasks onto free CPUs, subject to each node's free page
#   budget.  A test is skipped this pass if it does not currently fit in
#   the node's remaining pages; it is retried on a later pass once a
#   running job frees pages.  Tests are scheduled in list order, so a
#   large test that does not fit yet does not block smaller tests behind
#   it from filling the remaining CPUs.
sow () {
  if [[ "${#TEST_LIST[@]}" -eq 0 ]]; then return; fi
  for numa in "${NUMAS[@]}"; do
    if [[ "${NUMA_SLOTS[$numa]}" -eq 0 ]]; then continue; fi
    declare -n cpus="NUMA_CPUMAP_$numa"
    for cpu in "${cpus[@]}"; do
      if [[ "${NUMA_SLOTS[$numa]}" -eq 0 ]]; then break;    fi
      if [[ -n "${CPU2PID[$cpu]:-}"      ]]; then continue; fi
      if [[ "${#TEST_LIST[@]}"     -eq 0 ]]; then return  ; fi
      # Found a free CPU.  Find the first queued test that fits in this
      # node's remaining page budget.
      local idx=-1 i
      for i in "${!TEST_LIST[@]}"; do
        local need; need="$(test_pages "${TEST_LIST[$i]##*/}")"
        if [[ "$need" -le "${NUMA_PAGES[$numa]}" ]]; then idx="$i"; break; fi
      done
      # No queued test fits right now; wait for a job to free pages.
      if [[ "$idx" -eq -1 ]]; then break; fi
      local test="${TEST_LIST[$idx]}"
      local need; need="$(test_pages "${test##*/}")"
      TEST_LIST=( "${TEST_LIST[@]:0:$idx}" "${TEST_LIST[@]:$((idx+1))}" )
      NUMA_SLOTS[$numa]="$(( NUMA_SLOTS[numa] - 1 ))"
      NUMA_PAGES[$numa]="$(( NUMA_PAGES[numa] - need ))"
      dispatch "$numa" "$cpu" "$test" "$need"
    done
  done
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
      local numa="${PID2NUMA["$pid"]}"
      local cpu="${PID2CPU["$pid"]}"
      local unit="${PID2UNIT["$pid"]}"
      local log="${PID2LOG["$pid"]}"
      local pages="${PID2PAGES["$pid"]}"
      local logfull="${log%.log}-full.log"
      unset PIDS["$pid"]
      unset PID2NUMA["$pid"]
      unset PID2CPU["$pid"]
      unset CPU2PID["$cpu"]
      unset PID2UNIT["$pid"]
      unset PID2LOG["$pid"]
      unset PID2PAGES["$pid"]
      NUMA_SLOTS[$numa]="$(( NUMA_SLOTS[numa] + 1 ))"
      NUMA_PAGES[$numa]="$(( NUMA_PAGES[numa] + pages ))"
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
