#!/bin/bash
# Sweep the NIGHTLY backtest ledgers under deepasan+memguard firedancer-dev.
# These are large (90M-1.2B accounts; some replay 100k-600k slots), so the
# sweep is ordered lightest-first, uses a generous per-ledger timeout, and
# continues past failures.  Memory-corruption hits are archived + symbolized.
set -u

FC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$FC_ROOT"

BIN=build/clang-deepasan-memguard/bin/firedancer-dev
export OBJDIR=build/clang-deepasan-memguard
# Stricter ASAN: also catch stack-use-after-return, strict str* checks, and
# global init-order bugs.  Leak detection stays off (noisy against a
# validator's long-lived arenas).  symbolize=0 -> clean capture under tiles;
# we symbolize offline on a hit.
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1:symbolize=0:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1:strict_init_order=1:handle_abort=1
export MALLOC_CHECK_=0

RESULTS=${RESULTS:-/tmp/bt-nightly}
mkdir -p "$RESULTS/findings"
SUMMARY="$RESULTS/summary.tsv"
: > "$SUMMARY"
PER_LEDGER_TIMEOUT=${PER_LEDGER_TIMEOUT:-21600}   # 6h cap per ledger

# Nightly ledgers, ordered lightest -> heaviest (accounts x slots).
LEDGERS=(
  "-l testnet-389765300 -m 90000000 -e 389765400"                       # 90M acc, ~100 slots
  "-l testnet-387596256 -m 90000000 -e 387596373 --exec 64"             # 90M acc, ~117 slots
  "-l testnet-380636816 -m 200000000 -e 381116303 --exec 64"            # 200M acc, ~480k slots
  "-l devnet-433989075 -m 200000000 -e 434592005 --exec 64"             # 200M acc, ~603k slots
  "-l mainnet-400468865 -m 1200000000 -e 400468870"                     # 1.2B acc, ~5 slots
  "-l mainnet-391824000 -m 1100000000 -e 391824001"                     # 1.1B acc, 1 slot
  "-l mainnet-393520696 -m 1100000000 -e 393984000"                     # 1.1B acc, ~463k slots
)

for args in "${LEDGERS[@]}"; do
  name=$(echo "$args" | sed -n 's/.*-l \([^ ]*\).*/\1/p')
  log="$RESULTS/${name}.log"
  echo "=== $(date +%H:%M:%S) START $name ===" | tee -a "$SUMMARY"
  # Clean stale workspace files so a prior (possibly killed) run's leftovers
  # don't cause spurious ENOMEM at hugepage reservation.
  pgrep -f "firedancer-dev backtest" >/dev/null || rm -f /mnt/.fd/.huge/*.wksp /mnt/.fd/.gigantic/*.wksp 2>/dev/null
  start=$SECONDS
  timeout "$PER_LEDGER_TIMEOUT" src/flamenco/runtime/tests/run_ledger_backtest.sh $args -nr > "$log" 2>&1
  rc=$?
  dur=$((SECONDS-start))

  if grep -qiE "ERROR: AddressSanitizer|MEMGUARD:" "$log"; then
    verdict="SANITIZER_HIT"
    cp "$log" "$RESULTS/findings/${name}.log"
    # Offline-symbolize any module+offset frames.
    grep -aoE "\\+0x[0-9a-f]+\\)" "$log" | tr -d '+)' | sort -u | \
      xargs -r llvm-symbolizer --obj="$BIN" 2>/dev/null > "$RESULTS/findings/${name}.symbolized.txt" || true
  elif grep -qE "SIGSEGV|SIGABRT|SIGBUS" "$log"; then
    verdict="CRASH"; cp "$log" "$RESULTS/findings/${name}.log"
  elif [ "$rc" -eq 124 ]; then
    verdict="TIMEOUT_${PER_LEDGER_TIMEOUT}s"
  elif [ "$rc" -eq 0 ] && grep -q "Finished backtest" "$log"; then
    verdict="PASS"
  elif grep -qiE "ENOMEM|Out of memory|reserve .* pages" "$log"; then
    verdict="ENV_ENOMEM_rc${rc}"   # too big for this machine under ASAN, not a bug
  else
    verdict="FAIL_rc${rc}"
  fi
  printf "%s\t%s\t%ss\trc=%s\n" "$verdict" "$name" "$dur" "$rc" | tee -a "$SUMMARY"
done

echo "=== NIGHTLY SWEEP DONE ===" | tee -a "$SUMMARY"
