#!/bin/bash
# Sweep backtest ledgers under the deepasan+memguard firedancer-dev build,
# hunting for memory-corruption / UAF in the real runtime replay path.
# Continues past failures; archives any sanitizer report for symbolization.
set -u

FC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$FC_ROOT"

export OBJDIR=build/clang-deepasan-memguard
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0:handle_abort=1:exitcode=99
export MALLOC_CHECK_=0

RESULTS=${RESULTS:-/tmp/bt-sweep}
mkdir -p "$RESULTS/findings"
SUMMARY="$RESULTS/summary.tsv"
: > "$SUMMARY"

# Ledger invocations, ordered small/edge-case first, big 16-tile last.
LEDGERS=(
  "-l genesis-v4.0.0 1 -m 3000 -e 1352 -g"
  "-l deployment-before-boundary-v4.1.0-beta.1 1 -m 1000 -e 75"
  "-l vote-states-v4-local-v4.1.0-beta.1 1 -m 3000 -e 1000"
  "-l progcache-stale-entry-v4.1.0-beta.1 1 -m 10000 -e 135"
  "-l commission_rate_in_basis_points_boundary-v4.1.0-beta.1 1 -m 10000 -e 950"
  "-l commission_rate_in_basis_points_snapshot-v4.1.0-beta.1 1 -m 10000 -e 950"
  "-l vote-stake-scenarios-v4.1.0-beta.1 1 -m 10000"
  "-l breakpoint-385786458-v4.1.0-beta.1 1 -m 2000000 -e 385786452"
  "-l mainnet-391824000-boundary-v4.1.0-beta.1 2 -m 2000000 -e 391824016"
  "-l testnet-384169347-v4.1.0-beta.1 1 -m 2000000 -e 384169377 --root-distance 32 --max-live-slots 64"
  "-l testnet-387596258-v4.1.0-beta.1 1 -m 2000000 -e 387596373"
  "-l devnet-370199634-v4.1.0-beta.1 3 -m 200000 -e 370199634"
  "-l mainnet-308392063-v4.1.0-beta.1 5 -m 2000000 -e 308392063"
  "-l devnet-350814254-v4.1.0-beta.1 3 -m 2000000 -e 350814284"
  "-l testnet-281546597-v4.1.0-beta.1 3 -m 2000000 -e 281546597"
  "-l mainnet-324823213-v4.1.0-beta.1 4 -m 2000000 -e 324823214"
  "-l mainnet-325467935-v4.1.0-beta.1 4 -m 2000000 -e 325467935"
  "-l testnet-283927487-v4.1.0-beta.1 3 -m 2000000 -e 283927497"
  "-l testnet-281688085-v4.1.0-beta.1 3 -m 2000000 -e 281688086"
  "-l testnet-321168308-v4.1.0-beta.1 3 -m 2000000 -e 321168308"
  "-l mainnet-327324660-v4.1.0-beta.1 4 -m 2000000 -e 327324660"
  "-l devnet-378683870-v4.1.0-beta.1 3 -m 2000000 -e 378683872"
  "-l mainnet-330219081-v4.1.0-beta.1 4 -m 2000000 -e 330219082"
  "-l devnet-372721907-v4.1.0-beta.1 3 -m 2000000 -e 372721910"
  "-l mainnet-331691646-v4.1.0-beta.1 4 -m 2000000 -e 331691647"
  "-l testnet-336218682-v4.1.0-beta.1 5 -m 2000000 -e 336218683"
  "-l testnet-340269866-v4.1.0-beta.1 5 -m 2000000 -e 340269872"
  "-l testnet-346556000-v4.1.0-beta.1 3 -m 2000000 -e 346556337"
  "-l devnet-380592002-v4.1.0-beta.1 3 -m 2000000 -e 380592006"
  "-l testnet-384395810-v4.1.0-beta.1 3 -m 2000000 -e 384395820"
  "-l mainnet-254462437-v4.1.0-beta.1 16 -m 10000000 -e 254462598"
)

for args in "${LEDGERS[@]}"; do
  name=$(echo "$args" | sed -n 's/.*-l \([^ ]*\).*/\1/p')
  log="$RESULTS/${name}.log"
  echo "=== $(date +%H:%M:%S) START $name ===" | tee -a "$SUMMARY"
  start=$SECONDS
  src/flamenco/runtime/tests/run_ledger_backtest.sh $args > "$log" 2>&1
  rc=$?
  dur=$((SECONDS-start))

  # Classify outcome.
  if grep -qiE "ERROR: AddressSanitizer|MEMGUARD:" "$log"; then
    verdict="SANITIZER_HIT"
    cp "$log" "$RESULTS/findings/${name}.log"
  elif grep -qE "SIGSEGV|SIGABRT|SIGBUS" "$log"; then
    verdict="CRASH"
    cp "$log" "$RESULTS/findings/${name}.log"
  elif [ "$rc" -eq 0 ] && grep -q "Finished backtest" "$log"; then
    verdict="PASS"
  else
    verdict="FAIL_rc${rc}"
  fi
  printf "%s\t%s\t%ss\trc=%s\n" "$verdict" "$name" "$dur" "$rc" | tee -a "$SUMMARY"
done

echo "=== SWEEP DONE ===" | tee -a "$SUMMARY"
