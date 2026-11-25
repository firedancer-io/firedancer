#!/bin/bash
set -eou pipefail

# Replays a ledger with agave-ledger-tool, with yellowstone-grpc loaded
# as a geyser plugin, and captures what yellowstone served.  The
# captures are the oracle side of the comparison in
# contrib/dragon/README.md: contrib/dragon/capture.py writes them in
# the same normalized form as the captures of a dragon run, so
# contrib/dragon/diff.py compares the two directly.
#
# Environment:
#   LEDGER          the ledger directory (rocksdb + genesis + snapshot archive)
#   END_SLOT        --halt-at-slot
#   YELLOWSTONE_SO  libyellowstone_grpc_geyser.so built against this agave
#   LEDGER_TOOL     agave-ledger-tool built from the same agave tree
#   OUT             where the work tree, logs and captures go
#   ORACLE_PORT     the port the plugin listens on (10900)
#   KEEP_WORK       1 to keep the multi-gigabyte work tree

cd "$(dirname "${BASH_SOURCE[0]}")/../../.."

LEDGER=${LEDGER:?LEDGER is required}
END_SLOT=${END_SLOT:?END_SLOT is required}
YELLOWSTONE_SO=${YELLOWSTONE_SO:?YELLOWSTONE_SO is required}
LEDGER_TOOL=${LEDGER_TOOL:?LEDGER_TOOL is required}
OUT=${OUT:-$(mktemp -d /tmp/dragon-oracle-XXXXXX)}
ORACLE_PORT=${ORACLE_PORT:-10900}
KEEP_WORK=${KEEP_WORK:-0}

LEDGER=$(realpath "$LEDGER")
WORK="$OUT/work"
CAPTURE="$OUT/capture"
LOG="$OUT/ledger-tool.log"
mkdir -p "$OUT" "$CAPTURE"

cleanup() {
  pkill -f "capture.py --port $ORACLE_PORT" 2>/dev/null || true
  if [[ "$KEEP_WORK" != "1" ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT

# ------------------------------------------------------------- the work tree
#
# ledger-tool writes into its ledger directory whatever the command line
# says otherwise: with a read-only blockstore the bank snapshots and the
# accounts go to <ledger>/ledger_tool, and the transaction status
# service needs write access to the blockstore to record block time,
# block height and rewards.  Replaying a copy keeps all of that out of
# the ledger under test.  The rocksdb copy is a reflink on a filesystem
# that has them.

rm -rf "$WORK"
mkdir -p "$WORK" "$OUT/accounts" "$OUT/snapshots"
cp -r --reflink=auto "$LEDGER/rocksdb" "$WORK/rocksdb"
rm -f "$WORK/rocksdb/LOCK"
rm -rf "$WORK/rocksdb/solana-secondary"
for f in genesis.bin genesis.tar.bz2; do
  [[ -e "$LEDGER/$f" ]] && ln -sf "$LEDGER/$f" "$WORK/$f"
done

sed -e "s#@YELLOWSTONE_SO@#$YELLOWSTONE_SO#" \
    -e "s#@ORACLE_PORT@#$ORACLE_PORT#" \
    contrib/dragon/oracle/yellowstone.json.template > "$OUT/yellowstone.json"

# -------------------------------------------------------------- the replay
#
# --limit-load-slot-count-from-snapshot is set above the number of
# storages in any snapshot: it loads everything, and it is what turns
# the capitalization and accounts-lt-hash checks of
# snapshot_bank_utils.rs:226,268 into warnings.  A perf ledger carries a
# minimized snapshot, whose lt hash is the one of the full state it was
# minimized from, so those checks fail on a snapshot that is perfectly
# good for replaying its own slot range.
#
# --use-snapshot-archives-at-startup when-newest asks for a read-write
# blockstore (ledger_utils.rs:620-624).  The transaction status service
# writes block time, block height and rewards for every frozen bank
# whether or not --enable-rpc-transaction-history is given
# (transaction_status_service.rs:279-318), and dies on a read-only one.

"$LEDGER_TOOL" --ledger "$WORK" verify \
    --geyser-plugin-config "$OUT/yellowstone.json" \
    --halt-at-slot "$END_SLOT" \
    --limit-load-slot-count-from-snapshot 100000000 \
    --use-snapshot-archives-at-startup when-newest \
    --accounts "$OUT/accounts" \
    --snapshots "$OUT/snapshots" \
    --full-snapshot-archive-path "$LEDGER" \
    --incremental-snapshot-archive-path "$LEDGER" \
    > "$LOG" 2>&1 &
LT=$!

for i in $(seq 1 600); do
  (exec 3<>/dev/tcp/127.0.0.1/$ORACLE_PORT) 2>/dev/null && break
  kill -0 $LT 2>/dev/null || { echo "ledger-tool exited before the plugin came up"; tail -40 "$LOG"; exit 1; }
  sleep 0.1
done
echo "  plugin listening on $ORACLE_PORT after $(python3 -c "print($i/10.0)")s"

# The plugin binds its port in on_load, which is before the snapshot
# archive is opened, so the clients have the whole snapshot load to
# subscribe in.  How much of it they used is checked after the run.
PIDS=()
CAPTURES=()
capture() {
  # capture <name> <filter spec> <commitment>
  python3 contrib/dragon/capture.py --port "$ORACLE_PORT" \
      --filters "contrib/dragon/filters/$2" --commitment "$3" \
      --out "$CAPTURE/$1" --seconds 86400 --idle-timeout 120 --quiet \
      > "$CAPTURE/$1.log" 2>&1 &
  PIDS+=( $! )
  CAPTURES+=( "$1" )
}

capture slots      slots.json               processed
capture txn_p      transactions.json        processed
capture txns_p     transactions_status.json processed
capture acct_p     accounts.json            processed
capture acctf_p    accounts_full.json       processed
capture bm_p       blocks_meta.json         processed

wait $LT || echo "  ledger-tool exited non-zero"
echo "  replay done, waiting for the capture clients"
for pid in "${PIDS[@]}"; do wait "$pid" || true; done

# ------------------------------------------------------------- what it saw

echo "Subscriptions vs the first bank"
first_bank=$(grep -n -m1 'bank frozen: ' "$LOG" | cut -d: -f1)
subscribed=$(awk -v n="$first_bank" 'NR<n' "$LOG" | grep -c 'filter updated' || true)
echo "  $subscribed of ${#CAPTURES[@]} clients subscribed before the first bank froze"

echo "Captures"
for name in "${CAPTURES[@]}"; do
  meta="$CAPTURE/$name.meta.json"
  [[ -f "$meta" ]] || { echo "  $name: no metadata"; continue; }
  python3 -c "
import json
m = json.load(open('$meta'))
print('  %-9s %8d messages %9.1f MiB  %-30s gaps %d  %s'
      % ('$name', m['messages'], m['message_bytes']/1048576.0,
         m.get('stop_reason'), len(m['gaps']),
         json.dumps(m.get('counts', {}), sort_keys=True)))"
done

echo "Slots"
python3 -c "
import json, glob, sys
for path in sorted(glob.glob('$CAPTURE/*.jsonl')):
    slots = set()
    for line in open(path):
        slots.add(json.loads(line)['slot'])
    if slots:
        print('  %-40s %4d slots %d..%d' % (path.split('/')[-1], len(slots), min(slots), max(slots)))"

echo "  output in $OUT"
