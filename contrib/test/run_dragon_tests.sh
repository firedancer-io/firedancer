#!/bin/bash
set -eou pipefail

# Replays a ledger twice -- once without the dragon tile and once with
# it -- captures what the tile served, and checks the two runs against
# each other and the captures against themselves.
#
# A run fails if the backtest fails, if enabling dragon changes a bank
# hash, if a capture came back empty, or if contrib/dragon/selfcheck.py
# reports a failing check.
#
# Environment:
#   DUMP           where ledgers live (./dump)
#   OBJDIR         build directory (make objdir)
#   LEDGER         ledger directory name under $DUMP
#   END_SLOT       last slot to replay
#   OUT            where the captures and logs go (mktemp -d)
#   DRAGON_PORT    port the tile listens on (10801)
#   SKIP_BASELINE  1 to skip the run without dragon (then no hash check)
#   KEEP_ACCOUNTS  1 to leave the private accounts database behind
#   SUDO           what to run the validator with (sudo; "" for none)
#
# Oracle mode (contrib/dragon/README.md, plan section 8) adds a replay of
# the same ledger by agave-ledger-tool with yellowstone-grpc loaded, and
# diffs the two servers stream by stream:
#   ORACLE         1 to run it (off by default, so CI is unchanged)
#   YELLOWSTONE_SO libyellowstone_grpc_geyser.so built against this agave
#   LEDGER_TOOL    agave-ledger-tool built from the same agave tree
#   ORACLE_PORT    the port the plugin listens on (10900)
#   ORACLE_CAPTURE an existing oracle capture directory to diff against,
#                  instead of replaying the ledger again
#   ORACLE_STRICT  1 to fail the run on a difference the diff still reports
#   ORACLE_ACCOUNTS_FULL 1 to also subscribe to every account's whole data

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source contrib/test/ledger_common.sh

DUMP=${DUMP:="./dump"}
OBJDIR=${OBJDIR:-$(make --silent --no-print-directory objdir 2>/dev/null || true)}
: "${OBJDIR:?cannot determine OBJDIR (make objdir failed)}"
LEDGER=${LEDGER:-"mainnet-424669000-solcap-v4.2.0-beta.1-vat"}
END_SLOT=${END_SLOT:-424669025}
OUT=${OUT:-$(mktemp -d /tmp/dragon-test-XXXXXX)}
DRAGON_PORT=${DRAGON_PORT:-10801}
METRICS_PORT=${METRICS_PORT:-7999}
SKIP_BASELINE=${SKIP_BASELINE:-0}
KEEP_ACCOUNTS=${KEEP_ACCOUNTS:-0}
CAPTURE_SECONDS=${CAPTURE_SECONDS:-3600}
SUDO=${SUDO-sudo}
ORACLE=${ORACLE:-0}
ORACLE_PORT=${ORACLE_PORT:-10900}
ORACLE_CAPTURE=${ORACLE_CAPTURE:-}
REDOWNLOAD=1

while [[ $# -gt 0 ]]; do
  case $1 in
    -nr|--no-redownload) REDOWNLOAD=0; shift ;;
    *) echo "unknown option $1"; exit 1 ;;
  esac
done

mkdir -p "$OUT"
ACCOUNTS_DB="$OUT/accounts.db"
CAPTURE="$OUT/capture"
mkdir -p "$CAPTURE"

status=0
BACKTEST_LOG="$OUT/dragon.run.log"

on_err() {
  local ec=$?
  echo_error "run_dragon_tests.sh failed at line ${BASH_LINENO[0]} (exit ${ec}): ${BASH_COMMAND}"
  if [[ -f "$BACKTEST_LOG" ]]; then
    echo "----- last 60 lines of ${BACKTEST_LOG} -----" >&2
    tail -n 60 "$BACKTEST_LOG" >&2 || true
  fi
  exit "$ec"
}
trap on_err ERR

cleanup() {
  pkill -f "capture.py --port $DRAGON_PORT" 2>/dev/null || true
  if [[ "$KEEP_ACCOUNTS" != "1" ]]; then
    $SUDO rm -f "$ACCOUNTS_DB" || true
  fi
}
trap cleanup EXIT

# ------------------------------------------------------------- the ledger

download_and_extract_ledger() {
  echo "Downloading gs://firedancer-ci-resources/$LEDGER.tar.gz"
  gcloud storage cat gs://firedancer-ci-resources/$LEDGER.tar.gz \
    | tee $DUMP/$LEDGER.tar.gz | tar zxf - -C $DUMP
}

if [[ ! -e $DUMP/$LEDGER ]]; then
  if [[ "$REDOWNLOAD" != "1" ]]; then
    echo_error "no ledger at $DUMP/$LEDGER and --no-redownload given"
    exit 1
  fi
  download_and_extract_ledger
fi

# fd requires the snapshots path to not be group/world accessible
chmod -R 0700 $DUMP/$LEDGER

if [[ ! -e $DUMP/$LEDGER/shreds.pcapng.zst ]]; then
  make -B -C contrib/blockstore blockstore2shredcap
  echo "Running blockstore2shredcap ..."
  contrib/blockstore/blockstore2shredcap --rocksdb $DUMP/$LEDGER/rocksdb \
      --out $DUMP/$LEDGER/shreds.pcapng.zst --zstd
fi

LEDGER_DIR=$(realpath $DUMP/$LEDGER)

# ------------------------------------------------------------ the configs

write_config() {
  # write_config <path> <log path> <dragon section>
  cat > "$1" << EOF
telemetry = false
[snapshots]
    incremental_snapshots = false
    [snapshots.sources]
        servers = []
        [snapshots.sources.gossip]
            allow_any = false
            allow_list = []
[layout]
    execrp_tile_count = 6
[tiles]
    [tiles.gui]
        enabled = false
    [tiles.rpc]
        enabled = false
    [tiles.metric]
        prometheus_listen_port = ${METRICS_PORT}
$3
[accounts]
    max_accounts = 4000000
[runtime]
    max_live_slots = 32
    max_fork_width = 4
[log]
    level_stderr = "NOTICE"
    path = "$2"
[paths]
    snapshots = "${LEDGER_DIR}"
    accounts = "${ACCOUNTS_DB}"
    genesis = "${LEDGER_DIR}/genesis.bin"
[gossip]
    entrypoints = [ "0.0.0.0:1" ]
[development]
    [development.genesis]
        validate_genesis_hash = false
    [development.ledger_input]
        format = "pcap"
        path = "${LEDGER_DIR}/shreds.pcapng.zst"
        end_slot = ${END_SLOT}
    [development.backtest]
        root_distance = 2
EOF
}

# max_message_bytes is at least stream_queue_bytes, so that an update
# too large for a subscriber's queue is still delivered whole.
read -r -d '' DRAGON_SECTION << EOF || true
    [tiles.dragon]
        enabled = true
        listen_address = "127.0.0.1"
        listen_port = ${DRAGON_PORT}
        deferred_delivery = true
        accounts = true
        max_clients = 12
        max_streams_per_client = 2
        stream_queue_bytes = 16777216
        max_message_bytes = 16777216
        deferred_buffer_max_bytes = 268435456
EOF

write_config "$OUT/dragon_off.toml" "$OUT/dragon_off.fd.log" ""
write_config "$OUT/dragon_on.toml"  "$OUT/dragon_on.fd.log"  "$DRAGON_SECTION"

hashes_of() {
  grep -oE 'slot=[0-9]+, hash=[1-9A-HJ-NP-Za-km-z]+' "$1" | sort -u
}

# ------------------------------------------------------- the baseline run

if [[ "$SKIP_BASELINE" != "1" ]]; then
  echo_notice "Replaying $LEDGER to slot $END_SLOT without dragon ..."
  $SUDO rm -f "$ACCOUNTS_DB"
  $SUDO $OBJDIR/bin/firedancer-dev backtest --config "$OUT/dragon_off.toml" --no-watch \
       > "$OUT/baseline.run.log" 2>&1
  hashes_of "$OUT/baseline.run.log" > "$OUT/baseline.hashes.txt"
  echo "  $(wc -l < "$OUT/baseline.hashes.txt") bank hashes"
fi

# ----------------------------------------------------------- the dragon run

echo_notice "Replaying $LEDGER to slot $END_SLOT with dragon on port $DRAGON_PORT ..."
$SUDO rm -f "$ACCOUNTS_DB"
$SUDO $OBJDIR/bin/firedancer-dev backtest --config "$OUT/dragon_on.toml" --no-watch \
     > "$BACKTEST_LOG" 2>&1 &
BT=$!

for i in $(seq 1 1200); do
  grep -q 'dragon server listening' "$BACKTEST_LOG" 2>/dev/null && break
  kill -0 $BT 2>/dev/null || { echo_error "backtest exited before the server came up"; exit 1; }
  sleep 0.2
done
echo "  server up after $(( i / 5 ))s"

# One subscription per stream and level, each on its own connection, so
# that a slow one cannot hold up the others.  The clients stop when the
# backtest exits: the connection drops, the one reconnect they are
# allowed finds nothing listening, and they decode what they captured.
PIDS=()
CAPTURES=()

capture() {
  # capture <name> <filter spec> <commitment> [extra capture.py args]
  local name=$1 spec=$2 level=$3; shift 3
  python3 contrib/dragon/capture.py --port "$DRAGON_PORT" \
      --filters "contrib/dragon/filters/$spec" --commitment "$level" \
      --out "$CAPTURE/$name" --seconds "$CAPTURE_SECONDS" \
      --idle-timeout 120 --quiet "$@" > "$CAPTURE/$name.log" 2>&1 &
  PIDS+=( $! )
  CAPTURES+=( "$name" )
}

# capture.py decompresses with the zstandard module or the zstd
# binary, so the compressed wire path is only exercised where one of
# them exists.
ZSTD_ARGS=()
if python3 -c 'import zstandard' 2>/dev/null || command -v zstd >/dev/null 2>&1; then
  ZSTD_ARGS=( --zstd )
else
  echo "  no zstd decoder for python; capturing everything identity coded"
fi

capture slots    slots.json         processed
capture txn_p    transactions.json  processed
# the same stream over the compressed wire path, so that the
# self-consistency checks below also cover zstd round-tripping
capture txn_f    transactions.json  finalized "${ZSTD_ARGS[@]}"
capture acct_p   accounts.json      processed
capture acct_f   accounts.json      finalized
capture bm_p     blocks_meta.json   processed
capture bm_f     blocks_meta.json   finalized
capture blocks_f blocks.json        finalized

# What the oracle can produce a counterpart for.  Accounts with their
# whole data rather than the 32-byte slice of accounts.json are opt-in:
# a backtest replays several times faster than the cluster does, so a
# subscriber to every account's full data has to take tens of megabytes
# a second more than a live one would, and the tile closes it as lagged
# long before the replay ends unless stream_queue_bytes is raised to
# match (contrib/dragon/README.md).
if [[ "$ORACLE" == "1" ]]; then
  capture txns_p transactions_status.json processed
  [[ "${ORACLE_ACCOUNTS_FULL:-0}" == "1" ]] && capture acctf_p accounts_full.json processed
fi

# The counters are a scrape of a running tile, so the run keeps the
# last one that succeeded: slowly while the replay is going, then every
# 50 ms once it reports itself done, and on past the exit of the
# validator until the endpoint refuses -- fd_stem writes each tile's
# final metrics after its run loop returns
# (src/disco/stem/fd_stem.c:903-907), so the last state a tile
# publishes is only readable in the window between that write and the
# metric tile going away.
scrape_metrics() {
  curl -sf --max-time 4 "http://127.0.0.1:$METRICS_PORT/metrics" \
       --output "$OUT/metrics.new" 2>/dev/null || return 1
  [[ -s "$OUT/metrics.new" ]] || return 1
  mv "$OUT/metrics.new" "$OUT/metrics.txt"
}

( fast=0
  while kill -0 $BT 2>/dev/null; do
    scrape_metrics || true
    if [[ $fast -eq 0 ]] && grep -q "Backtest playback done" "$BACKTEST_LOG" 2>/dev/null; then
      fast=1
    fi
    if [[ $fast -eq 1 ]]; then sleep 0.05; else sleep 0.25; fi
  done
  for _ in $(seq 1 100); do
    scrape_metrics || break
    sleep 0.05
  done ) &
MET=$!

wait $BT || { echo_error "backtest exited non-zero"; status=1; }
kill $MET 2>/dev/null || true
echo "  replay done, waiting for the capture clients"
for pid in "${PIDS[@]}"; do
  wait "$pid" || true
done

hashes_of "$BACKTEST_LOG" > "$OUT/dragon.hashes.txt"

# ------------------------------------------------------------- the checks

echo_notice "Bank hashes"
echo "  dragon: $(wc -l < "$OUT/dragon.hashes.txt") hashes, md5 $(md5sum < "$OUT/dragon.hashes.txt" | cut -d' ' -f1)"
if [[ "$SKIP_BASELINE" != "1" ]]; then
  echo "  no dragon: $(wc -l < "$OUT/baseline.hashes.txt") hashes, md5 $(md5sum < "$OUT/baseline.hashes.txt" | cut -d' ' -f1)"
  if ! cmp -s "$OUT/baseline.hashes.txt" "$OUT/dragon.hashes.txt"; then
    echo_error "FAIL bank hashes differ with the dragon tile enabled"
    diff "$OUT/baseline.hashes.txt" "$OUT/dragon.hashes.txt" | head -20 || true
    status=1
  else
    echo "  identical"
  fi
fi

for log in "$BACKTEST_LOG" "$OUT/baseline.run.log"; do
  [[ -f "$log" ]] || continue
  if grep -q "Bank hash mismatch" "$log"; then
    echo_error "FAIL $log reports a bank hash mismatch"
    status=1
  fi
done

echo_notice "Captures"
for name in "${CAPTURES[@]}"; do
  meta="$CAPTURE/$name.meta.json"
  if [[ ! -f "$meta" ]]; then
    echo_error "FAIL capture $name produced no metadata"
    status=1
    continue
  fi
  line=$(python3 -c "
import json,sys
m=json.load(open('$meta'))
print('%-9s %8d messages %9.1f MiB  %-22s gaps %d  %s'
      % ('$name', m['messages'], m['message_bytes']/1048576.0,
         m.get('stop_reason'), len(m['gaps']),
         json.dumps(m.get('counts', {}), sort_keys=True)))
sys.exit(0 if m['messages'] else 1)") || { echo_error "FAIL capture $name is empty"; status=1; }
  echo "  $line"
done

# Every commit record whose account data did not fit names its slot in
# the log; those slots are the only ones where the finalized content of
# an account may differ from what processed carried.
TRUNCATED="$OUT/truncated.txt"
if [[ -r "$OUT/dragon_on.fd.log" ]]; then
  grep "dragon truncated record" "$OUT/dragon_on.fd.log" > "$TRUNCATED" || true
else
  $SUDO grep "dragon truncated record" "$OUT/dragon_on.fd.log" > "$TRUNCATED" || true
fi
echo "  $(wc -l < "$TRUNCATED") truncated record(s) in the log"

echo_notice "Self-consistency"
python3 contrib/dragon/selfcheck.py \
    --level processed=$CAPTURE/txn_p \
    --level processed=$CAPTURE/acct_p \
    --level processed=$CAPTURE/bm_p \
    --level finalized=$CAPTURE/txn_f \
    --level finalized=$CAPTURE/acct_f \
    --level finalized=$CAPTURE/bm_f \
    --level finalized=$CAPTURE/blocks_f \
    --slots $CAPTURE/slots \
    --truncated-log "$TRUNCATED" \
    --metrics "$OUT/metrics.txt" \
    --json "$OUT/selfcheck.json" || status=1

# ------------------------------------------------------------- the oracle

if [[ "$ORACLE" == "1" ]]; then
  ORACLE_DIR="$OUT/oracle"
  if [[ -z "$ORACLE_CAPTURE" ]]; then
    echo_notice "Oracle: yellowstone-grpc under agave-ledger-tool"
    YELLOWSTONE_SO=${YELLOWSTONE_SO:?ORACLE=1 needs YELLOWSTONE_SO}
    LEDGER_TOOL=${LEDGER_TOOL:?ORACLE=1 needs LEDGER_TOOL}
    LEDGER="$LEDGER_DIR" END_SLOT="$END_SLOT" OUT="$ORACLE_DIR" \
      ORACLE_PORT="$ORACLE_PORT" YELLOWSTONE_SO="$YELLOWSTONE_SO" \
      LEDGER_TOOL="$LEDGER_TOOL" \
      contrib/dragon/oracle/run_oracle.sh
    ORACLE_CAPTURE="$ORACLE_DIR/capture"
  else
    echo_notice "Oracle: reusing the captures in $ORACLE_CAPTURE"
  fi

  # Offline agave fires only the account and transaction callbacks
  # (ledger-tool/src/ledger_utils.rs:277-290), so those are the streams
  # that have two sides.
  #
  # The two fields masked on transactions are the differences
  # contrib/dragon/README.md accounts for and that have no fix in the
  # dragon tile: token balances, which are out of its scope (D15), and
  # the log text, which is the runtime's.  Nothing is masked on
  # accounts.  What the diff reports is therefore what is not yet
  # explained; ORACLE_STRICT=1 makes that fail the run.
  echo_notice "Oracle diff"
  for pair in "txn_p txn_p" "txns_p txns_p" "acct_p acct_p" "acctf_p acctf_p"; do
    a=${pair% *}; b=${pair#* }
    [[ -s "$ORACLE_CAPTURE/$a.jsonl" ]] || { echo "  $a: the oracle captured nothing"; continue; }
    [[ -s "$CAPTURE/$b.jsonl" ]] || { echo "  $b: not captured on this run"; continue; }
    mask=()
    [[ "$a" == txn_p ]] && mask=( --ignore pre_token_balances --ignore post_token_balances
                                  --ignore log_messages )
    echo "  --- $a ---"
    python3 contrib/dragon/diff.py "$ORACLE_CAPTURE/$a.jsonl" "$CAPTURE/$b.jsonl" \
        --label-a yellowstone --label-b dragon "${mask[@]}" \
        --drop-startup-a --common-slots --skip-first 1 --skip-last 1 \
        | sed 's/^/  /' \
      || { [[ "${ORACLE_STRICT:-0}" == "1" ]] && status=1; }
  done
fi

echo_notice "Summary"
echo "  output in $OUT"
if [[ $status -eq 0 ]]; then
  echo -e "\033[32mPASS\033[0m run_dragon_tests.sh"
else
  echo_error "FAIL run_dragon_tests.sh"
fi
exit $status
