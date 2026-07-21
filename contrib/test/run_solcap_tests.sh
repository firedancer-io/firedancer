#!/bin/bash
set -eou pipefail

source contrib/test/ledger_common.sh

DUMP=${DUMP:="./dump"}
OBJDIR=${OBJDIR:-build/native/gcc}
SKIP_INGEST=${SKIP_INGEST:-0}

LEDGER="mainnet-424669000-solcap"
REDOWNLOAD=1

BACKTEST_LOG="/tmp/ledger_log_solcap"

# Surface failures: with `set -e` a failing command aborts the script with
# no context, and several steps below capture output to log files.  This
# trap prints the failing command, line, and exit code, and dumps the
# backtest log tail so the real error is visible in CI instead of a bare
# non-zero exit.
on_err() {
  local ec=$?
  echo "::error::run_solcap_tests.sh failed at line ${BASH_LINENO[0]} (exit ${ec}): ${BASH_COMMAND}" >&2
  if [[ -f "$BACKTEST_LOG" ]]; then
    echo "----- last 100 lines of ${BACKTEST_LOG} -----" >&2
    tail -n 100 "$BACKTEST_LOG" >&2 || true
    echo "---------------------------------------------" >&2
  fi
  exit "$ec"
}
trap on_err ERR

while [[ $# -gt 0 ]]; do
case $1 in
    -nr|--no-redownload)
       REDOWNLOAD=0
       shift
       ;;
    -*|--*)
       echo "unknown option $1"
       exit 1
       ;;
    *)
       POSITION_ARGS+=("$1")
       shift
       ;;
  esac
done

download_and_extract_ledger() {
  echo "Downloading gs://firedancer-ci-resources/$LEDGER.tar.gz"
  if [ "`gcloud auth list |& grep  firedancer-scratch | wc -l`" == "0" ]; then
    if [ "`gcloud auth list |& grep  firedancer-ci | wc -l`" == "0" ]; then
      if [ -f /etc/firedancer-scratch-bucket-key.json ]; then
        gcloud auth activate-service-account --key-file /etc/firedancer-scratch-bucket-key.json
      fi
      if [ -f /etc/firedancer-ci-78fff3e07c8b.json ]; then
        gcloud auth activate-service-account --key-file /etc/firedancer-ci-78fff3e07c8b.json
      fi
    fi
  fi
  gcloud storage cat gs://firedancer-ci-resources/$LEDGER.tar.gz | tee $DUMP/$LEDGER.tar.gz | tar zxf - -C $DUMP
}

if [[ ! -e $DUMP/$LEDGER ]]; then
  download_and_extract_ledger
fi

# Clone and build solcap-tools.  Capture output to a log and only print
# it on failure, so a broken clone/fetch/checkout/build surfaces its
# error in CI instead of failing silently.
echo "Building solcap-tools ..."
ORIG_DIR=$(pwd)
SOLCAP_BUILD_LOG="$(mktemp)"
run_quiet() {
  if ! "$@" > "$SOLCAP_BUILD_LOG" 2>&1; then
    echo "::error::solcap-tools step failed: $*" >&2
    cat "$SOLCAP_BUILD_LOG" >&2
    exit 1
  fi
}
cd $DUMP
if [ ! -d "solcap-tools" ]; then
  run_quiet git clone https://github.com/firedancer-io/solcap-tools.git
fi
cd solcap-tools
run_quiet git fetch
run_quiet git checkout 44dc8e2a5c65435daf57b009c108234f316224f7
run_quiet cargo build --release
cd "$ORIG_DIR"

export ledger_dir=$(realpath $DUMP/$LEDGER)
export dump_dir=$(realpath $DUMP)

cat > "$DUMP/mainnet-424669000-solcap_current.toml" << EOF

[snapshots]
    incremental_snapshots = false
    [snapshots.sources]
        servers = []
        [snapshots.sources.gossip]
            allow_any = false
            allow_list = []
[layout]
    shred_tile_count = 4
    verify_tile_count = 2
    execrp_tile_count = 6
[tiles]
    [tiles.gui]
        enabled = false
    [tiles.rpc]
        enabled = false
[accounts]
    max_accounts = 4000000
[runtime]
    max_live_slots = 64
    max_fork_width = 4
[log]
    level_stderr = "NOTICE"
    path = "/tmp/ledger_log_solcap"
[paths]
    snapshots = "${ledger_dir}"
    accounts = "${ledger_dir}/accounts.db"
    genesis = "${ledger_dir}/genesis.bin"
[capture]
    solcap_capture = "${dump_dir}/mainnet-424669000.solcap"
[gossip]
    entrypoints = [ "0.0.0.0:1" ]
[development.ledger_input]
    format = "pcap"
    path = "${ledger_dir}/shreds.pcapng.zst"
    end_slot = 424669025
EOF

echo "Running firedancer-dev configure fini all ..."
$OBJDIR/bin/firedancer-dev configure fini all

convert_rocksdb_to_shredcap() {
  rm -f $DUMP/$LEDGER/shreds.pcapng.zst.tmp
  if ! $OBJDIR/bin/fd_blockstore2shredcap --rocksdb $DUMP/$LEDGER/rocksdb --out $DUMP/$LEDGER/shreds.pcapng.zst.tmp --zstd; then
    rm -f $DUMP/$LEDGER/shreds.pcapng.zst.tmp
    return 1
  fi
  mv $DUMP/$LEDGER/shreds.pcapng.zst.tmp $DUMP/$LEDGER/shreds.pcapng.zst
}

if [[ ! -e $DUMP/$LEDGER/shreds.pcapng.zst ]]; then
  echo "Running fd_blockstore2shredcap ..."
  if ! convert_rocksdb_to_shredcap; then
    # A cached ledger may have a corrupt rocksdb (eg. damaged by a converter
    # version that deleted unopened column families); re-download once.
    echo "conversion failed; re-downloading ledger and retrying"
    rm -rf $DUMP/$LEDGER
    download_and_extract_ledger
    convert_rocksdb_to_shredcap
  fi
fi

echo "Running backtest (full log at ${BACKTEST_LOG}) ..."
$OBJDIR/bin/firedancer-dev backtest --config $DUMP/mainnet-424669000-solcap_current.toml

# Run solcap-tools diff and check the summary for zero differences
echo "Running solcap-tools diff ..."
DIFF_OUTPUT=$($DUMP/solcap-tools/target/release/solcap-tools diff $DUMP/mainnet-424669000.solcap $DUMP/$LEDGER/ledger_tool/bank_hash_details/ -v 5)
echo "$DIFF_OUTPUT"

SUMMARY=$(echo "$DIFF_OUTPUT" | tail -3)
DIFFERING_SLOTS=$(echo "$SUMMARY" | grep -ioP 'Differing Slots: \K\d+' || true)
DIFFERING_ACCOUNTS=$(echo "$SUMMARY" | grep -ioP 'Differing Accounts: \K\d+' || true)

# If the summary did not parse, treat that as a failure rather than
# silently passing (empty != "0").
if [[ -z "$DIFFERING_SLOTS" || -z "$DIFFERING_ACCOUNTS" ]]; then
  echo -e "\033[0;31mFAIL\033[0m Could not parse solcap diff summary (Differing Slots='${DIFFERING_SLOTS}', Differing Accounts='${DIFFERING_ACCOUNTS}'). Full diff output above." >&2
  exit 1
fi

if [[ "$DIFFERING_SLOTS" != "0" || "$DIFFERING_ACCOUNTS" != "0" ]]; then
  echo -e "\033[0;31mFAIL\033[0m Solcap diff found mismatches! Differing Slots: $DIFFERING_SLOTS, Differing Accounts: $DIFFERING_ACCOUNTS" >&2
  exit 1
fi

echo "Solcap diff clean: 0 differing slots, 0 differing accounts"
exit 0
