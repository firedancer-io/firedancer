#!/bin/bash
set -eou pipefail

source contrib/test/ledger_common.sh

DUMP=${DUMP:="./dump"}
OBJDIR=${OBJDIR:-build/native/gcc}
SKIP_INGEST=${SKIP_INGEST:-0}

LEDGER="mainnet-406545575-solcap"
REDOWNLOAD=1

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

# Clone and build solcap-tools
ORIG_DIR=$(pwd)
cd $DUMP
if [ ! -d "solcap-tools" ]; then
  git clone https://github.com/firedancer-io/solcap-tools.git > /dev/null 2>&1
fi
cd solcap-tools
git fetch > /dev/null 2>&1
git checkout 44dc8e2a5c65435daf57b009c108234f316224f7 > /dev/null 2>&1
cargo build --release > /dev/null 2>&1
cd "$ORIG_DIR"

export ledger_dir=$(realpath $DUMP/$LEDGER)
export dump_dir=$(realpath $DUMP)

cat > "$DUMP/mainnet-406545575-solcap_current.toml" << EOF

[snapshots]
    incremental_snapshots = false
    [snapshots.sources]
        servers = []
        [snapshots.sources.gossip]
            allow_any = false
            allow_list = []
[layout]
    shred_tile_count = 4
    snapshot_hash_tile_count = 1
    verify_tile_count = 2
    execrp_tile_count = 6
[tiles]
    [tiles.archiver]
        end_slot = 406545600
        rocksdb_path = "${ledger_dir}/rocksdb"
        ingest_mode = "rocksdb"
    [tiles.replay]
        enable_features = [  ]
    [tiles.gui]
        enabled = false
    [tiles.rpc]
        enabled = false
[accounts]
    file_size_gib = 5
    max_accounts = 4000000
[runtime]
    max_live_slots = 64
    max_fork_width = 4
[log]
    level_stderr = "NOTICE"
    path = "/tmp/ledger_log_solcap"

[paths]
    snapshots = "${ledger_dir}"

[capture]
    solcap_capture = "${dump_dir}/mainnet-406545575.solcap"
[development]
    [development.snapshots]
        disable_lthash_verification = true
[gossip]
    entrypoints = [ "0.0.0.0:1" ]
EOF

$OBJDIR/bin/firedancer-dev configure fini all
$OBJDIR/bin/firedancer-dev backtest --config $DUMP/mainnet-406545575-solcap_current.toml

# Run solcap-tools diff and check the summary for zero differences
DIFF_OUTPUT=$($DUMP/solcap-tools/target/release/solcap-tools diff $DUMP/mainnet-406545575.solcap $DUMP/$LEDGER/ledger_tool/bank_hash_details/ -v 5)
echo "$DIFF_OUTPUT"

SUMMARY=$(echo "$DIFF_OUTPUT" | tail -3) > /dev/null 2>&1
DIFFERING_SLOTS=$(echo "$SUMMARY" | grep -ioP 'Differing Slots: \K\d+' || echo "") > /dev/null 2>&1
DIFFERING_ACCOUNTS=$(echo "$SUMMARY" | grep -ioP 'Differing Accounts: \K\d+' || echo "") > /dev/null 2>&1

if [[ "$DIFFERING_SLOTS" != "0" || "$DIFFERING_ACCOUNTS" != "0" ]]; then
  echo -e "\033[0;31mFAIL\033[0m Solcap diff found mismatches! Differing Slots: $DIFFERING_SLOTS, Differing Accounts: $DIFFERING_ACCOUNTS" >&2
  exit 1
fi

exit 0
