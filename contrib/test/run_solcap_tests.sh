#!/bin/bash
set -xeou pipefail

source contrib/test/ledger_common.sh

DUMP=${DUMP:="./dump"}
OBJDIR=${OBJDIR:-build/native/gcc}
echo $OBJDIR

LEDGER="devnet-398736132-solcap"
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

if [[ ! -e $DUMP/$LEDGER && SKIP_INGEST -eq 0 ]]; then
  download_and_extract_ledger
  create_checksum
else
  check_ledger_checksum_and_redownload
fi

rm -rf $DUMP/$LEDGER/devnet-398736132_current.toml
rm -rf $DUMP/$LEDGER/fd.solcap

cp $DUMP/$LEDGER/devnet-398736132.toml $DUMP/$LEDGER/devnet-398736132_current.toml

export ledger_dir=$(realpath $DUMP/$LEDGER)
sed -i "s#{ledger_dir}#${ledger_dir}#g" "$DUMP/$LEDGER/devnet-398736132_current.toml"
sed -i "s/max_total_banks = [0-9]*/max_total_banks = 32/g" "$DUMP/$LEDGER/devnet-398736132_current.toml"
sed -i -z "s/\[snapshots\].*\[layout\]/[layout]/" "$DUMP/$LEDGER/devnet-398736132_current.toml"
sed -i "/writer_tile_count/d" "$DUMP/$LEDGER/devnet-398736132_current.toml"
sed -i "/lock_pages/d" "$DUMP/$LEDGER/devnet-398736132_current.toml"
sed -i "/heap_size_gib/d" "$DUMP/$LEDGER/devnet-398736132_current.toml"
sed -i "/max_total_banks/d" "$DUMP/$LEDGER/devnet-398736132_current.toml"
sed -i "/max_fork_width/d" "$DUMP/$LEDGER/devnet-398736132_current.toml"
sed -i "/cluster_version/d" "$DUMP/$LEDGER/devnet-398736132_current.toml"

echo "
[gossip]
  entrypoints = [ \"0.0.0.0:1\" ]" >> "$DUMP/$LEDGER/devnet-398736132_current.toml"

echo "
[snapshots]
    incremental_snapshots = false
    [snapshots.sources]
        servers = []
        [snapshots.sources.gossip]
            allow_any = false
            allow_list = []" >> "$DUMP/$LEDGER/devnet-398736132_current.toml"

$OBJDIR/bin/firedancer-dev configure init all --config $DUMP/$LEDGER/devnet-398736132_current.toml
$OBJDIR/bin/firedancer-dev backtest --config $DUMP/$LEDGER/devnet-398736132_current.toml
$OBJDIR/bin/firedancer-dev configure fini all --config $DUMP/$LEDGER/devnet-398736132_current.toml

$OBJDIR/bin/fd_solcap_import $DUMP/$LEDGER/bank_hash_details/ $DUMP/$LEDGER/solana.solcap
$OBJDIR/bin/fd_solcap_diff $DUMP/$LEDGER/solana.solcap $DUMP/$LEDGER/fd.solcap -v 4

# check that the ledger is not corrupted after a run
check_ledger_checksum
