DUMP_DIR=${DUMP_DIR:="./dump"}
echo $OBJDIR

LEDGER="devnet-398736132"

if [[ ! -e $DUMP_DIR/$LEDGER && SKIP_INGEST -eq 0 ]]; then
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
  gcloud storage cat gs://firedancer-ci-resources/$LEDGER.tar.gz | tee $DUMP_DIR/$LEDGER.tar.gz | tar zxf - -C $DUMP_DIR
fi

rm -rf $DUMP_DIR/$LEDGER/devnet-398736132_current.toml
rm -rf $DUMP_DIR/$LEDGER/fd.solcap

cp $DUMP_DIR/$LEDGER/devnet-398736132.toml $DUMP_DIR/$LEDGER/devnet-398736132_current.toml

export dump_dir=$(realpath $DUMP_DIR)
sed -i "s#{dump_dir}#${dump_dir}#g" "$DUMP_DIR/$LEDGER/devnet-398736132_current.toml"

$OBJDIR/bin/firedancer-dev configure init all --config $DUMP_DIR/$LEDGER/devnet-398736132_current.toml &> /dev/null
$OBJDIR/bin/firedancer-dev backtest --config $DUMP_DIR/$LEDGER/devnet-398736132_current.toml
$OBJDIR/bin/firedancer-dev configure fini all --config $DUMP_DIR/$LEDGER/devnet-398736132_current.toml &> /dev/null

$OBJDIR/bin/fd_solcap_diff $DUMP_DIR/$LEDGER/solana.solcap $DUMP_DIR/$LEDGER/fd.solcap -v 4
