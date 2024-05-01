#!/bin/bash

# This script can be used to produce a solcap file for a given ledger for both firedancer
# and solana. It can also be used to produce a diff between the two solcap files.

solcap_script="src/flamenco/capture/solcap.sh"
solcap_fd_ledger_dump="$FIREDANCER/dump"
solcap_ledger_min_basename=$(basename "$LEDGER_MIN")
solcap_diff_output="${solcap_ledger_min_basename}_diff"

if [ ! -d "$FIREDANCER" ]; then
  echo "[-] $FIREDANCER not found"
  exit 1
fi

if [ ! -f "$FIREDANCER/$solcap_script" ]; then
  echo "[-] $FIREDANCER/$solcap_script not found"
  exit 1
fi

cp -rf $LEDGER_MIN $solcap_fd_ledger_dump

set +x
cd $FIREDANCER || exit
SOLANADIR=$SOLANA_BUILD_DIR $solcap_script --firedancer-solcap $FIREDANCER_SOLCAP --solana-solcap $SOLANA_SOLCAP \
  --end-slot $END_SLOT --ledger dump/$solcap_ledger_min_basename/ \
  --checkpoint $CHECKPOINT --output $solcap_diff_output --verbosity $VERBOSITY
set -x

echo -e "[~] solcap diff \n"
cat $FIREDANCER/$solcap_diff_output
