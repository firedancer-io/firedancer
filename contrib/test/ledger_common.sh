#!/bin/bash

echo_notice() {
  echo -e "\033[34m$1\033[0m"
}

echo_error() {
  echo -e "\033[31m$1$2\033[0m"
}

create_checksum() {
  # generate checksum of ledger
  find $DUMP/$LEDGER -type f \( -name "snapshot*" -o -name "genesis*" -o -wholename "*rocksdb*" \) -print0 | xargs -0 md5sum | sort > $DUMP/$LEDGER/checksum.txt
}

redownload_ledger_or_fail() {
  if [[ $REDOWNLOAD -eq 1 ]]; then
    echo_notice "Redownloading ledger $LEDGER"
    rm -rf $DUMP/$LEDGER
    download_and_extract_ledger
    create_checksum
  else
    echo_error "If you want to redownload the ledger, please remove the -nr flag and try again."
    exit 1
  fi
}

check_ledger_checksum() {
  if [ ! -f "$DUMP/$LEDGER/checksum.txt" ]; then
    echo_error "original checksum file does not exist."
    exit 1
  fi

  # check existing checksum
  find $DUMP/$LEDGER -type f \( -name "snapshot*" -o -name "genesis*" -o -wholename "*rocksdb*" \) -print0 | xargs -0 md5sum | sort > $DUMP/$LEDGER/checksum_temp.txt

  if ! diff -u $DUMP/$LEDGER/checksum.txt $DUMP/$LEDGER/checksum_temp.txt > /dev/null; then
    echo_error "Checksum mismatch for existing ledger $LEDGER. This likely means the ledger is corrupted. \
vimdiff $DUMP/$LEDGER/checksum.txt $DUMP/$LEDGER/checksum_temp.txt to see the differences."
  else
    rm $DUMP/$LEDGER/checksum_temp.txt
  fi
}

check_ledger_checksum_and_redownload() {
  if [ ! -f "$DUMP/$LEDGER/checksum.txt" ]; then
    echo_error "original checksum file does not exist."
    redownload_ledger_or_fail
  fi

  # check existing checksum
  find $DUMP/$LEDGER -type f \( -name "snapshot*" -o -name "genesis*" -o -wholename "*rocksdb*" \) -print0 | xargs -0 md5sum | sort > $DUMP/$LEDGER/checksum_temp.txt

  if ! diff -u $DUMP/$LEDGER/checksum.txt $DUMP/$LEDGER/checksum_temp.txt > /dev/null; then
    echo_error "Checksum mismatch for existing ledger $LEDGER. This likely means the ledger is corrupted. \
vimdiff $DUMP/$LEDGER/checksum.txt $DUMP/$LEDGER/checksum_temp.txt to see the differences. \
If you are running locally, please disable redownload with -nr and inspect the differences. "
    redownload_ledger_or_fail
  else
    rm $DUMP/$LEDGER/checksum_temp.txt
  fi
}
