#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

URL='http://localhost:8899/incremental-snapshot.tar.bz2'
NUM_TRIES=10

URL="${1:-$URL}"
NUM_TRIES="${2:-$NUM_TRIES}"

# we have to do this because the validator's incremental snapshot endpoint is flaky
for i in $(seq 1 $NUM_TRIES); do
  s=$(curl -s --max-redirs 0 $URL)
  if ! wget -q --trust-server-names $URL; then
    sleep 1
  else
    echo "${s:1}"
    exit 0
  fi
done

echo "failed after $NUM_TRIES tries to wget $URL"
exit 1
