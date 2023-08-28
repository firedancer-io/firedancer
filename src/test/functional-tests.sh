#!/bin/bash

# bash strict mode
set -euo pipefail
IFS=$'\n\t'
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "${SCRIPT_DIR}/../../"

export LOG_PATH=${LOG_PATH:-~/log}

./src/test/frank-single-transaction.sh
./src/test/frank-leader-schedule.sh
