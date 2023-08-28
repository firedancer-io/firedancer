#!/bin/bash

# bash strict mode
set -euo pipefail
IFS=$'\n\t'
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd "${SCRIPT_DIR}/../../"

LOG_PATH=${LOG_PATH:-~/log}

# frank-single-transaction.sh needs to be run first so that a log is generated
grep -qE 'schedule clean read! length [1-9]' "${LOG_PATH}"