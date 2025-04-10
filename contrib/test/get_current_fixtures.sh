#!/bin/bash
set -euo pipefail

# Required env vars: AWS_ACCESS_KEY_ID, AWS_SECRET_KEY_ID
# Example usage: ./get_current_fixtures.sh "sol_txn_diff"

if [ $# -ne 2 ]; then
  echo "Usage: $0 <lineage>"
  echo "Example: $0 sol_txn_diff contrib/test/test-vectors-fixtures/txn-fixtures/current-program-tests.list"
  exit 1
fi

NUM_PROCESSES=${NUM_PROCESSES:-12}

HARNESS_PATH="/home/cali/repos/solfuzz"
LINEAGE="$1"
OUT_FILE="$2"

# Determine the harness based on lineage
# For sol_txn_diff → harness is txn
if [[ $LINEAGE == "sol_"*"_diff" ]]; then
  # Extract what's between "sol_" and "_diff"
  HARNESS=$(echo $LINEAGE | sed 's/sol_\(.*\)_diff/\1/')
else
  # Fallback if the pattern doesn't match
  HARNESS=$LINEAGE
fi

echo "Using harness: $HARNESS"

S3_BUCKET="fuzzcorp-cmin-e72f016"
S3_PREFIX="prj_rvfruw8lACo/${LINEAGE}"
TEMP_DIR="./dump/temp_corpus_${LINEAGE}"
DUMP_DIR="./dump/test-vectors/${HARNESS}/current-fixtures"
OUTPUT_ZIP="current_fixtures_${LINEAGE}.zip"

mkdir -p dump

# Check for required environment variables
if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
  echo "Error: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables must be set"
  exit 1 fi
echo "Getting latest corpus for lineage: $LINEAGE"
fi

# clear dump dir
if [[ -d "$DUMP_DIR" ]]; then
  rm -rf $DUMP_DIR/*
fi

# Create temporary directories
mkdir -p "$TEMP_DIR"
mkdir -p "$DUMP_DIR"

# List the S3 bucket and find the latest zip file
LATEST_ZIP=$(aws s3 ls "s3://${S3_BUCKET}/${S3_PREFIX}/" --recursive | grep '\.zip$' | sort -k1,2 | tail -n 1 | awk '{print $4}')

if [ -z "$LATEST_ZIP" ]; then
  echo "Error: No zip files found in s3://${S3_BUCKET}/${S3_PREFIX}/"
  exit 1
fi

echo "Found latest corpus: $LATEST_ZIP"

# Download the latest zip file
aws s3 cp "s3://${S3_BUCKET}/${LATEST_ZIP}" "${TEMP_DIR}/corpus.zip"
# Download fuzzcorp assets
aws s3 cp "s3://fuzzcorp-seedcorpus-dropbox-6dd4ad2/org_rvfruw8l/prj_rvfruw8lACo/sol_txn/latest.zip" "${TEMP_DIR}/latest.zip"
unzip -q -o "${TEMP_DIR}/latest.zip" -d "${TEMP_DIR}"
# Extract the corpus
echo "Extracting corpus..."
unzip -q -o "${TEMP_DIR}/corpus.zip" -d "${TEMP_DIR}/corpus"

# Run each file in the corpus through the fuzzer
echo "Running fuzzer on corpus files..."
export DUMP_DIR

# Count files for progress tracking
TOTAL_FILES=$(find "${TEMP_DIR}/corpus" -type f | wc -l)
PROCESSED=0
export FIREDANCER_TARGET="/home/cali/repos/firedancer/fuzz-build/native/clang/lib/libfd_exec_sol_compat.so"
# check env vars for targets
if [ -z "${FIREDANCER_TARGET:-}" ] || [ -z "${SOLFUZZ_TARGET:-}" ]; then
  echo "Error: FIREDANCER_TARGET and SOLFUZZ_TARGET environment variables must be set"
  exit 1
fi

export ASAN_OPTIONS=abort_on_error=1:allow_user_segv_handler=0:symbolize=1:detect_leaks=0
export DUMP_DIR="$DUMP_DIR"
export SOLFUZZ_TARGETS="$FIREDANCER_TARGET"
export FUZZCORP_ASSETS_DIR="${TEMP_DIR}"
find "${TEMP_DIR}/corpus" -type f | xargs -P $NUM_PROCESSES -n 1000 $HARNESS_PATH/build/fuzz_sol_${HARNESS} -rss_limit_mb=10000 -timeout=5 || true

# Clean up temporary files
echo "Cleaning up temporary files..."
find "$DUMP_DIR" -type f ! -name "*.fix" -exec rm -f {} \;

# output fixtures to out file
find $DUMP_DIR -type f > $OUT_FILE

echo "Done! Fixtures are available in $DUMP_DIR"