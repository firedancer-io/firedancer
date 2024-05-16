#!/bin/bash -f

# Defaults
BRANCH="main"

# Read command-line args
while [[ $# -gt 0 ]]; do
  case $1 in
    -r|--repo-dir)
       REPO_DIR="$2"
       shift 2
       ;;
    -b|--branch)
       BRANCH="$2"
       shift 2
       ;;
    -s|--slack-webhook-url)
       SLACK_WEBHOOK_URL="$2"
       shift 2
       ;;
    *)
      echo "Unknown flag"
      exit 1
      ;;
  esac
done

# Error if required args are not provided
if [ -z "${REPO_DIR}" ]; then
  echo "Error: Repository directory not specified"
  exit 1
fi

if [ -z "${SLACK_WEBHOOK_URL}" ]; then
  echo "Error: Slack webhook URL not specified"
  exit 1
fi

# Pull the latest code
cd $REPO_DIR
git checkout $BRANCH
git pull origin $BRANCH
COMMIT=$(git rev-parse HEAD)

# Notify start of the test
start_message="Alert: Starting Nightly Ledger Test using Commit \`$COMMIT\` on Branch \`$BRANCH\`"
start_json_payload=$(cat <<EOF
{
    "text": "$start_message"
}
EOF
)
curl -X POST -H 'Content-type: application/json' --data "$start_json_payload" $SLACK_WEBHOOK_URL

# Set up environment
make distclean && make clean
./deps.sh nuke
echo "y" | ./deps.sh +dev
make -j CC=clang EXTRAS=llvm-cov

# Run the test
make run-runtime-test-nightly -j CC=clang EXTRAS=llvm-cov > ~/run_nightly_tests.txt
status=$?

# Notify the test status
if [ $status -eq 0 ]; then
    end_message="Alert: Nightly Ledger Test Passed using Commit \`$COMMIT\` on Branch \`$BRANCH\`"
else
    end_message="@here Alert: Nightly Ledger Test Failed using Commit \`$COMMIT\` on Branch \`$BRANCH\`"
fi

mapfile -t log_infos < <(grep 'Log for ledger' ~/run_nightly_tests.txt)

for log_info in "${log_infos[@]}"; do
    if [[ $log_info =~ ledger[[:space:]]+([a-zA-Z0-9-]+) ]]; then
        ledger="${BASH_REMATCH[1]}"
    fi

    if [[ $log_info =~ Log[[:space:]]at[[:space:]]+\"([^\"]+)\" ]]; then
        log_file="${BASH_REMATCH[1]}"
    fi

    start_slot=$(grep "recovered slot_bank" "$log_file" | tail -n 1 | awk -F'slot=' '{print $2}' | awk '{print $1}')
    mismatched=$(grep "Bank hash mismatch!" "$log_file" | tail -n 1)

    if [[ -n "$mismatched" ]]; then
        mismatch_slot=$(grep "Bank hash mismatch!" "$log_file" | tail -n 1 | awk -F'slot=' '{print $2}' | awk '{print $1}')
        end_message+=$'\n'" - Ledger \`$ledger\` Starting at Slot \`$start_slot\` Failed at Slot \`$mismatch_slot\`, Log at: \`$log_file\`"
    else
        replay_completed=$(grep "replay completed" "$log_file" | tail -n 1)
        info="${replay_completed#*replay completed - }"
        end_message+=$'\n'" - Ledger \`$ledger\` Starting at Slot \`$start_slot\` Passed: $info"
    fi
done

./src/flamenco/runtime/tests/run_conformance_tests.sh -i /data/insn_pb/ -fdr $REPO_DIR -fdb $BRANCH

json_payload=$(cat <<EOF
{
    "text": "$end_message",
    "link_names": 1
}
EOF
)
curl -X POST -H 'Content-type: application/json' --data "$json_payload" $SLACK_WEBHOOK_URL
