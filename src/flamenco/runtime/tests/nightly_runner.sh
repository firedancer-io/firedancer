#!/bin/bash -f

# Pull the latest code
cd $FD_NIGHTLY_REPO_DIR
git checkout $FD_NIGHTLY_BRANCH
git pull origin $FD_NIGHTLY_BRANCH
export FD_NIGHTLY_COMMIT=$(git rev-parse HEAD)

# Set up environment
PATH=/opt/rh/gcc-toolset-12/root/usr/bin:$PATH
export PATH
PKG_CONFIG_PATH=/usr/lib64/pkgconfig:$PKG_CONFIG_PATH

make distclean && make clean
./deps.sh nuke
FD_AUTO_INSTALL_PACKAGES=1 ./deps.sh +dev fetch check install
source ~/.cargo/env
make -j

send_slack_message() {
    local MESSAGE="$1"
    json_payload=$(cat <<EOF
{
    "text": "$MESSAGE",
    "link_names": 1
}
EOF
)
    curl -X POST -H 'Content-type: application/json' --data "$json_payload" "$SLACK_WEBHOOK_URL"
}

set +e
set -x

echo "Running Backtest Tests"

./src/flamenco/runtime/tests/run_backtest_tests_all.sh
status=$?

set +x

echo "Backtest script exit status: $status"

if [ $status -eq 0 ]; then
    send_slack_message "Nightly Backtest Passed"
else
    send_slack_message "@here Nightly Backtest Ledger Tests Failed"
fi
