#!/bin/bash
set -e

src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-epoch-per-200-v2.3.0 -y 1 -m 2000000 -e 984 -c 2.3.0 "$@"
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-346556000 -y 3 -m 2000000 -e 346556337 -c 2.3.0 "$@"
src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-bpf-loader-v2.3.0 -y 1 -m 3000 -e 108 -c 2.3.0 "$@"
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-380592002-v2.3.0 -y 3 -m 2000000 -e 380592006 -c 2.3.0 "$@"
src/flamenco/runtime/tests/run_ledger_backtest.sh -l local-multi-boundary -y 1 -m 1000 -e 2325 -c 2.3.0 "$@"
src/flamenco/runtime/tests/run_ledger_backtest.sh -l genesis-v3.0 -y 1 -m 3000 -e 1280 -c 3.0.0 -g "$@"
