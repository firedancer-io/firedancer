#!/bin/bash
set -e

src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-391824000 -y 600 -m 1100000000 -e 391824001 -v true --funk
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-433989075 -y 400 -m 200000000 -e 434592005 --exec 64 --funk
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-393520696 -y 600 -m 1100000000 -e 393984000 --funk
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-380636816 -y 50 -m 200000000 -e 381116303 --exec 64 --funk
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-387596256 -y 30 -m 90000000 -e 387596373 -lt -v true --exec 64 --funk
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-400468865 -y 600 -m 1200000000 -e 400468870 -v true --funk
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-389765300 -y 30 -m 90000000 -e 389765400 -v true --funk
