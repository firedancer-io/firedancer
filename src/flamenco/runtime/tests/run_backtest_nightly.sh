#!/bin/bash
set -e

src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-391824000 -y 600 -m 1100000000 -e 391824001 -v true
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-433989075 -y 400 -m 200000000 -e 434592005
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-393520696 -y 600 -m 1100000000 -e 393984037
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-380636816 -y 50 -m 200000000 -e 381116303
