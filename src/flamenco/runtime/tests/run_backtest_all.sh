#!/bin/bash
set -e

src/flamenco/runtime/tests/run_ledger_backtest.sh -l genesis-vat-alpenglow-agave-v4.4-968b24ce -g -m 3000 -e 1360
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-block-revenue-sharing-agave-v4.4-57a35916-pr15795 -m 2000000 -e 1400
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-remove-inactive-stakes-agave-v4.4-6afe9919 -m 2000000 -e 1100
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-block-revenue-sharing-remove-inactive-stakes-agave-v4.4-57a35916-pr15795 -m 2000000 -e 1400
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-legacy-vote-ixs -m 2000000 -e 126
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-deactivated-stake -m 2000000 -e 810
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-leader-credits -m 2000000 -e 3915
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-alpenclock-lamports -m 2000000 -e 280
