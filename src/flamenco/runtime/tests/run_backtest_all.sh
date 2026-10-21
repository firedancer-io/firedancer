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
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-migration-rewards -m 2000000 -e 1086 --zst
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-migration-epoch-end -m 2000000 -e 1087 --zst
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-migration-no-ag-credits -m 2000000 -e 1087 --zst
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-migration-epoch-start -m 2000000 -e 1599 --zst
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-migration-ag-only-voter -m 2000000 -e 1087 --zst
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-migration-no-tower-points -m 2000000 -e 1125 --zst
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-migration-vote-recreate -m 2000000 -e 1637 --zst
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-migration-validators -m 2000000 -e 2112 --zst
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-migration-validators-boundary-snap -m 2000000 -e 1600 --zst
src/flamenco/runtime/tests/run_ledger_backtest.sh -l alpenglow-migration-validators-mid-payout -m 2000000 -e 1600 --zst
