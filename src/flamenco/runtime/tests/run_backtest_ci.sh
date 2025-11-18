#!/bin/bash
set -e

src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-308392063-v2.3.0 -y 5 -m 2000000 -e 308392090
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-350814254-v2.3.0 -y 3 -m 2000000 -e 350814284 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-281546597-v2.3.0 -y 3 -m 2000000 -e 281546597
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-324823213-v2.3.0 -y 4 -m 2000000 -e 324823214
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-325467935-v2.3.0 -y 4 -m 2000000 -e 325467936
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-283927487-v2.3.0 -y 3 -m 2000000 -e 283927497
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-281688085-v2.3.0 -y 3 -m 2000000 -e 281688086
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-321168308-v2.3.0 -y 3 -m 2000000 -e 321168308
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-327324660-v2.3.0 -y 4 -m 2000000 -e 327324660
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-370199634-v2.3.0 -y 3 -m 200000 -e 370199634
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-378683870-v2.3.0 -y 3 -m 2000000 -e 378683872
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-330219081-v2.3.0 -y 4 -m 2000000 -e 330219082
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-372721907-v2.3.0 -y 3 -m 2000000 -e 372721910
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-331691646-v2.3.0 -y 4 -m 2000000 -e 331691647
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-336218682-v2.3.0 -y 5 -m 2000000 -e 336218683
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-340269866-v2.3.0 -y 5 -m 2000000 -e 340269872
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-390056400-v2.3.0 -y 10 -m 2000000 -e 390056406
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-254462437-v2.3.0 -y 16 -m 10000000 -e 254462598
src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-epoch-per-200-v2.3.0 -y 1 -m 2000000 -e 984
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-346556000 -y 3 -m 2000000 -e 346556337
src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-bpf-loader-v2.3.0 -y 1 -m 3000 -e 108
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-380592002-v2.3.0 -y 3 -m 2000000 -e 380592006
src/flamenco/runtime/tests/run_ledger_backtest.sh -l local-multi-boundary -y 1 -m 1000 -e 2325
src/flamenco/runtime/tests/run_ledger_backtest.sh -l genesis-v3.0 -y 1 -m 3000 -e 1280 -g
src/flamenco/runtime/tests/run_ledger_backtest.sh -l localnet-stake-v3.0.0 -y 1 -m 3000 -e 541
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-378539412 -y 5 -m 2000000 -e 378539445
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-422969842 -y 1 -m 2000000 -e 422969848
src/flamenco/runtime/tests/run_ledger_backtest.sh -l breakpoint-385786458 -y 1 -m 2000000 -e 385786458
src/flamenco/runtime/tests/run_ledger_backtest.sh -l vote-states-v4-local -y 1 -m 3000 -e 1000
