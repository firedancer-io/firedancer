#!/bin/bash
set -e

src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-308392063-v2.3.0 -y 5 -m 2000000 -e 308392090 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-350814254-v2.3.0 -y 3 -m 2000000 -e 350814284 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-281546597-v2.3.0 -y 3 -m 2000000 -e 281546597 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-324823213-v2.3.0 -y 4 -m 2000000 -e 324823214 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-325467935-v2.3.0 -y 4 -m 2000000 -e 325467936 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-283927487-v2.3.0 -y 3 -m 2000000 -e 283927497 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-321168308-v2.3.0 -y 3 -m 2000000 -e 321168308 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-327324660-v2.3.0 -y 4 -m 2000000 -e 327324660 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-370199634-v2.3.0 -y 3 -m 200000 -e 370199634 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-378683870-v2.3.0 -y 3 -m 2000000 -e 378683872 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-330219081-v2.3.0 -y 4 -m 2000000 -e 330219082 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-372721907-v2.3.0 -y 3 -m 2000000 -e 372721910 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-331691646-v2.3.0 -y 4 -m 2000000 -e 331691647 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-336218682-v2.3.0 -y 5 -m 2000000 -e 336218683 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-340269866-v2.3.0 -y 5 -m 2000000 -e 340269872 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-390056400-v2.3.0 -y 10 -m 2000000 -e 390056406 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-254462437-v2.3.0 -y 16 -m 10000000 -e 254462598 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-epoch-per-200-v2.3.0 -y 1 -m 2000000 -e 984 -c 2.3.0
src/flamenco/runtime/tests/run_ledger_backtest.sh -l localnet-1678201-v2.3.0 -y 1 -m 2000000 -e 1679200 -c 2.3.0 -i shredcap
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-346796573-v2.3.0 -y 30 -m 90000000 -e 346796800 -c 2.3.0 -i shredcap -v true
