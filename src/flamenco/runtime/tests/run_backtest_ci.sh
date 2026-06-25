#!/bin/bash
set -e

src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-308392063-v4.1.0-beta.1 -m 2000000 -e 308392063
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-350814254-v4.1.0-beta.1 -m 2000000 -e 350814284
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-281546597-v4.1.0-beta.1 -m 2000000 -e 281546597
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-324823213-v4.1.0-beta.1 -m 2000000 -e 324823214
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-325467935-v4.1.0-beta.1 -m 2000000 -e 325467935
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-283927487-v4.1.0-beta.1 -m 2000000 -e 283927497
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-281688085-v4.1.0-beta.1 -m 2000000 -e 281688086
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-321168308-v4.1.0-beta.1 -m 2000000 -e 321168308
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-327324660-v4.1.0-beta.1 -m 2000000 -e 327324660
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-370199634-v4.1.0-beta.1 -m 200000 -e 370199634
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-378683870-v4.1.0-beta.1 -m 2000000 -e 378683872
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-330219081-v4.1.0-beta.1 -m 2000000 -e 330219082
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-372721907-v4.1.0-beta.1 -m 2000000 -e 372721910
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-331691646-v4.1.0-beta.1 -m 2000000 -e 331691647
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-336218682-v4.1.0-beta.1 -m 2000000 -e 336218683
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-340269866-v4.1.0-beta.1 -m 2000000 -e 340269872
# Disabled, as it had increase_tx_account_lock_limit enabled which is no longer supported
# src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-390056400-v4.1.0-beta.1 -m 2000000 -e 390056406
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-254462437-v4.1.0-beta.1 -m 10000000 -e 254462598
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-346556000-v4.1.0-beta.1 -m 2000000 -e 346556337
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-380592002-v4.1.0-beta.1 -m 2000000 -e 380592006
src/flamenco/runtime/tests/run_ledger_backtest.sh -l genesis-v4.0.0 -m 3000 -e 1352 -g
# Disabled, as it had increase_tx_account_lock_limit enabled which is no longer supported
# src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-422969842-v4.1.0-beta.1 -m 2000000 -e 422969848
src/flamenco/runtime/tests/run_ledger_backtest.sh -l breakpoint-385786458-v4.1.0-beta.1 -m 2000000 -e 385786452
src/flamenco/runtime/tests/run_ledger_backtest.sh -l vote-states-v4-local-v4.1.0-beta.1 -m 3000 -e 1000
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-384169347-v4.1.0-beta.1 -m 2000000 -e 384169377 --root-distance 32 --max-live-slots 64
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-384395810-v4.1.0-beta.1 -m 2000000 -e 384395820
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-387596258-v4.1.0-beta.1 -m 2000000 -e 387596373
src/flamenco/runtime/tests/run_ledger_backtest.sh -l deployment-before-boundary-v4.1.0-beta.1 -m 1000 -e 75
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-391824000-boundary-v4.1.0-beta.1 -m 2000000 -e 391824016
src/flamenco/runtime/tests/run_ledger_backtest.sh -l vote-stake-scenarios-v4.1.0-beta.1 -m 10000
# [skipped: fails under v4.1: SIMD-0232 custom_commission_collector fee routing not in firedancer] src/flamenco/runtime/tests/run_ledger_backtest.sh -l vat-activation -m 20000 -e 540
src/flamenco/runtime/tests/run_ledger_backtest.sh -l progcache-stale-entry-v4.1.0-beta.1 -m 10000 -e 135
src/flamenco/runtime/tests/run_ledger_backtest.sh -l commission_rate_in_basis_points_boundary-v4.1.0-beta.1 -m 10000 -e 950
src/flamenco/runtime/tests/run_ledger_backtest.sh -l commission_rate_in_basis_points_snapshot-v4.1.0-beta.1 -m 10000 -e 950
src/flamenco/runtime/tests/run_ledger_backtest.sh -l rent_relax_only -m 2000000 -e 325
src/flamenco/runtime/tests/run_ledger_backtest.sh -l rent_lamports_per_byte_6333 -m 2000000 -e 325
src/flamenco/runtime/tests/run_ledger_backtest.sh -l rent_lamports_per_byte_696 -m 2000000 -e 325
src/flamenco/runtime/tests/run_ledger_backtest.sh -l rent_lamports_per_byte_6960 -m 2000000 -e 325
