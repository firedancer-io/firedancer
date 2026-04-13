#!/bin/bash
set -e

# Notes:
# - snapshot lthash has been enabled for all tests (except for those
#   where the original lthash is wrong - as documented below)
#   TODO expand.

src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-519-v4.0.0 -y 3 -m 2000000 -e 255312007 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257066033-v4.0.0 -y 3 -m 2000000 -e 257066038 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257066844-v4.0.0 -y 3 -m 2000000 -e 257066849 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257067457-v4.0.0 -y 3 -m 2000000 -e 257067461 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257068890-v4.0.0 -y 3 -m 2000000 -e 257068895 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257181622-v4.0.0 -y 3 -m 2000000 -e 257181624 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-254462437-v4.0.0 -y 16 -m 10000000 -e 254462598 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-262654839-v4.0.0 -y 3 -m 10000000 -e 262654840 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257037451-v4.0.0 -y 3 -m 2000000 -e 257037454 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257035225-v4.0.0 -y 4 -m 2000000 -e 257035233 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257465453-v4.0.0 -y 4 -m 10000000 -e 257465454 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257058865-v4.0.0 -y 3 -m 2000000 -e 257058870 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257059815-v4.0.0 -y 3 -m 2000000 -e 257059818 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257061172-v4.0.0 -y 3 -m 2000000 -e 257061175 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257222682-v4.0.0 -y 3 -m 2000000 -e 257222688 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-264890264-v4.0.0 -y 3 -m 2000000 -e 264890265 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257229353-v4.0.0 -y 4 -m 2000000 -e 257229357 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257257983-v4.0.0 -y 3 -m 2000000 -e 257257986 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267728520-v4.0.0 -y 3 -m 2000000 -e 267728522 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267651942-v4.0.0 -y 3 -m 2000000 -e 267651943 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267081197-v4.0.0 -y 3 -m 2000000 -e 267081198 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267085604-v4.0.0 -y 3 -m 2000000 -e 267085605 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-265688706-v4.0.0 -y 3 -m 2000000 -e 265688707 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-265330432-v4.0.0 -y 3 -m 2000000 -e 265330433 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-268575190-v4.0.0 -y 3 -m 2000000 -e 268575191 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-268129380-v4.0.0 -y 3 -m 2000000 -e 268129380 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-268163043-v4.0.0 -y 3 -m 2000000 -e 268163043 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-269511381-v4.0.0 -y 3 -m 2000000 -e 269511381 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-269567236-v4.0.0 -y 3 -m 2000000 -e 269567236 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-266134813-v4.0.0 -y 3 -m 2000000 -e 266134814 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-266545736-v4.0.0 -y 3 -m 2000000 -e 266545737 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267059180-v4.0.0 -y 3 -m 2000000 -e 267059181 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267580466-v4.0.0 -y 3 -m 2000000 -e 267580467 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-268196194-v4.0.0 -y 3 -m 2000000 -e 268196195 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267766641-v4.0.0 -y 3 -m 2000000 -e 267766642 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-269648145-v4.0.0 -y 3 -m 2000000 -e 269648146 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-281688085-v4.0.0 -y 3 -m 2000000 -e 281688086 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-277660422-v4.0.0 -y 3 -m 2000000 -e 277660423 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-277876060-v4.0.0 -y 3 -m 2000000 -e 277876061 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-277927063-v4.0.0 -y 3 -m 2000000 -e 277927065 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-281375356-v4.0.0 -y 3 -m 2000000 -e 281375359 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-251418170-v4.0.0 -y 5 -m 2000000 -e 251418233 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-282232100-v4.0.0 -y 3 -m 2000000 -e 282232101 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-282151715-v4.0.0 -y 3 -m 2000000 -e 282151717 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-286450148-v4.0.0 -y 3 -m 2000000 -e 286450151 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-epoch-per-200-v4.0.0 -y 1 -m 2000000 -e 984 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-epoch-per-300-v4.0.0 -y 1 -m 2000000 -e 984 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-epoch-per-500-v4.0.0 -y 1 -m 2000000 -e 984 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-297489336-v4.0.0 -y 3 -m 2000000 -e 297489363 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-300377724-v4.0.0 -y 5 -m 2000000 -e 300377728 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-300645644-v4.0.0 -y 5 -m 2000000 -e 300645644 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-300648964-v4.0.0 -y 5 -m 2000000 -e 300648964 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-301359740-v4.0.0 -y 5 -m 2000000 -e 301359740 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257181032-v4.0.0 -y 3 -m 2000000 -e 257181035 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257047660-v4.0.0 -y 3 -m 2000000 -e 257047662 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257047659-v4.0.0 -y 3 -m 2000000 -e 257047660 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-308445707-v4.0.0 -y 5 -m 2000000 -e 308445711 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-307395181-v4.0.0 -y 3 -m 2000000 -e 307395190 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-308392063-v4.0.0 -y 5 -m 2000000 -e 308392063 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-350814254-v4.0.0 -y 3 -m 2000000 -e 350814284 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-311586340-v4.0.0 -y 3 -m 2000000 -e 311586380 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-281546597-v4.0.0 -y 3 -m 2000000 -e 281546597 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-324823213-v4.0.0 -y 4 -m 2000000 -e 324823214 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-325467935-v4.0.0 -y 4 -m 2000000 -e 325467935 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-283927487-v4.0.0 -y 3 -m 2000000 -e 283927497 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-321168308-v4.0.0 -y 3 -m 2000000 -e 321168308 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-327324660-v4.0.0 -y 4 -m 2000000 -e 327324660 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-370199634-v4.0.0 -y 3 -m 200000 -e 370199634 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-330219081-v4.0.0 -y 4 -m 2000000 -e 330219082 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-372721907-v4.0.0 -y 3 -m 2000000 -e 372721910 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-331691646-v4.0.0 -y 4 -m 2000000 -e 331691647 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-378683870-v4.0.0 -y 3 -m 2000000 -e 378683872 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-380592002-v4.0.0 -y 3 -m 2000000 -e 380592006 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-336218682-v4.0.0 -y 5 -m 2000000 -e 336218683
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-340269866-v4.0.0 -y 5 -m 2000000 -e 340269872
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-340272018-v4.0.0 -y 5 -m 2000000 -e 340272023
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-390056400-v4.0.0 -y 10 -m 2000000 -e 390056406
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-346556000-v4.0.0 -y 3 -m 2000000 -e 346556337 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-346179946-v4.0.0 -y 30 -m 90000000 -e 346179950 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-bpf-loader-v4.0.0 -y 1 -m 1000 -e 108 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l local-multi-boundary-v4.0.0 -y 1 -m 1000 -e 2325 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l genesis-v4.0.0 -y 1 -m 3000 -e 1352 -g -lt --funk
src/flamenco/runtime/tests/run_ledger_backtest.sh -l localnet-stake-v4.0.0 -y 1 -m 3000 -e 541 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-413869565-v4.0.0 -y 40 -m 100000000 -e 413869600 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-376969880-v4.0.0 -y 1 -m 2000000 -e 376969880
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-422969842-v4.0.0 -y 1 -m 2000000 -e 422969848 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-384169347-v4.0.0 -y 1 -m 2000000 -e 384169377 --root-distance 32 --max-live-slots 64
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-384395810-v4.0.0 -y 3 -m 2000000 -e 384395820
src/flamenco/runtime/tests/run_ledger_backtest.sh -l breakpoint-385786458-v4.0.0 -y 1 -m 2000000 -e 385786458
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-386300256-v4.0.0 -y 1 -m 2000000 -e 386300289 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-387596258-v4.0.0 -y 1 -m 2000000 -e 387596373
src/flamenco/runtime/tests/run_ledger_backtest.sh -l deployment-before-boundary-v4.0.0 -y 1 -m 1000 -e 75
src/flamenco/runtime/tests/run_ledger_backtest.sh -l vote-stake-scenarios-v4.0.0-alpha.0 -y 1 -m 10000
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-391824000-boundary -y 2 -m 2000000 -e 391824016

# Direct mapping has 3 different interplaying feature gates:
# syscall_parameter_address_restrictions, virtual_address_space_adjustments and account_data_direct_mapping
# account_data_direct_mapping is dependent on virtual_address_space_adjustments,
# which is in turn dependent on syscall_parameter_address_restrictions.
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-368528500-direct-mapping-3 -y 3 -m 2000000 -e 368528501 -o EDGMC5kxFxGk4ixsNkGt8bW7QL5hDMXnbwaZvYMwNfzF,7VgiehxNxu53KdxgLspGQY8myE6f7UokaWa4jsGcaSz
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-368528500-direct-mapping-4 -y 3 -m 2000000 -e 368528501 -o EDGMC5kxFxGk4ixsNkGt8bW7QL5hDMXnbwaZvYMwNfzF,7VgiehxNxu53KdxgLspGQY8myE6f7UokaWa4jsGcaSz,CR3dVN2Yoo95Y96kLSTaziWDAQT2MNEpiWh5cqVq2pNE
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-368528500-direct-mapping-5 -y 3 -m 2000000 -e 368528501 -o EDGMC5kxFxGk4ixsNkGt8bW7QL5hDMXnbwaZvYMwNfzF
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-362107883-direct-mapping-3 -y 1 -m 2000000 -e 362219427 -o EDGMC5kxFxGk4ixsNkGt8bW7QL5hDMXnbwaZvYMwNfzF,7VgiehxNxu53KdxgLspGQY8myE6f7UokaWa4jsGcaSz,CR3dVN2Yoo95Y96kLSTaziWDAQT2MNEpiWh5cqVq2pNE

# Local cluster ledgers testing specific feature gates
src/flamenco/runtime/tests/run_ledger_backtest.sh -l localnet-deprecate-rent-exemption-threshold-v4.0.0 -y 1 -m 1000 -e 260 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l relax-intrabatch-account-locks-v4.0.0 -y 1 -m 1000 -e 240
src/flamenco/runtime/tests/run_ledger_backtest.sh -l vote-states-v4-local-v4.0.0 -y 1 -m 3000 -e 1000 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l limit_instruction_accounts_rekey -y 1 -m 1000 -e 275
src/flamenco/runtime/tests/run_ledger_backtest.sh -l enshrine_slashing_program -y 1 -m 1000 -e 260
src/flamenco/runtime/tests/run_ledger_backtest.sh -l create_account_allow_prefund -y 1 -m 1000 -e 520
src/flamenco/runtime/tests/run_ledger_backtest.sh -l relax_programdata_account_check_migration -y 1 -m 1000 -e 260
src/flamenco/runtime/tests/run_ledger_backtest.sh -l replace_spl_token_with_p_token -y 1 -m 1000 -e 720
src/flamenco/runtime/tests/run_ledger_backtest.sh -l syscall-parameter-address-restrictions -y 1 -m 1000 -e 312
src/flamenco/runtime/tests/run_ledger_backtest.sh -l virtual-address-space-adjustments -y 1 -m 1000 -e 819
src/flamenco/runtime/tests/run_ledger_backtest.sh -l account-data-direct-mapping -y 1 -m 1000 -e 1395
src/flamenco/runtime/tests/run_ledger_backtest.sh -l enable_sbpf_v3_deployment_and_execution -y 1 -m 1000 -e 961
src/flamenco/runtime/tests/run_ledger_backtest.sh -l upgrade_bpf_stake_program_to_v5 -y 1 -m 1000 -e 586
src/flamenco/runtime/tests/run_ledger_backtest.sh -l delay-comission-updates-7 -y 1 -m 10000 -e 1596
src/flamenco/runtime/tests/run_ledger_backtest.sh -l delay-comission-updates-8 -y 1 -m 10000 -e 1596
src/flamenco/runtime/tests/run_ledger_backtest.sh -l vat-activation -y 1 -m 10000 -e 540
src/flamenco/runtime/tests/run_ledger_backtest.sh -l enable_bls12_381_syscall -y 1 -m 1000 -e 379
