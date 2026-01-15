#!/bin/bash
set -e

# Notes:
# - snapshot lthash has been enabled for all tests (except for those
#   where the original lthash is wrong - as documented below)
# - vinyl is enabled only on an arbitrary subset of tests for now.
#   TODO expand.

src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-519-v3.0.0 -y 3 -m 2000000 -e 255312007 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-519-v3.0.0 -y 3 -m 2000000 -e 255312007 -lt --vinyl
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257066033-v3.0.0 -y 3 -m 2000000 -e 257066038 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257066844-v3.0.0 -y 3 -m 2000000 -e 257066849 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257067457-v3.0.0 -y 3 -m 2000000 -e 257067461 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257068890-v3.0.0 -y 3 -m 2000000 -e 257068895 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257181622-v3.0.0 -y 3 -m 2000000 -e 257181624 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-254462437-v3.0.0 -y 16 -m 10000000 -e 254462598 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-262654839-v3.0.0 -y 3 -m 10000000 -e 262654840 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257037451-v3.0.0 -y 3 -m 2000000 -e 257037454 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257035225-v3.0.0 -y 4 -m 2000000 -e 257035233 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257465453-v3.0.0 -y 4 -m 10000000 -e 257465454 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257058865-v3.0.0 -y 3 -m 2000000 -e 257058870 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257059815-v3.0.0 -y 3 -m 2000000 -e 257059818 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257061172-v3.0.0 -y 3 -m 2000000 -e 257061175 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257222682-v3.0.0 -y 3 -m 2000000 -e 257222688 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-264890264-v3.0.0 -y 3 -m 2000000 -e 264890265 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257229353-v3.0.0 -y 4 -m 2000000 -e 257229357 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257257983-v3.0.0 -y 3 -m 2000000 -e 257257986 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267728520-v3.0.0 -y 3 -m 2000000 -e 267728522 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267651942-v3.0.0 -y 3 -m 2000000 -e 267651943 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267081197-v3.0.0 -y 3 -m 2000000 -e 267081198 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267085604-v3.0.0 -y 3 -m 2000000 -e 267085605 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-265688706-v3.0.0 -y 3 -m 2000000 -e 265688707 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-265688706-v3.0.0 -y 3 -m 2000000 -e 265688707 -lt --vinyl
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-265330432-v3.0.0 -y 3 -m 2000000 -e 265330433 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-268575190-v3.0.0 -y 3 -m 2000000 -e 268575191 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-268129380-v3.0.0 -y 3 -m 2000000 -e 268129380 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-268163043-v3.0.0 -y 3 -m 2000000 -e 268163043 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-269511381-v3.0.0 -y 3 -m 2000000 -e 269511381 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-269567236-v3.0.0 -y 3 -m 2000000 -e 269567236 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-266134813-v3.0.0 -y 3 -m 2000000 -e 266134814 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-266545736-v3.0.0 -y 3 -m 2000000 -e 266545737 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267059180-v3.0.0 -y 3 -m 2000000 -e 267059181 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267580466-v3.0.0 -y 3 -m 2000000 -e 267580467 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-268196194-v3.0.0 -y 3 -m 2000000 -e 268196195 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-267766641-v3.0.0 -y 3 -m 2000000 -e 267766642 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-269648145-v3.0.0 -y 3 -m 2000000 -e 269648146 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-281688085-v3.0.0 -y 3 -m 2000000 -e 281688086 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-277660422-v3.0.0 -y 3 -m 2000000 -e 277660423 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-277876060-v3.0.0 -y 3 -m 2000000 -e 277876061 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-277927063-v3.0.0 -y 3 -m 2000000 -e 277927065 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-281375356-v3.0.0 -y 3 -m 2000000 -e 281375359 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-251418170-v3.0.0 -y 5 -m 2000000 -e 251418233 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-282232100-v3.0.0 -y 3 -m 2000000 -e 282232101 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-282151715-v3.0.0 -y 3 -m 2000000 -e 282151717 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-286450148-v3.0.0 -y 3 -m 2000000 -e 286450151 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-epoch-per-200-v3.0.0 -y 1 -m 2000000 -e 984 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-epoch-per-300-v3.0.0 -y 1 -m 2000000 -e 984 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-epoch-per-500-v3.0.0 -y 1 -m 2000000 -e 984 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-epoch-per-500-v3.0.0 -y 1 -m 2000000 -e 984 -lt --vinyl
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-297489336-v3.0.0 -y 3 -m 2000000 -e 297489363 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-300377724-v3.0.0 -y 5 -m 2000000 -e 300377728 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-300645644-v3.0.0 -y 5 -m 2000000 -e 300645644 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-300648964-v3.0.0 -y 5 -m 2000000 -e 300648964 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-301359740-v3.0.0 -y 5 -m 2000000 -e 301359740 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257181032-v3.0.0 -y 3 -m 2000000 -e 257181035 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257047660-v3.0.0 -y 3 -m 2000000 -e 257047662 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257047659-v3.0.0 -y 3 -m 2000000 -e 257047660 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-308445707-v3.0.0 -y 5 -m 2000000 -e 308445711 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-307395181-v3.0.0 -y 3 -m 2000000 -e 307395190 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-308392063-v3.0.0 -y 5 -m 2000000 -e 308392090 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-350814254-v3.0.0 -y 3 -m 2000000 -e 350814284 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-311586340-v3.0.0 -y 3 -m 2000000 -e 311586380 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-281546597-v3.0.0 -y 3 -m 2000000 -e 281546597 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-324823213-v3.0.0 -y 4 -m 2000000 -e 324823214 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-325467935-v3.0.0 -y 4 -m 2000000 -e 325467936 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-283927487-v3.0.0 -y 3 -m 2000000 -e 283927497 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-321168308-v3.0.0 -y 3 -m 2000000 -e 321168308 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-327324660-v3.0.0 -y 4 -m 2000000 -e 327324660 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-370199634-v3.0.0 -y 3 -m 200000 -e 370199634 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-370199634-v3.0.0 -y 3 -m 200000 -e 370199634 -lt --vinyl
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-330219081-v3.0.0 -y 4 -m 2000000 -e 330219082 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-372721907-v3.0.0 -y 3 -m 2000000 -e 372721910 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-331691646-v3.0.0 -y 4 -m 2000000 -e 331691647 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-378683870-v3.0.0 -y 3 -m 2000000 -e 378683872 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-380592002-v3.0.0 -y 3 -m 2000000 -e 380592006 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-336218682-v3.0.0 -y 5 -m 2000000 -e 336218683
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-340269866-v3.0.0 -y 5 -m 2000000 -e 340269872
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-340272018-v3.0.0 -y 5 -m 2000000 -e 340272023
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-390056400-v3.0.0 -y 10 -m 2000000 -e 390056406
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-346556000 -y 3 -m 2000000 -e 346556337 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-346179946 -y 30 -m 90000000 -e 346179950 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l multi-bpf-loader-v3.0.0 -y 1 -m 1000 -e 108 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l local-multi-boundary -y 1 -m 1000 -e 2325 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l local-multi-boundary -y 1 -m 1000 -e 2325 -lt --vinyl
src/flamenco/runtime/tests/run_ledger_backtest.sh -l genesis-v3.0 -y 1 -m 3000 -e 1280 -g -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l localnet-stake-v3.0.0 -y 1 -m 3000 -e 541 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-368528500-stricter-abi -y 5 -m 2000000 -e 368528527 -o sD3uVpaavUXQRvDXrMFCQ2CqLqnbz5mK8ttWNXbtD3r
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-368528500-direct-mapping -y 5 -m 2000000 -e 368528527 -o sD3uVpaavUXQRvDXrMFCQ2CqLqnbz5mK8ttWNXbtD3r,DFN8MyKpQqFW31qczcahgnnxcAHQc6P94wtTEX5EP1RA
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-362107883-direct-mapping-2 -y 1 -m 2000000 -e 362219427 -o sD3uVpaavUXQRvDXrMFCQ2CqLqnbz5mK8ttWNXbtD3r,DFN8MyKpQqFW31qczcahgnnxcAHQc6P94wtTEX5EP1RA
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-413869565 -y 40 -m 100000000 -e 413869600 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-376969880 -y 1 -m 2000000 -e 376969900
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-422969842 -y 1 -m 2000000 -e 422969848 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-376969880-r2 -y 1 -m 2000000 -e 376969900 -o 5xXZc66h4UdB6Yq7FzdBxBiRAFMMScMLwHxk2QZDaNZL
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-376969880-simd-339 -y 1 -m 2000000 -e 376969900 -o H6iVbVaDZgDphcPbcZwc5LoznMPWQfnJ1AM7L1xzqvt5
src/flamenco/runtime/tests/run_ledger_backtest.sh -l breakpoint-385786458 -y 1 -m 2000000 -e 385786458
src/flamenco/runtime/tests/run_ledger_backtest.sh -l localnet-deprecate-rent-exemption-threshold -y 1 -m 1000 -e 260 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l localnet-static-instruction-limit -y 1 -m 1000 -e 191 -lt
src/flamenco/runtime/tests/run_ledger_backtest.sh -l vote-states-v4-local -y 1 -m 3000 -e 1000 -lt
