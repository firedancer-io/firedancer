#!/bin/bash
set -e

src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-308392063-no-rent -s snapshot-308392062-FDuB6CFKod14xGRGmdiRpQx2uaKyp3GDkyai2Ba7eH8d.tar.zst -y 5 -m 2000000 -e 308392090 -c 2.1.14
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-350814254-no-rent -s snapshot-350814253-G5P3eNtkWUGkZ8b871wvf6d78wYxBJp637PCWJuQByZa.tar.zst -y 2 -m 1000000 -e 350814284 -c 2.1.14
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-281546597-no-rent -s snapshot-281546592-5jvGg895YBu829SzrJA4rrExcLSpY1MgVwQshNcJX5EB.tar.zst -y 3 -m 2000000 -e 281546597 -c 2.0.23
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-324823213-no-rent -s snapshot-324823212-sk3zF16dk7gEsgLf1mGDhj6qRp87kFjJdEWZmhr4Kju.tar.zst -y 4 -m 2000000 -e 324823214 -c 2.0.23
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-325467935-no-rent -s snapshot-325467934-DDmw2omWPAPKueV2n3ggx3VtesR7h7smx8PMwssWVbBy.tar.zst -y 4 -m 2000000 -e 325467936 -c 2.1.14
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-283927487-no-rent -s snapshot-283927486-7gCbg5g4BnD9SkQUjpHvhepWsQTpo2WaZaA5bhcNBMhG.tar.zst -y 3 -m 2000000 -e 283927497 -c 2.0.23
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-321168308 -s snapshot-321168307-DecxjCHDsiQgbqZPHptgz1tystKi3QmV3Rd3QEgcxs2W.tar.zst -y 3 -m 2000000 -e 321168308 -c 2.1.13
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-327324660 -s snapshot-327324659-85G1Hp5JsY1EiixLgFk1VRacP9bu1EGczBunvuJWgMDw.tar.zst -y 4 -m 2000000 -e 327324660 -c 2.1.14
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-370199634 -s snapshot-370199633-D8mrtzcNV8iNVarHs4mi55QHrCfmzDScYL8BBYXUHAwW.tar.zst -y 2 -m 1000000 -e 370199634 -c 2.1.14
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-378683870 -s snapshot-378683869-7iuK12gAgSaB97WbmiTb4QPVbnqfFWCtq9F6CvfSgBj5.tar.zst -y 2 -m 2000000 -e 378683872 -c 2.1.14
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-330219081 -s snapshot-330219080-2QzJWhxjNohZR2xeeFDkxt2UcdvSKZ8HhXaFdRXwg8iC.tar.zst -y 4 -m 2000000 -e 330219086 -c 2.1.14
src/flamenco/runtime/tests/run_ledger_backtest.sh -l devnet-372721907 -s snapshot-372721906-FtUjok2JfLPwJCRVcioV12M8FWbbJaC91XEJzm4eZy53.tar.zst -y 2 -m 2000000 -e 372721910 -c 2.1.14
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-331691646 -s snapshot-331691639-3NmZ4rd7nHfn6tuS4E5gUfAwWMoBAQ6K1yntNkyhPbrb.tar.zst -y 4 -m 2000000 -e 331691650  -c 2.1.14
src/flamenco/runtime/tests/run_ledger_backtest.sh -l mainnet-257039990-no-rent-per -s snapshot-257039990-BSgErEc6ppN4p91meqPvUiXPiEhbakBNHMQQ4wKmceYv.tar.zst -y 5 -m 10000000 -e 257040003 -c 2.1.14
src/flamenco/runtime/tests/run_ledger_backtest.sh -l testnet-336218682 -s snapshot-336218681-BDsErdHkqa5iQGCNkSvQpeon8GLFsgeNEkckrMKboJ4N.tar.zst -y 3 -m 2000000 -e 336218683  -c 2.2.14
