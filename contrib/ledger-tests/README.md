# Ledger Conformance CLI Tool

### Description

This ledger test CLI tool `ledger_conformance.sh` provides a command line interface to consolidate bank hash mismatch debugging operations. It currently manages operations like fetching, minimizing, replaying and uploading ledgers.

### Usage

### Subcommands and key options

This section lists some subcommands and their key options. For full options, run `./ledger_conformance.sh SUBCOMMAND`

- `fetch-recent`
  - Initialize the ledger tests by fetching a recent ledger.
- `minify`
  - Minimize a recent ledger for bank hash mismatches.
  - Options:
    - `--mode edge`: Minimize around an epoch edge with some offset.
    - `--mode exact`: Minimize around a specific [start_slot, end_slot].
- `replay`
  - Replay the minimized ledger to check for bank hash mismatches and upload the minimized one block ledger to the cloud storage.
- `solcap`
  - Produce a diff between firedancer and solana labs solcaps.
- `all`
  - Run all commands - fetch-recent, minify, replay in sequence.
  - In the `all` subcommand, bounds are checked if rooted, if not it searches for a bound that is rooted.
  - Options:
    - `--no-fetch`: Run all the commands excluding fetch-recent. Just pass in the ledger directories.
    - `--repetitions once --mode edge|exact`: Run the full cycle of commands once.
    - `--repetitions multiple --mode exact`:
      - Replay the entire ledger in multiple iterations.
      - `--start-slot` and `--end-slot` define the absolute bounds to replay the ledger.
      - If start_slot and end_slot are not specified (recommended), the check range is `[first_rooted(max(snap, rocksdb_min)), last_rooted(rocksdb_max)]`
      - The replay looks for a mismatch from `start_slot` toward `end_slot`, until it encounters a mismatch.
      - Then it would repeat the cycle, starting from the next hourly snapshot after mismatch+1. The snapshot is skipped if the first slot is not rooted.

### Examples

To fetch the latest mainnet ledger and find all bank hash mismatches:

```
./ledger_conformance.sh all \
        --network mainnet \
        --repetitions multiple \
        --ledger $PATH_TO_LEDGER \
        --ledger-min $PATH_TO_LEDGER_MIN \
        --solana-build-dir $PATH_TO_SOLANA_TARGET_RELEASE_DIR \
        --firedancer-root-dir $PATH_TO_FIREDANCER_ROOT_DIR \
        --gigantic-pages 750 \
        --index-max 700000000 \
        --upload $UPLOAD_URL
```

If you already have an existing ledger to start from at $PATH_TO_LEDGER, append `--no-fetch`:

```
./ledger_conformance.sh all \
        --network testnet \
        --repetitions multiple \
        --ledger $PATH_TO_LEDGER \
        --ledger-min $PATH_TO_LEDGER_MIN \
        --solana-build-dir $PATH_TO_SOLANA_TARGET_RELEASE_DIR \
        --firedancer-root-dir $PATH_TO_FIREDANCER_ROOT_DIR \
        --upload $UPLOAD_URL \
        --no-fetch
```
