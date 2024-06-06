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
      - If they are not specified (recommended), the check range is `[first_rooted(max(snap, rocksdb_min)), last_rooted(rocksdb_max)]`
      - The replay looks for a mismatch from start_slot toward end_slot, until it encounters a mismatch. Then, it would start again from mismatch+1, repeating the cycle.
      - Depending on where these bank hash mismatches are encountered, a possible list of snapshots might look like `[range_start, Abhm, range_end], (Abhm, Bbhm, range_end], ... (Ybhm, Zbhm, range_end]` which translates into the uploads `[Abhm-1, Abhm+1], [Bbhm-1, Bbhm+1], ..., [Zbhm-1, Zbhm+1]`
    - `--repetitions multiple --mode exact --rep-sz 100`:
      - Breaks the ledger up into multiple repetitions of the specified size. solana-ledger-tool has some issues with minimizing larger ledgers.
      - Passing --rep-sz is only recommended if the ledger to minimize into is too large, since this takes additional time to run.
      - This has the same output as running without --rep-sz, but breaks the process up into multiple iterations of some rep size.
      - For example, running this against a ledger with rocksdb bounds of size S, will break into chunks `[first_rooted(start_slot), last_rooted(start_slot + S/n - 1)], [first_rooted(start_slot + S/n), last_rooted(start_slot + 2S/n - 1)]` ...
      - Following, each of these chunks might have their own set of bank hash mismatches `[first_rooted(start_slot), ABhm, Bbhm, Cbhm .... last_rooted(start_slot + S/n - 1)]`

### Examples

To fetch the latest testnet ledger and find all bank hash mismatches:

```
./ledger_conformance.sh all --network testnet --mode exact --repetitions multiple --rep-sz 100 --ledger PATH_TO_LEDGER --ledger-min PATH_TO_LEDGER_MIN --solana-build-dir PATH_TO_SOLANA_TARGET_RELEASE_DIR --firedancer-root-dir PATH_TO_FIREDANCER_ROOT_DIR
```

If you already have an existing ledger to start from, append `--no-fetch`

```
./ledger_conformance.sh all --network testnet --mode exact --repetitions multiple --rep-sz 100 --ledger PATH_TO_LEDGER --ledger-min PATH_TO_LEDGER_MIN --solana-build-dir PATH_TO_SOLANA_TARGET_RELEASE_DIR --firedancer-root-dir PATH_TO_FIREDANCER_ROOT_DIR --no-fetch
```
