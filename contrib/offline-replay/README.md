# Offline Replay

Continuously validates Firedancer's runtime against real cluster history.
The harness watches a Solana ledger archive bucket (mainnet/testnet/
devnet) and replays each new ledger through `firedancer-dev backtest`,
comparing Firedancer's bank hashes against the canonical ones computed
by Agave. On a mismatch or crash it uploads a minimized
reproduction ledger to `gs://firedancer-ci-resources/`, posts to Slack,
and resumes replaying past the bad slot.

## Files

| File | Purpose |
| --- | --- |
| `run_offline_replay_backtest.sh` | The harness. Infinite loop, polls the bucket hourly. |
| `offline_replay_network_parameters.sh` | Per-network settings (bucket, genesis URL, max account index). |
| `offline_replay.toml` | Firedancer config template; `{placeholder}` values are filled in per run. |

A small wrapper script (not checked in — it contains Slack webhook URLs)
exports the environment below and runs `run_offline_replay_backtest.sh`.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `FIREDANCER_REPO`, `FD_BRANCH` | Firedancer checkout and branch to test |
| `AGAVE_REPO` | Agave checkout (for `agave-ledger-tool`) |
| `NETWORK` | `mainnet`, `testnet`, or `devnet` |
| `NETWORK_PARAMETERS_FILE` | path to `offline_replay_network_parameters.sh` |
| `BILLING_PROJECT` | GCP billing project for bucket access |
| `LATEST_RUN_BUCKET_SLOT_FILE` | state file holding the last processed bucket slot |
| `SLACK_WEBHOOK_URL` | progress notifications |
| `SLACK_MISMATCH_WEBHOOK_URL` | mismatch notifications |
| `SLACK_DEBUG_WEBHOOK_URL` | debug notifications |
| `LOG_DIR` (optional) | log directory, default `/data/offline-replay/logs` |
| `AGAVE_TAG` (optional) | fallback tag if a ledger's `version.txt` is unreadable |
| `OBJDIR` (optional) | Firedancer build dir, default `build/native/gcc` |

## Deployment

Runs as the `svc_firedancer` service account on the replay machine:

| What | Where |
| --- | --- |
| Wrapper | `/home/svc_firedancer/offline_replay.sh` |
| GUI (during replay) | `http://tsewr2-ossdev-firedancer34.jumpisolated.com/` |
| Metrics (during replay) | `http://tsewr2-ossdev-firedancer34.jumpisolated.com:7999/metrics` |
| Firedancer repo | `/home/svc_firedancer/repos/firedancer` (shared checkout, writable by the whole team) |
| Agave repo | `/home/svc_firedancer/repos/agave` |
| State file | `/home/svc_firedancer/newest_bucket_slot.txt` |
| Logs | `/data/offline-replay/logs` |

GCS access uses the `firedancer-scratch@isol-firedancer` service account.

## How it works

1. Poll the bucket hourly for a slot directory newer than the one in the
   state file. Only the newest ledger is processed; since ledgers are
   uploaded roughly every two days, the hourly poll never skips one in
   practice.
2. Build the `agave-ledger-tool` version named in the ledger's
   `version.txt`.
3. Download genesis, `rocksdb.tar.zst`, and the lowest rooted snapshot
   within the rocksdb bounds.
4. Build the latest Firedancer on `$FD_BRANCH` with
   `EXTRAS=offline-replay`.
5. Convert the rocksdb into a shredcap capture
   (`fd_blockstore2shredcap`) covering the replay range; the backtest
   ingests the capture, while the rocksdb directory is kept for the
   minimization tooling.
6. Replay with `firedancer-dev backtest` up to the rocksdb rooted max. A
   pass is clean if the log contains `Backtest playback done.` and no
   `Bank hash mismatch!`.
7. On a mismatch or failure: build a minimized ledger around the bad slot
   (`fd_ledger --cmd minify` + `agave-ledger-tool create-snapshot
   --minimized`), upload it and the gzipped log to
   `gs://firedancer-ci-resources/`, then resume from a snapshot just past
   the bad slot. Gives up after more than 5 mismatches or 5 failures on
   one ledger.

## Logs

All logs live in `/data/offline-replay/logs`:

- `<network>_offline_replay_<bucket-slot>.log` — backtest output for one
  ledger. Kept for 30 days.
- `<network>_offline_replay_<bucket-slot>_harness.log` — the harness's own
  output for that ledger run (builds, downloads, git operations), with a
  timestamped `===` marker per step. Kept for 30 days.
- `harness.log` — harness output between ledger runs (startup and hourly
  bucket polls). Small and kept indefinitely.
- On every mismatch/failure the log is also gzipped and uploaded to
  `gs://firedancer-ci-resources/<network>-<slot>.log.gz`, next to the
  minimized ledger — so failures can be investigated without access to
  the replay machine.
- The backtest logs at DEBUG level, so logs can be large.

## Slack

- `$SLACK_WEBHOOK_URL` — step-by-step progress, mismatch alerts, upload
  locations, repro command.
- `$SLACK_MISMATCH_WEBHOOK_URL` — mismatch-only channel: minimized ledger
  and log uploads.
- `$SLACK_DEBUG_WEBHOOK_URL` — currently unused.

## Reproducing a mismatch

Every mismatch alert includes the exact command:

```
src/flamenco/runtime/tests/run_ledger_backtest.sh -l <network>-<slot> -m 2000000 -e <end-slot>
```

First download and extract
`gs://firedancer-ci-resources/<network>-<slot>.tar.gz` into `dump/`.

## Operational notes

- The state file must exist and contain a slot number before the first
  run.
- Export `AGAVE_TAG` in the wrapper as a fallback for ledgers with an
  unreadable `version.txt`.
- Ledgers are staged under `$FIREDANCER_REPO/dump/`; a mainnet rocksdb is
  hundreds of GB. Clean runs delete their ledger dir; mismatch ledgers
  are kept for debugging and must be cleaned up by hand.
- The harness runs `git pull` in both repos each cycle — keep the
  deployed checkouts free of uncommitted changes.
- Run it detached, e.g. `nohup ./offline_replay.sh &` — the harness
  redirects all of its own output into the log files above, so nothing
  depends on how it is launched.

## Debugging a hung backtest

If replay goes quiet (Slack stops, log stops advancing):

- `http://localhost:7999/metrics` — `replay_slot_replayed_total` and
  `link_frag_consumed_total` show which tile stalled.
- Map tile threads from log lines (`pid:tid ... fd1:[group]:tile:idx`),
  attach `gdb -p <tid>`, and break in the stuck tile's `during_credit`
  (e.g. `src/discof/backtest/fd_backtest_tile.c`).

One known trap: `genesis.tar.bz2` bundles a slot-0-only `rocksdb/`
directory. If it gets extracted, it defeats the harness's "rocksdb
already exists" check, the real rocksdb is never downloaded, and replay
idles forever with no error. This is why the harness extracts only
`genesis.bin` from the tarball — preserve that if you touch the genesis
handling.
