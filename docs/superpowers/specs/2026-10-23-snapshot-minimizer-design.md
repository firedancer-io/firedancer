# Snapshot minimizer design

Date: 2026-10-23.  Repos: firedancer main 057fe146f, agave master
46a6217aad.  Research notes with file and line references live in the
worker directory next to this checkout
(`minimizer-research-synthesis.md`, `minimizer-research-full.json`).

## 1. What this is

A new command that turns a bank hash mismatch into a small ledger that
replays the mismatch in seconds:

    firedancer-dev snapshot-minimize --ledger <dir> --start-slot S --end-slot E --out <dir>

Names used below, always with the same meaning:

    X   slot of the snapshot in the ledger dir we boot from (full, or full + incremental)
    S   slot of the minimized snapshot we write;  X <= S
    E   last slot the minimized ledger will replay;  S < E
    B   the bad slot from the mismatch log;  S < B <= E

Input is a ledger directory as the backtest already uses it: one full
snapshot (plus optional incremental), `shreds.pcapng.zst` or `rocksdb/`,
and `genesis.bin`.  Output is a new ledger directory with
`snapshot-S-<hash>.tar.zst`, a shredcap trimmed to slots S..E, and
`genesis.bin`.  `run_ledger_backtest.sh -l <out> -e E` then reproduces
the mismatch.

## 2. Why

Today a minimized ledger needs an Agave checkout, a RocksDB ledger,
`agave-ledger-tool create-snapshot --minimized`, and `blockstore_minify`.
Agave replays X..S in Agave, then shrinks and purges its whole accounts
database.  That takes hours and lots of memory, and the script that drove
it (`contrib/offline-replay/run_offline_replay_backtest.sh`) was deleted
on 2026-09-16.  We already have the fastest replayer for X..S: the
backtest.  The minimizer reuses it and writes only the accounts we keep.

Agave's tool also has gaps we fix on purpose: it keeps slot S's storage
and write cache by accident (that is the only reason the `alpenclock`
account survives), it leaves out fee collectors and rotated leader
identities, and its output diverges when a new epoch starts inside
S+1..E because capitalization is rewritten to the kept sum.

## 3. Goals, non-goals, anti-goals

Goals
- Same bank hash at every slot S+1..E as the full ledger, including when
  a new epoch starts inside that span.
- Minutes, not hours: replay X..S at backtest speed, then write only the
  kept accounts.  No walk over the whole accounts database.
- Firedancer only.  No Agave, no RocksDB library.  Runs on any box that
  can run a backtest.
- Output loads in Firedancer.  It also loads in Agave once anza-xyz/agave
  PR 15834 lands, with `--accounts-db-skip-initial-hash-calculation`
  (Agave's own minimized snapshots need the same flag).
- Smaller than Agave's output.  Stake accounts are kept only when the
  span needs them.

Non-goals
- Producing a snapshot at an S that is not reachable from the ledger's
  snapshot by replay.  S must satisfy X <= S and the shredcap must cover
  X+1..E.
- Accounts that only slots after E would touch.  The recorder sees
  exactly what S+1..E load, including lookup tables extended by CPI,
  which Agave's scan misses.
- Checking that the output reproduces the mismatch.  That is a separate
  backtest run on the output.
- Hooking the command into the offline-replay service.  First version is
  the command only.

Anti-goals
- Any change to the snapshot loader to make the file load.  The output
  must pass the normal checks.
- Recomputing the lt hash.  Every Alpenglow block footer carries the real
  bank hash and replay refuses a different one.
- New memory or state in the full client.  Everything here lives in the
  backtest topology only.

## 4. Facts the design rests on

Checked against the code on 2026-10-23, then re-checked by an
independent review.

Backtest
- The backtest reads only shredcap (`src/discof/backtest/fd_backtest_src.c`).
  RocksDB is converted by `contrib/blockstore/blockstore2shredcap`, which
  `run_ledger_backtest.sh` builds on demand and which already takes
  `--start-slot` and `--end-slot`.  The capture must start at a slot <= S
  or the backt tile stops with "Snapshot too old for ledger"
  (`fd_backtest_tile.c:393-397`).
- Replay checks the footer's bank hash first (`fd_replay_tile.c:1797-1836`)
  and marks the bank dead on mismatch; the backt tile turns a dead slot
  into a fatal error (`fd_backtest_tile.c:439-449`) and compares good
  slots against the shredcap record (`:471-482`).  So executing B kills
  the run.  Both need the original hash chain.
- The backt tile roots a slot R only after a slot >= R + root_distance
  completes (`fd_backtest_tile.c:484-492`; default 32, CI uses 2).  It
  exits when a slot >= end_slot completes or when the capture is drained
  (`:502-504`).
- The backtest topology is built three times during boot
  (`src/app/firedancer-dev/commands/backtest.c:482, :525-526`).

Loader
- Manifest capitalization must equal the exact sum of loaded lamports
  (`fd_snapin_tile.c:1831-1860`).  Clock, Rent and SlotHistory accounts
  are required (`:520-530`), StakeHistory too when EpochRewards is
  active (`:603-605`).  The feature set and the stake delegations are
  rebuilt from accounts.  The lt hash is never recomputed over the
  accounts.  A zero-lamport record is loaded and then treated as absent;
  the stake snoop skips it; it adds nothing to the sum.

Replay
- Capitalization is read in three places, all in the first slot of a new
  epoch (`fd_runtime.c:707`, `fd_rewards.c:1713`, `:1738`, `:2338-2341`).
  It is never hashed (`fd_runtime.c:1753`).
- A missing vote account does not abort: footer signers are skipped
  (`fd_alpenglow.c:341-354`, `:638`), fees are burned
  (`fd_runtime.c:249-251`), and the new epoch's stake set silently drops
  it (`fd_stakes.c:647-650`).  Each of these changes the lt hash with no
  error, which is worse than an abort.

Producer
- `ctx->snapmk.scheduled_at_slot` already exists.  An admin message sets
  it (`fd_replay_tile.c:4024-4031`), it starts as ULONG_MAX (`:4612`), and
  the snapshot fires on the first rooted bank at or after it (`:3163`).
- snapmk needs the `replay_snapmk` and `snaprd_out` links or it refuses to
  start (`fd_snapmk_tile.c:479-481`); snapzp needs its link and workspace
  too.  The incremental path never asks snaprd for anything, so snaprd
  can sit idle.
- snapmk already streams pubkey batches (`fd_backup_delta_msg_t`,
  `snapmk_accdb_delta` at `fd_snapmk_tile.c:1235-1263`) and snapzp reads
  each one at the pinned fork with `fd_accdb_read_one_nocache`
  (`fd_snapzp_tile.c:561`).  A miss is written as a zero-lamport record
  (`:566-578`).  The source is picked at `:1427`.
- `snap_start` waits until the accdb root fork equals the pinned bank's
  fork, then freezes compaction (`fd_snapmk_tile.c:1746-1757`,
  `fd_accdb.c:4543-4553`).  Reads at that fork see the state at S only
  after this point.  A readonly accdb join supports exactly
  `fd_accdb_read_one_nocache`, `fd_accdb_exists` and `fd_accdb_lamports`
  (`fd_accdb.h:119-120`).
- snapmk writes into `paths.snapshots` (`topology.c:1906`), the same
  directory the file pool is opened from (`run.c:1298-1301`) and the
  loader reads from (`topology.c:1493`).  In a backtest that is the
  ledger directory (`run_ledger_backtest.sh:235`).  Boot deletes full
  snapshots beyond `max_full_snapshots_to_keep` (`run.c:1360`), and
  snapmk recycles the oldest full when the pool is full
  (`fd_snapmk_tile.c:1640-1649`).  O_DIRECT descriptors are opened as
  soon as a snapzp tile exists and a failure is fatal (`run.c:1285`,
  `:1395-1400`).
- The tar order is version, manifest, accounts, status cache, end
  (`fd_snapmk_tile.c:1419-1510`).  The manifest copies capitalization and
  the lt hash straight from the bank (`fd_ssmanifest_encoder.c:61`,
  `:344`); the filename hash is blake3 of the lt hash (`:1744`).  Extra
  tar entries can be appended with `zip_append`, as the status cache is
  (`:710-725`).  The epoch stakes written are E-3..E+1.

Agave
- Agave ignores the manifest's storage list for archives
  (`serde_snapshot.rs:116`).  PR 15834 (open, mergeable, awaiting review)
  rebuilds vote accounts from the stored accounts and takes stake history
  from the sysvar account, removing the two manifest fields our writer
  leaves empty.
- Agave's `SnapshotMinimizer` keeps: transaction keys with lookup tables
  resolved at S, active and inactive features, reserved keys (every
  builtin, sysvar, precompile, incinerator), four SPL ids, three Alpenglow
  accounts, the stakes-cache vote and stake accounts with node pubkeys,
  owners, and programdata for every upgradeable program in the set
  (`runtime/src/snapshot_minimizer.rs:52-96`, `:186-207`).

## 5. How it works

### 5.1 Trim the block data and copy genesis

For a `rocksdb/` input the command runs `blockstore2shredcap --start-slot
S --end-slot E` straight into `<out>`; that tool already writes the bank
hash and root records.  For a pcapng input it copies the frames for slots
S..E with the pcapng writers in `src/util/net/fd_pcapng.h`, including
slot S's shreds and records so the "Snapshot too old" check passes.
`genesis.bin` is copied.  No parsing of transactions happens here.

### 5.2 Boot and replay X+1..E, root held at S

The command builds the backtest topology plus the production snapshot
block exactly as `topology.c` wires it: snapmk, N snapzp, and snaprd,
which idles.  It boots from the ledger's snapshot X (full, or full +
incremental) and replays X+1..E as a backtest does.  Periodic snapshot
intervals are zero so nothing else fires.  The pool keeps at least two
full snapshots so snapmk never recycles X.

Three things differ from a normal backtest.  First, right after the
snapshot handshake the backt tile sends replay the existing admin
request "snapshot at the first rooted slot at or after S", the same
message the admin tile sends for `snapshot-create`.  Replay needs no
new code.  Second, the backt tile hands out roots as usual for slots
below S, then stops.  Every bank from S+1 to E stays alive on top of S,
so the state at S is never changed.  At startup the command refuses to
run unless `max_live_slots >= E - S + root_distance + 2`, with that
message.  Third, a dead bank (the bad slot) is expected in this mode
and is not fatal; replay cannot build on a dead bank, so the run ends
there if B < E.

When the last slot has run, the backt tile certifies S as the root.
Replay advances its root to S and the scheduled snapshot fires on bank
S.  When S is already the boot slot X there is nothing to root, so the
backt tile sends the "snapshot the root now" form of the same admin
request instead.

### 5.3 The recorder

While slots S+1..E execute, the executor loads the accounts of every
transaction.  At that point the recorder inserts each key into one hash
set in a backtest-only workspace object: fee payer, program ids, every
instruction account, every resolved lookup table address, and the
programdata an upgradeable program points at.  Keys that do not exist at
S are inserted too; they simply have nothing to copy.  The set is sized
from the span's transaction count, one insert per account load, gated by
the mode flag so production is untouched.

### 5.4 The short list the recorder cannot see

Some accounts are read by the loader when the small ledger boots, or by
replay outside any transaction, so the recorder never sees them.  After
the last slot they are added by name, using bank S:

1.  Every feature account, active or not.  A missing one reads as
    disabled.
2.  Every vote account in every epoch-stakes set the manifest carries
    (T-3 through T+1), with its node account, block revenue collector
    and inflation rewards collector.
3.  Every sysvar account, every builtin, precompile, the native loader,
    the sysvar owner and the incinerator.
4.  The Alpenglow accounts: the genesis certificate ("carlgration"), the
    inflation state ("vote_reward_account"), the reward epoch delegated
    stakes account, and the "alpenclock" account every footer rewrites.
5.  SPL token, token-2022, associated token and native mint ids, for
    parity with Agave.
6.  Only if `epoch(E) != epoch(S)`, or the EpochRewards sysvar is active
    at S (rewards still being paid out): every stake account in bank S's
    delegation cache, and the vote account each one delegates to.
7.  Only if a feature that migrates a builtin to core BPF activates at a
    new epoch inside the span: the migration's source buffer account.

Outside case 6, stake accounts are kept only if a transaction touched
them.  That is the main size win over Agave.

Size bound: the recorder set plus 5 x 2000 vote accounts, plus the stake
delegation cache (2.15 M entries by default) when case 6 fires.  About
4 M entries, 128 MiB, in this topology only.

### 5.5 Capitalization and the balancing account

Both loaders require the file to sum to the manifest capitalization, and
the first slot of a new epoch needs the real capitalization for rewards.
So the manifest keeps bank S's capitalization untouched, and snapmk
always writes one extra account that makes the file sum to it: a
system-owned account with no data holding `capitalization - kept sum`
lamports.  Its pubkey is the sha256 of "firedancer snapshot minimizer";
one `fd_accdb_exists` check aborts if that key is somehow taken at S.
Nothing can reference the key, so it never changes and never enters the
lt hash.  The kept sum comes from one pass over the set with
`fd_accdb_lamports` at the S fork before the manifest is written.

The record is appended by snapmk with `zip_append`, the way the status
cache entry is, using one appendvec slot ticket.

### 5.6 Writing

Once replay has rooted S, snapmk pins bank S, freezes compaction, and
writes a full snapshot as today, except that
the account source is the keep set: batches go out as
`fd_backup_delta_msg_t`, snapzp reads each at the S fork, frames and
compresses.  A miss stays a zero-lamport record; the loader treats it as
absent.  Then the balancing record, the status cache, the end block.  The
lt hash is bank S's, so the filename hash is unchanged.

The file lands in the ledger directory, because snapmk, the pool and the
loader share `paths.snapshots`.  After `FD_SNAPMK_MSG_CREATED` the
command moves the file named in the message into `<out>`.  O_DIRECT must
work on the ledger directory; the command refuses up front if it does
not (tmpfs).

### 5.7 Exit

In minimize mode the backt tile does not exit on end_slot or on a
drained capture.  It listens on `snapmk_out` and exits with code 0 after
`FD_SNAPMK_MSG_CREATED` for slot S, or with a non-zero code after
`FD_SNAPMK_MSG_FAILED`.

## 6. Decisions already made

- Reuse the backtest for X..S and the producer tiles for writing.  A
  file-to-file filter was rejected because X is usually far before S and
  account states at S need execution.
- S must be reachable by replay from the ledger's snapshot.
- Keep the original lt hash and bank hash.  Never recompute.
- Balancing account instead of refusing spans with a new epoch or
  changing the loader.
- Agave-loadable output is a goal, satisfied by PR 15834 plus the hidden
  flag; no extra manifest work in this project.
- Stake accounts only when needed (new epoch in span, or rewards still
  paying at S).
- First version is the command; offline-replay integration later.

- Agreed 2026-10-23: replay X+1..E with the root held at S and record the
  accounts the blocks after S load, instead of parsing transactions out
  of the shreds before boot.  Exact, and no lookup table, programdata or
  owner logic to maintain.
- The keep set and writer live in snapmk as a mode plus a library file,
  not in a new tile.  snapmk already has every join the keep set needs.
- Replay is not modified.  The backt tile schedules the snapshot through
  the existing admin request and decides when S becomes the root.
- The balancing account is always written, so the manifest
  capitalization is never overridden.
- Misses stay zero-lamport records; no writer change for them.

## 7. Left to the builder

- Where exactly the recorder hooks in the executor (the point after
  lookup tables are resolved and programdata is checked) and how several
  execrp tiles share one set without a lock on the hot path (per-tile
  sets merged at the end are fine).
- How the keep set, the mode flag and S reach snapmk and the backt tile
  (tile config fields or a topology object).
- The pcapng trimmer for pcapng input.  The typed bank hash and root
  records are documented in `src/discof/backtest/fd_shredcap.h`; the only
  writer for them today is `blockstore2shredcap.c`, which also has a
  small zstd stream writer (`:312-348`).
- Error handling: refuse if the shredcap does not cover X+1..E, if S has
  no root record, if `<out>` exists, if E is past the capture, if
  `max_live_slots < E - S + 1`, or if O_DIRECT fails on the ledger
  directory.

## 8. Steps

Each step is one PR that builds and tests alone.

| Step | What | Rough size |
|---|---|---|
| 1 | snapmk: pubkey-array account source and the balancing record; roundtrip test in `test_snap_roundtrip.c` | ~80 lines |
| 2 | backt tile: schedule the snapshot through the admin request, hold roots at S, survive the dead slot, certify S at the end, move the file, exit on CREATED/FAILED | ~120 lines |
| 3 | recorder in the executor plus the keep-set library (boot-time list, stake rule, lamport sum), with a unit test against a loaded snapshot | ~400 lines |
| 4 | pcapng trimmer with a test on a small capture | ~150 lines |
| 5 | `firedancer-dev snapshot-minimize`: topology, arguments, checks, moving the output | ~300 lines |
| 6 | Test script: minimize a CI ledger, replay the output, compare bank hashes; README with numbers | script + README |

## 9. Verification

- Unit tests for the keep set classes against a loaded snapshot and for
  the pcapng trimmer against a small capture.
- Minimize three CI ledgers (`run_backtest_ci.sh`): one inside an epoch,
  one spanning a new epoch, one that boots full + incremental.  Replay
  the output with `run_ledger_backtest.sh -e E` and compare every bank
  hash line against the full run.
- Measure, do not assume: wall time of the X..S replay, of the keep set
  build, and of the write, on a mainnet ledger with and without case 9
  (about 1.4 M by-pubkey disk reads).  Report a table next to the
  artifacts, not in the PR.
- Load one output with `agave-ledger-tool verify
  --accounts-db-skip-initial-hash-calculation` on a build that includes
  PR 15834.
- Compare output size and run time against Agave's
  `create-snapshot --minimized` on the same ledger.
