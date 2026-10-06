# Instant Boot

## What It Does

Instant boot lets a new Firedancer validator start executing live
blocks within seconds, instead of waiting for a snapshot to load
first. It works by taking the accounts it needs from a running
Firedancer validator's stream, and replaying blocks from there right
away. The normal snapshot load still runs in the background at the
same time. Nothing from that snapshot is trusted, and the booting
validator won't advance its root or take a leader slot, until the
background load finishes. Instant boot is opt-in on both validators
and off by default.

## Requirements

- Both validators have to be Firedancer. There is no cross-client
  support.
- The serving validator needs snapshot production on, with
  incremental snapshots: `[layout] enable_snapshot_production = true`
  (off by default; its own comment currently warns this feature isn't
  supported yet) and `[snapshots] incremental_snapshot_interval_blocks`
  nonzero (`200` by default). It also needs `[snapshots.server]
  enabled = true`, the snapshot file server. A stream starts every
  time this validator makes a new incremental snapshot, except across
  an epoch boundary (see Known Limits).
- The booting validator needs `[snapshots] incremental_snapshots =
  true` (the default) and the serving validator's address. Under
  instant boot, it ignores any local snapshot files and any other
  configured snapshot peers or sources: its only snapshot source is
  the instant boot server, at the slot the stream started at.

## Configuration

These are the keys instant boot adds, under `[snapshots.instant_boot]`:

| Key | Side | Default | Notes |
|---|---|---|---|
| `[snapshots.instant_boot] enabled` | Booting | `false` | Turns on instant boot. |
| `[snapshots.instant_boot] server` | Booting | `""` | Serving validator's address, `host:port` or `http://host:port`. Has to be a plain IPv4 address in practice (see Known Limits). |
| `[snapshots.instant_boot.serve] enabled` | Serving | `false` | Turns on boot streams. Needs `[snapshots.server] enabled = true`. |
| `[snapshots.instant_boot.serve] stream_lifetime_seconds` | Serving | `240` | How long a stream is served before it's closed and recycled. Must be more than the client's fixed 180 second join floor; the margin above it is how long a client has to find the stream. |
| `[snapshots.instant_boot.serve] max_open_streams` | Serving | `3` | How many streams are served at once (1 to 8). |
| `[snapshots.instant_boot.serve] max_keys_per_stream` | Serving | `4000000` | How many accounts one stream can carry. The tile rounds this up to a power of two, `4,194,304` at the default, and keeps 40 bytes per entry, which is 160 MiB of the 225 MiB a stream costs. A stream closes once it has carried three quarters of those entries, `3,145,728` at the default. |

## Enable the Serving Side

Set `[layout] enable_snapshot_production = true` with a nonzero
`[snapshots] incremental_snapshot_interval_blocks`, `[snapshots.server]
enabled = true`, and `[snapshots.instant_boot.serve] enabled = true`.

### Memory

All of it is taken at startup, whether or not a stream is ever
opened. With the defaults that is **985 MiB**:

| Part | Bytes | MiB | Scales with |
|---|---|---|---|
| Account sets of the blocks the tile keeps | 103,809,024 | 99.0 | fixed (192 blocks of 528 KiB) |
| Account read buffer | 10,485,760 | 10.0 | fixed |
| Compression buffer | 4,194,304 | 4.0 | fixed |
| Accounts and status cache joins, writer state | 70,068,224 | 66.8 | `[runtime] max_live_slots`, `[limits] max_txn_per_slot` |
| Open streams, 3 x 236,251,136 | 708,753,408 | 675.9 | `max_open_streams`, and `max_keys_per_stream` within it |
| `replay_strmk` data ring | 134,225,920 | 128.0 | fixed (32,770 x 4,096 byte frags) |
| `replay_strmk` descriptor ring | 1,048,576 | 1.0 | fixed |
| **Total** | **1,032,585,216** | **984.8** | |

The first four rows and the stream rows are the stream tile's own
workspace; `replay_strmk` is a workspace of its own, which the replay
tile writes and the stream tile reads.

A stream's 225.3 MiB is a 64 MiB write buffer, the 160 MiB
sent-account table, a 1.24 MiB compressor and a 64 KiB record of the
blocks it has carried. Only that part moves when you change the
settings: three streams is 675.9 MiB of it, one stream is 225.3 MiB.

## Enable the Booting Side

Set `[snapshots.instant_boot] enabled = true` and `server` to the
serving validator's address and port, for example `server =
"10.0.0.5:8902"` (the same port `[snapshots.server]` listens on).

## What to Expect in the Logs

### On the Serving Node

1. A stream opens at the slot the validator just rooted:
   `boot stream at slot %lu opened in %ld millis (%lu bytes, %lu accounts)`
2. Once the matching incremental snapshot file exists, the stream is
   listed so a client can find it:
   `serving the boot stream at slot %lu`

### On the Booting Node

1. The stream downloader finds and joins a listed stream. This is
   logged at `INFO`, so it goes to the log file but not the console
   by default:
   `joining the instant boot stream for slot %lu at %s`
2. The snapshot control tile starts downloading the matching full and
   incremental snapshot pair from the same server:
   `downloading the %s snapshot for stream slot %lu from the instant boot server %s%s%s`
3. Once the stream's manifest and status cache are processed, replay
   starts executing new blocks, even though the background snapshot
   load is still running. Also logged at `INFO`:
   `replay ready at slot %lu (%.3f s after snapshot done, %.3f s since boot)`
   ("snapshot done" here means the stream's manifest and status
   cache, not the background load — that is the whole point of
   instant boot.)
4. The background snapshot load finishes:
   `loaded %s accounts %s(%s dups)%s from snapshot in %.3f seconds`
   followed by:
   `instant boot: snapshot load finished, stake state complete`
5. The stream downloader leaves the stream, since there is nothing
   left to load:
   `background snapshot load is done, leaving the instant boot stream`

## How to Confirm It Worked

Compare the time of the first `replay ready at slot %lu` line (the one
with a real slot number, not `0`) against the time of the `loaded ...
accounts ... from snapshot in ... seconds` line. Both are in the
booting validator's own log. If instant boot worked, `replay ready`
comes first, by close to the time a snapshot load normally takes
(around a minute).

Three internal counters exist for this (`instant_boot_slot`,
`instant_boot_done`, `instant_boot_pick`), but they are plumbing
between tiles, not metrics. They are not exposed anywhere an operator
can read today.

## Known Limits and Failure Behavior

- Any stream failure after it starts kills the booting validator, for
  example: `instant boot: boot stream failed upstream, restart with
  instant boot disabled`. Restart with `[snapshots.instant_boot]
  enabled = false` to boot normally.
- If the stream's starting slot falls right at the start of a new
  epoch, or a rewards payout is running at that slot, replay pauses
  there until the background load finishes. There is no separate log
  line for this, just a pause.
- **A stream never spans an epoch boundary.** An epoch boundary and an
  epoch rewards payout credit stake accounts that no transaction names,
  so the serving validator cannot carry those accounts in a stream. It
  resets the feed at the boundary, closing every open stream:
  `resetting the boot streams: a block crosses an epoch boundary or an
  epoch rewards payout`. It also starts no new stream while the
  condition holds. A validator that joined a stream within a lifetime
  of a boundary therefore sees its stream break, the same as any other
  reset, and has to restart against the next incremental snapshot once
  the boundary is past.

  The reset is also why the serving node logs a refusal for the first
  incremental snapshots after a boundary: `not starting a boot stream
  at slot %lu: slot %lu already ran and the blocks that follow it are
  not kept`. The reset threw away the blocks the tile keeps, so it
  cannot cover the gap between the snapshot's slot and the blocks
  running now. Once enough blocks have run for the retention to reach
  back that far again, the next incremental snapshot starts a stream
  normally. The same line shows up after any other reset, for the same
  reason.
- A listed stream stays open for `stream_lifetime_seconds` (240
  seconds by default). The booting validator only joins a stream with
  at least 180 seconds of life left (fixed, not configurable), so it
  has to pick one up within about a minute of it being listed. If no
  usable stream turns up within 5 minutes, it gives up fatally:
  `no boot stream offered for 300 s`. The `expires` field in the index
  is the serving validator's own wall clock, so clock skew between the
  two machines shifts that join window by the same amount.
- With the defaults, three streams of 240 seconds each started one
  incremental snapshot apart, there are stretches with no joinable
  stream: a stream is only joinable for its first 60 seconds, so if
  incremental snapshots are further apart than that, a booting
  validator may have to wait for the next one. It keeps retrying for
  the full 300 seconds before giving up.
- There is no way to fetch one missing account on demand. Everything
  the booting validator gets before the background load finishes has
  to come from a block the serving validator actually executed.
- `server` has to be a plain IPv4 address and port, over plain HTTP. A
  hostname or `https://` fails at startup: `[snapshots.instant_boot]
  server "%s" must give an IPv4 address`.
- The serving validator's incremental snapshot has to be at exactly
  the stream's slot, or the booting validator dies: `instant boot:
  incremental snapshot is not at the stream slot (manifest slot %lu,
  stream slot %lu)`. This is a safety check and should not happen on
  its own.
- A reset on the serving side closes every open stream at once, for
  example if the serving validator falls behind: `resetting the boot
  streams: the stream tile owed a bank reference for too long`. A fork
  going away under a block's reads closes only the streams that needed
  that block: `the fork slot %lu was read at is gone, breaking the boot
  streams that needed it`. A booting client that had already joined a
  closed stream sees it as a stream failure, same as above. One still
  looking for a stream to join just waits for the next one.
- If a validator's blocks touch more accounts than
  `max_keys_per_stream` allows, the server closes the stream early or
  breaks it outright: `the boot stream at slot %lu carried %lu
  accounts, which is all [snapshots.instant_boot.serve.max_keys_per_stream]
  allows for`. Raise the setting if this shows up often.
- The ordinary snapshot download-speed check (`[snapshots]
  min_download_speed_mibs`) also applies to the first part of a boot
  stream download. A slow link to the serving validator can trip it
  before the download settles into its normal low-traffic tail.
- The new tiles this adds have no metrics of their own yet.

## Manual Two-Node Run

1. On the serving node: turn on `[snapshots.server]`, `[layout]
   enable_snapshot_production`, and `[snapshots.instant_boot.serve]`,
   and restart it.
2. On the booting node: turn on `[snapshots.instant_boot]`, set
   `server` to the serving node's address, and start it.
3. Compare the booting node's first `replay ready at slot %lu`
   timestamp against its `loaded ... accounts ... from snapshot in ...
   seconds` timestamp, as above.
