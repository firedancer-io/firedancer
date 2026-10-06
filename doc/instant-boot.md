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
  time this validator makes a new incremental snapshot.
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
| `[snapshots.instant_boot.serve] stream_lifetime_seconds` | Serving | `240` | How long a stream is served before it's closed and recycled. |
| `[snapshots.instant_boot.serve] max_open_streams` | Serving | `3` | How many streams are served at once (1 to 8). |
| `[snapshots.instant_boot.serve] max_keys_per_stream` | Serving | `4000000` | How many accounts one stream can carry. At this default, costs 160 MiB per stream (225 MiB counting its write buffer and compressor). A stream closes once it has carried three quarters of this. |

## Enable the Serving Side

Set `[layout] enable_snapshot_production = true`, `[snapshots.server]
enabled = true`, and `[snapshots.instant_boot.serve] enabled = true`.

This costs 66 MiB by itself (99 MiB with blocks still in flight),
before any stream opens. Each open stream then costs another 160 MiB
(225 MiB counting its write buffer and compressor) at the default
`max_keys_per_stream`. With the defaults (3 streams), that is up to
about 770 MiB total.

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
- A listed stream stays open for `stream_lifetime_seconds` (240
  seconds by default). The booting validator only joins a stream with
  at least 180 seconds of life left (fixed, not configurable), so it
  has to pick one up within about a minute of it being listed. If no
  usable stream turns up within 5 minutes, it gives up fatally:
  `no boot stream offered for 300 s`.
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
  example if the serving validator falls behind (`resetting the boot
  streams: %s`, `the fork slot %lu was read at is gone, resetting the
  boot streams`). A booting client that had already joined the stream
  sees this as a stream failure, same as above. One still looking for
  a stream to join just waits for the next one.
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
