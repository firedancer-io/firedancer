# Instant boot: design

Status: agreed in conversation with mjain on 2026-10-05/06.  Base:
origin/main bdb49ce194.  Opt-in on both sides, off by default.

## Goal

A booting validator starts executing live blocks within seconds by
taking the state it needs from a running Firedancer validator, while
the normal snapshot load fills in the rest in the background.  The
snapshot is the floor.  Everything after the start slot comes from the
booting validator's own replay.

Slots are 200 ms.  A snapshot load takes about 60 seconds.  The gain is
that minute plus the catch-up a normal boot does afterwards.

## Vocabulary

- X: the slot the running validator's root was at when it started a
  stream.  The booting validator executes from X+1.
- Stream: one archive file per X on the running validator.  It starts
  with the manifest and status cache for X and then grows: for every
  block the running validator executes after X, the accounts that block
  uses for the first time since X, each with the value it had at X.
  "Uses" means every account a transaction names, plus the account
  the block credits with its fee reward at block end (the leader
  identity or its SIMD-0232 collector), which no transaction names.
  The alpenglow clock account, read by every block footer, travels in
  the bundle with the sysvars.
- Boot fork: a fork in the booting validator's accounts database,
  created under the incremental fork before anything starts.  It holds
  the accounts received from the stream.  Every fork replay creates
  descends from it.

## Running validator (stream tile, sibling of the snapshot maker)

1. Every time replay starts an incremental snapshot it also starts a
   stream at the same slot X (its published root, pinned for the
   snapshot anyway).  The stream tile holds bank X by reference for
   the seconds the manifest writer and the status-cache writer need,
   then releases it.  The stream appears in the index only once the
   incremental snapshot file for X exists, so a client always finds
   the matching pair.
2. Replay publishes each block's account key list (static keys plus
   lookup-table expansion) as it schedules the block, and holds a
   reference on that block's bank until the stream tile releases it.
   Replay drops the reference itself after a few slots and marks the
   stream broken if the stream tile does not release it.  The key-list
   link never backpressures replay; if it fills, the stream is broken.
3. For each block, the stream tile drops keys already sent for this
   stream, derives program-data accounts for upgradeable programs,
   reads the remaining accounts at the block's parent fork (their value
   at X; "does not exist" becomes a zero-lamport tombstone), appends
   them to the archive as appendvec entries tagged with slot X, then a
   slot marker, then releases the bank reference.  Reads are plain
   read-only acquires; compaction is never paused.
4. The archive uses the incremental snapshot container (tar plus zstd)
   so the existing writers, file server, download client, decompressor
   and parsers are reused.  It is named so the normal loader never
   mistakes it for an incremental.  The file server serves it with
   range requests while it is still growing.
5. Streams expire a few minutes after they start.  The server keeps
   about three alive at once.  An index lists open streams: X, start
   time, expiry.  Each stream keeps an "already sent" hash set keyed by
   pubkey (a few million entries); the log itself lives on disk.

## Booting validator

Accounts database rules (always on, cheap):

- Every head load honors the loader's chain lock sentinel.
- Every entry written by the snapshot loader carries bit 27 of the size
  word.  Normal writes clear it.
- While the hide flag is set, every read skips flagged entries unless
  the reading join asked to see them (the loader's own verification
  reads).  The flag is set only in instant-boot mode.
- The loader compares slots only against flagged entries, and links a
  new entry behind the last unflagged entry for the same pubkey, so a
  reader always meets the stream's or execution's version first.
  While the hide flag is set nothing removes chain nodes: the accounts
  database refuses purge and root advance, and replay defers fork
  purges until the load is done.  So the loader's interior insert
  never races a remover.
- A key is written into the boot fork at most once, and before any
  execution fork writes it.  Both hold because the receiver writes
  "only if absent" in arrival order and replay executes slot s only
  after the stream's marker for s has been parsed.

Restore pipeline:

- A setup control message runs before any download.  The lead tile
  resets the database, creates root, incremental and boot forks in that
  order, marks loading begun, sets the hide flag, and publishes the
  three fork ids.  Bank 0's accounts fork is the boot fork.
- Under the instant-boot flag the lead skips building the status cache,
  publishing the manifest and restoring features; those come from the
  stream.  The stake set still comes from the snapshot: every loader
  keeps snooping stake accounts into the root stake delegations while
  it writes, and the lead applies the incremental's stake fork at load
  end as it does today.  The stream carries no stake accounts.
- A load failure after bytes were written kills the process.
- The incremental snapshot loaded in the background is the one at
  exactly X.  The running validator starts a stream every time it
  starts an incremental snapshot, so each stream has a matching
  incremental, and lists the stream only once that incremental file
  exists.  On the booting side the stream downloader picks the stream
  and publishes X through a shared counter; the snapshot control tile
  waits for it, ignores local snapshot files and peers, and downloads
  the pair through the server's `/boot/<X>/full` and
  `/boot/<X>/incremental` redirects.  The lead checks the incremental
  manifest's slot against X and dies on a mismatch.  With both sources
  at X every account has one value, so nothing depends on which source
  a read lands on.
- At load end, once every writer has stopped: clear the hide flag
  (the accounts database refuses root advance while hidden), promote
  the incremental, ask the stream receiver to stop and wait until it
  has acknowledged, root the boot fork (bank 0's fork, so replay's
  first root advance finds its parent rooted), then signal replay.

Receiver tile:

- Reads the stream index, picks the newest stream with enough time
  left, downloads the archive and keeps pulling its tail by byte
  offset.  Parses manifest, status cache and appendvec entries with the
  existing parsers.  Publishes the manifest and DONE on the manifest
  link exactly as the loader does today.  Writes each account into the
  boot fork once if absent.  Reports the last complete slot marker to
  replay.  Stops writing and acknowledges when the lead asks at load
  end.  Any failure after start: log and exit; the operator restarts
  with instant boot off.

Replay:

- On manifest plus DONE it does today's DONE work except the
  stake-delegation refresh, stake totals and rewards recalculation;
  those run on the load-done signal.
- Executes slot s only after the stream marker for s.  The gate turns
  off at load-done.
- Does not advance the root and refuses leadership until load-done.
- Waits at the first block of a new epoch, or when the epoch-rewards
  sysvar says a payout is active at X, until load-done.

## Config

Server: enable, stream lifetime, max open streams, max keys per
stream; streams start with incremental snapshots, so snapshot
production with incrementals must be on.  Client: enable, server address.  Both off
by default.  With both off neither tile exists.

## Limits and exits

- 2048 unrooted slots on the booting side (about 6.8 minutes); a
  60-second load sits far inside it.
- Stream expiry on the server is the hard end of a client's window.
- Any client-side failure: exit and restart as a normal boot.

## Pieces (each lands alone)

1. Chain-lock hoist in accdb.
2. Loader flag bit, skip rule, insert behind.
3. Hide flag and per-join override.
4. Restore: setup state, skip flags, fatal exit, incremental at or after X.
5. Replay: split DONE, load-done signal, marker gate, boundary and
   leadership gates, key-list out-link, per-slot bank reference, short
   hold at stream start.
6. Receiver tile.
7. Stream tile.
