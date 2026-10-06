# Instant boot, plan C: the serving validator

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a running validator publish boot streams: for each stream started at slot X, a growing archive holding the manifest and status cache for X followed by one appendvec per later block with the accounts that block uses for the first time since X, valued as of X. Served over HTTP with range requests. Opt-in, off by default.

**Architecture:** A new tile `strmk` (stream maker, a sibling of the snapshot maker in `src/discof/backup`) owns the streams. Replay feeds it two things over a new unreliable link: each block's account keys as the scheduler parses them, and block start/end markers carrying the block's parent fork. Replay holds a reference on the parent bank from block start until `strmk` says it has read the block's pre-states, and drops the hold itself after a timeout, marking the stream broken. `strmk` reads pre-states at the parent fork through a read-only accounts join, encodes them with the snapshot account layout, and appends tar-plus-zstd frames to the stream file with the same code shape the snapshot maker uses. The existing snapshot file server (`snapsv`) serves the files and a small index.

**Tech Stack:** C, Firedancer tiles, zstd, `fd_tar`, `fd_http_server` (via `snapsv`), topology and config.

**Spec:** `docs/superpowers/specs/2026-10-06-instant-boot-design.md`

**Depends on:** nothing in plans A or B to compile, but the archive layout must match plan B's Global Constraints exactly.

## Global Constraints

- Worktree `/data/mjain/repos/scratch/worker-20261005-200945/firedancer`, branch `instant-boot`. Never touch `/data/mjain/repos/firedancer`.
- Build: `make -j firedancer-dev` plus the unit tests named in each task. Run tests with `--page-sz normal`. No integration tests.
- With `[snapshots.instant_boot.serve] enabled = false` (default) nothing changes: no tile, no link, no replay behavior.
- Archive layout (must match plan B): tar entries `version` ("1.2.0"), `snapshots/`, `snapshots/<X>/`, `snapshots/<X>/<X>` (bincode manifest from `fd_ssmanifest_writer`), `snapshots/status_cache` (from `fd_txncache_writer`), then `accounts/<X>.0` (bundle: all sysvars, the alpenglow clock account, all feature accounts, every vote account referenced by any `epoch_stakes` entry the manifest carries, which covers the epochs replay and tower read at boot), then for each block slot s after X in the order the serving validator executes them: zero or more overflow files `accounts/<s>.1`, `accounts/<s>.2`, ... followed by exactly one `accounts/<s>.0`. The receiver treats the end of `<s>.0` as "slot s complete". Each account entry uses the snapshot appendvec layout (`snap_acc_hdr_t` from `src/discof/backup/fd_backup.h`, slot field = X, then data padded to 8 bytes). An account that does not exist at X is written with zero lamports, zero data, system-program owner. One zstd frame per tar entry, each frame starting with the entry's tar header, as the compression worker (`fd_snapzp_tile.c`, `zip_flush`) does today. No end-of-archive marker until the stream closes.
- Index: a text file `boot-index` rewritten after every change: one line per open stream, newest first, `"<X> <base58 of blake3(accounts_lthash)> <expires_unix_seconds>\n"`. The hash is the same value `snapin` compares against the advertised hash today (see `process_manifest` in `fd_snapin_tile.c`, the blake3 of the manifest's accounts lthash).
- HTTP paths served by `snapsv`: `GET /boot/index` and `GET /boot/<X>.tar.zst`, both with range support, the latter growing while open.
- Config `[snapshots.instant_boot.serve]`: `enabled` (false), `stream_interval_slots` (300), `stream_lifetime_seconds` (240), `max_open_streams` (3), `max_keys_per_stream` (4000000). Memory per stream for the sent-set is `max_keys_per_stream * 40` bytes; say so in the config comment.
- Replay never blocks on `strmk`: the key link is unreliable; a hold on a parent bank older than 4 seconds is dropped by replay and the streams are marked broken.
- Style and commit rules as in plans A and B.

---

### Task 1: config, topology, tile skeleton, file server routes

**Files:**
- Modify: `src/app/shared/fd_config.h`, `src/app/shared/fd_config_parse.c`, `src/app/firedancer/config/default.toml`
- Modify: `src/disco/topo/fd_topo.h` (new `strmk` tile struct; `snapsv` gets `int instant_boot_serve;`; `replay` gets `int instant_boot_serve;`)
- Modify: `src/app/firedancer/topology.c`, `src/app/firedancer/main.c`, `src/app/firedancer-dev/main.h`
- Create: `src/discof/backup/fd_strmk_tile.c`, `src/discof/backup/fd_strmk_tile.h`, `src/discof/backup/fd_strmk_tile.seccomppolicy`, `src/discof/backup/Local.mk` entry
- Modify: `src/discof/backup/fd_snapsv_tile.c`

Deliverable: the tile exists, starts, opens its file pool, publishes nothing, and `snapsv` answers `/boot/index` with an empty body (200) when serving is enabled. Topology: `strmk` tile; links `replay_strmk` (depth 32768, mtu 4096, unreliable consumer), `strmk_replay` (depth 128, mtu 0; replay consumes it like `rpc_replay`: sig = bank index to release), `strmk_out` (depth 128, mtu `sizeof(fd_snapmk_msg_t)`; consumed by `snapsv`). `snapsv` is created when `snapshots.server.enabled && (enable_snapshot_production || instant_boot.serve.enabled)`; when only the latter, it has no `snapmk_out` in-link and that in-link becomes optional in the tile. `strmk` joins: accdb read-only with its own epoch fseq (copy the `rpc` plumbing in topology.c: the `accdb_epoch.<name>` fseq and the accdb tile's external epoch slots), banks read-only, txncache read-only (for the status-cache writer; check what join mode `fd_txncache_writer_init` needs by reading `snapmk`), and the `replay_slot` link is not needed.

File pool: `strmk` pre-opens `max_open_streams` placeholder files in `privileged_init` under `<paths.snapshots>/boot/` named `boot-stream-partial-<i>.tar.zst` at fixed descriptors `FD_STRMK_FD(i) = 210000+i`, plus `boot-index` at `210000+max_open_streams` and a scratch `boot-index.tmp` after it; it needs `allow_renameat` for the index swap. Mirror `fd_snapmk_tile.c`'s `privileged_init` and `populate_allowed_fds`.

`snapsv`: add routes `GET /boot/index` and `GET /boot/<slot>.tar.zst`. It learns files from `strmk_out` messages reusing `fd_snapmk_msg_created_t`/`deleted_t` with `pool_idx` mapped through `FD_STRMK_FD` instead of `FD_SNAP_FD` (add a `uint reserved` use: `reserved = 1` marks a boot-stream file; keep the struct unchanged). Because stream files grow, `snapsv` must take the current size from `fstat` on each request for boot-stream files instead of the cached `sz`; a range starting at or past the size answers 416. The index is served from its fd with `fstat` size as well.

- [ ] Steps: write the config, topology, tile skeleton (stem callbacks with empty `after_credit`, joins, fd pool), `snapsv` routes with a unit-level check if `snapsv` has tests (look for `test_snapsv*`); build `firedancer-dev`; confirm with `firedancer-dev mem` that `strmk` appears only when `serve.enabled=true`. Commit: `strmk: config, topology, file pool and routes`.

---

### Task 2: replay feeds blocks and holds parents

**Files:**
- Modify: `src/discof/replay/fd_replay_tile.c`, `src/discof/replay/fd_replay_tile_private.h`, `src/discof/replay/fd_replay_tile.h` (message structs), `src/discof/replay/fd_sched.c`, `src/discof/replay/fd_sched.h`

**Interfaces (produced, used by Task 3):** on `replay_strmk`, three message kinds selected by `sig`:
- `FD_STRMK_SIG_BLOCK_START (1)`: `struct { ulong slot; ulong bank_idx; ulong parent_bank_idx; ushort parent_accdb_fork_id; }`. Published from `replay_block_start` after the child bank exists; before publishing, `parent->refcnt++` and record `{parent_bank_idx, slot, tickcount}` in a 64-entry ring `strmk_holds`.
- `FD_STRMK_SIG_TXN_KEYS (2)`: `struct { ulong slot; ulong bank_idx; ushort key_cnt; fd_pubkey_t keys[]; }` with static keys followed by resolved lookup-table keys. Published from `fd_sched_parse_txn` right after `imms`/`alts` are known (the point where `fd_rdisp_add_txn` is called); when a transaction's tables could not be resolved at parse time (`serializing`), publish the table account keys themselves as well so the stream tile can resolve them. The scheduler needs a publish callback or the replay tile's stem context; follow how `fd_sched` already reaches replay-owned state (read `fd_sched.h`) and keep it minimal.
- `FD_STRMK_SIG_BLOCK_END (3)`: `struct { ulong slot; ulong bank_idx; ulong txn_cnt; fd_pubkey_t collector; }` published where replay marks the block complete (`publish_slot_completed`), and also for blocks that die (`FD_STRMK_SIG_BLOCK_DEAD (4)`, same struct, collector zeroed) so the stream tile can drop partial state. `collector` is the account that `fd_runtime_settle_fees` (`src/flamenco/runtime/fd_runtime.c`) credits with the block's fee reward at block end: the leader identity, or the SIMD-0232 block revenue collector when the `custom_commission_collector` feature is active. No transaction names that account, so the stream must carry it like any other key the block touches. Move the collector choice out of `fd_runtime_settle_fees` into a non-static `fd_runtime_fee_collector( fd_bank_t const * bank, fd_pubkey_t * collector )` declared in `fd_runtime.h`, call it from both places, and keep `fd_runtime_settle_fees` otherwise unchanged (same burn/pay logic on the returned key).
- `FD_STRMK_SIG_STREAM_START (5)`: `struct { ulong slot; ulong bank_idx; }` published when the stream tile asks for a new stream: the stream tile sends sig `FD_STRMK_REQ_START (ULONG_MAX)` on `strmk_replay`; replay, in the handler for that in-kind, does what `snapmk_start` does to pin the published root bank (`refcnt++`, record the hold) and replies with this message. Any other sig on `strmk_replay` is a bank index to release (`refcnt--`), exactly like `IN_KIND_RPC`.
- Timeout: in `after_credit`, if the oldest entry in `strmk_holds` is older than 4 seconds (`fd_tickcount` delta against `ctx->tick_per_ns`), `refcnt--` it, pop it, and publish `FD_STRMK_SIG_RESET (6)` (no payload). Also publish RESET if a publish on `replay_strmk` would overrun (the link is unreliable; replay cannot know, so instead the stream tile detects a sequence gap and resets itself; replay only publishes RESET on the timeout).

All under `ctx->instant_boot_serve` (from `tile->replay.instant_boot_serve`). Test: `make -j firedancer-dev`; existing replay tests; with the flag off `git diff` shows only guarded additions.

- [ ] Commit: `replay: feed block keys and holds to strmk`.

---

### Task 3: the stream tile

**Files:**
- Modify: `src/discof/backup/fd_strmk_tile.c`
- Create: `src/discof/backup/test_strmk_encode.c` (unit test for the appendvec encoding and the sent-set, registered in `Local.mk`)

Behavior:

1. **Streams.** `max_open_streams` slots, each `{ int open; ulong slot_x; uchar hash[32]; long started; long expires; int fd; ZSTD_CStream * zst; sent_set; ulong file_sz; }`. Every `stream_interval_slots` (compare the last block slot seen on `replay_strmk` with the last stream's X), if a free slot exists (expired streams are closed first: write the two zero blocks, end the frame, publish `deleted`, truncate), send `FD_STRMK_REQ_START` to replay. On `STREAM_START { slot, bank_idx }`: open the stream on the free slot, write `version`, the two directory headers, the manifest (`fd_ssmanifest_writer_init( writer, bank, leader?, accdb, root_fork_id, scratch )` exactly as `snapmk` calls it; read `snapmk` for the arguments), the status cache (`fd_txncache_writer_*` as `snapmk_status_cache_prepare`/`snapmk_status_cache`), then the bundle appendvec `accounts/<X>.0`: read at the bank's `accdb_fork_id` every key in `fd_sysvar_key_tbl`, the alpenglow clock account (`fd_alpenglow_pda( "alpenclock", &addr )`, read by the block footer in `fd_runtime.c` outside any transaction), every feature id (`fd_feature_id_t` table in `src/flamenco/features`), and every vote account pubkey referenced by any epoch stakes entry the manifest writer emits (find the iterator `snapmk`'s manifest writer or `fd_vote_stakes` exposes; replay's `fd_vote_stakes_refresh` at boot reads the epoch two back, and tower reads two epochs, so emitting all referenced epochs is the safe superset), encoded per the layout; then release the bank (`strmk_replay`, sig = bank_idx), compute the index hash (blake3 of the bank's accounts lthash as `snapin` checks it), write the index, publish `created` on `strmk_out` with `reserved=1`.
2. **Blocks.** Keep a small table of in-flight blocks keyed by `bank_idx` (at most 64): on `BLOCK_START` record slot and parent fork; on `TXN_KEYS` append keys to the block's key buffer (bounded; if full, mark the block overflowed and keep going, the receiver's one-off path is out of scope so an overflowed block makes the stream broken: close all streams and publish `deleted`); on `BLOCK_END`: append the message's `collector` to the block's key buffer (the fee collector is written at block end without a transaction naming it); then for every open stream, for each key not in that stream's sent-set: read `fd_accdb_read_one_nocache( accdb, parent_fork, key, ... )` into the 10 MiB scratch once per key (cache the read across streams within the block), if the owner is the upgradeable loader and the data parses as a `Program` state, also handle its program-data address the same way; encode into the stream's appendvec buffer (64 MB); when the buffer would overflow, flush it as an overflow file `accounts/<s>.<n>` (n from 1) and continue; at the end flush `accounts/<s>.0`; insert the keys into the sent-set; update the index entry's size via `created` with the new size. Then release the parent bank (`strmk_replay`, sig = parent_bank_idx). On `BLOCK_DEAD` drop the block's buffer and release the parent. On `RESET` or a sequence gap on `replay_strmk` (track `seq` from the stem callback), close every stream as broken.
3. **Encoding.** `snap_acc_hdr_t` with `slot = X`, `data_len`, `pubkey`, `lamports`, `rent_epoch = ULONG_MAX`, `owner`, `executable`, zero hash, then data, padded to 8 bytes. Reuse `fd_backup_tar_file_hdr`; one zstd frame per tar entry starting with the header block, then `ZSTD_e_end`, written with `fd_io_write` to the stream fd (copy `zip_append`/`zip_flush` from `fd_snapmk_tile.c` into this tile; do not share code across tiles by moving it in this task).
4. **Sent-set.** Open addressing on the 32-byte key, `max_keys_per_stream` slots, 40 bytes per slot (key + 8 bytes of state), in tile scratch; cleared when the stream closes.
5. **Hold discipline.** Release the parent bank for a block as soon as its pre-states are read, before encoding and writing, so replay's rooting is delayed only by the reads.

Test: `test_strmk_encode` round-trips a handful of accounts (including a nonexistent one and a 10 MiB one) through the encoder and `fd_ssparse` (feed the produced tar bytes, uncompressed, to the parser and compare headers and data), and checks the sent-set insert/lookup at capacity.

- [ ] Commit: `strmk: boot streams from replay block feed`.

---

### Task 4: bring-up notes

**Files:**
- Create: `doc/instant-boot.md` (how to enable both sides, what to expect in the logs, how to confirm the receiver is executing before the snapshot finishes, known limits: no one-off fetch path, boundary wait, stream expiry, abort-by-restart)

- [ ] Commit: `doc: instant boot bring-up`.

The two-node run itself is manual and belongs to mjain: enable `serve` on one node, point another node's `[snapshots.instant_boot].server` at it, and compare `replay ready at slot` timestamps against the snapshot `DONE` log lines.
