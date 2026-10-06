# Instant boot, plan B: the booting validator

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a validator start executing live blocks from a running validator's stream while its own snapshot load fills the accounts database in the background, all behind an opt-in config flag that is off by default.

**Architecture:** The stream is an archive in the incremental snapshot's container (tar plus zstd), so the booting side is a second instance of the existing download, decompress and parse tiles (`strld`, `strdc`, `strin`) running in "stream mode", writing into a boot fork instead of through the loader. The normal pipeline keeps loading the real snapshot; its lead tile creates the forks up front, hides what it writes, skips the bank, status cache, stake and feature work, and signals replay when done. Replay splits its startup work in two, gates block execution on per-slot markers from the stream, and refuses to root or lead until the load is done. Coordination between tiles uses two shared counters (fseq objects) and the existing snapin shared memory.

**Tech Stack:** C, Firedancer tiles (`src/discof/restore`, `src/discof/replay`), topology (`src/app/firedancer/topology.c`), config (`src/app/shared/fd_config*.c/h`, `src/app/firedancer/config/default.toml`), unit tests.

**Spec:** `docs/superpowers/specs/2026-10-06-instant-boot-design.md`

**Depends on:** plan A merged on this branch (`fd_accdb_snapshot_hide`, `fd_accdb_show_hidden`, loader flag bit).

## Global Constraints

- Worktree `/data/mjain/repos/scratch/worker-20261005-200945/firedancer`, branch `instant-boot`. Never touch `/data/mjain/repos/firedancer`.
- Build: `make -j firedancer-dev test_snapin_accdb test_snapin_tile test_ssparse test_snapld_tile` (objdir `build/native/gcc/11.5.0`). Run tests with `--page-sz normal`. Do not run integration tests.
- With `[snapshots.instant_boot] enabled = false` (the default) every existing test must pass unchanged and no new tile or link exists in the topology.
- Stream archive layout (produced by plan C; consumed here): a tar of `version`, `snapshots/<X>/<X>` (bincode manifest), `snapshots/status_cache`, then one appendvec file per slot named `accounts/<slot>.0`: the first is `accounts/<X>.0` holding sysvars, feature accounts and both epochs' vote accounts; each following `accounts/<s>.0` holds the accounts slot `s` touched for the first time since X, with their values at X, zero lamports meaning "did not exist". The whole stream is zstd-compressed, frames aligned to appendvec files, no end-of-archive marker until the stream closes.
- Shared objects: fseq `instant_boot_slot` (last slot whose appendvec has been fully written into the boot fork; written by `strin`, read by replay) and fseq `instant_boot_done` (1 once the background snapshot load is complete and the hide flag is cleared; written by the lead `snapin`, read by replay and `strld`/`strin`). The generic fseq object seeds `ULONG_MAX`; each writer stores 0 into its counter at tile start (the lead `snapin` for `done`, `strin` for `slot`) before anything else, and every reader treats `ULONG_MAX` as "not ready" (the slot gate blocks, the done flag is not set).
- `fd_snapin_shmem_t` gains `ulong setup_done; ulong boot_fork_id; ulong incr_fork_id; ulong stream_slot;` (the last written by `strin` once it has parsed the stream manifest).
- Style: smallest diff, one statement per line, braces on multi-line bodies, plain-English comments above the thing they describe, 72 columns, two spaces after a period, no coined names. Reuse existing functions; do not add helpers that duplicate them.
- Commits: one per task, one-line message, at most 10 words, no trailers, no body. `git add` only the files the task lists.

---

### Task 1: config, topology and shared objects (nothing behaves differently yet)

**Files:**
- Modify: `src/app/shared/fd_config.h` (the `snapshots` struct inside `firedancer`, near the `server` sub-struct)
- Modify: `src/app/shared/fd_config_parse.c` (next to the `snapshots.server.*` CFG_POP lines)
- Modify: `src/app/firedancer/config/default.toml` (after the `[snapshots.server]` block)
- Modify: `src/disco/topo/fd_topo.h` (`snapld`, `snapin`, `replay` tile structs)
- Modify: `src/app/firedancer/topology.c`
- Modify: `src/app/firedancer/main.c` and `src/app/firedancer-dev/main.h` (TILES tables)
- Modify: `src/discof/restore/fd_snapld_tile.c`, `fd_snapdc_tile.c`, `fd_snapin_tile.c` (second run-tile struct each)
- Test: existing topology build; `make -j firedancer-dev` and `firedancer-dev configure`-free check below

**Interfaces:**
- Produces: `config->firedancer.snapshots.instant_boot.enabled` (int), `config->firedancer.snapshots.instant_boot.server` (char[FD_URL_MAX]); `tile->snapld.stream` (int) and `tile->snapld.stream_server` (char[FD_URL_MAX]); `tile->snapin.stream` (int), `tile->snapin.instant_boot` (int), `tile->snapin.instant_boot_slot_obj_id`, `tile->snapin.instant_boot_done_obj_id` (ulong); `tile->replay.instant_boot` (int), `tile->replay.instant_boot_slot_obj_id`, `tile->replay.instant_boot_done_obj_id` (ulong); tiles named `strld`, `strdc`, `strin`; links `strld_dc`, `strdc_in`, `strin_ct` (no consumers), and a second `snapin_manif` link (kind 1) consumed by replay, gossip, repair/rotor and gui.

- [ ] **Step 1: Config fields and defaults**

In `src/app/shared/fd_config.h`, inside the `snapshots` struct of the `firedancer` config (the one that has `server`), add after the `server` sub-struct:

```c
    struct {
      int  enabled;
      char server[ FD_URL_MAX ];
    } instant_boot;
```

In `src/app/shared/fd_config_parse.c`, after the `snapshots.server.send_buffer_size_kib` line, add:

```c
  CFG_POP      ( bool,   snapshots.instant_boot.enabled                      );
  CFG_POP      ( cstr,   snapshots.instant_boot.server                       );
```

In `src/app/firedancer/config/default.toml`, after the `[snapshots.server]` block, add:

```toml
    # Instant boot takes the state needed to start executing from a
    # running Firedancer validator that serves a boot stream, while the
    # snapshot above still loads in the background.  Both validators
    # must be Firedancer.  Off by default; when off nothing here is
    # used and no extra tiles run.
    [snapshots.instant_boot]
        enabled = false

        # Address of the serving validator's stream server, as
        # host:port or http://host:port.  Required when enabled.
        server = ""
```

- [ ] **Step 2: Tile config fields**

In `src/disco/topo/fd_topo.h`:
- `snapld` struct: add `int  stream;` and `char stream_server[ FD_URL_MAX ];`.
- `snapin` struct: add `int   stream;`, `int   instant_boot;`, `ulong instant_boot_slot_obj_id;`, `ulong instant_boot_done_obj_id;`.
- `replay` struct: add `int   instant_boot;`, `ulong instant_boot_slot_obj_id;`, `ulong instant_boot_done_obj_id;`.

Check `FD_URL_MAX` is visible in `fd_topo.h` (it is used by `snapct.sources.servers` already).

- [ ] **Step 3: Second run-tile structs**

Each restore tile file ends with an `fd_topo_run_tile_t fd_tile_<name> = { .name = "<name>", ... };`. Add, right after each, a second struct with the same fields and a different name:

- `fd_snapld_tile.c`: `fd_topo_run_tile_t fd_tile_strld = { .name = "strld", <same remaining initializers as fd_tile_snapld> };`
- `fd_snapdc_tile.c`: `fd_topo_run_tile_t fd_tile_strdc = { .name = "strdc", ... };`
- `fd_snapin_tile.c`: `fd_topo_run_tile_t fd_tile_strin = { .name = "strin", ... };`

Copy the initializers verbatim (do not factor a macro). Add `&fd_tile_strld, &fd_tile_strdc, &fd_tile_strin,` to the TILES tables in `src/app/firedancer/main.c` and `src/app/firedancer-dev/main.h` next to the snapld/snapdc/snapin entries, and the matching `extern fd_topo_run_tile_t fd_tile_strld;` declarations where the others are declared (search for `fd_tile_snapld`).

- [ ] **Step 4: Topology**

In `src/app/firedancer/topology.c`, with `int instant_boot = snapshots_enabled && config->firedancer.snapshots.instant_boot.enabled;` defined next to `snapshots_enabled`:

1. Workspaces: inside `if( FD_LIKELY( snapshots_enabled ) )` where `snapct`/`snapld`/... workspaces are created, add `if( instant_boot ) { fd_topob_wksp( topo, "strld" ); fd_topob_wksp( topo, "strdc" ); fd_topob_wksp( topo, "strin" ); fd_topob_wksp( topo, "strld_dc" ); fd_topob_wksp( topo, "strdc_in" ); fd_topob_wksp( topo, "strin_ct" ); fd_topob_wksp( topo, "instant_boot" ); }`.
2. Links, next to the snapshot links:

```c
    if( instant_boot ) {
      fd_topob_link( topo, "strld_dc",     "strld_dc",     FD_SNAPSHOT_DATA_DEPTH,  FD_SNAPSHOT_DATA_MTU,           1UL );
      fd_topob_link( topo, "strdc_in",     "strdc_in",     FD_SNAPSHOT_DC_IN_DEPTH, FD_SNAPSHOT_DATA_MTU,           1UL );
      fd_topob_link( topo, "strin_ct",     "strin_ct",     128UL,                   0UL,                            1UL )->permit_no_consumers = 1;
      fd_topob_link( topo, "snapin_manif", "snapin_manif", 4UL,                     sizeof(fd_snapshot_manifest_t), 1UL );
    }
```

   The second `snapin_manif` link gets kind_id 1 automatically.
3. Tiles, next to the snapshot tiles: `if( instant_boot ) { fd_topob_tile( topo, "strld", "strld", "metric_in", tile_to_cpu[ topo->tile_cnt ], 0, 0, 0, 1 )->allow_shutdown = 1; fd_topob_tile( topo, "strdc", "strdc", ... , 0 )->allow_shutdown = 1; fd_topob_tile( topo, "strin", "strin", ..., 0 )->allow_shutdown = 1; }` (same argument pattern as the snapld/snapdc/snapin lines; `strld` is a waker client like `snapld`).
4. Wiring, next to the snapshot wiring:

```c
    if( instant_boot ) {
      fd_topob_tile_out( topo, "strld", 0UL,              "strld_dc",     0UL );
      fd_topob_tile_in ( topo, "strdc", 0UL, "metric_in", "strld_dc",     0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
      fd_topob_tile_out( topo, "strdc", 0UL,              "strdc_in",     0UL );
      fd_topob_tile_in ( topo, "strin", 0UL, "metric_in", "strdc_in",     0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
      fd_topob_tile_out( topo, "strin", 0UL,              "strin_ct",     0UL );
      fd_topob_tile_out( topo, "strin", 0UL,              "snapin_manif", 1UL );
      fd_topob_tile_in ( topo, "replay", 0UL, "metric_in", "snapin_manif", 1UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
      fd_topob_tile_in ( topo, "gossip", 0UL, "metric_in", "snapin_manif", 1UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
      fd_topob_tile_in ( topo, repair,   0UL, "metric_in", "snapin_manif", 1UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
      if( FD_LIKELY( config->tiles.gui.enabled ) ) fd_topob_tile_in( topo, "gui", 0UL, "metric_in", "snapin_manif", 1UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
    }
```

   Place the replay/gossip/repair/gui lines next to the existing kind-0 `snapin_manif` consumers so the in-link order stays grouped. `strin` also needs the same object uses as `snapin` (accdb RW, banks, txncache, snapin_shmem): find where `snapin` tiles get `fd_topob_tile_uses(...)` for those objects and add `strin` with the same modes.
5. Shared counters: where other fseq objects are created (search for `fd_topob_obj( topo, "fseq"`), add:

```c
  if( instant_boot ) {
    fd_topo_obj_t * slot_obj = fd_topob_obj( topo, "fseq", "instant_boot" );
    fd_topo_obj_t * done_obj = fd_topob_obj( topo, "fseq", "instant_boot" );
    FD_TEST( fd_pod_insertf_ulong( topo->props, slot_obj->id, "instant_boot_slot" ) );
    FD_TEST( fd_pod_insertf_ulong( topo->props, done_obj->id, "instant_boot_done" ) );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "strin",  0UL ) ], slot_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "snapin", 0UL ) ], done_obj, FD_SHMEM_JOIN_MODE_READ_WRITE );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "strin",  0UL ) ], done_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "strld",  0UL ) ], done_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], slot_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
    fd_topob_tile_uses( topo, &topo->tiles[ fd_topo_find_tile( topo, "replay", 0UL ) ], done_obj, FD_SHMEM_JOIN_MODE_READ_ONLY );
  }
```

   Follow the file's existing fseq pattern exactly (look at how `root_slot` or the waker fseqs are created and how their seed is set) rather than the sketch above if they differ.
6. `fd_topo_configure_tile`:
   - `"snapld"`: unchanged. Add a branch `"strld"` that copies the `snapld` branch and sets `tile->snapld.stream = 1;` and `strncpy( tile->snapld.stream_server, config->firedancer.snapshots.instant_boot.server, FD_URL_MAX );`.
   - `"strdc"`: copy the `snapdc` branch.
   - `"snapin"`: add `tile->snapin.instant_boot = instant_boot; tile->snapin.stream = 0;` and the two obj ids from the pod (`fd_pod_query_ulong( config->topo.props, "instant_boot_done", ULONG_MAX )`, same for slot).
   - `"strin"`: copy the `snapin` branch and set `tile->snapin.stream = 1; tile->snapin.instant_boot = 1;`.
   - `"replay"`: add `tile->replay.instant_boot = instant_boot;` and the two obj ids.
   `instant_boot` must be visible in `fd_topo_configure_tile`; compute it from `config` there the same way.
7. In the tile files, `strld`/`strdc`/`strin` must accept their link names: `snapld` asserts its in link is `snapct_ld` and out link `snapld_dc`; `snapdc` asserts `snapld_dc`/`snapdc_in`; `snapin` asserts `snapdc_in` and finds `snapin_ct`/`snapin_manif`. In this task only relax the assertions: in stream mode (`tile->snapld.stream` / `tile->snapin.stream`, and for `strdc` compare `tile->name`), accept `strld_dc`, `strdc_in`, `strin_ct`, and `snapin_manif` kind 1; `strld` has no in link (`tile->in_cnt==0`). Behavior changes come in tasks 3 and 4.

- [ ] **Step 5: Build and check both configurations**

Run: `make -j firedancer-dev && build/native/gcc/11.5.0/bin/firedancer-dev configure check 2>&1 | tail -2` is not required; instead confirm the topology builds in both modes by adding a temporary `FD_LOG_NOTICE` is also not required. Required checks:
- `make -j firedancer-dev test_snapin_accdb test_snapin_tile` builds clean.
- `build/native/gcc/11.5.0/unit-test/test_snapin_tile --page-sz normal 2>&1 | tail -1` and `test_snapin_accdb` pass.
- `grep -n 'strin\|strld\|strdc' src/app/firedancer/topology.c | wc -l` is nonzero and every occurrence sits under `if( instant_boot )`.
- Write a 10-line toml to `/tmp/ib.toml` with `[snapshots.instant_boot] enabled = true` and `server = "127.0.0.1:8903"` plus the minimum keys `firedancer-dev` needs, and run `build/native/gcc/11.5.0/bin/firedancer-dev mem --config /tmp/ib.toml 2>&1 | grep -c 'strin\|strld\|strdc'` (the `mem` command prints the topology). Expected: 3 or more. Run the same with `enabled = false`: expected 0. If `mem` needs more config than is practical, say so in the report and skip this check.

- [ ] **Step 6: Commit**

```bash
git add src/app/shared/fd_config.h src/app/shared/fd_config_parse.c src/app/firedancer/config/default.toml src/disco/topo/fd_topo.h src/app/firedancer/topology.c src/app/firedancer/main.c src/app/firedancer-dev/main.h src/discof/restore/fd_snapld_tile.c src/discof/restore/fd_snapdc_tile.c src/discof/restore/fd_snapin_tile.c
git commit -m "restore: instant boot config, tiles and links"
```

---

### Task 2: the lead loader tile under instant boot

**Files:**
- Modify: `src/discof/restore/fd_snapin_tile.c`
- Test: `src/discof/restore/test_snapin_accdb.c` (new case)

**Interfaces:**
- Consumes: `tile->snapin.instant_boot`, `tile->snapin.instant_boot_done_obj_id`, `fd_accdb_snapshot_hide`, `fd_accdb_show_hidden` (plan A), `fd_snapin_shmem_t` new fields from the Global Constraints.
- Produces: `shmem->setup_done`, `shmem->boot_fork_id`, `shmem->incr_fork_id`; `instant_boot_done` fseq set to 1 at load end.

Behavior under `ctx->instant_boot` (copied from `tile->snapin.instant_boot` in `unprivileged_init`; always 0 for `strin`-mode which Task 4 covers separately):

1. **Setup before anything else.** Add a `before_credit` (or at the top of `after_credit` if the tile has one; otherwise add a `STEM_CALLBACK_BEFORE_CREDIT`) that runs once on the lead when `ctx->instant_boot && !ctx->lead.setup_done`:

```c
  fd_fseq_update( ctx->lead.done_fseq, 0UL );
  fd_accdb_reset( ctx->accdb );
  fd_accdb_fork_id_t null_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  ctx->lead.accdb_root_fork_id = fd_accdb_attach_child( ctx->accdb, null_fork_id );
  ctx->lead.accdb_incr_fork_id = fd_accdb_attach_child( ctx->accdb, ctx->lead.accdb_root_fork_id );
  fd_accdb_fork_id_t boot_fork = fd_accdb_attach_child( ctx->accdb, ctx->lead.accdb_incr_fork_id );
  fd_accdb_snapshot_load_begin( ctx->accdb );
  fd_accdb_snapshot_hide( ctx->accdb, 1 );
  fd_accdb_show_hidden( ctx->accdb, 1 );
  FD_VOLATILE( ctx->shmem->boot_fork_id ) = boot_fork.val;
  FD_VOLATILE( ctx->shmem->incr_fork_id ) = ctx->lead.accdb_incr_fork_id.val;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( ctx->shmem->setup_done ) = 1UL;
  ctx->lead.setup_done = 1;
```

   Add `int setup_done;` to `fd_snapin_lead_t`, and the four fields to `fd_snapin_shmem_t` (zeroed wherever the shmem is initialised).
2. **INIT_FULL / INIT_INCR.** When `ctx->instant_boot`: skip `fd_stake_delegations_reset`, `fd_accdb_reset`, the root `attach_child`, `fd_accdb_snapshot_load_begin`, `fd_txncache_reset`, `txncache_staging_reset` and the slot-delta parser init on INIT_FULL; on INIT_INCR skip the `attach_child` (the fork already exists) and `fd_stake_delegations_new_fork` (leave `stake_fork` as `USHORT_MAX`). Keep everything else (metrics, manifest parser init, advertised slot/hash, shmem publish of `fork_id`).
3. **Stream data.** In the parse loop, when `ctx->instant_boot`: the `FD_SSPARSE_ADVANCE_STATUS_CACHE` case consumes and discards the bytes (do not stage, do not call the slot-delta parser); the manifest is still parsed and validated by `process_manifest`, but `populate_txncache` is skipped and the `fd_stem_publish` of the manifest is skipped. In `process_manifest`, when `ctx->instant_boot && !ctx->full`, after validation add:

```c
    ulong stream_slot = FD_VOLATILE_CONST( ctx->shmem->stream_slot );
    if( FD_UNLIKELY( !stream_slot ) ) {
      FD_LOG_ERR(( "instant boot: incremental snapshot arrived before the boot stream manifest" ));
    }
    if( FD_UNLIKELY( manifest->slot<stream_slot ) ) {
      FD_LOG_ERR(( "instant boot: incremental snapshot slot %lu is older than the boot stream slot %lu", manifest->slot, stream_slot ));
    }
```

4. **Stake snoop.** In `writer_flush`, wrap the "Update the snooped stake delegations" loop in `if( FD_LIKELY( !ctx->instant_boot ) )`. Every snapin tile reads `tile->snapin.instant_boot`, not just the lead.
5. **NEXT / DONE.** Keep `verify_sysvars` and `validate_capitalization` (the lead's join can see hidden nodes). On DONE when `ctx->instant_boot`: keep `fd_accdb_snapshot_recover_delta` and `fd_accdb_advance_root( incr )`; skip the two stake-delegation calls and `fd_features_restore_chunk`; after `fd_accdb_snapshot_load_end` add `fd_accdb_snapshot_hide( ctx->accdb, 0 );` and `fd_fseq_update( ctx->lead.done_fseq, 1UL );`; skip the `FD_SSMSG_DONE` publish. Join `done_fseq` in `unprivileged_init` from `tile->snapin.instant_boot_done_obj_id` when `instant_boot`.
6. **Failures are fatal.** In `transition_malformed`, before anything else: `if( FD_UNLIKELY( ctx->instant_boot ) ) FD_LOG_ERR(( "instant boot: snapshot load failed, restart with instant boot disabled" ));`.

- [ ] **Step 1: Write the failing test**

`src/discof/restore/test_snapin_accdb.c` drives the write path against a real accdb (read it first; it has a setup that creates forks and calls the writer). Add a case that sets `ctx->instant_boot = 1` on the test context, runs the existing happy path for a full load, and asserts: (a) the stake-delegation root has zero entries afterwards (the snoop was skipped), and (b) the loaded accounts are not visible through a plain join while the test holds the hide flag, and are visible after `fd_accdb_snapshot_hide( accdb, 0 )`. If the test harness constructs the tile context in a way that cannot flip `instant_boot`, add the smallest hook it needs (a field on the test's context struct). Name the case `test_instant_boot_skips_bank_state`.

- [ ] **Step 2: Build and run to see it fail**

Run: `make -j test_snapin_accdb && build/native/gcc/11.5.0/unit-test/test_snapin_accdb --page-sz normal 2>&1 | tail -2`
Expected: FAIL at the stake-delegation count or the visibility assertion.

- [ ] **Step 3: Implement items 1 to 6 above**

- [ ] **Step 4: Build and run**

Run: `make -j test_snapin_accdb test_snapin_tile firedancer-dev && build/native/gcc/11.5.0/unit-test/test_snapin_accdb --page-sz normal 2>&1 | tail -1 && build/native/gcc/11.5.0/unit-test/test_snapin_tile --page-sz normal 2>&1 | tail -1`
Expected: both pass.

- [ ] **Step 5: Commit**

```bash
git add src/discof/restore/fd_snapin_tile.c src/discof/restore/test_snapin_accdb.c
git commit -m "snapin: instant boot setup, hiding and skips"
```

---

### Task 3: parser end-of-appendvec event and the stream downloader

**Files:**
- Modify: `src/discof/restore/utils/fd_ssparse.h`, `src/discof/restore/utils/fd_ssparse.c`
- Modify: `src/discof/restore/utils/fd_sshttp.h`, `src/discof/restore/utils/fd_sshttp.c`
- Modify: `src/discof/restore/fd_snapld_tile.c`
- Test: `src/discof/restore/utils/test_ssparse.c`, `src/discof/restore/utils/test_sshttp.c`, `src/discof/restore/test_snapld_tile.c`

**Interfaces:**
- Produces: `FD_SSPARSE_ADVANCE_APPENDVEC_DONE (9)` with `result->appendvec.slot` and a new `result->appendvec.id` (the number after the dot in `accounts/<slot>.<id>`, also filled on `FD_SSPARSE_ADVANCE_APPENDVEC`) set, returned exactly once when the last byte of an appendvec entry has been consumed; `fd_sshttp_init` gains a `ulong range_start` parameter (0 means no Range header) and accepts status 206 when `range_start` is nonzero; `strld` behavior described below.

Parser:
- Find where `fd_ssparse` tracks the remaining bytes of the current appendvec entry (the tar entry size from the appendvec header) and the state transition back to reading tar headers. Emit `FD_SSPARSE_ADVANCE_APPENDVEC_DONE` with the slot at that transition, before the parser moves to the next header. Add a test in `test_ssparse.c` that feeds a two-appendvec archive and checks the sequence `APPENDVEC, ACCOUNT_*..., APPENDVEC_DONE, APPENDVEC, ..., APPENDVEC_DONE`.
- Also allow the parser to sit idle at a tar header boundary with no data and no end marker (the stream is open-ended); confirm `fd_ssparse_advance` returns `AGAIN` there rather than an error, and add a test case for a truncated-at-boundary archive.

HTTP client:
- Add `ulong range_start` to `fd_sshttp_init` (update the two callers in `fd_snapld_tile.c` and `fd_sshttp.c`'s redirect follow, passing 0 or the current value). When nonzero, add `"Range: bytes=%lu-\r\n"` to the request and accept `206` in the status check (keep `200` accepted when `range_start` is zero; a `200` with nonzero `range_start` is an error, since the server ignored the range and would resend the file). `416` (range not satisfiable) returns `FD_SSHTTP_ADVANCE_DONE` with zero bytes so the caller can retry later. Extend `test_sshttp.c` with a 206 response and a 416 response.

`strld` (the `snapld` tile with `tile->snapld.stream`):
- No in link, no snapct. On the first `after_credit`:
  1. Parse `stream_server` into `fd_ip4_port_t` (host:port, or `http://host:port`); resolve a hostname with `fd_http_resolver` the way `snapct` does if it is not an IPv4 literal; FD_LOG_ERR on failure.
  2. `GET /boot/index` into a small buffer. Format: one line per open stream, `"<slot> <hash_base58> <expires_unix>\n"`, newest first. Pick the first line whose `expires_unix - now > 180`. FD_LOG_ERR if none.
  3. Publish `FD_SNAPSHOT_MSG_CTRL_INIT_FULL` on `strld_dc` with `fd_ssctrl_init_t{ .file=0, .zstd=1, .slot=X, .snapshot_hash=hash, .is_redirect=0, .file_sz=0 }`, then start the download: `fd_sshttp_init( sshttp, addr, hostname, is_https, "/boot/<X>.tar.zst", path_len, 4UL, now, 0UL )`.
  4. Stream DATA frags exactly as the HTTP path does today (META first with `total_sz = content length`, `resolved_slot = X`), but on `FD_SSHTTP_ADVANCE_DONE`: do not send `LOAD_COMPLETE` or go FINISHING; instead remember `received_bytes`, and if `fd_fseq_query( done_fseq )` is 1 go to `FD_SNAPSHOT_STATE_SHUTDOWN`; otherwise after 100 ms call `fd_sshttp_init` again with `range_start = received_bytes` and continue. META is sent only once.
  5. The download-speed watchdog (`check_download_progress`) does not apply to the tail phase (the tail is idle most of the time): disable it once the first `DONE` has been seen.
  6. Any `transition_malformed` in stream mode is `FD_LOG_ERR`.
- `privileged_init` in stream mode opens no local files (`local_full_fd`/`local_incr_fd` stay -1) and still opens the socket and epoll fds; the seccomp policy is the same.

- [ ] **Step 1: Write the failing tests** (parser APPENDVEC_DONE sequence and idle-at-boundary; sshttp 206/416) as described, and a `test_snapld_tile.c` case that constructs the tile with `stream=1`, feeds a fake index response and a fake archive body through the existing test transport, and asserts the INIT_FULL and META frags and that a second request carries `Range: bytes=<n>-`. Read the existing tests first to reuse their transports; if `test_snapld_tile.c` cannot inject HTTP responses, write only the parser and sshttp tests and say so.

- [ ] **Step 2: Run to see them fail**

Run: `make -j test_ssparse test_sshttp test_snapld_tile && for t in test_ssparse test_sshttp test_snapld_tile; do build/native/gcc/11.5.0/unit-test/$t --page-sz normal 2>&1 | tail -1; done`
Expected: FAIL (compile errors for the new constant and parameter).

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run**

Same command. Expected: all pass. Also `make -j firedancer-dev` builds clean (callers of `fd_sshttp_init` updated).

- [ ] **Step 5: Commit**

```bash
git add src/discof/restore/utils/fd_ssparse.h src/discof/restore/utils/fd_ssparse.c src/discof/restore/utils/fd_sshttp.h src/discof/restore/utils/fd_sshttp.c src/discof/restore/fd_snapld_tile.c src/discof/restore/utils/test_ssparse.c src/discof/restore/utils/test_sshttp.c src/discof/restore/test_snapld_tile.c
git commit -m "restore: stream downloader and appendvec end event"
```

---

### Task 4: the stream parser tile (`strin`)

**Files:**
- Modify: `src/discof/restore/fd_snapin_tile.c`
- Test: `src/discof/restore/test_snapin_accdb.c`

**Interfaces:**
- Consumes: `tile->snapin.stream`, `shmem->setup_done`, `shmem->boot_fork_id`, `FD_SSPARSE_ADVANCE_APPENDVEC_DONE`, fseqs `instant_boot_slot` (RW) and `instant_boot_done` (RO), `fd_accdb_probe_pd_this_fork`.
- Produces: manifest and DONE on `snapin_manif` kind 1, `shmem->stream_slot`, per-slot markers in `instant_boot_slot`.

Behavior when `ctx->stream` (from `tile->snapin.stream`; the tile is kind 0 of its own name, so `is_lead()` is true):

1. **Wait for setup.** At tile start store 0 into the `instant_boot_slot` counter. `after_credit`/`before_credit`: do nothing until `FD_VOLATILE_CONST( ctx->shmem->setup_done )`; then record `ctx->boot_fork = (fd_accdb_fork_id_t){ .val=(ushort)shmem->boot_fork_id }`.
2. **INIT_FULL.** As the lead does today minus accdb work: no reset, no forks, no load_begin; keep `fd_txncache_reset`, staging reset, both parser inits, advertised slot/hash; publish `shmem->fork_id` is not needed (no other tiles). Ack on `strin_ct` as usual (it has no consumer).
3. **Manifest.** `process_manifest` runs with all validations; `populate_txncache` runs; then stamp `manifest->accdb_fork_id = ctx->boot_fork.val` and `manifest->txncache_fork_id` as today, publish `FD_SSMSG_MANIFEST_FULL`, and set `FD_VOLATILE( ctx->shmem->stream_slot ) = manifest->slot`.
4. **Accounts.** Replace the write path: in `writer_flush` when `ctx->stream`, do not reserve or pwrite and do not call the loader. For each staged account (same `batch` arrays): `fd_accdb_probe_pd_this_fork( accdb, boot_fork, pubkey, &pd, &len, &lamports )` tells whether a version written on the boot fork already exists; read its implementation to confirm which output indicates "a version with this fork's generation was found" and use that. If one exists, skip. Otherwise write it with the normal path: `fd_accdb_acquire( accdb, boot_fork, 1, &pubkey, writable=1, acc )`, fill `lamports`, `owner`, `executable`, `data_len`, copy data, set `acc->commit = 1`, `fd_accdb_release( accdb, 1, acc )`. A zero-lamport entry is written the same way (it becomes a tombstone). The existing header buffer still holds owner and data for each account; reuse it. Batch size stays 8 per `fd_accdb_acquire` call if the API allows multiple keys per bracket (it does: `pubkeys_cnt`); use one bracket per batch.
5. **Markers.** On `FD_SSPARSE_ADVANCE_APPENDVEC_DONE`: flush the writer; if `result->appendvec.id != 0` do nothing more (overflow files `<s>.1`, `<s>.2`, ... come before the final `<s>.0`); otherwise if `result->appendvec.slot == stream_slot` (the bundle) publish `FD_SSMSG_DONE` on the manifest link once, else `fd_fseq_update( ctx->slot_fseq, result->appendvec.slot )`.
6. **No verification, no snoop, no acks beyond INIT.** Skip `verify_sysvars`, `validate_capitalization`, the stake snoop, the capitalization accumulation, and the FINI/NEXT/DONE/SHUTDOWN handling (never sent). `transition_malformed` is `FD_LOG_ERR`.
7. **Shutdown.** `should_shutdown` returns 1 when `fd_fseq_query( done_fseq )==1`.

- [ ] **Step 1: Write the failing test**

In `test_snapin_accdb.c` add `test_stream_writes_boot_fork`: build an accdb with root, incremental and boot forks and `shmem->setup_done=1`, construct the tile context with `stream=1`, feed two account batches for the same pubkey through the writer, and assert exactly one version exists on the boot fork with the first batch's value, that a zero-lamport entry reads as absent on a child of the boot fork but exists as a node (probe reports a version on this fork), and that the marker fseq equals the appendvec slot after the APPENDVEC_DONE path runs.

- [ ] **Step 2: Run to see it fail**, **Step 3: Implement**, **Step 4: Run** (`make -j test_snapin_accdb test_snapin_tile firedancer-dev` then both tests), **Step 5: Commit**

```bash
git add src/discof/restore/fd_snapin_tile.c src/discof/restore/test_snapin_accdb.c
git commit -m "snapin: stream mode writes the boot fork"
```

---

### Task 5: replay under instant boot

**Files:**
- Modify: `src/discof/replay/fd_replay_tile.c`, `src/discof/replay/fd_replay_tile_private.h`
- Test: existing replay tests must still pass (`make -j unit-test` is too broad; run `test_replay*` targets that exist under `src/discof/replay`; if none exist, rely on the firedancer-dev build and a backtest smoke run is out of scope)

**Interfaces:**
- Consumes: `tile->replay.instant_boot`, the two fseqs (RO), `bank->f.features` restore via `fd_features_restore_chunk` (signature in `src/flamenco/features/fd_features.h`).

Changes, all under `ctx->instant_boot`:

1. **Context.** Add `int instant_boot; int load_done; ulong const * instant_boot_slot; ulong const * instant_boot_done;` and a stashed block start `struct { int pending; ulong bank_idx; ulong parent_bank_idx; ulong slot; } held_block_start;` to the tile context. Join the fseqs in `unprivileged_init`.
2. **DONE handler.** After `FD_TEST( fd_sysvar_rent_read(...) )`, when `instant_boot`, restore features from the bundle: `fd_features_restore_chunk( &bank->f.features, ctx->accdb, bank->accdb_fork_id, bank->f.slot, &bank->f.epoch_schedule, 0UL, 1UL );` (match the call in `fd_snapin_tile.c`). Then call `init_after_snapshot( ctx, stem, /*stakes_ready=*/!ctx->instant_boot )`.
3. **Split `init_after_snapshot`.** Add an `int stakes_ready` parameter. When 0, skip `fd_stake_delegations_refresh`, the three totals, the diff emission loop, `refresh_vote_account_staked`, and `fd_rewards_recalculate_partitioned_rewards`; everything else runs. Move those skipped calls into a new `static void finish_stake_state( fd_replay_tile_t * ctx )` (bank = bank 0 query, same code) that `init_after_snapshot` calls when `stakes_ready` and that the load-done path calls later.
4. **Load-done.** At the top of `after_credit`, before the `is_booted` check: `if( FD_UNLIKELY( ctx->instant_boot && !ctx->load_done && FD_VOLATILE_CONST( *ctx->instant_boot_done ) ) ) { finish_stake_state( ctx ); ctx->load_done = 1; FD_LOG_NOTICE(( "instant boot: snapshot load finished, stake state complete" )); }`.
5. **Marker gate.** Read the two counters with `ULONG_MAX` meaning "not ready": `done` is set only when the counter equals 1; the marker is `0` while the counter is `ULONG_MAX`. In `try_replay`, service `held_block_start` first: if pending and the gate below now allows it, run `replay_block_start` + `fd_sched_task_done( BLOCK_START )`, clear pending, return 1; if pending and still blocked, return 0. In the `FD_SCHED_TT_BLOCK_START` case, before calling `replay_block_start`, compute `blocked = ctx->instant_boot && !ctx->load_done && ( slot > FD_VOLATILE_CONST( *ctx->instant_boot_slot ) || block_needs_stake_state( ctx, parent_bank_idx, slot ) )`; if blocked, stash into `held_block_start` and return 1 without calling `fd_sched_task_done`. `block_needs_stake_state` returns 1 when `fd_slot_to_epoch( &parent->f.epoch_schedule, slot, NULL ) > parent->f.epoch` or `parent->stake_rewards_fork_id != USHORT_MAX` or the epoch-rewards sysvar in the parent's sysvar cache says a payout is active (reuse the check `fd_rewards_recalculate_partitioned_rewards` performs; read it and call the same view function).
6. **No rooting, no purging, no leadership.** First line of `try_advance_published_root`: `if( FD_UNLIKELY( ctx->instant_boot && !ctx->load_done ) ) return 0;`. Same line at the top of `try_become_leader` and `try_become_leader_ag`. In `try_prune_bank`, when `ctx->instant_boot && !ctx->load_done` and the prune needs cancellation (case 2), still cancel the txncache and progcache forks but push `cancel_info->accdb_fork_id` onto a deferred list (array of `max_live_slots` entries) instead of calling `fd_accdb_purge`; drain that list with `fd_accdb_purge` right after `finish_stake_state` runs at load-done. The accounts database refuses purge and root advance while loader nodes are hidden, so calling them early would crash.
7. **Second manifest link.** Replay already classifies in links by name; confirm `snapin_manif` kind 1 lands in `IN_KIND_SNAP` and no assertion requires kind 0.

- [ ] **Step 1: Build** `make -j firedancer-dev` and run whatever replay unit tests exist (`ls build/native/gcc/11.5.0/unit-test | grep -i replay`).
- [ ] **Step 2: Implement items 1 to 7.**
- [ ] **Step 3: Build and run the same tests; confirm with `enabled=false` nothing changed:** `git diff --stat` shows only the two replay files; grep that every new branch is under `ctx->instant_boot`.
- [ ] **Step 4: Commit**

```bash
git add src/discof/replay/fd_replay_tile.c src/discof/replay/fd_replay_tile_private.h
git commit -m "replay: instant boot gates and split startup"
```
