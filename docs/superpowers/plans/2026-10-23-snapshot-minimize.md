# Snapshot Minimizer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `firedancer-dev snapshot-minimize --ledger <dir> --start-slot S --end-slot E --out <dir>` replays a ledger from its snapshot X through E in the backtest, holds the root at S, records every account slots S+1..E load, and writes a small full snapshot at S plus a trimmed shredcap and genesis into `<out>`.

**Architecture:** The backtest topology gains the production snapshot writer block (snapmk, N snapzp, snaprd) and one shared pubkey set. The execrp tiles insert every loaded account key into the set while replaying slots after S. The backt tile stops certifying roots at S, and when the last slot has run it certifies S and asks replay (through the existing admin message) to snapshot it. snapmk, in a new "minimize" mode, adds the accounts the loader needs at boot, sums the kept lamports, feeds the set to snapzp as pubkey batches, and appends one balancing account so the file sums to bank S's untouched capitalization. The backt tile moves the finished file into `<out>` and exits.

**Tech Stack:** Firedancer C (tiles, stem, topology builder, accdb readonly API, fd_map_slot_para), vendored zstd, pcapng reader/writer in fd_util_extra.

**Spec:** `docs/superpowers/specs/2026-10-23-snapshot-minimizer-design.md`

**Worker rules (override the generic steps):** work in `/data/mjain/repos/scratch/worker-20261023-164037/firedancer` on branch `snapshot-minimize`. Build with `make -j CC=clang <target>`; objdir is `build/native/clang/21.1.8`. **Never commit.** Leave every change unstaged; mjain reviews hunks himself. Comments: few, short, plain English, 72 columns, no coined names. One statement per line. Smallest diff that works; reuse existing functions; no new state in the production client (everything here is gated off unless the backtest minimize mode is on).

> **Changed during the simplify wave (2026-10-24):** `fd_snapmin_sum_lamports` and `test_sum_and_balance` were dropped; snapmk sums the kept accounts' lamports while it streams them to snapzp and writes the balancing account in its FINISH step. On 2026-10-26 the three command-only config fields were grouped: `development.backtest.snapshot_minimize.{slot, max_accounts, boot_dir}` replaces `minimize_slot`, `minimize_max_accounts`, `minimize_boot_dir` below. The SDD ledger in `.superpowers/sdd/2026-10-23-snapshot-minimize/progress.md` has every ruling.

## Global Constraints

- Output file is a FULL snapshot named `snapshot-S-<base58(blake3(lthash))>.tar.zst`; lt hash and bank hash come from bank S untouched.
- Manifest capitalization is bank S's capitalization, untouched; the file sums to it because of one balancing account: system-owned, no data, pubkey `sha256("firedancer snapshot minimizer")`, lamports `capitalization - sum of kept lamports`. Abort if that key exists at S.
- Keep set contents at S (spec §5.3, §5.4): recorder keys (static keys, lookup table keys, resolved addresses, programdata) plus: all feature accounts; every vote account in the T-1..T-5 sets with node account, block collector and inflation collector; sysvars (14 ids listed in Task 1); builtins, stateless builtins, precompiles, native loader, stake, config, lookup table, feature, slashing, stake config program ids; the four Alpenglow PDAs (`carlgration`, `alpenclock`, `vote_reward_account`, `reward_epoch_delegated_stakes`); SPL token, token-2022, ATA, native mint; and only when `epoch(E) != epoch(S)` or EpochRewards is active at S: every stake account in the root delegation store plus its vote account, and the six core-BPF buffer addresses.
- Misses in the set are written as zero-lamport records (existing snapzp behaviour). The loader treats them as absent.
- `max_live_slots >= E - S + root_distance + 2` or the command refuses to run with that message.
- `max_full_snapshots_to_keep >= 2` in minimize mode so snapmk never recycles X.
- Snapshot production intervals are 0 in minimize mode.
- Agave loadability needs anza-xyz/agave PR 15834 plus `--accounts-db-skip-initial-hash-calculation`; not tested by unit tests.

## Review Focus

Inputs the spec implies that no task's unit test exercises. Each is pinned to a task's verification run below.

1. **S equals X** (snapshot already at S, nothing to replay): the root never advances, so the scheduled snapshot cannot fire; the backt tile must send the "snapshot now" admin command instead. Pinned to Task 3 step 7 and Task 6 run B.
2. **Bad slot right after S** (B = S+1 within root_distance): the dead-slot message must trigger the S cert and the snapshot, not a crash. Pinned to Task 6 run C.
3. **Keep set full**: insert returns `FD_MAP_ERR_FULL`; the run must stop with a message naming `--max-accounts`, never drop keys silently. Pinned to Task 4 step 4.
4. **Output dir on another filesystem**: `rename()` fails with EXDEV; copy then unlink instead of failing. Pinned to Task 3 step 6.
5. **Capture without a root record for S or without bank hash records in S+1..E**: refuse before boot with the slot named. Pinned to Task 5 step 3.

---

### Task 1: Pubkey set and keep-set library (`fd_snapmin`)

**Files:**
- Create: `src/discof/backup/fd_snapmin.h`, `src/discof/backup/fd_snapmin.c`, `src/discof/backup/test_snapmin.c`
- Modify: `src/discof/backup/Local.mk` (add `fd_snapmin` to the `fd_discof` objs on line 2's style, add `test_snapmin` unit test next to `test_snap_roundtrip`)
- Modify: `src/flamenco/runtime/fd_system_ids_pp.h`, `fd_system_ids.h`, `fd_system_ids.c`, `test_system_ids.c` (add `fd_solana_spl_token_2022_id` = `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`, `fd_solana_spl_associated_token_id` = `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`, same style as `fd_solana_spl_token_id`)

**Interfaces:**
- Consumes: `fd_map_slot_para.c` (`src/util/tmpl`), `fd_bank_t`, `fd_banks_t`, `fd_vote_stakes_iter_*`, `fd_stake_delegations_iter_*`, `fd_feature_iter_*`, `fd_builtins()`, `fd_stateless_builtins()`, `fd_precompiles()`, `fd_alpenglow_pda()`, `fd_sysvar_cache_epoch_rewards_read()`, `fd_slot_to_epoch()`, readonly accdb calls only (`fd_accdb_lamports`, `fd_accdb_exists`).
- Produces (all in `fd_snapmin.h`):

```c
/* One shared set of account addresses, written by many tiles at
   once and read by one tile afterwards. */
struct fd_snapmin_ele { fd_pubkey_t key; ulong used; };   /* used!=0 marks a live slot */
typedef struct fd_snapmin_ele fd_snapmin_ele_t;
typedef struct fd_snapmin fd_snapmin_t;                    /* local join, FD_SNAPMIN_JOIN_FOOTPRINT bytes */

ulong          fd_snapmin_align    ( void );
ulong          fd_snapmin_footprint( ulong ele_max );                 /* ele_max power of two */
void *         fd_snapmin_new      ( void * shmem, ulong ele_max, ulong seed );
fd_snapmin_t * fd_snapmin_join     ( void * ljoin, void * shmem );
int            fd_snapmin_insert   ( fd_snapmin_t * set, uchar const * pubkey ); /* 0 ok, FD_MAP_ERR_FULL */
ulong          fd_snapmin_cnt      ( fd_snapmin_t const * set );      /* distinct keys inserted */
ulong          fd_snapmin_next     ( fd_snapmin_t * set, ulong * cursor, fd_pubkey_t * out, ulong out_max ); /* single reader; returns count, 0 at end */

/* Accounts the loader and the first replayed slots read without a
   transaction naming them.  Everything comes from bank S and the
   root stake store; accdb is not touched. */
void  fd_snapmin_keep_boot_accounts( fd_snapmin_t * set, fd_bank_t * bank, fd_banks_t * banks, ulong end_slot );
ulong fd_snapmin_sum_lamports( fd_snapmin_t * set, fd_accdb_t * accdb, fd_accdb_fork_id_t fork_id );
void  fd_snapmin_balance_key( fd_pubkey_t * out );                   /* sha256 of "firedancer snapshot minimizer" */

extern fd_topo_obj_callbacks_t fd_obj_cb_snapmin;                    /* obj type "snapmin", pod key "obj.<id>.ele_max" */
```

- [ ] **Step 1: Write the failing test** `test_snapmin.c`, booted with `fd_svm_test_boot` exactly as `test_snap_roundtrip.c:1965-1985` (ROOT_SLOT 1770, 432 slots/epoch, 3 mock validators, `init_sysvars`, `init_feature_accounts`, `init_builtins` on). Cases:
  - `test_set`: new/join with `ele_max=1024`; insert the system program id (all zero bytes) and 3 random keys twice each; `fd_snapmin_cnt()==4`; `fd_snapmin_next()` over a cursor yields exactly those 4 keys then 0; inserting 1025 distinct keys into a 1024-slot set returns `FD_MAP_ERR_FULL` at some point.
  - `test_boot_accounts_same_epoch`: `end_slot = ROOT_SLOT+10` (same epoch, EpochRewards inactive): set contains every `ids[i].id` feature pubkey, the 14 sysvar ids, `fd_solana_system_program_id`, `fd_solana_bpf_loader_upgradeable_program_id`, `fd_solana_stake_program_id`, `fd_solana_address_lookup_table_program_id`, the 3 mock validators' vote and identity pubkeys (from `fd_vote_stakes_iter_*` at T_1/T_2), `fd_solana_spl_token_id`, `fd_solana_spl_token_2022_id`, the four PDAs (`fd_alpenglow_pda` on each seed); and does NOT contain the mock stake accounts (iterate `fd_banks_stake_delegations_root_query( mini->banks )` and assert none present).
  - `test_boot_accounts_new_epoch`: `end_slot = ROOT_SLOT + 432` (next epoch): all mock stake accounts present, `fd_solana_stake_program_v5_buffer_address` present.
  - `test_sum_and_balance`: `fd_snapmin_sum_lamports( set, mini->runtime->accdb, bank->accdb_fork_id )` equals the sum over the set of `fd_accdb_lamports(...)` computed by the test; `fd_snapmin_balance_key()` is deterministic and `!fd_accdb_exists( accdb, fork, key )`.
- [ ] **Step 2: Run it to make sure it fails** `make -j CC=clang test_snapmin` → fails to compile (no header).
- [ ] **Step 3: Implement** `fd_snapmin.h/.c`. Map: `MAP_NAME fd_snapmin_map`, `MAP_ELE_T fd_snapmin_ele_t`, `MAP_KEY_T fd_pubkey_t`, `MAP_KEY key`, `MAP_KEY_EQ` memcmp-equal, `MAP_KEY_HASH(k,seed) fd_hash( seed, k, 32 )`, `MAP_ELE_IS_FREE(ctx,e) (!(e)->used)`, `MAP_ELE_FREE`, `MAP_ELE_MOVE`, `MAP_VERSION_T ushort`, `MAP_LOCK_MAX 8192`, `MAP_IMPL_STYLE 1` in the header and `2` in the .c (copy `src/groove/fd_groove_meta.h:60-76`). Layout of the shared object: header `{ ulong magic; ulong ele_max; ulong cnt; }` then the map region then the element store, element store memset to zero in `new` before `fd_snapmin_map_new`. `insert`: `prepare( FD_MAP_FLAG_BLOCKING )`, if free set key, `used=1`, atomic `cnt++`, publish; else cancel. `next`: linear scan of the element store from `*cursor`, copying used keys, up to `out_max`. `keep_boot_accounts`: the class loops from spec §5.4 using the APIs listed in Interfaces; the sysvar list is `clock, epoch_rewards, epoch_schedule, last_restart_slot, recent_block_hashes, rent, slot_hashes, slot_history, stake_history, fees, instructions, rewards, owner, incinerator`; the vote set loop copies `fd_ssmanifest_writer.c:88-125` (kinds T_1..T_5 via `epoch_stakes_iter_kind`), inserting `pubkey`, `node_account`, `block_collector`, `inflation_collector`; the stake rule is `fd_slot_to_epoch( &bank->f.epoch_schedule, end_slot, NULL )!=bank->f.epoch || epoch_rewards.active`, iterating `fd_banks_stake_delegations_root_query( banks )` and inserting `stake_account` and `vote_account`; the six buffer ids are the externs at `fd_system_ids.h:50-55`. `fd_obj_cb_snapmin` follows `fd_obj_cb_backup` in `src/app/firedancer/callbacks.c:258-280` but lives in `fd_snapmin.c` (pattern `fd_obj_cb_snapin_shmem`, `fd_snapin_tile.c:2491`).
- [ ] **Step 4: Run the test** `make -j CC=clang test_snapmin && build/native/clang/21.1.8/unit-test/test_snapmin` → `pass`. Also `make -j CC=clang test_system_ids && build/native/clang/21.1.8/unit-test/test_system_ids` → pass.
- [ ] **Step 5: Leave unstaged.** Report the new files and the line counts.

---

### Task 2: snapmk minimize mode

**Files:**
- Modify: `src/disco/topo/fd_topo.h:758-771` (add to `snapmk`: `ulong snapmin_obj_id; ulong snapmin_end_slot;`)
- Modify: `src/app/firedancer/topology.c:1893-1906` (set `tile->snapmk.snapmin_obj_id = ULONG_MAX; snapmin_end_slot = 0UL;`)
- Modify: `src/discof/backup/fd_snapmk_tile.c`

**Interfaces:**
- Consumes: Task 1 (`fd_snapmin_join`, `fd_snapmin_keep_boot_accounts`, `fd_snapmin_sum_lamports`, `fd_snapmin_balance_key`, `fd_snapmin_next`).
- Produces: snapmk writes a full snapshot from the set when `tile->snapmk.snapmin_obj_id!=ULONG_MAX`. No message or link changes.

- [ ] **Step 1: Context fields.** In `struct fd_snapmk` add `fd_snapmin_t * snapmin; ulong snapmin_end_slot; ulong snapmin_cursor; ulong balance_lamports; fd_pubkey_t balance_key;` and a local join area in the scratch layout (`FD_SNAPMIN_JOIN_FOOTPRINT`). In `unprivileged_init` join the object when `tile->snapmk.snapmin_obj_id!=ULONG_MAX`, else `ctx->snapmin=NULL`.
- [ ] **Step 2: Build the set in `snap_start`.** After the compaction freeze (`fd_snapmk_tile.c:1754-1767`) and before `fd_ssmanifest_writer_init` (:1828), when `ctx->snapmin`: `FD_CHECK_ERR( !incremental, ... )`; `fd_snapmin_keep_boot_accounts( ctx->snapmin, bank, ctx->banks, ctx->snapmin_end_slot )`; `ulong kept = fd_snapmin_sum_lamports( ctx->snapmin, ctx->accdb, root_fork_id )`; `FD_CHECK_ERR( kept<=bank->f.capitalization, "kept lamports exceed capitalization" )`; `ctx->balance_lamports = bank->f.capitalization - kept`; `fd_snapmin_balance_key( &ctx->balance_key )`; `FD_CHECK_ERR( !fd_accdb_exists( ctx->accdb, root_fork_id, ctx->balance_key.uc ), "balancing account key already exists" )`; `ctx->snapmin_cursor = 0UL`; log NOTICE with the count and lamports.
- [ ] **Step 3: Account source.** At `:1427` pick `SNAPMK_STATE_ACCDB_DELTA` when `ctx->incremental || ctx->snapmin`. In `snapmk_accdb_delta` (:1234) take the batch from `fd_snapmin_next( ctx->snapmin, &ctx->snapmin_cursor, batch.pubkey, FD_BACKUP_CACHE_PARA )` when `ctx->snapmin`, else the existing loop; keep `ctx->delta.ele_cnt` accounting.
- [ ] **Step 4: Balancing record.** New static `snapmk_balance_record( fd_snapmk_t * ctx )` called in the shared `ACCDB_DISK_FINISH/ACCDB_DELTA_FINISH` case after the `lseek` (:1487) and before `snapmk_status_cache_prepare` (:1492), only when `ctx->snapmin`: take an appendvec ticket with snapzp's wrap rule (`fd_snapzp_tile.c:385-390`, `slot_lo=0`), `zip_reset`, `fd_backup_tar_file_hdr( &meta, sizeof(snap_acc_hdr_t) )`, name `accounts/<slot>.<id>`, `fd_tar_meta_set_chksum`, `zip_append( &meta, 512 )`, a `snap_acc_hdr_t` with `pubkey=balance_key`, `lamports=balance_lamports`, `owner=fd_solana_system_program_id`, all else zero, `zip_append`, zero pad to 512, `zip_flush( ctx, ZSTD_e_end )`. Skip the record when `balance_lamports==0`.
- [ ] **Step 5: Build** `make -j CC=clang firedancer-dev firedancer` → clean. Run `build/native/clang/21.1.8/unit-test/test_snapzp_tile` and `test_snap_roundtrip` → pass (unchanged behaviour).
- [ ] **Step 6: Leave unstaged.** Report hunks: ~60 lines in snapmk, 2 in fd_topo.h, 2 in topology.c.

---

### Task 3: Backtest tile minimize mode and config keys

**Files:**
- Modify: `src/app/shared/fd_config.h:114-118` (`development.backtest`: add `ulong minimize_slot; ulong minimize_max_accounts; char minimize_out_dir[ PATH_MAX ];`), `src/app/shared/fd_config_parse.c:94` (`CFG_POP` for the three), `src/app/shared/fd_config_json.c:489` (mirror), `src/app/firedancer/config/default.toml:2335-2340` (defaults `0`, `4194304`, `""`, with short comments)
- Modify: `src/disco/topo/fd_topo.h:611-617` (`backtest`: add `ulong minimize_slot; char minimize_out_dir[ PATH_MAX ]; char snapshots_path[ PATH_MAX ];`), `src/app/firedancer/topology.c:1866-1872` (fill them from `config->firedancer.development.backtest.*` and `config->paths.snapshots`)
- Modify: `src/discof/backtest/fd_backtest_tile.c`

**Interfaces:**
- Consumes: `fd_snapmk_msg_t` (`fd_snapmk_tile.h`), `FD_ADMINCTL_CMD_SNAP_CREATE` and result codes (`src/discof/admin/fd_adminctl.h`), replay's admin handling (`fd_replay_tile.c:3985-4059`, unchanged).
- Produces: in minimize mode the backt tile (a) sends `FD_ADMINCTL_CMD_SNAP_CREATE` with `sig=S` on out link `admin_replay` right after the snapshot-done handshake when `S > start_slot`; (b) never publishes a root cert for a slot `>= S` until the end; (c) on the last slot (completed `>= end_slot`, source drained, or any `REPLAY_SIG_SLOT_DEAD`) publishes the cert for S, or when `S == start_slot` sends `FD_ADMINCTL_CMD_SNAP_CREATE` with `sig=0`; (d) on `FD_SNAPMK_MSG_CREATED` for slot S moves `<snapshots_path>/<name>` to `<minimize_out_dir>/<name>` and calls `finish()`; on `FD_SNAPMK_MSG_FAILED` or a non-zero admin result `FD_LOG_ERR`. Link names: in `snapmk_out` → `IN_KIND_SNAPMK`, in `replay_admin` → `IN_KIND_ADMIN`, out `admin_replay` (optional, `fd_topo_find_tile_out_link`, ULONG_MAX when absent).

- [ ] **Step 1: Config plumbing** (fd_config.h, parse, json, default.toml, fd_topo.h, topology.c). Build `firedancer` and `firedancer-dev` → clean. Run `build/native/clang/21.1.8/bin/firedancer-dev configure check --config src/app/firedancer-dev/config/minimal.toml` only if cheap; otherwise rely on the build plus Task 6.
- [ ] **Step 2: Tile state.** Add to `fd_backt_tile_t`: `ulong minimize_slot; int minimize_scheduled; int minimize_ended; char minimize_out_dir[ PATH_MAX ]; char snapshots_path[ PATH_MAX ]; ulong admin_out_idx; fd_backt_out_t admin_out[1];` plus `#define IN_KIND_SNAPMK (3)` and `#define IN_KIND_ADMIN (4)`. Init from `tile->backtest.*`; `admin_out` via `fd_topo_find_tile_out_link( topo, tile, "admin_replay", 0UL )`; in-link names `snapmk_out`, `replay_admin` mapped in the init loop at `:658-661`. `FD_TEST( !ctx->minimize_slot || ctx->admin_out_idx!=ULONG_MAX )`.
- [ ] **Step 3: Schedule.** In the `IN_KIND_SNAP` DONE handler (`:383-421`), after `start_slot` is known and the source checked: if `minimize_slot && minimize_slot>start_slot` publish the admin frag `fd_stem_publish( stem, admin_out_idx, /*sig*/minimize_slot, 0UL, 0UL, fd_frag_meta_ctl( FD_ADMINCTL_CMD_SNAP_CREATE, 0, 0, 0 ), 0UL, tspub )` and set `minimize_scheduled=1`. Genesis mode with minimize is an error (`FD_LOG_ERR`).
- [ ] **Step 4: Hold the root.** In the root choice (`:484-494`) when `minimize_slot` and `*rooted_slots_peek_head_const(...) >= minimize_slot`, do not pop; `root_slot = prev_root`.
- [ ] **Step 5: End of replay.** New static `minimize_end( ctx, stem, tspub )`: returns if `minimize_ended`; sets it; `FD_LOG_NOTICE(( "replay reached the last slot, writing minimized snapshot at slot %lu", S ))`; if `S>start_slot` publish `fd_votor_certed_t{ kind=AG_CERT_KIND_FAST_FINAL, slot=S, block_id=rooted_slots_block_id[S%BANK_HASH_BUFFER_LEN] }` on `votor_out` exactly as `:511-519`; else publish the admin frag with `sig=0`. Call it instead of `finish()` at `:502-504` when `minimize_slot`, and from the `REPLAY_SIG_SLOT_DEAD` branch (`:441-451`, `FD_LOG_WARNING` instead of `FD_LOG_ERR`) and the bank-hash mismatch branch (`:476-483`, `FD_LOG_WARNING` instead of `FD_LOG_ERR`) when `minimize_slot`.
- [ ] **Step 6: Completion.** `IN_KIND_SNAPMK`: on `FD_SNAPMK_MSG_CREATED` with `created->slot==minimize_slot`: build `src = "<snapshots_path>/<name>"`, `dst = "<minimize_out_dir>/<name>"`; `rename( src, dst )`; on `EXDEV` copy with `copy_file_range` in a loop then `unlink( src )`; `FD_LOG_NOTICE(( "wrote %s", dst ))`; `finish( ctx, minimize_slot, fd_log_wallclock() )`. On `FD_SNAPMK_MSG_FAILED`: `FD_LOG_ERR(( "minimized snapshot creation failed" ))`. Other message types ignored. `IN_KIND_ADMIN`: `if( sig ) FD_LOG_ERR(( "replay rejected snapshot request (result %lu)", sig ))`.
- [ ] **Step 7: Build** `make -j CC=clang firedancer-dev` → clean. Run a plain backtest on the smallest CI ledger to prove no change when the mode is off (see Task 6 run A for the command).
- [ ] **Step 8: Leave unstaged.** Report hunks (~120 lines in the tile, ~25 config/topo lines).

---

### Task 4: Recorder in execrp and the snapshot block in the backtest topology

**Files:**
- Modify: `src/disco/topo/fd_topo.h:535-552` (`execrp`: add `ulong snapmin_obj_id; ulong snapmin_slot;`), `src/app/firedancer/topology.c:1630-1647` (set `snapmin_obj_id=ULONG_MAX; snapmin_slot=0UL;`)
- Modify: `src/discof/execrp/fd_execrp_tile.c`
- Modify: `src/app/firedancer-dev/commands/backtest.c`
- Modify: `src/app/firedancer-dev/main.h` (`extern fd_topo_obj_callbacks_t fd_obj_cb_snapmin;` and `&fd_obj_cb_snapmin,` in `CALLBACKS[]`)

**Interfaces:**
- Consumes: Task 1 set API; Task 2 snapmk fields; Task 3 backt fields and config keys; production wiring in `src/app/firedancer/topology.c:424-432, 475-488, 591-595, 738-741, 915-922, 989-991, 1186-1188, 1197-1207, 1226-1244, 1291-1306` and `fd_topo_configure_tile` branches `:1893-1920`.
- Produces: `backtest_topo( config_t * )` builds the snapshot block, the admin links and the `snapmin` object when `config->firedancer.development.backtest.minimize_slot!=0`; `fd_backtest_topo( config_t * )` and `fd_backtest_run( args_t *, config_t * )` are exported for Task 6 (`commands/backtest.h`).

- [ ] **Step 1: Recorder.** In `fd_execrp_tile_t` add `fd_snapmin_t * snapmin; ulong snapmin_slot;` and the join area in `scratch_footprint`. Join in `unprivileged_init` when `tile->execrp.snapmin_obj_id!=ULONG_MAX`. New static `record_txn_accounts( fd_execrp_tile_t * ctx )` called between `fd_runtime_prepare_and_execute_txn` (`:259`) and commit/cancel (`:264`), gated on `ctx->snapmin && ctx->bank->f.slot>ctx->snapmin_slot`. It inserts: the static keys from the payload (`TXN(txn)->acct_addr_cnt` at `acct_addr_off`), each lookup table key (`fd_txn_get_address_tables_const(txn)[i].addr_off`), `txn_out.accounts.keys[0..cnt)`, `txn_out.accounts.executable[i]->pubkey` for `i<executable_cnt`, and `executable_skipped_key[0..executable_skipped_cnt)`. Any `FD_MAP_ERR_FULL` → `FD_LOG_ERR(( "snapshot minimizer account set is full, raise [development.backtest] minimize_max_accounts" ))`.
- [ ] **Step 2: Topology.** In `backtest_topo`, `int minimize = !!config->firedancer.development.backtest.minimize_slot;`. When set: `FD_TEST( !disable_snap_loader )`; `ulong snapzp_tile_cnt = config->firedancer.layout.snapzp_tile_count;` (`FD_TEST( snapzp_tile_cnt>0 )`); add wksps `snapmk snapzp snapmk_zp replay_snapmk snapmk_out snaprd snaprd_out snapmin admin`; links `snapmk_zp` x N (1024, `sizeof(fd_backup_frag_t)`), `replay_snapmk` (16, `sizeof(fd_replay_snap_start_t)`), `snapmk_out` (128, `sizeof(fd_snapmk_msg_t)`), `snaprd_out` (1024, `FD_BACKUP_RD_MTU`), `admin_replay` and `replay_admin` (32, MTU 0); objs `fseq` → pod `snapzp.fseq`, `backup` → pod `backup` + `obj.%lu.max_accounts`, `snapmin` → pod `snapmin` + `obj.%lu.ele_max = minimize_max_accounts` (rounded up to a power of two), per-snapzp `accdb_epoch.snapzp.%lu` fseqs and `accdb_epoch.snapmk`; tiles `snapmk`, N x `snapzp`, `snaprd`; tile in/out exactly as `topology.c:915-922` plus replay in on `snapmk_out`, backt in on `snapmk_out`, backt out `admin_replay`, replay in `admin_replay`, replay out `replay_admin`, backt in `replay_admin`; `tile_uses`: banks RW for snapmk, txncache RW for snapmk, accdb RW snapmk / RO snapzp and snaprd, zp fseq, backup obj, snaprd_out dcache RO for snapzp, `snapmin` RW for snapmk and every execrp; accdb joiner count `+ 2 + snapzp_tile_cnt`; `tile->accdb.snapmk_epoch_obj_id` and `snapzp_epoch_obj_ids/cnt` (see `topology.c:1677-1683`). In the configure loop (`:439-454`) set `tile->snapmk.snapmin_obj_id`, `tile->snapmk.snapmin_end_slot = config->firedancer.development.ledger_input.end_slot`, `tile->execrp.snapmin_obj_id`, `tile->execrp.snapmin_slot = minimize_slot`, `tile->replay.full_snapshot_interval_blocks = 0`, `tile->replay.incremental_snapshot_interval_blocks = 0`.
- [ ] **Step 3: Export.** Add `src/app/firedancer-dev/commands/backtest.h` declaring `void fd_backtest_topo( config_t * config ); void fd_backtest_run( args_t * args, config_t * config );` implemented as thin non-static wrappers around `backtest_topo` and the body of `backtest_cmd_fn` (which then calls `fd_backtest_run`).
- [ ] **Step 4: Verify the full-set error path.** Build; then with a hand TOML setting `minimize_slot` to the boot slot of a CI ledger and `minimize_max_accounts = 2` run `firedancer-dev backtest --config <toml>` and confirm the run stops with the "account set is full" message (this exercises Review Focus 3 before the command exists; the run otherwise behaves as Task 6 run A).
- [ ] **Step 5: Build** `make -j CC=clang firedancer-dev firedancer` → clean; a plain backtest (mode off) still passes.
- [ ] **Step 6: Leave unstaged.** Report hunks (~40 recorder, ~110 topology, ~10 export).

---

### Task 5: Shredcap trimmer

**Files:**
- Create: `src/discof/backtest/fd_shredcap_trim.h`, `src/discof/backtest/fd_shredcap_trim.c`, `src/discof/backtest/test_shredcap_trim.c`
- Modify: `src/discof/backtest/fd_libc_zstd.h/.c` (add a write-side cookie), `src/discof/backtest/fd_backtest_src_pcap.c` (export the UDP payload finder), `src/discof/backtest/Local.mk`

**Interfaces:**
- Consumes: `fd_pcapng_iter_*`, `fd_pcapng_fwrite_shb/idb/pkt1`, `fd_zstd_rstream_open`, `fd_shred_parse`, `fd_shredcap.h` records.
- Produces:

```c
/* fd_libc_zstd.h */
FILE * fd_zstd_wstream_open( FILE * file, ZSTD_CStream * cstream, ulong buf_sz ); /* ftell returns bytes written so far */

/* fd_backtest_src_pcap.c, now exported */
uchar const * fd_backtest_src_pcap_udp_payload( fd_pcapng_frame_t const * frame, uint format, ulong * out_sz );

/* fd_shredcap_trim.h */
struct fd_shredcap_trim_stats { ulong first_slot; ulong last_slot; ulong shred_cnt; ulong bank_hash_cnt; int start_rooted; };
typedef struct fd_shredcap_trim_stats fd_shredcap_trim_stats_t;
int fd_shredcap_trim( char const * in_path, char const * out_path, ulong start_slot, ulong end_slot, fd_shredcap_trim_stats_t * stats ); /* 0 ok, else -1 with FD_LOG_WARNING naming the slot: no frames for start_slot, no root record for start_slot, or a slot in range with shreds but no bank hash record */
```

- [ ] **Step 1: Write the failing test** `test_shredcap_trim.c`: write a capture into a temp file with `fd_pcapng_fwrite_shb`, two IDBs (IPv4 `lo` 127.0.0.1, USER0 `shredcap0`), then for slots 1..5: two fake data shreds per slot (IPv4+UDP header as `blockstore2shredcap.c:494-539` wraps them, shred bytes: a legacy data shred of `FD_SHRED_MIN_SZ` with `variant=0xa5`, `slot`, `idx`), then a `BANK_HASH_V0` record and a `ROOT_SLOT_V0` record for the slot. Trim `[2,4]` into a second temp file; assert `fd_shredcap_trim` returns 0, `stats.first_slot==2`, `last_slot==4`, `shred_cnt==6`, `bank_hash_cnt==3`, `start_rooted==1`; open the output with `fd_backtest_src_create` (`format="auto"`) and check `fd_backtest_src_shred` yields 6 shreds with slots 2,2,3,3,4,4 and `fd_backtest_src_slot_info` reports `rooted` and `bank_hash_set` for 2..4 and not for 5. Trim `[2,9]` → returns 0 with `last_slot==5`. Trim with `start_slot=7` → returns -1.
- [ ] **Step 2: Run it to make sure it fails** `make -j CC=clang test_shredcap_trim` → compile error.
- [ ] **Step 3: Implement.** Writer cookie in `fd_libc_zstd.c` mirroring `rstream_*` (`write` compresses with `ZSTD_compressStream2( ZSTD_e_continue )`, `seek` answers `SEEK_CUR` with the logical count, `close` flushes with `ZSTD_e_end`). Trimmer: detect zstd by magic as `fd_backtest_src.c:16-87` does and open via `fd_zstd_rstream_open`; iterate frames; per frame compute the slot (metadata: `FD_LOAD( ulong, data+4 )`; shred: `fd_shred_parse( fd_backtest_src_pcap_udp_payload(...) )->slot`); write SHB and the two IDBs with the byte-identical options from the recon (`userappl="blockstore2shredcap"` is not required; use `fd_pcapng_shb_defaults`); copy frames with `start_slot<=slot<=end_slot` via `fd_pcapng_fwrite_pkt1( out, frame->data, frame->data_sz, NULL, 0UL, frame->if_idx, frame->ts )`; fill stats; return -1 if no frame of `start_slot` was seen or if `start_slot` had no root record (Review Focus 5).
- [ ] **Step 4: Run the test** → `pass`. `make -j CC=clang test_libc_zstd && build/.../test_libc_zstd` → pass.
- [ ] **Step 5: Leave unstaged.** Report (~150 trimmer, ~70 zstd cookie, ~10 export).

---

### Task 6: The `snapshot-minimize` command

**Files:**
- Create: `src/app/firedancer-dev/commands/snapshot_minimize.c`
- Modify: `src/app/firedancer-dev/Local.mk` (`add-objs,commands/snapshot_minimize`), `src/app/firedancer-dev/main.h` (`extern action_t fd_action_snapshot_minimize;` + `ACTIONS[]` entry), `src/app/shared/fd_action.h` (`struct { char ledger[ PATH_MAX ]; char out[ PATH_MAX ]; ulong start_slot; ulong end_slot; ulong max_accounts; int no_watch; } snapshot_minimize;` in `union fdctl_args`)

**Interfaces:**
- Consumes: `fd_backtest_topo`, `fd_backtest_run` (Task 4), `fd_shredcap_trim` (Task 5), config keys (Task 3), `configure_cmd_perm`, `run_cmd_perm` as in `backtest.c:511-518`.
- Produces: `action_t fd_action_snapshot_minimize = { .name="snapshot-minimize", .args, .fn, .perm, .topo, .usage="snapshot-minimize --ledger <dir> --start-slot <S> --end-slot <E> --out <dir> [--max-accounts <n>] [--no-watch]", .description="Write a minimized snapshot at S for replaying slots S+1..E from a ledger directory", .args_help }`.

- [ ] **Step 1: Args** (`fd_env_strip_cmdline_cstr/ulong/contains`, all four required, `FD_LOG_ERR` with the usage line if missing or `end_slot<=start_slot`).
- [ ] **Step 2: Config fixup** (in `fn`, before the topology rebuild, pattern `backtest.c:520-527`): `paths.snapshots = ledger`, `paths.genesis = <ledger>/genesis.bin`, `development.ledger_input.path = <ledger>/shreds.pcapng.zst` (if missing and `<ledger>/rocksdb` exists: `FD_LOG_ERR` printing the exact `contrib/blockstore/blockstore2shredcap --rocksdb <ledger>/rocksdb --out <ledger>/shreds.pcapng.zst --zstd` command), `development.ledger_input.end_slot = E`, `development.backtest.minimize_slot = S`, `minimize_out_dir = out`, `minimize_max_accounts` from the flag, `snapshots.full_snapshot_interval_blocks = 0`, `incremental_snapshot_interval_blocks = 0`, `max_full_snapshots_to_keep = fd_ulong_max( 2, cfg )`, `gossip.entrypoints_cnt` left as the TOML has it (the generated TOML must carry `[gossip] entrypoints = ["0.0.0.0:1"]` like `run_ledger_backtest.sh:265-268`; `FD_LOG_ERR` if zero).
- [ ] **Step 3: Checks before boot**: `<out>` must not exist (`mkdir` it, 0700); the ledger must hold a snapshot archive whose slot `<= S` (`fd_ssarchive_latest_best` style scan: pick the newest full/incremental with slot `<= S`, `FD_LOG_ERR` naming the available slots otherwise); `max_live_slots >= E-S+root_distance+2` (`FD_LOG_ERR(( "[runtime] max_live_slots must be at least %lu for this span", need ))`); O_DIRECT probe `open( "<ledger>/.snapmin-odirect-probe", O_WRONLY|O_CREAT|O_DIRECT, 0600 )` then unlink, `FD_LOG_ERR` on `EINVAL` (tmpfs); `fd_shredcap_trim( in, "<out>/shreds.pcapng.zst", S, E, &stats )` must return 0 (it refuses on its own when `S` has no root record or a slot in `[S,E]` has shreds but no bank hash record) or `FD_LOG_ERR`; copy `genesis.bin` with `copy_file_range`.
- [ ] **Step 4: Run.** `fd_backtest_topo( config )` then `fd_backtest_run( args(no_watch), config )`. `.topo = fd_backtest_topo` wrapper (mode off at that point is fine: the fixup rebuilds).
- [ ] **Step 5: Build** `make -j CC=clang firedancer-dev` → clean; `firedancer-dev snapshot-minimize --help` prints usage.
- [ ] **Step 6: Verification runs** (write a TOML with a unique `name` and `[hugetlbfs] mount_path`, `FD_BACKTEST_SHARED_HOST=1`, as the box runs other Firedancer instances; take the box lock per the resource-sharing rules; never use `run_ledger_backtest.sh` as is because it runs `sudo killall firedancer-dev`):
  - Run A (baseline, mode off): `firedancer-dev backtest --config <toml>` on CI ledger `alpenglow-leader-credits` (36 slots) → "Backtest playback done." (this is also Task 3/4's regression check).
  - Run B (S == X): `snapshot-minimize --ledger dump/alpenglow-leader-credits --start-slot <X> --end-slot <X+20> --out /tmp/min-b` → output has `snapshot-X-*.tar.zst`, `shreds.pcapng.zst`, `genesis.bin`; replaying `/tmp/min-b` with a backtest to `X+20` logs "Bank hash matches!" for every slot. (Review Focus 1.)
  - Run C (S > X, bad slot right after S): pick a CI ledger, first run a backtest to find bank hashes; craft nothing: instead minimize with `--start-slot X+5 --end-slot X+6` on a healthy ledger and replay the output; then simulate a mismatch by minimizing a ledger whose shredcap is edited? Simpler: use the mainnet ledger from Task 7 once a real mismatch exists. For this task: `--start-slot X+5 --end-slot X+6` must produce a snapshot at X+5 whose replay to X+6 matches. (Review Focus 2 is pinned to Task 7 run on a real bad slot.)
  - Record wall times (load, replay, keep set, write) from the log into the worker artifacts README.
- [ ] **Step 7: Leave unstaged.** Report (~250 lines).

---

### Task 7: Weekend validation (artifacts only, nothing in the tree)

**Files:** `/data/mjain/repos/scratch/worker-20261023-164037/minimizer-tests/README.md` plus scripts and logs there.

- [ ] **Step 1: Mainnet ledger.** The Agave node under `/data/mjain/agave-mainnet` (PR 15834 build) has `rocksdb/`, a full snapshot at X=460569171 and incrementals every 500 slots. Convert a slot range with `contrib/blockstore/blockstore2shredcap --rocksdb ... --start-slot <X> --end-slot <E> --zstd` into a ledger dir with `genesis.bin` (fetch via `agave-ledger-tool`'s `genesis.bin` from the rocksdb ledger dir) and the full (+ incremental) snapshot.
- [ ] **Step 2: Inside one epoch.** Minimize `S = incremental slot`, `E = S+40`; replay output; every bank hash matches; record size and times.
- [ ] **Step 3: Across the epoch boundary** (Sunday ~11:30 UTC): `S` = last incremental before the boundary, `E` = boundary + 40; replay output; bank hashes match through the first slots of the new epoch.
- [ ] **Step 4: Bad slot.** Take a minimized ledger and corrupt one account in the snapshot? No: instead use a real mismatch if one appears during the weekend; otherwise use the `remove-inactive-stakes` style CI ledgers whose expected hashes are known and edit one `BANK_HASH_V0` record in a copied shredcap to force a "mismatch" at B = S+1, run the minimizer, and confirm it still produces the snapshot at S (Review Focus 2).
- [ ] **Step 5: Agave load.** `agave-ledger-tool verify --accounts-db-skip-initial-hash-calculation --halt-at-slot E -l <minimized ledger dir with rocksdb copied in>` on the PR 15834 build; also `agave-ledger-tool create-snapshot S --minimized --ending-slot E` on the same ledger for the size/time comparison table.
- [ ] **Step 6: Soak.** Loop the minimizer over 20 consecutive 500-slot windows of the mainnet ledger overnight; replay each output; collect pass/fail and timings.
- [ ] **Step 7: README** with the tables (sizes, times, FD vs Agave) and the exact commands.
