# Instant boot, plan A: accounts database changes

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the accounts database (`src/flamenco/accdb`) safe for live reads and writes while the snapshot loader is writing, and let reads hide loader-written entries on request.

**Architecture:** Three small, always-correct changes to `fd_accdb.c`: every chain-head load honors the loader's lock sentinel; loader-written entries carry a flag bit and are inserted behind live versions of the same key; a shared hide flag makes reads skip flagged entries. Each lands as its own commit with unit tests, and the racesan build gets one new weave.

**Tech Stack:** C (Firedancer style, see CONTRIBUTING.md and src/tango), `make`, unit tests in `src/flamenco/accdb/test_accdb.c`, racesan weaves in `src/flamenco/accdb/test_accdb_racesan.c`.

**Spec:** `docs/superpowers/specs/2026-10-06-instant-boot-design.md`

## Global Constraints

- Worktree: `/data/mjain/repos/scratch/worker-20261005-200945/firedancer`, branch `instant-boot`. Never touch `/data/mjain/repos/firedancer`.
- Build: `make -j test_accdb test_accdb_cache bench_accdb_hotread test_snapin_accdb` (objdir `build/native/gcc/11.5.0`); run those with `--page-sz normal`. Racesan: `make -j BUILDDIR=gcc-racesan EXTRAS=racesan test_accdb_racesan` (objdir `build/gcc-racesan`); run that binary with NO arguments (any leftover argument is taken as a test-name filter, so `--page-sz normal` silently runs nothing), or with explicit test names. The racesan harness is cooperative: a spin loop only lets another fiber run at an `fd_racesan_hook` call, so any new spin loop that a weave can reach needs a hook inside it.
- Baseline (before any change): all four tests pass; `bench_accdb_hotread` reports 80 ns/op (12.48M ops/s). After task 4 it must stay within noise (under 85 ns/op over two runs).
- Style: smallest diff, one statement per line, braces on multi-line bodies, comments in plain English above the thing they describe, 72 columns, two spaces after a period. No coined names in comments ("the loader's lock", not "sentinel protocol"). No new helpers when an existing function does the job.
- Commits: one per task, message one line, at most 10 words, no trailers, no body. `git add` only the files listed in the task.
- Do not run `make` targets other than the ones above, and do not run integration tests.

---

### Task 1: honor the loader's chain lock everywhere

**Files:**
- Modify: `src/flamenco/accdb/fd_accdb_private.h` (after the `fd_accdb_accmeta_t` static asserts, around line 199)
- Modify: `src/flamenco/accdb/fd_accdb.c` (sites listed in step 3)
- Test: `src/flamenco/accdb/test_accdb.c`

**Interfaces:**
- Produces: `FD_ACCDB_CHAIN_LOCKED` and `fd_accdb_chain_head( uint const * head )` in `fd_accdb_private.h`, used by tasks 2 to 4.

Background. `fd_accdb_snapshot_write_batch` locks a hash chain by CAS-ing `UINT_MAX-1` into `acc_map[hash]` and unlocking with a plain store. Today that constant is a `#define` local to that function and nothing else checks it: a reader that loads a locked head indexes `acc_pool[UINT_MAX-1]`, and `release_inner`'s prepend CAS succeeds against the locked value so the loader's unlock store then drops the released node. This task makes every head load wait for the lock.

- [ ] **Step 1: Write the failing test**

Add to `src/flamenco/accdb/test_accdb.c`, after `test_snapshot_chain_locked_writers` (search for the function name; add the new function right after its closing brace):

```c
/* Snapshot loader threads write one key set while live threads
   write a second key set on a child fork and readers read both.  All
   keys land in a small chain table so chains are shared.  Nothing may
   crash, and after the threads join every live key must hold its last
   value and every loaded key its highest-slot value. */

#define LIVE_KEYS   (256UL)
#define LIVE_ROUNDS (64UL)

typedef struct {
  fd_accdb_t *        accdb;
  fd_accdb_fork_id_t  fork;
  uchar            (* pks)[ 32UL ];
  pthread_barrier_t * start;
  int volatile *      stop;
  ulong               rounds;
} live_ctx_t;

static void *
live_writer_main( void * _ctx ) {
  live_ctx_t * ctx = _ctx;
  int barrier_result = pthread_barrier_wait( ctx->start );
  FD_TEST( !barrier_result || barrier_result==PTHREAD_BARRIER_SERIAL_THREAD );
  uchar owner[ 32UL ] = { 9, 0 };
  uchar data[ 64UL ];
  for( ulong r=0UL; r<ctx->rounds; r++ ) {
    for( ulong k=0UL; k<LIVE_KEYS; k++ ) {
      memset( data, (int)(r&0xFFUL), sizeof(data) );
      accdb_write( ctx->accdb, ctx->fork, ctx->pks[ k ], 5000000UL+r, data, (k%64UL), owner );
    }
  }
  return NULL;
}

static void *
live_reader_main( void * _ctx ) {
  live_ctx_t * ctx = _ctx;
  int barrier_result = pthread_barrier_wait( ctx->start );
  FD_TEST( !barrier_result || barrier_result==PTHREAD_BARRIER_SERIAL_THREAD );
  ulong iter = 0UL;
  while( !FD_VOLATILE_CONST( *ctx->stop ) ) {
    ulong k = iter%LIVE_KEYS;
    ulong lamports = 0UL;
    accdb_read( ctx->accdb, ctx->fork, ctx->pks[ k ], &lamports, NULL, NULL, NULL );
    (void)fd_accdb_exists  ( ctx->accdb, ctx->fork, ctx->pks[ k ] );
    (void)fd_accdb_lamports( ctx->accdb, ctx->fork, ctx->pks[ k ] );
    iter++;
  }
  return NULL;
}

static void
test_snapshot_writers_vs_live( void ) {
  int fd;
  ulong psz = 11UL<<20UL;
  ulong max_accounts = 2048UL;
  fd_accdb_t * accdb = test_setup_ex( &fd, max_accounts, 64UL, 1024UL, 64UL, psz,
                                      TEST_CACHE_FOOTPRINT, TEST_CACHE_MIN_RESERVED,
                                      PAR_THREADS+4UL );

  fd_accdb_fork_id_t root  = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t child = fd_accdb_attach_child( accdb, root );
  fd_accdb_snapshot_load_begin( accdb );

  static uchar load_pks[ PAR_KEYS  ][ 32UL ];
  static uchar live_pks[ LIVE_KEYS ][ 32UL ];
  for( ulong k=0UL; k<PAR_KEYS; k++ ) {
    fd_memset( load_pks[ k ], 0, 32UL );
    load_pks[ k ][ 0 ] = (uchar)( k+1UL );
    load_pks[ k ][ 1 ] = 0x77;
  }
  for( ulong k=0UL; k<LIVE_KEYS; k++ ) {
    fd_memset( live_pks[ k ], 0, 32UL );
    live_pks[ k ][ 0 ] = (uchar)( k&0xFFUL );
    live_pks[ k ][ 1 ] = 0x88;
    live_pks[ k ][ 2 ] = (uchar)( k>>8 );
  }

  fd_accdb_t * loader_joins[ PAR_THREADS ];
  par_writer_ctx_t loader_ctxs[ PAR_THREADS ];
  for( ulong t=0UL; t<PAR_THREADS; t++ ) loader_joins[ t ] = test_join_writer( fd );
  memset( loader_ctxs, 0, sizeof(loader_ctxs) );
  for( ulong t=0UL; t<PAR_THREADS; t++ ) {
    loader_ctxs[ t ].accdb      = loader_joins[ t ];
    loader_ctxs[ t ].store.fd   = fd;
    loader_ctxs[ t ].thread_idx = t;
    loader_ctxs[ t ].fork       = SENTINEL;
    loader_ctxs[ t ].pks        = load_pks;
  }

  fd_accdb_t * live_join   = test_join_writer( fd );
  fd_accdb_t * reader_join = test_join_writer( fd );
  fd_accdb_t * reader2_join = test_join_writer( fd );
  int volatile stop = 0;
  pthread_barrier_t start;
  FD_TEST( !pthread_barrier_init( &start, NULL, (uint)(PAR_THREADS+3UL) ) );
  live_ctx_t live   = { .accdb=live_join,    .fork=child, .pks=live_pks, .start=&start, .stop=&stop, .rounds=LIVE_ROUNDS };
  live_ctx_t rd1    = { .accdb=reader_join,  .fork=child, .pks=live_pks, .start=&start, .stop=&stop, .rounds=0UL };
  live_ctx_t rd2    = { .accdb=reader2_join, .fork=root,  .pks=load_pks, .start=&start, .stop=&stop, .rounds=0UL };
  for( ulong t=0UL; t<PAR_THREADS; t++ ) loader_ctxs[ t ].start = &start;

  pthread_t threads[ PAR_THREADS+3UL ];
  for( ulong t=0UL; t<PAR_THREADS; t++ ) FD_TEST( !pthread_create( &threads[ t ], NULL, par_writer_main, &loader_ctxs[ t ] ) );
  FD_TEST( !pthread_create( &threads[ PAR_THREADS     ], NULL, live_writer_main, &live ) );
  FD_TEST( !pthread_create( &threads[ PAR_THREADS+1UL ], NULL, live_reader_main, &rd1  ) );
  FD_TEST( !pthread_create( &threads[ PAR_THREADS+2UL ], NULL, live_reader_main, &rd2  ) );
  for( ulong t=0UL; t<PAR_THREADS+1UL; t++ ) FD_TEST( !pthread_join( threads[ t ], NULL ) );
  stop = 1;
  FD_TEST( !pthread_join( threads[ PAR_THREADS+1UL ], NULL ) );
  FD_TEST( !pthread_join( threads[ PAR_THREADS+2UL ], NULL ) );
  FD_TEST( !pthread_barrier_destroy( &start ) );

  for( ulong k=0UL; k<LIVE_KEYS; k++ ) {
    ulong lamports = 0UL;
    FD_TEST( accdb_read( accdb, child, live_pks[ k ], &lamports, NULL, NULL, NULL ) );
    FD_TEST( lamports==5000000UL+LIVE_ROUNDS-1UL );
  }
  for( ulong k=0UL; k<PAR_KEYS; k++ ) {
    ulong lamports = 0UL;
    FD_TEST( accdb_read( accdb, root, load_pks[ k ], &lamports, NULL, NULL, NULL ) );
    FD_TEST( lamports==PAR_LAMPORTS( PAR_THREADS-1UL, k ) );
  }

  fd_accdb_snapshot_load_end( accdb );
  for( ulong t=0UL; t<PAR_THREADS; t++ ) free( loader_joins[ t ] );
  free( live_join );
  free( reader_join );
  free( reader2_join );
  test_teardown( accdb, fd );
}
```

Register it in `main` next to the call to `test_snapshot_chain_locked_writers()` (search for that call): add `test_snapshot_writers_vs_live();` on the following line.

Note: `accdb_write` and `accdb_read` are the existing helpers near line 130 of the test. `test_join_writer`, `par_writer_main`, `par_writer_ctx_t`, `PAR_THREADS`, `PAR_KEYS`, `PAR_LAMPORTS` already exist near line 1525.

- [ ] **Step 2: Build and run to see it fail**

Run: `make -j test_accdb && for i in 1 2 3 4 5; do build/native/gcc/11.5.0/unit-test/test_accdb --page-sz normal 2>&1 | tail -1; done`
Expected: at least one run ends in a crash (segfault or an `FD_TEST` failure on a live key's lamports). The failure is timing dependent; if all five runs pass, raise `LIVE_ROUNDS` to 512 and rerun once. Record what you saw.

- [ ] **Step 3: Add the shared lock value and the head loader**

In `src/flamenco/accdb/fd_accdb_private.h`, right after the two `FD_STATIC_ASSERT` lines that follow `typedef struct fd_accdb_accmeta fd_accdb_accmeta_t;`, add:

```c
/* The snapshot loader locks a hash chain by storing this value into
   the chain's head slot (see fd_accdb_snapshot_write_batch).  Every
   other load of a chain head goes through fd_accdb_chain_head so it
   waits for the lock to clear instead of following it. */

#define FD_ACCDB_CHAIN_LOCKED (UINT_MAX-1U)

static inline uint
fd_accdb_chain_head( uint const * head ) {
  for(;;) {
    uint acc = FD_VOLATILE_CONST( *head );
    if( FD_LIKELY( acc!=FD_ACCDB_CHAIN_LOCKED ) ) return acc;
    FD_SPIN_PAUSE();
  }
}
```

- [ ] **Step 4: Route every head load through it**

In `src/flamenco/accdb/fd_accdb.c`:

1. In `fd_accdb_snapshot_write_batch`, delete the line `#define CHAIN_LOCKED (UINT_MAX-1U)` and replace every `CHAIN_LOCKED` in that function with `FD_ACCDB_CHAIN_LOCKED`. Keep its own lock loop as it is (it must see the locked value).
2. Replace these loads (exact current text, one each):
   - `fd_accdb_acquire_inner`: `uint acc = FD_VOLATILE_CONST( accdb->acc_map[ acc_map_idxs[ i ] ] );` → `uint acc = fd_accdb_chain_head( &accdb->acc_map[ acc_map_idxs[ i ] ] );`
   - `fd_accdb_read_one_nocache`: `uint acc_idx = FD_VOLATILE_CONST( accdb->acc_map[ hash ] );` → `uint acc_idx = fd_accdb_chain_head( &accdb->acc_map[ hash ] );`
   - `fd_accdb_exists`, `fd_accdb_probe_pd_this_fork`, `fd_accdb_lamports` (three sites): `uint acc = FD_VOLATILE_CONST( accdb->acc_map[ hash ] );` → `uint acc = fd_accdb_chain_head( &accdb->acc_map[ hash ] );`
   - `release_inner` prepend loop: `uint old_head = FD_VOLATILE_CONST( accdb->acc_map[ accs[ i ]._acc_map_idx ] );` → `uint old_head = fd_accdb_chain_head( &accdb->acc_map[ accs[ i ]._acc_map_idx ] );`
   - `acc_unlink` head path: `uint old_head = FD_VOLATILE_CONST( accdb->acc_map[ map_idx ] );` → `uint old_head = fd_accdb_chain_head( &accdb->acc_map[ map_idx ] );`
   - `chain_prewalk`: `if( from_head[ i ] ) cur[ i ] = FD_VOLATILE_CONST( accdb->acc_map[ map_idxs[ i ] ] );` → `if( from_head[ i ] ) cur[ i ] = fd_accdb_chain_head( &accdb->acc_map[ map_idxs[ i ] ] );`
   - `purge_inner`: `uint cur = FD_VOLATILE_CONST( accdb->acc_map[ acc_map_idx ] );` → `uint cur = fd_accdb_chain_head( &accdb->acc_map[ acc_map_idx ] );`
   - `background_advance_root`, two sites: `uint chk = FD_VOLATILE_CONST( accdb->acc_map[ acc_map_idx ] );` (handholding) and `acc = FD_VOLATILE_CONST( accdb->acc_map[ acc_map_idx ] );` (tombstone path) → use `fd_accdb_chain_head( &accdb->acc_map[ acc_map_idx ] )`.
   - `background_compact`: `uint acc_idx = FD_VOLATILE_CONST( accdb->acc_map[ fd_hash32( meta->pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL) ] );` → `uint acc_idx = fd_accdb_chain_head( &accdb->acc_map[ fd_hash32( meta->pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL) ] );`
3. Then run `grep -n 'acc_map\[' src/flamenco/accdb/fd_accdb.c` and confirm the only remaining raw reads of `acc_map[...]` are inside `fd_accdb_snapshot_write_batch` (its lock loop and its unlock stores) and the stores in `fd_accdb_reset`. Any other read must use `fd_accdb_chain_head`.
4. Make the interior unlink retry. In `acc_unlink`, the two statements `FD_ATOMIC_CAS( &accdb->acc_pool[ prev ].map.next, acc_idx, accmeta->map.next );` (one in the head-changed branch, one in the `else` branch) are fire-and-forget. Replace each with a call to this new static function, placed just above `acc_unlink`:

```c
/* Splice acc_idx out of the interior of a chain.  prev is the node
   that preceded it when the caller walked the chain.  The snapshot
   loader may since have inserted a node between the two (task 2), so
   if the CAS fails re-walk from the head for the current predecessor.
   Only this thread removes nodes, so acc_idx is still on the chain. */

static inline void
chain_unlink_interior( fd_accdb_t * accdb,
                       uint         map_idx,
                       uint         prev,
                       uint         acc_idx,
                       uint         next ) {
  for(;;) {
    if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->acc_pool[ prev ].map.next, acc_idx, next )==acc_idx ) ) return;
    prev = fd_accdb_chain_head( &accdb->acc_map[ map_idx ] );
    while( FD_VOLATILE_CONST( accdb->acc_pool[ prev ].map.next )!=acc_idx ) {
      prev = FD_VOLATILE_CONST( accdb->acc_pool[ prev ].map.next );
    }
  }
}
```

   The calls become `chain_unlink_interior( accdb, map_idx, prev, acc_idx, accmeta->map.next );`.

- [ ] **Step 5: Build and run the tests**

Run: `make -j test_accdb test_accdb_cache test_snapin_accdb && for i in 1 2 3 4 5; do build/native/gcc/11.5.0/unit-test/test_accdb --page-sz normal 2>&1 | tail -1; done && build/native/gcc/11.5.0/unit-test/test_accdb_cache --page-sz normal 2>&1 | tail -1 && build/native/gcc/11.5.0/unit-test/test_snapin_accdb --page-sz normal 2>&1 | tail -1`
Expected: every line ends with `success` or `pass`.

- [ ] **Step 6: Commit**

```bash
git add src/flamenco/accdb/fd_accdb_private.h src/flamenco/accdb/fd_accdb.c src/flamenco/accdb/test_accdb.c
git commit -m "accdb: honor the snapshot chain lock everywhere"
```

---

### Task 2: racesan weave, release prepend against a snapshot write (run AFTER Task 3)

Order note: this task depends on Task 3. Before Task 3 the loader can overwrite a live node in place when it mistakes the node for one of its own, which makes this weave fail for the wrong reason. Execute Task 3, then this task.

**Files:**
- Modify: `src/flamenco/accdb/fd_accdb_private.h` (remove `fd_accdb_chain_head`) and `src/flamenco/accdb/fd_accdb.c` (define it there with a racesan hook; add one hook in `fd_accdb_snapshot_write_batch`)
- Test: `src/flamenco/accdb/test_accdb_racesan.c`
- Starting point: `.superpowers/sdd/2026-10-06-instant-boot-a-accdb/task-2.patch` holds a first draft of the hook and the test from an earlier attempt; apply it with `git apply` and then make the changes below.

**Interfaces:**
- Consumes: `FD_ACCDB_CHAIN_LOCKED`, the insert-behind rule from Task 3.
- Produces: racesan hook names `accdb_chain_head:locked` and `accdb_snapshot_write:locked`.

Background. Racesan weaves two fibers deterministically; a fiber yields only at `fd_racesan_hook` calls. `fd_accdb_chain_head` spins while a chain head holds the lock value, so the fiber holding the lock can never run unless the spin loop has a hook. Move the function from `fd_accdb_private.h` into `fd_accdb.c` (it has no other user) and give the loop a hook:

```c
/* Load a chain head, waiting while the snapshot loader holds the
   chain locked (see fd_accdb_snapshot_write_batch). */

static inline uint
fd_accdb_chain_head( uint const * head ) {
  for(;;) {
    uint acc = FD_VOLATILE_CONST( *head );
    if( FD_LIKELY( acc!=FD_ACCDB_CHAIN_LOCKED ) ) return acc;
    fd_racesan_hook( "accdb_chain_head:locked" );
    FD_SPIN_PAUSE();
  }
}
```

Keep `FD_ACCDB_CHAIN_LOCKED` in the private header. In `fd_accdb_snapshot_write_batch`, immediately after the lock loop succeeds and before the chain walk, add `fd_racesan_hook( "accdb_snapshot_write:locked" );`.

- [ ] **Step 1: Write the snapshot-write fiber and the test**

In `test_accdb_racesan.c`, next to `fiber_release_write`, add `fiber_snapshot_write( fiber, join, key, slot, lamports )` performing one full-mode snapshot write of `key` with zero data, following `test_write_batch` in `test_accdb.c` (reserve with `fd_accdb_snapshot_reserve_write`, `pwrite` a `fd_accdb_disk_meta_t` header to the join's fd, then `fd_accdb_snapshot_write_batch` with `SENTINEL`, cnt 1, and `FD_TEST` that it returns 0). The racesan joins need a file descriptor for the pwrite; use the one `join_new()` passes to `fd_accdb_new`, adding a `memfd_create` in `test_shmem_new` if there is none (mirror `test_setup_ex` in `test_accdb.c`).

Then add the test:

```c
/* A live commit prepends a new version of key on fork b while the
   snapshot loader writes the same key.  Whichever lands first, the
   commit must never be lost and the loaded node must sit behind it:
   fork b reads the committed value and the root reads the loaded
   value. */

static void
test_release_vs_snapshot_write( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jw  = join_new();
  fd_accdb_t * jl  = join_new();

  uchar key[ 32UL ]; mk_key( 43UL, key );

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  fd_accdb_snapshot_load_begin( ctl );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_accdb_fork_id_t b = fd_accdb_attach_child( ctl, root );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_release_write ( &g_fiber[0], jw, b, key, 400UL+i ) );
    fd_racesan_weave_add( w, fiber_snapshot_write( &g_fiber[1], jl, key, 10UL+i, 100UL+i ) );
    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );
    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    FD_TEST( fd_accdb_lamports( ctl, b,    key )==400UL+i );
    FD_TEST( fd_accdb_lamports( ctl, root, key )==100UL+i );

    /* The weave is over, so nothing inserts while b is removed. */
    fd_accdb_purge( ctl, b );
    drain_background( ctl );
  }

  fd_accdb_snapshot_load_end( ctl );
  join_delete( ctl );
  join_delete( jw );
  join_delete( jl );
  test_shmem_delete();
}
```

Register it in the `cases[]` table after `TEST( test_acquire_vs_release ),`. Notes: the loader's node stays at the root generation across iterations and `fd_accdb_purge( b )` only removes b's version, so from the second iteration on the loader finds its own node (the slot rises each iteration, so it replaces in place rather than reporting a duplicate) and, when the commit landed first, links or keeps that node behind b's. Use `fd_accdb_lamports` for the reads: a cached read of the loaded node during the load would overwrite the slot the loader keeps in `cache_idx`.

- [ ] **Step 2: Build and run**

Run: `make -j BUILDDIR=gcc-racesan EXTRAS=racesan test_accdb_racesan && build/gcc-racesan/unit-test/test_accdb_racesan 2>&1 | tail -3` (no arguments) and `make -j test_accdb && build/native/gcc/11.5.0/unit-test/test_accdb --page-sz normal 2>&1 | tail -1`.
Expected: the racesan run's final line reports pass, with `Running test_release_vs_snapshot_write` in the log; the normal test passes.

To see the weave catch the Task 1 bug, temporarily change the `release_inner` prepend loop's head load back to a raw `FD_VOLATILE_CONST` load (one line), rebuild, run only this test by name, observe the `FD_TEST( fd_accdb_lamports( ctl, b, key )==400UL+i )` failure, then restore the line and confirm `git diff` shows only the intended changes. Record both outcomes.

- [ ] **Step 3: Commit**

```bash
git add src/flamenco/accdb/fd_accdb_private.h src/flamenco/accdb/fd_accdb.c src/flamenco/accdb/test_accdb_racesan.c
git commit -m "accdb: racesan weave for commit vs snapshot write"
```

---

### Task 3: tag loader entries and keep live versions ahead

**Files:**
- Modify: `src/flamenco/accdb/fd_accdb_private.h` (size-word layout block)
- Modify: `src/flamenco/accdb/fd_accdb.c` (`fd_accdb_snapshot_write_batch`)
- Modify: `src/flamenco/accdb/fd_accdb.h` (doc comment of `fd_accdb_snapshot_write_batch`)
- Test: `src/flamenco/accdb/test_accdb.c`

**Interfaces:**
- Produces: `FD_ACCDB_SIZE_SNAPSHOT_BIT` (bit 27) and `FD_ACCDB_SIZE_SNAPSHOT(packed)` in `fd_accdb_private.h`, used by task 4.
- Contract (enforced in task 4): while loader nodes are hidden, nothing removes chain nodes (no purge, no root advance), so the loader's interior insert never races a remover.

Background. The loader compares `cache_idx` (holding the appendvec slot during a load) against the incoming slot for every same-pubkey node, and prepends new nodes at the head. Both are wrong once live versions of a key exist during a load: a live node's `cache_idx` is a cache index, and a loader node ahead of a live node would be found first by readers. Fix: mark loader nodes with bit 27 of the size word, compare only against marked nodes, and link a new loader node right behind the last unmarked node for the same pubkey. Normal commits rebuild the size word, so they clear the bit for free.

- [ ] **Step 1: Write the failing tests**

Add to `src/flamenco/accdb/test_accdb.c` after `test_snapshot_writers_vs_live` (replacing any `test_snapshot_skips_live` / `test_snapshot_bit_dup_check` from an earlier attempt):

```c
/* A live version of a key exists on a child fork before the loader
   writes the same key.  The loader must ignore the live node when it
   compares slots, must not touch it, and must place its own node
   behind it so the child keeps reading the live value while the root
   reads the loaded one. */

static void
test_snapshot_behind_live( void ) {
  int fd;
  ulong psz = 11UL<<20UL;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 1024UL, 64UL, psz );
  test_store_ctx_t store = { .fd=fd, .cnt=0UL };

  fd_accdb_fork_id_t root  = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t child = fd_accdb_attach_child( accdb, root );
  fd_accdb_snapshot_load_begin( accdb );

  uchar key[ 32UL ] = { 5, 0x99, 0 };
  uchar owner[ 32UL ] = { 9, 0 };
  accdb_write( accdb, child, key, 500UL, NULL, 0UL, owner );

  uchar const * pks[ 1 ]  = { key };
  ulong slots[ 1 ]        = { 10UL };
  ulong lamports[ 1 ]     = { 100UL };
  ulong data_lens[ 1 ]    = { 0UL };
  int   execs[ 1 ]        = { 0 };
  test_batch_result_t r = test_write_batch( accdb, SENTINEL, 1UL, pks, slots, lamports, data_lens, execs, &store );
  FD_TEST( !r.err );
  FD_TEST( r.loaded==1UL && r.replaced==0UL && r.ignored==0UL );
  FD_TEST( r.results[ 0 ]==FD_ACCDB_SNAPSHOT_WRITE_LOADED );

  /* Loaded nodes are read here with chain-walk-only lookups: a
     cached read would store a cache index into the node's cache_idx,
     which the loader still uses as the slot until the load ends.  In
     the product the hide flag keeps readers off loaded nodes. */
  ulong got = 0UL;
  FD_TEST( accdb_read( accdb, child, key, &got, NULL, NULL, NULL ) ); FD_TEST( got==500UL );
  FD_TEST( fd_accdb_lamports( accdb, root, key )==100UL );

  /* An older snapshot copy of the same key is still dropped, and a
     same-slot copy is still a corrupt snapshot, judged only against
     the loaded node. */
  slots[ 0 ] = 5UL; lamports[ 0 ] = 1UL;
  r = test_write_batch( accdb, SENTINEL, 1UL, pks, slots, lamports, data_lens, execs, &store );
  FD_TEST( !r.err && r.ignored==1UL && r.ignored_lamports==1UL );
  slots[ 0 ] = 10UL;
  r = test_write_batch( accdb, SENTINEL, 1UL, pks, slots, lamports, data_lens, execs, &store );
  FD_TEST( r.err==-1 );

  /* A newer snapshot copy replaces the loaded node in place and the
     live node still wins on the child. */
  slots[ 0 ] = 20UL; lamports[ 0 ] = 200UL;
  r = test_write_batch( accdb, SENTINEL, 1UL, pks, slots, lamports, data_lens, execs, &store );
  FD_TEST( !r.err && r.replaced==1UL && r.replaced_lamports==100UL );
  FD_TEST( accdb_read( accdb, child, key, &got, NULL, NULL, NULL ) ); FD_TEST( got==500UL );
  FD_TEST( fd_accdb_lamports( accdb, root, key )==200UL );

  /* Exactly two nodes exist for the key. */
  fd_accdb_flush_metrics( accdb );
  fd_accdb_shmem_metrics_t const * shmetrics = fd_accdb_shmetrics( accdb );
  FD_TEST( shmetrics->accounts_total==2UL );

  fd_accdb_snapshot_load_end( accdb );

  /* After the load a cached read of the loaded node is fine. */
  FD_TEST( accdb_read( accdb, root, key, &got, NULL, NULL, NULL ) ); FD_TEST( got==200UL );

  /* Rooting the child unlinks the loaded copy behind it. */
  fd_accdb_advance_root( accdb, child );
  drain_background( accdb );
  FD_TEST( accdb_read( accdb, child, key, &got, NULL, NULL, NULL ) ); FD_TEST( got==500UL );
  FD_TEST( shmetrics->accounts_total==1UL );

  test_teardown( accdb, fd );
}

/* Two live versions on a fork and its child, then the loader.  Each
   fork keeps reading its own version and the root reads the loaded
   one. */

static void
test_snapshot_behind_two_live( void ) {
  int fd;
  ulong psz = 11UL<<20UL;
  fd_accdb_t * accdb = test_setup( &fd, 1024UL, 64UL, 1024UL, 64UL, psz );
  test_store_ctx_t store = { .fd=fd, .cnt=0UL };

  fd_accdb_fork_id_t root  = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t f     = fd_accdb_attach_child( accdb, root );
  fd_accdb_fork_id_t g     = fd_accdb_attach_child( accdb, f );
  fd_accdb_snapshot_load_begin( accdb );

  uchar key[ 32UL ] = { 6, 0x99, 0 };
  uchar owner[ 32UL ] = { 9, 0 };
  accdb_write( accdb, f, key, 500UL, NULL, 0UL, owner );
  accdb_write( accdb, g, key, 600UL, NULL, 0UL, owner );

  uchar const * pks[ 1 ] = { key };
  ulong slots[ 1 ] = { 10UL };
  ulong lamports[ 1 ] = { 100UL };
  ulong data_lens[ 1 ] = { 0UL };
  int   execs[ 1 ] = { 0 };
  test_batch_result_t r = test_write_batch( accdb, SENTINEL, 1UL, pks, slots, lamports, data_lens, execs, &store );
  FD_TEST( !r.err && r.loaded==1UL );

  ulong got = 0UL;
  FD_TEST( accdb_read( accdb, g,    key, &got, NULL, NULL, NULL ) ); FD_TEST( got==600UL );
  FD_TEST( accdb_read( accdb, f,    key, &got, NULL, NULL, NULL ) ); FD_TEST( got==500UL );
  FD_TEST( fd_accdb_lamports( accdb, root, key )==100UL );

  fd_accdb_snapshot_load_end( accdb );
  test_teardown( accdb, fd );
}
```

Register both in `main` right after `test_snapshot_writers_vs_live();`, each with an `FD_LOG_NOTICE` line like the neighbours.

- [ ] **Step 2: Build and run to see them fail**

Run: `make -j test_accdb && build/native/gcc/11.5.0/unit-test/test_accdb --page-sz normal 2>&1 | tail -2`
Expected: FAIL. Today the loader compares the live node's `cache_idx` as a slot, so the first batch is either ignored or overwrites the live node; the first `FD_TEST( got==500UL )` or the result checks fail.

- [ ] **Step 3: Add the bit**

In `src/flamenco/accdb/fd_accdb_private.h`, in the size-word layout block:

- Change the comment line `bits 27..0  data length in bytes                  (FD_ACCDB_SIZE_MASK)` to two lines:
  `bit  27     snapshot flag,    in-memory only      (FD_ACCDB_SIZE_SNAPSHOT_BIT)` and
  `bits 26..0  data length in bytes                  (FD_ACCDB_SIZE_MASK)`.
- Change `The data length is therefore 28 bits, max 256 MiB` to `The data length is therefore 27 bits, max 128 MiB`, and fix the counts of packed fields and in-memory flags in that comment.
- Add to the list of in-memory flags: `- snapshot (bit 27): set on every node written by the snapshot loader.  Normal commits rebuild the word and so clear it.  The loader compares slots only against nodes that carry it, and reads can be told to skip them while a load runs.`
- Add `#define FD_ACCDB_SIZE_SNAPSHOT_BIT    (1U<<27)` after the `PD_WRITE_BIT` define, change `FD_ACCDB_SIZE_MASK` to `((1U<<27)-1U)`, add `#define FD_ACCDB_SIZE_SNAPSHOT(p)     (!!((p) & FD_ACCDB_SIZE_SNAPSHOT_BIT))` after the `PD_WRITE(p)` macro, and change the static assert to `FD_STATIC_ASSERT( (10UL<<20) < (1UL<<27), snapshot_bit_collides_with_len );`.

Then audit every write to `executable_size` in `fd_accdb.c`: the two commit sites in `release_inner` rebuild the word (intended); every other read-modify-write must preserve bits it does not own. List what you found in the report.

- [ ] **Step 4: Change the loader**

In `fd_accdb_snapshot_write_batch`:

1. Declare `fd_accdb_accmeta_t * behind = NULL;` next to `existing` and `cross_existing`, with the comment `/* last node for this pubkey that the loader did not write */`.
2. In the walk, inside the `if( FD_UNLIKELY( !memcmp( pubkeys[ i ], candidate->key.pubkey, 32UL ) ) ) {` block, make the first statement:

```c
        if( FD_UNLIKELY( !FD_ACCDB_SIZE_SNAPSHOT( candidate->executable_size ) ) ) {
          behind   = candidate;
          next_acc = candidate->map.next;
          continue;
        }
```

3. Move the four field assignments (`accmeta->cache_idx`, `accmeta->lamports`, `accmeta->executable_size`, `accmeta->offset_fork`) so they happen before the node is linked into the chain, and set the bit:

```c
    accmeta->cache_idx       = (uint)slots[ i ];
    accmeta->lamports        = lamports[ i ];
    accmeta->executable_size = FD_ACCDB_SIZE_PACK( (uint)data_lens[ i ], executables[ i ] )
                             | FD_ACCDB_SIZE_SNAPSHOT_BIT;
    ulong file_off           = file_offsets[ i ];
    accmeta->offset_fork     = incremental ? fd_accdb_acc_pack_offset_fork( file_off, fork_id.val ) : file_off;
    FD_COMPILER_MFENCE();
```

   For the `existing` (in-place) path this is just a reorder. For a new node the assignments come after `fd_memcpy( accmeta->key.pubkey, ... )` and `accmeta->key.generation = ...` and before the linking below.

4. Replace the linking of a new node (`accmeta->map.next = chain_head; new_head = acc_idx;`) with:

```c
      if( FD_UNLIKELY( behind ) ) {
        /* Readers must meet the live version first, so link the
           loaded node right behind the last live one.  Nothing
           removes nodes while a load runs (see fd_accdb_purge and
           fd_accdb_advance_root), so behind stays on the chain. */
        for(;;) {
          uint after = FD_VOLATILE_CONST( behind->map.next );
          accmeta->map.next = after;
          FD_COMPILER_MFENCE();
          if( FD_LIKELY( FD_ATOMIC_CAS( &behind->map.next, after, acc_idx )==after ) ) break;
          FD_SPIN_PAUSE();
        }
      } else {
        accmeta->map.next = chain_head;
        new_head          = acc_idx;
      }
```

   The txn record push for incremental mode stays where it is. The final `FD_VOLATILE( accdb->acc_map[ hashes[ i ] ] ) = new_head;` store remains and doubles as the unlock (with `new_head==chain_head` when the node went behind a live one).

5. In `fd_accdb.h`, in the doc comment of `fd_accdb_snapshot_write_batch`, replace the sentence `Snapshot loading excludes non-snapshot accdb operations while these locks are held.` with: `Live reads and commits may run concurrently with a load: every chain head load waits for the lock, loader-written nodes carry FD_ACCDB_SIZE_SNAPSHOT_BIT, slots are compared only against such nodes, and a new node is linked behind any live version of the same pubkey.  Node removal (purge, root advance) must not run while loader nodes are hidden.`  Remove `FD_ACCDB_SNAPSHOT_WRITE_LIVE` and its consumer branch in `fd_snapin_tile.c` if an earlier attempt added them.

- [ ] **Step 5: Build and run**

Run: `make -j test_accdb test_snapin_accdb && for i in 1 2 3; do build/native/gcc/11.5.0/unit-test/test_accdb --page-sz normal 2>&1 | tail -1; done && build/native/gcc/11.5.0/unit-test/test_snapin_accdb --page-sz normal 2>&1 | tail -1 && make -j BUILDDIR=gcc-racesan EXTRAS=racesan test_accdb_racesan && build/gcc-racesan/unit-test/test_accdb_racesan 2>&1 | tail -1`
Expected: all pass (racesan with no arguments).

- [ ] **Step 6: Commit**

```bash
git add src/flamenco/accdb/fd_accdb_private.h src/flamenco/accdb/fd_accdb.c src/flamenco/accdb/fd_accdb.h src/flamenco/accdb/test_accdb.c src/discof/restore/fd_snapin_tile.c
git commit -m "accdb: tag loader nodes and keep live versions ahead"
```

---

### Task 4: hide loader nodes on request

**Files:**
- Modify: `src/flamenco/accdb/fd_accdb_private.h` (shmem struct near `int snapshot_loading;` around line 380; local join struct, search for `show_hidden` placement next to `acquire_state`)
- Modify: `src/flamenco/accdb/fd_accdb.h` (two new functions, next to `fd_accdb_snapshot_load_begin`)
- Modify: `src/flamenco/accdb/fd_accdb.c` (the five walks, `fd_accdb_reset`, the two new functions)
- Test: `src/flamenco/accdb/test_accdb.c`

**Interfaces:**
- Consumes: `FD_ACCDB_SIZE_SNAPSHOT(packed)` from task 3.
- Produces: `void fd_accdb_snapshot_hide( fd_accdb_t * accdb, int hide );` and `void fd_accdb_show_hidden( fd_accdb_t * accdb, int show );` used by the restore plan.

- [ ] **Step 1: Write the failing test**

Add to `src/flamenco/accdb/test_accdb.c` after `test_snapshot_behind_two_live`:

```c
/* While hidden, loader-written nodes read as absent on every path,
   except on a join that asked to see them.  Live writes made while
   hidden stay visible.  Unhiding reveals the loaded nodes behind the
   live ones. */

static void
test_snapshot_hidden( void ) {
  int fd;
  ulong psz = 11UL<<20UL;
  fd_accdb_t * accdb = test_setup_ex( &fd, 1024UL, 64UL, 1024UL, 64UL, psz,
                                      TEST_CACHE_FOOTPRINT, TEST_CACHE_MIN_RESERVED, 2UL );
  fd_accdb_t * seer = test_join_writer( fd );
  test_store_ctx_t store = { .fd=fd, .cnt=0UL };

  fd_accdb_fork_id_t root  = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t child = fd_accdb_attach_child( accdb, root );
  fd_accdb_snapshot_load_begin( accdb );
  fd_accdb_snapshot_hide( accdb, 1 );
  fd_accdb_show_hidden( seer, 1 );

  uchar key[ 32UL ] = { 7, 0x99, 0 };
  uchar key2[ 32UL ] = { 8, 0x99, 0 };
  uchar owner[ 32UL ] = { 9, 0 };

  uchar const * pks[ 2 ] = { key, key2 };
  ulong slots[ 2 ] = { 10UL, 10UL };
  ulong lamports[ 2 ] = { 100UL, 7UL };
  ulong data_lens[ 2 ] = { 0UL, 0UL };
  int   execs[ 2 ] = { 0, 0 };
  test_batch_result_t r = test_write_batch( accdb, SENTINEL, 2UL, pks, slots, lamports, data_lens, execs, &store );
  FD_TEST( !r.err && r.loaded==2UL );

  ulong got = 0UL;
  FD_TEST( !accdb_read( accdb, root,  key, &got, NULL, NULL, NULL ) );
  FD_TEST( !accdb_read( accdb, child, key, &got, NULL, NULL, NULL ) );
  FD_TEST( !fd_accdb_exists  ( accdb, child, key ) );
  FD_TEST( !fd_accdb_lamports( accdb, child, key ) );
  FD_TEST(  accdb_read( seer, root, key, &got, NULL, NULL, NULL ) ); FD_TEST( got==100UL );
  FD_TEST(  fd_accdb_lamports( seer, child, key2 )==7UL );

  accdb_write( accdb, child, key, 500UL, NULL, 0UL, owner );
  FD_TEST(  accdb_read( accdb, child, key, &got, NULL, NULL, NULL ) ); FD_TEST( got==500UL );
  FD_TEST( !accdb_read( accdb, root,  key, &got, NULL, NULL, NULL ) );

  fd_accdb_snapshot_hide( accdb, 0 );
  FD_TEST(  accdb_read( accdb, child, key,  &got, NULL, NULL, NULL ) ); FD_TEST( got==500UL );
  FD_TEST(  accdb_read( accdb, root,  key,  &got, NULL, NULL, NULL ) ); FD_TEST( got==100UL );
  FD_TEST(  fd_accdb_lamports( accdb, child, key2 )==7UL );

  fd_accdb_snapshot_load_end( accdb );
  free( seer );
  test_teardown( accdb, fd );
}
```

Also cover the no-cache read path if a read-only join helper exists in this test file (search for `fd_accdb_join_readonly`); if there is one, add two checks mirroring the `exists` lines using `fd_accdb_read_one_nocache`. If there is none, leave it; the five walks share the same predicate text and the implementer checks that site by reading it.

Register the test in `main` right after `test_snapshot_behind_two_live();`.

- [ ] **Step 2: Build to see it fail**

Run: `make -j test_accdb 2>&1 | tail -3`
Expected: compile error, `fd_accdb_snapshot_hide` and `fd_accdb_show_hidden` undeclared.

- [ ] **Step 3: Add the flag, the override and the API**

In `src/flamenco/accdb/fd_accdb_private.h`:
- In the shmem struct, right after `int snapshot_loading;`, add `int snapshot_hidden;` with the comment `/* Reads skip loader-written nodes while set (fd_accdb_snapshot_hide). */`.
- In the local join struct (`struct fd_accdb_private` or whatever holds `acquire_state`; search for `acquire_state;`), add `int show_hidden;` with the comment `/* This join may read loader-written nodes while they are hidden. */`.

In `src/flamenco/accdb/fd_accdb.h`, right after the declaration of `fd_accdb_snapshot_load_begin`:

```c
/* fd_accdb_snapshot_hide makes every read behave as if nodes written
   by the snapshot loader were absent (hide=1) or visible again
   (hide=0).  Used by the instant-boot path, where live execution runs
   while the loader is still writing.  Only the loader's lead tile
   calls it, and only while no snapshot is being produced.

   fd_accdb_show_hidden lets one join keep reading loader-written nodes
   while they are hidden, so the loader can verify what it wrote. */

void
fd_accdb_snapshot_hide( fd_accdb_t * accdb,
                        int          hide );

void
fd_accdb_show_hidden( fd_accdb_t * accdb,
                      int          show );
```

In `src/flamenco/accdb/fd_accdb.c`, right after `fd_accdb_snapshot_load_begin`:

```c
void
fd_accdb_snapshot_hide( fd_accdb_t * accdb,
                        int          hide ) {
  FD_VOLATILE( accdb->shmem->snapshot_hidden ) = hide;
}

void
fd_accdb_show_hidden( fd_accdb_t * accdb,
                      int          show ) {
  accdb->show_hidden = show;
}
```

In `fd_accdb_reset`, next to `shmem->snapshot_loading = 0;`, add `shmem->snapshot_hidden = 0;`.

Guard node removal while hidden: in `fd_accdb_advance_root`, next to the existing `FD_CHECK_CRIT` that refuses to run during snapshot production, add `FD_CHECK_CRIT( !FD_VOLATILE_CONST( accdb->shmem->snapshot_hidden ), "root advance while loader nodes are hidden" );` and add the same check at the top of `fd_accdb_purge` (message "purge while loader nodes are hidden"). The loader links nodes behind live ones while hidden, and that is only safe when nothing removes nodes. Add a unit assertion-free note to the doc comments of both functions in `fd_accdb.h`: "Must not be called while fd_accdb_snapshot_hide is in effect." In `fd_accdb_new` (where the local join fields are zeroed; search for `acquire_state` being initialized), make sure `show_hidden` starts at 0 (if the struct is memset, nothing to add).

- [ ] **Step 4: Apply the rule in the five walks**

In each of `fd_accdb_acquire_inner`, `fd_accdb_read_one_nocache`, `fd_accdb_exists`, `fd_accdb_probe_pd_this_fork`, `fd_accdb_lamports`, just before the walk loop (after `root_generation` is read), add:

```c
  int hide = FD_VOLATILE_CONST( accdb->shmem->snapshot_hidden ) && !accdb->show_hidden;
```

(in `fd_accdb_acquire_inner` put it before the `for( ulong i=0UL; i<pubkeys_cnt; i++ )` loop) and extend the skip condition in the loop. The condition currently reads, in each walk,

```c
    if( FD_UNLIKELY( (candidate->key.generation>root_generation && ... ) ) || memcmp( pubkey, candidate->key.pubkey, 32UL ) ) {
```

Add one more skip reason in front of the `memcmp`:

```c
    if( FD_UNLIKELY( (candidate->key.generation>root_generation && ... ) ) ||
        (hide && FD_ACCDB_SIZE_SNAPSHOT( FD_VOLATILE_CONST( candidate->executable_size ) )) ||
        memcmp( pubkey, candidate->key.pubkey, 32UL ) ) {
```

Keep each walk's variable names (`candidate` vs `candidate_acc`, `pubkey` vs `pubkeys[ i ]`). Where a condition is on one long line, break it into one reason per line as above; do not reflow unrelated lines.

- [ ] **Step 5: Build, run, and measure**

Run: `make -j test_accdb test_accdb_cache test_snapin_accdb bench_accdb_hotread && for i in 1 2 3; do build/native/gcc/11.5.0/unit-test/test_accdb --page-sz normal 2>&1 | tail -1; done && build/native/gcc/11.5.0/unit-test/test_accdb_cache --page-sz normal 2>&1 | tail -1 && build/native/gcc/11.5.0/unit-test/test_snapin_accdb --page-sz normal 2>&1 | tail -1 && make -j BUILDDIR=gcc-racesan EXTRAS=racesan test_accdb_racesan && build/gcc-racesan/unit-test/test_accdb_racesan --page-sz normal 2>&1 | tail -1`
Expected: all pass.

Then: `for i in 1 2; do build/native/gcc/11.5.0/unit-test/bench_accdb_hotread --page-sz normal 2>&1 | grep 'hot-read:'; done`
Expected: both runs at or under 85 ns/op (baseline 80). If slower, move the `hide` test after the generation test so the common path does not evaluate it, re-measure, and report the numbers.

- [ ] **Step 6: Commit**

```bash
git add src/flamenco/accdb/fd_accdb_private.h src/flamenco/accdb/fd_accdb.h src/flamenco/accdb/fd_accdb.c src/flamenco/accdb/test_accdb.c
git commit -m "accdb: hide loader nodes while loading on request"
```
