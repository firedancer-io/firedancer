/* test_accdb_racesan.c reproduces the tombstone-orphan -> EBR-leak ->
   writeback-poison corruption as a deterministic, single-threaded
   schedule.

   The bug (confirmed against commit 9220a11aaf):

     1. Account P is open (lamports!=0) on the root, then CLOSED
        (lamports==0, a "tombstone") on fork F.  F is advanced to root.
        advance_root's tombstone self-unlink (background_advance_root,
        ~fd_accdb.c:1062) acc_unlinks F's tombstone version new_acc (the
        chain HEAD) and defers its accmeta slot for epoch-gated release.

     2. A descendant fork D of F writably re-acquires P.  The chain walk
        selects the tombstone new_acc (writable tombstones are not nulled),
        and cache_try_pin pins new_acc's resident, dirty (persisted==0)
        cache line.

     3. acc_unlink's reclaim CAS (refcnt 0 -> EVICT_SENTINEL) fails under
        D's pin, so it SKIPS the line (fd_accdb.c:877).  The line is now
        ORPHANED: acc_idx still points at new_acc's slot, persisted==0,
        owner==P's owner, key==P.

     4. EBR leak: after D's acquire returns, D's published epoch is reset
        to ULONG_MAX while the pin is still held (until release).
        wait_for_epoch_drain treats ULONG_MAX as "drained", so a later
        drain_deferred_frees releases new_acc's accmeta slot WHILE D pins
        the orphaned line.

     5. That freed slot is recycled (LIFO) to a fresh live account B.  The
        orphaned line's acc_idx now aliases B's accmeta.

     6. After D releases (refcnt -> 0), CLOCK pre-eviction
        (background_preevict) writes the orphaned dirty line back to disk,
        synthesizing a record with pubkey=B (from B's accmeta) and
        owner=P's owner (from the orphaned line) -- a silent
        wrong-owner-valid-key poison -- and republishes B's accmeta
        offset_fork to point at it.  A future cold-load of B then reads
        P's owner.

   No detector catches this (cold-load identity checks validate the
   on-disk PUBKEY, which reads correctly as B), so the corruption is
   silent; the oracle is a direct read-back of B's owner.

   The schedule is deterministic and single-threaded: the only
   "concurrency" the bug needs is that D holds a cache-line pin across the
   advance_root + drain while its EPOCH reads as idle (ULONG_MAX) -- a
   structural property of the acquire/release epoch window, not a thread
   interleaving.  We therefore drive it directly rather than via racesan
   fibers; the racesan hooks added to fd_accdb.c are exercised as no-ops
   here and remain available for finer-grained interleaving tests. */

#define _GNU_SOURCE

#include "fd_accdb.h"
#include "../../util/fd_util.h"
#include "../../util/racesan/fd_racesan_async.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define TEST_CACHE_FOOTPRINT (16UL<<30UL)

static fd_accdb_shmem_t * test_shmem_mem;

static fd_accdb_shmem_t * test_shmem;   /* shared shmem, for extra joins   */
static int               test_fd;       /* shared backing fd, for extra joins */
static ulong             test_max_live_slots;

static fd_accdb_t *
test_setup( int * out_fd,
            ulong max_accounts,
            ulong max_live_slots,
            ulong max_account_writes_per_slot,
            ulong partition_cnt,
            ulong partition_sz ) {
  int fd = memfd_create( "accdb_racesan", 0 );
  if( FD_UNLIKELY( fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));
  *out_fd = fd;
  test_fd  = fd;
  test_max_live_slots = max_live_slots;

  /* joiner_cnt=2: the orphan/poison tests model TWO concurrent tiles (a
     reader "D" holding a pin on one handle while a committer/advance_root
     drives the other), so the shmem must admit a second joiner with its
     own epoch slot. */
  ulong cache_fp = TEST_CACHE_FOOTPRINT;
  ulong shmem_fp = fd_accdb_shmem_footprint( max_accounts, max_live_slots, max_account_writes_per_slot, partition_cnt, cache_fp, 640UL, 2UL );
  FD_TEST( shmem_fp );
  void * shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  FD_TEST( shmem_mem );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( shmem_mem, max_accounts, max_live_slots,
                          max_account_writes_per_slot, partition_cnt,
                          partition_sz, cache_fp, 640UL, 0, 42UL, 2UL ) );
  FD_TEST( shmem );
  test_shmem_mem = shmem_mem;
  test_shmem     = shmem;

  ulong accdb_fp = fd_accdb_footprint( max_live_slots );
  FD_TEST( accdb_fp );
  void * accdb_mem = aligned_alloc( fd_accdb_align(), accdb_fp );
  FD_TEST( accdb_mem );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( accdb_mem, shmem, fd, 0UL, NULL ) );
  FD_TEST( accdb );
  return accdb;
}

/* test_join_extra creates a SECOND accdb handle on the same shmem (its own
   joiner epoch slot), modelling a separate exec tile.  Used so a reader
   can hold an acquire bracket on one handle while the main handle commits
   / advances root — mirroring production, where the one-bracket-per-handle
   invariant holds because each tile has its own handle. */
static fd_accdb_t *
test_join_extra( void ) {
  ulong accdb_fp = fd_accdb_footprint( test_max_live_slots );
  void * accdb_mem = aligned_alloc( fd_accdb_align(), accdb_fp );
  FD_TEST( accdb_mem );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( accdb_mem, test_shmem, test_fd, 0UL, NULL ) );
  FD_TEST( accdb );
  return accdb;
}

static void
test_teardown( fd_accdb_t * accdb,
               int          fd ) {
  free( test_shmem_mem );
  free( accdb );
  close( fd );
}

static void
drain_background( fd_accdb_t * accdb ) {
  int charge_busy = 0;
  fd_accdb_background( accdb, &charge_busy );
}

/* drain_background_n drives the background tile until it reports no more
   work (charge_busy stays 0) or a bounded number of iterations elapses.
   Each call performs at most one unit of work (advance_root, purge, or a
   pre-eviction sweep), so several calls are needed to flush a queued
   command and then run pre-eviction. */
static void
drain_background_n( fd_accdb_t * accdb,
                    ulong        n ) {
  for( ulong i=0UL; i<n; i++ ) drain_background( accdb );
}

/* Force a full pre-eviction sweep (ignore the cache watermark) so the
   writeback path runs deterministically without manufacturing real cache
   pressure. */
void fd_accdb_debug_force_preevict( fd_accdb_t * accdb );

/* Locate the resident cache line holding `pubkey`; fills out_class/out_idx.
   Returns 1 on hit, 0 if no resident line matches. */
int fd_accdb_debug_find_line( fd_accdb_t * accdb, uchar const * pubkey, ulong * out_class, ulong * out_idx );

/* Evict + write back one specific cache line via the foreground evictor's
   claim sequence (CAS refcnt 0->EVICT_SENTINEL), suspendable at the
   racesan hook "clock_evict:post_sentinel".  Returns the captured evicted
   acc_idx. */
uint fd_accdb_debug_clock_evict_line( fd_accdb_t * accdb, ulong size_class, ulong line_idx );

static void
write_acc( fd_accdb_t *       accdb,
           fd_accdb_fork_id_t fork_id,
           uchar const *      pubkey,
           ulong              lamports,
           uchar const *      owner,
           uchar const *      data,
           ulong              data_len ) {
  uchar const * pks[1] = { pubkey };
  int wr[1] = { 1 };
  fd_acc_t acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( accdb, fork_id, 1UL, pks, wr, acc );
  acc[0].lamports = lamports;
  acc[0].data_len = data_len;
  memcpy( acc[0].owner, owner, 32UL );
  if( data_len && data ) memcpy( acc[0].data, data, data_len );
  acc[0].commit = 1;
  fd_accdb_release( accdb, 1UL, acc );
}

static void
test_tombstone_orphan_ebr_poison( void ) {
  int fd;
  /* Small pools so the recycled accmeta slot is reused quickly and the
     cache pressure for pre-eviction is easy to trigger. */
  fd_accdb_t * accdb = test_setup( &fd, 256UL, 16UL, 1024UL, 1024UL, 1UL<<30UL );
  /* Separate handle for the "D reader" tile so its long-held acquire
     bracket does not collide with the committer/advance_root bracket on
     the main handle (one bracket per handle, as in production). */
  fd_accdb_t * accdb_d = test_join_extra();

  uchar pubkey_P[ 32 ] = { 'P', 0 };
  uchar pubkey_B[ 32 ] = { 'B', 0 };
  uchar owner_P [ 32 ] = { 0xAA, 0 };
  uchar owner_B [ 32 ] = { 0xBB, 0 };

  /* Fork tree:  root0  ->  F  ->  D
     advance_root(F) requires F be a direct child of the current root. */
  fd_accdb_fork_id_t root0 = fd_accdb_attach_child( accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  fd_accdb_fork_id_t F     = fd_accdb_attach_child( accdb, root0 );
  fd_accdb_fork_id_t D     = fd_accdb_attach_child( accdb, F );

  /* P open on root0. */
  write_acc( accdb, root0, pubkey_P, 100UL, owner_P, NULL, 0UL );

  /* P closed (tombstone) on F. */
  write_acc( accdb, F, pubkey_P, 0UL, owner_P, NULL, 0UL );

  /* D writably re-acquires P (the tombstone) and HOLDS the pin.  After
     this returns, D's epoch reads ULONG_MAX but the cache line stays
     pinned (refcnt=1). */
  uchar const * pks_P[1] = { pubkey_P };
  int wr[1] = { 1 };
  fd_acc_t acc_D[1];
  memset( acc_D, 0, sizeof(acc_D) );
  fd_accdb_acquire( accdb_d, D, 1UL, pks_P, wr, acc_D );
  /* The re-acquire sees a closed account. */
  FD_TEST( acc_D[0].lamports==0UL );

  /* Advance root to F.  background_advance_root tombstone-unlinks F's
     new_acc; the reclaim CAS fails under D's pin -> orphaned line; the
     accmeta slot is deferred for release (deferred_acc_append). */
  fd_accdb_advance_root( accdb, F );
  drain_background_n( accdb, 4UL ); /* run the queued advance_root */

  /* Advance root again (to D).  drain_deferred_frees runs at the START of
     background_advance_root; D's published epoch reads ULONG_MAX (D's
     acquire returned), so wait_for_epoch_drain treats it as drained and
     releases the orphaned accmeta slot back to acc_pool -- WHILE the
     orphaned line still references it. */
  fd_accdb_advance_root( accdb, D );
  drain_background_n( accdb, 4UL );

  /* Commit fresh accounts to consume the freed accmeta slots.  The drain
     released the orphaned slot back to the pool, so one of these fresh
     accounts is handed the orphaned line's acc_idx and becomes the
     poisoned victim.  We commit two because the freed chain has two
     slots (P's open + P's tombstone versions); the orphaned line aliases
     the tombstone slot, which is the second one handed out. */
  write_acc( accdb, D, pubkey_B,  200UL, owner_B, NULL, 0UL );
  uchar pubkey_B2[ 32 ] = { 'C', 0 };
  uchar owner_B2 [ 32 ] = { 0xCC, 0 };
  write_acc( accdb, D, pubkey_B2, 300UL, owner_B2, NULL, 0UL );

  /* Flush the recycled victims to disk WHILE D still pins the orphaned
     line.  The orphan (refcnt=1) is skipped by pre-eviction; the victims'
     own correct cache lines (refcnt=0) are evicted and written back
     correctly, so each victim's accmeta now points at a correct on-disk
     record and has NO resident cache line.  This models the mainnet
     signature: the victim is "ancient/untouched" (cold, disk-only) by the
     time the orphan is finally written back. */
  fd_accdb_debug_force_preevict( accdb );

  /* D releases its pin (orphan refcnt -> 0). */
  fd_accdb_release( accdb_d, 1UL, acc_D );

  /* Now pre-eviction writes the orphaned dirty line back to disk:
     pubkey=victim (from the recycled accmeta) + owner=P (from the
     orphaned line), and republishes the victim accmeta's offset_fork to
     that poison record.  There is no resident victim line left to correct
     it afterward. */
  fd_accdb_debug_force_preevict( accdb );

  /* Cold-load each victim from disk.  If the poison fired, the victim
     that aliased the orphaned slot reads back P's owner. */
  uchar const * victims[2] = { pubkey_B, pubkey_B2 };
  uchar const * vowner [2] = { owner_B,  owner_B2  };
  int poisoned = 0;
  for( int v=0; v<2; v++ ) {
    uchar got_owner[ 32 ];
    uchar const * pks_v[1] = { victims[v] };
    int rd[1] = { 0 };
    fd_acc_t acc_v[1];
    memset( acc_v, 0, sizeof(acc_v) );
    fd_accdb_acquire( accdb, D, 1UL, pks_v, rd, acc_v );
    memcpy( got_owner, acc_v[0].owner, 32UL );
    fd_accdb_release( accdb, 1UL, acc_v );
    FD_LOG_NOTICE(( "victim %d pk0=%02x read owner0=%02x (expected %02x)",
                    v, victims[v][0], got_owner[0], vowner[v][0] ));
    if( !memcmp( got_owner, owner_P, 32UL ) ) {
      FD_LOG_WARNING(( "POISON: victim pk0=%02x read back P's owner (wrong-owner-valid-key)", victims[v][0] ));
      poisoned = 1;
    } else {
      FD_TEST( !memcmp( got_owner, vowner[v], 32UL ) );
    }
  }
  if( poisoned ) {
    FD_LOG_ERR(( "POISON CONFIRMED: tombstone-orphan / EBR-leak / writeback poison reproduced" ));
  }

  free( accdb_d );
  test_teardown( accdb, fd );
}

/* ------------------------------------------------------------------ */
/* SENTINEL case: acc_unlink observes a line already claimed for eviction */
/* ------------------------------------------------------------------ */

/* Fiber context: evict (+ write back) one specific cache line, suspending
   at clock_evict:post_sentinel while it holds EVICT_SENTINEL. */
#define EVICT_FIBER_STACK_SZ (1UL<<21)
struct evict_fiber {
  fd_racesan_async_t async[1];
  fd_accdb_t *       accdb;
  ulong              size_class;
  ulong              line_idx;
};
typedef struct evict_fiber evict_fiber_t;

static void
evict_fiber_exec( void * _ctx ) {
  evict_fiber_t * f = _ctx;
  fd_accdb_debug_clock_evict_line( f->accdb, f->size_class, f->line_idx );
}

/* test_sentinel_unlink_no_poison proves the acc_unlink EVICT_SENTINEL
   branch (the "do nothing" else) is correct.

   Schedule (single thread, one fiber):
     1. P open on root, closed (tombstone) on F, with P's tombstone line
        resident + dirty.
     2. Fiber E begins evicting P's line: it CASes refcnt 0->EVICT_SENTINEL
        and SUSPENDS at clock_evict:post_sentinel, BEFORE clearing
        accmeta->cache_idx — so the accmeta still points at the line.
     3. Main thread runs advance_root(F): background_advance_root's
        tombstone self-unlink calls acc_unlink(P).  Its reclaim CAS finds
        refcnt==EVICT_SENTINEL and takes the do-nothing else branch
        (it must NOT sever / touch the line E owns).
     4. Fiber E resumes and finishes the writeback of P's record.
     5. Oracle: the on-disk record E wrote names P with P's own owner — the
        slot was never recycled out from under E, so no pubkey=NEW/owner=OLD
        poison.  (In production the evictor's held EBR epoch is what blocks
        the slot recycle; the single-threaded schedule here reproduces the
        same ordering and shows the outcome is a correct, non-poison
        writeback.) */
static void
test_sentinel_unlink_no_poison( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 256UL, 16UL, 1024UL, 1024UL, 1UL<<30UL );

  uchar pubkey_P[ 32 ] = { 'P', 0 };
  uchar owner_P [ 32 ] = { 0xAA, 0 };

  fd_accdb_fork_id_t root0 = fd_accdb_attach_child( accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  fd_accdb_fork_id_t F     = fd_accdb_attach_child( accdb, root0 );

  /* P open on root0, then closed (tombstone) on F.  The close commit
     leaves P's tombstone version resident + dirty (persisted==0). */
  write_acc( accdb, root0, pubkey_P, 100UL, owner_P, NULL, 0UL );
  write_acc( accdb, F,     pubkey_P,   0UL, owner_P, NULL, 0UL );

  /* Locate P's resident tombstone line. */
  ulong cls, idx;
  FD_TEST( fd_accdb_debug_find_line( accdb, pubkey_P, &cls, &idx ) );

  /* Fiber E: claim P's line for eviction and suspend holding the
     sentinel, before it clears the accmeta back-reference. */
  static evict_fiber_t e[1];
  e->accdb      = accdb;
  e->size_class = cls;
  e->line_idx   = idx;
  void * e_stack = fd_racesan_stack_create( EVICT_FIBER_STACK_SZ );
  fd_racesan_async_new( e->async, e_stack, EVICT_FIBER_STACK_SZ, evict_fiber_exec, e );
  int r = fd_racesan_async_step_until( e->async, "clock_evict:post_sentinel", 100000UL );
  FD_TEST( r==FD_RACESAN_ASYNC_RET_HOOK );

  /* Main thread: advance_root(F) -> acc_unlink(P) observes the sentinel
     and must take the do-nothing else branch (no crash, no sever). */
  fd_accdb_advance_root( accdb, F );
  drain_background_n( accdb, 4UL );

  /* Resume E: finish the writeback of P's record. */
  for(;;) {
    r = fd_racesan_async_step( e->async );
    if( r==FD_RACESAN_ASYNC_RET_EXIT ) break;
    FD_TEST( r==FD_RACESAN_ASYNC_RET_HOOK );
  }
  fd_racesan_async_delete( e->async );
  fd_racesan_stack_destroy( e_stack, EVICT_FIBER_STACK_SZ );

  /* Oracle: read P back.  P is a tombstone (lamports==0), so acquire
     zeroes the owner regardless; the meaningful check is that the on-disk
     record E synthesized still names P (not a recycled foreign account).
     Read it via a fresh cold load and assert no poison: a non-tombstone
     foreign account would surface here as lamports!=0 with a foreign
     owner.  P must read back as closed. */
  uchar const * pks_P[1] = { pubkey_P };
  int rd[1] = { 0 };
  fd_acc_t acc_P[1];
  memset( acc_P, 0, sizeof(acc_P) );
  fd_accdb_acquire( accdb, F, 1UL, pks_P, rd, acc_P );
  FD_LOG_NOTICE(( "P read back lamports=%lu (expected 0, tombstone)", acc_P[0].lamports ));
  FD_TEST( acc_P[0].lamports==0UL );
  fd_accdb_release( accdb, 1UL, acc_P );

  test_teardown( accdb, fd );
}

/* ------------------------------------------------------------------ */
/* STEP-14 case: acc_unlink must not strand a reader pinned mid-acquire */
/* ------------------------------------------------------------------ */

/* Fiber context: read-acquire P on a fork, cache-hitting (and pinning)
   P's resident line.  Suspends at "cache_try_pin:pinned" (STEP 3 of
   fd_accdb_acquire_inner) holding the pin, then runs to completion
   through STEP 13/14/15. */
#define READ_FIBER_STACK_SZ (1UL<<21)
struct read_fiber {
  fd_racesan_async_t async[1];
  fd_accdb_t *       accdb;
  fd_accdb_fork_id_t fork_id;
  uchar const *      pubkey;
  fd_acc_t           acc[1];
};
typedef struct read_fiber read_fiber_t;

static void
read_fiber_exec( void * _ctx ) {
  read_fiber_t * f = _ctx;
  uchar const * pks[1] = { f->pubkey };
  int wr[1] = { 1 };
  memset( f->acc, 0, sizeof(f->acc) );
  fd_accdb_acquire( f->accdb, f->fork_id, 1UL, pks, wr, f->acc );
  fd_accdb_release( f->accdb, 1UL, f->acc );
}

/* test_step14_orphan_no_hang proves the acc_unlink pinned-reader branch
   does NOT strand a reader that pinned the line mid-acquire.

   Regression for the hang introduced when acc_unlink severed
   line->acc_idx to UINT_MAX: that value is the cold-load "still loading"
   sentinel, and acquire_inner STEP-14 spins `while(acc_idx==UINT_MAX)`
   forever for a line nobody will ever re-publish.

   Schedule (single thread, one fiber):
     1. P open on root, closed (tombstone) on F, line resident + dirty.
     2. Fiber R writably re-acquires P; at STEP 3 it cache-hits and PINS
        P's resident line (refcnt 0->1) and SUSPENDS at
        "cache_try_pin:pinned" — i.e. between STEP 3 and STEP 14.
     3. Main thread runs advance_root(F): acc_unlink(P)'s reclaim CAS
        fails under R's pin and takes the pinned-reader branch, which must
        neutralize the writeback WITHOUT severing acc_idx.
     4. Fiber R resumes.  STEP 14 must observe acc_idx!=UINT_MAX and
        return promptly; the fiber EXITS.  With the buggy sever, STEP 14
        spins forever (no hook inside the spin) and this never returns —
        a hang, caught by the test timeout. */
static void
test_step14_orphan_no_hang( void ) {
  int fd;
  fd_accdb_t * accdb = test_setup( &fd, 256UL, 16UL, 1024UL, 1024UL, 1UL<<30UL );

  uchar pubkey_P[ 32 ] = { 'P', 0 };
  uchar owner_P [ 32 ] = { 0xAA, 0 };

  fd_accdb_fork_id_t root0 = fd_accdb_attach_child( accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  fd_accdb_fork_id_t F     = fd_accdb_attach_child( accdb, root0 );

  /* P open on root0, closed (tombstone) on F; tombstone line resident +
     dirty (persisted==0). */
  write_acc( accdb, root0, pubkey_P, 100UL, owner_P, NULL, 0UL );
  write_acc( accdb, F,     pubkey_P,   0UL, owner_P, NULL, 0UL );

  /* Fiber R: writably re-acquire P (cache hit), pin the line, suspend at
     STEP 3's pin hook holding refcnt=1. */
  static read_fiber_t rf[1];
  rf->accdb   = accdb;
  rf->fork_id = F;
  rf->pubkey  = pubkey_P;
  void * rf_stack = fd_racesan_stack_create( READ_FIBER_STACK_SZ );
  fd_racesan_async_new( rf->async, rf_stack, READ_FIBER_STACK_SZ, read_fiber_exec, rf );
  int rc = fd_racesan_async_step_until( rf->async, "cache_try_pin:pinned", 100000UL );
  FD_TEST( rc==FD_RACESAN_ASYNC_RET_HOOK );

  /* Main thread: advance_root(F) -> acc_unlink(P) sees R's pin and takes
     the pinned-reader branch (must not sever acc_idx). */
  fd_accdb_advance_root( accdb, F );
  drain_background_n( accdb, 4UL );

  /* Resume R to completion.  If STEP-14 was stranded by an acc_idx sever,
     this loop never terminates (the spin has no hook to yield on) and the
     test hangs — the regression signal.  With the persisted-only fix R
     exits promptly. */
  for(;;) {
    rc = fd_racesan_async_step( rf->async );
    if( rc==FD_RACESAN_ASYNC_RET_EXIT ) break;
    FD_TEST( rc==FD_RACESAN_ASYNC_RET_HOOK );
  }
  fd_racesan_async_delete( rf->async );
  fd_racesan_stack_destroy( rf_stack, READ_FIBER_STACK_SZ );

  FD_LOG_NOTICE(( "STEP-14 reader resumed without hang" ));

  test_teardown( accdb, fd );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_tombstone_orphan_ebr_poison();
  test_sentinel_unlink_no_poison();
  test_step14_orphan_no_hang();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
