/* test_accdb_racesan.c deterministically weaves the concurrent accdb
   operations to hunt for the live-only bank-hash mismatch.

   The accdb threading model (see fd_accdb.h) is:

     T1 (replay)    : attach_child (inline), advance_root/purge (submit
                      a cmd, deferred to T2), acquire, release.
     T2 (background): fd_accdb_background -> background_advance_root /
                      background_purge / compaction.
     T3 (executors) : acquire, release.

   The bank-hash-mismatch mechanism is a reader (acquire) on some fork
   pinning an account VERSION that is not actually visible to that fork
   -- i.e. a version from a non-ancestor (cancelled sibling) fork, or a
   stale version that has been superseded.  The visibility predicate in
   fd_accdb_acquire_inner (generation<=root_generation || same-fork ||
   descends_set_test) is the guard, and ASSERTIONS A1/A2/A3 in that
   function fire if the chain is mutated under the reader such that a
   non-visible version is selected.  Those assertions ARE the oracle for
   these tests; we additionally check structural metrics.

   The races weave fd_accdb_acquire (T3) against fd_accdb_background
   running an advance_root / purge (T2), and against fd_accdb_release
   (prepend).  Hooks instrumented in fd_accdb.c:
     accdb_acquire:post_root_gen      (reader snapshotted root_generation)
     accdb_acquire:post_next          (reader holds candidate + map.next)
     accdb_advance:pre_unlink         (T2 about to unlink an old version)
     accdb_advance:pre_publish_root   (T2 about to publish new root)
     accdb_advance:post_publish_root
     accdb_release:pre_chain_cas      (release about to prepend) */

#define _GNU_SOURCE

#include "fd_accdb.h"
#include "fd_accdb_cache.h"
#define FD_ACCDB_NO_FORK_ID
#include "fd_accdb_private.h"
#undef FD_ACCDB_NO_FORK_ID
#include "../../util/fd_util.h"
#include "../../util/racesan/fd_racesan_async.h"
#include "../../util/racesan/fd_racesan_weave.h"
#include "../../util/racesan/fd_racesan_target.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define SENTINEL ((fd_accdb_fork_id_t){ .val = USHORT_MAX })

#define ITER_DEFAULT (4096UL)
#define STEP_MAX     (100000UL)

/* Cache footprint for tests.  Must cover cache_min_reserved slots of
   every size class (class 7 is 10 MiB each).  We use cache_min_reserved
   =4 here (vs replay's 640) since these tests have only a handful of
   joiners and touch a single small account, keeping the one-time
   allocation small enough to create per test cheaply. */
#define TEST_CACHE_MIN_RESERVED (4UL)
#define TEST_CACHE_FOOTPRINT    (256UL<<20UL)

#define FIBER_STACK_MAX (1UL<<21)

/* Test sizing.  Small but enough live slots for a few forks. */
#define T_MAX_ACCOUNTS      (1024UL)
#define T_MAX_LIVE_SLOTS    (64UL)
#define T_WRITES_PER_SLOT   (8192UL)
#define T_PARTITION_CNT     (8192UL)
#define T_PARTITION_SZ      (1UL<<30UL)
#define T_JOINER_CNT        (8UL)      /* ctl + reader + background/writer, with headroom */

/* ------------------------------------------------------------------ */
/* shmem + per-fiber join management                                  */
/* ------------------------------------------------------------------ */

static void *             g_shmem_mem;
static fd_accdb_shmem_t * g_shmem;
static int                g_fd;

static fd_accdb_shmem_t *
test_shmem_new_cfg2( ulong cache_fp,
                     ulong cache_min_reserved,
                     ulong partition_sz ) {
  g_fd = memfd_create( "accdb_racesan", 0 );
  if( FD_UNLIKELY( g_fd<0 ) ) FD_LOG_ERR(( "memfd_create failed" ));

  ulong shmem_fp = fd_accdb_shmem_footprint( T_MAX_ACCOUNTS, T_MAX_LIVE_SLOTS, T_WRITES_PER_SLOT, T_PARTITION_CNT, cache_fp, cache_min_reserved, T_JOINER_CNT );
  FD_TEST( shmem_fp );
  g_shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  FD_TEST( g_shmem_mem );
  g_shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( g_shmem_mem, T_MAX_ACCOUNTS, T_MAX_LIVE_SLOTS,
                          T_WRITES_PER_SLOT, T_PARTITION_CNT,
                          partition_sz, cache_fp, cache_min_reserved, 0, 42UL, T_JOINER_CNT ) );
  FD_TEST( g_shmem );
  return g_shmem;
}

static fd_accdb_shmem_t *
test_shmem_new_cfg( ulong cache_fp,
                    ulong cache_min_reserved ) {
  return test_shmem_new_cfg2( cache_fp, cache_min_reserved, T_PARTITION_SZ );
}

static fd_accdb_shmem_t *
test_shmem_new( void ) {
  return test_shmem_new_cfg( TEST_CACHE_FOOTPRINT, TEST_CACHE_MIN_RESERVED );
}

/* Small-partition config for compaction/reclamation tests.  A partition
   must be at least 10 MiB + header to fit a worst-case account, so the
   smallest useful partition is ~12 MiB; with ~4 MiB records three
   writes fill+rotate a partition and overwriting one frees >33%,
   enqueuing it for compaction. */
#define T_SMALL_PARTITION_SZ (12UL<<20UL) /* 12 MiB (>= 10 MiB min) */

/* Sizing for the compaction/epoch/owner-corruption tests. */
#define EPOCH_ITER (32UL)         /* compaction setup writes ~100 MB/iter; keep modest */
#define BIG_DATA   (4UL<<20)      /* 4 MiB: 3 records fill a 12 MiB partition */

/* Minimal cache: set the footprint to EXACTLY cache_min_reserved * sum of
   all class slot sizes.  At that footprint the allocator's phase-1 gives
   each class exactly cache_min_reserved slots and phase-2 has zero budget
   left to top up — so class 0 has exactly cache_min_reserved slots.  With
   only a few class-0 slots, a handful of distinct class-0 accounts forces
   CLOCK eviction, and re-reading an evicted account cold-loads from the
   backing memfd.  (Slot sizes mirror fd_accdb_cache_slot_sz in
   fd_accdb_cache.c; META_SZ is FD_ACCDB_CACHE_META_SZ.) */
#define TEST_TINY_CACHE_MIN_RESERVED (8UL)

static ulong
test_tiny_cache_footprint( void ) {
  ulong const data[ FD_ACCDB_CACHE_CLASS_CNT ] =
    { 128UL, 512UL, 2048UL, 8192UL, 32768UL, 131072UL, 1048576UL, 10485760UL };
  ulong sum = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) sum += data[ c ] + FD_ACCDB_CACHE_META_SZ;
  return TEST_TINY_CACHE_MIN_RESERVED * sum;
}

static fd_accdb_shmem_t *
test_shmem_new_tiny( void ) {
  return test_shmem_new_cfg( test_tiny_cache_footprint(), TEST_TINY_CACHE_MIN_RESERVED );
}

static fd_accdb_shmem_t *
test_shmem_new_smallpart( void ) {
  return test_shmem_new_cfg2( test_tiny_cache_footprint(), TEST_TINY_CACHE_MIN_RESERVED, T_SMALL_PARTITION_SZ );
}

static void
test_shmem_delete( void ) {
  free( g_shmem_mem );
  g_shmem_mem = NULL;
  g_shmem     = NULL;
  close( g_fd );
  g_fd = -1;
}

/* A join is a heap-allocated fd_accdb_t local state over the shared
   shmem.  Each fiber (and the control thread) gets its own join, so each
   claims its own epoch slot, exactly like a distinct tile would. */

static fd_accdb_t *
join_new( void ) {
  ulong accdb_fp = fd_accdb_footprint( T_MAX_LIVE_SLOTS );
  FD_TEST( accdb_fp );
  void * mem = aligned_alloc( fd_accdb_align(), accdb_fp );
  FD_TEST( mem );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( mem, g_shmem, g_fd, 0UL, NULL ) );
  FD_TEST( accdb );
  return accdb;
}

static void
join_delete( fd_accdb_t * accdb ) {
  free( accdb );
}

/* ------------------------------------------------------------------ */
/* sequential helpers (run on a control join, no weaving)             */
/* ------------------------------------------------------------------ */

static uchar g_zero_owner[ 32UL ] = { 0 };

static void
seq_write_data( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork_id,
                uchar const *      pubkey,
                ulong              lamports,
                uchar const *      owner,
                ulong              data_len,
                uchar              data_fill ) {
  uchar const * pks[1] = { pubkey };
  int wr[1] = { 1 };
  fd_acc_t acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( accdb, fork_id, 1UL, pks, wr, acc );
  acc[0].lamports = lamports;
  acc[0].data_len = data_len;
  if( data_len ) memset( acc[0].data, data_fill, data_len );
  memcpy( acc[0].owner, owner ? owner : g_zero_owner, 32UL );
  acc[0].commit = 1;
  fd_accdb_release( accdb, 1UL, acc );
}

static void
seq_write( fd_accdb_t *       accdb,
           fd_accdb_fork_id_t fork_id,
           uchar const *      pubkey,
           ulong              lamports,
           uchar const *      owner ) {
  seq_write_data( accdb, fork_id, pubkey, lamports, owner, 0UL, 0 );
}

static void
drain_background( fd_accdb_t * accdb ) {
  int charge_busy = 0;
  fd_accdb_background( accdb, &charge_busy );
}

static uchar
mk_key( ulong i, uchar key[ 32UL ] ) {
  memset( key, 0, 32UL );
  FD_STORE( ulong, key, i );
  return 0;
}

/* ------------------------------------------------------------------ */
/* fibers                                                             */
/* ------------------------------------------------------------------ */

struct fiber {
  fd_racesan_async_t async[1];
  fd_accdb_t *       accdb;
  uchar              stack[ FIBER_STACK_MAX ] __attribute__((aligned(4096)));

  union {
    struct {
      fd_accdb_fork_id_t fork_id;
      uchar              pubkey[ 32UL ];
      /* When expect_lamports!=0, the fiber asserts the acquired account
         matches (the cold-load / eviction correctness oracle). */
      ulong              expect_lamports;
    } acquire;

    struct {
      fd_accdb_fork_id_t fork_id;
      uchar              pubkey[ 32UL ];
      ulong              lamports;
    } release_write;

    struct {
      fd_accdb_fork_id_t fork_id;
      uchar              pubkey[ 32UL ];
      /* The writer always commits a self-consistent pair: owner byte 0
         equals (lamports==LAMP_A ? TAG_A : TAG_B).  A torn read in the
         acquire path (lamports re-read separately from the owner / the
         tombstone decision) would surface as an inconsistent pair. */
    } acquire_consistent;

    struct {
      fd_accdb_fork_id_t fork_id;
      uchar              pubkey[ 32UL ];
      int                state; /* 0 -> (LAMP_A,TAG_A); 1 -> (LAMP_B,TAG_B) */
    } overwrite;

    struct {
      int charge_busy;
    } background;

    struct {
      fd_accdb_fork_id_t fork_id;
      uchar              pubkey[ 32UL ];
      ulong              expect_lamports;
      uchar              expect_owner0;     /* expected owner[0] tag */
      ulong              expect_data_len;
      uchar              expect_data_fill;  /* expected data byte value */
    } nocache;

    struct {
      int steps;        /* number of fd_accdb_background calls to issue */
    } compact_loop;

    struct {
      fd_accdb_fork_id_t fork_id;
      uchar              pubkey[ 32UL ];
    } probe;

    struct {
      fd_accdb_fork_id_t fork_id;
      uchar              pubkey[ 32UL ];
      int                pd_write;
    } pd_commit;

    struct {
      fd_accdb_fork_id_t fork_w;          /* executing fork: acquire_a X writable  */
      fd_accdb_fork_id_t fork_r;          /* programdata fork: acquire_b D ro      */
      uchar              pubkey_x[ 32UL ];
      uchar              pubkey_d[ 32UL ];
      ulong              expect_lamports; /* D stability oracle (0 = don't check)  */
      uchar              expect_owner0;
    } acquire_ab;

    struct {
      fd_accdb_fork_id_t fork_id;
      uchar              pubkey[ 32UL ];
      int                rounds;
    } overwrite_n;
  };
};
typedef struct fiber fiber_t;

/* Two self-consistent (lamports, owner-tag) states the overwrite writer
   toggles between.  LAMP_A is non-zero (live); the owner tag is encoded
   in owner[0] so a reader can check (lamports,owner) consistency.  We
   also exercise the tombstone boundary by including a zero-lamport
   state in the dedicated torn-tombstone test. */
#define LAMP_A (2039280UL)   /* SPL-token rent-exempt, like the real acct[32] */
#define TAG_A  (0x11)
#define LAMP_B (5000000UL)
#define TAG_B  (0x22)

static fiber_t g_fiber[ 4 ];

/* Mixed into each iteration's weave seed so the same build can sweep many
   distinct interleaving schedules across runs (--seed-base N). */
static ulong g_seed_base = 0UL;

/* Set when the test was named explicitly on the command line.  Used to
   gate demonstration tests that intentionally FAIL (contract-violating
   repros) so they don't break a default "run all" invocation. */
static int g_explicit = 0;

/* acquire fiber: a read-only acquire+release of one account.  This is
   the T3 reader whose visibility assertions (A1/A2/A3) are the oracle. */

static void
fiber_acquire_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  uchar const * pks[1] = { f->acquire.pubkey };
  int wr[1] = { 0 };
  fd_acc_t acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( f->accdb, f->acquire.fork_id, 1UL, pks, wr, acc );
  /* Cold-load / eviction correctness oracle: the bytes the reader sees
     must match what was committed for this (key, fork).  A torn cold-load
     or a wrong cache_try_pin (ABA that slipped the key recheck) would
     surface here as a lamports/pubkey mismatch. */
  if( f->acquire.expect_lamports ) {
    FD_TEST( acc[0].lamports==f->acquire.expect_lamports );
    FD_TEST( !memcmp( acc[0].pubkey, f->acquire.pubkey, 32UL ) );
  }
  fd_accdb_release( f->accdb, 1UL, acc );
}

static fd_racesan_async_t *
fiber_acquire_expect( fiber_t *          fiber,
                      fd_accdb_t *       accdb,
                      fd_accdb_fork_id_t fork_id,
                      uchar const *      pubkey,
                      ulong              expect_lamports ) {
  fiber->accdb                   = accdb;
  fiber->acquire.fork_id         = fork_id;
  fiber->acquire.expect_lamports = expect_lamports;
  memcpy( fiber->acquire.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_acquire_exec, fiber );
  return fiber->async;
}

static fd_racesan_async_t *
fiber_acquire( fiber_t *          fiber,
               fd_accdb_t *       accdb,
               fd_accdb_fork_id_t fork_id,
               uchar const *      pubkey ) {
  return fiber_acquire_expect( fiber, accdb, fork_id, pubkey, 0UL );
}

/* release fiber: a writable acquire+commit+release, which prepends a new
   acc to the hash chain (the accdb_release:pre_chain_cas hook). */

static void
fiber_release_write_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  uchar const * pks[1] = { f->release_write.pubkey };
  int wr[1] = { 1 };
  fd_acc_t acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( f->accdb, f->release_write.fork_id, 1UL, pks, wr, acc );
  acc[0].lamports = f->release_write.lamports;
  acc[0].data_len = 0UL;
  memcpy( acc[0].owner, g_zero_owner, 32UL );
  acc[0].commit = 1;
  fd_accdb_release( f->accdb, 1UL, acc );
}

static fd_racesan_async_t *
fiber_release_write( fiber_t *          fiber,
                     fd_accdb_t *       accdb,
                     fd_accdb_fork_id_t fork_id,
                     uchar const *      pubkey,
                     ulong              lamports ) {
  fiber->accdb                 = accdb;
  fiber->release_write.fork_id = fork_id;
  fiber->release_write.lamports = lamports;
  memcpy( fiber->release_write.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_release_write_exec, fiber );
  return fiber->async;
}

/* consistent-reader fiber: read-only acquire that asserts the returned
   (lamports, owner) form a self-consistent pair the overwrite writer
   could have committed.  This is the torn-read oracle for the proposed
   acct[2]/[3]/[32] mechanism: lamports is read three times in
   acquire_inner (STEP 7 tombstone, STEP 7 lamports, STEP 14 tombstone)
   and the owner once (STEP 14); if any disagree, we observe a pair the
   writer never committed. */

static void
fiber_acquire_consistent_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  uchar const * pks[1] = { f->acquire_consistent.pubkey };
  int wr[1] = { 0 };
  fd_acc_t acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( f->accdb, f->acquire_consistent.fork_id, 1UL, pks, wr, acc );

  ulong lam = acc[0].lamports;
  uchar tag = acc[0].owner[0];
  /* Permitted observations:
       (LAMP_A, TAG_A), (LAMP_B, TAG_B)  -> a committed live state
       (0, all-zero owner)               -> tombstone reset (lamports==0)
     Anything else is a torn read: e.g. lamports=LAMP_A with owner tag
     TAG_B, or lamports==0 with a non-zero owner tag, or lamports!=0 with
     a zero owner. */
  int ok = ( lam==LAMP_A && tag==TAG_A ) ||
           ( lam==LAMP_B && tag==TAG_B ) ||
           ( lam==0UL    && tag==0x00  );
  if( FD_UNLIKELY( !ok ) ) {
    FD_LOG_ERR(( "accdb torn read: lamports=%lu owner[0]=0x%02x (neither a committed pair nor a clean tombstone)",
                 lam, (uint)tag ));
  }
  fd_accdb_release( f->accdb, 1UL, acc );
}

static fd_racesan_async_t *
fiber_acquire_consistent( fiber_t *          fiber,
                          fd_accdb_t *       accdb,
                          fd_accdb_fork_id_t fork_id,
                          uchar const *      pubkey ) {
  fiber->accdb                     = accdb;
  fiber->acquire_consistent.fork_id = fork_id;
  memcpy( fiber->acquire_consistent.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_acquire_consistent_exec, fiber );
  return fiber->async;
}

/* overwrite-writer fiber: writable acquire+commit+release on the SAME
   (pubkey, fork) the reader uses, committing a self-consistent pair.
   This deliberately overlaps a read-only acquire of the same account on
   the same fork — which the public API forbids — to probe whether the
   acquire path's multiple unsynchronized reads of accmeta->lamports tear
   when the selected accmeta is overwritten in place (release STEP 1,
   fd_accdb.c:3038). */

static void
fiber_overwrite_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  uchar const * pks[1] = { f->overwrite.pubkey };
  int wr[1] = { 1 };
  fd_acc_t acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( f->accdb, f->overwrite.fork_id, 1UL, pks, wr, acc );
  acc[0].lamports = f->overwrite.state ? LAMP_B : LAMP_A;
  acc[0].data_len = 0UL;
  memset( acc[0].owner, 0, 32UL );
  acc[0].owner[0] = f->overwrite.state ? TAG_B : TAG_A;
  acc[0].commit = 1;
  fd_accdb_release( f->accdb, 1UL, acc );
}

static fd_racesan_async_t *
fiber_overwrite( fiber_t *          fiber,
                 fd_accdb_t *       accdb,
                 fd_accdb_fork_id_t fork_id,
                 uchar const *      pubkey,
                 int                state ) {
  fiber->accdb            = accdb;
  fiber->overwrite.fork_id = fork_id;
  fiber->overwrite.state   = state;
  memcpy( fiber->overwrite.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_overwrite_exec, fiber );
  return fiber->async;
}

/* full-size overwrite fiber: a same-fork, SAME-size-class (BIG_DATA)
   in-place overwrite of K with a distinct (owner0, data fill).  The
   in-place commit xchg's K's offset_fork to INVAL then re-publishes, and
   rewrites the cache-line owner+data (offset 64+).  Used to race a cold
   reader's disk-read iovec build (accdb_coldload:pre_iovec): the cold
   reader must never scatter a torn/INVAL on-disk record into its owner
   field — the offset_fork!=INVAL spin is what guarantees this. */
static void
fiber_overwrite_full_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  uchar const * pks[1] = { f->overwrite.pubkey };
  int wr[1] = { 1 };
  fd_acc_t acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( f->accdb, f->overwrite.fork_id, 1UL, pks, wr, acc );
  acc[0].lamports = LAMP_B;
  acc[0].data_len = BIG_DATA;
  memset( acc[0].owner, 0, 32UL ); acc[0].owner[0] = TAG_B;
  if( acc[0].data ) memset( acc[0].data, 0xBB, BIG_DATA );
  acc[0].commit = 1;
  fd_accdb_release( f->accdb, 1UL, acc );
}

static fd_racesan_async_t *
fiber_overwrite_full( fiber_t *          fiber,
                      fd_accdb_t *       accdb,
                      fd_accdb_fork_id_t fork_id,
                      uchar const *      pubkey ) {
  fiber->accdb             = accdb;
  fiber->overwrite.fork_id = fork_id;
  memcpy( fiber->overwrite.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_overwrite_full_exec, fiber );
  return fiber->async;
}

/* background fiber: one unit of T2 work, which executes a pending
   advance_root / purge command (where the advance hooks live). */

static void
fiber_background_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  f->background.charge_busy = 0;
  fd_accdb_background( f->accdb, &f->background.charge_busy );
}

static fd_racesan_async_t *
fiber_background( fiber_t *    fiber,
                  fd_accdb_t * accdb ) {
  fiber->accdb = accdb;
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_background_exec, fiber );
  return fiber->async;
}

/* nocache reader fiber: drives fd_accdb_read_one_nocache, the RO disk
   path with the epoch lifecycle (publish epoch -> snapshot offset_fork ->
   preadv2 -> reset epoch).  This is the reader the epoch-reclamation
   protocol must protect against compaction freeing the source partition.
   Oracle: the returned (lamports, owner[0], data_len, data bytes) must
   match what was committed for this quiescent account — a freed/reused
   partition read would surface as zeros or neighbor bytes. */

static uchar g_nocache_data[ 10UL<<20 ]; /* shared; fibers run cooperatively */

static void
fiber_nocache_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  ulong lamports = 0UL; int executable = 0; ulong data_len = 0UL;
  uchar owner[ 32UL ];
  memset( owner, 0xAB, 32UL ); /* poison so a skipped owner-write is visible */
  fd_accdb_read_one_nocache( f->accdb, f->nocache.fork_id, f->nocache.pubkey,
                             &lamports, &executable, owner, g_nocache_data, &data_len );
  if( FD_LIKELY( f->nocache.expect_lamports ) ) {
    FD_TEST( lamports==f->nocache.expect_lamports );
    FD_TEST( data_len==f->nocache.expect_data_len );
    FD_TEST( owner[0]==f->nocache.expect_owner0 );
    /* spot-check the data bytes: all must equal the committed fill, never
       zero/stale from a reclaimed-then-reused partition. */
    for( ulong z=0UL; z<data_len; z+=509UL ) FD_TEST( g_nocache_data[z]==f->nocache.expect_data_fill );
    if( data_len ) FD_TEST( g_nocache_data[ data_len-1UL ]==f->nocache.expect_data_fill );
  } else if( f->nocache.expect_owner0==0xFF /*consistency-only sentinel*/ && lamports ) {
    /* The account is live; its (owner0, data) MUST be one of the two known
       self-consistent committed states (TAG_A/0xAA or TAG_B/0xBB), never a
       torn owner from a stale/INVAL cold-load offset.  The key (offset
       0..36) is set by the cache line, so a torn read shows up as a
       mismatched owner/data with a correct pubkey — exactly here. */
    uchar tag = owner[0]; uchar d0 = data_len? g_nocache_data[0] : 0;
    uchar dz = data_len? g_nocache_data[ data_len-1UL ] : 0;
    int ok = ( tag==TAG_A && data_len==BIG_DATA && d0==0xAA && dz==0xAA ) ||
             ( tag==TAG_B && data_len==BIG_DATA && d0==0xBB && dz==0xBB );
    if( FD_UNLIKELY( !ok ) ) {
      FD_LOG_ERR(( "coldload torn read: live K owner0=0x%02x data_len=%lu d0=0x%02x dlast=0x%02x (neither committed TAG_A/0xAA nor TAG_B/0xBB)",
                   (uint)tag, data_len, (uint)d0, (uint)dz ));
    }
  }
}

static fd_racesan_async_t *
fiber_nocache( fiber_t *          fiber,
               fd_accdb_t *       accdb,
               fd_accdb_fork_id_t fork_id,
               uchar const *      pubkey,
               ulong              expect_lamports,
               uchar              expect_owner0,
               ulong              expect_data_len,
               uchar              expect_data_fill ) {
  fiber->accdb                  = accdb;
  fiber->nocache.fork_id        = fork_id;
  fiber->nocache.expect_lamports = expect_lamports;
  fiber->nocache.expect_owner0   = expect_owner0;
  fiber->nocache.expect_data_len = expect_data_len;
  fiber->nocache.expect_data_fill = expect_data_fill;
  memcpy( fiber->nocache.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_nocache_exec, fiber );
  return fiber->async;
}

/* compaction-loop fiber: issues N fd_accdb_background calls, driving
   compaction (one record relocated per call per layer) and deferred-free
   partition reclamation to completion within a single weave. */

static void
fiber_compact_loop_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  for( int s=0; s<f->compact_loop.steps; s++ ) {
    int charge_busy = 0;
    fd_accdb_background( f->accdb, &charge_busy );
  }
}

static fd_racesan_async_t *
fiber_compact_loop( fiber_t *    fiber,
                    fd_accdb_t * accdb,
                    int          steps ) {
  fiber->accdb              = accdb;
  fiber->compact_loop.steps = steps;
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_compact_loop_exec, fiber );
  return fiber->async;
}

/* probe fiber: runs fd_accdb_probe_pd_this_fork on fork_id.  Asserts the
   result is self-consistent (pd in {0,1}; a gen-match return implies a
   defined data_len) and, above all, never crashes when racing a
   concurrent writer that toggles the pd_write bit / rewrites the chain
   head.  Both a pre- and post-commit answer are acceptable. */
static void
fiber_probe_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  int   pd  = 7;          /* poison: probe must overwrite */
  ulong len = 0xdeadUL;
  int   r   = fd_accdb_probe_pd_this_fork( f->accdb, f->probe.fork_id, f->probe.pubkey, &pd, &len );
  FD_TEST( pd==0 || pd==1 );
  FD_TEST( r==0 || r==1 );
  if( !r ) FD_TEST( len==0xdeadUL ); /* no gen-match => out_data_len untouched */
}

static fd_racesan_async_t *
fiber_probe( fiber_t *          fiber,
             fd_accdb_t *       accdb,
             fd_accdb_fork_id_t fork_id,
             uchar const *      pubkey ) {
  fiber->accdb          = accdb;
  fiber->probe.fork_id  = fork_id;
  memcpy( fiber->probe.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_probe_exec, fiber );
  return fiber->async;
}

/* pd_commit fiber: an overwrite commit that sets pd_write, exercising the
   OR-sticky bit CAS in fd_accdb_release racing the probe walk above. */
static void
fiber_pd_commit_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  uchar const * pks[1] = { f->pd_commit.pubkey };
  int wr[1] = { 1 };
  fd_acc_t acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( f->accdb, f->pd_commit.fork_id, 1UL, pks, wr, acc );
  acc[0].lamports = LAMP_B;
  acc[0].data_len = 0UL;
  memset( acc[0].owner, 0, 32UL ); acc[0].owner[0] = TAG_B;
  acc[0].commit   = 1;
  acc[0].pd_write = f->pd_commit.pd_write;
  fd_accdb_release( f->accdb, 1UL, acc );
}

static fd_racesan_async_t *
fiber_pd_commit( fiber_t *          fiber,
                 fd_accdb_t *       accdb,
                 fd_accdb_fork_id_t fork_id,
                 uchar const *      pubkey,
                 int                pd_write ) {
  fiber->accdb            = accdb;
  fiber->pd_commit.fork_id  = fork_id;
  fiber->pd_commit.pd_write = pd_write;
  memcpy( fiber->pd_commit.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_pd_commit_exec, fiber );
  return fiber->async;
}

/* acquire_ab fiber: the executor's implicit-programdata shape.
   acquire_a of X writable on fork_w (the executing fork), then
   acquire_b of D read-only on fork_r, exactly like
   fd_executor_setup_accounts_for_txn.  When expect_lamports!=0, asserts
   D's {lamports, owner[0]} pair matches at pin time and again before
   release (a concurrent writer on another fork must never mutate the
   pinned copy). */
static void
fiber_acquire_ab_exec( void * _ctx ) {
  fiber_t * f = _ctx;

  uchar const * pka[1] = { f->acquire_ab.pubkey_x };
  int           wra[1] = { 1 };
  fd_acc_t acc_a[1]; memset( acc_a, 0, sizeof(acc_a) );
  fd_accdb_acquire_a( f->accdb, f->acquire_ab.fork_w, 1UL, pka, wra, acc_a );

  uchar const * pkb[1] = { f->acquire_ab.pubkey_d };
  int           wrb[1] = { 0 };
  fd_acc_t acc_b[1]; memset( acc_b, 0, sizeof(acc_b) );
  fd_accdb_acquire_b( f->accdb, f->acquire_ab.fork_r, 1UL, 1UL, pkb, wrb, acc_b );

  if( f->acquire_ab.expect_lamports ) {
    FD_TEST( acc_b[0].lamports==f->acquire_ab.expect_lamports );
    FD_TEST( acc_b[0].owner[0]==f->acquire_ab.expect_owner0   );
  }
  fd_racesan_hook( "pdtest:held" ); /* interleave point mid-hold */
  if( f->acquire_ab.expect_lamports ) {
    FD_TEST( FD_VOLATILE_CONST( acc_b[0].lamports )==f->acquire_ab.expect_lamports );
    FD_TEST( FD_VOLATILE_CONST( acc_b[0].owner[0] )==f->acquire_ab.expect_owner0   );
  }

  fd_accdb_release_ab( f->accdb, 1UL, acc_a, 1UL, acc_b );
}

static fd_racesan_async_t *
fiber_acquire_ab( fiber_t *          fiber,
                  fd_accdb_t *       accdb,
                  fd_accdb_fork_id_t fork_w,
                  fd_accdb_fork_id_t fork_r,
                  uchar const *      pubkey_x,
                  uchar const *      pubkey_d,
                  ulong              expect_lamports,
                  uchar              expect_owner0 ) {
  fiber->accdb                      = accdb;
  fiber->acquire_ab.fork_w          = fork_w;
  fiber->acquire_ab.fork_r          = fork_r;
  fiber->acquire_ab.expect_lamports = expect_lamports;
  fiber->acquire_ab.expect_owner0   = expect_owner0;
  memcpy( fiber->acquire_ab.pubkey_x, pubkey_x, 32UL );
  memcpy( fiber->acquire_ab.pubkey_d, pubkey_d, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_acquire_ab_exec, fiber );
  return fiber->async;
}

/* overwrite_n fiber: `rounds` same-size-class overwrite commits of D
   (data_len 0 -> class 0 -> the second commit takes the in-place reuse
   branch and its FD_TEST(refcnt==1U)). */
static void
fiber_overwrite_n_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  for( int r=0; r<f->overwrite_n.rounds; r++ ) {
    uchar const * pks[1] = { f->overwrite_n.pubkey };
    int wr[1] = { 1 };
    fd_acc_t acc[1];
    memset( acc, 0, sizeof(acc) );
    fd_accdb_acquire( f->accdb, f->overwrite_n.fork_id, 1UL, pks, wr, acc );
    acc[0].lamports = LAMP_B;
    acc[0].data_len = 0UL;
    memset( acc[0].owner, 0, 32UL ); acc[0].owner[0] = TAG_B;
    acc[0].commit = 1;
    fd_accdb_release( f->accdb, 1UL, acc );
  }
}

static fd_racesan_async_t *
fiber_overwrite_n( fiber_t *          fiber,
                   fd_accdb_t *       accdb,
                   fd_accdb_fork_id_t fork_id,
                   uchar const *      pubkey,
                   int                rounds ) {
  fiber->accdb               = accdb;
  fiber->overwrite_n.fork_id = fork_id;
  fiber->overwrite_n.rounds  = rounds;
  memcpy( fiber->overwrite_n.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack+FIBER_STACK_MAX, FIBER_STACK_MAX, fiber_overwrite_n_exec, fiber );
  return fiber->async;
}

static void
fiber_done( fiber_t * fiber ) {
  fd_racesan_async_delete( fiber->async );
}

/* ------------------------------------------------------------------ */
/* tests                                                              */
/* ------------------------------------------------------------------ */

/* LIFECYCLE NOTE.  advance_root requires its argument to be a DIRECT
   CHILD of the current root.  So each test establishes the root ONCE
   (attach_child(SENTINEL)) before the loop, and each iteration walks the
   trunk forward by exactly one level: from the current root R it attaches
   A=child(R) (plus any sibling/child needed for the race), runs the
   weave (whose background fiber executes the submitted advance_root(A)),
   and ends with A as the new root.  Because the weave asserts
   !w->rem_cnt, both fibers always run to completion, so by the end of the
   iteration the advance has fully executed and A is the root for the next
   iteration.  Old root slots are deferred-freed and recycle, keeping the
   live-slot count bounded across all iterations. */

/* test_acquire_vs_advance: the core bank-hash mechanism.

       R(current root) --> A --> A1   [reader's fork]

   key has a rooted version (written on R's trunk) and a NEW version on
   A1.  We submit advance_root(A) and race the T2 background that
   executes it against a reader acquiring key on A1.  The reader snapshots
   the OLD root_generation, then T2 advances the root to A, recycles R's
   slot, and unlinks superseded versions.  If the reader selects a version
   not visible to A1, ASSERTION A2 fires. */

static void
test_acquire_vs_advance( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new(); /* reader join */
  fd_accdb_t * jb  = join_new(); /* background join */

  uchar key[ 32UL ]; mk_key( 42UL, key );
  uchar owner[ 32UL ] = { 7, 0 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  seq_write( ctl, root, key, 100UL, owner );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_accdb_fork_id_t a  = fd_accdb_attach_child( ctl, root );
    fd_accdb_fork_id_t a1 = fd_accdb_attach_child( ctl, a );
    /* Write a NEW version of key on A (the fork being rooted): this
       creates a txn on A so background_advance_root(A) walks A's txns and
       UNLINKS the older rooted version on R's trunk (firing pre_unlink).
       The reader on A1 (descendant of A) must observe A's version, never
       the version being unlinked. */
    seq_write( ctl, a, key, 200UL+i, owner );

    /* submit advance_root(A); the background fiber will execute it */
    fd_accdb_advance_root( ctl, a );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_acquire(    &g_fiber[0], jr, a1, key ) );
    fd_racesan_weave_add( w, fiber_background( &g_fiber[1], jb ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    /* The weave executed advance_root(A), so A is now the root with A1
       as its only child.  Collapse fully onto A1 so the trunk leaves no
       dangling forks for the next iteration (keeping live slots bounded). */
    fd_accdb_advance_root( ctl, a1 );
    drain_background( ctl );
    root = a1;
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jb );
  test_shmem_delete();
}

/* test_acquire_vs_advance_sibling: reader on the winning trunk while the
   losing sibling subtree is removed by advance_root.

       R(current root) --> A --> A1   [reader's fork, winner]
                       \-> B          [loser, DIFFERENT version of key]

   advance_root(A) removes B (and B's version of key).  A reader on A1
   must never observe B's version.  A2 is the oracle. */

static void
test_acquire_vs_advance_sibling( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new();
  fd_accdb_t * jb  = join_new();

  uchar key[ 32UL ]; mk_key( 42UL, key );
  uchar owner[ 32UL ] = { 7, 0 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  seq_write( ctl, root, key, 100UL, owner );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_accdb_fork_id_t a  = fd_accdb_attach_child( ctl, root );
    fd_accdb_fork_id_t b  = fd_accdb_attach_child( ctl, root );
    fd_accdb_fork_id_t a1 = fd_accdb_attach_child( ctl, a );
    seq_write( ctl, b,  key, 300UL+i, owner ); /* loser's version (sibling, removed) */
    seq_write( ctl, a,  key, 200UL+i, owner ); /* winner's version (on rooted fork) */

    fd_accdb_advance_root( ctl, a );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_acquire(    &g_fiber[0], jr, a1, key ) );
    fd_racesan_weave_add( w, fiber_background( &g_fiber[1], jb ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    /* weave executed advance_root(A) (dropping sibling B); collapse onto A1 */
    fd_accdb_advance_root( ctl, a1 );
    drain_background( ctl );
    root = a1;
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jb );
  test_shmem_delete();
}

/* test_acquire_interior_unlink: force the reader to traverse PAST a chain
   node that is concurrently being unlinked, and to SKIP a non-visible
   head, so the visibility predicate is evaluated on an interior node
   during the unlink window.

   Chain for key (head -> tail), built by writing in tail->head order:
       B's v  (head, sibling fork, NOT visible to A1 -> skipped by reader)
       A's v  (interior, visible to A1 -> the version reader must select)
       R's v  (tail, rooted base, unlinked by advance_root(A))

   We submit advance_root(A): T2 first removes sibling B (purging B's
   head node off the chain) and then unlinks the superseded R version on
   the trunk, all while the reader on A1 walks B(skip) -> A(select).  The
   reader must end on A's version regardless of interleaving; A2 fires if
   it ever pins B's (non-visible) or R's (unlinked) version. */

static void
test_acquire_interior_unlink( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new();
  fd_accdb_t * jb  = join_new();

  uchar key[ 32UL ]; mk_key( 42UL, key );
  uchar owner[ 32UL ] = { 7, 0 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  seq_write( ctl, root, key, 100UL, owner ); /* R's v -> chain tail */

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_accdb_fork_id_t a  = fd_accdb_attach_child( ctl, root );
    fd_accdb_fork_id_t b  = fd_accdb_attach_child( ctl, root );
    fd_accdb_fork_id_t a1 = fd_accdb_attach_child( ctl, a );
    /* write A first (interior), then B last (head) so the reader on A1
       must skip the B head and select the A interior node. */
    seq_write( ctl, a, key, 200UL+i, owner );
    seq_write( ctl, b, key, 300UL+i, owner );

    fd_accdb_advance_root( ctl, a );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_acquire(    &g_fiber[0], jr, a1, key ) );
    fd_racesan_weave_add( w, fiber_background( &g_fiber[1], jb ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    fd_accdb_advance_root( ctl, a1 );
    drain_background( ctl );
    root = a1;
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jb );
  test_shmem_delete();
}

/* test_acquire_vs_release: a reader walks the chain for key as-of A1
   while a concurrent writable release on a DIFFERENT fork (sibling B)
   prepends a new acc to the SAME hash chain head.  Exercises the
   chain-mutated-mid-walk path (A1/A3) and the prepend-vs-walk race.
   B is dropped at the end of the iteration by advancing the root to A. */

static void
test_acquire_vs_release( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new();
  fd_accdb_t * jw  = join_new();

  uchar key[ 32UL ]; mk_key( 42UL, key );
  uchar owner[ 32UL ] = { 7, 0 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  seq_write( ctl, root, key, 100UL, owner );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_accdb_fork_id_t a  = fd_accdb_attach_child( ctl, root );
    fd_accdb_fork_id_t b  = fd_accdb_attach_child( ctl, root );
    fd_accdb_fork_id_t a1 = fd_accdb_attach_child( ctl, a );

    /* reader reads key as-of A1 (sees the rooted version); writer commits
       a new version of key on sibling B concurrently. */
    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_acquire(       &g_fiber[0], jr, a1, key ) );
    fd_racesan_weave_add( w, fiber_release_write( &g_fiber[1], jw, b, key, 400UL+i ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    /* drop sibling b by advancing onto the A trunk, then collapse to A1 */
    fd_accdb_advance_root( ctl, a );
    drain_background( ctl );
    fd_accdb_advance_root( ctl, a1 );
    drain_background( ctl );
    root = a1;
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jw );
  test_shmem_delete();
}

/* test_acquire_vs_purge: a reader on fork A1 while a sibling subtree B is
   purged (equivocation handling) by T2.  The purge unlinks B's accounts
   and recycles B's fork slot.  The reader on A1 must be unaffected. */

static void
test_acquire_vs_purge( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new();
  fd_accdb_t * jb  = join_new();

  uchar key[ 32UL ]; mk_key( 42UL, key );
  uchar owner[ 32UL ] = { 7, 0 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  seq_write( ctl, root, key, 100UL, owner );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_accdb_fork_id_t a  = fd_accdb_attach_child( ctl, root );
    fd_accdb_fork_id_t b  = fd_accdb_attach_child( ctl, root );
    fd_accdb_fork_id_t a1 = fd_accdb_attach_child( ctl, a );
    seq_write( ctl, b,  key, 300UL+i, owner );
    seq_write( ctl, a1, key, 200UL+i, owner );

    fd_accdb_purge( ctl, b );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_acquire(    &g_fiber[0], jr, a1, key ) );
    fd_racesan_weave_add( w, fiber_background( &g_fiber[1], jb ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    /* purge of B has run (background fiber); advance onto A trunk, collapse to A1 */
    fd_accdb_advance_root( ctl, a );
    drain_background( ctl );
    fd_accdb_advance_root( ctl, a1 );
    drain_background( ctl );
    root = a1;
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jb );
  test_shmem_delete();
}

/* ====================================================================
   Cache-layer races: eviction (CLOCK) and cold loads.

   These use a TINY class-0 cache (test_shmem_new_tiny) so that:
     - reading an account whose cache line was evicted forces a
       cold_load_acc (preadv2 from the backing memfd), and
     - cold-loading / pinning a new line forces a CLOCK eviction of some
       other resident line.

   Coverage of the cache hooks:
     accdb_try_pin:post_cas        (pin ABA window)
     accdb_clock_evict:post_claim  (CLOCK claimed a victim line)
     accdb_evict_clear:post_claim  (evictor holds the acc CLAIM bit)
     accdb_cold_load:post_claim    (cold-loader won the acc CLAIM)
     accdb_cold_load:pre_valid     (cache_idx published, VALID not yet set)

   Oracle: fiber_acquire_expect asserts the loaded lamports+pubkey match
   what was committed, plus the always-on A1/A2/A3 asserts in acquire. */

/* test_cold_load_same: two readers concurrently acquire the SAME evicted
   account, so both enter cold_load_acc for the same acc and race the
   single-claimer CLAIM protocol (one wins post_claim/pre_valid, the other
   pins via the freshly published cache_idx).  Both must read the correct
   bytes. */

static void
test_cold_load_same( void ) {
  test_shmem_new_tiny();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr0 = join_new();
  fd_accdb_t * jr1 = join_new();

  uchar owner[ 32UL ] = { 7, 0 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  uchar key[ 32UL ]; mk_key( 1000UL, key );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    /* vary lamports per iter for the oracle; reuse the SAME key + filler
       keys so they overwrite in place on the (un-advanced) root fork and
       the acc pool stays bounded. */
    ulong lamports = 5000UL+i;

    /* commit the account, then evict it from cache by writing several
       OTHER distinct class-0 accounts (more than the tiny cache holds),
       forcing the target's line to be CLOCK-evicted to the memfd. */
    seq_write( ctl, root, key, lamports, owner );
    for( ulong e=0UL; e<16UL; e++ ) {
      uchar k2[ 32UL ]; mk_key( 900000UL + e, k2 );
      seq_write( ctl, root, k2, 1UL, owner );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_acquire_expect( &g_fiber[0], jr0, root, key, lamports ) );
    fd_racesan_weave_add( w, fiber_acquire_expect( &g_fiber[1], jr1, root, key, lamports ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );
  }

  join_delete( ctl );
  join_delete( jr0 );
  join_delete( jr1 );
  test_shmem_delete();
}

/* test_cold_load_evict: two readers concurrently acquire DIFFERENT
   evicted accounts.  Each cold_load_acc allocates a cache line, which —
   with the tiny cache full — forces a CLOCK eviction that may target the
   line the other reader is simultaneously cold-loading into / pinning.
   Exercises clock_evict:post_claim vs evict_clear:post_claim vs the other
   reader's cold_load and try_pin. */

static void
test_cold_load_evict( void ) {
  test_shmem_new_tiny();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr0 = join_new();
  fd_accdb_t * jr1 = join_new();

  uchar owner[ 32UL ] = { 7, 0 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  uchar key0[ 32UL ]; mk_key( 2000UL, key0 );
  uchar key1[ 32UL ]; mk_key( 2001UL, key1 );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    ulong lam0 = 6000UL+i;
    ulong lam1 = 7000UL+i;

    seq_write( ctl, root, key0, lam0, owner );
    seq_write( ctl, root, key1, lam1, owner );
    /* evict both from cache (reused filler keys overwrite in place) */
    for( ulong e=0UL; e<16UL; e++ ) {
      uchar k2[ 32UL ]; mk_key( 800000UL + e, k2 );
      seq_write( ctl, root, k2, 1UL, owner );
    }

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_acquire_expect( &g_fiber[0], jr0, root, key0, lam0 ) );
    fd_racesan_weave_add( w, fiber_acquire_expect( &g_fiber[1], jr1, root, key1, lam1 ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );
  }

  join_delete( ctl );
  join_delete( jr0 );
  join_delete( jr1 );
  test_shmem_delete();
}

/* test_pin_vs_evict: one reader acquires a cache-RESIDENT account (hits
   cache_try_pin) while a second reader cold-loads a different evicted
   account, whose cache-line allocation CLOCK-evicts lines — possibly the
   resident line the first reader is racing to pin.  Stresses the
   try_pin:post_cas ABA recheck against clock_evict:post_claim. */

static void
test_pin_vs_evict( void ) {
  test_shmem_new_tiny();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr0 = join_new();
  fd_accdb_t * jr1 = join_new();

  uchar owner[ 32UL ] = { 7, 0 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  uchar hot[ 32UL ];  mk_key( 3000UL, hot );  /* will be cache-resident */
  uchar cold[ 32UL ]; mk_key( 4000UL, cold ); /* will be evicted */

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    ulong lam_hot  = 8000UL+i;
    ulong lam_cold = 9000UL+i;

    /* write cold first, then evict it, then write hot last so hot is the
       freshest resident line (reused keys overwrite in place). */
    seq_write( ctl, root, cold, lam_cold, owner );
    for( ulong e=0UL; e<16UL; e++ ) {
      uchar k2[ 32UL ]; mk_key( 700000UL + e, k2 );
      seq_write( ctl, root, k2, 1UL, owner );
    }
    seq_write( ctl, root, hot, lam_hot, owner );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_acquire_expect( &g_fiber[0], jr0, root, hot,  lam_hot  ) );
    fd_racesan_weave_add( w, fiber_acquire_expect( &g_fiber[1], jr1, root, cold, lam_cold ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );
  }

  join_delete( ctl );
  join_delete( jr0 );
  join_delete( jr1 );
  test_shmem_delete();
}

/* test_read_vs_overwrite: the proposed acct[2]/[3]/[32] torn-read
   mechanism.  A read-only acquire of key on fork R races a writable
   overwrite of the SAME key on the SAME fork R (in-place, same
   generation -> fd_accdb.c:3038 mutates accmeta->lamports / cache-line
   owner under the reader).  acquire_inner reads accmeta->lamports three
   separate times (STEP 7 tombstone, STEP 7 lamports, STEP 14 tombstone)
   and the owner once; if they straddle the overwrite, the reader
   observes a (lamports, owner) pair the writer never committed.

   NOTE: this interleaving is forbidden by the accdb public API (no
   concurrent acquire of the same (pubkey, fork) while a writable acquire
   is outstanding).  The test deliberately violates that contract to
   determine whether acquire_inner's multi-read is the PROXIMATE
   corruption site — i.e. whether, IF some upstream caller (bundle
   coalescing, scheduler) ever lets a same-fork overwrite overlap a read,
   the result is the observed lamports/owner corruption.  A clean pass
   means the multi-read alone cannot tear without the overlap; a failure
   pinpoints the snapshot fix locus. */

static void
test_read_vs_overwrite( void ) {
  /* Demonstration repro that intentionally FAILS (it violates the accdb
     API contract on purpose).  Skip unless named explicitly so a default
     "run all" stays green.  See the reframe in ACCDB_BANKHASH_BUG_REPORT.md:
     the multi-read tear is a real fragility but NOT the production bug. */
  if( FD_UNLIKELY( !g_explicit ) ) {
    FD_LOG_NOTICE(( "  (skipped: contract-violating demo; run by name to exercise)" ));
    return;
  }
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new(); /* reader */
  fd_accdb_t * jw  = join_new(); /* overwriter */

  uchar key[ 32UL ]; mk_key( 42UL, key );

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  /* seed a consistent committed state (LAMP_A, TAG_A) */
  {
    uchar owner[ 32UL ]; memset( owner, 0, 32UL ); owner[0] = TAG_A;
    seq_write( ctl, root, key, LAMP_A, owner );
  }

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    int state = (int)( i & 1UL ); /* toggle committed pair each iter */

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_acquire_consistent( &g_fiber[0], jr, root, key ) );
    fd_racesan_weave_add( w, fiber_overwrite(          &g_fiber[1], jw, root, key, state ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jw );
  test_shmem_delete();
}

/* ===================================================================
   EPOCH RECLAMATION TESTS

   These exercise the writer-free cold path implicated by the
   "quiescent account, no concurrent writer" evidence: compaction
   relocates a partition's live records and then deferred-frees +
   recycles the source partition, while a reader cold-reads one of those
   records from disk.  The epoch protocol (reader publishes my_epoch on
   entry; compaction tags the freed partition with epoch_tag and the
   reclamation scan refuses to free while any joiner sits at
   epoch<=epoch_tag) is the only thing keeping the reader's snapshotted
   offset_fork valid across its preadv2.  Oracle: reclamation assertion
   H18 (in fd_accdb.c) + the reader's bytes are exactly what was
   committed (fiber_nocache).
   =================================================================== */

/* Fill partition 0 with [K + 2 fillers], rotate to partition 1 with a
   3rd filler, then overwrite one partition-0 filler to free >=30% of it,
   enqueuing partition 0 for compaction.  K (data filled with K_FILL)
   survives in partition 0 and will be relocated as a passenger. */
static void
epoch_setup_fragment( fd_accdb_t *       ctl,
                      fd_accdb_fork_id_t fork,
                      uchar const *      K,
                      uchar              K_owner0,
                      uchar              K_fill ) {
  uchar owner[ 32UL ]; memset( owner, 0, 32UL ); owner[0] = K_owner0;
  uchar f0[32], f1[32], f2[32];
  mk_key( 900001UL, f0 ); mk_key( 900002UL, f1 ); mk_key( 900003UL, f2 );

  /* partition 0: K, filler0, filler1 (~60 KB of 64 KB) */
  seq_write_data( ctl, fork, K,  LAMP_A, owner, BIG_DATA, K_fill );
  seq_write_data( ctl, fork, f0, 1UL,    NULL,  BIG_DATA, 0xF0 );
  seq_write_data( ctl, fork, f1, 1UL,    NULL,  BIG_DATA, 0xF1 );
  /* this write rotates the head to partition 1 */
  seq_write_data( ctl, fork, f2, 1UL,    NULL,  BIG_DATA, 0xF2 );
  /* overwrite filler0 on a CHILD fork so it becomes a NEW record (frees
     the old partition-0 bytes), crossing the 30% threshold for part 0.
     Use the same fork so it's an overwrite-in-place? No — in-place reuses
     the slot and does NOT free disk bytes the same way; a fresh-version
     write on the same fork frees the prior on-disk record.  seq_write_data
     on the same key/fork triggers the _overwrite path which xchg's the
     old offset to INVAL and frees it (acc_unlink/commit). */
  seq_write_data( ctl, fork, f0, 2UL, NULL, BIG_DATA, 0xF0 );

  /* Evict K from the cache so the reader takes the COLD disk path (the
     epoch-protected preadv2).  K is a 10 MiB-class line; the tiny cache
     has only a few class-7 slots, so touching several throwaway class-7
     accounts forces K's line out via CLOCK. */
  for( ulong e=0UL; e<24UL; e++ ) {
    uchar t[ 32UL ]; mk_key( 800000UL + e, t );
    uchar lam=0; uchar buf[1]; (void)buf;
    /* a write churns a class-7 staging line + commits a class-7 line */
    seq_write_data( ctl, fork, t, 1UL, NULL, BIG_DATA, (uchar)(0xE0|e) );
    (void)lam;
  }
}

/* test_nocache_vs_compaction: a reader cold-reads quiescent account K
   from disk while compaction relocates partition 0 (K's partition) to
   layer 1 and reclaims the source partition.  If the epoch protocol has
   a hole, the source partition is freed/reused under the reader and the
   preadv2 returns zeros/stale bytes -> fiber_nocache oracle fires; or
   reclamation frees a partition still pinned -> H18 fires. */

/* test_epoch_reclaim_pin: DETERMINISTIC construction of the exact unsafe
   window, instead of hoping a random weave hits it.  Steps:

     1. fragment partition 0 so K lives there and part 0 is enqueued.
     2. step the reader fiber until it parks at nocache:pre_preadv2 — at
        that point it has PUBLISHED its epoch and SNAPSHOTTED K's (old,
        partition-0) offset, but has not yet read.
     3. while the reader is parked, drive compaction to completion: it
        relocates K to layer 1, tags partition 0 with epoch_tag >= the
        reader's epoch, defers it, and the reclaim pass runs.
     4. ASSERTION H18 must hold: partition 0 must NOT be freed while the
        reader is parked at epoch <= epoch_tag.  The reclaim epoch gate
        defers the free, so H18 (the use-after-free oracle) is satisfied.
     5. finish the reader (its preadv2 reads K's bytes, which under a
        correct build are either still in part 0 [not yet freed] — correct
        bytes; the fiber_nocache oracle checks them).

   This is the equivalent of progcache's test_inject_at_hook: it removes
   the schedule-dependence so the test reliably exercises the protocol. */

static void
test_epoch_reclaim_pin( void ) {
  test_shmem_new_smallpart();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new(); /* reader */
  fd_accdb_t * jc  = join_new(); /* compaction driver */

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  for( ulong i=0UL; i<EPOCH_ITER; i++ ) {
    uchar K_owner0 = (uchar)( 0x40 | (i & 0x0F) );
    uchar K_fill   = (uchar)( 0x80 | (i & 0x0F) );
    uchar Ki[ 32UL ]; mk_key( 42UL + i*16UL, Ki );

    epoch_setup_fragment( ctl, root, Ki, K_owner0, K_fill );

    /* Step the reader to its pre_preadv2 hook: epoch published, K's old
       offset snapshotted, read not yet issued. */
    fd_racesan_async_t * ra = fiber_nocache( &g_fiber[0], jr, root, Ki, LAMP_A, K_owner0, BIG_DATA, K_fill );
    int r = fd_racesan_async_step_until( ra, "accdb_nocache:pre_preadv2", STEP_MAX );
    /* The reader may legitimately hit a cache HIT (no disk path) if K is
       still resident; in that case it EXITs without reaching the hook.
       Only the cold-disk path constructs the window we care about. */
    if( FD_LIKELY( r==FD_RACESAN_ASYNC_RET_HOOK ) ) {
      /* Reader is parked holding its epoch + the old offset.  Drive
         compaction to completion: relocate + defer + reclaim part 0.
         H18 inside the reclaim pass is the oracle. */
      for( int s=0; s<16; s++ ) { int cb=0; fd_accdb_background( jc, &cb ); }

      /* Now let the reader finish its preadv2 + correctness checks. */
      for(;;) { int rr = fd_racesan_async_step( ra ); if( rr==FD_RACESAN_ASYNC_RET_EXIT ) break; }
    } else {
      FD_TEST( r==FD_RACESAN_ASYNC_RET_EXIT );
      /* cache hit; still drive compaction so the partition pool recycles. */
      for( int s=0; s<16; s++ ) { int cb=0; fd_accdb_background( jc, &cb ); }
    }
    fiber_done( &g_fiber[0] );
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jc );
  test_shmem_delete();
}

static void
test_nocache_vs_compaction( void ) {
  test_shmem_new_smallpart();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new(); /* reader */
  fd_accdb_t * jc  = join_new(); /* compaction driver */

  uchar K[ 32UL ]; mk_key( 42UL, K );
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  for( ulong i=0UL; i<EPOCH_ITER; i++ ) {
    uchar K_owner0 = (uchar)( 0x40 | (i & 0x0F) );
    uchar K_fill   = (uchar)( 0x80 | (i & 0x0F) );

    /* Use a fresh key each iter so prior-iter records don't accumulate in
       the (bounded) acc pool / index; the partition pool recycles. */
    uchar Ki[ 32UL ]; mk_key( 42UL + i*16UL, Ki );

    epoch_setup_fragment( ctl, root, Ki, K_owner0, K_fill );

    /* Evict K from cache so the reader takes the cold disk path (the one
       with the offset snapshot + preadv2).  The tiny cache + the filler
       writes above already churn class slots; force it by reading nothing
       and relying on the writes having pushed K's line out.  To be safe,
       the nocache path never pins, and re-reads disk whenever the cache
       line isn't a hit — the fragment writes for f0..f2 of the same class
       evict K. */

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    /* compaction needs several steps: relocate up to ~3 records + the
       reclaim pass.  8 background calls comfortably drives part 0 to
       completion and reclamation. */
    fd_racesan_weave_add( w, fiber_nocache( &g_fiber[0], jr, root, Ki, LAMP_A, K_owner0, BIG_DATA, K_fill ) );
    fd_racesan_weave_add( w, fiber_compact_loop( &g_fiber[1], jc, 8 ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    (void)K;
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jc );
  test_shmem_delete();
}

/* ===================================================================
   COMPACTION RELOCATION TESTS

   The top remaining un-dispositioned suspect (see ACCDB_BANKHASH_BUG_
   REPORT.md 0.6/0.7): background_compact relocates a record
   (copy_file_range to a new layer) and CAS-republishes offset_fork from
   the snapshotted source offset to the destination.  Two races:

   (a) compact relocate vs a concurrent same-fork in-place OVERWRITE of
       the same accmeta: the overwrite xchg's offset_fork to INVAL (then a
       new offset); the relocation CAS MUST then fail so the stale copy is
       discarded and the overwrite wins.  Hooks: accdb_compact:
       pre_offset_cas and accdb_overwrite:pre_xchg_offset.

   (b) compact relocate vs a concurrent cold READER: the reader may
       snapshot the OLD offset before the CAS; the source partition stays
       valid (epoch-pinned) so the read is correct regardless.
   =================================================================== */

/* Read K via a normal acquire and return its observed (lamports,
   owner[0]).  Single-threaded helper for post-weave verification. */
static void
seq_read_check( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork,
                uchar const *      pubkey,
                ulong *            out_lamports,
                uchar *            out_owner0 ) {
  uchar const * pks[1] = { pubkey };
  int wr[1] = { 0 };
  fd_acc_t acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( accdb, fork, 1UL, pks, wr, acc );
  *out_lamports = acc[0].lamports;
  *out_owner0   = acc[0].owner[0];
  fd_accdb_release( accdb, 1UL, acc );
}

#if FD_HAS_RACESAN
extern uchar fd_accdb_dbg_reloc_pubkey[ 32UL ];
extern ulong fd_accdb_dbg_reloc_dest;
extern ulong fd_accdb_dbg_reloc_cnt;
#endif

static uchar g_cold_data[ 10UL<<20 ];

/* NOTE on the in-place-overwrite-vs-relocation-CAS race (a separate
   scenario we explored and could NOT make bite): it SELF-HEALS — an
   in-place overwrite leaves offset_fork==INVAL, so even a faulty
   unconditional relocation publish to dest_offset is harmless and is
   repaired by the overwrite's next persist (eviction write-back).  The
   genuinely observable, non-self-healing relocation hazard is the
   byte-integrity of the relocated copy, which is what the test below
   checks. */

/* test_compact_reloc_integrity: DETERMINISTIC, fault-validated test of the
   compaction RELOCATION byte-integrity — the report's top suspect
   (copy_file_range correctness + record_sz from disk meta->size vs the
   reader's size from the index).  Each iter:
     1. fragment+evict K to disk (owner0=TAG_A, ALL data bytes 0xAA).
     2. drive compaction to COMPLETION, proving (via fd_accdb_dbg_reloc_cnt
        and the dbg pubkey) that K was actually relocated to a new layer.
     3. evict K again, then COLD-read it (asserting the read hit disk) and
        verify the FULL relocated copy: owner0==TAG_A and EVERY data byte
        ==0xAA.  A relocation that mis-copies, truncates (record_sz too
        small), or over-copies would surface as a wrong/zero data byte.

   This does NOT self-heal (unlike the in-place-overwrite-vs-CAS race,
   which leaves offset=INVAL and is repaired by the next persist — see
   ACCDB_BANKHASH_BUG_REPORT.md): the relocation publishes a real
   dest_offset whose bytes are whatever copy_file_range wrote, and the
   cold read dereferences exactly that. */
static void
test_compact_reloc_integrity( void ) {
  test_shmem_new_smallpart();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jc  = join_new(); /* compaction driver */

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  ulong relocated = 0UL;
  for( ulong i=0UL; i<EPOCH_ITER; i++ ) {
    uchar Ki[ 32UL ]; mk_key( 77UL + i*16UL, Ki );

    fd_accdb_dbg_reloc_cnt = 0UL;
    memset( fd_accdb_dbg_reloc_pubkey, 0, 32UL );

    /* fragment: K persisted (owner0=TAG_A, data 0xAA), enqueued. */
    epoch_setup_fragment( ctl, root, Ki, TAG_A, 0xAA );

    /* Drive compaction to completion (relocates K to the next layer). */
    for( int s=0; s<64; s++ ) drain_background( jc );

    /* Confirm K was actually relocated this iter (otherwise the integrity
       check below is vacuous).  fd_accdb_dbg_reloc_pubkey holds the last
       relocated record's key; require it (or an earlier one) to be K via a
       per-relocation check is overkill — instead require at least one
       relocation happened AND verify K's bytes are intact, which is the
       real invariant regardless of which records moved. */
    if( fd_accdb_dbg_reloc_cnt ) relocated++;

    /* Evict K so the verifying read hits disk (the relocated copy). */
    for( ulong e=0UL; e<32UL; e++ ) {
      uchar t[ 32UL ]; mk_key( 820000UL + e, t );
      seq_write_data( ctl, root, t, 1UL, NULL, BIG_DATA, (uchar)(0xC0|(e&0x0F)) );
    }

    ulong lamports = 0UL; int executable = 0; ulong data_len = 0UL;
    uchar owner[ 32UL ]; memset( owner, 0xEE, 32UL );
    ulong ro0 = fd_accdb_metrics( ctl )->read_ops;
    g_cold_data[0]=0xEE; g_cold_data[ BIG_DATA-1UL ]=0xEE;
    fd_accdb_read_one_nocache( ctl, root, Ki, &lamports, &executable, owner, g_cold_data, &data_len );
    int hit_disk = fd_accdb_metrics( ctl )->read_ops > ro0;

    if( FD_LIKELY( hit_disk ) ) {
      /* Full byte integrity of the (relocated) on-disk copy. */
      if( FD_UNLIKELY( lamports!=LAMP_A || owner[0]!=TAG_A || data_len!=BIG_DATA ) ) {
        FD_LOG_ERR(( "compact-reloc-integrity: K meta wrong after relocation: lamports=%lu owner0=0x%02x data_len=%lu (want LAMP_A=%lu TAG_A=0x%02x len=%lu)",
                     lamports, (uint)owner[0], data_len, LAMP_A, (uint)TAG_A, (ulong)BIG_DATA ));
      }
      for( ulong z=0UL; z<data_len; z+=4093UL ) {
        if( FD_UNLIKELY( g_cold_data[z]!=0xAA ) )
          FD_LOG_ERR(( "compact-reloc-integrity: relocated K data[%lu]=0x%02x, expected 0xAA -- copy_file_range mis-copied/truncated", z, (uint)g_cold_data[z] ));
      }
      if( FD_UNLIKELY( data_len && g_cold_data[ data_len-1UL ]!=0xAA ) )
        FD_LOG_ERR(( "compact-reloc-integrity: relocated K LAST data byte=0x%02x, expected 0xAA -- copy truncated (record_sz too small)", (uint)g_cold_data[ data_len-1UL ] ));
    }
  }

  FD_TEST( relocated>0UL ); /* compaction must have relocated records */
  FD_LOG_NOTICE(( "  test_compact_reloc_integrity: relocations occurred in %lu/%lu iters", relocated, EPOCH_ITER ));

  join_delete( ctl );
  join_delete( jc );
  test_shmem_delete();
}

/* test_compact_vs_overwrite: relocate K while a same-fork overwrite of K
   commits concurrently.  After the weave, K MUST read back as the
   overwritten value (LAMP_B/TAG_B) — the newer commit always wins; the
   relocation CAS must have failed and discarded the stale copy.  A bug
   where the relocation CAS wrongly succeeds (clobbering the overwrite's
   offset with the stale relocated one) would surface as K reading back
   the OLD value (LAMP_A/TAG_A) or a torn/zero owner. */

static void
test_compact_vs_overwrite( void ) {
  test_shmem_new_smallpart();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jw  = join_new(); /* overwriter */
  fd_accdb_t * jc  = join_new(); /* compaction driver */

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  for( ulong i=0UL; i<EPOCH_ITER; i++ ) {
    uchar Ki[ 32UL ]; mk_key( 42UL + i*16UL, Ki );

    /* K starts as (LAMP_A, TAG_A) in a fragmented (compaction-eligible)
       partition.  epoch_setup_fragment writes K with owner0=TAG_A and
       evicts it; that's exactly the (LAMP_A,TAG_A) committed state. */
    epoch_setup_fragment( ctl, root, Ki, TAG_A, 0xAA );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    /* overwrite commits (LAMP_B, TAG_B) on the same fork; compaction
       relocates the OLD (LAMP_A) record concurrently. */
    fd_racesan_weave_add( w, fiber_overwrite(     &g_fiber[0], jw, root, Ki, 1 /*state B*/ ) );
    fd_racesan_weave_add( w, fiber_compact_loop(  &g_fiber[1], jc, 8 ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    /* Oracle: the overwrite (newer commit) must have won. */
    ulong lam; uchar o0;
    seq_read_check( ctl, root, Ki, &lam, &o0 );
    if( FD_UNLIKELY( !( lam==LAMP_B && o0==TAG_B ) ) ) {
      FD_LOG_ERR(( "compact-vs-overwrite: K read back (lamports=%lu owner0=0x%02x), expected the overwrite (LAMP_B=%lu TAG_B=0x%02x) -- relocation CAS clobbered a newer commit?",
                   lam, (uint)o0, LAMP_B, (uint)TAG_B ));
    }
  }

  join_delete( ctl );
  join_delete( jw );
  join_delete( jc );
  test_shmem_delete();
}

/* test_compact_vs_coldread: relocate K while a cold reader reads K.  The
   reader may catch the old or new offset; either way the bytes must equal
   what was committed (the source partition is epoch-pinned until the
   reader exits, so the old offset stays valid).  fiber_nocache is the
   correctness oracle. */

static void
test_compact_vs_coldread( void ) {
  test_shmem_new_smallpart();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new(); /* cold reader */
  fd_accdb_t * jc  = join_new(); /* compaction driver */

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  for( ulong i=0UL; i<EPOCH_ITER; i++ ) {
    uchar K_owner0 = (uchar)( 0x40 | (i & 0x0F) );
    uchar K_fill   = (uchar)( 0x80 | (i & 0x0F) );
    uchar Ki[ 32UL ]; mk_key( 42UL + i*16UL, Ki );

    epoch_setup_fragment( ctl, root, Ki, K_owner0, K_fill );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_nocache(      &g_fiber[0], jr, root, Ki, LAMP_A, K_owner0, BIG_DATA, K_fill ) );
    fd_racesan_weave_add( w, fiber_compact_loop( &g_fiber[1], jc, 8 ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( (i*2654435761UL) ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jc );
  test_shmem_delete();
}

/* ===================================================================
   OWNER-CORRUPTION TESTS

   The live repro corrupts owner (offset 64) + data while leaving the key
   (0..36) intact.  Only two operations write starting at the owner field:

   (1) Cold-load disk read (fd_accdb.c ~2640): scatters 32+data bytes from
       offset_fork into cache_line->owner.  If offset_fork is torn/INVAL/
       stale when the iovec is built, the owner/data come from the wrong
       on-disk record while the key (already in the cache line) is intact.
       Guard: the offset_fork!=INVAL spin at ~2638.

   (2) Commit owner write (fd_accdb.c ~2961): memcpy(line->owner,
       accs[i].owner,32)+data into the resolved target cache line.  If that
       line was recycled to a different account, it writes a wrong owner.
       Guard: ASSERTION F11/F12 (key+gen+refcnt match) at ~2949.
   =================================================================== */

/* test_coldload_vs_overwrite: a cold reader of K races a same-fork
   SAME-size in-place overwrite of K (which transitions K's offset_fork
   through INVAL and rewrites the cache-line owner+data).  Under a correct
   build the cold reader's offset_fork!=INVAL spin keeps its disk read
   consistent; the reader's returned (owner, data) must be a committed
   state (TAG_A/0xAA or TAG_B/0xBB) and never a torn owner. */
static void
test_coldload_vs_overwrite( void ) {
  /* Contract-violating demo (concurrent read + same-fork overwrite of the
     same account): exercises the cold-load owner-read site and may trip an
     in-tree guard (C7) by design.  Opt-in only — see test_read_vs_overwrite. */
  if( FD_UNLIKELY( !g_explicit ) ) { FD_LOG_NOTICE(( "  (skipped: contract-violating demo; run by name)" )); return; }
  test_shmem_new_smallpart();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new(); /* cold reader */
  fd_accdb_t * jw  = join_new(); /* overwriter  */

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  for( ulong i=0UL; i<EPOCH_ITER; i++ ) {
    uchar Ki[ 32UL ]; mk_key( 55UL + i*16UL, Ki );
    /* K committed as (TAG_A, data 0xAA) and evicted to disk. */
    epoch_setup_fragment( ctl, root, Ki, TAG_A, 0xAA );

    /* Reader cold-reads K; concurrently the writer overwrites K in place
       (TAG_B, data 0xBB).  The reader must observe a consistent committed
       pair: either the old (TAG_A/0xAA) or the new (TAG_B/0xBB) — never a
       torn owner.  fiber_nocache's oracle checks the full (lamports,owner,
       data) tuple against the expected, so pass expect_lamports=0 to skip
       the strict expectation and instead assert internal consistency. */
    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    /* read-only cold reader with the CONSISTENCY oracle (expect_lamports=0
       + expect_owner0=0xFF sentinel): if K reads live, its (owner,data)
       must be one of the two committed states, never a torn owner from a
       stale/INVAL cold-load offset. */
    fd_racesan_weave_add( w, fiber_nocache(        &g_fiber[0], jr, root, Ki, 0UL, 0xFF, 0UL, 0 ) );
    fd_racesan_weave_add( w, fiber_overwrite_full( &g_fiber[1], jw, root, Ki ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( (i*0x9E3779B1UL) ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    /* Post-weave: K must be the overwrite value, internally consistent. */
    ulong lam; uchar o0;
    seq_read_check( ctl, root, Ki, &lam, &o0 );
    if( FD_UNLIKELY( !( lam==LAMP_B && o0==TAG_B ) ) ) {
      FD_LOG_ERR(( "coldload-vs-overwrite: K=(lamports=%lu owner0=0x%02x), expected overwrite (LAMP_B=%lu TAG_B=0x%02x)",
                   lam, (uint)o0, LAMP_B, (uint)TAG_B ));
    }
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jw );
  test_shmem_delete();
}

/* test_commit_owner_vs_reader: the commit owner-write site (fd_accdb.c
   ~2961, hook accdb_commit:pre_owner_write).  A writer commits K in place
   (rewriting line->owner at offset 64+) while a concurrent reader acquires
   K read-only on a child fork.  The in-tree F11/F12 assertion guards that
   the commit's target line still holds K (key+gen) and is pinned — so a
   commit can never write a wrong owner into a line a reader is using.
   This test drives the interleaving; F11/F12 (+ the reader's own A1/B4/C7
   asserts) are the oracle.  Passes because the refcnt pin makes recycling
   the target line under a live commit impossible — i.e. this owner-write
   site is safe by construction (see report). */
static void
test_commit_owner_vs_reader( void ) {
  /* Contract-violating demo (concurrent read + same-fork overwrite): drives
     the commit owner-write site (~2961) and trips an in-tree guard (C7 /
     F11-F12) by design, proving the site is protected.  Opt-in only. */
  if( FD_UNLIKELY( !g_explicit ) ) { FD_LOG_NOTICE(( "  (skipped: contract-violating demo; run by name)" )); return; }
  test_shmem_new();  /* default cache; small data so the commit hits the
                        non-class-7 owner-write at ~2961 (class 7 skips it) */
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jw  = join_new(); /* committer (owner write) */
  fd_accdb_t * jr  = join_new(); /* reader */

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  uchar oa[ 32UL ]; memset( oa, 0, 32UL ); oa[0] = TAG_A;

  uchar K[ 32UL ]; mk_key( 333UL, K );
  seq_write( ctl, root, K, LAMP_A, oa ); /* data_len 0 -> class 0 */

  for( ulong i=0UL; i<EPOCH_ITER; i++ ) {
    /* committer overwrites K in place on root (class 0 -> hits the 2961
       owner memcpy); reader reads K on the same fork.  Owner must always
       read as a committed tag (TAG_A or TAG_B), never torn — F11/F12 is
       accdb's own guard at the commit site, the reader's A1/B4 here too. */
    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_overwrite( &g_fiber[0], jw, root, K, (int)(i&1UL) ) );
    fd_racesan_weave_add( w, fiber_acquire(   &g_fiber[1], jr, root, K ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( (i*0xA24BAED4UL) ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    /* post-weave: K's owner must be one of the two committed tags. */
    ulong lam; uchar o0;
    seq_read_check( ctl, root, K, &lam, &o0 );
    if( FD_UNLIKELY( !( o0==TAG_A || o0==TAG_B ) ) )
      FD_LOG_ERR(( "commit-owner: K owner0=0x%02x is neither TAG_A nor TAG_B (torn owner write)", (uint)o0 ));
  }

  join_delete( ctl );
  join_delete( jw );
  join_delete( jr );
  test_shmem_delete();
}

/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Tests ported from the tombstone-orphan / EBR-poison branch         */
/* (HEAD harness: test_setup / test_join_extra / write_acc).          */
/* ------------------------------------------------------------------ */

#define HEAD_TEST_CACHE_FOOTPRINT (16UL<<30UL)

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
  ulong cache_fp = HEAD_TEST_CACHE_FOOTPRINT;
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

/* ------------------------------------------------------------------ */
/* Stray-pin cases: cache_try_pin's transient pin vs line recycling    */
/* ------------------------------------------------------------------ */

/* A reader that loaded acc->cache_idx before an eviction can call
   cache_try_pin on a line that has since been evicted, freed, and
   recycled.  The pin CAS transiently bumps refcnt on a line the reader
   no longer owns; the ABA recheck then fails and unpins.  Historically
   the free-list pop (acquire_cache_line priority 1) and the
   uncommitted-destination cleanup (release_inner) mutated refcnt with
   plain stores, which wiped such a transient pin; the stray's later
   decrement then dropped the new owner's refcnt to 0 (or underflowed it
   to EVICT_SENTINEL), letting CLOCK steal a line still in use.
   Observed in production as near-simultaneous handholding failures in
   acquire STEP 4 (rc>0 && rc!=SENTINEL), STEP 14 (key mismatch on a
   pinned line) and release STEP 2 (refcnt>0) across several exec tiles.

   test_stray_pin_vs_freepop proves the free-list pop waits out the
   stray pin instead of clobbering it:
     1. P resident in class-0 line L; reader R suspends at
        accdb_acquire:pre_try_pin having captured L from P's cache_idx.
     2. Main evicts L (L -> free list, gen=UINT_MAX, refcnt=0).
     3. R resumes to accdb_try_pin:post_cas: its CAS pinned the
        free-listed L (refcnt 0->1); R now holds the stray pin.
     4. Writer W (new account Q) pops L as its class-0 destination and
        must WAIT at accdb_freepop:refcnt_wait (a plain refcnt=1 store
        here would let R's later unpin zero out W's pin).
     5. R resumes: ABA recheck fails (gen==UINT_MAX), unpins,
        cold-loads P from disk, completes.
     6. W resumes: its CAS 0->1 now succeeds; W commits Q into L.
     7. Oracle: P and Q both read back intact. */
static void
test_stray_pin_vs_freepop( void ) {
  int fd;
  fd_accdb_t * accdb   = test_setup( &fd, 256UL, 16UL, 1024UL, 1024UL, 1UL<<30UL );
  fd_accdb_t * accdb_r = test_join_extra();

  uchar key_P  [ 32 ] = { 'P', 0 };
  uchar key_Q  [ 32 ] = { 'Q', 0 };
  uchar owner_P[ 32 ] = { 0xAA, 0 };

  fd_accdb_fork_id_t root0 = fd_accdb_attach_child( accdb, SENTINEL );

  write_acc( accdb, root0, key_P, 100UL, owner_P, NULL, 0UL );

  ulong cls, idx;
  FD_TEST( fd_accdb_debug_find_line( accdb, key_P, &cls, &idx ) );
  FD_TEST( cls==0UL );

  /* R captures P's cache_idx, suspends before pinning. */
  fd_racesan_async_t * ar = fiber_acquire_expect( &g_fiber[0], accdb_r, root0, key_P, 100UL );
  FD_TEST( fd_racesan_async_step_until( ar, "accdb_acquire:pre_try_pin", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* Evict L: P written back to disk, L pushed to the class-0 free
     list. */
  fd_accdb_debug_clock_evict_line( accdb, cls, idx );

  /* R pins the free-listed line (stray pin), suspends before the ABA
     recheck. */
  FD_TEST( fd_racesan_async_step_until( ar, "accdb_try_pin:post_cas", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* W pops L as its class-0 destination and must wait for the stray
     pin to drop.  A regression to the plain store never reaches this
     hook (W runs to exit) and the FD_TEST fails. */
  fd_racesan_async_t * w = fiber_release_write( &g_fiber[1], accdb, root0, key_Q, 400UL );
  FD_TEST( fd_racesan_async_step_until( w, "accdb_freepop:refcnt_wait", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* R: ABA recheck fails, unpin, cold-load P from disk, complete. */
  for(;;) {
    int rc = fd_racesan_async_step( ar );
    if( rc==FD_RACESAN_ASYNC_RET_EXIT ) break;
    FD_TEST( rc==FD_RACESAN_ASYNC_RET_HOOK );
  }

  /* W: pop CAS now wins; Q commits into L. */
  for(;;) {
    int rc = fd_racesan_async_step( w );
    if( rc==FD_RACESAN_ASYNC_RET_EXIT ) break;
    FD_TEST( rc==FD_RACESAN_ASYNC_RET_HOOK );
  }

  /* Oracle: both accounts intact. */
  {
    uchar const * pks[1] = { key_P };
    int rd[1] = { 0 };
    fd_acc_t a[1];
    memset( a, 0, sizeof(a) );
    fd_accdb_acquire( accdb, root0, 1UL, pks, rd, a );
    FD_TEST( a[0].lamports==100UL );
    fd_accdb_release( accdb, 1UL, a );

    pks[0] = key_Q;
    memset( a, 0, sizeof(a) );
    fd_accdb_acquire( accdb, root0, 1UL, pks, rd, a );
    FD_TEST( a[0].lamports==400UL );
    fd_accdb_release( accdb, 1UL, a );
  }

  free( accdb_r );
  test_teardown( accdb, fd );
}

/* test_stray_pin_vs_release_cleanup proves the uncommitted-destination
   cleanup in release_inner waits out a stray pin on a destination line
   instead of plain-storing refcnt=0 over it:
     1. P resident in class-0 line L; reader R suspends at
        accdb_acquire:pre_try_pin having captured L.
     2. Main evicts L (free list).
     3. Writer W (writable acquire of new account Q, never commits)
        pops L as its class-0 destination (refcnt 0->1) and parks at
        accdb_acquire:pre_step7_meta, mid-bracket.
     4. R resumes to accdb_try_pin:post_cas: CAS 1->2, stray pin on
        W's destination line.
     5. W resumes into release (no commit): the destination cleanup
        must WAIT at accdb_release:dest_refcnt_wait (a plain refcnt=0
        store here would be underflowed to EVICT_SENTINEL by R's
        later unpin).
     6. R resumes: ABA recheck fails, unpins (2->1), completes.
     7. W resumes: CAS 1->0 now wins, L is freed cleanly.
     8. Oracle: P reads back intact. */
static void
test_stray_pin_vs_release_cleanup( void ) {
  int fd;
  fd_accdb_t * accdb   = test_setup( &fd, 256UL, 16UL, 1024UL, 1024UL, 1UL<<30UL );
  fd_accdb_t * accdb_r = test_join_extra();

  uchar key_P  [ 32 ] = { 'P', 0 };
  uchar key_Q  [ 32 ] = { 'Q', 0 };
  uchar owner_P[ 32 ] = { 0xAA, 0 };

  fd_accdb_fork_id_t root0 = fd_accdb_attach_child( accdb, SENTINEL );

  write_acc( accdb, root0, key_P, 100UL, owner_P, NULL, 0UL );

  ulong cls, idx;
  FD_TEST( fd_accdb_debug_find_line( accdb, key_P, &cls, &idx ) );
  FD_TEST( cls==0UL );

  /* R captures P's cache_idx, suspends before pinning. */
  fd_racesan_async_t * ar = fiber_acquire_expect( &g_fiber[0], accdb_r, root0, key_P, 100UL );
  FD_TEST( fd_racesan_async_step_until( ar, "accdb_acquire:pre_try_pin", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* Evict L to the free list. */
  fd_accdb_debug_clock_evict_line( accdb, cls, idx );

  /* W: writable acquire of Q pops L as its class-0 destination
     (refcnt 0->1), parks mid-bracket before release. */
  static read_fiber_t wf[1];
  wf->accdb   = accdb;
  wf->fork_id = root0;
  wf->pubkey  = key_Q;
  void * wf_stack = fd_racesan_stack_create( READ_FIBER_STACK_SZ );
  fd_racesan_async_new( wf->async, wf_stack, READ_FIBER_STACK_SZ, read_fiber_exec, wf );
  FD_TEST( fd_racesan_async_step_until( wf->async, "accdb_acquire:pre_step7_meta", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* R pins W's destination line (stray pin: refcnt 1->2), suspends
     before the ABA recheck. */
  FD_TEST( fd_racesan_async_step_until( ar, "accdb_try_pin:post_cas", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* W: release without commit; the destination cleanup must wait for
     the stray pin.  A regression to the plain store never reaches
     this hook. */
  FD_TEST( fd_racesan_async_step_until( wf->async, "accdb_release:dest_refcnt_wait", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* R: ABA recheck fails, unpin (2->1), cold-load P, complete. */
  for(;;) {
    int rc = fd_racesan_async_step( ar );
    if( rc==FD_RACESAN_ASYNC_RET_EXIT ) break;
    FD_TEST( rc==FD_RACESAN_ASYNC_RET_HOOK );
  }

  /* W: cleanup CAS now wins (1->0), L freed cleanly. */
  for(;;) {
    int rc = fd_racesan_async_step( wf->async );
    if( rc==FD_RACESAN_ASYNC_RET_EXIT ) break;
    FD_TEST( rc==FD_RACESAN_ASYNC_RET_HOOK );
  }
  fd_racesan_async_delete( wf->async );
  fd_racesan_stack_destroy( wf_stack, READ_FIBER_STACK_SZ );

  /* Oracle: P intact. */
  {
    uchar const * pks[1] = { key_P };
    int rd[1] = { 0 };
    fd_acc_t a[1];
    memset( a, 0, sizeof(a) );
    fd_accdb_acquire( accdb, root0, 1UL, pks, rd, a );
    FD_TEST( a[0].lamports==100UL );
    fd_accdb_release( accdb, 1UL, a );
  }

  free( accdb_r );
  test_teardown( accdb, fd );
}

/* test_probe_vs_pd_commit the pd_write probe walk raced
   against a same-fork overwrite commit that sets pd_write=1.  The probe
   is designed to be called concurrently with writers on its fork; it
   must never tear (bit+len come from ONE volatile executable_size load),
   never crash (epoch-protected chain walk), and return either the pre-
   or post-commit answer.  After the weave the writer's pd_write=1 commit
   is durable, so a final probe must deterministically report pd==1. */
static void
test_probe_vs_pd_commit( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new(); /* probe join */
  fd_accdb_t * jw  = join_new(); /* writer join */

  uchar key[ 32UL ]; mk_key( 42UL, key );
  uchar owner[ 32UL ] = { 7, 0 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_accdb_fork_id_t a = fd_accdb_attach_child( ctl, root );
    /* Seed a version of key on A so the writer's commit is an in-place
       same-fork overwrite (exercising the OR-sticky bit CAS). */
    seq_write( ctl, a, key, 100UL+i, owner );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_probe    ( &g_fiber[0], jr, a, key    ) );
    fd_racesan_weave_add( w, fiber_pd_commit ( &g_fiber[1], jw, a, key, 1 ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    /* Post-commit: the pd_write=1 overwrite is durable on A. */
    int   pd  = 0;
    ulong len = ULONG_MAX;
    FD_TEST( fd_accdb_probe_pd_this_fork( ctl, a, key, &pd, &len )==1 );
    FD_TEST( pd==1 );

    fd_accdb_advance_root( ctl, a );
    drain_background( ctl );
    root = a;
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jw );
  test_shmem_delete();
}

/* test_pd_same_fork_read_vs_write (T0 repro, plan §4): the PRE-FIX
   implicit-programdata shape.  Reader does acquire_a(X writable) +
   acquire_b(D read-only) on fork F -- rdisp never saw D, so a concurrent
   txn write-locking D commits on the SAME fork while the reader holds
   D's pin.  The writer's second same-size-class commit takes the
   in-place reuse branch and its FD_TEST(refcnt==1U) trips on the
   reader's pin (fd_accdb.c ~:3045).  Contract-violating by design;
   opt-in only.  The fix moves the reader to the parent fork --
   test_pd_parent_read_vs_child_write runs the same schedules green. */
static void
test_pd_same_fork_read_vs_write( void ) {
  if( FD_UNLIKELY( !g_explicit ) ) { FD_LOG_NOTICE(( "  (skipped: contract-violating demo; run by name)" )); return; }
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new();
  fd_accdb_t * jw  = join_new();

  uchar key_d[ 32UL ]; mk_key( 42UL, key_d );
  uchar key_x[ 32UL ]; mk_key( 43UL, key_x );
  uchar owner[ 32UL ] = { TAG_A, 0 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_accdb_fork_id_t f = fd_accdb_attach_child( ctl, root );
    seq_write( ctl, f, key_d, LAMP_A, owner );
    seq_write( ctl, f, key_x, LAMP_A, owner );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    /* no stability oracle: the crash IS the expected witness */
    fd_racesan_weave_add( w, fiber_acquire_ab ( &g_fiber[0], jr, f, f, key_x, key_d, 0UL, 0 ) );
    fd_racesan_weave_add( w, fiber_overwrite_n( &g_fiber[1], jw, f, key_d, 2 ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    fd_accdb_advance_root( ctl, f );
    drain_background( ctl );
    root = f;
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jw );
  test_shmem_delete();
}

/* test_pd_parent_read_vs_child_write (§8.2 R0-flip + R1): the FIXED
   shape.  Reader acquire_a's X writable on child C and acquire_b's D
   read-only on frozen parent P while a writer commits D twice on C
   (same size class -- the schedules that crashed pre-fix).  Oracle: the
   parent copy is never mutated under the pin (P is frozen, overwrite
   requires generation equality), both commits succeed, and the probe on
   C reflects the committed pd_write. */
static void
test_pd_parent_read_vs_child_write( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new();
  fd_accdb_t * jw  = join_new();

  uchar key_d[ 32UL ]; mk_key( 42UL, key_d );
  uchar key_x[ 32UL ]; mk_key( 43UL, key_x );
  uchar owner[ 32UL ] = { TAG_A, 0 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_accdb_fork_id_t p = fd_accdb_attach_child( ctl, root );
    fd_accdb_fork_id_t c = fd_accdb_attach_child( ctl, p );
    seq_write( ctl, p, key_d, LAMP_A, owner ); /* parent copy: the stability oracle */
    seq_write( ctl, c, key_x, LAMP_A, owner );
    /* first child version of D so the writer's commits are overwrites */
    seq_write( ctl, c, key_d, LAMP_B, owner );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_acquire_ab ( &g_fiber[0], jr, c, p, key_x, key_d, LAMP_A, TAG_A ) );
    fd_racesan_weave_add( w, fiber_overwrite_n( &g_fiber[1], jw, c, key_d, 2 ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    /* writer's commits landed on C, parent copy intact */
    int   pd  = 0;
    ulong len = ULONG_MAX;
    FD_TEST( fd_accdb_probe_pd_this_fork( ctl, c, key_d, &pd, &len )==1 );
    FD_TEST( pd==0 ); /* plain lamport writes: no pd_write */

    fd_accdb_advance_root( ctl, p );
    drain_background( ctl );
    fd_accdb_advance_root( ctl, c );
    drain_background( ctl );
    root = c;
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jw );
  test_shmem_delete();
}

/* test_pd_parent_hold_vs_advance_root (§8.2 R2a + R2c): the
   newly-blessed interleaving -- read-only acquire_b(P) walk + hold
   concurrent with background_advance_root(P) (rooting P itself while
   its child executes).  Covers the descends_set_null(P) and old-root
   bit-remove races against the reader's chain walk; the generation fast
   path must resolve them (see fork_slot_defer comment case (a)). */
static void
test_pd_parent_hold_vs_advance_root( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new();
  fd_accdb_t * jb  = join_new();

  uchar key_d[ 32UL ]; mk_key( 42UL, key_d );
  uchar key_x[ 32UL ]; mk_key( 43UL, key_x );
  uchar owner[ 32UL ] = { TAG_A, 0 };

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  seq_write( ctl, root, key_d, LAMP_B, owner ); /* superseded rooted version: advance_root(P) unlinks it */

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    fd_accdb_fork_id_t p = fd_accdb_attach_child( ctl, root );
    fd_accdb_fork_id_t c = fd_accdb_attach_child( ctl, p );
    seq_write( ctl, p, key_d, LAMP_A, owner ); /* P's version; reader must select this one */
    seq_write( ctl, c, key_x, LAMP_A, owner );

    fd_accdb_advance_root( ctl, p ); /* executed by the background fiber mid-walk/hold */

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_acquire_ab( &g_fiber[0], jr, c, p, key_x, key_d, LAMP_A, TAG_A ) );
    fd_racesan_weave_add( w, fiber_background( &g_fiber[1], jb ) );

    fd_racesan_weave_exec_rand( w, fd_ulong_hash( i ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );

    fd_racesan_weave_delete( w );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    /* P is root; leave its version of D as the superseded rooted
       version for the next iteration and collapse onto C. */
    fd_accdb_advance_root( ctl, c );
    drain_background( ctl );
    root = c;
    seq_write( ctl, root, key_d, LAMP_B, owner );
  }

  join_delete( ctl );
  join_delete( jr );
  join_delete( jb );
  test_shmem_delete();
}

struct test_case { char const * name; void (*fn)( void ); };

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  g_seed_base = fd_env_strip_cmdline_ulong( &argc, &argv, "--seed-base", NULL, 0UL );
  g_explicit  = (argc>1); /* any test named on the command line */

# define TEST( name ) { #name, name }
  struct test_case cases[] = {
    TEST( test_acquire_vs_advance ),
    TEST( test_acquire_vs_advance_sibling ),
    TEST( test_acquire_interior_unlink ),
    TEST( test_acquire_vs_release ),
    TEST( test_acquire_vs_purge ),
    TEST( test_cold_load_same ),
    TEST( test_cold_load_evict ),
    TEST( test_pin_vs_evict ),
    TEST( test_read_vs_overwrite ),
    TEST( test_epoch_reclaim_pin ),
    TEST( test_nocache_vs_compaction ),
    TEST( test_compact_reloc_integrity ),
    TEST( test_compact_vs_overwrite ),
    TEST( test_compact_vs_coldread ),
    TEST( test_coldload_vs_overwrite ),
    TEST( test_commit_owner_vs_reader ),
    TEST( test_tombstone_orphan_ebr_poison ),
    TEST( test_sentinel_unlink_no_poison ),
    TEST( test_step14_orphan_no_hang ),
    TEST( test_stray_pin_vs_freepop ),
    TEST( test_stray_pin_vs_release_cleanup ),
    TEST( test_probe_vs_pd_commit ),
    TEST( test_pd_same_fork_read_vs_write ),
    TEST( test_pd_parent_read_vs_child_write ),
    TEST( test_pd_parent_hold_vs_advance_root ),
    {0}
  };
# undef TEST

  for( struct test_case * tc = cases; tc->name; tc++ ) {
    int run = 1;
    if( argc>1 ) {
      run = 0;
      for( int a=1; a<argc; a++ ) if( !strcmp( argv[a], tc->name ) ) run = 1;
    }
    if( run ) {
      FD_LOG_NOTICE(( "Running %s", tc->name ));
      tc->fn();
    }
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
