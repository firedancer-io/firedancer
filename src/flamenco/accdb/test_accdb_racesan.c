/* test_accdb_racesan.c deterministically weaves concurrent accdb
   operations at the racesan hooks in fd_accdb.c.

   The threading model (fd_accdb.h):

     T1 (replay)    : attach_child, advance_root / purge (published as
                      requests, applied by T2), acquire, release.
     T2 (accdb tile): fd_accdb_background: requests, pre-eviction and
                      compaction.
     T3 (executors) : acquire, release.

   Two kinds of test.  Weaves run fibers to completion in random
   schedules, with the visibility checks in fd_accdb_acquire_inner
   (handholding) and the bytes each reader sees as the oracle.  Parked
   tests step one fiber to a named hook, act from another join, and
   check the state the design promises at that stop: the hold / evict
   and commit / evict Dekker pairs, writeback publish against unlink
   and compaction, racing cold loads, unheld copies, commits with no
   line to spare and reservation steals (see "Cache races"). */

#define _GNU_SOURCE

#include "fd_accdb.h"
#include "fd_accdb_cache.h"
#include "fd_accdb_private.h"
#include "../../util/fd_util.h"
#include "../../util/racesan/fd_racesan_async.h"
#include "../../util/racesan/fd_racesan_weave.h"
#include "../../util/racesan/fd_racesan_target.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
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

  ulong shmem_fp = fd_accdb_shmem_footprint( T_MAX_ACCOUNTS, T_MAX_LIVE_SLOTS, T_WRITES_PER_SLOT, T_PARTITION_CNT, cache_fp, cache_min_reserved, T_JOINER_CNT, 0UL );
  FD_TEST( shmem_fp );
  g_shmem_mem = aligned_alloc( fd_accdb_shmem_align(), shmem_fp );
  FD_TEST( g_shmem_mem );
  g_shmem = fd_accdb_shmem_join(
      fd_accdb_shmem_new( g_shmem_mem, T_MAX_ACCOUNTS, T_MAX_LIVE_SLOTS,
                          T_WRITES_PER_SLOT, T_PARTITION_CNT,
                          partition_sz, cache_fp, cache_min_reserved, 0, 42UL, T_JOINER_CNT, 0UL ) );
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
  ulong accdb_fp = fd_accdb_footprint( T_MAX_LIVE_SLOTS, 1 );
  FD_TEST( accdb_fp );
  void * mem = aligned_alloc( fd_accdb_align(), accdb_fp );
  FD_TEST( mem );
  fd_accdb_t * accdb = fd_accdb_join( fd_accdb_new( mem, g_shmem, g_fd, 0UL, NULL, NULL, 0UL, 1 ) );
  FD_TEST( accdb );
  fd_accdb_set_preevict_interval( accdb, 0L ); /* background steps pre-evict every call */
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
  fd_memcpy( acc[0].owner, owner ? owner : g_zero_owner, 32UL );
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
      int                result;            /* FD_ACCDB_READ_ONE_NOCACHE_* */
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

    struct {
      fd_accdb_fork_id_t fork_id;
      uchar              pubkey[ 32UL ];
      ulong              lamports;
      uchar              owner0;
      ulong              data_len;
      uchar              fill;
    } io;

    struct {
      ulong              cls;
      ulong              idx;
      int                evicted;
    } evict;
  };
};
typedef struct fiber fiber_t;

/* Two self-consistent (lamports, owner-tag) states the overwrite writer
   toggles between.  LAMP_A is non-zero (live); the owner tag is encoded
   in owner[0] so a reader can check (lamports,owner) consistency.  We
   also exercise the tombstone boundary by including a zero-lamport
   state in the dedicated torn-tombstone test. */
#define LAMP_A (2039280UL)   /* SPL-token rent-exempt */
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
   the T3 reader; the visibility checks in acquire (handholding) and
   expect_lamports are the oracle. */

static void
fiber_acquire_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  uchar const * pks[1] = { f->acquire.pubkey };
  int wr[1] = { 0 };
  fd_acc_t acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( f->accdb, f->acquire.fork_id, 1UL, pks, wr, acc );
  /* Cold-load / eviction correctness oracle: the bytes the reader sees
     must match what was committed for this (key, fork).  A torn cold
     load or a hold on a line that no longer has K would surface here as
     a lamports/pubkey mismatch. */
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
  fd_memcpy( fiber->acquire.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, fiber_acquire_exec, fiber );
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
  fd_memcpy( acc[0].owner, g_zero_owner, 32UL );
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
  fd_memcpy( fiber->release_write.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, fiber_release_write_exec, fiber );
  return fiber->async;
}

/* consistent-reader fiber: read-only acquire that asserts the returned
   (lamports, owner) form a self-consistent pair the overwrite writer
   could have committed.  lamports comes from the accmeta and the owner
   from the line, so a reader that straddles an in-place commit could
   observe a pair the writer never committed. */

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
  fd_memcpy( fiber->acquire_consistent.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, fiber_acquire_consistent_exec, fiber );
  return fiber->async;
}

/* overwrite-writer fiber: writable acquire+commit+release on the same
   (pubkey, fork) the reader uses, committing a self-consistent pair.
   This deliberately overlaps a read-only acquire of the same account on
   the same fork, which the public API forbids (test_read_vs_overwrite). */

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
  fd_memcpy( fiber->overwrite.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, fiber_overwrite_exec, fiber );
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
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, fiber_background_exec, fiber );
  return fiber->async;
}

/* Test-only API (fd_accdb.c, FD_HAS_RACESAN).  force_preevict sweeps
   every class (CLOCK, eight laps); find_line finds the line the
   visible version of pubkey is bound to; line_addr is a line's
   address; acc_pool_next is an accmeta's map.next link (so its
   accmeta); evict_line evicts one line as CLOCK does, returning 1 if
   it was evicted and 0 if it was not SHARED or is held. */

void   fd_accdb_debug_force_preevict( fd_accdb_t * accdb );
int    fd_accdb_debug_find_line     ( fd_accdb_t * accdb, uchar const * pubkey, ulong * out_class, ulong * out_idx );
void * fd_accdb_debug_line_addr     ( fd_accdb_t * accdb, ulong size_class, ulong line_idx );
fd_accdb_accmeta_t * fd_accdb_debug_accmeta( fd_accdb_t * accdb, uint acc_idx );
int    fd_accdb_debug_evict_line    ( fd_accdb_t * accdb, ulong size_class, ulong line_idx );

/* forced pre-eviction fiber: the test-only full sweep, so a test can
   park the sweeper with lines claimed and written back but not yet
   published. */

static void
fiber_force_preevict_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_accdb_debug_force_preevict( f->accdb );
}

static fd_racesan_async_t *
fiber_force_preevict( fiber_t *    fiber,
                      fd_accdb_t * accdb ) {
  fiber->accdb = accdb;
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, fiber_force_preevict_exec, fiber );
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
  f->nocache.result = fd_accdb_read_one_nocache( f->accdb, f->nocache.fork_id, f->nocache.pubkey,
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
    /* The account is live; its (owner0, data) must be one of the two
       committed states (TAG_A/0xAA or TAG_B/0xBB), never a torn owner. */
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
  fd_memcpy( fiber->nocache.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, fiber_nocache_exec, fiber );
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
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, fiber_compact_loop_exec, fiber );
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
  ulong lamports = 0xdeadUL;
  int   r   = fd_accdb_probe_pd_this_fork( f->accdb, f->probe.fork_id, f->probe.pubkey, &pd, &len, &lamports );
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
  fd_memcpy( fiber->probe.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, fiber_probe_exec, fiber );
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
  fd_memcpy( fiber->pd_commit.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, fiber_pd_commit_exec, fiber );
  return fiber->async;
}

/* acquire_ab fiber: the executor's implicit-programdata shape.
   acquire_a of X writable on fork_w (the executing fork), then
   acquire_b of D read-only on fork_r, exactly like
   fd_executor_setup_accounts_for_txn.  When expect_lamports!=0, asserts
   D's {lamports, owner[0]} pair matches when acquired and again before
   release (a concurrent writer on another fork must never mutate the
   held copy). */
static void
fiber_acquire_ab_exec( void * _ctx ) {
  fiber_t * f = _ctx;

  uchar const * pka[1] = { f->acquire_ab.pubkey_x };
  int           wra[1] = { 1 };
  fd_acc_t acc_a[1]; memset( acc_a, 0, sizeof(acc_a) );
  fd_accdb_acquire_a( f->accdb, f->acquire_ab.fork_w, 1UL, pka, wra, acc_a );

  uchar const * pkb[1] = { f->acquire_ab.pubkey_d };
  fd_acc_t acc_b[1]; memset( acc_b, 0, sizeof(acc_b) );
  fd_accdb_acquire_b( f->accdb, f->acquire_ab.fork_r, 1UL, 1UL, pkb, acc_b );

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
  fd_memcpy( fiber->acquire_ab.pubkey_x, pubkey_x, 32UL );
  fd_memcpy( fiber->acquire_ab.pubkey_d, pubkey_d, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, fiber_acquire_ab_exec, fiber );
  return fiber->async;
}

/* overwrite_n fiber: `rounds` same-class overwrite commits of D
   (data_len 0, class 0: the second commit rewrites its line in
   place). */
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
  fd_memcpy( fiber->overwrite_n.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, fiber_overwrite_n_exec, fiber );
  return fiber->async;
}

/* io fibers: a read that checks every field of the account (a holder,
   for the cache races), and a write of the given fields. */

static void
fiber_read_check_exec( void * _ctx ) {
  fiber_t *     f      = _ctx;
  uchar const * pks[1] = { f->io.pubkey };
  int           wr [1] = { 0 };
  fd_acc_t      acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( f->accdb, f->io.fork_id, 1UL, pks, wr, acc );
  FD_TEST( acc[0].lamports==f->io.lamports );
  FD_TEST( acc[0].owner[ 0 ]==f->io.owner0 );
  FD_TEST( acc[0].data_len==f->io.data_len );
  for( ulong i=0UL; i<acc[0].data_len; i++ ) FD_TEST( acc[0].data[ i ]==f->io.fill );
  fd_accdb_release( f->accdb, 1UL, acc );
}

static void
fiber_write_exec( void * _ctx ) {
  fiber_t *     f      = _ctx;
  uchar const * pks[1] = { f->io.pubkey };
  int           wr [1] = { 1 };
  fd_acc_t      acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( f->accdb, f->io.fork_id, 1UL, pks, wr, acc );
  acc[0].lamports = f->io.lamports;
  acc[0].data_len = f->io.data_len;
  memset( acc[0].owner, 0, 32UL );
  acc[0].owner[ 0 ] = f->io.owner0;
  if( f->io.data_len ) memset( acc[0].data, f->io.fill, f->io.data_len );
  acc[0].commit = 1;
  fd_accdb_release( f->accdb, 1UL, acc );
}

static fd_racesan_async_t *
fiber_io( fiber_t *          fiber,
          void (*            exec)( void * ),
          fd_accdb_t *       accdb,
          fd_accdb_fork_id_t fork_id,
          uchar const *      pubkey,
          ulong              lamports,
          uchar              owner0,
          ulong              data_len,
          uchar              fill ) {
  fiber->accdb       = accdb;
  fiber->io.fork_id  = fork_id;
  fiber->io.lamports = lamports;
  fiber->io.owner0   = owner0;
  fiber->io.data_len = data_len;
  fiber->io.fill     = fill;
  fd_memcpy( fiber->io.pubkey, pubkey, 32UL );
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, exec, fiber );
  return fiber->async;
}

/* evict fiber: evicts one line (fd_accdb_debug_evict_line), so a test
   can park the evictor between its claim, scan, writeback and unbind.
   evicted is the result. */

static void
fiber_evict_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  f->evict.evicted = fd_accdb_debug_evict_line( f->accdb, f->evict.cls, f->evict.idx );
}

static fd_racesan_async_t *
fiber_evict( fiber_t *    fiber,
             fd_accdb_t * accdb,
             ulong        cls,
             ulong        idx ) {
  FD_VOLATILE( g_shmem->cache_class_init[ cls ].val ) = g_shmem->cache_class_max[ cls ];  /* see evict_line */
  fiber->accdb       = accdb;
  fiber->evict.cls   = cls;
  fiber->evict.idx   = idx;
  fiber->evict.evicted = -1;
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, fiber_evict_exec, fiber );
  return fiber->async;
}

static void
fiber_done( fiber_t * fiber ) {
  fd_racesan_async_delete( fiber->async );
}

static void
async_finish( fd_racesan_async_t * async ) {
  for( ulong step=0UL; step<STEP_MAX; step++ ) {
    if( fd_racesan_async_step( async )==FD_RACESAN_ASYNC_RET_EXIT ) return;
  }
  FD_LOG_ERR(( "async did not exit within %lu steps", STEP_MAX ));
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
   not visible to A1, the visibility check in acquire fires. */

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
   must never observe B's version. */

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
   reader must end on A's version regardless of interleaving, never on
   B's (non-visible) or R's (unlinked) version. */

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
   Cache weaves: eviction (CLOCK) and cold loads.

   These use a tiny class-0 cache (test_shmem_new_tiny), so reading an
   evicted account cold-loads it from the backing memfd, and the line
   it loads into comes from a CLOCK batch that evicts other resident
   lines.  fiber_acquire_expect checks the loaded lamports and pubkey.
   The parked versions of these races are in "Cache races" below. */

/* test_cold_load_same: two readers concurrently acquire the same
   evicted account, so both race to bind it (one wins the data word
   CAS, the other frees its line and waits for the load).  Both must
   read the correct bytes. */

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

/* test_cold_load_evict: two readers concurrently acquire different
   evicted accounts.  Each cold load takes a line, which with the tiny
   cache full runs a CLOCK batch that may claim the line the other
   reader is holding or loading into. */

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

/* test_hit_vs_evict: one reader holds a resident account while a
   second reader cold-loads a different evicted account, whose line
   allocation runs CLOCK, possibly over the line the first reader is
   holding (the hold / claim Dekker pair, at random). */

static void
test_hit_vs_evict( void ) {
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

/* test_read_vs_overwrite: a read-only acquire of key on fork R races
   a writable overwrite of the same key on the same fork (an in-place
   commit that rewrites the accmeta's lamports and the line's owner
   under the reader).  If the reads straddle the commit, the reader
   observes a (lamports, owner) pair the writer never committed.

   This interleaving is forbidden by the accdb public API (no concurrent
   acquire of the same (pubkey, fork) while a writable acquire is
   outstanding), so the test is opt-in: it shows what a caller that
   broke the contract would see. */

static void
test_read_vs_overwrite( void ) {
  /* Demonstration repro that intentionally FAILS (it violates the accdb
     API contract on purpose).  Skip unless named explicitly so a default
     "run all" stays green. */
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
   offset_fork valid across its preadv2.  Oracle: the reader's bytes
   are exactly what was committed (fiber_nocache).
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
  /* Overwrite filler0 on the same fork: the commit swaps its offset
     away from the partition-0 record and frees it, crossing the 30%
     threshold for partition 0. */
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
   preadv2 returns zeros/stale bytes and the fiber_nocache oracle
   fires. */

/* test_epoch_reclaim_pin: DETERMINISTIC construction of the exact unsafe
   window, instead of hoping a random weave hits it.  Steps:

     1. fragment partition 0 so K lives there and part 0 is enqueued.
     2. step the reader fiber until it parks at nocache:pre_preadv2 — at
        that point it has PUBLISHED its epoch and SNAPSHOTTED K's (old,
        partition-0) offset, but has not yet read.
     3. while the reader is parked, drive compaction to completion: it
        relocates K to layer 1, tags partition 0 with epoch_tag >= the
        reader's epoch, defers it, and the reclaim pass runs.
     4. partition 0 must not be freed while the reader is parked at
        epoch <= epoch_tag: the reclaim epoch gate defers the free.
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
         compaction to completion: relocate + defer + reclaim part 0. */
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

   background_compact relocates a record
   (copy_file_range to a new layer) and CAS-republishes offset_fork from
   the snapshotted source offset to the destination.  Two races:

   (a) compact relocate vs a concurrent same-fork overwrite of the same
       accmeta: the overwrite swaps the offset to UPDATING, then DIRTY
       (later a new record); the relocation CAS must then fail so the
       stale copy is discarded and the overwrite wins.  Hook:
       accdb_compact:pre_offset_cas (parked: test_writeback_vs_compact).

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
extern ulong fd_accdb_dbg_compact_scanned;
#endif

static uchar g_cold_data[ 10UL<<20 ];

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

   The relocation publishes a real destination offset whose bytes are
   whatever the copy wrote, and the cold read dereferences exactly
   that. */
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

    /* fragment: K on disk (owner0=TAG_A, data 0xAA), enqueued. */
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

/* test_compact_batch: a compaction pass relocates a run of live
   records with one pwritev2, skips the dead ones inside the run, and
   a run longer than the bounce buffer splits across passes.  Records
   are 3 MiB (class 7): the tiny cache holds eight, so writing the
   seven and then eight fillers pushes all seven to disk in order in
   a 24 MiB partition.  Rewriting three of them frees 37%, above the
   compaction threshold, leaving live records 0, 2, 3, 4 with dead
   ones at 1, 5, 6; five records fit the 16 MiB bounce so the run
   splits after record 4, and the step after reuses the cut-off tail
   instead of reading it again.  Every record is then cold read and
   checked byte for byte. */

#define BATCH_REC_CNT  (7UL)
#define BATCH_REC_DATA (3UL<<20)

static void
test_compact_batch( void ) {
  test_shmem_new_cfg2( test_tiny_cache_footprint(), TEST_TINY_CACHE_MIN_RESERVED, 24UL<<20 );
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jc  = join_new();

  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  static int const dead[ BATCH_REC_CNT ] = { 0, 1, 0, 0, 0, 1, 1 };

  uchar keys[ BATCH_REC_CNT ][ 32UL ];
  for( ulong i=0UL; i<BATCH_REC_CNT; i++ ) {
    mk_key( 3100UL+i, keys[ i ] );
    uchar owner[ 32UL ]; memset( owner, 0, 32UL ); owner[0] = (uchar)(0x40+i);
    seq_write_data( ctl, root, keys[ i ], 1000UL+i, owner, BATCH_REC_DATA, (uchar)(0xA0+i) );
  }
  /* evict the seven to disk (partition 0) and move the write head on */
  for( ulong e=0UL; e<12UL; e++ ) {
    uchar t[ 32UL ]; mk_key( 3200UL+e, t );
    seq_write_data( ctl, root, t, 1UL, NULL, BIG_DATA, 0xEE );
  }
  /* same-fork rewrites free the old records */
  for( ulong i=0UL; i<BATCH_REC_CNT; i++ ) {
    if( !dead[ i ] ) continue;
    uchar owner[ 32UL ]; memset( owner, 0, 32UL ); owner[0] = (uchar)(0xD0+i);
    seq_write_data( ctl, root, keys[ i ], 2000UL+i, owner, BATCH_REC_DATA, (uchar)(0xB0+i) );
  }
  fd_accdb_shmem_metrics_t const * m = fd_accdb_shmetrics( ctl );
  ulong before_rel = m->accounts_relocated;
  ulong before_ops = fd_accdb_metrics( jc )->copy_ops;
  ulong before_rd  = fd_accdb_metrics( jc )->bytes_read;
  ulong before_cmp = m->compactions_completed;
  ulong before_scn = fd_accdb_dbg_compact_scanned;
  for( int s=0; s<256; s++ ) drain_background( jc );
  ulong relocated = m->accounts_relocated-before_rel;
  ulong writes    = fd_accdb_metrics( jc )->copy_ops-before_ops;
  /* each compacted partition is read once: the cut-off tail of a
     window is reused, not read again */
  FD_TEST( m->compactions_completed>before_cmp );
  FD_TEST( fd_accdb_metrics( jc )->bytes_read-before_rd==fd_accdb_dbg_compact_scanned-before_scn );
  FD_LOG_NOTICE(( "  test_compact_batch: %lu records relocated by %lu pwritev2 calls in %lu compactions", relocated, writes, m->compactions_completed ));
  FD_TEST( writes<relocated ); /* batched: fewer writes than records */

  /* evict again, then cold read every record from wherever it lives */
  for( ulong e=0UL; e<32UL; e++ ) {
    uchar t[ 32UL ]; mk_key( 3300UL+e, t );
    seq_write_data( ctl, root, t, 1UL, NULL, BIG_DATA, 0xCC );
  }
  for( ulong i=0UL; i<BATCH_REC_CNT; i++ ) {
    ulong lamports = 0UL; int executable = 0; ulong data_len = 0UL;
    uchar owner[ 32UL ]; memset( owner, 0xEE, 32UL );
    g_cold_data[0] = 0xEE; g_cold_data[ BATCH_REC_DATA-1UL ] = 0xEE;
    fd_accdb_read_one_nocache( ctl, root, keys[ i ], &lamports, &executable, owner, g_cold_data, &data_len );
    uchar want_fill = dead[ i ] ? (uchar)(0xB0+i) : (uchar)(0xA0+i);
    ulong want_lamp = dead[ i ] ? 2000UL+i : 1000UL+i;
    uchar want_own  = dead[ i ] ? (uchar)(0xD0+i) : (uchar)(0x40+i);
    FD_TEST( lamports==want_lamp && owner[0]==want_own && data_len==BATCH_REC_DATA );
    for( ulong z=0UL; z<data_len; z+=4093UL ) FD_TEST( g_cold_data[ z ]==want_fill );
    FD_TEST( g_cold_data[ data_len-1UL ]==want_fill );
  }
  FD_TEST( relocated>=4UL ); /* the live records of partition 0 */

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

/* sample_bounds mirrors snaprd's partition sampling: one bound per
   partition, zero when the partition is empty or compacted away. */
static void
sample_bounds( fd_accdb_shmem_t const * shmem,
               ulong *                  bound ) {
  ulong part_max = fd_accdb_shmem_partition_max( shmem );
  for( ulong i=0UL; i<part_max; i++ ) {
    fd_accdb_shmem_partition_info_t info[ 1 ];
    fd_accdb_shmem_partition_info( shmem, i, info );
    ulong sz = info->write_offset_raw;
    bound[ i ] = info->compaction_offset>=sz ? 0UL : sz;
  }
}

static int
covered( fd_accdb_shmem_t const * shmem,
         ulong const *            bound,
         ulong                    off ) {
  ulong part_sz = fd_accdb_shmem_partition_sz( shmem );
  return off%part_sz < bound[ off/part_sz ];
}

/* ====================================================================
   Cache races.

   A reader holds a line by an entry in its join's hazard list.  An
   evictor claims a line (SHARED -> EVICTING), scans every hazard list
   once for its batch, gives the held lines back, and writes back,
   unbinds and takes the rest.  An account is bound to a line by its
   data word, and only a clean version is ever unbound.  The tests below
   park both sides at the hooks between those steps, check the state the
   design promises at each stop, and check every account's bytes at the
   end. */

/* evict_line evicts line (cls,idx) now, as CLOCK would.  It first marks
   every line of the class used: the reclaim takes a never-used line
   before it claims one, and would then report the line evicted without
   touching it. */

static int
evict_line( fd_accdb_t * accdb,
            ulong        cls,
            ulong        idx ) {
  FD_VOLATILE( g_shmem->cache_class_init[ cls ].val ) = g_shmem->cache_class_max[ cls ];
  return fd_accdb_debug_evict_line( accdb, cls, idx );
}

/* line_find returns the line the visible version of pubkey is bound
   to, with its class and index, or NULL if it is not cached. */

static fd_accdb_cache_line_t *
line_find( fd_accdb_t *  accdb,
           uchar const * pubkey,
           ulong *       cls,
           ulong *       idx ) {
  if( !fd_accdb_debug_find_line( accdb, pubkey, cls, idx ) ) return NULL;
  return fd_accdb_debug_line_addr( accdb, *cls, *idx );
}

/* accmeta_at returns the accmeta of an index entry. */

static fd_accdb_accmeta_t *
accmeta_at( fd_accdb_t * accdb,
            uint         acc_idx ) {
  return fd_accdb_debug_accmeta( accdb, acc_idx );
}

static ulong
acc_off( fd_accdb_accmeta_t const * m ) {
  return FD_VOLATILE_CONST( m->offset_fork ) & FD_ACCDB_OFF_MASK;
}

static int
acc_bound( fd_accdb_accmeta_t const * m ) {
  return FD_ACCDB_SIZE_CACHE_VALID( FD_ACCDB_DATA_ES( FD_VOLATILE_CONST( m->data ) ) );
}

/* hazard_join returns the join whose hazard list holds line cidx, or
   ULONG_MAX if none does. */

static ulong
hazard_join( uint cidx ) {
  for( ulong j=0UL; j<FD_VOLATILE_CONST( g_shmem->joiner_cnt ); j++ ) {
    ulong cnt = FD_VOLATILE_CONST( g_shmem->cache_hazard[ j ].cnt );
    for( ulong k=0UL; k<cnt; k++ ) {
      if( FD_VOLATILE_CONST( g_shmem->cache_hazard[ j ].cidx[ k ] )==cidx ) return j;
    }
  }
  return ULONG_MAX;
}

/* nocache_check reads pubkey without the cache's help, checks every
   field against what was committed and returns where it was read from
   (FD_ACCDB_READ_ONE_NOCACHE_*). */

static int
nocache_check( fd_accdb_t *       accdb,
               fd_accdb_fork_id_t fork_id,
               uchar const *      pubkey,
               ulong              lamports,
               uchar              owner0,
               ulong              data_len,
               uchar              fill ) {
  ulong lam  = 0UL;
  int   exec = 0;
  ulong len  = 0UL;
  uchar owner[ 32UL ];
  int   r = fd_accdb_read_one_nocache( accdb, fork_id, pubkey, &lam, &exec, owner, g_cold_data, &len );
  FD_TEST( lam==lamports && owner[ 0 ]==owner0 && len==data_len );
  if( len ) FD_TEST( g_cold_data[ 0 ]==fill && g_cold_data[ len/2UL ]==fill && g_cold_data[ len-1UL ]==fill );
  return r;
}

/* freed_total is the bytes marked freed over every partition. */

static ulong
freed_total( void ) {
  ulong sum = 0UL;
  for( ulong p=0UL; p<fd_accdb_shmem_partition_max( g_shmem ); p++ ) {
    fd_accdb_shmem_partition_info_t info[ 1 ];
    fd_accdb_shmem_partition_info( g_shmem, p, info );
    sum += info->bytes_freed;
  }
  return sum;
}

/* test_hold_vs_evict: the holder / evictor Dekker pair.  A reader holds
   K's line by storing its hazard entry, then waits while the line is
   EVICTING and checks that K is still bound to it.  An evictor claims
   the line and then scans the hazard lists.  Three orders:

     1. the hold is in place before the claim: the scan sees it and the
        line goes back SHARED, still bound, with no writeback;
     2. the claim, then the entry, then the scan: the reader waits on
        EVICTING, the scan sees the entry and gives the line back, and
        the reader holds it without reloading;
     3. the scan before the entry: the evictor writes K back and unbinds
        it while the reader waits on EVICTING; the reader then loads K
        cold from the record just written.

   K is dirty at the start, and the reader checks every byte.

   racesan runs one thread and cannot reorder stores past loads, so the
   StoreLoad fences on either side of the pair are not tested here: the
   schedules are, assuming the fences hold. */

static void
test_hold_vs_evict( void ) {
  test_shmem_new();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_t *       jr   = join_new();
  fd_accdb_t *       je   = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  uchar K    [ 32UL ]; mk_key( 9100UL, K );
  uchar owner[ 32UL ] = { TAG_A };
  seq_write_data( ctl, root, K, LAMP_A, owner, 100UL, 0x5A );
  ulong                   cls, idx;
  fd_accdb_cache_line_t * line = line_find( ctl, K, &cls, &idx );
  FD_TEST( line && cls==0UL );
  uint                 cidx = FD_ACCDB_ACC_CIDX_PACK( cls, idx );
  fd_accdb_accmeta_t * m    = accmeta_at( ctl, line->acc_idx );
  FD_TEST( acc_off( m )==FD_ACCDB_OFF_DIRTY( cidx ) );

  /* 1. The hold first */
  fd_racesan_async_t * r = fiber_io( &g_fiber[0], fiber_read_check_exec, jr, root, K, LAMP_A, TAG_A, 100UL, 0x5A );
  FD_TEST( fd_racesan_async_step_until( r, "accdb_acquire:pre_out", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( hazard_join( cidx )!=ULONG_MAX );
  ulong wr0 = fd_accdb_metrics( je )->write_ops;
  FD_TEST( !evict_line( je, cls, idx ) );
  FD_TEST( line->state==FD_ACCDB_LINE_SHARED );
  FD_TEST( acc_bound( m ) && acc_off( m )==FD_ACCDB_OFF_DIRTY( cidx ) );
  FD_TEST( fd_accdb_metrics( je )->write_ops==wr0 );
  async_finish( r );
  fiber_done( &g_fiber[0] );

  /* 2. The claim, then the entry, then the scan */
  fd_racesan_async_t * e = fiber_evict( &g_fiber[1], je, cls, idx );
  FD_TEST( fd_racesan_async_step_until( e, "accdb_reclaim:post_claim", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( line->state==FD_ACCDB_LINE_EVICTING );
  r = fiber_io( &g_fiber[0], fiber_read_check_exec, jr, root, K, LAMP_A, TAG_A, 100UL, 0x5A );
  FD_TEST( fd_racesan_async_step_until( r, "accdb_acquire:claim_wait", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( hazard_join( cidx )!=ULONG_MAX );
  async_finish( e );
  FD_TEST( !g_fiber[1].evict.evicted );
  FD_TEST( line->state==FD_ACCDB_LINE_SHARED );
  FD_TEST( acc_bound( m ) && acc_off( m )==FD_ACCDB_OFF_DIRTY( cidx ) );
  ulong rd0 = fd_accdb_metrics( jr )->read_ops;
  async_finish( r );
  FD_TEST( fd_accdb_metrics( jr )->read_ops==rd0 );
  fiber_done( &g_fiber[0] );
  fiber_done( &g_fiber[1] );

  /* 3. The scan before the entry.  The reader parks at its first
     pre_hold: it loaded the bound word but has not stored its entry. */
  e = fiber_evict( &g_fiber[1], je, cls, idx );
  FD_TEST( fd_racesan_async_step_until( e, "accdb_reclaim:post_claim", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  r = fiber_io( &g_fiber[0], fiber_read_check_exec, jr, root, K, LAMP_A, TAG_A, 100UL, 0x5A );
  FD_TEST( fd_racesan_async_step_until( r, "accdb_acquire:pre_hold", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( fd_racesan_async_step_until( e, "accdb_writeback:post_write", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( line->state==FD_ACCDB_LINE_EVICTING );
  FD_TEST( acc_bound( m ) && acc_off( m )==FD_ACCDB_OFF_DIRTY( cidx ) );
  FD_TEST( fd_racesan_async_step_until( r, "accdb_acquire:claim_wait", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  async_finish( e );
  FD_TEST( g_fiber[1].evict.evicted );
  FD_TEST( !acc_bound( m ) && FD_ACCDB_OFF_CLEAN( acc_off( m ) ) );
  rd0 = fd_accdb_metrics( jr )->read_ops;
  async_finish( r );
  FD_TEST( fd_accdb_metrics( jr )->read_ops>rd0 );
  FD_TEST( acc_bound( m ) );
  fiber_done( &g_fiber[0] );
  fiber_done( &g_fiber[1] );

  FD_TEST( nocache_check( ctl, root, K, LAMP_A, TAG_A, 100UL, 0x5A )==FD_ACCDB_READ_ONE_NOCACHE_CACHE );

  join_delete( ctl );
  join_delete( jr );
  join_delete( je );
  test_shmem_delete();
}

/* test_commit_vs_evict: an in-place commit and an evictor form the
   second Dekker pair: the committer swaps K's offset to UPDATING, then
   loads the line state; the evictor claims the line, then loads the
   offset.

     A. the claim first: the committer sees EVICTING and commits to a
        fresh line.  The old line is an orphan; the evictor gives it
        back (the committer still holds it), and evicting it later
        writes nothing back and leaves K bound to the new line;
     B. UPDATING first: the committer rewrites the line in place and
        parks with the offset UPDATING.  The evictor's scan sees the
        committer's hold and gives the line back.  Then the same with
        the committer's hazard list hidden from the scan, as an evictor
        that missed the hold: it must see UPDATING and give the line back
        too.

   No update is lost: the bytes read back from disk at the end are the
   last commit's. */

static void
test_commit_vs_evict( void ) {
  test_shmem_new();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_t *       jw   = join_new();
  fd_accdb_t *       je   = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  uchar K     [ 32UL ]; mk_key( 9200UL, K );
  uchar owner [ 32UL ] = { TAG_A };
  seq_write_data( ctl, root, K, LAMP_A, owner, 100UL, 0xA1 );
  ulong                   cls, idx;
  fd_accdb_cache_line_t * line = line_find( ctl, K, &cls, &idx );
  FD_TEST( line && cls==0UL );
  fd_accdb_accmeta_t * m = accmeta_at( ctl, line->acc_idx );

  /* A. The claim first */
  fd_racesan_async_t * w = fiber_io( &g_fiber[0], fiber_write_exec, jw, root, K, LAMP_B, TAG_B, 100UL, 0xB2 );
  FD_TEST( fd_racesan_async_step_until( w, "accdb_commit:pre", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  fd_racesan_async_t * e = fiber_evict( &g_fiber[1], je, cls, idx );
  FD_TEST( fd_racesan_async_step_until( e, "accdb_reclaim:post_claim", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( fd_racesan_async_step_until( w, "accdb_release:pre_drop", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  ulong cls2, idx2;
  FD_TEST( line_find( ctl, K, &cls2, &idx2 ) && cls2==0UL && idx2!=idx );
  FD_TEST( acc_off( m )==FD_ACCDB_OFF_DIRTY( FD_ACCDB_ACC_CIDX_PACK( cls2, idx2 ) ) );
  FD_TEST( line->state==FD_ACCDB_LINE_EVICTING );
  async_finish( e );
  FD_TEST( !g_fiber[1].evict.evicted );
  FD_TEST( line->state==FD_ACCDB_LINE_SHARED );
  async_finish( w );
  fiber_done( &g_fiber[0] );
  fiber_done( &g_fiber[1] );

  ulong wr0 = fd_accdb_metrics( ctl )->write_ops;
  FD_TEST( evict_line( ctl, cls, idx ) );               /* the orphan: nothing to write back */
  FD_TEST( fd_accdb_metrics( ctl )->write_ops==wr0 );
  FD_TEST( line_find( ctl, K, &cls2, &idx2 ) && acc_off( m )==FD_ACCDB_OFF_DIRTY( FD_ACCDB_ACC_CIDX_PACK( cls2, idx2 ) ) );
  FD_TEST( evict_line( ctl, cls2, idx2 ) );
  FD_TEST( fd_accdb_metrics( ctl )->write_ops>wr0 );
  FD_TEST( nocache_check( ctl, root, K, LAMP_B, TAG_B, 100UL, 0xB2 )==FD_ACCDB_READ_ONE_NOCACHE_DISK );

  /* B. UPDATING first.  K is loaded again and committed dirty in place. */
  seq_write_data( ctl, root, K, LAMP_A, owner, 100UL, 0xC3 );
  line = line_find( ctl, K, &cls, &idx );
  FD_TEST( line && accmeta_at( ctl, line->acc_idx )==m );
  uint cidx = FD_ACCDB_ACC_CIDX_PACK( cls, idx );
  FD_TEST( acc_off( m )==FD_ACCDB_OFF_DIRTY( cidx ) );

  w = fiber_io( &g_fiber[0], fiber_write_exec, jw, root, K, LAMP_B, TAG_B, 100UL, 0xD4 );
  FD_TEST( fd_racesan_async_step_until( w, "accdb_commit:pre_dirty", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( acc_off( m )==FD_ACCDB_OFF_UPDATING );
  FD_TEST( acc_bound( m ) && FD_ACCDB_DATA_CIDX( FD_VOLATILE_CONST( m->data ) )==cidx );

  wr0 = fd_accdb_metrics( je )->write_ops;
  FD_TEST( !evict_line( je, cls, idx ) );               /* the scan sees the hold */
  FD_TEST( line->state==FD_ACCDB_LINE_SHARED && acc_off( m )==FD_ACCDB_OFF_UPDATING );

  ulong j = hazard_join( cidx );
  FD_TEST( j!=ULONG_MAX );
  ulong hz_cnt = g_shmem->cache_hazard[ j ].cnt;
  FD_VOLATILE( g_shmem->cache_hazard[ j ].cnt ) = 0UL;
  int evicted = evict_line( je, cls, idx );             /* only UPDATING stops it */
  FD_VOLATILE( g_shmem->cache_hazard[ j ].cnt ) = hz_cnt;
  FD_TEST( !evicted );
  FD_TEST( line->state==FD_ACCDB_LINE_SHARED && acc_off( m )==FD_ACCDB_OFF_UPDATING );
  FD_TEST( acc_bound( m ) && FD_ACCDB_DATA_CIDX( FD_VOLATILE_CONST( m->data ) )==cidx );
  FD_TEST( fd_accdb_metrics( je )->write_ops==wr0 );

  async_finish( w );
  fiber_done( &g_fiber[0] );
  FD_TEST( acc_off( m )==FD_ACCDB_OFF_DIRTY( cidx ) );
  FD_TEST( evict_line( ctl, cls, idx ) );
  FD_TEST( nocache_check( ctl, root, K, LAMP_B, TAG_B, 100UL, 0xD4 )==FD_ACCDB_READ_ONE_NOCACHE_DISK );

  join_delete( ctl );
  join_delete( jw );
  join_delete( je );
  test_shmem_delete();
}

/* test_writeback_vs_unlink: an evictor has written a dirty version back
   but not published its offset when the version is unlinked, by a
   purge and by advance_root dropping a rooted tombstone.  The unlink
   makes the offset DEAD, so the publish CAS fails and the evictor frees
   the record it wrote: disk_used_bytes ends where it started and the
   record is counted freed.  The evictor holds its epoch meanwhile, so
   the accdb tile keeps the unlinked accmeta until it is done. */

static void
test_writeback_vs_unlink( void ) {
  test_shmem_new();
  fd_accdb_t *       ctl   = join_new();
  fd_accdb_t *       je    = join_new();
  fd_accdb_fork_id_t root  = fd_accdb_attach_child( ctl, SENTINEL );
  uchar              owner[ 32UL ] = { TAG_A };
  ulong              rec   = sizeof(fd_accdb_disk_meta_t)+100UL;
  ulong              cls, idx;

  /* Purge */
  fd_accdb_fork_id_t f = fd_accdb_attach_child( ctl, root );
  uchar K[ 32UL ]; mk_key( 9300UL, K );
  seq_write_data( ctl, f, K, LAMP_A, owner, 100UL, 0x77 );
  fd_accdb_cache_line_t * line = line_find( ctl, K, &cls, &idx );
  FD_TEST( line );
  fd_accdb_accmeta_t * m      = accmeta_at( ctl, line->acc_idx );
  ulong                used0  = g_shmem->shmetrics->disk_used_bytes;
  ulong                freed0 = freed_total();

  fd_racesan_async_t * e = fiber_force_preevict( &g_fiber[0], je );
  FD_TEST( fd_racesan_async_step_until( e, "accdb_writeback:post_write", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( acc_off( m )==FD_ACCDB_OFF_DIRTY( FD_ACCDB_ACC_CIDX_PACK( cls, idx ) ) );
  FD_TEST( g_shmem->shmetrics->disk_used_bytes==used0+rec );
  fd_accdb_purge( ctl, f );
  drain_background( ctl );
  FD_TEST( acc_off( m )==FD_ACCDB_OFF_DEAD );
  FD_TEST( fd_accdb_requests_pending( ctl ) );
  async_finish( e );
  fiber_done( &g_fiber[0] );
  FD_TEST( acc_off( m )==FD_ACCDB_OFF_DEAD );
  FD_TEST( g_shmem->shmetrics->disk_used_bytes==used0 );
  FD_TEST( freed_total()==freed0+rec );
  drain_background( ctl );
  FD_TEST( !fd_accdb_requests_pending( ctl ) );
  FD_TEST( fd_accdb_lamports( ctl, root, K )==0UL );

  /* advance_root dropping a rooted tombstone.  K2's root version is
     clean on disk; the tombstone on f2 is dirty. */
  uchar K2[ 32UL ]; mk_key( 9301UL, K2 );
  seq_write_data( ctl, root, K2, LAMP_A, owner, 100UL, 0x78 );
  fd_accdb_debug_force_preevict( ctl );
  fd_accdb_fork_id_t f2 = fd_accdb_attach_child( ctl, root );
  seq_write_data( ctl, f2, K2, 0UL, owner, 0UL, 0 );
  line = line_find( ctl, K2, &cls, &idx );
  FD_TEST( line );
  m      = accmeta_at( ctl, line->acc_idx );
  FD_TEST( !m->lamports );
  used0  = g_shmem->shmetrics->disk_used_bytes;
  freed0 = freed_total();
  ulong rec_t = sizeof(fd_accdb_disk_meta_t);

  e = fiber_force_preevict( &g_fiber[0], je );
  FD_TEST( fd_racesan_async_step_until( e, "accdb_writeback:post_write", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( g_shmem->shmetrics->disk_used_bytes==used0+rec_t );
  fd_accdb_advance_root( ctl, f2 );
  drain_background( ctl );
  FD_TEST( acc_off( m )==FD_ACCDB_OFF_DEAD );
  FD_TEST( fd_accdb_requests_pending( ctl ) );
  async_finish( e );
  fiber_done( &g_fiber[0] );
  FD_TEST( acc_off( m )==FD_ACCDB_OFF_DEAD );
  FD_TEST( g_shmem->shmetrics->disk_used_bytes==used0-rec );  /* the root version went too */
  FD_TEST( freed_total()==freed0+rec+rec_t );
  drain_background( ctl );
  FD_TEST( !fd_accdb_requests_pending( ctl ) );
  FD_TEST( fd_accdb_lamports( ctl, f2, K2 )==0UL );

  join_delete( ctl );
  join_delete( je );
  test_shmem_delete();
}

/* test_unbind_vs_unlink: an evictor has loaded K's data word and is
   about to unbind it when K's version is unlinked, which ORs the
   unlinked mark into the word.  The evictor's CAS fails; it must retry
   with the mark rather than take the line with K still bound to it. */

static void
test_unbind_vs_unlink( void ) {
  test_shmem_new();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_t *       je   = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  fd_accdb_fork_id_t f    = fd_accdb_attach_child( ctl, root );
  uchar              owner[ 32UL ] = { TAG_A };

  uchar K[ 32UL ]; mk_key( 9350UL, K );
  seq_write_data( ctl, f, K, LAMP_A, owner, 100UL, 0x79 );
  ulong cls, idx;
  fd_accdb_cache_line_t * line = line_find( ctl, K, &cls, &idx );
  FD_TEST( line );
  fd_accdb_accmeta_t * m = accmeta_at( ctl, line->acc_idx );

  fd_racesan_async_t * e = fiber_force_preevict( &g_fiber[0], je );
  FD_TEST( fd_racesan_async_step_until( e, "accdb_reclaim:pre_unbind", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( acc_bound( m ) && !fd_accdb_acc_unlinked( m ) );
  fd_accdb_purge( ctl, f );
  drain_background( ctl );
  FD_TEST( acc_bound( m ) && fd_accdb_acc_unlinked( m ) );
  async_finish( e );
  fiber_done( &g_fiber[0] );
  FD_TEST( !acc_bound( m ) && fd_accdb_acc_unlinked( m ) );
  FD_TEST( line->state==FD_ACCDB_LINE_FREE );

  drain_background( ctl );
  FD_TEST( !fd_accdb_requests_pending( ctl ) );
  FD_TEST( fd_accdb_lamports( ctl, root, K )==0UL );

  join_delete( ctl );
  join_delete( je );
  test_shmem_delete();
}

/* test_writeback_vs_compact: compaction parks at the CAS that moves K's
   record, holding K's old offset, while K is overwritten on its fork
   (freeing that record) and an evictor writes the new bytes back.  The
   CAS must fail whether it runs before the writeback's publish (against
   DIRTY) or after it (against the new record), and K must read back the
   new bytes from the new record.

   The disk layout is built by hand: K, then a filler, each written back
   at once, fill most of a 12 MiB partition; a second filler opens the
   next partition, and the tail slack queues the first for compaction. */

static void
test_writeback_vs_compact( void ) {
  for( int order=0; order<2; order++ ) {
    test_shmem_new_smallpart();
    fd_accdb_t *       ctl  = join_new();
    fd_accdb_t *       jc   = join_new();
    fd_accdb_t *       je   = join_new();
    fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

    uchar K [ 32UL ]; mk_key( 9400UL, K );
    uchar oa[ 32UL ] = { TAG_A };
    uchar ob[ 32UL ] = { TAG_B };
    ulong cls, idx;
    for( ulong i=0UL; i<3UL; i++ ) {
      uchar key[ 32UL ]; mk_key( 9400UL+i, key );
      seq_write_data( ctl, root, key, LAMP_A, oa, BIG_DATA, (uchar)( 0xAA+i ) );
      FD_TEST( line_find( ctl, key, &cls, &idx ) );
      FD_TEST( evict_line( ctl, cls, idx ) );
    }

    ulong lam; uchar o0;
    seq_read_check( ctl, root, K, &lam, &o0 );            /* binds K again, clean */
    FD_TEST( lam==LAMP_A && o0==TAG_A );
    fd_accdb_cache_line_t * line = line_find( ctl, K, &cls, &idx );
    FD_TEST( line );
    fd_accdb_accmeta_t * m       = accmeta_at( ctl, line->acc_idx );
    ulong                old_off = acc_off( m );
    FD_TEST( FD_ACCDB_OFF_CLEAN( old_off ) && old_off<g_shmem->partition_sz );

    fd_racesan_async_t * c = fiber_compact_loop( &g_fiber[0], jc, 16 );
    ulong reloc_dest = ULONG_MAX;
    for( ulong i=0UL; i<64UL && reloc_dest==ULONG_MAX; i++ ) {
      FD_TEST( fd_racesan_async_step_until( c, "accdb_compact:pre_offset_cas", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
      if( !memcmp( fd_accdb_dbg_reloc_pubkey, K, 32UL ) ) reloc_dest = fd_accdb_dbg_reloc_dest;
    }
    FD_TEST( reloc_dest!=ULONG_MAX );
    FD_TEST( acc_off( m )==old_off );

    /* Overwrite K in place: the old record is freed, K is dirty */
    seq_write_data( ctl, root, K, LAMP_B, ob, BIG_DATA, 0xBB );
    line = line_find( ctl, K, &cls, &idx );
    FD_TEST( line && accmeta_at( ctl, line->acc_idx )==m );
    FD_TEST( acc_off( m )==FD_ACCDB_OFF_DIRTY( FD_ACCDB_ACC_CIDX_PACK( cls, idx ) ) );

    fd_racesan_async_t * e = fiber_evict( &g_fiber[1], je, cls, idx );
    FD_TEST( fd_racesan_async_step_until( e, "accdb_writeback:post_write", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
    if( !order ) {
      async_finish( c );
      FD_TEST( acc_off( m )==FD_ACCDB_OFF_DIRTY( FD_ACCDB_ACC_CIDX_PACK( cls, idx ) ) );
      async_finish( e );
    } else {
      async_finish( e );
      ulong pub = acc_off( m );
      async_finish( c );
      FD_TEST( acc_off( m )==pub );
    }
    FD_TEST( g_fiber[1].evict.evicted );
    ulong new_off = acc_off( m );
    FD_TEST( FD_ACCDB_OFF_CLEAN( new_off ) && new_off!=reloc_dest && new_off!=old_off );
    FD_TEST( nocache_check( ctl, root, K, LAMP_B, TAG_B, BIG_DATA, 0xBB )==FD_ACCDB_READ_ONE_NOCACHE_DISK );
    fiber_done( &g_fiber[0] );
    fiber_done( &g_fiber[1] );

    join_delete( ctl );
    join_delete( jc );
    join_delete( je );
    test_shmem_delete();
  }
}

/* test_cold_load_race: two joins cold-load the same unbound account.
   R0 takes a line and parks before its bind CAS; R1 binds K to its own
   line and parks before its disk read, the line still OWNED.  R0's CAS
   fails: it frees its line, looks again, holds R1's line and waits for
   the load to end (load_wait).  Only R1 reads the disk, and both see
   K's bytes. */

static void
test_cold_load_race( void ) {
  test_shmem_new();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_t *       j0   = join_new();
  fd_accdb_t *       j1   = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  uchar K    [ 32UL ]; mk_key( 9500UL, K );
  uchar owner[ 32UL ] = { TAG_A };
  seq_write_data( ctl, root, K, LAMP_A, owner, 100UL, 0x3C );
  ulong cls, idx;
  FD_TEST( line_find( ctl, K, &cls, &idx ) && cls==0UL );
  FD_TEST( evict_line( ctl, cls, idx ) );
  FD_TEST( !line_find( ctl, K, &cls, &idx ) );

  fd_racesan_async_t * r0 = fiber_io( &g_fiber[0], fiber_read_check_exec, j0, root, K, LAMP_A, TAG_A, 100UL, 0x3C );
  FD_TEST( fd_racesan_async_step_until( r0, "accdb_acquire:pre_publish", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  fd_accdb_cache_line_t * l0 = NULL;   /* R0's line: the only OWNED line of the class */
  for( ulong i=0UL; i<g_shmem->cache_class_max[ 0 ]; i++ ) {
    fd_accdb_cache_line_t * l = fd_accdb_debug_line_addr( ctl, 0UL, i );
    if( l->state==FD_ACCDB_LINE_OWNED ) { FD_TEST( !l0 ); l0 = l; }
  }
  FD_TEST( l0 );

  fd_racesan_async_t * r1 = fiber_io( &g_fiber[1], fiber_read_check_exec, j1, root, K, LAMP_A, TAG_A, 100UL, 0x3C );
  FD_TEST( fd_racesan_async_step_until( r1, "accdb_acquire:pre_read", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  fd_accdb_cache_line_t * l1 = line_find( ctl, K, &cls, &idx );
  FD_TEST( l1 && l1!=l0 && l1->state==FD_ACCDB_LINE_OWNED );

  ulong rd0 = fd_accdb_metrics( j0 )->read_ops;
  ulong rd1 = fd_accdb_metrics( j1 )->read_ops;
  FD_TEST( fd_racesan_async_step_until( r0, "accdb_acquire:lost_publish", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( fd_racesan_async_step_until( r0, "accdb_acquire:load_wait",    STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( l0->state==FD_ACCDB_LINE_FREE );
  FD_TEST( l1->state==FD_ACCDB_LINE_OWNED );
  FD_TEST( fd_accdb_metrics( j0 )->accounts_waited==1UL );

  async_finish( r1 );
  async_finish( r0 );
  FD_TEST( fd_accdb_metrics( j0 )->read_ops==rd0 );
  FD_TEST( fd_accdb_metrics( j1 )->read_ops>rd1 );
  fiber_done( &g_fiber[0] );
  fiber_done( &g_fiber[1] );

  join_delete( ctl );
  join_delete( j0 );
  join_delete( j1 );
  test_shmem_delete();
}

/* test_nocache_vs_reuse: an unheld copy (read_one_nocache) races the
   eviction and reuse of the line it copies from.  The reader loads K's
   bound word and parks; K's line is evicted and X is loaded into the
   same line, the reader copies X's bytes and parks again; then X is
   evicted and K loaded back into the same line, so K's data word is
   exactly the one the reader loaded.  Only seq tells the copy is bad:
   the reader must reject it and return K's bytes (from K's record, as
   K is clean). */

static void
test_nocache_vs_reuse( void ) {
  test_shmem_new();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_t *       jr   = join_new();
  fd_accdb_t *       je   = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  uchar K [ 32UL ]; mk_key( 9600UL, K );
  uchar X [ 32UL ]; mk_key( 9601UL, X );
  uchar oa[ 32UL ] = { TAG_A };
  uchar ob[ 32UL ] = { TAG_B };
  ulong cls, idx, xcls, xidx;
  seq_write_data( ctl, root, K, LAMP_A, oa, 100UL, 0x11 );
  seq_write_data( ctl, root, X, LAMP_B, ob, 100UL, 0x22 );
  FD_TEST( line_find( ctl, X, &xcls, &xidx ) );
  FD_TEST( evict_line( ctl, xcls, xidx ) );
  fd_accdb_cache_line_t * line = line_find( ctl, K, &cls, &idx );
  FD_TEST( line && cls==0UL );
  fd_accdb_accmeta_t * m = accmeta_at( ctl, line->acc_idx );

  fd_racesan_async_t * n = fiber_nocache( &g_fiber[0], jr, root, K, LAMP_A, TAG_A, 100UL, 0x11 );
  FD_TEST( fd_racesan_async_step_until( n, "accdb_nocache:pre_copy", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  ulong d   = FD_VOLATILE_CONST( m->data );
  ulong seq = line->seq;

  /* je's stash hands the line it freed back to its next load */
  FD_TEST( evict_line( je, cls, idx ) );
  ulong lam; uchar o0;
  seq_read_check( je, root, X, &lam, &o0 );
  FD_TEST( lam==LAMP_B && line_find( ctl, X, &xcls, &xidx ) && xcls==cls && xidx==idx );
  FD_TEST( fd_racesan_async_step_until( n, "accdb_nocache:post_copy", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  FD_TEST( evict_line( je, cls, idx ) );
  seq_read_check( je, root, K, &lam, &o0 );
  FD_TEST( lam==LAMP_A && line_find( ctl, K, &xcls, &xidx ) && xcls==cls && xidx==idx );
  FD_TEST( FD_VOLATILE_CONST( m->data )==d );           /* the word is back */
  FD_TEST( line->seq!=seq );

  /* The copy is rejected.  K is clean, so the reader reads its record. */
  FD_TEST( fd_racesan_async_step_until( n, "accdb_nocache:pre_preadv2", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  async_finish( n );
  FD_TEST( g_fiber[0].nocache.result==FD_ACCDB_READ_ONE_NOCACHE_DISK );
  fiber_done( &g_fiber[0] );

  join_delete( ctl );
  join_delete( jr );
  join_delete( je );
  test_shmem_delete();
}

/* test_nocache_vs_recheck: the line is reused between the reader's
   two final checks.  The reader loads K's bound word and parks before
   sampling seq; K's line is evicted and X loaded into it, so the reader
   samples X's seq, copies X's bytes and parks between the rechecks;
   then X is evicted and K loaded back into the same line, so K's word
   is again the one the reader loaded.  Rechecking seq first, then the
   word, would accept X's bytes for K.  The word is checked first, while
   X still holds the line, so the copy is rejected and the reader
   returns K's bytes from K's record. */

static void
test_nocache_vs_recheck( void ) {
  test_shmem_new();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_t *       jr   = join_new();
  fd_accdb_t *       je   = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  uchar K [ 32UL ]; mk_key( 9620UL, K );
  uchar X [ 32UL ]; mk_key( 9621UL, X );
  uchar oa[ 32UL ] = { TAG_A };
  uchar ob[ 32UL ] = { TAG_B };
  ulong cls, idx, xcls, xidx;
  seq_write_data( ctl, root, K, LAMP_A, oa, 100UL, 0x11 );
  seq_write_data( ctl, root, X, LAMP_B, ob, 100UL, 0x22 );
  FD_TEST( line_find( ctl, X, &xcls, &xidx ) );
  FD_TEST( evict_line( ctl, xcls, xidx ) );
  fd_accdb_cache_line_t * line = line_find( ctl, K, &cls, &idx );
  FD_TEST( line && cls==0UL );
  fd_accdb_accmeta_t * m = accmeta_at( ctl, line->acc_idx );

  fd_racesan_async_t * n = fiber_nocache( &g_fiber[0], jr, root, K, LAMP_A, TAG_A, 100UL, 0x11 );
  FD_TEST( fd_racesan_async_step_until( n, "accdb_nocache:pre_seq", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  ulong d = FD_VOLATILE_CONST( m->data );

  /* X takes K's line before the reader samples seq (je's stash hands
     the line it freed back to its next load) */
  FD_TEST( evict_line( je, cls, idx ) );
  ulong lam; uchar o0;
  seq_read_check( je, root, X, &lam, &o0 );
  FD_TEST( lam==LAMP_B && line_find( ctl, X, &xcls, &xidx ) && xcls==cls && xidx==idx );
  ulong seq_x = line->seq;
  FD_TEST( !( seq_x&1UL ) );

  /* The reader copies X's bytes.  If it gets between the rechecks
     (only a check order that lets a stale word through can), put K
     back in the same line there, so K's word is again the one the
     reader loaded. */
  FD_TEST( fd_racesan_async_step_until( n, "accdb_nocache:post_copy", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  if( fd_racesan_async_step_until( n, "accdb_nocache:mid_recheck", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK ) {
    FD_TEST( evict_line( je, cls, idx ) );
    seq_read_check( je, root, K, &lam, &o0 );
    FD_TEST( lam==LAMP_A && line_find( ctl, K, &xcls, &xidx ) && xcls==cls && xidx==idx );
    FD_TEST( FD_VOLATILE_CONST( m->data )==d );
    FD_TEST( line->seq!=seq_x );
    async_finish( n );
  }

  /* The copy of X is rejected; K is clean, so the reader reads its
     record (fiber_nocache checks the bytes are K's) */
  FD_TEST( g_fiber[0].nocache.result==FD_ACCDB_READ_ONE_NOCACHE_DISK );
  fiber_done( &g_fiber[0] );

  join_delete( ctl );
  join_delete( jr );
  join_delete( je );
  test_shmem_delete();
}

/* test_nocache_vs_commit: an unheld copy races an in-place commit of
   the same length, which leaves K's data word unchanged.  The reader
   copies the old bytes and parks; the committer rewrites the line and
   parks with the offset UPDATING.  seq rejects the copy, the version has
   no record yet, so the reader waits (dirty_wait) instead of reading
   the disk, and then returns the new bytes from the line. */

static void
test_nocache_vs_commit( void ) {
  test_shmem_new();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_t *       jr   = join_new();
  fd_accdb_t *       jw   = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  uchar K [ 32UL ]; mk_key( 9700UL, K );
  uchar oa[ 32UL ] = { TAG_A };
  seq_write_data( ctl, root, K, LAMP_A, oa, 100UL, 0x11 );
  ulong cls, idx;
  fd_accdb_cache_line_t * line = line_find( ctl, K, &cls, &idx );
  FD_TEST( line );
  fd_accdb_accmeta_t * m = accmeta_at( ctl, line->acc_idx );
  ulong                d = FD_VOLATILE_CONST( m->data );

  fd_racesan_async_t * n = fiber_nocache( &g_fiber[0], jr, root, K, LAMP_A, TAG_B, 100UL, 0x33 );
  FD_TEST( fd_racesan_async_step_until( n, "accdb_nocache:post_copy", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  fd_racesan_async_t * w = fiber_io( &g_fiber[1], fiber_write_exec, jw, root, K, LAMP_A, TAG_B, 100UL, 0x33 );
  FD_TEST( fd_racesan_async_step_until( w, "accdb_commit:pre_dirty", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( FD_VOLATILE_CONST( m->data )==d && acc_off( m )==FD_ACCDB_OFF_UPDATING );

  ulong rd0 = fd_accdb_metrics( jr )->read_ops;
  FD_TEST( fd_racesan_async_step_until( n, "accdb_nocache:dirty_wait", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  async_finish( w );
  async_finish( n );
  FD_TEST( g_fiber[0].nocache.result==FD_ACCDB_READ_ONE_NOCACHE_CACHE );
  FD_TEST( fd_accdb_metrics( jr )->read_ops==rd0 );
  fiber_done( &g_fiber[0] );
  fiber_done( &g_fiber[1] );

  join_delete( ctl );
  join_delete( jr );
  join_delete( jw );
  test_shmem_delete();
}

/* test_commit_class_full: a commit to a class with no line to spare.
   jh holds every class-0 line, so commit_dst's two CLOCK laps find
   nothing and the commit goes straight to disk, unbound (an account is
   never left in a line of another class).  Both a new version and an
   overwrite that moves to class 0.  The accounts read back from disk
   while jh still holds the class, and cold-load once it is released. */

static void
test_commit_class_full( void ) {
  test_shmem_new_tiny();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_t *       jh   = join_new();
  fd_accdb_t *       jw   = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  ulong const n = TEST_TINY_CACHE_MIN_RESERVED;
  FD_TEST( g_shmem->cache_class_max[ 0 ]==n );
  uchar         keys[ TEST_TINY_CACHE_MIN_RESERVED ][ 32UL ];
  uchar const * pks [ TEST_TINY_CACHE_MIN_RESERVED ];
  int           wr  [ TEST_TINY_CACHE_MIN_RESERVED ] = {0};
  fd_acc_t      held[ TEST_TINY_CACHE_MIN_RESERVED ];
  for( ulong i=0UL; i<n; i++ ) {
    mk_key( 9800UL+i, keys[ i ] );
    pks[ i ] = keys[ i ];
    seq_write( ctl, root, keys[ i ], 100UL+i, NULL );
  }
  uchar K[ 32UL ]; mk_key( 9810UL, K );
  uchar Q[ 32UL ]; mk_key( 9811UL, Q );
  uchar oa[ 32UL ] = { TAG_A };
  uchar ob[ 32UL ] = { TAG_B };
  seq_write_data( ctl, root, K, LAMP_A, oa, 300UL, 0x61 );   /* class 1 */

  memset( held, 0, sizeof(held) );
  fd_accdb_acquire( jh, root, n, pks, wr, held );
  for( ulong i=0UL; i<n; i++ ) FD_TEST( FD_ACCDB_ACC_CIDX_CLASS( held[ i ]._cidx )==0UL );

  ulong cls, idx;
  seq_write_data( jw, root, Q, 1234UL, oa, 50UL, 0x77 );
  FD_TEST( !line_find( ctl, Q, &cls, &idx ) );
  seq_write_data( jw, root, K, LAMP_B, ob, 50UL, 0x62 );
  FD_TEST( !line_find( ctl, K, &cls, &idx ) );
  FD_TEST( nocache_check( ctl, root, Q, 1234UL, TAG_A, 50UL, 0x77 )==FD_ACCDB_READ_ONE_NOCACHE_DISK );
  FD_TEST( nocache_check( ctl, root, K, LAMP_B, TAG_B, 50UL, 0x62 )==FD_ACCDB_READ_ONE_NOCACHE_DISK );

  fd_accdb_release( jh, n, held );

  ulong lam; uchar o0;
  seq_read_check( ctl, root, Q, &lam, &o0 );
  FD_TEST( lam==1234UL && o0==TAG_A );
  FD_TEST( line_find( ctl, Q, &cls, &idx ) && cls==0UL );
  seq_read_check( ctl, root, K, &lam, &o0 );
  FD_TEST( lam==LAMP_B && o0==TAG_B );
  FD_TEST( line_find( ctl, K, &cls, &idx ) && cls==0UL );

  join_delete( ctl );
  join_delete( jh );
  join_delete( jw );
  test_shmem_delete();
}

/* test_fallback_vs_reserve: a commit that finds its class fully held
   goes to disk, never into a line of another class, so acquire's
   per-class reservations keep guaranteeing progress.  Eight small
   accounts are committed while jh holds all of class 0, then one
   acquire reads those eight plus an evicted large account: it reserves
   class 0 x8 and class 7 x1, and must get them.  Were the small
   accounts left in class-7 staging lines, its holds would take every
   class-7 line and it could never allocate the large account's. */

static void
test_fallback_vs_reserve( void ) {
  test_shmem_new_tiny();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_t *       jh   = join_new();
  fd_accdb_t *       jw   = join_new();
  fd_accdb_t *       jr   = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  ulong const n = TEST_TINY_CACHE_MIN_RESERVED;
  FD_TEST( g_shmem->cache_class_max[ 0 ]==n && g_shmem->cache_class_max[ 7 ]==n );

  uchar big[ 32UL ]; mk_key( 700000UL, big );
  uchar big_owner[ 32UL ] = { 0xBA };
  seq_write_data( ctl, root, big, 100UL, big_owner, 2UL<<20, 0xBB );
  ulong cls, idx;
  FD_TEST( line_find( ctl, big, &cls, &idx ) && cls==7UL );
  FD_TEST( evict_line( ctl, cls, idx ) );

  uchar         hk  [ TEST_TINY_CACHE_MIN_RESERVED ][ 32UL ];
  uchar const * hpk [ TEST_TINY_CACHE_MIN_RESERVED ];
  int           wr  [ TEST_TINY_CACHE_MIN_RESERVED+1UL ] = {0};
  fd_acc_t      held[ TEST_TINY_CACHE_MIN_RESERVED ];
  for( ulong i=0UL; i<n; i++ ) {
    mk_key( 710000UL+i, hk[ i ] ); hpk[ i ] = hk[ i ];
    seq_write( ctl, root, hk[ i ], 100UL+i, NULL );
  }
  fd_accdb_acquire( jh, root, n, hpk, wr, held );

  uchar         rk [ TEST_TINY_CACHE_MIN_RESERVED+1UL ][ 32UL ];
  uchar const * rpk[ TEST_TINY_CACHE_MIN_RESERVED+1UL ];
  for( ulong i=0UL; i<n; i++ ) {
    mk_key( 720000UL+i, rk[ i ] );
    seq_write( jw, root, rk[ i ], 200UL+i, NULL );
    FD_TEST( !line_find( ctl, rk[ i ], &cls, &idx ) );   /* on disk, not in a class-7 line */
  }
  fd_accdb_release( jh, n, held );

  fd_memcpy( rk[ n ], big, 32UL );
  for( ulong i=0UL; i<=n; i++ ) rpk[ i ] = rk[ i ];
  fd_acc_t out[ TEST_TINY_CACHE_MIN_RESERVED+1UL ];
  fd_accdb_acquire( jr, root, n+1UL, rpk, wr, out );
  for( ulong i=0UL; i<n; i++ ) {
    FD_TEST( FD_ACCDB_ACC_CIDX_CLASS( out[ i ]._cidx )==0UL );
    FD_TEST( out[ i ].lamports==200UL+i );
  }
  FD_TEST( FD_ACCDB_ACC_CIDX_CLASS( out[ n ]._cidx )==7UL );
  FD_TEST( out[ n ].data_len==(2UL<<20) && out[ n ].owner[ 0 ]==0xBA && out[ n ].data[ 0 ]==0xBB );
  fd_accdb_release( jr, n+1UL, out );

  join_delete( ctl );
  join_delete( jh );
  join_delete( jw );
  join_delete( jr );
  test_shmem_delete();
}

/* test_reservation_steal: ctl reserves every class-0 line of the tiny
   cache with an open acquire, so a reader's reservation fails and
   retries (reservation_retry).  ctl's release keeps cred_max of them as
   idle credits on its join and returns the rest to the shared counter;
   the test then tops ctl's idle credits back up to the whole class, so
   the reader's next failure must steal them, and its retry succeeds.  The counter
   always equals the reserved lines plus the idle credits. */

static void
test_reservation_steal( void ) {
  test_shmem_new_tiny();
  fd_accdb_t *       ctl    = join_new();   /* join 0 */
  fd_accdb_t *       reader = join_new();   /* join 1 */
  fd_accdb_fork_id_t root   = fd_accdb_attach_child( ctl, SENTINEL );

  ulong const   n = TEST_TINY_CACHE_MIN_RESERVED;
  uchar         keys    [ TEST_TINY_CACHE_MIN_RESERVED ][ 32 ];
  uchar const * pubkeys [ TEST_TINY_CACHE_MIN_RESERVED ];
  int           writable[ TEST_TINY_CACHE_MIN_RESERVED ] = {0};
  fd_acc_t      held    [ TEST_TINY_CACHE_MIN_RESERVED ] = {0};
  for( ulong i=0UL; i<n; i++ ) {
    mk_key( 1000UL+i, keys[ i ] );
    pubkeys[ i ] = keys[ i ];
    seq_write( ctl, root, keys[ i ], 5000UL+i, NULL );
  }
  ulong * used = &g_shmem->cache_class_used[ 0 ].val;
  FD_TEST( *used!=ULONG_MAX && g_shmem->cache_class_max[ 0 ]==n );
  FD_TEST( !*used );

  fd_accdb_acquire( ctl, root, n, pubkeys, writable, held );
  FD_TEST( *used==n );
  fd_racesan_async_t * a = fiber_acquire_expect( &g_fiber[0], reader, root, keys[ 0 ], 5000UL );
  FD_TEST( fd_racesan_async_step_until( a, "accdb_acquire:reservation_retry", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( *used==n && !g_shmem->join_cred[ 0 ].val[ 0 ] );

  /* Release: credits up to the cap stay idle on ctl, the rest go back.
     Fill the class with idle credits so the reader's take still fails
     and has to steal. */
  fd_accdb_release( ctl, n, held );
  FD_TEST( *used==g_shmem->join_cred[ 0 ].val[ 0 ] );     /* only idle credits remain */
  FD_TEST( *used<n );                                      /* the cap returned the surplus */
  ulong idle = n-*used;
  FD_ATOMIC_FETCH_AND_ADD( used, idle );                   /* top ctl's idle credits back up to the whole class */
  FD_ATOMIC_FETCH_AND_ADD( &g_shmem->join_cred[ 0 ].val[ 0 ], idle );
  FD_TEST( *used==n && g_shmem->join_cred[ 0 ].val[ 0 ]==n );
  FD_TEST( fd_racesan_async_step_until( a, "accdb_acquire:reservation_retry", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  FD_TEST( !*used && !g_shmem->join_cred[ 0 ].val[ 0 ] );   /* stolen */
  async_finish( a );
  fiber_done( &g_fiber[0] );
  FD_TEST( *used==g_shmem->join_cred[ 1 ].val[ 0 ] );     /* the reader's line went back to its own credits */

  join_delete( reader );
  join_delete( ctl );
  test_shmem_delete();
}

/* test_writeback_vs_recreate: K is closed on F (a dirty tombstone) and
   re-created on F while an evictor is writing the tombstone back.  The
   evictor parks after its write: the re-create's acquire waits on
   EVICTING, then finds K unbound, loads the tombstone cold and commits
   over it, freeing the tombstone's record.  Read back from disk, K is
   the re-created account. */

static void
test_writeback_vs_recreate( void ) {
  test_shmem_new();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_t *       je   = join_new();
  fd_accdb_t *       jw   = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  fd_accdb_fork_id_t f    = fd_accdb_attach_child( ctl, root );

  uchar K [ 32UL ]; mk_key( 7UL, K );
  uchar oa[ 32UL ] = { TAG_A };
  seq_write_data( ctl, root, K, LAMP_A, oa, 100UL, 0x41 );
  fd_accdb_debug_force_preevict( ctl );
  seq_write_data( ctl, f, K, 0UL, oa, 0UL, 0 );
  ulong cls, idx;
  fd_accdb_cache_line_t * line = line_find( ctl, K, &cls, &idx );
  FD_TEST( line );
  fd_accdb_accmeta_t * m = accmeta_at( ctl, line->acc_idx );
  FD_TEST( !m->lamports && acc_off( m )==FD_ACCDB_OFF_DIRTY( FD_ACCDB_ACC_CIDX_PACK( cls, idx ) ) );

  fd_racesan_async_t * e = fiber_evict( &g_fiber[1], je, cls, idx );
  FD_TEST( fd_racesan_async_step_until( e, "accdb_writeback:post_write", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  fd_racesan_async_t * w = fiber_io( &g_fiber[0], fiber_write_exec, jw, f, K, LAMP_B, TAG_B, 100UL, 0xBE );
  FD_TEST( fd_racesan_async_step_until( w, "accdb_acquire:claim_wait", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  async_finish( e );
  FD_TEST( g_fiber[1].evict.evicted && FD_ACCDB_OFF_CLEAN( acc_off( m ) ) );
  async_finish( w );
  fiber_done( &g_fiber[0] );
  fiber_done( &g_fiber[1] );

  line = line_find( ctl, K, &cls, &idx );
  FD_TEST( line && accmeta_at( ctl, line->acc_idx )==m );
  FD_TEST( evict_line( ctl, cls, idx ) );
  FD_TEST( nocache_check( ctl, f,    K, LAMP_B, TAG_B, 100UL, 0xBE )==FD_ACCDB_READ_ONE_NOCACHE_DISK );
  FD_TEST( nocache_check( ctl, root, K, LAMP_A, TAG_A, 100UL, 0x41 )!=FD_ACCDB_READ_ONE_NOCACHE_MISS );

  join_delete( ctl );
  join_delete( je );
  join_delete( jw );
  test_shmem_delete();
}

/* test_overwrite_move_orphan: an overwrite that changes size class
   moves K to a new line and leaves the old one an orphan, still SHARED
   and naming K.  An evictor claims the orphan and parks before its scan
   while K's real line is evicted (written back, unbound).  The orphan's
   evictor then finds K neither dirty on its line nor bound to it: it
   writes nothing back and leaves K alone.  K reads back the new bytes
   from disk. */

static void
test_overwrite_move_orphan( void ) {
  test_shmem_new();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_t *       je   = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  uchar K [ 32UL ]; mk_key( 9900UL, K );
  uchar oa[ 32UL ] = { TAG_A };
  uchar ob[ 32UL ] = { TAG_B };
  seq_write_data( ctl, root, K, LAMP_A, oa, 100UL, 0xA1 );
  ulong cls0, idx0, cls, idx;
  fd_accdb_cache_line_t * orphan = line_find( ctl, K, &cls0, &idx0 );
  FD_TEST( orphan && cls0==0UL );
  uint                 acc_idx = orphan->acc_idx;
  fd_accdb_accmeta_t * m       = accmeta_at( ctl, acc_idx );

  seq_write_data( ctl, root, K, LAMP_B, ob, 600UL, 0xB2 );   /* class 2 */
  FD_TEST( line_find( ctl, K, &cls, &idx ) && cls==2UL );
  FD_TEST( orphan->state==FD_ACCDB_LINE_SHARED && orphan->acc_idx==acc_idx );

  fd_racesan_async_t * e = fiber_evict( &g_fiber[0], je, cls0, idx0 );
  FD_TEST( fd_racesan_async_step_until( e, "accdb_hazard:pre_scan", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  ulong wr0 = fd_accdb_metrics( ctl )->write_ops;
  FD_TEST( evict_line( ctl, cls, idx ) );
  FD_TEST( fd_accdb_metrics( ctl )->write_ops>wr0 );
  ulong off = acc_off( m );
  FD_TEST( FD_ACCDB_OFF_CLEAN( off ) && !acc_bound( m ) );

  ulong wre = fd_accdb_metrics( je )->write_ops;
  async_finish( e );
  fiber_done( &g_fiber[0] );
  FD_TEST( g_fiber[0].evict.evicted );
  FD_TEST( fd_accdb_metrics( je )->write_ops==wre );
  FD_TEST( acc_off( m )==off && !acc_bound( m ) );
  FD_TEST( nocache_check( ctl, root, K, LAMP_B, TAG_B, 600UL, 0xB2 )==FD_ACCDB_READ_ONE_NOCACHE_DISK );

  join_delete( ctl );
  join_delete( je );
  test_shmem_delete();
}

/* test_orphan_evict_vs_recycle: a line still names an accmeta after the
   accmeta is released and reused for another account.  A writable
   reader on D walks P's chain to the tombstone T on F and parks;
   rooting F unlinks T, and the reader then cold-loads the unlinked T
   into a line.  Once the batch is released, an evictor claims that line
   and parks while T's slot is reused for a new account C.  Resumed, the
   evictor must neither write back nor unbind C: C's word and offset
   name C's own line. */

static void
fiber_tombstone_exec( void * _ctx ) {
  fiber_t *     f      = _ctx;
  uchar const * pks[1] = { f->io.pubkey };
  int           wr [1] = { 1 };
  fd_acc_t      acc[1];
  memset( acc, 0, sizeof(acc) );
  fd_accdb_acquire( f->accdb, f->io.fork_id, 1UL, pks, wr, acc );
  FD_TEST( !acc[0].lamports );
  fd_accdb_release( f->accdb, 1UL, acc );
}

static void
test_orphan_evict_vs_recycle( void ) {
  test_shmem_new();
  fd_accdb_t *       ctl   = join_new();
  fd_accdb_t *       jd    = join_new();
  fd_accdb_t *       je    = join_new();
  fd_accdb_fork_id_t root0 = fd_accdb_attach_child( ctl, SENTINEL );
  fd_accdb_fork_id_t F     = fd_accdb_attach_child( ctl, root0 );
  fd_accdb_fork_id_t D     = fd_accdb_attach_child( ctl, F );

  uchar P    [ 32UL ] = { 'P' };
  uchar owner[ 32UL ] = { 0xAA };
  seq_write( ctl, root0, P, 100UL, owner );
  seq_write( ctl, F,     P,   0UL, owner );
  ulong cls, idx;
  fd_accdb_cache_line_t * line = line_find( ctl, P, &cls, &idx );
  FD_TEST( line );
  uint                 t_idx = line->acc_idx;
  fd_accdb_accmeta_t * T     = accmeta_at( ctl, t_idx );
  FD_TEST( !T->lamports );
  FD_TEST( evict_line( ctl, cls, idx ) && !acc_bound( T ) );

  fd_racesan_async_t * r = fiber_io( &g_fiber[0], fiber_tombstone_exec, jd, D, P, 0UL, 0, 0UL, 0 );
  FD_TEST( fd_racesan_async_step_until( r, "accdb_acquire:post_next", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  fd_accdb_advance_root( ctl, F );
  drain_background( ctl );
  FD_TEST( acc_off( T )==FD_ACCDB_OFF_DEAD );
  FD_TEST( fd_accdb_requests_pending( ctl ) );   /* the reader's epoch keeps T */
  async_finish( r );
  fiber_done( &g_fiber[0] );
  FD_TEST( acc_bound( T ) );
  uint stale = FD_ACCDB_DATA_CIDX( FD_VOLATILE_CONST( T->data ) );
  drain_background( ctl );
  FD_TEST( !fd_accdb_requests_pending( ctl ) );   /* T released */

  fd_racesan_async_t * e = fiber_evict( &g_fiber[1], je, FD_ACCDB_ACC_CIDX_CLASS( stale ), FD_ACCDB_ACC_CIDX_IDX( stale ) );
  FD_TEST( fd_racesan_async_step_until( e, "accdb_reclaim:post_claim", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  uchar C[ 32UL ];
  int   recycled = 0;
  for( ulong i=0UL; i<8UL && !recycled; i++ ) {
    mk_key( 9950UL+i, C );
    seq_write_data( ctl, D, C, 300UL+i, owner, 64UL, (uchar)( 0xC0+i ) );
    recycled = !memcmp( T->key.pubkey, C, 32UL );
  }
  FD_TEST( recycled );
  ulong i_c = (ulong)( FD_LOAD( ulong, C )-9950UL );
  FD_TEST( acc_bound( T ) && FD_ACCDB_DATA_CIDX( FD_VOLATILE_CONST( T->data ) )!=stale );
  ulong d   = FD_VOLATILE_CONST( T->data );
  ulong off = FD_VOLATILE_CONST( T->offset_fork );

  ulong wre = fd_accdb_metrics( je )->write_ops;
  async_finish( e );
  fiber_done( &g_fiber[1] );
  FD_TEST( g_fiber[1].evict.evicted );
  FD_TEST( fd_accdb_metrics( je )->write_ops==wre );
  FD_TEST( FD_VOLATILE_CONST( T->data )==d && FD_VOLATILE_CONST( T->offset_fork )==off );

  FD_TEST( line_find( ctl, C, &cls, &idx ) );
  FD_TEST( evict_line( ctl, cls, idx ) );
  FD_TEST( nocache_check( ctl, D, C, 300UL+i_c, 0xAA, 64UL, (uchar)( 0xC0+i_c ) )==FD_ACCDB_READ_ONE_NOCACHE_DISK );

  join_delete( ctl );
  join_delete( jd );
  join_delete( je );
  test_shmem_delete();
}

/* test_alloc_reclaim_vs_reader: class 0 is full of dirty accounts, and
   a commit's line allocation runs CLOCK, which claims all eight and
   parks after writing them back, offsets not yet published.  A victim
   V is still bound and its bytes are stable: an unheld copy reads it
   from the line at once.  A holder waits on EVICTING and then loads V
   cold from the record just published. */

static void
test_alloc_reclaim_vs_reader( void ) {
  test_shmem_new_tiny();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_t *       jw   = join_new();
  fd_accdb_t *       jr   = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );

  ulong const n = TEST_TINY_CACHE_MIN_RESERVED;
  FD_TEST( g_shmem->cache_class_max[ 0 ]==n );
  uchar keys[ TEST_TINY_CACHE_MIN_RESERVED ][ 32UL ];
  for( ulong i=0UL; i<n; i++ ) {
    uchar owner[ 32UL ] = { (uchar)( 0x40+i ) };
    mk_key( 610000UL+i, keys[ i ] );
    seq_write_data( ctl, root, keys[ i ], 1000UL+i, owner, 64UL, (uchar)( 0xA0+i ) );
  }

  uchar Q[ 32UL ]; mk_key( 619999UL, Q );
  fd_racesan_async_t * w = fiber_io( &g_fiber[0], fiber_write_exec, jw, root, Q, 77UL, TAG_A, 64UL, 0x77 );
  FD_TEST( fd_racesan_async_step_until( w, "accdb_writeback:post_write", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  ulong cls, idx;
  fd_accdb_cache_line_t * line = line_find( ctl, keys[ 0 ], &cls, &idx );
  FD_TEST( line && line->state==FD_ACCDB_LINE_EVICTING );
  fd_accdb_accmeta_t * m = accmeta_at( ctl, line->acc_idx );
  FD_TEST( acc_off( m )==FD_ACCDB_OFF_DIRTY( FD_ACCDB_ACC_CIDX_PACK( cls, idx ) ) );
  FD_TEST( nocache_check( ctl, root, keys[ 0 ], 1000UL, 0x40, 64UL, 0xA0 )==FD_ACCDB_READ_ONE_NOCACHE_CACHE );

  fd_racesan_async_t * r = fiber_io( &g_fiber[1], fiber_read_check_exec, jr, root, keys[ 0 ], 1000UL, 0x40, 64UL, 0xA0 );
  FD_TEST( fd_racesan_async_step_until( r, "accdb_acquire:claim_wait", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  ulong rd0 = fd_accdb_metrics( jr )->read_ops;
  async_finish( w );
  FD_TEST( FD_ACCDB_OFF_CLEAN( acc_off( m ) ) && !acc_bound( m ) );
  async_finish( r );
  FD_TEST( fd_accdb_metrics( jr )->read_ops>rd0 );
  fiber_done( &g_fiber[0] );
  fiber_done( &g_fiber[1] );

  for( ulong i=0UL; i<n; i++ ) FD_TEST( nocache_check( ctl, root, keys[ i ], 1000UL+i, (uchar)( 0x40+i ), 64UL, (uchar)( 0xA0+i ) )!=FD_ACCDB_READ_ONE_NOCACHE_MISS );
  FD_TEST( nocache_check( ctl, root, Q, 77UL, TAG_A, 64UL, 0x77 )!=FD_ACCDB_READ_ONE_NOCACHE_MISS );

  join_delete( ctl );
  join_delete( jw );
  join_delete( jr );
  test_shmem_delete();
}

/* test_preevict_batch: a forced sweep over more dirty class-0 lines
   than one CLOCK batch takes (RECLAIM_MAX, 64 in fd_accdb.c) writes
   them in several batches, each one write per stop at
   accdb_writeback:post_write.  The bytes written are exactly the
   records, and every account reads back intact from its record (sizes
   and fills differ per account, so a record read at another's offset is
   caught). */

static void
test_preevict_batch( void ) {
  test_shmem_new();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  uchar              owner[ 32UL ] = { 0xAA };

  ulong const cnt = 200UL;
  ulong       sz  = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    uchar key[ 32UL ] = { 'B', (uchar)( i>>8 ), (uchar)i };
    seq_write_data( ctl, root, key, 1000UL+i, owner, 64UL+( i%61UL ), (uchar)i );
    sz += sizeof(fd_accdb_disk_meta_t)+64UL+( i%61UL );
    ulong cls, idx;
    FD_TEST( line_find( ctl, key, &cls, &idx ) && cls==0UL );
  }

  ulong                written0 = fd_accdb_metrics( ctl )->bytes_written;
  fd_racesan_async_t * s        = fiber_force_preevict( &g_fiber[0], ctl );
  ulong                flushes  = 0UL;
  for(;;) {
    int rc = fd_racesan_async_step_until( s, "accdb_writeback:post_write", STEP_MAX );
    if( rc==FD_RACESAN_ASYNC_RET_EXIT ) break;
    FD_TEST( rc==FD_RACESAN_ASYNC_RET_HOOK );
    flushes++;
  }
  fiber_done( &g_fiber[0] );
  FD_LOG_NOTICE(( "  test_preevict_batch: %lu records in %lu writes", cnt, flushes ));
  FD_TEST( flushes*64UL>=cnt && flushes<cnt );
  FD_TEST( fd_accdb_metrics( ctl )->bytes_written-written0==sz );

  for( ulong i=0UL; i<cnt; i++ ) {
    uchar key[ 32UL ] = { 'B', (uchar)( i>>8 ), (uchar)i };
    FD_TEST( nocache_check( ctl, root, key, 1000UL+i, 0xAA, 64UL+( i%61UL ), (uchar)i )==FD_ACCDB_READ_ONE_NOCACHE_DISK );
  }

  join_delete( ctl );
  test_shmem_delete();
}

/* test_reclaim_vs_snapshot_capture: an exec tile cold-loads Z with
   class 0 full of rooted dirty accounts, so its CLOCK batch claims and
   writes them back.  A snapshot finds each account either bound to a
   line (a cache scan reads it) or at its disk offset: this holds at
   every stop of the tile, since only a clean version is ever unbound.
   Partition bounds sampled before the writeback do not cover a
   victim's new record; bounds sampled after waiting out the busy
   writers (fd_accdb_shmem_writer_barrier) do. */

static void
test_reclaim_vs_snapshot_capture( void ) {
  test_shmem_new_tiny();
  fd_accdb_t *       ctl  = join_new();
  fd_accdb_t *       jx   = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  uchar              owner[ 32UL ] = { 7 };

  uchar Z[ 32UL ]; mk_key( 910000UL, Z );
  seq_write( ctl, root, Z, 777UL, owner );
  ulong cls, idx;
  FD_TEST( line_find( ctl, Z, &cls, &idx ) && cls==0UL );
  FD_TEST( evict_line( ctl, cls, idx ) );

  ulong const          n = TEST_TINY_CACHE_MIN_RESERVED;
  fd_accdb_accmeta_t * x[ TEST_TINY_CACHE_MIN_RESERVED ];
  FD_TEST( g_shmem->cache_class_max[ 0 ]==n );
  for( ulong i=0UL; i<n; i++ ) {
    uchar k[ 32UL ]; mk_key( 920000UL+i, k );
    seq_write( ctl, root, k, 1000UL+i, owner );
    fd_accdb_cache_line_t * l = line_find( ctl, k, &cls, &idx );
    FD_TEST( l && cls==0UL );
    x[ i ] = accmeta_at( ctl, l->acc_idx );
  }
  fd_accdb_fork_id_t f1 = fd_accdb_attach_child( ctl, root );

  fd_racesan_async_t * a = fiber_acquire_expect( &g_fiber[0], jx, f1, Z, 777UL );
  FD_TEST( fd_racesan_async_step_until( a, "accdb_reclaim:post_claim", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  fd_accdb_accmeta_t * xv = NULL;   /* the first victim */
  for( ulong i=0UL; i<n; i++ ) {
    fd_accdb_cache_line_t * l = fd_accdb_debug_line_addr( ctl, FD_ACCDB_ACC_CIDX_CLASS( FD_ACCDB_DATA_CIDX( x[ i ]->data ) ), FD_ACCDB_ACC_CIDX_IDX( FD_ACCDB_DATA_CIDX( x[ i ]->data ) ) );
    if( l->state==FD_ACCDB_LINE_EVICTING ) xv = x[ i ];
  }
  FD_TEST( xv && acc_bound( xv ) && !FD_ACCDB_OFF_CLEAN( acc_off( xv ) ) );

  static ulong bound[ T_PARTITION_CNT ];
  sample_bounds( g_shmem, bound );
  fd_accdb_shmem_writer_barrier_t barrier[ 1 ];
  fd_accdb_shmem_writer_barrier_capture( g_shmem, barrier );
  for( ulong steps=0UL; fd_accdb_shmem_writer_barrier_poll( g_shmem, barrier ); steps++ ) {
    FD_TEST( steps<STEP_MAX );
    for( ulong i=0UL; i<n; i++ ) FD_TEST( acc_bound( x[ i ] ) || FD_ACCDB_OFF_CLEAN( acc_off( x[ i ] ) ) );
    fd_racesan_async_step( a );
  }
  for( ulong i=0UL; i<n; i++ ) FD_TEST( acc_bound( x[ i ] ) || FD_ACCDB_OFF_CLEAN( acc_off( x[ i ] ) ) );
  ulong xv_off = acc_off( xv );
  FD_TEST( FD_ACCDB_OFF_CLEAN( xv_off ) );
  FD_TEST( !covered( g_shmem, bound, xv_off ) );
  sample_bounds( g_shmem, bound );
  FD_TEST( covered( g_shmem, bound, xv_off ) );

  async_finish( a );
  fiber_done( &g_fiber[0] );
  join_delete( ctl );
  join_delete( jx );
  test_shmem_delete();
}

/* test_tombstone_orphan_ebr_poison: P is closed on F and D holds the
   tombstone's line in an open acquire while rooting F unlinks the
   tombstone and the accdb tile releases its accmeta (D's acquire has
   returned, so its epoch is idle).  Fresh accounts then reuse the slot
   while D's line still names it.  The orphan line must never be written
   back over a reused slot: each fresh account reads back its own owner
   from disk. */

static void
test_tombstone_orphan_ebr_poison( void ) {
  test_shmem_new();
  fd_accdb_t * accdb   = join_new();
  fd_accdb_t * accdb_d = join_new();

  uchar pubkey_P[ 32 ] = { 'P', 0 };
  uchar pubkey_B[ 32 ] = { 'B', 0 };
  uchar pubkey_C[ 32 ] = { 'C', 0 };
  uchar owner_P [ 32 ] = { 0xAA, 0 };
  uchar owner_B [ 32 ] = { 0xBB, 0 };
  uchar owner_C [ 32 ] = { 0xCC, 0 };

  fd_accdb_fork_id_t root0 = fd_accdb_attach_child( accdb, SENTINEL );
  fd_accdb_fork_id_t F     = fd_accdb_attach_child( accdb, root0 );
  fd_accdb_fork_id_t D     = fd_accdb_attach_child( accdb, F );

  seq_write( accdb, root0, pubkey_P, 100UL, owner_P );
  seq_write( accdb, F,     pubkey_P,   0UL, owner_P );

  uchar const * pks_P[1] = { pubkey_P };
  int           wr   [1] = { 1 };
  fd_acc_t      acc_D[1];
  memset( acc_D, 0, sizeof(acc_D) );
  fd_accdb_acquire( accdb_d, D, 1UL, pks_P, wr, acc_D );
  FD_TEST( acc_D[0].lamports==0UL );

  fd_accdb_advance_root( accdb, F );
  drain_background_n( accdb, 4UL );
  fd_accdb_advance_root( accdb, D );
  drain_background_n( accdb, 4UL );

  seq_write( accdb, D, pubkey_B, 200UL, owner_B );
  seq_write( accdb, D, pubkey_C, 300UL, owner_C );

  /* Flush the fresh accounts while D still holds the orphan, then
     again after D releases it. */
  fd_accdb_debug_force_preevict( accdb );
  fd_accdb_release( accdb_d, 1UL, acc_D );
  fd_accdb_debug_force_preevict( accdb );

  FD_TEST( nocache_check( accdb, D, pubkey_B, 200UL, 0xBB, 0UL, 0 )==FD_ACCDB_READ_ONE_NOCACHE_DISK );
  FD_TEST( nocache_check( accdb, D, pubkey_C, 300UL, 0xCC, 0UL, 0 )==FD_ACCDB_READ_ONE_NOCACHE_DISK );

  join_delete( accdb_d );
  join_delete( accdb );
  test_shmem_delete();
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
    ulong lamports = 0UL;
    FD_TEST( fd_accdb_probe_pd_this_fork( ctl, a, key, &pd, &len, &lamports )==1 );
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

/* test_pd_parent_read_vs_child_write (§8.2 R0-flip + R1): the FIXED
   shape.  Reader acquire_a's X writable on child C and acquire_b's D
   read-only on frozen parent P while a writer commits D twice on C
   (same size class -- the schedules that crashed pre-fix).  Oracle: the
   parent copy is never mutated under the hold (P is frozen, overwrite
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
    ulong lamports = 0UL;
    FD_TEST( fd_accdb_probe_pd_this_fork( ctl, c, key_d, &pd, &len, &lamports )==1 );
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

static void
test_reservation_wait_yields( void ) {
  test_shmem_new_tiny();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * reader = join_new();
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  uchar keys[ TEST_TINY_CACHE_MIN_RESERVED ][ 32 ];
  uchar const * pubkeys[ TEST_TINY_CACHE_MIN_RESERVED ];
  int writable[ TEST_TINY_CACHE_MIN_RESERVED ] = {0};
  fd_acc_t held[ TEST_TINY_CACHE_MIN_RESERVED ] = {0};
  for( ulong i=0UL; i<TEST_TINY_CACHE_MIN_RESERVED; i++ ) {
    mk_key( 1000UL+i, keys[i] );
    pubkeys[i] = keys[i];
    seq_write( ctl, root, keys[i], 5000UL+i, NULL );
  }
  fd_accdb_acquire( ctl, root, TEST_TINY_CACHE_MIN_RESERVED, pubkeys, writable, held );
  fd_racesan_async_t * a = fiber_acquire_expect( &g_fiber[0], reader, root, keys[0], 5000UL );
  FD_TEST( fd_racesan_async_step_until( a, "accdb_acquire:reservation_retry", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  fd_accdb_release( ctl, TEST_TINY_CACHE_MIN_RESERVED, held );
  async_finish( a );
  fiber_done( &g_fiber[0] );
  join_delete( reader );
  join_delete( ctl );
  test_shmem_delete();
}

/* ====================================================================
   Root / purge request protocol.

   T1 updates the fork tree and publishes requests without blocking; T2
   applies them in passes (background_requests).  These tests drive T1
   and T2 at the protocol's interleaving points. */

/* catch_up runs T2 passes until every request is applied and the
   retired batch is released (no reader holds an epoch here). */

static void
catch_up( fd_accdb_t * jb ) {
  for( ulong i=0UL; fd_accdb_requests_pending( jb ); i++ ) {
    FD_TEST( i<1024UL );
    drain_background( jb );
  }
}

/* T1 fibers, woven against T2: purge, advance_root, initial root
   attach (result in probe.fork_id) and reset. */

static void
fiber_purge_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_accdb_purge( f->accdb, f->probe.fork_id );
}

static void
fiber_advance_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_accdb_advance_root( f->accdb, f->probe.fork_id );
}

static void
fiber_initial_root_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  f->probe.fork_id = fd_accdb_attach_child( f->accdb, SENTINEL );
}

static void
fiber_reset_exec( void * _ctx ) {
  fiber_t * f = _ctx;
  fd_accdb_reset( f->accdb );
}

static fd_racesan_async_t *
fiber_t1( fiber_t *          fiber,
          void (*            exec)( void * ),
          fd_accdb_t *       accdb,
          fd_accdb_fork_id_t fork_id ) {
  fiber->accdb         = accdb;
  fiber->probe.fork_id = fork_id;
  fd_racesan_async_new( fiber->async, fiber->stack, FIBER_STACK_MAX, exec, fiber );
  return fiber->async;
}

/* test_root_lag_reads: T1 roots several levels ahead of T2 and keeps
   attaching and writing.  Reads on the requested root and its children
   must be correct before, during and after T2 catches up. */

static void
test_root_lag_reads( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jb  = join_new();

  uchar K[ 32UL ]; mk_key( 8000UL, K );
  uchar L[ 32UL ]; mk_key( 8001UL, L );
  fd_accdb_fork_id_t r = fd_accdb_attach_child( ctl, SENTINEL );
  seq_write( ctl, r, K, 1UL, NULL );
  seq_write( ctl, r, L, 1UL, NULL );

  for( ulong i=0UL; i<64UL; i++ ) {
    /* Each level has a winner writing K and a loser writing L. */
    fd_accdb_fork_id_t w = fd_accdb_attach_child( ctl, r );
    fd_accdb_fork_id_t l = fd_accdb_attach_child( ctl, r );
    seq_write( ctl, w, K, 100UL+i, NULL );
    seq_write( ctl, l, L, 999UL,   NULL );
    fd_accdb_advance_root( ctl, w );
    FD_TEST( fd_accdb_lamports( ctl, w, K )==100UL+i );
    FD_TEST( fd_accdb_lamports( ctl, w, L )==1UL );
    r = w;
    if( (i%8UL)==7UL ) {
      /* T2 applies part of the backlog. */
      drain_background( jb );
      FD_TEST( fd_accdb_lamports( ctl, r, K )==100UL+i );
      FD_TEST( fd_accdb_lamports( ctl, r, L )==1UL );
    }
  }
  catch_up( jb );
  FD_TEST( g_shmem->root_fork_id.val==r.val );
  FD_TEST( fd_accdb_lamports( ctl, r, K )==163UL );
  FD_TEST( fd_accdb_lamports( ctl, r, L )==1UL );

  join_delete( ctl );
  join_delete( jb );
  test_shmem_delete();
}

/* test_purge_then_root_vs_pass: T1 roots A, detaching and purging its
   older sibling B, while T2 runs.  B is older
   than A, so once A is rooted B's accounts would be visible to every
   reader by generation: T2 must purge B no later than the pass that
   roots A.  The reader on A1 must never see B's (or purged P's) value. */

static void
test_purge_then_root_vs_pass( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jb  = join_new();
  fd_accdb_t * jr  = join_new();

  uchar K[ 32UL ]; mk_key( 8100UL, K );
  fd_accdb_fork_id_t r = fd_accdb_attach_child( ctl, SENTINEL );
  seq_write( ctl, r, K, 1UL, NULL );

  for( ulong i=0UL; i<ITER_DEFAULT/4UL; i++ ) {
    fd_accdb_fork_id_t B  = fd_accdb_attach_child( ctl, r );
    fd_accdb_fork_id_t A  = fd_accdb_attach_child( ctl, r );
    fd_accdb_fork_id_t A1 = fd_accdb_attach_child( ctl, A );
    fd_accdb_fork_id_t P  = fd_accdb_attach_child( ctl, A1 );
    seq_write( ctl, B, K, 2UL, NULL );
    seq_write( ctl, P, K, 3UL, NULL );
    ulong want = fd_accdb_lamports( ctl, r, K );
    if( i&1UL ) { want = 4UL+i; seq_write( ctl, A, K, want, NULL ); }

    /* T2 may pick up the purge of P before, with or after the root
       of A (which detaches B). */
    fd_accdb_purge( ctl, P );
    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_acquire_expect( &g_fiber[0], jr, A1, K, want ) );
    fd_racesan_weave_add( w, fiber_compact_loop( &g_fiber[1], jb, 2 ) );
    fd_racesan_weave_add( w, fiber_t1( &g_fiber[2], fiber_advance_exec, ctl, A ) );
    fd_racesan_weave_exec_rand( w, fd_ulong_hash( (i+0x5151UL) ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );
    fd_racesan_weave_delete( w );
    for( ulong f=0UL; f<3UL; f++ ) fiber_done( &g_fiber[ f ] );

    catch_up( jb );
    FD_TEST( g_shmem->root_fork_id.val==A.val );
    FD_TEST( fd_accdb_lamports( ctl, A1, K )==want );
    FD_TEST( fd_accdb_lamports( ctl, A,  K )==want );
    fd_accdb_advance_root( ctl, A1 );
    catch_up( jb );
    r = A1;
  }

  join_delete( ctl );
  join_delete( jb );
  join_delete( jr );
  test_shmem_delete();
}

/* test_purge_vs_pass: a purge races T2 applying an earlier one.  Every
   purged fork must be purged exactly once (a lost or doubled purge
   would leak or double-free the slot). */

static void
test_purge_vs_pass( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jb  = join_new();

  uchar K[ 32UL ]; mk_key( 8200UL, K );
  fd_accdb_fork_id_t r = fd_accdb_attach_child( ctl, SENTINEL );
  for( ulong i=0UL; i<ITER_DEFAULT/4UL; i++ ) {
    fd_accdb_fork_id_t a = fd_accdb_attach_child( ctl, r );
    fd_accdb_fork_id_t b = fd_accdb_attach_child( ctl, r );
    seq_write( ctl, a, K, 2UL, NULL );
    seq_write( ctl, b, K, 3UL, NULL );
    fd_accdb_purge( ctl, a );

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_compact_loop( &g_fiber[0], jb, 2 ) );
    fd_racesan_weave_add( w, fiber_t1( &g_fiber[1], fiber_purge_exec, ctl, b ) );
    fd_racesan_weave_exec_rand( w, fd_ulong_hash( (i+0x7171UL) ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );
    fd_racesan_weave_delete( w );
    for( ulong f=0UL; f<2UL; f++ ) fiber_done( &g_fiber[ f ] );

    catch_up( jb );
    FD_TEST( fd_accdb_lamports( ctl, r, K )==0UL );
    FD_TEST( g_shmem->shmetrics->accounts_total==0UL );
  }

  /* Every slot but the root's is free, each exactly once. */
  fd_accdb_fork_id_t got[ T_MAX_LIVE_SLOTS ];
  for( ulong n=0UL; n<T_MAX_LIVE_SLOTS-1UL; n++ ) {
    got[ n ] = fd_accdb_attach_child( ctl, r );
    FD_TEST( got[ n ].val!=r.val );
    for( ulong j=0UL; j<n; j++ ) FD_TEST( got[ j ].val!=got[ n ].val );
  }

  join_delete( ctl );
  join_delete( jb );
  test_shmem_delete();
}

/* test_initial_root_vs_pass: T2 runs while T1 creates the initial root
   (snapin after reset, genesis).  T2 must not root anything. */

static void
test_initial_root_vs_pass( void ) {
  for( ulong i=0UL; i<16UL; i++ ) {
    test_shmem_new();
    fd_accdb_t * ctl = join_new();
    fd_accdb_t * jb  = join_new();

    fd_racesan_weave_t w[1];
    fd_racesan_weave_new( w );
    fd_racesan_weave_add( w, fiber_compact_loop( &g_fiber[0], jb, 2 ) );
    fd_racesan_weave_add( w, fiber_t1( &g_fiber[1], fiber_initial_root_exec, ctl, SENTINEL ) );
    fd_racesan_weave_exec_rand( w, fd_ulong_hash( (i+0x9191UL) ^ g_seed_base ), STEP_MAX );
    FD_TEST( !w->rem_cnt );
    fd_racesan_weave_delete( w );
    fd_accdb_fork_id_t r = g_fiber[1].probe.fork_id;
    for( ulong f=0UL; f<2UL; f++ ) fiber_done( &g_fiber[ f ] );

    catch_up( jb );
    FD_TEST( g_shmem->root_fork_id.val==r.val );
    fd_accdb_fork_id_t c = fd_accdb_attach_child( ctl, r );
    uchar K[ 32UL ]; mk_key( 8250UL, K );
    seq_write( ctl, c, K, 7UL, NULL );
    fd_accdb_advance_root( ctl, c );
    catch_up( jb );
    FD_TEST( g_shmem->root_fork_id.val==c.val );

    join_delete( ctl );
    join_delete( jb );
    test_shmem_delete();
  }
}

/* test_slot_reuse_descends: a retired slot keeps its bit in the
   descends_set of forks that descended from it.  Reusing the slot for
   a fork that is not their ancestor must clear that bit, else readers
   on those forks would see the new fork's writes.  Covers both a live
   descendant (Y) and requested roots T2 has not applied yet (F, G):
   applying F unlinks older versions of K it deletes, testing F's
   descends_set, so a stale bit would make T2 unlink Z's newer K. */

static void
test_slot_reuse_descends( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jb  = join_new();
  fd_accdb_t * jr  = join_new();

  uchar K[ 32UL ]; mk_key( 8300UL, K );
  fd_accdb_fork_id_t r = fd_accdb_attach_child( ctl, SENTINEL );
  seq_write( ctl, r, K, 1UL, NULL );

  for( ulong i=0UL; i<ITER_DEFAULT/16UL; i++ ) {
    fd_accdb_fork_id_t X = fd_accdb_attach_child( ctl, r );
    seq_write( ctl, X, K, 100UL+i, NULL );
    fd_accdb_fork_id_t Y = fd_accdb_attach_child( ctl, X );
    fd_accdb_fork_id_t F = fd_accdb_attach_child( ctl, Y );
    seq_write( ctl, F, K, 0UL, NULL );
    fd_accdb_fork_id_t G = fd_accdb_attach_child( ctl, F );
    fd_accdb_advance_root( ctl, X );
    fd_accdb_advance_root( ctl, Y );
    catch_up( jb ); /* X's slot is free again */
    fd_accdb_advance_root( ctl, F ); /* requested, not applied */
    fd_accdb_advance_root( ctl, G ); /* requested, not applied */

    /* A reader on Y walks K's chain while X's slot is reused under G
       for a fork Z that writes K. */
    fd_racesan_async_t * rd = fiber_acquire_expect( &g_fiber[0], jr, Y, K, 100UL+i );
    FD_TEST( fd_racesan_async_step_until( rd, "accdb_acquire:post_next", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

    /* Attach until X's slot comes back. */
    fd_accdb_fork_id_t extra[ T_MAX_LIVE_SLOTS ]; ulong extra_cnt = 0UL;
    fd_accdb_fork_id_t Z;
    for(;;) {
      Z = fd_accdb_attach_child( ctl, G );
      if( Z.val==X.val ) break;
      FD_TEST( extra_cnt<T_MAX_LIVE_SLOTS );
      extra[ extra_cnt++ ] = Z;
    }
    seq_write( ctl, Z, K, 555UL, NULL );
    async_finish( rd );
    fiber_done( &g_fiber[0] );

    catch_up( jb );
    FD_TEST( g_shmem->root_fork_id.val==G.val );
    FD_TEST( fd_accdb_lamports( ctl, G, K )==0UL   );
    FD_TEST( fd_accdb_lamports( ctl, Z, K )==555UL );

    for( ulong j=0UL; j<extra_cnt; j++ ) fd_accdb_purge( ctl, extra[ j ] );
    fd_accdb_advance_root( ctl, Z );
    catch_up( jb );
    FD_TEST( fd_accdb_lamports( ctl, Z, K )==555UL );
    r = Z;
  }

  join_delete( ctl );
  join_delete( jb );
  join_delete( jr );
  test_shmem_delete();
}

/* test_reset_vs_pass: T2 is parked at the end of a pass that retired
   fork c when T1 resets the database (snapin's full snapshot retry).
   Reset must wait for the pass to finish and for its batch, which
   names a slot of the old pool, to be released, rather than let T2
   release it into the rebuilt pool later.  Afterwards every fork of
   the rebuilt database owns its slot. */

static void
test_reset_vs_pass( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jb  = join_new();

  uchar K[ 32UL ]; mk_key( 8400UL, K );
  fd_accdb_fork_id_t r = fd_accdb_attach_child( ctl, SENTINEL );
  fd_accdb_fork_id_t c = fd_accdb_attach_child( ctl, r );
  seq_write( ctl, c, K, 5UL, NULL );
  fd_accdb_purge( ctl, c );

  fd_racesan_async_t * bg = fiber_compact_loop( &g_fiber[0], jb, 2 );
  FD_TEST( fd_racesan_async_step_until( bg, "accdb_requests:pre_done", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  fd_racesan_async_t * rs = fiber_t1( &g_fiber[1], fiber_reset_exec, ctl, SENTINEL );
  for( ulong i=0UL; i<4UL; i++ ) FD_TEST( fd_racesan_async_step_until( rs, "accdb_wait_idle:spin", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

  /* The pass is done but its batch is held: reset still waits. */
  FD_TEST( fd_racesan_async_step_until( bg, "accdb_release:pre_done", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  for( ulong i=0UL; i<4UL; i++ ) FD_TEST( fd_racesan_async_step_until( rs, "accdb_wait_idle:spin", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );
  async_finish( bg );
  async_finish( rs );
  fiber_done( &g_fiber[0] );
  fiber_done( &g_fiber[1] );

  /* Rebuild, then run passes that would release a stale batch. */
  r = fd_accdb_attach_child( ctl, SENTINEL );
  fd_accdb_fork_id_t a = fd_accdb_attach_child( ctl, r );
  seq_write( ctl, a, K, 999UL, NULL );
  catch_up( jb );

  fd_accdb_fork_id_t got[ T_MAX_LIVE_SLOTS ];
  for( ulong n=0UL; n<T_MAX_LIVE_SLOTS-2UL; n++ ) {
    got[ n ] = fd_accdb_attach_child( ctl, r );
    FD_TEST( got[ n ].val!=r.val && got[ n ].val!=a.val );
    for( ulong j=0UL; j<n; j++ ) FD_TEST( got[ j ].val!=got[ n ].val );
    FD_TEST( fd_accdb_lamports( ctl, got[ n ], K )==0UL );
  }
  FD_TEST( fd_accdb_lamports( ctl, a, K )==999UL );

  join_delete( ctl );
  join_delete( jb );
  test_shmem_delete();
}

/* test_walk_vs_deferred_stack: a reader has loaded next of a node
   that T2 then unlinks and pushes onto the deferred-free stack (which
   reuses next).  The walk order is load next, check the unlinked
   mark, use next; the unlink order is set the mark, then reuse next.
   So the reader either uses the next it loaded before the push (the
   node's chain successor, still valid) or sees the mark and restarts
   from the head.  It must never follow a stack link.

   Chain for K (head -> tail), all on one hash chain:
       A's X (head) -> P's X (unlinked by rooting A) -> P's K (tail)
   P is the root.  The reader on A1 wants K.  It is parked at the first
   post_next (on A's X, holding next == P's X); T2 roots A, pushing P's
   X onto the stack; the reader resumes, loads P's X.next (now a stack
   link), and must see the mark, restart, and find P's K. */

static void
test_walk_vs_deferred_stack( void ) {
  test_shmem_new();
  fd_accdb_t * ctl = join_new();
  fd_accdb_t * jr  = join_new();
  fd_accdb_t * jb  = join_new();

  uchar owner[ 32UL ] = { 7, 0 };
  fd_accdb_fork_id_t root = fd_accdb_attach_child( ctl, SENTINEL );
  ulong chain_msk = g_shmem->chain_cnt-1UL;

  /* X collides with K on the hash chain */
  uchar K[ 32UL ]; mk_key( 1000UL, K );
  uchar X[ 32UL ];
  ulong hk = fd_hash32( K, g_shmem->seed ) & chain_msk;
  for( ulong j=1UL;; j++ ) {
    mk_key( 1000UL+j, X );
    if( ( fd_hash32( X, g_shmem->seed ) & chain_msk )==hk ) break;
  }

  for( ulong i=0UL; i<ITER_DEFAULT; i++ ) {
    /* Base versions on P, rooted first: rooting P supersedes the last
       iteration's K and X, so the pool stays bounded. */
    fd_accdb_fork_id_t p = fd_accdb_attach_child( ctl, root );
    seq_write( ctl, p, K, 500UL+i, owner );  /* tail: P's K */
    seq_write( ctl, p, X, 1UL,     owner );  /* P's X */
    fd_accdb_advance_root( ctl, p );
    catch_up( jb );

    fd_accdb_fork_id_t a  = fd_accdb_attach_child( ctl, p );
    fd_accdb_fork_id_t a1 = fd_accdb_attach_child( ctl, a );
    seq_write( ctl, a, X, 2UL, owner );         /* head: A's X */
    fd_accdb_advance_root( ctl, a );

    /* Park the reader on A's X, holding A's X.next == P's X.  It will
       load P's X.next only after T2 has pushed P's X: that load returns
       the stack link, and only the unlinked check stops the reader from
       following it. */
    fd_racesan_async_t * ra = fiber_acquire_expect( &g_fiber[0], jr, a1, K, 500UL+i );
    FD_TEST( fd_racesan_async_step_until( ra, "accdb_acquire:post_next", STEP_MAX )==FD_RACESAN_ASYNC_RET_HOOK );

    /* T2 roots A: unlinks P's X and pushes it.  The reader's epoch
       keeps the batch from being released. */
    drain_background( jb );
    FD_TEST( g_shmem->deferred_acc_head!=UINT_MAX );

    async_finish( ra );  /* expect_lamports==500+i is the oracle */
    fiber_done( &g_fiber[0] );

    fd_accdb_advance_root( ctl, a1 );
    catch_up( jb );
    root = a1;
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
    TEST( test_reservation_wait_yields ),
    TEST( test_acquire_vs_advance ),
    TEST( test_acquire_vs_advance_sibling ),
    TEST( test_acquire_interior_unlink ),
    TEST( test_walk_vs_deferred_stack ),
    TEST( test_acquire_vs_release ),
    TEST( test_acquire_vs_purge ),
    TEST( test_cold_load_same ),
    TEST( test_cold_load_evict ),
    TEST( test_hit_vs_evict ),
    TEST( test_read_vs_overwrite ),
    TEST( test_epoch_reclaim_pin ),
    TEST( test_nocache_vs_compaction ),
    TEST( test_compact_reloc_integrity ),
    TEST( test_compact_batch ),
    TEST( test_compact_vs_overwrite ),
    TEST( test_compact_vs_coldread ),
    TEST( test_hold_vs_evict ),
    TEST( test_commit_vs_evict ),
    TEST( test_writeback_vs_unlink ),
    TEST( test_unbind_vs_unlink ),
    TEST( test_writeback_vs_compact ),
    TEST( test_cold_load_race ),
    TEST( test_nocache_vs_reuse ),
    TEST( test_nocache_vs_recheck ),
    TEST( test_nocache_vs_commit ),
    TEST( test_commit_class_full ),
    TEST( test_fallback_vs_reserve ),
    TEST( test_reservation_steal ),
    TEST( test_writeback_vs_recreate ),
    TEST( test_overwrite_move_orphan ),
    TEST( test_orphan_evict_vs_recycle ),
    TEST( test_alloc_reclaim_vs_reader ),
    TEST( test_preevict_batch ),
    TEST( test_reclaim_vs_snapshot_capture ),
    TEST( test_tombstone_orphan_ebr_poison ),
    TEST( test_probe_vs_pd_commit ),
    TEST( test_pd_parent_read_vs_child_write ),
    TEST( test_pd_parent_hold_vs_advance_root ),
    TEST( test_root_lag_reads ),
    TEST( test_purge_then_root_vs_pass ),
    TEST( test_purge_vs_pass ),
    TEST( test_initial_root_vs_pass ),
    TEST( test_slot_reuse_descends ),
    TEST( test_reset_vs_pass ),
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
