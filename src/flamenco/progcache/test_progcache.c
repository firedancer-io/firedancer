/* test_progcache.c contains single-threaded correctness tests for
   progcache. */

#include "test_progcache_common.c"
#include "fd_progcache_clock.h"
#include "fd_progcache_reclaim.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/program/fd_bpf_loader_program.h"
#include "../runtime/fd_bank.h"
#include "../features/fd_features.h"
#include "../../util/tmpl/fd_unit_test.c"
#include <stdlib.h>
#include <regex.h>
#if FD_HAS_THREADS
#include <pthread.h>
#include <time.h>
#include <stdatomic.h>
#endif

static fd_wksp_t * wksp;

struct test_env {
  fd_wksp_t *    wksp;
  fd_progcache_t progcache[1];
  fd_features_t  features[1];
  uchar scratch[ FD_PROGCACHE_SCRATCH_FOOTPRINT ] __attribute__((aligned(FD_PROGCACHE_SCRATCH_ALIGN)));
};

typedef struct test_env test_env_t;

/* test_env_create allocates a new account database and program cache
   from a wksp.  Joins an admin and user client to the program cache, as
   well as a database client. */

static test_env_t *
test_env_create_ex( fd_wksp_t * wksp,
                    ulong       txn_max,
                    ulong       progcache_sz ) {
  ulong wksp_tag = 1UL;

  void * progcache_mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, progcache_sz ), wksp_tag );
  FD_TEST( fd_progcache_shmem_new( progcache_mem, wksp_tag, 1UL, txn_max, progcache_sz ) );

  test_env_t * env = fd_wksp_alloc_laddr( wksp, alignof(test_env_t), sizeof(test_env_t), wksp_tag );
  FD_TEST( env );
  memset( env, 0, offsetof(test_env_t, scratch) );

  env->wksp = wksp;
  FD_TEST( fd_progcache_join( env->progcache, progcache_mem, env->scratch, sizeof(env->scratch) ) );

  return env;
}

static test_env_t *
test_env_create( fd_wksp_t * wksp ) {
  return test_env_create_ex( wksp, 16UL, fd_progcache_shmem_min_sz( 16UL ) );
}

/* test_env_destroy frees all test env objects. */

static void
test_env_destroy( test_env_t * env ) {
  FD_TEST( !fd_progcache_verify( env->progcache->join ) );
  fd_progcache_shmem_t * progcache_mem = NULL;
  FD_TEST( fd_progcache_leave( env->progcache, &progcache_mem ) );
  fd_wksp_free_laddr( fd_progcache_shmem_delete( progcache_mem ) );
  fd_wksp_free_laddr( env );
}

FD_IMPORT_BINARY( valid_program_data,        "src/ballet/sbpf/fixtures/hello_solana_program.so" );
FD_IMPORT_BINARY( bigger_valid_program_data, "src/ballet/sbpf/fixtures/clock_sysvar_program.so" );
FD_IMPORT_BINARY( invalid_program_data,      "src/ballet/sbpf/fixtures/malformed_bytecode.so"   );

/* query_rec_exact fetches a program record at a precise xid:key pair. */

static fd_progcache_rec_t const *
query_rec_exact( test_env_t *           env,
                 fd_progcache_fork_id_t fork_id,
                 fd_pubkey_t const *    key ) {
  fd_progcache_rec_key_t pair = { .xid = fork_id, .prog = *key };
  fd_prog_recm_query_t query[1];
  int query_err = fd_prog_recm_query_try( env->progcache->join->rec.map, &pair, NULL, query, 0 );
  if( query_err==FD_MAP_ERR_KEY ) return NULL;
  if( FD_UNLIKELY( query_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_query_try failed: %i-%s", query_err, fd_map_strerror( query_err ) ));
  return fd_prog_recm_query_ele_const( query );
}

/* test_peek and test_pull wrap fd_progcache_{peek,pull} and
   immediately release the read lock on the returned record.  This is
   safe in single-threaded tests where record lifetimes are managed
   by cancel/publish/destroy. */

static fd_progcache_rec_t *
test_peek( fd_progcache_t *       cache,
           fd_progcache_fork_id_t fork_id,
           fd_pubkey_t const *    prog_addr,
           ulong                  feature_slot,
           ulong                  deploy_slot ) {
  fd_progcache_rec_t * rec = fd_progcache_peek( cache, fork_id, prog_addr, feature_slot, deploy_slot );
  if( rec ) fd_progcache_rec_close( cache, rec );
  return rec;
}

static fd_progcache_rec_t *
test_pull( fd_progcache_t *           cache,
           fd_acc_t const *           prog_ro,
           fd_progcache_fork_id_t     fork_id,
           fd_pubkey_t const *        prog_addr,
           fd_prog_load_env_t const * env ) {
  fd_progcache_rec_t * rec = fd_progcache_pull( cache, fork_id, prog_addr, env, prog_ro );
  if( rec ) fd_progcache_rec_close( cache, rec );
  return rec;
}

/* test_evict runs one eviction and gives back the record it hands over, so
   the class ends up as it would have with no caller waiting for the slot.
   Returns whether a record was evicted. */

static int
test_evict( fd_progcache_t * cache,
            ulong            sz ) {
  fd_progcache_rec_t * rec = fd_prog_evict( cache, sz );
  if( !rec ) return 0;
  fd_progcache_rec_abandon( cache->join, rec );
  return 1;
}

/* test_root roots the fork, making its records evictable, and hands back a fresh
   child of the new root so pulls and peeks keep working. */

FD_FN_UNUSED static fd_progcache_fork_id_t
test_root( fd_progcache_join_t *  join,
           fd_progcache_fork_id_t xid ) {
  fd_progcache_advance_root( join, xid );
  return fd_progcache_attach_child( join, xid );
}

/* test_invalid_owner: Account exists but is not owned by BPF loader */

FD_UNIT_TEST( invalid_owner ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t fork_a = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_system_program_id, /* not a BPF loader */
                     1, invalid_program_data, invalid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  FD_TEST( !test_pull( env->progcache, acc.entry, fork_a, &key, &load_env ) );

  fd_progcache_cancel_fork( env->progcache->join, fork_a );
  test_env_destroy( env );
}

/* test_invalid_program: Program account exists but fails loading */

FD_UNIT_TEST( invalid_program ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t fork_a = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, invalid_program_data, invalid_program_data_sz );

  FD_TEST( !test_peek( env->progcache, fork_a, &key, 0UL, 0UL ) );
  FD_TEST( env->progcache->lineage->fork_depth==1UL );
  FD_TEST( env->progcache->lineage->fork[ 0 ]==fork_a );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( !rec->data_gaddr );
  FD_TEST( test_peek( env->progcache, fork_a, &key, 0UL, 0UL )==rec );

  fd_progcache_cancel_fork( env->progcache->join, fork_a );
  test_env_destroy( env );
}

/* test_valid_program: Load a valid program account */

FD_UNIT_TEST( valid_program ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t fork_a = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  FD_TEST( !test_peek( env->progcache, fork_a, &key, 0UL, 0UL ) );
  FD_TEST( env->progcache->lineage->fork_depth==1UL );
  FD_TEST( env->progcache->lineage->fork[ 0 ]==fork_a );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->data_gaddr );
  FD_TEST( test_peek( env->progcache, fork_a, &key, 0UL, 0UL )==rec );
  FD_TEST( env->progcache->lineage->fork_depth==1UL );

  fd_progcache_fork_id_t fork_b = fd_progcache_attach_child( env->progcache->join, fork_a );
  FD_TEST( test_peek( env->progcache, fork_b, &key, 0UL, 0UL )==rec );
  FD_TEST( env->progcache->lineage->fork_depth==2UL );

  load_env.feature_slot = 0UL;
  fd_progcache_rec_t const * rec2 = test_pull( env->progcache, acc.entry, fork_b, &key, &load_env );
  FD_TEST( rec==rec2 );
  FD_TEST( test_peek( env->progcache, fork_b, &key, 0UL, 0UL )==rec );

  fd_progcache_cancel_fork( env->progcache->join, fork_a ); /* should also cancel fork_b */
  test_env_destroy( env );
}

/* test_cache_fill_evicts: fill a single size class past its slot count so
   the per-class eviction path (acquire fails -> evict -> retry)
   actually runs, and verify programs still load (no spill) as the class
   recycles slots.  Uses a small heap so the 128 KiB class has few
   slots. */

FD_UNIT_TEST( cache_fill_evicts ) {
  test_env_t * env = test_env_create_ex( wksp, 16UL, fd_progcache_shmem_min_sz( 16UL ) );
  fd_progcache_fork_id_t fork = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };

  /* hello_solana_program.so is small -> 128 KiB class (class 0). */
  ulong class0_slots = env->progcache->join->shmem->cache.class_max[ 0 ];
  FD_TEST( class0_slots>0UL );

  ulong over = 20UL;
  ulong n    = class0_slots + over;
  FD_TEST( n<512UL ); /* rec pool must not be the bottleneck */

  ulong oom0   = env->progcache->metrics->class_full_cnt;
  ulong evict0 = env->progcache->metrics->evict_cnt;
  ulong spill0 = env->progcache->metrics->spill_cnt;

  for( ulong i=0UL; i<n; i++ ) {
    /* Only rooted records are evictable, so root once the class is full: the
       overflow then evicts the rooted fills. */
    if( FD_UNLIKELY( i==class0_slots ) ) fork = test_root( env->progcache->join, fork );

    fd_pubkey_t key = test_key( 1000UL+i );
    test_account_t acc;
    test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                       1, valid_program_data, valid_program_data_sz );
    fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, fork, &key, &load_env );
    FD_TEST( rec );             /* loaded             */
    FD_TEST( rec->data_gaddr ); /* got a cache slot    */
    FD_TEST( rec->data_max==fd_progcache_cache_slot_sz[ 0 ] ); /* in the 128 KiB class */
  }

  ulong oom_d   = env->progcache->metrics->class_full_cnt - oom0;
  ulong evict_d = env->progcache->metrics->evict_cnt    - evict0;
  ulong spill_d = env->progcache->metrics->spill_cnt    - spill0;

  /* Every insert past the class capacity must have hit the class-full
     path and been resolved by eviction (not spill). */
  FD_TEST( oom_d  >=over ); /* at least `over` allocations found the class full */
  FD_TEST( evict_d>=over ); /* and eviction ran to make room                  */
  FD_TEST( spill_d==0UL  ); /* eviction always succeeded; nothing spilled      */

  /* Never more slots in use than the class provides. */
  FD_TEST( fd_progcache_class_free_cnt( env->progcache->join->shmem, 0 )<=class0_slots );

  fd_progcache_cancel_fork( env->progcache->join, fork );
  test_env_destroy( env );
}

/* test_epoch_boundary: Ensure that a valid program gets re-verified
   after an epoch boundary. */

FD_UNIT_TEST( epoch_boundary ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t fork_a = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  FD_TEST( !test_peek( env->progcache, fork_a, &key, 0UL, 0UL ) );
  FD_TEST( env->progcache->lineage->fork_depth==1UL );
  FD_TEST( env->progcache->lineage->fork[ 0 ]==fork_a );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->data_gaddr );
  FD_TEST( test_peek( env->progcache, fork_a, &key, 0UL, 0UL )==rec );

  fd_progcache_fork_id_t fork_b = fd_progcache_attach_child( env->progcache->join, fork_a );
  load_env.feature_slot = 64UL;
  fd_progcache_rec_t const * rec2 = test_pull( env->progcache, acc.entry, fork_b, &key, &load_env );
  FD_TEST( rec2 );
  FD_TEST( rec!=rec2 );
  FD_TEST( rec2->data_gaddr );
  FD_TEST( test_peek( env->progcache, fork_b, &key, 64UL, 0UL )==rec2 );

  fd_progcache_cancel_fork( env->progcache->join, fork_b );
  fd_progcache_cancel_fork( env->progcache->join, fork_a );
  test_env_destroy( env );
}

FD_UNIT_TEST( epoch_boundary2 ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t fork_a = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t prog_key       = test_key( 1UL );
  fd_pubkey_t prog0_data_key = test_key( 2UL );
  fd_pubkey_t prog1_data_key = test_key( 4UL );

  test_account_t prog0;      static uchar prog0_buf     [ 4096  ];
  test_account_t prog0_data; static uchar prog0_data_buf[ 50000 ];
  test_account_t prog1;      static uchar prog1_buf     [ 4096  ];
  test_account_t prog1_data; static uchar prog1_data_buf[ 50000 ];

  /* Invoke old program at epoch 0 */
  test_account_init_v3( &prog0, prog0_buf, sizeof(prog0_buf), &prog_key, &prog0_data_key );
  test_account_init_v3_data(
      &prog0_data,
      prog0_data_buf, sizeof(prog0_data_buf),
      &prog0_data_key,
      valid_program_data, valid_program_data_sz,
      1UL
  );
  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t const * rec1 = test_pull( env->progcache, prog0_data.entry, fork_a, &prog_key, &load_env );
  FD_TEST( rec1 );
  FD_TEST( test_peek( env->progcache, fork_a, &prog_key, 0UL, 1UL )==rec1 );

  /* Invoke old program at epoch 1 */
  fd_prog_load_env_t load_env2 = {
    .features     = env->features,
    .feature_slot = 64UL
  };
  fd_progcache_fork_id_t fork_b = fd_progcache_attach_child( env->progcache->join, fork_a );
  fd_progcache_rec_t const * rec2 = test_pull( env->progcache, prog0_data.entry, fork_b, &prog_key, &load_env2 );
  FD_TEST( rec1!=rec2 );
  FD_TEST( query_rec_exact( env, fork_b, &prog_key )==rec2 );

  /* Invoke new (redeployed) program at epoch1 */
  test_account_init_v3( &prog1, prog1_buf, sizeof(prog1_buf), &prog_key, &prog1_data_key );
  test_account_init_v3_data(
      &prog1_data,
      prog1_data_buf, sizeof(prog1_data_buf),
      &prog1_data_key,
      bigger_valid_program_data, bigger_valid_program_data_sz,
      64UL
  );
  fd_progcache_fork_id_t fork_c = fd_progcache_attach_child( env->progcache->join, fork_b );
  fd_progcache_rec_t const * rec3 = test_pull( env->progcache, prog1_data.entry, fork_c, &prog_key, &load_env2 );
  FD_TEST( rec3!=rec1 && rec3!=rec2 );
  FD_TEST( query_rec_exact( env, fork_c, &prog_key )==rec3 );

  fd_progcache_cancel_fork( env->progcache->join, fork_c );
  fd_progcache_cancel_fork( env->progcache->join, fork_b );
  fd_progcache_cancel_fork( env->progcache->join, fork_a );
  test_env_destroy( env );
}

/* feature_slot_key verifies fd_prog_load_env_from_bank's feature_slot, the
   program-cache validity key.  Two features activate at slots 200 and 500.
   Walking the epoch-start slots, the key (= newest active feature slot)
   changes -- so the cache rebuilds -- only on a boundary that actually
   activates a feature:

     epoch starts at | feature_slot | rebuild?
                 100 |          0   | no  (no feature active yet)
                 200 |        200   | yes (feature@200 activates)
                 300 |        200   | no
                 400 |        200   | no
                 500 |        500   | yes (feature@500 activates)
                 600 |        500   | no                                   */

FD_UNIT_TEST( feature_slot_key ) {
#if FD_PROGCACHE_EB_ALWAYS_INVALIDATE
  /* No feature-set key in this build, and the fixture has no epoch schedule. */
  FD_LOG_NOTICE(( "skipped: FD_PROGCACHE_EB_ALWAYS_INVALIDATE" ));
#else
  fd_bank_t * bank = fd_wksp_alloc_laddr( wksp, FD_BANKS_ALIGN, sizeof(fd_bank_t), 1UL );
  FD_TEST( bank );
  for( ulong i=0UL; i<FD_FEATURE_ID_CNT; i++ ) bank->f.features.f[ i ] = FD_FEATURE_DISABLED;
  bank->f.features.f[ 0 ] = 200UL;
  bank->f.features.f[ 1 ] = 500UL;

  static struct { ulong epoch_slot0; ulong feature_slot; int rebuild; } const cases[] = {
    { 100UL,   0UL, 0 },
    { 200UL, 200UL, 1 },
    { 300UL, 200UL, 0 },
    { 400UL, 200UL, 0 },
    { 500UL, 500UL, 1 },
    { 600UL, 500UL, 0 },
  };

  fd_prog_load_env_t env;
  ulong prev_key = 0UL;  /* empty cache */
  for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[0]); i++ ) {
    bank->f.slot = cases[ i ].epoch_slot0;
    fd_prog_load_env_from_bank( &env, bank );
    FD_TEST( env.feature_slot == cases[ i ].feature_slot );
    FD_TEST( (int)( env.feature_slot != prev_key ) == cases[ i ].rebuild );  /* key change <=> rebuild */
    prev_key = env.feature_slot;
  }

  fd_wksp_free_laddr( bank );
#endif
}

/* eb_reload_bench measures the per-program reload cost (ELF parse + verify)
   that an epoch boundary incurs when the feature-set key changes, and shows
   that an unchanged key reuses the cached entry (no reload).  This quantifies
   the work saved per program when a no-feature-change epoch boundary no longer
   bumps the key. */

FD_UNIT_TEST( eb_reload_bench ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t fork = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, bigger_valid_program_data, bigger_valid_program_data_sz );

  /* Warm the cache at feature_slot 0. */
  fd_prog_load_env_t e0 = { .features = env->features, .feature_slot = 0UL };
  fd_progcache_rec_t const * r0 = test_pull( env->progcache, acc.entry, fork, &key, &e0 );
  FD_TEST( r0 );

  /* FIX: feature set unchanged across the boundary -> same key -> a child fork
     (next epoch) at the same feature_slot reuses the cached entry (no reload). */
  ulong const N = 8UL;
  fd_progcache_fork_id_t forks[ N+1 ];
  forks[ 0 ] = fork;
  ulong fills_before = env->progcache->metrics->fill_cnt;
  fd_progcache_fork_id_t fork_same = fd_progcache_attach_child( env->progcache->join, fork );
  fd_progcache_rec_t const * r_hit = test_pull( env->progcache, acc.entry, fork_same, &key, &e0 );
  FD_TEST( r_hit==r0 );                                         /* survives the EB */
  FD_TEST( env->progcache->metrics->fill_cnt==fills_before );   /* no reload */
  fd_progcache_cancel_fork( env->progcache->join, fork_same );

  /* BASELINE: the key bumps every boundary -> reload.  Each child fork pulled
     at a new feature_slot forces a re-parse+verify.  Time N reloads. */
  ulong load_ticks0 = env->progcache->metrics->cum_load_ticks;
  ulong fills0      = env->progcache->metrics->fill_cnt;
  long  t0          = fd_log_wallclock();
  for( ulong i=1UL; i<=N; i++ ) {
    forks[ i ] = fd_progcache_attach_child( env->progcache->join, forks[ i-1UL ] );
    fd_prog_load_env_t ei = { .features = env->features, .feature_slot = 1000UL+i };
    FD_TEST( test_pull( env->progcache, acc.entry, forks[ i ], &key, &ei ) );
  }
  long  t1     = fd_log_wallclock();
  ulong fills  = env->progcache->metrics->fill_cnt - fills0;
  ulong dticks = env->progcache->metrics->cum_load_ticks - load_ticks0;
  FD_TEST( fills==N ); /* every key bump reloaded */
  FD_LOG_NOTICE(( "EB reload bench: %lu reloads of a %lu-byte program, %.1f us/program (wall), load_ticks/program=%lu",
                  fills, bigger_valid_program_data_sz, (double)(t1-t0)/1e3/(double)fills, dticks/fills ));
  FD_LOG_NOTICE(( "  => a no-feature-change epoch boundary saves ~this per cached program reused after the boundary" ));

  for( ulong i=N; i>=1UL; i-- ) fd_progcache_cancel_fork( env->progcache->join, forks[ i ] );
  fd_progcache_cancel_fork( env->progcache->join, fork );
  test_env_destroy( env );
}

FD_UNIT_TEST( publish_trivial ) {
  /* Exercise a sequence of prepare/publish operations seen when running
     'firedancer-dev backtest' */

  test_env_t * env = test_env_create( wksp );

  fd_progcache_fork_id_t fork_368528500 = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );
  fd_progcache_advance_root( env->progcache->join, fork_368528500 );

  /* FIXME more operations here ... */

  test_env_destroy( env );
}

/* test_root_nonroot_prio: non-rooted record should take priority over
   rooted records. */

FD_UNIT_TEST( root_nonroot_prio ) {
  test_env_t * env = test_env_create( wksp );

  fd_progcache_fork_id_t fork_1 = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() ); /* account deployed here */
  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  fd_progcache_advance_root( env->progcache->join, fork_1 );

  fd_progcache_fork_id_t fork_2 = fd_progcache_attach_child( env->progcache->join, fork_1 ); /* root */
  fd_progcache_fork_id_t fork_3 = fd_progcache_attach_child( env->progcache->join, fork_2 ); /* account redeployed here */
  fd_progcache_fork_id_t fork_4 = fd_progcache_attach_child( env->progcache->join, fork_3 ); /* tip */

  fd_prog_load_env_t load_env1 = {
    .features     = env->features,
    .feature_slot = 1UL
  };
  fd_progcache_rec_t const * rec1 = test_pull( env->progcache, acc.entry, fork_2, &key, &load_env1 );
  FD_TEST( rec1 );
  fd_progcache_advance_root( env->progcache->join, fork_2 );

  fd_prog_load_env_t load_env4 = {
    .features     = env->features,
    .feature_slot = 4UL
  };
  fd_progcache_rec_t const * rec4 = test_pull( env->progcache, acc.entry, fork_4, &key, &load_env4 );
  FD_TEST( rec4 );

  fd_progcache_cancel_fork( env->progcache->join, fork_4 );
  fd_progcache_cancel_fork( env->progcache->join, fork_3 );
  test_env_destroy( env );
}

/* test_reattach_after_cancel_all: Attach child after all siblings were
   cancelled — parent's child_head/tail were reset.  Verify they're
   re-established correctly. */

FD_UNIT_TEST( reattach_after_cancel_all ) {
  test_env_t * env = test_env_create( wksp );

  fd_progcache_fork_id_t parent  = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );
  fd_progcache_fork_id_t child_a = fd_progcache_attach_child( env->progcache->join, parent );
  fd_progcache_fork_id_t child_b = fd_progcache_attach_child( env->progcache->join, parent );
  fd_progcache_fork_id_t child_c = fd_progcache_attach_child( env->progcache->join, parent );

  uint parent_idx = (uint)fd_prog_txnm_idx_query_const( env->progcache->join->txn.map, &parent, UINT_MAX, env->progcache->join->txn.pool );
  FD_TEST( parent_idx!=UINT_MAX );
  fd_progcache_txn_t * parent_txn = &env->progcache->join->txn.pool[ parent_idx ];
  FD_TEST( parent_txn->child_head_idx!=UINT_MAX );
  FD_TEST( parent_txn->child_tail_idx!=UINT_MAX );

  fd_progcache_cancel_fork( env->progcache->join, child_c );
  fd_progcache_cancel_fork( env->progcache->join, child_b );
  fd_progcache_cancel_fork( env->progcache->join, child_a );

  FD_TEST( parent_txn->child_head_idx==UINT_MAX );
  FD_TEST( parent_txn->child_tail_idx==UINT_MAX );

  fd_progcache_fork_id_t child_d = fd_progcache_attach_child( env->progcache->join, parent );

  FD_TEST( parent_txn->child_head_idx!=UINT_MAX );
  FD_TEST( parent_txn->child_tail_idx!=UINT_MAX );
  FD_TEST( parent_txn->child_head_idx==parent_txn->child_tail_idx );

  fd_progcache_txn_t * child_d_txn = &env->progcache->join->txn.pool[ parent_txn->child_head_idx ];
  FD_TEST( child_d_txn->xid==child_d );
  FD_TEST( child_d_txn->parent_idx==parent_idx );
  FD_TEST( child_d_txn->sibling_prev_idx==UINT_MAX );
  FD_TEST( child_d_txn->sibling_next_idx==UINT_MAX );

  FD_TEST( !fd_progcache_verify( env->progcache->join ) );

  fd_progcache_cancel_fork( env->progcache->join, child_d );
  fd_progcache_cancel_fork( env->progcache->join, parent );
  test_env_destroy( env );
}

/* test_reclaim_empty: a sweep of an idle cache collects nothing */

FD_UNIT_TEST( reclaim_empty ) {
  test_env_t * env = test_env_create( wksp );

  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==0UL );

  test_env_destroy( env );
}

/* test_reclaim_no_readers: a detached zombie with no readers is collected
   by the sweep; an attached one is left to cancel. */

FD_UNIT_TEST( reclaim_no_readers ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t * rec = test_pull( env->progcache, acc.entry, xid, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->exists );

  long freed = fd_prog_delete_rec( env->progcache->join, rec );
  FD_TEST( freed>=0L );

  /* Still attached to its fork: the sweep leaves the zombie to cancel. */
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==0UL );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  test_env_destroy( env );
}

/* test_reclaim_active_reader: a zombie with an active reader is skipped
   by the sweep until the reader closes. */

FD_UNIT_TEST( reclaim_active_reader ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  FD_TEST( test_pull( env->progcache, acc.entry, xid, &key, &load_env ) );

  fd_progcache_rec_t * rec = fd_progcache_peek( env->progcache, xid, &key, 0UL, 0UL );
  FD_TEST( rec );

  /* Cancel unmaps and detaches the record: a zombie, still read-held. */
  fd_progcache_cancel_fork( env->progcache->join, xid );
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==0UL );

  /* Closing the last reader makes it collectable. */
  fd_progcache_rec_close( env->progcache, rec );
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  test_env_destroy( env );
}

/* test_cross_join_reclaim: a record removed from the map by one join (A) while
   another join (B) holds it read-locked must be collectable by B once it
   closes -- zombies live in the shared record array, visible to every join's
   sweep, so an idle A cannot strand the slot. */

FD_UNIT_TEST( cross_join_reclaim ) {
  test_env_t *           env   = test_env_create( wksp );   /* join A + shmem */
  fd_progcache_t *       A     = env->progcache;
  fd_progcache_shmem_t * shmem = A->join->shmem;

  /* Second independent join B onto the same shared cache. */
  fd_progcache_t * B    = fd_wksp_alloc_laddr( wksp, alignof(fd_progcache_t), sizeof(fd_progcache_t), 1UL );
  uchar *          bscr = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT, 1UL );
  FD_TEST( fd_progcache_join( B, shmem, bscr, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );

  fd_progcache_fork_id_t xid = fd_progcache_attach_child( A->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };

  /* A populates the record; B then opens (and holds) a read lock on it. */
  FD_TEST( test_pull( A, acc.entry, xid, &key, &load_env ) );
  fd_progcache_rec_t * rec = fd_progcache_peek( B, xid, &key, 0UL, 0UL );
  FD_TEST( rec );

  /* A unmaps and detaches it via cancel.  Collection cannot happen while B
     reads it -- and A is not the join that becomes the final reader, which is
     exactly the stranding case. */
  fd_progcache_cancel_fork( A->join, xid );
  FD_TEST( fd_prog_reclaim_work( A->join )==0UL );      /* deferred: B still reading */

  /* B releases the read lock, and B (NOT A) is the join that collects it. */
  fd_progcache_rec_close( B, rec );
  FD_TEST( fd_prog_reclaim_work( B->join )==1UL );      /* cross-join collection */
  FD_TEST( fd_progcache_leave( B, NULL ) );
  test_env_destroy( env );
}

/* test_reclaim_txn_unlink: a deleted record stays linked to its txn until
   cancel detaches it; collection never touches the fork's record list. */

FD_UNIT_TEST( reclaim_txn_unlink ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 1UL
  };
  fd_progcache_rec_t * rec = test_pull( env->progcache, acc.entry, xid, &key, &load_env );
  FD_TEST( rec );

  uint txn_idx = atomic_load_explicit( &rec->txn_idx, memory_order_relaxed );
  FD_TEST( txn_idx!=UINT_MAX );
  fd_progcache_txn_t * txn = &env->progcache->join->txn.pool[ txn_idx ];
  FD_TEST( txn->rec_head_idx!=UINT_MAX );

  fd_prog_delete_rec( env->progcache->join, rec );
  /* The zombie stays on the fork's record list; the sweep leaves it alone. */
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==0UL );
  FD_TEST( txn->rec_head_idx!=UINT_MAX );

  /* Cancel detaches it; only then is it collectable. */
  fd_progcache_cancel_fork( env->progcache->join, xid );
  FD_TEST( txn->rec_head_idx==UINT_MAX );
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  test_env_destroy( env );
}

/* test_housekeeping: with class 0 full, each round of ticks gives the class
   one preevict turn, topping its free list to 2 slots and no further, without
   touching the eviction metrics. */

FD_UNIT_TEST( housekeeping ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_join_t *  join  = env->progcache->join;
  fd_progcache_shmem_t * shmem = join->shmem;
  fd_progcache_fork_id_t xid   = fd_progcache_attach_child( join, fd_progcache_fork_id_initial() );

  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };
  test_account_t * acc = fd_wksp_alloc_laddr( wksp, alignof(test_account_t), sizeof(test_account_t), 1UL );
  FD_TEST( acc );

  ulong class0_slots = shmem->cache.class_max[ 0 ];
  for( ulong i=0UL; i<class0_slots; i++ ) {
    fd_pubkey_t k = test_key( i+1UL );
    test_account_init( acc, &k, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
    FD_TEST( test_pull( env->progcache, acc->entry, xid, &k, &load_env ) );
  }
  xid = test_root( join, xid ); /* detach everything */
  FD_TEST( fd_progcache_class_free_cnt( shmem, 0UL )==0UL );

  ulong evicts0 = env->progcache->metrics->evict_cnt;
  for( ulong round=1UL; round<=3UL; round++ ) {
    for( ulong c=0UL; c<FD_PROGCACHE_CACHE_CLASS_CNT; c++ ) fd_progcache_housekeeping( join );
    FD_TEST( fd_progcache_class_free_cnt( shmem, 0UL )==fd_ulong_min( round, 2UL ) );
  }
  FD_TEST( env->progcache->metrics->evict_cnt==evicts0 );

  FD_TEST( !fd_progcache_verify( join ) );
  fd_progcache_cancel_fork( join, xid );
  fd_wksp_free_laddr( acc );
  test_env_destroy( env );
}

/* test_preevict: the housekeeping top-up frees a slot via the eviction sweep
   only when the class free list is below target, takes only rooted victims,
   and bumps no metrics. */

FD_UNIT_TEST( preevict ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_join_t *  join  = env->progcache->join;
  fd_progcache_shmem_t * shmem = join->shmem;
  fd_progcache_fork_id_t xid   = fd_progcache_attach_child( join, fd_progcache_fork_id_initial() );

  fd_prog_load_env_t   load_env = { .features = env->features, .feature_slot = 0UL };
  fd_pubkey_t          key[ 2 ];
  test_account_t       acc[ 2 ];
  fd_progcache_rec_t * rec[ 2 ];
  for( ulong i=0UL; i<2UL; i++ ) {
    key[ i ] = test_key( i+1UL );
    test_account_init( &acc[ i ], &key[ i ], &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
    rec[ i ] = test_pull( env->progcache, acc[ i ].entry, xid, &key[ i ], &load_env );
    FD_TEST( rec[ i ] );
  }

  ulong free0   = fd_progcache_class_free_cnt( shmem, 0UL );
  ulong evicts0 = env->progcache->metrics->evict_cnt;

  /* Attached records are not victims: the sweep comes up empty. */
  FD_TEST( fd_prog_preevict( join, 0UL, free0+1UL )==0UL );
  FD_TEST( fd_progcache_class_free_cnt( shmem, 0UL )==free0 );

  xid = test_root( join, xid ); /* detach both */

  /* Free list already at target: no sweep. */
  FD_TEST( fd_prog_preevict( join, 0UL, free0 )==0UL );
  FD_TEST( fd_progcache_class_free_cnt( shmem, 0UL )==free0 );

  /* Below target: one sweep claims a rooted victim and frees its slot. */
  FD_TEST( fd_prog_preevict( join, 0UL, free0+1UL )==1UL );
  FD_TEST( fd_progcache_class_free_cnt( shmem, 0UL )==free0+1UL );

  /* Exactly one of the two is gone, and the admin sweep bumped no metrics. */
  uchar st0 = __atomic_load_n( &rec[ 0 ]->state, __ATOMIC_RELAXED );
  uchar st1 = __atomic_load_n( &rec[ 1 ]->state, __ATOMIC_RELAXED );
  FD_TEST( ( st0==0 ) ^ ( st1==0 ) );
  FD_TEST( env->progcache->metrics->evict_cnt==evicts0 );

  /* Back at target: no further sweep. */
  FD_TEST( fd_prog_preevict( join, 0UL, free0+1UL )==0UL );

  FD_TEST( !fd_progcache_verify( join ) );
  fd_progcache_cancel_fork( join, xid );
  test_env_destroy( env );
}

/* test_preevict_zombie: a zombie drawn by the admin sweep is handed over and
   its slot released to the free list, without bumping the eviction metrics. */

FD_UNIT_TEST( preevict_zombie ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_join_t *  join  = env->progcache->join;
  fd_progcache_shmem_t * shmem = join->shmem;
  fd_progcache_fork_id_t xid   = fd_progcache_attach_child( join, fd_progcache_fork_id_initial() );

  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };
  fd_pubkey_t    key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
  fd_progcache_rec_t * rec = test_pull( env->progcache, acc.entry, xid, &key, &load_env );
  FD_TEST( rec );

  xid = test_root( join, xid ); /* detach */
  FD_TEST( fd_prog_delete_rec( join, rec )>=0L ); /* zombie */

  ulong free0   = fd_progcache_class_free_cnt( shmem, 0UL );
  ulong evicts0 = env->progcache->metrics->evict_cnt;

  /* Aim the hand at the zombie: the sweep hands it over, preevict frees it. */
  shmem->cache.clock_hand[ 0 ].val = (ulong)( rec - join->rec.ele ) - shmem->cache.rec_base[ 0 ];
  FD_TEST( fd_prog_preevict( join, 0UL, free0+1UL )==1UL );
  FD_TEST( fd_progcache_class_free_cnt( shmem, 0UL )==free0+1UL );
  FD_TEST( __atomic_load_n( &rec->state, __ATOMIC_RELAXED )==0 );
  FD_TEST( env->progcache->metrics->evict_cnt==evicts0 );

  FD_TEST( !fd_progcache_verify( join ) );
  fd_progcache_cancel_fork( join, xid );
  test_env_destroy( env );
}

FD_UNIT_TEST( join_null_scratch ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 512UL<<20 ), 1UL );
  FD_TEST( fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, 512UL<<20 ) );
  fd_progcache_t cache[1];
  FD_TEST( !fd_progcache_join( cache, mem, NULL, 4096UL ) );
  fd_wksp_free_laddr( fd_progcache_shmem_delete( mem ) );
}

FD_UNIT_TEST( join_misaligned_scratch ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 512UL<<20 ), 1UL );
  FD_TEST( fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, 512UL<<20 ) );
  uchar scratch_buf[ FD_PROGCACHE_SCRATCH_ALIGN ] __attribute__((aligned(FD_PROGCACHE_SCRATCH_ALIGN)));
  fd_progcache_t cache[1];
  FD_TEST( !fd_progcache_join( cache, mem, scratch_buf+1, sizeof(scratch_buf)-1 ) );
  fd_wksp_free_laddr( fd_progcache_shmem_delete( mem ) );
}

FD_UNIT_TEST( shmem_new_zero_txn_max ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 512UL<<20 ), 1UL );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, 0UL, 512UL<<20 ) );
  fd_wksp_free_laddr( mem );
}

FD_UNIT_TEST( shmem_new_oversized_txn_max ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 512UL<<20 ), 1UL );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, (ulong)UINT_MAX+1UL, 512UL<<20 ) );
  fd_wksp_free_laddr( mem );
}

/* test_cache_class: footprint -> class mapping boundaries. */

FD_UNIT_TEST( cache_class ) {
  FD_TEST( fd_progcache_cache_class(          0UL )==0UL ); /* non-executable: smallest class */
  FD_TEST( fd_progcache_cache_class(          1UL )==0UL );
  FD_TEST( fd_progcache_cache_class(     131072UL )==0UL );
  FD_TEST( fd_progcache_cache_class(     131073UL )==1UL );
  FD_TEST( fd_progcache_cache_class(     524288UL )==1UL );
  FD_TEST( fd_progcache_cache_class(    1048576UL )==2UL );
  FD_TEST( fd_progcache_cache_class(    2097152UL )==3UL );
  FD_TEST( fd_progcache_cache_class(    2097153UL )==4UL );
  FD_TEST( fd_progcache_cache_class(    4194304UL )==4UL );
  FD_TEST( fd_progcache_cache_class(    4194305UL )==5UL );
  FD_TEST( fd_progcache_cache_class( FD_RUNTIME_ACC_SZ_MAX )==5UL );
  FD_TEST( fd_progcache_cache_class( FD_PROGCACHE_CACHE_SLOT_TOP_SZ )==5UL );
  FD_TEST( fd_progcache_cache_class( FD_PROGCACHE_CACHE_SLOT_TOP_SZ+1UL )==FD_PROGCACHE_CACHE_CLASS_CNT );
}

/* test_cache_provision: the provisioner fits the budget, never starves a
   class, scales the nx class off the data classes, and rejects tiny
   budgets. */

static void
check_provision( ulong txn_max,
                 ulong heap ) {
  ulong sc[ FD_PROGCACHE_CACHE_CLASS_CNT ];
  ulong rec_max = fd_progcache_setup_slots( txn_max, heap, sc );
  FD_TEST( rec_max );
  ulong used = 0UL;
  ulong tot  = 0UL;
  for( ulong c=0UL; c<FD_PROGCACHE_CACHE_CLASS_CNT; c++ ) {
    if( c<FD_PROGCACHE_CACHE_CLASS_CNT ) FD_TEST( sc[c]>=fd_progcache_cache_class_min( c ) );
    used += sc[c]*fd_progcache_cache_slot_sz[c];
    tot  += sc[c];
  }
  FD_TEST( tot==rec_max );

  /* The budget covers everything, so it is what the caller must reserve. */
  FD_TEST( fd_progcache_shmem_footprint( txn_max, heap )==heap );
  FD_TEST( used<heap );
}

FD_UNIT_TEST( cache_provision ) {
  ulong txn_max = 64UL;
  check_provision( txn_max, 1792UL<<20 ); /* production default */
  check_provision( txn_max,  768UL<<20 );
  check_provision( txn_max,  512UL<<20 );

  /* The structural minimum provisions with every class at its guaranteed
     minimum; one byte less is rejected. */
  ulong min_sz = fd_progcache_shmem_min_sz( txn_max );
  check_provision( txn_max, min_sz );
  ulong sc[ FD_PROGCACHE_CACHE_CLASS_CNT ];
  FD_TEST( !fd_progcache_setup_slots( txn_max, min_sz-1UL, sc ) );
  FD_TEST(  fd_progcache_setup_slots( txn_max, min_sz,     sc ) );
  for( ulong c=0UL; c<FD_PROGCACHE_CACHE_CLASS_CNT; c++ ) {
    FD_TEST( sc[ c ]==fd_progcache_cache_class_min( c ) );
  }
}

/* test_shmem_dirty_memory: construction must not rely on zero-filled
   memory.  Pattern-fill the shmem region, construct, use, and delete: a
   constructor that leaves cache fields (notably arena_gaddr) uninitialized
   would free garbage addresses on delete. */

FD_UNIT_TEST( shmem_dirty_memory ) {
  ulong txn_max = 16UL;
  ulong heap    = 512UL<<20;
  ulong fp      = fd_progcache_shmem_footprint( txn_max, heap );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fp, 1UL );
  FD_TEST( mem );
  fd_memset( mem, 0xCC, fp );
  fd_progcache_shmem_t * shmem = fd_progcache_shmem_new( mem, 1UL, 1UL, txn_max, heap );
  FD_TEST( shmem );

  fd_progcache_t cache[1];
  uchar * scratch = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT, 1UL );
  FD_TEST( fd_progcache_join( cache, shmem, scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( cache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
  fd_features_t features[1]; memset( features, 0, sizeof(fd_features_t) );
  fd_prog_load_env_t load_env = { .features = features, .feature_slot = 0UL };
  FD_TEST( test_pull( cache, acc.entry, xid, &key, &load_env ) );

  fd_progcache_cancel_fork( cache->join, xid );
  FD_TEST( !fd_progcache_verify( cache->join ) );
  FD_TEST( fd_progcache_leave( cache, NULL ) );
  fd_wksp_free_laddr( fd_progcache_shmem_delete( shmem ) );
  fd_wksp_free_laddr( scratch );
}

/* The smallest accepted progcache_sz brackets the class-minimum gate in
   setup_slots, which the tests above do not reach. */

FD_UNIT_TEST( provision_boundary ) {
  ulong txn_max = 16UL;
  ulong sz;
  for( sz=64UL<<20; sz<=512UL<<20; sz += 1UL<<20 ) {
    if( fd_progcache_shmem_footprint( txn_max, sz ) ) break;
  }
  FD_TEST( sz<=512UL<<20 );                                          /* boundary found */
  FD_TEST( !fd_progcache_shmem_footprint( txn_max, sz-(1UL<<20) ) ); /* below: rejected */

  ulong fp = fd_progcache_shmem_footprint( txn_max, sz );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fp, 1UL );
  FD_TEST( mem );
  fd_progcache_shmem_t * shmem = fd_progcache_shmem_new( mem, 1UL, 1UL, txn_max, sz );
  FD_TEST( shmem );                                                  /* boundary constructs */
  fd_wksp_free_laddr( fd_progcache_shmem_delete( shmem ) );
}

FD_UNIT_TEST( shmem_new_small_heap ) {
  /* a budget too small for every class is rejected */
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 512UL<<20 ), 1UL );
  FD_TEST( !fd_progcache_shmem_footprint( 16UL, 16UL<<20 ) );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, 16UL<<20 ) );
  fd_wksp_free_laddr( mem );
}

/* fd_progcache_verify must reject a corrupted structure, not just accept a
   healthy one.  Each case perturbs one invariant, checks verify fails, then
   restores it. */

FD_UNIT_TEST( verify_detects_corruption ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_join_t * join = env->progcache->join;
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key1 = test_key( 1UL );
  test_account_t acc1;
  test_account_init( &acc1, &key1, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };
  fd_progcache_rec_t * rec = test_pull( env->progcache, acc1.entry, xid, &key1, &load_env );
  FD_TEST( rec );
  ulong rec_idx = (ulong)( rec - join->rec.ele );
  FD_TEST( !fd_progcache_verify( join ) );

  FD_LOG_NOTICE(( "injecting corruption: the FAIL warnings below are expected" ));

  /* A mapped record must be LIVE. */
  uchar st = __atomic_load_n( &join->rec.ele[ rec_idx ].state, __ATOMIC_RELAXED );
  __atomic_store_n( &join->rec.ele[ rec_idx ].state, (uchar)( st & ~FD_PROGCACHE_REC_LIVE ), __ATOMIC_RELAXED );
  FD_TEST( fd_progcache_verify( join ) );
  __atomic_store_n( &join->rec.ele[ rec_idx ].state, st, __ATOMIC_RELAXED );
  FD_TEST( !fd_progcache_verify( join ) );

  /* A mapped record must exist. */
  rec->exists = 0;
  FD_TEST( fd_progcache_verify( join ) );
  rec->exists = 1;
  FD_TEST( !fd_progcache_verify( join ) );

  /* The magic guards the whole structure. */
  ulong magic = join->shmem->magic;
  join->shmem->magic = 0UL;
  FD_TEST( fd_progcache_verify( join ) );
  join->shmem->magic = magic;
  FD_TEST( !fd_progcache_verify( join ) );

  /* A txn record list must be prev/next consistent. */
  uint saved_prev = rec->prev_idx;
  rec->prev_idx = 12345U;
  FD_TEST( fd_progcache_verify( join ) );
  rec->prev_idx = saved_prev;
  FD_TEST( !fd_progcache_verify( join ) );

  fd_progcache_cancel_fork( join, xid );
  FD_TEST( !fd_progcache_verify( join ) );
  test_env_destroy( env );
}

FD_UNIT_TEST( shmem_delete_fast ) {
  ulong txn_max  = 16UL;
  ulong wksp_tag =  2UL;

  fd_progcache_shmem_t * progcache_mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, 512UL<<20 ), wksp_tag );
  FD_TEST( fd_progcache_shmem_new( progcache_mem, wksp_tag, 1UL, txn_max, 512UL<<20 ) );

  uchar scratch[ 65536 ] __attribute__((aligned(FD_PROGCACHE_SCRATCH_ALIGN)));
  fd_progcache_t cache[1];
  FD_TEST( fd_progcache_join( cache, progcache_mem, scratch, sizeof(scratch) ) );

  fd_progcache_fork_id_t fork = fd_progcache_attach_child( cache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  fd_features_t features[1]; memset( features, 0, sizeof(fd_features_t) );
  fd_prog_load_env_t load_env = {
    .features     = features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t * rec = test_pull( cache, acc.entry, fork, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->data_gaddr );

  fd_progcache_shmem_t * shmem_out = NULL;
  FD_TEST( fd_progcache_leave( cache, &shmem_out ) );
  FD_TEST( shmem_out==(fd_progcache_shmem_t *)progcache_mem );

  FD_TEST( fd_progcache_shmem_delete_fast( shmem_out ) );
}

/* test_reclaim_mixed: of two zombies, only the one without an active reader
   is collected; the other waits for its close. */

FD_UNIT_TEST( reclaim_mixed ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key1 = test_key( 1UL );
  fd_pubkey_t key2 = test_key( 2UL );
  test_account_t acc1, acc2;
  test_account_init( &acc1, &key1, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  test_account_init( &acc2, &key2, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  FD_TEST( test_pull( env->progcache, acc1.entry, xid, &key1, &load_env ) );
  FD_TEST( test_pull( env->progcache, acc2.entry, xid, &key2, &load_env ) );

  fd_progcache_rec_t * rec1 = fd_progcache_peek( env->progcache, xid, &key1, 0UL, 0UL );
  FD_TEST( rec1 );
  fd_progcache_rec_t * rec2 = fd_progcache_peek( env->progcache, xid, &key2, 0UL, 0UL );
  FD_TEST( rec2 );
  fd_progcache_rec_close( env->progcache, rec2 );

  /* Cancel unmaps and detaches both; rec1 is still read-held. */
  fd_progcache_cancel_fork( env->progcache->join, xid );

  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL ); /* rec2 only */

  /* rec1's close makes the remaining zombie collectable. */
  fd_progcache_rec_close( env->progcache, rec1 );
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  test_env_destroy( env );
}

FD_UNIT_TEST( loader_v3_ok ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t fork_a = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  uchar buf[ 655536 ];
  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init_v3_data(
      &acc,
      buf, sizeof(buf),
      &key,
      valid_program_data, valid_program_data_sz,
      42UL
  );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->data_gaddr );

  FD_TEST( test_peek( env->progcache, fork_a, &key, 0UL, 42UL )==rec  );
  FD_TEST( test_peek( env->progcache, fork_a, &key, 0UL,  0UL )==NULL );

  fd_progcache_cancel_fork( env->progcache->join, fork_a );
  test_env_destroy( env );
}

FD_UNIT_TEST( loader_v3_wrong_account_type ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t fork_a = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  ulong data_sz = PROGRAMDATA_METADATA_SIZE + valid_program_data_sz;
  uchar data[ PROGRAMDATA_METADATA_SIZE + 1048576 ];
  FD_TEST( data_sz<=sizeof(data) );

  fd_bpf_state_t state = {
    .discriminant = FD_BPF_STATE_BUFFER,
    .inner = { .buffer = { .has_authority_address = 0, .authority_address = {{0}} } }
  };
  ulong out_sz = 0UL;
  FD_TEST( !fd_bpf_state_encode( &state, data, PROGRAMDATA_METADATA_SIZE, &out_sz ) );
  fd_memcpy( data+PROGRAMDATA_METADATA_SIZE, valid_program_data, valid_program_data_sz );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_upgradeable_program_id,
                     1, data, data_sz );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, fork_a, &key, &load_env );
  FD_TEST( !rec );

  fd_progcache_cancel_fork( env->progcache->join, fork_a );
  test_env_destroy( env );
}

FD_UNIT_TEST( loader_v3_undersize ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t fork_a = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  uchar data[ PROGRAMDATA_METADATA_SIZE-1 ];
  memset( data, 0, sizeof(data) );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_upgradeable_program_id,
                     1, data, sizeof(data) );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, fork_a, &key, &load_env );
  FD_TEST( !rec );

  fd_progcache_cancel_fork( env->progcache->join, fork_a );
  test_env_destroy( env );
}

FD_UNIT_TEST( loader_v3_corrupt ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t fork_a = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  uchar data[ PROGRAMDATA_METADATA_SIZE+1 ];
  memset( data, 0x41, sizeof(data) );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_upgradeable_program_id,
                     1, data, sizeof(data) );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, fork_a, &key, &load_env );
  FD_TEST( !rec );

  fd_progcache_cancel_fork( env->progcache->join, fork_a );
  test_env_destroy( env );
}

FD_UNIT_TEST( loader_v3_epoch_boundary ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t fork_a = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  uchar buf[ 655536 ];
  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init_v3_data(
      &acc,
      buf, sizeof(buf),
      &key,
      valid_program_data, valid_program_data_sz,
      42UL
  );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t const * rec1 = test_pull( env->progcache, acc.entry, fork_a, &key, &load_env );
  FD_TEST( rec1 );
  FD_TEST( rec1->data_gaddr );

  fd_progcache_fork_id_t fork_b = fd_progcache_attach_child( env->progcache->join, fork_a );

  load_env.feature_slot = 100UL;
  fd_progcache_rec_t const * rec2 = test_pull( env->progcache, acc.entry, fork_b, &key, &load_env );
  FD_TEST( rec2 );
  FD_TEST( rec2->data_gaddr );
  FD_TEST( rec1!=rec2 );

  FD_TEST( test_peek( env->progcache, fork_a, &key,   0UL, 42UL )==rec1 );
  FD_TEST( test_peek( env->progcache, fork_b, &key, 100UL, 42UL )==rec2 );
  FD_TEST( test_peek( env->progcache, fork_b, &key,   0UL, 42UL )==rec1 );

  fd_progcache_advance_root( env->progcache->join, fork_a );
  FD_TEST( test_peek( env->progcache, fork_a, &key,   0UL, 42UL )==rec1 );
  FD_TEST( test_peek( env->progcache, fork_b, &key, 100UL, 42UL )==rec2 );
  FD_TEST( test_peek( env->progcache, fork_b, &key,   0UL, 42UL )==rec1 );

  test_env_destroy( env );
}

FD_UNIT_TEST( loader_v3_epoch_boundary_skipped_slots ) {
  test_env_t * env = test_env_create( wksp );

  ulong const mainnet_slots_per_epoch = 432000UL;
  ulong const epoch                   = 1000UL;
  ulong const e0                      = mainnet_slots_per_epoch * epoch;

  fd_pubkey_t key = test_key( 1UL );
  test_account_t fork_a_acc;
  uchar fork_a_buf[ 65536 ];
  test_account_init_v3_data(
      &fork_a_acc,
      fork_a_buf, sizeof(fork_a_buf),
      &key,
      bigger_valid_program_data, bigger_valid_program_data_sz,
      e0-1UL
  );

  test_account_t fork_b_acc;
  uchar fork_b_buf[ 65536 ];
  test_account_init_v3_data(
      &fork_b_acc,
      fork_b_buf, sizeof(fork_b_buf),
      &key,
      valid_program_data, valid_program_data_sz,
      1UL
  );
  FD_TEST( fork_a_acc.entry->data_len!=fork_b_acc.entry->data_len );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = e0
  };

  fd_progcache_fork_id_t root = fd_progcache_fork_id_initial();

  /* Fork A upgraded the program at e0-1 and invokes after skipped slot e0. */
  fd_progcache_fork_id_t fork_a_deploy = fd_progcache_attach_child( env->progcache->join, root );
  fd_progcache_fork_id_t fork_a_invoke = fd_progcache_attach_child( env->progcache->join, fork_a_deploy );

  fd_progcache_rec_t const * rec_a = test_pull( env->progcache, fork_a_acc.entry, fork_a_invoke, &key, &load_env );
  FD_TEST( rec_a );
  FD_TEST( rec_a->data_gaddr );
  FD_TEST( query_rec_exact( env, fork_a_deploy, &key )==NULL  );
  FD_TEST( query_rec_exact( env, fork_a_invoke, &key )==rec_a );
  FD_TEST( query_rec_exact( env, root, &key )==NULL );

  /* Fork B crosses the same skipped epoch boundary without fork A's
     upgrade.  It supplies different loader-v3 ProgramData bytes, so it
     must not receive fork A's loaded program record. */
  fd_progcache_fork_id_t fork_b_invoke = fd_progcache_attach_child( env->progcache->join, root );

  fd_progcache_rec_t const * rec_b = test_pull( env->progcache, fork_b_acc.entry, fork_b_invoke, &key, &load_env );
  FD_TEST( rec_b );
  FD_TEST( rec_b!=rec_a );
  FD_TEST( query_rec_exact( env, fork_a_invoke, &key )==rec_a );
  FD_TEST( query_rec_exact( env, fork_b_invoke, &key )==rec_b );
  FD_TEST( query_rec_exact( env, root,          &key )==NULL  );

  fd_progcache_cancel_fork( env->progcache->join, fork_b_invoke );
  fd_progcache_cancel_fork( env->progcache->join, fork_a_deploy );

  test_env_destroy( env );
}

/* test_clock_evict_all_visited: First pass clears visited bits,
   second pass evicts. */

FD_UNIT_TEST( clock_evict_all_visited ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key1 = test_key( 1UL );
  fd_pubkey_t key2 = test_key( 2UL );
  fd_pubkey_t key3 = test_key( 3UL );
  test_account_t acc1, acc2, acc3;
  test_account_init( &acc1, &key1, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  test_account_init( &acc2, &key2, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  test_account_init( &acc3, &key3, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };

  fd_progcache_rec_t * rec1 = test_pull( env->progcache, acc1.entry, xid, &key1, &load_env );
  fd_progcache_rec_t * rec2 = test_pull( env->progcache, acc2.entry, xid, &key2, &load_env );
  fd_progcache_rec_t * rec3 = test_pull( env->progcache, acc3.entry, xid, &key3, &load_env );
  FD_TEST( rec1 && rec2 && rec3 );

  xid = test_root( env->progcache->join, xid ); /* only rooted records are evictable */

  /* Ensure visited bits are set */
  ulong rec1_idx = (ulong)( rec1 - env->progcache->join->rec.ele );
  ulong rec2_idx = (ulong)( rec2 - env->progcache->join->rec.ele );
  ulong rec3_idx = (ulong)( rec3 - env->progcache->join->rec.ele );
  fd_prog_state_touch( env->progcache->join->rec.ele, rec1_idx );
  fd_prog_state_touch( env->progcache->join->rec.ele, rec2_idx );
  fd_prog_state_touch( env->progcache->join->rec.ele, rec3_idx );

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;

  /* Per-class CLOCK: each fd_prog_evict clears a visited victim (second
     chance) or evicts an unvisited one; three calls evict all three
     (all three programs live in the same small class). */
  for( ulong i=0UL; i<3UL; i++ ) test_evict( env->progcache, valid_program_data_sz );

  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before == 3UL );
  FD_TEST( !test_peek( env->progcache, xid, &key1, 0UL, 0UL ) );
  FD_TEST( !test_peek( env->progcache, xid, &key2, 0UL, 0UL ) );
  FD_TEST( !test_peek( env->progcache, xid, &key3, 0UL, 0UL ) );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_clock_evict_unvisited: an unvisited entry is evicted on the next pass. */

FD_UNIT_TEST( clock_evict_unvisited ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key1 = test_key( 1UL );
  test_account_t acc1;
  test_account_init( &acc1, &key1, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t * rec1 = test_pull( env->progcache, acc1.entry, xid, &key1, &load_env );
  FD_TEST( rec1 );

  xid = test_root( env->progcache->join, xid ); /* only rooted records are evictable */

  ulong rec_idx = (ulong)( rec1 - env->progcache->join->rec.ele );

  /* Clear visited flag so the next pass evicts immediately (no second chance) */
  __atomic_fetch_and( &env->progcache->join->rec.ele[ rec_idx ].state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  test_evict( env->progcache, valid_program_data_sz );

  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before == 1UL );
  FD_TEST( !test_peek( env->progcache, xid, &key1, 0UL, 0UL ) );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_clock_evict_empty_cache: No-op eviction on empty cache. */

FD_UNIT_TEST( clock_evict_empty_cache ) {
  test_env_t * env = test_env_create( wksp );

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  test_evict( env->progcache, valid_program_data_sz );

  FD_TEST( env->progcache->metrics->evict_cnt == evict_cnt_before );
  FD_TEST( !fd_progcache_verify( env->progcache->join ) );

  test_env_destroy( env );
}

/* test_clock_evict_rooted_claim: a zombie drawn by the sweep is handed over
   directly, leaving the live record untouched, while a rooted mapped record
   is claimed via delete; both count as successful evicts. */

FD_UNIT_TEST( clock_evict_rooted_claim ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_join_t *  join = env->progcache->join;
  fd_progcache_fork_id_t xid  = fd_progcache_attach_child( join, fd_progcache_fork_id_initial() );

  fd_pubkey_t keyA = test_key( 1UL );
  fd_pubkey_t keyB = test_key( 2UL );
  test_account_t accA, accB;
  test_account_init( &accA, &keyA, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
  test_account_init( &accB, &keyB, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };

  fd_progcache_rec_t * recA = test_pull( env->progcache, accA.entry, xid, &keyA, &load_env );
  fd_progcache_rec_t * recB = test_pull( env->progcache, accB.entry, xid, &keyB, &load_env );
  FD_TEST( recA && recB && recA!=recB );

  /* Rooting detaches both but leaves them mapped. */
  fd_progcache_advance_root( join, xid );
  FD_TEST( atomic_load_explicit( &recA->txn_idx, memory_order_relaxed )==UINT_MAX );

  /* Turn B into a zombie. */
  FD_TEST( fd_prog_delete_rec( join, recB )>=0L );

  /* Spend A's second chance so a draw on its slot takes it. */
  __atomic_fetch_and( &join->rec.ele[ recA-join->rec.ele ].state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );

  ulong base    = join->shmem->cache.rec_base[ 0 ];
  ulong evicts0 = env->progcache->metrics->evict_cnt;
  ulong evsz0   = env->progcache->metrics->evict_tot_sz;
  ulong szA     = recA->rodata_sz;
  ulong szB     = recB->rodata_sz;
  FD_TEST( szA && szB );

  /* Aim the hand at B: the zombie is handed over, A untouched. */
  join->shmem->cache.clock_hand[ 0 ].val = (ulong)( recB - join->rec.ele ) - base;
  fd_progcache_rec_t * got = fd_prog_evict( env->progcache, valid_program_data_sz );
  FD_TEST( got==recB );
  FD_TEST( env->progcache->metrics->evict_cnt   ==evicts0+1UL );
  FD_TEST( env->progcache->metrics->evict_tot_sz==evsz0+szB );
  uchar stA = __atomic_load_n( &recA->state, __ATOMIC_RELAXED );
  FD_TEST( ( stA & ( FD_PROGCACHE_REC_LIVE|FD_PROGCACHE_REC_MAPPED ) )==( FD_PROGCACHE_REC_LIVE|FD_PROGCACHE_REC_MAPPED ) );
  FD_TEST( !fd_progcache_verify( join ) );
  fd_progcache_rec_abandon( join, got );

  /* Aim the hand at A: the live record is claimed via delete. */
  join->shmem->cache.clock_hand[ 0 ].val = (ulong)( recA - join->rec.ele ) - base;
  got = fd_prog_evict( env->progcache, valid_program_data_sz );
  FD_TEST( got==recA );
  FD_TEST( env->progcache->metrics->evict_cnt   ==evicts0+2UL );
  FD_TEST( env->progcache->metrics->evict_tot_sz==evsz0+szB+szA );
  FD_TEST( !fd_progcache_verify( join ) );
  fd_progcache_rec_abandon( join, got );

  test_env_destroy( env );
}

/* test_delete_rec_claim_aba: a sweep decides to evict a record, the slot is
   reused under a different key before the claim lands, and the decided-on key
   must be what gets removed -- so the new owner's entry survives. */

FD_UNIT_TEST( delete_rec_claim_aba ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_join_t *  join = env->progcache->join;
  fd_progcache_fork_id_t xid  = fd_progcache_attach_child( join, fd_progcache_fork_id_initial() );

  fd_pubkey_t keyA = test_key( 1UL );
  fd_pubkey_t keyB = test_key( 2UL );
  test_account_t accA, accB;
  test_account_init( &accA, &keyA, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
  test_account_init( &accB, &keyB, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };

  /* A occupies a slot; snapshot the key a sweep would have decided on. */
  fd_progcache_rec_t * recA = test_pull( env->progcache, accA.entry, xid, &keyA, &load_env );
  FD_TEST( recA );
  fd_progcache_rec_key_t pairA = recA->pair;

  /* Retire the slot and hand it to B. */
  xid = test_root( join, xid ); /* detach A so the sweep can collect it */
  FD_TEST( fd_prog_delete_rec( join, recA )>=0L );
  FD_TEST( fd_prog_reclaim_work( join )==1UL );
  fd_progcache_rec_t * recB = test_pull( env->progcache, accB.entry, xid, &keyB, &load_env );
  FD_TEST( recB==recA ); /* same slot, different key */

  /* The stale decision must not remove B. */
  FD_TEST( fd_prog_delete_rec_claim( join, recB, &pairA )==-1L );
  FD_TEST( !fd_progcache_verify( join ) );

  FD_TEST( test_peek( env->progcache, xid, &keyB, 0UL, recB->deploy_slot )==recB ); /* peek does not fill */

  test_env_destroy( env );
}

/* test_clock_evict_delete_fails: a stale LIVE byte on a freed slot reads as
   a zombie; the sweep skips it (a free slot is write-locked) and evicts the
   next candidate. */

FD_UNIT_TEST( clock_evict_delete_fails ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key1 = test_key( 1UL );
  fd_pubkey_t key2 = test_key( 2UL );
  test_account_t acc1, acc2;
  test_account_init( &acc1, &key1, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  test_account_init( &acc2, &key2, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t * rec1 = test_pull( env->progcache, acc1.entry, xid, &key1, &load_env );
  fd_progcache_rec_t * rec2 = test_pull( env->progcache, acc2.entry, xid, &key2, &load_env );
  FD_TEST( rec1 && rec2 );

  xid = test_root( env->progcache->join, xid ); /* only rooted records are evictable */

  ulong rec1_idx = (ulong)( rec1 - env->progcache->join->rec.ele );
  ulong rec2_idx = (ulong)( rec2 - env->progcache->join->rec.ele );

  /* Clear visited flags */
  fd_progcache_rec_t * recs = env->progcache->join->rec.ele;
  __atomic_fetch_and( &recs[ rec1_idx ].state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );
  __atomic_fetch_and( &recs[ rec2_idx ].state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );

  /* Remove rec1 from index, then re-set its LIVE flag to simulate a stale
     state byte (race between concurrent delete and eviction). */
  fd_prog_delete_rec( env->progcache->join, rec1 );
  fd_prog_reclaim_work( env->progcache->join );
  __atomic_fetch_or( &recs[ rec1_idx ].state, FD_PROGCACHE_REC_LIVE, __ATOMIC_RELAXED );

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;

  /* rec1's stale LIVE byte reads as a zombie whose free slot is write-locked,
     so the sweep skips it; rec2 (unvisited) is evicted. */
  test_evict( env->progcache, valid_program_data_sz );

  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before >= 1UL );
  FD_TEST( !test_peek( env->progcache, xid, &key2, 0UL, 0UL ) );

  fd_prog_state_clear( recs, rec1_idx ); /* undo the injected flag */
  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_evict_hands_over_slot: an unheld first candidate is handed straight to
   the caller -- the sweep stops there, and the slot never appears on the class
   free list where another thread could take it. */

FD_UNIT_TEST( evict_hands_over_slot ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };

  /* Two unheld candidates, so stopping at the first is observable. */
  fd_pubkey_t          key[ 2 ];
  fd_progcache_rec_t * rec[ 2 ];
  for( ulong i=0UL; i<2UL; i++ ) {
    key[ i ] = test_key( i+1UL );
    test_account_t acc;
    test_account_init( &acc, &key[ i ], &fd_solana_bpf_loader_program_id,
                       1, valid_program_data, valid_program_data_sz );
    rec[ i ] = test_pull( env->progcache, acc.entry, xid, &key[ i ], &load_env );
    FD_TEST( rec[ i ] );
  }

  fd_progcache_join_t * join  = env->progcache->join;
  xid = test_root( join, xid ); /* only rooted records are evictable */
  for( ulong i=0UL; i<2UL; i++ )
    __atomic_fetch_and( &rec[ i ]->state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );

  ulong lo           = rec[ 1 ]<rec[ 0 ] ? 1UL : 0UL;  /* the sweep walks low index to high */
  ulong c            = fd_progcache_rec_class( join->shmem, (ulong)( rec[ lo ] - join->rec.ele ) );
  ulong free_before  = fd_progcache_class_free_cnt( join->shmem, c );
  ulong evict_before = env->progcache->metrics->evict_cnt;

  fd_progcache_rec_t * got = fd_prog_evict( env->progcache, valid_program_data_sz );
  FD_TEST( got==rec[ lo ] );                                                    /* the first candidate */
  FD_TEST( env->progcache->metrics->evict_cnt-evict_before==1UL );              /* stopped there */
  FD_TEST( fd_progcache_class_free_cnt( join->shmem, c )==free_before ); /* never went free */
  FD_TEST( got->data_gaddr );                                                   /* usable: value slot attached */
  FD_TEST( got->lock.value==(ushort)1 );                                        /* read-locked by us alone */
  FD_TEST( !test_peek( env->progcache, xid, &key[ lo ], 0UL, 0UL ) );           /* out of the map */
  FD_TEST( test_peek( env->progcache, xid, &key[ 1UL-lo ], 0UL, 0UL ) );        /* the other survived */

  fd_progcache_rec_abandon( join, got );
  FD_TEST( fd_progcache_class_free_cnt( join->shmem, c )==free_before+1UL );

  fd_progcache_cancel_fork( join, xid );
  test_env_destroy( env );
}

/* test_evict_skips_pinned_victims: a record whose reader has not released would
   yield no slot, so the sweep steps over it -- leaving it mapped -- and takes the
   next unreferenced one. */

FD_UNIT_TEST( evict_skips_pinned_victims ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };

  fd_pubkey_t          key[ 2 ];
  fd_progcache_rec_t * rec[ 2 ];
  for( ulong i=0UL; i<2UL; i++ ) {
    key[ i ] = test_key( i+1UL );
    test_account_t acc;
    test_account_init( &acc, &key[ i ], &fd_solana_bpf_loader_program_id,
                       1, valid_program_data, valid_program_data_sz );
    rec[ i ] = fd_progcache_pull( env->progcache, xid, &key[ i ], &load_env, acc.entry );
    FD_TEST( rec[ i ] );
  }

  fd_progcache_join_t * join  = env->progcache->join;
  xid = test_root( join, xid ); /* only rooted records are evictable */

  /* The sweep walks the class low index to high, so releasing the higher of the
     two leaves a read-locked victim in front of it. */
  ulong hi = rec[ 1 ]>rec[ 0 ] ? 1UL : 0UL;
  ulong lo = 1UL-hi;
  fd_progcache_rec_close( env->progcache, rec[ hi ] );

  for( ulong i=0UL; i<2UL; i++ )
    __atomic_fetch_and( &rec[ i ]->state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );

  ulong c            = fd_progcache_rec_class( join->shmem, (ulong)( rec[ hi ] - join->rec.ele ) );
  ulong free_before  = fd_progcache_class_free_cnt( join->shmem, c );
  ulong evict_before = env->progcache->metrics->evict_cnt;

  fd_progcache_rec_t * got = fd_prog_evict( env->progcache, valid_program_data_sz );
  FD_TEST( got==rec[ hi ] );                                       /* skipped past the pinned victim */
  FD_TEST( env->progcache->metrics->evict_cnt-evict_before==1UL ); /* only the unreferenced one unmapped */
  FD_TEST( fd_progcache_class_free_cnt( join->shmem, c )==free_before ); /* handed over, not freed */
  FD_TEST(  test_peek( env->progcache, xid, &key[ lo ], 0UL, 0UL ) ); /* the pinned entry still serves */
  FD_TEST( !test_peek( env->progcache, xid, &key[ hi ], 0UL, 0UL ) );

  /* Only the claimed slot returns: the skipped record was never unmapped, so
     releasing its reader leaves it mapped. */
  fd_progcache_rec_abandon( join, got );
  fd_progcache_rec_close( env->progcache, rec[ lo ] );
  FD_TEST( fd_progcache_class_free_cnt( join->shmem, c )==free_before+1UL );

  fd_progcache_cancel_fork( join, xid );
  test_env_destroy( env );
}

/* test_evict_gives_up_when_all_pinned: with every candidate read-locked the sweep
   hands back nothing and unmaps nothing -- the caller spills from here, and the
   cache keeps every entry it had. */

FD_UNIT_TEST( evict_gives_up_when_all_pinned ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };

  /* Every record in the class held, so a sweep that unmapped its victims before
     testing them would wipe all three. */
  fd_pubkey_t          key[ 3 ];
  fd_progcache_rec_t * rec[ 3 ];
  for( ulong i=0UL; i<3UL; i++ ) {
    key[ i ] = test_key( i+1UL );
    test_account_t acc;
    test_account_init( &acc, &key[ i ], &fd_solana_bpf_loader_program_id,
                       1, valid_program_data, valid_program_data_sz );
    rec[ i ] = fd_progcache_pull( env->progcache, xid, &key[ i ], &load_env, acc.entry );
    FD_TEST( rec[ i ] );
  }

  fd_progcache_join_t * join  = env->progcache->join;
  for( ulong i=0UL; i<3UL; i++ )
    __atomic_fetch_and( &rec[ i ]->state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );

  ulong c            = fd_progcache_rec_class( join->shmem, (ulong)( rec[ 0 ] - join->rec.ele ) );
  ulong free_before  = fd_progcache_class_free_cnt( join->shmem, c );
  ulong evict_before = env->progcache->metrics->evict_cnt;

  FD_TEST( !fd_prog_evict( env->progcache, valid_program_data_sz ) );  /* nothing claimable */
  FD_TEST( env->progcache->metrics->evict_cnt-evict_before==0UL );     /* and nothing unmapped */
  FD_TEST( fd_progcache_class_free_cnt( join->shmem, c )==free_before );

  ulong live = 0UL;
  for( ulong i=0UL; i<3UL; i++ ) live += !!test_peek( env->progcache, xid, &key[ i ], 0UL, 0UL );
  FD_TEST( live==3UL );                                                /* every entry survives */

  /* Releasing the readers leaves them mapped: a skipped record was never
     unmapped, so no slot comes back. */
  for( ulong i=0UL; i<3UL; i++ ) fd_progcache_rec_close( env->progcache, rec[ i ] );
  FD_TEST( fd_progcache_class_free_cnt( join->shmem, c )==free_before );

  fd_progcache_cancel_fork( join, xid );
  test_env_destroy( env );
}

/* test_clock_evict_frees_bytes: evicting a data-class entry accounts its
   freed bytes (evict_tot_sz increases). */

FD_UNIT_TEST( clock_evict_frees_bytes ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key1 = test_key( 1UL );
  test_account_t acc1;
  test_account_init( &acc1, &key1, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t * rec1 = test_pull( env->progcache, acc1.entry, xid, &key1, &load_env );
  FD_TEST( rec1 );
  FD_TEST( rec1->data_gaddr );

  xid = test_root( env->progcache->join, xid ); /* only rooted records are evictable */

  ulong rec_idx = (ulong)( rec1 - env->progcache->join->rec.ele );

  /* Clear visited flag */
  __atomic_fetch_and( &env->progcache->join->rec.ele[ rec_idx ].state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  ulong evict_sz_before  = env->progcache->metrics->evict_tot_sz;

  test_evict( env->progcache, valid_program_data_sz );

  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before == 1UL );
  FD_TEST( env->progcache->metrics->evict_tot_sz - evict_sz_before > 0UL );
  FD_TEST( !test_peek( env->progcache, xid, &key1, 0UL, 0UL ) );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_pull_refreshes_clock_bit: a cache hit via pull() marks the record
   accessed for CLOCK replacement, so frequently-pulled programs are
   protected from eviction.  fd_prog_state_touch runs on insert and on
   pull hits (not in peek, which is a pure query).

   Setup: two records with their visited bits cleared (as if the CLOCK
   hand had already passed once).  We then pull ("hit") only the hot
   record and run one eviction starting the hand at the hot record.  A
   correct CLOCK gives the just-accessed hot record a second chance and
   evicts the cold record instead; without the touch-on-hit the hand
   evicts the hot record first. */

FD_UNIT_TEST( pull_refreshes_clock_bit ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key_hot  = test_key( 1UL );
  fd_pubkey_t key_cold = test_key( 2UL );
  test_account_t acc_hot, acc_cold;
  test_account_init( &acc_hot,  &key_hot,  &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  test_account_init( &acc_cold, &key_cold, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features     = env->features,
    .feature_slot = 0UL
  };
  fd_progcache_rec_t * rec_hot  = test_pull( env->progcache, acc_hot.entry,  xid, &key_hot,  &load_env );
  fd_progcache_rec_t * rec_cold = test_pull( env->progcache, acc_cold.entry, xid, &key_cold, &load_env );
  FD_TEST( rec_hot && rec_cold );

  xid = test_root( env->progcache->join, xid ); /* only rooted records are evictable */

  ulong hot_idx  = (ulong)( rec_hot  - env->progcache->join->rec.ele );
  ulong cold_idx = (ulong)( rec_cold - env->progcache->join->rec.ele );

  /* Clear both visited flags (insert sets them) to simulate the CLOCK
     hand having already passed once. */
  fd_progcache_rec_t * recs = env->progcache->join->rec.ele;
  __atomic_fetch_and( &recs[ hot_idx ].state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );
  __atomic_fetch_and( &recs[ cold_idx ].state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );

  /* Pull (hit) only the hot program.  This must re-set its reference
     bit.  (peek is pure and would not.) */
  FD_TEST( test_pull( env->progcache, acc_hot.entry, xid, &key_hot, &load_env )==rec_hot );

  /* Evict one record from the class.  The per-class CLOCK gives the just-
     pulled hot record a second chance and evicts the cold record instead. */
  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  test_evict( env->progcache, valid_program_data_sz );
  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before == 1UL );

  /* The hot (recently-pulled) program survives; the cold one is evicted.
     (peek is used here only as a pure existence check.) */
  FD_TEST(  test_peek( env->progcache, xid, &key_hot,  0UL, 0UL ) );
  FD_TEST( !test_peek( env->progcache, xid, &key_cold, 0UL, 0UL ) );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_nx_class: a program that does not load is cached in place as a
   non-executable record -- no program data, still holding the slot of the class
   its footprint asked for, and still evictable via that class's CLOCK. */

FD_UNIT_TEST( nx_class ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, invalid_program_data, invalid_program_data_sz );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };

  ulong cls    = fd_progcache_cache_class( invalid_program_data_sz );
  ulong free0  = fd_progcache_class_free_cnt( env->progcache->join->shmem, cls );

  fd_progcache_rec_t * rec = fd_progcache_pull( env->progcache, xid, &key, &load_env, acc.entry );
  FD_TEST( rec );                                  /* cached (FailedVerification) */
  FD_TEST( !rec->data_gaddr );                     /* non-executable: no program data */
  ulong rec_idx = (ulong)( rec - env->progcache->join->rec.ele );
  FD_TEST( fd_progcache_rec_class( env->progcache->join->shmem, rec_idx )==cls ); /* kept in place */
  FD_TEST( fd_progcache_class_free_cnt( env->progcache->join->shmem, cls )==free0-1UL );
  fd_progcache_rec_close( env->progcache, rec );

  xid = test_root( env->progcache->join, xid ); /* only rooted records are evictable */

  /* Evict it (clear visited so it goes on the first pass). */
  __atomic_fetch_and( &env->progcache->join->rec.ele[ rec_idx ].state, (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );
  ulong evict_before = env->progcache->metrics->evict_cnt;
  test_evict( env->progcache, invalid_program_data_sz );
  FD_TEST( env->progcache->metrics->evict_cnt - evict_before >= 1UL );
  FD_TEST( !test_peek( env->progcache, xid, &key, 0UL, 0UL ) );                    /* gone */
  FD_TEST( fd_progcache_class_free_cnt( env->progcache->join->shmem, cls )==free0 ); /* slot returned */

  /* A program that fails ELF peek has no footprint, so it takes the smallest class. */
  fd_pubkey_t   junk_key = test_key( 2UL );
  uchar         junk[ 8 ] = {0};
  test_account_t junk_acc;
  test_account_init( &junk_acc, &junk_key, &fd_solana_bpf_loader_program_id, 1, junk, sizeof(junk) );
  ulong junk_cls  = fd_progcache_cache_class( 0UL );
  ulong junk_free = fd_progcache_class_free_cnt( env->progcache->join->shmem, junk_cls );
  fd_progcache_rec_t * junk_rec = fd_progcache_pull( env->progcache, xid, &junk_key, &load_env, junk_acc.entry );
  FD_TEST( junk_rec );
  FD_TEST( !junk_rec->data_gaddr );
  FD_TEST( fd_progcache_rec_class( env->progcache->join->shmem,
                                   (ulong)( junk_rec - env->progcache->join->rec.ele ) )==junk_cls );
  FD_TEST( fd_progcache_class_free_cnt( env->progcache->join->shmem, junk_cls )==junk_free-1UL );
  fd_progcache_rec_close( env->progcache, junk_rec );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_nx_spill: saturate the class a peek-fail program lands in (every record
   held by an open reader, so eviction defers and none frees), then pull one more
   peek-fail program.  Its acquisition must fall back to the spill ws
   (non-executable result), and nothing may be left mapped. */

FD_UNIT_TEST( nx_spill ) {
  test_env_t *           env   = test_env_create_ex( wksp, 16UL, 512UL<<20 );
  fd_progcache_t *       pc    = env->progcache;
  fd_progcache_shmem_t * shmem = pc->join->shmem;
  fd_progcache_fork_id_t xid   = fd_progcache_attach_child( pc->join, fd_progcache_fork_id_initial() );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };

  ulong nx    = fd_progcache_cache_class( 0UL ); /* the class a footprint-0 record takes */
  ulong class_max = shmem->cache.class_max[ nx ];

  test_account_t *      acc  = fd_wksp_alloc_laddr( wksp, alignof(test_account_t), sizeof(test_account_t), 1UL );
  fd_progcache_rec_t ** held = fd_wksp_alloc_laddr( wksp, alignof(void *), class_max*sizeof(void *), 1UL );
  FD_TEST( acc && held );

  /* Saturate: class_max distinct peek-fail programs, all held open. */
  uchar junk[ 8 ] = {0};
  for( ulong i=0UL; i<class_max; i++ ) {
    fd_pubkey_t k = test_key( 1000UL+i );
    test_account_init( acc, &k, &fd_solana_bpf_loader_program_id, 1, junk, sizeof(junk) );
    held[ i ] = fd_progcache_pull( pc, xid, &k, &load_env, acc->entry );
    FD_TEST( held[ i ] && !held[ i ]->data_gaddr );
    FD_TEST( fd_progcache_rec_class( shmem, (ulong)( held[ i ]-pc->join->rec.ele ) )==nx );
  }
  FD_TEST( fd_progcache_class_free_cnt( shmem, nx )==0UL );

  /* One more peek-fail pull: the class is exhausted -> spill fallback. */
  ulong oom0   = pc->metrics->class_full_cnt;
  ulong spill0 = pc->metrics->spill_cnt;
  fd_pubkey_t k = test_key( 999999UL );
  test_account_init( acc, &k, &fd_solana_bpf_loader_program_id, 1, junk, sizeof(junk) );
  fd_progcache_rec_t * srec = fd_progcache_pull( pc, xid, &k, &load_env, acc->entry );
  FD_TEST( srec );
  FD_TEST( srec>=shmem->spill.rec && srec<shmem->spill.rec+FD_MAX_INSTRUCTION_STACK_DEPTH ); /* served from spill ws */
  FD_TEST( !srec->data_gaddr );                        /* non-executable result */
  FD_TEST( !fd_progcache_rec_calldests( srec, pc->join->data_base ) ); /* nx sentinel, not a wksp-base pointer */
  FD_TEST( pc->metrics->class_full_cnt >oom0   );        /* exhaustion path taken */
  FD_TEST( pc->metrics->spill_cnt    >spill0 );
  FD_TEST( !test_peek( pc, xid, &k, 0UL, 0UL ) );      /* record was unpublished, not left mapped */
  fd_progcache_rec_close( pc, srec );                  /* releases the spill ws */

  /* Cleanup: release the readers, cancel the fork, collect the zombies;
     every nx slot must return. */
  for( ulong i=0UL; i<class_max; i++ ) fd_progcache_rec_close( pc, held[ i ] );
  fd_progcache_cancel_fork( pc->join, xid );
  fd_prog_reclaim_work( pc->join );
  FD_TEST( fd_progcache_class_free_cnt( shmem, nx )==class_max );

  test_env_destroy( env );
}


/* test_spill_basic: fill a size class and hold read locks on every slot, so
   the next insert cannot evict anyone and must fall back to the spill scratch.
   Single-threaded, so the spill ws is uncontended (trywrite succeeds) and the
   program still loads correctly from the spad. */

FD_UNIT_TEST( spill_basic ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };

  ulong n0 = env->progcache->join->shmem->cache.class_max[ 0 ]; /* 128 KiB class */
  FD_TEST( n0>0UL );

  /* One reusable account buffer (test_account_t is 1 MiB -- too big for an
     array on the stack).  pull copies the program into its cache slot, so the
     buffer can be reused for the next distinct-keyed program. */
  test_account_t * acc = fd_wksp_alloc_laddr( wksp, alignof(test_account_t), sizeof(test_account_t), 1UL );
  FD_TEST( acc );

  /* Hold a read lock on every class-0 slot (distinct programs, same image). */
  fd_progcache_rec_t ** held = fd_wksp_alloc_laddr( wksp, alignof(void *), n0*sizeof(void *), 1UL );
  FD_TEST( held );
  for( ulong i=0UL; i<n0; i++ ) {
    fd_pubkey_t k = test_key( 100UL+i );
    test_account_init( acc, &k, &fd_solana_bpf_loader_program_id,
                       1, valid_program_data, valid_program_data_sz );
    held[i] = fd_progcache_pull( env->progcache, xid, &k, &load_env, acc->entry );
    FD_TEST( held[i] && held[i]->data_gaddr );
    FD_TEST( fd_progcache_rec_class( env->progcache->join->shmem, (ulong)( held[i]-env->progcache->join->rec.ele ) )==0UL ); /* real class-0 record */
  }

  /* One more class-0 program: class full + all slots read-locked -> spill. */
  ulong spill_before = env->progcache->metrics->spill_cnt;
  fd_pubkey_t spill_key = test_key( 9999UL );
  test_account_init( acc, &spill_key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  fd_progcache_rec_t * srec = fd_progcache_pull( env->progcache, xid, &spill_key, &load_env, acc->entry );
  FD_TEST( srec );                                                    /* loaded (via spill) */
  FD_TEST( srec->data_gaddr && srec->rodata_sz>0U );                  /* program data present */
  FD_TEST( env->progcache->metrics->spill_cnt - spill_before == 1UL );/* went through spill */
  fd_progcache_rec_close( env->progcache, srec );                     /* closes spill scratch */

  for( ulong i=0UL; i<n0; i++ ) fd_progcache_rec_close( env->progcache, held[i] );
  fd_wksp_free_laddr( held );
  fd_wksp_free_laddr( acc );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_spill_sticks_for_nested_frames: once a frame has spilled, the deeper
   frames of that CPI stack stay in the spad even when their class has a slot to
   spare -- the tile does not return to the cache mid-stack. */

FD_UNIT_TEST( spill_sticks_for_nested_frames ) {
  test_env_t *           env   = test_env_create( wksp );
  fd_progcache_t *       pc    = env->progcache;
  fd_progcache_shmem_t * shmem = pc->join->shmem;
  fd_progcache_fork_id_t xid   = fd_progcache_attach_child( pc->join, fd_progcache_fork_id_initial() );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };

  ulong n0 = shmem->cache.class_max[ 0 ];
  FD_TEST( n0>0UL );

  test_account_t *      acc  = fd_wksp_alloc_laddr( wksp, alignof(test_account_t), sizeof(test_account_t), 1UL );
  fd_progcache_rec_t ** held = fd_wksp_alloc_laddr( wksp, alignof(void *), n0*sizeof(void *), 1UL );
  FD_TEST( acc && held );

  /* Hold a read lock on every class-0 slot, so the next program must spill. */
  for( ulong i=0UL; i<n0; i++ ) {
    fd_pubkey_t k = test_key( 100UL+i );
    test_account_init( acc, &k, &fd_solana_bpf_loader_program_id,
                       1, valid_program_data, valid_program_data_sz );
    held[ i ] = fd_progcache_pull( pc, xid, &k, &load_env, acc->entry );
    FD_TEST( held[ i ] && held[ i ]->data_gaddr );
    FD_TEST( fd_progcache_rec_class( shmem, (ulong)( held[ i ]-pc->join->rec.ele ) )==0UL );
  }
  FD_TEST( fd_progcache_class_free_cnt( shmem, 0UL )==0UL );

  /* Frame 1: class 0 is exhausted and every slot is read-locked -> spill. */
  ulong spill0 = pc->metrics->spill_cnt;
  fd_pubkey_t k1 = test_key( 900001UL );
  test_account_init( acc, &k1, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  fd_progcache_rec_t * rec1 = fd_progcache_pull( pc, xid, &k1, &load_env, acc->entry );
  FD_TEST( rec1>=shmem->spill.rec && rec1<shmem->spill.rec+FD_MAX_INSTRUCTION_STACK_DEPTH );
  FD_TEST( pc->metrics->spill_cnt-spill0==1UL );
  FD_TEST( pc->spill_active==1U );

  /* Give class 0 a slot back while the spill frame is open: release one holder
     and remove its record outright, so no CLOCK decision is involved. */
  fd_progcache_rec_close( pc, held[ 0 ] );
  xid = test_root( pc->join, xid ); /* detach it so the sweep can collect it */
  FD_TEST( fd_prog_delete_rec( pc->join, held[ 0 ] )>=0L );
  FD_TEST( fd_prog_reclaim_work( pc->join )==1UL );
  FD_TEST( fd_progcache_class_free_cnt( shmem, 0UL )==1UL );

  /* Frame 2: that free slot fits, but the tile is already spilling. */
  fd_pubkey_t k2 = test_key( 900002UL );
  test_account_init( acc, &k2, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  fd_progcache_rec_t * rec2 = fd_progcache_pull( pc, xid, &k2, &load_env, acc->entry );
  FD_TEST( rec2>=shmem->spill.rec && rec2<shmem->spill.rec+FD_MAX_INSTRUCTION_STACK_DEPTH ); /* spad, not the slot */
  FD_TEST( rec2->data_gaddr );                                                    /* loaded into the spad */
  FD_TEST( pc->metrics->spill_cnt-spill0==2UL );
  FD_TEST( pc->spill_active==2U );                                                /* one holder, two frames */
  FD_TEST( fd_progcache_class_free_cnt( shmem, 0UL )==1UL ); /* slot untouched */
  FD_TEST( !test_peek( pc, xid, &k2, 0UL, 0UL ) );                                /* nothing published */

  /* Unwind LIFO: the ws lock releases only when the outermost frame closes. */
  fd_progcache_rec_close( pc, rec2 );
  FD_TEST( pc->spill_active==1U );
  FD_TEST( FD_VOLATILE_CONST( shmem->spill.lock.value )==FD_RWLOCK_WRITE_LOCK );
  fd_progcache_rec_close( pc, rec1 );
  FD_TEST( pc->spill_active==0U );
  FD_TEST( FD_VOLATILE_CONST( shmem->spill.lock.value )==0 );

  for( ulong i=1UL; i<n0; i++ ) fd_progcache_rec_close( pc, held[ i ] );
  fd_wksp_free_laddr( held );
  fd_wksp_free_laddr( acc );
  fd_progcache_cancel_fork( pc->join, xid );
  test_env_destroy( env );
}

/* test_spill_lock: single-threaded lifecycle of the exclusive spill ws lock.
   With a class full and every slot read-locked, two *nested* spills (the
   second taken while the first's rec is still held, as a deeper CPI frame
   would) must: acquire the ws lock on the first spill, REUSE it on the second
   (not re-acquire), keep it held until the last spill rec closes, and release
   it exactly when spill_active returns to 0 -- with the spad reclaimed LIFO.
   This validates the lock/refcount/spad machinery that a multi-threaded test
   later relies on for mutual exclusion. */

FD_UNIT_TEST( spill_lock ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };
  fd_progcache_shmem_t * sh = env->progcache->join->shmem;

  ulong n0 = env->progcache->join->shmem->cache.class_max[ 0 ];
  FD_TEST( n0>0UL );

  test_account_t * acc = fd_wksp_alloc_laddr( wksp, alignof(test_account_t), sizeof(test_account_t), 1UL );
  FD_TEST( acc );

  /* Fill and hold a read lock on every class-0 slot. */
  fd_progcache_rec_t ** held = fd_wksp_alloc_laddr( wksp, alignof(void *), n0*sizeof(void *), 1UL );
  FD_TEST( held );
  for( ulong i=0UL; i<n0; i++ ) {
    fd_pubkey_t k = test_key( 100UL+i );
    test_account_init( acc, &k, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
    held[i] = fd_progcache_pull( env->progcache, xid, &k, &load_env, acc->entry );
    FD_TEST( held[i] );
    FD_TEST( fd_progcache_rec_class( env->progcache->join->shmem, (ulong)( held[i]-env->progcache->join->rec.ele ) )==0UL );
  }

  FD_TEST( env->progcache->spill_active==0U );
  FD_TEST( FD_VOLATILE_CONST( sh->spill.lock.value )==0 ); /* ws lock free */

  /* Frame 1: spills, acquiring the ws lock. */
  fd_pubkey_t kx = test_key( 9001UL );
  test_account_init( acc, &kx, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
  fd_progcache_rec_t * recx = fd_progcache_pull( env->progcache, xid, &kx, &load_env, acc->entry );
  FD_TEST( recx && recx->data_gaddr );
  FD_TEST( env->progcache->spill_active==1U );
  FD_TEST( FD_VOLATILE_CONST( sh->spill.lock.value )==FD_RWLOCK_WRITE_LOCK ); /* acquired */
  uint spad_after1 = sh->spill.spad_used;
  FD_TEST( spad_after1>0U );

  /* Frame 2 (nested: recx still held): spills, REUSING the ws lock. */
  fd_pubkey_t ky = test_key( 9002UL );
  test_account_init( acc, &ky, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
  fd_progcache_rec_t * recy = fd_progcache_pull( env->progcache, xid, &ky, &load_env, acc->entry );
  FD_TEST( recy && recy->data_gaddr );
  FD_TEST( env->progcache->spill_active==2U );                                   /* refcount, one holder */
  FD_TEST( FD_VOLATILE_CONST( sh->spill.lock.value )==FD_RWLOCK_WRITE_LOCK );    /* still held */
  FD_TEST( sh->spill.spad_used>spad_after1 );                                    /* second frame took spad */
  FD_TEST( recx->data_gaddr!=recy->data_gaddr );                                 /* distinct spad regions */

  /* Unwind LIFO: close frame 2, then frame 1. */
  fd_progcache_rec_close( env->progcache, recy );
  FD_TEST( env->progcache->spill_active==1U );
  FD_TEST( FD_VOLATILE_CONST( sh->spill.lock.value )==FD_RWLOCK_WRITE_LOCK );    /* still held (frame 1 open) */
  FD_TEST( sh->spill.spad_used==spad_after1 );                                   /* spad rewound (LIFO cascade) */

  fd_progcache_rec_close( env->progcache, recx );
  FD_TEST( env->progcache->spill_active==0U );
  FD_TEST( FD_VOLATILE_CONST( sh->spill.lock.value )==0 );                       /* released exactly at 0 */
  FD_TEST( sh->spill.spad_used==0U );                                            /* spad fully reclaimed */

  for( ulong i=0UL; i<n0; i++ ) fd_progcache_rec_close( env->progcache, held[i] );
  fd_wksp_free_laddr( held );
  fd_wksp_free_laddr( acc );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

#if FD_HAS_THREADS
/* test_spill_concurrent: many threads share one progcache sized so that the
   records they hold outnumber the class's slots.  Eviction therefore cannot
   satisfy everyone and the surplus must come from the spill, whose ws lock has
   a single holder cache-wide -- so the threads serialise on it.  A watchdog
   fails the test if forward progress stalls (deadlock or a lost wakeup); an
   integrity check on every pulled program (rodata_sz must match the reference)
   catches spad corruption from a broken lock.  CONC_HOLD stays
   <= FD_MAX_INSTRUCTION_STACK_DEPTH so whoever holds the spill can always run
   to completion and release it, which is what makes the serialisation
   progress rather than deadlock. */

#define CONC_NTHREAD 8UL
#define CONC_HOLD    4UL

/* Watchdog stall threshold in 100ms ticks (--stall-ticks; default 3s).
   Slow environments (e.g. valgrind serializes threads with long time
   slices) need a larger value to avoid false deadlock reports. */
static ulong g_stall_ticks = 30UL;

struct conc_ctx {
  fd_progcache_shmem_t * shmem;
  fd_features_t const *  features;
  fd_progcache_fork_id_t fork;
  ulong                  idx;
  ulong                  ref_rodata_sz;
  fd_progcache_t *       cache;   /* pre-allocated per-thread join handle */
  uchar *                scratch; /* pre-allocated per-thread load scratch */
  test_account_t *       acc;     /* pre-allocated per-thread account buffer */
  atomic_int *           stop;
  atomic_ulong           progress;
  atomic_ulong           spills;
};

static void *
conc_worker( void * arg ) {
  struct conc_ctx * c = arg;
  FD_TEST( fd_progcache_join( c->cache, c->shmem, c->scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
  fd_prog_load_env_t load_env = { .features = c->features, .feature_slot = 0UL };

  fd_progcache_rec_t * held[ CONC_HOLD ];
  ulong iter = 0UL;
  while( !atomic_load_explicit( c->stop, memory_order_relaxed ) ) {
    for( ulong j=0UL; j<CONC_HOLD; j++ ) {
      /* distinct key per (thread,iter,frame) -> distinct entries fill the
         class; once every slot is read-locked, the pull spills. */
      fd_pubkey_t k = test_key( c->idx*100000000UL + iter*100UL + j );
      test_account_init( c->acc, &k, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
      fd_progcache_rec_t * r = fd_progcache_pull( c->cache, c->fork, &k, &load_env, c->acc->entry );
      FD_TEST( r && r->data_gaddr );                    /* loaded via slot or spill */
      FD_TEST( r->rodata_sz==(uint)c->ref_rodata_sz );  /* integrity: no corruption */
      held[j] = r;
    }
    for( ulong j=CONC_HOLD; j>0UL; j-- ) fd_progcache_rec_close( c->cache, held[j-1UL] ); /* LIFO unwind */
    atomic_store_explicit( &c->progress, ++iter, memory_order_relaxed );
  }
  atomic_store_explicit( &c->spills, c->cache->metrics->spill_cnt, memory_order_relaxed );
  fd_progcache_leave( c->cache, NULL );
  return NULL;
}

/* test_cancel_concurrent_readers: fork churn against live readers.  The admin
   thread fills and cancels sibling forks while workers hold records of another
   fork, so cancel's record deletion and zombie collection run against active
   readers and contend the same classes. */

FD_UNIT_TEST( cancel_concurrent_readers ) {
  ulong wksp_tag  = 1UL;
  ulong txn_max   = 64UL;
  /* Headroom past the floor: the workers' records are attached (their fork is
     never rooted), so at the bare minimum every worker miss would serialize
     through the spill lock instead of contending the classes. */
  ulong progcache_sz = fd_progcache_shmem_min_sz( 64UL ) + (17UL<<20);

  void * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, progcache_sz ), wksp_tag );
  FD_TEST( mem );
  fd_progcache_shmem_t * shmem = fd_progcache_shmem_new( mem, wksp_tag, 1UL, txn_max, progcache_sz );
  FD_TEST( shmem );

  fd_features_t features[1]; fd_memset( features, 0, sizeof(features) );

  fd_progcache_t * admin = fd_wksp_alloc_laddr( wksp, alignof(fd_progcache_t), sizeof(fd_progcache_t), wksp_tag );
  uchar *          ascr  = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT, wksp_tag );
  FD_TEST( fd_progcache_join( admin, shmem, ascr, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );

  /* The workers' fork is never published or cancelled: an insert on a fork
     being torn down is a caller-contract violation, not a race. */
  fd_progcache_fork_id_t fork = fd_progcache_attach_child( admin->join, fd_progcache_fork_id_initial() );

  fd_prog_load_env_t load_env = { .features = features, .feature_slot = 0UL };
  fd_pubkey_t rk = test_key( 7UL );
  test_account_t * racc = fd_wksp_alloc_laddr( wksp, alignof(test_account_t), sizeof(test_account_t), wksp_tag );
  test_account_init( racc, &rk, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
  fd_progcache_rec_t * rr = fd_progcache_pull( admin, fork, &rk, &load_env, racc->entry );
  FD_TEST( rr && rr->rodata_sz>0U );
  ulong ref_rodata_sz = rr->rodata_sz;
  fd_progcache_rec_close( admin, rr );

  atomic_int stop; atomic_store( &stop, 0 );
  struct conc_ctx ctx[ CONC_NTHREAD ];
  pthread_t       th [ CONC_NTHREAD ];
  for( ulong i=0UL; i<CONC_NTHREAD; i++ ) {
    ctx[i].shmem = shmem; ctx[i].features = features; ctx[i].fork = fork; ctx[i].idx = i;
    ctx[i].ref_rodata_sz = ref_rodata_sz; ctx[i].stop = &stop;
    ctx[i].cache   = fd_wksp_alloc_laddr( wksp, alignof(fd_progcache_t), sizeof(fd_progcache_t), wksp_tag );
    ctx[i].scratch = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT, wksp_tag );
    ctx[i].acc     = fd_wksp_alloc_laddr( wksp, alignof(test_account_t), sizeof(test_account_t), wksp_tag );
    FD_TEST( ctx[i].cache && ctx[i].scratch && ctx[i].acc );
    atomic_store( &ctx[i].progress, 0UL );
    atomic_store( &ctx[i].spills,   0UL );
    FD_TEST( 0==pthread_create( &th[i], NULL, conc_worker, &ctx[i] ) );
  }

  /* Wait for every reader to complete at least one iteration, so the churn
     genuinely runs against active readers and the progress assertion cannot
     depend on scheduling. */
  long deadline = fd_log_wallclock() + (long)60e9;
  for( ulong i=0UL; i<CONC_NTHREAD; i++ ) {
    while( !atomic_load_explicit( &ctx[i].progress, memory_order_relaxed ) ) {
      FD_SPIN_PAUSE();
      FD_TEST( fd_log_wallclock()<deadline );
    }
  }

  /* Churn sibling forks: fill each with records, then cancel it. */
  test_account_t * cacc = fd_wksp_alloc_laddr( wksp, alignof(test_account_t), sizeof(test_account_t), wksp_tag );
  FD_TEST( cacc );
  ulong const ROUNDS = 64UL;
  for( ulong r=0UL; r<ROUNDS; r++ ) {
    fd_progcache_fork_id_t victim = fd_progcache_attach_child( admin->join, fd_progcache_fork_id_initial() );
    for( ulong j=0UL; j<4UL; j++ ) {
      fd_pubkey_t k = test_key( 900000000UL + r*100UL + j );
      test_account_init( cacc, &k, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
      fd_progcache_rec_t * v = fd_progcache_pull( admin, victim, &k, &load_env, cacc->entry );
      FD_TEST( v && v->data_gaddr );
      fd_progcache_rec_close( admin, v );
    }
    fd_progcache_cancel_fork( admin->join, victim ); /* deletes its records under live readers */
    fd_prog_reclaim_work( admin->join );
  }

  atomic_store( &stop, 1 );
  ulong iters = 0UL;
  for( ulong i=0UL; i<CONC_NTHREAD; i++ ) {
    FD_TEST( 0==pthread_join( th[i], NULL ) );
    iters += atomic_load_explicit( &ctx[i].progress, memory_order_relaxed );
  }
  FD_TEST( iters>=CONC_NTHREAD );                  /* every reader made progress */

  fd_prog_reclaim_work( admin->join );
  FD_TEST( !fd_progcache_verify( admin->join ) );  /* structural integrity after the churn */
  FD_LOG_NOTICE(( "cancel_concurrent_readers: %lu rounds against %lu reader iters", ROUNDS, iters ));

  fd_progcache_cancel_fork( admin->join, fork );
  FD_TEST( !fd_progcache_verify( admin->join ) );
  fd_progcache_leave( admin, NULL );
  for( ulong i=0UL; i<CONC_NTHREAD; i++ ) {
    fd_wksp_free_laddr( ctx[i].cache ); fd_wksp_free_laddr( ctx[i].scratch ); fd_wksp_free_laddr( ctx[i].acc );
  }
  fd_wksp_free_laddr( cacc ); fd_wksp_free_laddr( racc ); fd_wksp_free_laddr( ascr ); fd_wksp_free_laddr( admin );
  fd_wksp_free_laddr( fd_progcache_shmem_delete( shmem ) );
}

FD_UNIT_TEST( spill_concurrent ) {
  ulong wksp_tag = 1UL;
  ulong txn_max  = 64UL;
  /* The smallest legal budget puts every small class at its 20-slot minimum
     (class 0 gets 22), fewer than the CONC_NTHREAD*CONC_HOLD records the
     threads hold at once -- so the cache cannot satisfy them all and the
     surplus must come from the spill. */
  ulong progcache_sz = fd_progcache_shmem_min_sz( txn_max );

  void * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, progcache_sz ), wksp_tag );
  FD_TEST( mem );
  fd_progcache_shmem_t * shmem = fd_progcache_shmem_new( mem, wksp_tag, 1UL, txn_max, progcache_sz );
  FD_TEST( shmem );

  fd_features_t features[1]; fd_memset( features, 0, sizeof(features) );

  /* admin join + a reference pull that fixes the expected rodata_sz. */
  fd_progcache_t * admin = fd_wksp_alloc_laddr( wksp, alignof(fd_progcache_t), sizeof(fd_progcache_t), wksp_tag );
  uchar *          ascr  = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT, wksp_tag );
  FD_TEST( fd_progcache_join( admin, shmem, ascr, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
  fd_progcache_fork_id_t fork = fd_progcache_attach_child( admin->join, fd_progcache_fork_id_initial() );

  fd_prog_load_env_t load_env = { .features = features, .feature_slot = 0UL };
  fd_pubkey_t rk = test_key( 7UL );
  test_account_t * racc = fd_wksp_alloc_laddr( wksp, alignof(test_account_t), sizeof(test_account_t), wksp_tag );
  test_account_init( racc, &rk, &fd_solana_bpf_loader_program_id, 1, valid_program_data, valid_program_data_sz );
  fd_progcache_rec_t * rr = fd_progcache_pull( admin, fork, &rk, &load_env, racc->entry );
  FD_TEST( rr && rr->rodata_sz>0U );
  ulong ref_rodata_sz = rr->rodata_sz;
  fd_progcache_rec_close( admin, rr );

  atomic_int stop; atomic_store( &stop, 0 );
  struct conc_ctx ctx[ CONC_NTHREAD ];
  pthread_t       th [ CONC_NTHREAD ];
  for( ulong i=0UL; i<CONC_NTHREAD; i++ ) {
    ctx[i].shmem = shmem; ctx[i].features = features; ctx[i].fork = fork; ctx[i].idx = i;
    ctx[i].ref_rodata_sz = ref_rodata_sz; ctx[i].stop = &stop;
    ctx[i].cache   = fd_wksp_alloc_laddr( wksp, alignof(fd_progcache_t), sizeof(fd_progcache_t), wksp_tag );
    ctx[i].scratch = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT, wksp_tag );
    ctx[i].acc     = fd_wksp_alloc_laddr( wksp, alignof(test_account_t), sizeof(test_account_t), wksp_tag );
    FD_TEST( ctx[i].cache && ctx[i].scratch && ctx[i].acc );
    atomic_store( &ctx[i].progress, 0UL );
    atomic_store( &ctx[i].spills,   0UL );
    FD_TEST( 0==pthread_create( &th[i], NULL, conc_worker, &ctx[i] ) );
  }

  /* Watchdog: fail if total forward progress stalls (deadlock). */
  ulong prev = 0UL; ulong stall = 0UL; int ran = 0;
  for( int t=0; t<50; t++ ) {                        /* ~5s of observation */
    nanosleep( &(struct timespec){ .tv_sec=0, .tv_nsec=100000000L }, NULL ); /* 100 ms */
    ulong total = 0UL;
    for( ulong i=0UL; i<CONC_NTHREAD; i++ ) total += atomic_load_explicit( &ctx[i].progress, memory_order_relaxed );
    if( total>prev ) { stall = 0UL; ran = 1; } else stall++;
    prev = total;
    if( FD_UNLIKELY( stall>=g_stall_ticks ) )
      FD_LOG_ERR(( "progcache spill concurrency stalled %lu ms (deadlock); total iters=%lu", stall*100UL, total ));
  }
  FD_TEST( ran && prev>0UL );                         /* real work happened */

  atomic_store( &stop, 1 );
  ulong spills = 0UL;
  for( ulong i=0UL; i<CONC_NTHREAD; i++ ) {
    FD_TEST( 0==pthread_join( th[i], NULL ) );
    spills += atomic_load_explicit( &ctx[i].spills, memory_order_relaxed );
  }
  FD_TEST( spills>0UL );                              /* the spill path was actually exercised */
  FD_TEST( !fd_progcache_verify( admin->join ) );     /* structural integrity after the storm */
  FD_LOG_NOTICE(( "spill_concurrent: %lu threads x %lu-deep, iters=%lu, spills=%lu -> no deadlock, no corruption",
                  CONC_NTHREAD, CONC_HOLD, prev, spills ));

  fd_progcache_cancel_fork( admin->join, fork );
  fd_progcache_leave( admin, NULL );
  for( ulong i=0UL; i<CONC_NTHREAD; i++ ) {
    fd_wksp_free_laddr( ctx[i].acc ); fd_wksp_free_laddr( ctx[i].scratch ); fd_wksp_free_laddr( ctx[i].cache );
  }
  fd_wksp_free_laddr( racc ); fd_wksp_free_laddr( ascr ); fd_wksp_free_laddr( admin );
  fd_wksp_free_laddr( fd_progcache_shmem_delete( shmem ) );
}
#endif /* FD_HAS_THREADS */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
#if FD_HAS_THREADS
  g_stall_ticks          = fd_env_strip_cmdline_ulong( &argc, &argv, "--stall-ticks", NULL, 30UL                        );
#endif
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 2UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_unit_tests( argc, argv );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
