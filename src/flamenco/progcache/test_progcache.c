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
                    ulong       shared_sz ) {
  ulong wksp_tag = 1UL;

  void * progcache_mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, shared_sz ), wksp_tag );
  FD_TEST( fd_progcache_shmem_new( progcache_mem, wksp_tag, 1UL, txn_max, shared_sz ) );

  test_env_t * env = fd_wksp_alloc_laddr( wksp, alignof(test_env_t), sizeof(test_env_t), wksp_tag );
  FD_TEST( env );
  memset( env, 0, offsetof(test_env_t, scratch) );

  env->wksp = wksp;
  FD_TEST( fd_progcache_join( env->progcache, progcache_mem, env->scratch, sizeof(env->scratch) ) );

  return env;
}

static test_env_t *
test_env_create( fd_wksp_t * wksp ) {
  return test_env_create_ex( wksp, 16UL, 256UL<<20 );
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
  test_env_t * env = test_env_create_ex( wksp, 16UL, 160UL<<20 );
  fd_progcache_fork_id_t fork = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };

  /* hello_solana_program.so is small -> 128 KiB class (class 0). */
  ulong class0_slots = env->progcache->join->shmem->cache.nslot[ 0 ];
  FD_TEST( class0_slots>0UL );

  ulong over = 20UL;
  ulong n    = class0_slots + over;
  FD_TEST( n<512UL ); /* rec pool must not be the bottleneck */

  ulong full0  = env->progcache->metrics->class_full_cnt;
  ulong evict0 = env->progcache->metrics->evict_cnt;
  ulong spill0 = env->progcache->metrics->spill_cnt;

  for( ulong i=0UL; i<n; i++ ) {
    fd_pubkey_t key = test_key( 1000UL+i );
    test_account_t acc;
    test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                       1, valid_program_data, valid_program_data_sz );
    fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, fork, &key, &load_env );
    FD_TEST( rec );             /* loaded             */
    FD_TEST( rec->data_gaddr ); /* got a cache slot    */
    FD_TEST( rec->data_max==fd_progcache_slot_sz[ 0 ] ); /* in the 128 KiB class */
  }

  ulong full_d  = env->progcache->metrics->class_full_cnt - full0;
  ulong evict_d = env->progcache->metrics->evict_cnt    - evict0;
  ulong spill_d = env->progcache->metrics->spill_cnt    - spill0;

  /* Every insert past the class capacity must have hit the class-full
     path and been resolved by eviction (not spill). */
  FD_TEST( full_d >=over ); /* at least `over` allocations found the class full */
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

/* test_reclaim_empty: Reclaim on empty queue returns 0 */

FD_UNIT_TEST( reclaim_empty ) {
  test_env_t * env = test_env_create( wksp );

  FD_TEST( env->progcache->join->shmem->rec.reclaim_head==UINT_MAX );
  FD_TEST( fd_progcache_reclaim_work( env->progcache->join )==0UL );

  test_env_destroy( env );
}

/* test_reclaim_no_readers: Single record with no active readers should
   be freed by reclaim_work. */

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

  long freed = fd_progcache_delete_rec( env->progcache->join, rec );
  FD_TEST( freed>=0L );
  FD_TEST( env->progcache->join->shmem->rec.reclaim_head!=UINT_MAX );

  FD_TEST( fd_progcache_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( env->progcache->join->shmem->rec.reclaim_head==UINT_MAX );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_reclaim_active_reader: Record with an active reader should be
   deferred by reclaim_work until the reader releases the lock. */

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

  fd_progcache_delete_rec( env->progcache->join, rec );
  FD_TEST( fd_progcache_reclaim_work( env->progcache->join )==0UL );
  FD_TEST( env->progcache->join->shmem->rec.reclaim_head!=UINT_MAX );

  fd_progcache_rec_close( env->progcache, rec );
  FD_TEST( fd_progcache_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( env->progcache->join->shmem->rec.reclaim_head==UINT_MAX );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_cross_join_reclaim: a record removed from the map by one join (A) while
   another join (B) holds it read-locked must be reclaimable by B once it
   closes -- the deferred-reclaim list is shared across joins, not owned by the
   deleter, so an idle A cannot strand the slot. */

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

  /* A removes it from the map and enqueues it for reclaim.  Reclaim cannot
     finish while B reads it -- and A is not the join that becomes the final
     reader, which is exactly the stranding case. */
  fd_progcache_delete_rec( A->join, rec );
  FD_TEST( fd_progcache_reclaim_work( A->join )==0UL );      /* deferred: B still reading */
  FD_TEST( shmem->rec.reclaim_head!=UINT_MAX );

  /* B releases the read lock, then B (NOT A) drains the shared reclaim list. */
  fd_progcache_rec_close( B, rec );
  FD_TEST( fd_progcache_reclaim_work( B->join )==1UL );      /* cross-join reclaim */
  FD_TEST( shmem->rec.reclaim_head==UINT_MAX );

  fd_progcache_cancel_fork( A->join, xid );
  FD_TEST( fd_progcache_leave( B, NULL ) );
  test_env_destroy( env );
}

/* test_reclaim_txn_unlink: Record linked to a txn should be unlinked
   from the txn's record list before being freed. */

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

  fd_progcache_delete_rec( env->progcache->join, rec );
  FD_TEST( fd_progcache_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( txn->rec_head_idx==UINT_MAX );
  FD_TEST( txn->rec_tail_idx==UINT_MAX );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

FD_UNIT_TEST( join_null_scratch ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 256UL<<20 ), 1UL );
  FD_TEST( fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, 256UL<<20 ) );
  fd_progcache_t cache[1];
  FD_TEST( !fd_progcache_join( cache, mem, NULL, 4096UL ) );
  fd_wksp_free_laddr( fd_progcache_shmem_delete( mem ) );
}

FD_UNIT_TEST( join_misaligned_scratch ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 256UL<<20 ), 1UL );
  FD_TEST( fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, 256UL<<20 ) );
  uchar scratch_buf[ FD_PROGCACHE_SCRATCH_ALIGN ] __attribute__((aligned(FD_PROGCACHE_SCRATCH_ALIGN)));
  fd_progcache_t cache[1];
  FD_TEST( !fd_progcache_join( cache, mem, scratch_buf+1, sizeof(scratch_buf)-1 ) );
  fd_wksp_free_laddr( fd_progcache_shmem_delete( mem ) );
}

FD_UNIT_TEST( shmem_new_zero_txn_max ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 256UL<<20 ), 1UL );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, 0UL, 256UL<<20 ) );
  fd_wksp_free_laddr( mem );
}

FD_UNIT_TEST( shmem_new_oversized_txn_max ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 256UL<<20 ), 1UL );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, (ulong)UINT_MAX+1UL, 256UL<<20 ) );
  fd_wksp_free_laddr( mem );
}

/* test_cache_class: footprint -> class mapping boundaries. */

FD_UNIT_TEST( cache_class ) {
  FD_TEST( fd_progcache_class(          0UL )==FD_PROGCACHE_NX_CLASS ); /* non-executable -> nx */
  FD_TEST( fd_progcache_class(          1UL )==0UL );
  FD_TEST( fd_progcache_class(     131072UL )==0UL );
  FD_TEST( fd_progcache_class(     131073UL )==1UL );
  FD_TEST( fd_progcache_class(     524288UL )==1UL );
  FD_TEST( fd_progcache_class(    1048576UL )==2UL );
  FD_TEST( fd_progcache_class(    2097152UL )==3UL );
  FD_TEST( fd_progcache_class(    2097153UL )==4UL );
  FD_TEST( fd_progcache_class(    4194304UL )==4UL );
  FD_TEST( fd_progcache_class(    4194305UL )==5UL );
  FD_TEST( fd_progcache_class( FD_RUNTIME_ACC_SZ_MAX )==5UL );
  FD_TEST( fd_progcache_class( FD_PROGCACHE_SLOT_TOP_SZ )==5UL );
  FD_TEST( fd_progcache_class( FD_PROGCACHE_SLOT_TOP_SZ+1UL )==FD_PROGCACHE_CLASS_CNT );
}

/* test_cache_provision: the provisioner fits the budget, never starves a
   class, gives the nx class its fixed count, and rejects tiny budgets. */

static void
check_provision( ulong heap ) {
  ulong sc[ FD_PROGCACHE_CLASS_CNT ];
  FD_TEST( fd_progcache_class_cnt( heap, sc ) );
  ulong used = 0UL;
  for( ulong c=0UL; c<FD_PROGCACHE_CLASS_CNT; c++ ) {
    FD_TEST( sc[c]>=fd_progcache_class_min( c ) );
    used += sc[c]*fd_progcache_slot_sz[c];
  }
  FD_TEST( used<=heap );
  FD_TEST( sc[ FD_PROGCACHE_NX_CLASS ]==FD_PROGCACHE_NX_SLOTS );
}

FD_UNIT_TEST( cache_provision ) {
  check_provision( 1792UL<<20 ); /* production default */
  check_provision(  768UL<<20 );
  check_provision(  256UL<<20 );
  check_provision( 128UL<<20 );
  check_provision( 96UL<<20 );

  /* The structural minimum (the guaranteed class minimums) provisions with
     every class populated; one byte less is rejected. */
  ulong min_value = 0UL;
  for( ulong c=0UL; c<FD_PROGCACHE_DATA_CLASS_CNT; c++ ) min_value += fd_progcache_class_min( c )*fd_progcache_slot_sz[ c ];
  check_provision( min_value );
  ulong sc[ FD_PROGCACHE_CLASS_CNT ];
  FD_TEST( !fd_progcache_class_cnt( min_value-1UL, sc ) );
}

/* test_wksp_geometry: fd_progcache_wksp_sz must be a true inverse of
   fd_progcache_shared_sz.  Topology converts a workspace size into a
   shared budget while the minimum-size check converts a budget back into
   a workspace size; if the two disagree, a workspace that passes the
   minimum check can still fail to provision. */

FD_UNIT_TEST( wksp_geometry ) {
  static ulong const shared[] = {
    1UL<<20, 16UL<<20, 96UL<<20, 143UL<<20, 256UL<<20, 768UL<<20, 1792UL<<20, 2048UL<<20, 8UL<<30
  };
  for( ulong i=0UL; i<sizeof(shared)/sizeof(shared[0]); i++ ) {
    ulong wksp_sz = fd_progcache_wksp_sz( shared[i] );
    FD_TEST( wksp_sz>=shared[i] );                            /* never shrinks */
    FD_TEST( fd_progcache_shared_sz( wksp_sz )>=shared[i] );  /* covers the request */
    FD_TEST( fd_progcache_wksp_part_max( wksp_sz ) );         /* partitions reservable */
  }

  /* And the minimum a caller is told to provide really does provision. */
  for( ulong txn_max=1UL; txn_max<=64UL; txn_max*=4UL ) {
    ulong min_sz = fd_progcache_min_wksp_sz( txn_max );
    FD_TEST( fd_progcache_shmem_footprint( txn_max, fd_progcache_shared_sz( min_sz ) ) );
  }
}

/* test_shmem_dirty_memory: construction must not rely on zero-filled
   memory.  Pattern-fill the shmem region, construct, use, and delete: a
   constructor that leaves cache fields (notably arena_gaddr) uninitialized
   would free garbage addresses on delete. */

FD_UNIT_TEST( shmem_dirty_memory ) {
  ulong txn_max = 16UL;
  ulong heap    = 256UL<<20;
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

/* test_shmem_new_arena_oom_retry: a wksp too small for the value arenas
   makes construction fail partway through the class loop; it must roll
   back cleanly (even in dirty memory) and be retryable in the same shmem. */

FD_UNIT_TEST( shmem_new_arena_oom_retry ) {
  fd_wksp_t * w2 = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 20000UL, fd_log_cpu_id(), "progcache_oom", 0UL ); /* ~78 MiB */
  FD_TEST( w2 );
  ulong txn_max = 16UL;
  ulong heap    = 256UL<<20; /* arenas (~250 MiB) cannot fit */
  ulong fp      = fd_progcache_shmem_footprint( txn_max, heap );
  void * mem = fd_wksp_alloc_laddr( w2, fd_progcache_shmem_align(), fp, 1UL );
  FD_TEST( mem );
  fd_memset( mem, 0xCC, fp );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, txn_max, heap ) ); /* arena alloc fails -> rollback */
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, txn_max, heap ) ); /* retry in same (now dirtied) shmem */
  fd_wksp_free_laddr( mem );                                          /* wksp still consistent */
  fd_wksp_delete_anonymous( w2 );
}

FD_UNIT_TEST( shmem_new_small_heap ) {
  /* heap too small to give every class a slot is rejected */
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 256UL<<20 ), 1UL );
  FD_TEST( !fd_progcache_shmem_footprint( 16UL, 16UL<<20 ) );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, 16UL<<20 ) );
  fd_wksp_free_laddr( mem );
}

FD_UNIT_TEST( shmem_delete_fast ) {
  ulong txn_max  = 16UL;
  ulong wksp_tag =  2UL;

  fd_progcache_shmem_t * progcache_mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, 256UL<<20 ), wksp_tag );
  FD_TEST( fd_progcache_shmem_new( progcache_mem, wksp_tag, 1UL, txn_max, 256UL<<20 ) );

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

/* test_reclaim_mixed: Multiple records enqueued for reclaim with mixed
   readability.  Only records without active readers should be freed. */

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

  fd_progcache_delete_rec( env->progcache->join, rec1 );
  fd_progcache_delete_rec( env->progcache->join, rec2 );

  FD_TEST( fd_progcache_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( env->progcache->join->shmem->rec.reclaim_head!=UINT_MAX );

  fd_progcache_rec_close( env->progcache, rec1 );

  FD_TEST( fd_progcache_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( env->progcache->join->shmem->rec.reclaim_head==UINT_MAX );

  fd_progcache_cancel_fork( env->progcache->join, xid );
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

  /* Ensure visited bits are set */
  ulong rec1_idx = (ulong)( rec1 - env->progcache->join->rec.ele );
  ulong rec2_idx = (ulong)( rec2 - env->progcache->join->rec.ele );
  ulong rec3_idx = (ulong)( rec3 - env->progcache->join->rec.ele );
  fd_progcache_state_touch( env->progcache->join->rec.state, rec1_idx );
  fd_progcache_state_touch( env->progcache->join->rec.state, rec2_idx );
  fd_progcache_state_touch( env->progcache->join->rec.state, rec3_idx );

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;

  /* Per-class CLOCK: each fd_progcache_evict clears a visited victim (second
     chance) or evicts an unvisited one; three calls evict all three
     (all three programs live in the same small class). */
  for( ulong i=0UL; i<3UL; i++ ) fd_progcache_evict( env->progcache, valid_program_data_sz );

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

  ulong rec_idx = (ulong)( rec1 - env->progcache->join->rec.ele );

  /* Clear visited flag so the next pass evicts immediately (no second chance) */
  __atomic_fetch_and( &env->progcache->join->rec.state[ rec_idx ], (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  fd_progcache_evict( env->progcache, valid_program_data_sz );

  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before == 1UL );
  FD_TEST( !test_peek( env->progcache, xid, &key1, 0UL, 0UL ) );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_clock_evict_empty_cache: No-op eviction on empty cache. */

FD_UNIT_TEST( clock_evict_empty_cache ) {
  test_env_t * env = test_env_create( wksp );

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  fd_progcache_evict( env->progcache, valid_program_data_sz );

  FD_TEST( env->progcache->metrics->evict_cnt == evict_cnt_before );
  FD_TEST( !fd_progcache_verify( env->progcache->join ) );

  test_env_destroy( env );
}

/* test_clock_evict_delete_fails: fd_progcache_delete_rec returns -1 for a
   stale exists bit.  Eviction should skip it and keep going. */

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

  ulong rec1_idx = (ulong)( rec1 - env->progcache->join->rec.ele );
  ulong rec2_idx = (ulong)( rec2 - env->progcache->join->rec.ele );

  /* Clear visited flags */
  uchar * state = env->progcache->join->rec.state;
  __atomic_fetch_and( &state[ rec1_idx ], (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );
  __atomic_fetch_and( &state[ rec2_idx ], (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );

  /* Remove rec1 from the index but leave it awaiting reclaim.  Deletion
     does not touch the state byte, so rec1 keeps a LIVE bit that no longer
     corresponds to a mapped record, and it is unlocked, so the CLOCK can
     claim it. */
  FD_TEST( fd_progcache_delete_rec( env->progcache->join, rec1 )>=0L );
  FD_TEST( __atomic_load_n( &state[ rec1_idx ], __ATOMIC_RELAXED ) & FD_PROGCACHE_REC_LIVE );

  /* Point the class hand at rec1 so it is the first slot examined. */
  fd_progcache_shmem_t * shmem = env->progcache->join->shmem;
  shmem->cache.clock_hand[ fd_progcache_rec_class( shmem, rec1_idx ) ] = rec1_idx;

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;

  /* The CLOCK claims rec1, its delete fails (no longer in the map), so it
     retires the stale LIVE bit and moves on to evict rec2 (unvisited). */
  fd_progcache_evict( env->progcache, valid_program_data_sz );

  FD_TEST( !( __atomic_load_n( &state[ rec1_idx ], __ATOMIC_RELAXED ) & FD_PROGCACHE_REC_LIVE ) );
  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before >= 1UL );
  FD_TEST( !test_peek( env->progcache, xid, &key2, 0UL, 0UL ) );

  fd_progcache_cancel_fork( env->progcache->join, xid );
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

  ulong rec_idx = (ulong)( rec1 - env->progcache->join->rec.ele );

  /* Clear visited flag */
  __atomic_fetch_and( &env->progcache->join->rec.state[ rec_idx ], (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  ulong evict_sz_before  = env->progcache->metrics->evict_tot_sz;

  fd_progcache_evict( env->progcache, valid_program_data_sz );

  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before == 1UL );
  FD_TEST( env->progcache->metrics->evict_tot_sz - evict_sz_before > 0UL );
  FD_TEST( !test_peek( env->progcache, xid, &key1, 0UL, 0UL ) );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_pull_refreshes_clock_bit: a cache hit via pull() marks the record
   accessed for CLOCK replacement, so frequently-pulled programs are
   protected from eviction.  fd_progcache_state_touch runs on insert and on
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

  ulong hot_idx  = (ulong)( rec_hot  - env->progcache->join->rec.ele );
  ulong cold_idx = (ulong)( rec_cold - env->progcache->join->rec.ele );

  /* Clear both visited flags (insert sets them) to simulate the CLOCK
     hand having already passed once. */
  uchar * state = env->progcache->join->rec.state;
  __atomic_fetch_and( &state[ hot_idx  ], (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );
  __atomic_fetch_and( &state[ cold_idx ], (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );

  /* Pull (hit) only the hot program.  This must re-set its reference
     bit.  (peek is pure and would not.) */
  FD_TEST( test_pull( env->progcache, acc_hot.entry, xid, &key_hot, &load_env )==rec_hot );

  /* Evict one record from the class.  The per-class CLOCK gives the just-
     pulled hot record a second chance and evicts the cold record instead. */
  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  fd_progcache_evict( env->progcache, valid_program_data_sz );
  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before == 1UL );

  /* The hot (recently-pulled) program survives; the cold one is evicted.
     (peek is used here only as a pure existence check.) */
  FD_TEST(  test_peek( env->progcache, xid, &key_hot,  0UL, 0UL ) );
  FD_TEST( !test_peek( env->progcache, xid, &key_cold, 0UL, 0UL ) );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_nx_class: a program that fails to load is cached as a non-executable
   (nx) record living in the nx size class -- it holds an nx slot (so it is
   evictable via the per-class CLOCK) but no program data. */

FD_UNIT_TEST( nx_class ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( env->progcache->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, invalid_program_data, invalid_program_data_sz );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };

  ulong nx = FD_PROGCACHE_NX_CLASS;
  ulong nx_free_before = fd_progcache_class_free_cnt( env->progcache->join->shmem, nx );
  ulong fill_before = env->progcache->metrics->fill_per_class[ nx ];
  ulong hit_before  = env->progcache->metrics->hit_per_class [ nx ];

  fd_progcache_rec_t * rec = fd_progcache_pull( env->progcache, xid, &key, &load_env, acc.entry );
  FD_TEST( rec );                                  /* cached (FailedVerification) */
  FD_TEST( !rec->data_gaddr );                     /* non-executable: no program data */
  ulong rec_idx = (ulong)( rec - env->progcache->join->rec.ele );
  FD_TEST( fd_progcache_rec_class( env->progcache->join->shmem, rec_idx )==nx ); /* lives in the nx class */
  fd_progcache_rec_close( env->progcache, rec );

  FD_TEST( fd_progcache_class_free_cnt( env->progcache->join->shmem, nx )==nx_free_before-1UL ); /* one nx slot in use */
  FD_TEST( env->progcache->metrics->fill_per_class[ nx ]==fill_before+1UL ); /* the fill is attributed to nx */

  /* A repeat pull hits the cached nx record, also attributed to nx. */
  fd_progcache_rec_t * hit_rec = fd_progcache_pull( env->progcache, xid, &key, &load_env, acc.entry );
  FD_TEST( hit_rec==rec );
  FD_TEST( env->progcache->metrics->hit_per_class[ nx ]==hit_before+1UL );
  fd_progcache_rec_close( env->progcache, hit_rec );

  /* Evict it from the nx class (clear visited so it goes on the first pass). */
  __atomic_fetch_and( &env->progcache->join->rec.state[ rec_idx ], (uchar)~FD_PROGCACHE_REC_VISITED, __ATOMIC_RELAXED );
  ulong evict_before = env->progcache->metrics->evict_cnt;
  ulong evict_nx_before = env->progcache->metrics->evict_per_class[ nx ];
  fd_progcache_evict( env->progcache, 0UL ); /* size 0 -> nx class */
  FD_TEST( env->progcache->metrics->evict_cnt - evict_before >= 1UL );
  FD_TEST( env->progcache->metrics->evict_per_class[ nx ] > evict_nx_before );
  FD_TEST( !test_peek( env->progcache, xid, &key, 0UL, 0UL ) );                    /* gone */
  FD_TEST( fd_progcache_class_free_cnt( env->progcache->join->shmem, nx )==nx_free_before );    /* slot returned */

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_nx_spill: saturate the nx class (every record held by an open
   reader, so eviction defers and none frees), then pull one more
   verify-fail program.  Its nx acquisition (the second acquisition of
   that insert, after the data record is abandoned) must fall back to the
   spill ws (non-executable result), and nothing may be left mapped. */

FD_UNIT_TEST( nx_spill ) {
  test_env_t *           env   = test_env_create( wksp );
  fd_progcache_t *       pc    = env->progcache;
  fd_progcache_shmem_t * shmem = pc->join->shmem;
  fd_progcache_fork_id_t xid   = fd_progcache_attach_child( pc->join, fd_progcache_fork_id_initial() );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };

  ulong nx    = FD_PROGCACHE_NX_CLASS;
  ulong nslot = shmem->cache.nslot[ nx ];

  test_account_t *      acc  = fd_wksp_alloc_laddr( wksp, alignof(test_account_t), sizeof(test_account_t), 1UL );
  fd_progcache_rec_t ** held = fd_wksp_alloc_laddr( wksp, alignof(void *), nslot*sizeof(void *), 1UL );
  FD_TEST( acc && held );

  /* Saturate: nslot distinct verify-fail programs (peek passes, load fails ->
     each migrates into an nx slot), all held open. */
  for( ulong i=0UL; i<nslot; i++ ) {
    fd_pubkey_t k = test_key( 1000UL+i );
    test_account_init( acc, &k, &fd_solana_bpf_loader_program_id, 1, invalid_program_data, invalid_program_data_sz );
    held[ i ] = fd_progcache_pull( pc, xid, &k, &load_env, acc->entry );
    FD_TEST( held[ i ] && !held[ i ]->data_gaddr );
    FD_TEST( fd_progcache_rec_class( shmem, (ulong)( held[ i ]-pc->join->rec.ele ) )==nx );
  }
  FD_TEST( fd_progcache_class_free_cnt( shmem, nx )==0UL );

  /* One more verify-fail pull: migration retries exhaust -> spill fallback. */
  ulong full0  = pc->metrics->class_full_cnt;
  ulong spill0 = pc->metrics->spill_cnt;
  fd_pubkey_t k = test_key( 999999UL );
  test_account_init( acc, &k, &fd_solana_bpf_loader_program_id, 1, invalid_program_data, invalid_program_data_sz );
  fd_progcache_rec_t * srec = fd_progcache_pull( pc, xid, &k, &load_env, acc->entry );
  FD_TEST( srec );
  FD_TEST( srec>=shmem->spill.rec && srec<shmem->spill.rec+FD_MAX_INSTRUCTION_STACK_DEPTH ); /* served from spill ws */
  FD_TEST( !srec->data_gaddr );                        /* non-executable result */
  FD_TEST( pc->metrics->class_full_cnt>full0 );        /* exhaustion path taken */
  FD_TEST( pc->metrics->spill_cnt    >spill0 );
  FD_TEST( !test_peek( pc, xid, &k, 0UL, 0UL ) );      /* record was unpublished, not left mapped */
  fd_progcache_rec_close( pc, srec );                  /* releases the spill ws */

  /* Cleanup: release the readers, drain deferred reclaim, cancel the fork;
     every nx slot must return. */
  for( ulong i=0UL; i<nslot; i++ ) fd_progcache_rec_close( pc, held[ i ] );
  fd_progcache_reclaim_work( pc->join );
  fd_progcache_cancel_fork( pc->join, xid );
  FD_TEST( fd_progcache_class_free_cnt( shmem, nx )==nslot );

  fd_wksp_free_laddr( held );
  fd_wksp_free_laddr( acc );
  test_env_destroy( env );
}

/* test_verify_detects_slot_faults: fd_progcache_verify is the structural check
   the other tests lean on, so its per-class slot accounting has to actually
   detect the faults it exists for.  Inject each one, confirm verify rejects,
   restore, confirm verify accepts again. */

FD_UNIT_TEST( verify_detects_slot_faults ) {
  test_env_t *           env   = test_env_create( wksp );
  fd_progcache_t *       pc    = env->progcache;
  fd_progcache_shmem_t * shmem = pc->join->shmem;

  ulong  c  = 0UL;                                     /* the 128 KiB class */
  ulong  base = shmem->cache.rec_base[ c ];
  uint * fs   = fd_prog_freestack_join( fd_wksp_laddr_fast( pc->join->data_base,
                                                            shmem->cache.free_gaddr[ c ] ) );
  FD_TEST( fd_prog_freestack_cnt( fs )>0UL );
  FD_TEST( !fd_progcache_verify( pc->join ) );         /* clean baseline */

  FD_LOG_NOTICE(( "injecting slot faults: the FAIL warnings below are expected" ));

  /* A slot freed twice: the repeated index inflates the free count past
     nslot. */
  fd_prog_freestack_push( fs, (uint)base );
  FD_TEST( fd_progcache_verify( pc->join ) );
  fd_prog_freestack_pop( fs );
  FD_TEST( !fd_progcache_verify( pc->join ) );

  /* A leaked slot: off the free list and never made live. */
  uint leaked = fd_prog_freestack_pop( fs );
  FD_TEST( fd_progcache_verify( pc->join ) );
  fd_prog_freestack_push( fs, leaked );
  FD_TEST( !fd_progcache_verify( pc->join ) );

  /* A live record sitting on the free list. */
  __atomic_fetch_or( &pc->join->rec.state[ base ], FD_PROGCACHE_REC_LIVE, __ATOMIC_RELAXED );
  FD_TEST( fd_progcache_verify( pc->join ) );
  __atomic_store_n( &pc->join->rec.state[ base ], (uchar)0, __ATOMIC_RELAXED );
  FD_TEST( !fd_progcache_verify( pc->join ) );

  test_env_destroy( env );
}

/* test_metrics_per_class_sums: every scalar counter is paired with a per-class
   breakdown, so the breakdown must sum to the scalar.  This is what an
   unreachable class bucket breaks: before non-executable entries were
   attributed to the nx class, hit_cnt and fill_cnt were incremented for them
   while their per-class buckets were not, and these sums did not match. */

FD_UNIT_TEST( metrics_per_class_sums ) {
  test_env_t *           env = test_env_create( wksp );
  fd_progcache_t *       pc  = env->progcache;
  fd_progcache_fork_id_t xid = fd_progcache_attach_child( pc->join, fd_progcache_fork_id_initial() );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };

  /* Exercise fills, hits and non-executable entries so several buckets and
     both loader outcomes are represented. */
  test_account_t acc;
  for( ulong i=0UL; i<8UL; i++ ) {
    fd_pubkey_t k = test_key( 700UL+i );
    int valid = !(i&1UL);
    test_account_init( &acc, &k, &fd_solana_bpf_loader_program_id, 1,
                       valid ? valid_program_data      : invalid_program_data,
                       valid ? valid_program_data_sz   : invalid_program_data_sz );
    FD_TEST( test_pull( pc, acc.entry, xid, &k, &load_env ) );
    FD_TEST( test_pull( pc, acc.entry, xid, &k, &load_env ) );   /* a hit */
  }

  fd_progcache_metrics_t const * m = pc->metrics;
  ulong hit=0UL, fill=0UL, evict=0UL, spill=0UL;
  for( ulong c=0UL; c<FD_PROGCACHE_CLASS_CNT; c++ ) {
    hit   += m->hit_per_class  [ c ];
    fill  += m->fill_per_class [ c ];
    evict += m->evict_per_class[ c ];
    spill += m->spill_per_class[ c ];
  }
  /* Equality, not >=: every increment site pairs the two, and a program large
     enough to fall outside every class is unreachable. */
  FD_TEST( hit  ==m->hit_cnt   );
  FD_TEST( fill ==m->fill_cnt  );
  FD_TEST( evict==m->evict_cnt );
  FD_TEST( spill==m->spill_cnt );

  fd_progcache_cancel_fork( pc->join, xid );
  test_env_destroy( env );
}

/* test_spill_revision: a record whose (fork, program) key is already mapped
   at a different revision cannot join the index, so the requested revision
   is served from the spill ws without being published. */

FD_UNIT_TEST( spill_revision ) {
  test_env_t *           env   = test_env_create( wksp );
  fd_progcache_t *       pc    = env->progcache;
  fd_progcache_shmem_t * shmem = pc->join->shmem;
  fd_progcache_fork_id_t xid   = fd_progcache_attach_child( pc->join, fd_progcache_fork_id_initial() );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  /* Cache the program at feature_slot 0. */
  fd_prog_load_env_t env0 = { .features = env->features, .feature_slot = 0UL };
  FD_TEST( test_pull( pc, acc.entry, xid, &key, &env0 ) );

  /* Pull it again on the same fork at a different feature_slot.  Lookups key
     on feature_slot so this misses, but the index already holds this
     (fork, program) key, leaving the insert nowhere to publish. */
  fd_prog_load_env_t env1 = { .features = env->features, .feature_slot = 1UL };
  ulong spill0 = pc->metrics->spill_cnt;
  ulong miss0  = pc->metrics->miss_cnt;
  fd_progcache_rec_t * srec = fd_progcache_pull( pc, xid, &key, &env1, acc.entry );
  FD_TEST( srec );
  FD_TEST( srec>=shmem->spill.rec && srec<shmem->spill.rec+FD_MAX_INSTRUCTION_STACK_DEPTH ); /* from the spill ws */
  FD_TEST( srec->feature_slot==1UL );                  /* the requested revision */
  FD_TEST( pc->metrics->spill_cnt==spill0+1UL );
  FD_TEST( pc->metrics->miss_cnt  >miss0 );
  ulong dslot = srec->deploy_slot;
  FD_TEST( !test_peek( pc, xid, &key, 1UL, dslot ) );  /* never published */
  fd_progcache_rec_close( pc, srec );                  /* releases the spill ws */

  FD_TEST( test_peek( pc, xid, &key, 0UL, dslot ) );   /* the original survives */

  fd_progcache_cancel_fork( pc->join, xid );
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

  ulong n0 = env->progcache->join->shmem->cache.nslot[ 0 ]; /* 128 KiB class */
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

  ulong n0 = env->progcache->join->shmem->cache.nslot[ 0 ];
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
/* test_spill_block: a class with nothing evictable cannot be made to yield by
   rescanning it, so when the spill ws is already held the insert must block
   for it instead of spinning.  A helper thread holds the spill ws for a fixed
   interval; the insert may only complete after it is released. */

struct spill_hold_ctx {
  fd_progcache_shmem_t * shmem;
  int volatile           held;      /* holder owns the spill ws          */
  int volatile           incoming;  /* requester is about to ask for it  */
  long                   hold_ns;
};

/* Holds the spill ws until the requester says it is about to ask for it, then
   keeps holding for hold_ns.  Waiting on `incoming` rather than sleeping from
   the start means the hold window is still open when the request lands, no
   matter how the requester is scheduled beforehand. */

static void *
spill_hold_worker( void * _ctx ) {
  struct spill_hold_ctx * ctx = _ctx;
  fd_rwlock_write( &ctx->shmem->spill.lock );
  FD_VOLATILE( ctx->held ) = 1;
  while( !FD_VOLATILE_CONST( ctx->incoming ) ) FD_SPIN_PAUSE();
  fd_log_sleep( ctx->hold_ns );
  fd_rwlock_unwrite( &ctx->shmem->spill.lock );
  return NULL;
}

FD_UNIT_TEST( spill_block ) {
  test_env_t *           env   = test_env_create( wksp );
  fd_progcache_t *       pc    = env->progcache;
  fd_progcache_shmem_t * shmem = pc->join->shmem;
  fd_progcache_fork_id_t xid   = fd_progcache_attach_child( pc->join, fd_progcache_fork_id_initial() );
  fd_prog_load_env_t load_env = { .features = env->features, .feature_slot = 0UL };

  ulong nx    = FD_PROGCACHE_NX_CLASS;
  ulong nslot = shmem->cache.nslot[ nx ];

  test_account_t *      acc  = fd_wksp_alloc_laddr( wksp, alignof(test_account_t), sizeof(test_account_t), 1UL );
  fd_progcache_rec_t ** held = fd_wksp_alloc_laddr( wksp, alignof(void *), nslot*sizeof(void *), 1UL );
  FD_TEST( acc && held );

  /* Saturate the nx class, every slot held open so nothing is evictable. */
  for( ulong i=0UL; i<nslot; i++ ) {
    fd_pubkey_t k = test_key( 2000UL+i );
    test_account_init( acc, &k, &fd_solana_bpf_loader_program_id, 1, invalid_program_data, invalid_program_data_sz );
    held[ i ] = fd_progcache_pull( pc, xid, &k, &load_env, acc->entry );
    FD_TEST( held[ i ] );
  }
  FD_TEST( fd_progcache_class_free_cnt( shmem, nx )==0UL );

  /* Hand the spill ws to a helper thread and wait until it owns it. */
  long                  hold_ns = 100000000L; /* 100 ms */
  struct spill_hold_ctx hctx    = { .shmem = shmem, .held = 0, .incoming = 0, .hold_ns = hold_ns };
  pthread_t             th;
  FD_TEST( 0==pthread_create( &th, NULL, spill_hold_worker, &hctx ) );
  while( !FD_VOLATILE_CONST( hctx.held ) ) FD_SPIN_PAUSE();

  /* The class yields nothing and the spill ws is taken, so this must wait. */
  ulong spill0 = pc->metrics->spill_cnt;
  fd_pubkey_t k = test_key( 299999UL );
  test_account_init( acc, &k, &fd_solana_bpf_loader_program_id, 1, invalid_program_data, invalid_program_data_sz );
  FD_VOLATILE( hctx.incoming ) = 1;
  long                 t0   = fd_log_wallclock();
  fd_progcache_rec_t * srec = fd_progcache_pull( pc, xid, &k, &load_env, acc->entry );
  long                 dt   = fd_log_wallclock() - t0;

  FD_TEST( 0==pthread_join( th, NULL ) );
  FD_TEST( srec );
  FD_TEST( srec>=shmem->spill.rec && srec<shmem->spill.rec+FD_MAX_INSTRUCTION_STACK_DEPTH );
  FD_TEST( pc->metrics->spill_cnt>spill0 );
  FD_TEST( dt>=hold_ns/5L ); /* it waited for the holder rather than spinning on the class */
  fd_progcache_rec_close( pc, srec );

  for( ulong i=0UL; i<nslot; i++ ) fd_progcache_rec_close( pc, held[ i ] );
  fd_progcache_reclaim_work( pc->join );
  fd_progcache_cancel_fork( pc->join, xid );
  FD_TEST( fd_progcache_class_free_cnt( shmem, nx )==nslot );

  fd_wksp_free_laddr( held );
  fd_wksp_free_laddr( acc );
  test_env_destroy( env );
}

/* test_spill_concurrent: many threads share one progcache and hammer a small
   class so its slots fill and, being read-locked, force spills -- exercising
   the exclusive spill ws lock under real parallelism.  A watchdog fails the
   test if forward progress stalls (deadlock); an integrity check on every
   pulled program (rodata_sz must match the reference) catches spad corruption
   from a broken lock.  CONC_HOLD stays <= FD_MAX_INSTRUCTION_STACK_DEPTH so a
   single thread never needs more than one spill stack. */

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

FD_UNIT_TEST( spill_concurrent ) {
  ulong wksp_tag = 1UL;
  ulong txn_max  = 64UL;
  ulong shared_sz = 160UL<<20;                      /* small enough that class 0 is a few dozen slots */

  void * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, shared_sz ), wksp_tag );
  FD_TEST( mem );
  fd_progcache_shmem_t * shmem = fd_progcache_shmem_new( mem, wksp_tag, 1UL, txn_max, shared_sz );
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
    fd_log_sleep( 100000000L ); /* 100 ms */
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
  /* Whether the stress trips the spill path depends on how the threads
     interleave, so it is reported rather than asserted; spill_basic,
     spill_lock and nx_spill cover that path deterministically.  What this
     test asserts is the absence of deadlock and corruption under load. */

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
