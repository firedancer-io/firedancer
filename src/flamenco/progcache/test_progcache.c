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
test_env_create( fd_wksp_t * wksp ) {
  ulong txn_max           = 16UL;
  ulong progcache_rec_max = 32UL;
  ulong wksp_tag          =  1UL;

  void * progcache_mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, progcache_rec_max ), wksp_tag );
  FD_TEST( fd_progcache_shmem_new( progcache_mem, wksp_tag, 1UL, txn_max, progcache_rec_max ) );

  test_env_t * env = fd_wksp_alloc_laddr( wksp, alignof(test_env_t), sizeof(test_env_t), wksp_tag );
  FD_TEST( env );
  memset( env, 0, offsetof(test_env_t, scratch) );

  env->wksp = wksp;
  FD_TEST( fd_progcache_join( env->progcache, progcache_mem, env->scratch, sizeof(env->scratch) ) );

  return env;
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

  FD_TEST( env->progcache->join->rec.reclaim_head==UINT_MAX );
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==0UL );

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

  long freed = fd_prog_delete_rec( env->progcache->join, rec );
  FD_TEST( freed>=0L );
  FD_TEST( env->progcache->join->rec.reclaim_head!=UINT_MAX );

  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( env->progcache->join->rec.reclaim_head==UINT_MAX );

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

  fd_prog_delete_rec( env->progcache->join, rec );
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==0UL );
  FD_TEST( env->progcache->join->rec.reclaim_head!=UINT_MAX );

  fd_progcache_rec_close( env->progcache, rec );
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( env->progcache->join->rec.reclaim_head==UINT_MAX );

  fd_progcache_cancel_fork( env->progcache->join, xid );
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

  fd_prog_delete_rec( env->progcache->join, rec );
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( txn->rec_head_idx==UINT_MAX );
  FD_TEST( txn->rec_tail_idx==UINT_MAX );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

FD_UNIT_TEST( join_null_scratch ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 32UL ), 1UL );
  FD_TEST( fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, 32UL ) );
  fd_progcache_t cache[1];
  FD_TEST( !fd_progcache_join( cache, mem, NULL, 4096UL ) );
  fd_wksp_free_laddr( fd_progcache_shmem_delete( mem ) );
}

FD_UNIT_TEST( join_misaligned_scratch ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 32UL ), 1UL );
  FD_TEST( fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, 32UL ) );
  uchar scratch_buf[ FD_PROGCACHE_SCRATCH_ALIGN ] __attribute__((aligned(FD_PROGCACHE_SCRATCH_ALIGN)));
  fd_progcache_t cache[1];
  FD_TEST( !fd_progcache_join( cache, mem, scratch_buf+1, sizeof(scratch_buf)-1 ) );
  fd_wksp_free_laddr( fd_progcache_shmem_delete( mem ) );
}

FD_UNIT_TEST( shmem_new_zero_txn_max ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 32UL ), 1UL );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, 0UL, 32UL ) );
  fd_wksp_free_laddr( mem );
}

FD_UNIT_TEST( shmem_new_zero_rec_max ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 32UL ), 1UL );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, 0UL ) );
  fd_wksp_free_laddr( mem );
}

FD_UNIT_TEST( shmem_new_oversized_txn_max ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 32UL ), 1UL );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, (ulong)UINT_MAX+1UL, 32UL ) );
  fd_wksp_free_laddr( mem );
}

FD_UNIT_TEST( shmem_new_oversized_rec_max ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 32UL ), 1UL );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, (ulong)UINT_MAX+1UL ) );
  fd_wksp_free_laddr( mem );
}

FD_UNIT_TEST( shmem_delete_fast ) {
  ulong txn_max           = 16UL;
  ulong progcache_rec_max = 32UL;
  ulong wksp_tag          =  2UL;

  fd_progcache_shmem_t * progcache_mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, progcache_rec_max ), wksp_tag );
  FD_TEST( fd_progcache_shmem_new( progcache_mem, wksp_tag, 1UL, txn_max, progcache_rec_max ) );

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

  fd_prog_delete_rec( env->progcache->join, rec1 );
  fd_prog_delete_rec( env->progcache->join, rec2 );

  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( env->progcache->join->rec.reclaim_head!=UINT_MAX );

  fd_progcache_rec_close( env->progcache, rec1 );

  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( env->progcache->join->rec.reclaim_head==UINT_MAX );

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
  ulong rec1_idx = (ulong)( rec1 - env->progcache->join->rec.pool->ele );
  ulong rec2_idx = (ulong)( rec2 - env->progcache->join->rec.pool->ele );
  ulong rec3_idx = (ulong)( rec3 - env->progcache->join->rec.pool->ele );
  fd_prog_clock_touch( env->progcache->join->clock.bits, rec1_idx );
  fd_prog_clock_touch( env->progcache->join->clock.bits, rec2_idx );
  fd_prog_clock_touch( env->progcache->join->clock.bits, rec3_idx );

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  env->progcache->join->shmem->clock.head = 0UL;

  fd_prog_clock_evict( env->progcache, 3UL, 0UL );

  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before == 3UL );
  FD_TEST( !test_peek( env->progcache, xid, &key1, 0UL, 0UL ) );
  FD_TEST( !test_peek( env->progcache, xid, &key2, 0UL, 0UL ) );
  FD_TEST( !test_peek( env->progcache, xid, &key3, 0UL, 0UL ) );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_clock_evict_wraps_around: Head wraps from rec_max back to 0. */

FD_UNIT_TEST( clock_evict_wraps_around ) {
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

  ulong rec_max = env->progcache->join->rec.pool->ele_max;
  ulong rec_idx = (ulong)( rec1 - env->progcache->join->rec.pool->ele );

  /* Clear visited bit */
  atomic_ulong * slot_p = fd_prog_cbits_slot( env->progcache->join->clock.bits, rec_idx );
  ulong vmask = 1UL<<fd_prog_visited_bit( rec_idx );
  atomic_fetch_and_explicit( slot_p, ~vmask, memory_order_relaxed );

  /* Start head near end so it must wrap */
  env->progcache->join->shmem->clock.head = rec_max - 1UL;

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  fd_prog_clock_evict( env->progcache, 1UL, 0UL );

  FD_TEST( env->progcache->join->shmem->clock.head <= rec_max );
  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before == 1UL );
  FD_TEST( !test_peek( env->progcache, xid, &key1, 0UL, 0UL ) );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_clock_evict_empty_cache: No-op eviction on empty cache. */

FD_UNIT_TEST( clock_evict_empty_cache ) {
  test_env_t * env = test_env_create( wksp );

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  fd_prog_clock_evict( env->progcache, 1UL, 0UL );

  FD_TEST( env->progcache->metrics->evict_cnt == evict_cnt_before );
  FD_TEST( !fd_progcache_verify( env->progcache->join ) );

  test_env_destroy( env );
}

/* test_clock_evict_delete_fails: fd_prog_delete_rec returns -1 for a
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

  ulong rec1_idx = (ulong)( rec1 - env->progcache->join->rec.pool->ele );
  ulong rec2_idx = (ulong)( rec2 - env->progcache->join->rec.pool->ele );

  /* Clear visited bits */
  atomic_ulong * slot1_p = fd_prog_cbits_slot( env->progcache->join->clock.bits, rec1_idx );
  ulong vmask1 = 1UL<<fd_prog_visited_bit( rec1_idx );
  atomic_fetch_and_explicit( slot1_p, ~vmask1, memory_order_relaxed );

  atomic_ulong * slot2_p = fd_prog_cbits_slot( env->progcache->join->clock.bits, rec2_idx );
  ulong vmask2 = 1UL<<fd_prog_visited_bit( rec2_idx );
  atomic_fetch_and_explicit( slot2_p, ~vmask2, memory_order_relaxed );

  /* Remove rec1 from index, then re-set its exists bit to simulate
     a stale cbit (race between concurrent delete and eviction). */
  fd_prog_delete_rec( env->progcache->join, rec1 );
  fd_prog_reclaim_work( env->progcache->join );
  ulong emask1 = 1UL<<fd_prog_exists_bit( rec1_idx );
  atomic_fetch_or_explicit( slot1_p, emask1, memory_order_relaxed );

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  ulong head_start = fd_ulong_min( rec1_idx, rec2_idx );
  env->progcache->join->shmem->clock.head = head_start;

  /* rec1 delete fails (-1), rec2 succeeds */
  fd_prog_clock_evict( env->progcache, 1UL, 0UL );

  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before >= 1UL );
  FD_TEST( !test_peek( env->progcache, xid, &key2, 0UL, 0UL ) );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_clock_evict_heap_only: rec_min=0, heap_min>0 evicts by heap. */

FD_UNIT_TEST( clock_evict_heap_only ) {
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

  ulong rec_idx = (ulong)( rec1 - env->progcache->join->rec.pool->ele );

  /* Clear visited bit */
  atomic_ulong * slot_p = fd_prog_cbits_slot( env->progcache->join->clock.bits, rec_idx );
  ulong vmask = 1UL<<fd_prog_visited_bit( rec_idx );
  atomic_fetch_and_explicit( slot_p, ~vmask, memory_order_relaxed );

  env->progcache->join->shmem->clock.head = 0UL;

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  ulong evict_sz_before  = env->progcache->metrics->evict_tot_sz;

  fd_prog_clock_evict( env->progcache, 0UL, 1UL );

  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before == 1UL );
  FD_TEST( env->progcache->metrics->evict_tot_sz - evict_sz_before > 0UL );
  FD_TEST( !test_peek( env->progcache, xid, &key1, 0UL, 0UL ) );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

/* test_pull_refreshes_clock_bit: a cache hit via pull() marks the record
   accessed for CLOCK replacement, so frequently-pulled programs are
   protected from eviction.  fd_prog_clock_touch runs on insert and on
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

  ulong hot_idx  = (ulong)( rec_hot  - env->progcache->join->rec.pool->ele );
  ulong cold_idx = (ulong)( rec_cold - env->progcache->join->rec.pool->ele );

  /* Clear both visited bits (insert sets them) to simulate the CLOCK
     hand having already passed once. */
  atomic_ulong * hot_slot  = fd_prog_cbits_slot( env->progcache->join->clock.bits, hot_idx  );
  atomic_ulong * cold_slot = fd_prog_cbits_slot( env->progcache->join->clock.bits, cold_idx );
  atomic_fetch_and_explicit( hot_slot,  ~( 1UL<<fd_prog_visited_bit( hot_idx  ) ), memory_order_relaxed );
  atomic_fetch_and_explicit( cold_slot, ~( 1UL<<fd_prog_visited_bit( cold_idx ) ), memory_order_relaxed );

  /* Pull (hit) only the hot program.  This must re-set its reference
     bit.  (peek is pure and would not.) */
  FD_TEST( test_pull( env->progcache, acc_hot.entry, xid, &key_hot, &load_env )==rec_hot );

  /* Evict one record, starting the hand at the hot record. */
  env->progcache->join->shmem->clock.head = hot_idx;
  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  fd_prog_clock_evict( env->progcache, 1UL, 0UL );
  FD_TEST( env->progcache->metrics->evict_cnt - evict_cnt_before == 1UL );

  /* The hot (recently-pulled) program survives; the cold one is evicted.
     (peek is used here only as a pure existence check.) */
  FD_TEST(  test_peek( env->progcache, xid, &key_hot,  0UL, 0UL ) );
  FD_TEST( !test_peek( env->progcache, xid, &key_cold, 0UL, 0UL ) );

  fd_progcache_cancel_fork( env->progcache->join, xid );
  test_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
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
