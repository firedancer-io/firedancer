/* test_progcache.c contains single-threaded correctness tests for
   progcache. */

#include "test_progcache_common.c"
#include "fd_progcache_reclaim.h"
#include "fd_progcache_clock.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/program/fd_bpf_loader_program.h"
#include "../features/fd_features.h"
#include "../types/fd_types.h"
#include <stdlib.h>
#include <regex.h>

struct test_env {
  fd_wksp_t *    wksp;
  fd_progcache_t progcache[1];
  fd_features_t  features[1];
  uchar scratch[ FD_PROGCACHE_SCRATCH_FOOTPRINT ] __attribute__((aligned(FD_PROGCACHE_SCRATCH_ALIGN)));
};

typedef struct test_env test_env_t;

/* test_env_create allocates a new account database (funk) and loaded
   program cache from a wksp.  Joins an admin and user client to the
   program cache, as well as a database client. */

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

/* test_env_txn_prepare creates a new in-prep funk transaction off
   parent with the given xid, in both accdb and progcache. */

static void
test_env_txn_prepare( test_env_t *     env,
                      fd_progcache_xid_t const * parent,
                      fd_progcache_xid_t const * xid ) {
  fd_progcache_xid_t root[1];
  if( !parent ) {
    fd_progcache_txn_xid_set_root( root );
    parent = root;
  }
  fd_progcache_attach_child( env->progcache->join, parent, xid );
}

/* test_env_txn_cancel destroys a subtree of in-prep funk transactions
   with root 'xid', in both accdb and progcache. */

static void
test_env_txn_cancel( test_env_t *     env,
                     fd_progcache_xid_t const * xid ) {
  fd_progcache_cancel( env->progcache->join, xid );
}

/* test_env_txn_publish publishes (i.e. roots) a subtree of in-prep funk
   transactions with root 'xid', in both accdb and progcache. */

static void
test_env_txn_publish( test_env_t *     env,
                      fd_progcache_xid_t const * xid ) {
  fd_progcache_advance_root( env->progcache->join, xid );
}

FD_IMPORT_BINARY( valid_program_data,        "src/ballet/sbpf/fixtures/hello_solana_program.so" );
FD_IMPORT_BINARY( bigger_valid_program_data, "src/ballet/sbpf/fixtures/clock_sysvar_program.so" );
FD_IMPORT_BINARY( invalid_program_data,      "src/ballet/sbpf/fixtures/malformed_bytecode.so"   );

/* query_rec_exact fetches a funk record at a precise xid:key pair. */

static fd_progcache_rec_t const *
query_rec_exact( test_env_t *           env,
                 fd_progcache_xid_t const *       xid,
                 fd_pubkey_t const *    key ) {
  fd_progcache_xid_key_pair_t pair[1];
  fd_progcache_txn_xid_copy( pair->xid, xid );
  memcpy( pair->key, key, 32 );

  fd_prog_recm_query_t query[1];
  int query_err = fd_prog_recm_query_try( env->progcache->join->rec.map, pair, NULL, query, 0 );
  if( query_err==FD_MAP_ERR_KEY ) return NULL;
  if( FD_UNLIKELY( query_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_query_try failed: %i-%s", query_err, fd_map_strerror( query_err ) ));

  return fd_prog_recm_query_ele_const( query );
}

/* test_peek and test_pull wrap fd_progcache_{peek,pull} and
   immediately release the read lock on the returned record.  This is
   safe in single-threaded tests where record lifetimes are managed
   by cancel/publish/destroy. */

static fd_progcache_rec_t    *
test_peek( fd_progcache_t    * cache,
           fd_progcache_xid_t    const * xid,
           fd_pubkey_t const * prog_addr,
           ulong               epoch_slot0 ) {
  fd_progcache_rec_t * rec = fd_progcache_peek( cache, xid, prog_addr, epoch_slot0 );
  if( rec ) fd_progcache_rec_close( cache, rec );
  return rec;
}

static fd_progcache_rec_t    *
test_pull( fd_progcache_t    *        cache,
           fd_accdb_entry_t     *        prog_ro,
           fd_progcache_xid_t    const *        xid,
           fd_pubkey_t const *        prog_addr,
           fd_prog_load_env_t const * env ) {
  fd_progcache_rec_t * rec = fd_progcache_pull( cache, xid, prog_addr, env, prog_ro, (fd_pubkey_t const *)prog_ro->owner );
  if( rec ) fd_progcache_rec_close( cache, rec );
  return rec;
}

/* test_account_does_not_exist: Program account missing, but querying at
   a fork. */

static void
test_account_does_not_exist( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  (void)test_env_txn_publish;

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_invalid_owner: Account exists but is not owned by BPF loader */

static void
test_invalid_owner( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_system_program_id, /* not a BPF loader */
                     1, invalid_program_data, invalid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  FD_TEST( !test_pull( env->progcache, acc.entry, &fork_a, &key, &load_env ) );

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_invalid_program: Program account exists but fails loading */

static void
test_invalid_program( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, invalid_program_data, invalid_program_data_sz );

  FD_TEST( !test_peek( env->progcache, &fork_a, &key, 0UL ) );
  FD_TEST( env->progcache->lineage->fork_depth==1UL );
  FD_TEST( fd_progcache_txn_xid_eq( &env->progcache->lineage->fork[ 0 ], &fork_a   ) );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, &fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( !rec->data_gaddr );
  FD_TEST( test_peek( env->progcache, &fork_a, &key, load_env.epoch_slot0 )==rec );

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_valid_program: Load a valid program account */

static void
test_valid_program( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  FD_TEST( !test_peek( env->progcache, &fork_a, &key, 0UL ) );
  FD_TEST( env->progcache->lineage->fork_depth==1UL );
  FD_TEST( fd_progcache_txn_xid_eq( &env->progcache->lineage->fork[ 0 ], &fork_a   ) );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, &fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->data_gaddr );
  FD_TEST( test_peek( env->progcache, &fork_a, &key, 0UL )==rec );
  FD_TEST( env->progcache->lineage->fork_depth==1UL );

  fd_progcache_xid_t fork_b = { .ul = { 64UL, 2UL } };
  test_env_txn_prepare( env, &fork_a, &fork_b );
  FD_TEST( test_peek( env->progcache, &fork_b, &key, 0UL )==rec );
  FD_TEST( env->progcache->lineage->fork_depth==2UL );

  load_env.epoch       = 0UL;
  load_env.epoch_slot0 = 0UL;
  fd_progcache_rec_t const * rec2 = test_pull( env->progcache, acc.entry, &fork_b, &key, &load_env );
  FD_TEST( rec==rec2 );
  FD_TEST( test_peek( env->progcache, &fork_b, &key, 0UL )==rec );

  test_env_txn_cancel( env, &fork_a ); /* should also cancel fork_b */
  test_env_destroy( env );
}

/* test_epoch_boundary: Ensure that a valid program gets re-verified
   after an epoch boundary. */

static void
test_epoch_boundary( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  FD_TEST( !test_peek( env->progcache, &fork_a, &key, 0UL ) );
  FD_TEST( env->progcache->lineage->fork_depth==1UL );
  FD_TEST( fd_progcache_txn_xid_eq( &env->progcache->lineage->fork[ 0 ], &fork_a   ) );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, &fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->data_gaddr );
  FD_TEST( test_peek( env->progcache, &fork_a, &key, 0UL )==rec );

  fd_progcache_xid_t fork_b = { .ul = { 64UL, 2UL } };
  test_env_txn_prepare( env, &fork_a, &fork_b );
  load_env.epoch       =  1UL;
  load_env.epoch_slot0 = 64UL;
  fd_progcache_rec_t const * rec2 = test_pull( env->progcache, acc.entry, &fork_b, &key, &load_env );
  FD_TEST( rec2 );
  FD_TEST( rec!=rec2 );
  FD_TEST( rec2->data_gaddr );
  FD_TEST( test_peek( env->progcache, &fork_b, &key, load_env.epoch_slot0 )==rec2 );

  test_env_txn_cancel( env, &fork_b );
  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_publish_gc: fd_progcache_txn_publish should garbage-collect
   stale entries. */

static void
test_publish_gc( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env_a = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 1UL
  };
  fd_progcache_rec_t const * rec_a = test_pull( env->progcache, acc.entry, &fork_a, &key, &load_env_a );
  FD_TEST( rec_a );
  FD_TEST( rec_a->data_gaddr );

  fd_progcache_xid_t fork_b = { .ul = { 2UL, 1UL } };
  test_env_txn_prepare( env, &fork_a, &fork_b );
  fd_prog_load_env_t load_env_b = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 2UL
  };
  fd_progcache_rec_t const * rec_b = test_pull( env->progcache, acc.entry, &fork_b, &key, &load_env_b );
  FD_TEST( rec_b );
  FD_TEST( rec_b->data_gaddr );

  fd_progcache_xid_t fork_c = { .ul = { 3UL, 2UL } };
  test_env_txn_prepare( env, &fork_b, &fork_c );
  fd_prog_load_env_t load_env_c = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 3UL
  };
  fd_progcache_rec_t const * rec_c = test_pull( env->progcache, acc.entry, &fork_c, &key, &load_env_c );
  FD_TEST( rec_c );
  FD_TEST( rec_c->data_gaddr );

  FD_TEST( test_peek( env->progcache, &fork_a, &key, 1UL )==rec_a );
  FD_TEST( test_peek( env->progcache, &fork_b, &key, 2UL )==rec_b );
  FD_TEST( test_peek( env->progcache, &fork_c, &key, 3UL )==rec_c );

  fd_progcache_rec_t const * frec_a = query_rec_exact( env, &fork_a, &key );
  fd_progcache_rec_t const * frec_b = query_rec_exact( env, &fork_b, &key );
  fd_progcache_rec_t const * frec_c = query_rec_exact( env, &fork_c, &key );
  FD_TEST( frec_a ); FD_TEST( frec_b ); FD_TEST( frec_c );
  FD_TEST( frec_a!=frec_b && frec_a!=frec_c && frec_b!=frec_c );

  fd_progcache_xid_t root; fd_progcache_txn_xid_set_root( &root );
  test_env_txn_publish( env, &fork_a );
  FD_TEST( query_rec_exact( env, &fork_a, &key )==NULL   );
  FD_TEST( query_rec_exact( env, &root,   &key )==frec_a );
  FD_TEST( test_peek( env->progcache, &fork_a, &key, 1UL )==rec_a );

  test_env_txn_publish( env, &fork_b );
  FD_TEST( query_rec_exact( env, &fork_a, &key )==NULL );
  FD_TEST( query_rec_exact( env, &fork_b, &key )==NULL );
  FD_TEST( query_rec_exact( env, &root,   &key )==frec_b );

  test_env_txn_publish( env, &fork_c );
  FD_TEST( query_rec_exact( env, &fork_a, &key )==NULL   );
  FD_TEST( query_rec_exact( env, &fork_b, &key )==NULL   );
  FD_TEST( query_rec_exact( env, &fork_c, &key )==NULL   );
  FD_TEST( query_rec_exact( env, &root,   &key )==frec_c );

  /* Verify that only frec_c exists in funk rec map */
  ulong chain_idx = fd_prog_recm_iter_chain_idx( env->progcache->join->rec.map, &frec_c->pair );
  ulong chain_cnt = 0UL;
  for( fd_prog_recm_iter_t iter = fd_prog_recm_iter( env->progcache->join->rec.map, chain_idx );
       !fd_prog_recm_iter_done( iter );
       iter = fd_prog_recm_iter_next( iter ) ) {
    chain_cnt++;
  }
  FD_TEST( chain_cnt==1UL );

  test_env_destroy( env );
}

static void
test_publish_trivial( fd_wksp_t * wksp ) {
  /* Exercise a sequence of prepare/publish operations seen when running
     'firedancer-dev backtest' */

  test_env_t * env = test_env_create( wksp );

  fd_progcache_xid_t root; fd_progcache_txn_xid_set_root( &root );
  fd_progcache_xid_t fork_368528500 = { .ul = { 368528500UL, 368528500UL } };
  fd_progcache_attach_child( env->progcache->join, &root, &fork_368528500 );
  fd_progcache_advance_root( env->progcache->join,        &fork_368528500 );

  /* FIXME more operations here ... */
}

/* test_root_nonroot_prio: non-rooted record should take priority over
   rooted records. */

static void
test_root_nonroot_prio( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t fork_1 = { .ul = { 1UL, 1UL } }; /* account deployed here */
  fd_progcache_xid_t fork_2 = { .ul = { 2UL, 1UL } }; /* root */
  fd_progcache_xid_t fork_3 = { .ul = { 3UL, 2UL } }; /* account redeployed here */
  fd_progcache_xid_t fork_4 = { .ul = { 4UL, 2UL } }; /* tip */

  test_env_txn_prepare( env, NULL, &fork_1 );
  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  test_env_txn_publish( env, &fork_1 );

  test_env_txn_prepare( env, &fork_1, &fork_2 );
  test_env_txn_prepare( env, &fork_2, &fork_3 );
  test_env_txn_prepare( env, &fork_3, &fork_4 );

  fd_prog_load_env_t load_env1 = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 1UL
  };
  fd_progcache_rec_t const * rec1 = test_pull( env->progcache, acc.entry, &fork_1, &key, &load_env1 );
  FD_TEST( rec1 );
  FD_TEST( rec1->slot==1UL );

  fd_prog_load_env_t load_env4 = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 4UL
  };
  fd_progcache_rec_t const * rec4 = test_pull( env->progcache, acc.entry, &fork_4, &key, &load_env4 );
  FD_TEST( rec4 );
  FD_TEST( rec4->slot==4UL );

  test_env_txn_cancel( env, &fork_4 );
  test_env_txn_cancel( env, &fork_3 );
  test_env_destroy( env );
}

/* test_reattach_after_cancel_all: Attach child after all siblings were
   cancelled — parent's child_head/tail were reset.  Verify they're
   re-established correctly. */

static void
test_reattach_after_cancel_all( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );

  fd_progcache_xid_t parent  = { .ul = { 1UL, 1UL } };
  fd_progcache_xid_t child_a = { .ul = { 2UL, 2UL } };
  fd_progcache_xid_t child_b = { .ul = { 3UL, 2UL } };
  fd_progcache_xid_t child_c = { .ul = { 4UL, 2UL } };
  test_env_txn_prepare( env, NULL,    &parent  );
  test_env_txn_prepare( env, &parent, &child_a );
  test_env_txn_prepare( env, &parent, &child_b );
  test_env_txn_prepare( env, &parent, &child_c );

  uint parent_idx = (uint)fd_prog_txnm_idx_query_const( env->progcache->join->txn.map, &parent, UINT_MAX, env->progcache->join->txn.pool );
  FD_TEST( parent_idx!=UINT_MAX );
  fd_progcache_txn_t * parent_txn = &env->progcache->join->txn.pool[ parent_idx ];
  FD_TEST( parent_txn->child_head_idx!=UINT_MAX );
  FD_TEST( parent_txn->child_tail_idx!=UINT_MAX );

  test_env_txn_cancel( env, &child_c );
  test_env_txn_cancel( env, &child_b );
  test_env_txn_cancel( env, &child_a );

  FD_TEST( parent_txn->child_head_idx==UINT_MAX );
  FD_TEST( parent_txn->child_tail_idx==UINT_MAX );

  fd_progcache_xid_t child_d = { .ul = { 5UL, 2UL } };
  test_env_txn_prepare( env, &parent, &child_d );

  FD_TEST( parent_txn->child_head_idx!=UINT_MAX );
  FD_TEST( parent_txn->child_tail_idx!=UINT_MAX );
  FD_TEST( parent_txn->child_head_idx==parent_txn->child_tail_idx );

  fd_progcache_txn_t * child_d_txn = &env->progcache->join->txn.pool[ parent_txn->child_head_idx ];
  FD_TEST( fd_progcache_txn_xid_eq( &child_d_txn->xid, &child_d ) );
  FD_TEST( child_d_txn->parent_idx==parent_idx );
  FD_TEST( child_d_txn->sibling_prev_idx==UINT_MAX );
  FD_TEST( child_d_txn->sibling_next_idx==UINT_MAX );

  FD_TEST( !fd_progcache_verify( env->progcache->join ) );

  test_env_txn_cancel( env, &child_d );
  test_env_txn_cancel( env, &parent );
  test_env_destroy( env );
}

/* test_reclaim_empty: Reclaim on empty queue returns 0 */

static void
test_reclaim_empty( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );

  FD_TEST( env->progcache->join->rec.reclaim_head==UINT_MAX );
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==0UL );

  test_env_destroy( env );
}

/* test_reclaim_no_readers: Single record with no active readers should
   be freed by reclaim_work. */

static void
test_reclaim_no_readers( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t xid = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &xid );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t * rec = test_pull( env->progcache, acc.entry, &xid, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->exists );

  long freed = fd_prog_delete_rec( env->progcache->join, rec );
  FD_TEST( freed>=0L );
  FD_TEST( env->progcache->join->rec.reclaim_head!=UINT_MAX );

  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( env->progcache->join->rec.reclaim_head==UINT_MAX );

  test_env_txn_cancel( env, &xid );
  test_env_destroy( env );
}

/* test_reclaim_active_reader: Record with an active reader should be
   deferred by reclaim_work until the reader releases the lock. */

static void
test_reclaim_active_reader( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t xid = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &xid );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  FD_TEST( test_pull( env->progcache, acc.entry, &xid, &key, &load_env ) );

  fd_progcache_rec_t * rec = fd_progcache_peek( env->progcache, &xid, &key, 0UL );
  FD_TEST( rec );

  fd_prog_delete_rec( env->progcache->join, rec );
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==0UL );
  FD_TEST( env->progcache->join->rec.reclaim_head!=UINT_MAX );

  fd_progcache_rec_close( env->progcache, rec );
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( env->progcache->join->rec.reclaim_head==UINT_MAX );

  test_env_txn_cancel( env, &xid );
  test_env_destroy( env );
}

/* test_reclaim_txn_unlink: Record linked to a txn should be unlinked
   from the txn's record list before being freed. */

static void
test_reclaim_txn_unlink( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t xid = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &xid );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 1UL
  };
  fd_progcache_rec_t * rec = test_pull( env->progcache, acc.entry, &xid, &key, &load_env );
  FD_TEST( rec );

  uint txn_idx = atomic_load_explicit( &rec->txn_idx, memory_order_relaxed );
  FD_TEST( txn_idx!=UINT_MAX );
  fd_progcache_txn_t * txn = &env->progcache->join->txn.pool[ txn_idx ];
  FD_TEST( txn->rec_head_idx!=UINT_MAX );

  fd_prog_delete_rec( env->progcache->join, rec );
  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( txn->rec_head_idx==UINT_MAX );
  FD_TEST( txn->rec_tail_idx==UINT_MAX );

  test_env_txn_cancel( env, &xid );
  test_env_destroy( env );
}

static void
test_join_null_scratch( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 32UL ), 1UL );
  FD_TEST( fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, 32UL ) );
  fd_progcache_t cache[1];
  FD_TEST( !fd_progcache_join( cache, mem, NULL, 4096UL ) );
  fd_wksp_free_laddr( fd_progcache_shmem_delete( mem ) );
}

static void
test_join_misaligned_scratch( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 32UL ), 1UL );
  FD_TEST( fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, 32UL ) );
  uchar scratch_buf[ FD_PROGCACHE_SCRATCH_ALIGN ] __attribute__((aligned(FD_PROGCACHE_SCRATCH_ALIGN)));
  fd_progcache_t cache[1];
  FD_TEST( !fd_progcache_join( cache, mem, scratch_buf+1, sizeof(scratch_buf)-1 ) );
  fd_wksp_free_laddr( fd_progcache_shmem_delete( mem ) );
}

static void
test_shmem_new_zero_txn_max( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 32UL ), 1UL );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, 0UL, 32UL ) );
  fd_wksp_free_laddr( mem );
}

static void
test_shmem_new_zero_rec_max( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 32UL ), 1UL );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, 0UL ) );
  fd_wksp_free_laddr( mem );
}

static void
test_shmem_new_oversized_txn_max( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 32UL ), 1UL );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, (ulong)UINT_MAX+1UL, 32UL ) );
  fd_wksp_free_laddr( mem );
}

static void
test_shmem_new_oversized_rec_max( fd_wksp_t * wksp ) {
  fd_progcache_shmem_t * mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( 16UL, 32UL ), 1UL );
  FD_TEST( !fd_progcache_shmem_new( mem, 1UL, 1UL, 16UL, (ulong)UINT_MAX+1UL ) );
  fd_wksp_free_laddr( mem );
}

static void
test_shmem_delete_fast( fd_wksp_t * wksp ) {
  ulong txn_max           = 16UL;
  ulong progcache_rec_max = 32UL;
  ulong wksp_tag          =  2UL;

  fd_progcache_shmem_t * progcache_mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, progcache_rec_max ), wksp_tag );
  FD_TEST( fd_progcache_shmem_new( progcache_mem, wksp_tag, 1UL, txn_max, progcache_rec_max ) );

  uchar scratch[ 65536 ] __attribute__((aligned(FD_PROGCACHE_SCRATCH_ALIGN)));
  fd_progcache_t cache[1];
  FD_TEST( fd_progcache_join( cache, progcache_mem, scratch, sizeof(scratch) ) );

  fd_progcache_xid_t root; fd_progcache_txn_xid_set_root( &root );
  fd_progcache_xid_t fork = { .ul = { 1UL, 1UL } };
  fd_progcache_attach_child( cache->join, &root, &fork );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  fd_features_t features[1]; memset( features, 0, sizeof(fd_features_t) );
  fd_prog_load_env_t load_env = {
    .features    = features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t * rec = test_pull( cache, acc.entry, &fork, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->data_gaddr );

  fd_progcache_shmem_t * shmem_out = NULL;
  FD_TEST( fd_progcache_leave( cache, &shmem_out ) );
  FD_TEST( shmem_out==(fd_progcache_shmem_t *)progcache_mem );

  FD_TEST( fd_progcache_shmem_delete_fast( shmem_out ) );
}

/* test_reclaim_mixed: Multiple records enqueued for reclaim with mixed
   readability.  Only records without active readers should be freed. */

static void
test_reclaim_mixed( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t xid = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &xid );

  fd_pubkey_t key1 = test_key( 1UL );
  fd_pubkey_t key2 = test_key( 2UL );
  test_account_t acc1, acc2;
  test_account_init( &acc1, &key1, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  test_account_init( &acc2, &key2, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  FD_TEST( test_pull( env->progcache, acc1.entry, &xid, &key1, &load_env ) );
  FD_TEST( test_pull( env->progcache, acc2.entry, &xid, &key2, &load_env ) );

  fd_progcache_rec_t * rec1 = fd_progcache_peek( env->progcache, &xid, &key1, 0UL );
  FD_TEST( rec1 );
  fd_progcache_rec_t * rec2 = fd_progcache_peek( env->progcache, &xid, &key2, 0UL );
  FD_TEST( rec2 );
  fd_progcache_rec_close( env->progcache, rec2 );

  fd_prog_delete_rec( env->progcache->join, rec1 );
  fd_prog_delete_rec( env->progcache->join, rec2 );

  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( env->progcache->join->rec.reclaim_head!=UINT_MAX );

  fd_progcache_rec_close( env->progcache, rec1 );

  FD_TEST( fd_prog_reclaim_work( env->progcache->join )==1UL );
  FD_TEST( env->progcache->join->rec.reclaim_head==UINT_MAX );

  test_env_txn_cancel( env, &xid );
  test_env_destroy( env );
}

static void
test_loader_v3_ok( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  ulong data_sz = PROGRAMDATA_METADATA_SIZE + valid_program_data_sz;
  uchar data[ PROGRAMDATA_METADATA_SIZE + 655536 ];
  FD_TEST( data_sz<=sizeof(data) );

  fd_bpf_state_t state = {
    .discriminant = FD_BPF_STATE_PROGRAM_DATA,
    .inner = {
      .program_data = {
        .slot = 42UL,
        .has_upgrade_authority_address = 0,
        .upgrade_authority_address = {{0}}
      }
    }
  };
  ulong out_sz = 0UL;
  FD_TEST( !fd_bpf_state_encode( &state, data, PROGRAMDATA_METADATA_SIZE, &out_sz ) );
  fd_memcpy( data+PROGRAMDATA_METADATA_SIZE, valid_program_data, valid_program_data_sz );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_upgradeable_program_id,
                     1, data, data_sz );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, &fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->data_gaddr );

  FD_TEST( test_peek( env->progcache, &fork_a, &key, 42UL )==rec );
  FD_TEST( !test_peek( env->progcache, &fork_a, &key, 0UL ) );

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

static void
test_loader_v3_wrong_account_type( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

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
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, &fork_a, &key, &load_env );
  FD_TEST( !rec );

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

static void
test_loader_v3_undersize( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  uchar data[ PROGRAMDATA_METADATA_SIZE-1 ];
  memset( data, 0, sizeof(data) );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_upgradeable_program_id,
                     1, data, sizeof(data) );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, &fork_a, &key, &load_env );
  FD_TEST( !rec );

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

static void
test_loader_v3_corrupt( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  uchar data[ PROGRAMDATA_METADATA_SIZE+1 ];
  memset( data, 0x41, sizeof(data) );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_upgradeable_program_id,
                     1, data, sizeof(data) );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = test_pull( env->progcache, acc.entry, &fork_a, &key, &load_env );
  FD_TEST( !rec );

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

static void
test_loader_v3_epoch_boundary( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  ulong data_sz = PROGRAMDATA_METADATA_SIZE + valid_program_data_sz;
  uchar data[ PROGRAMDATA_METADATA_SIZE + 1048576 ];
  FD_TEST( data_sz<=sizeof(data) );

  fd_bpf_state_t state = {
    .discriminant = FD_BPF_STATE_PROGRAM_DATA,
    .inner = {
      .program_data = {
        .slot = 42UL,
        .has_upgrade_authority_address = 0,
        .upgrade_authority_address = {{0}}
      }
    }
  };
  ulong out_sz = 0UL;
  FD_TEST( !fd_bpf_state_encode( &state, data, PROGRAMDATA_METADATA_SIZE, &out_sz ) );
  fd_memcpy( data+PROGRAMDATA_METADATA_SIZE, valid_program_data, valid_program_data_sz );

  fd_pubkey_t key = test_key( 1UL );
  test_account_t acc;
  test_account_init( &acc, &key, &fd_solana_bpf_loader_upgradeable_program_id,
                     1, data, data_sz );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec1 = test_pull( env->progcache, acc.entry, &fork_a, &key, &load_env );
  FD_TEST( rec1 );
  FD_TEST( rec1->data_gaddr );
  FD_TEST( rec1->slot==42UL );

  fd_progcache_xid_t fork_b = { .ul = { 100UL, 2UL } };
  test_env_txn_prepare( env, &fork_a, &fork_b );

  load_env.epoch       = 1UL;
  load_env.epoch_slot0 = 100UL;
  fd_progcache_rec_t const * rec2 = test_pull( env->progcache, acc.entry, &fork_b, &key, &load_env );
  FD_TEST( rec2 );
  FD_TEST( rec2->data_gaddr );
  FD_TEST( rec2->slot==100UL );
  FD_TEST( rec1!=rec2 );

  FD_TEST( test_peek( env->progcache, &fork_a, &key,  42UL )==rec1 );
  FD_TEST( test_peek( env->progcache, &fork_b, &key, 100UL )==rec2 );
  FD_TEST( test_peek( env->progcache, &fork_b, &key, 42UL )==rec1 );

  test_env_txn_cancel( env, &fork_b );
  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_clock_evict_all_visited: First pass clears visited bits,
   second pass evicts. */

static void
test_clock_evict_all_visited( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t xid = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &xid );

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
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };

  fd_progcache_rec_t * rec1 = test_pull( env->progcache, acc1.entry, &xid, &key1, &load_env );
  fd_progcache_rec_t * rec2 = test_pull( env->progcache, acc2.entry, &xid, &key2, &load_env );
  fd_progcache_rec_t * rec3 = test_pull( env->progcache, acc3.entry, &xid, &key3, &load_env );
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
  FD_TEST( !test_peek( env->progcache, &xid, &key1, 0UL ) );
  FD_TEST( !test_peek( env->progcache, &xid, &key2, 0UL ) );
  FD_TEST( !test_peek( env->progcache, &xid, &key3, 0UL ) );

  test_env_txn_cancel( env, &xid );
  test_env_destroy( env );
}

/* test_clock_evict_wraps_around: Head wraps from rec_max back to 0. */

static void
test_clock_evict_wraps_around( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t xid = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &xid );

  fd_pubkey_t key1 = test_key( 1UL );
  test_account_t acc1;
  test_account_init( &acc1, &key1, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t * rec1 = test_pull( env->progcache, acc1.entry, &xid, &key1, &load_env );
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
  FD_TEST( !test_peek( env->progcache, &xid, &key1, 0UL ) );

  test_env_txn_cancel( env, &xid );
  test_env_destroy( env );
}

/* test_clock_evict_empty_cache: No-op eviction on empty cache. */

static void
test_clock_evict_empty_cache( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );

  ulong evict_cnt_before = env->progcache->metrics->evict_cnt;
  fd_prog_clock_evict( env->progcache, 1UL, 0UL );

  FD_TEST( env->progcache->metrics->evict_cnt == evict_cnt_before );
  FD_TEST( !fd_progcache_verify( env->progcache->join ) );

  test_env_destroy( env );
}

/* test_clock_evict_delete_fails: fd_prog_delete_rec returns -1 for a
   stale exists bit.  Eviction should skip it and keep going. */

static void
test_clock_evict_delete_fails( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t xid = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &xid );

  fd_pubkey_t key1 = test_key( 1UL );
  fd_pubkey_t key2 = test_key( 2UL );
  test_account_t acc1, acc2;
  test_account_init( &acc1, &key1, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );
  test_account_init( &acc2, &key2, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t * rec1 = test_pull( env->progcache, acc1.entry, &xid, &key1, &load_env );
  fd_progcache_rec_t * rec2 = test_pull( env->progcache, acc2.entry, &xid, &key2, &load_env );
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
  FD_TEST( !test_peek( env->progcache, &xid, &key2, 0UL ) );

  test_env_txn_cancel( env, &xid );
  test_env_destroy( env );
}

/* test_clock_evict_heap_only: rec_min=0, heap_min>0 evicts by heap. */

static void
test_clock_evict_heap_only( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_progcache_xid_t xid = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &xid );

  fd_pubkey_t key1 = test_key( 1UL );
  test_account_t acc1;
  test_account_init( &acc1, &key1, &fd_solana_bpf_loader_program_id,
                     1, valid_program_data, valid_program_data_sz );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t * rec1 = test_pull( env->progcache, acc1.entry, &xid, &key1, &load_env );
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
  FD_TEST( !test_peek( env->progcache, &xid, &key1, 0UL ) );

  test_env_txn_cancel( env, &xid );
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
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

# define TEST( name ) { #name, name }
  struct test_case cases[] = {
    TEST( test_account_does_not_exist ),
    TEST( test_invalid_owner ),
    TEST( test_invalid_program ),
    TEST( test_valid_program ),
    TEST( test_epoch_boundary ),
    TEST( test_publish_gc ),
    TEST( test_publish_trivial ),
    TEST( test_root_nonroot_prio ),
    TEST( test_reattach_after_cancel_all ),
    TEST( test_reclaim_empty ),
    TEST( test_reclaim_no_readers ),
    TEST( test_reclaim_active_reader ),
    TEST( test_reclaim_txn_unlink ),
    TEST( test_reclaim_mixed ),
    TEST( test_join_null_scratch ),
    TEST( test_join_misaligned_scratch ),
    TEST( test_shmem_new_zero_txn_max ),
    TEST( test_shmem_new_zero_rec_max ),
    TEST( test_shmem_new_oversized_txn_max ),
    TEST( test_shmem_new_oversized_rec_max ),
    TEST( test_shmem_delete_fast ),
    TEST( test_loader_v3_ok ),
    TEST( test_loader_v3_wrong_account_type ),
    TEST( test_loader_v3_undersize ),
    TEST( test_loader_v3_corrupt ),
    TEST( test_loader_v3_epoch_boundary ),
    TEST( test_clock_evict_all_visited ),
    TEST( test_clock_evict_wraps_around ),
    TEST( test_clock_evict_empty_cache ),
    TEST( test_clock_evict_delete_fails ),
    TEST( test_clock_evict_heap_only ),
    {0}
  };
# undef TEST
  for( struct test_case * tc = cases; tc->name; tc++ ) {
    if( match_test_name( tc->name, argc, argv ) ) {
      FD_LOG_NOTICE(( "Running %s", tc->name ));
      tc->fn( wksp );
    }
  }

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
