/* test_progcache.c contains single-threaded correctness tests for
   progcache. */

#include "fd_progcache_admin.h"
#include "fd_progcache_user.h"
#include "../runtime/fd_bank.h"

/* Load in programdata for tests */
FD_IMPORT_BINARY( valid_program_data,        "src/ballet/sbpf/fixtures/hello_solana_program.so" );
FD_IMPORT_BINARY( bigger_valid_program_data, "src/ballet/sbpf/fixtures/clock_sysvar_program.so" );
FD_IMPORT_BINARY( invalid_program_data,      "src/ballet/sbpf/fixtures/malformed_bytecode.so"   );

struct test_env {
  fd_wksp_t *          wksp;

  fd_progcache_admin_t progcache_admin[1];
  fd_progcache_t       progcache[1];
  fd_funk_t            accdb[1];
  fd_features_t        features[1];

  uchar scratch[ FD_PROGCACHE_SCRATCH_FOOTPRINT ] __attribute__((aligned(FD_PROGCACHE_SCRATCH_ALIGN)));
};

typedef struct test_env test_env_t;

/* test_env_create allocates a new account database (funk) and loaded
   program cache (also funk) from a wksp.  Joins an admin and user
   client to the program cache, as well as a database client. */

static test_env_t *
test_env_create( fd_wksp_t * wksp ) {
  ulong txn_max           = 16UL;
  ulong accdb_rec_max     = 32UL;
  ulong progcache_rec_max = 32UL;
  ulong wksp_tag          =  1UL;

  void * accdb_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, accdb_rec_max ), wksp_tag );
  FD_TEST( fd_funk_new( accdb_mem, wksp_tag, 1UL, txn_max, accdb_rec_max ) );

  void * progcache_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, progcache_rec_max ), wksp_tag );
  FD_TEST( fd_funk_new( progcache_mem, wksp_tag, 1UL, txn_max, progcache_rec_max ) );

  test_env_t * env = fd_wksp_alloc_laddr( wksp, alignof(test_env_t), sizeof(test_env_t), wksp_tag );
  FD_TEST( env );
  memset( env, 0, sizeof(test_env_t) );

  env->wksp = wksp;
  FD_TEST( fd_progcache_admin_join( env->progcache_admin, progcache_mem ) );
  FD_TEST( fd_progcache_join( env->progcache, progcache_mem, env->scratch, sizeof(env->scratch) ) );
  FD_TEST( fd_funk_join( env->accdb, accdb_mem ) );

  return env;
}

/* test_env_destroy frees all test env objects. */

static void
test_env_destroy( test_env_t * env ) {
  fd_progcache_verify_stat_t stat[1];
  fd_progcache_verify( env->progcache_admin, stat );

  void * accdb_mem = NULL;
  FD_TEST( fd_progcache_admin_leave( env->progcache_admin, &accdb_mem ) );
  FD_TEST( fd_progcache_leave      ( env->progcache,       &accdb_mem ) );
  fd_wksp_free_laddr( fd_funk_delete( accdb_mem ) );

  void * progcache_mem = NULL;
  FD_TEST( fd_funk_leave( env->accdb, &progcache_mem ) );
  fd_wksp_free_laddr( fd_funk_delete( progcache_mem ) );

  fd_wksp_free_laddr( env );
}

/* test_env_txn_prepare creates a new in-prep funk transaction off
   parent with the given xid, in both accdb and progcache. */

static void
test_env_txn_prepare( test_env_t *              env,
                      fd_funk_txn_xid_t const * parent,
                      fd_funk_txn_xid_t const * xid ) {
  fd_funk_txn_xid_t root[1];
  if( !parent ) {
    fd_funk_txn_xid_set_root( root );
    parent = root;
  }
  fd_funk_txn_prepare( env->accdb, parent, xid );
  fd_progcache_txn_prepare( env->progcache_admin, parent, xid );
}

/* test_env_txn_cancel destroys a subtree of in-prep funk transactions
   with root 'xid', in both accdb and progcache. */

static void
test_env_txn_cancel( test_env_t *              env,
                     fd_funk_txn_xid_t const * xid ) {
  fd_funk_txn_cancel( env->accdb, xid );
  fd_progcache_txn_cancel( env->progcache_admin, xid );
}

/* test_env_txn_publish publishes (i.e. roots) a subtree of in-prep funk
   transactions with root 'xid', in both accdb and progcache. */

static void
test_env_txn_publish( test_env_t *              env,
                      fd_funk_txn_xid_t const * xid ) {
  fd_funk_txn_publish( env->accdb, xid );
  fd_progcache_txn_publish( env->progcache_admin, xid );
}

static fd_funk_rec_key_t
test_key( ulong x ) {
  fd_funk_rec_key_t key = {0};
  key.ul[0] = x;
  return key;
}

/* create_test_account creates an account in the account database. */

static void
create_test_account( test_env_t * env,
                     fd_funk_txn_xid_t const * xid,
                     void const * pubkey_,
                     void const * owner_,
                     void const * data,
                     ulong        data_len,
                     uchar        executable ) {
  fd_pubkey_t pubkey = FD_LOAD( fd_pubkey_t, pubkey_ );
  fd_pubkey_t owner  = FD_LOAD( fd_pubkey_t, owner_ ) ;

  fd_txn_account_t acc[1];
  fd_funk_rec_prepare_t prepare = {0};
  int err = fd_txn_account_init_from_funk_mutable( /* acc         */ acc,
                                                   /* pubkey      */ &pubkey,
                                                   /* funk        */ env->accdb,
                                                   /* xid         */ xid,
                                                   /* do_create   */ 1,
                                                   /* min_data_sz */ data_len,
                                                   /* prepare     */ &prepare );
  FD_TEST( !err );

  if( data ) {
    fd_txn_account_set_data( acc, data, data_len );
  }

  acc->starting_lamports = 1UL;
  acc->starting_dlen     = data_len;
  fd_txn_account_set_lamports( acc, 1UL );
  fd_txn_account_set_executable( acc, executable );
  fd_txn_account_set_owner( acc, &owner );

  fd_txn_account_mutable_fini( acc, env->accdb, &prepare );
}

/* query_rec_exact fetches a funk record at a precise xid:key pair. */

static fd_funk_rec_t const *
query_rec_exact( test_env_t *              env,
                 fd_funk_txn_xid_t const * xid,
                 fd_funk_rec_key_t const * key ) {
  fd_funk_xid_key_pair_t pair[1];
  fd_funk_txn_xid_copy( pair->xid, xid );
  fd_funk_rec_key_copy( pair->key, key );

  fd_funk_rec_map_query_t query[1];
  int query_err = fd_funk_rec_map_query_try( env->progcache->funk->rec_map, pair, NULL, query, 0 );
  if( query_err==FD_MAP_ERR_KEY ) return NULL;
  if( FD_UNLIKELY( query_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_rec_map_query_try failed: %i-%s", query_err, fd_map_strerror( query_err ) ));

  return fd_funk_rec_map_query_ele_const( query );
}

/* test_empty: Account database and progcache completely empty.
   Query at root should fail. */

static void
test_empty( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );

  fd_funk_txn_xid_t xid[1]; fd_funk_txn_xid_set_root( xid );
  fd_funk_rec_key_t key = test_key( 1UL );
  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .slot        = 1UL,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = fd_progcache_pull( env->progcache, env->accdb, xid, &key, &load_env );
  FD_TEST( !rec );

  test_env_destroy( env );
}

/* test_account_does_not_exist: Program account missing, but querying at
   a fork. */

static void
test_account_does_not_exist( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_funk_txn_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  (void)test_env_txn_publish;

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_invalid_owner: Account exists but is not owned by BPF loader */

static void
test_invalid_owner( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_funk_txn_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_funk_rec_key_t key = test_key( 1UL );
  create_test_account( env, &fork_a, &key,
                       &fd_solana_system_program_id, /* not a BPF laoder */
                       invalid_program_data,
                       invalid_program_data_sz,
                       1 );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .slot        = 1UL,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  FD_TEST( !fd_progcache_pull( env->progcache, env->accdb, &fork_a, &key, &load_env ) );

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_invalid_program: Program account exists but fails loading */

static void
test_invalid_program( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_funk_txn_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_funk_rec_key_t key = test_key( 1UL );
  create_test_account( env, &fork_a, &key,
                       &fd_solana_bpf_loader_program_id,
                       invalid_program_data,
                       invalid_program_data_sz,
                       1 );

  FD_TEST( !fd_progcache_peek( env->progcache, &fork_a, &key, 0UL ) );
  FD_TEST( env->progcache->fork_depth==2UL );
  FD_TEST( fd_funk_txn_xid_eq( &env->progcache->fork[ 0 ], &fork_a ) );
  FD_TEST( fd_funk_txn_xid_eq( &env->progcache->fork[ 1 ], fd_funk_root( env->progcache->funk ) ) );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .slot        = 1UL,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = fd_progcache_pull( env->progcache, env->accdb, &fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( !rec->executable );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_a, &key, load_env.epoch_slot0 )==rec );

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_valid_program: Load a valid program account */

static void
test_valid_program( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_funk_txn_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_funk_rec_key_t key = test_key( 1UL );
  create_test_account( env, &fork_a, &key,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  FD_TEST( !fd_progcache_peek( env->progcache, &fork_a, &key, 0UL ) );
  FD_TEST( env->progcache->fork_depth==2UL );
  FD_TEST( fd_funk_txn_xid_eq( &env->progcache->fork[ 0 ], &fork_a ) );
  FD_TEST( fd_funk_txn_xid_eq( &env->progcache->fork[ 1 ], fd_funk_root( env->progcache->funk ) ) );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .slot        = 1UL,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = fd_progcache_pull( env->progcache, env->accdb, &fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->executable );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_a, &key, 0UL )==rec );
  FD_TEST( env->progcache->fork_depth==2UL );

  fd_funk_txn_xid_t fork_b = { .ul = { 64UL, 2UL } };
  test_env_txn_prepare( env, &fork_a, &fork_b );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_b, &key, 0UL )==rec );
  FD_TEST( env->progcache->fork_depth==3UL );

  load_env.slot        = 64UL;
  load_env.epoch       =  0UL;
  load_env.epoch_slot0 =  0UL;
  fd_progcache_rec_t const * rec2 = fd_progcache_pull( env->progcache, env->accdb, &fork_b, &key, &load_env );
  FD_TEST( rec==rec2 );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_b, &key, 0UL )==rec );

  test_env_txn_cancel( env, &fork_a ); /* should also cancel fork_b */
  test_env_destroy( env );
}

/* test_epoch_boundary: Ensure that a valid program gets re-verified
   after an epoch boundary. */

static void
test_epoch_boundary( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_funk_txn_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_funk_rec_key_t key = test_key( 1UL );
  create_test_account( env, &fork_a, &key,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  FD_TEST( !fd_progcache_peek( env->progcache, &fork_a, &key, 0UL ) );
  FD_TEST( env->progcache->fork_depth==2UL );
  FD_TEST( fd_funk_txn_xid_eq( &env->progcache->fork[ 0 ], &fork_a ) );
  FD_TEST( fd_funk_txn_xid_eq( &env->progcache->fork[ 1 ], fd_funk_root( env->progcache->funk ) ) );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .slot        = 1UL,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = fd_progcache_pull( env->progcache, env->accdb, &fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->executable );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_a, &key, 0UL )==rec );

  fd_funk_txn_xid_t fork_b = { .ul = { 64UL, 2UL } };
  test_env_txn_prepare( env, &fork_a, &fork_b );
  load_env.slot        = 64UL;
  load_env.epoch       =  1UL;
  load_env.epoch_slot0 = 64UL;
  fd_progcache_rec_t const * rec2 = fd_progcache_pull( env->progcache, env->accdb, &fork_b, &key, &load_env );
  FD_TEST( rec2 );
  FD_TEST( rec!=rec2 );
  FD_TEST( rec2->executable );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_b, &key, load_env.epoch_slot0 )==rec2 );

  test_env_txn_cancel( env, &fork_b );
  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_invalidate: Ensure that an fd_progcache_invalidate call
   overrides a previously created cache entry. */

static void
test_invalidate( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_funk_txn_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_funk_rec_key_t key = test_key( 1UL );
  create_test_account( env, &fork_a, &key,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .slot        = 1UL,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = fd_progcache_pull( env->progcache, env->accdb, &fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->executable );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_a, &key, 0UL )==rec );

  fd_funk_txn_xid_t fork_b = { .ul = { 2UL, 1UL } };
  test_env_txn_prepare( env, &fork_a, &fork_b );
  fd_progcache_rec_t const * rec2 = fd_progcache_invalidate( env->progcache, &fork_b, &key, fork_b.ul[0] );
  FD_TEST( rec2!=rec );
  FD_TEST( !rec2->executable );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_b, &key, 0UL )==rec2 );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_a, &key, 0UL )==rec );

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_invalidate_nonexistent: fd_progcache_invalidate should create an
   entry even if there are no other cache entries for the same key.
   (To prevent a future fill predating the invalidation from having side
   effects for slots after the invalidation.) */

static void
test_invalidate_nonexistent( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_funk_txn_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_funk_rec_key_t key = test_key( 1UL );
  fd_progcache_rec_t const * rec = fd_progcache_invalidate( env->progcache, &fork_a, &key, fork_a.ul[0] );
  FD_TEST( rec );
  FD_TEST( !rec->executable );

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_invalidate_pull: fd_progcache_pull should recover from an
   earlier fd_progcache_invalidate call (in a future slot). */

static void
test_invalidate_pull( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_funk_txn_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_funk_rec_key_t key = test_key( 1UL );
  create_test_account( env, &fork_a, &key,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* Create initial cache entry */
  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .slot        = 1UL,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = fd_progcache_pull( env->progcache, env->accdb, &fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->executable );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_a, &key, 0UL )==rec );

  /* Create cache invalidation entry */
  fd_funk_txn_xid_t fork_b = { .ul = { 2UL, 1UL } };
  test_env_txn_prepare( env, &fork_a, &fork_b );
  fd_progcache_rec_t const * rec2 = fd_progcache_invalidate( env->progcache, &fork_b, &key, fork_b.ul[0] );
  FD_TEST( rec2!=rec );
  FD_TEST( !rec2->executable );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_b, &key, 0UL )==rec2 );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_a, &key, 0UL )==rec );

  /* Loading the program should create another cache entry */
  fd_funk_txn_xid_t fork_c = { .ul = { 3UL, 2UL } };
  test_env_txn_prepare( env, &fork_b, &fork_c );
  load_env.slot = 3UL;
  fd_progcache_rec_t const * rec3 = fd_progcache_pull( env->progcache, env->accdb, &fork_c, &key, &load_env );
  FD_TEST( rec3 );
  FD_TEST( rec3!=rec2 && rec3!=rec );
  FD_TEST( rec3->executable );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_c, &key, 0UL )==rec3 );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_b, &key, 0UL )==rec2 );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_a, &key, 0UL )==rec  );

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_invalidate_dup: fd_progcache_invalidate should create a cache
   invalidation entry, even if last update was an invalidation.  Because
   a future cache access could create a cache entry between the two
   retro-actively. */

static void
test_invalidate_dup( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_funk_txn_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_funk_rec_key_t key = test_key( 1UL );
  create_test_account( env, &fork_a, &key,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* Create initial cache entry */
  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .slot        = 1UL,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = fd_progcache_pull( env->progcache, env->accdb, &fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->executable );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_a, &key, 0UL )==rec );

  /* Create cache invalidation entry */
  fd_funk_txn_xid_t fork_b = { .ul = { 2UL, 1UL } };
  test_env_txn_prepare( env, &fork_a, &fork_b );
  fd_progcache_rec_t const * rec2 = fd_progcache_invalidate( env->progcache, &fork_b, &key, fork_b.ul[0] );
  FD_TEST( rec2!=rec );
  FD_TEST( !rec2->executable );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_b, &key, 0UL )==rec2 );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_a, &key, 0UL )==rec );

  /* Create cache invalidation entry */
  fd_funk_txn_xid_t fork_c = { .ul = { 3UL, 2UL } };
  test_env_txn_prepare( env, &fork_b, &fork_c );
  fd_progcache_rec_t const * rec3 = fd_progcache_invalidate( env->progcache, &fork_c, &key, fork_c.ul[0] );
  FD_TEST( rec3 && rec2!=rec3 );
  FD_TEST( !rec3->executable );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_c, &key, 0UL )==rec3 );

  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_invalidate_epoch_boundary: fd_progcache_invalidate after a cache
   entry, even if the program is already invalid (due to an epoch
   boundary).  Because a future cache access could create a cache entry
   between the two retro-actively.  */

static void
test_invalidate_epoch_boundary( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_funk_txn_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_funk_rec_key_t key = test_key( 1UL );
  create_test_account( env, &fork_a, &key,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  FD_TEST( !fd_progcache_peek( env->progcache, &fork_a, &key, 0UL ) );
  FD_TEST( env->progcache->fork_depth==2UL );
  FD_TEST( fd_funk_txn_xid_eq( &env->progcache->fork[ 0 ], &fork_a ) );
  FD_TEST( fd_funk_txn_xid_eq( &env->progcache->fork[ 1 ], fd_funk_root( env->progcache->funk ) ) );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .slot        = 1UL,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec = fd_progcache_pull( env->progcache, env->accdb, &fork_a, &key, &load_env );
  FD_TEST( rec );
  FD_TEST( rec->executable );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_a, &key, 0UL )==rec );

  fd_funk_txn_xid_t fork_b = { .ul = { 64UL, 2UL } };
  test_env_txn_prepare( env, &fork_a, &fork_b );
  load_env.slot        = 64UL;
  load_env.epoch       =  1UL;
  load_env.epoch_slot0 = 64UL;
  fd_progcache_rec_t const * rec2 = fd_progcache_invalidate( env->progcache, &fork_b, &key, fork_b.ul[0] );
  FD_TEST( rec2 && rec!=rec2 );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_b, &key, load_env.epoch_slot0 )==rec2 );

  test_env_txn_cancel( env, &fork_b );
  test_env_txn_cancel( env, &fork_a );
  test_env_destroy( env );
}

/* test_publish_gc: fd_progcache_txn_publish should garbage-collect
   stale entries. */

static void
test_publish_gc( fd_wksp_t * wksp ) {
  test_env_t * env = test_env_create( wksp );
  fd_funk_txn_xid_t fork_a = { .ul = { 1UL, 1UL } };
  test_env_txn_prepare( env, NULL, &fork_a );

  fd_funk_rec_key_t key = test_key( 1UL );
  create_test_account( env, &fork_a, &key,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  fd_prog_load_env_t load_env = {
    .features    = env->features,
    .slot        = 1UL,
    .epoch       = 0UL,
    .epoch_slot0 = 0UL
  };
  fd_progcache_rec_t const * rec_a = fd_progcache_pull( env->progcache, env->accdb, &fork_a, &key, &load_env );
  FD_TEST( rec_a );
  FD_TEST( rec_a->executable );

  fd_funk_txn_xid_t fork_b = { .ul = { 2UL, 1UL } };
  test_env_txn_prepare( env, &fork_a, &fork_b );
  fd_progcache_rec_t const * rec_b = fd_progcache_invalidate( env->progcache, &fork_b, &key, fork_b.ul[0] );
  FD_TEST( rec_b );

  fd_funk_txn_xid_t fork_c = { .ul = { 3UL, 2UL } };
  test_env_txn_prepare( env, &fork_b, &fork_c );
  load_env.slot = 3UL;
  fd_progcache_rec_t const * rec_c = fd_progcache_pull( env->progcache, env->accdb, &fork_c, &key, &load_env );
  FD_TEST( rec_c );
  FD_TEST( rec_c->executable );

  FD_TEST( fd_progcache_peek( env->progcache, &fork_a, &key, 0UL )==rec_a );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_b, &key, 0UL )==rec_b );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_c, &key, 0UL )==rec_c );

  fd_funk_rec_t const * frec_a = query_rec_exact( env, &fork_a, &key );
  fd_funk_rec_t const * frec_b = query_rec_exact( env, &fork_b, &key );
  fd_funk_rec_t const * frec_c = query_rec_exact( env, &fork_c, &key );
  FD_TEST( frec_a ); FD_TEST( frec_b ); FD_TEST( frec_c );
  FD_TEST( frec_a!=frec_b && frec_a!=frec_c && frec_b!=frec_c );

  fd_funk_txn_xid_t root; fd_funk_txn_xid_set_root( &root );
  test_env_txn_publish( env, &fork_a );
  FD_TEST( query_rec_exact( env, &fork_a, &key )==NULL   );
  FD_TEST( query_rec_exact( env, &root,   &key )==frec_a );
  FD_TEST( fd_progcache_peek( env->progcache, &fork_a, &key, 0UL )==rec_a );

  test_env_txn_publish( env, &fork_b );
  FD_TEST( query_rec_exact( env, &fork_a, &key )==NULL   );
  FD_TEST( query_rec_exact( env, &fork_b, &key )==NULL   );
  FD_TEST( query_rec_exact( env, &root,   &key )==frec_b );

  test_env_txn_publish( env, &fork_c );
  FD_TEST( query_rec_exact( env, &fork_a, &key )==NULL   );
  FD_TEST( query_rec_exact( env, &fork_b, &key )==NULL   );
  FD_TEST( query_rec_exact( env, &fork_c, &key )==NULL   );
  FD_TEST( query_rec_exact( env, &root,   &key )==frec_c );

  test_env_destroy( env );
}

static void
test_publish_trivial( fd_wksp_t * wksp ) {
  /* Exercise a sequence of prepare/publish operations seen when running
     'firedancer-dev backtest' */

  test_env_t * env = test_env_create( wksp );

  fd_funk_txn_xid_t root; fd_funk_txn_xid_set_root( &root );
  fd_funk_txn_xid_t fork_368528500 = { .ul = { 368528500UL, 368528500UL } };
  fd_progcache_txn_prepare( env->progcache_admin, &root, &fork_368528500 );
  fd_progcache_txn_publish( env->progcache_admin,        &fork_368528500 );

  /* FIXME more operations here ... */
}


struct test_case {
  char const * name;
  void      (* fn)( fd_wksp_t * wksp );
};

static int
match_test_name( char const * test_name,
                 int          argc,
                 char **      argv ) {
  if( argc<=1 ) return 1;
  for( int i=1; i<argc; i++ ) {
    if( strstr( test_name, argv[ i ] ) ) return 1;
  }
  return 0;
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
    TEST( test_empty ),
    TEST( test_account_does_not_exist ),
    TEST( test_invalid_owner ),
    TEST( test_invalid_program ),
    TEST( test_valid_program ),
    TEST( test_epoch_boundary ),
    TEST( test_invalidate ),
    TEST( test_invalidate_nonexistent ),
    TEST( test_invalidate_pull ),
    TEST( test_invalidate_dup ),
    TEST( test_invalidate_epoch_boundary ),
    TEST( test_publish_gc ),
    TEST( test_publish_trivial ),
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
