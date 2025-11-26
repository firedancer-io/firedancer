
#include "fd_progcache_admin.h"
#include "fd_progcache_user.h"
#include "../accdb/fd_accdb_admin.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "../runtime/fd_txn_account.h"
#include "../features/fd_features.h"

struct test_env {
  fd_wksp_t *          wksp;

  fd_progcache_admin_t progcache_admin[1];
  fd_progcache_t       progcache[1];
  fd_accdb_admin_t     accdb_admin[1];
  fd_accdb_user_t      accdb[1];
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
  FD_TEST( fd_progcache_join      ( env->progcache, progcache_mem, env->scratch, sizeof(env->scratch) ) );
  FD_TEST( fd_accdb_admin_join    ( env->accdb_admin, accdb_mem ) );
  FD_TEST( fd_accdb_user_v1_init  ( env->accdb,       accdb_mem ) );

  return env;
}

/* test_env_destroy frees all test env objects. */

static void
test_env_destroy( test_env_t * env ) {
  fd_progcache_verify( env->progcache_admin );

  void * progcache_mem = NULL;
  FD_TEST( fd_progcache_admin_leave( env->progcache_admin, &progcache_mem ) );
  FD_TEST( fd_progcache_leave      ( env->progcache,       &progcache_mem ) );
  fd_wksp_free_laddr( fd_funk_delete( progcache_mem ) );

  void * accdb_mem = NULL;
  FD_TEST( fd_accdb_admin_leave( env->accdb_admin, &accdb_mem ) );
  fd_accdb_user_fini( env->accdb );
  fd_wksp_free_laddr( fd_funk_delete( accdb_mem ) );

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
  fd_accdb_attach_child        ( env->accdb_admin,     parent, xid );
  fd_progcache_txn_attach_child( env->progcache_admin, parent, xid );
}

/* test_env_txn_cancel destroys a subtree of in-prep funk transactions
   with root 'xid', in both accdb and progcache. */

static void
test_env_txn_cancel( test_env_t *              env,
                     fd_funk_txn_xid_t const * xid ) {
  fd_accdb_cancel        ( env->accdb_admin,     xid );
  fd_progcache_txn_cancel( env->progcache_admin, xid );
}

/* test_env_txn_publish publishes (i.e. roots) a subtree of in-prep funk
   transactions with root 'xid', in both accdb and progcache. */

FD_FN_UNUSED static void
test_env_txn_publish( test_env_t *              env,
                      fd_funk_txn_xid_t const * xid ) {
  fd_accdb_advance_root( env->accdb_admin, xid );
  fd_progcache_txn_advance_root( env->progcache_admin, xid );
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
  int ok = !!fd_txn_account_init_from_funk_mutable( /* acc         */ acc,
                                                   /* pubkey      */ &pubkey,
                                                   /* funk        */ env->accdb,
                                                   /* xid         */ xid,
                                                   /* do_create   */ 1,
                                                   /* min_data_sz */ data_len,
                                                   /* prepare     */ &prepare );
  FD_TEST( ok );

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
