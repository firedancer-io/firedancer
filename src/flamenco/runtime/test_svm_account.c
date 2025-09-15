/* This test exercises SVM account macros.  In particular, ensures that
   bank fields (LtHash, capitalization) are updated correctly.

   In this file, functions prefixed with mock_ concern the test setup,
   functions prefixed with test_ are the actual test code. */

/* Test non-existent -> non-existent */
/* Test non-existent -> existent */
/* Test existent -> existent */
/* Test existent -> non-existent */

#include "fd_bank.h"
#include "fd_svm_account.h"

/* mock_accdb_session holds a minimal environment against which the SVM
   account API is tested. */

#define WKSP_TAG_MISC 1UL
#define WKSP_TAG_FUNK 2UL

struct mock_accdb_session {
  /* Account database handle */
  fd_wksp_t *          wksp;
  void *               funk_mem;
  fd_funk_t            funk[1];
  fd_funk_txn_t *      funk_txn;
  fd_funk_txn_xid_t    txn_xid;
  fd_accdb_client_t *  accdb;

  /* Minimal slot context for accdb-related bank fields */
  fd_banks_t *       banks;
  fd_bank_t *        bank;
  fd_exec_slot_ctx_t slot_ctx[1];
};
typedef struct mock_accdb_session mock_accdb_session_t;

/* mock_accdb_{create,destroy} {acquire/initialize,delete/free} objects
   that make up a mock_accdb_session from a wksp. */

static void
mock_accdb_create( mock_accdb_session_t * session,
                   fd_wksp_t *            wksp ) {
  memset( session, 0, sizeof(mock_accdb_session_t) );
  session->wksp = wksp;

  /* Allocate funk shm cache */
  ulong const txn_max   =  4UL;
  ulong const rec_max   = 32UL;
  ulong const funk_seed =  1UL;
  void * funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), WKSP_TAG_FUNK );
  FD_TEST( funk_mem );
  FD_TEST( fd_funk_new( funk_mem, WKSP_TAG_FUNK, funk_seed, txn_max, rec_max ) );
  FD_TEST( fd_funk_join( session->funk, funk_mem ) );
  session->funk_txn = NULL; /* root txn */

  /* Allocate account database client */
  ulong const acct_para_max =    1UL;
  ulong const acct_data_max = 1024UL;
  void * accdb_mem = fd_wksp_alloc_laddr( wksp, fd_accdb_client_align(), fd_accdb_client_footprint( acct_para_max, acct_data_max ), WKSP_TAG_MISC );
  FD_TEST( accdb_mem );
  fd_accdb_client_t * accdb = fd_accdb_client_new( accdb_mem, funk_mem, acct_para_max, acct_data_max );
  FD_TEST( accdb );

  /* Allocate bank (FIXME is the bank manager object necessary here?) */
  ulong  max_total_banks = 1UL;
  ulong  max_fork_width  = 1UL;
  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( max_total_banks, max_fork_width ), WKSP_TAG_MISC );
  FD_TEST( banks_mem );
  fd_banks_t * banks = fd_banks_new( banks_mem, max_total_banks, max_fork_width );
  FD_TEST( banks );

  /* Create empty bank */
  fd_hash_t genesis_block_id = {.uc={1,2,3}};
  fd_bank_t * bank = fd_banks_init_bank( banks, &genesis_block_id );

  /* Create slot context object */
  fd_exec_slot_ctx_t * slot_ctx = session->slot_ctx;
  memset( slot_ctx, 0, sizeof(fd_exec_slot_ctx_t) );
  slot_ctx->banks    = banks;
  slot_ctx->bank     = bank;
  slot_ctx->funk     = session->funk;
  slot_ctx->funk_txn = session->funk_txn;

  session->funk_mem = funk_mem;
  session->accdb    = accdb;
  session->banks    = banks;
  session->bank     = bank;

  fd_lthash_value_t lthash = fd_bank_lthash_get( bank );
  FD_TEST( fd_lthash_is_zero( &lthash ) );
}

static void
mock_accdb_destroy( mock_accdb_session_t * session ) {
  memset( session->slot_ctx, 0, sizeof(fd_exec_slot_ctx_t) );

  fd_wksp_free_laddr( fd_accdb_client_delete( session->accdb ) );
  session->accdb = NULL;

  fd_funk_leave( session->funk, NULL );
  memset( session->funk, 0, sizeof(fd_funk_t) );

  fd_funk_delete_fast( session->funk_mem );
  session->funk_mem = NULL;

  session->bank = NULL;
  fd_wksp_free_laddr( fd_banks_delete( session->banks ) );

  session->wksp = NULL;
}

/* mock_account_insert manually inserts an account record into funk DB
   cache.  Assumes that the target account does not already exists.
   Returns the newly created funk record pointer, which is initialized
   to hold an empty account. */

static fd_funk_rec_t *
mock_account_insert( mock_accdb_session_t * session,
                     void const *           address,
                     ulong                  data_sz ) {
  fd_funk_t * funk = session->funk;
  fd_funk_rec_key_t rec_key = fd_funk_acc_key( address );
  fd_funk_rec_prepare_t prepare[1];
  fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, session->funk_txn, &rec_key, prepare, NULL );
  FD_TEST( rec );

  fd_account_rec_t * acc = fd_funk_val_truncate( rec, fd_funk_alloc( funk ), session->wksp, 8UL, data_sz, NULL );
  fd_account_meta_init( &acc->meta );
  acc->meta.dlen = (uint)data_sz;
  memset( acc->data, 0, data_sz );

  fd_funk_rec_publish( session->funk, prepare );
  return rec;
}

/* mock_account_remove removes a record from funk DB cache. */

static void
mock_account_remove( mock_accdb_session_t * session,
                     void const *           address ) {
  fd_funk_rec_key_t rec_key = fd_funk_acc_key( address );
  fd_funk_rec_remove( session->funk, session->funk_txn, &rec_key, NULL );
}

static void
test_runtime_account_read( void ) {
  (void)mock_account_insert;
  (void)mock_account_remove;
}

static void
test_runtime_account_update_noop( fd_wksp_t * wksp ) {
  mock_accdb_session_t session[1];
  mock_accdb_create( session, wksp );

  fd_pubkey_t const key1 = {.uc={1,2,3}};
  FD_RUNTIME_ACCOUNT_READ_BEGIN( session->slot_ctx, &session->txn_xid, key1.uc, rec ) {
    FD_TEST( fd_accdb_ref_lamports( rec )==0UL );
  }
  FD_RUNTIME_ACCOUNT_READ_END;

  /* Manually insert a record */


  /* Account record, capitalization, and LtHash should not change if
     user does not do any writes */

  mock_accdb_destroy( session );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_sz  = FD_SHMEM_NORMAL_PAGE_SZ;
  ulong       page_cnt = 524288UL;
  ulong       cpu_idx  = fd_log_cpu_id();
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( page_sz, page_cnt, cpu_idx, "wksp", 0UL );
  FD_TEST( wksp );

  test_runtime_account_read();
  test_runtime_account_update_noop( wksp );

  fd_wksp_usage_t wksp_usage;
  FD_TEST( fd_wksp_usage( wksp, NULL, 0UL, &wksp_usage ) );
  FD_TEST( wksp_usage.free_cnt==wksp_usage.total_cnt );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
