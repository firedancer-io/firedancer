#include "fd_progcache.h"
#include "../runtime/fd_bank.h"

/* FIXME verify that progcache_rec >= align of all sub objects */

#if FD_HAS_HOSTED

#define TEST_WKSP_TAG 1234UL

/* Load in programdata for tests */
FD_IMPORT_BINARY( valid_program_data, "src/ballet/sbpf/fixtures/hello_solana_program.so" );
FD_IMPORT_BINARY( bigger_valid_program_data, "src/ballet/sbpf/fixtures/clock_sysvar_program.so" );
FD_IMPORT_BINARY( invalid_program_data, "src/ballet/sbpf/fixtures/malformed_bytecode.so" );

/* Test program pubkeys */
static fd_pubkey_t const test_program_pubkey = {
  .uc = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
          0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 }
};

/* Test setup and teardown helpers */
static fd_wksp_t *         test_wksp  = NULL;
static fd_progcache_t *    test_cache = NULL;
static fd_funk_t *         test_accdb = NULL;
static fd_bank_t *         test_bank  = NULL;
static fd_banks_t *        test_banks = NULL;
static fd_funk_txn_xid_t   test_xid   = {0};

static void
test_teardown( void ) {
  if( test_accdb ) {
    fd_funk_leave( test_accdb, NULL );
    test_accdb = NULL;
  }

  if( test_wksp ) {
    fd_wksp_delete_anonymous( test_wksp );
    test_wksp = NULL;
  }
}

/* Helper to create a funk transaction */
static fd_funk_txn_xid_t
test_funk_txn_create( void ) {
  fd_funk_txn_xid_t xid = { .ul={ 433000UL, 123UL } };
  fd_funk_txn_xid_t root; fd_funk_txn_xid_set_root( &root );
  fd_funk_txn_prepare( test_accdb,       &root, &xid );
  fd_funk_txn_prepare( test_cache->funk, &root, &xid );
  return xid;
}

static void
test_funk_txn_cancel( void ) {
  fd_funk_txn_cancel( test_cache->funk, &test_xid );
  fd_funk_txn_cancel( test_accdb,       &test_xid );
}

/* Helper to create a test account */
static void
create_test_account( fd_funk_txn_xid_t const * xid,
                     fd_pubkey_t const * pubkey,
                     fd_pubkey_t const * owner,
                     uchar const *       data,
                     ulong               data_len,
                     uchar               executable ) {
  FD_TXN_ACCOUNT_DECL( acc );
  fd_funk_rec_prepare_t prepare = {0};
  int err = fd_txn_account_init_from_funk_mutable( /* acc         */ acc,
                                                   /* pubkey      */ pubkey,
                                                   /* funk        */ test_accdb,
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
  fd_txn_account_set_owner( acc, owner );

  fd_txn_account_mutable_fini( acc, test_accdb, &prepare );
}

static void
update_account_data( fd_pubkey_t const * pubkey,
                     uchar const *       data,
                     ulong               data_len ) {
  FD_TXN_ACCOUNT_DECL( acc );
  fd_funk_rec_prepare_t prepare = {0};
  int err = fd_txn_account_init_from_funk_mutable( /* acc         */ acc,
                                                   /* pubkey      */ pubkey,
                                                   /* funk        */ test_accdb,
                                                   /* xid         */ &test_xid,
                                                   /* do_create   */ 0,
                                                   /* min_data_sz */ data_len,
                                                   /* prepare     */ &prepare );
  FD_TEST( !err );
  FD_TEST( data );

  fd_txn_account_set_data( acc, data, data_len );
  fd_txn_account_mutable_fini( acc, test_accdb, &prepare );
}

/* Test 1: Account doesn't exist */
static void
test_account_does_not_exist( void ) {
  FD_LOG_INFO(( "Testing: Account doesn't exist" ));

  test_xid = test_funk_txn_create();

  /* Call with a non-existent pubkey */
  fd_pubkey_t const non_existent_pubkey = {0};

  /* This should return early without doing anything */
  FD_TEST( fd_progcache_pull( test_cache, test_accdb, &test_xid, &non_existent_pubkey, 1UL, test_bank )==NULL );

  /* Verify no cache entry was created */
  FD_TEST( fd_progcache_peek( test_cache, &test_xid, &non_existent_pubkey )==NULL );

  test_funk_txn_cancel();
}

/* Test 2: Account exists but is not owned by a BPF loader */
static void
test_account_not_bpf_loader_owner( void ) {
  FD_LOG_INFO(( "Testing: Account exists but is not owned by a BPF loader" ));

  test_xid = test_funk_txn_create();

  /* Create an account owned by a non-BPF loader */
  create_test_account( &test_xid,
                       &test_program_pubkey,
                       &fd_solana_system_program_id,
                       invalid_program_data,
                       invalid_program_data_sz,
                       1 );

  /* This should return early without doing anything */
  FD_TEST( fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank )==NULL );

  /* Verify no cache entry was created */
  FD_TEST( fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey )==NULL );

  test_funk_txn_cancel();
}

/* Test 3: Program is not in cache yet (first time), but program fails validations */
static void
test_invalid_program_not_in_cache_first_time( void ) {
  FD_LOG_INFO(( "Testing: Program is not in cache yet (first time), but program fails validations" ));

  test_xid = test_funk_txn_create();

  /* Create a BPF loader account */
  create_test_account( &test_xid,
                       &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       invalid_program_data,
                       invalid_program_data_sz,
                       1 );

  /* This should create a cache entry */
  FD_TEST( fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank ) );

  /* Verify cache entry was created */
  fd_progcache_rec_t const * rec = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( rec );
  FD_TEST( rec->executable==0 );
  FD_TEST( rec->last_slot_verified==fd_bank_slot_get( test_bank ) );

  test_funk_txn_cancel();
}

/* Test 4: Program is not in cache yet (first time), but program passes validations */
static void
test_valid_program_not_in_cache_first_time( void ) {
  FD_LOG_INFO(( "Testing: Program is not in cache yet (first time), but program passes validations" ));

  test_xid = test_funk_txn_create();

  /* Create a BPF loader account */
  create_test_account( &test_xid,
                       &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* This should create a cache entry */
  FD_TEST( fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank ) );

  /* Verify cache entry was created */
  fd_progcache_rec_t const * rec = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( rec );
  FD_TEST( rec->executable==1 );
  FD_TEST( rec->last_slot_verified==fd_bank_slot_get( test_bank ) );

  test_funk_txn_cancel();
}

/* Test 5: Program is in cache but needs reverification
   (different epoch) */
static void
test_program_in_cache_needs_reverification( void ) {
  FD_LOG_INFO(( "Testing: Program is in cache but needs reverification (different epoch)" ));

  test_xid = test_funk_txn_create();

  /* Create a BPF loader account */
  create_test_account( &test_xid,
                       &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* First call to create cache entry */
  FD_TEST( fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank ) );

  /* Verify cache entry was created */
  fd_progcache_rec_t const * valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==1 );
  FD_TEST( valid_prog->last_slot_verified==fd_bank_slot_get( test_bank ) );
  FD_TEST( valid_prog->last_slot_modified==0UL );

  /* Fast forward to next epoch */
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 432000UL );

  /* This should trigger reverification */
  FD_TEST( fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank ) );

  /* Verify the cache entry was updated */
  valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==1 );
  FD_TEST( valid_prog->last_slot_verified==fd_bank_slot_get( test_bank ) );
  FD_TEST( valid_prog->last_slot_modified==0UL );

  test_funk_txn_cancel();
}

/* Test 6: Program is in cache and was just modified, so it should be
   queued for reverification */
static void
test_program_in_cache_queued_for_reverification( void ) {
  FD_LOG_INFO(( "Testing: Program is in cache and was just modified, so it should be queued for reverification" ));

  test_xid = test_funk_txn_create();

  /* Create a BPF loader account */
  create_test_account( &test_xid,
                       &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* First call to create cache entry */
  FD_TEST( fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank ) );

  /* Verify cache entry was created */
  fd_progcache_rec_t const * valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==1 );
  FD_TEST( valid_prog->last_slot_verified==fd_bank_slot_get( test_bank ) );

  /* Fast forward to a future slot */
  ulong original_slot = fd_bank_slot_get( test_bank );
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 1000UL );
  ulong future_slot = fd_bank_slot_get( test_bank );
  FD_TEST( future_slot>original_slot );

  /* Get the program account to pass to the queue function */
  FD_TXN_ACCOUNT_DECL( program_acc );
  int err = fd_txn_account_init_from_funk_readonly( program_acc, &test_program_pubkey, test_accdb, &test_xid );
  FD_TEST( !err );

  /* Queue the program for reverification */
  fd_progcache_invalidate( test_cache, &test_xid, &test_program_pubkey, future_slot, 1UL );

  /* Verify the cache entry was updated with the future slot as last_slot_modified */
  valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==0 );
  FD_TEST( valid_prog->last_slot_modified==future_slot );
  FD_TEST( valid_prog->last_slot_verified==future_slot );
  FD_TEST( valid_prog->last_slot_modified>original_slot );

  /* Reverify the cache entry at the future slot */
  fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank );

  /* Verify the cache entry was updated */
  valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==1 );
  FD_TEST( valid_prog->last_slot_modified==future_slot );
  FD_TEST( valid_prog->last_slot_verified==future_slot );

  test_funk_txn_cancel();
}

/* Test 7: Program queued for reverification but program doesn't exist
   in the cache yet */
static void
test_program_queued_for_reverification_account_does_not_exist( void ) {
  FD_LOG_INFO(( "Testing: Program queued for reverification but account doesn't exist" ));

  test_xid = test_funk_txn_create();

  /* Create a BPF loader account but don't add it to the cache */
  create_test_account( &test_xid,
                       &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* Fast forward to a future slot */
  ulong original_slot = fd_bank_slot_get( test_bank );
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 1000UL );
  ulong future_slot = fd_bank_slot_get( test_bank );
  FD_TEST( future_slot>original_slot );

  /* Get the program account to pass to the queue function */
  FD_TXN_ACCOUNT_DECL( program_acc );
  int err = fd_txn_account_init_from_funk_readonly( program_acc, &test_program_pubkey, test_accdb, &test_xid );
  FD_TEST( !err );

  /* Try to queue the program for reverification - this should return early since it's not in cache */
  fd_progcache_invalidate( test_cache, &test_xid, &test_program_pubkey, future_slot, 1UL );

  /* Verify no cache entry was created since the program wasn't in the cache */
  FD_TEST( !fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey ) );

  test_funk_txn_cancel();
}

/* Test 8: Program is in cache and was just modified and queued for
   reverification, so when it is next reverified the
   `last_slot_verified` should be set to the current slot */
static void
test_program_in_cache_queued_for_reverification_and_processed( void ) {
  FD_LOG_INFO(( "Testing: Program is in cache and was just modified and queued for reverification, so the last slot reverification ran should be set to the current slot" ));

  test_xid = test_funk_txn_create();

  /* Create a BPF loader account */
  create_test_account( &test_xid,
                       &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* First call to create cache entry */
  fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank );

  /* Verify cache entry was created */
  fd_progcache_rec_t const * valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==1 );
  FD_TEST( valid_prog->last_slot_verified==fd_bank_slot_get( test_bank ) );

  /* Fast forward to a future slot */
  ulong original_slot = fd_bank_slot_get( test_bank );
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 11000UL );
  ulong future_slot = fd_bank_slot_get( test_bank );
  FD_TEST( future_slot>original_slot );

  /* Get the program account to pass to the queue function */
  FD_TXN_ACCOUNT_DECL( program_acc );
  int err = fd_txn_account_init_from_funk_readonly( program_acc, &test_program_pubkey, test_accdb, &test_xid );
  FD_TEST( !err );

  /* Queue the program for reverification */
  fd_progcache_invalidate( test_cache, &test_xid, &test_program_pubkey, future_slot, 1UL );

  /* Verify the cache entry was updated with the future slot as last_slot_modified */
  valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==0 );
  FD_TEST( valid_prog->last_slot_modified==future_slot );
  FD_TEST( valid_prog->last_slot_verified==future_slot );
  FD_TEST( valid_prog->last_slot_modified>original_slot );

  /* Fast forward to a future slot */
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 11000UL );
  ulong future_update_slot = fd_bank_slot_get( test_bank );
  FD_TEST( future_update_slot>future_slot );

  /* Now update the cache entry at the future slot */
  fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank );

  /* Verify the cache entry was updated */
  valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==1 );
  FD_TEST( valid_prog->last_slot_verified==future_update_slot );
  FD_TEST( valid_prog->last_slot_modified==future_slot );

  test_funk_txn_cancel();
}

/* Test 9: Genesis program fails verification, and is reverified later */
static void
test_invalid_genesis_program_reverified_after_genesis( void ) {
  FD_LOG_INFO(( "Testing: Program fails verification in genesis, and is reverified later" ));

  test_xid = test_funk_txn_create();
  fd_bank_slot_set( test_bank, 0UL );

  /* Create a BPF loader account */
  create_test_account( &test_xid,
                       &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       invalid_program_data,
                       invalid_program_data_sz,
                       1 );

  /* First call to create cache entry */
  fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank );

  /* Verify cache entry was created */
  fd_progcache_rec_t const * valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==0 );
  FD_TEST( valid_prog->last_slot_modified==0UL );
  FD_TEST( valid_prog->last_slot_verified==0UL );

  /* Fast forward to a future slot */
  ulong original_slot = fd_bank_slot_get( test_bank );
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 11000UL );
  ulong future_slot = fd_bank_slot_get( test_bank );
  FD_TEST( future_slot>original_slot );

  /* Program invoked, update cache entry */
  fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank );

  /* Verify the cache entry was updated */
  valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==0 );
  FD_TEST( valid_prog->last_slot_verified==future_slot );
  FD_TEST( valid_prog->last_slot_modified==0UL );

  test_funk_txn_cancel();
}

/* Test 10: Genesis program passes verification, and is reverified
   later */
static void
test_valid_genesis_program_reverified_after_genesis( void ) {
  FD_LOG_INFO(( "Testing: Program passes verification in genesis, and is reverified later" ));

  test_xid = test_funk_txn_create();
  fd_bank_slot_set( test_bank, 0UL );

  /* Create a BPF loader account */
  create_test_account( &test_xid,
                       &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* First call to create cache entry */
  fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank );

  /* Verify cache entry was created */
  fd_progcache_rec_t const * valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==1 );
  FD_TEST( valid_prog->last_slot_modified==0UL );
  FD_TEST( valid_prog->last_slot_verified==0UL );

  /* Fast forward to a future slot */
  ulong original_slot = fd_bank_slot_get( test_bank );
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 11000UL );
  ulong future_slot = fd_bank_slot_get( test_bank );
  FD_TEST( future_slot>original_slot );

  /* Program invoked, update cache entry */
  fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank );

  /* Verify the cache entry was updated */
  valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==1 );
  FD_TEST( valid_prog->last_slot_verified==future_slot );
  FD_TEST( valid_prog->last_slot_modified==0UL );

  test_funk_txn_cancel();
}

/* Test 11: Program gets upgraded with a larger programdata size */
static void
test_program_upgraded_with_larger_programdata( void ) {
  FD_LOG_INFO(( "Testing: Program gets upgraded with a larger programdata size" ));

  test_xid = test_funk_txn_create();
  fd_bank_slot_set( test_bank, 0UL );

  /* Create a BPF loader account */
  create_test_account( &test_xid,
                       &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* First call to create cache entry */
  FD_TEST( fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank ) );

  /* Verify cache entry was created */
  fd_progcache_rec_t const * valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==1 );
  FD_TEST( valid_prog->last_slot_modified==0UL );
  FD_TEST( valid_prog->last_slot_verified==0UL );

  /* "Upgrade" the program by modifying the programdata */
  update_account_data( &test_program_pubkey, bigger_valid_program_data, bigger_valid_program_data_sz );

  /* Queue the program for reverification */
  ulong original_slot = fd_bank_slot_get( test_bank );
  fd_progcache_invalidate( test_cache, &test_xid, &test_program_pubkey, original_slot, 1UL );

  /* Advance slot number */
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 1UL );
  ulong future_slot = fd_bank_slot_get( test_bank );
  FD_TEST( future_slot>original_slot );

  /* Verify the cache entry was updated with the future slot as last_slot_modified */
  valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==0 );
  FD_TEST( valid_prog->last_slot_modified==original_slot );
  FD_TEST( valid_prog->last_slot_verified==original_slot );

  /* Store the old program cache funk record size */
  fd_funk_rec_key_t id; memcpy( &id, &test_program_pubkey, 32UL );
  fd_funk_rec_query_t query[1];
  fd_funk_rec_t const * prev_rec = fd_funk_rec_query_try_global( test_cache->funk, &test_xid, &id, NULL, query );
  FD_TEST( prev_rec );
  ulong prev_rec_sz = prev_rec->val_sz;
  FD_TEST( !fd_funk_rec_query_test( query ) );

  /* Program invoked, update cache entry */
  fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank );

  /* Get the new program cache funk record size, and make sure it's
     larger */
  fd_funk_rec_t const * new_rec = fd_funk_rec_query_try_global( test_cache->funk, &test_xid, &id, NULL, query );
  FD_TEST( new_rec );
  ulong new_rec_sz = new_rec->val_sz;
  FD_TEST( new_rec_sz>prev_rec_sz );
  FD_TEST( !fd_funk_rec_query_test( query ) );

  /* Verify the cache entry was updated */
  valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==1 );
  FD_TEST( valid_prog->last_slot_verified==future_slot );
  FD_TEST( valid_prog->last_slot_modified==original_slot );

  test_funk_txn_cancel();
}

/* Test 12: Rooted program */

static void
test_program_rooted( void ) {
  FD_LOG_INFO(( "Testing: Rooted program" ));

  test_xid = test_funk_txn_create();
  fd_bank_slot_set( test_bank, 0UL );

  /* Create a BPF loader account */
  create_test_account( &test_xid,
                       &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  fd_funk_txn_publish( test_accdb,       &test_xid );
  fd_funk_txn_publish( test_cache->funk, &test_xid );

  /* Fill cache on rooted fork */
  FD_TEST( fd_progcache_pull( test_cache, test_accdb, &test_xid, &test_program_pubkey, 1UL, test_bank ) );
  FD_TEST( fd_funk_txn_xid_eq( fd_funk_last_publish( test_cache->funk ), &test_xid ) );
  FD_TEST( fd_funk_txn_xid_eq( fd_funk_last_publish( test_accdb       ), &test_xid ) );

  /* Verify cache entry was created */
  fd_progcache_rec_t const * valid_prog = fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->executable==1 );
  FD_TEST( valid_prog->last_slot_modified==0UL );
  FD_TEST( valid_prog->last_slot_verified==0UL );

  fd_funk_txn_cancel_all( test_accdb );
  fd_funk_txn_remove_published( test_accdb );

  /* Verify that cache entry is removed by reset */
  fd_progcache_reset( test_cache );
  FD_TEST( fd_progcache_peek( test_cache, &test_xid, &test_program_pubkey )==NULL );
  fd_progcache_clear( test_cache );
  FD_TEST( fd_progcache_peek( test_cache, fd_funk_last_publish( test_cache->funk ), &test_program_pubkey )==NULL );
}

/* Test 13: Epoch boundary */

static int
find_rec( fd_progcache_t *            cache,
          fd_funk_txn_xid_t const *   xid,
          fd_pubkey_t const *         pubkey,
          fd_progcache_rec_t const *  expected ) {
  fd_funk_rec_key_t id; memcpy( &id, pubkey, 32UL );
  fd_funk_rec_query_t query[1];
  fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( cache->funk, xid, &id, NULL, query );
  if( !rec ) return 0;
  if( fd_funk_rec_query_test( query ) ) return 0;
  return fd_funk_txn_xid_eq( rec->pair.xid, xid ) && fd_wksp_laddr_fast( cache->funk->wksp, rec->val_gaddr )==expected;
}

static void
bank_slot_set( fd_bank_t * bank, ulong slot ) {
  fd_bank_slot_set( bank, slot );
  fd_bank_epoch_set( bank, slot / 432000UL );
}

static void
test_epoch_boundary( void ) {
  FD_LOG_INFO(( "Testing: Epoch boundary" ));

  /* Fork graph:
     A -> B -> C # -> D -> G
                 #      -> H
            -> E # -> F

     '#' marks an epoch boundary
     'A' is the last published (root)
     Program is created at 'B'
     Feature activations at 'C' and 'E' respectively */

  fd_funk_txn_xid_t const fork_a = { .ul={ 863997UL, 1UL } };
  fd_funk_txn_xid_t const fork_b = { .ul={ 863998UL, 2UL } };
  fd_funk_txn_xid_t const fork_c = { .ul={ 863999UL, 3UL } };
  fd_funk_txn_xid_t const fork_d = { .ul={ 864000UL, 4UL } };
  fd_funk_txn_xid_t const fork_e = { .ul={ 863999UL, 5UL } };
  fd_funk_txn_xid_t const fork_f = { .ul={ 864001UL, 6UL } };
  fd_funk_txn_xid_t const fork_g = { .ul={ 864002UL, 7UL } };
  fd_funk_txn_xid_t const fork_h = { .ul={ 864003UL, 8UL } };

  fd_funk_txn_prepare( test_accdb,       fd_funk_last_publish( test_accdb       ), &fork_a );
  fd_funk_txn_prepare( test_cache->funk, fd_funk_last_publish( test_cache->funk ), &fork_a );
  fd_funk_txn_publish( test_accdb,       &fork_a );
  fd_funk_txn_publish( test_cache->funk, &fork_a );

  fd_funk_txn_prepare( test_accdb,       &fork_a, &fork_b );
  fd_funk_txn_prepare( test_cache->funk, &fork_a, &fork_b );
  create_test_account( &fork_b,
                       &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  fd_funk_txn_prepare( test_accdb,       &fork_b, &fork_c );
  fd_funk_txn_prepare( test_cache->funk, &fork_b, &fork_c );
  fd_funk_txn_prepare( test_accdb,       &fork_b, &fork_e );
  fd_funk_txn_prepare( test_cache->funk, &fork_b, &fork_e );
  fd_funk_txn_prepare( test_accdb,       &fork_c, &fork_d );
  fd_funk_txn_prepare( test_cache->funk, &fork_c, &fork_d );
  fd_funk_txn_prepare( test_accdb,       &fork_e, &fork_f );
  fd_funk_txn_prepare( test_cache->funk, &fork_e, &fork_f );
  fd_funk_txn_prepare( test_accdb,       &fork_d, &fork_g );
  fd_funk_txn_prepare( test_cache->funk, &fork_d, &fork_g );
  fd_funk_txn_prepare( test_accdb,       &fork_d, &fork_h );
  fd_funk_txn_prepare( test_cache->funk, &fork_d, &fork_h );

  /* Pull program from fork G, should create cache entry at D */
  FD_TEST( !fd_progcache_peek( test_cache, &fork_d, &test_program_pubkey ) );
  bank_slot_set( test_bank, fork_g.ul[0] );
  FD_TEST( fd_bank_epoch_get( test_bank )==2UL );
  fd_progcache_rec_t const * rec_d = fd_progcache_pull( test_cache, test_accdb, &fork_g, &test_program_pubkey, 1UL, test_bank );
  FD_TEST( find_rec( test_cache, &fork_d, &test_program_pubkey, rec_d ) );
  FD_TEST( fd_progcache_peek( test_cache, &fork_d, &test_program_pubkey )==rec_d );

  /* Pull program from fork H, should reuse existing cache entry */
  FD_TEST( fd_progcache_peek( test_cache, &fork_h, &test_program_pubkey )==rec_d );

  /* Pull program from fork F, should create cache entry at F */
  FD_TEST( !fd_progcache_peek( test_cache, &fork_f, &test_program_pubkey ) );
  bank_slot_set( test_bank, fork_f.ul[0] );
  FD_TEST( fd_bank_epoch_get( test_bank )==2UL );
  fd_progcache_rec_t const * rec_f = fd_progcache_pull( test_cache, test_accdb, &fork_f, &test_program_pubkey, 1UL, test_bank );
  FD_TEST( find_rec( test_cache, &fork_f, &test_program_pubkey, rec_f ) );
  FD_TEST( fd_progcache_peek( test_cache, &fork_f, &test_program_pubkey )==rec_f );

  /* Pull program from fork D, should reuse existing cache entry */
  FD_TEST( fd_progcache_peek( test_cache, &fork_d, &test_program_pubkey )==rec_d );

  /* Pull program from fork E, should create cache entry at B */
  FD_TEST( !fd_progcache_peek( test_cache, &fork_e, &test_program_pubkey ) );
  bank_slot_set( test_bank, fork_e.ul[0] );
  FD_TEST( fd_bank_epoch_get( test_bank )==1UL );
  fd_progcache_rec_t const * rec_b = fd_progcache_pull( test_cache, test_accdb, &fork_e, &test_program_pubkey, 1UL, test_bank );
  FD_TEST( find_rec( test_cache, &fork_b, &test_program_pubkey, rec_b ) );
  FD_TEST( fd_progcache_peek( test_cache, &fork_e, &test_program_pubkey )==rec_b );

  /* Root fork B */
  fd_funk_txn_publish( test_accdb,       &fork_b );
  fd_funk_txn_publish( test_cache->funk, &fork_b );

  /* Pull program from fork C, should reuse existing cache entry */
  FD_TEST( fd_progcache_peek( test_cache, &fork_c, &test_program_pubkey )==rec_b );

  /* Root fork D */
  fd_funk_txn_publish( test_accdb,       &fork_d );
  fd_funk_txn_publish( test_cache->funk, &fork_d );

  /* Pull program from fork G, should reuse existing cache entry */
  FD_TEST( fd_progcache_peek( test_cache, &fork_g, &test_program_pubkey )==rec_d );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Create workspace */
  test_wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 2UL, fd_log_cpu_id(), "test_wksp", 0UL );
  FD_TEST( test_wksp );

  ulong accdb_rec_max = 128UL;
  ulong accdb_txn_max =  16UL;

  ulong progcache_rec_max = 64UL;
  ulong progcache_txn_max = 16UL;

  /* Create funk */
  void * accdb_mem = fd_wksp_alloc_laddr( test_wksp, fd_funk_align(), fd_funk_footprint( accdb_txn_max, accdb_rec_max ), TEST_WKSP_TAG );
  FD_TEST( accdb_mem );

  void * progcache_mem = fd_wksp_alloc_laddr( test_wksp, fd_funk_align(), fd_funk_footprint( progcache_txn_max, progcache_rec_max ), TEST_WKSP_TAG );
  FD_TEST( progcache_mem );

  void * shaccdb = fd_funk_new( accdb_mem, 1234UL, 5678UL, accdb_txn_max, accdb_rec_max );
  FD_TEST( shaccdb );

  void * shprogcache = fd_funk_new( progcache_mem, 1235UL, 5679UL, progcache_txn_max, progcache_rec_max );
  FD_TEST( shprogcache );

  fd_funk_t funk_[1];
  test_accdb = fd_funk_join( funk_, shaccdb );
  FD_TEST( test_accdb );

  fd_progcache_t progcache_[1];
  test_cache = fd_progcache_join( progcache_, shprogcache );
  FD_TEST( test_cache );

  /* Set up bank */
  ulong   banks_footprint = fd_banks_footprint( 1UL, 1UL );
  uchar * banks_mem       = fd_wksp_alloc_laddr( test_wksp, fd_banks_align(), banks_footprint, TEST_WKSP_TAG );
  FD_TEST( banks_mem );

  fd_banks_t * banks = fd_banks_join( fd_banks_new( banks_mem, 1UL, 1UL ) );
  FD_TEST( banks );
  fd_bank_t * bank = fd_banks_init_bank( banks );
  fd_bank_slot_set( bank, 433000UL );
  FD_TEST( bank );

  test_bank  = bank;
  test_banks = banks;

  fd_epoch_schedule_t epoch_schedule = {
      .slots_per_epoch             = 432000UL,
      .leader_schedule_slot_offset = 432000UL,
      .warmup                      = 0,
      .first_normal_epoch          = 0UL,
      .first_normal_slot           = 0UL
  };
  fd_bank_epoch_schedule_set( bank, epoch_schedule );

  test_account_does_not_exist();
  test_account_not_bpf_loader_owner();
  test_invalid_program_not_in_cache_first_time();
  test_valid_program_not_in_cache_first_time();
  test_program_in_cache_needs_reverification();
  test_program_in_cache_queued_for_reverification();
  test_program_queued_for_reverification_account_does_not_exist();
  test_program_in_cache_queued_for_reverification_and_processed();
  test_invalid_genesis_program_reverified_after_genesis();
  test_valid_genesis_program_reverified_after_genesis();
  test_program_upgraded_with_larger_programdata();
  test_program_rooted();
  test_epoch_boundary();

  test_teardown();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#undef TEST_WKSP_TAG

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_HOSTED capabilities" ));
  fd_halt();
  return 0;
}

#endif
