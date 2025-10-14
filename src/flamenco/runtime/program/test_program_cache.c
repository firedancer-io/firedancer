#include "fd_program_cache.h"
#include "../fd_bank.h"

#if FD_HAS_HOSTED

#define TEST_WKSP_TAG 1234UL

/* Load in programdata for tests */
FD_IMPORT_BINARY( valid_program_data, "src/ballet/sbpf/fixtures/hello_solana_program.so" );
FD_IMPORT_BINARY( bigger_valid_program_data, "src/ballet/sbpf/fixtures/clock_sysvar_program.so" );
FD_IMPORT_BINARY( zero_text_cnt_elf, "src/ballet/sbpf/fixtures/zero_text_cnt.elf" );

static uchar const invalid_program_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

/* Test program pubkeys */
static fd_pubkey_t const test_program_pubkey = {
  .uc = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
          0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 }
};

static ulong const SPAD_MEM_MAX = 100UL << 20; /* 100MB */

/* Test setup and teardown helpers */
static fd_wksp_t *         test_wksp = NULL;
static fd_funk_t *         test_funk = NULL;
static fd_spad_t *         test_spad = NULL;
static fd_bank_t *         test_bank = NULL;
static fd_banks_t *        test_banks = NULL;
static fd_funk_txn_xid_t   test_xid  = {0};

static void
test_teardown( void ) {

  if( test_spad ) {
    fd_spad_leave( test_spad );
    test_spad = NULL;
  }

  if( test_funk ) {
    fd_funk_leave( test_funk, NULL );
    test_funk = NULL;
  }

  if( test_wksp ) {
    fd_wksp_delete_anonymous( test_wksp );
    test_wksp = NULL;
  }
}

/* Helper to create a funk transaction */
static fd_funk_txn_xid_t
create_test_funk_txn( void ) {
  fd_funk_txn_xid_t xid = fd_funk_generate_xid();
  fd_funk_txn_xid_t root; fd_funk_txn_xid_set_root( &root );
  fd_funk_txn_prepare( test_funk, &root, &xid );
  return xid;
}

/* Helper to create a test account */
static void
create_test_account( fd_pubkey_t const * pubkey,
                     fd_pubkey_t const * owner,
                     uchar const *       data,
                     ulong               data_len,
                     uchar               executable ) {
  fd_txn_account_t acc[1];
  fd_funk_rec_prepare_t prepare = {0};
  int err = fd_txn_account_init_from_funk_mutable( /* acc         */ acc,
                                                   /* pubkey      */ pubkey,
                                                   /* funk        */ test_funk,
                                                   /* xid         */ &test_xid,
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

  fd_txn_account_mutable_fini( acc, test_funk, &prepare );
}

static void
update_account_data( fd_pubkey_t const * pubkey,
                     uchar const *       data,
                     ulong               data_len ) {
  fd_txn_account_t acc[1];
  fd_funk_rec_prepare_t prepare = {0};
  int err = fd_txn_account_init_from_funk_mutable( /* acc         */ acc,
                                                   /* pubkey      */ pubkey,
                                                   /* funk        */ test_funk,
                                                   /* xid         */ &test_xid,
                                                   /* do_create   */ 0,
                                                   /* min_data_sz */ data_len,
                                                   /* prepare     */ &prepare );
  FD_TEST( !err );
  FD_TEST( data );

  fd_txn_account_set_data( acc, data, data_len );
  fd_txn_account_mutable_fini( acc, test_funk, &prepare );
}

/* Test 1: Account doesn't exist */
static void
test_account_does_not_exist( void ) {
  FD_LOG_NOTICE(( "Testing: Account doesn't exist" ));

  test_xid = create_test_funk_txn();

  /* Call with a non-existent pubkey */
  fd_pubkey_t const non_existent_pubkey = {0};

  /* This should return early without doing anything */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &non_existent_pubkey, test_spad );

  /* Verify no cache entry was created */
  fd_program_cache_entry_t const * valid_prog = NULL;
  int err = fd_program_cache_load_entry( test_funk, &test_xid, &non_existent_pubkey, &valid_prog );
  FD_TEST( err==-1 ); /* Should not exist */

  fd_funk_txn_cancel( test_funk, &test_xid );
}

/* Test 2: Account exists but is not owned by a BPF loader */
static void
test_account_not_bpf_loader_owner( void ) {
  FD_LOG_NOTICE(( "Testing: Account exists but is not owned by a BPF loader" ));

  test_xid = create_test_funk_txn();

  /* Create an account owned by a non-BPF loader */
  create_test_account( &test_program_pubkey,
                       &fd_solana_system_program_id,
                       invalid_program_data,
                       sizeof(invalid_program_data),
                       1 );

  /* This should return early without doing anything */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify no cache entry was created */
  fd_program_cache_entry_t const * valid_prog = NULL;
  int err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( err==-1 ); /* Should not exist */

  fd_funk_txn_cancel( test_funk, &test_xid );
}

/* Test 3: Program is not in cache yet (first time), but program fails validations */
static void
test_invalid_program_not_in_cache_first_time( void ) {
  FD_LOG_NOTICE(( "Testing: Program is not in cache yet (first time), but program fails validations" ));

  test_xid = create_test_funk_txn();

  /* Create a BPF loader account */
  create_test_account( &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       invalid_program_data,
                       sizeof(invalid_program_data),
                       1 );

  /* This should create a cache entry */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify cache entry was created */
  fd_program_cache_entry_t const * valid_prog = NULL;
  int err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err ); /* Should exist */
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_verified==fd_bank_slot_get( test_bank ) );

  fd_funk_txn_cancel( test_funk, &test_xid );
}

/* Test 4: Program is not in cache yet (first time), but program passes validations */
static void
test_valid_program_not_in_cache_first_time( void ) {
  FD_LOG_NOTICE(( "Testing: Program is not in cache yet (first time), but program passes validations" ));

  test_xid = create_test_funk_txn();

  /* Create a BPF loader account */
  create_test_account( &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* This should create a cache entry */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify cache entry was created */
  fd_program_cache_entry_t const * valid_prog = NULL;
  int err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err ); /* Should exist */
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_verified==fd_bank_slot_get( test_bank ) );

  fd_funk_txn_cancel( test_funk, &test_xid );
}

/* Test 5: Program is in cache but needs reverification
   (different epoch) */
static void
test_program_in_cache_needs_reverification( void ) {
  FD_LOG_NOTICE(( "Testing: Program is in cache but needs reverification (different epoch)" ));

  test_xid = create_test_funk_txn();

  /* Create a BPF loader account */
  create_test_account( &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* First call to create cache entry */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify cache entry was created */
  fd_program_cache_entry_t const * valid_prog = NULL;
  int err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_verified==fd_bank_slot_get( test_bank ) );
  FD_TEST( valid_prog->last_slot_modified==0UL );

  /* Fast forward to next epoch */
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 432000UL );

  /* This should trigger reverification */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify the cache entry was updated */
  err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_verified==fd_bank_slot_get( test_bank ) );
  FD_TEST( valid_prog->last_slot_modified==0UL );

  fd_funk_txn_cancel( test_funk, &test_xid );
}

/* Test 6: Program is in cache and was just modified, so it should be
   queued for reverification */
static void
test_program_in_cache_queued_for_reverification( void ) {
  FD_LOG_NOTICE(( "Testing: Program is in cache and was just modified, so it should be queued for reverification" ));

  test_xid = create_test_funk_txn();

  /* Create a BPF loader account */
  create_test_account( &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* First call to create cache entry */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify cache entry was created */
  fd_program_cache_entry_t const * valid_prog = NULL;
  int err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_verified==fd_bank_slot_get( test_bank ) );

  /* Fast forward to a future slot */
  ulong original_slot = fd_bank_slot_get( test_bank );
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 1000UL );
  ulong future_slot = fd_bank_slot_get( test_bank );
  FD_TEST( future_slot>original_slot );

  /* Get the program account to pass to the queue function */
  fd_txn_account_t program_acc[1];
  err = fd_txn_account_init_from_funk_readonly( program_acc, &test_program_pubkey, test_funk, &test_xid );
  FD_TEST( !err );

  /* Queue the program for reverification */
  fd_program_cache_queue_program_for_reverification( test_funk, &test_xid, &test_program_pubkey, future_slot );

  /* Verify the cache entry was updated with the future slot as last_slot_modified */
  err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_modified==future_slot );
  FD_TEST( valid_prog->last_slot_verified==original_slot );
  FD_TEST( valid_prog->last_slot_modified>original_slot );

  /* Reverify the cache entry at the future slot */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify the cache entry was updated */
  err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_modified==future_slot );
  FD_TEST( valid_prog->last_slot_verified==future_slot );

  fd_funk_txn_cancel( test_funk, &test_xid );
}

/* Test 7: Program queued for reverification but program doesn't exist
   in the cache yet */
static void
test_program_queued_for_reverification_account_does_not_exist( void ) {
  FD_LOG_NOTICE(( "Testing: Program queued for reverification but account doesn't exist" ));

  test_xid = create_test_funk_txn();

  /* Create a BPF loader account but don't add it to the cache */
  create_test_account( &test_program_pubkey,
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
  fd_txn_account_t program_acc[1];
  int err = fd_txn_account_init_from_funk_readonly( program_acc, &test_program_pubkey, test_funk, &test_xid );
  FD_TEST( !err );

  /* Try to queue the program for reverification - this should return early since it's not in cache */
  fd_program_cache_queue_program_for_reverification( test_funk, &test_xid, &test_program_pubkey, future_slot );

  /* Verify no cache entry was created since the program wasn't in the cache */
  fd_program_cache_entry_t const * valid_prog = NULL;
  err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( err ); /* Should not exist */

  fd_funk_txn_cancel( test_funk, &test_xid );
}

/* Test 8: Program is in cache and was just modified and queued for
   reverification, so when it is next reverified the
   `last_slot_verified` should be set to the current slot */
static void
test_program_in_cache_queued_for_reverification_and_processed( void ) {
  FD_LOG_NOTICE(( "Testing: Program is in cache and was just modified and queued for reverification, so the last slot reverification ran should be set to the current slot" ));

  test_xid = create_test_funk_txn();

  /* Create a BPF loader account */
  create_test_account( &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* First call to create cache entry */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify cache entry was created */
  fd_program_cache_entry_t const * valid_prog = NULL;
  int err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_verified==fd_bank_slot_get( test_bank ) );

  /* Fast forward to a future slot */
  ulong original_slot = fd_bank_slot_get( test_bank );
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 11000UL );
  ulong future_slot = fd_bank_slot_get( test_bank );
  FD_TEST( future_slot>original_slot );

  /* Get the program account to pass to the queue function */
  fd_txn_account_t program_acc[1];
  err = fd_txn_account_init_from_funk_readonly( program_acc, &test_program_pubkey, test_funk, &test_xid );
  FD_TEST( !err );

  /* Queue the program for reverification */
  fd_program_cache_queue_program_for_reverification( test_funk, &test_xid, &test_program_pubkey, future_slot );

  /* Verify the cache entry was updated with the future slot as last_slot_modified */
  err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_modified==future_slot );
  FD_TEST( valid_prog->last_slot_verified==original_slot );
  FD_TEST( valid_prog->last_slot_modified>original_slot );

  /* Fast forward to a future slot */
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 11000UL );
  ulong future_update_slot = fd_bank_slot_get( test_bank );
  FD_TEST( future_update_slot>future_slot );

  /* Now update the cache entry at the future slot */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify the cache entry was updated */
  err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_verified==future_update_slot );
  FD_TEST( valid_prog->last_slot_modified==future_slot );

  fd_funk_txn_cancel( test_funk, &test_xid );
}

/* Test 9: Genesis program fails verification, and is reverified later */
static void
test_invalid_genesis_program_reverified_after_genesis( void ) {
  FD_LOG_NOTICE(( "Testing: Program fails verification in genesis, and is reverified later" ));

  test_xid = create_test_funk_txn();
  fd_bank_slot_set( test_bank, 0UL );

  /* Create a BPF loader account */
  create_test_account( &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       invalid_program_data,
                       sizeof(invalid_program_data),
                       1 );

  /* First call to create cache entry */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify cache entry was created */
  fd_program_cache_entry_t const * valid_prog = NULL;
  int err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_modified==0UL );
  FD_TEST( valid_prog->last_slot_verified==0UL );

  /* Fast forward to a future slot */
  ulong original_slot = fd_bank_slot_get( test_bank );
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 11000UL );
  ulong future_slot = fd_bank_slot_get( test_bank );
  FD_TEST( future_slot>original_slot );

  /* Program invoked, update cache entry */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify the cache entry was updated */
  err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_verified==future_slot );
  FD_TEST( valid_prog->last_slot_modified==0UL );

  fd_funk_txn_cancel( test_funk, &test_xid );
}

/* Test 10: Genesis program passes verification, and is reverified
   later */
static void
test_valid_genesis_program_reverified_after_genesis( void ) {
  FD_LOG_NOTICE(( "Testing: Program passes verification in genesis, and is reverified later" ));

  test_xid = create_test_funk_txn();
  fd_bank_slot_set( test_bank, 0UL );

  /* Create a BPF loader account */
  create_test_account( &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* First call to create cache entry */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify cache entry was created */
  fd_program_cache_entry_t const * valid_prog = NULL;
  int err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_modified==0UL );
  FD_TEST( valid_prog->last_slot_verified==0UL );

  /* Fast forward to a future slot */
  ulong original_slot = fd_bank_slot_get( test_bank );
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 11000UL );
  ulong future_slot = fd_bank_slot_get( test_bank );
  FD_TEST( future_slot>original_slot );

  /* Program invoked, update cache entry */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify the cache entry was updated */
  err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_verified==future_slot );
  FD_TEST( valid_prog->last_slot_modified==0UL );

  fd_funk_txn_cancel( test_funk, &test_xid );
}

/* Test 11: Program gets upgraded with a larger programdata size */
static void
test_program_upgraded_with_larger_programdata( void ) {
  FD_LOG_NOTICE(( "Testing: Program gets upgraded with a larger programdata size" ));

  test_xid = create_test_funk_txn();
  fd_bank_slot_set( test_bank, 0UL );

  /* Create a BPF loader account */
  create_test_account( &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* First call to create cache entry */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify cache entry was created */
  fd_program_cache_entry_t const * valid_prog = NULL;
  int err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_modified==0UL );
  FD_TEST( valid_prog->last_slot_verified==0UL );

  /* Fast forward to a future slot */
  ulong original_slot = fd_bank_slot_get( test_bank );
  fd_bank_slot_set( test_bank, fd_bank_slot_get( test_bank ) + 11000UL );
  ulong future_slot = fd_bank_slot_get( test_bank );
  FD_TEST( future_slot>original_slot );

  /* "Upgrade" the program by modifying the programdata */
  update_account_data( &test_program_pubkey, bigger_valid_program_data, bigger_valid_program_data_sz );

  /* Queue the program for reverification */
  fd_program_cache_queue_program_for_reverification( test_funk, &test_xid, &test_program_pubkey, future_slot );

  /* Verify the cache entry was updated with the future slot as last_slot_modified */
  err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_modified==future_slot );
  FD_TEST( valid_prog->last_slot_verified==original_slot );
  FD_TEST( valid_prog->last_slot_modified>original_slot );

  /* Store the old program cache funk record size */
  fd_funk_rec_key_t id = fd_program_cache_key( &test_program_pubkey );
  fd_funk_rec_query_t query[1];
  fd_funk_rec_t const * prev_rec = fd_funk_rec_query_try_global( test_funk, &test_xid, &id, NULL, query );
  FD_TEST( prev_rec );
  ulong prev_rec_sz = prev_rec->val_sz;
  FD_TEST( !fd_funk_rec_query_test( query ) );

  /* Program invoked, update cache entry */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Get the new program cache funk record size, and make sure it's
     larger */
  fd_funk_rec_t const * new_rec = fd_funk_rec_query_try_global( test_funk, &test_xid, &id, NULL, query );
  FD_TEST( new_rec );
  ulong new_rec_sz = new_rec->val_sz;
  FD_TEST( new_rec_sz>prev_rec_sz );
  FD_TEST( !fd_funk_rec_query_test( query ) );

  /* Verify the cache entry was updated */
  err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_verified==future_slot );
  FD_TEST( valid_prog->last_slot_modified==future_slot );

  fd_funk_txn_cancel( test_funk, &test_xid );
}

static void
test_zero_text_cnt_program_account( void ) {
  FD_LOG_NOTICE(( "Testing: Inserting an ELF with text_cnt=0 into the program cache" ));

  test_xid = create_test_funk_txn();

  /* Create a BPF loader account */
  create_test_account( &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       zero_text_cnt_elf,
                       zero_text_cnt_elf_sz,
                       1 );

  /* VM validate checks should catch this */
  fd_program_cache_update_program( test_bank, test_funk, &test_xid, &test_program_pubkey, test_spad );

  /* Verify failed verification cache entry was created */
  fd_program_cache_entry_t const * valid_prog = NULL;
  int err = fd_program_cache_load_entry( test_funk, &test_xid, &test_program_pubkey, &valid_prog );
  FD_TEST( !err ); /* Should exist */
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_PROGRAM_CACHE_ENTRY_MAGIC );
  FD_TEST( valid_prog->failed_verification );
  FD_TEST( valid_prog->last_slot_verified==fd_bank_slot_get( test_bank ) );

  fd_funk_txn_cancel( test_funk, &test_xid );
}


int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Starting BPF program cache tests" ));

    /* Create workspace */
  test_wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 3UL, fd_log_cpu_id(), "test_wksp", 0UL );
  FD_TEST( test_wksp );

  /* Create funk */
  ulong funk_align = fd_funk_align();
  ulong funk_footprint = fd_funk_footprint( 1024UL, 1024UL );
  void * funk_mem = fd_wksp_alloc_laddr( test_wksp, funk_align, funk_footprint, TEST_WKSP_TAG );
  FD_TEST( funk_mem );

  void * shfunk = fd_funk_new( funk_mem, 1234UL, 5678UL, 1024UL, 1024UL );
  FD_TEST( shfunk );

  fd_funk_t funk_[1];
  test_funk = fd_funk_join( funk_, shfunk );
  FD_TEST( test_funk );

  /* Create spad */
  ulong spad_align = fd_spad_align();
  ulong spad_footprint = fd_spad_footprint( SPAD_MEM_MAX );
  void * spad_mem = fd_wksp_alloc_laddr( test_wksp, spad_align, spad_footprint, TEST_WKSP_TAG );
  FD_TEST( spad_mem );

  test_spad = fd_spad_join( fd_spad_new( spad_mem, SPAD_MEM_MAX ) );
  FD_TEST( test_spad );

  FD_SPAD_FRAME_BEGIN( test_spad ) {

    /* Set up bank */
    ulong        banks_footprint = fd_banks_footprint( 1UL, 1UL );
    uchar *      banks_mem       = fd_wksp_alloc_laddr( test_wksp, fd_banks_align(), banks_footprint, TEST_WKSP_TAG );
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
    test_zero_text_cnt_program_account();
  } FD_SPAD_FRAME_END;

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
