#include "fd_bpf_program_util.h"
#include "../../../util/fd_util.h"

#if FD_HAS_HOSTED

#define TEST_WKSP_TAG 1234UL

/* Load in programdata for tests */
FD_IMPORT_BINARY( valid_program_data, "src/ballet/sbpf/fixtures/hello_solana_program.so" );

static uchar const invalid_program_data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

/* Test program pubkeys */
static fd_pubkey_t const test_program_pubkey = {
  .uc = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
          0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 }
};

static ulong const SPAD_MEM_MAX = 100UL << 20; /* 100MB */

/* Test setup and teardown helpers */
static fd_wksp_t * test_wksp = NULL;
static fd_funk_t * test_funk = NULL;
static fd_spad_t * test_spad = NULL;
static fd_exec_slot_ctx_t * test_slot_ctx = NULL;

static void
test_teardown( void ) {
  if( test_slot_ctx ) {
    fd_exec_slot_ctx_leave( test_slot_ctx );
    test_slot_ctx = NULL;
  }

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
static fd_funk_txn_t *
create_test_funk_txn( void ) {
  fd_funk_txn_xid_t xid = fd_funk_generate_xid();
  fd_funk_txn_start_write( test_funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( test_funk, NULL, &xid, 1 );
  fd_funk_txn_end_write( test_funk );
  FD_TEST( funk_txn );
  return funk_txn;
}

/* Helper to create a test account */
static void
create_test_account( fd_pubkey_t const * pubkey,
                     fd_pubkey_t const * owner,
                     uchar const *       data,
                     ulong               data_len,
                     uchar               executable ) {
  FD_TXN_ACCOUNT_DECL( acc );
  int err = fd_txn_account_init_from_funk_mutable( /* acc         */ acc,
                                                   /* pubkey      */ pubkey,
                                                   /* funk        */ test_funk,
                                                   /* txn         */ test_slot_ctx->funk_txn,
                                                   /* do_create   */ 1,
                                                   /* min_data_sz */ data_len );
  FD_TEST( !err );

  if( data ) {
    acc->vt->set_data( acc, data, data_len );
  }

  acc->starting_lamports = 1UL;
  acc->starting_dlen     = data_len;
  acc->vt->set_lamports( acc, 1UL );
  acc->vt->set_executable( acc, executable );
  acc->vt->set_rent_epoch( acc, ULONG_MAX );
  acc->vt->set_owner( acc, owner );

  /* make the account read-only by default */
  acc->vt->set_readonly( acc );

  fd_txn_account_mutable_fini( acc, test_funk, test_slot_ctx->funk_txn );
}

/* Test 1: Account doesn't exist */
static void
test_account_does_not_exist( void ) {
  FD_LOG_NOTICE(( "Testing: Account doesn't exist" ));

  fd_funk_txn_t * funk_txn = create_test_funk_txn();
  test_slot_ctx->funk_txn = funk_txn;

  /* Call with a non-existent pubkey */
  fd_pubkey_t const non_existent_pubkey = {0};

  /* This should return early without doing anything */
  fd_bpf_program_update_program_cache( test_slot_ctx, &non_existent_pubkey, test_spad );

  /* Verify no cache entry was created */
  fd_sbpf_validated_program_t const * valid_prog = NULL;
  int err = fd_bpf_load_cache_entry( test_funk, funk_txn, &non_existent_pubkey, &valid_prog );
  FD_TEST( err==-1 ); /* Should not exist */

  fd_funk_txn_cancel( test_funk, funk_txn, 0 );
}

/* Test 2: Account exists but is not owned by a BPF loader */
static void
test_account_not_bpf_loader_owner( void ) {
  FD_LOG_NOTICE(( "Testing: Account exists but is not owned by a BPF loader" ));

  fd_funk_txn_t * funk_txn = create_test_funk_txn();
  test_slot_ctx->funk_txn = funk_txn;

  /* Create an account owned by a non-BPF loader */
  create_test_account( &test_program_pubkey,
                       &fd_solana_system_program_id,
                       invalid_program_data,
                       sizeof(invalid_program_data),
                       1 );

  /* This should return early without doing anything */
  fd_bpf_program_update_program_cache( test_slot_ctx, &test_program_pubkey, test_spad );

  /* Verify no cache entry was created */
  fd_sbpf_validated_program_t const * valid_prog = NULL;
  int err = fd_bpf_load_cache_entry( test_funk, funk_txn, &test_program_pubkey, &valid_prog );
  FD_TEST( err==-1 ); /* Should not exist */

  fd_funk_txn_cancel( test_funk, funk_txn, 0 );
}

/* Test 3: Program is not in cache yet (first time), but program fails validations */
static void
test_invalid_program_not_in_cache_first_time( void ) {
  FD_LOG_NOTICE(( "Testing: Program is not in cache yet (first time), but program fails validations" ));

  fd_funk_txn_t * funk_txn = create_test_funk_txn();
  test_slot_ctx->funk_txn = funk_txn;

  /* Create a BPF loader account */
  create_test_account( &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       invalid_program_data,
                       sizeof(invalid_program_data),
                       1 );

  /* This should create a cache entry */
  fd_bpf_program_update_program_cache( test_slot_ctx, &test_program_pubkey, test_spad );

  /* Verify cache entry was created */
  fd_sbpf_validated_program_t const * valid_prog = NULL;
  int err = fd_bpf_load_cache_entry( test_funk, funk_txn, &test_program_pubkey, &valid_prog );
  FD_TEST( !err ); /* Should exist */
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_SBPF_VALIDATED_PROGRAM_MAGIC );
  FD_TEST( valid_prog->failed_verification );

  fd_funk_txn_cancel( test_funk, funk_txn, 0 );
}

/* Test 4: Program is not in cache yet (first time), but program passes validations */
static void
test_valid_program_not_in_cache_first_time( void ) {
  FD_LOG_NOTICE(( "Testing: Program is not in cache yet (first time), but program passes validations" ));

  fd_funk_txn_t * funk_txn = create_test_funk_txn();
  test_slot_ctx->funk_txn = funk_txn;

  /* Create a BPF loader account */
  create_test_account( &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* This should create a cache entry */
  fd_bpf_program_update_program_cache( test_slot_ctx, &test_program_pubkey, test_spad );

  /* Verify cache entry was created */
  fd_sbpf_validated_program_t const * valid_prog = NULL;
  int err = fd_bpf_load_cache_entry( test_funk, funk_txn, &test_program_pubkey, &valid_prog );
  FD_TEST( !err ); /* Should exist */
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_SBPF_VALIDATED_PROGRAM_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_epoch_verification_ran==1UL );

  fd_funk_txn_cancel( test_funk, funk_txn, 0 );
}

/* Test 5: Program is in cache but needs reverification (different epoch) */
static void
test_program_in_cache_needs_reverification( void ) {
  FD_LOG_NOTICE(( "Testing: Program is in cache but needs reverification (different epoch)" ));

  fd_funk_txn_t * funk_txn = create_test_funk_txn();
  test_slot_ctx->funk_txn = funk_txn;

  /* Create a BPF loader account */
  create_test_account( &test_program_pubkey,
                       &fd_solana_bpf_loader_program_id,
                       valid_program_data,
                       valid_program_data_sz,
                       1 );

  /* First call to create cache entry */
  fd_bpf_program_update_program_cache( test_slot_ctx, &test_program_pubkey, test_spad );

  /* Verify cache entry was created */
  fd_sbpf_validated_program_t const * valid_prog = NULL;
  int err = fd_bpf_load_cache_entry( test_funk, funk_txn, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_SBPF_VALIDATED_PROGRAM_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_epoch_verification_ran==1UL );

  /* Fast forward to next epoch */
  test_slot_ctx->bank->slot += 432000UL;

  /* This should trigger reverification */
  fd_bpf_program_update_program_cache( test_slot_ctx, &test_program_pubkey, test_spad );

  /* Verify the cache entry was updated */
  err = fd_bpf_load_cache_entry( test_funk, funk_txn, &test_program_pubkey, &valid_prog );
  FD_TEST( !err );
  FD_TEST( valid_prog );
  FD_TEST( valid_prog->magic==FD_SBPF_VALIDATED_PROGRAM_MAGIC );
  FD_TEST( !valid_prog->failed_verification );
  FD_TEST( valid_prog->last_epoch_verification_ran==2UL );

  fd_funk_txn_cancel( test_funk, funk_txn, 0 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Starting BPF program cache tests" ));

    /* Create workspace */
  test_wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, 2UL, fd_log_cpu_id(), "test_wksp", 0UL );
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

    /* Create slot context */
    ulong slot_align = FD_EXEC_SLOT_CTX_ALIGN;
    ulong slot_footprint = FD_EXEC_SLOT_CTX_FOOTPRINT;
    uchar * slot_mem = fd_spad_alloc( test_spad, slot_align, slot_footprint );
    test_slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_mem ) );
    FD_TEST( test_slot_ctx );

    /* Set up slot context */
    test_slot_ctx->funk = test_funk;

    /* Set up bank */
    ulong        banks_footprint = fd_banks_footprint( 1UL );
    uchar *      banks_mem       = fd_wksp_alloc_laddr( test_wksp, fd_banks_align(), banks_footprint, TEST_WKSP_TAG );
    FD_TEST( banks_mem );

    fd_banks_t * banks = fd_banks_join( fd_banks_new( banks_mem, 1UL ) );
    FD_TEST( banks );
    fd_bank_t * bank = fd_banks_init_bank( banks, 433000UL ); // Epoch 1
    FD_TEST( bank );

    test_slot_ctx->bank  = bank;
    test_slot_ctx->banks = banks;

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
  } FD_SPAD_FRAME_END;

  test_teardown();

  FD_LOG_NOTICE(( "All BPF program cache tests passed" ));
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
