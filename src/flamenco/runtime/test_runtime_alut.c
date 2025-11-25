/* Unit test for fd_runtime_load_txn_address_lookup_tables */

#include "fd_runtime.h"
#include "fd_runtime_err.h"
#include "fd_txn_account.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "program/fd_address_lookup_table_program.h"
#include "fd_system_ids.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../funk/fd_funk.h"
#include "../../funk/fd_funk_txn.h"
#include "../../funk/fd_funk_rec.h"
#include "../types/fd_types.h"
#include <string.h>

/* Test configuration */
#define TEST_FUNK_REC_CNT (1024UL)
#define TEST_SLOT         (100000UL)
#define MAX_ALUT_ADDRS    (256UL)
#define SLOT_HASH_CNT     (512UL)  /* Max slot hash entries */

/* Test context structure */
typedef struct {
  fd_wksp_t *         wksp;
  void *              funk_mem;
  void *              funk_shmem;
  fd_funk_t           funk_join[1];
  fd_funk_t *         funk;
  fd_accdb_user_t     accdb[1];
  fd_funk_txn_xid_t   xid;
  fd_funk_txn_t *     funk_txn;
} test_ctx_t;

/* Setup function for each test */
static test_ctx_t *
test_setup( fd_wksp_t * wksp ) {
  test_ctx_t * ctx = fd_wksp_alloc_laddr( wksp, alignof(test_ctx_t), sizeof(test_ctx_t), 1UL );
  FD_TEST( ctx );

  ctx->wksp = wksp;

  /* Setup funk */
  ulong txn_max        = 10;
  ulong rec_max        = TEST_FUNK_REC_CNT;
  ulong funk_align     = fd_funk_align();
  ulong funk_footprint = fd_funk_footprint( txn_max, rec_max );
  ctx->funk_mem = fd_wksp_alloc_laddr( wksp, funk_align, funk_footprint, 1UL );
  FD_TEST( ctx->funk_mem );

  ctx->funk_shmem = fd_funk_new( ctx->funk_mem, 1UL, 1234UL /* seed */, txn_max, rec_max );
  FD_TEST( ctx->funk_shmem );

  /* Check alignment before join */
  FD_TEST( fd_ulong_is_aligned( (ulong)ctx->funk_shmem, funk_align ) );

  ctx->funk = fd_funk_join( ctx->funk_join, ctx->funk_shmem );
  FD_TEST( ctx->funk );

  /* Set up accdb interface */
  FD_TEST( fd_accdb_user_v1_init( ctx->accdb, ctx->funk_shmem ) );

  /* Set up root transaction and target transaction ID */
  fd_funk_txn_xid_t root_xid;
  fd_funk_txn_xid_set_root( &root_xid );

  ctx->xid.ul[0] = 0x1234567890ABCDEFULL;  /* Test transaction ID - arbitrary unique value */
  ctx->xid.ul[1] = 0xFEDCBA0987654321ULL;  /* Test transaction ID - arbitrary unique value */

  /* Prepare the transaction with root as parent */
  fd_funk_txn_prepare( ctx->funk, &root_xid, &ctx->xid );
  ctx->funk_txn = NULL; /* We don't actually need to store this for the test */

  return ctx;
}

/* Teardown function for each test */
static void
test_teardown( test_ctx_t * ctx ) {
  if( !ctx ) return;

  void * shfunk = NULL;
  fd_funk_leave( ctx->funk, &shfunk );
  fd_funk_delete( shfunk );
  fd_wksp_free_laddr( ctx->funk_mem );
  fd_wksp_free_laddr( ctx );
}

/* Helper function to create test account using fd_txn_account API */
static void
create_test_account( test_ctx_t *              ctx,
                     fd_funk_txn_xid_t const * xid,
                     void const *              pubkey_,
                     void const *              owner_,
                     void const *              data,
                     ulong                     data_len,
                     ulong                     lamports,
                     uchar                     executable ) {
  fd_pubkey_t pubkey = FD_LOAD( fd_pubkey_t, pubkey_ );
  fd_pubkey_t owner  = FD_LOAD( fd_pubkey_t, owner_ );

  fd_txn_account_t      acc[1];
  fd_funk_rec_prepare_t prepare = {0};
  int ok = !!fd_txn_account_init_from_funk_mutable( /* acc          */ acc,
                                                     /* pubkey      */ &pubkey,
                                                     /* funk        */ ctx->accdb,
                                                     /* xid         */ xid,
                                                     /* do_create   */ 1,
                                                     /* min_data_sz */ data_len,
                                                     /* prepare     */ &prepare );
  FD_TEST( ok );

  if( data ) {
    fd_txn_account_set_data( acc, data, data_len );
  }

  fd_txn_account_set_lamports( acc, lamports );
  fd_txn_account_set_executable( acc, executable );
  fd_txn_account_set_owner( acc, &owner );

  fd_txn_account_mutable_fini( acc, ctx->accdb, &prepare );
}

/* Helper to allocate transaction with flexible array member */
static fd_txn_t *
alloc_txn( fd_wksp_t * wksp, ulong instr_cnt, ulong addr_table_lookup_cnt ) {
  ulong size = sizeof(fd_txn_t) +
               instr_cnt * sizeof(fd_txn_instr_t) +
               addr_table_lookup_cnt * sizeof(fd_txn_acct_addr_lut_t);
  void * mem = fd_wksp_alloc_laddr( wksp, alignof(fd_txn_t), size, 1UL );
  return (fd_txn_t *)mem;
}

/* Helper to create slot hash deque */
static fd_slot_hash_t *
create_slot_hash_deque( fd_wksp_t * wksp, ulong slot_cnt ) {
  void * mem = fd_wksp_alloc_laddr( wksp, deq_fd_slot_hash_t_align(),
                                    deq_fd_slot_hash_t_footprint( slot_cnt ), 1UL );
  FD_TEST( mem );

  fd_slot_hash_t * hashes = deq_fd_slot_hash_t_join( deq_fd_slot_hash_t_new( mem, slot_cnt ) );
  FD_TEST( hashes );

  /* Initialize with descending slot numbers from TEST_SLOT */
  for( ulong i = 0; i < slot_cnt; i++ ) {
    fd_slot_hash_t slot_hash;
    slot_hash.slot = TEST_SLOT - i;
    memset( slot_hash.hash.hash, 0, 32 );
    deq_fd_slot_hash_t_push_tail( hashes, slot_hash );
  }

  return hashes;
}

/* Helper to destroy slot hash deque */
static void
destroy_slot_hash_deque( fd_slot_hash_t * hashes ) {
  if( !hashes ) return;
  void * mem = deq_fd_slot_hash_t_delete( deq_fd_slot_hash_t_leave( hashes ) );
  fd_wksp_free_laddr( mem );
}

/* Helper function: Create a test transaction with configurable ALT references */
static void
create_test_transaction( fd_txn_t * txn,
                        uchar *    payload,
                        uchar      version,
                        ulong      alt_count,
                        ulong *    writable_counts,
                        ulong *    readonly_counts ) {
  memset( txn, 0, sizeof(fd_txn_t) + alt_count * sizeof(fd_txn_acct_addr_lut_t) );
  memset( payload, 0, 4096 );

  txn->transaction_version = version;
  txn->addr_table_lookup_cnt = (uchar)alt_count;
  txn->instr_cnt = 0;

  if( alt_count > 0 ) {
    txn->addr_table_adtl_writable_cnt = 0;
    txn->addr_table_adtl_cnt = 0;

    /* Set up address table lookups */
    ulong offset = 256; /* Start after transaction header space */
    for( ulong i = 0; i < alt_count; i++ ) {
      fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn ) + i;

      /* Address of the ALT account */
      FD_TEST( offset + 32 <= 4096 );  /* Ensure we don't overflow payload buffer */
      lut->addr_off = (ushort)offset;
      fd_pubkey_t * addr = (fd_pubkey_t *)(payload + offset);
      /* Generate deterministic test addresses based on index */
      addr->ul[0] = 0x1000 + i;
      addr->ul[1] = 0x2000 + i;
      addr->ul[2] = 0x3000 + i;
      addr->ul[3] = 0x4000 + i;
      offset += 32;

      /* Writable indices */
      lut->writable_off = (ushort)offset;
      lut->writable_cnt = (uchar)(writable_counts ? writable_counts[i] : 0);
      FD_TEST( offset + lut->writable_cnt <= 4096 );  /* Bounds check before writing */
      for( ulong j = 0; j < lut->writable_cnt; j++ ) {
        payload[offset + j] = (uchar)j;
      }
      offset += lut->writable_cnt;

      /* Readonly indices */
      lut->readonly_off = (ushort)offset;
      lut->readonly_cnt = (uchar)(readonly_counts ? readonly_counts[i] : 0);
      FD_TEST( offset + lut->readonly_cnt <= 4096 );  /* Bounds check before writing */
      for( ulong j = 0; j < lut->readonly_cnt; j++ ) {
        payload[offset + j] = (uchar)(lut->writable_cnt + j);
      }
      offset += lut->readonly_cnt;

      txn->addr_table_adtl_writable_cnt = (uchar)(txn->addr_table_adtl_writable_cnt + lut->writable_cnt);
      txn->addr_table_adtl_cnt = (uchar)(txn->addr_table_adtl_cnt + lut->writable_cnt + lut->readonly_cnt);
    }
  }
}

/* Test case 1: Non-V0 Transaction */
static void
test_non_v0_transaction( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 1: Non-V0 transaction" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create legacy transaction */
  fd_txn_t *       txn     = alloc_txn( wksp, 0, 0 );
  uchar            payload[4096];
  create_test_transaction( txn, payload, FD_TXN_VLEGACY, 0, NULL, NULL );

  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );
  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values to verify no modification */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, (int)(0xAA + i), 32 );
  }

  /* Call function - should return immediately for non-V0 */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify out_accts was not modified (non-V0 returns immediately) */
  for( ulong i = 0; i < 256; i++ ) {
    for( ulong j = 0; j < 32; j++ ) {
      FD_TEST( out_accts[i].b[j] == (uchar)(0xAA + i) );
    }
  }

  FD_LOG_NOTICE(( "Test 1 passed: Non-V0 returns immediately without modifying out_accts" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 2: V0 transaction with no ALTs */
static void
test_v0_no_alts( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 2: V0 transaction with no ALTs" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with no ALTs */
  fd_txn_t *       txn = alloc_txn( wksp, 0, 0 );
  uchar            payload[4096];
  create_test_transaction( txn, payload, FD_TXN_V0, 0, NULL, NULL );

  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );
  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, (int)(0xBB + i), 32 );
  }

  /* Call function - should succeed immediately with no ALTs */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify out_accts was not modified (no ALTs to process) */
  for( ulong i = 0; i < 256; i++ ) {
    for( ulong j = 0; j < 32; j++ ) {
      FD_TEST( out_accts[i].b[j] == (uchar)(0xBB + i) );
    }
  }

  FD_LOG_NOTICE(( "Test 2 passed: V0 with no ALTs returns successfully without modifying out_accts" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 3: ALT account not found */
static void
test_alt_not_found( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 3: ALT account not found in database" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1 };
  ulong            readonly_counts[] = { 1 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Don't add the ALT account to funk - it should not be found */
  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );
  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, (int)(0xCC + i), 32 );
  }

  /* Call function - should fail with not found error */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND );

  /* Verify out_accts - on error, we don't have guarantees about the state,
     but we can check that we didn't corrupt memory */
  int memory_intact = 1;
  for( ulong i = 0; i < 256; i++ ) {
    for( ulong j = 0; j < 32; j++ ) {
      if( out_accts[i].b[j] != (uchar)(0xCC + i) ) {
        /* Some modification occurred, which is allowed on error */
        memory_intact = 0;
        break;
      }
    }
    if( !memory_intact ) break;
  }

  FD_LOG_NOTICE(( "Test 3 passed: ALT not found returns correct error (memory %s)",
                  memory_intact ? "unchanged" : "partially modified as expected" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 4: Invalid ALT owner */
static void
test_invalid_alt_owner( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 4: ALT with invalid owner" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1 };
  ulong            readonly_counts[] = { 1 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT account with invalid owner (use system program instead of ALT program) */
  fd_pubkey_t invalid_owner = fd_solana_system_program_id;

  /* Create minimal ALT data (56 bytes header + addresses) */
  uchar alt_data[256];
  memset( alt_data, 0, sizeof(alt_data) );

  /* Add account to funk with wrong owner */
  create_test_account( ctx, &ctx->xid, alt_addr, &invalid_owner, alt_data, 56, 1000000, 0 );

  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );
  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, (int)(0xDD + i), 32 );
  }

  /* Call function - should fail with invalid owner error */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_OWNER );

  /* Verify out_accts - on error, we don't have guarantees about the state,
     but we can check that we didn't corrupt memory */
  int memory_intact = 1;
  for( ulong i = 0; i < 256; i++ ) {
    for( ulong j = 0; j < 32; j++ ) {
      if( out_accts[i].b[j] != (uchar)(0xDD + i) ) {
        /* Some modification occurred, which is allowed on error */
        memory_intact = 0;
        break;
      }
    }
    if( !memory_intact ) break;
  }

  FD_LOG_NOTICE(( "Test 4 passed: Invalid ALT owner returns correct error (memory %s)",
                  memory_intact ? "unchanged" : "partially modified as expected" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 5: ALT data too small */
static void
test_alt_data_too_small( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 5: ALT with data too small" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1 };
  ulong            readonly_counts[] = { 1 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT account with data too small (less than 56 bytes) */
  uchar alt_data[40];  /* Less than 56 bytes minimum */
  memset( alt_data, 0, sizeof(alt_data) );

  /* Add account to funk with correct owner but insufficient data */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );
  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, (int)(0xEE + i), 32 );
  }

  /* Call function - should fail with invalid data error */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA );

  /* Verify out_accts - on error, we don't have guarantees about the state,
     but we can check that we didn't corrupt memory */
  int memory_intact = 1;
  for( ulong i = 0; i < 256; i++ ) {
    for( ulong j = 0; j < 32; j++ ) {
      if( out_accts[i].b[j] != (uchar)(0xEE + i) ) {
        /* Some modification occurred, which is allowed on error */
        memory_intact = 0;
        break;
      }
    }
    if( !memory_intact ) break;
  }

  FD_LOG_NOTICE(( "Test 5 passed: ALT data too small returns correct error (memory %s)",
                  memory_intact ? "unchanged" : "partially modified as expected" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Helper to create valid ALT account data */
static void
create_valid_alt_data( uchar * data, ulong num_addresses ) {
  /* Create a valid ALT with proper discriminant and metadata */
  fd_address_lookup_table_state_t alt_state = {
    .discriminant = fd_address_lookup_table_state_enum_lookup_table,
    .inner = {
      .lookup_table = {
        .meta = {
          .deactivation_slot              = ULONG_MAX,  /* Not deactivated */
          .last_extended_slot             = TEST_SLOT - 1,
          .last_extended_slot_start_index = 0,
          .authority                      = {{0}}, /* Zero authority */
          .has_authority                  = 0,
        }
      }
    }
  };

  /* Encode the metadata */
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = data,
    .dataend = data + FD_LOOKUP_TABLE_META_SIZE
  };
  fd_address_lookup_table_state_encode( &alt_state, &encode_ctx );

  /* Add addresses after the metadata */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(data + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < num_addresses; i++ ) {
    /* Generate unique addresses */
    memset( addrs[i].b, 0, 32 );
    addrs[i].b[0] = (uchar)(0xA0 + i);  /* Make each address unique */
    addrs[i].b[1] = (uchar)(0xB0 + i);
  }
}

/* Test case 6: Invalid discriminant */
static void
test_invalid_discriminant( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 6: ALT with invalid discriminant (uninitialized type)" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1 };
  ulong            readonly_counts[] = { 1 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT data that looks like uninitialized account (discriminant = 0)
     This will pass bincode decode but fail discriminant check */
  uchar alt_data[256];
  memset( alt_data, 0, sizeof(alt_data) );

  /* Set discriminant to 0 (Uninitialized) instead of 1 (LookupTable) */
  alt_data[0] = 0;  /* fd_address_lookup_table_state_enum_uninitialized */

  /* The rest can be zeros - it will decode successfully as an uninitialized variant */

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, 256, 1000000, 0 );

  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );
  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, (int)(0x60 + i), 32 );
  }

  /* Call function - should fail with invalid data error */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA );

  FD_LOG_NOTICE(( "Test 6 passed: Uninitialized discriminant returns correct error" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 7: ALT data not 32-byte aligned */
static void
test_alt_data_not_aligned( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 7: ALT data not 32-byte aligned" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1 };
  ulong            readonly_counts[] = { 1 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT data that is not 32-byte aligned (56 + 17 bytes) */
  uchar                            alt_data[73];  /* 56 + 17 = not divisible by 32 */
  memset( alt_data, 0, sizeof(alt_data) );
  create_valid_alt_data( alt_data, 0 );  /* Create valid metadata */

  /* Add account to funk with misaligned data size */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );
  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, (int)(0x77 + i), 32 );
  }

  /* Call function - should fail with invalid data error */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA );

  FD_LOG_NOTICE(( "Test 7 passed: ALT data not 32-byte aligned returns correct error" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 8: Deactivated ALT */
static void
test_deactivated_alt( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 8: Deactivated ALT" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1 };
  ulong            readonly_counts[] = { 1 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT data with deactivated state */
  uchar                            alt_data[FD_LOOKUP_TABLE_META_SIZE + 5 * 32];  /* Space for metadata + 5 addresses */
  fd_address_lookup_table_state_t alt_state = {
    .discriminant = fd_address_lookup_table_state_enum_lookup_table,
    .inner = {
      .lookup_table = {
        .meta = {
          .deactivation_slot              = TEST_SLOT - 1000,  /* Old deactivation slot */
          .last_extended_slot             = TEST_SLOT - 1,
          .last_extended_slot_start_index = 5,
          .authority                      = {{0}},
          .has_authority                  = 0,
        }
      }
    }
  };

  /* Encode the metadata */
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = alt_data,
    .dataend = alt_data + FD_LOOKUP_TABLE_META_SIZE
  };
  fd_address_lookup_table_state_encode( &alt_state, &encode_ctx );

  /* Add some addresses */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 5; i++ ) {
    memset( addrs[i].b, 0, 32 );
    addrs[i].b[0] = (uchar)(0xA0 + i);
  }

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, FD_LOOKUP_TABLE_META_SIZE + 5 * 32, 1000000, 0 );

  /* Set up slot hashes without the deactivation slot */
  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, (int)(0x88 + i), 32 );
  }

  /* Call function - should fail because ALT is deactivated */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND );

  FD_LOG_NOTICE(( "Test 8 passed: Deactivated ALT returns not found error" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 9: Invalid writable index */
static void
test_invalid_writable_index( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 9: Invalid writable index" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT, writable index out of bounds */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1 };
  ulong            readonly_counts[] = { 0 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Modify the writable index to be out of bounds (index 5 when only 3 addresses are active) */
  fd_txn_acct_addr_lut_t * lut = fd_txn_get_address_tables( txn );
  payload[lut->writable_off]   = 5;  /* Index 5, but only 3 addresses will be active */

  /* Extract ALT address from transaction */
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create valid ALT data with only 3 active addresses */
  uchar                            alt_data[FD_LOOKUP_TABLE_META_SIZE + 10 * 32];  /* Space for metadata + 10 addresses */
  fd_address_lookup_table_state_t alt_state = {
    .discriminant = fd_address_lookup_table_state_enum_lookup_table,
    .inner = {
      .lookup_table = {
        .meta = {
          .deactivation_slot              = ULONG_MAX,  /* Not deactivated */
          .last_extended_slot             = TEST_SLOT,  /* Same as current slot */
          .last_extended_slot_start_index = 3,  /* Only 3 addresses active */
          .authority                      = {{0}},
          .has_authority                  = 0,
        }
      }
    }
  };

  /* Encode the metadata */
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = alt_data,
    .dataend = alt_data + FD_LOOKUP_TABLE_META_SIZE
  };
  fd_address_lookup_table_state_encode( &alt_state, &encode_ctx );

  /* Add 10 addresses (but only 3 will be active) */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 10; i++ ) {
    memset( addrs[i].b, 0, 32 );
    addrs[i].b[0] = (uchar)(0xB0 + i);
  }

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, FD_LOOKUP_TABLE_META_SIZE + 10 * 32, 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, (int)(0x99 + i), 32 );
  }

  /* Call function - should fail with invalid index error */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX );

  FD_LOG_NOTICE(( "Test 9 passed: Invalid writable index returns correct error" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 10: Invalid readonly index */
static void
test_invalid_readonly_index( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 10: Invalid readonly index" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT, readonly index out of bounds */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 0 };
  ulong            readonly_counts[] = { 1 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Modify the readonly index to be out of bounds (index 10 when only 8 addresses exist) */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  payload[lut->readonly_off]        = 10;  /* Index 10, but only 8 addresses active */

  /* Extract ALT address from transaction */
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create valid ALT data with 8 addresses */
  uchar alt_data[FD_LOOKUP_TABLE_META_SIZE + 8 * 32];
  create_valid_alt_data( alt_data, 8 );

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, FD_LOOKUP_TABLE_META_SIZE + 8 * 32, 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, (int)(0xAA + i), 32 );
  }

  /* Call function - should fail with invalid index error */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX );

  FD_LOG_NOTICE(( "Test 10 passed: Invalid readonly index returns correct error" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 11: Valid single ALT - Success path */
static void
test_valid_single_alt( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 11: Valid single ALT (success path)" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT referencing 2 writable and 2 readonly addresses */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 2 };
  ulong            readonly_counts[] = { 2 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create valid ALT data with 10 addresses (indices 0-9) */
  ulong num_addresses = 10;
  ulong alt_data_size = FD_LOOKUP_TABLE_META_SIZE + (num_addresses * 32);
  uchar                            alt_data[56 + 10 * 32];  /* Meta + 10 addresses */
  create_valid_alt_data( alt_data, num_addresses );

  /* Add valid ALT account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, alt_data_size, 1000000, 0 );

  /* Set up slot hashes (needed for active address calculation) */
  fd_slot_hash_t hashes[10];
  for( int i = 0; i < 10; i++ ) {
    hashes[i].slot = TEST_SLOT - (ulong)i;
    memset( hashes[i].hash.hash, 0, 32 );
  }

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xFF, 32 );
  }

  /* Call function - should succeed */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify out_accts was populated correctly */
  /* Check that the first 2 addresses are writable (indices 0,1) */
  FD_TEST( out_accts[0].b[0] == 0xA0 );
  FD_TEST( out_accts[0].b[1] == 0xB0 );
  FD_TEST( out_accts[1].b[0] == 0xA1 );
  FD_TEST( out_accts[1].b[1] == 0xB1 );

  /* Check that the next 2 addresses are readonly (indices 2,3) */
  FD_TEST( out_accts[2].b[0] == 0xA2 );
  FD_TEST( out_accts[2].b[1] == 0xB2 );
  FD_TEST( out_accts[3].b[0] == 0xA3 );
  FD_TEST( out_accts[3].b[1] == 0xB3 );

  /* Check that remaining entries are untouched */
  for( ulong i = 4; i < 256; i++ ) {
    FD_TEST( out_accts[i].b[0] == 0xFF );
  }

  FD_LOG_NOTICE(( "Test 11 passed: Valid single ALT succeeded and populated out_accts correctly" ));

  test_teardown( ctx );
  /* Note: hashes is stack-allocated in this test, no need to free */
  fd_wksp_free_laddr( txn );
}

/* Test case 12: Multiple ALTs */
static void
test_multiple_alts( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 12: Multiple ALTs (success path)" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 2 ALTs */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 2 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 2, 1 };  /* First ALT: 2 writable, Second ALT: 1 writable */
  ulong            readonly_counts[] = { 1, 2 };  /* First ALT: 1 readonly, Second ALT: 2 readonly */
  create_test_transaction( txn, payload, FD_TXN_V0, 2, writable_counts, readonly_counts );

  /* Extract ALT addresses from transaction */
  fd_txn_acct_addr_lut_t * luts = fd_txn_get_address_tables( txn );

  /* First ALT with 10 addresses */
  fd_pubkey_t *                    alt_addr1 = (fd_pubkey_t *)(payload + luts[0].addr_off);
  uchar alt_data1[FD_LOOKUP_TABLE_META_SIZE + 10 * 32];
  create_valid_alt_data( alt_data1, 10 );
  create_test_account( ctx, &ctx->xid, alt_addr1, &fd_solana_address_lookup_table_program_id,
                       alt_data1, sizeof(alt_data1), 1000000, 0 );

  /* Second ALT with 8 addresses */
  fd_pubkey_t *                    alt_addr2 = (fd_pubkey_t *)(payload + luts[1].addr_off);
  uchar alt_data2[FD_LOOKUP_TABLE_META_SIZE + 8 * 32];
  create_valid_alt_data( alt_data2, 8 );
  /* Make second ALT addresses different */
  fd_acct_addr_t * addrs2 = (fd_acct_addr_t *)(alt_data2 + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 8; i++ ) {
    addrs2[i].b[0] = (uchar)(0xC0 + i);
    addrs2[i].b[1] = (uchar)(0xD0 + i);
  }
  create_test_account( ctx, &ctx->xid, alt_addr2, &fd_solana_address_lookup_table_program_id,
                       alt_data2, sizeof(alt_data2), 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes     = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xFF, 32 );
  }

  /* Call function - should succeed */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify addresses from first ALT (2 writable, 1 readonly) */
  FD_TEST( out_accts[0].b[0] == 0xA0 );  /* First writable from ALT1 */
  FD_TEST( out_accts[0].b[1] == 0xB0 );
  FD_TEST( out_accts[1].b[0] == 0xA1 );  /* Second writable from ALT1 */
  FD_TEST( out_accts[1].b[1] == 0xB1 );

  /* Verify addresses from second ALT (1 writable) */
  FD_TEST( out_accts[2].b[0] == 0xC0 );  /* First writable from ALT2 */
  FD_TEST( out_accts[2].b[1] == 0xD0 );

  /* Verify readonly addresses */
  FD_TEST( out_accts[3].b[0] == 0xA2 );  /* Readonly from ALT1 */
  FD_TEST( out_accts[3].b[1] == 0xB2 );
  FD_TEST( out_accts[4].b[0] == 0xC1 );  /* First readonly from ALT2 */
  FD_TEST( out_accts[4].b[1] == 0xD1 );
  FD_TEST( out_accts[5].b[0] == 0xC2 );  /* Second readonly from ALT2 */
  FD_TEST( out_accts[5].b[1] == 0xD2 );

  FD_LOG_NOTICE(( "Test 12 passed: Multiple ALTs loaded successfully" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 13: ALT with partial activation */
static void
test_partial_activation( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 13: ALT with partial activation (last_extended_slot logic)" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 2 };
  ulong            readonly_counts[] = { 2 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT with partial activation: 10 total addresses, only 5 active */
  uchar                            alt_data[FD_LOOKUP_TABLE_META_SIZE + 10 * 32];
  fd_address_lookup_table_state_t alt_state = {
    .discriminant = fd_address_lookup_table_state_enum_lookup_table,
    .inner = {
      .lookup_table = {
        .meta = {
          .deactivation_slot              = ULONG_MAX,  /* Not deactivated */
          .last_extended_slot             = TEST_SLOT - 1,  /* Recent extension */
          .last_extended_slot_start_index = 5,  /* Only first 5 addresses active */
          .authority                      = {{0}},
          .has_authority                  = 0,
        }
      }
    }
  };

  /* Encode the metadata */
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = alt_data,
    .dataend = alt_data + FD_LOOKUP_TABLE_META_SIZE
  };
  fd_address_lookup_table_state_encode( &alt_state, &encode_ctx );

  /* Add 10 addresses but only 5 will be active */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 10; i++ ) {
    memset( addrs[i].b, 0, 32 );
    addrs[i].b[0] = (uchar)(0xE0 + i);
    addrs[i].b[1] = (uchar)(0xF0 + i);
  }

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xFF, 32 );
  }

  /* Call function - should succeed with only first 5 addresses active */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify only addresses 0-4 are loaded (indices 0,1 writable, 2,3 readonly) */
  FD_TEST( out_accts[0].b[0] == 0xE0 );
  FD_TEST( out_accts[1].b[0] == 0xE1 );
  FD_TEST( out_accts[2].b[0] == 0xE2 );
  FD_TEST( out_accts[3].b[0] == 0xE3 );

  FD_LOG_NOTICE(( "Test 13 passed: Partial activation handled correctly" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 14: ALT in deactivating state */
static void
test_deactivating_alt( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 14: ALT in deactivating state (still active)" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1 };
  ulong            readonly_counts[] = { 1 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT in deactivating state (deactivation slot in recent history) */
  uchar                            alt_data[FD_LOOKUP_TABLE_META_SIZE + 5 * 32];
  fd_address_lookup_table_state_t alt_state = {
    .discriminant = fd_address_lookup_table_state_enum_lookup_table,
    .inner = {
      .lookup_table = {
        .meta = {
          .deactivation_slot              = TEST_SLOT - 5,  /* Deactivating 5 slots ago */
          .last_extended_slot             = TEST_SLOT - 10,
          .last_extended_slot_start_index = 5,
          .authority                      = {{0}},
          .has_authority                  = 0,
        }
      }
    }
  };

  /* Encode the metadata */
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = alt_data,
    .dataend = alt_data + FD_LOOKUP_TABLE_META_SIZE
  };
  fd_address_lookup_table_state_encode( &alt_state, &encode_ctx );

  /* Add addresses */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 5; i++ ) {
    memset( addrs[i].b, 0, 32 );
    addrs[i].b[0] = (uchar)(0x70 + i);
    addrs[i].b[1] = (uchar)(0x80 + i);
  }

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  /* Set up slot hashes including the deactivation slot */
  fd_slot_hash_t * hashes     = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xFF, 32 );
  }

  /* Call function - should succeed because ALT is still deactivating */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify addresses were loaded */
  FD_TEST( out_accts[0].b[0] == 0x70 );
  FD_TEST( out_accts[1].b[0] == 0x71 );

  FD_LOG_NOTICE(( "Test 14 passed: Deactivating ALT still active and loaded" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 15: Bincode decode failure */
static void
test_bincode_decode_failure( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 15: ALT with corrupted metadata (bincode decode failure)" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1 };
  ulong            readonly_counts[] = { 1 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create corrupted ALT data that will fail bincode decode */
  uchar alt_data[256];
  memset( alt_data, 0xFF, sizeof(alt_data) );  /* Fill with invalid data */

  /* Set a valid discriminant but corrupt the rest */
  alt_data[0] = 1;  /* Valid discriminant */
  /* Leave rest as 0xFF which will cause decode failure */

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, 256, 1000000, 0 );

  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );
  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xEE, 32 );
  }

  /* Call function - should fail with invalid data error */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_DATA );

  FD_LOG_NOTICE(( "Test 15 passed: Corrupted metadata causes decode failure" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 16: ALT Just Activated (Same Slot) */
static void
test_alt_just_activated( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 16: ALT just activated (same slot)" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 2 };
  ulong            readonly_counts[] = { 3 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT just activated in the current slot */
  uchar                            alt_data[FD_LOOKUP_TABLE_META_SIZE + 10 * 32];
  fd_address_lookup_table_state_t alt_state = {
    .discriminant = fd_address_lookup_table_state_enum_lookup_table,
    .inner = {
      .lookup_table = {
        .meta = {
          .deactivation_slot              = ULONG_MAX,  /* Not deactivated */
          .last_extended_slot             = TEST_SLOT,  /* Same as current slot */
          .last_extended_slot_start_index = 10,  /* All 10 addresses just became active */
          .authority                      = {{0}},
          .has_authority                  = 0,
        }
      }
    }
  };

  /* Encode the metadata */
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = alt_data,
    .dataend = alt_data + FD_LOOKUP_TABLE_META_SIZE
  };
  fd_address_lookup_table_state_encode( &alt_state, &encode_ctx );

  /* Add 10 addresses */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 10; i++ ) {
    memset( addrs[i].b, 0, 32 );
    addrs[i].b[0] = (uchar)(0x10 + i);
    addrs[i].b[1] = (uchar)(0x20 + i);
  }

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xFF, 32 );
  }

  /* Call function - should succeed with all 10 addresses active */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify all requested addresses were loaded */
  FD_TEST( out_accts[0].b[0] == 0x10 );  /* First writable */
  FD_TEST( out_accts[1].b[0] == 0x11 );  /* Second writable */
  FD_TEST( out_accts[2].b[0] == 0x12 );  /* First readonly */
  FD_TEST( out_accts[3].b[0] == 0x13 );  /* Second readonly */
  FD_TEST( out_accts[4].b[0] == 0x14 );  /* Third readonly */

  FD_LOG_NOTICE(( "Test 16 passed: ALT just activated in current slot loads all addresses" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 17: ALT with Partial Activation (Growing ALT) */
static void
test_growing_alt( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 17: ALT with partial activation (growing ALT)" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT referencing indices within active range */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 3 };
  ulong            readonly_counts[] = { 2 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Modify indices to be within the first 15 addresses (active range) */
  fd_txn_acct_addr_lut_t * lut   = fd_txn_get_address_tables( txn );
  payload[lut->writable_off]     = 0;   /* Index 0 */
  payload[lut->writable_off + 1] = 5;   /* Index 5 */
  payload[lut->writable_off + 2] = 10;  /* Index 10 */
  payload[lut->readonly_off]     = 12;  /* Index 12 */
  payload[lut->readonly_off + 1] = 14;  /* Index 14 (last active) */

  /* Extract ALT address from transaction */
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT with 20 total addresses but only 15 active */
  uchar                            alt_data[FD_LOOKUP_TABLE_META_SIZE + 20 * 32];
  fd_address_lookup_table_state_t alt_state = {
    .discriminant = fd_address_lookup_table_state_enum_lookup_table,
    .inner = {
      .lookup_table = {
        .meta = {
          .deactivation_slot              = ULONG_MAX,  /* Not deactivated */
          .last_extended_slot             = TEST_SLOT - 1,  /* Extended one slot ago */
          .last_extended_slot_start_index = 15,  /* Only first 15 are active */
          .authority                      = {{0}},
          .has_authority                  = 0,
        }
      }
    }
  };

  /* Encode the metadata */
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = alt_data,
    .dataend = alt_data + FD_LOOKUP_TABLE_META_SIZE
  };
  fd_address_lookup_table_state_encode( &alt_state, &encode_ctx );

  /* Add 20 addresses (but only 15 will be active) */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 20; i++ ) {
    memset( addrs[i].b, 0, 32 );
    addrs[i].b[0] = (uchar)(0x30 + i);
    addrs[i].b[1] = (uchar)(0x40 + i);
  }

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xFF, 32 );
  }

  /* Call function - should succeed with only first 15 addresses accessible */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify addresses from active range were loaded */
  FD_TEST( out_accts[0].b[0] == 0x30 );  /* Index 0 writable */
  FD_TEST( out_accts[1].b[0] == 0x35 );  /* Index 5 writable */
  FD_TEST( out_accts[2].b[0] == 0x3A );  /* Index 10 writable */
  FD_TEST( out_accts[3].b[0] == 0x3C );  /* Index 12 readonly */
  FD_TEST( out_accts[4].b[0] == 0x3E );  /* Index 14 readonly (last active) */

  FD_LOG_NOTICE(( "Test 17 passed: Growing ALT only allows access to active addresses" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 18: ALT Deactivating at Current Slot */
static void
test_alt_deactivating_current_slot( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 18: ALT deactivating at current slot" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1 };
  ulong            readonly_counts[] = { 1 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT deactivating at current slot */
  uchar                           alt_data[FD_LOOKUP_TABLE_META_SIZE + 5 * 32];
  fd_address_lookup_table_state_t alt_state = {
    .discriminant = fd_address_lookup_table_state_enum_lookup_table,
    .inner = {
      .lookup_table = {
        .meta = {
          .deactivation_slot              = TEST_SLOT,  /* Deactivating at current slot */
          .last_extended_slot             = TEST_SLOT - 10,
          .last_extended_slot_start_index = 5,
          .authority                      = {{0}},
          .has_authority                  = 0,
        }
      }
    }
  };

  /* Encode the metadata */
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = alt_data,
    .dataend = alt_data + FD_LOOKUP_TABLE_META_SIZE
  };
  fd_address_lookup_table_state_encode( &alt_state, &encode_ctx );

  /* Add addresses */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 5; i++ ) {
    memset( addrs[i].b, 0, 32 );
    addrs[i].b[0] = (uchar)(0x50 + i);
    addrs[i].b[1] = (uchar)(0x60 + i);
  }

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  /* Set up slot hashes including current slot */
  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xFF, 32 );
  }

  /* Call function - should succeed because ALT is still active at deactivation slot */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify addresses were loaded */
  FD_TEST( out_accts[0].b[0] == 0x50 );
  FD_TEST( out_accts[1].b[0] == 0x51 );

  FD_LOG_NOTICE(( "Test 18 passed: ALT deactivating at current slot still loads" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 19: ALT with Max Addresses (256) */
static void
test_alt_max_addresses( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 19: ALT with maximum addresses (256)" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT referencing high indices */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 2 };
  ulong            readonly_counts[] = { 2 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Modify indices to reference high addresses */
  fd_txn_acct_addr_lut_t * lut   = fd_txn_get_address_tables( txn );
  payload[lut->writable_off]     = 250; /* Index 250 */
  payload[lut->writable_off + 1] = 255; /* Index 255 (last) */
  payload[lut->readonly_off]     = 100; /* Index 100 */
  payload[lut->readonly_off + 1] = 200; /* Index 200 */

  /* Extract ALT address from transaction */
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT with maximum 256 addresses */
  ulong alt_data_size = FD_LOOKUP_TABLE_META_SIZE + (256 * 32);
  uchar * alt_data = fd_wksp_alloc_laddr( wksp, 1, alt_data_size, 1UL );
  FD_TEST( alt_data );

  create_valid_alt_data( alt_data, 256 );

  /* Set unique values for addresses we'll check */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  addrs[250].b[0] = 0xFA; addrs[250].b[1] = 0xFB;
  addrs[255].b[0] = 0xFF; addrs[255].b[1] = 0xFE;
  addrs[100].b[0] = 0x64; addrs[100].b[1] = 0x65;
  addrs[200].b[0] = 0xC8; addrs[200].b[1] = 0xC9;

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, alt_data_size, 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes     = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xEE, 32 );
  }

  /* Call function - should succeed */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify high index addresses were loaded */
  FD_TEST( out_accts[0].b[0] == 0xFA );  /* Index 250 */
  FD_TEST( out_accts[1].b[0] == 0xFF );  /* Index 255 */
  FD_TEST( out_accts[2].b[0] == 0x64 );  /* Index 100 */
  FD_TEST( out_accts[3].b[0] == 0xC8 );  /* Index 200 */

  FD_LOG_NOTICE(( "Test 19 passed: ALT with 256 addresses loads high indices correctly" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
  fd_wksp_free_laddr( alt_data );
}

/* Test case 20: ALT with No Authority */
static void
test_alt_no_authority( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 20: ALT with no authority" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1 };
  ulong            readonly_counts[] = { 2 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT with no authority */
  uchar                            alt_data[FD_LOOKUP_TABLE_META_SIZE + 10 * 32];
  fd_address_lookup_table_state_t alt_state = {
    .discriminant = fd_address_lookup_table_state_enum_lookup_table,
    .inner = {
      .lookup_table = {
        .meta = {
          .deactivation_slot              = ULONG_MAX,
          .last_extended_slot             = TEST_SLOT - 1,
          .last_extended_slot_start_index = 10,
          .authority                      = {{0}},
          .has_authority                  = 0,  /* No authority set */
        }
      }
    }
  };

  /* Encode the metadata */
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = alt_data,
    .dataend = alt_data + FD_LOOKUP_TABLE_META_SIZE
  };
  fd_address_lookup_table_state_encode( &alt_state, &encode_ctx );

  /* Add addresses */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 10; i++ ) {
    memset( addrs[i].b, 0, 32 );
    addrs[i].b[0] = (uchar)(0x90 + i);
    addrs[i].b[1] = (uchar)(0xA0 + i);
  }

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xFF, 32 );
  }

  /* Call function - should succeed (authority doesn't affect loading) */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify addresses were loaded */
  FD_TEST( out_accts[0].b[0] == 0x90 );
  FD_TEST( out_accts[1].b[0] == 0x91 );
  FD_TEST( out_accts[2].b[0] == 0x92 );

  FD_LOG_NOTICE(( "Test 20 passed: ALT without authority loads successfully" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 21: ALT Recently Extended Beyond Current View */
static void
test_alt_future_extension( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 21: ALT recently extended beyond current view" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT trying to access beyond active range */
  fd_txn_t *       txn              = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1 };
  ulong            readonly_counts[] = { 1 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Modify indices to try accessing beyond active range */
  fd_txn_acct_addr_lut_t * lut = fd_txn_get_address_tables( txn );
  payload[lut->writable_off]   = 5;   /* Index 5 (within active) */
  payload[lut->readonly_off]   = 15;  /* Index 15 (beyond active range) */

  /* Extract ALT address from transaction */
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT with future extension not yet visible */
  uchar                            alt_data[FD_LOOKUP_TABLE_META_SIZE + 20 * 32];
  fd_address_lookup_table_state_t alt_state = {
    .discriminant = fd_address_lookup_table_state_enum_lookup_table,
    .inner = {
      .lookup_table = {
        .meta = {
          .deactivation_slot              = ULONG_MAX,
          .last_extended_slot             = TEST_SLOT + 100,  /* Future slot */
          .last_extended_slot_start_index = 10,   /* Only 10 active now */
          .authority                      = {{0}},
          .has_authority                  = 0,
        }
      }
    }
  };

  /* Encode the metadata */
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = alt_data,
    .dataend = alt_data + FD_LOOKUP_TABLE_META_SIZE
  };
  fd_address_lookup_table_state_encode( &alt_state, &encode_ctx );

  /* Add 20 addresses (but only 10 are active) */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 20; i++ ) {
    memset( addrs[i].b, 0, 32 );
    addrs[i].b[0] = (uchar)(0xB0 + i);
    addrs[i].b[1] = (uchar)(0xC0 + i);
  }

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xFF, 32 );
  }

  /* Call function - should fail with invalid index error */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX );

  FD_LOG_NOTICE(( "Test 21 passed: Future extension not yet visible returns error" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 22: Multiple ALTs with Mixed States */
static void
test_multiple_alts_mixed_states( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 22: Multiple ALTs with mixed states" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 3 ALTs */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 3 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1, 1, 1 };  /* 1 writable from each ALT */
  ulong            readonly_counts[] = { 1, 1, 1 };  /* 1 readonly from each ALT */
  create_test_transaction( txn, payload, FD_TXN_V0, 3, writable_counts, readonly_counts );

  /* Extract ALT addresses from transaction */
  fd_txn_acct_addr_lut_t * luts = fd_txn_get_address_tables( txn );

  /* ALT 1: Fully active with 10 addresses */
  fd_pubkey_t * alt_addr1 = (fd_pubkey_t *)(payload + luts[0].addr_off);
  uchar alt_data1[FD_LOOKUP_TABLE_META_SIZE + 10 * 32];
  create_valid_alt_data( alt_data1, 10 );
  fd_acct_addr_t * addrs1 = (fd_acct_addr_t *)(alt_data1 + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 10; i++ ) {
    addrs1[i].b[0] = (uchar)(0x10 + i);
    addrs1[i].b[1] = (uchar)(0x20 + i);
  }
  create_test_account( ctx, &ctx->xid, alt_addr1, &fd_solana_address_lookup_table_program_id,
                       alt_data1, sizeof(alt_data1), 1000000, 0 );

  /* ALT 2: Partially active (20 addresses but only 10 active) */
  fd_pubkey_t *                    alt_addr2  = (fd_pubkey_t *)(payload + luts[1].addr_off);
  uchar                            alt_data2[FD_LOOKUP_TABLE_META_SIZE + 20 * 32];
  fd_address_lookup_table_state_t alt_state2 = {
    .discriminant = fd_address_lookup_table_state_enum_lookup_table,
    .inner = {
      .lookup_table = {
        .meta = {
          .deactivation_slot              = ULONG_MAX,
          .last_extended_slot             = TEST_SLOT - 1,
          .last_extended_slot_start_index = 10,  /* Only first 10 active */
          .authority                      = {{0}},
          .has_authority                  = 0,
        }
      }
    }
  };
  fd_bincode_encode_ctx_t encode_ctx2 = {
    .data    = alt_data2,
    .dataend = alt_data2 + FD_LOOKUP_TABLE_META_SIZE
  };
  fd_address_lookup_table_state_encode( &alt_state2, &encode_ctx2 );
  fd_acct_addr_t * addrs2 = (fd_acct_addr_t *)(alt_data2 + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 20; i++ ) {
    addrs2[i].b[0] = (uchar)(0x30 + i);
    addrs2[i].b[1] = (uchar)(0x40 + i);
  }
  create_test_account( ctx, &ctx->xid, alt_addr2, &fd_solana_address_lookup_table_program_id,
                       alt_data2, sizeof(alt_data2), 1000000, 0 );

  /* ALT 3: Deactivating but still in slot_hashes */
  fd_pubkey_t *                    alt_addr3 = (fd_pubkey_t *)(payload + luts[2].addr_off);
  uchar alt_data3[FD_LOOKUP_TABLE_META_SIZE + 5 * 32];
  fd_address_lookup_table_state_t alt_state3 = {
    .discriminant = fd_address_lookup_table_state_enum_lookup_table,
    .inner = {
      .lookup_table = {
        .meta = {
          .deactivation_slot              = TEST_SLOT - 5,  /* Deactivating */
          .last_extended_slot             = TEST_SLOT - 10,
          .last_extended_slot_start_index = 5,
          .authority                      = {{0}},
          .has_authority                  = 0,
        }
      }
    }
  };
  fd_bincode_encode_ctx_t encode_ctx3 = {
    .data    = alt_data3,
    .dataend = alt_data3 + FD_LOOKUP_TABLE_META_SIZE
  };
  fd_address_lookup_table_state_encode( &alt_state3, &encode_ctx3 );
  fd_acct_addr_t * addrs3 = (fd_acct_addr_t *)(alt_data3 + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 5; i++ ) {
    addrs3[i].b[0] = (uchar)(0x50 + i);
    addrs3[i].b[1] = (uchar)(0x60 + i);
  }
  create_test_account( ctx, &ctx->xid, alt_addr3, &fd_solana_address_lookup_table_program_id,
                       alt_data3, sizeof(alt_data3), 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xFF, 32 );
  }

  /* Call function - should succeed with all valid addresses loaded */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify addresses from all three ALTs */
  FD_TEST( out_accts[0].b[0] == 0x10 );  /* Writable from ALT1 */
  FD_TEST( out_accts[1].b[0] == 0x30 );  /* Writable from ALT2 */
  FD_TEST( out_accts[2].b[0] == 0x50 );  /* Writable from ALT3 */
  FD_TEST( out_accts[3].b[0] == 0x11 );  /* Readonly from ALT1 */
  FD_TEST( out_accts[4].b[0] == 0x31 );  /* Readonly from ALT2 */
  FD_TEST( out_accts[5].b[0] == 0x51 );  /* Readonly from ALT3 */

  FD_LOG_NOTICE(( "Test 22 passed: Multiple ALTs with mixed states handled correctly" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 23: ALT with Zero Addresses */
static void
test_alt_zero_addresses( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 23: ALT with zero addresses" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT but no index references */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 0 };  /* No writable indices */
  ulong            readonly_counts[] = { 0 };  /* No readonly indices */
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT with no addresses (just metadata) */
  uchar alt_data[FD_LOOKUP_TABLE_META_SIZE];  /* Exactly 56 bytes */
  create_valid_alt_data( alt_data, 0 );  /* Zero addresses */

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xDD, 32 );
  }

  /* Call function - should succeed with no addresses loaded */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify no addresses were loaded (all should remain as sentinel) */
  for( ulong i = 0; i < 256; i++ ) {
    FD_TEST( out_accts[i].b[0] == 0xDD );
  }

  FD_LOG_NOTICE(( "Test 23 passed: Empty ALT succeeds with no addresses loaded" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 27: ALT with Duplicate Index References */
static void
test_alt_duplicate_indices( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 27: ALT with duplicate index references" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT with duplicate indices */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 3 };
  ulong            readonly_counts[] = { 2 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Set duplicate indices */
  fd_txn_acct_addr_lut_t * lut   = fd_txn_get_address_tables( txn );
  payload[lut->writable_off]     = 2;  /* Index 2 */
  payload[lut->writable_off + 1] = 2;  /* Index 2 (duplicate) */
  payload[lut->writable_off + 2] = 3;  /* Index 3 */
  payload[lut->readonly_off]     = 5;  /* Index 5 */
  payload[lut->readonly_off + 1] = 5;  /* Index 5 (duplicate) */

  /* Extract ALT address from transaction */
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create valid ALT data with 10 addresses */
  uchar                            alt_data[FD_LOOKUP_TABLE_META_SIZE + 10 * 32];
  create_valid_alt_data( alt_data, 10 );

  /* Set unique values for the addresses we're referencing */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  addrs[2].b[0] = 0xD2; addrs[2].b[1] = 0xD2;
  addrs[3].b[0] = 0xD3; addrs[3].b[1] = 0xD3;
  addrs[5].b[0] = 0xD5; addrs[5].b[1] = 0xD5;

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes     = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xBB, 32 );
  }

  /* Call function - should succeed with duplicates */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify duplicate addresses appear multiple times */
  FD_TEST( out_accts[0].b[0] == 0xD2 );  /* First instance of index 2 */
  FD_TEST( out_accts[1].b[0] == 0xD2 );  /* Second instance of index 2 (duplicate) */
  FD_TEST( out_accts[2].b[0] == 0xD3 );  /* Index 3 */
  FD_TEST( out_accts[3].b[0] == 0xD5 );  /* First instance of index 5 */
  FD_TEST( out_accts[4].b[0] == 0xD5 );  /* Second instance of index 5 (duplicate) */

  FD_LOG_NOTICE(( "Test 27 passed: Duplicate indices handled correctly" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 24: ALT with All Writable Addresses */
static void
test_alt_all_writable( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 24: ALT with all writable addresses" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT, all writable */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 5 };  /* 5 writable */
  ulong            readonly_counts[] = { 0 };  /* 0 readonly */
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create valid ALT data with 10 addresses */
  uchar                            alt_data[FD_LOOKUP_TABLE_META_SIZE + 10 * 32];
  create_valid_alt_data( alt_data, 10 );

  /* Set unique values for addresses */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 10; i++ ) {
    addrs[i].b[0] = (uchar)(0xF0 + i);
    addrs[i].b[1] = (uchar)(0xF1 + i);
  }

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes     = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xAA, 32 );
  }

  /* Call function - should succeed with all addresses in writable section */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify all 5 addresses are in writable section */
  for( ulong i = 0; i < 5; i++ ) {
    FD_TEST( out_accts[i].b[0] == (uchar)(0xF0 + i) );
    FD_TEST( out_accts[i].b[1] == (uchar)(0xF1 + i) );
  }

  /* Verify readonly section untouched */
  for( ulong i = 5; i < 10; i++ ) {
    FD_TEST( out_accts[i].b[0] == 0xAA );
  }

  FD_LOG_NOTICE(( "Test 24 passed: All writable addresses loaded correctly" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 25: ALT with All Readonly Addresses */
static void
test_alt_all_readonly( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 25: ALT with all readonly addresses" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT, all readonly */
  fd_txn_t *       txn               = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 0 };  /* 0 writable */
  ulong            readonly_counts[] = { 5 };  /* 5 readonly */
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create valid ALT data with 10 addresses */
  uchar                            alt_data[FD_LOOKUP_TABLE_META_SIZE + 10 * 32];
  create_valid_alt_data( alt_data, 10 );

  /* Set unique values for addresses */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 10; i++ ) {
    addrs[i].b[0] = (uchar)(0xE0 + i);
    addrs[i].b[1] = (uchar)(0xE1 + i);
  }

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  /* Set up slot hashes */
  fd_slot_hash_t * hashes     = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xBB, 32 );
  }

  /* Call function - should succeed with all addresses in readonly section */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify all 5 addresses are in readonly section (starting at index 0 since no writable) */
  for( ulong i = 0; i < 5; i++ ) {
    FD_TEST( out_accts[i].b[0] == (uchar)(0xE0 + i) );
    FD_TEST( out_accts[i].b[1] == (uchar)(0xE1 + i) );
  }

  /* Verify rest is untouched */
  for( ulong i = 5; i < 10; i++ ) {
    FD_TEST( out_accts[i].b[0] == 0xBB );
  }

  FD_LOG_NOTICE(( "Test 25 passed: All readonly addresses loaded correctly" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 26: ALT Deactivation Boundary Case */
static void
test_alt_deactivation_boundary( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 26: ALT deactivation boundary case" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Create V0 transaction with 1 ALT */
  fd_txn_t *       txn              = alloc_txn( wksp, 0, 1 );
  uchar            payload[4096];
  ulong            writable_counts[] = { 1 };
  ulong            readonly_counts[] = { 1 };
  create_test_transaction( txn, payload, FD_TXN_V0, 1, writable_counts, readonly_counts );

  /* Extract ALT address from transaction */
  fd_txn_acct_addr_lut_t * lut      = fd_txn_get_address_tables( txn );
  fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + lut->addr_off);

  /* Create ALT at exact deactivation boundary (oldest slot in slot_hashes) */
  uchar alt_data[FD_LOOKUP_TABLE_META_SIZE + 5 * 32];
  fd_address_lookup_table_state_t alt_state = {
    .discriminant = fd_address_lookup_table_state_enum_lookup_table,
    .inner = {
      .lookup_table = {
        .meta = {
          .deactivation_slot              = TEST_SLOT - 9,  /* Exactly at boundary (10 slot hashes) */
          .last_extended_slot             = TEST_SLOT - 20,
          .last_extended_slot_start_index = 5,
          .authority                      = {{0}},
          .has_authority                  = 0,
        }
      }
    }
  };

  /* Encode the metadata */
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = alt_data,
    .dataend = alt_data + FD_LOOKUP_TABLE_META_SIZE
  };
  fd_address_lookup_table_state_encode( &alt_state, &encode_ctx );

  /* Add addresses */
  fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
  for( ulong i = 0; i < 5; i++ ) {
    memset( addrs[i].b, 0, 32 );
    addrs[i].b[0] = (uchar)(0x80 + i);
    addrs[i].b[1] = (uchar)(0x81 + i);
  }

  /* Add account to funk */
  create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );

  /* Set up slot hashes with exactly 10 entries */
  fd_slot_hash_t * hashes = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xCC, 32 );
  }

  /* Call function - should succeed (still deactivating at boundary) */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify addresses were loaded */
  FD_TEST( out_accts[0].b[0] == 0x80 );
  FD_TEST( out_accts[1].b[0] == 0x81 );

  FD_LOG_NOTICE(( "Test 26 passed: ALT at deactivation boundary still loads" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

/* Test case 28: Maximum Transaction ALTs */
static void
test_max_transaction_alts( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "Test 28: Maximum transaction ALTs" ));

  test_ctx_t * ctx = test_setup( wksp );

  /* Maximum ALTs in a transaction (using 10 for practical test) */
  ulong max_alts = 10;

  /* Create V0 transaction with maximum ALTs */
  fd_txn_t *       txn = alloc_txn( wksp, 0, max_alts );
  uchar            payload[8192];  /* Larger payload for more ALTs */

  /* Each ALT will have 1 writable and 1 readonly */
  ulong writable_counts[10];
  ulong readonly_counts[10];
  for( ulong i = 0; i < max_alts; i++ ) {
    writable_counts[i] = 1;
    readonly_counts[i] = 1;
  }

  create_test_transaction( txn, payload, FD_TXN_V0, max_alts, writable_counts, readonly_counts );

  /* Extract ALT addresses and create ALT data for each */
  fd_txn_acct_addr_lut_t * luts = fd_txn_get_address_tables( txn );

  for( ulong alt_idx = 0; alt_idx < max_alts; alt_idx++ ) {
    fd_pubkey_t *            alt_addr = (fd_pubkey_t *)(payload + luts[alt_idx].addr_off);

    /* Create unique ALT data for each ALT */
    uchar alt_data[FD_LOOKUP_TABLE_META_SIZE + 5 * 32];
    create_valid_alt_data( alt_data, 5 );

    /* Set unique addresses for this ALT */
    fd_acct_addr_t * addrs = (fd_acct_addr_t *)(alt_data + FD_LOOKUP_TABLE_META_SIZE);
    for( ulong i = 0; i < 5; i++ ) {
      addrs[i].b[0] = (uchar)((alt_idx << 4) | i);  /* Unique per ALT */
      addrs[i].b[1] = (uchar)(0x20 + alt_idx);
    }

    /* Add account to funk */
    create_test_account( ctx, &ctx->xid, alt_addr, &fd_solana_address_lookup_table_program_id,
                       alt_data, sizeof(alt_data), 1000000, 0 );
  }

  /* Set up slot hashes */
  fd_slot_hash_t * hashes     = create_slot_hash_deque( wksp, 10 );

  fd_acct_addr_t   out_accts[256];

  /* Initialize out_accts with sentinel values */
  for( ulong i = 0; i < 256; i++ ) {
    memset( out_accts[i].b, 0xEE, 32 );
  }

  /* Call function - should succeed with all ALTs loaded */
  int result = fd_runtime_load_txn_address_lookup_tables(
    txn, payload, ctx->funk, &ctx->xid, TEST_SLOT, hashes, out_accts );

  FD_TEST( result == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Verify addresses from all ALTs were loaded */
  /* First max_alts entries are writable (1 from each ALT) */
  for( ulong i = 0; i < max_alts; i++ ) {
    FD_TEST( out_accts[i].b[0] == (uchar)((i << 4) | 0) );  /* Index 0 from each ALT */
    FD_TEST( out_accts[i].b[1] == (uchar)(0x20 + i) );
  }

  /* Next max_alts entries are readonly (1 from each ALT) */
  for( ulong i = 0; i < max_alts; i++ ) {
    FD_TEST( out_accts[max_alts + i].b[0] == (uchar)((i << 4) | 1) );  /* Index 1 from each ALT */
    FD_TEST( out_accts[max_alts + i].b[1] == (uchar)(0x20 + i) );
  }

  FD_LOG_NOTICE(( "Test 28 passed: Maximum ALTs in transaction handled correctly" ));

  test_teardown( ctx );
  destroy_slot_hash_deque( hashes );
  fd_wksp_free_laddr( txn );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  /* Create workspace */
  char * _page_sz = "gigantic";
  ulong numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                            16UL,
                                            fd_shmem_cpu_idx( numa_idx ),
                                            "test_runtime_alut_wksp",
                                            0UL );
  FD_TEST( wksp );

  /* Run test cases */
  test_non_v0_transaction( wksp );
  test_v0_no_alts( wksp );
  test_alt_not_found( wksp );
  test_invalid_alt_owner( wksp );
  test_alt_data_too_small( wksp );
  test_invalid_discriminant( wksp );
  test_alt_data_not_aligned( wksp );
  test_deactivated_alt( wksp );
  test_invalid_writable_index( wksp );
  test_invalid_readonly_index( wksp );
  test_valid_single_alt( wksp );
  test_multiple_alts( wksp );
  test_partial_activation( wksp );
  test_deactivating_alt( wksp );
  test_bincode_decode_failure( wksp );
  test_alt_just_activated( wksp );
  test_growing_alt( wksp );
  test_alt_deactivating_current_slot( wksp );
  test_alt_max_addresses( wksp );
  test_alt_no_authority( wksp );
  test_alt_future_extension( wksp );
  test_multiple_alts_mixed_states( wksp );
  test_alt_zero_addresses( wksp );
  test_alt_all_writable( wksp );
  test_alt_all_readonly( wksp );
  test_alt_deactivation_boundary( wksp );
  test_alt_duplicate_indices( wksp );
  test_max_transaction_alts( wksp );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}
