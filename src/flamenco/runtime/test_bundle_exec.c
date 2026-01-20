#include "fd_acc_pool.h"
#include "fd_runtime.h"
#include "fd_runtime_stack.h"
#include "fd_bank.h"
#include "fd_system_ids.h"
#include "sysvar/fd_sysvar_rent.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_stake_history.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_cache.h"
#include "../accdb/fd_accdb_admin_v1.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "../features/fd_features.h"
#include "../accdb/fd_accdb_sync.h"

/* Values before deprecate_rent_exemption_threshold is activated */
#define TEST_DEFAULT_LAMPORTS_PER_UINT8_YEAR (3480UL)
#define TEST_DEFAULT_EXEMPTION_THRESHOLD     (2.0)

/* Values after deprecate_rent_exemption_threshold is activated */
#define TEST_NEW_LAMPORTS_PER_UINT8_YEAR (6960UL)
#define TEST_NEW_EXEMPTION_THRESHOLD     (1.0)

#define TEST_SLOTS_PER_EPOCH         (3UL)
#define TEST_FEATURE_ACTIVATION_SLOT (TEST_SLOTS_PER_EPOCH * 2)

#define TEST_ACC_POOL_ACCOUNT_CNT (32UL)

struct test_env {
  fd_wksp_t *          wksp;
  ulong                tag;
  fd_banks_t           banks[1];
  fd_bank_t            bank[1];
  void *               funk_mem;
  fd_accdb_admin_t     accdb_admin[1];
  fd_accdb_user_t      accdb[1];
  fd_funk_txn_xid_t    xid;
  fd_runtime_stack_t * runtime_stack;

  fd_runtime_t *       runtime;
  fd_txn_in_t          txn_in;
  fd_txn_out_t         txn_out[ 5UL];
};
typedef struct test_env test_env_t;

static void
create_test_account( fd_accdb_user_t *         user,
                     fd_funk_txn_xid_t const * xid,
                     fd_pubkey_t const *       pubkey,
                     ulong                     lamports,
                     uint                      dlen,
                     uchar *                   data,
                     ulong                     slot ) {
  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( user, rw, xid, pubkey, dlen, FD_ACCDB_FLAG_CREATE ) );
  fd_accdb_ref_data_set( user, rw, data, dlen );
  fd_funk_rec_t * rec = (void *)rw->ref->user_data;
  FD_TEST( rec->val_sz    == sizeof(fd_account_meta_t)+dlen );
  FD_TEST( rec->val_max   >= sizeof(fd_account_meta_t)+dlen );
  FD_TEST( rw->meta->dlen == dlen );
  rw->meta->lamports = lamports;
  rw->meta->slot = slot;
  rw->meta->executable = 0;
  memset( rw->meta->owner, 0UL, 32UL );
  fd_accdb_close_rw( user, rw );
}

static void
init_rent_sysvar( test_env_t * env,
                  ulong        lamports_per_uint8_year,
                  double       exemption_threshold ) {
  fd_rent_t rent = {
    .lamports_per_uint8_year = lamports_per_uint8_year,
    .exemption_threshold     = exemption_threshold,
    .burn_percent            = 50
  };

  fd_bank_rent_set( env->bank, rent );
  fd_sysvar_rent_write( env->bank, env->accdb, &env->xid, NULL, &rent );
}

  static void
  init_epoch_schedule_sysvar( test_env_t * env ) {
    fd_epoch_schedule_t epoch_schedule = {
      .slots_per_epoch             = TEST_SLOTS_PER_EPOCH,
      .leader_schedule_slot_offset = TEST_SLOTS_PER_EPOCH,
      .warmup                      = 0,
      .first_normal_epoch          = 0UL,
      .first_normal_slot           = 0UL
    };

    fd_bank_epoch_schedule_set( env->bank, epoch_schedule );
    fd_sysvar_epoch_schedule_write( env->bank, env->accdb, &env->xid, NULL, &epoch_schedule );
  }

  static void
  init_stake_history_sysvar( test_env_t * env ) {
    fd_sysvar_stake_history_init( env->bank, env->accdb, &env->xid, NULL );
  }

  static void
  init_clock_sysvar( test_env_t * env ) {
    fd_sysvar_clock_init( env->bank, env->accdb, &env->xid, NULL );
  }

  static void
  init_blockhash_queue( test_env_t * env ) {
    ulong blockhash_seed = 12345UL;
    fd_blockhashes_t * bhq = fd_blockhashes_init( fd_bank_block_hash_queue_modify( env->bank ), blockhash_seed );

    fd_hash_t dummy_hash = {0};
    fd_memset( dummy_hash.uc, 0xAB, FD_HASH_FOOTPRINT );
    fd_blockhash_info_t * info = fd_blockhashes_push_new( bhq, &dummy_hash );
    info->fee_calculator.lamports_per_signature = 0UL;
  }

  static test_env_t *
  test_env_create( test_env_t * env,
                  fd_wksp_t *  wksp ) {
    fd_memset( env, 0, sizeof(test_env_t) );
    env->wksp = wksp;
    env->tag  = 1UL;

    ulong const funk_seed       = 17UL;
    ulong const txn_max         = 1UL;
    ulong const rec_max         = 16UL;
    ulong const max_total_banks = 2UL;
    ulong const max_fork_width  = 2UL;

    env->funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), env->tag );
    FD_TEST( env->funk_mem );
    FD_TEST( fd_funk_new( env->funk_mem, env->tag, funk_seed, txn_max, rec_max ) );

    FD_TEST( fd_accdb_admin_v1_init( env->accdb_admin, env->funk_mem ) );
    FD_TEST( fd_accdb_user_v1_init( env->accdb, env->funk_mem ) );

    fd_banks_data_t * banks_data = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( max_total_banks, max_fork_width ), env->tag );
    FD_TEST( banks_data );
    fd_banks_locks_t * banks_locks = fd_wksp_alloc_laddr( wksp, alignof(fd_banks_locks_t), sizeof(fd_banks_locks_t), env->tag );
    FD_TEST( banks_locks );
    fd_banks_locks_init( banks_locks );

    FD_TEST( fd_banks_join( env->banks, fd_banks_new( banks_data, max_total_banks, max_fork_width, 0, 8888UL ), banks_locks ) );

    FD_TEST( fd_banks_init_bank( env->bank, env->banks ) );

    env->runtime_stack = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_stack_t), sizeof(fd_runtime_stack_t), env->tag );
    FD_TEST( env->runtime_stack );
    fd_memset( env->runtime_stack, 0, sizeof(fd_runtime_stack_t) );

    fd_funk_txn_xid_t root[1];
    fd_funk_txn_xid_set_root( root );
    env->xid = (fd_funk_txn_xid_t){ .ul = { 0UL, env->bank->data->idx } };
    fd_accdb_attach_child( env->accdb_admin, root, &env->xid );

    init_rent_sysvar( env, TEST_DEFAULT_LAMPORTS_PER_UINT8_YEAR, TEST_DEFAULT_EXEMPTION_THRESHOLD );
    init_epoch_schedule_sysvar( env );
    init_stake_history_sysvar( env );
    init_clock_sysvar( env );
    init_blockhash_queue( env );

    fd_bank_slot_set( env->bank, 0UL );
    fd_bank_epoch_set( env->bank, 0UL );

    fd_features_t features = {0};
    fd_features_disable_all( &features );
    features.deprecate_rent_exemption_threshold = TEST_FEATURE_ACTIVATION_SLOT;
    fd_bank_features_set( env->bank, features );

    fd_accdb_advance_root( env->accdb_admin, &env->xid );

    env->runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), env->tag );

    uchar * acc_pool_mem = fd_wksp_alloc_laddr( wksp, fd_acc_pool_align(), fd_acc_pool_footprint( TEST_ACC_POOL_ACCOUNT_CNT ), env->tag );
    fd_acc_pool_t * acc_pool = fd_acc_pool_join( fd_acc_pool_new( acc_pool_mem, TEST_ACC_POOL_ACCOUNT_CNT ) );
    FD_TEST( acc_pool );

    env->runtime->accdb                    = &env->accdb[0];
    env->runtime->progcache                = NULL;
    env->runtime->status_cache             = NULL;
    env->runtime->acc_pool                 = acc_pool;
    env->runtime->log.log_collector        = NULL;
    env->runtime->log.enable_log_collector = 0;
    env->runtime->log.dumping_mem          = NULL;
    env->runtime->log.enable_vm_tracing    = 0;
    env->runtime->log.tracing_mem          = NULL;
    env->runtime->log.capture_ctx          = NULL;

    return env;
  }

static void
process_slot( test_env_t * env,
              ulong        slot ) {
  fd_bank_t * parent_bank = env->bank;
  ulong parent_slot       = fd_bank_slot_get( parent_bank );
  ulong parent_bank_idx   = parent_bank->data->idx;

  FD_TEST( parent_bank->data->flags & FD_BANK_FLAGS_FROZEN );

  ulong new_bank_idx = fd_banks_new_bank( env->bank, env->banks, parent_bank_idx, 0L )->data->idx;
  fd_bank_t * new_bank = fd_banks_clone_from_parent( env->bank, env->banks, new_bank_idx );
  FD_TEST( new_bank );

  fd_bank_slot_set( new_bank, slot );
  fd_bank_parent_slot_set( new_bank, parent_slot );

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( new_bank );
  ulong epoch = fd_slot_to_epoch( epoch_schedule, slot, NULL );
  fd_bank_epoch_set( new_bank, epoch );

  fd_funk_txn_xid_t xid        = { .ul = { slot, new_bank_idx } };
  fd_funk_txn_xid_t parent_xid = { .ul = { parent_slot, parent_bank_idx } };
  fd_accdb_attach_child( env->accdb_admin, &parent_xid, &xid );

  env->xid = xid;

  int is_epoch_boundary = 0;
  fd_runtime_block_execute_prepare( env->banks, env->bank, env->accdb, env->runtime_stack, NULL, &is_epoch_boundary );
}

#define FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _to_add, _sz ) __extension__({ \
  if( FD_UNLIKELY( (*_cur_data)+_sz>_begin+FD_TXN_MTU ) ) return ULONG_MAX;          \
  fd_memcpy( *_cur_data, _to_add, _sz );                                             \
  *_cur_data += _sz;                                                                 \
})

#define FD_CHECKED_ADD_CU16_TO_TXN_DATA( _begin, _cur_data, _to_add ) __extension__({ \
  do {                                                                               \
     uchar _buf[3];                                                                  \
     fd_bincode_encode_ctx_t _encode_ctx = { .data = _buf, .dataend = _buf+3 };      \
     fd_bincode_compact_u16_encode( &_to_add, &_encode_ctx );                        \
     ulong _sz = (ulong) ((uchar *)_encode_ctx.data - _buf );                        \
     FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _buf, _sz );                     \
  } while(0);                                                                        \
})


ulong
txn_serialize( uchar *          txn_raw_begin,
               ulong            signatures_cnt,
               fd_signature_t * signatures,
               ulong            num_required_signatures,
               ulong            num_readonly_signed_accounts,
               ulong            num_readonly_unsigned_accounts,
               ulong            account_keys_cnt,
               fd_pubkey_t *    account_keys,
               fd_hash_t *      recent_blockhash ) {
  uchar * txn_raw_cur_ptr = txn_raw_begin;

  /* Compact array of signatures (https://solana.com/docs/core/transactions#transaction)
     Note that although documentation interchangably refers to the signature cnt as a compact-u16
     and a u8, the max signature cnt is capped at 48 (due to txn size limits), so u8 and compact-u16
     is represented the same way anyways and can be parsed identically. */
  // Note: always create a valid txn with 1+ signatures, add an empty signature if none is provided
  uchar signature_cnt = fd_uchar_max( 1, (uchar)signatures_cnt );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &signature_cnt, sizeof(uchar) );
  for( uchar i = 0; i < signature_cnt; ++i ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &signatures[i], FD_TXN_SIGNATURE_SZ );
  }

  /* Message */
  /* For v0 transactions, the highest bit of the num_required_signatures is set, and an extra byte is used for the version.
     https://solanacookbook.com/guides/versioned-transactions.html#versioned-transactions-transactionv0

     We will always create a transaction with at least 1 signature, and cap the signature count to 127 to avoid
     collisions with the header_b0 tag. */
  uchar header_b0 = (uchar) 0x80UL;
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &header_b0, sizeof(uchar) );

  /* Header (3 bytes) (https://solana.com/docs/core/transactions#message-header) */
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_required_signatures,        sizeof(uchar) );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_readonly_signed_accounts,   sizeof(uchar) );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_readonly_unsigned_accounts, sizeof(uchar) );

  /* Compact array of account addresses (https://solana.com/docs/core/transactions#compact-array-format) */
  // Array length is a compact u16
  ushort num_acct_keys = (ushort)account_keys_cnt;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, num_acct_keys );
  for( ushort i = 0; i < num_acct_keys; ++i ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &account_keys[i], sizeof(fd_pubkey_t) );
  }

  /* Recent blockhash (32 bytes) (https://solana.com/docs/core/transactions#recent-blockhash) */
  // Note: add an empty blockhash if none is provided
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, recent_blockhash, sizeof(fd_hash_t) );

  /* Compact array of instructions (https://solana.com/docs/core/transactions#array-of-instructions) */
  // Instruction count is a compact u16
  ushort instr_count = 0;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instr_count );

  /* Address table lookups (N/A for legacy transactions) */
  ushort addr_table_cnt = 0;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, addr_table_cnt );

  return (ulong)(txn_raw_cur_ptr - txn_raw_begin);
}

static void
test_execute_bundles( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_create( env, wksp );

  process_slot( env, 10UL );

  fd_pubkey_t pubkey1 = { .ul[0] = 1UL };
  create_test_account( env->accdb, &env->xid, &pubkey1, 1000000UL, 0UL, NULL, 10UL );
  fd_pubkey_t pubkey2 = { .ul[0] = 2UL };
  uchar data2[5] = {6, 7, 8, 9, 10};
  create_test_account( env->accdb, &env->xid, &pubkey2, 1000000UL, 5UL, data2, 10UL );
  fd_pubkey_t pubkey3 = { .ul[0] = 3UL };
  uchar data3[5] = {11, 12, 13, 14, 15};
  create_test_account( env->accdb, &env->xid, &pubkey3, 1000000UL, 5UL, data3, 10UL );

  fd_signature_t signature = {0};

  fd_hash_t dummy_hash = {0};
  fd_memset( dummy_hash.uc, 0xAB, FD_HASH_FOOTPRINT );
  fd_pubkey_t account_keys[3] = { pubkey1, pubkey2, pubkey3 };

  /* First test: successful execution of bundle where we reuse a
     writable account.
     rw -> rw */

  /* Execute first transaction in bundle.  There are no instructions in
     the transaction, so we execute an empty transaction and mock a
     lamports change to the second account. */
  fd_txn_p_t txn_p = {0};
  ulong sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, account_keys, &dummy_hash );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  ulong starting_ro_active = env->accdb->base.ro_active;
  ulong starting_rw_active = env->accdb->base.rw_active;
  FD_TEST( starting_ro_active == env->accdb->base.ro_active );
  FD_TEST( starting_rw_active == env->accdb->base.rw_active );

  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 1;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[0].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[0].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[0].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[0].accounts.is_writable[1] == 1 );
  FD_TEST( env->txn_out[0].accounts.account[1].meta->lamports == 1000000UL );
  env->txn_out[0].accounts.account[1].meta->lamports = 2000000UL;

  /* Execute a second transaction in the bundle.  It is identical to the
     bundle executed in the previous transaction.  However, we now
     expect the second account to have 2000000 lamports instead of
     1000000 lamports. */
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );
  FD_TEST( env->txn_out[1].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[1].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[1].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[1].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[1].accounts.is_writable[1] == 1 );
  FD_TEST( env->txn_out[1].accounts.account[1].meta->lamports == 2000000UL );

  /* To further confirm the above comment, we execute the same
     transaction a third time but outside of a bundle and expect the
     second account to have 1000000 lamports again. */
  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[2].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[2].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[2].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[2].accounts.is_writable[1] == 1 );
  FD_TEST( env->txn_out[2].accounts.account[1].meta->lamports == 1000000UL );
  env->txn_out[2].err.is_committable = 0;
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[2] );

  /* Now commit both bundle transactions and make sure that all accdb
     and account pool references are released. */
  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[0] );
  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[1] );
  FD_TEST( fd_acc_pool_free( env->runtime->acc_pool ) == TEST_ACC_POOL_ACCOUNT_CNT );
  FD_TEST( starting_ro_active == env->accdb->base.ro_active );
  FD_TEST( starting_rw_active == env->accdb->base.rw_active );

  /* Now we expect the second account to have 2000000 lamports again
     since the bundle transaction modified the balance and was
     committed. */
  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[2].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[2].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[2].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[2].accounts.is_writable[1] == 1 );
  FD_TEST( env->txn_out[2].accounts.account[1].meta->lamports == 2000000UL );
  env->txn_out[2].err.is_committable = 0;
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[2] );

  /* Second Test: successful execution of bundle where we reuse an
     writable account as a readonly account in a following transaction.
     We use this account as writable a second time in a third
     transaction and once again as readonly in a fourth transaction.
     rw -> ro -> rw -> ro */
  FD_TEST( fd_acc_pool_free( env->runtime->acc_pool ) == TEST_ACC_POOL_ACCOUNT_CNT );
  FD_TEST( starting_ro_active == env->accdb->base.ro_active );
  FD_TEST( starting_rw_active == env->accdb->base.rw_active );

  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, account_keys, &dummy_hash );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  /* Execute a first transaction where the second account is writable
     and the balance is incremented by 1. */

  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 1;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[0].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[0].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[0].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[0].accounts.is_writable[1] == 1 );
  env->txn_out[0].accounts.account[1].meta->lamports = 2000001UL;

  /* Execute a second transaction in the bundle where an account is
     reused but as read-only. */
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 1UL, 2UL, account_keys, &dummy_hash );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );
  FD_TEST( env->txn_out[1].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[1].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[1].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[1].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[1].accounts.is_writable[1] == 0 );
  FD_TEST( env->txn_out[1].accounts.account[1].meta->lamports == 2000001UL );

  /* A third bundle transaction where the account is reused as
     writable again. */
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, account_keys, &dummy_hash );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 2;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  env->txn_in.bundle.prev_txn_outs[1] = &env->txn_out[1];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[2].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[2].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[2].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[2].accounts.is_writable[1] == 1 );
  FD_TEST( env->txn_out[2].accounts.account[1].meta->lamports == 2000001UL );
  env->txn_out[2].accounts.account[1].meta->lamports = 2000011UL;

  /* A fourth transaction where the second account is once again
     passed in as read-only.  Make sure that the right version of the
     account is being reussed. */
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, account_keys, &dummy_hash );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 3;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  env->txn_in.bundle.prev_txn_outs[1] = &env->txn_out[1];
  env->txn_in.bundle.prev_txn_outs[2] = &env->txn_out[2];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[3] );
  FD_TEST( env->txn_out[3].err.is_committable );
  FD_TEST( env->txn_out[3].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[3].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[3].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[3].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[3].accounts.is_writable[1] == 1 );
  FD_TEST( env->txn_out[3].accounts.account[1].meta->lamports == 2000011UL );

  /* Commit all bundle transactions and make sure that all accdb
     and account pool references are released. */
  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[0] );
  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[1] );
  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[2] );
  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[3] );
  FD_TEST( fd_acc_pool_free( env->runtime->acc_pool ) == TEST_ACC_POOL_ACCOUNT_CNT );
  FD_TEST( starting_ro_active == env->accdb->base.ro_active );
  FD_TEST( starting_rw_active == env->accdb->base.rw_active );

  /* Test 3: Bundle fails */

  FD_TEST( fd_acc_pool_free( env->runtime->acc_pool ) == TEST_ACC_POOL_ACCOUNT_CNT );
  FD_TEST( starting_ro_active == env->accdb->base.ro_active );
  FD_TEST( starting_rw_active == env->accdb->base.rw_active );

  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, account_keys, &dummy_hash );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  /* Execute a first transaction where the second account is writable
     and the balance is incremented by 1. */

  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 1;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[0].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[0].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[0].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[0].accounts.is_writable[1] == 1 );
  FD_TEST( env->txn_out[0].accounts.account[1].meta->lamports == 2000011UL );
  env->txn_out[0].accounts.account[1].meta->lamports = 2000021UL;
  env->txn_out[0].err.is_committable = 0;
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[0] );

  FD_TEST( fd_acc_pool_free( env->runtime->acc_pool ) == TEST_ACC_POOL_ACCOUNT_CNT );
  FD_TEST( starting_ro_active == env->accdb->base.ro_active );
  FD_TEST( starting_rw_active == env->accdb->base.rw_active );

  /* Test 4: Bundle fails with last transaction failing. */

  FD_TEST( fd_acc_pool_free( env->runtime->acc_pool ) == TEST_ACC_POOL_ACCOUNT_CNT );
  FD_TEST( starting_ro_active == env->accdb->base.ro_active );
  FD_TEST( starting_rw_active == env->accdb->base.rw_active );

  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, account_keys, &dummy_hash );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  /* Execute a first transaction where the second account is writable
     and the balance is incremented by 1. */

  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 1;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[0].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[0].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[0].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[0].accounts.is_writable[1] == 1 );
  FD_TEST( env->txn_out[0].accounts.account[1].meta->lamports == 2000011UL );
  env->txn_out[0].accounts.account[1].meta->lamports = 2000021UL;

  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );
  FD_TEST( env->txn_out[1].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[1].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[1].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[1].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[1].accounts.is_writable[1] == 1 );
  FD_TEST( env->txn_out[1].accounts.account[1].meta->lamports == 2000021UL );
  env->txn_out[1].accounts.account[1].meta->lamports = 2000031UL;

  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 2;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  env->txn_in.bundle.prev_txn_outs[1] = &env->txn_out[1];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[2].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[2].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[2].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[2].accounts.is_writable[1] == 1 );
  FD_TEST( env->txn_out[2].accounts.account[1].meta->lamports == 2000031UL );
  env->txn_out[2].accounts.account[1].meta->lamports = 2000041UL;

  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 1UL, 2UL, account_keys, &dummy_hash );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 3;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  env->txn_in.bundle.prev_txn_outs[1] = &env->txn_out[1];
  env->txn_in.bundle.prev_txn_outs[2] = &env->txn_out[2];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[3] );
  FD_TEST( env->txn_out[3].err.is_committable );
  FD_TEST( env->txn_out[3].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[3].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[3].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[3].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[3].accounts.is_writable[1] == 0 );
  FD_TEST( env->txn_out[3].accounts.account[1].meta->lamports == 2000041UL );

  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, account_keys, &dummy_hash );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 4;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  env->txn_in.bundle.prev_txn_outs[1] = &env->txn_out[1];
  env->txn_in.bundle.prev_txn_outs[2] = &env->txn_out[2];
  env->txn_in.bundle.prev_txn_outs[3] = &env->txn_out[3];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[4] );
  FD_TEST( env->txn_out[4].err.is_committable );
  FD_TEST( env->txn_out[4].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[4].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[4].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[4].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[4].accounts.is_writable[1] == 1 );
  FD_TEST( env->txn_out[4].accounts.account[1].meta->lamports == 2000041UL );
  env->txn_out[4].err.txn_err = FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;

  env->txn_out[0].err.is_committable = 0;
  env->txn_out[1].err.is_committable = 0;
  env->txn_out[2].err.is_committable = 0;
  env->txn_out[3].err.is_committable = 0;
  env->txn_out[4].err.is_committable = 0;

  fd_runtime_cancel_txn( env->runtime, &env->txn_out[0] );
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[1] );
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[2] );
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[3] );
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[4] );

  FD_TEST( fd_acc_pool_free( env->runtime->acc_pool ) == TEST_ACC_POOL_ACCOUNT_CNT );
  FD_TEST( starting_ro_active == env->accdb->base.ro_active );
  FD_TEST( starting_rw_active == env->accdb->base.rw_active );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx > fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr( &argc, &argv,  "--page-sz",  NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 6UL );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_execute_bundles( wksp );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
