#include "fd_acc_pool.h"
#include "fd_runtime.h"
#include "fd_runtime_stack.h"
#include "fd_bank.h"
#include "fd_system_ids.h"
#include "fd_alut.h"
#include "sysvar/fd_sysvar_rent.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_stake_history.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_cache.h"
#include "sysvar/fd_sysvar_slot_hashes.h"
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
  void *               funk_locks;
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
                     ulong                     slot,
                     fd_pubkey_t const *       owner ) {
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
  memcpy( rw->meta->owner, owner->uc, 32UL );
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

  env->bank->data->f.rent = rent;
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

    env->bank->data->f.epoch_schedule = epoch_schedule;
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
    fd_blockhashes_t * bhq = fd_blockhashes_init( &env->bank->data->f.block_hash_queue, blockhash_seed );

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
    ulong const txn_max         = 2UL;
    ulong const rec_max         = 16UL;
    ulong const max_total_banks = 2UL;
    ulong const max_fork_width  = 2UL;

    env->funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_shmem_footprint( txn_max, rec_max ), env->tag );
    FD_TEST( env->funk_mem );
    env->funk_locks = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_locks_footprint( txn_max, rec_max ), env->tag );
    FD_TEST( env->funk_locks );
    FD_TEST( fd_funk_shmem_new( env->funk_mem, env->tag, funk_seed, txn_max, rec_max ) );
    FD_TEST( fd_funk_locks_new( env->funk_locks, txn_max, rec_max ) );

    FD_TEST( fd_accdb_admin_v1_init( env->accdb_admin, env->funk_mem, env->funk_locks ) );
    FD_TEST( fd_accdb_user_v1_init( env->accdb, env->funk_mem, env->funk_locks, txn_max ) );

    fd_banks_data_t * banks_data = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( max_total_banks, max_fork_width, 2048UL, 2048UL ), env->tag );
    FD_TEST( banks_data );
    fd_banks_locks_t * banks_locks = fd_wksp_alloc_laddr( wksp, alignof(fd_banks_locks_t), sizeof(fd_banks_locks_t), env->tag );
    FD_TEST( banks_locks );
    fd_banks_locks_init( banks_locks );

    FD_TEST( fd_banks_join( env->banks, fd_banks_new( banks_data, max_total_banks, max_fork_width, 2048UL, 2048UL, 0, 8888UL ), banks_locks ) );

    FD_TEST( fd_banks_init_bank( env->bank, env->banks ) );

    env->runtime_stack = fd_wksp_alloc_laddr( wksp, fd_runtime_stack_align(), fd_runtime_stack_footprint( 2048UL, 2048UL, 2048UL ), env->tag );
    FD_TEST( env->runtime_stack );
    FD_TEST( fd_runtime_stack_join( fd_runtime_stack_new( env->runtime_stack, 2048UL, 2048UL, 2048UL, 999UL ) ) );

    fd_funk_txn_xid_t root[1];
    fd_funk_txn_xid_set_root( root );
    env->xid = (fd_funk_txn_xid_t){ .ul = { 9UL, env->bank->data->idx } };
    fd_accdb_attach_child( env->accdb_admin, root, &env->xid );

    init_rent_sysvar( env, TEST_DEFAULT_LAMPORTS_PER_UINT8_YEAR, TEST_DEFAULT_EXEMPTION_THRESHOLD );
    init_epoch_schedule_sysvar( env );
    init_stake_history_sysvar( env );
    init_clock_sysvar( env );
    init_blockhash_queue( env );

    env->bank->data->f.slot = 9UL;
    env->bank->data->f.epoch = 4UL;

    fd_features_t features = {0};
    fd_features_disable_all( &features );
    features.deprecate_rent_exemption_threshold = TEST_FEATURE_ACTIVATION_SLOT;
    env->bank->data->f.features = features;

    fd_bank_top_votes_t_2_modify( env->bank );

    fd_accdb_advance_root( env->accdb_admin, &env->xid );

    env->runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), env->tag );
    memset( env->runtime, 0, sizeof(fd_runtime_t) );

    uchar * acc_pool_mem = fd_wksp_alloc_laddr( wksp, fd_acc_pool_align(), fd_acc_pool_footprint( TEST_ACC_POOL_ACCOUNT_CNT ), env->tag );
    fd_acc_pool_t * acc_pool = fd_acc_pool_join( fd_acc_pool_new( acc_pool_mem, TEST_ACC_POOL_ACCOUNT_CNT ) );
    FD_TEST( acc_pool );

    env->runtime->accdb                    = &env->accdb[0];
    env->runtime->progcache                = NULL;
    env->runtime->status_cache             = NULL;
    env->runtime->acc_pool                 = acc_pool;
    memset( &env->runtime->log, 0, sizeof(env->runtime->log) );

    return env;
  }

static void
process_slot( test_env_t * env,
              ulong        slot ) {
  fd_bank_t * parent_bank = env->bank;
  ulong parent_slot       = parent_bank->data->f.slot;
  ulong parent_bank_idx   = parent_bank->data->idx;

  FD_TEST( parent_bank->data->flags & FD_BANK_FLAGS_FROZEN );

  ulong new_bank_idx = fd_banks_new_bank( env->bank, env->banks, parent_bank_idx, 0L )->data->idx;
  fd_bank_t * new_bank = fd_banks_clone_from_parent( env->bank, env->banks, new_bank_idx );
  FD_TEST( new_bank );

  new_bank->data->f.slot = slot;
  new_bank->data->f.parent_slot = parent_slot;

  fd_epoch_schedule_t const * epoch_schedule = &new_bank->data->f.epoch_schedule;
  ulong epoch = fd_slot_to_epoch( epoch_schedule, slot, NULL );
  new_bank->data->f.epoch = epoch;

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

  fd_pubkey_t system = {0};
  fd_pubkey_t pubkey1 = { .ul[0] = 1UL };
  create_test_account( env->accdb, &env->xid, &pubkey1, 1000000UL, 0UL, NULL, 10UL, &system );
  fd_pubkey_t pubkey2 = { .ul[0] = 2UL };
  uchar data2[5] = {6, 7, 8, 9, 10};
  create_test_account( env->accdb, &env->xid, &pubkey2, 1000000UL, 5UL, data2, 10UL, &system );
  fd_pubkey_t pubkey3 = { .ul[0] = 3UL };
  uchar data3[5] = {11, 12, 13, 14, 15};
  create_test_account( env->accdb, &env->xid, &pubkey3, 1000000UL, 5UL, data3, 10UL, &system );

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

/* Test 5: Account reclaim divergence between bundle and replay mode. */

  fd_pubkey_t some_program = { .ul[0] = 0xDEADBEEFUL };
  fd_pubkey_t victim       = { .ul[0] = 0xCAFEUL };
  uchar victim_data[64];
  memset( victim_data, 0xAA, 64UL );
  create_test_account( env->accdb, &env->xid, &victim, 500000UL, 64UL, victim_data, 10UL, &some_program );

  /* We need victim in the account_keys of the transaction.
     Use [pubkey1, victim] so victim is index 1. */
  fd_pubkey_t reclaim_keys[2] = { pubkey1, victim };
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, reclaim_keys, &dummy_hash );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  /* tx0: Execute with victim writable, then drain lamports to 0. */
  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 1;
  env->txn_in.bundle.prev_txn_cnt = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( env->txn_out[0].accounts.account[1].meta->lamports == 500000UL );
  FD_TEST( env->txn_out[0].accounts.account[1].meta->dlen == 64UL );
  FD_TEST( !memcmp( env->txn_out[0].accounts.account[1].meta->owner, &some_program, 32UL ) );

  /* Simulate SBF program draining the account to 0 lamports. */
  env->txn_out[0].accounts.account[1].meta->lamports = 0UL;

  /* tx1: Execute with victim writable, reading from prev_txn_outs.
     In bundle mode, victim will have all of its metadata zeroed out
     since the account is reclaimed. */
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );
  FD_TEST( env->txn_out[1].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );

  /* KEY ASSERTION: In bundle mode, tx1 should not see the un-reclaimed
     state from tx0.  The dlen should also not be 64 since from tx1's
     POV, the account should not exist yet. */
  FD_TEST( env->txn_out[1].accounts.account[1].meta->lamports == 0UL );
  FD_TEST( env->txn_out[1].accounts.account[1].meta->dlen != 64UL );
  FD_TEST( memcmp( env->txn_out[1].accounts.account[1].meta->owner, &some_program, 32UL ) );

  /* Now commit both bundle transactions. */
  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[0] );
  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[1] );

  /* Execute a non-bundle txn to read the account post-commit */
  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );

  /* After commit+reclaim: owner is zeroed and dlen is 0. */
  FD_TEST( env->txn_out[2].accounts.account[1].meta->lamports == 0UL );
  FD_TEST( env->txn_out[2].accounts.account[1].meta->dlen == 0UL );
  fd_pubkey_t zero_owner = {0};
  FD_TEST( !memcmp( env->txn_out[2].accounts.account[1].meta->owner, &zero_owner, 32UL ) );

  env->txn_out[2].err.is_committable = 0;
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[2] );

  FD_TEST( fd_acc_pool_free( env->runtime->acc_pool ) == TEST_ACC_POOL_ACCOUNT_CNT );
  FD_TEST( starting_ro_active == env->accdb->base.ro_active );
  FD_TEST( starting_rw_active == env->accdb->base.rw_active );

  fd_pubkey_t system_prog    = {0};
  fd_pubkey_t payer          = { .ul[0] = 0xC0DE01UL };
  fd_pubkey_t program_key    = { .ul[0] = 0xC0DE02UL };
  fd_pubkey_t programdata_key= { .ul[0] = 0xC0DE03UL };
  fd_pubkey_t authority_key  = { .ul[0] = 0xC0DE04UL };

  create_test_account( env->accdb, &env->xid, &payer, 10000000UL, 0UL, NULL, 10UL, &system_prog );

  /* Program account: owned by upgradeable BPF loader, state = program pointing at programdata. */
  uchar program_data_buf[ SIZE_OF_PROGRAM ];
  {
    fd_bpf_upgradeable_loader_state_t state;
    fd_memset( &state, 0, sizeof(state) );
    state.discriminant                    = fd_bpf_upgradeable_loader_state_enum_program;
    state.inner.program.programdata_address = programdata_key;
    fd_bincode_encode_ctx_t ctx = { .data = program_data_buf, .dataend = program_data_buf + SIZE_OF_PROGRAM };
    FD_TEST( fd_bpf_upgradeable_loader_state_encode( &state, &ctx ) == FD_BINCODE_SUCCESS );
  }
  create_test_account( env->accdb, &env->xid, &program_key, 1000000UL,
                      SIZE_OF_PROGRAM, program_data_buf, 5UL,
                      &fd_solana_bpf_loader_upgradeable_program_id );

  /* Programdata account: state = program_data with OLD slot = 5 (< current slot 10).
    A real upgrade would set slot to the current slot; we start with the pre-upgrade state. */
  uchar programdata_data_buf[ PROGRAMDATA_METADATA_SIZE ];
  {
    fd_bpf_upgradeable_loader_state_t state;
    fd_memset( &state, 0, sizeof(state) );
    state.discriminant                                   = fd_bpf_upgradeable_loader_state_enum_program_data;
    state.inner.program_data.slot                        = 5UL;
    state.inner.program_data.upgrade_authority_address   = authority_key;
    state.inner.program_data.has_upgrade_authority_address = 1;
    fd_bincode_encode_ctx_t ctx = { .data = programdata_data_buf, .dataend = programdata_data_buf + PROGRAMDATA_METADATA_SIZE };
    FD_TEST( fd_bpf_upgradeable_loader_state_encode( &state, &ctx ) == FD_BINCODE_SUCCESS );
  }
  create_test_account( env->accdb, &env->xid, &programdata_key, 1000000UL,
                      PROGRAMDATA_METADATA_SIZE, programdata_data_buf, 5UL,
                      &fd_solana_bpf_loader_upgradeable_program_id );


/* test_bundle_program_coherency: regression test for the bundle program-cache coherency bug.
   Bug summary: when txn1 in a bundle upgrades an upgradeable BPF program (updating the
   programdata account), txn2 in the same bundle may observe stale programdata state from accdb
   rather than the bundle-forwarded state from txn1.  This happens because
   fd_executor_setup_executable_account loads the programdata account directly from accdb via
   fd_accdb_open_ro, bypassing the prev_txn_outs bundle-forwarding path.

   Specifically:
   - When txn2 does NOT include programdata in its own account list, the bundle-forwarding path
     (which only applies to accounts in the current transaction's account set) cannot help.
   - fd_executor_setup_executable_account derives programdata_address from the program account
     state and loads it from accdb — always using the committed (pre-bundle) state.
   - The delayed-visibility check at fd_bpf_loader_program.c reads this stale programdata slot,
     so it may incorrectly pass if the upgrade happened in the same bundle.

   This test asserts the CORRECT behavior: after txn1 upgrades a program (setting
   programdata.slot = current_slot), the programdata loaded into txn2's executable-account
   table should reflect the bundle-updated state (slot == 10), not the stale accdb state
   (slot == 5).

   Expected result: FD_TEST( pd_state.slot == 10UL ) passes.
   Current result with the bug present: FAIL — slot == 5 is observed. */

  /* Transaction 1: simulated upgrade.  Accounts: [payer, program, programdata] (all writable).
    We execute an empty transaction (no instructions) then manually update the programdata
    slot field in txn_out[0] to simulate what a real upgrade instruction would write. */
  txn_p = (fd_txn_p_t){0};
  fd_pubkey_t txn1_keys[3] = { payer, program_key, programdata_key };
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 3UL, txn1_keys, &dummy_hash );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  env->txn_in.txn                 = &txn_p;
  env->txn_in.bundle.is_bundle    = 1;
  env->txn_in.bundle.prev_txn_cnt = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );

  /* Locate programdata in txn1's output accounts. */
  int pd_idx = -1;
  for( ushort i = 0; i < env->txn_out[0].accounts.cnt; i++ ) {
    if( fd_pubkey_eq( &env->txn_out[0].accounts.keys[i], &programdata_key ) ) {
      pd_idx = i;
      break;
    }
  }
  FD_TEST( pd_idx >= 0 );
  FD_TEST( env->txn_out[0].accounts.is_writable[ pd_idx ] );

  /* Simulate the upgrade: set programdata.slot = 10 (= current slot) in txn1's output.
    After a real upgrade instruction, the on-chain programdata.slot would equal the upgrade slot,
    which triggers the delayed-visibility check for any same-slot invocation. */
  uchar * pd_out_data = fd_account_data( env->txn_out[0].accounts.account[ pd_idx ].meta );
  {
    fd_bpf_upgradeable_loader_state_t upgraded;
    fd_memset( &upgraded, 0, sizeof(upgraded) );
    upgraded.discriminant                                   = fd_bpf_upgradeable_loader_state_enum_program_data;
    upgraded.inner.program_data.slot                        = 10UL; /* now equals current slot */
    upgraded.inner.program_data.upgrade_authority_address   = authority_key;
    upgraded.inner.program_data.has_upgrade_authority_address = 1;
    fd_bincode_encode_ctx_t ctx = { .data = pd_out_data, .dataend = pd_out_data + PROGRAMDATA_METADATA_SIZE };
    FD_TEST( fd_bpf_upgradeable_loader_state_encode( &upgraded, &ctx ) == FD_BINCODE_SUCCESS );
  }

  /* Transaction 2: invoke the program WITHOUT listing programdata in the account set.
    Accounts: [payer, program_key] only — programdata_key is intentionally absent.
    This is the scenario in the bug: the invoking transaction does not explicitly include
    programdata, so the bundle-forwarding path (which only covers accounts in the current
    transaction's account list) cannot supply the updated programdata. */
  fd_pubkey_t txn2_keys[2] = { payer, program_key };
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, txn2_keys, &dummy_hash );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );

  /* KEY ASSERTION: inspect the programdata that was loaded into runtime->accounts.executable
    during txn2's account setup (fd_executor_setup_executable_account).

    fd_executor_setup_executable_account derives programdata_key from the program account state
    and opens it via fd_accdb_open_ro — directly from accdb, not from prev_txn_outs.  So the
    loaded programdata reflects the committed (pre-bundle) accdb state: slot == 5.

    The CORRECT bundle-coherent behavior would be to load the programdata from txn1's output
    (slot == 10), so that the delayed-visibility check fires and txn2 is rejected.

    When the bug is present:  pd_state.slot == 5  → assertion FAILS.
    When the bug is fixed:    pd_state.slot == 10 → assertion PASSES. */
  int found_programdata = 0;
  for( ushort i = 0; i < env->runtime->accounts.executable_cnt; i++ ) {
    fd_accdb_ro_t const * ro = &env->runtime->accounts.executable[i];
    if( !fd_pubkey_eq( fd_accdb_ref_address( ro ), &programdata_key ) ) continue;

    fd_bpf_upgradeable_loader_state_t pd_state[1];
    FD_TEST( fd_bpf_loader_program_get_state( ro->meta, pd_state ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( fd_bpf_upgradeable_loader_state_is_program_data( pd_state ) );

    /* Asserts correct (post-fix) behavior: programdata slot must reflect the bundle-updated
      state from txn1 (slot == 10), not the stale accdb state (slot == 5). */
    FD_TEST( pd_state->inner.program_data.slot == 10UL );
    found_programdata = 1;
    break;
  }
  FD_TEST( found_programdata );

  /* Clean up outstanding txn_outs from previous test */
  env->txn_out[0].err.is_committable = 0;
  env->txn_out[1].err.is_committable = 0;
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[0] );
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[1] );

  /* ==========================================================================
     Test: Bundle ALT stale read (regression)
     ==========================================================================
     Regression test for a bug where fd_executor_setup_txn_alut_account_keys
     was reading ALT accounts directly from funk rather than from
     prev_txn_outs.  When an earlier transaction in a bundle modifies an
     ALT (e.g. extends it), a later transaction must see those changes.

     Scenario:
       - An ALT account exists in funk with 4 addresses, but only 2 are
         initially active (last_extended_slot == current_slot, start_index == 2).
       - Txn0 in the bundle includes the ALT as writable and simulates an
         extension by setting last_extended_slot_start_index = 4 (all active).
       - Txn1 in the bundle is a V0 transaction that uses the ALT to resolve
         address at index 3, which is only valid after the extension.
       - Txn1 should succeed because it sees the extended ALT from txn0.
     ========================================================================== */

  {
    FD_TEST( fd_acc_pool_free( env->runtime->acc_pool ) == TEST_ACC_POOL_ACCOUNT_CNT );

    /* Initialize slot hashes sysvar so the sysvar cache can serve them
       to fd_executor_setup_txn_alut_account_keys. */

    uchar __attribute__((aligned(FD_SYSVAR_SLOT_HASHES_ALIGN)))
        slot_hashes_mem[ FD_SYSVAR_SLOT_HASHES_FOOTPRINT ];
    fd_sysvar_slot_hashes_new( slot_hashes_mem, FD_SYSVAR_SLOT_HASHES_CAP );

    fd_slot_hash_t * sh_deq = NULL;
    fd_slot_hashes_global_t * sh_global = fd_sysvar_slot_hashes_join( slot_hashes_mem, &sh_deq );
    FD_TEST( sh_global && sh_deq );

    for( ulong i = 0UL; i < 10UL; i++ ) {
      fd_slot_hash_t entry = { .slot = 10UL - i };
      fd_memset( entry.hash.hash, 0, 32UL );
      deq_fd_slot_hash_t_push_tail( sh_deq, entry );
    }

    fd_sysvar_slot_hashes_write( env->bank, env->accdb, &env->xid, NULL, sh_global );
    fd_sysvar_slot_hashes_leave( sh_global, sh_deq );
    fd_sysvar_slot_hashes_delete( slot_hashes_mem );

    fd_sysvar_cache_restore( env->bank, env->accdb, &env->xid );

    /* Create an ALT account with 4 address entries but only 2 are
       initially active (last_extended_slot == current_slot == 10,
       last_extended_slot_start_index == 2).

       The on-disk format is:
         [56 bytes]  fd_address_lookup_table_state_t (bincode-encoded)
         [N * 32 bytes]  addresses */

    fd_pubkey_t alut_key = { .ul[0] = 0xA107UL };

    ulong num_alut_addrs = 4UL;
    ulong alut_data_sz   = FD_LOOKUP_TABLE_META_SIZE + num_alut_addrs * 32UL;
    uchar alut_data[ FD_LOOKUP_TABLE_META_SIZE + 4 * 32 ];

    fd_address_lookup_table_state_t alut_state = {
      .discriminant = fd_address_lookup_table_state_enum_lookup_table,
      .inner = { .lookup_table = { .meta = {
        .deactivation_slot              = ULONG_MAX,
        .last_extended_slot             = 10UL,
        .last_extended_slot_start_index = 2,
        .authority                      = {{0}},
        .has_authority                  = 0,
      } } }
    };
    fd_bincode_encode_ctx_t enc_ctx = {
      .data    = alut_data,
      .dataend = alut_data + FD_LOOKUP_TABLE_META_SIZE
    };
    FD_TEST( fd_address_lookup_table_state_encode( &alut_state, &enc_ctx ) == FD_BINCODE_SUCCESS );

    fd_acct_addr_t * alut_addrs = (fd_acct_addr_t *)( alut_data + FD_LOOKUP_TABLE_META_SIZE );
    for( ulong i = 0UL; i < num_alut_addrs; i++ ) {
      fd_memset( alut_addrs[i].b, 0, 32UL );
      alut_addrs[i].b[0] = (uchar)( 0xE0 + i );
      alut_addrs[i].b[1] = (uchar)( 0xF0 + i );
    }

    create_test_account( env->accdb, &env->xid, &alut_key, 1000000UL,
                         (uint)alut_data_sz, alut_data, 10UL,
                         &fd_solana_address_lookup_table_program_id );

    /* ------------------------------------------------------------------
       Txn0: include the ALT as a writable account in a legacy-style
       transaction (no ALT lookups in this txn itself).  After execution,
       simulate the extension by modifying the ALT metadata in txn_out.
       ------------------------------------------------------------------ */

    fd_pubkey_t txn0_keys[2] = { pubkey1, alut_key };
    txn_p = (fd_txn_p_t){0};
    sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL,
                        2UL, txn0_keys, &dummy_hash );
    FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

    env->txn_in.txn                 = &txn_p;
    env->txn_in.bundle.is_bundle    = 1;
    env->txn_in.bundle.prev_txn_cnt = 0;
    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank,
                                        &env->txn_in, &env->txn_out[0] );
    FD_TEST( env->txn_out[0].err.is_committable );
    FD_TEST( env->txn_out[0].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );

    /* Find the ALT account in txn0's output and verify it's writable. */
    int alut_idx = -1;
    for( ushort i = 0; i < env->txn_out[0].accounts.cnt; i++ ) {
      if( fd_pubkey_eq( &env->txn_out[0].accounts.keys[i], &alut_key ) ) {
        alut_idx = i;
        break;
      }
    }
    FD_TEST( alut_idx >= 0 );
    FD_TEST( env->txn_out[0].accounts.is_writable[ alut_idx ] );

    /* Simulate extending the ALT: update last_extended_slot_start_index
       from 2 to 4 so that all 4 addresses become active. */
    uchar * alut_out_data = fd_account_data(
        env->txn_out[0].accounts.account[ alut_idx ].meta );
    fd_address_lookup_table_state_t extended_state = alut_state;
    extended_state.inner.lookup_table.meta.last_extended_slot_start_index = 4;
    fd_bincode_encode_ctx_t enc_ctx2 = {
      .data    = alut_out_data,
      .dataend = alut_out_data + FD_LOOKUP_TABLE_META_SIZE
    };
    FD_TEST( fd_address_lookup_table_state_encode( &extended_state, &enc_ctx2 )
             == FD_BINCODE_SUCCESS );

    /* ------------------------------------------------------------------
       Txn1: a V0 transaction that uses the ALT to resolve address at
       index 3 (writable).  Index 3 is only valid if the extension from
       txn0 is visible.

       We manually construct the fd_txn_t descriptor and payload since
       the existing txn_serialize helper doesn't support ALT references.
       ------------------------------------------------------------------ */

    fd_txn_p_t txn1_p = {0};
    uchar * pl = txn1_p.payload;
    ulong   off = 0UL;

    /* signature count (compact-u16 == 1 byte for values < 128) */
    pl[off++] = 1;
    fd_memset( pl + off, 0, 64UL );  /* one empty signature */
    off += 64UL;

    /* V0 prefix byte */
    pl[off++] = 0x80;

    /* message header */
    pl[off++] = 1;   /* num_required_signatures */
    pl[off++] = 0;   /* num_readonly_signed */
    pl[off++] = 0;   /* num_readonly_unsigned */

    /* static account keys: just pubkey1 (fee payer) */
    pl[off++] = 1;   /* compact-u16 account count */
    fd_memcpy( pl + off, &pubkey1, 32UL );
    ulong acct_addr_off = off;
    off += 32UL;

    /* recent blockhash */
    ulong rbh_off = off;
    fd_memcpy( pl + off, &dummy_hash, 32UL );
    off += 32UL;

    /* instruction count = 0 */
    pl[off++] = 0;

    /* address table lookups: 1 lookup referencing alut_key,
       writable_indices = [3], readonly_indices = [] */
    pl[off++] = 1;   /* addr_table_lookup_cnt */
    ulong alut_addr_payload_off = off;
    fd_memcpy( pl + off, &alut_key, 32UL );
    off += 32UL;
    pl[off++] = 1;   /* writable count */
    pl[off++] = 3;   /* writable index: address at position 3 */
    ulong writable_off = off - 1UL;
    pl[off++] = 0;   /* readonly count */

    txn1_p.payload_sz = (ushort)off;

    /* Build a matching fd_txn_t descriptor.  We use a union with enough
       room for 0 instructions + 1 ALT lookup. */
    uchar txn1_mem[ sizeof(fd_txn_t) + sizeof(fd_txn_acct_addr_lut_t) ] __attribute__((aligned(16UL)));
    fd_txn_t * txn1 = (fd_txn_t *)txn1_mem;
    fd_memset( txn1, 0, sizeof(txn1_mem) );

    txn1->transaction_version       = FD_TXN_V0;
    txn1->signature_cnt             = 1;
    txn1->signature_off             = 1;
    txn1->message_off               = 65;
    txn1->readonly_signed_cnt       = 0;
    txn1->readonly_unsigned_cnt     = 0;
    txn1->acct_addr_cnt             = 1;
    txn1->acct_addr_off             = (ushort)acct_addr_off;
    txn1->recent_blockhash_off      = (ushort)rbh_off;
    txn1->instr_cnt                 = 0;
    txn1->addr_table_lookup_cnt     = 1;
    txn1->addr_table_adtl_writable_cnt = 1;
    txn1->addr_table_adtl_cnt       = 1;

    fd_txn_acct_addr_lut_t * lut = fd_txn_get_address_tables( txn1 );
    lut->addr_off     = (ushort)alut_addr_payload_off;
    lut->writable_cnt = 1;
    lut->writable_off = (ushort)writable_off;
    lut->readonly_cnt = 0;
    lut->readonly_off = (ushort)off;

    FD_TEST( sizeof(txn1_mem) <= sizeof(txn1_p._) );
    fd_memcpy( txn1_p._, txn1_mem, sizeof(txn1_mem) );

    env->txn_in.txn                     = &txn1_p;
    env->txn_in.bundle.is_bundle        = 1;
    env->txn_in.bundle.prev_txn_cnt     = 1;
    env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank,
                                        &env->txn_in, &env->txn_out[1] );

    FD_TEST( env->txn_out[1].err.is_committable );
    FD_TEST( env->txn_out[1].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );

    /* Verify the resolved address matches what we put into index 3. */
    fd_pubkey_t expected_addr = {{0}};
    expected_addr.uc[0] = 0xE3;
    expected_addr.uc[1] = 0xF3;
    FD_TEST( fd_pubkey_eq( &env->txn_out[1].accounts.keys[1], &expected_addr ) );

    /* Clean up */
    if( env->txn_out[1].err.is_committable ) {
      fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[1] );
    } else {
      fd_runtime_cancel_txn( env->runtime, &env->txn_out[1] );
    }
    fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[0] );
  }
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
