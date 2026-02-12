/* Test accounts_resize_delta tracking with signed arithmetic. */

#include "../fd_acc_pool.h"
#include "../fd_runtime.h"
#include "../fd_runtime_stack.h"
#include "../fd_bank.h"
#include "../fd_system_ids.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../sysvar/fd_sysvar_stake_history.h"
#include "../sysvar/fd_sysvar_clock.h"
#include "../program/fd_builtin_programs.h"
#include "../../accdb/fd_accdb_admin_v1.h"
#include "../../accdb/fd_accdb_impl_v1.h"
#include "../../features/fd_features.h"
#include "../../accdb/fd_accdb_sync.h"
#include "../../progcache/fd_progcache_admin.h"
#include "../../progcache/fd_progcache_user.h"
#include "../../log_collector/fd_log_collector.h"

#define MiB (1L << 20)

#define TEST_SLOTS_PER_EPOCH       (3UL)
#define TEST_ACC_POOL_ACCOUNT_CNT  (32UL)
#define TEST_LAMPORTS              (100000000000UL)

#define LOADER_V4_SET_PROGRAM_LENGTH_IX (2U)
#define LOADER_V4_PROGRAM_DATA_OFFSET   (48UL)
#define LOADER_V4_STATUS_RETRACTED      (0UL)

#define SYSTEM_PROGRAM_IX_ALLOCATE (8U)

struct test_env {
  fd_wksp_t *          wksp;
  ulong                tag;
  fd_banks_t           banks[1];
  fd_bank_t            bank[1];
  void *               funk_mem;
  fd_accdb_admin_t     accdb_admin[1];
  fd_accdb_user_t      accdb[1];
  void *               pcache_mem;
  fd_progcache_admin_t progcache_admin[1];
  fd_progcache_t       progcache[1];
  uchar *              progcache_scratch;
  fd_funk_txn_xid_t    xid;
  fd_runtime_stack_t * runtime_stack;

  fd_runtime_t *       runtime;
  fd_txn_in_t          txn_in;
  fd_txn_out_t         txn_out[1];
  fd_log_collector_t   log_collector[1];
};
typedef struct test_env test_env_t;

static void
create_account_raw( fd_accdb_user_t *         user,
                    fd_funk_txn_xid_t const * xid,
                    fd_pubkey_t const *       pubkey,
                    ulong                     lamports,
                    uint                      dlen,
                    uchar *                   data,
                    fd_pubkey_t const *       owner ) {
  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( user, rw, xid, pubkey, dlen, FD_ACCDB_FLAG_CREATE ) );
  fd_accdb_ref_data_set( user, rw, data, dlen );
  rw->meta->lamports = lamports;
  rw->meta->slot = 10UL;
  rw->meta->executable = 0;
  if( owner ) {
    memcpy( rw->meta->owner, owner->key, 32UL );
  } else {
    memset( rw->meta->owner, 0UL, 32UL );
  }
  fd_accdb_close_rw( user, rw );
}

static void
init_rent_sysvar( test_env_t * env ) {
  fd_rent_t rent = {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
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
test_env_init( test_env_t * env, fd_wksp_t * wksp, int enable_loader_v4 ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->wksp = wksp;
  env->tag  = 1UL;

  ulong const funk_seed       = 17UL;
  ulong const txn_max         = 16UL;
  ulong const rec_max         = 1024UL;
  ulong const max_total_banks = 2UL;
  ulong const max_fork_width  = 2UL;

  env->funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), env->tag );
  FD_TEST( env->funk_mem );
  FD_TEST( fd_funk_new( env->funk_mem, env->tag, funk_seed, txn_max, rec_max ) );
  FD_TEST( fd_accdb_admin_v1_init( env->accdb_admin, env->funk_mem ) );
  FD_TEST( fd_accdb_user_v1_init( env->accdb, env->funk_mem ) );

  env->pcache_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), env->tag );
  FD_TEST( env->pcache_mem );
  FD_TEST( fd_funk_new( env->pcache_mem, env->tag, funk_seed+1, txn_max, rec_max ) );
  env->progcache_scratch = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT, env->tag );
  FD_TEST( env->progcache_scratch );
  FD_TEST( fd_progcache_join( env->progcache, env->pcache_mem, env->progcache_scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
  FD_TEST( fd_progcache_admin_join( env->progcache_admin, env->pcache_mem ) );

  fd_banks_data_t * banks_data = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( max_total_banks, max_fork_width ), env->tag );
  FD_TEST( banks_data );
  fd_banks_locks_t * banks_locks = fd_wksp_alloc_laddr( wksp, alignof(fd_banks_locks_t), sizeof(fd_banks_locks_t), env->tag );
  FD_TEST( banks_locks );
  fd_banks_locks_init( banks_locks );
  FD_TEST( fd_banks_join( env->banks, fd_banks_new( banks_data, max_total_banks, max_fork_width, 8888UL ), banks_locks ) );
  FD_TEST( fd_banks_init_bank( env->bank, env->banks ) );

  env->runtime_stack = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_stack_t), sizeof(fd_runtime_stack_t), env->tag );
  FD_TEST( env->runtime_stack );
  fd_memset( env->runtime_stack, 0, sizeof(fd_runtime_stack_t) );

  fd_funk_txn_xid_t root[1];
  fd_funk_txn_xid_set_root( root );
  env->xid = (fd_funk_txn_xid_t){ .ul = { 0UL, env->bank->data->idx } };
  fd_accdb_attach_child( env->accdb_admin, root, &env->xid );
  fd_progcache_txn_attach_child( env->progcache_admin, root, &env->xid );

  init_rent_sysvar( env );
  init_epoch_schedule_sysvar( env );
  init_stake_history_sysvar( env );
  init_clock_sysvar( env );
  init_blockhash_queue( env );

  fd_bank_slot_set( env->bank, 0UL );
  fd_bank_epoch_set( env->bank, 0UL );

  if( enable_loader_v4 ) {
    fd_features_t features = {0};
    fd_features_disable_all( &features );
    features.enable_loader_v4 = 0UL;
    fd_bank_features_set( env->bank, features );
  }

  fd_builtin_programs_init( env->bank, env->accdb, &env->xid, NULL );

  env->runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), env->tag );
  uchar * acc_pool_mem = fd_wksp_alloc_laddr( wksp, fd_acc_pool_align(), fd_acc_pool_footprint( TEST_ACC_POOL_ACCOUNT_CNT ), env->tag );
  fd_acc_pool_t * acc_pool = fd_acc_pool_join( fd_acc_pool_new( acc_pool_mem, TEST_ACC_POOL_ACCOUNT_CNT ) );
  FD_TEST( acc_pool );

  env->runtime->accdb                    = &env->accdb[0];
  env->runtime->progcache                = env->progcache;
  env->runtime->status_cache             = NULL;
  env->runtime->acc_pool                 = acc_pool;
  fd_log_collector_init( env->log_collector, 0 );
  env->runtime->log.log_collector        = env->log_collector;
  env->runtime->log.enable_log_collector = 0;
  env->runtime->log.dumping_mem          = NULL;
  env->runtime->log.enable_vm_tracing    = 0;
  env->runtime->log.tracing_mem          = NULL;
  env->runtime->log.capture_ctx          = NULL;

  return env;
}

static void
test_env_cleanup( test_env_t * env ) {
  FD_TEST( env );

  env->txn_out[0].err.is_committable = 0;
  if( env->runtime ) {
    fd_runtime_cancel_txn( env->runtime, &env->txn_out[0] );
  }

  fd_accdb_cancel( env->accdb_admin, &env->xid );
  fd_progcache_txn_cancel( env->progcache_admin, &env->xid );

  if( env->runtime ) {
    if( env->runtime->acc_pool ) {
      fd_wksp_free_laddr( env->runtime->acc_pool );
    }
    fd_wksp_free_laddr( env->runtime );
  }

  fd_wksp_free_laddr( env->runtime_stack );
  fd_wksp_free_laddr( env->banks->data );
  fd_wksp_free_laddr( env->banks->locks );

  fd_progcache_leave( env->progcache, NULL );
  void * pcache_funk = NULL;
  fd_progcache_admin_leave( env->progcache_admin, &pcache_funk );
  fd_wksp_free_laddr( fd_funk_delete( pcache_funk ) );
  fd_wksp_free_laddr( env->progcache_scratch );

  void * accdb_shfunk = fd_accdb_admin_v1_funk( env->accdb_admin )->shmem;
  fd_accdb_admin_fini( env->accdb_admin );
  fd_accdb_user_fini( env->accdb );
  fd_wksp_free_laddr( fd_funk_delete( accdb_shfunk ) );

  fd_wksp_reset( env->wksp, (uint)env->tag );
  fd_memset( env, 0, sizeof(test_env_t) );
}

static void
process_slot( test_env_t * env, ulong slot ) {
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
  fd_progcache_txn_attach_child( env->progcache_admin, &parent_xid, &xid );

  env->xid = xid;

  int is_epoch_boundary = 0;
  fd_runtime_block_execute_prepare( env->banks, env->bank, env->accdb, env->runtime_stack, NULL, &is_epoch_boundary );
}

static void
create_allocatable_account( test_env_t * env, fd_pubkey_t const * pubkey ) {
  fd_pubkey_t system_program = fd_solana_system_program_id;
  create_account_raw( env->accdb, &env->xid, pubkey, TEST_LAMPORTS, 0UL, NULL, &system_program );
}

static void
create_loader_v4_program( test_env_t *        env,
                          fd_pubkey_t const * pubkey,
                          fd_pubkey_t const * authority,
                          ulong               program_size ) {
  ulong dlen = LOADER_V4_PROGRAM_DATA_OFFSET + program_size;
  uchar * data = fd_alloca( 8UL, dlen );
  fd_memset( data, 0, dlen );

  FD_STORE( ulong, data, 0UL );
  fd_memcpy( data + 8, authority->uc, 32 );
  FD_STORE( ulong, data + 40, LOADER_V4_STATUS_RETRACTED );

  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( env->accdb, rw, &env->xid, pubkey, (uint)dlen, FD_ACCDB_FLAG_CREATE ) );
  fd_accdb_ref_data_set( env->accdb, rw, data, (uint)dlen );
  rw->meta->lamports = TEST_LAMPORTS;
  rw->meta->slot = 10UL;
  rw->meta->executable = 1;
  fd_memcpy( rw->meta->owner, fd_solana_bpf_loader_v4_program_id.uc, 32 );
  fd_accdb_close_rw( env->accdb, rw );
}

static void
create_simple_account( test_env_t * env, fd_pubkey_t const * pubkey, ulong lamports ) {
  create_account_raw( env->accdb, &env->xid, pubkey, lamports, 0UL, NULL, NULL );
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

struct txn_instr {
  uchar   program_id_idx;
  uchar * account_idxs;
  ushort  account_idxs_cnt;
  uchar * data;
  ushort  data_sz;
};
typedef struct txn_instr txn_instr_t;

static ulong
txn_serialize( uchar *          txn_raw_begin,
               ulong            signatures_cnt,
               fd_signature_t * signatures,
               ulong            num_required_signatures,
               ulong            num_readonly_signed_accounts,
               ulong            num_readonly_unsigned_accounts,
               ulong            account_keys_cnt,
               fd_pubkey_t *    account_keys,
               fd_hash_t *      recent_blockhash,
               txn_instr_t *    instrs,
               ushort           instr_cnt ) {
  uchar * txn_raw_cur_ptr = txn_raw_begin;

  uchar signature_cnt = fd_uchar_max( 1, (uchar)signatures_cnt );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &signature_cnt, sizeof(uchar) );
  for( uchar i = 0; i < signature_cnt; ++i ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &signatures[i], FD_TXN_SIGNATURE_SZ );
  }

  uchar header_b0 = (uchar) 0x80UL;
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &header_b0, sizeof(uchar) );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_required_signatures,        sizeof(uchar) );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_readonly_signed_accounts,   sizeof(uchar) );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_readonly_unsigned_accounts, sizeof(uchar) );

  ushort num_acct_keys = (ushort)account_keys_cnt;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, num_acct_keys );
  for( ushort i = 0; i < num_acct_keys; ++i ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &account_keys[i], sizeof(fd_pubkey_t) );
  }

  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, recent_blockhash, sizeof(fd_hash_t) );

  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instr_cnt );
  for( ushort i = 0; i < instr_cnt; ++i ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &instrs[i].program_id_idx, sizeof(uchar) );
    FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instrs[i].account_idxs_cnt );
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instrs[i].account_idxs, instrs[i].account_idxs_cnt );
    FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instrs[i].data_sz );
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instrs[i].data, instrs[i].data_sz );
  }

  ushort addr_table_cnt = 0;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, addr_table_cnt );

  return (ulong)(txn_raw_cur_ptr - txn_raw_begin);
}

static void
build_allocate_instr( uchar * data, ulong space ) {
  data[0] = SYSTEM_PROGRAM_IX_ALLOCATE;
  data[1] = 0; data[2] = 0; data[3] = 0;
  for( int i = 0; i < 8; i++ ) {
    data[4+i] = (uchar)((space >> (i*8)) & 0xFF);
  }
}

static void
build_shrink_instr( uchar * data, uint new_size ) {
  data[0] = LOADER_V4_SET_PROGRAM_LENGTH_IX;
  data[1] = 0; data[2] = 0; data[3] = 0;
  data[4] = (uchar)(new_size       & 0xFF);
  data[5] = (uchar)((new_size>>8)  & 0xFF);
  data[6] = (uchar)((new_size>>16) & 0xFF);
  data[7] = (uchar)((new_size>>24) & 0xFF);
}

static void
execute_txn( test_env_t *     env,
             fd_pubkey_t *    account_keys,
             ulong            account_keys_cnt,
             ulong            num_signers,
             ulong            num_readonly_unsigned,
             txn_instr_t *    instrs,
             ushort           instr_cnt ) {
  fd_signature_t signatures[8] = {0};
  fd_hash_t blockhash = {0};
  fd_memset( blockhash.uc, 0xAB, FD_HASH_FOOTPRINT );

  fd_txn_p_t txn_p = {0};
  ulong sz = txn_serialize( txn_p.payload, num_signers, signatures, num_signers,
                            0UL, num_readonly_unsigned, account_keys_cnt, account_keys,
                            &blockhash, instrs, instr_cnt );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 0;

  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
}

static int
txn_succeeded( test_env_t * env ) {
  return env->txn_out[0].err.is_committable &&
         env->txn_out[0].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS;
}

static long
get_resize_delta( test_env_t * env ) {
  return env->txn_out[0].details.accounts_resize_delta;
}

/* Empty txn has delta=0 */
static void
test_empty_txn_delta_is_zero( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_init( env, wksp, 0 );
  process_slot( env, 10UL );

  fd_pubkey_t acct1 = { .ul[0] = 1UL };
  fd_pubkey_t acct2 = { .ul[0] = 2UL };
  create_simple_account( env, &acct1, 1000000UL );
  create_simple_account( env, &acct2, 1000000UL );

  fd_pubkey_t keys[2] = { acct1, acct2 };
  execute_txn( env, keys, 2, 1, 0, NULL, 0 );

  FD_TEST( txn_succeeded( env ) );
  FD_TEST( get_resize_delta( env ) == 0L );

  test_env_cleanup( env );
  FD_LOG_NOTICE(( "test_empty_txn_delta_is_zero: PASSED" ));
}

/* 10+9=19 MiB under limit */
static void
test_allocate_19mib_succeeds( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_init( env, wksp, 0 );
  process_slot( env, 10UL );

  fd_pubkey_t acct_a = { .ul[0] = 0xA0UL };
  fd_pubkey_t acct_b = { .ul[0] = 0xB0UL };
  create_allocatable_account( env, &acct_a );
  create_allocatable_account( env, &acct_b );

  fd_pubkey_t system = fd_solana_system_program_id;
  fd_pubkey_t keys[3] = { acct_a, acct_b, system };

  uchar data_a[12], data_b[12];
  build_allocate_instr( data_a, 10UL * (ulong)MiB );
  build_allocate_instr( data_b,  9UL * (ulong)MiB );

  uchar idx_a[1] = {0}, idx_b[1] = {1};
  txn_instr_t instrs[2] = {
    { .program_id_idx = 2, .account_idxs = idx_a, .account_idxs_cnt = 1, .data = data_a, .data_sz = 12 },
    { .program_id_idx = 2, .account_idxs = idx_b, .account_idxs_cnt = 1, .data = data_b, .data_sz = 12 },
  };
  execute_txn( env, keys, 3, 2, 1, instrs, 2 );

  FD_TEST( txn_succeeded( env ) );
  FD_TEST( get_resize_delta( env ) == 19L * MiB );
  FD_LOG_NOTICE(( "test_allocate_19mib_succeeds: PASSED (delta = %ld MiB)", get_resize_delta( env ) / MiB ));

  test_env_cleanup( env );
}

/* 10+10=20 MiB at limit */
static void
test_allocate_20mib_succeeds( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_init( env, wksp, 0 );
  process_slot( env, 10UL );

  fd_pubkey_t acct_a = { .ul[0] = 0xA2UL };
  fd_pubkey_t acct_b = { .ul[0] = 0xB2UL };
  create_allocatable_account( env, &acct_a );
  create_allocatable_account( env, &acct_b );

  fd_pubkey_t system = fd_solana_system_program_id;
  fd_pubkey_t keys[3] = { acct_a, acct_b, system };

  uchar data_a[12], data_b[12];
  build_allocate_instr( data_a, 10UL * (ulong)MiB );
  build_allocate_instr( data_b, 10UL * (ulong)MiB );

  uchar idx_a[1] = {0}, idx_b[1] = {1};
  txn_instr_t instrs[2] = {
    { .program_id_idx = 2, .account_idxs = idx_a, .account_idxs_cnt = 1, .data = data_a, .data_sz = 12 },
    { .program_id_idx = 2, .account_idxs = idx_b, .account_idxs_cnt = 1, .data = data_b, .data_sz = 12 },
  };
  execute_txn( env, keys, 3, 2, 1, instrs, 2 );

  FD_TEST( txn_succeeded( env ) );
  FD_TEST( get_resize_delta( env ) == 20L * MiB );
  FD_LOG_NOTICE(( "test_allocate_20mib_succeeds: PASSED (delta = %ld MiB)", get_resize_delta( env ) / MiB ));

  test_env_cleanup( env );
}

/* 15+10=25 MiB exceeds limit */
static void
test_allocate_25mib_fails( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_init( env, wksp, 0 );
  process_slot( env, 10UL );

  fd_pubkey_t acct_a = { .ul[0] = 0xA1UL };
  fd_pubkey_t acct_b = { .ul[0] = 0xB1UL };
  create_allocatable_account( env, &acct_a );
  create_allocatable_account( env, &acct_b );

  fd_pubkey_t system = fd_solana_system_program_id;
  fd_pubkey_t keys[3] = { acct_a, acct_b, system };

  uchar data_a[12], data_b[12];
  build_allocate_instr( data_a, 15UL * (ulong)MiB );
  build_allocate_instr( data_b, 10UL * (ulong)MiB );

  uchar idx_a[1] = {0}, idx_b[1] = {1};
  txn_instr_t instrs[2] = {
    { .program_id_idx = 2, .account_idxs = idx_a, .account_idxs_cnt = 1, .data = data_a, .data_sz = 12 },
    { .program_id_idx = 2, .account_idxs = idx_b, .account_idxs_cnt = 1, .data = data_b, .data_sz = 12 },
  };
  execute_txn( env, keys, 3, 2, 1, instrs, 2 );

  FD_TEST( !txn_succeeded( env ) );

  test_env_cleanup( env );
  FD_LOG_NOTICE(( "test_allocate_25mib_fails: PASSED" ));
}

/* Shrink gives negative delta */
static void
test_shrink_gives_negative_delta( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_init( env, wksp, 1 );
  process_slot( env, 10UL );

  fd_pubkey_t authority  = { .ul[0] = 0xA3UL };
  fd_pubkey_t program    = { .ul[0] = 0xC3UL };
  fd_pubkey_t recipient  = { .ul[0] = 0xD3UL };
  ulong program_size = 5UL * (ulong)MiB;

  create_simple_account( env, &authority, TEST_LAMPORTS );
  create_loader_v4_program( env, &program, &authority, program_size );
  create_simple_account( env, &recipient, 1000000UL );

  fd_pubkey_t loader_v4 = fd_solana_bpf_loader_v4_program_id;
  fd_pubkey_t keys[4] = { authority, program, recipient, loader_v4 };

  uchar shrink_data[8];
  build_shrink_instr( shrink_data, 0 );

  uchar idx[3] = { 1, 0, 2 };
  txn_instr_t instrs[1] = {
    { .program_id_idx = 3, .account_idxs = idx, .account_idxs_cnt = 3, .data = shrink_data, .data_sz = 8 },
  };
  execute_txn( env, keys, 4, 1, 1, instrs, 1 );

  FD_TEST( txn_succeeded( env ) );
  FD_TEST( get_resize_delta( env ) < 0L );
  FD_TEST( get_resize_delta( env ) <= -5L * MiB );
  FD_LOG_NOTICE(( "test_shrink_gives_negative_delta: PASSED (delta = %ld bytes)", get_resize_delta( env ) ));

  test_env_cleanup( env );
}

/* Shrink enables allocation that would otherwise exceed limit.
   10+10-5+5 = 20 MiB. With unsigned arithmetic this would fail. */
static void
test_shrink_enables_more_allocation( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_init( env, wksp, 1 );
  process_slot( env, 10UL );

  fd_pubkey_t authority  = { .ul[0] = 0xA4UL };
  fd_pubkey_t program    = { .ul[0] = 0xC4UL };
  fd_pubkey_t recipient  = { .ul[0] = 0xD4UL };
  fd_pubkey_t acct_a     = { .ul[0] = 0xE4UL };
  fd_pubkey_t acct_b     = { .ul[0] = 0xF4UL };
  fd_pubkey_t acct_c     = { .ul[0] = 0x14UL };
  ulong shrink_size = 5UL * (ulong)MiB;

  create_simple_account( env, &authority, TEST_LAMPORTS );
  create_loader_v4_program( env, &program, &authority, shrink_size );
  create_simple_account( env, &recipient, 1000000UL );
  create_allocatable_account( env, &acct_a );
  create_allocatable_account( env, &acct_b );
  create_allocatable_account( env, &acct_c );

  fd_pubkey_t system = fd_solana_system_program_id;
  fd_pubkey_t loader_v4 = fd_solana_bpf_loader_v4_program_id;
  fd_pubkey_t keys[8] = { authority, acct_a, acct_b, acct_c, program, recipient, system, loader_v4 };

  uchar alloc_a[12], alloc_b[12], alloc_c[12], shrink[8];
  build_allocate_instr( alloc_a, 10UL * (ulong)MiB );
  build_allocate_instr( alloc_b, 10UL * (ulong)MiB );
  build_allocate_instr( alloc_c,  5UL * (ulong)MiB );
  build_shrink_instr( shrink, 0 );

  uchar idx_a[1] = {1}, idx_b[1] = {2}, idx_c[1] = {3};
  uchar idx_shrink[3] = { 4, 0, 5 };

  txn_instr_t instrs[4] = {
    { .program_id_idx = 6, .account_idxs = idx_a,      .account_idxs_cnt = 1, .data = alloc_a, .data_sz = 12 },
    { .program_id_idx = 6, .account_idxs = idx_b,      .account_idxs_cnt = 1, .data = alloc_b, .data_sz = 12 },
    { .program_id_idx = 7, .account_idxs = idx_shrink, .account_idxs_cnt = 3, .data = shrink,  .data_sz = 8 },
    { .program_id_idx = 6, .account_idxs = idx_c,      .account_idxs_cnt = 1, .data = alloc_c, .data_sz = 12 },
  };
  execute_txn( env, keys, 8, 4, 2, instrs, 4 );

  FD_TEST( txn_succeeded( env ) );
  long delta = get_resize_delta( env );
  /* Expected: 10 MiB + 10 MiB - (5 MiB + 48 bytes metadata) + 5 MiB = 20 MiB - 48 bytes */
  FD_TEST( delta == 20L * MiB - (long)LOADER_V4_PROGRAM_DATA_OFFSET );
  FD_LOG_NOTICE(( "test_shrink_enables_more_allocation: PASSED (delta = %ld bytes)", delta ));

  test_env_cleanup( env );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx > fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr( &argc, &argv,  "--page-sz",  NULL, "normal" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1572864UL );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_empty_txn_delta_is_zero( wksp );
  test_allocate_19mib_succeeds( wksp );
  test_allocate_20mib_succeeds( wksp );
  test_allocate_25mib_fails( wksp );
  test_shrink_gives_negative_delta( wksp );
  test_shrink_enables_more_allocation( wksp );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
