/* Test for SIMD-0312: create_account_allow_prefund */

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
#include "../../progcache/fd_progcache.h"
#include "../../progcache/fd_progcache_admin.h"
#include "../../progcache/fd_progcache_user.h"
#include "../../log_collector/fd_log_collector.h"

#define TEST_SLOTS_PER_EPOCH      (3UL)
#define TEST_ACC_POOL_ACCOUNT_CNT (32UL)
#define TEST_LAMPORTS             (100000000000UL)

static fd_pubkey_t const TO_PUBKEY = {{
  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
}};

static fd_pubkey_t const FROM_PUBKEY = {{
  0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
  0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
  0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
  0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,
}};

static fd_pubkey_t const OWNER_PUBKEY = {{
  0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
  0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
  0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
  0x03,0x03,0x03,0x03,0x03,0x03,0x03,0x03,
}};

struct test_env {
  fd_wksp_t *          wksp;
  ulong                tag;
  fd_banks_t *         banks;
  fd_bank_t *          bank;
  void *               funk_mem;
  void *               funk_locks;
  fd_accdb_admin_t     accdb_admin[1];
  fd_accdb_user_t      accdb[1];
  void *               pcache_mem;
  fd_progcache_t       progcache[1];
  uchar *              progcache_scratch;
  fd_funk_txn_xid_t    xid;
  fd_runtime_stack_t * runtime_stack;

  fd_runtime_t *       runtime;
  fd_txn_p_t           txn_p[1];
  fd_txn_in_t          txn_in[1];
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
  env->bank->f.rent = rent;
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
  env->bank->f.epoch_schedule = epoch_schedule;
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
  fd_blockhashes_t * bhq = fd_blockhashes_init( &env->bank->f.block_hash_queue, blockhash_seed );
  fd_hash_t dummy_hash = {0};
  fd_memset( dummy_hash.uc, 0xAB, FD_HASH_FOOTPRINT );
  fd_blockhash_info_t * info = fd_blockhashes_push_new( bhq, &dummy_hash );
  info->fee_calculator.lamports_per_signature = 0UL;
}

static test_env_t *
test_env_init( test_env_t * env, fd_wksp_t * wksp ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->wksp = wksp;
  env->tag  = 1UL;

  ulong const funk_seed       = 17UL;
  ulong const txn_max         = 16UL;
  ulong const rec_max         = 1024UL;
  ulong const max_total_banks = 2UL;
  ulong const max_fork_width  = 2UL;

  env->funk_mem   = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_shmem_footprint( txn_max, rec_max ), env->tag );
  env->funk_locks = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_locks_footprint( txn_max, rec_max ), env->tag );
  FD_TEST( env->funk_mem );
  FD_TEST( env->funk_locks );
  FD_TEST( fd_funk_shmem_new( env->funk_mem, env->tag, funk_seed, txn_max, rec_max ) );
  FD_TEST( fd_funk_locks_new( env->funk_locks, txn_max, rec_max ) );
  FD_TEST( fd_accdb_admin_v1_init( env->accdb_admin, env->funk_mem, env->funk_locks ) );
  FD_TEST( fd_accdb_user_v1_init( env->accdb, env->funk_mem, env->funk_locks, txn_max ) );

  env->pcache_mem = fd_wksp_alloc_laddr( wksp, fd_progcache_shmem_align(), fd_progcache_shmem_footprint( txn_max, rec_max ), env->tag );
  FD_TEST( env->pcache_mem );
  FD_TEST( fd_progcache_shmem_new( env->pcache_mem, env->tag, funk_seed+1, txn_max, rec_max ) );
  env->progcache_scratch = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT, env->tag );
  FD_TEST( env->progcache_scratch );
  FD_TEST( fd_progcache_join( env->progcache, env->pcache_mem, env->progcache_scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );

  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( max_total_banks, max_fork_width, 2048UL, 2048UL ), env->tag );
  FD_TEST( banks_mem );
  env->banks = fd_banks_join( fd_banks_new( banks_mem, max_total_banks, max_fork_width, 2048UL, 2048UL, 0, 8888UL ) );
  FD_TEST( env->banks );
  env->bank = fd_banks_init_bank( env->banks );
  FD_TEST( env->bank );

  env->runtime_stack = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_stack_t), sizeof(fd_runtime_stack_t), env->tag );
  FD_TEST( env->runtime_stack );
  fd_memset( env->runtime_stack, 0, sizeof(fd_runtime_stack_t) );

  fd_funk_txn_xid_t root[1];
  fd_funk_txn_xid_set_root( root );
  env->xid = (fd_funk_txn_xid_t){ .ul = { 9UL, env->bank->idx } };
  fd_accdb_attach_child    ( env->accdb_admin,     root, &env->xid );
  fd_progcache_attach_child( env->progcache->join, root, &env->xid );

  init_rent_sysvar( env );
  init_epoch_schedule_sysvar( env );
  init_stake_history_sysvar( env );
  init_clock_sysvar( env );
  init_blockhash_queue( env );

  env->bank->f.slot = 9UL;
  env->bank->f.epoch = 4UL;

  fd_bank_top_votes_t_2_modify( env->bank );

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
  memset( &env->runtime->log, 0, sizeof(env->runtime->log) );
  env->runtime->log.log_collector        = env->log_collector;

  return env;
}

static void
test_env_cleanup( test_env_t * env ) {
  FD_TEST( env );

  env->txn_out[0].err.is_committable = 0;
  if( env->runtime ) {
    fd_runtime_cancel_txn( env->runtime, &env->txn_out[0] );
  }

  fd_accdb_cancel    ( env->accdb_admin,     &env->xid );
  fd_progcache_cancel( env->progcache->join, &env->xid );

  if( env->runtime ) {
    if( env->runtime->acc_pool ) {
      fd_wksp_free_laddr( env->runtime->acc_pool );
    }
    fd_wksp_free_laddr( env->runtime );
  }

  fd_wksp_free_laddr( env->runtime_stack );
  fd_wksp_free_laddr( env->banks );

  fd_progcache_shmem_t * shpcache = NULL;
  fd_progcache_leave( env->progcache, &shpcache );
  fd_wksp_free_laddr( fd_progcache_shmem_delete( shpcache ) );
  fd_wksp_free_laddr( env->progcache_scratch );

  void * accdb_shfunk = fd_accdb_admin_v1_funk( env->accdb_admin )->shmem;
  fd_accdb_admin_fini( env->accdb_admin );
  fd_accdb_user_fini( env->accdb );
  fd_wksp_free_laddr( env->funk_locks );
  fd_wksp_free_laddr( fd_funk_delete( accdb_shfunk ) );

  fd_wksp_reset( env->wksp, (uint)env->tag );
  fd_memset( env, 0, sizeof(test_env_t) );
}

static void
process_slot( test_env_t * env, ulong slot ) {
  fd_bank_t * parent_bank = env->bank;
  ulong parent_slot       = parent_bank->f.slot;
  ulong parent_bank_idx   = parent_bank->idx;

  FD_TEST( parent_bank->flags & FD_BANK_FLAGS_FROZEN );

  ulong new_bank_idx = fd_banks_new_bank( env->banks, parent_bank_idx, 0L )->idx;
  fd_bank_t * new_bank = fd_banks_clone_from_parent( env->banks, new_bank_idx );
  FD_TEST( new_bank );

  new_bank->f.slot = slot;
  new_bank->f.parent_slot = parent_slot;

  fd_epoch_schedule_t const * epoch_schedule = &new_bank->f.epoch_schedule;
  ulong epoch = fd_slot_to_epoch( epoch_schedule, slot, NULL );
  new_bank->f.epoch = epoch;

  fd_funk_txn_xid_t xid        = { .ul = { slot, new_bank_idx } };
  fd_funk_txn_xid_t parent_xid = { .ul = { parent_slot, parent_bank_idx } };
  fd_accdb_attach_child    ( env->accdb_admin,     &parent_xid, &xid );
  fd_progcache_attach_child( env->progcache->join, &parent_xid, &xid );

  env->xid  = xid;
  env->bank = new_bank;

  int is_epoch_boundary = 0;
  fd_runtime_block_execute_prepare( env->banks, env->bank, env->accdb, env->runtime_stack, NULL, &is_epoch_boundary );
}

static void
setup_test( test_env_t * env, fd_wksp_t * wksp, int enable_feature ) {
  test_env_init( env, wksp );
  process_slot( env, 10UL );
  fd_features_enable_cleaned_up( &env->bank->f.features );
  if( enable_feature ) {
    FD_FEATURE_SET_ACTIVE( &env->bank->f.features, create_account_allow_prefund, 0UL );
  }
}

/* Build a legacy transaction containing a single CreateAccountAllowPrefund
   instruction (discriminant 13).  If from is NULL, no funding account is
   included (lamports==0 path). */

static ulong
build_txn( test_env_t *        env,
           ulong               lamports,
           ulong               space,
           fd_pubkey_t const * owner,
           fd_pubkey_t const * to,
           fd_pubkey_t const * from,
           int                 to_is_signer,
           int                 from_is_signer ) {
  uchar * p     = env->txn_p->payload;
  uchar * start = p;

  int has_from    = (from != NULL);
  int num_signers = 0;
  if( to_is_signer                 ) num_signers++;
  if( has_from && from_is_signer   ) num_signers++;
  if( num_signers==0               ) num_signers = 1;

  /* Signatures */
  *p++ = (uchar)num_signers;
  for( int i=0; i<num_signers; i++ ) {
    memset( p, 0, 64 );
    p += 64;
  }

  /* Message header */
  uchar num_accounts;
  uchar num_readonly_unsigned;

  if( has_from ) {
    num_accounts = 3;
    if( to_is_signer && from_is_signer ) {
      *p++ = 2; /* num_required_signatures */
      *p++ = 0; /* num_readonly_signed */
      *p++ = 1; /* num_readonly_unsigned (system_program) */
      num_readonly_unsigned = 1;
    } else if( to_is_signer && !from_is_signer ) {
      *p++ = 1;
      *p++ = 0;
      *p++ = 1;
      num_readonly_unsigned = 1;
    } else if( !to_is_signer && from_is_signer ) {
      *p++ = 1;
      *p++ = 0;
      *p++ = 1;
      num_readonly_unsigned = 1;
    } else {
      *p++ = 1;
      *p++ = 0;
      *p++ = 1;
      num_readonly_unsigned = 1;
    }
  } else {
    num_accounts = 2;
    *p++ = 1;
    *p++ = 0;
    *p++ = 1;
    num_readonly_unsigned = 1;
  }
  (void)num_readonly_unsigned;

  /* Account keys */
  *p++ = num_accounts;
  if( has_from && !to_is_signer && from_is_signer ) {
    memcpy( p, from->key, 32 ); p += 32;
    memcpy( p, to->key,   32 ); p += 32;
  } else {
    memcpy( p, to->key, 32 ); p += 32;
    if( has_from ) { memcpy( p, from->key, 32 ); p += 32; }
  }
  memcpy( p, fd_solana_system_program_id.key, 32 ); p += 32;

  /* Recent blockhash */
  memset( p, 0xAB, 32 );
  p += 32;

  /* Instructions: 1 instruction */
  *p++ = 1;
  *p++ = (uchar)(num_accounts - 1); /* program_id index */

  if( has_from ) {
    *p++ = 2; /* 2 accounts in instruction */
    if( !to_is_signer && from_is_signer ) {
      *p++ = 1; /* to */
      *p++ = 0; /* from */
    } else {
      *p++ = 0; /* to */
      *p++ = 1; /* from */
    }
  } else {
    *p++ = 1;
    *p++ = 0; /* to */
  }

  /* Instruction data: u32(13) | u64 lamports | u64 space | [u8;32] owner */
  *p++ = 52; /* data length (compact-u16) */
  uint disc = 13;
  memcpy( p, &disc,     4  ); p += 4;
  memcpy( p, &lamports, 8  ); p += 8;
  memcpy( p, &space,    8  ); p += 8;
  memcpy( p, owner->key, 32 ); p += 32;

  ulong payload_sz = (ulong)(p - start);
  env->txn_p->payload_sz = payload_sz;
  FD_TEST( fd_txn_parse( env->txn_p->payload, payload_sz, TXN(env->txn_p), NULL ) > 0 );

  env->txn_in->txn              = env->txn_p;
  env->txn_in->bundle.is_bundle = 0;

  return payload_sz;
}

static int
txn_succeeded( test_env_t * env ) {
  return env->txn_out[0].err.is_committable &&
         env->txn_out[0].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS;
}

static int
txn_instr_err( test_env_t * env ) {
  return env->txn_out[0].err.exec_err;
}

static void
execute_txn( test_env_t * env ) {
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, env->txn_in, env->txn_out );
}

/* Run a single test case.  Sets up the environment, creates accounts,
   builds and executes the transaction, checks the result, and cleans up. */

static void
run_test( fd_wksp_t *         wksp,
          char const *        name,
          int                 enable_feature,
          /* to account setup */
          ulong               to_lamports,
          uint                to_dlen,
          uchar *             to_data,
          fd_pubkey_t const * to_owner,
          /* from account setup (NULL to_owner means system-owned) */
          fd_pubkey_t const * from,
          ulong               from_lamports,
          uint                from_dlen,
          uchar *             from_data,
          /* instruction params */
          ulong               ix_lamports,
          ulong               ix_space,
          fd_pubkey_t const * ix_owner,
          int                 to_is_signer,
          int                 from_is_signer,
          /* expected result */
          int                 expect_success,
          int                 expect_instr_err ) {
  test_env_t env[1];
  setup_test( env, wksp, enable_feature );

  fd_pubkey_t const * effective_to_owner = to_owner ? to_owner : &fd_solana_system_program_id;
  create_account_raw( env->accdb, &env->xid, &TO_PUBKEY, to_lamports, to_dlen, to_data, effective_to_owner );

  if( from ) {
    fd_pubkey_t const * from_owner_key = &fd_solana_system_program_id;
    create_account_raw( env->accdb, &env->xid, &FROM_PUBKEY, from_lamports, from_dlen, from_data, from_owner_key );
  }

  build_txn( env, ix_lamports, ix_space, ix_owner,
             &TO_PUBKEY, from ? &FROM_PUBKEY : NULL,
             to_is_signer, from_is_signer );

  execute_txn( env );

  if( expect_success ) {
    FD_TEST( txn_succeeded( env ) );
  } else {
    FD_TEST( !txn_succeeded( env ) );
    if( expect_instr_err >= 0 ) {
      FD_TEST( txn_instr_err( env ) == expect_instr_err );
    }
  }

  test_env_cleanup( env );
  FD_LOG_NOTICE(( "%s... ok", name ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _name    = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 5UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );

  fd_wksp_t * wksp;
  if( _name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", _name ));
    wksp = fd_wksp_attach( _name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  uchar some_data[32] = {0xFF};

  /* Feature gate */
  run_test( wksp, "feature_inactive",
            0, TEST_LAMPORTS, 0, NULL, NULL,
            &FROM_PUBKEY, TEST_LAMPORTS, 0, NULL,
            1000UL, 100UL, &OWNER_PUBKEY, 1, 1,
            0, FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );

  run_test( wksp, "feature_active_happy_path",
            1, TEST_LAMPORTS, 0, NULL, NULL,
            &FROM_PUBKEY, TEST_LAMPORTS, 0, NULL,
            1000UL, 100UL, &OWNER_PUBKEY, 1, 1,
            1, -1 );

  /* Account count: lamports>0 but only 1 account */
  run_test( wksp, "lamports_gt0_missing_from",
            1, TEST_LAMPORTS, 0, NULL, NULL,
            NULL, 0, 0, NULL,
            1000UL, 100UL, &OWNER_PUBKEY, 1, 0,
            0, FD_EXECUTOR_INSTR_ERR_MISSING_ACC );

  /* lamports==0, 1 account (no from needed) */
  run_test( wksp, "lamports_zero_one_account",
            1, TEST_LAMPORTS, 0, NULL, NULL,
            NULL, 0, 0, NULL,
            0UL, 100UL, &OWNER_PUBKEY, 1, 0,
            1, -1 );

  /* Signer checks */
  run_test( wksp, "to_not_signer",
            1, TEST_LAMPORTS, 0, NULL, NULL,
            &FROM_PUBKEY, TEST_LAMPORTS, 0, NULL,
            1000UL, 100UL, &OWNER_PUBKEY, 0, 1,
            0, -1 );

  run_test( wksp, "from_not_signer",
            1, TEST_LAMPORTS, 0, NULL, NULL,
            &FROM_PUBKEY, TEST_LAMPORTS, 0, NULL,
            1000UL, 100UL, &OWNER_PUBKEY, 1, 0,
            0, -1 );

  /* To-account state: account already has data */
  run_test( wksp, "to_has_data",
            1, TEST_LAMPORTS, 32, some_data, NULL,
            &FROM_PUBKEY, TEST_LAMPORTS, 0, NULL,
            1000UL, 100UL, &OWNER_PUBKEY, 1, 1,
            0, -1 );

  /* To-account state: non-system owner */
  run_test( wksp, "to_nonsystem_owner",
            1, TEST_LAMPORTS, 0, NULL, &OWNER_PUBKEY,
            &FROM_PUBKEY, TEST_LAMPORTS, 0, NULL,
            1000UL, 100UL, &OWNER_PUBKEY, 1, 1,
            0, -1 );

  /* To-account state: both data and non-system owner */
  run_test( wksp, "to_data_and_nonsystem_owner",
            1, TEST_LAMPORTS, 16, some_data, &OWNER_PUBKEY,
            &FROM_PUBKEY, TEST_LAMPORTS, 0, NULL,
            1000UL, 100UL, &OWNER_PUBKEY, 1, 1,
            0, -1 );

  /* To-account state: lamports and data */
  run_test( wksp, "to_lamports_and_data",
            1, 500000UL, 16, some_data, NULL,
            &FROM_PUBKEY, TEST_LAMPORTS, 0, NULL,
            1000UL, 100UL, &OWNER_PUBKEY, 1, 1,
            0, -1 );

  /* Space validation */
  run_test( wksp, "space_zero",
            1, TEST_LAMPORTS, 0, NULL, NULL,
            &FROM_PUBKEY, TEST_LAMPORTS, 0, NULL,
            1000UL, 0UL, &OWNER_PUBKEY, 1, 1,
            1, -1 );

  run_test( wksp, "space_exceeds_max",
            1, TEST_LAMPORTS, 0, NULL, NULL,
            &FROM_PUBKEY, TEST_LAMPORTS, 0, NULL,
            1000UL, 10485761UL, &OWNER_PUBKEY, 1, 1,
            0, -1 );

  run_test( wksp, "space_at_max",
            1, TEST_LAMPORTS, 0, NULL, NULL,
            &FROM_PUBKEY, TEST_LAMPORTS, 0, NULL,
            1000UL, 10485760UL, &OWNER_PUBKEY, 1, 1,
            1, -1 );

  /* Owner = system program (no-op in assign) */
  run_test( wksp, "owner_system_program",
            1, TEST_LAMPORTS, 0, NULL, NULL,
            &FROM_PUBKEY, TEST_LAMPORTS, 0, NULL,
            1000UL, 100UL, &fd_solana_system_program_id, 1, 1,
            1, -1 );

  /* Transfer: from has insufficient lamports */
  run_test( wksp, "from_insufficient_lamports",
            1, TEST_LAMPORTS, 0, NULL, NULL,
            &FROM_PUBKEY, 500UL, 0, NULL,
            1000UL, 100UL, &OWNER_PUBKEY, 1, 1,
            0, -1 );

  /* Transfer: from carries data */
  uchar from_data[16] = {1};
  run_test( wksp, "from_has_data",
            1, TEST_LAMPORTS, 0, NULL, NULL,
            &FROM_PUBKEY, TEST_LAMPORTS, 16, from_data,
            1000UL, 100UL, &OWNER_PUBKEY, 1, 1,
            0, -1 );

  /* Prefunded main use case: lamports=0, to already has rent */
  run_test( wksp, "prefunded_main_use_case",
            1, 10000000UL, 0, NULL, NULL,
            NULL, 0, 0, NULL,
            0UL, 100UL, &OWNER_PUBKEY, 1, 0,
            1, -1 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
