/* Test for the bounds on the number of accounts referenced by a single
   instruction. The worst case is FD_INSTR_ACCT_MAX: 1094. Transactions with
   >FD_INSTR_ACCT_MAX instruction accounts are not possible due to the MTU.

   Instructions with FD_INSTR_ACCT_MAX accounts should be correctly
   represented in the instruction trace to avoid conformance issues,
   which is what this test checks. */

#include "info/fd_instr_info.h"
#include "fd_runtime.h"
#include "fd_bank.h"
#include "fd_system_ids.h"
#include "fd_acc_pool.h"
#include "fd_acc_mgr.h"
#include "program/fd_builtin_programs.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_rent.h"
#include "sysvar/fd_sysvar_stake_history.h"
#include "../accdb/fd_accdb_admin.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "../progcache/fd_progcache_admin.h"
#include "../progcache/fd_progcache_user.h"
#include "../log_collector/fd_log_collector.h"
#include "../../disco/fd_txn_p.h"
#include "../../funk/fd_funk_rec.h"
#include "../../funk/fd_funk_val.h"

struct test_env {
  fd_wksp_t *          wksp;
  ulong                tag;
  void *               funk_mem;
  fd_accdb_admin_t     accdb_admin[1];
  fd_accdb_user_t      accdb[1];
  void *               pcache_mem;
  fd_progcache_admin_t progcache_admin[1];
  fd_progcache_t       progcache[1];
  uchar *              progcache_scratch;
  void *               banks_mem;
  fd_banks_t *         banks;
  fd_bank_t *          bank;
  void *               acc_pool_mem;
  fd_acc_pool_t *      acc_pool;
  fd_runtime_t *       runtime;
  fd_funk_txn_xid_t    xid;
  fd_pubkey_t          fee_payer;
  fd_log_collector_t   log_collector[1];
};
typedef struct test_env test_env_t;

static void
init_sysvars( test_env_t * env ) {
  fd_rent_t rent = { .lamports_per_uint8_year = 3480UL, .exemption_threshold = 2.0, .burn_percent = 50 };
  fd_bank_rent_set( env->bank, rent );
  fd_sysvar_rent_write( env->bank, env->accdb, &env->xid, NULL, &rent );

  fd_epoch_schedule_t epoch_schedule = {
    .slots_per_epoch             = 432000UL,
    .leader_schedule_slot_offset = 432000UL,
    .warmup                      = 0,
    .first_normal_epoch          = 0UL,
    .first_normal_slot           = 0UL
  };
  fd_bank_epoch_schedule_set( env->bank, epoch_schedule );
  fd_sysvar_epoch_schedule_write( env->bank, env->accdb, &env->xid, NULL, &epoch_schedule );

  fd_sysvar_stake_history_init( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_clock_init( env->bank, env->accdb, &env->xid, NULL );
}

static void
init_blockhash_queue( test_env_t * env ) {
  fd_blockhashes_t * bhq = fd_blockhashes_init( fd_bank_block_hash_queue_modify( env->bank ), 12345UL );
  fd_hash_t dummy_hash = {0};
  fd_blockhash_info_t * info = fd_blockhashes_push_new( bhq, &dummy_hash );
  info->fee_calculator.lamports_per_signature = 0UL;
  fd_bank_poh_set( env->bank, dummy_hash );
}

static void
init_fee_payer( test_env_t * env ) {
  fd_memset( &env->fee_payer, 0x01, sizeof(fd_pubkey_t) );

  fd_funk_t * funk = fd_accdb_user_v1_funk( env->accdb );
  fd_funk_rec_key_t rec_key = fd_funk_acc_key( &env->fee_payer );
  fd_funk_rec_prepare_t prepare[1];
  fd_funk_rec_t * rec = fd_funk_rec_prepare( funk, &env->xid, &rec_key, prepare, NULL );
  FD_TEST( rec );

  uchar * rec_data = fd_funk_val_truncate( rec, fd_funk_alloc( funk ), fd_funk_wksp( funk ), 0UL, sizeof(fd_account_meta_t), NULL );
  FD_TEST( rec_data );

  fd_account_meta_t * meta = (fd_account_meta_t *)rec_data;
  fd_account_meta_init( meta );
  meta->lamports = 1000000000UL;

  fd_funk_rec_publish( funk, prepare );
}

static test_env_t *
test_env_create( test_env_t * env, fd_wksp_t * wksp ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->wksp = wksp;
  env->tag  = 1UL;

  ulong funk_seed       = 17UL;
  ulong txn_max         = 16UL;
  ulong rec_max         = 1024UL;
  ulong max_total_banks = 2UL;
  ulong max_fork_width  = 2UL;
  ulong acc_pool_cnt    = 4UL;

  env->funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), env->tag );
  FD_TEST( env->funk_mem );
  FD_TEST( fd_funk_new( env->funk_mem, env->tag, funk_seed, txn_max, rec_max ) );
  FD_TEST( fd_accdb_admin_join( env->accdb_admin, env->funk_mem ) );
  FD_TEST( fd_accdb_user_v1_init( env->accdb, env->funk_mem ) );

  env->pcache_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint( txn_max, rec_max ), env->tag );
  FD_TEST( env->pcache_mem );
  FD_TEST( fd_funk_new( env->pcache_mem, env->tag, funk_seed+1, txn_max, rec_max ) );
  env->progcache_scratch = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT, env->tag );
  FD_TEST( env->progcache_scratch );
  FD_TEST( fd_progcache_join( env->progcache, env->pcache_mem, env->progcache_scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
  FD_TEST( fd_progcache_admin_join( env->progcache_admin, env->pcache_mem ) );

  env->banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( max_total_banks, max_fork_width ), env->tag );
  FD_TEST( env->banks_mem );
  fd_banks_t * banksl_join = fd_wksp_alloc_laddr( wksp, alignof(fd_banks_t), sizeof(fd_banks_t), env->tag );
  env->banks = fd_banks_join( banksl_join, fd_banks_new( env->banks_mem, max_total_banks, max_fork_width, 0, 8888UL ), NULL );
  FD_TEST( env->banks );
  env->bank = fd_banks_init_bank( env->banks );
  FD_TEST( env->bank );

  env->acc_pool_mem = fd_wksp_alloc_laddr( wksp, fd_acc_pool_align(), fd_acc_pool_footprint( acc_pool_cnt ), env->tag );
  FD_TEST( env->acc_pool_mem );
  env->acc_pool = fd_acc_pool_join( fd_acc_pool_new( env->acc_pool_mem, acc_pool_cnt ) );
  FD_TEST( env->acc_pool );

  env->runtime = fd_wksp_alloc_laddr( wksp, alignof(fd_runtime_t), sizeof(fd_runtime_t), env->tag );
  FD_TEST( env->runtime );
  fd_memset( env->runtime, 0, sizeof(fd_runtime_t) );

  fd_funk_txn_xid_t root[1];
  fd_funk_txn_xid_set_root( root );
  env->xid = (fd_funk_txn_xid_t){ .ul = { 10UL, env->bank->idx } };
  fd_accdb_attach_child( env->accdb_admin, root, &env->xid );
  fd_progcache_txn_attach_child( env->progcache_admin, root, &env->xid );

  fd_bank_slot_set( env->bank, 10UL );
  fd_bank_parent_slot_set( env->bank, 9UL );
  fd_bank_epoch_set( env->bank, 0UL );

  env->runtime->accdb        = env->accdb;
  env->runtime->funk         = fd_accdb_user_v1_funk( env->accdb );
  env->runtime->status_cache = NULL;
  env->runtime->progcache    = env->progcache;
  env->runtime->acc_pool     = env->acc_pool;

  fd_log_collector_init( env->log_collector, 0 );
  env->runtime->log.log_collector = env->log_collector;

  init_sysvars( env );
  init_blockhash_queue( env );
  fd_builtin_programs_init( env->bank, env->accdb, &env->xid, NULL );
  init_fee_payer( env );

  return env;
}

static void
test_env_destroy( test_env_t * env ) {
  fd_accdb_cancel( env->accdb_admin, &env->xid );
  fd_progcache_txn_cancel( env->progcache_admin, &env->xid );

  fd_wksp_free_laddr( env->runtime );
  fd_wksp_free_laddr( env->acc_pool_mem );
  fd_banks_delete( fd_banks_leave( env->banks ) );
  fd_wksp_free_laddr( env->banks_mem );

  fd_progcache_leave( env->progcache, NULL );
  void * pcache_funk = NULL;
  fd_progcache_admin_leave( env->progcache_admin, &pcache_funk );
  fd_wksp_free_laddr( fd_funk_delete( pcache_funk ) );
  fd_wksp_free_laddr( env->progcache_scratch );

  fd_alloc_compact( fd_funk_alloc( env->accdb_admin->funk ) );
  void * funk_mem = NULL;
  fd_accdb_admin_leave( env->accdb_admin, &funk_mem );
  fd_accdb_user_fini( env->accdb );
  fd_wksp_free_laddr( fd_funk_delete( funk_mem ) );

  fd_memset( env, 0, sizeof(test_env_t) );
}

static void
setup_txn( test_env_t * env, fd_txn_p_t * txn_p, fd_txn_out_t * txn_out, fd_txn_in_t * txn_in, ushort instr_acct_cnt ) {
  fd_memset( txn_p, 0, sizeof(fd_txn_p_t) );
  fd_memset( txn_out, 0, sizeof(fd_txn_out_t) );

  fd_txn_t * txn = TXN( txn_p );
  txn->transaction_version  = FD_TXN_VLEGACY;
  txn->signature_cnt        = 1;
  txn->acct_addr_cnt        = 2;
  txn->instr_cnt            = 1;
  txn->recent_blockhash_off = 0;
  txn->acct_addr_off        = 32;

  fd_memcpy( txn_p->payload + 32, &env->fee_payer, sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload + 64, &fd_solana_compute_budget_program_id, sizeof(fd_pubkey_t) );

  txn->instr[0].program_id = 1;
  txn->instr[0].acct_cnt   = instr_acct_cnt;
  txn->instr[0].acct_off   = 96;

  for( ushort i=0; i<instr_acct_cnt; i++ ) {
    txn_p->payload[96+i] = 0;
  }

  ushort data_off = (ushort)(96 + instr_acct_cnt);
  txn->instr[0].data_off = data_off;
  txn->instr[0].data_sz  = 5;

  /* SetComputeUnitLimit(200000) */
  txn_p->payload[data_off+0] = 2;
  txn_p->payload[data_off+1] = 0x40;
  txn_p->payload[data_off+2] = 0x0D;
  txn_p->payload[data_off+3] = 0x03;
  txn_p->payload[data_off+4] = 0x00;

  txn_in->txn              = txn_p;
  txn_in->bundle.is_bundle = 0;
}

static void
verify_trace_accts( test_env_t * env, ushort expected_cnt ) {
  FD_TEST( env->runtime->instr.trace_length == 1 );
  fd_instr_info_t const * trace = &env->runtime->instr.trace[0];
  FD_TEST( trace->acct_cnt == expected_cnt );
  for( ushort i=0; i<expected_cnt; i++ ) {
    fd_instruction_account_t expected = {
      .index_in_transaction = 0,
      .index_in_caller      = 0,
      .index_in_callee      = i,
      .is_writable          = 1,
      .is_signer            = 1,
    };
    FD_TEST( !memcmp( &trace->accounts[i], &expected, sizeof(fd_instruction_account_t) ) );
  }
}

/* More than 256, the previous (incorrect) limit */
static void
test_500_instr_accts( fd_wksp_t * wksp ) {
  test_env_t   env[1];
  fd_txn_p_t   txn_p[1];
  fd_txn_out_t txn_out[1];
  fd_txn_in_t  txn_in[1];

  test_env_create( env, wksp );
  setup_txn( env, txn_p, txn_out, txn_in, 500 );
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, txn_in, txn_out );
  FD_TEST( txn_out->err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );
  verify_trace_accts( env, 500 );
  test_env_destroy( env );
}

/* Worst-case allowed number of instruction accounts */
static void
test_1094_instr_accts( fd_wksp_t * wksp ) {
  test_env_t   env[1];
  fd_txn_p_t   txn_p[1];
  fd_txn_out_t txn_out[1];
  fd_txn_in_t  txn_in[1];

  test_env_create( env, wksp );
  setup_txn( env, txn_p, txn_out, txn_in, FD_INSTR_ACCT_MAX );
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, txn_in, txn_out );
  FD_TEST( txn_out->err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );
  verify_trace_accts( env, FD_INSTR_ACCT_MAX );
  test_env_destroy( env );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx > fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr( &argc, &argv,  "--page-sz",  NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 5UL );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  FD_TEST( page_sz );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "test_instr_acct_bounds", 0UL );
  FD_TEST( wksp );

  test_500_instr_accts( wksp );
  test_1094_instr_accts( wksp );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
