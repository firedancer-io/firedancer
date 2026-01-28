#include "fd_vote_program.h"
#include "../../../ballet/hex/fd_hex.h"

#include "../fd_acc_pool.h"
#include "../fd_runtime.h"
#include "../fd_runtime_stack.h"
#include "../fd_bank.h"
#include "../fd_system_ids.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../sysvar/fd_sysvar_stake_history.h"
#include "../sysvar/fd_sysvar_clock.h"
#include "../sysvar/fd_sysvar_cache.h"
#include "../../accdb/fd_accdb_admin_v1.h"
#include "../../accdb/fd_accdb_impl_v1.h"
#include "../../features/fd_features.h"
#include "../../accdb/fd_accdb_sync.h"

#include <stdlib.h> // ARM64: malloc(3), free(3)

// turn on/off benches
#define BENCH 0

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

// static void
// create_test_account( fd_accdb_user_t *         user,
//                      fd_funk_txn_xid_t const * xid,
//                      fd_pubkey_t const *       pubkey,
//                      ulong                     lamports,
//                      uint                      dlen,
//                      uchar *                   data,
//                      ulong                     slot ) {
//   fd_accdb_rw_t rw[1];
//   FD_TEST( fd_accdb_open_rw( user, rw, xid, pubkey, dlen, FD_ACCDB_FLAG_CREATE ) );
//   fd_accdb_ref_data_set( user, rw, data, dlen );
//   fd_funk_rec_t * rec = (void *)rw->ref->user_data;
//   FD_TEST( rec->val_sz    == sizeof(fd_account_meta_t)+dlen );
//   FD_TEST( rec->val_max   >= sizeof(fd_account_meta_t)+dlen );
//   FD_TEST( rw->meta->dlen == dlen );
//   rw->meta->lamports = lamports;
//   rw->meta->slot = slot;
//   rw->meta->executable = 0;
//   memset( rw->meta->owner, 0UL, 32UL );
//   fd_accdb_close_rw( user, rw );
// }

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


void
log_bench( char const * descr,
           ulong        iter,
           long         dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-31s %11.3fK/s/core %10.3f ns/call", descr, (double)khz, (double)tau ));
}

FD_FN_UNUSED static void
test_account_initialize( fd_wksp_t * wksp ) {
  static char * hex =
    "03"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "03010407"
    "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b"
    "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a"
    "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "06a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b2100000000"
    "06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000"
    "0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000"
    "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17"
    "02"
    "0302000134"
    /* system.create_account */
    "00000000601f9d0100000000b20e0000000000000761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000"
    "06040105040265"
    /* vote.initialize_account */
    "000000000aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a80aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a80880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b64"
  ;

  // ulong offset = 518;
  // ulong cu = 2100;

  test_env_t env[1];
  test_env_create( env, wksp );
  process_slot( env, 10UL );

  /* decode and parse txn */
  fd_txn_p_t txn_p[1];
  fd_txn_t * txn = TXN(txn_p);
  ulong txn_sz = strlen(hex) / 2;
  txn_p->payload_sz = txn_sz;
  fd_hex_decode( txn_p->payload, hex, txn_sz );
  FD_TEST( fd_txn_parse( txn_p->payload, txn_sz, txn, NULL )>0 );

#if 0
  /* setup bank and enable all features */
  fd_bank_data_t bank_data[1];
  fd_bank_t bank[1] = {{ .data = bank_data }};
  fd_bank_slot_set( bank, 0UL );
  fd_features_t * features = fd_bank_features_modify( bank );
  fd_features_enable_all( features );


  /* prepare txn_in */
  fd_txn_in_t txn_in[1];
  txn_in->txn = txn_p;
  txn_in->bundle.is_bundle = 0;

  fd_exec_instr_ctx_t ctx[1];
  fd_txn_out_t txn_out[1];
  fd_instr_info_t instr[1];
  fd_log_collector_t log_collector[1];
  runtime->log.log_collector = log_collector;


  fd_runtime_reset_runtime( runtime );
  fd_runtime_new_txn_out( txn_in, txn_out );

  fd_executor_setup_accounts_for_txn( runtime, bank, txn_in, txn_out );
  FD_TEST( fd_executor_load_transaction_accounts( runtime, bank, txn_in, txn_out )==0 );

  // load test data
  // create_test_ctx( &ctx, runtime, txn_out, instr, txn_p->payload, txn_sz, offset, cu );
  ctx->runtime = runtime;
  ctx->bank = bank;
  ctx->txn_out = txn_out;
  ctx->txn_out->details.compute_budget.compute_meter = cu;
  // ctx->instr = instr;
  instr->data_sz = (ushort)(txn_sz - offset); //TODO: this only works if the instruction is the last one
  memcpy( instr->data, &txn_p->payload[offset], instr->data_sz );
  fd_log_collector_init( ctx->runtime->log.log_collector, 1 );
#endif

  env->txn_out->details.compute_budget.compute_meter = 2100+1;

  env->txn_in.txn              = txn_p;
  env->txn_in.bundle.is_bundle = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );

  // valid
  // FD_TEST( fd_vote_program_execute( ctx )==FD_EXECUTOR_INSTR_SUCCESS );

  /* Benchmarks */
  FD_LOG_NOTICE(( "test_account_initialize... ok" ));
#if BENCH
  ulong iter = 10000UL;
  long dt = fd_log_wallclock();
  for( ulong rem=iter; rem; rem-- ) {
    FD_COMPILER_FORGET( ctx );
    fd_vote_program_execute( &ctx );
  }
  dt = fd_log_wallclock() - dt;
  log_bench( "fd_vote_program_execute(account_initialize)", iter, dt );
#endif
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * name     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--wksp",      NULL, NULL            );
  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"      );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 5UL             );
  ulong        near_cpu = fd_env_strip_cmdline_ulong( &argc, &argv, "--near-cpu",  NULL, fd_log_cpu_id() );

  fd_wksp_t * wksp;
  if( name ) {
    FD_LOG_NOTICE(( "Attaching to --wksp %s", name ));
    wksp = fd_wksp_attach( name );
  } else {
    FD_LOG_NOTICE(( "--wksp not specified, using an anonymous local workspace, --page-sz %s, --page-cnt %lu, --near-cpu %lu",
                    _page_sz, page_cnt, near_cpu ));
    wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, near_cpu, "wksp", 0UL );
  }

  test_account_initialize( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
