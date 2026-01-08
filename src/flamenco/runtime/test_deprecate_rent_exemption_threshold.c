/* Test for SIMD-0194: deprecate_rent_exemption_threshold

   This test simulates passing through several epoch boundaries, checking that
   the value of rent in the accounts db, the bank and the sysvar cache is
   updated correctly at the slot where deprecate_rent_exemption_threshold
   is activated. */

#include "fd_runtime.h"
#include "fd_runtime_stack.h"
#include "fd_bank.h"
#include "fd_system_ids.h"
#include "sysvar/fd_sysvar_rent.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_stake_history.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_cache.h"
#include "../accdb/fd_accdb_admin.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "../features/fd_features.h"
#include "../../funk/fd_funk.h"
#include "../../funk/fd_funk_rec.h"

/* Values before deprecate_rent_exemption_threshold is activated */
#define TEST_DEFAULT_LAMPORTS_PER_UINT8_YEAR (3480UL)
#define TEST_DEFAULT_EXEMPTION_THRESHOLD     (2.0)

/* Values after deprecate_rent_exemption_threshold is activated */
#define TEST_NEW_LAMPORTS_PER_UINT8_YEAR (6960UL)
#define TEST_NEW_EXEMPTION_THRESHOLD     (1.0)

#define TEST_SLOTS_PER_EPOCH         (3UL)
#define TEST_FEATURE_ACTIVATION_SLOT (TEST_SLOTS_PER_EPOCH * 2)

struct test_env {
  fd_wksp_t *          wksp;
  ulong                tag;
  void *               banks_mem;
  fd_banks_t *         banks;
  fd_bank_t            bank[1];
  void *               funk_mem;
  fd_accdb_admin_t     accdb_admin[1];
  fd_accdb_user_t      accdb[1];
  fd_funk_txn_xid_t    xid;
  fd_runtime_stack_t * runtime_stack;
};
typedef struct test_env test_env_t;

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
                 fd_wksp_t *  wksp,
                 fd_banks_t * banksl_join ) {
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

  FD_TEST( fd_accdb_admin_join( env->accdb_admin, env->funk_mem ) );
  FD_TEST( fd_accdb_user_v1_init( env->accdb, env->funk_mem ) );

  env->banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( max_total_banks, max_fork_width ), env->tag );
  FD_TEST( env->banks_mem );
  env->banks = fd_banks_join( banksl_join, fd_banks_new( env->banks_mem, max_total_banks, max_fork_width, 0, 8888UL ), NULL );
  FD_TEST( env->banks );

  //env->bank = fd_banks_init_bank( env->banks ); TODO:FIXME:
  FD_TEST( env->bank );

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

  return env;
}

static void
test_env_destroy( test_env_t * env ) {
  FD_TEST( env );

  fd_wksp_free_laddr( env->runtime_stack );
  fd_banks_delete( fd_banks_leave( env->banks ) );
  fd_wksp_free_laddr( env->banks_mem );
  fd_alloc_compact( fd_funk_alloc( env->accdb_admin->funk ) );

  void * funk_mem = NULL;
  fd_accdb_admin_leave( env->accdb_admin, &funk_mem );
  fd_accdb_user_fini( env->accdb );
  fd_wksp_free_laddr( fd_funk_delete( funk_mem ) );

  fd_wksp_usage_t usage[1];
  fd_wksp_usage( env->wksp, &env->tag, 1UL, usage );
  FD_TEST( usage->used_cnt == 0UL );
  FD_TEST( usage->used_sz  == 0UL );

  fd_memset( env, 0, sizeof(test_env_t) );
}

static void
verify_rent_values( test_env_t * env,
                    ulong        expected_lamports,
                    double       expected_threshold ) {
  fd_funk_t * funk = fd_accdb_user_v1_funk( env->accdb );

  fd_rent_t funk_rent[1];
  FD_TEST( fd_sysvar_rent_read( funk, &env->xid, funk_rent ) );
  FD_TEST( funk_rent->lamports_per_uint8_year == expected_lamports );
  FD_TEST( funk_rent->exemption_threshold     == expected_threshold );

  fd_rent_t const * bank_rent = fd_bank_rent_query( env->bank );
  FD_TEST( bank_rent );
  FD_TEST( bank_rent->lamports_per_uint8_year == expected_lamports );
  FD_TEST( bank_rent->exemption_threshold     == expected_threshold );

  fd_sysvar_cache_t const * sysvar_cache = fd_bank_sysvar_cache_query( env->bank );
  fd_rent_t cache_rent[1];
  FD_TEST( fd_sysvar_cache_rent_read( sysvar_cache, cache_rent ) );
  FD_TEST( cache_rent->lamports_per_uint8_year == expected_lamports );
  FD_TEST( cache_rent->exemption_threshold     == expected_threshold );
}

static int
rent_was_modified_in_txn( test_env_t *                env,
                          fd_funk_txn_xid_t const *   xid ) {
  fd_accdb_peek_t peek[1];
  FD_TEST( fd_accdb_peek( env->accdb, peek, xid, &fd_sysvar_rent_id ) );
  return fd_funk_txn_xid_eq( peek->acc->rec->pair.xid, xid );
}

static int
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

  //env->bank = new_bank;
  env->xid  = xid;

  int is_epoch_boundary = 0;
  fd_runtime_block_execute_prepare( env->banks, env->bank, env->accdb, env->runtime_stack, NULL, &is_epoch_boundary );

  int rent_modified = rent_was_modified_in_txn( env, &xid );

  fd_banks_mark_bank_frozen( env->banks, new_bank );

  fd_accdb_advance_root( env->accdb_admin, &xid );
  fd_banks_advance_root( env->banks, new_bank_idx );

  return rent_modified;
}

/* Advance to target slot and return whether rent was modified in that slot. */
static int
advance_to_slot( test_env_t * env,
                 ulong        target_slot ) {
  ulong current_slot = fd_bank_slot_get( env->bank );
  int rent_modified = 0;
  for( ulong slot = current_slot + 1UL; slot <= target_slot; slot++ ) {
    rent_modified = process_slot( env, slot );
  }
  return rent_modified;
}

/* - Epoch 1: deprecate_rent_exemption_threshold not activated
   - Epoch 2: deprecate_rent_exemption_threshold activation epoch
   - Epoch 3: after deprecate_rent_exemption_threshold activation epoch */
static void
test_deprecate_rent_exemption_threshold( fd_wksp_t * wksp ) {
  test_env_t env[1];
  fd_banks_t banksl_join[1];
  test_env_create( env, wksp, banksl_join );

  /* Advance to last slot of epoch 1. Rent should not change. */
  int rent_modified = advance_to_slot( env, (2UL * TEST_SLOTS_PER_EPOCH) - 1UL );
  verify_rent_values( env, TEST_DEFAULT_LAMPORTS_PER_UINT8_YEAR, TEST_DEFAULT_EXEMPTION_THRESHOLD );
  FD_TEST( !rent_modified );

  /* Advance to first slot of epoch 2. Rent should change. */
  rent_modified = advance_to_slot( env, 2UL * TEST_SLOTS_PER_EPOCH );
  verify_rent_values( env, TEST_NEW_LAMPORTS_PER_UINT8_YEAR, TEST_NEW_EXEMPTION_THRESHOLD );
  FD_TEST( rent_modified );

  /* Advance to first slot of epoch 3. Rent should not change. */
  rent_modified = advance_to_slot( env, 3UL * TEST_SLOTS_PER_EPOCH );
  verify_rent_values( env, TEST_NEW_LAMPORTS_PER_UINT8_YEAR, TEST_NEW_EXEMPTION_THRESHOLD );
  FD_TEST( !rent_modified );

  test_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx > fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr( &argc, &argv,  "--page-sz",  NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 2UL );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_deprecate_rent_exemption_threshold( wksp );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
