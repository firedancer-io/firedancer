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
#include "../../../ballet/hex/fd_hex.h"
#include "fd_vote_program.h"
#include "vote/fd_vote_codec.h"
#include "vote/fd_authorized_voters.h"
#include "vote/fd_vote_state_v3.h"
#include "vote/fd_vote_state_v4.h"
#include "vote/fd_vote_state_versioned.h"

#include <stdlib.h>

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
  fd_txn_p_t           txn_p[1]; /* added this */
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
test_env_init( test_env_t * env, fd_wksp_t * wksp, int enable_loader_v4 ) {
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

  env->runtime_stack = fd_wksp_alloc_laddr( wksp, fd_runtime_stack_align(), fd_runtime_stack_footprint( 2048UL, 2048UL, 2048UL ), env->tag );
  FD_TEST( env->runtime_stack );
  FD_TEST( fd_runtime_stack_join( fd_runtime_stack_new( env->runtime_stack, 2048UL, 2048UL, 2048UL, 999UL ) ) );

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

  if( enable_loader_v4 ) {
    fd_features_t features = {0};
    fd_features_disable_all( &features );
    features.enable_loader_v4 = 0UL;
    env->bank->f.features = features;
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

  FD_TEST( parent_bank->state==FD_BANK_STATE_FROZEN );

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
create_simple_account( test_env_t * env, fd_pubkey_t const * pubkey, ulong lamports ) {
  create_account_raw( env->accdb, &env->xid, pubkey, lamports, 0UL, NULL, NULL );
}

static int
txn_succeeded( test_env_t * env ) {
  return env->txn_out[0].err.is_committable &&
         env->txn_out[0].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS;
}

static void
setup_account_initialize_txn( test_env_t * env ) {
  /* https://explorer.solana.com/tx/5jvysdwH5a3HCug5AfcJEKgbVGjfKUBiEFtKwrU88QmwUUgVMLqejjAmB3R4xpY7XQGf8VKBXyrNMnu58EFc8L3S */
  static char * hex =
    "03"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "03010407"
    "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b" /* signer */
    "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a" /* vote account */
    "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "06a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b2100000000"
    "06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000"
    "0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000"
    "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17" /* blockhash */
    /* the original txn has 2 instructions: system.create_account
       followed by vote.initialize_account.
       to make the test focus on vote_program, we remove the first tx
       and manually add the account.
    "02"
    "0302000134"
    // system.create_account
    "00000000601f9d0100000000b20e0000000000000761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000"
    "06040105040265"
    // vote.initialize_account
    "000000000aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a80aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a80880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b64"
    */
    "01"
    "06040105040265"
    /* vote.initialize_account */
    "000000000aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a80aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a80880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b64"
  ;

  /* repeatable code */

  process_slot( env, 10UL );
  /* features */
  fd_features_enable_cleaned_up( &env->bank->f.features );

  /* decode and parse txn */
  ulong txn_sz = strlen(hex) / 2;
  env->txn_p->payload_sz = txn_sz;
  fd_hex_decode( env->txn_p->payload, hex, txn_sz );
  FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );

  /* add the blockhash */
  fd_hash_t blockhash[1];
  fd_hex_decode( blockhash, "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17", 32 );
  fd_blockhashes_push_new( &env->bank->f.block_hash_queue, blockhash );

  /* add the signer to the accdb with 1 SOL */
  fd_pubkey_t pubkey[1];
  fd_hex_decode( pubkey, "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b", 32 );
  create_simple_account( env, pubkey, 1000000000UL );

  /* manually create the vote account */
  fd_hex_decode( pubkey, "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a", 32 );
  uchar data[3762UL] = { 0 };
  create_account_raw( env->accdb, &env->xid, pubkey, 1000000000UL, 3762UL, data, &fd_solana_vote_program_id );

  /* connect txn_in to the input tx */
  env->txn_in->txn              = env->txn_p;
  env->txn_in->bundle.is_bundle = 0;
}

static void
setup_account_initialize_v2_txn( test_env_t * env ) {
  static char * hex =
    "03"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "03010508"
    "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b" /* signer */
    "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a" /* vote account */
    "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "06a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b2100000000"
    "06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000"
    "0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000"
    "0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000"
    "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17" /* blockhash */
    "02"
    /* compute budget */
    "070005"
    "02e5860100"
    /* ix header for vote.initialize_account_v2 */
    "060401050402"
    "B802"
    /* vote.initialize_account_v2 */
    "10000000"
    "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8"
    "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8"
    /* bls pubkey */ "8160635a65d58a24c1b50ea84d957f16f54f4ff7deab3cc8b1858cd18f6ad72c479886092b9d53ebc47deb2660aea3d6"
    /* bls proof  */ "89905944ac6a5e7bf605e1fe69a9602f9bb4c67aa0b41f759497edbed0047a51bd6f9301430433ecbf1eed7b1a3b91351152875251560f859c77444ce342dc322d704a4192c721f5c456a2936dc9eee947750bf18b2b925fd556bff732866231"
    "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b"
    "0000"
    "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a"
    "0000"
    "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8"
  ;

  /* repeatable code */

  process_slot( env, 10UL );
  /* features */
  fd_features_enable_cleaned_up( &env->bank->f.features );

  /* decode and parse txn */
  ulong txn_sz = strlen(hex) / 2;
  env->txn_p->payload_sz = txn_sz;
  fd_hex_decode( env->txn_p->payload, hex, txn_sz );
  FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );

  /* add the blockhash */
  fd_hash_t blockhash[1];
  fd_hex_decode( blockhash, "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17", 32 );
  fd_blockhashes_push_new( &env->bank->f.block_hash_queue, blockhash );

  /* add the signer to the accdb with 1 SOL */
  fd_pubkey_t pubkey[1];
  fd_hex_decode( pubkey, "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b", 32 );
  create_simple_account( env, pubkey, 1000000000UL );

  /* manually create the vote account */
  fd_hex_decode( pubkey, "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a", 32 );
  uchar data[3762UL] = { 0 };
  create_account_raw( env->accdb, &env->xid, pubkey, 1000000000UL, 3762UL, data, &fd_solana_vote_program_id );

  /* connect txn_in to the input tx */
  env->txn_in->txn              = env->txn_p;
  env->txn_in->bundle.is_bundle = 0;
}

static void
test_account_initialize( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_init( env, wksp, 0 );

  setup_account_initialize_txn( env );

  /* Run the vote program */
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( txn_succeeded( env ) );

  /* Assert that the vote account is now populated */
  fd_account_meta_t * vote_account_meta = env->txn_out->accounts.account[1].meta;
  FD_TEST( vote_account_meta->dlen>0 );
  FD_TEST( !fd_mem_iszero( fd_account_data( vote_account_meta ), vote_account_meta->dlen ) );

  test_env_cleanup( env );
  FD_LOG_NOTICE(( "test_account_initialize... ok" ));
}

static void
test_account_initialize_simd_0387( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_init( env, wksp, 0 );

  setup_account_initialize_txn( env );

  /* Enable SIMD-0387 feature */
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, vote_state_v4, 0UL );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, bls_pubkey_management_in_vote_account, 0UL );

  /* Run the vote program */
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( txn_succeeded( env ) );

  test_env_cleanup( env );
  FD_LOG_NOTICE(( "test_account_initialize_simd_0387... ok" ));
}

/* InitializeAccountV2 requires all 6 features to be active:
   vote_state_v4, bls_pubkey_management_in_vote_account,
   commission_rate_in_basis_points, custom_commission_collector,
   block_revenue_sharing, vote_account_initialize_v2.
   Since the last 4 are not yet implemented (hardcoded to 0),
   InitializeAccountV2 will always fail.

   TODO: un-comment tests when the features are implemented. */

#if 0
static void
test_account_initialize_v2( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_init( env, wksp, 0 );

  setup_account_initialize_v2_txn( env );

  /* Enable SIMD-0387 feature */
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, vote_state_v4, 0UL );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, bls_pubkey_management_in_vote_account, 0UL );

  /* Run the vote program */
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( txn_succeeded( env ) );

  /* Assert that the vote account is now populated */
  fd_account_meta_t * vote_account_meta = env->txn_out->accounts.account[1].meta;
  FD_TEST( vote_account_meta->dlen>0 );
  FD_TEST( !fd_mem_iszero( fd_account_data( vote_account_meta ), vote_account_meta->dlen ) );

  test_env_cleanup( env );
  FD_LOG_NOTICE(( "test_account_initialize_v2... ok" ));
}
#endif

static void
test_account_initialize_v2_invalid_proof( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_init( env, wksp, 0 );

  setup_account_initialize_v2_txn( env );

  /* Invalidate proof */
  ulong proof_off = env->txn_p->payload_sz - 32-2 - 32-2 - 32 - 96;
  env->txn_p->payload[ proof_off ] = 0xFF;

  /* Enable SIMD-0387 feature */
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, vote_state_v4, 0UL );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, bls_pubkey_management_in_vote_account, 0UL );

  /* Run the vote program */
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( !txn_succeeded( env ) );

  test_env_cleanup( env );
  FD_LOG_NOTICE(( "test_account_initialize_v2_invalid_proof... ok" ));
}

static void
test_account_initialize_v2_no_simd_0387( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_init( env, wksp, 0 );

  setup_account_initialize_v2_txn( env );

  /* Run the vote program - should fail */
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( !txn_succeeded( env ) );

  test_env_cleanup( env );
  FD_LOG_NOTICE(( "test_account_initialize_v2_no_simd_0387... ok" ));
}

static void
test_authorized_voters_footprint( void ) {
  FD_TEST( FD_AUTHORIZED_VOTERS_POOL_ALIGN  == fd_vote_authorized_voters_pool_align() );
  FD_TEST( FD_AUTHORIZED_VOTERS_TREAP_ALIGN == fd_vote_authorized_voters_treap_align() );

  ulong pool_required  = fd_vote_authorized_voters_pool_footprint( MAX_AUTHORIZED_VOTERS_CAPACITY );
  ulong treap_required = fd_vote_authorized_voters_treap_footprint( MAX_AUTHORIZED_VOTERS_CAPACITY );

  FD_LOG_NOTICE(( "authorized voters pool required: %lu, FD_AUTHORIZED_VOTERS_POOL_FOOTPRINT: %lu",
                   pool_required, (ulong)FD_AUTHORIZED_VOTERS_POOL_FOOTPRINT ));
  FD_TEST( pool_required == FD_AUTHORIZED_VOTERS_POOL_FOOTPRINT );

  FD_LOG_NOTICE(( "authorized voters treap required: %lu, FD_AUTHORIZED_VOTERS_TREAP_FOOTPRINT: %lu",
                   treap_required, (ulong)FD_AUTHORIZED_VOTERS_TREAP_FOOTPRINT ));
  FD_TEST( treap_required == FD_AUTHORIZED_VOTERS_TREAP_FOOTPRINT );

  FD_LOG_NOTICE(( "test_authorized_voters_footprint... ok" ));
}

static void
test_vote_lockouts_footprint( void ) {
  FD_TEST( FD_VOTE_INSTR_LOCKOUTS_ALIGN == deq_fd_vote_lockout_t_align() );

  ulong required = deq_fd_vote_lockout_t_footprint( FD_VOTE_INSTR_MAX_LOCKOUT_OFFSETS_LEN );

  FD_LOG_NOTICE(( "vote lockouts required: %lu, FD_VOTE_INSTR_LOCKOUTS_FOOTPRINT: %lu",
                   required, (ulong)FD_VOTE_INSTR_LOCKOUTS_FOOTPRINT ));
  FD_TEST( required == FD_VOTE_INSTR_LOCKOUTS_FOOTPRINT );

  FD_LOG_NOTICE(( "test_vote_lockouts_footprint... ok" ));
}

static void
test_landed_votes_footprint( void ) {
  FD_TEST( FD_LANDED_VOTES_ALIGN == deq_fd_landed_vote_t_align() );

  ulong required = deq_fd_landed_vote_t_footprint( MAX_LOCKOUT_HISTORY_CAPACITY );

  FD_LOG_NOTICE(( "landed votes required: %lu, MAX_LOCKOUT_HISTORY_CAPACITY: %lu",
                   required, (ulong)FD_LANDED_VOTES_FOOTPRINT ));
  FD_TEST( required == FD_LANDED_VOTES_FOOTPRINT );

  FD_LOG_NOTICE(( "test_landed_votes_footprint... ok" ));
}

static void
test_epoch_credits_footprint( void ) {
  FD_TEST( FD_EPOCH_CREDITS_ALIGN == deq_fd_vote_epoch_credits_t_align() );

  ulong required = deq_fd_vote_epoch_credits_t_footprint();

  FD_LOG_NOTICE(( "epoch credits required: %lu, FD_EPOCH_CREDITS_FOOTPRINT: %lu",
                   required, (ulong)FD_EPOCH_CREDITS_FOOTPRINT ));
  FD_TEST( required == FD_EPOCH_CREDITS_FOOTPRINT );

  FD_LOG_NOTICE(( "test_epoch_credits_footprint... ok" ));
}

static void
test_vote_instruction_footprints( void ) {
  FD_TEST( FD_VOTE_INSTR_SLOTS_ALIGN == deq_ulong_align() );
  FD_TEST( FD_VOTE_INSTR_SLOTS_FOOTPRINT == deq_ulong_footprint( FD_VOTE_INSTR_MAX_SLOT_NUMS_LEN ) );

  FD_TEST( FD_VOTE_INSTR_UPDATE_LOCKOUTS_ALIGN == deq_fd_vote_lockout_t_align() );
  FD_TEST( FD_VOTE_INSTR_UPDATE_LOCKOUTS_FOOTPRINT == deq_fd_vote_lockout_t_footprint( FD_VOTE_INSTR_MAX_LOCKOUTS_LEN ) );

  FD_TEST( FD_VOTE_INSTR_LOCKOUT_OFFSET_ALIGN == alignof(fd_lockout_offset_t) );
  FD_TEST( FD_VOTE_INSTR_LOCKOUT_OFFSET_FOOTPRINT == sizeof(fd_lockout_offset_t) * FD_VOTE_INSTR_MAX_LOCKOUT_OFFSETS_LEN );

  FD_TEST( FD_VOTE_INSTR_SEED_MAX == FD_TXN_MTU );

  FD_TEST( FD_VOTE_INSTR_LANDED_VOTES_ALIGN == deq_fd_landed_vote_t_align() );
  FD_TEST( FD_VOTE_INSTR_LANDED_VOTES_FOOTPRINT == deq_fd_landed_vote_t_footprint( FD_VOTE_INSTR_MAX_LOCKOUT_OFFSETS_LEN ) );

  FD_LOG_NOTICE(( "test_vote_instruction_footprints... ok" ));
}

/**********************************************************************/
/* Helpers for unit tests below                                       */
/**********************************************************************/

/* A minimal ctx mock: only txn_out is valid.
   Used for functions that only write ctx->txn_out->err.custom_err. */
static void
make_mock_ctx( fd_txn_out_t * txn_out, fd_exec_instr_ctx_t * ctx ) {
  fd_memset( txn_out, 0, sizeof(*txn_out) );
  fd_memset( ctx,     0, sizeof(*ctx)     );
  ctx->txn_out = txn_out;
}

/* Build a V3 vote state in *versioned using the given pubkey as all
   identities and the given epoch as the initial clock epoch. */
static void
make_v3_state( fd_vote_state_versioned_t * versioned,
               fd_pubkey_t const *         pubkey,
               ulong                       clock_epoch ) {
  fd_vote_init_t vote_init = {
    .authorized_voter    = *pubkey,
    .authorized_withdrawer = *pubkey,
    .node_pubkey         = *pubkey,
    .commission          = 0
  };
  fd_sol_sysvar_clock_t clock = { .epoch = clock_epoch };
  fd_vote_program_v3_create_new( &vote_init, &clock, versioned );
}

/* Build a V4 vote state in *versioned.  vote_pubkey is the vote account
   key (used to populate inflation_rewards_collector). */
static void
make_v4_state( fd_vote_state_versioned_t * versioned,
               fd_pubkey_t const *         vote_pubkey,
               fd_pubkey_t const *         pubkey,
               ulong                       clock_epoch ) {
  fd_vote_init_t vote_init = {
    .authorized_voter      = *pubkey,
    .authorized_withdrawer = *pubkey,
    .node_pubkey           = *pubkey,
    .commission            = 0
  };
  fd_sol_sysvar_clock_t clock = { .epoch = clock_epoch };
  fd_vote_state_v4_create_new_with_defaults( vote_pubkey, &vote_init, &clock, versioned );
}

/* Count the number of entries in the authorized_voters treap. */
static ulong
authorized_voters_len_v3( fd_vote_state_v3_t const * v3 ) {
  return fd_vote_authorized_voters_treap_ele_cnt( v3->authorized_voters.treap );
}
static ulong
authorized_voters_len_v4( fd_vote_state_v4_t const * v4 ) {
  return fd_vote_authorized_voters_treap_ele_cnt( v4->authorized_voters.treap );
}

/* Get total credits from the epoch_credits deque (credits of last entry). */
static ulong
total_credits( fd_vote_state_versioned_t * versioned ) {
  fd_vote_epoch_credits_t const * ec = fd_vsv_get_epoch_credits( versioned );
  if( deq_fd_vote_epoch_credits_t_empty( ec ) ) return 0UL;
  return deq_fd_vote_epoch_credits_t_peek_tail_const( ec )->credits;
}

/**********************************************************************/
/* Group 1: Size / constant tests                                     */
/* Ports: test_v3_v4_size_equality                                    */
/**********************************************************************/

static void
test_v3_v4_size_equality( void ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L2255 */
  FD_TEST( FD_VOTE_STATE_V3_SZ == FD_VOTE_STATE_V4_SZ );
  /* V1_14_11 is smaller than V3 */
  FD_TEST( FD_VOTE_STATE_V2_SZ < FD_VOTE_STATE_V3_SZ );
  FD_LOG_NOTICE(( "test_v3_v4_size_equality... ok" ));
}

/**********************************************************************/
/* Group 2: get_and_update_authorized_voter tests                     */
/* Ports: test_get_and_update_authorized_voter_v3                     */
/*        test_get_and_update_authorized_voter_v4                     */
/**********************************************************************/

static void
test_get_and_update_authorized_voter_v3( void ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L1384 */
  fd_pubkey_t original_voter = {{ 0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t new_voter      = {{ 0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  fd_vote_state_versioned_t versioned[1];
  make_v3_state( versioned, &original_voter, 0 );
  fd_vote_state_v3_t * v3 = &versioned->v3;

  FD_TEST( authorized_voters_len_v3( v3 ) == 1 );

  /* Querying epoch 1 should still return original_voter */
  fd_pubkey_t * out = NULL;
  FD_TEST( fd_vote_state_v3_get_and_update_authorized_voter( v3, 1, &out ) == FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_pubkey_eq( out, &original_voter ) );

  /* Query at epoch 5 — original_voter still valid, epochs 0..5 purged */
  FD_TEST( fd_vote_state_v3_get_and_update_authorized_voter( v3, 5, &out ) == FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_pubkey_eq( out, &original_voter ) );
  FD_TEST( authorized_voters_len_v3( v3 ) == 1 );
  for( ulong i=0; i<5; i++ ) {
    FD_TEST( !fd_authorized_voters_contains( &v3->authorized_voters, i ) );
  }

  /* Set a new voter for epoch 7 */
  fd_txn_out_t txn_out[1]; fd_exec_instr_ctx_t ctx[1];
  make_mock_ctx( txn_out, ctx );
  FD_TEST( fd_vote_state_v3_set_new_authorized_voter(
    ctx, v3, &new_voter, 5, 7, NULL, 1, NULL, 0 ) == FD_EXECUTOR_INSTR_SUCCESS );

  /* Epoch 6 → original_voter */
  FD_TEST( fd_vote_state_v3_get_and_update_authorized_voter( v3, 6, &out ) == FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_pubkey_eq( out, &original_voter ) );

  /* Epochs 7..9 → new_voter */
  for( ulong i=7; i<10; i++ ) {
    FD_TEST( fd_vote_state_v3_get_and_update_authorized_voter( v3, i, &out ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( fd_pubkey_eq( out, &new_voter ) );
  }

  /* After advancing to epoch 9, only one entry remains */
  FD_TEST( authorized_voters_len_v3( v3 ) == 1 );

  FD_LOG_NOTICE(( "test_get_and_update_authorized_voter_v3... ok" ));
}

static void
test_get_and_update_authorized_voter_v4( void ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L1454
     V4 retains current_epoch-1 (purges up to sat_sub(epoch,1)).  */
  fd_pubkey_t vote_pubkey   = {{ 0xAA,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t original_voter = {{ 0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t new_voter      = {{ 0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  fd_vote_state_versioned_t versioned[1];
  make_v4_state( versioned, &vote_pubkey, &original_voter, 0 );
  fd_vote_state_v4_t * v4 = &versioned->v4;

  FD_TEST( authorized_voters_len_v4( v4 ) == 1 );

  /* Epoch 1 → original_voter */
  fd_pubkey_t * out = NULL;
  FD_TEST( fd_vote_state_v4_get_and_update_authorized_voter( v4, 1, &out ) == FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_pubkey_eq( out, &original_voter ) );

  /* Epoch 5 → original_voter; epochs 0..5 purged (V4 purges up to epoch-1=4, so 0..4) */
  FD_TEST( fd_vote_state_v4_get_and_update_authorized_voter( v4, 5, &out ) == FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_pubkey_eq( out, &original_voter ) );
  FD_TEST( authorized_voters_len_v4( v4 ) == 1 );
  for( ulong i=0; i<=5; i++ ) {
    FD_TEST( !fd_authorized_voters_contains( &v4->authorized_voters, i ) );
  }

  /* Query epochs 6 and 7 back-to-back → len becomes 2 (retains epoch 6 and 7) */
  FD_TEST( fd_vote_state_v4_get_and_update_authorized_voter( v4, 6, &out ) == FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_pubkey_eq( out, &original_voter ) );
  FD_TEST( fd_vote_state_v4_get_and_update_authorized_voter( v4, 7, &out ) == FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_pubkey_eq( out, &original_voter ) );
  FD_TEST( authorized_voters_len_v4( v4 ) == 2 );

  /* Set new voter at epoch 9 */
  fd_txn_out_t txn_out[1]; fd_exec_instr_ctx_t ctx[1];
  make_mock_ctx( txn_out, ctx );
  FD_TEST( fd_vote_state_v4_set_new_authorized_voter(
    ctx, v4, &new_voter, 7, 9, NULL, 1, NULL, 0 ) == FD_EXECUTOR_INSTR_SUCCESS );

  /* Epoch 8 → original_voter */
  FD_TEST( fd_vote_state_v4_get_and_update_authorized_voter( v4, 8, &out ) == FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_pubkey_eq( out, &original_voter ) );

  /* Epochs 9..11 → new_voter */
  for( ulong i=9; i<12; i++ ) {
    FD_TEST( fd_vote_state_v4_get_and_update_authorized_voter( v4, i, &out ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( fd_pubkey_eq( out, &new_voter ) );
  }
  FD_TEST( authorized_voters_len_v4( v4 ) == 2 );

  /* Skip to epoch 15 → only 1 entry retained */
  FD_TEST( fd_vote_state_v4_get_and_update_authorized_voter( v4, 15, &out ) == FD_EXECUTOR_INSTR_SUCCESS );
  FD_TEST( fd_pubkey_eq( out, &new_voter ) );
  FD_TEST( authorized_voters_len_v4( v4 ) == 1 );

  FD_LOG_NOTICE(( "test_get_and_update_authorized_voter_v4... ok" ));
}

/**********************************************************************/
/* Group 3: Authorized voter locking tests                            */
/* Ports: test_authorized_voter_is_locked_within_epoch               */
/**********************************************************************/

/* Helper: runs the locking check for any vote state version.
   v is a versioned pointer.  original_voter is the initial voter.   */
static void
assert_authorized_voter_is_locked_within_epoch_v3( fd_vote_state_v3_t * v3,
                                                    fd_pubkey_t const *  original_voter ) {
  fd_pubkey_t new_voter = {{ 0x77,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                              0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_txn_out_t txn_out[1]; fd_exec_instr_ctx_t ctx[1];
  make_mock_ctx( txn_out, ctx );

  /* Same-epoch → TooSoonToReauthorize */
  int rc = fd_vote_state_v3_set_new_authorized_voter(
    ctx, v3, &new_voter, 1, 1, NULL, 1, NULL, 0 );
  FD_TEST( rc == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR );
  FD_TEST( txn_out->err.custom_err == (uint)FD_VOTE_ERR_TOO_SOON_TO_REAUTHORIZE );

  /* original voter unchanged for epoch 1 */
  fd_pubkey_t * out = NULL;
  fd_vote_state_v3_get_and_update_authorized_voter( v3, 1, &out );
  FD_TEST( fd_pubkey_eq( out, original_voter ) );

  /* Setting for future epoch 2 should succeed */
  make_mock_ctx( txn_out, ctx );
  FD_TEST( fd_vote_state_v3_set_new_authorized_voter(
    ctx, v3, &new_voter, 1, 2, NULL, 1, NULL, 0 ) == FD_EXECUTOR_INSTR_SUCCESS );

  /* Same-epoch again (epoch 3) → TooSoonToReauthorize */
  make_mock_ctx( txn_out, ctx );
  rc = fd_vote_state_v3_set_new_authorized_voter(
    ctx, v3, original_voter, 3, 3, NULL, 1, NULL, 0 );
  FD_TEST( rc == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR );
  FD_TEST( txn_out->err.custom_err == (uint)FD_VOTE_ERR_TOO_SOON_TO_REAUTHORIZE );

  /* epoch 3 is still new_voter (not original) */
  out = NULL;
  fd_vote_state_v3_get_and_update_authorized_voter( v3, 3, &out );
  FD_TEST( fd_pubkey_eq( out, &new_voter ) );
}

static void
assert_authorized_voter_is_locked_within_epoch_v4( fd_vote_state_v4_t * v4,
                                                    fd_pubkey_t const *  original_voter ) {
  fd_pubkey_t new_voter = {{ 0x77,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                              0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_txn_out_t txn_out[1]; fd_exec_instr_ctx_t ctx[1];
  make_mock_ctx( txn_out, ctx );

  /* Same-epoch → TooSoonToReauthorize */
  int rc = fd_vote_state_v4_set_new_authorized_voter(
    ctx, v4, &new_voter, 1, 1, NULL, 1, NULL, 0 );
  FD_TEST( rc == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR );
  FD_TEST( txn_out->err.custom_err == (uint)FD_VOTE_ERR_TOO_SOON_TO_REAUTHORIZE );

  /* original voter unchanged */
  fd_pubkey_t * out = NULL;
  fd_vote_state_v4_get_and_update_authorized_voter( v4, 1, &out );
  FD_TEST( fd_pubkey_eq( out, original_voter ) );

  /* Future epoch 2 → success */
  make_mock_ctx( txn_out, ctx );
  FD_TEST( fd_vote_state_v4_set_new_authorized_voter(
    ctx, v4, &new_voter, 1, 2, NULL, 1, NULL, 0 ) == FD_EXECUTOR_INSTR_SUCCESS );

  /* Same-epoch (3→3) → TooSoonToReauthorize */
  make_mock_ctx( txn_out, ctx );
  rc = fd_vote_state_v4_set_new_authorized_voter(
    ctx, v4, original_voter, 3, 3, NULL, 1, NULL, 0 );
  FD_TEST( rc == FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR );
  FD_TEST( txn_out->err.custom_err == (uint)FD_VOTE_ERR_TOO_SOON_TO_REAUTHORIZE );

  /* epoch 3 still new_voter */
  out = NULL;
  fd_vote_state_v4_get_and_update_authorized_voter( v4, 3, &out );
  FD_TEST( fd_pubkey_eq( out, &new_voter ) );
}

static void
test_authorized_voter_is_locked_within_epoch( void ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L1362 */
  fd_pubkey_t vote_pubkey   = {{ 0xAA,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t original_voter = {{ 0x11,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  fd_vote_state_versioned_t versioned_v3[1];
  make_v3_state( versioned_v3, &original_voter, 0 );
  assert_authorized_voter_is_locked_within_epoch_v3( &versioned_v3->v3, &original_voter );

  fd_vote_state_versioned_t versioned_v4[1];
  make_v4_state( versioned_v4, &vote_pubkey, &original_voter, 0 );
  assert_authorized_voter_is_locked_within_epoch_v4( &versioned_v4->v4, &original_voter );

  FD_LOG_NOTICE(( "test_authorized_voter_is_locked_within_epoch... ok" ));
}

/**********************************************************************/
/* Group 4: set_new_authorized_voter                                  */
/* Ports: test_set_new_authorized_voter                               */
/**********************************************************************/

/* Helper shared by V3 and V4 variants.  Calls set_new_authorized_voter
   and validates the common post-conditions (new voter is recorded for
   target_epoch).  For V3 the caller also checks prior_voters.         */
static void
set_new_authorized_voter_and_assert_v3( fd_vote_state_v3_t * v3,
                                        fd_pubkey_t const *  original_voter,
                                        ulong                epoch_offset ) {
  fd_pubkey_t new_voter = {{ 0x99,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                              0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  fd_txn_out_t txn_out[1]; fd_exec_instr_ctx_t ctx[1];
  make_mock_ctx( txn_out, ctx );

  FD_TEST( fd_vote_state_v3_set_new_authorized_voter(
    ctx, v3, &new_voter, 0, epoch_offset, NULL, 1, NULL, 0 ) == FD_EXECUTOR_INSTR_SUCCESS );

  /* The new voter must be present in the treap */
  FD_TEST( fd_authorized_voters_contains( &v3->authorized_voters, epoch_offset ) );

  /* prior_voters must have an entry: last entry should have original_voter pubkey */
  FD_TEST( !v3->prior_voters.is_empty );
  fd_vote_prior_voter_t * pv = &v3->prior_voters.buf[ v3->prior_voters.idx ];
  FD_TEST( fd_pubkey_eq( &pv->pubkey, original_voter ) );
}

static void
set_new_authorized_voter_and_assert_v4( fd_vote_state_v4_t * v4,
                                        ulong                epoch_offset ) {
  fd_pubkey_t new_voter = {{ 0x99,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                              0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  fd_txn_out_t txn_out[1]; fd_exec_instr_ctx_t ctx[1];
  make_mock_ctx( txn_out, ctx );

  FD_TEST( fd_vote_state_v4_set_new_authorized_voter(
    ctx, v4, &new_voter, 0, epoch_offset, NULL, 1, NULL, 0 ) == FD_EXECUTOR_INSTR_SUCCESS );

  FD_TEST( fd_authorized_voters_contains( &v4->authorized_voters, epoch_offset ) );
  /* V4 has no prior_voters field */
}

static void
test_set_new_authorized_voter( void ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L1297 */
  fd_pubkey_t vote_pubkey    = {{ 0xBB,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t original_voter = {{ 0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  ulong epoch_offset = 15;

  /* V3: prior_voters should record the old voter */
  fd_vote_state_versioned_t versioned_v3[1];
  make_v3_state( versioned_v3, &original_voter, 0 );
  FD_TEST( versioned_v3->v3.prior_voters.is_empty );
  set_new_authorized_voter_and_assert_v3( &versioned_v3->v3, &original_voter, epoch_offset );

  /* V4: no prior_voters — just check treap */
  fd_vote_state_versioned_t versioned_v4[1];
  make_v4_state( versioned_v4, &vote_pubkey, &original_voter, 0 );
  set_new_authorized_voter_and_assert_v4( &versioned_v4->v4, epoch_offset );

  FD_LOG_NOTICE(( "test_set_new_authorized_voter... ok" ));
}

/**********************************************************************/
/* Group 5: BLS authorized voter tests                                */
/* Ports: test_get_and_update_authorized_voter_v4_with_bls            */
/**********************************************************************/

static void
test_get_and_update_authorized_voter_v4_with_bls( void ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L2323 */
  fd_pubkey_t vote_pubkey    = {{ 0xCC,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t original_voter = {{ 0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t new_voter      = {{ 0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t newer_voter    = {{ 0x03,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  fd_vote_state_versioned_t versioned[1];
  make_v4_state( versioned, &vote_pubkey, &original_voter, 0 );
  fd_vote_state_v4_t * v4 = &versioned->v4;

  FD_TEST( authorized_voters_len_v4( v4 ) == 1 );
  FD_TEST( !fd_vsv_has_bls_pubkey( versioned ) );

  /* Set new voter with a BLS key */
  uchar bls_key[FD_BLS_PUBKEY_COMPRESSED_SZ];
  fd_memset( bls_key, 0x03, FD_BLS_PUBKEY_COMPRESSED_SZ );
  fd_txn_out_t txn_out[1]; fd_exec_instr_ctx_t ctx[1];
  make_mock_ctx( txn_out, ctx );
  FD_TEST( fd_vote_state_v4_set_new_authorized_voter(
    ctx, v4, &new_voter, 0, 1, bls_key, 1, NULL, 0 ) == FD_EXECUTOR_INSTR_SUCCESS );

  FD_TEST( authorized_voters_len_v4( v4 ) == 2 );
  FD_TEST( v4->has_bls_pubkey_compressed );
  FD_TEST( !memcmp( v4->bls_pubkey_compressed, bls_key, FD_BLS_PUBKEY_COMPRESSED_SZ ) );
  FD_TEST( fd_vsv_has_bls_pubkey( versioned ) );

  /* Set another voter with a different BLS key */
  uchar newer_bls_key[FD_BLS_PUBKEY_COMPRESSED_SZ];
  fd_memset( newer_bls_key, 0x07, FD_BLS_PUBKEY_COMPRESSED_SZ );
  make_mock_ctx( txn_out, ctx );
  FD_TEST( fd_vote_state_v4_set_new_authorized_voter(
    ctx, v4, &newer_voter, 1, 2, newer_bls_key, 1, NULL, 0 ) == FD_EXECUTOR_INSTR_SUCCESS );

  FD_TEST( authorized_voters_len_v4( v4 ) == 3 );
  FD_TEST( v4->has_bls_pubkey_compressed );
  FD_TEST( !memcmp( v4->bls_pubkey_compressed, newer_bls_key, FD_BLS_PUBKEY_COMPRESSED_SZ ) );

  /* V3 rejects BLS pubkey */
  fd_vote_state_versioned_t versioned_v3[1];
  make_v3_state( versioned_v3, &original_voter, 0 );
  make_mock_ctx( txn_out, ctx );
  FD_TEST( fd_vote_state_v3_set_new_authorized_voter(
    ctx, &versioned_v3->v3, &new_voter, 0, 1, bls_key, 1, NULL, 0 )
    == FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );

  FD_LOG_NOTICE(( "test_get_and_update_authorized_voter_v4_with_bls... ok" ));
}

/**********************************************************************/
/* Group 6: Epoch credits tests                                       */
/* Ports: test_vote_state_epoch_credits                               */
/*        test_vote_state_epoch0_no_credits                           */
/*        test_vote_state_increment_credits                           */
/**********************************************************************/

static void
test_vote_state_epoch_credits_impl( fd_vote_state_versioned_t * versioned ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L1598 */
  FD_TEST( total_credits( versioned ) == 0 );
  FD_TEST( deq_fd_vote_epoch_credits_t_empty( fd_vsv_get_epoch_credits( versioned ) ) );

  ulong credits    = 0;
  ulong prev       = 0;
  ulong epochs     = (ulong)(MAX_EPOCH_CREDITS_HISTORY + 2);

  for( ulong epoch=0; epoch<epochs; epoch++ ) {
    for( ulong j=0; j<epoch; j++ ) {
      fd_vsv_increment_credits( versioned, epoch, 1 );
      credits++;
    }
  }

  FD_TEST( total_credits( versioned ) == credits );

  fd_vote_epoch_credits_t const * ec = fd_vsv_get_epoch_credits( versioned );
  ulong len = deq_fd_vote_epoch_credits_t_cnt( ec );
  FD_TEST( len <= MAX_EPOCH_CREDITS_HISTORY );

  /* Verify the expected (epoch, credits, prev_credits) from the last MAX entries */
  /* Rebuild expected list from scratch */
  typedef struct { ulong epoch; ulong credits; ulong prev; } ec_entry_t;
  ec_entry_t expected[ MAX_EPOCH_CREDITS_HISTORY + 2 ];
  ulong n_expected = 0;
  credits = 0; prev = 0;
  for( ulong epoch=0; epoch<epochs; epoch++ ) {
    prev = credits;
    credits += epoch;
    expected[ n_expected++ ] = (ec_entry_t){ epoch, credits, prev };
  }
  /* Trim to last MAX_EPOCH_CREDITS_HISTORY */
  ulong trim = n_expected > MAX_EPOCH_CREDITS_HISTORY
    ? n_expected - MAX_EPOCH_CREDITS_HISTORY : 0;
  ulong n_trimmed = n_expected - trim;

  FD_TEST( len == n_trimmed );

  ulong i = 0;
  for( deq_fd_vote_epoch_credits_t_iter_t it = deq_fd_vote_epoch_credits_t_iter_init( ec );
       !deq_fd_vote_epoch_credits_t_iter_done( ec, it );
       it = deq_fd_vote_epoch_credits_t_iter_next( ec, it ), i++ ) {
    fd_vote_epoch_credits_t const * e = deq_fd_vote_epoch_credits_t_iter_ele_const( ec, it );
    ec_entry_t * x = &expected[ trim + i ];
    FD_TEST( e->epoch == x->epoch );
    FD_TEST( e->credits == x->credits );
    FD_TEST( e->prev_credits == x->prev );
  }
}

static void
test_vote_state_epoch_credits( void ) {
  fd_pubkey_t pk = {{ 0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  fd_vote_state_versioned_t v3[1]; make_v3_state( v3, &pk, 0 );
  test_vote_state_epoch_credits_impl( v3 );

  fd_vote_state_versioned_t v4[1]; make_v4_state( v4, &pk, &pk, 0 );
  test_vote_state_epoch_credits_impl( v4 );

  FD_LOG_NOTICE(( "test_vote_state_epoch_credits... ok" ));
}

static void
test_vote_state_epoch0_no_credits( void ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L1623 */
  fd_pubkey_t pk = {{ 0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  for( int v=0; v<2; v++ ) {
    fd_vote_state_versioned_t versioned[1];
    if( v==0 ) make_v3_state( versioned, &pk, 0 );
    else       make_v4_state( versioned, &pk, &pk, 0 );

    fd_vote_epoch_credits_t const * ec = fd_vsv_get_epoch_credits( versioned );
    FD_TEST( deq_fd_vote_epoch_credits_t_empty( ec ) );

    fd_vsv_increment_credits( versioned, 1, 1 );
    FD_TEST( deq_fd_vote_epoch_credits_t_cnt( fd_vsv_get_epoch_credits( versioned ) ) == 1 );

    fd_vsv_increment_credits( versioned, 2, 1 );
    FD_TEST( deq_fd_vote_epoch_credits_t_cnt( fd_vsv_get_epoch_credits( versioned ) ) == 2 );
  }

  FD_LOG_NOTICE(( "test_vote_state_epoch0_no_credits... ok" ));
}

static void
test_vote_state_increment_credits( void ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L1634 */
  fd_pubkey_t pk = {{ 0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  for( int v=0; v<2; v++ ) {
    fd_vote_state_versioned_t versioned[1];
    if( v==0 ) make_v3_state( versioned, &pk, 0 );
    else       make_v4_state( versioned, &pk, &pk, 0 );

    ulong n = (ulong)(MAX_EPOCH_CREDITS_HISTORY + 2);
    for( ulong i=0; i<n; i++ ) {
      fd_vsv_increment_credits( versioned, i, 1 );
    }

    FD_TEST( total_credits( versioned ) == n );
    FD_TEST( deq_fd_vote_epoch_credits_t_cnt( fd_vsv_get_epoch_credits( versioned ) )
             <= MAX_EPOCH_CREDITS_HISTORY );
  }

  FD_LOG_NOTICE(( "test_vote_state_increment_credits... ok" ));
}

/**********************************************************************/
/* Group 7: Commission BPS tests                                      */
/* Ports: test_v4_commission_basis_points                             */
/*        test_set_inflation_rewards_commission_bps                   */
/**********************************************************************/

static void
test_v4_commission_basis_points( void ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L2093
     V4 stores commission as basis_points = commission * 100.          */
  static uchar commissions[] = { 0, 1, 5, 10, 25, 50, 75, 100, 255 };
  static ushort expected_bps[] = { 0, 100, 500, 1000, 2500, 5000, 7500, 10000, 25500 };

  fd_pubkey_t vote_pubkey = {{ 0xDD,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t pk          = {{ 0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  for( ulong i=0; i<sizeof(commissions)/sizeof(commissions[0]); i++ ) {
    fd_vote_init_t vi = {
      .authorized_voter      = pk,
      .authorized_withdrawer = pk,
      .node_pubkey           = pk,
      .commission            = commissions[i]
    };
    fd_sol_sysvar_clock_t clock = {0};
    fd_vote_state_versioned_t versioned[1];
    fd_vote_state_v4_create_new_with_defaults( &vote_pubkey, &vi, &clock, versioned );
    FD_TEST( versioned->v4.inflation_rewards_commission_bps == expected_bps[i] );
    FD_TEST( fd_vsv_get_commission( versioned ) == commissions[i] );
  }

  FD_LOG_NOTICE(( "test_v4_commission_basis_points... ok" ));
}

static void
test_set_inflation_rewards_commission_bps( void ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L2384 */
  fd_pubkey_t pk = {{ 0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  /* V3: fd_vsv_set_commission uses percent, not BPS.
     Setting commission to 5 stores 5 in v3.commission.
     fd_vsv_get_commission returns it as-is (no BPS conversion for V3). */
  fd_vote_state_versioned_t v3[1];
  make_v3_state( v3, &pk, 0 );
  uchar orig_commission = fd_vsv_get_commission( v3 );
  /* The set_commission call stores commission as percent in V3 */
  fd_vsv_set_commission( v3, 5 );
  /* V3 get_commission returns the stored percent directly */
  FD_TEST( fd_vsv_get_commission( v3 ) == 5 );
  /* Directly setting BPS field has no effect through set_commission in V3 */
  fd_vsv_set_commission( v3, orig_commission );
  FD_TEST( fd_vsv_get_commission( v3 ) == orig_commission );

  /* V4: inflation_rewards_commission_bps is a live field.
     fd_vsv_get_commission() returns bps / 100.
     Values > 10000 bps are allowed (capping is done at reward calc time). */
  fd_pubkey_t vote_pubkey = {{ 0xEE,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_vote_state_versioned_t v4[1];
  make_v4_state( v4, &vote_pubkey, &pk, 0 );

  static ushort bps_vals[] = { 0, 100, 500, 1000, 5000, 10000, 10001, 15000, 65535 };
  for( ulong i=0; i<sizeof(bps_vals)/sizeof(bps_vals[0]); i++ ) {
    ushort bps = bps_vals[i];
    v4->v4.inflation_rewards_commission_bps = bps;
    /* get_commission returns bps/100 as a truncated uchar */
    FD_TEST( fd_vsv_get_commission( v4 ) == (uchar)(bps/100) );
  }

  FD_LOG_NOTICE(( "test_set_inflation_rewards_commission_bps... ok" ));
}

/**********************************************************************/
/* Group 8: Version conversion tests                                  */
/* Ports: test_v4_conversion_from_all_versions                        */
/**********************************************************************/

static void
test_v4_conversion_from_all_versions( void ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L2119 */
  fd_pubkey_t vote_pubkey          = {{ 0xAA,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t node_pubkey          = {{ 0xBB,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t authorized_voter     = {{ 0xCC,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t authorized_withdrawer = {{ 0xDD,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                          0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  uchar commission = 42;

  /* --- V1_14_11 → V4 --- */
  {
    fd_vote_state_versioned_t versioned[1];
    fd_vote_state_versioned_new( versioned, fd_vote_state_versioned_enum_v1_14_11 );
    fd_vote_state_1_14_11_t * s = &versioned->v1_14_11;
    s->node_pubkey           = node_pubkey;
    s->authorized_withdrawer = authorized_withdrawer;
    s->commission            = commission;
    s->prior_voters.is_empty = 1;
    s->prior_voters.idx      = 31;
    /* Insert one authorized voter */
    fd_vote_authorized_voter_t * av =
      fd_vote_authorized_voters_pool_ele_acquire( s->authorized_voters.pool );
    av->epoch = 0; av->pubkey = authorized_voter; av->prio = av->pubkey.uc[0];
    fd_vote_authorized_voters_treap_ele_insert( s->authorized_voters.treap, av,
                                                s->authorized_voters.pool );

    FD_TEST( fd_vsv_try_convert_to_v4( versioned, &vote_pubkey ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( versioned->kind == fd_vote_state_versioned_enum_v4 );
    fd_vote_state_v4_t * v4 = &versioned->v4;
    FD_TEST( fd_pubkey_eq( &v4->node_pubkey, &node_pubkey ) );
    FD_TEST( fd_pubkey_eq( &v4->authorized_withdrawer, &authorized_withdrawer ) );
    /* SIMD-0185 defaults */
    FD_TEST( v4->inflation_rewards_commission_bps == (ushort)(commission * 100) );
    FD_TEST( fd_pubkey_eq( &v4->inflation_rewards_collector, &vote_pubkey ) );
    FD_TEST( fd_pubkey_eq( &v4->block_revenue_collector, &node_pubkey ) );
    FD_TEST( v4->block_revenue_commission_bps == (ushort)DEFAULT_BLOCK_REVENUE_COMMISSION_BPS );
    FD_TEST( v4->pending_delegator_rewards == 0 );
    FD_TEST( !v4->has_bls_pubkey_compressed );
  }

  /* --- V3 → V4 --- */
  {
    fd_vote_init_t vi = {
      .authorized_voter      = authorized_voter,
      .authorized_withdrawer = authorized_withdrawer,
      .node_pubkey           = node_pubkey,
      .commission            = commission
    };
    fd_sol_sysvar_clock_t clock = {0};
    fd_vote_state_versioned_t versioned[1];
    fd_vote_program_v3_create_new( &vi, &clock, versioned );

    FD_TEST( fd_vsv_try_convert_to_v4( versioned, &vote_pubkey ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( versioned->kind == fd_vote_state_versioned_enum_v4 );
    fd_vote_state_v4_t * v4 = &versioned->v4;
    FD_TEST( fd_pubkey_eq( &v4->node_pubkey, &node_pubkey ) );
    FD_TEST( fd_pubkey_eq( &v4->authorized_withdrawer, &authorized_withdrawer ) );
    FD_TEST( v4->inflation_rewards_commission_bps == (ushort)(commission * 100) );
    FD_TEST( fd_pubkey_eq( &v4->inflation_rewards_collector, &vote_pubkey ) );
    FD_TEST( fd_pubkey_eq( &v4->block_revenue_collector, &node_pubkey ) );
    FD_TEST( v4->block_revenue_commission_bps == (ushort)DEFAULT_BLOCK_REVENUE_COMMISSION_BPS );
    FD_TEST( v4->pending_delegator_rewards == 0 );
    FD_TEST( !v4->has_bls_pubkey_compressed );
  }

  /* --- V4 → V4 (identity) --- */
  {
    fd_pubkey_t custom_collector = {{ 0xFF,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                       0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
    fd_vote_init_t vi = {
      .authorized_voter      = authorized_voter,
      .authorized_withdrawer = authorized_withdrawer,
      .node_pubkey           = node_pubkey,
      .commission            = commission
    };
    fd_sol_sysvar_clock_t clock = {0};
    fd_vote_state_versioned_t versioned[1];
    fd_vote_state_v4_create_new_with_defaults( &vote_pubkey, &vi, &clock, versioned );
    /* Customize some V4-specific fields */
    versioned->v4.inflation_rewards_commission_bps = 1234;
    versioned->v4.block_revenue_commission_bps = 5678;
    versioned->v4.inflation_rewards_collector  = custom_collector;
    versioned->v4.pending_delegator_rewards    = 999;

    /* Snapshot before conversion */
    ushort saved_ir_bps  = versioned->v4.inflation_rewards_commission_bps;
    ushort saved_br_bps  = versioned->v4.block_revenue_commission_bps;
    ulong  saved_rewards = versioned->v4.pending_delegator_rewards;

    FD_TEST( fd_vsv_try_convert_to_v4( versioned, &vote_pubkey ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( versioned->kind == fd_vote_state_versioned_enum_v4 );
    /* Fields must be unchanged (identity) */
    FD_TEST( versioned->v4.inflation_rewards_commission_bps == saved_ir_bps );
    FD_TEST( versioned->v4.block_revenue_commission_bps     == saved_br_bps );
    FD_TEST( versioned->v4.pending_delegator_rewards        == saved_rewards );
    FD_TEST( fd_pubkey_eq( &versioned->v4.inflation_rewards_collector, &custom_collector ) );
  }

  FD_LOG_NOTICE(( "test_v4_conversion_from_all_versions... ok" ));
}

/**********************************************************************/
/* Group 9: Account init / deinit tests                               */
/* Ports: test_init_vote_account_state_v3/v4                          */
/*        test_deinitialize_vote_account_state_v3/v4                  */
/*                                                                    */
/* These require a borrowed_account_t backed by a real accdb.         */
/* We use the existing test_env_t infrastructure plus a lightweight   */
/* setup that populates a vote account into the accdb and opens it.   */
/**********************************************************************/

/* Struct that holds the backing memory for a mock borrowed account
   together with a minimal exec_instr_ctx for resize/mutation checks. */
struct mock_vote_ba {
  /* Instruction info: 1 account (vote account at callee idx 0) */
  fd_instr_info_t     instr[1];
  /* Transaction output: 2 slots — [0]=program, [1]=vote account */
  fd_txn_out_t        txn_out[1];
  /* Exec instr context */
  fd_exec_instr_ctx_t ctx[1];
  /* Meta + data: large enough for the largest V4 state */
  uchar               acc_mem[ sizeof(fd_account_meta_t) + FD_VOTE_STATE_V4_SZ ];
  /* Borrowed account ref count */
  ulong               refcnt;
  /* Pubkeys */
  fd_pubkey_t         vote_pubkey[1];
};
typedef struct mock_vote_ba mock_vote_ba_t;

static void
mock_vote_ba_init( mock_vote_ba_t *    m,
                   fd_pubkey_t const * vote_pubkey,
                   fd_bank_t *         bank,
                   ulong               lamports,
                   ulong               dlen ) {
  fd_memset( m, 0, sizeof(*m) );

  m->vote_pubkey[0] = *vote_pubkey;

  /* Instruction info: program at txn-idx 0, vote account at callee-idx 0 */
  m->instr->program_id             = 0; /* txn-level index of the vote program */
  m->instr->acct_cnt               = 1;
  m->instr->accounts[0].index_in_transaction = 1; /* vote acc at txn-idx 1 */
  m->instr->accounts[0].index_in_callee      = 0;
  m->instr->accounts[0].is_writable          = 1;
  m->instr->accounts[0].is_signer            = 0;

  /* Transaction output */
  m->txn_out->accounts.cnt = 2;
  fd_memcpy( m->txn_out->accounts.keys[0].key,
             fd_solana_vote_program_id.key, 32 ); /* slot 0 = program */
  fd_memcpy( m->txn_out->accounts.keys[1].key,
             vote_pubkey->key, 32 );              /* slot 1 = vote account */

  /* Exec instr context */
  m->ctx->instr   = m->instr;
  m->ctx->txn_out = m->txn_out;
  m->ctx->bank    = bank;

  /* Account meta */
  fd_account_meta_t * meta = (fd_account_meta_t *)m->acc_mem;
  meta->lamports = lamports;
  meta->dlen     = (uint)dlen;
  fd_memcpy( meta->owner, fd_solana_vote_program_id.key, 32 );
}

static fd_borrowed_account_t *
mock_vote_ba_borrow( mock_vote_ba_t * m ) {
  static fd_borrowed_account_t ba[1];
  m->refcnt = 1;
  fd_account_meta_t * meta = (fd_account_meta_t *)m->acc_mem;
  fd_borrowed_account_init( ba, m->vote_pubkey, meta, m->ctx, 0, &m->refcnt );
  return ba;
}

static fd_account_meta_t *
mock_vote_ba_meta( mock_vote_ba_t * m ) {
  return (fd_account_meta_t *)m->acc_mem;
}

/* Compute the rent-exempt minimum balance for a given account size using
   the default rent params (same as Agave's Rent::default).
   lamports_per_uint8_year=3480, exemption_threshold=2.0, burn_percent=50 */
static ulong
rent_exempt_minimum( ulong dlen ) {
  fd_rent_t rent = {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
    .burn_percent            = 50
  };
  return fd_rent_exempt_minimum_balance( &rent, dlen );
}

static void
test_init_vote_account_state_v3( fd_wksp_t * wksp ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L1902
     Three cases:
       (1) dlen=V2_SZ, lamports=rent_exempt(V2) → can't resize → V1_14_11
       (2) dlen=V2_SZ, lamports=rent_exempt(V3) → resize to V3 → writes V3
       (3) dlen=V3_SZ, lamports=rent_exempt(V3) → already right size → V3 */

  test_env_t env[1];
  test_env_init( env, wksp, 0 );
  process_slot( env, 10UL );

  fd_pubkey_t vote_pubkey = {{ 0x10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t node_pubkey = {{ 0x20,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t auth_voter  = {{ 0x30,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t auth_wdr    = {{ 0x40,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  fd_vote_init_t vote_init = {
    .node_pubkey           = node_pubkey,
    .authorized_voter      = auth_voter,
    .authorized_withdrawer = auth_wdr,
    .commission            = 5
  };
  fd_sol_sysvar_clock_t clock = {0};

  /* Case 1: dlen=V2_SZ, lamports=rent_exempt(V2) → falls back to V1_14_11 */
  {
    mock_vote_ba_t m[1];
    mock_vote_ba_init( m, &vote_pubkey, env->bank,
                       rent_exempt_minimum( FD_VOTE_STATE_V2_SZ ),
                       FD_VOTE_STATE_V2_SZ );

    fd_vote_state_versioned_t versioned[1];
    fd_vote_program_v3_create_new( &vote_init, &clock, versioned );

    int rc = fd_vote_state_v3_set_vote_account_state( m->ctx, mock_vote_ba_borrow(m), versioned );
    FD_TEST( rc == FD_EXECUTOR_INSTR_SUCCESS );
    /* Account stays at V2 size → V1_14_11 serialized */
    FD_TEST( mock_vote_ba_meta(m)->dlen == FD_VOTE_STATE_V2_SZ );
    /* Deserialize and check version */
    fd_vote_state_versioned_t check[1];
    FD_TEST( fd_vsv_get_state( mock_vote_ba_meta(m), check ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( check->kind == fd_vote_state_versioned_enum_v1_14_11 );
    FD_TEST( fd_pubkey_eq( &check->v1_14_11.node_pubkey, &node_pubkey ) );
    FD_TEST( check->v1_14_11.commission == 5 );
  }

  /* Case 2: dlen=V2_SZ, lamports=rent_exempt(V3) → resize → V3 */
  {
    mock_vote_ba_t m[1];
    mock_vote_ba_init( m, &vote_pubkey, env->bank,
                       rent_exempt_minimum( FD_VOTE_STATE_V3_SZ ),
                       FD_VOTE_STATE_V2_SZ );

    fd_vote_state_versioned_t versioned[1];
    fd_vote_program_v3_create_new( &vote_init, &clock, versioned );

    int rc = fd_vote_state_v3_set_vote_account_state( m->ctx, mock_vote_ba_borrow(m), versioned );
    FD_TEST( rc == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( mock_vote_ba_meta(m)->dlen == FD_VOTE_STATE_V3_SZ );
    fd_vote_state_versioned_t check[1];
    FD_TEST( fd_vsv_get_state( mock_vote_ba_meta(m), check ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( check->kind == fd_vote_state_versioned_enum_v3 );
    FD_TEST( fd_pubkey_eq( &check->v3.node_pubkey, &node_pubkey ) );
    FD_TEST( check->v3.commission == 5 );
  }

  /* Case 3: dlen=V3_SZ, lamports=rent_exempt(V3) → V3 directly */
  {
    mock_vote_ba_t m[1];
    mock_vote_ba_init( m, &vote_pubkey, env->bank,
                       rent_exempt_minimum( FD_VOTE_STATE_V3_SZ ),
                       FD_VOTE_STATE_V3_SZ );

    fd_vote_state_versioned_t versioned[1];
    fd_vote_program_v3_create_new( &vote_init, &clock, versioned );

    int rc = fd_vote_state_v3_set_vote_account_state( m->ctx, mock_vote_ba_borrow(m), versioned );
    FD_TEST( rc == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( mock_vote_ba_meta(m)->dlen == FD_VOTE_STATE_V3_SZ );
    fd_vote_state_versioned_t check[1];
    FD_TEST( fd_vsv_get_state( mock_vote_ba_meta(m), check ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( check->kind == fd_vote_state_versioned_enum_v3 );
    FD_TEST( fd_pubkey_eq( &check->v3.node_pubkey, &node_pubkey ) );
  }

  test_env_cleanup( env );
  FD_LOG_NOTICE(( "test_init_vote_account_state_v3... ok" ));
}

static void
test_init_vote_account_state_v4( fd_wksp_t * wksp ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L1960
     (1) dlen=V2_SZ, lamports=rent_exempt(V2) → AccountNotRentExempt
     (2) dlen=V2_SZ, lamports=rent_exempt(V4) → resize → V4
     (3) dlen=V4_SZ, lamports=rent_exempt(V4) → V4 directly           */

  test_env_t env[1];
  test_env_init( env, wksp, 0 );
  process_slot( env, 10UL );

  fd_pubkey_t vote_pubkey = {{ 0x11,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t node_pubkey = {{ 0x21,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t auth_voter  = {{ 0x31,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};
  fd_pubkey_t auth_wdr    = {{ 0x41,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  fd_vote_init_t vote_init = {
    .node_pubkey           = node_pubkey,
    .authorized_voter      = auth_voter,
    .authorized_withdrawer = auth_wdr,
    .commission            = 5
  };
  fd_sol_sysvar_clock_t clock = {0};

  /* Case 1: too small + insufficient lamports → AccountNotRentExempt */
  {
    mock_vote_ba_t m[1];
    mock_vote_ba_init( m, &vote_pubkey, env->bank,
                       rent_exempt_minimum( FD_VOTE_STATE_V2_SZ ),
                       FD_VOTE_STATE_V2_SZ );

    fd_vote_state_versioned_t versioned[1];
    fd_vote_state_v4_create_new_with_defaults( &vote_pubkey, &vote_init, &clock, versioned );

    int rc = fd_vote_state_v4_set_vote_account_state( m->ctx, mock_vote_ba_borrow(m), versioned );
    FD_TEST( rc == FD_EXECUTOR_INSTR_ERR_ACC_NOT_RENT_EXEMPT );
  }

  /* Case 2: too small + sufficient lamports → resize → V4 */
  {
    mock_vote_ba_t m[1];
    mock_vote_ba_init( m, &vote_pubkey, env->bank,
                       rent_exempt_minimum( FD_VOTE_STATE_V4_SZ ),
                       FD_VOTE_STATE_V2_SZ );

    fd_vote_state_versioned_t versioned[1];
    fd_vote_state_v4_create_new_with_defaults( &vote_pubkey, &vote_init, &clock, versioned );

    int rc = fd_vote_state_v4_set_vote_account_state( m->ctx, mock_vote_ba_borrow(m), versioned );
    FD_TEST( rc == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( mock_vote_ba_meta(m)->dlen == FD_VOTE_STATE_V4_SZ );
    fd_vote_state_versioned_t check[1];
    FD_TEST( fd_vsv_get_state( mock_vote_ba_meta(m), check ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( check->kind == fd_vote_state_versioned_enum_v4 );
    FD_TEST( fd_pubkey_eq( &check->v4.node_pubkey, &node_pubkey ) );
    FD_TEST( check->v4.inflation_rewards_commission_bps == (ushort)(5*100) );
  }

  /* Case 3: already V4 size → success */
  {
    mock_vote_ba_t m[1];
    mock_vote_ba_init( m, &vote_pubkey, env->bank,
                       rent_exempt_minimum( FD_VOTE_STATE_V4_SZ ),
                       FD_VOTE_STATE_V4_SZ );

    fd_vote_state_versioned_t versioned[1];
    fd_vote_state_v4_create_new_with_defaults( &vote_pubkey, &vote_init, &clock, versioned );

    int rc = fd_vote_state_v4_set_vote_account_state( m->ctx, mock_vote_ba_borrow(m), versioned );
    FD_TEST( rc == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( mock_vote_ba_meta(m)->dlen == FD_VOTE_STATE_V4_SZ );
    fd_vote_state_versioned_t check[1];
    FD_TEST( fd_vsv_get_state( mock_vote_ba_meta(m), check ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( check->kind == fd_vote_state_versioned_enum_v4 );
  }

  test_env_cleanup( env );
  FD_LOG_NOTICE(( "test_init_vote_account_state_v4... ok" ));
}

static void
test_deinitialize_vote_account_state_v3( fd_wksp_t * wksp ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L2018
     Same three size/lamport cases as init_v3, but deinitializes.
     Result is always an uninitialized (empty authorized_voters) state. */

  test_env_t env[1];
  test_env_init( env, wksp, 0 );
  process_slot( env, 10UL );

  fd_pubkey_t vote_pubkey = {{ 0x12,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  /* Case 1: dlen=V2_SZ, lamports=rent_exempt(V2) → V1_14_11 uninitialized */
  {
    mock_vote_ba_t m[1];
    mock_vote_ba_init( m, &vote_pubkey, env->bank,
                       rent_exempt_minimum( FD_VOTE_STATE_V2_SZ ),
                       FD_VOTE_STATE_V2_SZ );
    fd_borrowed_account_t * ba = mock_vote_ba_borrow( m );
    int rc = fd_vsv_deinitialize_vote_account_state( m->ctx, ba, VOTE_STATE_TARGET_VERSION_V3 );
    FD_TEST( rc == FD_EXECUTOR_INSTR_SUCCESS );
    fd_vote_state_versioned_t check[1];
    FD_TEST( fd_vsv_get_state( mock_vote_ba_meta(m), check ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( check->kind == fd_vote_state_versioned_enum_v1_14_11 );
    FD_TEST( fd_vsv_is_uninitialized( check ) );
  }

  /* Case 2: dlen=V2_SZ, lamports=rent_exempt(V3) → V3 uninitialized */
  {
    mock_vote_ba_t m[1];
    mock_vote_ba_init( m, &vote_pubkey, env->bank,
                       rent_exempt_minimum( FD_VOTE_STATE_V3_SZ ),
                       FD_VOTE_STATE_V2_SZ );
    fd_borrowed_account_t * ba = mock_vote_ba_borrow( m );
    int rc = fd_vsv_deinitialize_vote_account_state( m->ctx, ba, VOTE_STATE_TARGET_VERSION_V3 );
    FD_TEST( rc == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( mock_vote_ba_meta(m)->dlen == FD_VOTE_STATE_V3_SZ );
    fd_vote_state_versioned_t check[1];
    FD_TEST( fd_vsv_get_state( mock_vote_ba_meta(m), check ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( check->kind == fd_vote_state_versioned_enum_v3 );
    FD_TEST( fd_vsv_is_uninitialized( check ) );
  }

  /* Case 3: dlen=V3_SZ, lamports=rent_exempt(V3) → V3 uninitialized */
  {
    mock_vote_ba_t m[1];
    mock_vote_ba_init( m, &vote_pubkey, env->bank,
                       rent_exempt_minimum( FD_VOTE_STATE_V3_SZ ),
                       FD_VOTE_STATE_V3_SZ );
    fd_borrowed_account_t * ba = mock_vote_ba_borrow( m );
    int rc = fd_vsv_deinitialize_vote_account_state( m->ctx, ba, VOTE_STATE_TARGET_VERSION_V3 );
    FD_TEST( rc == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( mock_vote_ba_meta(m)->dlen == FD_VOTE_STATE_V3_SZ );
    fd_vote_state_versioned_t check[1];
    FD_TEST( fd_vsv_get_state( mock_vote_ba_meta(m), check ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( check->kind == fd_vote_state_versioned_enum_v3 );
    FD_TEST( fd_vsv_is_uninitialized( check ) );
  }

  test_env_cleanup( env );
  FD_LOG_NOTICE(( "test_deinitialize_vote_account_state_v3... ok" ));
}

static void
test_deinitialize_vote_account_state_v4( fd_wksp_t * wksp ) {
  /* https://github.com/anza-xyz/agave/.../handler.rs#L2063
     V4 deinit zeroes ALL account data (SIMD-0185).
     Regardless of account size, the data is all zero after deinit.    */

  test_env_t env[1];
  test_env_init( env, wksp, 0 );
  process_slot( env, 10UL );

  fd_pubkey_t vote_pubkey = {{ 0x13,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }};

  /* Test with each of V2, V4 sized accounts */
  static ulong dlens[] = { FD_VOTE_STATE_V2_SZ, FD_VOTE_STATE_V4_SZ };
  for( ulong di=0; di<2; di++ ) {
    ulong dlen = dlens[di];
    mock_vote_ba_t m[1];
    /* Lamports must be enough to resize to V4 if needed */
    mock_vote_ba_init( m, &vote_pubkey, env->bank,
                       rent_exempt_minimum( FD_VOTE_STATE_V4_SZ ),
                       dlen );
    /* Write some non-zero data */
    uchar * data = fd_account_data( mock_vote_ba_meta(m) );
    fd_memset( data, 0xAB, dlen );

    fd_borrowed_account_t * ba = mock_vote_ba_borrow( m );
    int rc = fd_vsv_deinitialize_vote_account_state( m->ctx, ba, VOTE_STATE_TARGET_VERSION_V4 );
    FD_TEST( rc == FD_EXECUTOR_INSTR_SUCCESS );

    /* ALL data bytes must be zero */
    ulong act_dlen = mock_vote_ba_meta(m)->dlen;
    uchar const * act_data = fd_account_data( mock_vote_ba_meta(m) );
    FD_TEST( fd_mem_iszero( act_data, act_dlen ) );

    /* Deserializes as Uninitialized */
    fd_vote_state_versioned_t check[1];
    FD_TEST( fd_vsv_get_state( mock_vote_ba_meta(m), check ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( fd_vsv_is_uninitialized( check ) );
  }

  test_env_cleanup( env );
  FD_LOG_NOTICE(( "test_deinitialize_vote_account_state_v4... ok" ));
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
  FD_TEST( wksp );

  test_account_initialize( wksp );
  test_account_initialize_simd_0387( wksp );

  /* TODO: un-comment when all 6 InitializeAccountV2 features are implemented */
  // test_account_initialize_v2( wksp );
  test_account_initialize_v2_invalid_proof( wksp );
  test_account_initialize_v2_no_simd_0387( wksp ); /* remove when SIMD-0387 is cleaned up */

  test_authorized_voters_footprint();
  test_vote_lockouts_footprint();
  test_landed_votes_footprint();
  test_epoch_credits_footprint();
  test_vote_instruction_footprints();

  test_v3_v4_size_equality();
  test_get_and_update_authorized_voter_v3();
  test_get_and_update_authorized_voter_v4();
  test_authorized_voter_is_locked_within_epoch();
  test_set_new_authorized_voter();
  test_get_and_update_authorized_voter_v4_with_bls();
  test_vote_state_epoch_credits();
  test_vote_state_epoch0_no_credits();
  test_vote_state_increment_credits();
  test_v4_commission_basis_points();
  test_set_inflation_rewards_commission_bps();
  test_v4_conversion_from_all_versions();
  test_init_vote_account_state_v3( wksp );
  test_init_vote_account_state_v4( wksp );
  test_deinitialize_vote_account_state_v3( wksp );
  test_deinitialize_vote_account_state_v4( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
