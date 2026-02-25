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

#include <stdlib.h> // ARM64: malloc(3), free(3)

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
  void *               funk_locks;
  fd_accdb_admin_t     accdb_admin[1];
  fd_accdb_user_t      accdb[1];
  void *               pcache_mem;
  void *               pcache_locks;
  fd_progcache_admin_t progcache_admin[1];
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

  env->funk_mem   = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_shmem_footprint( txn_max, rec_max ), env->tag );
  env->funk_locks = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_locks_footprint( txn_max, rec_max ), env->tag );
  FD_TEST( env->funk_mem );
  FD_TEST( env->funk_locks );
  FD_TEST( fd_funk_shmem_new( env->funk_mem, env->tag, funk_seed, txn_max, rec_max ) );
  FD_TEST( fd_funk_locks_new( env->funk_locks, txn_max, rec_max ) );
  FD_TEST( fd_accdb_admin_v1_init( env->accdb_admin, env->funk_mem, env->funk_locks ) );
  FD_TEST( fd_accdb_user_v1_init( env->accdb, env->funk_mem, env->funk_locks, txn_max ) );

  env->pcache_mem   = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_shmem_footprint( txn_max, rec_max ), env->tag );
  env->pcache_locks = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_locks_footprint( txn_max, rec_max ), env->tag );
  FD_TEST( env->pcache_mem );
  FD_TEST( env->pcache_locks );
  FD_TEST( fd_funk_shmem_new( env->pcache_mem, env->tag, funk_seed+1, txn_max, rec_max ) );
  FD_TEST( fd_funk_locks_new( env->pcache_locks, txn_max, rec_max ) );
  env->progcache_scratch = fd_wksp_alloc_laddr( wksp, FD_PROGCACHE_SCRATCH_ALIGN, FD_PROGCACHE_SCRATCH_FOOTPRINT, env->tag );
  FD_TEST( env->progcache_scratch );
  FD_TEST( fd_progcache_join( env->progcache, env->pcache_mem, env->pcache_locks, env->progcache_scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) );
  FD_TEST( fd_progcache_admin_join( env->progcache_admin, env->pcache_mem, env->pcache_locks ) );

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

  fd_progcache_leave( env->progcache, NULL, NULL );
  void * pcache_funk = NULL;
  fd_progcache_admin_leave( env->progcache_admin, &pcache_funk, NULL );
  fd_wksp_free_laddr( env->pcache_locks );
  fd_wksp_free_laddr( fd_funk_delete( pcache_funk ) );
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
  fd_features_enable_cleaned_up( fd_bank_features_modify( env->bank ) );

  /* decode and parse txn */
  ulong txn_sz = strlen(hex) / 2;
  env->txn_p->payload_sz = txn_sz;
  fd_hex_decode( env->txn_p->payload, hex, txn_sz );
  FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );

  /* add the blockhash */
  fd_hash_t blockhash[1];
  fd_hex_decode( blockhash, "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17", 32 );
  fd_blockhashes_push_new( fd_bank_block_hash_queue_modify( env->bank ), blockhash );

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
  fd_features_enable_cleaned_up( fd_bank_features_modify( env->bank ) );

  /* decode and parse txn */
  ulong txn_sz = strlen(hex) / 2;
  env->txn_p->payload_sz = txn_sz;
  fd_hex_decode( env->txn_p->payload, hex, txn_sz );
  FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );

  /* add the blockhash */
  fd_hash_t blockhash[1];
  fd_hex_decode( blockhash, "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17", 32 );
  fd_blockhashes_push_new( fd_bank_block_hash_queue_modify( env->bank ), blockhash );

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
  FD_FEATURE_SET_ACTIVE( fd_bank_features_modify( env->bank ), vote_state_v4, 0UL );
  FD_FEATURE_SET_ACTIVE( fd_bank_features_modify( env->bank ), bls_pubkey_management_in_vote_account, 0UL );

  /* Run the vote program - should fail */
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( !txn_succeeded( env ) );

  test_env_cleanup( env );
  FD_LOG_NOTICE(( "test_account_initialize_simd_0387... ok" ));
}

static void
test_account_initialize_v2( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_init( env, wksp, 0 );

  setup_account_initialize_v2_txn( env );

  /* Enable SIMD-0387 feature */
  FD_FEATURE_SET_ACTIVE( fd_bank_features_modify( env->bank ), vote_state_v4, 0UL );
  FD_FEATURE_SET_ACTIVE( fd_bank_features_modify( env->bank ), bls_pubkey_management_in_vote_account, 0UL );

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

static void
test_account_initialize_v2_invalid_proof( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_init( env, wksp, 0 );

  setup_account_initialize_v2_txn( env );

  /* Invalidate proof */
  ulong proof_off = env->txn_p->payload_sz - 32-2 - 32-2 - 32 - 96;
  env->txn_p->payload[ proof_off ] = 0xFF;

  /* Enable SIMD-0387 feature */
  FD_FEATURE_SET_ACTIVE( fd_bank_features_modify( env->bank ), vote_state_v4, 0UL );
  FD_FEATURE_SET_ACTIVE( fd_bank_features_modify( env->bank ), bls_pubkey_management_in_vote_account, 0UL );

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
  FD_LOG_NOTICE(( "test_account_initialize_simd_0387... ok" ));
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
  test_account_initialize_simd_0387( wksp );

  test_account_initialize_v2( wksp );
  test_account_initialize_v2_invalid_proof( wksp );
  test_account_initialize_v2_no_simd_0387( wksp ); /* remove when SIMD-0387 is cleaned up */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
