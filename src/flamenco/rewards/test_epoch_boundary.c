/* Unit tests for epoch boundary with stake delegations and vote stakes.
   Exercises fd_stakes_activate_epoch and fd_begin_partitioned_rewards. */

#include "fd_rewards.h"
#include "fd_stake_rewards.h"
#include "../runtime/fd_runtime_stack.h"
#include "../runtime/fd_bank.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/program/fd_vote_program.h"
#include "../runtime/sysvar/fd_sysvar_rent.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../runtime/sysvar/fd_sysvar_clock.h"
#include "../runtime/sysvar/fd_sysvar_cache.h"
#include "../accdb/fd_accdb_admin_v1.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "../accdb/fd_accdb_sync.h"
#include "../features/fd_features.h"
#include "../stakes/fd_stake_types.h"
#include "../stakes/fd_stakes.h"

#define TEST_SLOTS_PER_EPOCH (32UL)

struct test_env {
  fd_wksp_t *          wksp;
  ulong                tag;
  fd_banks_t *         banks;
  fd_bank_t *          bank;
  void *               funk_mem;
  void *               funk_locks;
  fd_accdb_admin_t     accdb_admin[1];
  fd_accdb_user_t      accdb[1];
  fd_funk_txn_xid_t    xid;
  fd_runtime_stack_t * runtime_stack;
};
typedef struct test_env test_env_t;

static void
init_sysvars( test_env_t * env ) {
  fd_rent_t rent = {
    .lamports_per_uint8_year = 3480UL,
    .exemption_threshold     = 2.0,
    .burn_percent            = 50
  };
  env->bank->f.rent = rent;
  fd_sysvar_rent_write( env->bank, env->accdb, &env->xid, NULL, &rent );

  fd_epoch_schedule_t epoch_schedule = {
    .slots_per_epoch             = TEST_SLOTS_PER_EPOCH,
    .leader_schedule_slot_offset = TEST_SLOTS_PER_EPOCH,
    .warmup                      = 0,
    .first_normal_epoch          = 0UL,
    .first_normal_slot           = 0UL
  };
  env->bank->f.epoch_schedule = epoch_schedule;
  fd_sysvar_epoch_schedule_write( env->bank, env->accdb, &env->xid, NULL, &epoch_schedule );

  fd_sysvar_stake_history_init( env->bank, env->accdb, &env->xid, NULL );
  fd_sysvar_clock_init( env->bank, env->accdb, &env->xid, NULL );

  fd_blockhashes_t * bhq = fd_blockhashes_init( &env->bank->f.block_hash_queue, 12345UL );
  fd_hash_t dummy_hash = {0};
  fd_memset( dummy_hash.uc, 0xAB, FD_HASH_FOOTPRINT );
  fd_blockhash_info_t * info = fd_blockhashes_push_new( bhq, &dummy_hash );
  info->fee_calculator.lamports_per_signature = 0UL;
}

/* Create a vote account with epoch credits so that rewards points are
   nonzero.  commission=10 means 10% to voter, 90% to staker. */

static void
add_vote_account( test_env_t *        env,
                  fd_pubkey_t const * vote_account,
                  fd_pubkey_t const * node_pubkey,
                  uchar               commission,
                  ulong               credits,
                  ulong               prev_credits,
                  ushort              credits_epoch ) {
  uchar alloc_buf[ 16384 ] __attribute__((aligned(128)));
  void * alloc_mem = alloc_buf;

  fd_vote_state_versioned_t vsv[1];
  fd_vote_state_versioned_new_disc( vsv, fd_vote_state_versioned_enum_v3 );
  fd_vote_state_v3_t * vs = &vsv->inner.v3;
  vs->node_pubkey           = *node_pubkey;
  vs->authorized_withdrawer = *node_pubkey;
  vs->commission            = commission;

  vs->authorized_voters.pool  = fd_vote_authorized_voters_pool_join_new( &alloc_mem, 1UL );
  vs->authorized_voters.treap = fd_vote_authorized_voters_treap_join_new( &alloc_mem, 1UL );
  fd_vote_authorized_voter_t * voter = fd_vote_authorized_voters_pool_ele_acquire( vs->authorized_voters.pool );
  *voter = (fd_vote_authorized_voter_t){
    .epoch  = 0UL,
    .pubkey = *node_pubkey,
    .prio   = node_pubkey->ul[0]
  };
  fd_vote_authorized_voters_treap_ele_insert( vs->authorized_voters.treap, voter, vs->authorized_voters.pool );

  vs->epoch_credits = deq_fd_vote_epoch_credits_t_join_new( &alloc_mem, 64 );
  fd_vote_epoch_credits_t ec = {
    .epoch        = credits_epoch,
    .credits      = credits,
    .prev_credits = prev_credits,
  };
  deq_fd_vote_epoch_credits_t_push_tail( vs->epoch_credits, ec );

  uchar vote_state_data[ FD_VOTE_STATE_V3_SZ ] = {0};
  fd_bincode_encode_ctx_t encode = {
    .data    = vote_state_data,
    .dataend = vote_state_data + sizeof(vote_state_data)
  };
  FD_TEST( fd_vote_state_versioned_encode( vsv, &encode )==FD_BINCODE_SUCCESS );

  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( env->accdb, rw, &env->xid, vote_account, sizeof(vote_state_data), FD_ACCDB_FLAG_CREATE ) );
  fd_accdb_ref_data_set( env->accdb, rw, vote_state_data, sizeof(vote_state_data) );
  fd_accdb_ref_lamports_set( rw, 1000000000UL );
  fd_accdb_ref_exec_bit_set( rw, 0 );
  fd_memcpy( rw->meta->owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) );
  fd_accdb_close_rw( env->accdb, rw );
}

static void
add_delegated_stake_account( test_env_t *        env,
                             fd_pubkey_t const * stake_account,
                             fd_pubkey_t const * vote_account,
                             ulong               stake_lamports,
                             ulong               credits_observed ) {
  fd_accdb_rw_t rw[1];
  FD_TEST( fd_accdb_open_rw( env->accdb, rw, &env->xid, stake_account, FD_STAKE_STATE_SZ, FD_ACCDB_FLAG_CREATE ) );
  fd_accdb_ref_lamports_set( rw, stake_lamports + 1000000000UL );
  fd_accdb_ref_exec_bit_set( rw, 0 );
  fd_memcpy( rw->meta->owner, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) );
  fd_accdb_ref_data_sz_set( env->accdb, rw, FD_STAKE_STATE_SZ, 0 );
  FD_STORE( fd_stake_state_t, fd_accdb_ref_data( rw ), ((fd_stake_state_t) {
    .stake_type = FD_STAKE_STATE_STAKE,
    .stake = {
      .meta = {
        .staker     = *stake_account,
        .withdrawer = *stake_account
      },
      .stake = {
        .delegation = {
          .voter_pubkey         = *vote_account,
          .stake                = stake_lamports,
          .activation_epoch     = 0UL,
          .deactivation_epoch   = (ulong)-1,
          .warmup_cooldown_rate = 0.25
        },
        .credits_observed = credits_observed
      }
    }
  }) );
  fd_accdb_close_rw( env->accdb, rw );
}

static test_env_t *
test_env_create( test_env_t * env,
                 fd_wksp_t *  wksp ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->wksp = wksp;
  env->tag  = 1UL;

  ulong const funk_seed       = 17UL;
  ulong const txn_max         = 2UL;
  ulong const rec_max         = 64UL;
  ulong const max_total_banks = 4UL;
  ulong const max_fork_width  = 4UL;

  env->funk_mem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_shmem_footprint( txn_max, rec_max ), env->tag );
  FD_TEST( env->funk_mem );
  env->funk_locks = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_locks_footprint( txn_max, rec_max ), env->tag );
  FD_TEST( env->funk_locks );
  FD_TEST( fd_funk_shmem_new( env->funk_mem, env->tag, funk_seed, txn_max, rec_max ) );
  FD_TEST( fd_funk_locks_new( env->funk_locks, txn_max, rec_max ) );

  FD_TEST( fd_accdb_admin_v1_init( env->accdb_admin, env->funk_mem, env->funk_locks ) );
  FD_TEST( fd_accdb_user_v1_init( env->accdb, env->funk_mem, env->funk_locks, txn_max ) );

  ulong const max_stake = 16UL;
  ulong const max_vote  = 16UL;

  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( max_total_banks, max_fork_width, max_stake, max_vote ), env->tag );
  FD_TEST( banks_mem );
  env->banks = fd_banks_join( fd_banks_new( banks_mem, max_total_banks, max_fork_width, max_stake, max_vote, 0, 8888UL ) );
  FD_TEST( env->banks );

  env->bank = fd_banks_init_bank( env->banks );
  FD_TEST( env->bank );

  env->runtime_stack = fd_wksp_alloc_laddr( wksp, fd_runtime_stack_align(), fd_runtime_stack_footprint( max_vote, max_vote, max_stake ), env->tag );
  FD_TEST( env->runtime_stack );
  FD_TEST( fd_runtime_stack_join( fd_runtime_stack_new( env->runtime_stack, max_vote, max_vote, max_stake, 999UL ) ) );

  fd_funk_txn_xid_t root[1];
  fd_funk_txn_xid_set_root( root );
  env->xid = (fd_funk_txn_xid_t){ .ul = { 1UL, env->bank->idx } };
  fd_accdb_attach_child( env->accdb_admin, root, &env->xid );

  init_sysvars( env );

  fd_features_t features = {0};
  fd_features_disable_all( &features );
  features.devnet_and_testnet = 0UL;
  features.pico_inflation     = 0UL;
  env->bank->f.features = features;

  env->bank->f.inflation = (fd_inflation_t){
    .initial         = 0.08,
    .terminal        = 0.015,
    .taper           = 0.15,
    .foundation      = 0.05,
    .foundation_term = 7.0,
    .unused          = 0.0
  };
  env->bank->f.slots_per_year = 78892314.0;
  env->bank->f.capitalization = 500000000UL * 1000000000UL;

  env->bank->f.warmup_cooldown_rate_epoch = ULONG_MAX;

  fd_accdb_advance_root( env->accdb_admin, &env->xid );
  return env;
}

static void
test_env_destroy( test_env_t * env ) {
  FD_TEST( env );
  fd_wksp_free_laddr( env->runtime_stack );
  fd_wksp_free_laddr( env->banks );
  fd_accdb_admin_fini( env->accdb_admin );
  fd_accdb_user_fini( env->accdb );
  fd_wksp_free_laddr( fd_funk_delete( env->funk_mem ) );
  fd_wksp_free_laddr( env->funk_locks );

  fd_wksp_usage_t usage[1];
  fd_wksp_usage( env->wksp, &env->tag, 1UL, usage );
  FD_TEST( usage->used_cnt == 0UL );
  FD_TEST( usage->used_sz  == 0UL );

  fd_memset( env, 0, sizeof(test_env_t) );
}

/* Tier 1: after fd_stakes_activate_epoch, verify delegation count,
   total_epoch_stake, and vote_stakes fork contents. */

static void
test_stakes_activate_epoch( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_stakes_activate_epoch" ));
  test_env_t env[1];
  test_env_create( env, wksp );

  fd_pubkey_t vote_pubkey  = { .ul[0] = 0x10 };
  fd_pubkey_t stake_pubkey = { .ul[0] = 0x20 };

  ulong stake_amount = 1000000000UL;

  add_vote_account( env, &vote_pubkey, &vote_pubkey, 100, 100UL, 0UL, 0 );
  add_delegated_stake_account( env, &stake_pubkey, &vote_pubkey, stake_amount, 0UL );

  fd_stake_delegations_t * sd = fd_bank_stake_delegations_modify( env->bank );
  env->bank->stake_delegations_fork_id = fd_stake_delegations_new_fork( sd );
  fd_stake_delegations_fork_update( sd,
                                    env->bank->stake_delegations_fork_id,
                                    &stake_pubkey,
                                    &vote_pubkey,
                                    stake_amount,
                                    0UL, ULONG_MAX, 0UL, 0.25 );

  fd_bank_top_votes_t_2_modify( env->bank );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( env->bank );
  fd_vote_stakes_reset( vote_stakes );
  fd_vote_stakes_root_insert_key( vote_stakes, &vote_pubkey, &vote_pubkey, stake_amount, 0UL, 0UL );
  fd_vote_stakes_root_update_meta( vote_stakes, &vote_pubkey, &vote_pubkey, stake_amount, 1UL, 0UL );

  /* pre-boundary epoch: epoch 1, slot is at the start of epoch 1 */
  ulong pre_epoch = 1UL;
  env->bank->f.slot  = TEST_SLOTS_PER_EPOCH;
  env->bank->f.epoch = pre_epoch;

  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_frontier_query( env->banks, env->bank );
  FD_TEST( stake_delegations );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 1UL );

  fd_stake_history_t stake_history[1];
  FD_TEST( fd_sysvar_stake_history_read( env->accdb, &env->xid, stake_history ) );
  fd_stake_delegations_refresh( stake_delegations,
                                pre_epoch,
                                stake_history,
                                &env->bank->f.warmup_cooldown_rate_epoch,
                                env->accdb,
                                &env->xid );
  FD_TEST( stake_delegations->effective_stake == stake_amount );

  fd_stakes_activate_epoch( env->bank,
                            env->runtime_stack,
                            env->accdb,
                            &env->xid,
                            NULL,
                            stake_delegations,
                            &env->bank->f.warmup_cooldown_rate_epoch );

  FD_TEST( env->bank->f.epoch == pre_epoch + 1UL );
  FD_TEST( env->bank->f.total_epoch_stake == stake_amount );

  ulong vs_cnt = fd_vote_stakes_ele_cnt( vote_stakes, env->bank->vote_stakes_fork_id );
  FD_TEST( vs_cnt >= 1UL );

  fd_bank_stake_delegations_end_frontier_query( env->banks, env->bank );

  FD_LOG_NOTICE(( "test_stakes_activate_epoch: pass" ));
  test_env_destroy( env );
}

/* Tier 2: after fd_begin_partitioned_rewards, verify that the vote
   account received commission rewards and that stake partitions were
   initialized. */

static void
test_begin_partitioned_rewards( fd_wksp_t * wksp ) {
  FD_LOG_NOTICE(( "test_begin_partitioned_rewards" ));
  test_env_t env[1];
  test_env_create( env, wksp );

  fd_pubkey_t vote_pubkey  = { .ul[0] = 0x10 };
  fd_pubkey_t stake_pubkey = { .ul[0] = 0x20 };

  ulong stake_amount      = 1000000000UL;
  ulong credits_observed  = 0UL;
  ulong vote_credits      = 1000UL;
  uchar commission        = 10;

  add_vote_account( env, &vote_pubkey, &vote_pubkey,
                    commission,
                    vote_credits,     /* credits      */
                    0UL,              /* prev_credits */
                    (ushort)1 );      /* epoch 1 = rewarded epoch */
  add_delegated_stake_account( env, &stake_pubkey, &vote_pubkey,
                               stake_amount, credits_observed );

  fd_stake_delegations_t * sd = fd_bank_stake_delegations_modify( env->bank );
  env->bank->stake_delegations_fork_id = fd_stake_delegations_new_fork( sd );
  fd_stake_delegations_fork_update( sd,
                                    env->bank->stake_delegations_fork_id,
                                    &stake_pubkey,
                                    &vote_pubkey,
                                    stake_amount,
                                    0UL, ULONG_MAX,
                                    credits_observed, 0.25 );

  fd_bank_top_votes_t_2_modify( env->bank );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( env->bank );
  fd_vote_stakes_reset( vote_stakes );
  fd_vote_stakes_root_insert_key( vote_stakes, &vote_pubkey, &vote_pubkey, stake_amount, 0UL, 0UL );
  fd_vote_stakes_root_update_meta( vote_stakes, &vote_pubkey, &vote_pubkey, stake_amount, 1UL, 0UL );

  ulong pre_epoch = 1UL;
  env->bank->f.slot         = TEST_SLOTS_PER_EPOCH;
  env->bank->f.epoch        = pre_epoch;
  env->bank->f.block_height = TEST_SLOTS_PER_EPOCH;

  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_frontier_query( env->banks, env->bank );
  FD_TEST( stake_delegations );

  fd_stake_history_t stake_history[1];
  FD_TEST( fd_sysvar_stake_history_read( env->accdb, &env->xid, stake_history ) );
  fd_stake_delegations_refresh( stake_delegations,
                                pre_epoch,
                                stake_history,
                                &env->bank->f.warmup_cooldown_rate_epoch,
                                env->accdb,
                                &env->xid );

  fd_stakes_activate_epoch( env->bank,
                            env->runtime_stack,
                            env->accdb,
                            &env->xid,
                            NULL,
                            stake_delegations,
                            &env->bank->f.warmup_cooldown_rate_epoch );

  FD_TEST( env->bank->f.epoch == pre_epoch + 1UL );

  ulong vote_lamports_before = 0UL;
  {
    fd_accdb_ro_t ro[1];
    FD_TEST( fd_accdb_open_ro( env->accdb, ro, &env->xid, &vote_pubkey ) );
    vote_lamports_before = fd_accdb_ref_lamports( ro );
    fd_accdb_close_ro( env->accdb, ro );
  }

  fd_hash_t const * parent_blockhash = fd_blockhashes_peek_last_hash( &env->bank->f.block_hash_queue );
  FD_TEST( parent_blockhash );

  fd_begin_partitioned_rewards( env->bank,
                                env->accdb,
                                &env->xid,
                                env->runtime_stack,
                                NULL,
                                stake_delegations,
                                parent_blockhash,
                                pre_epoch );

  /* Vote account should have received commission rewards. */
  ulong vote_lamports_after = 0UL;
  {
    fd_accdb_ro_t ro[1];
    FD_TEST( fd_accdb_open_ro( env->accdb, ro, &env->xid, &vote_pubkey ) );
    vote_lamports_after = fd_accdb_ref_lamports( ro );
    fd_accdb_close_ro( env->accdb, ro );
  }

  FD_LOG_NOTICE(( "vote lamports before=%lu after=%lu", vote_lamports_before, vote_lamports_after ));
  FD_TEST( vote_lamports_after > vote_lamports_before );

  /* Stake rewards partitions should have been initialized. */
  fd_stake_rewards_t const * stake_rewards = fd_bank_stake_rewards_query( env->bank );
  FD_TEST( stake_rewards );
  FD_TEST( env->bank->stake_rewards_fork_id != UCHAR_MAX );

  uint num_partitions = fd_stake_rewards_num_partitions( stake_rewards, env->bank->stake_rewards_fork_id );
  FD_TEST( num_partitions >= 1U );

  fd_bank_stake_delegations_end_frontier_query( env->banks, env->bank );

  FD_LOG_NOTICE(( "test_begin_partitioned_rewards: pass" ));
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

  test_stakes_activate_epoch( wksp );
  test_begin_partitioned_rewards( wksp );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
