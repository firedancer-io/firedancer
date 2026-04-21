#define _GNU_SOURCE

/* Test for SIMD-0194: deprecate_rent_exemption_threshold

   This test simulates passing through several epoch boundaries,
   checking that the value of rent in the accounts db, the bank and
   the sysvar cache is updated correctly at the slot where
   deprecate_rent_exemption_threshold is activated. */

#include "fd_runtime.h"
#include "fd_runtime_stack.h"
#include "fd_bank.h"
#include "fd_system_ids.h"
#include "program/fd_vote_program.h"
#include "program/vote/fd_vote_codec.h"
#include "sysvar/fd_sysvar_rent.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_stake_history.h"
#include "sysvar/fd_sysvar_clock.h"
#include "sysvar/fd_sysvar_cache.h"
#include "../accdb/fd_accdb.h"
#include "../accdb/fd_accdb_shmem.h"
#include "../features/fd_features.h"
#include "../stakes/fd_stake_types.h"

#include <sys/mman.h>
#include <errno.h>

static fd_wksp_t *
fd_wksp_new_lazy( ulong footprint ) {
  footprint = fd_ulong_align_up( footprint, FD_SHMEM_NORMAL_PAGE_SZ );
  void * mem = mmap( NULL, footprint, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) FD_LOG_ERR(( "mmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  ulong part_max = fd_wksp_part_max_est( footprint, 64UL<<10 );
  FD_TEST( part_max );
  ulong data_max = fd_wksp_data_max_est( footprint, part_max );
  FD_TEST( data_max );
  fd_wksp_t * wksp = fd_wksp_join( fd_wksp_new( mem, "wksp", 1U, part_max, data_max ) );
  FD_TEST( wksp );
  FD_TEST( 0==fd_shmem_join_anonymous( "wksp", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, mem, FD_SHMEM_NORMAL_PAGE_SZ, footprint>>FD_SHMEM_NORMAL_LG_PAGE_SZ ) );
  return wksp;
}

static void
fd_wksp_delete_lazy( fd_wksp_t * wksp ) {
  void * mem       = (void *)wksp;
  ulong  footprint = fd_wksp_footprint( fd_wksp_part_max( wksp ), fd_wksp_data_max( wksp ) );
  fd_shmem_leave_anonymous( wksp, NULL );
  fd_wksp_delete( fd_wksp_leave( wksp ) );
  munmap( mem, footprint );
}

static void
drain_background( fd_accdb_t * accdb ) {
  int charge_busy = 0;
  fd_accdb_background( accdb, &charge_busy );
}

/* Values before deprecate_rent_exemption_threshold is activated */
#define TEST_DEFAULT_LAMPORTS_PER_UINT8_YEAR (3480UL)
#define TEST_DEFAULT_EXEMPTION_THRESHOLD     (2.0)

/* Before activation, bank and sysvar can have different burn_percent
   values */
#define TEST_DEFAULT_BANK_BURN_PERCENT       (50)
#define TEST_DEFAULT_SYSVAR_BURN_PERCENT     (100)

/* Values after deprecate_rent_exemption_threshold is activated */
#define TEST_NEW_LAMPORTS_PER_UINT8_YEAR (6960UL)
#define TEST_NEW_EXEMPTION_THRESHOLD     (1.0)

/* After activation, sysvar inherits burn_percent from bank */
#define TEST_NEW_BANK_BURN_PERCENT       TEST_DEFAULT_BANK_BURN_PERCENT
#define TEST_NEW_SYSVAR_BURN_PERCENT     TEST_NEW_BANK_BURN_PERCENT

#define TEST_SLOTS_PER_EPOCH         (3UL)
#define TEST_FEATURE_ACTIVATION_SLOT (TEST_SLOTS_PER_EPOCH * 2)

struct test_env {
  fd_wksp_t *          wksp;
  ulong                tag;
  fd_banks_t *         banks;
  fd_bank_t *          bank;
  fd_accdb_t *         accdb;
  void *               accdb_shmem;
  void *               accdb_ljoin;
  fd_accdb_fork_id_t   fork_id;
  fd_runtime_stack_t * runtime_stack;
};
typedef struct test_env test_env_t;

static void
init_rent_sysvar( test_env_t * env,
                  ulong        lamports_per_uint8_year,
                  double       exemption_threshold ) {
  fd_rent_t bank_rent = {
    .lamports_per_uint8_year = lamports_per_uint8_year,
    .exemption_threshold     = exemption_threshold,
    .burn_percent            = TEST_DEFAULT_BANK_BURN_PERCENT
  };
  env->bank->f.rent = bank_rent;

  fd_rent_t sysvar_rent = {
    .lamports_per_uint8_year = lamports_per_uint8_year,
    .exemption_threshold     = exemption_threshold,
    .burn_percent            = TEST_DEFAULT_SYSVAR_BURN_PERCENT
  };
  fd_sysvar_rent_write( env->bank, env->accdb, NULL, &sysvar_rent );
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
  fd_sysvar_epoch_schedule_write( env->bank, env->accdb, NULL, &epoch_schedule );
}

static void
init_stake_history_sysvar( test_env_t * env ) {
  fd_sysvar_stake_history_init( env->bank, env->accdb, NULL );

  /* Seed the stake history so that the warmup calculation treats the
     initial 1 SOL delegation as fully effective from the start. */
  fd_epoch_stake_history_entry_pair_t pair = {
    .epoch = 0UL,
    .entry = {
      .effective    = 1000000000UL,
      .activating   = 0UL,
      .deactivating = 0UL,
    }
  };
  fd_sysvar_stake_history_update( env->bank, env->accdb, NULL, &pair );
}

static void
init_clock_sysvar( test_env_t * env ) {
  fd_sysvar_clock_init( env->bank, env->accdb, NULL );
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

static void
add_vote_account( test_env_t *        env,
                  fd_pubkey_t const * vote_account,
                  fd_pubkey_t const * node_pubkey ) {
  uchar vote_state_data[ FD_VOTE_STATE_V3_SZ ] = {0};

  fd_vote_state_versioned_t versioned[1];
  fd_vote_state_versioned_new( versioned, fd_vote_state_versioned_enum_v3 );

  fd_vote_state_v3_t * vote_state   = &versioned->v3;
  vote_state->node_pubkey           = *node_pubkey;
  vote_state->authorized_withdrawer = *node_pubkey;
  vote_state->commission            = 100;
  vote_state->prior_voters.idx      = 31;
  vote_state->prior_voters.is_empty = 1;

  fd_vote_authorized_voter_t * voter = fd_vote_authorized_voters_pool_ele_acquire( vote_state->authorized_voters.pool );
  fd_memset( voter, 0, sizeof(fd_vote_authorized_voter_t) );
  voter->epoch  = 0UL;
  voter->pubkey = *node_pubkey;
  voter->prio   = node_pubkey->uc[0];
  fd_vote_authorized_voters_treap_ele_insert( vote_state->authorized_voters.treap, voter, vote_state->authorized_voters.pool );

  FD_TEST( !fd_vote_state_versioned_serialize( versioned, vote_state_data, sizeof(vote_state_data) ) );

  fd_accdb_entry_t entry = fd_accdb_write_one( env->accdb, env->fork_id, vote_account->key, 1, 1 );
  fd_memcpy( entry.data, vote_state_data, sizeof(vote_state_data) );
  entry.data_len   = sizeof(vote_state_data);
  entry.lamports   = 1000000000UL;
  entry.executable = 0;
  fd_memcpy( entry.owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) );
  entry.commit = 1;
  fd_accdb_unwrite_one( env->accdb, &entry );
}

static void
add_delegated_stake_account( test_env_t *        env,
                             fd_pubkey_t const * stake_account,
                             fd_pubkey_t const * vote_account ) {
  fd_accdb_entry_t entry = fd_accdb_write_one( env->accdb, env->fork_id, stake_account->key, 1, 1 );
  entry.lamports   = 2000000000UL;
  entry.executable = 0;
  fd_memcpy( entry.owner, fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) );
  entry.data_len   = FD_STAKE_STATE_SZ;
  FD_STORE( fd_stake_state_t, entry.data, ((fd_stake_state_t) {
    .stake_type = FD_STAKE_STATE_STAKE,
    .stake = {
      .meta = {
        .staker     = *stake_account,
        .withdrawer = *stake_account
      },
      .stake = {
        .delegation = {
          .voter_pubkey         = *vote_account,
          .stake                = 1000000000UL,
          .activation_epoch     = ULONG_MAX,
          .deactivation_epoch   = (ulong)-1,
          .warmup_cooldown_rate = 0.25
        }
      }
    }
  }) );
  entry.commit = 1;
  fd_accdb_unwrite_one( env->accdb, &entry );
}

static void
add_bank_stake_delegation_entry( test_env_t *        env,
                                 fd_pubkey_t const * stake_account,
                                 fd_pubkey_t const * vote_account ) {
  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_modify( env->bank );
  env->bank->stake_delegations_fork_id = fd_stake_delegations_new_fork( stake_delegations );

  fd_stake_delegations_fork_update( stake_delegations,
                                    env->bank->stake_delegations_fork_id,
                                    stake_account,
                                    vote_account,
                                    1000000000UL,
                                    ULONG_MAX,
                                    ULONG_MAX,
                                    0UL,
                                    FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
}

static test_env_t *
test_env_create( test_env_t * env,
                 fd_wksp_t *  wksp ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->wksp = wksp;
  env->tag  = 1UL;

  ulong const max_accounts                = 64UL;
  ulong const max_live_slots              = 8UL;
  ulong const max_account_writes_per_slot = 16UL;
  ulong const partition_cnt               = 1UL;
  ulong const partition_sz                = 16UL<<20;
  ulong const cache_fp                    = 16UL<<30;
  ulong const joiner_cnt                  = 1UL;
  ulong const seed                        = 17UL;
  ulong const max_total_banks             = 4UL;
  ulong const max_fork_width              = 4UL;

  ulong shmem_fp = fd_accdb_shmem_footprint( max_accounts, max_live_slots, max_account_writes_per_slot, partition_cnt, cache_fp, joiner_cnt );
  env->accdb_shmem = fd_wksp_alloc_laddr( wksp, fd_accdb_shmem_align(), shmem_fp, env->tag );
  FD_TEST( env->accdb_shmem );
  FD_TEST( fd_accdb_shmem_new( env->accdb_shmem, max_accounts, max_live_slots, max_account_writes_per_slot, partition_cnt, partition_sz, cache_fp, seed, joiner_cnt ) );
  fd_accdb_shmem_t * shmem = fd_accdb_shmem_join( env->accdb_shmem );
  FD_TEST( shmem );

  ulong accdb_fp = fd_accdb_footprint( max_live_slots );
  env->accdb_ljoin = fd_wksp_alloc_laddr( wksp, fd_accdb_align(), accdb_fp, env->tag );
  FD_TEST( env->accdb_ljoin );
  FD_TEST( fd_accdb_new( env->accdb_ljoin, shmem, 0 ) );
  env->accdb = fd_accdb_join( env->accdb_ljoin );
  FD_TEST( env->accdb );

  void * banks_mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( max_total_banks, max_fork_width, 2048UL, 2048UL ), env->tag );
  FD_TEST( banks_mem );

  env->banks = fd_banks_join( fd_banks_new( banks_mem, max_total_banks, max_fork_width, 2048UL, 2048UL, 0, 8888UL ) );
  FD_TEST( env->banks );

  env->bank = fd_banks_init_bank( env->banks );
  FD_TEST( env->bank );

  env->runtime_stack = fd_wksp_alloc_laddr( wksp, fd_runtime_stack_align(), fd_runtime_stack_footprint( 2048UL, 2048UL, 2048UL ), env->tag );
  FD_TEST( env->runtime_stack );
  FD_TEST( fd_runtime_stack_join( fd_runtime_stack_new( env->runtime_stack, 2048UL, 2048UL, 2048UL, 999UL ) ) );

  env->fork_id = fd_accdb_attach_child( env->accdb, (fd_accdb_fork_id_t){ .val = USHORT_MAX } );
  env->bank->accdb_fork_id = env->fork_id;

  init_rent_sysvar( env, TEST_DEFAULT_LAMPORTS_PER_UINT8_YEAR, TEST_DEFAULT_EXEMPTION_THRESHOLD );
  init_epoch_schedule_sysvar( env );
  init_stake_history_sysvar( env );
  init_clock_sysvar( env );
  init_blockhash_queue( env );

  env->bank->f.slot = 1UL;
  env->bank->f.epoch = 0UL;

  fd_bank_top_votes_t_2_modify( env->bank );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( env->bank );
  fd_vote_stakes_reset( vote_stakes );
  fd_pubkey_t pubkey = { .ul[0] = 1UL };
  add_vote_account( env, &pubkey, &pubkey );
  fd_vote_stakes_root_insert_key( vote_stakes, &pubkey, &pubkey, 1000000000UL, 0UL, 0UL );
  fd_vote_stakes_root_update_meta( vote_stakes, &pubkey, &pubkey, 1000000000UL, 1UL, 0UL );
  fd_pubkey_t stake_account = { .ul[0] = 2UL };
  add_delegated_stake_account( env, &stake_account, &pubkey );
  add_bank_stake_delegation_entry( env, &stake_account, &pubkey );

  /* Set up effective stake totals so the epoch boundary processing
     writes correct stake history entries for warmup calculation. */
  env->bank->f.total_effective_stake = 1000000000UL;
  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_modify( env->bank );
  stake_delegations->effective_stake = 1000000000UL;

  FD_LOG_NOTICE(("fork idx %u", env->bank->vote_stakes_fork_id));
  ulong cnt = fd_vote_stakes_ele_cnt( vote_stakes, env->bank->vote_stakes_fork_id );
  FD_LOG_NOTICE(("cnt %lu", cnt));

  fd_features_t features = {0};
  fd_features_disable_all( &features );
  features.deprecate_rent_exemption_threshold = TEST_FEATURE_ACTIVATION_SLOT;
  env->bank->f.features = features;

  return env;
}

static void
test_env_destroy( test_env_t * env ) {
  FD_TEST( env );

  fd_wksp_free_laddr( env->runtime_stack );
  fd_wksp_free_laddr( env->banks );

  fd_wksp_free_laddr( env->accdb_ljoin );
  fd_wksp_free_laddr( env->accdb_shmem );

  fd_wksp_usage_t usage[1];
  fd_wksp_usage( env->wksp, &env->tag, 1UL, usage );
  FD_TEST( usage->used_cnt == 0UL );
  FD_TEST( usage->used_sz  == 0UL );

  fd_memset( env, 0, sizeof(test_env_t) );
}

static void
verify_rent_values( test_env_t * env,
                    ulong        expected_lamports,
                    double       expected_threshold,
                    uchar        expected_bank_burn_percent,
                    uchar        expected_sysvar_burn_percent ) {
  /* Verify bank-level rent values */
  fd_rent_t const * bank_rent = &env->bank->f.rent;
  FD_TEST( bank_rent );
  FD_TEST( bank_rent->lamports_per_uint8_year == expected_lamports );
  FD_TEST( bank_rent->exemption_threshold     == expected_threshold );
  FD_TEST( bank_rent->burn_percent            == expected_bank_burn_percent );

  /* Verify sysvar cache rent values */
  fd_sysvar_cache_t const * sysvar_cache = &env->bank->f.sysvar_cache;
  fd_rent_t cache_rent[1];
  FD_TEST( fd_sysvar_cache_rent_read( sysvar_cache, cache_rent ) );
  FD_TEST( cache_rent->lamports_per_uint8_year == expected_lamports );
  FD_TEST( cache_rent->exemption_threshold     == expected_threshold );
  FD_TEST( cache_rent->burn_percent            == expected_sysvar_burn_percent );
}

/* Check if rent values changed from the given baseline. */
static int
rent_changed_from( test_env_t * env,
                   ulong        baseline_lamports,
                   double       baseline_threshold ) {
  fd_rent_t const * bank_rent = &env->bank->f.rent;
  return bank_rent->lamports_per_uint8_year != baseline_lamports ||
         bank_rent->exemption_threshold     != baseline_threshold;
}

static int
process_slot( test_env_t * env,
              ulong        slot ) {
  fd_bank_t * parent_bank = env->bank;
  ulong parent_bank_idx   = parent_bank->idx;

  FD_TEST( parent_bank->state==FD_BANK_STATE_FROZEN );

  /* Snapshot rent values before processing */
  ulong  prev_lamports  = env->bank->f.rent.lamports_per_uint8_year;
  double prev_threshold = env->bank->f.rent.exemption_threshold;

  ulong new_bank_idx = fd_banks_new_bank( env->banks, parent_bank_idx, 0L )->idx;
  fd_bank_t * new_bank = fd_banks_clone_from_parent( env->banks, new_bank_idx );
  FD_TEST( new_bank );

  new_bank->f.slot = slot;
  new_bank->f.parent_slot = parent_bank->f.slot;

  fd_accdb_fork_id_t new_fork_id = fd_accdb_attach_child( env->accdb, env->fork_id );
  new_bank->accdb_fork_id = new_fork_id;

  env->fork_id = new_fork_id;
  env->bank    = new_bank;

  int is_epoch_boundary = 0;
  fd_runtime_block_execute_prepare( env->banks, env->bank, env->accdb, env->runtime_stack, NULL, &is_epoch_boundary );

  int rent_modified = rent_changed_from( env, prev_lamports, prev_threshold );

  fd_banks_mark_bank_frozen( new_bank );

  fd_accdb_advance_root( env->accdb, new_fork_id );
  drain_background( env->accdb );
  fd_banks_advance_root( env->banks, new_bank_idx );

  return rent_modified;
}

/* Advance to target slot and return whether rent was modified in that
   slot. */
static int
advance_to_slot( test_env_t * env,
                 ulong        target_slot ) {
  ulong current_slot = env->bank->f.slot;
  int rent_modified = 0;
  for( ulong slot = current_slot + 1UL; slot <= target_slot; slot++ ) {
    rent_modified = process_slot( env, slot );
  }
  return rent_modified;
}

/* - Epoch 1: deprecate_rent_exemption_threshold not activated
   - Epoch 2: deprecate_rent_exemption_threshold activation epoch
   - Epoch 3: after deprecate_rent_exemption_threshold activation
     epoch */
static void
test_deprecate_rent_exemption_threshold( fd_wksp_t * wksp ) {
  test_env_t env[1];
  test_env_create( env, wksp );

  /* Advance to last slot of epoch 1. Rent should not change.
     Bank and sysvar have different burn_percent values. */
  int rent_modified = advance_to_slot( env, (2UL * TEST_SLOTS_PER_EPOCH) - 1UL );
  verify_rent_values( env,
                      TEST_DEFAULT_LAMPORTS_PER_UINT8_YEAR,
                      TEST_DEFAULT_EXEMPTION_THRESHOLD,
                      TEST_DEFAULT_BANK_BURN_PERCENT,
                      TEST_DEFAULT_SYSVAR_BURN_PERCENT );
  FD_TEST( !rent_modified );

  /* Advance to first slot of epoch 2. Rent should change.
     After activation, sysvar inherits burn_percent from bank. */
  rent_modified = advance_to_slot( env, 2UL * TEST_SLOTS_PER_EPOCH );
  verify_rent_values( env,
                      TEST_NEW_LAMPORTS_PER_UINT8_YEAR,
                      TEST_NEW_EXEMPTION_THRESHOLD,
                      TEST_NEW_BANK_BURN_PERCENT,
                      TEST_NEW_SYSVAR_BURN_PERCENT );
  FD_TEST( rent_modified );

  /* Advance to first slot of epoch 3. Rent should not change. */
  rent_modified = advance_to_slot( env, 3UL * TEST_SLOTS_PER_EPOCH );
  verify_rent_values( env,
                      TEST_NEW_LAMPORTS_PER_UINT8_YEAR,
                      TEST_NEW_EXEMPTION_THRESHOLD,
                      TEST_NEW_BANK_BURN_PERCENT,
                      TEST_NEW_SYSVAR_BURN_PERCENT );
  FD_TEST( !rent_modified );

  test_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong wksp_sz = 20UL<<30; /* 20 GiB virtual (demand-paged) */
  FD_LOG_NOTICE(( "Creating workspace (lazy paged, %lu GiB)", wksp_sz>>30 ));
  fd_wksp_t * wksp = fd_wksp_new_lazy( wksp_sz );
  FD_TEST( wksp );

  test_deprecate_rent_exemption_threshold( wksp );

  fd_wksp_delete_lazy( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
