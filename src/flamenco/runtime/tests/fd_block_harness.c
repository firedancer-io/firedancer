#include "fd_solfuzz_private.h"
#include "../fd_cost_tracker.h"
#include "fd_txn_harness.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"
#include "../fd_txn_account.h"
#include "../fd_runtime_stack.h"
#include "../program/fd_stake_program.h"
#include "../program/fd_vote_program.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_recent_hashes.h"
#include "../../accdb/fd_accdb_impl_v1.h"
#include "../../log_collector/fd_log_collector.h"
#include "../../rewards/fd_rewards.h"
#include "../../stakes/fd_stakes.h"
#include "../../types/fd_types.h"
#include "../../../disco/pack/fd_pack.h"
#include "generated/block.pb.h"

/* Templatized leader schedule sort helper functions */
typedef struct {
  fd_pubkey_t pk;
  ulong       sched_pos; /* track original position in sched[] */
} pk_with_pos_t;

#define SORT_NAME        sort_pkpos
#define SORT_KEY_T       pk_with_pos_t
#define SORT_BEFORE(a,b) (memcmp(&(a).pk, &(b).pk, sizeof(fd_pubkey_t))<0)
#include "../../../util/tmpl/fd_sort.c"  /* generates templatized sort_pkpos_*() APIs */

/* Fixed leader schedule hash seed (consistent with solfuzz-agave) */
#define LEADER_SCHEDULE_HASH_SEED 0xDEADFACEUL

/* Stripped down version of fd_refresh_vote_accounts that simply
   refreshes the stake delegation amount for each of the vote accounts
   using the stake delegations cache. */
static void
fd_solfuzz_block_refresh_vote_accounts( fd_vote_states_t *       vote_states,
                                        fd_vote_states_t *       vote_states_prev,
                                        fd_vote_states_t *       vote_states_prev_prev,
                                        fd_stake_delegations_t * stake_delegations,
                                        ulong                    epoch ) {
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t * node = fd_stake_delegations_iter_ele( iter );

    fd_pubkey_t * voter_pubkey = &node->vote_account;
    ulong         stake        = node->stake;

    /* Find the voter in the vote accounts cache and update their
       delegation amount */
    fd_vote_state_ele_t * vote_state = fd_vote_states_query( vote_states, voter_pubkey );
    if( !vote_state ) continue;

    vote_state->stake     += stake;
    vote_state->stake_t_1 += stake;
    vote_state->stake_t_2 += stake;
  }

  /* We need to set the stake_t_2 for the vote accounts in the vote
     states cache.  An important edge case to handle is if the current
     epoch is less than 2, that means we should use the current stakes
     because the stake_t_2 field is not yet populated. */
  fd_vote_states_iter_t vs_iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( vs_iter_, vote_states_prev_prev );
       !fd_vote_states_iter_done( iter );
       fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t * vote_state = fd_vote_states_iter_ele( iter );
    fd_vote_state_ele_t * vote_state_prev_prev = fd_vote_states_query( vote_states_prev_prev, &vote_state->vote_account );
    ulong t_2_stake = !!vote_state_prev_prev ? vote_state_prev_prev->stake : 0UL;
    vote_state->stake_t_2 = epoch>=2UL ? t_2_stake : vote_state->stake;
    vote_state->stake_t_2 = vote_state->stake;
  }

  /* Set stake_t_1 for the vote accounts in the vote states cache. */
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( vs_iter_, vote_states_prev );
       !fd_vote_states_iter_done( iter );
       fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t * vote_state = fd_vote_states_iter_ele( iter );
    fd_vote_state_ele_t * vote_state_prev = fd_vote_states_query( vote_states_prev, &vote_state->vote_account );
    ulong t_1_stake = !!vote_state_prev ? vote_state_prev->stake : 0UL;
    vote_state->stake_t_1 = epoch>=1UL ? t_1_stake : vote_state->stake;
    vote_state->stake_t_1 = vote_state->stake;
  }
}

/* Registers a single vote account into the current votes cache.  The
   entry is derived from the current present account state.  This
   function also registers a vote timestamp for the vote account. */
static void
fd_solfuzz_block_register_vote_account( fd_funk_t  *              funk,
                                        fd_funk_txn_xid_t const * xid,
                                        fd_vote_states_t *        vote_states,
                                        fd_pubkey_t *             pubkey ) {
  fd_txn_account_t acc[1];
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( acc, pubkey, funk, xid ) ) ) {
    return;
  }

  /* Account must be owned by the vote program */
  if( memcmp( fd_txn_account_get_owner( acc ), fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return;
  }

  /* Account must have > 0 lamports */
  if( fd_txn_account_get_lamports( acc )==0UL ) {
    return;
  }

  /* Account must be initialized correctly */
  if( FD_UNLIKELY( !fd_vote_state_versions_is_correct_and_initialized( acc->meta ) ) ) {
    return;
  }

  fd_vote_states_update_from_account(
      vote_states,
      acc->pubkey,
      fd_txn_account_get_data( acc ),
      fd_txn_account_get_data_len( acc ) );
}

/* Stores an entry in the stake delegations cache for the given vote
   account.  Deserializes and uses the present account state to derive
   delegation information. */
static void
fd_solfuzz_block_register_stake_delegation( fd_funk_t *               funk,
                                            fd_funk_txn_xid_t const * xid,
                                            fd_stake_delegations_t *  stake_delegations,
                                            fd_pubkey_t *             pubkey ) {
 fd_txn_account_t acc[1];
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( acc, pubkey, funk, xid ) ) ) {
    return;
  }

  /* Account must be owned by the stake program */
  if( memcmp( fd_txn_account_get_owner( acc ), fd_solana_stake_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return;
  }

  /* Account must have > 0 lamports */
  if( fd_txn_account_get_lamports( acc )==0UL ) {
    return;
  }

  /* Stake state must exist and be initialized correctly */
  fd_stake_state_v2_t stake_state;
  if( FD_UNLIKELY( fd_stake_get_state( acc->meta, &stake_state ) || !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
    return;
  }

  /* Skip 0-stake accounts */
  if( FD_UNLIKELY( stake_state.inner.stake.stake.delegation.stake==0UL ) ) {
    return;
  }

  /* Nothing to do if the account already exists in the cache */
  fd_stake_delegations_update(
      stake_delegations,
      pubkey,
      &stake_state.inner.stake.stake.delegation.voter_pubkey,
      stake_state.inner.stake.stake.delegation.stake,
      stake_state.inner.stake.stake.delegation.activation_epoch,
      stake_state.inner.stake.stake.delegation.deactivation_epoch,
      stake_state.inner.stake.stake.credits_observed,
      stake_state.inner.stake.stake.delegation.warmup_cooldown_rate );
}

/* Common helper method for populating a previous epoch's vote cache. */
static void
fd_solfuzz_pb_block_update_prev_epoch_votes_cache( fd_vote_states_t *            vote_states,
                                                   fd_exec_test_vote_account_t * vote_accounts,
                                                   pb_size_t                     vote_accounts_cnt,
                                                   fd_runtime_stack_t *          runtime_stack,
                                                   fd_spad_t *                   spad,
                                                   uchar                         is_t_1 ) {
  FD_SPAD_FRAME_BEGIN( spad ) {
    for( uint i=0U; i<vote_accounts_cnt; i++ ) {
      fd_exec_test_acct_state_t * vote_account  = &vote_accounts[i].vote_account;
      ulong                       stake         = vote_accounts[i].stake;
      uchar *                     vote_data     = vote_account->data->bytes;
      ulong                       vote_data_len = vote_account->data->size;
      fd_pubkey_t                 vote_address  = {0};
      fd_memcpy( &vote_address, vote_account->address, sizeof(fd_pubkey_t) );

      /* Try decoding the vote state from the account data. If it isn't
         decodable, don't try inserting it into the cache. */
      fd_vote_state_versioned_t * res = fd_bincode_decode_spad(
          vote_state_versioned, spad,
          vote_data,
          vote_data_len,
          NULL );
      if( res==NULL ) continue;
      if( res->discriminant==fd_vote_state_versioned_enum_v0_23_5 ) continue;

      fd_vote_states_update_from_account( vote_states, &vote_address, vote_data, vote_data_len );
      fd_vote_state_ele_t * vote_state = fd_vote_states_query( vote_states, &vote_address );
      vote_state->stake     += stake;
      vote_state->stake_t_1 += stake;
      vote_state->stake_t_2 += stake;

      if( !is_t_1 ) continue;

      /* Update vote credits for T-1 */
      fd_vote_epoch_credits_t * epoch_credits = NULL;
      switch( res->discriminant ) {
        case fd_vote_state_versioned_enum_v0_23_5:
          epoch_credits = res->inner.v0_23_5.epoch_credits;
          break;
        case fd_vote_state_versioned_enum_v1_14_11:
          epoch_credits = res->inner.v1_14_11.epoch_credits;
          break;
        case fd_vote_state_versioned_enum_current:
          epoch_credits = res->inner.current.epoch_credits;
          break;
        default:
          __builtin_unreachable();
      }

      fd_vote_state_credits_t * vote_credits = &runtime_stack->stakes.vote_credits[ vote_state->idx ];
      vote_credits->credits_cnt = 0UL;
      for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( epoch_credits );
           !deq_fd_vote_epoch_credits_t_iter_done( epoch_credits, iter );
           iter = deq_fd_vote_epoch_credits_t_iter_next( epoch_credits, iter ) ) {
        fd_vote_epoch_credits_t const * credit_ele = deq_fd_vote_epoch_credits_t_iter_ele_const( epoch_credits, iter );
        vote_credits->epoch[ vote_credits->credits_cnt ]        = (ushort)credit_ele->epoch;
        vote_credits->credits[ vote_credits->credits_cnt ]      = credit_ele->credits;
        vote_credits->prev_credits[ vote_credits->credits_cnt ] = credit_ele->prev_credits;
        vote_credits->credits_cnt++;
      }
    }
  } FD_SPAD_FRAME_END;
}

static void
fd_solfuzz_pb_block_ctx_destroy( fd_solfuzz_runner_t * runner ) {
  fd_accdb_clear( runner->accdb_admin );
  fd_progcache_clear( runner->progcache_admin );

  /* In order to check for leaks in the workspace, we need to compact the
     allocators. Without doing this, empty superblocks may be retained
     by the fd_alloc instance, which mean we cannot check for leaks. */
  fd_alloc_compact( runner->accdb_admin->funk->alloc );
  fd_alloc_compact( runner->progcache_admin->funk->alloc );
}

/* Sets up block execution context from an input test case to execute
   against the runtime.  Returns block_info on success and NULL on
   failure. */
static fd_txn_p_t *
fd_solfuzz_pb_block_ctx_create( fd_solfuzz_runner_t *                runner,
                                fd_exec_test_block_context_t const * test_ctx,
                                ulong *                              out_txn_cnt,
                                fd_hash_t *                          poh ) {
  fd_accdb_user_t * accdb = runner->accdb;
  fd_funk_t *       funk  = fd_accdb_user_v1_funk( runner->accdb );
  fd_bank_t *       bank  = runner->bank;
  fd_banks_t *      banks = runner->banks;

  fd_runtime_stack_t * runtime_stack = runner->runtime_stack;

  fd_banks_clear_bank( banks, bank );

  /* Generate unique ID for funk txn */
  fd_funk_txn_xid_t xid[1] = {{ .ul={ LONG_MAX,LONG_MAX } }};

  /* Create temporary funk transaction and slot / epoch contexts */
  fd_funk_txn_xid_t parent_xid; fd_funk_txn_xid_set_root( &parent_xid );
  fd_accdb_attach_child( runner->accdb_admin, &parent_xid, xid );
  fd_progcache_txn_attach_child( runner->progcache_admin, &parent_xid, xid );

  /* Restore feature flags */
  fd_features_t features = {0};
  if( !fd_solfuzz_pb_restore_features( &features, &test_ctx->epoch_ctx.features ) ) {
    return NULL;
  }
  fd_bank_features_set( bank, features );

  /* Set up slot context */
  ulong slot        = test_ctx->slot_ctx.slot;
  ulong parent_slot = test_ctx->slot_ctx.prev_slot;

  fd_hash_t * bank_hash = fd_bank_bank_hash_modify( bank );
  fd_memcpy( bank_hash, test_ctx->slot_ctx.parent_bank_hash, sizeof(fd_hash_t) );

  /* All bank mgr stuff here. */

  fd_bank_slot_set( bank, slot );

  fd_bank_parent_slot_set( bank, parent_slot );

  fd_bank_block_height_set( bank, test_ctx->slot_ctx.block_height );

  fd_bank_capitalization_set( bank, test_ctx->slot_ctx.prev_epoch_capitalization );

  // self.max_tick_height = (self.slot + 1) * self.ticks_per_slot;
  fd_bank_hashes_per_tick_set( bank, test_ctx->epoch_ctx.hashes_per_tick );

  fd_bank_ticks_per_slot_set( bank, test_ctx->epoch_ctx.ticks_per_slot );

  fd_bank_ns_per_slot_set( bank, (fd_w_u128_t) { .ul={ 400000000,0 } } ); // TODO: restore from input

  fd_bank_genesis_creation_time_set( bank, test_ctx->epoch_ctx.genesis_creation_time );

  fd_bank_slots_per_year_set( bank, test_ctx->epoch_ctx.slots_per_year );

  fd_bank_parent_signature_cnt_set( bank, test_ctx->slot_ctx.parent_signature_count );

  fd_fee_rate_governor_t * fee_rate_governor = fd_bank_fee_rate_governor_modify( bank );
  *fee_rate_governor = (fd_fee_rate_governor_t){
    .target_lamports_per_signature = test_ctx->slot_ctx.fee_rate_governor.target_lamports_per_signature,
    .target_signatures_per_slot    = test_ctx->slot_ctx.fee_rate_governor.target_signatures_per_slot,
    .min_lamports_per_signature    = test_ctx->slot_ctx.fee_rate_governor.min_lamports_per_signature,
    .max_lamports_per_signature    = test_ctx->slot_ctx.fee_rate_governor.max_lamports_per_signature,
    .burn_percent                  = (uchar)test_ctx->slot_ctx.fee_rate_governor.burn_percent
  };
  /* https://github.com/firedancer-io/solfuzz-agave/blob/agave-v3.0.3/src/block.rs#L393-L396 */
  fd_bank_rbh_lamports_per_sig_set( bank, FD_RUNTIME_FEE_STRUCTURE_LAMPORTS_PER_SIGNATURE );

  fd_inflation_t * inflation = fd_bank_inflation_modify( bank );
  *inflation = (fd_inflation_t){
    .initial         = test_ctx->epoch_ctx.inflation.initial,
    .terminal        = test_ctx->epoch_ctx.inflation.terminal,
    .taper           = test_ctx->epoch_ctx.inflation.taper,
    .foundation      = test_ctx->epoch_ctx.inflation.foundation,
    .foundation_term = test_ctx->epoch_ctx.inflation.foundation_term
  };

  fd_bank_block_height_set( bank, test_ctx->slot_ctx.block_height );

  /* Initialize the current running epoch stake and vote accounts */

  fd_vote_states_t * vote_states = fd_bank_vote_states_locking_modify( bank );
  vote_states = fd_vote_states_join( fd_vote_states_new( vote_states, FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  fd_bank_vote_states_end_locking_modify( bank );

  fd_vote_states_t * vote_states_prev = fd_bank_vote_states_prev_locking_modify( bank );
  vote_states_prev = fd_vote_states_join( fd_vote_states_new( vote_states_prev, FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  fd_bank_vote_states_prev_end_locking_modify( bank );

  fd_vote_states_t * vote_states_prev_prev = fd_bank_vote_states_prev_prev_locking_modify( bank );
  vote_states_prev_prev = fd_vote_states_join( fd_vote_states_new( vote_states_prev_prev, FD_RUNTIME_MAX_VOTE_ACCOUNTS, 999UL ) );
  fd_bank_vote_states_prev_prev_end_locking_modify( bank );

  fd_stake_delegations_t * stake_delegations = fd_banks_stake_delegations_root_query( banks );
  stake_delegations = fd_stake_delegations_join( fd_stake_delegations_new( stake_delegations, FD_RUNTIME_MAX_STAKE_ACCOUNTS, 0 ) );

  /* Load in all accounts with > 0 lamports provided in the context. The input expects unique account pubkeys. */
  vote_states = fd_bank_vote_states_locking_modify( bank );
  for( ushort i=0; i<test_ctx->acct_states_count; i++ ) {
    fd_solfuzz_pb_load_account( runner->runtime, accdb, xid, &test_ctx->acct_states[i], 1, i, NULL );

    /* Update vote accounts cache for epoch T */
    fd_pubkey_t pubkey;
    memcpy( &pubkey, test_ctx->acct_states[i].address, sizeof(fd_pubkey_t) );
    fd_solfuzz_block_register_vote_account(
        funk,
        xid,
        vote_states,
        &pubkey );

    /* Update the stake delegations cache for epoch T */
    fd_solfuzz_block_register_stake_delegation( funk, xid, stake_delegations, &pubkey );
  }

  /* Zero out vote stakes to avoid leakage across tests */
  fd_vote_states_reset_stakes( vote_states );

  /* Finish init epoch bank sysvars */
  fd_epoch_schedule_t epoch_schedule_[1];
  fd_epoch_schedule_t * epoch_schedule = fd_sysvar_epoch_schedule_read( funk, xid, epoch_schedule_ );
  FD_TEST( epoch_schedule );
  fd_bank_epoch_schedule_set( bank, *epoch_schedule );

  fd_rent_t rent[1];
  FD_TEST( fd_sysvar_rent_read( funk, xid, rent ) );
  fd_bank_rent_set( bank, *rent );

  /* Current epoch gets updated in process_new_epoch, so use the epoch
     from the parent slot */
  fd_bank_epoch_set( bank, fd_slot_to_epoch( epoch_schedule, parent_slot, NULL ) );

  /* Update vote cache for epoch T-1 */
  vote_states_prev = fd_bank_vote_states_prev_locking_modify( bank );
  fd_solfuzz_pb_block_update_prev_epoch_votes_cache(
      vote_states_prev,
      test_ctx->epoch_ctx.vote_accounts_t_1,
      test_ctx->epoch_ctx.vote_accounts_t_1_count,
      runtime_stack,
      runner->spad,
      1 );
  fd_bank_vote_states_prev_end_locking_modify( bank );

  /* Update vote cache for epoch T-2 */
  vote_states_prev_prev = fd_bank_vote_states_prev_prev_locking_modify( bank );
  fd_solfuzz_pb_block_update_prev_epoch_votes_cache(
      vote_states_prev_prev,
      test_ctx->epoch_ctx.vote_accounts_t_2,
      test_ctx->epoch_ctx.vote_accounts_t_2_count,
      runtime_stack,
      runner->spad,
      0 );

  /* Refresh vote accounts to calculate stake delegations */
  fd_solfuzz_block_refresh_vote_accounts(
    vote_states,
    vote_states_prev,
    vote_states_prev_prev,
    stake_delegations,
    fd_bank_epoch_get( bank ) );
  fd_bank_vote_states_end_locking_modify( bank );

  fd_bank_vote_states_prev_prev_end_locking_modify( bank );

  /* Update leader schedule */
  fd_runtime_update_leaders( bank, runtime_stack );

  /* Initialize the blockhash queue and recent blockhashes sysvar from the input blockhash queue */
  ulong blockhash_seed; FD_TEST( fd_rng_secure( &blockhash_seed, sizeof(ulong) ) );
  fd_blockhashes_init( fd_bank_block_hash_queue_modify( bank ), blockhash_seed );

  /* TODO: We might need to load this in from the input. We also need to
     size this out for worst case, but this also blows up the memory
     requirement. */
  /* Allocate all the memory for the rent fresh accounts list */

  // Set genesis hash to {0}
  fd_hash_t * genesis_hash = fd_bank_genesis_hash_modify( bank );
  fd_memset( genesis_hash->hash, 0, sizeof(fd_hash_t) );

  // Use the latest lamports per signature
  uchar __attribute__((aligned(FD_SYSVAR_RECENT_HASHES_ALIGN))) rbh_mem[FD_SYSVAR_RECENT_HASHES_FOOTPRINT];
  fd_recent_block_hashes_t const * rbh = fd_sysvar_recent_hashes_read( funk, xid, rbh_mem );
  if( rbh && !deq_fd_block_block_hash_entry_t_empty( rbh->hashes ) ) {
    fd_block_block_hash_entry_t const * last = deq_fd_block_block_hash_entry_t_peek_head_const( rbh->hashes );
    if( last && last->fee_calculator.lamports_per_signature!=0UL ) {
      fd_bank_rbh_lamports_per_sig_set( bank, last->fee_calculator.lamports_per_signature );
    }
  }

  /* Make a new funk transaction since we're done loading in accounts for context */
  fd_funk_txn_xid_t fork_xid = { .ul = { slot, 0UL } };
  fd_accdb_attach_child        ( runner->accdb_admin,     xid, &fork_xid );
  fd_progcache_txn_attach_child( runner->progcache_admin, xid, &fork_xid );
  xid[0] = fork_xid;

  /* Set the initial lthash from the input since we're in a new Funk txn */
  fd_lthash_value_t * lthash = fd_bank_lthash_locking_modify( bank );
  fd_memcpy( lthash, test_ctx->slot_ctx.parent_lthash, sizeof(fd_lthash_value_t) );
  fd_bank_lthash_end_locking_modify( bank );

  // Populate blockhash queue and recent blockhashes sysvar
  for( ushort i=0; i<test_ctx->blockhash_queue_count; ++i ) {
    fd_hash_t hash;
    memcpy( &hash, test_ctx->blockhash_queue[i]->bytes, sizeof(fd_hash_t) );
    fd_bank_poh_set( bank, hash );
    fd_sysvar_recent_hashes_update( bank, accdb, xid, NULL ); /* appends an entry */
  }

  /* Set the poh from the input.  This is the blockhash that will get
     inserted after. */
  memcpy( poh, test_ctx->slot_ctx.poh, sizeof(fd_hash_t) );

  /* Restore sysvar cache */
  fd_sysvar_cache_restore_fuzz( bank, funk, xid );

  /* Prepare raw transaction pointers and block / microblock infos */
  ulong        txn_cnt  = test_ctx->txns_count;
  fd_txn_p_t * txn_ptrs = fd_spad_alloc( runner->spad, alignof(fd_txn_p_t), txn_cnt * sizeof(fd_txn_p_t) );
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t * txn    = &txn_ptrs[i];
    ulong        msg_sz = fd_solfuzz_pb_txn_serialize( txn->payload, &test_ctx->txns[i] );

    // Reject any transactions over 1232 bytes
    if( FD_UNLIKELY( msg_sz==ULONG_MAX ) ) {
      return NULL;
    }
    txn->payload_sz = msg_sz;

    // Reject any transactions that cannot be parsed
    if( FD_UNLIKELY( !fd_txn_parse( txn->payload, msg_sz, TXN( txn ), NULL ) ) ) {
      return NULL;
    }
  }

  *out_txn_cnt = txn_cnt;
  return txn_ptrs;
}

/* Takes in a list of txn_p_t created from
   fd_runtime_fuzz_block_ctx_create and executes it against the runtime.
   Returns the execution result. */
static int
fd_solfuzz_block_ctx_exec( fd_solfuzz_runner_t * runner,
                           fd_txn_p_t *          txn_ptrs,
                           ulong                 txn_cnt,
                           fd_hash_t *           poh ) {
  int res = 0;

  // Prepare. Execute. Finalize.
  FD_SPAD_FRAME_BEGIN( runner->spad ) {
    fd_capture_ctx_t * capture_ctx = NULL;
    if( runner->solcap ) {
      void * capture_ctx_mem = fd_spad_alloc( runner->spad, fd_capture_ctx_align(), fd_capture_ctx_footprint() );
      capture_ctx            = fd_capture_ctx_new( capture_ctx_mem );
      if( FD_UNLIKELY( capture_ctx==NULL ) ) {
        FD_LOG_ERR(("capture_ctx_mem is NULL, cannot write solcap"));
      }
      capture_ctx->capture           = runner->solcap;
      capture_ctx->solcap_start_slot = fd_bank_slot_get( runner->bank );
      fd_solcap_writer_set_slot( capture_ctx->capture, fd_bank_slot_get( runner->bank ) );
    }

    fd_funk_t * funk = fd_accdb_user_v1_funk( runner->accdb );
    fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( runner->bank ), runner->bank->idx } };

    fd_rewards_recalculate_partitioned_rewards( runner->banks, runner->bank, funk, &xid, runner->runtime_stack, capture_ctx );

    /* Process new epoch may push a new spad frame onto the runtime spad. We should make sure this frame gets
       cleared (if it was allocated) before executing the block. */
    int is_epoch_boundary = 0;
    fd_runtime_block_execute_prepare( runner->banks, runner->bank, runner->accdb, runner->runtime_stack, capture_ctx, &is_epoch_boundary );

    /* Sequential transaction execution */
    for( ulong i=0UL; i<txn_cnt; i++ ) {
      fd_txn_p_t * txn = &txn_ptrs[i];

      /* Execute the transaction against the runtime */
      res = FD_RUNTIME_EXECUTE_SUCCESS;
      fd_txn_in_t  txn_in = { .txn = txn, .bundle.is_bundle = 0 };
      fd_txn_out_t txn_out;
      fd_runtime_t * runtime = runner->runtime;
      fd_log_collector_t log[1];
      runtime->log.log_collector = log;
      fd_solfuzz_txn_ctx_exec( runner, runtime, &txn_in, &res, &txn_out );
      txn_out.err.exec_err = res;

      if( FD_UNLIKELY( !txn_out.err.is_committable ) ) {
        return 0;
      }

      /* Finalize the transaction */
      fd_runtime_commit_txn( runtime, runner->bank, &txn_out );

      if( FD_UNLIKELY( !txn_out.err.is_committable ) ) {
        return 0;
      }

    }

    /* At this point we want to set the poh.  This is what will get
       updated in the blockhash queue. */
    fd_bank_poh_set( runner->bank, *poh );
    /* Finalize the block */
    fd_runtime_block_execute_finalize( runner->bank, runner->accdb, capture_ctx );
  } FD_SPAD_FRAME_END;

  return 1;
}

/* Canonical (Agave-aligned) schedule hash
   Unique pubkeys referenced by sched, sorted deterministically
   Per-rotation indices mapped into sorted-uniq array */
ulong
fd_solfuzz_block_hash_epoch_leaders( fd_solfuzz_runner_t *      runner,
                                     fd_epoch_leaders_t const * leaders,
                                     ulong                      seed,
                                     uchar                      out[16] ) {
  /* Single contiguous spad allocation for uniq[] and sched_mapped[] */
  void *buf = fd_spad_alloc(
    runner->spad,
    alignof(pk_with_pos_t),
    leaders->sched_cnt*sizeof(pk_with_pos_t) +
    leaders->sched_cnt*sizeof(uint) );

  pk_with_pos_t * tmp          = (pk_with_pos_t *)buf;
  uint          * sched_mapped = (uint *)( tmp + leaders->sched_cnt );

  /* Gather all pubkeys and original positions from sched[] (skip invalid) */
  ulong gather_cnt = 0UL;
  for( ulong i=0UL; i<leaders->sched_cnt; i++ ) {
    uint idx = leaders->sched[i];
    if( idx>=leaders->pub_cnt ) { /* invalid slot leader */
      sched_mapped[i] = 0U;       /* prefill invalid mapping */
      continue;
    }
    fd_memcpy( &tmp[gather_cnt].pk, &leaders->pub[idx], sizeof(fd_pubkey_t) );
    tmp[gather_cnt].sched_pos = i;
    gather_cnt++;
  }

  if( gather_cnt==0UL ) {
    /* No leaders => hash:=0, count:=0 */
    fd_memset( out, 0, sizeof(ulong)*2 );
    return 0UL;
  }

  /* Sort tmp[] by pubkey, note: comparator relies on first struct member */
  sort_pkpos_inplace( tmp, (ulong)gather_cnt );

  /* Dedupe and assign indices into sched_mapped[] during single pass */
  ulong uniq_cnt = 0UL;
  for( ulong i=0UL; i<gather_cnt; i++ ) {
    if( i==0UL || memcmp( &tmp[i].pk, &tmp[i-1].pk, sizeof(fd_pubkey_t) )!=0 )
      uniq_cnt++;
    /* uniq_cnt-1 is index in uniq set */
    sched_mapped[tmp[i].sched_pos] = (uint)(uniq_cnt-1UL);
  }

  /* Reconstruct contiguous uniq[] for hashing */
  fd_pubkey_t *uniq = fd_spad_alloc( runner->spad,
                                     alignof(fd_pubkey_t),
                                     uniq_cnt*sizeof(fd_pubkey_t) );
  {
    ulong write_pos = 0UL;
    for( ulong i=0UL; i<gather_cnt; i++ ) {
      if( i==0UL || memcmp( &tmp[i].pk, &tmp[i-1].pk, sizeof(fd_pubkey_t) )!=0 )
      fd_memcpy( &uniq[write_pos++], &tmp[i].pk, sizeof(fd_pubkey_t) );
    }
  }

  /* Hash sorted unique pubkeys */
  ulong h1 = fd_hash( seed, uniq, uniq_cnt * sizeof(fd_pubkey_t) );
  fd_memcpy( out, &h1, sizeof(ulong) );

  /* Hash mapped indices */
  ulong h2 = fd_hash( seed, sched_mapped, leaders->sched_cnt * sizeof(uint) );
  fd_memcpy( out + sizeof(ulong), &h2, sizeof(ulong) );

  return uniq_cnt;
}

static void
fd_solfuzz_pb_build_leader_schedule_effects( fd_solfuzz_runner_t *          runner,
                                             fd_funk_txn_xid_t const *      xid,
                                             fd_exec_test_block_effects_t * effects ) {
  /* Read epoch schedule sysvar */
  fd_funk_t * funk = fd_accdb_user_v1_funk( runner->accdb );
  fd_epoch_schedule_t es_;
  fd_epoch_schedule_t *sched = fd_sysvar_epoch_schedule_read( funk, xid, &es_ );
  FD_TEST( sched!=NULL );

  /* We will capture the leader schedule for the current epoch that we
     are in.  This will capture the leader schedule generated by an
     epoch boundary if one was crossed. */
  ulong epoch          = fd_bank_epoch_get( runner->bank );
  ulong ls_slot0       = fd_epoch_slot0( sched, epoch );
  ulong slots_in_epoch = fd_epoch_slot_cnt( sched, epoch );

  fd_epoch_leaders_t const * effects_leaders = fd_bank_epoch_leaders_locking_query( runner->bank );

  /* Fill out effects struct from the Agave epoch info */
  effects->has_leader_schedule               = 1;
  effects->leader_schedule.leaders_epoch     = epoch;
  effects->leader_schedule.leaders_slot0     = ls_slot0;
  effects->leader_schedule.leaders_slot_cnt  = slots_in_epoch;
  effects->leader_schedule.leaders_sched_cnt = slots_in_epoch;
  effects->leader_schedule.leader_pub_cnt    = fd_solfuzz_block_hash_epoch_leaders(
      runner, effects_leaders,
      LEADER_SCHEDULE_HASH_SEED,
      effects->leader_schedule.leader_schedule_hash
  );
  fd_bank_epoch_leaders_end_locking_query( runner->bank );
}

ulong
fd_solfuzz_pb_block_run( fd_solfuzz_runner_t * runner,
                          void const *         input_,
                          void **              output_,
                          void *               output_buf,
                          ulong                output_bufsz ) {
  fd_exec_test_block_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_block_effects_t **      output = fd_type_pun( output_ );

  FD_SPAD_FRAME_BEGIN( runner->spad ) {
    /* Set up the block execution context */
    ulong txn_cnt;
    fd_hash_t poh = {0};
    fd_txn_p_t * txn_ptrs = fd_solfuzz_pb_block_ctx_create( runner, input, &txn_cnt, &poh );
    if( txn_ptrs==NULL ) {
      fd_solfuzz_pb_block_ctx_destroy( runner );
      return 0;
    }

    fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( runner->bank ), runner->bank->idx } };

    /* Execute the constructed block against the runtime. */
    int is_committable = fd_solfuzz_block_ctx_exec( runner, txn_ptrs, txn_cnt, &poh );

    /* Start saving block exec results */
    FD_SCRATCH_ALLOC_INIT( l, output_buf );
    ulong output_end = (ulong)output_buf + output_bufsz;

    fd_exec_test_block_effects_t * effects =
    FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_block_effects_t),
                                sizeof(fd_exec_test_block_effects_t) );
    if( FD_UNLIKELY( _l > output_end ) ) {
      abort();
    }
    fd_memset( effects, 0, sizeof(fd_exec_test_block_effects_t) );

    /* Capture error status */
    effects->has_error = !is_committable;

    /* Capture capitalization */
    effects->slot_capitalization = !effects->has_error ? fd_bank_capitalization_get( runner->bank ) : 0UL;

    /* Capture hashes */
    fd_hash_t bank_hash = !effects->has_error ? fd_bank_bank_hash_get( runner->bank ) : (fd_hash_t){0};
    fd_memcpy( effects->bank_hash, bank_hash.hash, sizeof(fd_hash_t) );

    /* Capture cost tracker */
    fd_cost_tracker_t const * cost_tracker = fd_bank_cost_tracker_locking_query( runner->bank );
    effects->has_cost_tracker = 1;
    effects->cost_tracker = (fd_exec_test_cost_tracker_t) {
      .block_cost = cost_tracker ? cost_tracker->block_cost : 0UL,
      .vote_cost  = cost_tracker ? cost_tracker->vote_cost  : 0UL,
    };
    fd_bank_cost_tracker_end_locking_query( runner->bank );

    /* Effects: build T-epoch (bank epoch), T-stakes ephemeral leaders and report */
    fd_solfuzz_pb_build_leader_schedule_effects( runner, &xid, effects );

    ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
    fd_solfuzz_pb_block_ctx_destroy( runner );

    *output = effects;
    return actual_end - (ulong)output_buf;
  } FD_SPAD_FRAME_END;
}
