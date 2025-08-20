#include "fd_stakes.h"
#include "../runtime/fd_acc_mgr.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/context/fd_exec_slot_ctx.h"
#include "../runtime/program/fd_stake_program.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "fd_stake_delegations.h"

ulong
fd_stake_weights_by_node( fd_vote_states_t const * vote_states,
                          fd_vote_stake_weight_t * weights ) {

  ulong weights_cnt = 0;
  uchar iter_mem[FD_VOTE_STATE_ITER_FOOTPRINT];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( vote_states, iter_mem ); !fd_vote_states_iter_done( iter ); fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t const * vote_state = fd_vote_states_iter_ele( iter );
    if( FD_UNLIKELY( !vote_state->stake ) ) continue;

    fd_memcpy( weights[ weights_cnt ].vote_key.uc, &vote_state->vote_account, sizeof(fd_pubkey_t) );
    fd_memcpy( weights[ weights_cnt ].id_key.uc, &vote_state->node_account, sizeof(fd_pubkey_t) );
    weights[ weights_cnt ].stake = vote_state->stake;
    weights_cnt++;
  }
  sort_vote_weights_by_stake_vote_inplace( weights, weights_cnt );
  return weights_cnt;
}

static void
compute_stake_delegations( fd_bank_t *                bank,
                           ulong const                epoch,
                           fd_stake_history_t const * history,
                           ulong *                    new_rate_activation_epoch ) {

  ulong total_stake = 0UL;

  fd_vote_states_t * vote_states = fd_bank_vote_states_locking_modify( bank );
  if( FD_UNLIKELY( !vote_states ) ) {
    FD_LOG_CRIT(( "vote_states is NULL" ));
  }

  fd_stake_delegations_t const * stake_delegations = fd_bank_stake_delegations_locking_query( bank );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "stake_delegations is NULL" ));
  }
  fd_stake_delegation_map_t * stake_delegation_map  = fd_stake_delegations_get_map( stake_delegations );
  fd_stake_delegation_t *     stake_delegation_pool = fd_stake_delegations_get_pool( stake_delegations );

  /* Reset the vote stakes so we can re-compute them based on the most
     current stake delegation values. */
  fd_vote_states_reset_stakes( vote_states );

  for( fd_stake_delegation_map_iter_t iter = fd_stake_delegation_map_iter_init( stake_delegation_map, stake_delegation_pool );
       !fd_stake_delegation_map_iter_done( iter, stake_delegation_map, stake_delegation_pool );
       iter = fd_stake_delegation_map_iter_next( iter, stake_delegation_map, stake_delegation_pool ) ) {

    fd_stake_delegation_t const * stake_delegation = fd_stake_delegation_map_iter_ele_const( iter, stake_delegation_map, stake_delegation_pool );

    // Skip any delegations that are not in the delegation pool

    fd_delegation_t delegation = {
      .voter_pubkey         = stake_delegation->vote_account,
      .stake                = stake_delegation->stake,
      .deactivation_epoch   = stake_delegation->deactivation_epoch,
      .activation_epoch     = stake_delegation->activation_epoch,
      .warmup_cooldown_rate = stake_delegation->warmup_cooldown_rate,
    };

    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating(
        &delegation,
        epoch,
        history,
        new_rate_activation_epoch );

    fd_vote_state_ele_t * vote_state = fd_vote_states_query( vote_states, &stake_delegation->vote_account );
    if( vote_state ) {
      vote_state->stake += new_entry.effective;
    }

    total_stake += new_entry.effective;
  }

  fd_bank_total_epoch_stake_set( bank, total_stake );

  fd_bank_stake_delegations_end_locking_query( bank );

  fd_bank_vote_states_end_locking_modify( bank );
}

/* Refresh vote accounts.

   This updates the epoch bank stakes vote_accounts cache - that is, the total amount
   of delegated stake each vote account has, using the current delegation values from inside each
   stake account. Contrary to the Agave equivalent, it also merges the stakes cache vote accounts with the
   new vote account keys from this epoch.

   https://github.com/solana-labs/solana/blob/c091fd3da8014c0ef83b626318018f238f506435/runtime/src/stakes.rs#L562 */
void
fd_refresh_vote_accounts( fd_exec_slot_ctx_t *       slot_ctx,
                          fd_stake_history_t const * history,
                          ulong *                    new_rate_activation_epoch ) {

  compute_stake_delegations(
      slot_ctx->bank,
      fd_bank_epoch_get( slot_ctx->bank ),
      history,
      new_rate_activation_epoch );
}

static void
accumulate_stake_cache_delegations( fd_stake_delegations_t *   stake_delegations,
                                    fd_stake_history_t const * history,
                                    ulong *                    new_rate_activation_epoch,
                                    fd_stake_history_entry_t * accumulator,
                                    ulong                      epoch ) {

  fd_stake_delegation_t *     pool = fd_stake_delegations_get_pool( stake_delegations );
  fd_stake_delegation_map_t * map  = fd_stake_delegations_get_map( stake_delegations );

  ulong effective    = 0UL;
  ulong activating   = 0UL;
  ulong deactivating = 0UL;

  for( fd_stake_delegation_map_iter_t iter = fd_stake_delegation_map_iter_init( map, pool );
       !fd_stake_delegation_map_iter_done( iter, map, pool );
       iter = fd_stake_delegation_map_iter_next( iter, map, pool ) ) {
    fd_stake_delegation_t const * stake_delegation = fd_stake_delegation_map_iter_ele_const( iter, map, pool );

    fd_delegation_t delegation = {
      .voter_pubkey         = stake_delegation->vote_account,
      .stake                = stake_delegation->stake,
      .activation_epoch     = stake_delegation->activation_epoch,
      .deactivation_epoch   = stake_delegation->deactivation_epoch,
      .warmup_cooldown_rate = stake_delegation->warmup_cooldown_rate,
    };

    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating(
        &delegation,
        epoch,
        history,
        new_rate_activation_epoch );
    effective    += new_entry.effective;
    activating   += new_entry.activating;
    deactivating += new_entry.deactivating;
  }

  accumulator->effective    += effective;
  accumulator->activating   += activating;
  accumulator->deactivating += deactivating;

}

/* Accumulates information about epoch stakes into `temp_info`, which is a temporary cache
   used to save intermediate state about stake and vote accounts to avoid them from having to
   be recomputed on every access, especially at the epoch boundary. Also collects stats in `accumulator` */
void
fd_accumulate_stake_infos( fd_exec_slot_ctx_t const * slot_ctx,
                           fd_stake_delegations_t *   stake_delegations,
                           fd_stake_history_t const * history,
                           ulong *                    new_rate_activation_epoch,
                           fd_stake_history_entry_t * accumulator,
                           fd_spad_t *                runtime_spad ) {

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  ulong epoch = fd_bank_epoch_get( slot_ctx->bank );

  accumulate_stake_cache_delegations(
      stake_delegations,
      history,
      new_rate_activation_epoch,
      accumulator,
      epoch );

  } FD_SPAD_FRAME_END;
}

/* https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L169 */
void
fd_stakes_activate_epoch( fd_exec_slot_ctx_t * slot_ctx,
                          ulong *              new_rate_activation_epoch,
                          fd_spad_t *          runtime_spad ) {

  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join( (void*)fd_bank_stake_delegations_locking_modify( slot_ctx->bank ) );

  /* Current stake delegations: list of all current delegations in stake_delegations
     https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L180 */
  /* Add a new entry to the Stake History sysvar for the previous epoch
     https://github.com/solana-labs/solana/blob/88aeaa82a856fc807234e7da0b31b89f2dc0e091/runtime/src/stakes.rs#L181-L192 */

  fd_stake_history_t const * history = fd_sysvar_stake_history_read( slot_ctx->funk, slot_ctx->funk_txn, runtime_spad );
  if( FD_UNLIKELY( !history ) ) FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));

  fd_stake_history_entry_t accumulator = {
    .effective    = 0UL,
    .activating   = 0UL,
    .deactivating = 0UL
  };

  /* Accumulate stats for stake accounts */
  fd_accumulate_stake_infos(
      slot_ctx,
      stake_delegations,
      history,
      new_rate_activation_epoch,
      &accumulator,
      runtime_spad );

  /* https://github.com/anza-xyz/agave/blob/v2.1.6/runtime/src/stakes.rs#L359 */
  fd_epoch_stake_history_entry_pair_t new_elem = {
    .epoch        = fd_bank_epoch_get( slot_ctx->bank ),
    .entry        = {
      .effective    = accumulator.effective,
      .activating   = accumulator.activating,
      .deactivating = accumulator.deactivating
    }
  };

  fd_sysvar_stake_history_update( slot_ctx, &new_elem, runtime_spad );

  fd_bank_stake_delegations_end_locking_modify( slot_ctx->bank );

}

int
write_stake_state( fd_txn_account_t *    stake_acc_rec,
                   fd_stake_state_v2_t * stake_state ) {

  ulong encoded_stake_state_size = fd_stake_state_v2_size(stake_state);

  fd_bincode_encode_ctx_t ctx = {
    .data    = fd_txn_account_get_data_mut( stake_acc_rec ),
    .dataend = fd_txn_account_get_data_mut( stake_acc_rec ) + encoded_stake_state_size,
  };
  if( FD_UNLIKELY( fd_stake_state_v2_encode( stake_state, &ctx ) != FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "fd_stake_state_encode failed" ));
  }

  return 0;
}

/* Removes stake delegation from epoch stakes and updates vote account */
static void
fd_stakes_remove_stake_delegation( fd_txn_account_t *   stake_account,
                                   fd_bank_t *          bank ) {

  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join( fd_bank_stake_delegations_locking_modify( bank ) );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation pool" ));
  }

  fd_stake_delegations_remove( stake_delegations, stake_account->pubkey );

  fd_bank_stake_delegations_end_locking_modify( bank );
}

/* Updates stake delegation in epoch stakes */
static void
fd_stakes_upsert_stake_delegation( fd_txn_account_t * stake_account,
                                   fd_bank_t *        bank ) {

  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join( fd_bank_stake_delegations_locking_modify( bank ) );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation pool" ));
  }

  fd_stake_state_v2_t stake_state;
  int err = fd_stake_get_state( stake_account, &stake_state );
  if( FD_UNLIKELY( err != 0 ) ) {
    FD_LOG_WARNING(( "Failed to get stake state" ));
    fd_bank_stake_delegations_end_locking_modify( bank );
    return;
  }

  if( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
    FD_LOG_WARNING(( "Not a valid stake" ));
    fd_bank_stake_delegations_end_locking_modify( bank );
    return;
  }

  if( FD_UNLIKELY( stake_state.inner.stake.stake.delegation.stake==0UL ) ) {
    FD_LOG_WARNING(( "Stake is empty" ));
    fd_bank_stake_delegations_end_locking_modify( bank );
    return;
  }

  fd_stake_delegations_update(
      stake_delegations,
      stake_account->pubkey,
      &stake_state.inner.stake.stake.delegation.voter_pubkey,
      stake_state.inner.stake.stake.delegation.stake,
      stake_state.inner.stake.stake.delegation.activation_epoch,
      stake_state.inner.stake.stake.delegation.deactivation_epoch,
      stake_state.inner.stake.stake.credits_observed,
      stake_state.inner.stake.stake.delegation.warmup_cooldown_rate );

  fd_bank_stake_delegations_end_locking_modify( bank );
}

void
fd_update_stake_delegation( fd_txn_account_t * stake_account,
                            fd_bank_t *        bank ) {

  int is_empty  = fd_txn_account_get_lamports( stake_account )==0UL;
  int is_uninit = 1;
  if( fd_txn_account_get_data_len( stake_account )>=4UL ) {
    uint prefix = FD_LOAD( uint, fd_txn_account_get_data( stake_account ) );
    is_uninit = ( prefix==fd_stake_state_v2_enum_uninitialized );
  }

  if( is_empty || is_uninit ) {
    fd_stakes_remove_stake_delegation( stake_account, bank );
  } else {
    fd_stakes_upsert_stake_delegation( stake_account, bank );
  }
}

void
fd_refresh_stake_delegations( fd_exec_slot_ctx_t * slot_ctx ) {
  fd_bank_t * bank = slot_ctx->bank;

  fd_stake_delegations_t * stake_delegations = fd_stake_delegations_join( fd_bank_stake_delegations_locking_modify( bank ) );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "fd_runtime_refresh_stakes: stake_delegations is NULL" ));
  }

  fd_stake_delegation_map_t * stake_delegation_map  = fd_stake_delegations_get_map( stake_delegations );
  fd_stake_delegation_t *     stake_delegation_pool = fd_stake_delegations_get_pool( stake_delegations );

  for( fd_stake_delegation_map_iter_t iter = fd_stake_delegation_map_iter_init( stake_delegation_map, stake_delegation_pool );
       !fd_stake_delegation_map_iter_done( iter, stake_delegation_map, stake_delegation_pool );
       iter = fd_stake_delegation_map_iter_next( iter, stake_delegation_map, stake_delegation_pool ) ) {

    fd_stake_delegation_t * stake_delegation = fd_stake_delegation_map_iter_ele( iter, stake_delegation_map, stake_delegation_pool );

    FD_TXN_ACCOUNT_DECL( acct_rec );
    int err = fd_txn_account_init_from_funk_readonly( acct_rec,
                                                      &stake_delegation->stake_account,
                                                      slot_ctx->funk,
                                                      slot_ctx->funk_txn );

    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
      continue;
    }

    fd_stake_state_v2_t stake_state;
    err = fd_stake_get_state( acct_rec, &stake_state );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_CRIT(( "invariant violation: stake account has invalid state" ));
    }

    if( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
      FD_LOG_CRIT(( "invariant violation: stake account is not a stake" ));
    }

    fd_stake_delegations_update(
        stake_delegations,
        &stake_delegation->stake_account,
        &stake_state.inner.stake.stake.delegation.voter_pubkey,
        stake_state.inner.stake.stake.delegation.stake,
        stake_state.inner.stake.stake.delegation.activation_epoch,
        stake_state.inner.stake.stake.delegation.deactivation_epoch,
        stake_state.inner.stake.stake.credits_observed,
        stake_state.inner.stake.stake.delegation.warmup_cooldown_rate
    );
  }

  fd_bank_stake_delegations_end_locking_modify( slot_ctx->bank );
}
