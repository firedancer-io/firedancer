#include "fd_stakes.h"
#include "../runtime/fd_bank.h"
#include "../runtime/program/fd_stake_program.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "fd_stake_delegations.h"
#include "../accdb/fd_accdb_impl_v1.h"

ulong
fd_stake_weights_by_node( fd_vote_states_t const * vote_states,
                          fd_vote_stake_weight_t * weights ) {

  ulong weights_cnt = 0;
  fd_vote_states_iter_t iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states ); !fd_vote_states_iter_done( iter ); fd_vote_states_iter_next( iter ) ) {
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

/* We need to update the amount of stake that each vote account has for
   the given epoch.  This can only be done after the stake history
   sysvar has been updated.  We also cache the stakes for each of the
   vote accounts for the previous epoch.

   https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/stakes.rs#L471 */
void
fd_refresh_vote_accounts( fd_bank_t *                    bank,
                          fd_stake_delegations_t const * stake_delegations,
                          fd_stake_history_t const *     history,
                          ulong *                        new_rate_activation_epoch ) {

  ulong epoch = fd_bank_epoch_get( bank );

  ulong total_stake = 0UL;

  fd_vote_states_t * vote_states = fd_bank_vote_states_locking_modify( bank );
  if( FD_UNLIKELY( !vote_states ) ) {
    FD_LOG_CRIT(( "vote_states is NULL" ));
  }

  /* Reset the vote stakes so we can re-compute them based on the most
     current stake delegation values. */
  fd_vote_states_reset_stakes( vote_states );

  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_iter_ele( iter );

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
    if( FD_LIKELY( vote_state ) ) {
      total_stake       += new_entry.effective;
      vote_state->stake += new_entry.effective;
    }
  }

  fd_bank_total_epoch_stake_set( bank, total_stake );

  fd_bank_vote_states_end_locking_modify( bank );
}

/* https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/stakes.rs#L280 */
void
fd_stakes_activate_epoch( fd_bank_t *                    bank,
                          fd_accdb_user_t *              accdb,
                          fd_funk_txn_xid_t const *      xid,
                          fd_capture_ctx_t *             capture_ctx,
                          fd_stake_delegations_t const * stake_delegations,
                          ulong *                        new_rate_activation_epoch ) {

  /* First, we need to accumulate the stats for the current amount of
     effective, activating, and deactivating stake for the current
     epoch.  Once this is computed, we can add update our stake history
     sysvar.  Afterward, we can refresh the stake values for the vote
     accounts for the new epoch. */

  fd_stake_history_t stake_history[1];
  if( FD_UNLIKELY( !fd_sysvar_stake_history_read( accdb, xid, stake_history ) ) ) {
    FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));
  }

  fd_epoch_stake_history_entry_pair_t new_elem = {
    .epoch = fd_bank_epoch_get( bank ),
    .entry = {
      .effective    = 0UL,
      .activating   = 0UL,
      .deactivating = 0UL
    }
  };

  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_iter_ele( iter );

    fd_delegation_t delegation = {
      .voter_pubkey         = stake_delegation->vote_account,
      .stake                = stake_delegation->stake,
      .activation_epoch     = stake_delegation->activation_epoch,
      .deactivation_epoch   = stake_delegation->deactivation_epoch,
      .warmup_cooldown_rate = stake_delegation->warmup_cooldown_rate,
    };

    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating(
        &delegation,
        fd_bank_epoch_get( bank ),
        stake_history,
        new_rate_activation_epoch );
    new_elem.entry.effective    += new_entry.effective;
    new_elem.entry.activating   += new_entry.activating;
    new_elem.entry.deactivating += new_entry.deactivating;
  }

  fd_sysvar_stake_history_update( bank, accdb, xid, capture_ctx, &new_elem );

  if( FD_UNLIKELY( !fd_sysvar_stake_history_read( accdb, xid, stake_history ) ) ) {
    FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));
  }

  /* Now increment the epoch and recompute the stakes for the vote
     accounts for the new epoch value. */

  fd_bank_epoch_set( bank, fd_bank_epoch_get( bank ) + 1UL );

  fd_refresh_vote_accounts( bank,
                            stake_delegations,
                            stake_history,
                            new_rate_activation_epoch );

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

void
fd_stakes_update_stake_delegation( fd_pubkey_t const *       pubkey,
                                   fd_account_meta_t const * meta,
                                   fd_bank_t *               bank ) {

  fd_stake_delegations_t * stake_delegations_delta = fd_bank_stake_delegations_delta_locking_modify( bank );
  if( FD_UNLIKELY( !stake_delegations_delta ) ) {
    FD_LOG_CRIT(( "unable to retrieve join to stake delegation delta" ));
  }

  if( meta->lamports==0UL ) {
    fd_stake_delegations_remove( stake_delegations_delta, pubkey );
    fd_bank_stake_delegations_delta_end_locking_modify( bank );
    return;
  }

  fd_stake_state_v2_t stake_state;
  int err = fd_stake_get_state( meta, &stake_state );
  if( FD_UNLIKELY( err!=0 ) ) {
    fd_stake_delegations_remove( stake_delegations_delta, pubkey );
    fd_bank_stake_delegations_delta_end_locking_modify( bank );
    return;
  }

  if( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
    fd_stake_delegations_remove( stake_delegations_delta, pubkey );
    fd_bank_stake_delegations_delta_end_locking_modify( bank );
    return;
  }

  if( FD_UNLIKELY( fd_stake_state_v2_is_uninitialized( &stake_state ) ) ) {
    fd_stake_delegations_remove( stake_delegations_delta, pubkey );
    fd_bank_stake_delegations_delta_end_locking_modify( bank );
    return;
  }

  if( FD_UNLIKELY( stake_state.inner.stake.stake.delegation.stake==0UL ) ) {
    fd_stake_delegations_remove( stake_delegations_delta, pubkey );
    fd_bank_stake_delegations_delta_end_locking_modify( bank );
    return;
  }

  fd_stake_delegations_update( stake_delegations_delta,
                               pubkey,
                               &stake_state.inner.stake.stake.delegation.voter_pubkey,
                               stake_state.inner.stake.stake.delegation.stake,
                               stake_state.inner.stake.stake.delegation.activation_epoch,
                               stake_state.inner.stake.stake.delegation.deactivation_epoch,
                               stake_state.inner.stake.stake.credits_observed,
                               stake_state.inner.stake.stake.delegation.warmup_cooldown_rate );

  fd_bank_stake_delegations_delta_end_locking_modify( bank );
}

void
fd_stakes_update_vote_state( fd_pubkey_t const *       pubkey,
                             fd_account_meta_t const * meta,
                             fd_bank_t *               bank ) {

  fd_vote_states_t * vote_states = fd_bank_vote_states_locking_modify( bank );

  if( meta->lamports==0UL ) {
    fd_vote_states_remove( vote_states, pubkey );
    fd_bank_vote_states_end_locking_modify( bank );
    return;
  }

  if( !fd_vsv_is_correct_size_and_initialized( meta ) ) {
    fd_vote_states_remove( vote_states, pubkey );
    fd_bank_vote_states_end_locking_modify( bank );
    return;
  }

  fd_vote_states_update_from_account( vote_states,
                                      pubkey,
                                      fd_account_data( meta ),
                                      meta->dlen );
  fd_bank_vote_states_end_locking_modify( bank );
}
