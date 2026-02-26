#include "fd_stakes.h"
#include "../runtime/fd_bank.h"
#include "../runtime/program/fd_stake_program.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../runtime/fd_runtime_stack.h"
#include "fd_stake_delegations.h"
#include "../accdb/fd_accdb_impl_v1.h"

ulong
fd_stake_weights_by_node( fd_vote_stakes_t *       vote_stakes,
                          ushort                   fork_idx,
                          fd_vote_stake_weight_t * weights ) {
  ulong weights_cnt = 0;
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_fork_iter_init( vote_stakes, fork_idx, iter_mem );
       !fd_vote_stakes_fork_iter_done( vote_stakes, fork_idx, iter  );
       fd_vote_stakes_fork_iter_next( vote_stakes, fork_idx, iter ) ) {
    fd_pubkey_t pubkey;
    ulong       stake_t_2;
    fd_pubkey_t node_account_t_2;
    fd_vote_stakes_fork_iter_ele( vote_stakes, fork_idx, iter, &pubkey, NULL, &stake_t_2, NULL, &node_account_t_2 );
    if( FD_UNLIKELY( !stake_t_2 ) ) continue;

    fd_memcpy( weights[ weights_cnt ].vote_key.uc, &pubkey, sizeof(fd_pubkey_t) );
    fd_memcpy( weights[ weights_cnt ].id_key.uc, &node_account_t_2, sizeof(fd_pubkey_t) );
    weights[ weights_cnt ].stake = stake_t_2;
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
                          fd_runtime_stack_t *           runtime_stack,
                          fd_stake_delegations_t const * stake_delegations,
                          fd_stake_history_t const *     history,
                          ulong *                        new_rate_activation_epoch ) {

  fd_vote_ele_map_t * vote_ele_map = fd_type_pun( runtime_stack->stakes.vote_map_mem );
  fd_vote_ele_map_reset( vote_ele_map );
  ulong vote_ele_cnt = 0UL;

  ulong epoch = fd_bank_epoch_get( bank );

  ulong total_stake = 0UL;
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_iter_ele( iter );

    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating(
        stake_delegation,
        epoch,
        history,
        new_rate_activation_epoch );

    fd_vote_ele_t * vote_ele = fd_vote_ele_map_ele_query( vote_ele_map, &stake_delegation->vote_account, NULL, runtime_stack->stakes.vote_ele );
    if( FD_UNLIKELY( !vote_ele ) ) {
      vote_ele               = &runtime_stack->stakes.vote_ele[ vote_ele_cnt ];
      vote_ele->pubkey       = stake_delegation->vote_account;
      vote_ele->vote_rewards = 0UL;
      vote_ele->stake        = 0UL;
      vote_ele->invalid      = 0;
      fd_vote_ele_map_ele_insert( vote_ele_map, vote_ele, runtime_stack->stakes.vote_ele );
      vote_ele_cnt++;
    }
    vote_ele->stake += new_entry.effective;
    total_stake += new_entry.effective;
  }
  fd_bank_total_epoch_stake_set( bank, total_stake );
}

/* https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/stakes.rs#L280 */
void
fd_stakes_activate_epoch( fd_bank_t *                    bank,
                          fd_runtime_stack_t *           runtime_stack,
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

    fd_stake_history_entry_t new_entry = fd_stake_activating_and_deactivating(
        stake_delegation,
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
                            runtime_stack,
                            stake_delegations,
                            stake_history,
                            new_rate_activation_epoch );

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
