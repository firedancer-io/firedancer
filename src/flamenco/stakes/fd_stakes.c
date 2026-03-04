#include "fd_stakes.h"
#include "../runtime/fd_bank.h"
#include "../runtime/program/fd_stake_program.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../runtime/fd_runtime_stack.h"
#include "fd_stake_delegations.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "../accdb/fd_accdb_sync.h"

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

static void
get_vote_credits_commission( uchar const *       account_data,
                             ulong               account_data_len,
                             uchar *             buf,
                             fd_vote_rewards_t * vote_ele,
                             fd_pubkey_t *       node_account_t_1 ) {

  fd_bincode_decode_ctx_t ctx = {
    .data    = account_data,
    .dataend = account_data + account_data_len,
  };

  fd_vote_state_versioned_t * vsv = fd_vote_state_versioned_decode( buf, &ctx );
  if( FD_UNLIKELY( vsv==NULL ) ) {
    FD_LOG_CRIT(( "unable to decode vote state versioned" ));
  }

  fd_vote_epoch_credits_t * vote_credits = NULL;

  switch( vsv->discriminant ) {
  case fd_vote_state_versioned_enum_v1_14_11:
    vote_credits         = vsv->inner.v1_14_11.epoch_credits;
    vote_ele->commission = vsv->inner.v1_14_11.commission;
    *node_account_t_1    = vsv->inner.v1_14_11.node_pubkey;
    break;
  case fd_vote_state_versioned_enum_v3:
    vote_credits         = vsv->inner.v3.epoch_credits;
    vote_ele->commission = vsv->inner.v3.commission;
    *node_account_t_1    = vsv->inner.v3.node_pubkey;
    break;
  case fd_vote_state_versioned_enum_v4:
    vote_credits         = vsv->inner.v4.epoch_credits;
    vote_ele->commission = (uchar)(vsv->inner.v4.inflation_rewards_commission_bps/100);
    *node_account_t_1    = vsv->inner.v4.node_pubkey;
    break;
  default:
    __builtin_unreachable();
  }

  vote_ele->epoch_credits.cnt = 0UL;
  for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( vote_credits );
       !deq_fd_vote_epoch_credits_t_iter_done( vote_credits, iter );
       iter = deq_fd_vote_epoch_credits_t_iter_next( vote_credits, iter ) ) {
    fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( vote_credits, iter );
    vote_ele->epoch_credits.epoch[ vote_ele->epoch_credits.cnt ]        = (ushort)ele->epoch;
    vote_ele->epoch_credits.credits[ vote_ele->epoch_credits.cnt ]      = ele->credits;
    vote_ele->epoch_credits.prev_credits[ vote_ele->epoch_credits.cnt ] = ele->prev_credits;
    vote_ele->epoch_credits.cnt++;
  }
}

/* We need to update the amount of stake that each vote account has for
   the given epoch.  This can only be done after the stake history
   sysvar has been updated.  We also cache the stakes for each of the
   vote accounts for the previous epoch.

   https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/stakes.rs#L471 */
void
fd_refresh_vote_accounts( fd_bank_t *                    bank,
                          fd_accdb_user_t *              accdb,
                          fd_funk_txn_xid_t const *      xid,
                          fd_runtime_stack_t *           runtime_stack,
                          fd_stake_delegations_t const * stake_delegations,
                          fd_stake_history_t const *     history,
                          ulong *                        new_rate_activation_epoch ) {

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes_locking_modify( bank );

  ushort parent_idx = bank->data->vote_stakes_fork_id;
  ushort child_idx  = fd_vote_stakes_new_child( vote_stakes );

  bank->data->vote_stakes_fork_id = child_idx;


  uchar __attribute__((aligned(128))) vsv_buf[ FD_VOTE_STATE_VERSIONED_FOOTPRINT ];

  fd_vote_rewards_map_t * vote_ele_map = fd_type_pun( runtime_stack->stakes.vote_map_mem );
  fd_vote_rewards_map_reset( vote_ele_map );
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

    fd_vote_rewards_t * vote_ele = fd_vote_rewards_map_ele_query( vote_ele_map, &stake_delegation->vote_account, NULL, runtime_stack->stakes.vote_ele );
    if( FD_UNLIKELY( !vote_ele ) ) {
      vote_ele               = &runtime_stack->stakes.vote_ele[ vote_ele_cnt ];
      vote_ele->pubkey       = stake_delegation->vote_account;
      vote_ele->vote_rewards = 0UL;
      vote_ele->invalid      = 0;

      fd_accdb_ro_t vote_ro[1];
      if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, vote_ro, xid, &vote_ele->pubkey ) ) ) {
        vote_ele->invalid = 1;
      }

      if( FD_UNLIKELY( !fd_vsv_is_correct_size_and_initialized( vote_ro->meta ) ) ) {
        fd_accdb_close_ro( accdb, vote_ro );
        vote_ele->invalid = 1;
      }

      fd_pubkey_t node_account_t_1;
      if( FD_LIKELY( !vote_ele->invalid ) ) {
        get_vote_credits_commission( fd_accdb_ref_data_const( vote_ro ),
                                     fd_accdb_ref_data_sz( vote_ro ),
                                     vsv_buf,
                                     &runtime_stack->stakes.vote_ele[ vote_ele_cnt ],
                                     &node_account_t_1 );
        fd_accdb_close_ro( accdb, vote_ro );
      }

      fd_vote_rewards_map_ele_insert( vote_ele_map, vote_ele, runtime_stack->stakes.vote_ele );
      vote_ele_cnt++;

      ulong       old_stake_t_1;
      fd_pubkey_t node_account_t_2;
      int found = fd_vote_stakes_query( vote_stakes, parent_idx, &vote_ele->pubkey, &old_stake_t_1, NULL, &node_account_t_2, NULL );
      ulong stake_t_2 = found ? old_stake_t_1 : 0UL;

      fd_vote_stakes_insert_key( vote_stakes,
                                 child_idx,
                                 &stake_delegation->vote_account,
                                 &node_account_t_1,
                                 &node_account_t_2,
                                 stake_t_2,
                                 fd_bank_epoch_get( bank ) );
    }

    fd_vote_stakes_insert_update( vote_stakes,
                                  child_idx,
                                  &vote_ele->pubkey,
                                  new_entry.effective );

    total_stake += new_entry.effective;
  }
  fd_bank_total_epoch_stake_set( bank, total_stake );

  fd_vote_stakes_insert_fini( vote_stakes, child_idx );

  fd_bank_vote_stakes_end_locking_modify( bank );
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
                            accdb,
                            xid,
                            runtime_stack,
                            stake_delegations,
                            stake_history,
                            new_rate_activation_epoch );

}

void
fd_stakes_update_stake_delegation( fd_pubkey_t const *       pubkey,
                                   fd_account_meta_t const * meta,
                                   fd_bank_t *               bank ) {

  fd_stake_delegations_delta_t * stake_delegations_delta = fd_bank_stake_delegations_delta_locking_modify( bank );

  if( meta->lamports==0UL ) {
    fd_stake_delegations_delta_remove( stake_delegations_delta, bank->data->stake_delegations_fork_id, pubkey );
    fd_bank_stake_delegations_delta_end_locking_modify( bank );
    return;
  }

  fd_stake_state_v2_t stake_state;
  int err = fd_stake_get_state( meta, &stake_state );
  if( FD_UNLIKELY( err!=0 ) ) {
    fd_stake_delegations_delta_remove( stake_delegations_delta, bank->data->stake_delegations_fork_id, pubkey );
    fd_bank_stake_delegations_delta_end_locking_modify( bank );
    return;
  }

  if( FD_UNLIKELY( !fd_stake_state_v2_is_stake( &stake_state ) ) ) {
    fd_stake_delegations_delta_remove( stake_delegations_delta, bank->data->stake_delegations_fork_id, pubkey );
    fd_bank_stake_delegations_delta_end_locking_modify( bank );
    return;
  }

  if( FD_UNLIKELY( fd_stake_state_v2_is_uninitialized( &stake_state ) ) ) {
    fd_stake_delegations_delta_remove( stake_delegations_delta, bank->data->stake_delegations_fork_id, pubkey );
    fd_bank_stake_delegations_delta_end_locking_modify( bank );
    return;
  }

  if( FD_UNLIKELY( stake_state.inner.stake.stake.delegation.stake==0UL ) ) {
    fd_stake_delegations_delta_remove( stake_delegations_delta, bank->data->stake_delegations_fork_id, pubkey );
    fd_bank_stake_delegations_delta_end_locking_modify( bank );
    return;
  }

  fd_stake_delegations_delta_update( stake_delegations_delta, bank->data->stake_delegations_fork_id, pubkey,
                                     &stake_state.inner.stake.stake.delegation.voter_pubkey,
                                     stake_state.inner.stake.stake.delegation.stake,
                                     stake_state.inner.stake.stake.delegation.activation_epoch,
                                     stake_state.inner.stake.stake.delegation.deactivation_epoch,
                                     stake_state.inner.stake.stake.credits_observed,
                                     stake_state.inner.stake.stake.delegation.warmup_cooldown_rate );

  fd_bank_stake_delegations_delta_end_locking_modify( bank );
}
