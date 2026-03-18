#include <limits.h>

#include "fd_stakes.h"
#include "../runtime/fd_bank.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../runtime/fd_runtime_stack.h"
#include "../runtime/fd_system_ids.h"
#include "fd_stake_delegations.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "../accdb/fd_accdb_sync.h"
#include "../../util/bits/fd_sat.h"

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

#define DEFAULT_WARMUP_COOLDOWN_RATE               ( 0.25 )
#define NEW_WARMUP_COOLDOWN_RATE                   ( 0.09 )
#define DEFAULT_SLASH_PENALTY                      ( 12 )

/**********************************************************************/
/* Types                                                              */
/**********************************************************************/

struct effective_activating {
  ulong effective;
  ulong activating;
};
typedef struct effective_activating effective_activating_t;

typedef fd_stake_history_entry_t fd_stake_activation_status_t;

/**********************************************************************/
/* Static helpers                                                     */
/**********************************************************************/

static inline double
warmup_cooldown_rate( ulong current_epoch, ulong * new_rate_activation_epoch ) {
  ulong activation_epoch = new_rate_activation_epoch ? *new_rate_activation_epoch : ULONG_MAX;
  return current_epoch<activation_epoch ? DEFAULT_WARMUP_COOLDOWN_RATE : NEW_WARMUP_COOLDOWN_RATE;
}

static fd_stake_history_entry_t const *
fd_stake_history_ele_binary_search_const( fd_stake_history_t const * history,
                                          ulong epoch ) {
  ulong start = 0UL;
  ulong end  = history->fd_stake_history_len - 1;

  while ( start<=end ) {
    ulong mid = start + ( end - start ) / 2UL;
    if( history->fd_stake_history[mid].epoch==epoch ) {
      return &history->fd_stake_history[mid].entry;
    } else if( history->fd_stake_history[mid].epoch<epoch ) {
      if ( mid==0 ) return NULL;
      end = mid - 1;
    } else {
      start = mid + 1;
    }
  }
  return NULL;
}

static fd_stake_history_entry_t const *
fd_stake_history_ele_query_const( fd_stake_history_t const * history,
                                  ulong epoch ) {
  if( 0 == history->fd_stake_history_len ) {
    return NULL;
  }

  if( epoch > history->fd_stake_history[0].epoch ) {
    return NULL;
  }

  ulong off = (history->fd_stake_history[0].epoch - epoch);
  if( off >= history->fd_stake_history_len ) {
    return fd_stake_history_ele_binary_search_const( history, epoch );
  }

  ulong e = (off + history->fd_stake_history_offset) & (history->fd_stake_history_size - 1);

  if ( history->fd_stake_history[e].epoch == epoch ) {
    return &history->fd_stake_history[e].entry;
  }

  return fd_stake_history_ele_binary_search_const( history, epoch );
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L728
static effective_activating_t
stake_and_activating( fd_delegation_t const *    self,
                      ulong                      target_epoch,
                      fd_stake_history_t const * history,
                      ulong *                    new_rate_activation_epoch ) {
  ulong delegated_stake = self->stake;

  fd_stake_history_entry_t const * cluster_stake_at_activation_epoch;
  if( self->activation_epoch==ULONG_MAX ) {
    return ( effective_activating_t ){ .effective = delegated_stake, .activating = 0 };
  } else if( self->activation_epoch==self->deactivation_epoch ) {
    return ( effective_activating_t ){ .effective = 0, .activating = 0 };
  } else if( target_epoch==self->activation_epoch ) {
    return ( effective_activating_t ){ .effective = 0, .activating = delegated_stake };
  } else if( target_epoch<self->activation_epoch ) {
    return ( effective_activating_t ){ .effective = 0, .activating = 0 };
  } else if( history &&
              ( cluster_stake_at_activation_epoch = fd_stake_history_ele_query_const(
                    history, self->activation_epoch ) ) ) {
    ulong                            prev_epoch         = self->activation_epoch;
    fd_stake_history_entry_t const * prev_cluster_stake = cluster_stake_at_activation_epoch;

    ulong current_epoch;
    ulong current_effective_stake = 0;
    for( ;; ) {
      current_epoch = prev_epoch + 1;
      if( FD_LIKELY( prev_cluster_stake->activating==0 ) ) {
        break;
      }

      ulong  remaining_activating_stake = delegated_stake - current_effective_stake;
      double weight = (double)remaining_activating_stake / (double)prev_cluster_stake->activating;
      double warmup_cooldown_rate_ =
          warmup_cooldown_rate( current_epoch, new_rate_activation_epoch );

      double newly_effective_cluster_stake =
          (double)prev_cluster_stake->effective * warmup_cooldown_rate_;
      ulong newly_effective_stake =
          fd_ulong_max( fd_rust_cast_double_to_ulong( weight * newly_effective_cluster_stake ), 1 );

      current_effective_stake += newly_effective_stake;
      if( FD_LIKELY( current_effective_stake>=delegated_stake ) ) {
        current_effective_stake = delegated_stake;
        break;
      }

      if( FD_LIKELY( current_epoch>=target_epoch ||
                     current_epoch>=self->deactivation_epoch ) ) {
        break;
      }

      fd_stake_history_entry_t const * current_cluster_stake =
          fd_stake_history_ele_query_const( history, current_epoch );
      if( FD_LIKELY( current_cluster_stake ) ) {
        prev_epoch         = current_epoch;
        prev_cluster_stake = current_cluster_stake;
      } else {
        break;
      }
    }
    return ( effective_activating_t ){ .effective  = current_effective_stake,
                                       .activating = delegated_stake - current_effective_stake };
  } else {
    return ( effective_activating_t ){ .effective = delegated_stake, .activating = 0 };
  }
}

// https://github.com/anza-xyz/agave/blob/c8685ce0e1bb9b26014f1024de2cd2b8c308cbde/sdk/program/src/stake/state.rs#L641
static fd_stake_activation_status_t
stake_activating_and_deactivating( fd_delegation_t const *    self,
                                   ulong                      target_epoch,
                                   fd_stake_history_t const * stake_history,
                                   ulong *                    new_rate_activation_epoch ) {

  effective_activating_t effective_activating =
      stake_and_activating( self, target_epoch, stake_history, new_rate_activation_epoch );

  ulong effective_stake  = effective_activating.effective;
  ulong activating_stake = effective_activating.activating;

  fd_stake_history_entry_t const * cluster_stake_at_deactivation_epoch = NULL;

  if( target_epoch<self->deactivation_epoch ) {
    if( activating_stake==0 ) {
      return ( fd_stake_history_entry_t ){
          .effective = effective_stake, .deactivating = 0, .activating = 0 };
    } else {
      return ( fd_stake_history_entry_t ){
          .effective = effective_stake, .deactivating = 0, .activating = activating_stake };
    }
  } else if( target_epoch==self->deactivation_epoch ) {
    return ( fd_stake_history_entry_t ){
        .effective = effective_stake, .deactivating = effective_stake, .activating = 0 };
  } else if( stake_history &&
             ( cluster_stake_at_deactivation_epoch = fd_stake_history_ele_query_const( stake_history, self->deactivation_epoch ) ) ) {
    ulong                      prev_epoch         = self->deactivation_epoch;
    fd_stake_history_entry_t const * prev_cluster_stake = cluster_stake_at_deactivation_epoch;

    ulong current_epoch;
    ulong current_effective_stake = effective_stake;
    for( ;; ) {
      current_epoch = prev_epoch + 1;
      if( prev_cluster_stake->deactivating==0 ) break;

      double weight = (double)current_effective_stake / (double)prev_cluster_stake->deactivating;
      double warmup_cooldown_rate_ =
          warmup_cooldown_rate( current_epoch, new_rate_activation_epoch );

      double newly_not_effective_cluster_stake =
          (double)prev_cluster_stake->effective * warmup_cooldown_rate_;
      ulong newly_not_effective_stake =
          fd_ulong_max( fd_rust_cast_double_to_ulong( weight * newly_not_effective_cluster_stake ), 1 );

      current_effective_stake =
          fd_ulong_sat_sub( current_effective_stake, newly_not_effective_stake );
      if( current_effective_stake==0 ) break;

      if( current_epoch>=target_epoch ) break;

      fd_stake_history_entry_t const * current_cluster_stake = NULL;
      if( ( current_cluster_stake = fd_stake_history_ele_query_const(stake_history, current_epoch ) ) ) {
        prev_epoch         = current_epoch;
        prev_cluster_stake = current_cluster_stake;
      } else {
        break;
      }
    }
    return ( fd_stake_history_entry_t ){ .effective    = current_effective_stake,
                                         .deactivating = current_effective_stake,
                                         .activating   = 0 };
  } else {
    return ( fd_stake_history_entry_t ){ .effective = 0, .activating = 0, .deactivating = 0 };
  }
}

static void
write_stake_config( fd_accdb_user_t *         accdb,
                    fd_funk_txn_xid_t const * xid,
                    fd_stake_config_t const * stake_config ) {
  ulong               data_sz = fd_stake_config_size( stake_config );
  fd_pubkey_t const * address = &fd_solana_stake_program_config_id;

  fd_accdb_rw_t rw[1];
  fd_accdb_open_rw( accdb, rw, xid, address, data_sz, FD_ACCDB_FLAG_CREATE );

  /* FIXME update capitalization? */
  /* FIXME set owner to Config program? */
  /* FIXME Agave reflink? */
  /* FIXME derive lamport balance from rent instead of hardcoding */

  fd_accdb_ref_lamports_set( rw, 960480UL );
  fd_accdb_ref_exec_bit_set( rw, 0 );
  fd_accdb_ref_data_sz_set( accdb, rw, data_sz, 0 );
  fd_bincode_encode_ctx_t ctx = {
    .data    = fd_accdb_ref_data( rw ),
    .dataend = (uchar *)fd_accdb_ref_data( rw ) + data_sz
  };
  if( fd_stake_config_encode( stake_config, &ctx ) )
    FD_LOG_ERR( ( "fd_stake_config_encode failed" ) );

  fd_accdb_close_rw( accdb, rw );
}

/**********************************************************************/
/* Public API                                                         */
/**********************************************************************/

int
fd_stakes_new_warmup_cooldown_rate_epoch(
    fd_epoch_schedule_t const * epoch_schedule,
    fd_features_t const *       features,
    /* out */ ulong *           epoch,
    int *                       err
) {
  *err = 0;

  if( FD_UNLIKELY( !epoch_schedule ) ) {
    *epoch = ULONG_MAX;
    *err   = FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    return 1;
  }
  *epoch = fd_slot_to_epoch( epoch_schedule, features->reduce_stake_warmup_cooldown, NULL );
  return 1;
}

void
fd_stakes_config_init( fd_accdb_user_t *         accdb,
                       fd_funk_txn_xid_t const * xid ) {
  fd_stake_config_t stake_config = {
      .warmup_cooldown_rate = DEFAULT_WARMUP_COOLDOWN_RATE,
      .slash_penalty        = DEFAULT_SLASH_PENALTY,
  };
  write_stake_config( accdb, xid, &stake_config );
}

int
fd_stakes_get_state( fd_account_meta_t const * meta,
                     fd_stake_state_v2_t *     out ) {
  int rc;

  fd_bincode_decode_ctx_t bincode_ctx = {
    .data    = fd_account_data( meta ),
    .dataend = fd_account_data( meta ) + meta->dlen,
  };

  ulong total_sz = 0UL;
  rc = fd_stake_state_v2_decode_footprint( &bincode_ctx, &total_sz );
  if( FD_UNLIKELY( rc!=FD_BINCODE_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  fd_stake_state_v2_decode( out, &bincode_ctx );

  return 0;
}

fd_stake_history_entry_t
fd_stakes_activating_and_deactivating( fd_stake_delegation_t const * stake_delegation,
                                       ulong                         target_epoch,
                                       fd_stake_history_t const *    stake_history,
                                       ulong *                       new_rate_activation_epoch ) {
  fd_delegation_t delegation = {
    .voter_pubkey         = stake_delegation->vote_account,
    .stake                = stake_delegation->stake,
    .deactivation_epoch   = stake_delegation->deactivation_epoch==USHORT_MAX ? ULONG_MAX : stake_delegation->deactivation_epoch,
    .activation_epoch     = stake_delegation->activation_epoch==USHORT_MAX ? ULONG_MAX : stake_delegation->activation_epoch,
    .warmup_cooldown_rate = fd_stake_delegations_warmup_cooldown_rate_to_double( stake_delegation->warmup_cooldown_rate ),
  };

  return stake_activating_and_deactivating(
    &delegation, target_epoch, stake_history, new_rate_activation_epoch );
}

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

ulong
fd_stake_weights_by_node_next( fd_vote_stakes_t *       vote_stakes,
                               ushort                   fork_idx,
                               fd_vote_stake_weight_t * weights ) {
  ulong weights_cnt = 0;
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_fork_iter_init( vote_stakes, fork_idx, iter_mem );
       !fd_vote_stakes_fork_iter_done( vote_stakes, fork_idx, iter  );
       fd_vote_stakes_fork_iter_next( vote_stakes, fork_idx, iter ) ) {
    fd_pubkey_t pubkey;
    ulong       stake_t_1;
    fd_pubkey_t node_account_t_1;
    fd_vote_stakes_fork_iter_ele( vote_stakes, fork_idx, iter, &pubkey, &stake_t_1, NULL, &node_account_t_1, NULL );
    if( FD_UNLIKELY( !stake_t_1 ) ) continue;

    fd_memcpy( weights[ weights_cnt ].vote_key.uc, &pubkey, sizeof(fd_pubkey_t) );
    fd_memcpy( weights[ weights_cnt ].id_key.uc, &node_account_t_1, sizeof(fd_pubkey_t) );
    weights[ weights_cnt ].stake = stake_t_1;
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
                             fd_pubkey_t *       node_account_t_1,
                             ulong *             last_vote_slot,
                             long *              last_vote_timestamp ) {

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
    *last_vote_slot      = vsv->inner.v1_14_11.last_timestamp.slot;
    *last_vote_timestamp = vsv->inner.v1_14_11.last_timestamp.timestamp;
    break;
  case fd_vote_state_versioned_enum_v3:
    vote_credits         = vsv->inner.v3.epoch_credits;
    vote_ele->commission = vsv->inner.v3.commission;
    *node_account_t_1    = vsv->inner.v3.node_pubkey;
    *last_vote_slot      = vsv->inner.v3.last_timestamp.slot;
    *last_vote_timestamp = vsv->inner.v3.last_timestamp.timestamp;
    break;
  case fd_vote_state_versioned_enum_v4:
    vote_credits         = vsv->inner.v4.epoch_credits;
    vote_ele->commission = (uchar)(vsv->inner.v4.inflation_rewards_commission_bps/100);
    *node_account_t_1    = vsv->inner.v4.node_pubkey;
    *last_vote_slot      = vsv->inner.v4.last_timestamp.slot;
    *last_vote_timestamp = vsv->inner.v4.last_timestamp.timestamp;
    break;
  default:
    FD_LOG_CRIT(( "invalid vote state version %u", vsv->discriminant ));
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

  fd_top_votes_t * top_votes = fd_bank_top_votes_modify( bank );
  fd_top_votes_init( top_votes );

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

    fd_stake_history_entry_t new_entry = fd_stakes_activating_and_deactivating(
        stake_delegation,
        epoch,
        history,
        new_rate_activation_epoch );

    if( FD_UNLIKELY( !fd_vote_stakes_query_pubkey( vote_stakes, child_idx, &stake_delegation->vote_account ) ) ) {
      fd_accdb_ro_t vote_ro[1];

      ulong       old_stake_t_1        = 0UL;
      fd_pubkey_t old_node_account_t_1 = {0};
      int exists_prev = fd_vote_stakes_query_t_1( vote_stakes, parent_idx, &stake_delegation->vote_account, &old_stake_t_1, &old_node_account_t_1 );
      int exists_curr = 1;
      if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, vote_ro, xid, &stake_delegation->vote_account ) ) ) {
        exists_curr = 0;
      } else if( FD_UNLIKELY( !fd_vsv_is_correct_size_and_initialized( vote_ro->meta ) ) ) {
        fd_accdb_close_ro( accdb, vote_ro );
        exists_curr = 0;
      }

      if( FD_UNLIKELY( !exists_curr ) ) {
        /* If the vote account does not exist going into the epoch
           boundary, and did not exist at the end of the last epoch
           boundary, then we can fully skip it. */
        if( FD_UNLIKELY( !exists_prev ) ) continue;

        /* If the account does not exist but did in the previous epoch,
           it still needs to be added to the top votes and the vote
           stakes data structure in case the vote account is revived
           again. */
        fd_top_votes_insert( top_votes,
                             &stake_delegation->vote_account,
                             &old_node_account_t_1,
                             old_stake_t_1,
                             0UL,
                             0L );
        fd_top_votes_invalidate( top_votes, &stake_delegation->vote_account );

        fd_vote_stakes_insert_key(
            vote_stakes,
            child_idx,
            &stake_delegation->vote_account,
            &old_node_account_t_1,
            &old_node_account_t_1,
            old_stake_t_1,
            fd_bank_epoch_get( bank ),
            0 );
      } else {
        /* If the account currently exists, we need to insert the entry
           into the vote stakes data structure.  We will treat the t-2
           stake as 0 if the account did not exist at the end of the
           last epoch boundary.*/
        fd_pubkey_t curr_node_account_t_1;
        ulong       last_vote_slot;
        long        last_vote_timestamp;
        get_vote_credits_commission( fd_accdb_ref_data_const( vote_ro ),
                                    fd_accdb_ref_data_sz( vote_ro ),
                                    vsv_buf,
                                    &runtime_stack->stakes.vote_ele[ vote_ele_cnt ],
                                    &curr_node_account_t_1,
                                    &last_vote_slot,
                                    &last_vote_timestamp );
        fd_accdb_close_ro( accdb, vote_ro );

        /* If old_node_account_t_1 gets zero-initialized which means
           that it is still valid to use. */
        fd_vote_stakes_insert_key(
            vote_stakes,
            child_idx,
            &stake_delegation->vote_account,
            &curr_node_account_t_1,
            &old_node_account_t_1,
            old_stake_t_1,
            fd_bank_epoch_get( bank ),
            1 );

        fd_top_votes_insert(
            top_votes,
            &stake_delegation->vote_account,
            &old_node_account_t_1,
            old_stake_t_1,
            last_vote_slot,
            last_vote_timestamp );

        fd_vote_rewards_t * vote_ele = &runtime_stack->stakes.vote_ele[ vote_ele_cnt ];
        vote_ele->pubkey             = stake_delegation->vote_account;
        vote_ele->vote_rewards       = 0UL;
        fd_vote_rewards_map_ele_insert( vote_ele_map, vote_ele, runtime_stack->stakes.vote_ele );
        vote_ele_cnt++;
      }
    }

    fd_vote_stakes_insert_update( vote_stakes,
                                  child_idx,
                                  &stake_delegation->vote_account,
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

    fd_stake_history_entry_t new_entry = fd_stakes_activating_and_deactivating(
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
  int err = fd_stakes_get_state( meta, &stake_state );
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
