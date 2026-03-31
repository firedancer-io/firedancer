#include <limits.h>

#include "fd_stakes.h"
#include "../runtime/fd_bank.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../runtime/sysvar/fd_sysvar_cache.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../runtime/fd_runtime_stack.h"
#include "../runtime/fd_system_ids.h"
#include "fd_stake_delegations.h"
#include "../accdb/fd_accdb_sync.h"
#include "../../util/bits/fd_sat.h"
#include "fd_stake_types.h"

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
fd_stake_history_entry_t
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

void
fd_stakes_config_init( fd_accdb_user_t *         accdb,
                       fd_funk_txn_xid_t const * xid ) {
  fd_stake_config_t stake_config = {
      .warmup_cooldown_rate = DEFAULT_WARMUP_COOLDOWN_RATE,
      .slash_penalty        = DEFAULT_SLASH_PENALTY,
  };
  write_stake_config( accdb, xid, &stake_config );
}

fd_stake_state_t const *
fd_stake_state_view( uchar const * data,
                     ulong         data_sz ) {
  if( FD_UNLIKELY( data_sz<4UL ) ) return NULL;
  uint stake_type = FD_LOAD( uint, data );
  switch( stake_type ) {
  case FD_STAKE_STATE_UNINITIALIZED:
    break;
  case FD_STAKE_STATE_INITIALIZED:
    if( FD_UNLIKELY( data_sz<124 ) ) return NULL;
    break;
  case FD_STAKE_STATE_STAKE:
    if( FD_UNLIKELY( data_sz<197 ) ) return NULL;
    break;
  case FD_STAKE_STATE_REWARDS_POOL:
    break;
  default:
    return NULL;
  }
  return fd_type_pun_const( data );
}

fd_stake_state_t const *
fd_stakes_get_state( fd_account_meta_t const * meta ) {
  if( FD_UNLIKELY( 0!=memcmp( meta->owner, &fd_solana_stake_program_id, sizeof(fd_pubkey_t) ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( meta->lamports==0UL ) ) return NULL;
  return fd_stake_state_view( fd_account_data( meta ), meta->dlen );
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
fd_stake_weights_by_node( fd_top_votes_t const *   top_votes_t_2,
                          fd_vote_stakes_t *       vote_stakes,
                          ushort                   fork_idx,
                          fd_vote_stake_weight_t * weights,
                          int                      vat_enabled ) {
  ulong weights_cnt = 0;
  if( vat_enabled ) {
    uchar __attribute__((aligned(FD_TOP_VOTES_ITER_ALIGN))) iter_mem[ FD_TOP_VOTES_ITER_FOOTPRINT ];
    for( fd_top_votes_iter_t * iter = fd_top_votes_iter_init( top_votes_t_2, iter_mem );
         !fd_top_votes_iter_done( top_votes_t_2, iter );
         fd_top_votes_iter_next( top_votes_t_2, iter ) ) {
      fd_pubkey_t pubkey;
      ulong       stake_t_2;
      fd_pubkey_t node_account_t_2;
      fd_top_votes_iter_ele( top_votes_t_2, iter, &pubkey, &node_account_t_2, &stake_t_2, NULL, NULL, NULL );

      fd_memcpy( weights[ weights_cnt ].vote_key.uc, &pubkey, sizeof(fd_pubkey_t) );
      fd_memcpy( weights[ weights_cnt ].id_key.uc, &node_account_t_2, sizeof(fd_pubkey_t) );
      weights[ weights_cnt ].stake = stake_t_2;
      weights_cnt++;
    }
  } else {
    uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
    for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_fork_iter_init( vote_stakes, fork_idx, iter_mem );
         !fd_vote_stakes_fork_iter_done( vote_stakes, fork_idx, iter  );
         fd_vote_stakes_fork_iter_next( vote_stakes, fork_idx, iter ) ) {
      fd_pubkey_t pubkey;
      ulong       stake_t_2;
      fd_pubkey_t node_account_t_2;
      fd_vote_stakes_fork_iter_ele( vote_stakes, fork_idx, iter, &pubkey, NULL, &stake_t_2, NULL, &node_account_t_2, NULL, NULL );
      if( FD_UNLIKELY( !stake_t_2 ) ) continue;

      fd_memcpy( weights[ weights_cnt ].vote_key.uc, &pubkey, sizeof(fd_pubkey_t) );
      fd_memcpy( weights[ weights_cnt ].id_key.uc, &node_account_t_2, sizeof(fd_pubkey_t) );
      weights[ weights_cnt ].stake = stake_t_2;
      weights_cnt++;
    }
    fd_vote_stakes_fork_iter_fini( vote_stakes );
  }

  sort_vote_weights_by_stake_vote_inplace( weights, weights_cnt );

  return weights_cnt;
}

ulong
fd_stake_weights_by_node_next( fd_top_votes_t const *   top_votes_t_1,
                               fd_vote_stakes_t *       vote_stakes,
                               ushort                   fork_idx,
                               fd_vote_stake_weight_t * weights,
                               int                      vat_enabled ) {

  ulong weights_cnt = 0;
  if( vat_enabled ) {
    uchar __attribute__((aligned(FD_TOP_VOTES_ITER_ALIGN))) iter_mem[ FD_TOP_VOTES_ITER_FOOTPRINT ];
    for( fd_top_votes_iter_t * iter = fd_top_votes_iter_init( top_votes_t_1, iter_mem );
         !fd_top_votes_iter_done( top_votes_t_1, iter );
         fd_top_votes_iter_next( top_votes_t_1, iter ) ) {
      fd_pubkey_t pubkey;
      ulong       stake_t_1;
      fd_pubkey_t node_account_t_1;
      fd_top_votes_iter_ele( top_votes_t_1, iter, &pubkey, &node_account_t_1, &stake_t_1, NULL, NULL, NULL );

      fd_memcpy( weights[ weights_cnt ].vote_key.uc, &pubkey, sizeof(fd_pubkey_t) );
      fd_memcpy( weights[ weights_cnt ].id_key.uc, &node_account_t_1, sizeof(fd_pubkey_t) );
      weights[ weights_cnt ].stake = stake_t_1;
      weights_cnt++;
    }
  } else {
    uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
    for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_fork_iter_init( vote_stakes, fork_idx, iter_mem );
         !fd_vote_stakes_fork_iter_done( vote_stakes, fork_idx, iter );
         fd_vote_stakes_fork_iter_next( vote_stakes, fork_idx, iter ) ) {

      fd_pubkey_t pubkey;
      ulong       stake_t_1;
      fd_pubkey_t node_account_t_1;
      fd_vote_stakes_fork_iter_ele( vote_stakes, fork_idx, iter, &pubkey, &stake_t_1, NULL, &node_account_t_1, NULL, NULL, NULL );
      if( FD_UNLIKELY( !stake_t_1 ) ) continue;

      fd_memcpy( weights[ weights_cnt ].vote_key.uc, &pubkey, sizeof(fd_pubkey_t) );
      fd_memcpy( weights[ weights_cnt ].id_key.uc, &node_account_t_1, sizeof(fd_pubkey_t) );
      weights[ weights_cnt ].stake = stake_t_1;
      weights_cnt++;
    }
    fd_vote_stakes_fork_iter_fini( vote_stakes );
  }

  sort_vote_weights_by_stake_vote_inplace( weights, weights_cnt );

  return weights_cnt;
}

static void
get_vote_credits_commission( uchar const *        account_data,
                             ulong                account_data_len,
                             uchar *              buf,
                             uchar *              commission_t_1,
                             fd_pubkey_t *        node_account_t_1,
                             fd_epoch_credits_t * epoch_credits_opt ) {

  fd_bincode_decode_ctx_t ctx = {
    .data    = account_data,
    .dataend = account_data + account_data_len,
  };

  fd_vote_state_versioned_t * vsv = fd_vote_state_versioned_decode( buf, &ctx );
  if( FD_UNLIKELY( vsv==NULL ) ) {
    FD_LOG_CRIT(( "unable to decode vote state versioned" ));
  }
  fd_vote_epoch_credits_t * vote_epoch_credits = NULL;

  switch( vsv->discriminant ) {
  case fd_vote_state_versioned_enum_v1_14_11:
    *commission_t_1      = vsv->inner.v1_14_11.commission;
    *node_account_t_1    = vsv->inner.v1_14_11.node_pubkey;
    vote_epoch_credits   = vsv->inner.v1_14_11.epoch_credits;
    break;
  case fd_vote_state_versioned_enum_v3:
    *commission_t_1      = vsv->inner.v3.commission;
    *node_account_t_1    = vsv->inner.v3.node_pubkey;
    vote_epoch_credits   = vsv->inner.v3.epoch_credits;
    break;
  case fd_vote_state_versioned_enum_v4:
    *commission_t_1      = (uchar)(vsv->inner.v4.inflation_rewards_commission_bps/100);
    *node_account_t_1    = vsv->inner.v4.node_pubkey;
    vote_epoch_credits   = vsv->inner.v4.epoch_credits;
    break;
  default:
    FD_LOG_CRIT(( "invalid vote state version %u", vsv->discriminant ));
  }

  if( !epoch_credits_opt ) return;
  epoch_credits_opt->cnt          = 0UL;
  epoch_credits_opt->base_credits = 0UL;

  deq_fd_vote_epoch_credits_t_iter_t first = deq_fd_vote_epoch_credits_t_iter_init( vote_epoch_credits );
  if( !deq_fd_vote_epoch_credits_t_iter_done( vote_epoch_credits, first ) ) {
    fd_vote_epoch_credits_t * first_ele = deq_fd_vote_epoch_credits_t_iter_ele( vote_epoch_credits, first );
    epoch_credits_opt->base_credits = first_ele->prev_credits;
  }

  ulong base = epoch_credits_opt->base_credits;
  for( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( vote_epoch_credits );
       !deq_fd_vote_epoch_credits_t_iter_done( vote_epoch_credits, iter );
       iter = deq_fd_vote_epoch_credits_t_iter_next( vote_epoch_credits, iter ) ) {
    fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( vote_epoch_credits, iter );
    ulong i = epoch_credits_opt->cnt;
    epoch_credits_opt->epoch[ i ]              = (ushort)ele->epoch;
    epoch_credits_opt->credits_delta[ i ]      = (uint)( ele->credits      - base );
    epoch_credits_opt->prev_credits_delta[ i ] = (uint)( ele->prev_credits - base );
    epoch_credits_opt->cnt++;
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

  fd_vote_rewards_map_t * vote_reward_map = runtime_stack->stakes.vote_map;
  fd_vote_rewards_map_reset( vote_reward_map );
  ulong vote_reward_cnt = 0UL;

  uchar __attribute__((aligned(128))) vsv_buf[ FD_VOTE_STATE_VERSIONED_FOOTPRINT ];

  /* First accumulate stakes across all delegations for all vote
     accounts.  At this point, don't care if they are valid accounts or
     if they will be inserted into the top votes set. */

  fd_stake_accum_t *     stake_accum_pool = runtime_stack->stakes.stake_accum;
  fd_stake_accum_map_t * stake_accum_map  = runtime_stack->stakes.stake_accum_map;

  fd_stake_accum_map_reset( runtime_stack->stakes.stake_accum_map );
  ulong epoch              = bank->f.epoch;
  ulong total_stake        = 0UL;
  ulong total_activating   = 0UL;
  ulong total_deactivating = 0UL;
  ulong staked_accounts    = 0UL;
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
    total_stake        += new_entry.effective;
    total_activating   += new_entry.activating;
    total_deactivating += new_entry.deactivating;

    fd_stake_accum_t * stake_accum = fd_stake_accum_map_ele_query( stake_accum_map, &stake_delegation->vote_account, NULL, stake_accum_pool );
    if( FD_UNLIKELY( !stake_accum ) ) {
      if( FD_UNLIKELY( staked_accounts>=runtime_stack->max_vote_accounts ) ) {
        FD_LOG_ERR(( "invariant violation: staked_accounts >= max_vote_accounts" ));
      }
      stake_accum = &runtime_stack->stakes.stake_accum[ staked_accounts ];
      stake_accum->pubkey = stake_delegation->vote_account;
      stake_accum->stake  = new_entry.effective;
      fd_stake_accum_map_ele_insert( stake_accum_map, stake_accum, stake_accum_pool );
      staked_accounts++;
    } else {
      stake_accum->stake += new_entry.effective;
    }
  }

  /* Only update total_*_stake at the epoch boundary.  These values
     are snapshots of the stake totals for the current epoch. */
  bank->f.total_activating_stake   = total_activating;
  bank->f.total_deactivating_stake = total_deactivating;
  bank->f.total_epoch_stake        = total_stake;

  /* Copy the top votes set for the t-1 epoch into the t-2 epoch now
     that the epoch boundary is being crossed.  Reset the existing t-1
     top votes set to prepare it for insertion.  Refresh the states of
     the t-2 top votes set: figure out if the account still exists and
     what the last vote timestamp and slot are. */

  fd_top_votes_t * top_votes_t_1 = fd_bank_top_votes_t_1_modify( bank );
  fd_top_votes_t * top_votes_t_2 = fd_bank_top_votes_t_2_modify( bank );
  fd_memcpy( top_votes_t_2, top_votes_t_1, FD_TOP_VOTES_MAX_FOOTPRINT );
  fd_top_votes_init( top_votes_t_1 );

  uchar __attribute__((aligned(FD_TOP_VOTES_ITER_ALIGN))) top_votes_iter_mem[ FD_TOP_VOTES_ITER_FOOTPRINT ];
  for( fd_top_votes_iter_t * iter = fd_top_votes_iter_init( top_votes_t_2, top_votes_iter_mem );
       !fd_top_votes_iter_done( top_votes_t_2, iter );
       fd_top_votes_iter_next( top_votes_t_2, iter ) ) {
    fd_pubkey_t pubkey;
    uchar       commission_t_2;
    fd_top_votes_iter_ele( top_votes_t_2, iter, &pubkey, NULL, NULL, &commission_t_2, NULL, NULL );

    fd_accdb_ro_t vote_ro[1];
    if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, vote_ro, xid, &pubkey ) ) ) {
      fd_top_votes_invalidate( top_votes_t_2, &pubkey );
      continue;
    }
    if( FD_UNLIKELY( !fd_vsv_is_correct_size_and_initialized( vote_ro->meta ) ) ) {
      fd_top_votes_invalidate( top_votes_t_2, &pubkey );
      fd_accdb_close_ro( accdb, vote_ro );
      continue;
    }

    fd_vote_block_timestamp_t last_vote = fd_vsv_get_vote_block_timestamp( fd_account_data( vote_ro->meta ), vote_ro->meta->dlen );
    fd_top_votes_update( top_votes_t_2, &pubkey, last_vote.slot, last_vote.timestamp );

    if( FD_FEATURE_ACTIVE_BANK( bank, validator_admission_ticket ) ) {
      uchar                commission_t_1   = 0;
      fd_pubkey_t          node_account_t_1 = {0};
      fd_epoch_credits_t * epoch_credits    = &runtime_stack->stakes.epoch_credits[ vote_reward_cnt ];
      get_vote_credits_commission( fd_accdb_ref_data_const( vote_ro ), fd_accdb_ref_data_sz( vote_ro ), vsv_buf, &commission_t_1, &node_account_t_1, epoch_credits );
      fd_vote_rewards_t * vote_ele = &runtime_stack->stakes.vote_ele[ vote_reward_cnt ];
      vote_ele->pubkey             = pubkey;
      vote_ele->vote_rewards       = 0UL;
      vote_ele->commission_t_1     = commission_t_1;
      vote_ele->commission_t_2     = commission_t_2;
      fd_vote_rewards_map_ele_insert( vote_reward_map, vote_ele, runtime_stack->stakes.vote_ele );
      vote_reward_cnt++;
    }
    fd_accdb_close_ro( accdb, vote_ro );
  }

  /* Now for each staked vote account, figure out if it is a valid
     account and insert into the vote stakes (an account can not exist
     but still be inserted into the vote stakes if it existed in the
     previous epoch or vice versa).  The only condition an account is
     not inserted into the vote stakes is if it didn't exist in the
     previous epoch and in the current one. */

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ushort parent_idx = bank->vote_stakes_fork_id;
  ushort child_idx  = fd_vote_stakes_new_child( vote_stakes );
  bank->vote_stakes_fork_id = child_idx;

  for( fd_stake_accum_map_iter_t iter = fd_stake_accum_map_iter_init( stake_accum_map, stake_accum_pool );
       !fd_stake_accum_map_iter_done( iter, stake_accum_map, stake_accum_pool );
       iter = fd_stake_accum_map_iter_next( iter, stake_accum_map, stake_accum_pool ) ) {
    fd_stake_accum_t * stake_accum = fd_stake_accum_map_iter_ele( iter, stake_accum_map, stake_accum_pool );

    fd_pubkey_t node_account_t_2 = {0};
    ulong       stake_t_2        = 0UL;
    uchar       commission_t_2   = 0;
    int         exists_prev      = fd_vote_stakes_query_t_1( vote_stakes, parent_idx, &stake_accum->pubkey, &stake_t_2, &node_account_t_2, &commission_t_2 );

    fd_pubkey_t node_account_t_1 = {0};
    ulong       stake_t_1        = 0UL;
    uchar       commission_t_1   = 0;

    fd_accdb_ro_t vote_ro[1];
    int exists_curr = 1;
    if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, vote_ro, xid, &stake_accum->pubkey ) ) ) {
      exists_curr = 0;
    } else if( FD_UNLIKELY( !fd_vsv_is_correct_size_and_initialized( vote_ro->meta ) ) ) {
      exists_curr = 0;
      fd_accdb_close_ro( accdb, vote_ro );
    } else {
      fd_epoch_credits_t * epoch_credits = vote_reward_cnt<runtime_stack->expected_vote_accounts ? &runtime_stack->stakes.epoch_credits[ vote_reward_cnt ] : NULL;
      get_vote_credits_commission( fd_accdb_ref_data_const( vote_ro ), fd_accdb_ref_data_sz( vote_ro ), vsv_buf, &commission_t_1, &node_account_t_1, epoch_credits );

      stake_t_1 = stake_accum->stake;

      if( !FD_FEATURE_ACTIVE_BANK( bank, validator_admission_ticket ) ) {
        fd_vote_rewards_t * vote_ele = &runtime_stack->stakes.vote_ele[ vote_reward_cnt ];
        vote_ele->pubkey             = stake_accum->pubkey;
        vote_ele->vote_rewards       = 0UL;
        vote_ele->commission_t_1     = commission_t_1;
        vote_ele->commission_t_2     = exists_prev ? commission_t_2 : commission_t_1;
        fd_vote_rewards_map_ele_insert( vote_reward_map, vote_ele, runtime_stack->stakes.vote_ele );
        vote_reward_cnt++;
      }


      if( FD_FEATURE_ACTIVE_BANK( bank, validator_admission_ticket ) ) {
        if( FD_UNLIKELY( !fd_vsv_is_v4_with_bls_pubkey( vote_ro->meta ) ) ) {
          fd_accdb_close_ro( accdb, vote_ro );
          continue;
        }
      }
      fd_accdb_close_ro( accdb, vote_ro );
      fd_top_votes_insert( top_votes_t_1, &stake_accum->pubkey, &node_account_t_1, stake_t_1, commission_t_1 );
    }

    if( FD_UNLIKELY( !exists_curr && !exists_prev ) ) continue;
    fd_vote_stakes_insert(
        vote_stakes, child_idx, &stake_accum->pubkey,
        &node_account_t_1, &node_account_t_2,
        stake_t_1, stake_t_2,
        commission_t_1, commission_t_2,
        bank->f.epoch );
  }
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

  /* We can update our stake history sysvar based on the bank stake values.
     Afterward, we can refresh the stake values for the vote accounts. */

  fd_stake_history_t stake_history[1];
  if( FD_UNLIKELY( !fd_sysvar_stake_history_read( accdb, xid, stake_history ) ) ) {
    FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));
  }

  fd_epoch_stake_history_entry_pair_t elem = {
    .epoch = bank->f.epoch,
    .entry = {
      .effective    = stake_delegations->effective_stake,
      .activating   = stake_delegations->activating_stake,
      .deactivating = stake_delegations->deactivating_stake,
    }
  };
  fd_sysvar_stake_history_update( bank, accdb, xid, capture_ctx, &elem );

  if( FD_UNLIKELY( !fd_sysvar_stake_history_read( accdb, xid, stake_history ) ) ) {
    FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));
  }

  /* Now increment the epoch and recompute the stakes for the vote
     accounts for the new epoch value. */

  bank->f.epoch = bank->f.epoch + 1UL;

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

  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_modify( bank );

  /* fd_stakes_get_state returns NULL for closed/invalid accounts. */
  fd_stake_state_t const * stake_state = fd_stakes_get_state( meta );
  if( FD_LIKELY( stake_state != NULL &&
                 stake_state->stake_type == FD_STAKE_STATE_STAKE &&
                 stake_state->stake.stake.delegation.stake != 0UL ) ) {

    ulong new_stake = stake_state->stake.stake.delegation.stake;
    fd_stake_delegations_fork_update( stake_delegations, bank->stake_delegations_fork_id, pubkey,
                                      &stake_state->stake.stake.delegation.voter_pubkey,
                                      new_stake,
                                      stake_state->stake.stake.delegation.activation_epoch,
                                      stake_state->stake.stake.delegation.deactivation_epoch,
                                      stake_state->stake.stake.credits_observed,
                                      stake_state->stake.stake.delegation.warmup_cooldown_rate );

  } else {
    fd_stake_delegations_fork_remove( stake_delegations, bank->stake_delegations_fork_id, pubkey );
  }
}
