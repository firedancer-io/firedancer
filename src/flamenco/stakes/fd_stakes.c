#include <limits.h>

#include "fd_stakes.h"
#include "../runtime/fd_bank.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../runtime/program/vote/fd_vote_codec.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../runtime/sysvar/fd_sysvar_cache.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../runtime/program/fd_vote_program.h"
#include "../runtime/fd_runtime_stack.h"
#include "../runtime/fd_system_ids.h"
#include "fd_stake_delegations.h"
#include "../accdb/fd_accdb_sync.h"
#include "../../util/bits/fd_sat.h"
#include "fd_stake_types.h"
#include "fd_top_votes.h"

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

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
  return fd_stake_delegations_warmup_cooldown_rate_to_double(
    fd_stake_warmup_cooldown_rate( current_epoch, new_rate_activation_epoch ) );
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

/**********************************************************************/
/* Public API                                                         */
/**********************************************************************/

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

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.7/leader-schedule/src/lib.rs#L80-L83
     We do not deduplicate the weights here, unlike Agave, as it is
     guaranteed there will be no duplicate stake entries for a given fork
     in the stakes map. */

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

  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.7/leader-schedule/src/lib.rs#L80-L83
     We do not deduplicate the weights here, unlike Agave, as it is
     guaranteed there will be no duplicate stake entries for a given fork
     in the stakes map. */

  return weights_cnt;
}

static void
get_vote_credits( uchar const *        account_data,
                  ulong                account_data_len,
                  fd_epoch_credits_t * epoch_credits ) {

  fd_vote_epoch_credits_t const * vote_epoch_credits = fd_vote_account_epoch_credits( account_data, account_data_len, &epoch_credits->cnt );
  FD_TEST( vote_epoch_credits );

  ulong base = epoch_credits->cnt ? vote_epoch_credits[0].prev_credits : 0UL;
  for( ulong i=0UL; i<epoch_credits->cnt; i++ ) {
    fd_vote_epoch_credits_t const * ele        = &vote_epoch_credits[ i ];
    epoch_credits->epoch[ i ]              = (ushort)ele->epoch;
    epoch_credits->credits_delta[ i ]      = (uint)( ele->credits      - base );
    epoch_credits->prev_credits_delta[ i ] = (uint)( ele->prev_credits - base );
  }

  epoch_credits->base_credits = base;
}

void
fd_refresh_vote_accounts_vat( fd_bank_t *                    bank,
                              fd_accdb_user_t *              accdb,
                              fd_funk_txn_xid_t const *      xid,
                              fd_runtime_stack_t *           runtime_stack,
                              fd_stake_delegations_t const * stake_delegations,
                              fd_stake_history_t const *     history,
                              ulong *                        new_rate_activation_epoch ) {

  fd_top_votes_t * top_votes_t_1 = fd_bank_top_votes_t_1_modify( bank );
  fd_top_votes_t * top_votes_t_2 = fd_bank_top_votes_t_2_modify( bank );

  uchar __attribute__((aligned(FD_TOP_VOTES_ALIGN))) top_votes_t_3_mem[ FD_TOP_VOTES_MAX_FOOTPRINT ];

  /* Copy over the old t-2 top votes into a temporary t-3 buffer.  Copy
     over the old t-1 top votes to the t-2 top votes.  Reset the
     existing t-1 top votes to prepare it for insertion. Handle the
     transition to the next epoch. */
  fd_memcpy( top_votes_t_3_mem, top_votes_t_2, FD_TOP_VOTES_MAX_FOOTPRINT );
  fd_memcpy( top_votes_t_2,     top_votes_t_1, FD_TOP_VOTES_MAX_FOOTPRINT );
  fd_top_votes_init( top_votes_t_1 );
  fd_top_votes_t * top_votes_t_3 = fd_type_pun( top_votes_t_3_mem );

  fd_stake_accum_map_reset( runtime_stack->stakes.stake_accum_map );
  ulong epoch              = bank->f.epoch;
  ulong total_stake        = 0UL;
  ulong total_activating   = 0UL;
  ulong total_deactivating = 0UL;
  ulong staked_accounts    = 0UL;

  fd_stake_accum_t *     stake_accum_pool = runtime_stack->stakes.stake_accum;
  fd_stake_accum_map_t * stake_accum_map  = runtime_stack->stakes.stake_accum_map;

  /* Accumulate stakes across all delegations for all vote accounts. */
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
      if( FD_UNLIKELY( staked_accounts>=runtime_stack->shmem->max_vote_accounts ) ) {
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
  bank->f.total_effective_stake    = total_stake;

  /* Iterate over the valid delegated vote accounts and insert them into
     the top votes set for the t-1 epoch. */

  for( fd_stake_accum_map_iter_t iter = fd_stake_accum_map_iter_init( stake_accum_map, stake_accum_pool );
       !fd_stake_accum_map_iter_done( iter, stake_accum_map, stake_accum_pool );
       iter = fd_stake_accum_map_iter_next( iter, stake_accum_map, stake_accum_pool ) ) {
    fd_stake_accum_t * stake_accum = fd_stake_accum_map_iter_ele( iter, stake_accum_map, stake_accum_pool );

    fd_pubkey_t node_account_t_1 = {0};
    ulong       stake_t_1        = stake_accum->stake;
    uchar       commission_t_1   = 0;

    fd_accdb_ro_t vote_ro[1];
    /* Agave's VAT filter also checks lamports against the VoteStateV4
       rent-exempt minimum. */
    if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, vote_ro, xid, &stake_accum->pubkey ) ) ) {
      continue;
    }
    ulong vote_account_lamports = vote_ro->meta->lamports;
    ulong vote_account_rent_exempt_minimum = fd_rent_exempt_minimum_balance( &bank->f.rent, FD_VOTE_STATE_V4_SZ );
    if( FD_UNLIKELY( vote_account_lamports < vote_account_rent_exempt_minimum ) ) {
      fd_accdb_close_ro( accdb, vote_ro );
      continue;
    }
    if( FD_UNLIKELY( !fd_vsv_is_correct_size_owner_and_init( vote_ro->meta ) ||
                            !fd_vote_account_is_v4_with_bls_pubkey( fd_account_data( vote_ro->meta ), vote_ro->meta->dlen ) ) ) {
      fd_accdb_close_ro( accdb, vote_ro );
      continue;
    }

    FD_TEST( !fd_vote_account_commission( fd_accdb_ref_data_const( vote_ro ), fd_accdb_ref_data_sz( vote_ro ), &commission_t_1 ) );
    FD_TEST( !fd_vote_account_node_pubkey( fd_accdb_ref_data_const( vote_ro ), fd_accdb_ref_data_sz( vote_ro ), &node_account_t_1 ) );

    fd_top_votes_insert( top_votes_t_1, &stake_accum->pubkey, &node_account_t_1, stake_t_1, commission_t_1 );
    fd_accdb_close_ro( accdb, vote_ro );
  }

  /* Seed status for the t-2 top votes set for clock calculation. */
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
    if( FD_UNLIKELY( !fd_vsv_is_correct_size_owner_and_init( vote_ro->meta ) ) ) {
      fd_top_votes_invalidate( top_votes_t_2, &pubkey );
      fd_accdb_close_ro( accdb, vote_ro );
      continue;
    }

    fd_vote_block_timestamp_t last_vote;
    FD_TEST( !fd_vote_account_last_timestamp( fd_account_data( vote_ro->meta ), vote_ro->meta->dlen, &last_vote ) );
    fd_top_votes_update( top_votes_t_2, &pubkey, last_vote.slot, last_vote.timestamp );
    fd_accdb_close_ro( accdb, vote_ro );
  }

  /* Populate the vote rewards map with the final set of filtered vote
     accounts. */
  fd_vote_rewards_map_t * vote_reward_map = runtime_stack->stakes.vote_map;
  fd_vote_rewards_map_reset( vote_reward_map );
  ulong vote_reward_cnt = 0UL;

  /* If VAT feature has just been activated, we want to reference the
     t-2/t-3 commissions from the vote stakes and not the top votes. */
  ulong vat_epoch  = fd_slot_to_epoch( &bank->f.epoch_schedule, bank->f.features.validator_admission_ticket, NULL );
  int   vat_in_t_2 = bank->f.epoch>vat_epoch;
  int   vat_in_t_3 = fd_ulong_sat_sub(bank->f.epoch, 1UL )>vat_epoch;

  ushort             parent_idx  = bank->vote_stakes_fork_id;
  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );

  /* Populate the vote rewards map with the final set of filtered vote
     accounts for the t-1 epoch. */
  bank->f.total_epoch_stake = 0UL;
  for( fd_top_votes_iter_t * iter = fd_top_votes_iter_init( top_votes_t_1, top_votes_iter_mem );
       !fd_top_votes_iter_done( top_votes_t_1, iter );
       fd_top_votes_iter_next( top_votes_t_1, iter ) ) {
    fd_pubkey_t pubkey;
    ulong       stake;
    uchar       commission_t_1 = 0;
    fd_top_votes_iter_ele( top_votes_t_1, iter, &pubkey, NULL, &stake, &commission_t_1, NULL, NULL );

    int   exists_t_3 = 0;
    uchar commission_t_3 = 0;
    if( FD_LIKELY( vat_in_t_3 ) ) {
      exists_t_3 = fd_top_votes_query( top_votes_t_3, &pubkey, NULL, NULL, NULL, NULL, &commission_t_3 );
    } else {
      exists_t_3 = fd_vote_stakes_query_t_2( vote_stakes, parent_idx, &pubkey, NULL, NULL, &commission_t_3 );
    }

    int   exists_t_2     = 0;
    uchar commission_t_2 = 0;
    if( FD_LIKELY( vat_in_t_2 ) ) {
      exists_t_2 = fd_top_votes_query( top_votes_t_2, &pubkey, NULL, NULL, NULL, NULL, &commission_t_2 );
    } else {
      exists_t_2 = fd_vote_stakes_query_t_1( vote_stakes, parent_idx, &pubkey, NULL, NULL, &commission_t_2 );
    }

    fd_vote_rewards_t * vote_ele = &runtime_stack->stakes.vote_ele[ vote_reward_cnt ];
    vote_ele->pubkey             = pubkey;
    vote_ele->vote_rewards       = 0UL;
    if( FD_FEATURE_ACTIVE_BANK( bank, delay_commission_updates ) ) {
      vote_ele->commission = exists_t_3 ? commission_t_3 : (exists_t_2 ? commission_t_2 : commission_t_1);
    } else {
      vote_ele->commission = commission_t_1;
    }

    fd_accdb_ro_t vote_ro[1];
    FD_TEST( fd_accdb_open_ro( accdb, vote_ro, xid, &pubkey ) );
    fd_epoch_credits_t * epoch_credits = &fd_bank_epoch_credits( bank )[ vote_reward_cnt ];
    get_vote_credits( fd_accdb_ref_data_const( vote_ro ), fd_accdb_ref_data_sz( vote_ro ), epoch_credits );
    fd_accdb_close_ro( accdb, vote_ro );

    fd_vote_rewards_map_ele_insert( vote_reward_map, vote_ele, runtime_stack->stakes.vote_ele );
    vote_reward_cnt++;
    bank->f.total_epoch_stake += stake;
  }
  *fd_bank_epoch_credits_len( bank ) = vote_reward_cnt;
}

/* Split-phase entry points for the parallel delegation refresh.
   These factor the work in fd_refresh_vote_accounts_no_vat into
   (a) a sequential pre-seed that runs on replay, (b) a per-tile
   worker that processes one partition of stake_delegations into a
   local dedup stash, (c) a replay-side merge pass that folds one
   tile's stash into the shared stake_accum_map, and (d) a finalize
   step + a sequential post pass.  See fd_stakes.h for the high-level
   protocol. */

void
fd_refresh_vote_accounts_no_vat_pre( fd_bank_t *          bank,
                                     fd_runtime_stack_t * runtime_stack,
                                     ulong *              staked_accounts_out ) {
  fd_stake_accum_t *     stake_accum_pool = runtime_stack->stakes.stake_accum;
  fd_stake_accum_map_t * stake_accum_map  = runtime_stack->stakes.stake_accum_map;

  fd_vote_rewards_map_t * vote_reward_map = runtime_stack->stakes.vote_map;
  fd_vote_rewards_map_reset( vote_reward_map );
  fd_stake_accum_map_reset( stake_accum_map );

  ushort parent_idx     = bank->vote_stakes_fork_id;
  ulong  staked_accounts = 0UL;

  fd_vote_stakes_t * vs = fd_bank_vote_stakes( bank );
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem_vs[ FD_VOTE_STAKES_ITER_FOOTPRINT ];
  for( fd_vote_stakes_iter_t * vs_iter = fd_vote_stakes_fork_iter_init( vs, parent_idx, iter_mem_vs );
       !fd_vote_stakes_fork_iter_done( vs, parent_idx, vs_iter );
       fd_vote_stakes_fork_iter_next( vs, parent_idx, vs_iter ) ) {
    fd_pubkey_t vs_pubkey;
    fd_vote_stakes_fork_iter_ele( vs, parent_idx, vs_iter, &vs_pubkey, NULL, NULL, NULL, NULL, NULL, NULL );
    if( FD_UNLIKELY( staked_accounts>=runtime_stack->shmem->max_vote_accounts ) ) {
      FD_LOG_ERR(( "invariant violation: staked_accounts >= max_vote_accounts" ));
    }
    fd_stake_accum_t * sa = &stake_accum_pool[ staked_accounts ];
    sa->pubkey = vs_pubkey;
    sa->stake  = 0UL;
    fd_stake_accum_map_ele_insert( stake_accum_map, sa, stake_accum_pool );
    staked_accounts++;
  }
  fd_vote_stakes_fork_iter_fini( vs );

  fd_new_votes_t * new_votes = fd_bank_new_votes( bank );
  ushort           fork_indices[ FD_RUNTIME_MAX_FORK_CNT ];
  ulong            forks_cnt = fd_banks_new_votes_fork_indices( bank, fork_indices );

  uchar __attribute__((aligned(FD_NEW_VOTES_ITER_ALIGN))) iter_mem[ FD_NEW_VOTES_ITER_FOOTPRINT ];
  fd_new_votes_iter_t * nv_iter = fd_new_votes_iter_init( new_votes, fork_indices, forks_cnt, iter_mem );
  for( ; !fd_new_votes_iter_done( nv_iter ); fd_new_votes_iter_next( nv_iter ) ) {
    fd_pubkey_t const * pubkey = fd_new_votes_iter_ele( nv_iter );
    fd_stake_accum_t * existing = fd_stake_accum_map_ele_query( stake_accum_map, pubkey, NULL, stake_accum_pool );
    if( FD_LIKELY( !existing ) ) {
      if( FD_UNLIKELY( staked_accounts>=runtime_stack->shmem->max_vote_accounts ) ) {
        FD_LOG_ERR(( "invariant violation: staked_accounts >= max_vote_accounts" ));
      }
      fd_stake_accum_t * sa = &stake_accum_pool[ staked_accounts ];
      sa->pubkey = *pubkey;
      sa->stake  = 0UL;
      fd_stake_accum_map_ele_insert( stake_accum_map, sa, stake_accum_pool );
      staked_accounts++;
    }
  }
  fd_new_votes_iter_fini( nv_iter );

  *staked_accounts_out = staked_accounts;
}

int
fd_refresh_delegations_partitioned( fd_bank_t *                    bank,
                                    fd_runtime_stack_t *           runtime_stack,
                                    fd_stake_delegations_t const * stake_delegations,
                                    fd_stake_history_t const *     history,
                                    ulong                          partition_idx,
                                    ulong                          total_partitions,
                                    int                            is_resume,
                                    ulong *                        new_rate_activation_epoch,
                                    ulong *                        out_effective,
                                    ulong *                        out_activating,
                                    ulong *                        out_deactivating ) {
  ulong epoch = bank->f.epoch;
  ulong cap   = fd_runtime_stack_refresh_local_cap( runtime_stack->shmem->expected_vote_accounts );

  fd_stake_accum_t *        local_pool = runtime_stack->refresh.local_stake_accum;
  fd_stake_accum_map_t *    local_map  = runtime_stack->refresh.local_stake_accum_map;
  ulong *                   local_cnt  = runtime_stack->refresh.local_stake_accum_cnt;
  fd_refresh_tile_state_t * state      = runtime_stack->refresh.local_state;

  fd_stake_delegations_pool_iter_t iter_[1];
  fd_stake_delegations_pool_iter_t * iter;
  if( is_resume ) {
    iter = fd_stake_delegations_pool_iter_init_partition( iter_, stake_delegations, partition_idx, total_partitions );
    iter->cur = state->saved_iter_cur;
    iter->hi  = state->saved_iter_hi;
  } else {
    fd_stake_accum_map_reset( local_map );
    *local_cnt = 0UL;
    memset( state, 0, sizeof(*state) );
    iter = fd_stake_delegations_pool_iter_init_partition( iter_, stake_delegations, partition_idx, total_partitions );
  }

  ulong total_effective    = 0UL;
  ulong total_activating   = 0UL;
  ulong total_deactivating = 0UL;

  while( !fd_stake_delegations_pool_iter_done( iter ) ) {
    fd_stake_delegation_t const * deleg = fd_stake_delegations_pool_iter_ele( iter );

    fd_stake_accum_t * accum = fd_stake_accum_map_ele_query( local_map, &deleg->vote_account, NULL, local_pool );

    if( FD_UNLIKELY( !accum && *local_cnt>=cap ) ) {
      /* Local stash full.  Save iterator state (this delegation has
         NOT been processed yet -- do not touch scalars) and return a
         flush indicator.  Replay must drain the slot and send a
         resume message before the worker can continue. */
      state->saved_iter_cur       = iter->cur;
      state->saved_iter_hi        = iter->hi;
      state->in_progress          = 1UL;
      *out_effective    = total_effective;
      *out_activating   = total_activating;
      *out_deactivating = total_deactivating;
      return 1;
    }

    fd_stake_history_entry_t new_entry = fd_stakes_activating_and_deactivating( deleg, epoch, history, new_rate_activation_epoch );
    total_effective    += new_entry.effective;
    total_activating   += new_entry.activating;
    total_deactivating += new_entry.deactivating;

    if( !accum ) {
      accum = &local_pool[ *local_cnt ];
      accum->pubkey = deleg->vote_account;
      accum->stake  = new_entry.effective;
      fd_stake_accum_map_ele_insert( local_map, accum, local_pool );
      (*local_cnt)++;
    } else {
      accum->stake += new_entry.effective;
    }

    fd_stake_delegations_pool_iter_next( iter );
  }

  state->in_progress = 0UL;
  *out_effective    = total_effective;
  *out_activating   = total_activating;
  *out_deactivating = total_deactivating;
  return 0;
}

void
fd_refresh_delegations_merge_tile_slot( fd_runtime_stack_t * runtime_stack,
                                        ulong                slot_idx,
                                        ulong *              staked_accounts_inout ) {
  fd_runtime_stack_shmem_t * shmem       = runtime_stack->shmem;
  fd_stake_accum_t *         shared_pool = runtime_stack->stakes.stake_accum;
  fd_stake_accum_map_t *     shared_map  = runtime_stack->stakes.stake_accum_map;

  fd_stake_accum_t *     tile_pool    = fd_runtime_stack_shmem_refresh_pool( shmem, slot_idx );
  fd_stake_accum_map_t * tile_map     = fd_runtime_stack_shmem_refresh_map_join( shmem, slot_idx );
  ulong *                tile_cnt_ptr = fd_runtime_stack_shmem_refresh_cnt( shmem, slot_idx );
  ulong                  tile_cnt        = *tile_cnt_ptr;
  ulong                  staked_accounts = *staked_accounts_inout;

  for( ulong i=0UL; i<tile_cnt; i++ ) {
    fd_stake_accum_t * local  = &tile_pool[ i ];
    fd_stake_accum_t * shared = fd_stake_accum_map_ele_query( shared_map, &local->pubkey, NULL, shared_pool );
    if( shared ) {
      shared->stake += local->stake;
    } else {
      if( FD_UNLIKELY( staked_accounts>=shmem->max_vote_accounts ) ) {
        FD_LOG_ERR(( "invariant violation: staked_accounts >= max_vote_accounts during merge" ));
      }
      shared = &shared_pool[ staked_accounts ];
      shared->pubkey = local->pubkey;
      shared->stake  = local->stake;
      fd_stake_accum_map_ele_insert( shared_map, shared, shared_pool );
      staked_accounts++;
    }
  }

  /* Clear the slot so the worker can reuse it on resume (or so the
     next epoch starts clean). */
  fd_stake_accum_map_reset( tile_map );
  *tile_cnt_ptr = 0UL;

  *staked_accounts_inout = staked_accounts;
}

void
fd_refresh_delegations_finalize( fd_bank_t * bank,
                                 ulong       total_effective,
                                 ulong       total_activating,
                                 ulong       total_deactivating ) {
  bank->f.total_activating_stake   = total_activating;
  bank->f.total_deactivating_stake = total_deactivating;
  bank->f.total_effective_stake    = total_effective;
}

void
fd_refresh_vote_accounts_no_vat_post( fd_bank_t *               bank,
                                      fd_accdb_user_t *         accdb,
                                      fd_funk_txn_xid_t const * xid,
                                      fd_runtime_stack_t *      runtime_stack ) {
  fd_stake_accum_t *      stake_accum_pool = runtime_stack->stakes.stake_accum;
  fd_stake_accum_map_t *  stake_accum_map  = runtime_stack->stakes.stake_accum_map;
  fd_vote_rewards_map_t * vote_reward_map  = runtime_stack->stakes.vote_map;
  ushort                  parent_idx       = bank->vote_stakes_fork_id;
  ulong                   vote_reward_cnt  = 0UL;

  /* Phase B: refresh top votes. */
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
    if( FD_UNLIKELY( !fd_vsv_is_correct_size_owner_and_init( vote_ro->meta ) ) ) {
      fd_top_votes_invalidate( top_votes_t_2, &pubkey );
      fd_accdb_close_ro( accdb, vote_ro );
      continue;
    }

    fd_vote_block_timestamp_t last_vote;
    FD_TEST( !fd_vote_account_last_timestamp( fd_account_data( vote_ro->meta ), vote_ro->meta->dlen, &last_vote ) );
    fd_top_votes_update( top_votes_t_2, &pubkey, last_vote.slot, last_vote.timestamp );
    fd_accdb_close_ro( accdb, vote_ro );
  }

  /* Phase C: votestakes. */
  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ushort             child_idx   = fd_vote_stakes_new_child( vote_stakes );
  bank->vote_stakes_fork_id      = child_idx;

  bank->f.total_epoch_stake = 0UL;
  for( fd_stake_accum_map_iter_t iter = fd_stake_accum_map_iter_init( stake_accum_map, stake_accum_pool );
       !fd_stake_accum_map_iter_done( iter, stake_accum_map, stake_accum_pool );
       iter = fd_stake_accum_map_iter_next( iter, stake_accum_map, stake_accum_pool ) ) {
    fd_stake_accum_t * stake_accum = fd_stake_accum_map_iter_ele( iter, stake_accum_map, stake_accum_pool );

    fd_pubkey_t node_account_t_2 = {0};
    ulong       stake_t_2        = 0UL;
    uchar       commission_t_2   = 0;
    int         exists_t_2       = fd_vote_stakes_query_t_1( vote_stakes, parent_idx, &stake_accum->pubkey, &stake_t_2, &node_account_t_2, &commission_t_2 );

    fd_pubkey_t node_account_t_1 = {0};
    ulong       stake_t_1        = 0UL;
    uchar       commission_t_1   = 0;

    fd_accdb_ro_t vote_ro[1];
    int exists_t_1 = 1;
    if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, vote_ro, xid, &stake_accum->pubkey ) ) ) {
      exists_t_1 = 0;
    } else if( FD_UNLIKELY( !fd_vsv_is_correct_size_owner_and_init( vote_ro->meta ) ) ) {
      exists_t_1 = 0;
      fd_accdb_close_ro( accdb, vote_ro );
    } else {

      FD_TEST( !fd_vote_account_commission( fd_accdb_ref_data_const( vote_ro ), fd_accdb_ref_data_sz( vote_ro ), &commission_t_1 ) );
      FD_TEST( !fd_vote_account_node_pubkey( fd_accdb_ref_data_const( vote_ro ), fd_accdb_ref_data_sz( vote_ro ), &node_account_t_1 ) );

      stake_t_1 = stake_accum->stake;
      bank->f.total_epoch_stake += stake_t_1;

      fd_pubkey_t node_account_t_3 = {0};
      ulong       stake_t_3        = 0UL;
      uchar       commission_t_3   = 0;
      int         exists_t_3       = fd_vote_stakes_query_t_2( vote_stakes, parent_idx, &stake_accum->pubkey, &stake_t_3, &node_account_t_3, &commission_t_3 );

      fd_epoch_credits_t * epoch_credits = &fd_bank_epoch_credits( bank )[ vote_reward_cnt ];
      get_vote_credits( fd_accdb_ref_data_const( vote_ro ), fd_accdb_ref_data_sz( vote_ro ), epoch_credits );
      fd_vote_rewards_t * vote_ele = &runtime_stack->stakes.vote_ele[ vote_reward_cnt ];
      vote_ele->pubkey             = stake_accum->pubkey;
      vote_ele->vote_rewards       = 0UL;
      if( FD_FEATURE_ACTIVE_BANK( bank, delay_commission_updates ) ) {
        vote_ele->commission = exists_t_3 ? commission_t_3 : (exists_t_2 ? commission_t_2 : commission_t_1);
      } else {
        vote_ele->commission = commission_t_1;
      }
      fd_vote_rewards_map_ele_insert( vote_reward_map, vote_ele, runtime_stack->stakes.vote_ele );
      vote_reward_cnt++;

      if( FD_LIKELY( fd_vote_account_is_v4_with_bls_pubkey( fd_account_data( vote_ro->meta ), vote_ro->meta->dlen ) ) ) {
        fd_top_votes_insert( top_votes_t_1, &stake_accum->pubkey, &node_account_t_1, stake_t_1, commission_t_1 );
      }
      fd_accdb_close_ro( accdb, vote_ro );
    }

    if( FD_UNLIKELY( !exists_t_1 && !exists_t_2 ) ) continue;
    fd_vote_stakes_insert(
        vote_stakes, child_idx, &stake_accum->pubkey,
        &node_account_t_1, &node_account_t_2,
        stake_t_1, stake_t_2,
        commission_t_1, commission_t_2,
        (uchar)exists_t_1, (uchar)exists_t_2,
        bank->f.epoch );
  }
  *fd_bank_epoch_credits_len( bank ) = vote_reward_cnt;
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
                                      fd_stake_warmup_cooldown_rate( bank->f.epoch, &bank->f.warmup_cooldown_rate_epoch ) );

  } else {
    fd_stake_delegations_fork_remove( stake_delegations, bank->stake_delegations_fork_id, pubkey );
  }
}
