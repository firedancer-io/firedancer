#include "fd_stakes.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../runtime/program/fd_vote_program.h"
#include "../runtime/fd_runtime_stack.h"
#include "../runtime/fd_system_ids.h"
#include "../../util/bits/fd_sat.h"

/**********************************************************************/
/* Constants                                                          */
/**********************************************************************/

#define DEFAULT_SLASH_PENALTY                ( 12 )

/* https://github.com/solana-program/stake/blob/interface@v4.3.0/interface/src/warmup_cooldown_allowance.rs#L3-L5 */
#define FD_BASIS_POINTS_PER_UNIT             (10000UL)
#define FD_ORIGINAL_WARMUP_COOLDOWN_RATE_BPS (2500UL)
#define FD_TOWER_WARMUP_COOLDOWN_RATE_BPS    (900UL)

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

// https://github.com/solana-program/stake/blob/interface@v4.3.0/interface/src/state.rs#L694-L778
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
              ( cluster_stake_at_activation_epoch = fd_sysvar_stake_history_query( history, self->activation_epoch ) ) ) {
    ulong                            prev_epoch         = self->activation_epoch;
    fd_stake_history_entry_t const * prev_cluster_stake = cluster_stake_at_activation_epoch;

    ulong current_epoch;
    ulong current_effective_stake = 0;
    for( ;; ) {
      current_epoch = prev_epoch + 1;
      if( FD_LIKELY( prev_cluster_stake->activating==0 ) ) {
        break;
      }

      ulong remaining_activating_stake = delegated_stake - current_effective_stake;
      ulong newly_effective_stake = fd_ulong_max( fd_stake_calculate_change_allowance_float( current_epoch, remaining_activating_stake, prev_cluster_stake->activating, prev_cluster_stake->effective, new_rate_activation_epoch ), 1 );

      current_effective_stake += newly_effective_stake;
      if( FD_LIKELY( current_effective_stake>=delegated_stake ) ) {
        current_effective_stake = delegated_stake;
        break;
      }

      if( FD_LIKELY( current_epoch>=target_epoch ||
                     current_epoch>=self->deactivation_epoch ) ) {
        break;
      }

      fd_stake_history_entry_t const * current_cluster_stake = fd_sysvar_stake_history_query( history, current_epoch );
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

/* https://github.com/solana-program/stake/blob/interface@v4.3.0/interface/src/state.rs#L606-L690 */
fd_stake_history_entry_t
stake_activating_and_deactivating( fd_delegation_t const *    self,
                                   ulong                      target_epoch,
                                   fd_stake_history_t const * stake_history,
                                   ulong *                    new_rate_activation_epoch ) {

  effective_activating_t effective_activating = stake_and_activating( self, target_epoch, stake_history, new_rate_activation_epoch );

  ulong effective_stake  = effective_activating.effective;
  ulong activating_stake = effective_activating.activating;

  fd_stake_history_entry_t const * cluster_stake_at_deactivation_epoch = NULL;

  if( target_epoch<self->deactivation_epoch ) {
    if( activating_stake==0 ) {
      return ( fd_stake_history_entry_t ){ .effective = effective_stake, .deactivating = 0, .activating = 0 };
    } else {
      return ( fd_stake_history_entry_t ){ .effective = effective_stake, .deactivating = 0, .activating = activating_stake };
    }
  } else if( target_epoch==self->deactivation_epoch ) {
    return ( fd_stake_history_entry_t ){ .effective = effective_stake, .deactivating = effective_stake, .activating = 0 };
  } else if( stake_history &&
             ( cluster_stake_at_deactivation_epoch = fd_sysvar_stake_history_query( stake_history, self->deactivation_epoch ) ) ) {
    ulong                            prev_epoch         = self->deactivation_epoch;
    fd_stake_history_entry_t const * prev_cluster_stake = cluster_stake_at_deactivation_epoch;

    ulong current_epoch;
    ulong current_effective_stake = effective_stake;
    for( ;; ) {
      current_epoch = prev_epoch + 1;
      if( prev_cluster_stake->deactivating==0 ) break;

      ulong newly_not_effective_stake = fd_ulong_max( fd_stake_calculate_change_allowance_float( current_epoch, current_effective_stake, prev_cluster_stake->deactivating, prev_cluster_stake->effective, new_rate_activation_epoch ), 1 );

      current_effective_stake = fd_ulong_sat_sub( current_effective_stake, newly_not_effective_stake );
      if( current_effective_stake==0 ) break;

      if( current_epoch>=target_epoch ) break;

      fd_stake_history_entry_t const * current_cluster_stake = NULL;
      if( ( current_cluster_stake = fd_sysvar_stake_history_query(stake_history, current_epoch ) ) ) {
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

/* https://github.com/solana-program/stake/blob/interface@v4.3.0/interface/src/warmup_cooldown_allowance.rs#L7-L14 */
static ulong
fd_stake_warmup_cooldown_rate_bps( ulong current_epoch, ulong * opt_rate_change_activation_epoch ) {
  if( opt_rate_change_activation_epoch && current_epoch>=*opt_rate_change_activation_epoch ) {
    return FD_TOWER_WARMUP_COOLDOWN_RATE_BPS;
  } else {
    return FD_ORIGINAL_WARMUP_COOLDOWN_RATE_BPS;
  }
}

/* https://github.com/solana-program/stake/blob/interface@v4.3.0/interface/src/warmup_cooldown_allowance.rs#L54-L93 */
static ulong
calculate_stake_change_allowance( ulong   epoch,
                                  ulong   account_portion,
                                  ulong   cluster_portion,
                                  ulong   cluster_effective,
                                  ulong * opt_rate_change_activation_epoch ) {
  if( account_portion==0UL || cluster_portion==0UL || cluster_effective==0UL ) {
    return 0UL;
  }

  ulong rate_bps = fd_stake_warmup_cooldown_rate_bps( epoch, opt_rate_change_activation_epoch );

  uint128 numerator   = fd_uint128_sat_mul( fd_uint128_sat_mul( (uint128)account_portion, (uint128)cluster_effective ),
                                            (uint128)rate_bps );
  uint128 denominator = fd_uint128_sat_mul( (uint128)cluster_portion, (uint128)FD_BASIS_POINTS_PER_UNIT );

  /* denominator is never zero due to guard above */
  uint128 delta = numerator / denominator;
  uint128 cap   = (uint128)account_portion;
  return (ulong)( delta<cap ? delta : cap );
}

/* https://github.com/solana-program/stake/blob/interface@v4.3.0/interface/src/warmup_cooldown_allowance.rs#L16-L33 */
ulong
fd_stake_calculate_activation_allowance( ulong                            current_epoch,
                                         ulong                            account_activating_stake,
                                         fd_stake_history_entry_t const * prev_epoch_cluster_state,
                                         ulong *                          opt_rate_change_activation_epoch ) {
  return calculate_stake_change_allowance( current_epoch,
                                           account_activating_stake,
                                           prev_epoch_cluster_state->activating,
                                           prev_epoch_cluster_state->effective,
                                           opt_rate_change_activation_epoch );
}

/* https://github.com/solana-program/stake/blob/interface@v4.3.0/interface/src/warmup_cooldown_allowance.rs#L35-L52 */
static ulong
fd_stake_calculate_deactivation_allowance( ulong                            current_epoch,
                                           ulong                            account_deactivating_stake,
                                           fd_stake_history_entry_t const * prev_epoch_cluster_state,
                                           ulong *                          opt_rate_change_activation_epoch ) {
  return calculate_stake_change_allowance( current_epoch,
                                           account_deactivating_stake,
                                           prev_epoch_cluster_state->deactivating,
                                           prev_epoch_cluster_state->effective,
                                           opt_rate_change_activation_epoch );
}

/* Fixed-point version of stake_and_activating.
   Mirrors exactly the logic in the on-chain stake program:
   https://github.com/solana-program/stake/blob/interface@v4.3.0/interface/src/state.rs#L881-L971 */
static effective_activating_t
stake_and_activating_v2( fd_delegation_t const *    self,
                         ulong                      target_epoch,
                         fd_stake_history_t const * history,
                         ulong *                    new_rate_activation_epoch ) {
  ulong delegated_stake = self->stake;

  fd_stake_history_entry_t const * prev_cluster_stake = NULL;

  if( self->activation_epoch==ULONG_MAX ) {
    return ( effective_activating_t ){ .effective = delegated_stake, .activating = 0UL };
  } else if( self->activation_epoch==self->deactivation_epoch ) {
    return ( effective_activating_t ){ .effective = 0UL, .activating = 0UL };
  } else if( target_epoch==self->activation_epoch ) {
    return ( effective_activating_t ){ .effective = 0UL, .activating = delegated_stake };
  } else if( target_epoch<self->activation_epoch ) {
    return ( effective_activating_t ){ .effective = 0UL, .activating = 0UL };
  } else if( history &&
             ( prev_cluster_stake = fd_sysvar_stake_history_query( history, self->activation_epoch ) ) ) {

    ulong prev_epoch = self->activation_epoch;

    ulong current_epoch;
    ulong activated_stake_amount = 0UL;
    for(;;) {
      current_epoch = prev_epoch + 1UL;

      /* If there is no activating stake at prev epoch, we should have
         been fully effective at this moment */
      if( FD_LIKELY( prev_cluster_stake->activating==0UL ) ) break;

      /* Calculate how much of this account's remaining stake becomes
         effective in current_epoch. */
      ulong remaining_activating_stake = delegated_stake - activated_stake_amount;
      ulong newly_effective_stake      = fd_stake_calculate_activation_allowance( current_epoch,
                                                                                  remaining_activating_stake,
                                                                                  prev_cluster_stake,
                                                                                  new_rate_activation_epoch );

      /* Add the newly effective stake, clamping the per-epoch increase
         to at least 1 lamport so warmup always makes progress */
      activated_stake_amount += fd_ulong_max( newly_effective_stake, 1UL );

      /* Stop if we've fully warmed up this account's stake. */
      if( FD_LIKELY( activated_stake_amount>=delegated_stake ) ) {
        activated_stake_amount = delegated_stake;
        break;
      }

      /* Stop when we've reached the time bound for this query */
      if( FD_LIKELY( current_epoch>=target_epoch || current_epoch>=self->deactivation_epoch ) ) break;

      /* Advance to the next epoch if we have history,
         otherwise we can't model further warmup */
      fd_stake_history_entry_t const * current_cluster_stake =
          fd_sysvar_stake_history_query( history, current_epoch );
      if( FD_LIKELY( current_cluster_stake ) ) {
        prev_epoch         = current_epoch;
        prev_cluster_stake = current_cluster_stake;
      } else {
        break;
      }
    }

    return ( effective_activating_t ){ .effective  = activated_stake_amount,
                                       .activating = delegated_stake - activated_stake_amount };
  } else {
    return ( effective_activating_t ){ .effective = delegated_stake, .activating = 0UL };
  }
}

/* Fixed-point version of stake_activating_and_deactivating.
   Mirrors exactly the logic in the on-chain stake program:
   https://github.com/solana-program/stake/blob/interface@v4.3.0/interface/src/state.rs#L790-L879 */
static fd_stake_history_entry_t
stake_activating_and_deactivating_v2( fd_delegation_t const *    self,
                                      ulong                      target_epoch,
                                      fd_stake_history_t const * history,
                                      ulong *                    new_rate_activation_epoch ) {
  effective_activating_t effective_activating =
      stake_and_activating_v2( self, target_epoch, history, new_rate_activation_epoch );
  ulong effective_stake  = effective_activating.effective;
  ulong activating_stake = effective_activating.activating;

  fd_stake_history_entry_t const * prev_cluster_stake = NULL;

  if( target_epoch<self->deactivation_epoch ) {
    if( activating_stake==0UL ) {
      return ( fd_stake_history_entry_t ){ .effective = effective_stake, .activating = 0UL, .deactivating = 0UL };
    } else {
      return ( fd_stake_history_entry_t ){ .effective = effective_stake, .activating = activating_stake, .deactivating = 0UL };
    }
  } else if( target_epoch==self->deactivation_epoch ) {
    return ( fd_stake_history_entry_t ){ .effective = effective_stake, .activating = 0UL, .deactivating = effective_stake };
  } else if( history &&
             ( prev_cluster_stake = fd_sysvar_stake_history_query( history, self->deactivation_epoch ) ) ) {
    ulong prev_epoch = self->deactivation_epoch;

    /* https://github.com/solana-program/stake/blob/interface@v4.3.0/interface/src/state.rs#L830-L871 */
    ulong current_epoch;
    ulong remaining_deactivating_stake = effective_stake;
    for(;;) {
      current_epoch = prev_epoch + 1UL;

      /* If there is no deactivating stake at prev epoch, we should
         have been fully undelegated at this moment */
      if( FD_LIKELY( prev_cluster_stake->deactivating==0UL ) ) break;

      /* Compute how much of this account's stake cools down in
         current_epoch */
      ulong newly_deactivated_stake = fd_stake_calculate_deactivation_allowance( current_epoch,
                                                                                 remaining_deactivating_stake,
                                                                                 prev_cluster_stake,
                                                                                 new_rate_activation_epoch );

      /* Subtract the newly deactivated stake, clamping the per-epoch
         decrease to at least 1 lamport so cooldown always makes
         progress */
      remaining_deactivating_stake =
          fd_ulong_sat_sub( remaining_deactivating_stake, fd_ulong_max( newly_deactivated_stake, 1UL ) );

      /* Stop if we've fully cooled down this account */
      if( remaining_deactivating_stake==0UL ) break;

      /* Stop when we've reached the time bound for this query */
      if( current_epoch>=target_epoch ) break;

      /* Advance to the next epoch if we have history,
         otherwise we can't model further cooldown */
      fd_stake_history_entry_t const * current_cluster_stake =
          fd_sysvar_stake_history_query( history, current_epoch );
      if( FD_LIKELY( current_cluster_stake ) ) {
        prev_epoch         = current_epoch;
        prev_cluster_stake = current_cluster_stake;
      } else {
        break;
      }
    }

    return ( fd_stake_history_entry_t ){ .effective    = remaining_deactivating_stake,
                                         .activating    = 0UL,
                                         .deactivating = remaining_deactivating_stake };
  } else {
    return ( fd_stake_history_entry_t ){ .effective = 0UL, .activating = 0UL, .deactivating = 0UL };
  }
}

/* https://github.com/anza-xyz/agave/blob/v4.2.0-beta.1/runtime/src/stake_delegation.rs#L27-L41 */
fd_stake_history_entry_t
fd_delegation_activation_status( fd_delegation_t const *    self,
                                 ulong                      target_epoch,
                                 fd_stake_history_t const * stake_history,
                                 ulong *                    new_rate_activation_epoch,
                                 int                        use_fixed_point_stake_math ) {
  if( use_fixed_point_stake_math ) {
    return stake_activating_and_deactivating_v2( self, target_epoch, stake_history, new_rate_activation_epoch );
  } else {
    return stake_activating_and_deactivating( self, target_epoch, stake_history, new_rate_activation_epoch );
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
fd_stakes_get_state( fd_acc_t const * acc ) {
  if( FD_UNLIKELY( memcmp( acc->owner, &fd_solana_stake_program_id, 32UL ) ) ) return NULL;
  if( FD_UNLIKELY( acc->lamports==0UL ) ) return NULL;
  return fd_stake_state_view( acc->data, acc->data_len );
}

fd_stake_history_entry_t
fd_stakes_activating_and_deactivating( fd_stake_delegation_t const * stake_delegation,
                                       ulong                         target_epoch,
                                       fd_stake_history_t const *    stake_history,
                                       ulong *                       new_rate_activation_epoch,
                                       int                           use_fixed_point_stake_math ) {
  fd_delegation_t delegation = {
    .voter_pubkey         = stake_delegation->vote_account,
    .stake                = stake_delegation->stake,
    .deactivation_epoch   = stake_delegation->deactivation_epoch==USHORT_MAX ? ULONG_MAX : stake_delegation->deactivation_epoch,
    .activation_epoch     = stake_delegation->activation_epoch==USHORT_MAX ? ULONG_MAX : stake_delegation->activation_epoch,
    .warmup_cooldown_rate = fd_stake_delegations_warmup_cooldown_rate_to_double( stake_delegation->warmup_cooldown_rate ),
  };

  return fd_delegation_activation_status( &delegation, target_epoch, stake_history, new_rate_activation_epoch, use_fixed_point_stake_math );
}

ulong
fd_stake_weights_by_node( fd_vote_stakes_t const * vote_stakes,
                          ulong                    fork_id,
                          int                      use_t_1,
                          fd_vote_stake_weight_t * weights ) {

  /* We don't care if an account is invalid, we just want to get the
     stake weights: they are calculated from an older snapshot of
     vote account stakes. */
  ulong weights_cnt = 0;
  uchar __attribute__((aligned(FD_VOTE_STAKES_T_1_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_T_1_ITER_FOOTPRINT ];
  if( use_t_1 ) {
    for( fd_vote_stakes_t_1_iter_t * iter = fd_vote_stakes_t_1_iter_init( vote_stakes, fork_id, iter_mem );
         !fd_vote_stakes_t_1_iter_done( vote_stakes, fork_id, iter );
         fd_vote_stakes_t_1_iter_next( vote_stakes, fork_id, iter ) ) {
      fd_pubkey_t pubkey;
      ulong       stake;
      fd_pubkey_t node_account;
      fd_vote_stakes_t_1_iter_ele( vote_stakes, fork_id, iter, &pubkey, &node_account, &stake, NULL );

      FD_TEST( weights_cnt<MAX_STAKE_WEIGHTS );
      fd_memcpy( weights[ weights_cnt ].vote_key.uc, &pubkey, sizeof(fd_pubkey_t) );
      fd_memcpy( weights[ weights_cnt ].id_key.uc, &node_account, sizeof(fd_pubkey_t) );
      weights[ weights_cnt ].stake = stake;
      fd_memset( weights[ weights_cnt ].bls_key, 0, sizeof(weights[ weights_cnt ].bls_key) );
      weights_cnt++;
    }
  } else {
    for( fd_vote_stakes_t_2_iter_t * iter = fd_vote_stakes_t_2_iter_init( vote_stakes, fork_id, iter_mem );
         !fd_vote_stakes_t_2_iter_done( vote_stakes, fork_id, iter );
         fd_vote_stakes_t_2_iter_next( vote_stakes, fork_id, iter ) ) {
      fd_pubkey_t pubkey;
      ulong       stake;
      fd_pubkey_t node_account;
      fd_vote_stakes_t_2_iter_ele( vote_stakes, fork_id, iter, &pubkey, &node_account, &stake, NULL, NULL, NULL, NULL );

      FD_TEST( weights_cnt<MAX_STAKE_WEIGHTS );
      fd_memcpy( weights[ weights_cnt ].vote_key.uc, &pubkey, sizeof(fd_pubkey_t) );
      fd_memcpy( weights[ weights_cnt ].id_key.uc, &node_account, sizeof(fd_pubkey_t) );
      weights[ weights_cnt ].stake = stake;
      fd_memset( weights[ weights_cnt ].bls_key, 0, sizeof(weights[ weights_cnt ].bls_key) );
      weights_cnt++;
    }
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
                  ushort               commission,
                  fd_epoch_credits_t * epoch_credits ) {

  ulong                           cnt                = 0UL;
  fd_vote_epoch_credits_t const * vote_epoch_credits = fd_vote_account_epoch_credits( account_data, account_data_len, &cnt );
  FD_TEST( vote_epoch_credits );
  FD_TEST( cnt<=FD_EPOCH_CREDITS_MAX );
  epoch_credits->commission = commission;

  ulong n          = 0UL;
  ulong base       = 0UL;
  ulong marker_idx = UCHAR_MAX;
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_vote_epoch_credits_t const * ele = &vote_epoch_credits[ i ];

    if( fd_vote_epoch_credits_is_alpenglow_marker( ele ) ) {
      marker_idx = n;
      continue;
    }
    if( !n ) base = ele->prev_credits;

    FD_TEST( ele->epoch<=USHORT_MAX );           /* Epoch should fit. */

    epoch_credits->epoch[ n ]              = (ushort)ele->epoch;
    epoch_credits->credits_delta[ n ]      = ele->credits      - base;
    epoch_credits->prev_credits_delta[ n ] = ele->prev_credits - base;
    n++;
  }

  epoch_credits->cnt          = (uchar)n;
  epoch_credits->marker_idx   = (uchar)marker_idx;
  epoch_credits->base_credits = base;
  epoch_credits->fast_path_ok = fd_epoch_credits_fast_path_ok( epoch_credits );
}

void
fd_refresh_vote_accounts( fd_bank_t *                    bank,
                          fd_accdb_t *                   accdb,
                          fd_runtime_stack_t *           runtime_stack,
                          fd_stake_delegations_t const * stake_delegations,
                          fd_stake_history_t const *     history,
                          ulong *                        new_rate_activation_epoch ) {
  fd_bank_epoch_credits_new_fork( bank );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ulong              fork_id     = bank->vote_stakes_fork_id;

  fd_stake_accum_map_reset( runtime_stack->stakes.stake_accum_map );
  ulong epoch                      = bank->f.epoch;
  ulong total_stake                = 0UL;
  ulong total_activating           = 0UL;
  ulong total_deactivating         = 0UL;
  ulong staked_accounts            = 0UL;
  int   use_fixed_point_stake_math = FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 );

  fd_stake_accum_t *     stake_accum_pool = runtime_stack->stakes.stake_accum;
  fd_stake_accum_map_t * stake_accum_map  = runtime_stack->stakes.stake_accum_map;

  /* Accumulate stakes across all delegations for all vote accounts. */
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations, accdb, bank->accdb_fork_id, epoch, new_rate_activation_epoch );
      !fd_stake_delegations_iter_done( iter );
      fd_stake_delegations_iter_next( iter ) ) {

    fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_iter_ele( iter );

    fd_stake_history_entry_t new_acc;
    uchar st = stake_delegation->state;
    if( FD_LIKELY( st==FD_STAKE_DELEGATION_STATE_WARMED ) ) {
      new_acc = (fd_stake_history_entry_t){ .effective = stake_delegation->stake, .activating = 0UL, .deactivating = 0UL };
    } else if( st==FD_STAKE_DELEGATION_STATE_COOLED ) {
      new_acc = (fd_stake_history_entry_t){ .effective = 0UL, .activating = 0UL, .deactivating = 0UL };
    } else {
      new_acc = fd_stakes_activating_and_deactivating( stake_delegation, epoch, history, new_rate_activation_epoch, use_fixed_point_stake_math );
    }
    total_stake        += new_acc.effective;
    total_activating   += new_acc.activating;
    total_deactivating += new_acc.deactivating;
    if( FD_UNLIKELY( !new_acc.effective ) ) continue;

    fd_stake_accum_t * stake_accum = fd_stake_accum_map_ele_query( stake_accum_map, &stake_delegation->vote_account, NULL, stake_accum_pool );
    if( FD_UNLIKELY( !stake_accum ) ) {
      if( FD_UNLIKELY( staked_accounts>=runtime_stack->max_staked_vote_accounts ) ) {
        FD_LOG_ERR(( "invariant violation: staked_accounts >= max_vote_accounts" ));
      }
      stake_accum = &runtime_stack->stakes.stake_accum[ staked_accounts ];
      stake_accum->pubkey = stake_delegation->vote_account;
      stake_accum->stake  = new_acc.effective;
      fd_stake_accum_map_ele_insert( stake_accum_map, stake_accum, stake_accum_pool );
      staked_accounts++;
    } else {
      stake_accum->stake += new_acc.effective;
    }
  }

  /* Only update total_*_stake at the epoch boundary.  These values
     are snapshots of the stake totals for the current epoch. */
  bank->f.total_activating_stake   = total_activating;
  bank->f.total_deactivating_stake = total_deactivating;
  bank->f.total_effective_stake    = total_stake;

  /* Iterate over the valid delegated vote accounts and insert them into
     the top votes set for the t-1 epoch. */

  /* Rotate the SIMD-0232 collector override fork for the new epoch. */
  fd_collector_overrides_t * overrides = fd_bank_collector_overrides( bank );
  ushort co_child = fd_collector_overrides_new_child( overrides );
  fd_collector_overrides_inherit( overrides, bank->collector_overrides_fork_id, co_child, fd_ulong_sat_sub( bank->f.epoch, 1UL ) );
  bank->collector_overrides_fork_id = co_child;

  for( fd_stake_accum_map_iter_t iter = fd_stake_accum_map_iter_init( stake_accum_map, stake_accum_pool );
       !fd_stake_accum_map_iter_done( iter, stake_accum_map, stake_accum_pool );
       iter = fd_stake_accum_map_iter_next( iter, stake_accum_map, stake_accum_pool ) ) {
    fd_stake_accum_t * stake_accum = fd_stake_accum_map_iter_ele( iter, stake_accum_map, stake_accum_pool );

    fd_pubkey_t node_account_t_1 = {0};
    ulong       stake_t_1        = stake_accum->stake;
    ushort      commission_t_1   = 0;

    if( FD_UNLIKELY( !stake_t_1 ) ) continue;

    fd_acc_t acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, stake_accum->pubkey.uc );
    /* Agave's VAT filter also checks lamports against the VoteStateV4
       rent-exempt minimum. */
    if( FD_UNLIKELY( !acc.lamports ) ) {
      fd_accdb_unread_one( accdb, &acc );
      continue;
    }

    ulong vote_account_lamports            = acc.lamports;
    ulong vote_account_rent_exempt_minimum = fd_rent_exempt_minimum_balance( &bank->f.rent, FD_VOTE_STATE_V4_SZ );
    if( FD_UNLIKELY( vote_account_lamports < vote_account_rent_exempt_minimum ) ) {
      fd_accdb_unread_one( accdb, &acc );
      continue;
    }
    if( FD_UNLIKELY( !fd_vsv_is_correct_size_owner_and_init( acc.owner, acc.data, acc.data_len ) ||
                     !fd_vote_account_is_v4_with_bls_pubkey( acc.data, acc.data_len ) ) ) {
      fd_accdb_unread_one( accdb, &acc );
      continue;
    }

    FD_TEST( !fd_vote_account_commission_bps( acc.data, acc.data_len, FD_FEATURE_ACTIVE_BANK( bank, commission_rate_in_basis_points ), &commission_t_1 ) );
    FD_TEST( !fd_vote_account_node_pubkey( acc.data, acc.data_len, &node_account_t_1 ) );

    fd_vote_stakes_insert( vote_stakes, fork_id, &stake_accum->pubkey, &node_account_t_1, stake_t_1, commission_t_1 );
    fd_accdb_unread_one( accdb, &acc );
  }

  /* Capture SIMD-0232 collector overrides for the admitted t-1 set.
     Only admitted vote accounts can be scheduled as leaders or earn
     inflation rewards, so collectors of accounts outside the set are
     never consulted.  Capturing after selection bounds the override
     store by the admitted set size. */
  {
    uchar __attribute__((aligned(FD_VOTE_STAKES_T_1_ITER_ALIGN))) co_iter_mem[ FD_VOTE_STAKES_T_1_ITER_FOOTPRINT ];
    for( fd_vote_stakes_t_1_iter_t * iter = fd_vote_stakes_t_1_iter_init( vote_stakes, fork_id, co_iter_mem );
         !fd_vote_stakes_t_1_iter_done( vote_stakes, fork_id, iter );
         fd_vote_stakes_t_1_iter_next( vote_stakes, fork_id, iter ) ) {
      fd_pubkey_t vote_pubkey;
      fd_pubkey_t node_pubkey;
      fd_vote_stakes_t_1_iter_ele( vote_stakes, fork_id, iter, &vote_pubkey, &node_pubkey, NULL, NULL );

      fd_acc_t acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, vote_pubkey.uc );
      fd_pubkey_t inflation_collector;
      fd_pubkey_t block_collector;
      FD_TEST( !fd_vote_account_collectors( acc.data, acc.data_len, &vote_pubkey, &node_pubkey, &inflation_collector, &block_collector ) );
      int has_inflation = !fd_pubkey_eq( &inflation_collector, &vote_pubkey );
      int has_block     = !fd_pubkey_eq( &block_collector, &node_pubkey );
      if( FD_UNLIKELY( has_inflation | has_block ) ) {
        fd_collector_overrides_upsert( overrides, co_child, bank->f.epoch, &vote_pubkey,
                                       has_inflation, &inflation_collector,
                                       has_block, &block_collector );
      }
      fd_accdb_unread_one( accdb, &acc );
    }
  }

  /* Seed status for the t-2 top votes set for clock calculation. */
  fd_vote_stakes_refresh( vote_stakes, fork_id, accdb, bank->accdb_fork_id );

  /* Populate the vote rewards map with the final set of filtered vote
     accounts. */
  fd_vote_rewards_map_t * vote_reward_map = runtime_stack->stakes.vote_map;
  fd_vote_rewards_map_reset( vote_reward_map );
  ulong vote_reward_cnt = 0UL;

  /* Populate the vote rewards map with the final set of filtered vote
     accounts for the t-1 epoch. */
  bank->f.total_epoch_stake = 0UL;
  uchar __attribute__((aligned(FD_VOTE_STAKES_T_1_ITER_ALIGN))) t_1_iter_mem[ FD_VOTE_STAKES_T_1_ITER_FOOTPRINT ];
  for( fd_vote_stakes_t_1_iter_t * iter = fd_vote_stakes_t_1_iter_init( vote_stakes, fork_id, t_1_iter_mem );
       !fd_vote_stakes_t_1_iter_done( vote_stakes, fork_id, iter );
       fd_vote_stakes_t_1_iter_next( vote_stakes, fork_id, iter ) ) {
    fd_pubkey_t pubkey;
    ulong       stake;
    ushort      commission_t_1 = 0;
    fd_vote_stakes_t_1_iter_ele( vote_stakes, fork_id, iter, &pubkey, NULL, &stake, &commission_t_1 );

    ushort commission_t_3 = 0;
    int    exists_t_3     = fd_vote_stakes_query_t_3( vote_stakes, fork_id, &pubkey, NULL, NULL, &commission_t_3 );

    ushort commission_t_2 = 0;
    int    exists_t_2     = fd_vote_stakes_query_t_2( vote_stakes, fork_id, &pubkey, NULL, NULL, NULL, NULL, &commission_t_2, NULL );

    fd_vote_rewards_t * vote_ele = &runtime_stack->stakes.vote_ele[ vote_reward_cnt ];
    vote_ele->pubkey             = pubkey;
    vote_ele->vote_rewards       = 0UL;
    if( FD_FEATURE_ACTIVE_BANK( bank, delay_commission_updates ) ) {
      vote_ele->commission = exists_t_3 ? commission_t_3 : (exists_t_2 ? commission_t_2 : commission_t_1);
    } else {
      vote_ele->commission = commission_t_1;
    }

    fd_acc_t acc = fd_accdb_read_one( accdb, bank->accdb_fork_id, pubkey.uc );
    FD_TEST( acc.lamports );

    if( FD_UNLIKELY( vote_reward_cnt>=FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS ) ) {
      FD_LOG_ERR(( "invariant violation: vote_reward_cnt >= epoch credits max" ));
    }
    fd_epoch_credits_t * epoch_credits = &fd_bank_epoch_credits( bank )[ vote_reward_cnt ];
    fd_memcpy( epoch_credits->pubkey, &pubkey, sizeof(fd_pubkey_t) );
    get_vote_credits( acc.data, acc.data_len, vote_ele->commission, epoch_credits );
    fd_accdb_unread_one( accdb, &acc );

    fd_vote_rewards_map_ele_insert( vote_reward_map, vote_ele, runtime_stack->stakes.vote_ele );
    vote_reward_cnt++;
    bank->f.total_epoch_stake += stake;
  }
  *fd_bank_epoch_credits_len( bank ) = vote_reward_cnt;
}

/* https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/stakes.rs#L280 */
void
fd_stakes_activate_epoch( fd_bank_t *                    bank,
                          fd_runtime_stack_t *           runtime_stack,
                          fd_accdb_t *                   accdb,
                          fd_capture_ctx_t *             capture_ctx,
                          fd_stake_delegations_t *       stake_delegations,
                          ulong *                        new_rate_activation_epoch ) {
  /* We can update our stake history sysvar based on the bank stake values.
     Afterward, we can refresh the stake values for the vote accounts. */

  fd_stake_history_entry_t elem = {
    .epoch        = bank->f.epoch,
    .effective    = stake_delegations->effective_stake,
    .activating   = stake_delegations->activating_stake,
    .deactivating = stake_delegations->deactivating_stake,
  };

  /* Agave recomputes each stake history entry from scratch every epoch
     boundary, whereas Firedancer keeps running totals. Therefore,
     at the boundary where upgrade_bpf_stake_program_to_v5_1 is
     activated, we need to recompute the stake history entry for the
     epoch that has just ended, so that all the delegations for this
     entry are summed using the new fixed point arithmetic. We only
     need to do this once, at the feature activation epoch boundary.

     https://github.com/anza-xyz/agave/blob/v4.2.0-beta.1/runtime/src/stakes.rs#L444-L477

     The same recomputation needs to be done as soon as fallback stake
     accounts are enabled. */
  int fallback = fd_stake_delegations_pubkey_fallback( stake_delegations );
  if( FD_UNLIKELY( fallback || FD_FEATURE_JUST_ACTIVATED_BANK( bank, upgrade_bpf_stake_program_to_v5_1 ) ) ) {
    fd_stake_history_t history[1];
    if( FD_UNLIKELY( !fd_sysvar_cache_stake_history_view( &bank->f.sysvar_cache, history ) ) ) {
      FD_LOG_CRIT(( "invariant violation: StakeHistory sysvar missing or invalid" ));
    }
    ulong effective    = 0UL;
    ulong activating   = 0UL;
    ulong deactivating = 0UL;

    int use_fixed_point_stake_math = FD_FEATURE_ACTIVE_BANK( bank, upgrade_bpf_stake_program_to_v5_1 );

    fd_stake_delegations_iter_t iter_[1];
    for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations, accdb, bank->accdb_fork_id, bank->f.epoch, new_rate_activation_epoch );
         !fd_stake_delegations_iter_done( iter );
         fd_stake_delegations_iter_next( iter ) ) {
      fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_iter_ele( iter );
      fd_stake_history_entry_t      acc              = fd_stakes_activating_and_deactivating(
          stake_delegation, bank->f.epoch, history, new_rate_activation_epoch, use_fixed_point_stake_math );
      effective    += acc.effective;
      activating   += acc.activating;
      deactivating += acc.deactivating;
    }

    elem.effective    = effective;
    elem.activating   = activating;
    elem.deactivating = deactivating;
  }

  fd_sysvar_stake_history_update( bank, accdb, capture_ctx, &elem );

  /* Snapshot the stake history sysvar into a local buffer and release
     the accdb bracket before calling fd_refresh_vote_accounts, which
     performs its own accdb acquires.  fd_sysvar_stake_history_view
     aliases the source bytes, so the bracket cannot be held open across
     an inner acquire. */
  uchar              stake_history_data[ FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ ];
  fd_stake_history_t stake_history[1];
  {
    fd_acc_t ro = fd_accdb_read_one( accdb, bank->accdb_fork_id, fd_sysvar_stake_history_id.uc );
    if( FD_UNLIKELY( !ro.lamports ) ) FD_LOG_ERR(( "StakeHistory sysvar is missing" ));
    ulong copy_sz = fd_ulong_min( ro.data_len, FD_SYSVAR_STAKE_HISTORY_BINCODE_SZ );
    fd_memcpy( stake_history_data, ro.data, copy_sz );
    fd_accdb_unread_one( accdb, &ro );
    if( FD_UNLIKELY( !fd_sysvar_stake_history_view( stake_history, stake_history_data, copy_sz ) ) ) {
      FD_LOG_HEXDUMP_ERR(( "Invalid StakeHistory sysvar", stake_history_data, copy_sz ));
    }
  }

  if( FD_UNLIKELY( !fd_sysvar_stake_history_is_contiguous( stake_history ) ) ) {
    fd_stake_delegations_invalidate_warmed( stake_delegations );
  }

  /* Now increment the epoch and recompute the stakes for the vote
     accounts for the new epoch value. */

  bank->f.epoch = fd_slot_to_epoch( &bank->f.epoch_schedule, bank->f.slot, NULL );

  fd_refresh_vote_accounts( bank,
                            accdb,
                            runtime_stack,
                            stake_delegations,
                            stake_history,
                            new_rate_activation_epoch );
}


void
fd_stakes_update_stake_delegation( fd_pubkey_t const * pubkey,
                                   fd_acc_t const *    acc,
                                   fd_bank_t *         bank ) {

  fd_stake_state_t const * stake_state       = fd_stakes_get_state( acc );
  fd_stake_state_t const * prior_stake_state = NULL;
  if( FD_LIKELY( acc->prior_lamports && !memcmp( acc->prior_owner, &fd_solana_stake_program_id, 32UL ) ) ) {
    prior_stake_state = fd_stake_state_view( acc->prior_data, acc->prior_data_len );
  }

  int current_has_delegation = stake_state && stake_state->stake_type==FD_STAKE_STATE_STAKE;
  int prior_has_delegation   = prior_stake_state && prior_stake_state->stake_type==FD_STAKE_STATE_STAKE;

  /* If the current stake state isn't a delegation and it was a
     delegation in the previous stake state, insert a tombstone into the
     stake delegation's fork. */
  if( FD_UNLIKELY( !current_has_delegation ) ) {
    if( FD_LIKELY( !prior_has_delegation ) ) return; /* nothing to remove from */
    fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_modify( bank );
    fd_stake_delegations_fork_remove( stake_delegations, bank->stake_delegations_fork_id, pubkey );
    return;
  }

  /* Agave replaces the cached version of the account whenever the
     account changes. */

  int account_changed = acc->prior_lamports  !=acc->lamports   ||
                        acc->prior_executable!=acc->executable ||
                        acc->prior_data_len  !=acc->data_len   ||
                        memcmp( acc->prior_owner, acc->owner, sizeof(fd_pubkey_t) );
  if( FD_LIKELY( !account_changed && acc->data_len ) ) {
    account_changed = !!memcmp( acc->prior_data, acc->data, acc->data_len );
  }
  if( FD_LIKELY( prior_has_delegation && !account_changed ) ) return;

  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_modify( bank );
  ulong new_stake = stake_state->stake.stake.delegation.stake;
  fd_stake_delegations_fork_update( stake_delegations, bank->stake_delegations_fork_id, pubkey,
                                    &stake_state->stake.stake.delegation.voter_pubkey,
                                    new_stake,
                                    stake_state->stake.stake.delegation.activation_epoch,
                                    stake_state->stake.stake.delegation.deactivation_epoch,
                                    stake_state->stake.stake.credits_observed,
                                    acc->lamports,
                                    (uint)acc->data_len,
                                    fd_stake_warmup_cooldown_rate( bank->f.epoch, &bank->f.warmup_cooldown_rate_epoch ) );
}
