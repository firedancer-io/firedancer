#include "fd_rewards.h"
#include <math.h>

#include "../runtime/fd_acc_mgr.h"
#include "../runtime/fd_executor_err.h"
#include "../runtime/program/fd_vote_program.h"
#include "../runtime/sysvar/fd_sysvar_epoch_rewards.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../stakes/fd_stakes.h"
#include "../runtime/program/fd_stake_program.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../runtime/context/fd_capture_ctx.h"
#include "../runtime/fd_runtime.h"

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/sdk/src/inflation.rs#L85 */
static double
total( fd_inflation_t const * inflation, double year ) {
  if ( FD_UNLIKELY( year == 0.0 ) ) {
    FD_LOG_ERR(( "inflation year 0" ));
  }
  double tapered = inflation->initial * pow( (1.0 - inflation->taper), year );
  return (tapered > inflation->terminal) ? tapered : inflation->terminal;
}

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/sdk/src/inflation.rs#L102 */
static double
foundation( fd_inflation_t const * inflation, double year ) {
  return (year < inflation->foundation_term) ? inflation->foundation * total(inflation, year) : 0.0;
}

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/sdk/src/inflation.rs#L97 */
static double
validator( fd_inflation_t const * inflation, double year) {
  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/sdk/src/inflation.rs#L96-L99 */
  FD_LOG_DEBUG(("Validator Rate: %.16f %.16f %.16f %.16f %.16f", year, total( inflation, year ), foundation( inflation, year ), inflation->taper, inflation->initial));
  return total( inflation, year ) - foundation( inflation, year );
}

/* Calculates the starting slot for inflation from the activation slot. The activation slot is the earliest
    activation slot of the following features:
    - devnet_and_testnet
    - full_inflation_enable, if full_inflation_vote has been activated

    https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank.rs#L2095 */
static FD_FN_CONST ulong
get_inflation_start_slot( fd_bank_t const * bank ) {
  ulong devnet_and_testnet = FD_FEATURE_ACTIVE_BANK( bank, devnet_and_testnet )
      ? fd_bank_features_query( bank )->devnet_and_testnet
      : ULONG_MAX;

  ulong enable = ULONG_MAX;
  if( FD_FEATURE_ACTIVE_BANK( bank, full_inflation_vote ) &&
      FD_FEATURE_ACTIVE_BANK( bank, full_inflation_enable ) ) {
    enable = fd_bank_features_query( bank )->full_inflation_enable;
  }

  ulong min_slot = fd_ulong_min( enable, devnet_and_testnet );
  if( min_slot == ULONG_MAX ) {
    if( FD_FEATURE_ACTIVE_BANK( bank, pico_inflation ) ) {
      min_slot = fd_bank_features_query( bank )->pico_inflation;
    } else {
      min_slot = 0;
    }
  }
  return min_slot;
}

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank.rs#L2110 */
static ulong
get_inflation_num_slots( fd_bank_t const *           bank,
                         fd_epoch_schedule_t const * epoch_schedule,
                         ulong                       slot ) {
  ulong inflation_activation_slot = get_inflation_start_slot( bank );
  ulong inflation_start_slot      = fd_epoch_slot0( epoch_schedule,
                                                    fd_ulong_sat_sub( fd_slot_to_epoch( epoch_schedule,
                                                                                        inflation_activation_slot, NULL ),
                                                                      1UL ) );

  ulong epoch = fd_slot_to_epoch( epoch_schedule, slot, NULL );

  return fd_epoch_slot0( epoch_schedule, epoch ) - inflation_start_slot;
}

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank.rs#L2121 */
static double
slot_in_year_for_inflation( fd_bank_t const * bank ) {
  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );
  ulong num_slots = get_inflation_num_slots( bank, epoch_schedule, fd_bank_slot_get( bank ) );
  return (double)num_slots / (double)fd_bank_slots_per_year_get( bank );
}

/* For a given stake and vote_state, calculate how many points were earned (credits * stake) and new value
   for credits_observed were the points paid

    https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L109 */
static void
calculate_stake_points_and_credits( fd_stake_history_t const *     stake_history,
                                    fd_stake_delegation_t const *  stake,
                                    fd_vote_state_ele_t const *    vote_state,
                                    ulong *                        new_rate_activation_epoch,
                                    fd_calculated_stake_points_t * result ) {

  ulong credits_in_stake = stake->credits_observed;
  ulong credits_in_vote  = 0UL;
  if( FD_LIKELY( vote_state->credits_cnt>0UL ) ) {
    credits_in_vote = vote_state->credits[vote_state->credits_cnt-1UL];
  }

  /* If the Vote account has less credits observed than the Stake account,
      something is wrong and we need to force an update.

      https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L142 */
  if( FD_UNLIKELY( credits_in_vote < credits_in_stake ) ) {
    result->points = 0;
    result->new_credits_observed = credits_in_vote;
    result->force_credits_update_with_skipped_reward = 1;
    return;
  }

  /* If the Vote account has the same amount of credits observed as the Stake account,
      then the Vote account hasn't earnt any credits and so there is nothing to update.

      https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L148 */
  if( FD_UNLIKELY( credits_in_vote == credits_in_stake ) ) {
    result->points = 0;
    result->new_credits_observed = credits_in_vote;
    result->force_credits_update_with_skipped_reward = 0;
    return;
  }

  /* Calculate the points for each epoch credit */
  uint128 points               = 0;
  ulong   new_credits_observed = credits_in_stake;
  for( ulong i=0UL; i<vote_state->credits_cnt; i++ ) {

    ulong final_epoch_credits   = vote_state->credits[i];
    ulong initial_epoch_credits = vote_state->prev_credits[i];
    uint128 earned_credits = 0;
    if( FD_LIKELY( credits_in_stake < initial_epoch_credits ) ) {
      earned_credits = (uint128)(final_epoch_credits - initial_epoch_credits);
    } else if( FD_UNLIKELY( credits_in_stake < final_epoch_credits ) ) {
      earned_credits = (uint128)(final_epoch_credits - new_credits_observed);
    }

    new_credits_observed = fd_ulong_max( new_credits_observed, final_epoch_credits );

    fd_delegation_t delegation = {
      .voter_pubkey         = stake->vote_account,
      .stake                = stake->stake,
      .activation_epoch     = stake->activation_epoch,
      .deactivation_epoch   = stake->deactivation_epoch,
      .warmup_cooldown_rate = stake->warmup_cooldown_rate,
    };

    ulong stake_amount = fd_stake_activating_and_deactivating(
        &delegation,
        vote_state->epoch[i],
        stake_history,
        new_rate_activation_epoch ).effective;

    points += (uint128)stake_amount * earned_credits;

  }


  result->points = points;
  result->new_credits_observed = new_credits_observed;
  result->force_credits_update_with_skipped_reward = 0;
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/rewards.rs#L127 */
static int
calculate_stake_rewards( fd_stake_history_t const *      stake_history,
                         fd_stake_delegation_t const *   stake,
                         fd_vote_state_ele_t const *     vote_state,
                         ulong                           rewarded_epoch,
                         fd_point_value_t *              point_value,
                         ulong *                         new_rate_activation_epoch,
                         fd_calculated_stake_rewards_t * result ) {
  fd_calculated_stake_points_t stake_points_result = {0};

  calculate_stake_points_and_credits(
      stake_history,
      stake,
      vote_state,
      new_rate_activation_epoch,
      &stake_points_result);

  // Drive credits_observed forward unconditionally when rewards are disabled
  // or when this is the stake's activation epoch
  if( ( point_value->rewards==0UL ) ||
      ( stake->activation_epoch==rewarded_epoch ) ) {
      stake_points_result.force_credits_update_with_skipped_reward |= 1;
  }

  if( stake_points_result.force_credits_update_with_skipped_reward ) {
    result->staker_rewards = 0;
    result->voter_rewards = 0;
    result->new_credits_observed = stake_points_result.new_credits_observed;
    return 0;
  }
  if( stake_points_result.points == 0 || point_value->points == 0 ) {
    return 1;
  }

  /* FIXME: need to error out if the conversion from uint128 to u64 fails, also use 128 checked mul and div */
  ulong rewards = (ulong)(stake_points_result.points * (uint128)(point_value->rewards) / (uint128) point_value->points);
  if( rewards == 0 ) {
    return 1;
  }

  fd_commission_split_t split_result;
  fd_vote_commission_split( vote_state->commission, rewards, &split_result );
  if( split_result.is_split && (split_result.voter_portion == 0 || split_result.staker_portion == 0) ) {
    return 1;
  }

  result->staker_rewards = split_result.staker_portion;
  result->voter_rewards = split_result.voter_portion;
  result->new_credits_observed = stake_points_result.new_credits_observed;
  return 0;
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/rewards.rs#L33 */
static int
redeem_rewards( fd_stake_history_t const *      stake_history,
                fd_stake_delegation_t const *   stake,
                fd_vote_state_ele_t const *     vote_state,
                ulong                           rewarded_epoch,
                fd_point_value_t *              point_value,
                ulong *                         new_rate_activation_epoch,
                fd_calculated_stake_rewards_t * calculated_stake_rewards ) {

  int rc = calculate_stake_rewards(
      stake_history,
      stake,
      vote_state,
      rewarded_epoch,
      point_value,
      new_rate_activation_epoch,
      calculated_stake_rewards );
  if( FD_UNLIKELY( rc!=0 ) ) {
    return rc;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L70 */
static int
calculate_points( fd_stake_delegation_t const * stake,
                  fd_vote_state_ele_t const *   vote_state,
                  fd_stake_history_t const  *   stake_history,
                  ulong *                       new_rate_activation_epoch,
                  uint128 *                     result ) {
  fd_calculated_stake_points_t stake_point_result;
  calculate_stake_points_and_credits( stake_history,
                                      stake,
                                      vote_state,
                                      new_rate_activation_epoch,
                                      &stake_point_result );
  *result = stake_point_result.points;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* Returns the length of the given epoch in slots

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/sdk/program/src/epoch_schedule.rs#L103 */
static ulong
get_slots_in_epoch( ulong                       epoch,
                    fd_epoch_schedule_t const * epoch_schedule ) {
  return (epoch < epoch_schedule->first_normal_epoch) ?
          1UL << fd_ulong_sat_add(epoch, FD_EPOCH_LEN_MIN_TRAILING_ZERO) :
          epoch_schedule->slots_per_epoch;
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L2082 */
static double
epoch_duration_in_years( fd_bank_t const * bank,
                         ulong             prev_epoch ) {
  ulong slots_in_epoch = get_slots_in_epoch( prev_epoch, fd_bank_epoch_schedule_query( bank ) );
  return (double)slots_in_epoch / (double)fd_bank_slots_per_year_get( bank );
}

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank.rs#L2128 */
static void
calculate_previous_epoch_inflation_rewards( fd_bank_t const *                   bank,
                                            ulong                               prev_epoch_capitalization,
                                            ulong                               prev_epoch,
                                            fd_prev_epoch_inflation_rewards_t * rewards ) {
  double slot_in_year = slot_in_year_for_inflation( bank );

  rewards->validator_rate               = validator( fd_bank_inflation_query( bank ), slot_in_year );
  rewards->foundation_rate              = foundation( fd_bank_inflation_query( bank ), slot_in_year );
  rewards->prev_epoch_duration_in_years = epoch_duration_in_years( bank, prev_epoch );
  rewards->validator_rewards            = (ulong)(rewards->validator_rate * (double)prev_epoch_capitalization * rewards->prev_epoch_duration_in_years);
  FD_LOG_DEBUG(( "Rewards %lu, Rate %.16f, Duration %.18f Capitalization %lu Slot in year %.16f", rewards->validator_rewards, rewards->validator_rate, rewards->prev_epoch_duration_in_years, prev_epoch_capitalization, slot_in_year ));
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/lib.rs#L29 */
static ulong
get_minimum_stake_delegation( fd_exec_slot_ctx_t const * slot_ctx ) {
  if( !FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, stake_minimum_delegation_for_rewards ) ) {
    return 0UL;
  }

  if( FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, stake_raise_minimum_delegation_to_1_sol ) ) {
    return LAMPORTS_PER_SOL;
  }

  return 1;
}

static uint128
calculate_points_all( fd_exec_slot_ctx_t const *     slot_ctx,
                      fd_stake_delegations_t const * stake_delegations,
                      fd_stake_history_t const *     stake_history,
                      ulong *                        new_warmup_cooldown_rate_epoch,
                      ulong                          minimum_stake_delegation ) {

  uint128 total_points = 0;

  fd_vote_states_t const * vote_states = fd_bank_vote_states_locking_query( slot_ctx->bank );

  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_iter_ele( iter );

    if( FD_UNLIKELY( stake_delegation->stake<minimum_stake_delegation ) ) {
      continue;
    }

    fd_vote_state_ele_t * vote_state_ele = fd_vote_states_query( vote_states, &stake_delegation->vote_account );
    if( FD_UNLIKELY( !vote_state_ele ) ) {
      continue;
    }

    uint128 account_points;
    int err = calculate_points(
        stake_delegation,
        vote_state_ele,
        stake_history,
        new_warmup_cooldown_rate_epoch, &account_points );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_DEBUG(( "failed to calculate points" ));
      continue;
    }

    total_points += account_points;
  }

  fd_bank_vote_states_end_locking_query( slot_ctx->bank );

  return total_points;
}

/* Calculates epoch reward points from stake/vote accounts.
    https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L472 */
static void
calculate_reward_points_partitioned( fd_exec_slot_ctx_t *           slot_ctx,
                                     fd_stake_delegations_t const * stake_delegations,
                                     fd_stake_history_t const *     stake_history,
                                     ulong                          rewards,
                                     fd_point_value_t *             result ) {
  ulong minimum_stake_delegation = get_minimum_stake_delegation( slot_ctx );

  /* Calculate the points for each stake delegation */
  int _err[1];
  ulong   new_warmup_cooldown_rate_epoch_val = 0UL;
  ulong * new_warmup_cooldown_rate_epoch     = &new_warmup_cooldown_rate_epoch_val;
  int is_some = fd_new_warmup_cooldown_rate_epoch(
      fd_bank_epoch_schedule_query( slot_ctx->bank ),
      fd_bank_features_query( slot_ctx->bank ),
      fd_bank_slot_get( slot_ctx->bank ),
      new_warmup_cooldown_rate_epoch,
      _err );
  if( FD_UNLIKELY( !is_some ) ) {
    new_warmup_cooldown_rate_epoch = NULL;
  }

  uint128 points = calculate_points_all(
      slot_ctx,
      stake_delegations,
      stake_history,
      new_warmup_cooldown_rate_epoch,
      minimum_stake_delegation );

  if( points > 0 ) {
    result->points  = points;
    result->rewards = rewards;
  }
}

static void
calculate_stake_vote_rewards_account( fd_exec_slot_ctx_t const *                 slot_ctx,
                                      fd_stake_delegations_t const *             stake_delegations,
                                      fd_capture_ctx_t const *                   capture_ctx,
                                      fd_stake_history_t const *                 stake_history,
                                      ulong const                                rewarded_epoch,
                                      ulong *                                    new_warmup_cooldown_rate_epoch,
                                      fd_point_value_t *                         point_value,
                                      fd_calculate_stake_vote_rewards_result_t * result,
                                      fd_spad_t *                                spad,
                                      int                                        is_recalculation ) {

  FD_SPAD_FRAME_BEGIN( spad ) {

  ulong minimum_stake_delegation = get_minimum_stake_delegation( slot_ctx );
  ulong total_stake_rewards      = 0UL;
  ulong dlist_additional_cnt     = 0UL;
  ulong stake_delegation_cnt     = fd_stake_delegations_cnt( stake_delegations );

  /* Build a local vote reward map */
  fd_vote_reward_t_mapnode_t * vote_reward_map_pool = fd_vote_reward_t_map_join( fd_vote_reward_t_map_new( fd_spad_alloc(
      spad, fd_vote_reward_t_map_align(), fd_vote_reward_t_map_footprint( stake_delegation_cnt ) ), stake_delegation_cnt ) );
  fd_vote_reward_t_mapnode_t * vote_reward_map_root = NULL;

  fd_vote_states_t const * vote_states = NULL;
  if( !is_recalculation ) {
    vote_states = fd_bank_vote_states_locking_query( slot_ctx->bank );
  } else {
    vote_states = fd_bank_vote_states_prev_locking_query( slot_ctx->bank );
  }
  if( FD_UNLIKELY( !vote_states ) ) {
    FD_LOG_CRIT(( "vote_states is NULL" ));
  }

  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_iter_ele( iter );

    if( FD_FEATURE_ACTIVE_BANK( slot_ctx->bank, stake_minimum_delegation_for_rewards ) ) {
      if( stake_delegation->stake<minimum_stake_delegation ) {
        continue;
      }
    }

    fd_pubkey_t const *   voter_acc      = &stake_delegation->vote_account;
    fd_vote_state_ele_t * vote_state_ele = fd_vote_states_query( vote_states, voter_acc );
    if( FD_UNLIKELY( !vote_state_ele ) ) {
      FD_LOG_DEBUG(( "failed to query vote state" ));
      continue;
    }

    /* Note, this doesn't actually redeem any rewards.. this is a misnomer. */
    fd_calculated_stake_rewards_t calculated_stake_rewards[1] = {0};

    int err = redeem_rewards(
        stake_history,
        stake_delegation,
        vote_state_ele,
        rewarded_epoch,
        point_value,
        new_warmup_cooldown_rate_epoch,
        calculated_stake_rewards );

    if( FD_UNLIKELY( err!=0 ) ) {
      FD_LOG_DEBUG(( "redeem_rewards failed for %s with error %d", FD_BASE58_ENC_32_ALLOCA( &stake_delegation->stake_account ), err ));
      continue;
    }

    if( capture_ctx ) {
      fd_solcap_write_stake_reward_event( capture_ctx->capture,
          &stake_delegation->stake_account,
          voter_acc,
          vote_state_ele->commission,
          (long)calculated_stake_rewards->voter_rewards,
          (long)calculated_stake_rewards->staker_rewards,
          (long)calculated_stake_rewards->new_credits_observed );
    }

    // Find and update the vote reward node in the local map
    fd_vote_reward_t_mapnode_t vote_map_key[1];
    vote_map_key->elem.pubkey = *voter_acc;
    fd_vote_reward_t_mapnode_t * vote_reward_node = fd_vote_reward_t_map_find( result->vote_reward_map_pool, result->vote_reward_map_root, vote_map_key );
    if( FD_UNLIKELY( vote_reward_node==NULL ) ) {
      FD_LOG_WARNING(( "vote account is missing from the vote rewards pool" ));
      continue;
    }

    vote_reward_node = fd_vote_reward_t_map_find( vote_reward_map_pool, vote_reward_map_root, vote_map_key );

    if( vote_reward_node==NULL ) {
      vote_reward_node                    = fd_vote_reward_t_map_acquire( vote_reward_map_pool );
      vote_reward_node->elem.pubkey       = *voter_acc;
      vote_reward_node->elem.commission   = vote_state_ele->commission;
      vote_reward_node->elem.vote_rewards = calculated_stake_rewards->voter_rewards;
      vote_reward_node->elem.needs_store  = 1;
      fd_vote_reward_t_map_insert( vote_reward_map_pool, &vote_reward_map_root, vote_reward_node );
    } else {
      vote_reward_node->elem.vote_rewards += calculated_stake_rewards->voter_rewards;
    }

    /* Add the stake reward to list of all stake rewards. The update is
      thread-safe because each index in the dlist is only ever accessed
      / written to once among all threads. */


    fd_stake_reward_t * stake_reward = fd_stake_reward_calculation_pool_ele_acquire( result->stake_reward_calculation.pool );
    if( FD_UNLIKELY( !stake_reward ) ) {
      FD_LOG_CRIT(( "insufficient space allocated for stake reward calculation pool" ));
    }

    fd_memcpy( stake_reward->stake_pubkey.uc, &stake_delegation->stake_account, sizeof(fd_pubkey_t) );
    stake_reward->lamports         = calculated_stake_rewards->staker_rewards;
    stake_reward->credits_observed = calculated_stake_rewards->new_credits_observed;
    stake_reward->valid            = 1;

    /* Update the total stake rewards */
    total_stake_rewards += calculated_stake_rewards->staker_rewards;
    dlist_additional_cnt++;

    fd_stake_reward_calculation_dlist_ele_push_tail( result->stake_reward_calculation.stake_rewards, stake_reward, result->stake_reward_calculation.pool );
  }

  if( !is_recalculation ) {
    fd_bank_vote_states_end_locking_query( slot_ctx->bank );
  } else {
    fd_bank_vote_states_prev_end_locking_query( slot_ctx->bank );
  }

  /* Merge vote rewards with result after */
  for( fd_vote_reward_t_mapnode_t * vote_reward_node = fd_vote_reward_t_map_minimum( vote_reward_map_pool, vote_reward_map_root );
        vote_reward_node;
        vote_reward_node = fd_vote_reward_t_map_successor( vote_reward_map_pool, vote_reward_node ) ) {

    fd_vote_reward_t_mapnode_t * result_reward_node = fd_vote_reward_t_map_find( result->vote_reward_map_pool, result->vote_reward_map_root, vote_reward_node );
    result_reward_node->elem.commission    = vote_reward_node->elem.commission;
    result_reward_node->elem.vote_rewards += vote_reward_node->elem.vote_rewards;
    result_reward_node->elem.needs_store   = 1;
  }

  result->stake_reward_calculation.total_stake_rewards_lamports += total_stake_rewards;
  result->stake_reward_calculation.stake_rewards_len            += dlist_additional_cnt;

  } FD_SPAD_FRAME_END;


}

/* Calculates epoch rewards for stake/vote accounts.
   Returns vote rewards, stake rewards, and the sum of all stake rewards
   in lamports.

   In future, the calculation will be cached in the snapshot, but
   for now we just re-calculate it (as Agave does).
   calculate_stake_vote_rewards is responsible for calculating
   stake account rewards based off of a combination of the
   stake delegation state as well as the vote account. If this
   calculation is done at the end of an epoch, we can just use the
   vote states at the end of the current epoch. However, because we
   are presumably booting up a node in the middle of rewards
   distribution, we need to make sure that we are using the vote
   states from the end of the previous epoch.

   https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L323 */
static void
calculate_stake_vote_rewards( fd_exec_slot_ctx_t *                       slot_ctx,
                              fd_stake_delegations_t const *             stake_delegations,
                              fd_capture_ctx_t *                         capture_ctx,
                              fd_stake_history_t const *                 stake_history,
                              ulong                                      rewarded_epoch,
                              fd_point_value_t *                         point_value,
                              fd_calculate_stake_vote_rewards_result_t * result,
                              fd_spad_t *                                runtime_spad,
                              int                                        is_recalculation ) {

  int _err[1];
  ulong   new_warmup_cooldown_rate_epoch_val = 0UL;
  ulong * new_warmup_cooldown_rate_epoch     = &new_warmup_cooldown_rate_epoch_val;
  int is_some = fd_new_warmup_cooldown_rate_epoch(
      fd_bank_epoch_schedule_query( slot_ctx->bank ),
      fd_bank_features_query( slot_ctx->bank ),
      fd_bank_slot_get( slot_ctx->bank ),
      new_warmup_cooldown_rate_epoch,
      _err );
  if( FD_UNLIKELY( !is_some ) ) {
    new_warmup_cooldown_rate_epoch = NULL;
  }

  ulong rewards_max_count = fd_stake_delegations_cnt( stake_delegations );

  /* Create the stake rewards pool and dlist. The pool will be destoyed after the stake rewards have been distributed. */
  result->stake_reward_calculation.pool = fd_stake_reward_calculation_pool_join( fd_stake_reward_calculation_pool_new( fd_spad_alloc( runtime_spad,
                                                                                                                                      fd_stake_reward_calculation_pool_align(),
                                                                                                                                      fd_stake_reward_calculation_pool_footprint( rewards_max_count ) ),
                                                                                                                                      rewards_max_count ) );
  result->stake_reward_calculation.stake_rewards = fd_spad_alloc( runtime_spad,
                                                                  fd_stake_reward_calculation_dlist_align(),
                                                                  fd_stake_reward_calculation_dlist_footprint() );

  fd_stake_reward_calculation_dlist_new( result->stake_reward_calculation.stake_rewards );
  result->stake_reward_calculation.stake_rewards_len = 0UL;

  fd_vote_states_t const * vote_states = NULL;
  if( !is_recalculation ) {
    vote_states = fd_bank_vote_states_locking_query( slot_ctx->bank );
  } else {
    vote_states = fd_bank_vote_states_prev_locking_query( slot_ctx->bank );
  }
  if( FD_UNLIKELY( !vote_states ) ) {
    FD_LOG_CRIT(( "vote_states is NULL" ));
  }

  /* Create the vote rewards map. This will be destroyed after the vote rewards have been distributed. */
  ulong vote_account_cnt       = fd_vote_states_cnt( vote_states );
  result->vote_reward_map_pool = fd_vote_reward_t_map_join( fd_vote_reward_t_map_new( fd_spad_alloc( runtime_spad,
                                                                                                     fd_vote_reward_t_map_align(),
                                                                                                     fd_vote_reward_t_map_footprint( vote_account_cnt )),
                                                                                      vote_account_cnt ) );
  result->vote_reward_map_root = NULL;

  /* Pre-fill the vote pubkeys in the vote rewards map pool */
  fd_vote_states_iter_t iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states ); !fd_vote_states_iter_done( iter ); fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t const * vote_state = fd_vote_states_iter_ele( iter );

    fd_vote_reward_t_mapnode_t * vote_reward_node = fd_vote_reward_t_map_acquire( result->vote_reward_map_pool );

    vote_reward_node->elem.pubkey       = vote_state->vote_account;
    vote_reward_node->elem.vote_rewards = 0UL;
    vote_reward_node->elem.needs_store  = 0;

    fd_vote_reward_t_map_insert( result->vote_reward_map_pool, &result->vote_reward_map_root, vote_reward_node );
  }

  if( !is_recalculation ) {
    fd_bank_vote_states_end_locking_query( slot_ctx->bank );
  } else {
    fd_bank_vote_states_prev_end_locking_query( slot_ctx->bank );
  }

  /* Loop over all the delegations
     https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L367  */
  calculate_stake_vote_rewards_account(
      slot_ctx,
      stake_delegations,
      capture_ctx,
      stake_history,
      rewarded_epoch,
      new_warmup_cooldown_rate_epoch,
      point_value,
      result,
      runtime_spad,
      is_recalculation );
}

/* Calculate epoch reward and return vote and stake rewards.

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L273 */
static void
calculate_validator_rewards( fd_exec_slot_ctx_t *                      slot_ctx,
                             fd_stake_delegations_t const *            stake_delegations,
                             fd_capture_ctx_t *                        capture_ctx,
                             ulong                                     rewarded_epoch,
                             ulong                                     rewards,
                             fd_calculate_validator_rewards_result_t * result,
                             fd_spad_t *                               runtime_spad ) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L2759-L2786 */
  fd_stake_history_t const * stake_history = fd_sysvar_stake_history_read( slot_ctx->funk, slot_ctx->funk_txn, runtime_spad );
    if( FD_UNLIKELY( !stake_history ) ) {
    FD_LOG_ERR(( "Unable to read and decode stake history sysvar" ));
  }

  /* Calculate the epoch reward points from stake/vote accounts */
  calculate_reward_points_partitioned(
      slot_ctx,
      stake_delegations,
      stake_history,
      rewards,
      &result->point_value );

  if( capture_ctx ) {
    ulong const epoch = fd_bank_epoch_get( slot_ctx->bank );
    fd_solcap_writer_stake_rewards_begin( capture_ctx->capture,
        epoch,
        epoch-1, /* FIXME this is not strictly correct */
        result->point_value.rewards,
        result->point_value.points );
  }

  /* Calculate the stake and vote rewards for each account. We want to
     use the vote states from the end of the current_epoch. */
  calculate_stake_vote_rewards(
      slot_ctx,
      stake_delegations,
      capture_ctx,
      stake_history,
      rewarded_epoch,
      &result->point_value,
      &result->calculate_stake_vote_rewards_result,
      runtime_spad,
      0 );
}

/* Calculate the number of blocks required to distribute rewards to all stake accounts.

    https://github.com/anza-xyz/agave/blob/9a7bf72940f4b3cd7fc94f54e005868ce707d53d/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L214
 */
static ulong
get_reward_distribution_num_blocks( fd_epoch_schedule_t const * epoch_schedule,
                                    ulong                       slot,
                                    ulong                       total_stake_accounts ) {
  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L1250-L1267 */
  if( epoch_schedule->warmup &&
      fd_slot_to_epoch( epoch_schedule, slot, NULL ) < epoch_schedule->first_normal_epoch ) {
    return 1UL;
  }

  ulong num_chunks = total_stake_accounts / (ulong)STAKE_ACCOUNT_STORES_PER_BLOCK + (total_stake_accounts % STAKE_ACCOUNT_STORES_PER_BLOCK != 0);
  num_chunks       = fd_ulong_max( num_chunks, 1UL );
  num_chunks       = fd_ulong_min( num_chunks,
                                   fd_ulong_max( epoch_schedule->slots_per_epoch / (ulong)MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH, 1UL ) );
  return num_chunks;
}

static void
hash_rewards_into_partitions( fd_bank_t *                     bank,
                              fd_stake_reward_calculation_t * stake_reward_calculation,
                              fd_hash_t const *               parent_blockhash,
                              ulong                           num_partitions ) {

  fd_epoch_rewards_t * epoch_rewards = fd_epoch_rewards_join( fd_epoch_rewards_new( fd_bank_epoch_rewards_locking_modify( bank ), FD_RUNTIME_MAX_STAKE_ACCOUNTS ) );
  if( FD_UNLIKELY( !epoch_rewards ) ) {
    FD_LOG_CRIT(( "failed to join epoch rewards" ));
  }
  fd_epoch_rewards_set_num_partitions( epoch_rewards, num_partitions );

  /* Iterate over all the stake rewards, moving references to them into the appropiate partitions.
      IMPORTANT: after this, we cannot use the original stake rewards dlist anymore. */
  fd_stake_reward_calculation_dlist_iter_t next_iter;
  for( fd_stake_reward_calculation_dlist_iter_t iter = fd_stake_reward_calculation_dlist_iter_fwd_init( stake_reward_calculation->stake_rewards, stake_reward_calculation->pool );
        !fd_stake_reward_calculation_dlist_iter_done( iter, stake_reward_calculation->stake_rewards, stake_reward_calculation->pool );
        iter = next_iter ) {
    fd_stake_reward_t * stake_reward = fd_stake_reward_calculation_dlist_iter_ele( iter, stake_reward_calculation->stake_rewards, stake_reward_calculation->pool );
    /* Cache the next iter here, as we will overwrite the DLIST_NEXT value further down in the loop iteration. */
    next_iter = fd_stake_reward_calculation_dlist_iter_fwd_next( iter, stake_reward_calculation->stake_rewards, stake_reward_calculation->pool );

    if( FD_UNLIKELY( !stake_reward->valid ) ) {
      continue;
    }

    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/epoch_rewards_hasher.rs#L43C31-L61 */
    int err = fd_epoch_rewards_hash_and_insert(
        epoch_rewards,
        parent_blockhash,
        &stake_reward->stake_pubkey,
        stake_reward->credits_observed,
        stake_reward->lamports );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_CRIT(( "failed to hash and insert stake reward" ));
    }
  }

  fd_bank_epoch_rewards_end_locking_modify( bank );
}

/* Calculate rewards from previous epoch to prepare for partitioned distribution.

   https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L214 */
static void
calculate_rewards_for_partitioning( fd_exec_slot_ctx_t *                   slot_ctx,
                                    fd_stake_delegations_t const *         stake_delegations,
                                    fd_capture_ctx_t *                     capture_ctx,
                                    ulong                                  prev_epoch,
                                    const fd_hash_t *                      parent_blockhash,
                                    fd_partitioned_rewards_calculation_t * result,
                                    fd_spad_t *                            runtime_spad ) {
  /* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L227 */
  fd_prev_epoch_inflation_rewards_t rewards;

  calculate_previous_epoch_inflation_rewards( slot_ctx->bank,
                                              fd_bank_capitalization_get( slot_ctx->bank ),
                                              prev_epoch,
                                              &rewards );

  fd_calculate_validator_rewards_result_t validator_result[1] = {0};
  calculate_validator_rewards( slot_ctx,
                               stake_delegations,
                               capture_ctx,
                               prev_epoch,
                               rewards.validator_rewards,
                               validator_result,
                               runtime_spad );

  fd_stake_reward_calculation_t * stake_reward_calculation = &validator_result->calculate_stake_vote_rewards_result.stake_reward_calculation;
  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( slot_ctx->bank );

  ulong num_partitions = get_reward_distribution_num_blocks(
      epoch_schedule,
      fd_bank_slot_get( slot_ctx->bank ),
      stake_reward_calculation->stake_rewards_len );
  hash_rewards_into_partitions(
      slot_ctx->bank,
      stake_reward_calculation,
      parent_blockhash,
      num_partitions );

  result->stake_rewards_by_partition.total_stake_rewards_lamports =
    validator_result->calculate_stake_vote_rewards_result.stake_reward_calculation.total_stake_rewards_lamports;

  result->vote_reward_map_pool         = validator_result->calculate_stake_vote_rewards_result.vote_reward_map_pool;
  result->vote_reward_map_root         = validator_result->calculate_stake_vote_rewards_result.vote_reward_map_root;
  result->validator_rewards            = rewards.validator_rewards;
  result->validator_rate               = rewards.validator_rate;
  result->foundation_rate              = rewards.foundation_rate;
  result->prev_epoch_duration_in_years = rewards.prev_epoch_duration_in_years;
  result->capitalization               = fd_bank_capitalization_get( slot_ctx->bank );
  result->point_value                  = validator_result->point_value;
}

/* Calculate rewards from previous epoch and distribute vote rewards

   https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L97 */
static void
calculate_rewards_and_distribute_vote_rewards( fd_exec_slot_ctx_t *           slot_ctx,
                                               fd_stake_delegations_t const * stake_delegations,
                                               fd_capture_ctx_t *             capture_ctx,
                                               ulong                          prev_epoch,
                                               fd_hash_t const *              parent_blockhash,
                                               fd_spad_t *                    runtime_spad ) {

  /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L2406-L2492 */
  fd_partitioned_rewards_calculation_t rewards_calc_result[1] = {0};
  calculate_rewards_for_partitioning( slot_ctx,
                                      stake_delegations,
                                      capture_ctx,
                                      prev_epoch,
                                      parent_blockhash,
                                      rewards_calc_result,
                                      runtime_spad );

  /* Iterate over all the vote reward nodes */
  ulong distributed_rewards = 0UL;
  for( fd_vote_reward_t_mapnode_t * vote_reward_node = fd_vote_reward_t_map_minimum( rewards_calc_result->vote_reward_map_pool, rewards_calc_result->vote_reward_map_root);
       vote_reward_node;
       vote_reward_node = fd_vote_reward_t_map_successor( rewards_calc_result->vote_reward_map_pool, vote_reward_node ) ) {

    if( FD_UNLIKELY( !vote_reward_node->elem.needs_store ) ) {
      continue;
    }

    fd_pubkey_t const * vote_pubkey = &vote_reward_node->elem.pubkey;
    FD_TXN_ACCOUNT_DECL( vote_rec );
    fd_funk_rec_prepare_t prepare = {0};

    if( FD_UNLIKELY( fd_txn_account_init_from_funk_mutable( vote_rec,
                                                            vote_pubkey,
                                                            slot_ctx->funk,
                                                            slot_ctx->funk_txn,
                                                            1,
                                                            0UL,
                                                            &prepare )!=FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_ERR(( "Unable to modify vote account" ));
    }

    fd_lthash_value_t prev_hash[1];
    fd_hashes_account_lthash(
      vote_pubkey,
      fd_txn_account_get_meta( vote_rec ),
      fd_txn_account_get_data( vote_rec ),
      prev_hash );

    fd_txn_account_set_slot( vote_rec, fd_bank_slot_get( slot_ctx->bank ) );

    if( FD_UNLIKELY( fd_txn_account_checked_add_lamports( vote_rec, vote_reward_node->elem.vote_rewards ) ) ) {
      FD_LOG_ERR(( "Adding lamports to vote account would cause overflow" ));
    }

    fd_hashes_update_lthash( vote_rec, prev_hash,slot_ctx->bank, capture_ctx );
    fd_txn_account_mutable_fini( vote_rec, slot_ctx->funk, slot_ctx->funk_txn, &prepare );

    distributed_rewards = fd_ulong_sat_add( distributed_rewards, vote_reward_node->elem.vote_rewards );

    if( capture_ctx ) {
      fd_solcap_write_vote_account_payout( capture_ctx->capture,
          vote_pubkey,
          fd_bank_slot_get( slot_ctx->bank ),
          fd_txn_account_get_lamports( vote_rec ),
          (long)vote_reward_node->elem.vote_rewards );
    }
  }

  /* There is no need to free the vote reward map since it was spad*/

  /* Verify that we didn't pay any more than we expected to */
  ulong total_rewards = fd_ulong_sat_add( distributed_rewards, rewards_calc_result->stake_rewards_by_partition.total_stake_rewards_lamports );
  if( FD_UNLIKELY( rewards_calc_result->validator_rewards<total_rewards ) ) {
    FD_LOG_CRIT(( "Unexpected rewards calculation result" ));
  }

  fd_bank_capitalization_set( slot_ctx->bank, fd_bank_capitalization_get( slot_ctx->bank ) + distributed_rewards );

  fd_epoch_rewards_t * epoch_rewards = fd_bank_epoch_rewards_locking_modify( slot_ctx->bank );
  fd_epoch_rewards_set_distributed_rewards( epoch_rewards, distributed_rewards );
  fd_epoch_rewards_set_total_rewards( epoch_rewards, rewards_calc_result->point_value.rewards );
  fd_epoch_rewards_set_total_points( epoch_rewards, rewards_calc_result->point_value.points );
  fd_bank_epoch_rewards_end_locking_modify( slot_ctx->bank );
}

/* Distributes a single partitioned reward to a single stake account */
static int
distribute_epoch_reward_to_stake_acc( fd_exec_slot_ctx_t * slot_ctx,
                                      fd_capture_ctx_t *   capture_ctx,
                                      fd_pubkey_t *        stake_pubkey,
                                      ulong                reward_lamports,
                                      ulong                new_credits_observed ) {
  FD_TXN_ACCOUNT_DECL( stake_acc_rec );
  fd_funk_rec_prepare_t prepare = {0};
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_mutable( stake_acc_rec,
                                                          stake_pubkey,
                                                          slot_ctx->funk,
                                                          slot_ctx->funk_txn,
                                                          0,
                                                          0UL,
                                                          &prepare )!=FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_ERR(( "Unable to modify stake account" ));
  }

  fd_lthash_value_t prev_hash[1];
  fd_hashes_account_lthash(
    stake_pubkey,
    fd_txn_account_get_meta( stake_acc_rec ),
    fd_txn_account_get_data( stake_acc_rec ),
    prev_hash );

  fd_txn_account_set_slot( stake_acc_rec, fd_bank_slot_get( slot_ctx->bank ) );

  fd_stake_state_v2_t stake_state[1] = {0};
  if( fd_stake_get_state( stake_acc_rec, stake_state ) != 0 ) {
    FD_LOG_DEBUG(( "failed to read stake state for %s", FD_BASE58_ENC_32_ALLOCA( stake_pubkey ) ));
    return 1;
  }

  if ( !fd_stake_state_v2_is_stake( stake_state ) ) {
    FD_LOG_DEBUG(( "non-stake stake account, this should never happen" ));
    return 1;
  }

  if( fd_txn_account_checked_add_lamports( stake_acc_rec, reward_lamports ) ) {
    FD_LOG_DEBUG(( "failed to add lamports to stake account" ));
    return 1;
  }

  ulong old_credits_observed = stake_state->inner.stake.stake.credits_observed;
  stake_state->inner.stake.stake.credits_observed = new_credits_observed;
  stake_state->inner.stake.stake.delegation.stake = fd_ulong_sat_add( stake_state->inner.stake.stake.delegation.stake,
                                                                      reward_lamports );

  /* The stake account has just been updated, so we need to update the
     stake delegations stored in the bank. */
  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_delta_locking_modify( slot_ctx->bank );
  fd_stake_delegations_update(
      stake_delegations,
      stake_pubkey,
      &stake_state->inner.stake.stake.delegation.voter_pubkey,
      stake_state->inner.stake.stake.delegation.stake,
      stake_state->inner.stake.stake.delegation.activation_epoch,
      stake_state->inner.stake.stake.delegation.deactivation_epoch,
      stake_state->inner.stake.stake.credits_observed,
      stake_state->inner.stake.stake.delegation.warmup_cooldown_rate );
  fd_bank_stake_delegations_delta_end_locking_modify( slot_ctx->bank );

  if( capture_ctx ) {
    fd_solcap_write_stake_account_payout( capture_ctx->capture,
        stake_pubkey,
        fd_bank_slot_get( slot_ctx->bank ),
        fd_txn_account_get_lamports( stake_acc_rec ),
        (long)reward_lamports,
        new_credits_observed,
        (long)( new_credits_observed-old_credits_observed ),
        stake_state->inner.stake.stake.delegation.stake,
        (long)reward_lamports );
  }

  if( FD_UNLIKELY( write_stake_state( stake_acc_rec, stake_state ) != 0 ) ) {
    FD_LOG_ERR(( "write_stake_state failed" ));
  }

  fd_hashes_update_lthash( stake_acc_rec, prev_hash, slot_ctx->bank, capture_ctx );
  fd_txn_account_mutable_fini( stake_acc_rec, slot_ctx->funk, slot_ctx->funk_txn, &prepare );

  return 0;
}

/* Sets the epoch reward status to inactive, and destroys any allocated state associated with the active state. */
static void
set_epoch_reward_status_inactive( fd_bank_t * bank ) {
  fd_epoch_rewards_t * epoch_rewards = fd_bank_epoch_rewards_locking_modify( bank );
  if( fd_epoch_rewards_is_active( epoch_rewards ) ) {
    FD_LOG_NOTICE(( "Done partitioning rewards for current epoch" ));
  }
  fd_epoch_rewards_set_active( epoch_rewards, 0 );
  fd_bank_epoch_rewards_end_locking_modify( bank );
}

/* Sets the epoch reward status to active.

    Takes ownership of the given stake_rewards_by_partition data structure,
    which will be destroyed when set_epoch_reward_status_inactive is called. */
static void
set_epoch_reward_status_active( fd_exec_slot_ctx_t * slot_ctx,
                                ulong                distribution_starting_block_height ) {
  FD_LOG_NOTICE(( "Setting epoch reward status as active" ));

  fd_epoch_rewards_t * epoch_rewards = fd_bank_epoch_rewards_locking_modify( slot_ctx->bank );

  fd_epoch_rewards_set_active( epoch_rewards, 1 );
  fd_epoch_rewards_set_starting_block_height( epoch_rewards, distribution_starting_block_height );
  fd_bank_epoch_rewards_end_locking_modify( slot_ctx->bank );
}

/*  Process reward credits for a partition of rewards.
    Store the rewards to AccountsDB, update reward history record and total capitalization

    https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L88 */
static void
distribute_epoch_rewards_in_partition( fd_epoch_stake_reward_dlist_t * stake_reward_dlist,
                                       fd_epoch_stake_reward_t *       stake_reward_pool,
                                       fd_exec_slot_ctx_t *            slot_ctx,
                                       fd_capture_ctx_t *              capture_ctx ) {

  ulong lamports_distributed = 0UL;
  ulong lamports_burned      = 0UL;

  for( fd_epoch_stake_reward_dlist_iter_t iter = fd_epoch_stake_reward_dlist_iter_fwd_init( stake_reward_dlist, stake_reward_pool );
        !fd_epoch_stake_reward_dlist_iter_done( iter, stake_reward_dlist, stake_reward_pool );
        iter = fd_epoch_stake_reward_dlist_iter_fwd_next( iter, stake_reward_dlist, stake_reward_pool ) ) {
    fd_epoch_stake_reward_t * stake_reward = fd_epoch_stake_reward_dlist_iter_ele( iter, stake_reward_dlist, stake_reward_pool );
    if( FD_LIKELY( !distribute_epoch_reward_to_stake_acc(
        slot_ctx,
        capture_ctx,
        &stake_reward->stake_pubkey,
        stake_reward->lamports,
        stake_reward->credits_observed ) )  ) {
      lamports_distributed += stake_reward->lamports;
    } else {
      lamports_burned += stake_reward->lamports;
    }
  }

  /* Update the epoch rewards sysvar with the amount distributed and burnt */
  fd_sysvar_epoch_rewards_distribute( slot_ctx, lamports_distributed + lamports_burned );

  FD_LOG_DEBUG(( "lamports burned: %lu, lamports distributed: %lu", lamports_burned, lamports_distributed ));

  fd_bank_capitalization_set( slot_ctx->bank, fd_bank_capitalization_get( slot_ctx->bank ) + lamports_distributed );
}

/* Process reward distribution for the block if it is inside reward interval.

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L42 */
void
fd_distribute_partitioned_epoch_rewards( fd_exec_slot_ctx_t * slot_ctx,
                                         fd_capture_ctx_t *   capture_ctx ) {

  fd_epoch_rewards_t const * epoch_rewards = fd_bank_epoch_rewards_locking_query( slot_ctx->bank );

  if( !fd_epoch_rewards_is_active( epoch_rewards ) ) {
    fd_bank_epoch_rewards_end_locking_query( slot_ctx->bank );
    return;
  }

  ulong height                             = fd_bank_block_height_get( slot_ctx->bank );
  ulong distribution_starting_block_height = fd_epoch_rewards_get_starting_block_height( epoch_rewards );
  ulong distribution_end_exclusive         = fd_epoch_rewards_get_exclusive_ending_block_height( epoch_rewards );

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( slot_ctx->bank );
  ulong                       epoch          = fd_bank_epoch_get( slot_ctx->bank );

  if( FD_UNLIKELY( get_slots_in_epoch( epoch, epoch_schedule ) <= fd_epoch_rewards_get_num_partitions( epoch_rewards ) ) ) {
    FD_LOG_CRIT(( "Should not be distributing rewards" ));
  }

  if( (height>=distribution_starting_block_height) && (height < distribution_end_exclusive) ) {

    fd_epoch_stake_reward_t * stake_reward_pool = fd_epoch_rewards_get_stake_reward_pool( epoch_rewards );
    if( FD_UNLIKELY( !stake_reward_pool ) ) {
      FD_LOG_CRIT(( "failed to get stake reward pool" ));
    }

    ulong                           partition_index    = height - distribution_starting_block_height;
    fd_epoch_stake_reward_dlist_t * stake_reward_dlist = fd_epoch_rewards_get_partition_index( epoch_rewards, partition_index );
    if( FD_UNLIKELY( !stake_reward_dlist ) ) {
      FD_LOG_CRIT(( "failed to get partition dlist" ));
    }

    distribute_epoch_rewards_in_partition( stake_reward_dlist,
                                           stake_reward_pool,
                                           slot_ctx,
                                           capture_ctx );
  }

  fd_bank_epoch_rewards_end_locking_query( slot_ctx->bank );

  /* If we have finished distributing rewards, set the status to inactive */
  if( fd_ulong_sat_add( height, 1UL ) >= distribution_end_exclusive ) {
    set_epoch_reward_status_inactive( slot_ctx->bank );
    fd_sysvar_epoch_rewards_set_inactive( slot_ctx );
  }
}

/* Partitioned epoch rewards entry-point.

   https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L41
*/
void
fd_begin_partitioned_rewards( fd_exec_slot_ctx_t *           slot_ctx,
                              fd_stake_delegations_t const * stake_delegations,
                              fd_capture_ctx_t *             capture_ctx,
                              fd_hash_t const *              parent_blockhash,
                              ulong                          parent_epoch,
                              fd_spad_t *                    runtime_spad ) {

  /* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L55 */
  calculate_rewards_and_distribute_vote_rewards(
      slot_ctx,
      stake_delegations,
      capture_ctx,
      parent_epoch,
      parent_blockhash,
      runtime_spad );

  /* https://github.com/anza-xyz/agave/blob/9a7bf72940f4b3cd7fc94f54e005868ce707d53d/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L62 */
  ulong distribution_starting_block_height = fd_bank_block_height_get( slot_ctx->bank ) + REWARD_CALCULATION_NUM_BLOCKS;

  /* Set the epoch reward status to be active */
  set_epoch_reward_status_active( slot_ctx, distribution_starting_block_height );

  /* Initialize the epoch rewards sysvar
    https://github.com/anza-xyz/agave/blob/9a7bf72940f4b3cd7fc94f54e005868ce707d53d/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L78 */
  fd_epoch_rewards_t const * epoch_rewards = fd_bank_epoch_rewards_locking_query( slot_ctx->bank );
  fd_sysvar_epoch_rewards_init(
      slot_ctx,
      fd_epoch_rewards_get_distributed_rewards( epoch_rewards ),
      distribution_starting_block_height,
      fd_epoch_rewards_get_num_partitions( epoch_rewards ),
      fd_epoch_rewards_get_total_rewards( epoch_rewards ),
      fd_epoch_rewards_get_total_points( epoch_rewards ),
      parent_blockhash );
  fd_bank_epoch_rewards_end_locking_query( slot_ctx->bank );
}

/*
    Re-calculates partitioned stake rewards.
    This updates the slot context's epoch reward status with the recalculated partitioned rewards.

    https://github.com/anza-xyz/agave/blob/v2.2.14/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L521 */
void
fd_rewards_recalculate_partitioned_rewards( fd_exec_slot_ctx_t * slot_ctx,
                                            fd_capture_ctx_t *   capture_ctx,
                                            fd_spad_t *          runtime_spad ) {
  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  fd_sysvar_epoch_rewards_t epoch_rewards[1];
  if( FD_UNLIKELY( !fd_sysvar_epoch_rewards_read( slot_ctx->funk, slot_ctx->funk_txn, epoch_rewards ) ) ) {
    FD_LOG_DEBUG(( "Failed to read or decode epoch rewards sysvar - may not have been created yet" ));
    set_epoch_reward_status_inactive( slot_ctx->bank );
    return;
  }

  FD_LOG_NOTICE(( "recalculating partitioned rewards" ));

  if( FD_UNLIKELY( epoch_rewards->active ) ) {

    /* If partitioned rewards are active, the rewarded epoch is always the immediately
        preceeding epoch.

        https://github.com/anza-xyz/agave/blob/2316fea4c0852e59c071f72d72db020017ffd7d0/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L566 */
    FD_LOG_NOTICE(( "epoch rewards is active" ));

    ulong const slot           = fd_bank_slot_get( slot_ctx->bank );
    ulong const epoch          = fd_bank_epoch_get( slot_ctx->bank );
    ulong const rewarded_epoch = fd_ulong_sat_sub( epoch, 1UL );

    int _err[1] = {0};
    ulong new_warmup_cooldown_rate_epoch_;
    ulong * new_warmup_cooldown_rate_epoch = &new_warmup_cooldown_rate_epoch_;
    int is_some = fd_new_warmup_cooldown_rate_epoch(
        fd_bank_epoch_schedule_query( slot_ctx->bank ),
        fd_bank_features_query( slot_ctx->bank ),
        slot,
        new_warmup_cooldown_rate_epoch,
        _err );
    if( FD_UNLIKELY( !is_some ) ) {
      new_warmup_cooldown_rate_epoch = NULL;
    }

    fd_stake_history_t const * stake_history = fd_sysvar_stake_history_read( slot_ctx->funk, slot_ctx->funk_txn, runtime_spad );
    if( FD_UNLIKELY( !stake_history ) ) {
      FD_LOG_ERR(( "Unable to read and decode stake history sysvar" ));
    }

    fd_point_value_t point_value = { .points  = epoch_rewards->total_points,
                                     .rewards = epoch_rewards->total_rewards };

    fd_stake_history_entry_t _accumulator = {
        .effective   = 0UL,
        .activating  = 0UL,
        .deactivating = 0UL
    };

    fd_stake_delegations_t const * stake_delegations = fd_bank_stake_delegations_frontier_query( slot_ctx->banks, slot_ctx->bank );
    if( FD_UNLIKELY( !stake_delegations ) ) {
      FD_LOG_CRIT(( "stake_delegations is NULL" ));
    }

    fd_accumulate_stake_infos(
        epoch,
        stake_delegations,
        stake_history,
        new_warmup_cooldown_rate_epoch,
        &_accumulator );

    /* Make sure is_recalculation is ==1 since we are booting up in the
       middle of rewards distribution (so we should use the epoch
       stakes for the end of epoch E-1 since we are still distributing
       rewards for the previous epoch). */
    fd_calculate_stake_vote_rewards_result_t calculate_stake_vote_rewards_result[1];
    calculate_stake_vote_rewards(
        slot_ctx,
        stake_delegations,
        capture_ctx,
        stake_history,
        rewarded_epoch,
        &point_value,
        calculate_stake_vote_rewards_result,
        runtime_spad,
        1 /* is_recalculation */ );

    /* The vote reward map isn't actually used in this code path and
       will only be freed after rewards have been distributed. */


    /* Use the epoch rewards sysvar parent_blockhash and num_partitions.
       https://github.com/anza-xyz/agave/blob/v2.2.14/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L579 */
    hash_rewards_into_partitions(
        slot_ctx->bank,
        &calculate_stake_vote_rewards_result->stake_reward_calculation,
        &epoch_rewards->parent_blockhash,
        epoch_rewards->num_partitions );

    /* Update the epoch reward status with the newly re-calculated partitions. */
    set_epoch_reward_status_active( slot_ctx, epoch_rewards->distribution_starting_block_height );
  } else {
    set_epoch_reward_status_inactive( slot_ctx->bank );
  }

  } FD_SPAD_FRAME_END;
}
