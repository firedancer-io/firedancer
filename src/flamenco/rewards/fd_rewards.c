#include "fd_rewards.h"
#include "fd_stake_rewards.h"
#include <math.h>

#include "../runtime/sysvar/fd_sysvar_epoch_rewards.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../stakes/fd_stakes.h"
#include "../runtime/program/fd_stake_program.h"
#include "../runtime/program/vote/fd_vote_state_versioned.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../capture/fd_capture_ctx.h"
#include "../runtime/fd_runtime_stack.h"
#include "../runtime/fd_runtime.h"
#include "../accdb/fd_accdb_sync.h"

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

  ulong enable = fd_bank_features_query( bank )->full_inflation_enable;

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


static void
get_vote_credits_commission( uchar const *       account_data,
                             ulong               account_data_len,
                             uchar *             buf,
                             fd_vote_rewards_t * vote_ele ) {

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
  case fd_vote_state_versioned_enum_v0_23_5:
    vote_credits           = vsv->inner.v0_23_5.epoch_credits;
    vote_ele->commission   = vsv->inner.v0_23_5.commission;
    vote_ele->node_account = vsv->inner.v0_23_5.node_pubkey;
    break;
  case fd_vote_state_versioned_enum_v1_14_11:
    vote_credits           = vsv->inner.v1_14_11.epoch_credits;
    vote_ele->commission   = vsv->inner.v1_14_11.commission;
    vote_ele->node_account = vsv->inner.v1_14_11.node_pubkey;
    break;
  case fd_vote_state_versioned_enum_v3:
    vote_credits           = vsv->inner.v3.epoch_credits;
    vote_ele->commission   = vsv->inner.v3.commission;
    vote_ele->node_account = vsv->inner.v3.node_pubkey;
    break;
  case fd_vote_state_versioned_enum_v4:
    vote_credits           = vsv->inner.v4.epoch_credits;
    vote_ele->commission   = (uchar)(vsv->inner.v4.inflation_rewards_commission_bps/100);
    vote_ele->node_account = vsv->inner.v4.node_pubkey;
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

/* For a given stake and vote_state, calculate how many points were earned (credits * stake) and new value
   for credits_observed were the points paid

    https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L109 */
static void
calculate_stake_points_and_credits( fd_stake_history_t const *     stake_history,
                                    fd_stake_delegation_t const *  stake,
                                    fd_runtime_stack_t *           runtime_stack,
                                    ulong                          vote_state_idx,
                                    ulong *                        new_rate_activation_epoch,
                                    fd_calculated_stake_points_t * result ) {

  fd_vote_rewards_t * vote_ele = &runtime_stack->stakes.vote_ele[ vote_state_idx ];

  ulong credits_in_stake = stake->credits_observed;
  ulong credits_cnt      = vote_ele->epoch_credits.cnt;
  ulong credits_in_vote  = credits_cnt > 0UL ? vote_ele->epoch_credits.credits[ credits_cnt - 1UL ] : 0UL;

  /* If the Vote account has less credits observed than the Stake account,
      something is wrong and we need to force an update.

      https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L142 */
  if( FD_UNLIKELY( credits_in_vote < credits_in_stake ) ) {
    result->points.ud = 0;
    result->new_credits_observed = credits_in_vote;
    result->force_credits_update_with_skipped_reward = 1;
    return;
  }

  /* If the Vote account has the same amount of credits observed as the Stake account,
      then the Vote account hasn't earnt any credits and so there is nothing to update.

      https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L148 */
  if( FD_UNLIKELY( credits_in_vote == credits_in_stake ) ) {
    result->points.ud = 0;
    result->new_credits_observed = credits_in_vote;
    result->force_credits_update_with_skipped_reward = 0;
    return;
  }

  /* Calculate the points for each epoch credit */
  uint128 points               = 0;
  ulong   new_credits_observed = credits_in_stake;
  for( ulong i=0UL; i<vote_ele->epoch_credits.cnt; i++ ) {

    ulong final_epoch_credits   = vote_ele->epoch_credits.credits[ i ];
    ulong initial_epoch_credits = vote_ele->epoch_credits.prev_credits[ i ];
    uint128 earned_credits = 0;
    if( FD_LIKELY( credits_in_stake < initial_epoch_credits ) ) {
      earned_credits = (uint128)(final_epoch_credits - initial_epoch_credits);
    } else if( FD_UNLIKELY( credits_in_stake < final_epoch_credits ) ) {
      earned_credits = (uint128)(final_epoch_credits - new_credits_observed);
    }

    new_credits_observed = fd_ulong_max( new_credits_observed, final_epoch_credits );

    ulong stake_amount = fd_stake_activating_and_deactivating(
        stake,
        vote_ele->epoch_credits.epoch[ i ],
        stake_history,
        new_rate_activation_epoch ).effective;

    points += (uint128)stake_amount * earned_credits;
  }

  result->points.ud = points;
  result->new_credits_observed = new_credits_observed;
  result->force_credits_update_with_skipped_reward = 0;
}

struct fd_commission_split {
  ulong voter_portion;
  ulong staker_portion;
  uint  is_split;
};
typedef struct fd_commission_split fd_commission_split_t;

/// returns commission split as (voter_portion, staker_portion, was_split) tuple
///
/// if commission calculation is 100% one way or other, indicate with false for was_split

// https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L543
void
fd_vote_commission_split( uchar                   commission,
                          ulong                   on,
                          fd_commission_split_t * result ) {
  uint commission_split = fd_uint_min( (uint)commission, 100 );
  result->is_split      = (commission_split != 0 && commission_split != 100);
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L545
  if( commission_split==0U ) {
    result->voter_portion  = 0;
    result->staker_portion = on;
    return;
  }
  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L546
  if( commission_split==100U ) {
    result->voter_portion  = on;
    result->staker_portion = 0;
    return;
  }
  /* Note: order of operations may matter for int division. That's why I didn't make the
   * optimization of getting out the common calculations */

  // ... This is copied from the solana comments...
  //
  // Calculate mine and theirs independently and symmetrically instead
  // of using the remainder of the other to treat them strictly
  // equally. This is also to cancel the rewarding if either of the
  // parties should receive only fractional lamports, resulting in not
  // being rewarded at all. Thus, note that we intentionally discard
  // any residual fractional lamports.

  // https://github.com/anza-xyz/agave/blob/v2.0.1/sdk/program/src/vote/state/mod.rs#L548
  result->voter_portion =
      (ulong)((uint128)on * (uint128)commission_split / (uint128)100);
  result->staker_portion =
      (ulong)((uint128)on * (uint128)( 100 - commission_split ) / (uint128)100);
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/rewards.rs#L33 */
static int
redeem_rewards( fd_stake_delegation_t const *   stake,
                ulong                           vote_state_idx,
                ulong                           rewarded_epoch,
                ulong                           total_rewards,
                uint128                         total_points,
                fd_runtime_stack_t *            runtime_stack,
                fd_calculated_stake_rewards_t * result ) {

  /* The firedancer implementation of redeem_rewards inlines a lot of
     the helper functions that the Agave implementation uses.
     In Agave: redeem_rewards calls redeem_stake_rewards which calls
     calculate_stake_rewards. */

  fd_calculated_stake_points_t stake_points_result = runtime_stack->stakes.stake_points_result[ stake->idx ];

  // Drive credits_observed forward unconditionally when rewards are disabled
  // or when this is the stake's activation epoch
  if( total_rewards==0UL || stake->activation_epoch==rewarded_epoch ) {
      stake_points_result.force_credits_update_with_skipped_reward = 1;
  }

  if( stake_points_result.force_credits_update_with_skipped_reward ) {
    result->staker_rewards       = 0;
    result->voter_rewards        = 0;
    result->new_credits_observed = stake_points_result.new_credits_observed;
    return 0;
  }
  if( stake_points_result.points.ud==0 || total_points==0 ) {
    return 1;
  }

  uint128 rewards_u128;
  if( FD_UNLIKELY( __builtin_mul_overflow( stake_points_result.points.ud, (uint128)(total_rewards), &rewards_u128 ) ) ) {
    FD_LOG_ERR(( "Rewards intermediate calculation should fit within u128" ));
  }

  FD_TEST( total_points );
  rewards_u128 /=  (uint128) total_points;

  if( FD_UNLIKELY( rewards_u128>(uint128)ULONG_MAX ) ) {
    FD_LOG_ERR(( "Rewards should fit within u64" ));
  }

  ulong rewards = (ulong)rewards_u128;
  if( rewards == 0 ) {
    return 1;
  }

  uchar commission = runtime_stack->stakes.vote_ele[ vote_state_idx ].commission;
  fd_commission_split_t split_result;
  fd_vote_commission_split( commission, rewards, &split_result );
  if( split_result.is_split && (split_result.voter_portion == 0 || split_result.staker_portion == 0) ) {
    return 1;
  }

  result->staker_rewards       = split_result.staker_portion;
  result->voter_rewards        = split_result.voter_portion;
  result->new_credits_observed = stake_points_result.new_credits_observed;
  return 0;
}

/* Returns the length of the given epoch in slots

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/sdk/program/src/epoch_schedule.rs#L103 */
static ulong
get_slots_in_epoch( ulong                       epoch,
                    fd_epoch_schedule_t const * epoch_schedule ) {
  return epoch < epoch_schedule->first_normal_epoch ?
         1UL << fd_ulong_sat_add( epoch, FD_EPOCH_LEN_MIN_TRAILING_ZERO ) :
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
get_minimum_stake_delegation( fd_bank_t * bank ) {
  if( !FD_FEATURE_ACTIVE_BANK( bank, stake_minimum_delegation_for_rewards ) ) {
    return 0UL;
  }

  if( FD_FEATURE_ACTIVE_BANK( bank, stake_raise_minimum_delegation_to_1_sol ) ) {
    return LAMPORTS_PER_SOL;
  }

  return 1;
}

/* Calculate the number of blocks required to distribute rewards to all stake accounts.

    https://github.com/anza-xyz/agave/blob/9a7bf72940f4b3cd7fc94f54e005868ce707d53d/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L214
 */
 static uint
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
   return (uint)num_chunks;
 }

/* Calculates epoch reward points from stake/vote accounts.
   https://github.com/anza-xyz/agave/blob/v2.3.1/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L445 */
static uint128
calculate_reward_points_partitioned( fd_bank_t *                    bank,
                                     fd_stake_delegations_t const * stake_delegations,
                                     fd_stake_history_t const *     stake_history,
                                     fd_runtime_stack_t *           runtime_stack ) {
  ulong minimum_stake_delegation = get_minimum_stake_delegation( bank );

  /* Calculate the points for each stake delegation */
  int _err[1];
  ulong   new_warmup_cooldown_rate_epoch_val = 0UL;
  ulong * new_warmup_cooldown_rate_epoch     = &new_warmup_cooldown_rate_epoch_val;
  int is_some = fd_new_warmup_cooldown_rate_epoch(
      fd_bank_epoch_schedule_query( bank ),
      fd_bank_features_query( bank ),
      new_warmup_cooldown_rate_epoch,
      _err );
  if( FD_UNLIKELY( !is_some ) ) {
    new_warmup_cooldown_rate_epoch = NULL;
  }

  uint128 total_points = 0;

  fd_vote_rewards_t *     vote_ele     = runtime_stack->stakes.vote_ele;
  fd_vote_rewards_map_t * vote_ele_map = fd_type_pun( runtime_stack->stakes.vote_map_mem );

  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_iter_ele( iter );

    if( FD_UNLIKELY( stake_delegation->stake<minimum_stake_delegation ) ) {
      continue;
    }

    uint idx = (uint)fd_vote_rewards_map_idx_query( vote_ele_map, &stake_delegation->vote_account, UINT_MAX, vote_ele );
    FD_TEST( idx!=UINT_MAX );

    if( FD_UNLIKELY( vote_ele[idx].invalid ) ) continue;

    fd_calculated_stake_points_t * stake_point_result = &runtime_stack->stakes.stake_points_result[ stake_delegation->idx ];
    calculate_stake_points_and_credits( stake_history,
                                        stake_delegation,
                                        runtime_stack,
                                        idx,
                                        new_warmup_cooldown_rate_epoch,
                                        stake_point_result );

    total_points += stake_point_result->points.ud;
  }

  return total_points;
}

/* Calculates epoch rewards for stake/vote accounts.
   Returns vote rewards, stake rewards, and the sum of all stake rewards
   in lamports.

   In the future, the calculation will be cached in the snapshot, but
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
calculate_stake_vote_rewards( fd_bank_t *                    bank,
                              fd_stake_delegations_t const * stake_delegations,
                              fd_capture_ctx_t *             capture_ctx FD_PARAM_UNUSED,
                              fd_stake_history_t const *     stake_history,
                              ulong                          rewarded_epoch,
                              ulong                          total_rewards,
                              uint128                        total_points,
                              fd_runtime_stack_t *           runtime_stack,
                              int                            is_recalculation ) {

  int _err[1];
  ulong   new_warmup_cooldown_rate_epoch_val = 0UL;
  ulong * new_warmup_cooldown_rate_epoch     = &new_warmup_cooldown_rate_epoch_val;
  int is_some = fd_new_warmup_cooldown_rate_epoch(
      fd_bank_epoch_schedule_query( bank ),
      fd_bank_features_query( bank ),
      new_warmup_cooldown_rate_epoch,
      _err );
  if( FD_UNLIKELY( !is_some ) ) {
    new_warmup_cooldown_rate_epoch = NULL;
  }

  ulong minimum_stake_delegation = get_minimum_stake_delegation( bank );

  runtime_stack->stakes.stake_rewards_cnt = 0UL;

  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_iter_ele( iter );

    if( FD_FEATURE_ACTIVE_BANK( bank, stake_minimum_delegation_for_rewards ) ) {
      if( stake_delegation->stake<minimum_stake_delegation ) {
        continue;
      }
    }
    fd_calculated_stake_rewards_t * calculated_stake_rewards = &runtime_stack->stakes.stake_rewards_result[ stake_delegation->idx ];
    calculated_stake_rewards->success = 0;

    fd_vote_rewards_t * vote_ele = runtime_stack->stakes.vote_ele;
    fd_vote_rewards_map_t * vote_ele_map = fd_type_pun( runtime_stack->stakes.vote_map_mem );
    uint idx = (uint)fd_vote_rewards_map_idx_query( vote_ele_map, &stake_delegation->vote_account, UINT_MAX, vote_ele );
    if( FD_UNLIKELY( idx==UINT_MAX ) ) continue;
    if( FD_UNLIKELY( vote_ele[idx].invalid ) ) continue;

    if( is_recalculation ) {
      /* We have not cached the stake points yet if we are recalculating
         stake rewards so we need to recalculate them. */
      calculate_stake_points_and_credits(
          stake_history,
          stake_delegation,
          runtime_stack,
          idx,
          new_warmup_cooldown_rate_epoch,
          &runtime_stack->stakes.stake_points_result[ stake_delegation->idx ] );
    }

    /* redeem_rewards is actually just responsible for calculating the
       vote and stake rewards for each stake account.  It does not do
       rewards redemption: it is a misnomer. */
    int err = redeem_rewards(
        stake_delegation,
        idx,
        rewarded_epoch,
        total_rewards,
        total_points,
        runtime_stack,
        calculated_stake_rewards );

    if( FD_UNLIKELY( err!=0 ) ) {
      continue;
    }

    calculated_stake_rewards->success = 1;

    if( capture_ctx && capture_ctx->capture_solcap ) {
      uchar commission = runtime_stack->stakes.vote_ele[ idx ].commission;
      fd_capture_link_write_stake_reward_event( capture_ctx,
                                                fd_bank_slot_get( bank ),
                                                stake_delegation->stake_account,
                                                stake_delegation->vote_account,
                                                commission,
                                                (long)calculated_stake_rewards->voter_rewards,
                                                (long)calculated_stake_rewards->staker_rewards,
                                                (long)calculated_stake_rewards->new_credits_observed );
    }

    runtime_stack->stakes.vote_ele[ idx ].vote_rewards += calculated_stake_rewards->voter_rewards;
    runtime_stack->stakes.stake_rewards_cnt++;
  }
}

static void
setup_stake_partitions( fd_bank_t *                    bank,
                        fd_stake_delegations_t const * stake_delegations,
                        fd_runtime_stack_t *           runtime_stack,
                        fd_hash_t const *              parent_blockhash,
                        ulong                          starting_block_height,
                        uint                           num_partitions ) {

  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );
  uchar fork_idx = fd_stake_rewards_init( stake_rewards, fd_bank_epoch_get( bank ), parent_blockhash, starting_block_height, (uint)num_partitions );
  bank->data->stake_rewards_fork_id = fork_idx;

  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_iter_ele( iter );

    fd_calculated_stake_rewards_t * reward = &runtime_stack->stakes.stake_rewards_result[ stake_delegation->idx ];

    if( FD_UNLIKELY( !reward->success ) ) continue;

    fd_stake_rewards_insert(
      stake_rewards,
      fork_idx,
      &stake_delegation->stake_account,
      reward->staker_rewards,
      reward->new_credits_observed
    );
  }
}

/* Calculate epoch reward and return vote and stake rewards.

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L273 */
static uint128
calculate_validator_rewards( fd_bank_t *                    bank,
                             fd_accdb_user_t *              accdb,
                             fd_funk_txn_xid_t const *      xid,
                             fd_runtime_stack_t *           runtime_stack,
                             fd_stake_delegations_t const * stake_delegations,
                             fd_capture_ctx_t *             capture_ctx,
                             ulong                          rewarded_epoch,
                             ulong *                        rewards_out ) {

  fd_stake_history_t stake_history[1];
  if( FD_UNLIKELY( !fd_sysvar_stake_history_read( accdb, xid, stake_history ) ) ) {
    FD_LOG_ERR(( "Unable to read and decode stake history sysvar" ));
  }

  /* Calculate the epoch reward points from stake/vote accounts */
  uint128 total_points = calculate_reward_points_partitioned(
      bank,
      stake_delegations,
      stake_history,
      runtime_stack );

  /* If there are no points, then we set the rewards to 0. */
  *rewards_out = total_points>0UL ? *rewards_out: 0UL;

  if( capture_ctx && capture_ctx->capture_solcap ) {
    ulong epoch = fd_bank_epoch_get( bank );
    ulong slot  = fd_bank_slot_get( bank );
    fd_capture_link_write_stake_rewards_begin( capture_ctx,
                                               slot,
                                               epoch,
                                               epoch-1UL, /* FIXME: this is not strictly correct */
                                               *rewards_out,
                                               (ulong)total_points );
  }

  /* Calculate the stake and vote rewards for each account. We want to
     use the vote states from the end of the current_epoch. */
  calculate_stake_vote_rewards(
      bank,
      stake_delegations,
      capture_ctx,
      stake_history,
      rewarded_epoch,
      *rewards_out,
      total_points,
      runtime_stack,
      0 );

  fd_hash_t const * parent_blockhash      = fd_blockhashes_peek_last_hash( fd_bank_block_hash_queue_query( bank ) );
  ulong             starting_block_height = fd_bank_block_height_get( bank ) + REWARD_CALCULATION_NUM_BLOCKS;
  uint              num_partitions        = get_reward_distribution_num_blocks( fd_bank_epoch_schedule_query( bank ),
                                                                                fd_bank_slot_get( bank ),
                                                                                runtime_stack->stakes.stake_rewards_cnt );

  setup_stake_partitions( bank, stake_delegations, runtime_stack, parent_blockhash, starting_block_height, num_partitions );

  return total_points;
}

/* Calculate rewards from previous epoch to prepare for partitioned distribution.

   https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L277 */
static void
calculate_rewards_for_partitioning( fd_bank_t *                            bank,
                                    fd_accdb_user_t *                      accdb,
                                    fd_funk_txn_xid_t const *              xid,
                                    fd_runtime_stack_t *                   runtime_stack,
                                    fd_stake_delegations_t const *         stake_delegations,
                                    fd_capture_ctx_t *                     capture_ctx,
                                    ulong                                  prev_epoch,
                                    fd_partitioned_rewards_calculation_t * result ) {
  fd_prev_epoch_inflation_rewards_t rewards;

  calculate_previous_epoch_inflation_rewards( bank,
                                              fd_bank_capitalization_get( bank ),
                                              prev_epoch,
                                              &rewards );

  ulong total_rewards = rewards.validator_rewards;

  uint128 points = calculate_validator_rewards( bank,
                                                accdb,
                                                xid,
                                                runtime_stack,
                                                stake_delegations,
                                                capture_ctx,
                                                prev_epoch,
                                                &total_rewards );

  /* The agave client does not partition the stake rewards until the
     first distribution block.  We calculate the partitions during the
     boundary. */
  result->validator_points             = points;
  result->validator_rewards            = total_rewards;
  result->validator_rate               = rewards.validator_rate;
  result->foundation_rate              = rewards.foundation_rate;
  result->prev_epoch_duration_in_years = rewards.prev_epoch_duration_in_years;
  result->capitalization               = fd_bank_capitalization_get( bank );
}

/* Calculate rewards from previous epoch and distribute vote rewards
   https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L148 */
static void
calculate_rewards_and_distribute_vote_rewards( fd_bank_t *                    bank,
                                               fd_accdb_user_t *              accdb,
                                               fd_funk_txn_xid_t const *      xid,
                                               fd_runtime_stack_t *           runtime_stack,
                                               fd_stake_delegations_t const * stake_delegations,
                                               fd_capture_ctx_t *             capture_ctx,
                                               ulong                          prev_epoch ) {

  uchar __attribute__((aligned(128))) vsv_buf[ FD_VOTE_STATE_VERSIONED_FOOTPRINT ];

  fd_vote_rewards_t *     vote_ele_pool = runtime_stack->stakes.vote_ele;
  fd_vote_rewards_map_t * vote_ele_map  = fd_type_pun( runtime_stack->stakes.vote_map_mem );
  for( fd_vote_rewards_map_iter_t iter = fd_vote_rewards_map_iter_init( vote_ele_map, vote_ele_pool );
       !fd_vote_rewards_map_iter_done( iter, vote_ele_map, vote_ele_pool );
       iter = fd_vote_rewards_map_iter_next( iter, vote_ele_map, vote_ele_pool ) ) {

    uint idx = (uint)fd_vote_rewards_map_iter_idx( iter, vote_ele_map, vote_ele_pool );
    fd_vote_rewards_t * ele = &vote_ele_pool[idx];

    fd_accdb_ro_t vote_ro[1];
    if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, vote_ro, xid, &ele->pubkey ) ) ) {
      ele->invalid = 1;
      continue;
    }

    if( FD_UNLIKELY( !fd_vsv_is_correct_size_and_initialized( vote_ro->meta ) ) ) {
      fd_accdb_close_ro( accdb, vote_ro );
      ele->invalid = 1;
      continue;
    }

    get_vote_credits_commission( fd_accdb_ref_data_const( vote_ro ),
                                 fd_accdb_ref_data_sz( vote_ro ),
                                 vsv_buf,
                                 &runtime_stack->stakes.vote_ele[ idx ] );
    fd_accdb_close_ro( accdb, vote_ro );
  }

  /* First we must compute the stake and vote rewards for the just
     completed epoch.  We store the stake account rewards and vote
     states rewards in the bank */

  fd_partitioned_rewards_calculation_t rewards_calc_result[1] = {0};
  calculate_rewards_for_partitioning( bank,
                                      accdb,
                                      xid,
                                      runtime_stack,
                                      stake_delegations,
                                      capture_ctx,
                                      prev_epoch,
                                      rewards_calc_result );


  /* Iterate over all the vote reward nodes and distribute the rewards
     to the vote accounts.  After each reward has been paid out,
     calcualte the lthash for each vote account. */
  ulong distributed_rewards = 0UL;
  for( fd_vote_rewards_map_iter_t iter = fd_vote_rewards_map_iter_init( vote_ele_map, vote_ele_pool );
       !fd_vote_rewards_map_iter_done( iter, vote_ele_map, vote_ele_pool );
       iter = fd_vote_rewards_map_iter_next( iter, vote_ele_map, vote_ele_pool ) ) {

    uint idx = (uint)fd_vote_rewards_map_iter_idx( iter, vote_ele_map, vote_ele_pool );
    fd_vote_rewards_t * ele = &vote_ele_pool[idx];

    ulong rewards = runtime_stack->stakes.vote_ele[ idx ].vote_rewards;
    if( rewards==0UL ) {
      continue;
    }

    /* Credit rewards to vote account (creating a new system account if
       it does not exist) */
    fd_pubkey_t const * vote_pubkey = &ele->pubkey;
    fd_accdb_rw_t rw[1];
    fd_accdb_open_rw( accdb, rw, xid, vote_pubkey, 0UL, FD_ACCDB_FLAG_CREATE );
    fd_lthash_value_t prev_hash[1];
    fd_hashes_account_lthash( vote_pubkey, rw->meta, fd_accdb_ref_data_const( rw->ro ), prev_hash );
    ulong acc_lamports = fd_accdb_ref_lamports( rw->ro );
    if( FD_UNLIKELY( __builtin_uaddl_overflow( acc_lamports, rewards, &acc_lamports ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( vote_pubkey->key, addr_b58 );
      FD_LOG_EMERG(( "integer overflow while crediting %lu vote reward lamports to %s (previous balance %lu)",
                     rewards, addr_b58, fd_accdb_ref_lamports( rw->ro ) ));
    }
    fd_accdb_ref_lamports_set( rw, acc_lamports );
    fd_hashes_update_lthash( vote_pubkey, rw->meta, prev_hash,bank, capture_ctx );
    fd_accdb_close_rw( accdb, rw );

    distributed_rewards = fd_ulong_sat_add( distributed_rewards, rewards );
  }

  /* Verify that we didn't pay any more than we expected to */
  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );
  ulong total_stake_rewards = fd_stake_rewards_total_rewards( stake_rewards, bank->data->stake_rewards_fork_id );

  ulong total_rewards = fd_ulong_sat_add( distributed_rewards, total_stake_rewards );
  if( FD_UNLIKELY( rewards_calc_result->validator_rewards<total_rewards ) ) {
    FD_LOG_CRIT(( "Unexpected rewards calculation result" ));
  }

  fd_bank_capitalization_set( bank, fd_bank_capitalization_get( bank ) + distributed_rewards );

  runtime_stack->stakes.distributed_rewards = distributed_rewards;
  runtime_stack->stakes.total_rewards       = rewards_calc_result->validator_rewards;
  runtime_stack->stakes.total_points.ud     = rewards_calc_result->validator_points;
}

/* Distributes a single partitioned reward to a single stake account */
static int
distribute_epoch_reward_to_stake_acc( fd_bank_t *               bank,
                                      fd_accdb_user_t *         accdb,
                                      fd_funk_txn_xid_t const * xid,
                                      fd_capture_ctx_t *        capture_ctx,
                                      fd_pubkey_t *             stake_pubkey,
                                      ulong                     reward_lamports,
                                      ulong                     new_credits_observed ) {

  fd_accdb_rw_t rw[1];
  if( FD_UNLIKELY( !fd_accdb_open_rw( accdb, rw, xid, stake_pubkey, 0UL, 0 ) ) ) {
    return 1;  /* account does not exist */
  }

  fd_lthash_value_t prev_hash[1];
  fd_hashes_account_lthash( stake_pubkey, rw->meta, fd_accdb_ref_data_const( rw->ro ), prev_hash );
  fd_stake_state_v2_t stake_state[1] = {0};
  if( 0!=fd_stake_get_state( rw->meta, stake_state ) ||
      !fd_stake_state_v2_is_stake( stake_state ) ) {
    fd_accdb_close_rw( accdb, rw );
    return 1;  /* not a valid stake account */
  }

  /* Credit rewards to stake account */
  ulong acc_lamports = fd_accdb_ref_lamports( rw->ro );
  if( FD_UNLIKELY( __builtin_uaddl_overflow( acc_lamports, reward_lamports, &acc_lamports ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( stake_pubkey->key, addr_b58 );
    FD_LOG_EMERG(( "integer overflow while crediting %lu stake reward lamports to %s (previous balance %lu)",
                    reward_lamports, addr_b58, fd_accdb_ref_lamports( rw->ro ) ));
  }
  fd_accdb_ref_lamports_set( rw, acc_lamports );

  ulong old_credits_observed                      = stake_state->inner.stake.stake.credits_observed;
  stake_state->inner.stake.stake.credits_observed = new_credits_observed;
  stake_state->inner.stake.stake.delegation.stake = fd_ulong_sat_add( stake_state->inner.stake.stake.delegation.stake,
                                                                      reward_lamports );

  /* The stake account has just been updated, so we need to update the
     stake delegations stored in the bank. */
  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_delta_locking_modify( bank );
  fd_stake_delegations_update(
      stake_delegations,
      stake_pubkey,
      &stake_state->inner.stake.stake.delegation.voter_pubkey,
      stake_state->inner.stake.stake.delegation.stake,
      stake_state->inner.stake.stake.delegation.activation_epoch,
      stake_state->inner.stake.stake.delegation.deactivation_epoch,
      stake_state->inner.stake.stake.credits_observed,
      stake_state->inner.stake.stake.delegation.warmup_cooldown_rate );
  fd_bank_stake_delegations_delta_end_locking_modify( bank );

  if( capture_ctx && capture_ctx->capture_solcap ) {
    fd_capture_link_write_stake_account_payout( capture_ctx,
                                                fd_bank_slot_get( bank ),
                                                *stake_pubkey,
                                                fd_bank_slot_get( bank ),
                                                acc_lamports,
                                                (long)reward_lamports,
                                                new_credits_observed,
                                                (long)( new_credits_observed - old_credits_observed ),
                                                stake_state->inner.stake.stake.delegation.stake,
                                                (long)reward_lamports );
  }

  fd_bincode_encode_ctx_t ctx = { .data=fd_accdb_ref_data( rw ), .dataend=(uchar *)fd_accdb_ref_data( rw )+fd_accdb_ref_data_sz( rw->ro ) };
  if( FD_UNLIKELY( fd_stake_state_v2_encode( stake_state, &ctx )!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_ERR(( "fd_stake_state_encode failed" ));
  }

  fd_hashes_update_lthash( stake_pubkey, rw->meta, prev_hash, bank, capture_ctx );
  fd_accdb_close_rw( accdb, rw );

  return 0;
}

/* Process reward credits for a partition of rewards.  Store the rewards
   to AccountsDB, update reward history record and total capitalization
   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L88 */
static void
distribute_epoch_rewards_in_partition( fd_stake_rewards_t *      stake_rewards,
                                       ulong                     partition_idx,
                                       fd_bank_t *               bank,
                                       fd_accdb_user_t *         accdb,
                                       fd_funk_txn_xid_t const * xid,
                                       fd_capture_ctx_t *        capture_ctx ) {

  ulong lamports_distributed = 0UL;
  ulong lamports_burned      = 0UL;

  for( fd_stake_rewards_iter_init( stake_rewards, bank->data->stake_rewards_fork_id, (ushort)partition_idx );
       !fd_stake_rewards_iter_done( stake_rewards );
       fd_stake_rewards_iter_next( stake_rewards, bank->data->stake_rewards_fork_id ) ) {
    fd_pubkey_t pubkey;
    ulong       lamports;
    ulong       credits_observed;
    fd_stake_rewards_iter_ele( stake_rewards, bank->data->stake_rewards_fork_id, &pubkey, &lamports, &credits_observed );

    if( FD_LIKELY( !distribute_epoch_reward_to_stake_acc( bank,
                                                          accdb,
                                                          xid,
                                                          capture_ctx,
                                                          &pubkey,
                                                          lamports,
                                                          credits_observed ) )  ) {
      lamports_distributed += lamports;
    } else {
      lamports_burned += lamports;
    }
  }

  /* Update the epoch rewards sysvar with the amount distributed and burnt */
  fd_sysvar_epoch_rewards_distribute( bank, accdb, xid, capture_ctx, lamports_distributed + lamports_burned );

  FD_LOG_DEBUG(( "lamports burned: %lu, lamports distributed: %lu", lamports_burned, lamports_distributed ));

  fd_bank_capitalization_set( bank, fd_bank_capitalization_get( bank ) + lamports_distributed );
}

/* Process reward distribution for the block if it is inside reward interval.

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L42 */
void
fd_distribute_partitioned_epoch_rewards( fd_bank_t *               bank,
                                         fd_accdb_user_t *         accdb,
                                         fd_funk_txn_xid_t const * xid,
                                         fd_capture_ctx_t *        capture_ctx ) {
  if( FD_LIKELY( bank->data->stake_rewards_fork_id==UCHAR_MAX ) ) return;

  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );

  ulong block_height                       = fd_bank_block_height_get( bank );
  ulong distribution_starting_block_height = fd_stake_rewards_starting_block_height( stake_rewards, bank->data->stake_rewards_fork_id );
  ulong distribution_end_exclusive         = fd_stake_rewards_exclusive_ending_block_height( stake_rewards, bank->data->stake_rewards_fork_id );

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );
  ulong                       epoch          = fd_bank_epoch_get( bank );

  if( FD_UNLIKELY( get_slots_in_epoch( epoch, epoch_schedule ) <= fd_stake_rewards_num_partitions( stake_rewards, bank->data->stake_rewards_fork_id ) ) ) {
    FD_LOG_CRIT(( "Should not be distributing rewards" ));
  }

  if( FD_UNLIKELY( block_height>=distribution_starting_block_height && block_height<distribution_end_exclusive ) ) {

    ulong partition_idx = block_height-distribution_starting_block_height;
    distribute_epoch_rewards_in_partition( stake_rewards, partition_idx, bank, accdb, xid, capture_ctx );

    /* If we have finished distributing rewards, set the status to inactive */
    if( fd_ulong_sat_add( block_height, 1UL )>=distribution_end_exclusive ) {
      fd_sysvar_epoch_rewards_set_inactive( bank, accdb, xid, capture_ctx );
      bank->data->stake_rewards_fork_id = UCHAR_MAX;
    }
  }
}

/* Partitioned epoch rewards entry-point.

   https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L102
*/
void
fd_begin_partitioned_rewards( fd_bank_t *                    bank,
                              fd_accdb_user_t *              accdb,
                              fd_funk_txn_xid_t const *      xid,
                              fd_runtime_stack_t *           runtime_stack,
                              fd_capture_ctx_t *             capture_ctx,
                              fd_stake_delegations_t const * stake_delegations,
                              fd_hash_t const *              parent_blockhash,
                              ulong                          parent_epoch ) {

  calculate_rewards_and_distribute_vote_rewards(
      bank,
      accdb,
      xid,
      runtime_stack,
      stake_delegations,
      capture_ctx,
      parent_epoch );

  /* Once the rewards for vote accounts have been distributed and stake
     account rewards have been calculated, we can now set our epoch
     reward status to be active and we can initialize the epoch rewards
     sysvar.  This sysvar is then deleted once all of the partitioned
     stake rewards have been distributed.

     The Agave client calculates the partitions for each stake reward
     when the first distribution block is reached.  The Firedancer
     client differs here since we hash the partitions during the epoch
     boundary. */

  ulong distribution_starting_block_height = fd_bank_block_height_get( bank ) + REWARD_CALCULATION_NUM_BLOCKS;
  uint  num_partitions                     = fd_stake_rewards_num_partitions( fd_bank_stake_rewards_query( bank ), bank->data->stake_rewards_fork_id );

  fd_sysvar_epoch_rewards_init(
      bank,
      accdb,
      xid,
      capture_ctx,
      runtime_stack->stakes.distributed_rewards,
      distribution_starting_block_height,
      num_partitions,
      runtime_stack->stakes.total_rewards,
      runtime_stack->stakes.total_points.ud,
      parent_blockhash );
}

/*
    Re-calculates partitioned stake rewards.
    This updates the slot context's epoch reward status with the recalculated partitioned rewards.

    https://github.com/anza-xyz/agave/blob/v2.2.14/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L521 */
void
fd_rewards_recalculate_partitioned_rewards( fd_banks_t *              banks,
                                            fd_bank_t *               bank,
                                            fd_accdb_user_t *         accdb,
                                            fd_funk_txn_xid_t const * xid,
                                            fd_runtime_stack_t *      runtime_stack,
                                            fd_capture_ctx_t *        capture_ctx ) {

  fd_sysvar_epoch_rewards_t epoch_rewards_sysvar[1];
  if( FD_UNLIKELY( !fd_sysvar_epoch_rewards_read( accdb, xid, epoch_rewards_sysvar ) ) ) {
    FD_LOG_DEBUG(( "Failed to read or decode epoch rewards sysvar - may not have been created yet" ));
    return;
  }

  FD_LOG_DEBUG(( "recalculating partitioned rewards" ));

  if( FD_UNLIKELY( !epoch_rewards_sysvar->active ) ) {
    FD_LOG_DEBUG(( "epoch rewards is inactive" ));
    return;
  }

  /* If partitioned rewards are active, the rewarded epoch is always the immediately
      preceeding epoch.

      https://github.com/anza-xyz/agave/blob/2316fea4c0852e59c071f72d72db020017ffd7d0/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L566 */
  FD_LOG_DEBUG(( "epoch rewards is active" ));

  ulong const epoch          = fd_bank_epoch_get( bank );
  ulong const rewarded_epoch = fd_ulong_sat_sub( epoch, 1UL );

  int _err[1] = {0};
  ulong new_warmup_cooldown_rate_epoch_;
  ulong * new_warmup_cooldown_rate_epoch = &new_warmup_cooldown_rate_epoch_;
  int is_some = fd_new_warmup_cooldown_rate_epoch(
      fd_bank_epoch_schedule_query( bank ),
      fd_bank_features_query( bank ),
      new_warmup_cooldown_rate_epoch,
      _err );
  if( FD_UNLIKELY( !is_some ) ) {
    new_warmup_cooldown_rate_epoch = NULL;
  }

  fd_stake_history_t stake_history[1];
  if( FD_UNLIKELY( !fd_sysvar_stake_history_read( accdb, xid, stake_history ) ) ) {
    FD_LOG_ERR(( "Unable to read and decode stake history sysvar" ));
  }

  fd_stake_delegations_t const * stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "stake_delegations is NULL" ));
  }

  calculate_stake_vote_rewards(
      bank,
      stake_delegations,
      capture_ctx,
      stake_history,
      rewarded_epoch,
      epoch_rewards_sysvar->total_rewards,
      epoch_rewards_sysvar->total_points.ud,
      runtime_stack,
      1 );

  setup_stake_partitions(
      bank,
      stake_delegations,
      runtime_stack,
      &epoch_rewards_sysvar->parent_blockhash,
      epoch_rewards_sysvar->distribution_starting_block_height,
      (uint)epoch_rewards_sysvar->num_partitions );
}
