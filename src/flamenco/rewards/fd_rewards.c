#include "fd_rewards.h"
#include "fd_stake_rewards.h"
#include <math.h>

#include "../runtime/sysvar/fd_sysvar_epoch_rewards.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../stakes/fd_stakes.h"
#include "../runtime/program/vote/fd_vote_codec.h"
#include "../runtime/sysvar/fd_sysvar_stake_history.h"
#include "../runtime/sysvar/fd_sysvar_cache.h"
#include "../capture/fd_capture_ctx.h"
#include "../runtime/fd_runtime_stack.h"
#include "../runtime/fd_accdb_svm.h"
#include "../runtime/fd_hashes.h"
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
      ? bank->f.features.devnet_and_testnet
      : ULONG_MAX;

  ulong enable = bank->f.features.full_inflation_enable;

  ulong min_slot = fd_ulong_min( enable, devnet_and_testnet );
  if( min_slot == ULONG_MAX ) {
    if( FD_FEATURE_ACTIVE_BANK( bank, pico_inflation ) ) {
      min_slot = bank->f.features.pico_inflation;
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
  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong num_slots = get_inflation_num_slots( bank, epoch_schedule, bank->f.slot );
  return (double)num_slots / (double)bank->f.slots_per_year;
}

/* For a given stake and vote_state, calculate how many points were earned (credits * stake) and new value
   for credits_observed were the points paid

    https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L109 */
static void
calculate_stake_points_and_credits( fd_epoch_credits_t *           epoch_credits,
                                    fd_stake_history_t const *     stake_history,
                                    fd_stake_delegation_t const *  stake,
                                    ulong *                        new_rate_activation_epoch,
                                    fd_calculated_stake_points_t * result ) {

  ulong credits_in_stake = stake->credits_observed;
  ulong credits_cnt      = epoch_credits->cnt;
  ulong base             = epoch_credits->base_credits;
  ulong credits_in_vote  = credits_cnt > 0UL ? base + epoch_credits->credits_delta[ credits_cnt - 1UL ] : 0UL;


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
  for( ulong i=0UL; i<epoch_credits->cnt; i++ ) {

    ulong final_epoch_credits   = base + epoch_credits->credits_delta[ i ];
    ulong initial_epoch_credits = base + epoch_credits->prev_credits_delta[ i ];

    /* Vote account credits can only increase or stay the same, so
       initial_epoch_credits <= final_epoch_credits always holds. */
    FD_TEST( initial_epoch_credits<=final_epoch_credits );

    /* If final_epoch_credits <= credits_in_stake, then:
        initial_epoch_credits <= final_epoch_credits <= credits_in_stake

       * earned_credits = 0 since both conditions are false.
       * new_credits_observed stays the same since it is already set
         to credits_in_stake and final_epoch_credits <= credits_in_stake

       Since earned_credits = 0 and new_credits_observed stays the same,
       points computation can be skipped. */
    if( FD_LIKELY( final_epoch_credits<=credits_in_stake ) ) continue;

    uint128 earned_credits = 0;
    if( FD_LIKELY( credits_in_stake < initial_epoch_credits ) ) {
      earned_credits = (uint128)(final_epoch_credits - initial_epoch_credits);
    } else if( FD_UNLIKELY( credits_in_stake < final_epoch_credits ) ) {
      earned_credits = (uint128)(final_epoch_credits - new_credits_observed);
    }

    new_credits_observed = fd_ulong_max( new_credits_observed, final_epoch_credits );

    ulong stake_amount = fd_stakes_activating_and_deactivating(
        stake,
        epoch_credits->epoch[ i ],
        stake_history,
        new_rate_activation_epoch ).effective;

    points += (uint128)stake_amount * earned_credits;
  }

  result->points.ud = points;
  result->new_credits_observed = new_credits_observed;
  result->force_credits_update_with_skipped_reward = 0;
}

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
                fd_calculated_stake_points_t *  stake_points_result,
                fd_calculated_stake_rewards_t * result ) {

  /* The firedancer implementation of redeem_rewards inlines a lot of
     the helper functions that the Agave implementation uses.
     In Agave: redeem_rewards calls redeem_stake_rewards which calls
     calculate_stake_rewards. */

  // Drive credits_observed forward unconditionally when rewards are disabled
  // or when this is the stake's activation epoch
  if( total_rewards==0UL || stake->activation_epoch==rewarded_epoch ) {
      stake_points_result->force_credits_update_with_skipped_reward = 1;
  }

  if( stake_points_result->force_credits_update_with_skipped_reward ) {
    result->staker_rewards       = 0;
    result->voter_rewards        = 0;
    result->new_credits_observed = stake_points_result->new_credits_observed;
    return 0;
  }
  if( stake_points_result->points.ud==0 || total_points==0 ) {
    return 1;
  }

  uint128 rewards_u128;
  if( FD_UNLIKELY( __builtin_mul_overflow( stake_points_result->points.ud, (uint128)(total_rewards), &rewards_u128 ) ) ) {
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

  fd_commission_split_t split_result;
  fd_vote_commission_split( runtime_stack->stakes.vote_ele[ vote_state_idx ].commission, rewards, &split_result );
  if( split_result.is_split && (split_result.voter_portion == 0 || split_result.staker_portion == 0) ) {
    return 1;
  }

  result->staker_rewards       = split_result.staker_portion;
  result->voter_rewards        = split_result.voter_portion;
  result->new_credits_observed = stake_points_result->new_credits_observed;
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
  ulong slots_in_epoch = get_slots_in_epoch( prev_epoch, &bank->f.epoch_schedule );
  return (double)slots_in_epoch / (double)bank->f.slots_per_year;
}

static void
calculate_previous_epoch_inflation_rewards( fd_bank_t const *                   bank,
                                            ulong                               prev_epoch_capitalization,
                                            ulong                               prev_epoch,
                                            fd_prev_epoch_inflation_rewards_t * rewards );

/* fd_rewards_compute_total_rewards is the bridge-phase helper called
   by the replay tile between the parallel reward_points phase and
   the parallel calculate_stake_vote_rewards phase.

   It returns the total_rewards value (validator_rewards, in
   lamports) that will be passed to every parallel worker.  Matches
   the gating logic that used to live inside calculate_validator_
   rewards: rewards is zeroed out if total_points==0. */

ulong
fd_rewards_compute_total_rewards( fd_bank_t const * bank,
                                  ulong             prev_epoch,
                                  uint128           total_points ) {
  fd_prev_epoch_inflation_rewards_t rewards;
  calculate_previous_epoch_inflation_rewards( bank,
                                              bank->f.capitalization,
                                              prev_epoch,
                                              &rewards );
  return total_points>0UL ? rewards.validator_rewards : 0UL;
}

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank.rs#L2128 */
static void
calculate_previous_epoch_inflation_rewards( fd_bank_t const *                   bank,
                                            ulong                               prev_epoch_capitalization,
                                            ulong                               prev_epoch,
                                            fd_prev_epoch_inflation_rewards_t * rewards ) {
  double slot_in_year = slot_in_year_for_inflation( bank );

  rewards->validator_rate               = validator( &bank->f.inflation, slot_in_year );
  rewards->foundation_rate              = foundation( &bank->f.inflation, slot_in_year );
  rewards->prev_epoch_duration_in_years = epoch_duration_in_years( bank, prev_epoch );
  rewards->validator_rewards            = (ulong)(rewards->validator_rate * (double)prev_epoch_capitalization * rewards->prev_epoch_duration_in_years);
  FD_LOG_DEBUG(( "Rewards %lu, Rate %.16f, Duration %.18f Capitalization %lu Slot in year %.16f", rewards->validator_rewards, rewards->validator_rate, rewards->prev_epoch_duration_in_years, prev_epoch_capitalization, slot_in_year ));
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

uint
fd_rewards_get_reward_distribution_num_blocks( fd_epoch_schedule_t const * epoch_schedule,
                                               ulong                       slot,
                                               ulong                       total_stake_accounts ) {
  return get_reward_distribution_num_blocks( epoch_schedule, slot, total_stake_accounts );
}

uint128
calculate_reward_points_partitioned( fd_bank_t *                    bank,
                                     fd_stake_delegations_t const * stake_delegations,
                                     fd_stake_history_t const *     stake_history,
                                     fd_runtime_stack_t *           runtime_stack,
                                     ulong                          partition_idx,
                                     ulong                          total_partitions ) {
  /* Calculate the points for each stake delegation */
  uint128 total_points = 0;

  fd_vote_rewards_t *     vote_ele     = runtime_stack->stakes.vote_ele;
  fd_vote_rewards_map_t * vote_ele_map = runtime_stack->stakes.vote_map;

  fd_stake_delegations_pool_iter_t iter_[1];
  for( fd_stake_delegations_pool_iter_t * iter = fd_stake_delegations_pool_iter_init_partition( iter_, stake_delegations, partition_idx, total_partitions );
       !fd_stake_delegations_pool_iter_done( iter );
       fd_stake_delegations_pool_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation     = fd_stake_delegations_pool_iter_ele( iter );
    ulong                         stake_delegation_idx = iter->cur;

    /* Note that we don't check minimum delegation here, as there are
       no plans to activate stake_minimum_delegation_for_rewards.
       If this changes we need to skip stake accounts that are
       below the minimum delegation here. However we don't do this yet,
       to ensure that we audit the feature properly if this happens. */

    uint idx = (uint)fd_vote_rewards_map_idx_query_const( vote_ele_map, &stake_delegation->vote_account, UINT_MAX, vote_ele );
    if( FD_UNLIKELY( idx==UINT_MAX ) ) continue;

    fd_calculated_stake_points_t   stake_points_result_[1];
    fd_calculated_stake_points_t * stake_points_result;
    if( FD_UNLIKELY( stake_delegation_idx>=runtime_stack->shmem->expected_stake_accounts ) ) {
      stake_points_result = stake_points_result_;
    } else {
      stake_points_result = &runtime_stack->stakes.stake_points_result[ stake_delegation_idx ];
    }

    fd_epoch_credits_t * epoch_credits = &fd_bank_epoch_credits( bank )[ idx ];

    calculate_stake_points_and_credits( epoch_credits,
                                        stake_history,
                                        stake_delegation,
                                        &bank->f.warmup_cooldown_rate_epoch,
                                        stake_points_result );

    total_points += stake_points_result->points.ud;
  }

  return total_points;
}

/* calculate_stake_vote_rewards_partitioned is the parallel primitive
   for the stake / vote rewards computation phase.  Each exec tile
   invokes this with its own partition_idx in [0, total_partitions),
   and writes:

     * runtime_stack->stakes.stake_rewards_result[stake_delegation_idx]
       -- per-delegation slot, no contention across partitions.  Only
       written for in-cache delegations (idx < expected_stake_accounts);
       out-of-cache delegations are still processed but use a
       stack-local buffer (setup_stake_partitions will recompute them
       serially, matching the serial path's handling).

     * runtime_stack->stakes.vote_ele[idx].vote_rewards           (+=)
       -- shared with other partitions whose delegations reference
       the same vote account.  Accumulated with
       FD_ATOMIC_FETCH_AND_ADD so replay sees the correct sum after
       all exec tiles have replied.

     * runtime_stack->shmem->stake_rewards_cnt                    (+=)
       -- shared counter, same atomic treatment.

   The caller must:
     - have previously populated stake_points_result[] via
       calculate_reward_points_partitioned for in-cache
       delegations.  Out-of-cache delegations have their stake
       points recomputed inline here (same as the serial path).
     - have reset stake_rewards_cnt to 0 and vote_ele[].vote_rewards
       to 0 on the replay tile BEFORE dispatching (since exec tiles
       are additive).
     - pass the same total_rewards / total_points to every partition.

   No capture_ctx is accepted: solcap capture of per-stake reward
   events is a debugging affordance that is only wired through the
   serial fd_calculate_stake_vote_rewards path. */

void
calculate_stake_vote_rewards_partitioned( fd_bank_t *                    bank,
                                          fd_stake_delegations_t const * stake_delegations,
                                          fd_stake_history_t const *     stake_history,
                                          ulong                          rewarded_epoch,
                                          ulong                          total_rewards,
                                          uint128                        total_points,
                                          fd_runtime_stack_t *           runtime_stack,
                                          ulong                          partition_idx,
                                          ulong                          total_partitions ) {
  fd_vote_rewards_t *     vote_ele     = runtime_stack->stakes.vote_ele;
  fd_vote_rewards_map_t * vote_ele_map = runtime_stack->stakes.vote_map;
  ulong                   local_cnt    = 0UL;

  fd_stake_delegations_pool_iter_t iter_[1];
  for( fd_stake_delegations_pool_iter_t * iter = fd_stake_delegations_pool_iter_init_partition( iter_, stake_delegations, partition_idx, total_partitions );
       !fd_stake_delegations_pool_iter_done( iter );
       fd_stake_delegations_pool_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation     = fd_stake_delegations_pool_iter_ele( iter );
    ulong                         stake_delegation_idx = iter->cur;

    /* calculated_stake_rewards: write to the per-idx cache slot for
       in-cache delegations; for out-of-cache delegations, use a
       stack-local buffer (matches the serial path -- those entries
       are always recomputed later by setup_stake_partitions). */
    fd_calculated_stake_rewards_t   calculated_stake_rewards_[1];
    fd_calculated_stake_rewards_t * calculated_stake_rewards;
    int out_of_cache = stake_delegation_idx>=runtime_stack->shmem->expected_stake_accounts;
    if( FD_UNLIKELY( out_of_cache ) ) {
      calculated_stake_rewards = calculated_stake_rewards_;
    } else {
      calculated_stake_rewards = &runtime_stack->stakes.stake_rewards_result[ stake_delegation_idx ];
    }
    calculated_stake_rewards->success = 0;

    /* _const: no move-to-front, safe to call concurrently from
       multiple exec tiles. */
    uint idx = (uint)fd_vote_rewards_map_idx_query_const( vote_ele_map, &stake_delegation->vote_account, UINT_MAX, vote_ele );
    if( FD_UNLIKELY( idx==UINT_MAX ) ) continue;

    /* stake_points_result: read from cache for in-cache delegations;
       for out-of-cache delegations the reward_points phase couldn't
       have cached anything, so recompute using bank + stake_history
       like the serial path does. */
    fd_calculated_stake_points_t   stake_points_result_[1];
    fd_calculated_stake_points_t * stake_points_result;
    if( FD_UNLIKELY( out_of_cache ) ) {
      fd_epoch_credits_t * epoch_credits = &fd_bank_epoch_credits( bank )[ idx ];
      calculate_stake_points_and_credits( epoch_credits,
                                          stake_history,
                                          stake_delegation,
                                          &bank->f.warmup_cooldown_rate_epoch,
                                          stake_points_result_ );
      stake_points_result = stake_points_result_;
    } else {
      stake_points_result = &runtime_stack->stakes.stake_points_result[ stake_delegation_idx ];
    }

    /* redeem_rewards is actually just responsible for calculating the
       vote and stake rewards for each stake account. */
    int err = redeem_rewards(
        stake_delegation,
        idx,
        rewarded_epoch,
        total_rewards,
        total_points,
        runtime_stack,
        stake_points_result,
        calculated_stake_rewards );

    if( FD_UNLIKELY( err!=0 ) ) continue;

    calculated_stake_rewards->success = 1;

    /* Multiple delegations share a vote account; accumulate concurrently. */
    FD_ATOMIC_FETCH_AND_ADD( &runtime_stack->stakes.vote_ele[ idx ].vote_rewards,
                             calculated_stake_rewards->voter_rewards );
    local_cnt++;
  }

  if( local_cnt ) {
    FD_ATOMIC_FETCH_AND_ADD( &runtime_stack->shmem->stake_rewards_cnt, local_cnt );
  }
}



/* setup_stake_partitions_partitioned is the parallel primitive for
   populating the bank's stake_rewards partition lists.  Each exec
   tile invokes this with its own partition_idx in [0, total_partitions).
   fd_stake_rewards_insert is now concurrency safe (CAS-spin push
   onto partition_idxs_head + atomic fetch-and-add on the counters),
   so workers can insert in parallel without additional
   coordination.

   The caller (replay) must have already invoked
   fd_begin_partitioned_rewards_init_partitions, which calls
   fd_stake_rewards_init with the final num_partitions derived from
   stake_rewards_cnt and publishes the fork_idx on
   bank->stake_rewards_fork_id. */

void
setup_stake_partitions_partitioned( fd_bank_t *                    bank,
                                    fd_stake_delegations_t const * stake_delegations,
                                    fd_stake_history_t const *     stake_history,
                                    fd_runtime_stack_t *           runtime_stack,
                                    ulong                          rewarded_epoch,
                                    ulong                          total_rewards,
                                    uint128                        total_points,
                                    ulong                          partition_idx,
                                    ulong                          total_partitions ) {
  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );
  uchar                fork_idx      = bank->stake_rewards_fork_id;

  /* Initialize per-worker local partition chains to empty.  Only the
     range [0, partition_cnt) is used during this worker run. */
  uint * local_heads = runtime_stack->setup_stake_scratch.local_heads;
  uint * local_tails = runtime_stack->setup_stake_scratch.local_tails;
  uint   partition_cnt = fd_stake_rewards_num_partitions( stake_rewards, fork_idx );
  for( uint p=0U; p<partition_cnt; p++ ) local_heads[ p ] = UINT_MAX;
  /* local_tails is only read for partitions with non-empty chains, so
     initializing local_heads to UINT_MAX is sufficient. */

  fd_stake_rewards_reservation_t reservation = {0};

  fd_stake_delegations_pool_iter_t iter_[1];
  for( fd_stake_delegations_pool_iter_t * iter = fd_stake_delegations_pool_iter_init_partition( iter_, stake_delegations, partition_idx, total_partitions );
       !fd_stake_delegations_pool_iter_done( iter );
       fd_stake_delegations_pool_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation     = fd_stake_delegations_pool_iter_ele( iter );
    ulong                         stake_delegation_idx = iter->cur;

    fd_calculated_stake_rewards_t   calculated_stake_rewards_[1];
    fd_calculated_stake_rewards_t * calculated_stake_rewards;

    if( FD_UNLIKELY( stake_delegation_idx>=runtime_stack->shmem->expected_stake_accounts ) ) {
      /* OOB: recompute inline (no cache slot available) -- same
         pattern as the serial setup_stake_partitions. */
      calculated_stake_rewards = calculated_stake_rewards_;

      fd_vote_rewards_t *     vote_ele     = runtime_stack->stakes.vote_ele;
      fd_vote_rewards_map_t * vote_ele_map = runtime_stack->stakes.vote_map;
      uint idx = (uint)fd_vote_rewards_map_idx_query_const( vote_ele_map, &stake_delegation->vote_account, UINT_MAX, vote_ele );
      if( FD_UNLIKELY( idx==UINT_MAX ) ) continue;

      fd_epoch_credits_t * epoch_credits = &fd_bank_epoch_credits( bank )[ idx ];

      fd_calculated_stake_points_t stake_points_result[1];
      calculate_stake_points_and_credits(
          epoch_credits,
          stake_history,
          stake_delegation,
          &bank->f.warmup_cooldown_rate_epoch,
          stake_points_result );

      int err = redeem_rewards(
          stake_delegation,
          idx,
          rewarded_epoch,
          total_rewards,
          total_points,
          runtime_stack,
          stake_points_result,
          calculated_stake_rewards );
      calculated_stake_rewards->success = err==0;
    } else {
      calculated_stake_rewards = &runtime_stack->stakes.stake_rewards_result[ stake_delegation_idx ];
    }

    if( FD_UNLIKELY( !calculated_stake_rewards->success ) ) continue;

    fd_stake_rewards_insert_local_batched( stake_rewards,
                                           fork_idx,
                                           &stake_delegation->stake_account,
                                           calculated_stake_rewards->staker_rewards,
                                           calculated_stake_rewards->new_credits_observed,
                                           local_heads,
                                           local_tails,
                                           &reservation );
  }

  /* Splice per-partition local chains onto the shared heads.  One
     CAS-spin per non-empty partition. */
  fd_stake_rewards_splice_local( stake_rewards, fork_idx, local_heads, local_tails );
}

/* fd_begin_partitioned_rewards_init_partitions is the replay-side
   bridge between the parallel stake_vote_rewards phase and the
   parallel setup_stake_partitions phase.  Given the final
   stake_rewards_cnt (populated by exec tiles), it computes
   num_partitions, calls fd_stake_rewards_init, and publishes the
   fork index on bank->stake_rewards_fork_id so subsequent exec-tile
   workers can reference it.  Also emits the solcap stake_rewards
   "begin" capture event. */

void
fd_begin_partitioned_rewards_init_partitions( fd_bank_t *           bank,
                                              fd_runtime_stack_t *  runtime_stack,
                                              fd_capture_ctx_t *    capture_ctx,
                                              fd_hash_t const *     parent_blockhash,
                                              uint128               total_points,
                                              ulong                 total_rewards ) {
  if( capture_ctx && capture_ctx->capture_solcap ) {
    fd_capture_link_write_stake_rewards_begin( capture_ctx,
                                               bank->f.slot,
                                               bank->f.epoch,
                                               bank->f.epoch-1UL, /* FIXME: not strictly correct */
                                               total_rewards,
                                               (ulong)total_points );
  }

  ulong starting_block_height = bank->f.block_height + REWARD_CALCULATION_NUM_BLOCKS;
  uint  num_partitions        = get_reward_distribution_num_blocks( &bank->f.epoch_schedule,
                                                                    bank->f.slot,
                                                                    runtime_stack->shmem->stake_rewards_cnt );

  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );
  uchar fork_idx = fd_stake_rewards_init( stake_rewards, bank->f.epoch, parent_blockhash, starting_block_height, num_partitions );
  bank->stake_rewards_fork_id = fork_idx;
}

/* fd_begin_partitioned_rewards_finalize is the replay-side
   post-setup-stake-partitions entry point: after the parallel
   setup_stake_partitions phase has populated the bank's stake_rewards
   partition lists, replay calls this to distribute vote-account
   rewards, verify the calculated totals, publish summary state on
   runtime_stack, and initialize the epoch_rewards sysvar. */

void
fd_begin_partitioned_rewards_finalize( fd_bank_t *                    bank,
                                       fd_accdb_user_t *              accdb,
                                       fd_funk_txn_xid_t const *      xid,
                                       fd_runtime_stack_t *           runtime_stack,
                                       fd_capture_ctx_t *             capture_ctx,
                                       fd_hash_t const *              parent_blockhash,
                                       uint128                        total_points,
                                       ulong                          total_rewards ) {
  long ts0 = fd_log_wallclock();

  /* Distribute vote-account rewards.  vote_ele[].vote_rewards was
     accumulated in parallel by exec tiles; we're the single
     consumer. */
  fd_vote_rewards_t *     vote_ele_pool = runtime_stack->stakes.vote_ele;
  fd_vote_rewards_map_t * vote_ele_map  = runtime_stack->stakes.vote_map;
  ulong distributed_rewards = 0UL;
  for( fd_vote_rewards_map_iter_t iter = fd_vote_rewards_map_iter_init( vote_ele_map, vote_ele_pool );
       !fd_vote_rewards_map_iter_done( iter, vote_ele_map, vote_ele_pool );
       iter = fd_vote_rewards_map_iter_next( iter, vote_ele_map, vote_ele_pool ) ) {
    uint idx = (uint)fd_vote_rewards_map_iter_idx( iter, vote_ele_map, vote_ele_pool );
    fd_vote_rewards_t * ele = &vote_ele_pool[idx];

    ulong rewards = runtime_stack->stakes.vote_ele[ idx ].vote_rewards;
    if( rewards==0UL ) continue;

    fd_pubkey_t const * vote_pubkey = &ele->pubkey;
    fd_accdb_svm_credit( accdb, bank, xid, capture_ctx, vote_pubkey, rewards );
    distributed_rewards = fd_ulong_sat_add( distributed_rewards, rewards );
  }

  long ts1 = fd_log_wallclock();

  /* Verify that we didn't pay any more than we expected to */
  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );
  ulong total_stake_rewards = fd_stake_rewards_total_rewards( stake_rewards, bank->stake_rewards_fork_id );

  ulong total_paid = fd_ulong_sat_add( distributed_rewards, total_stake_rewards );
  if( FD_UNLIKELY( total_rewards<total_paid ) ) {
    FD_LOG_CRIT(( "Unexpected rewards calculation result" ));
  }

  runtime_stack->stakes.distributed_rewards = distributed_rewards;
  runtime_stack->stakes.total_rewards       = total_rewards;
  runtime_stack->stakes.total_points.ud     = total_points;

  ulong distribution_starting_block_height = bank->f.block_height + REWARD_CALCULATION_NUM_BLOCKS;
  uint  num_partitions_final = fd_stake_rewards_num_partitions( fd_bank_stake_rewards_query( bank ), bank->stake_rewards_fork_id );

  fd_sysvar_epoch_rewards_init( bank,
                                accdb,
                                xid,
                                capture_ctx,
                                runtime_stack->stakes.distributed_rewards,
                                distribution_starting_block_height,
                                num_partitions_final,
                                runtime_stack->stakes.total_rewards,
                                runtime_stack->stakes.total_points.ud,
                                parent_blockhash );

  FD_LOG_NOTICE(( "begin_rewards_finalize breakdown: distribute_vote_rewards=%.6f (seconds)",
                  (double)(ts1 - ts0) / 1e9 ));
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

  fd_stake_state_t const * stake_state_orig = fd_stakes_get_state( rw->meta );
  if( !stake_state_orig || stake_state_orig->stake_type != FD_STAKE_STATE_STAKE ) {
    fd_accdb_close_rw( accdb, rw );
    return 1;  /* not a valid stake account */
  }
  fd_stake_state_t stake_state[1] = { *stake_state_orig };

  fd_lthash_value_t prev_hash[1];
  fd_hashes_account_lthash( stake_pubkey, rw->meta, fd_accdb_ref_data_const( rw->ro ), prev_hash );

  /* Credit rewards to stake account */
  ulong acc_lamports = fd_accdb_ref_lamports( rw->ro );
  if( FD_UNLIKELY( __builtin_uaddl_overflow( acc_lamports, reward_lamports, &acc_lamports ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( stake_pubkey->key, addr_b58 );
    FD_LOG_EMERG(( "integer overflow while crediting %lu stake reward lamports to %s (previous balance %lu)",
                    reward_lamports, addr_b58, fd_accdb_ref_lamports( rw->ro ) ));
  }
  fd_accdb_ref_lamports_set( rw, acc_lamports );

  ulong old_credits_observed                = stake_state->stake.stake.credits_observed;
  stake_state->stake.stake.credits_observed = new_credits_observed;
  stake_state->stake.stake.delegation.stake = fd_ulong_sat_add( stake_state->stake.stake.delegation.stake, reward_lamports );

  fd_stake_delegations_t * stake_delegations_upd = fd_bank_stake_delegations_modify( bank );
  fd_stake_delegations_fork_update( stake_delegations_upd,
                                    bank->stake_delegations_fork_id,
                                    stake_pubkey,
                                    &stake_state->stake.stake.delegation.voter_pubkey,
                                    stake_state->stake.stake.delegation.stake,
                                    stake_state->stake.stake.delegation.activation_epoch,
                                    stake_state->stake.stake.delegation.deactivation_epoch,
                                    stake_state->stake.stake.credits_observed,
                                    fd_stake_warmup_cooldown_rate( bank->f.epoch, &bank->f.warmup_cooldown_rate_epoch ) );

  if( capture_ctx && capture_ctx->capture_solcap ) {
    fd_capture_link_write_stake_account_payout( capture_ctx,
                                                bank->f.slot,
                                                *stake_pubkey,
                                                bank->f.slot,
                                                acc_lamports,
                                                (long)reward_lamports,
                                                new_credits_observed,
                                                (long)( new_credits_observed - old_credits_observed ),
                                                stake_state->stake.stake.delegation.stake,
                                                (long)reward_lamports );
  }

  FD_STORE( fd_stake_state_t, fd_accdb_ref_data( rw ), *stake_state );
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

  for( fd_stake_rewards_iter_init( stake_rewards, bank->stake_rewards_fork_id, (ushort)partition_idx );
       !fd_stake_rewards_iter_done( stake_rewards );
       fd_stake_rewards_iter_next( stake_rewards, bank->stake_rewards_fork_id ) ) {
    fd_pubkey_t pubkey;
    ulong       lamports;
    ulong       credits_observed;
    fd_stake_rewards_iter_ele( stake_rewards, bank->stake_rewards_fork_id, &pubkey, &lamports, &credits_observed );

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

  bank->f.capitalization = bank->f.capitalization + lamports_distributed;
}

/* Process reward distribution for the block if it is inside reward interval.

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L42 */
void
fd_distribute_partitioned_epoch_rewards( fd_bank_t *               bank,
                                         fd_accdb_user_t *         accdb,
                                         fd_funk_txn_xid_t const * xid,
                                         fd_capture_ctx_t *        capture_ctx ) {
  if( FD_LIKELY( bank->stake_rewards_fork_id==UCHAR_MAX ) ) return;

  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );

  ulong block_height                       = bank->f.block_height;
  ulong distribution_starting_block_height = fd_stake_rewards_starting_block_height( stake_rewards, bank->stake_rewards_fork_id );
  ulong distribution_end_exclusive         = fd_stake_rewards_exclusive_ending_block_height( stake_rewards, bank->stake_rewards_fork_id );

  fd_epoch_schedule_t const * epoch_schedule = &bank->f.epoch_schedule;
  ulong                       epoch          = bank->f.epoch;

  if( FD_UNLIKELY( get_slots_in_epoch( epoch, epoch_schedule ) <= fd_stake_rewards_num_partitions( stake_rewards, bank->stake_rewards_fork_id ) ) ) {
    FD_LOG_CRIT(( "Should not be distributing rewards" ));
  }

  if( FD_UNLIKELY( block_height>=distribution_starting_block_height && block_height<distribution_end_exclusive ) ) {

    ulong partition_idx = block_height-distribution_starting_block_height;
    distribute_epoch_rewards_in_partition( stake_rewards, partition_idx, bank, accdb, xid, capture_ctx );

    /* If we have finished distributing rewards, set the status to inactive */
    if( fd_ulong_sat_add( block_height, 1UL )>=distribution_end_exclusive ) {
      fd_sysvar_epoch_rewards_set_inactive( bank, accdb, xid, capture_ctx );
      bank->stake_rewards_fork_id = UCHAR_MAX;
    }
  }
}

/* Partitioned epoch rewards entry-point.

   https://github.com/anza-xyz/agave/blob/v3.0.4/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L102
*/

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
                                            fd_capture_ctx_t *        capture_ctx FD_PARAM_UNUSED ) {

  /* If the snapshot was loaded while partitioned epoch rewards is
     active, then the vote rewards map must be populated with the state
     of the vote accounts as of the end of the previous epoch boundary.
     The epoch credits for these accounts are stored in the bank along
     with the t-3 commission.  With this, it's possible to recalculate
     the rewards for the previous epoch boundary.  We need the
     commission from the end of the t-3 epoch if we are calculating
     rewards for the transition from epoch t-1 to t since there needs to
     be a 2 epoch commission gap for the delay_commission_updates
     feature. */

  fd_vote_rewards_map_t * vote_ele_map = runtime_stack->stakes.vote_map;

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ushort             vs_fork_idx = bank->vote_stakes_fork_id;

  ulong epoch_credits_len = *fd_bank_epoch_credits_len( bank );
  for( ulong i=0UL; i<epoch_credits_len; i++ ) {
    fd_epoch_credits_t * epoch_credits = &fd_bank_epoch_credits( bank )[i];
    ulong stake_t_1;
    uchar commission_t_1;
    ulong stake_t_2;
    uchar commission_t_2;
    uchar exists_t_1 = 0;
    uchar exists_t_2 = 0;
    fd_vote_stakes_query( vote_stakes, vs_fork_idx, (fd_pubkey_t *)epoch_credits->pubkey, &stake_t_1, &stake_t_2, NULL, NULL, &commission_t_1, &commission_t_2, &exists_t_1, &exists_t_2 );

    fd_vote_rewards_t * vote_ele = &runtime_stack->stakes.vote_ele[i];
    vote_ele->pubkey       = *(fd_pubkey_t *)epoch_credits->pubkey;
    vote_ele->vote_rewards = 0UL;
    if( FD_FEATURE_ACTIVE_BANK( bank, delay_commission_updates ) ) {
      vote_ele->commission = exists_t_2 ? commission_t_2 : commission_t_1;
    } else {
      vote_ele->commission = commission_t_1;
    }
    fd_vote_rewards_map_idx_insert( vote_ele_map, i, runtime_stack->stakes.vote_ele );
  }

  if( FD_FEATURE_ACTIVE_BANK( bank, delay_commission_updates ) ) {
    ulong                     commission_t_3_len = *fd_bank_snapshot_commission_t_3_len( bank );
    fd_stashed_commission_t * commission_t_3     = fd_bank_snapshot_commission_t_3( bank );
    for( ulong i=0UL; i<commission_t_3_len; i++ ) {
      fd_stashed_commission_t const * ele = &commission_t_3[i];
      fd_vote_rewards_t * vote_ele = fd_vote_rewards_map_ele_query( vote_ele_map, (fd_pubkey_t *)ele->pubkey, NULL, runtime_stack->stakes.vote_ele );
      if( FD_LIKELY( vote_ele ) ) vote_ele->commission = ele->commission;
    }
  }

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

  ulong const epoch          = bank->f.epoch;
  ulong const rewarded_epoch = fd_ulong_sat_sub( epoch, 1UL );

  fd_stake_history_t stake_history[1];
  if( FD_UNLIKELY( !fd_sysvar_stake_history_read( accdb, xid, stake_history ) ) ) {
    FD_LOG_ERR(( "Unable to read and decode stake history sysvar" ));
  }

  fd_stake_delegations_t const * stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank );
  if( FD_UNLIKELY( !stake_delegations ) ) {
    FD_LOG_CRIT(( "stake_delegations is NULL" ));
  }

  /* Recompute the stake-vote-rewards result cache with one worker
     (serial).  The caller-supplied vote_ele array must be zeroed
     first so the atomic adds don't start from garbage. */
  runtime_stack->shmem->stake_rewards_cnt = 0UL;
  ulong vote_ele_cnt = *fd_bank_epoch_credits_len( bank );
  for( ulong i=0UL; i<vote_ele_cnt; i++ ) runtime_stack->stakes.vote_ele[ i ].vote_rewards = 0UL;

  calculate_stake_vote_rewards_partitioned( bank,
                                            stake_delegations,
                                            stake_history,
                                            rewarded_epoch,
                                            epoch_rewards_sysvar->total_rewards,
                                            epoch_rewards_sysvar->total_points.ud,
                                            runtime_stack,
                                            0UL, 1UL );

  /* Reinitialize stake_rewards fork using the snapshotted
     partition_cnt / starting_block_height (not the values
     fd_begin_partitioned_rewards_init_partitions would recompute). */
  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );
  bank->stake_rewards_fork_id = fd_stake_rewards_init( stake_rewards,
                                                       bank->f.epoch,
                                                       &epoch_rewards_sysvar->parent_blockhash,
                                                       epoch_rewards_sysvar->distribution_starting_block_height,
                                                       (uint)epoch_rewards_sysvar->num_partitions );

  setup_stake_partitions_partitioned( bank,
                                      stake_delegations,
                                      stake_history,
                                      runtime_stack,
                                      rewarded_epoch,
                                      epoch_rewards_sysvar->total_rewards,
                                      epoch_rewards_sysvar->total_points.ud,
                                      0UL, 1UL );

  fd_bank_stake_delegations_end_frontier_query( banks, bank );
}
