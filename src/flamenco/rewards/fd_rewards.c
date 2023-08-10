#include "fd_rewards.h"
#include "math.h"

static double
total(fd_inflation_t* inflation, double year) {
    double tapered = inflation->initial * pow((1.0 - inflation->taper), year);
    return (tapered > inflation->terminal) ? tapered : inflation->terminal;
}

static double
foundation(fd_inflation_t* inflation, double year) {
    return (year < inflation->foundation_term) ? inflation->foundation * total(inflation, year) : 0.0;
}

static double
validator(fd_inflation_t *inflation, double year) {
    return total(inflation, year) - foundation(inflation, year);
}

static ulong
get_inflation_start_slot() {
    /*
        https://github.com/firedancer-io/solana/blob/de02601d73d626edf98ef63efd772824746f2f33/runtime/src/bank.rs#L2313-L2331

        This function takes into the account of two feature flags `pico_inflation` and `full_inflation`
        The original solana function follows the below logic:
        - if `full_inflation` is enabled
            return first slot that `full_inflation` is enabled
        - else
            if `pico_inflation` is enabled
                return first slot that `pico_inflation` is enabled
            else
                return 0
        Since both features are enabled at slot 1 on mainnet since ledger v14, the performant & reasonable thing to do is to return 1 (the slot when full_inflation feature flag is enabled)
    */
    return 1;
}

static ulong
get_inflation_num_slots(fd_firedancer_banks_t * bank) {
    /* https://github.com/firedancer-io/solana/blob/de02601d73d626edf98ef63efd772824746f2f33/runtime/src/bank.rs#L2333-L2342 */
    ulong inflaction_activation_slot = get_inflation_start_slot();
    ulong inflation_start_slot = fd_sysvar_epoch_schedule_get_first_slot_in_epoch(
        &bank->epoch_schedule,
        fd_ulong_sat_sub(
            fd_slot_to_epoch(&bank->epoch_schedule, inflaction_activation_slot, NULL),
            1
            )
        );

    ulong epoch = fd_slot_to_epoch(&bank->epoch_schedule, bank->slot, NULL);

    return fd_sysvar_epoch_schedule_get_first_slot_in_epoch(&bank->epoch_schedule, epoch) - inflation_start_slot;
}


/// for a given stake and vote_state, calculate how many
///   points were earned (credits * stake) and new value
///   for credits_observed were the points paid
static void calculate_stake_points_and_credits (
  fd_stake_history_t * stake_history,
  fd_stake_state_t * stake_state,
  fd_vote_state_t * vote_state,
  fd_calculate_stake_points_t * result
) {
  ulong credits_in_stake = stake_state->inner.stake.stake.credits_observed;
  ulong credits_in_vote = deq_fd_vote_epoch_credits_t_empty( vote_state->epoch_credits) ? 0 : deq_fd_vote_epoch_credits_t_peek_tail_const( vote_state->epoch_credits )->credits;

  result->points = 0;
  result->force_credits_update_with_skipped_reward = credits_in_vote < credits_in_stake;
  if (credits_in_vote < credits_in_stake) {
    result->new_credits_observed = credits_in_vote;
    return;
  }
  if (credits_in_vote == credits_in_stake) {
    // don't hint caller and return current value if credits remain unchanged (= delinquent)
    result->new_credits_observed = credits_in_stake;
    return;
  }

  __uint128_t points = 0;
  ulong new_credits_observed = credits_in_stake;

  for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( vote_state->epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( vote_state->epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( vote_state->epoch_credits, iter ) ) {
    fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele(vote_state->epoch_credits, iter );
    ulong epoch = ele->epoch;
    ulong final_epoch_credits = ele->credits;
    ulong initial_epoch_credits = ele->prev_credits;
    __uint128_t earned_credits = 0;
    if (credits_in_stake < initial_epoch_credits) {
      earned_credits = (__uint128_t)(final_epoch_credits - initial_epoch_credits);
    } else if (credits_in_stake < final_epoch_credits) {
      earned_credits = (__uint128_t)(final_epoch_credits - new_credits_observed);
    }
    new_credits_observed = fd_ulong_max(new_credits_observed, final_epoch_credits);

    __uint128_t stake_amount = (__uint128_t)(stake_activating_and_deactivating(&stake_state->inner.stake.stake.delegation, epoch, stake_history).effective);
    points += stake_amount * earned_credits;
  }
  result->points = points;
  result->new_credits_observed = new_credits_observed;
  return;
}


static void calculate_and_redeem_stake_rewards(
  fd_stake_history_t * stake_history,
  fd_stake_state_t * stake_state,
  fd_vote_state_t * vote_state,
  ulong rewarded_epoch,
  fd_point_value_t * point_value,
  fd_calculated_stake_rewards_t * result
) {

  /* 
  implements the `calculate_stake_rewards` solana function
  for a given stake and vote_state, calculate what distributions and what updates should be made
  returns a tuple in the case of a payout of:
  * staker_rewards to be distributed
  * voter_rewards to be distributed
  * new value for credits_observed in the stake
  returns None if there's no payout or if any deserved payout is < 1 lamport */
  fd_calculate_stake_points_t stake_points_result; 
  calculate_stake_points_and_credits( stake_history, stake_state, vote_state, &stake_points_result);

  // Drive credits_observed forward unconditionally when rewards are disabled
  // or when this is the stake's activation epoch
  stake_points_result.force_credits_update_with_skipped_reward |= (point_value->rewards == 0);
  stake_points_result.force_credits_update_with_skipped_reward |= (stake_state->inner.stake.stake.delegation.activation_epoch == rewarded_epoch);

  if (stake_points_result.force_credits_update_with_skipped_reward) {
    result->staker_rewards = 0;
    result->voter_rewards = 0;
    result->new_credits_observed = stake_points_result.new_credits_observed;
    return;
  }
  if ( stake_points_result.points == 0 || point_value->points == 0 ) {
    result = NULL;
    return;
  }


  ulong rewards = (ulong)(stake_points_result.points * point_value->rewards / point_value->points);
  fd_commission_split_t split_result;
  fd_vote_commission_split( vote_state, rewards, &split_result );
  if (split_result.is_split && (split_result.voter_portion == 0 || split_result.staker_portion == 0)) {
    result = NULL;
    return;
  }

  result->staker_rewards = split_result.staker_portion;
  result->voter_rewards = split_result.voter_portion;
  result->new_credits_observed = stake_points_result.new_credits_observed;

  /* implements the `redeem_stake_rewards` solana function */
  stake_state->inner.stake.stake.credits_observed += result->new_credits_observed;
  stake_state->inner.stake.stake.delegation.stake += result->staker_rewards;
  return;
} 

int redeem_rewards(
  instruction_ctx_t* ctx,
  fd_pubkey_t * stake_acc,
  fd_vote_state_t * vote_state,
  ulong rewarded_epoch,
  fd_point_value_t * point_value
) {
    fd_stake_state_t stake_state;
    read_stake_state( ctx->global, stake_acc, &stake_state );
    if (!fd_stake_state_is_stake( &stake_state)) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_stake_history_t stake_history;
    fd_sysvar_stake_history_read( ctx->global, &stake_history);

    fd_calculated_stake_rewards_t * stake_rewards_result = NULL;
    calculate_and_redeem_stake_rewards(&stake_history, &stake_state, vote_state, rewarded_epoch, point_value, stake_rewards_result);
    if (stake_rewards_result == NULL) {
        ctx->txn_ctx->custom_err = 0; /* Err(StakeError::NoCreditsToRedeem.into()) */
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
    int err = write_stake_state( ctx->global, stake_acc, &stake_state, 0);
    if (err != 0 ) {
        return err;
    }

    char * raw_acc_data = (char*) fd_acc_mgr_view_data(ctx->global->acc_mgr, ctx->global->funk_txn, stake_acc, NULL, &err);
    fd_account_meta_t *metadata = (fd_account_meta_t *) raw_acc_data;

    fd_acc_mgr_set_lamports( ctx->global->acc_mgr, ctx->global->funk_txn, ctx->global->bank.slot, stake_acc, metadata->info.lamports + stake_rewards_result->staker_rewards);
    return FD_EXECUTOR_INSTR_SUCCESS;

}

int calculate_points(
    instruction_ctx_t * ctx,
    fd_pubkey_t * stake_acc,
    fd_vote_state_t * vote_state,
  __uint128_t * result
) {
    fd_stake_state_t stake_state;
    read_stake_state( ctx->global, stake_acc, &stake_state );
    if (!fd_stake_state_is_stake( &stake_state)) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_stake_history_t stake_history;
    fd_sysvar_stake_history_read( ctx->global, &stake_history);
    fd_calculate_stake_points_t stake_point_result;
    calculate_stake_points_and_credits(&stake_history, &stake_state, vote_state, &stake_point_result);
    *result = stake_point_result.points;

    return FD_EXECUTOR_INSTR_SUCCESS;
}


static double
epoch_duration_in_years(
    fd_firedancer_banks_t * bank,
    ulong prev_epoch
) {
    /* get_slots_in_epoch */
    ulong slots_in_epoch = (prev_epoch < bank->epoch_schedule.first_normal_epoch) ?
        1UL << fd_ulong_sat_add(prev_epoch, FD_EPOCH_LEN_MIN_TRAILING_ZERO) :
        bank->epoch_schedule.slots_per_epoch;
    return (double)slots_in_epoch / bank->slots_per_year;
}

void
calculate_previous_epoch_inflation_rewards(
    fd_firedancer_banks_t * bank,
    ulong prev_epoch_capitalization,
    ulong prev_epoch,
    prev_epoch_inflation_rewards_t * rewards
) {
    /* https://github.com/firedancer-io/solana/blob/de02601d73d626edf98ef63efd772824746f2f33/runtime/src/bank.rs#L2351-L2376 */


    /* slot_in_year_for_inflation 
    https://github.com/firedancer-io/solana/blob/de02601d73d626edf98ef63efd772824746f2f33/runtime/src/bank.rs#L2344-L2349
    */
    ulong num_slots = get_inflation_num_slots(bank);
    double slot_in_year = (double)num_slots / bank->slots_per_year;
    rewards->validator_rate = validator(&bank->inflation, slot_in_year);
    rewards->foundation_rate = foundation(&bank->inflation, slot_in_year);
    rewards->prev_epoch_duration_in_years = epoch_duration_in_years(bank, prev_epoch);
    rewards->validator_rewards = (ulong)(rewards->validator_rate * (double)prev_epoch_capitalization * rewards->prev_epoch_duration_in_years);
}

/// Calculates epoch reward points from stake/vote accounts.
/// Returns reward lamports and points for the epoch or none if points == 0.
void calculate_reward_points_partitioned(
    fd_global_ctx_t * global,
    fd_firedancer_banks_t * bank,
    ulong rewards
) {
    // global->solana_vote_program
    (void) global;
    (void) bank;
    (void) rewards;

}

/// Sum the lamports of the vote accounts and the delegated stake
ulong vote_balance_and_staked(fd_stakes_t * stakes) {
  /* TODO: implement pub(crate) fn vote_balance_and_staked*/
  (void) stakes;
  return 0;
}

/// Calculate epoch reward and return vote and stake rewards.
void calculate_validator_rewards(
    ulong prev_epoch,
    ulong validator_rewards
) {
    (void)prev_epoch;
    (void)validator_rewards;
}

// Calculate rewards from previous epoch to prepare for partitioned distribution.
void calculate_rewards_for_partitioning(
    fd_firedancer_banks_t * bank,
    ulong prev_epoch,
    partitioned_rewards_calculation_t * partitioned_rewards
) {
    prev_epoch_inflation_rewards_t rewards;
    calculate_previous_epoch_inflation_rewards(bank, bank->capitalization, prev_epoch, &rewards);

    ulong old_vote_balance_and_staked = vote_balance_and_staked(&bank->stakes);
    (void) old_vote_balance_and_staked;

    calculate_validator_rewards(prev_epoch, rewards.validator_rewards);
    (void) partitioned_rewards;

}

//calculate_rewards_for_partitioning

//calculate_rewards_and_distribute_vote_rewards

// update_rewards_with_thread_pool



