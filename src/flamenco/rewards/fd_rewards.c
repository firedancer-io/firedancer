#include "fd_rewards.h"
#include "fd_rewards_types.h"
#include "math.h"

#include "../runtime/fd_system_ids.h"
#include "../runtime/context/fd_exec_epoch_ctx.h"
#include "../runtime/context/fd_exec_slot_ctx.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

static double
total( fd_inflation_t const * inflation, double year ) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/sdk/src/inflation.rs#L84-L93 */
    FD_TEST( year >= 0.0 );
    double tapered = inflation->initial * pow((1.0 - inflation->taper), year);
    return (tapered > inflation->terminal) ? tapered : inflation->terminal;
}

static double
foundation( fd_inflation_t const * inflation, double year ) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/sdk/src/inflation.rs#L100-L108 */
    return (year < inflation->foundation_term) ? inflation->foundation * total(inflation, year) : 0.0;
}

static double
validator( fd_inflation_t const * inflation, double year) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/sdk/src/inflation.rs#L96-L99 */
    FD_LOG_DEBUG(("Validator Rate: %.16f %.16f %.16f %.16f %.16f", year, total( inflation, year ), foundation( inflation, year ), inflation->taper, inflation->initial));
    return total( inflation, year ) - foundation( inflation, year );
}

static FD_FN_CONST ulong
get_inflation_start_slot( fd_exec_slot_ctx_t * slot_ctx ) {
    ulong devnet_and_testnet = FD_FEATURE_ACTIVE(slot_ctx, devnet_and_testnet) ? slot_ctx->epoch_ctx->features.devnet_and_testnet : ULONG_MAX;
    ulong enable = ULONG_MAX;
    if (FD_FEATURE_ACTIVE( slot_ctx, full_inflation_vote ) && FD_FEATURE_ACTIVE(slot_ctx, full_inflation_enable)) {
        enable = slot_ctx->epoch_ctx->features.full_inflation_enable;
    }

    ulong min_slot = fd_ulong_min( enable, devnet_and_testnet );
    if ( min_slot == ULONG_MAX ) {
        if ( FD_FEATURE_ACTIVE( slot_ctx, pico_inflation ) ) {
            min_slot = slot_ctx->epoch_ctx->features.pico_inflation;
        } else {
            min_slot = 0;
        }
    }
    return min_slot;
}

static ulong
get_inflation_num_slots( fd_exec_slot_ctx_t * slot_ctx,
                         fd_epoch_schedule_t const * epoch_schedule,
                         ulong slot ) {
    /* https://github.com/firedancer-io/solana/blob/de02601d73d626edf98ef63efd772824746f2f33/runtime/src/bank.rs#L2333-L2342 */
    ulong inflation_activation_slot = get_inflation_start_slot( slot_ctx );
    ulong inflation_start_slot = fd_epoch_slot0(
        epoch_schedule,
        fd_ulong_sat_sub(
            fd_slot_to_epoch( epoch_schedule, inflation_activation_slot, NULL ),
            1 )
        );

    ulong epoch = fd_slot_to_epoch(epoch_schedule, slot, NULL);

    return fd_epoch_slot0(epoch_schedule, epoch) - inflation_start_slot;
}


// for a given stake and vote_state, calculate how many
//   points were earned (credits * stake) and new value
//   for credits_observed were the points paid
static void
calculate_stake_points_and_credits (
  fd_stake_history_t const *    stake_history,
  fd_stake_state_v2_t *         stake_state,
  fd_vote_state_versioned_t *   vote_state_versioned,
  fd_calculate_stake_points_t * result
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/programs/stake/src/stake_state.rs#L249-L351 */
    fd_vote_epoch_credits_t * epoch_credits;
    switch (vote_state_versioned->discriminant) {
        case fd_vote_state_versioned_enum_current:
            epoch_credits = vote_state_versioned->inner.current.epoch_credits;
            break;
        case fd_vote_state_versioned_enum_v0_23_5:
            epoch_credits = vote_state_versioned->inner.v0_23_5.epoch_credits;
            break;
        case fd_vote_state_versioned_enum_v1_14_11:
            epoch_credits = vote_state_versioned->inner.v1_14_11.epoch_credits;
            break;
        default:
            __builtin_unreachable();
    }
  ulong credits_in_stake = stake_state->inner.stake.stake.credits_observed;
  ulong credits_in_vote = deq_fd_vote_epoch_credits_t_empty( epoch_credits ) ? 0 : deq_fd_vote_epoch_credits_t_peek_tail_const( epoch_credits )->credits;
//   FD_LOG_WARNING(("Vote credits: %lu %32J %lu %lu %lu", credits_in_stake, stake_state->inner.stake.stake.delegation.voter_pubkey.key, credits_in_vote, deq_fd_vote_epoch_credits_t_peek_tail_const( epoch_credits )->epoch, deq_fd_vote_epoch_credits_t_peek_tail_const( epoch_credits )->prev_credits ));

  result->points = 0;
  result->force_credits_update_with_skipped_reward = credits_in_vote < credits_in_stake;
  if (credits_in_vote < credits_in_stake) {
    // FD_LOG_WARNING(("Vote credits 2: %lu %32J %lu %lu %lu", credits_in_stake, stake_state->inner.stake.stake.delegation.voter_pubkey.key, credits_in_vote, deq_fd_vote_epoch_credits_t_peek_tail_const( epoch_credits )->epoch, deq_fd_vote_epoch_credits_t_peek_tail_const( epoch_credits )->prev_credits ));

    result->new_credits_observed = credits_in_vote;
    return;
  }
  if (credits_in_vote == credits_in_stake) {
    // don't hint caller and return current value if credits remain unchanged (= delinquent)
    result->new_credits_observed = credits_in_stake;
    return;
  }

  uint128 points = 0;
  ulong new_credits_observed = credits_in_stake;

  for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( epoch_credits ); !deq_fd_vote_epoch_credits_t_iter_done( epoch_credits, iter ); iter = deq_fd_vote_epoch_credits_t_iter_next( epoch_credits, iter ) ) {
    fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele(epoch_credits, iter );
    ulong epoch = ele->epoch;
    ulong final_epoch_credits = ele->credits;
    ulong initial_epoch_credits = ele->prev_credits;
    uint128 earned_credits = 0;
    if (credits_in_stake < initial_epoch_credits) {
      earned_credits = (uint128)(final_epoch_credits - initial_epoch_credits);
    } else if (credits_in_stake < final_epoch_credits) {
      earned_credits = (uint128)(final_epoch_credits - new_credits_observed);
    }
    new_credits_observed = fd_ulong_max(new_credits_observed, final_epoch_credits);

    uint128 stake_amount = (uint128)(fd_stake_activating_and_deactivating(&stake_state->inner.stake.stake.delegation, epoch, stake_history, NULL).effective);
    points += stake_amount * earned_credits;
  }
  result->points = points;
  result->new_credits_observed = new_credits_observed;
//   FD_LOG_WARNING(("Vote credits 3: %lu", new_credits_observed ));

}


static int
calculate_stake_rewards(
  fd_stake_history_t const *      stake_history,
  fd_stake_state_v2_t *           stake_state,
  fd_vote_state_versioned_t *     vote_state_versioned,
  ulong                           rewarded_epoch,
  fd_point_value_t *              point_value,
  fd_calculated_stake_rewards_t * result
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/programs/stake/src/stake_state.rs#L360-L464 */
    /*
    implements the `calculate_stake_rewards` solana function
    for a given stake and vote_state, calculate what distributions and what updates should be made
    returns a tuple in the case of a payout of:
    * staker_rewards to be distributed
    * voter_rewards to be distributed
    * new value for credits_observed in the stake
    returns None if there's no payout or if any deserved payout is < 1 lamport */
    fd_calculate_stake_points_t stake_points_result = {0};
    // TODO
    calculate_stake_points_and_credits( stake_history, stake_state, vote_state_versioned, &stake_points_result);
    // FD_LOG_WARNING(("CSR: %lu", stake_points_result.new_credits_observed ));

    // Drive credits_observed forward unconditionally when rewards are disabled
    // or when this is the stake's activation epoch
    stake_points_result.force_credits_update_with_skipped_reward |= (point_value->rewards == 0);
    stake_points_result.force_credits_update_with_skipped_reward |= (stake_state->inner.stake.stake.delegation.activation_epoch == rewarded_epoch);

    if (stake_points_result.force_credits_update_with_skipped_reward) {
        result->staker_rewards = 0;
        result->voter_rewards = 0;
        result->new_credits_observed = stake_points_result.new_credits_observed;
        return 0;
    }
    if ( stake_points_result.points == 0 || point_value->points == 0 ) {
        return 1;
    }


    ulong rewards = (ulong)(stake_points_result.points * (uint128)point_value->rewards / (uint128) point_value->points);
    if (rewards == 0) {
        return 1;
    }

    fd_commission_split_t split_result;
    fd_vote_commission_split( vote_state_versioned, rewards, &split_result );
    if (split_result.is_split && (split_result.voter_portion == 0 || split_result.staker_portion == 0)) {
        return 1;
    }

    result->staker_rewards = split_result.staker_portion;
    result->voter_rewards = split_result.voter_portion;
    result->new_credits_observed = stake_points_result.new_credits_observed;

    /* implements the `redeem_stake_rewards` solana function */
    // stake_state->inner.stake.stake.credits_observed += result->new_credits_observed;
    // stake_state->inner.stake.stake.delegation.stake += result->staker_rewards;
    return 0;
}

static int
stake_state_redeem_rewards( fd_exec_slot_ctx_t *            slot_ctx,
                            fd_stake_history_t const *      stake_history,
                            fd_pubkey_t const *             stake_acc,
                            fd_vote_state_versioned_t *     vote_state,
                            ulong                           rewarded_epoch,
                            fd_point_value_t *              point_value,
                            fd_calculated_stake_rewards_t * result ) {

    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/programs/stake/src/stake_state.rs#L1525-L1571 */
    FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);
    int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, stake_acc_rec );
    if( FD_UNLIKELY( err ) ) {
        return err;
    }

    fd_stake_state_v2_t stake_state = {0};
    int rc = fd_stake_get_state(stake_acc_rec, &slot_ctx->valloc, &stake_state);
    if ( rc != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }
    // fd_stake_state_t stake_state;
    // read_stake_state( global, stake_acc_rec->const_meta, &stake_state );
    // if (!fd_stake_state_is_stake( &stake_state)) {
    //     return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    // }

    rc = calculate_stake_rewards(stake_history, &stake_state, vote_state, rewarded_epoch, point_value, result);
    // FD_LOG_WARNING(("SSRR: %32J RES->NCO: %lu, SS->NCO: %lu %lu", stake_acc->key, result->new_credits_observed, stake_state.discriminant, stake_state.inner.stake.stake.credits_observed));
    if (rc != 0) {
        // ctx->txn_ctx->custom_err = 0; /* Err(StakeError::NoCreditsToRedeem.into()) */
        return rc;
    }

    return FD_EXECUTOR_INSTR_SUCCESS;
}

int
calculate_points(
    fd_stake_state_v2_t *       stake_state,
    fd_vote_state_versioned_t * vote_state_versioned,
    fd_stake_history_t const *  stake_history,
    uint128 *                   result
) {
    // TODO
    // if (!fd_stake_state_is_stake( stake_state)) {
    //     return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    // }
    fd_calculate_stake_points_t stake_point_result;
    calculate_stake_points_and_credits(stake_history, stake_state, vote_state_versioned, &stake_point_result);
    *result = stake_point_result.points;

    return FD_EXECUTOR_INSTR_SUCCESS;
}


static double
epoch_duration_in_years(
    fd_epoch_bank_t const * epoch_bank,
    ulong prev_epoch
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L2283-L2288 */
    /* get_slots_in_epoch */
    ulong slots_in_epoch = (prev_epoch < epoch_bank->epoch_schedule.first_normal_epoch) ?
        1UL << fd_ulong_sat_add(prev_epoch, FD_EPOCH_LEN_MIN_TRAILING_ZERO) :
        epoch_bank->epoch_schedule.slots_per_epoch;
    return (double)slots_in_epoch / (double) epoch_bank->slots_per_year;
}

static void
calculate_previous_epoch_inflation_rewards(
    fd_exec_slot_ctx_t * slot_ctx,
    fd_epoch_bank_t const * epoch_bank,
    ulong slot,
    ulong prev_epoch_capitalization,
    ulong prev_epoch,
    fd_prev_epoch_inflation_rewards_t * rewards
) {
    /* https://github.com/firedancer-io/solana/blob/de02601d73d626edf98ef63efd772824746f2f33/runtime/src/bank.rs#L2351-L2376 */


    /* slot_in_year_for_inflation
    https://github.com/firedancer-io/solana/blob/de02601d73d626edf98ef63efd772824746f2f33/runtime/src/bank.rs#L2344-L2349
    */
    ulong num_slots = get_inflation_num_slots( slot_ctx, &epoch_bank->epoch_schedule, slot );
    double slot_in_year = (double)num_slots / (double)epoch_bank->slots_per_year;
    rewards->validator_rate = validator( &epoch_bank->inflation, slot_in_year );
    rewards->foundation_rate = foundation(&epoch_bank->inflation, slot_in_year);
    rewards->prev_epoch_duration_in_years = epoch_duration_in_years(epoch_bank, prev_epoch);
    rewards->validator_rewards = (ulong)(rewards->validator_rate * (double)prev_epoch_capitalization * rewards->prev_epoch_duration_in_years);
    FD_LOG_DEBUG(("Rewards %lu, Rate %.16f, Duration %.18f Capitalization %lu Slot in year %.16f", rewards->validator_rewards, rewards->validator_rate, rewards->prev_epoch_duration_in_years, prev_epoch_capitalization, slot_in_year));
}


// Sum the lamports of the vote accounts and the delegated stake
static ulong
vote_balance_and_staked( fd_exec_slot_ctx_t * slot_ctx, fd_stakes_t const * stakes) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/stakes.rs#L346-L356 */
    ulong result = 0;
    for( fd_vote_accounts_pair_t_mapnode_t const * n = fd_vote_accounts_pair_t_map_minimum_const( stakes->vote_accounts.vote_accounts_pool, stakes->vote_accounts.vote_accounts_root );
         n;
         n = fd_vote_accounts_pair_t_map_successor_const( stakes->vote_accounts.vote_accounts_pool, n ) ) {
        result += n->elem.value.lamports;
    }

    for( fd_vote_accounts_pair_t_mapnode_t const * n = fd_vote_accounts_pair_t_map_minimum_const( slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, slot_ctx->slot_bank.vote_account_keys.vote_accounts_root );
         n;
         n = fd_vote_accounts_pair_t_map_successor_const( slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, n ) ) {
        result += n->elem.value.lamports;
    }

    for( fd_delegation_pair_t_mapnode_t const * n = fd_delegation_pair_t_map_minimum_const( stakes->stake_delegations_pool, stakes->stake_delegations_root );
         n;
         n = fd_delegation_pair_t_map_successor_const( stakes->stake_delegations_pool, n ) ) {
        fd_pubkey_t const * stake_acc = &n->elem.account;
        FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);
        if (fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, stake_acc_rec ) != FD_ACC_MGR_SUCCESS  ) {
            continue;
        }

        fd_stake_state_v2_t stake_state;
        if (fd_stake_get_state( stake_acc_rec, &slot_ctx->valloc, &stake_state) != 0) {
            continue;
        }

        result += stake_state.inner.stake.stake.delegation.stake;
    }

    for( fd_stake_accounts_pair_t_mapnode_t const * n = fd_stake_accounts_pair_t_map_minimum_const( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root );
         n;
         n = fd_stake_accounts_pair_t_map_successor_const( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, n ) ) {
        fd_pubkey_t const * stake_acc = &n->elem.key;
        FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);
        if (fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, stake_acc_rec ) != FD_ACC_MGR_SUCCESS ) {
            continue;
        }
        // result += stake_acc_rec->const_meta->info.lamports;
        fd_stake_state_v2_t stake_state;
        if (fd_stake_get_state( stake_acc_rec, &slot_ctx->valloc, &stake_state) != 0) {
            continue;
        }

        result += stake_state.inner.stake.stake.delegation.stake;
    }

    return result;
}

static void
calculate_reward_points_account(
    fd_exec_slot_ctx_t *       slot_ctx,
    fd_stake_history_t const * stake_history,
    fd_pubkey_t const *        voter_acc,
    fd_pubkey_t const *        stake_acc,
    uint128 * points,
    ulong * actual_len
 ) {
    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    ulong min_stake_delegation = 1000000000;

    FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);
    if( 0!=fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, stake_acc_rec) ) {
        FD_LOG_DEBUG(("Stake acc not found %32J", stake_acc->uc));
        return;
    }

    if (stake_acc_rec->const_meta->info.lamports == 0) {
        FD_LOG_DEBUG(("Stake acc not found %32J", stake_acc->uc));
        return;
    }

    fd_stake_state_v2_t stake_state = {0};
    int rc = fd_stake_get_state(stake_acc_rec, &slot_ctx->valloc, &stake_state);
    if ( rc != 0 ) {
    //   FD_LOG_ERR(("failed to read"));
        return;
    }

    if (FD_FEATURE_ACTIVE(slot_ctx, stake_minimum_delegation_for_rewards)) {
        if (stake_state.inner.stake.stake.delegation.stake < min_stake_delegation) {
            return;
        }
    }
    *actual_len += 1;

    fd_vote_accounts_pair_t_mapnode_t key;
    fd_memcpy(&key.elem.key, voter_acc, sizeof(fd_pubkey_t));

    if (fd_vote_accounts_pair_t_map_find(epoch_bank->stakes.vote_accounts.vote_accounts_pool, epoch_bank->stakes.vote_accounts.vote_accounts_root, &key) == NULL) {
        return;
    }

    FD_BORROWED_ACCOUNT_DECL(voter_acc_rec);
    int read_err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, voter_acc, voter_acc_rec );
    if( read_err!=0 || 0!=memcmp( &voter_acc_rec->const_meta->info.owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) {
        return;
    }

    /* Deserialize vote account */
    fd_bincode_decode_ctx_t decode = {
        .data    = voter_acc_rec->const_data,
        .dataend = voter_acc_rec->const_data + voter_acc_rec->const_meta->dlen,
        /* TODO: Make this a instruction-scoped allocator */
        .valloc  = slot_ctx->valloc,
    };
    fd_vote_state_versioned_t vote_state[1] = {0};
    if( FD_UNLIKELY( 0!=fd_vote_state_versioned_decode( vote_state, &decode ) ) )
        FD_LOG_ERR(( "vote_state_versioned_decode failed" ));

    // fd_vote_epoch_credits_t * epoch_credits;
    // switch (vote_state->discriminant) {
    // case fd_vote_state_versioned_enum_current:
    //     epoch_credits = vote_state->inner.current.epoch_credits;
    //     break;
    // case fd_vote_state_versioned_enum_v0_23_5:
    //     epoch_credits = vote_state->inner.v0_23_5.epoch_credits;
    //     break;
    // case fd_vote_state_versioned_enum_v1_14_11:
    //     epoch_credits = vote_state->inner.v1_14_11.epoch_credits;
    //     break;
    // default:
    //     __builtin_unreachable();
    // }

    // FD_LOG_WARNING(("VOTE ACCOUNT: %32J, %lu", voter_acc->key, deq_fd_vote_epoch_credits_t_peek_tail_const( epoch_credits )->credits));

    uint128 result;
    *points += (calculate_points(&stake_state, vote_state, stake_history, &result) == FD_EXECUTOR_INSTR_SUCCESS ? result : 0);
    // FD_LOG_WARNING(("PER_ACC_POINTS: Acc: %32J, Points: %K", stake_acc->key, &result ));
    fd_bincode_destroy_ctx_t destroy = {.valloc = slot_ctx->valloc};
    fd_stake_state_v2_destroy( &stake_state, &destroy );
    fd_vote_state_versioned_destroy( vote_state, &destroy );
}

static void
calculate_reward_points_partitioned(
    fd_exec_slot_ctx_t *       slot_ctx,
    fd_stake_history_t const * stake_history,
    ulong                      rewards,
    fd_point_value_t *         result
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L2961-L3018 */
    uint128 points = 0;
    ulong actual_len = 0;
    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    FD_LOG_DEBUG(("Delegations len %lu, slot del len %lu", fd_delegation_pair_t_map_size( epoch_bank->stakes.stake_delegations_pool, epoch_bank->stakes.stake_delegations_root ), fd_stake_accounts_pair_t_map_size( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root )));
    for( fd_delegation_pair_t_mapnode_t const * n = fd_delegation_pair_t_map_minimum_const( epoch_bank->stakes.stake_delegations_pool, epoch_bank->stakes.stake_delegations_root );
         n;
         n = fd_delegation_pair_t_map_successor_const( epoch_bank->stakes.stake_delegations_pool, n )
    ) {
        fd_pubkey_t const * voter_acc = &n->elem.delegation.voter_pubkey;
        fd_pubkey_t const * stake_acc = &n->elem.account;
        //  FD_LOG_WARNING(("STAKE ACC1: %32J, %32J", stake_acc->key, voter_acc->key));
        calculate_reward_points_account( slot_ctx, stake_history, voter_acc, stake_acc, &points, &actual_len );
    }
    // FD_LOG_HEXDUMP_WARNING(( "POINTS 1", &points, 16 ));

    for ( fd_stake_accounts_pair_t_mapnode_t const * n = fd_stake_accounts_pair_t_map_minimum_const( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root );
          n;
          n = fd_stake_accounts_pair_t_map_successor_const( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, n ) ) {
        (void) n;
        fd_pubkey_t const * stake_acc = &n->elem.key;

        // FD_LOG_WARNING(("STAKE ACC2: %32J", stake_acc->key));
        FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);
        if( 0!=fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, stake_acc_rec) ) {
            FD_LOG_DEBUG(("Stake acc not found %32J", stake_acc->uc));
            continue;
        }

        if (stake_acc_rec->const_meta->info.lamports == 0) continue;

        fd_stake_state_v2_t stake_state = {0};
        int rc = fd_stake_get_state(stake_acc_rec, &slot_ctx->valloc, &stake_state);
        if ( rc != 0 ) {
            FD_LOG_WARNING(("Failed to read stake state from stake account %32J", stake_acc));
            continue;
        }

        fd_pubkey_t const * voter_acc = &stake_state.inner.stake.stake.delegation.voter_pubkey;
        calculate_reward_points_account( slot_ctx, stake_history, voter_acc, stake_acc, &points, &actual_len );
        fd_bincode_destroy_ctx_t destroy = {.valloc = slot_ctx->valloc};
        fd_stake_state_v2_destroy( &stake_state, &destroy );
    }

    // FD_LOG_HEXDUMP_WARNING(( "POINTS", &points, 16 ));
    // FD_LOG_WARNING(("REWARDS 2: %lu TOT POINTS: %llu",rewards, points ));
    if (points > 0) {
        result->points = points;
        result->rewards = rewards;
    } else {
        result = NULL;
    }
}

static void
calculate_stake_vote_rewards_account(
    fd_exec_slot_ctx_t *         slot_ctx,
    fd_stake_history_t const *   stake_history,
    ulong                        rewarded_epoch,
    fd_point_value_t *           point_value,
    fd_pubkey_t const *          voter_acc,
    fd_pubkey_t const *          stake_acc,
    fd_stake_reward_t *          stake_reward_deq,
    fd_vote_reward_t_mapnode_t * vote_reward_map,
    fd_acc_lamports_t *          total_stake_rewards
) {
    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    ulong min_stake_delegation = 1000000000;

    FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);
    int err = fd_acc_mgr_view(slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, stake_acc_rec);
    if (FD_UNLIKELY(err != FD_ACC_MGR_SUCCESS)) {
      FD_LOG_DEBUG(("stake_state::stake_state_redeem_rewards() %32J not found", stake_acc ));
      return;
    }

    if (stake_acc_rec->const_meta->info.lamports == 0) return;

    fd_stake_state_v2_t stake_state = {0};
    int rc = fd_stake_get_state(stake_acc_rec, &slot_ctx->valloc, &stake_state);
    if ( rc != 0 ) {
      // FD_LOG_ERR(("failed to read"));
      return;
    }

    if (FD_FEATURE_ACTIVE(slot_ctx, stake_minimum_delegation_for_rewards)) {
      if (stake_state.inner.stake.stake.delegation.stake < min_stake_delegation) {
        return;
      }
    }

    fd_vote_accounts_pair_t_mapnode_t key;
    fd_memcpy(&key.elem.key, voter_acc, sizeof(fd_pubkey_t));

    if (fd_vote_accounts_pair_t_map_find(epoch_bank->stakes.vote_accounts.vote_accounts_pool, epoch_bank->stakes.vote_accounts.vote_accounts_root, &key) == NULL
        && fd_vote_accounts_pair_t_map_find(slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, slot_ctx->slot_bank.vote_account_keys.vote_accounts_root, &key) == NULL) {
      return;
    }

    FD_BORROWED_ACCOUNT_DECL(voter_acc_rec);
    int read_err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, voter_acc, voter_acc_rec );
    if( read_err!=0 || 0!=memcmp( &voter_acc_rec->const_meta->info.owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) {
      return;
    }

    /* Read vote account */
    fd_bincode_decode_ctx_t decode = {
        .data    = voter_acc_rec->const_data,
        .dataend = voter_acc_rec->const_data + voter_acc_rec->const_meta->dlen,
        /* TODO: Make this a instruction-scoped allocator */
        .valloc  = slot_ctx->valloc,
    };
    fd_bincode_destroy_ctx_t destroy = {.valloc = slot_ctx->valloc};
    fd_vote_state_versioned_t vote_state_versioned[1] = {0};
    if( fd_vote_state_versioned_decode( vote_state_versioned, &decode ) != 0 ) {
      return;
    }

    uchar commission = 0U;
    switch (vote_state_versioned->discriminant) {
        case fd_vote_state_versioned_enum_current:
            commission = (uchar)vote_state_versioned->inner.current.commission;
            break;
        case fd_vote_state_versioned_enum_v0_23_5:
            commission = (uchar)vote_state_versioned->inner.v0_23_5.commission;
            break;
        case fd_vote_state_versioned_enum_v1_14_11:
            commission = (uchar)vote_state_versioned->inner.v1_14_11.commission;
            break;
        default:
            __builtin_unreachable();
    }

    fd_vote_reward_t_mapnode_t * node = fd_vote_reward_t_map_query(vote_reward_map, *voter_acc, NULL);
    if (node == NULL) {
        node = fd_vote_reward_t_map_insert(vote_reward_map, *voter_acc);
        node->vote_rewards = 0;
        fd_memcpy(&node->vote_pubkey, voter_acc, sizeof(fd_pubkey_t));
        node->commission = (uchar)commission;
        node->needs_store = 0;
    }

    fd_calculated_stake_rewards_t redeemed[1] = {0};
    rc = stake_state_redeem_rewards(slot_ctx, stake_history, stake_acc, vote_state_versioned, rewarded_epoch, point_value, redeemed);
    if ( rc != 0) {
        fd_vote_state_versioned_destroy( vote_state_versioned, &destroy );
        FD_LOG_DEBUG(("stake_state::stake_state_redeem_rewards() failed for %32J with error %d", stake_acc->key, rc ));
        return;
    }

    fd_acc_lamports_t post_lamports = stake_acc_rec->const_meta->info.lamports;

    // track total_stake_rewards
    *total_stake_rewards += redeemed->staker_rewards;

    // add stake_reward to the collection
    fd_stake_reward_t stake_reward;
    fd_memcpy(&stake_reward.stake_pubkey, stake_acc, sizeof(fd_pubkey_t));

    stake_reward.reward_info = (fd_reward_info_t) {
        .reward_type = { .discriminant = fd_reward_type_enum_staking },
        .commission = (uchar)commission,
        .lamports = redeemed->staker_rewards,
        .new_credits_observed = redeemed->new_credits_observed,
        .staker_rewards = redeemed->staker_rewards,
        .post_balance = post_lamports
    };

    // FD_LOG_WARNING(("STAKE REWARD: %32J %lu", stake_acc->key, redeemed->staker_rewards));
    deq_fd_stake_reward_t_push_tail( stake_reward_deq, stake_reward );

    // track voter rewards
    node->vote_rewards = fd_ulong_sat_add(node->vote_rewards, redeemed->voter_rewards);
    node->needs_store = 1;

    fd_stake_state_v2_destroy( &stake_state, &destroy );
    fd_vote_state_versioned_destroy( vote_state_versioned, &destroy );
}

// return reward info for each vote account
// return account data for each vote account that needs to be stored
// This return value is a little awkward at the moment so that downstream existing code in the non-partitioned rewards code path can be re-used without duplication or modification.
// This function is copied from the existing code path's `store_vote_accounts`.
// The primary differences:
// - we want this fn to have no side effects (such as actually storing vote accounts) so that we
//   can compare the expected results with the current code path
// - we want to be able to batch store the vote accounts later for improved performance/cache updating

/*
Calculates epoch rewards for stake/vote accounts
Returns vote rewards, stake rewards, and the sum of all stake rewards in lamports
*/
static void
calculate_stake_vote_rewards(
    fd_exec_slot_ctx_t *                slot_ctx,
    fd_stake_history_t const *          stake_history,
    ulong                               rewarded_epoch,
    fd_point_value_t *                  point_value,
    fd_validator_reward_calculation_t * result
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L3062-L3192 */
    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    fd_acc_lamports_t total_stake_rewards = 0;
    fd_stake_reward_t * stake_reward_deq = deq_fd_stake_reward_t_alloc( slot_ctx->valloc );
    fd_vote_reward_t_mapnode_t * vote_reward_map = fd_vote_reward_t_map_alloc( slot_ctx->valloc, 24 );  /* 2^24 slots */

    for( fd_delegation_pair_t_mapnode_t const * n = fd_delegation_pair_t_map_minimum_const( epoch_bank->stakes.stake_delegations_pool, epoch_bank->stakes.stake_delegations_root );
         n;
         n = fd_delegation_pair_t_map_successor_const( epoch_bank->stakes.stake_delegations_pool, n )
    ) {
        // fd_pubkey_t const * voter_acc = &n->elem.delegation.voter_pubkey;
        fd_pubkey_t const * stake_acc = &n->elem.account;

        FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);
        if( 0!=fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, stake_acc_rec) ) {
            FD_LOG_DEBUG(("Stake acc not found %32J", stake_acc->uc));
            continue;
        }

        fd_stake_state_v2_t stake_state = {0};
        int rc = fd_stake_get_state(stake_acc_rec, &slot_ctx->valloc, &stake_state);
        if ( rc != 0 ) {
            FD_LOG_WARNING(("Failed to read stake state from stake account %32J", stake_acc));
            continue;
        }
        fd_pubkey_t const * voter_acc = &stake_state.inner.stake.stake.delegation.voter_pubkey;

        calculate_stake_vote_rewards_account( slot_ctx, stake_history, rewarded_epoch, point_value, voter_acc, stake_acc, stake_reward_deq, vote_reward_map, &total_stake_rewards );
    }

    for ( fd_stake_accounts_pair_t_mapnode_t const * n = fd_stake_accounts_pair_t_map_minimum_const( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root );
         n;
         n = fd_stake_accounts_pair_t_map_successor_const( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, n) ) {
        fd_pubkey_t const * stake_acc = &n->elem.key;
        FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);
        if( 0!=fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, stake_acc_rec) ) {
            FD_LOG_DEBUG(("Stake acc not found %32J", stake_acc->uc));
            continue;
        }

        if (stake_acc_rec->const_meta->info.lamports == 0) continue;

        fd_stake_state_v2_t stake_state = {0};
        int rc = fd_stake_get_state(stake_acc_rec, &slot_ctx->valloc, &stake_state);
        if ( rc != 0 ) {
            FD_LOG_WARNING(("Failed to read stake state from stake account %32J", stake_acc));
            continue;
        }
        fd_pubkey_t const * voter_acc = &stake_state.inner.stake.stake.delegation.voter_pubkey;
        calculate_stake_vote_rewards_account( slot_ctx, stake_history, rewarded_epoch, point_value, voter_acc, stake_acc, stake_reward_deq, vote_reward_map, &total_stake_rewards );

        fd_bincode_destroy_ctx_t destroy = {.valloc = slot_ctx->valloc};
        fd_stake_state_v2_destroy( &stake_state, &destroy );
    }

    // FD_LOG_WARNING(( "TSRL: %lu", total_stake_rewards ));

    *result = (fd_validator_reward_calculation_t) {
        .total_stake_rewards_lamports = total_stake_rewards,
        .stake_reward_deq = stake_reward_deq,
        .vote_reward_map = vote_reward_map
    };
}

/* Calculate epoch reward and return vote and stake rewards. */
static void
calculate_validator_rewards(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong rewarded_epoch,
    ulong rewards,
    fd_validator_reward_calculation_t * result
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L2759-L2786 */
    fd_stake_history_t const * stake_history = fd_sysvar_cache_stake_history( slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !stake_history ) ) FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));

    fd_point_value_t point_value_result[1] = {0};
    calculate_reward_points_partitioned(slot_ctx, stake_history, rewards, point_value_result);
    calculate_stake_vote_rewards(slot_ctx, stake_history, rewarded_epoch, point_value_result, result);
}


// Calculate the number of blocks required to distribute rewards to all stake accounts.
// fn get_reward_distribution_num_blocks(&self, rewards: &StakeRewards) -> u64 {
static ulong
get_reward_distribution_num_blocks(
    fd_epoch_schedule_t const * epoch_schedule,
    ulong slot,
    fd_stake_reward_t * stake_reward_deq
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L1250-L1267 */
    if (epoch_schedule->warmup && fd_slot_to_epoch(epoch_schedule, slot, NULL) < epoch_schedule->first_normal_epoch) {
        return 1;
    }
    ulong total_stake_accounts = deq_fd_stake_reward_t_cnt(stake_reward_deq);
    ulong num_chunks = total_stake_accounts / (ulong)STAKE_ACCOUNT_STORES_PER_BLOCK + (total_stake_accounts % STAKE_ACCOUNT_STORES_PER_BLOCK != 0);
    num_chunks = fd_ulong_max(num_chunks, 1);
    num_chunks = fd_ulong_min(
        fd_ulong_max(
            epoch_schedule->slots_per_epoch / (ulong)MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH,
            1),
        1);
    return num_chunks;
}

static void
hash_rewards_into_partitions(
    fd_slot_bank_t const * bank,
    fd_stake_reward_t * stake_reward_deq,
    ulong num_partitions,
    fd_stake_rewards_vector_t * result
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/epoch_rewards_hasher.rs#L43C31-L61 */
    fd_siphash13_t  _sip[1] = {0};
    fd_siphash13_t * hasher = fd_siphash13_init( _sip, 0UL, 0UL );
    hasher = fd_siphash13_append( hasher, bank->banks_hash.hash, sizeof(fd_hash_t));

    fd_stake_rewards_vector_new( result );
    for (ulong i = 0; i < num_partitions; ++i) {
        fd_stake_rewards_t new_partition;
        fd_stake_rewards_new(&new_partition);
        fd_stake_rewards_vector_push( result, new_partition);
    }
    for (
        deq_fd_stake_reward_t_iter_t iter = deq_fd_stake_reward_t_iter_init(stake_reward_deq );
        !deq_fd_stake_reward_t_iter_done( stake_reward_deq, iter );
        iter =  deq_fd_stake_reward_t_iter_next( stake_reward_deq, iter)
    ) {
        fd_stake_reward_t * ele =  deq_fd_stake_reward_t_iter_ele( stake_reward_deq, iter );
        /* hash_address_to_partition: find partition index (0..partitions) by hashing `address` with the `hasher` */
        fd_siphash13_append( hasher, (const uchar *) ele->stake_pubkey.key, sizeof(fd_pubkey_t));
        ulong hash64 = fd_siphash13_fini(hasher);
        /* hash_to_partition */
        ulong partition_index = (ulong)(
            (uint128) num_partitions *
            (uint128) hash64 /
            ((uint128)ULONG_MAX + 1)
        );
        fd_stake_rewards_push(&result->elems[partition_index], ele);
    }
}

// Calculate rewards from previous epoch to prepare for partitioned distribution.
static void
calculate_rewards_for_partitioning(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong prev_epoch,
    fd_partitioned_rewards_calculation_t * result
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L2356-L2403 */
    fd_prev_epoch_inflation_rewards_t rewards;
    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    fd_slot_bank_t const * slot_bank = &slot_ctx->slot_bank;
    calculate_previous_epoch_inflation_rewards( slot_ctx, epoch_bank, slot_bank->slot, slot_bank->capitalization, prev_epoch, &rewards );

    ulong old_vote_balance_and_staked = vote_balance_and_staked(slot_ctx, &epoch_bank->stakes);

    fd_validator_reward_calculation_t validator_result[1] = {0};
    calculate_validator_rewards(slot_ctx, prev_epoch, rewards.validator_rewards, validator_result);

    ulong num_partitions = get_reward_distribution_num_blocks(&epoch_bank->epoch_schedule, slot_bank->slot, validator_result->stake_reward_deq);

    fd_stake_rewards_vector_t * hash_rewards_result = malloc(sizeof(fd_stake_rewards_vector_t));
    hash_rewards_into_partitions(slot_bank, validator_result->stake_reward_deq, num_partitions, hash_rewards_result);

    /* free stake_reward_deq */
    deq_fd_stake_reward_t_delete( validator_result->stake_reward_deq );

    *result = (fd_partitioned_rewards_calculation_t) {
        .vote_account_rewards = validator_result->vote_reward_map,
        .stake_rewards_by_partition = hash_rewards_result,
        .total_stake_rewards_lamports = validator_result->total_stake_rewards_lamports,
        .old_vote_balance_and_staked = old_vote_balance_and_staked,
        .validator_rewards = rewards.validator_rewards,
        .validator_rate = rewards.validator_rate,
        .foundation_rate = rewards.foundation_rate,
        .prev_epoch_duration_in_years = rewards.prev_epoch_duration_in_years,
        .capitalization = slot_bank->capitalization
    };
}

/* (TODO) unclear if we need to implement update_reward_history function on solana side. So far it doesn't do much other than logging / record keeping */
/* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L3471-L3484 */
// static void
// update_reward_history(
// ) {
//     return;
// }

// Calculate rewards from previous epoch and distribute vote rewards
static void
calculate_rewards_and_distribute_vote_rewards(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong prev_epoch,
    fd_calculate_rewards_and_distribute_vote_rewards_result_t * result
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L2406-L2492 */
    fd_partitioned_rewards_calculation_t rewards_calc_result[1] = {0};
    calculate_rewards_for_partitioning(slot_ctx, prev_epoch, rewards_calc_result);
    fd_vote_reward_t_mapnode_t * ref = rewards_calc_result->vote_account_rewards;
    for (ulong i = 0; i < fd_vote_reward_t_map_slot_cnt( rewards_calc_result->vote_account_rewards); ++i) {
        if (fd_vote_reward_t_map_key_equal( ref[i].vote_pubkey, fd_vote_reward_t_map_key_null() ) ) {
            continue;
        }
        fd_pubkey_t const * vote_pubkey = &ref[i].vote_pubkey;
        ulong min_data_sz = 0UL;
        FD_BORROWED_ACCOUNT_DECL(vote_rec);
        int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, vote_pubkey, 1, min_data_sz, vote_rec);
        FD_TEST( err == 0 );
        vote_rec->meta->info.lamports = fd_ulong_sat_add(vote_rec->meta->info.lamports, ref[i].vote_rewards);
    }
    /* TODO: update_reward_history (not sure if reward history is ever needed?) */
    // update_reward_history();

    // This is for vote rewards only.
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    ulong new_vote_balance_and_staked = vote_balance_and_staked( slot_ctx, &epoch_bank->stakes );
    ulong validator_rewards_paid = fd_ulong_sat_sub(new_vote_balance_and_staked, rewards_calc_result->old_vote_balance_and_staked);

    // verify that we didn't pay any more than we expected to
    FD_TEST( rewards_calc_result->validator_rewards >= fd_ulong_sat_add(validator_rewards_paid, rewards_calc_result->total_stake_rewards_lamports));

    FD_LOG_NOTICE((
        "distributed vote rewards: %lu out of %lu, remaining %lu",
        validator_rewards_paid,
        rewards_calc_result->validator_rewards,
        rewards_calc_result->total_stake_rewards_lamports
    ));

    slot_ctx->slot_bank.capitalization += validator_rewards_paid;

    /*
    // only useful for logging
    ulong active_stake = 0;
    for ( fd_stake_history_epochentry_pair_t_mapnode_t * n = fd_stake_history_epochentry_pair_t_map_minimum( bank->stakes.stake_history.entries_pool, bank->stakes.stake_history.entries_root ); n; n = fd_stake_history_epochentry_pair_t_map_successor( bank->stakes.stake_history.entries_pool, n ) ) {
        if (bank->stakes.stake_history.entries_pool->elem.epoch == prev_epoch) {
            active_stake = bank->stakes.stake_history.entries_pool->elem.entry.effective;
            break;
        }
    }
    */
    /* free vote reward map */
    fd_vote_reward_t_map_delete( rewards_calc_result->vote_account_rewards );

    result->total_rewards = fd_ulong_sat_add(validator_rewards_paid,  rewards_calc_result->total_stake_rewards_lamports);
    result->distributed_rewards = validator_rewards_paid;
    result->stake_rewards_by_partition = rewards_calc_result->stake_rewards_by_partition;
}

static void
bank_redeem_rewards(
    fd_exec_slot_ctx_t *                slot_ctx,
    ulong                               rewarded_epoch,
    fd_point_value_t *                  point_value,
    fd_stake_history_t const *          stake_history,
    fd_validator_reward_calculation_t * result
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L3194-L3288 */
    /* the current implement relies on partitioned version with no thread pool*/
    calculate_stake_vote_rewards( slot_ctx, stake_history, rewarded_epoch, point_value, result );
}

static void
calculate_reward_points(
    fd_exec_slot_ctx_t *       slot_ctx,
    fd_stake_history_t const * stake_history,
    ulong                      rewards,
    fd_point_value_t *         result
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L3020-L3058 */
    /* the current implement relies on partitioned version with no thread pool*/
    calculate_reward_points_partitioned( slot_ctx, stake_history, rewards, result );
}

// pay_validator_rewards_with_thread_pool
/* Load, calculate and payout epoch rewards for stake and vote accounts */
static void
pay_validator_rewards(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong rewarded_epoch,
    ulong rewards
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L2789-L2839 */
    fd_stake_history_t const * stake_history = fd_sysvar_cache_stake_history( slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !stake_history ) ) FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));
    fd_point_value_t point_value_result[1] = {{0}};
    calculate_reward_points(slot_ctx, stake_history, rewards, point_value_result);
    fd_validator_reward_calculation_t rewards_calc_result[1] = {0};
    bank_redeem_rewards( slot_ctx, rewarded_epoch, point_value_result, stake_history, rewards_calc_result );

    ulong validator_rewards_paid = 0;

    /* store vote accounts */
    fd_vote_reward_t_mapnode_t * ref = rewards_calc_result->vote_reward_map;
    FD_LOG_DEBUG(("Num vote rewards %lu", fd_vote_reward_t_map_key_cnt( rewards_calc_result->vote_reward_map)));
    for (ulong i = 0; i < fd_vote_reward_t_map_slot_cnt( rewards_calc_result->vote_reward_map); ++i) {
        if (fd_vote_reward_t_map_key_equal( ref[i].vote_pubkey, fd_vote_reward_t_map_key_null() ) ) {
            continue;
        }
        fd_pubkey_t const * vote_pubkey = &ref[i].vote_pubkey;
        if (ref[i].vote_rewards == 0 && !ref[i].needs_store) {
            continue;
        }
        FD_LOG_DEBUG(("Vote reward for %32J %lu", vote_pubkey->uc, ref[i].vote_rewards));
        ulong min_data_sz = 0UL;
        FD_BORROWED_ACCOUNT_DECL(vote_rec);
        int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, vote_pubkey, 1, min_data_sz, vote_rec);
        FD_TEST( err == 0 );
        vote_rec->meta->info.lamports = fd_ulong_sat_add(vote_rec->meta->info.lamports, ref[i].vote_rewards);
        vote_rec->meta->slot = slot_ctx->slot_bank.slot;
        validator_rewards_paid = fd_ulong_sat_add(validator_rewards_paid, ref[i].vote_rewards);
    }

    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    FD_LOG_DEBUG(("Num stake rewards %lu", deq_fd_stake_reward_t_cnt( rewards_calc_result->stake_reward_deq )));
    /* store stake accounts */
    for (
        deq_fd_stake_reward_t_iter_t iter = deq_fd_stake_reward_t_iter_init(rewards_calc_result->stake_reward_deq );
        !deq_fd_stake_reward_t_iter_done( rewards_calc_result->stake_reward_deq, iter );
        iter =  deq_fd_stake_reward_t_iter_next( rewards_calc_result->stake_reward_deq, iter)
    ) {
        fd_stake_reward_t * ele =  deq_fd_stake_reward_t_iter_ele( rewards_calc_result->stake_reward_deq, iter );
        fd_pubkey_t const * stake_pubkey = &ele->stake_pubkey;

        ulong min_data_sz = 0UL;
        FD_BORROWED_ACCOUNT_DECL(stake_rec);
        int err = fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_pubkey, 1, min_data_sz, stake_rec);
        FD_TEST( err == 0 );
        FD_LOG_DEBUG(("Stake reward for %32J Existing %lu reward lamps %lu staker reward %lu credits observed %lu", stake_pubkey->uc, stake_rec->meta->info.lamports, ele->reward_info.lamports, ele->reward_info.staker_rewards, ele->reward_info.new_credits_observed));
        stake_rec->meta->info.lamports = fd_ulong_sat_add(stake_rec->meta->info.lamports, ele->reward_info.lamports);
        stake_rec->meta->slot = slot_ctx->slot_bank.slot;
        validator_rewards_paid = fd_ulong_sat_add(validator_rewards_paid, ele->reward_info.lamports);

        fd_stake_state_v2_t stake_state;
        int rc = fd_stake_get_state(stake_rec, &slot_ctx->valloc, &stake_state);
        if ( rc != 0 ) {
            FD_LOG_ERR(("failed to read stake state for %32J", stake_pubkey ));
        }

        /* implements the `redeem_stake_rewards` solana function */
        stake_state.inner.stake.stake.credits_observed = ele->reward_info.new_credits_observed;
        stake_state.inner.stake.stake.delegation.stake += ele->reward_info.staker_rewards;
        fd_delegation_pair_t_mapnode_t query_node;
        fd_memcpy(&query_node.elem.account, stake_pubkey, sizeof(fd_pubkey_t));
        fd_delegation_pair_t_mapnode_t * node = fd_delegation_pair_t_map_find(epoch_bank->stakes.stake_delegations_pool, epoch_bank->stakes.stake_delegations_root, &query_node);
        if (node != NULL) {
            node->elem.delegation.stake += ele->reward_info.staker_rewards;
        }

        /* write_stake_state */
        err = write_stake_state( slot_ctx, stake_pubkey, &stake_state, 0);
        FD_TEST( err == 0 );
    }

    // FD_LOG_WARNING(("REWARDS PAID: %lu POST_CAP: %lu", validator_rewards_paid, slot_ctx->slot_bank.capitalization ));
    slot_ctx->slot_bank.capitalization = fd_ulong_sat_add(slot_ctx->slot_bank.capitalization, validator_rewards_paid);

    /* free stake_reward_deq and vote_reward_map */
    fd_valloc_free(slot_ctx->valloc, deq_fd_stake_reward_t_delete( deq_fd_stake_reward_t_leave( rewards_calc_result->stake_reward_deq ) ) );
    fd_valloc_free(slot_ctx->valloc, fd_vote_reward_t_map_delete( fd_vote_reward_t_map_leave( rewards_calc_result->vote_reward_map ) ) );

    // self.update_reward_history(stake_rewards, vote_rewards);
}

// update rewards based on the previous epoch
// non thread pool version below
void
update_rewards(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong prev_epoch
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L2515-L2599 */
    /* calculate_previous_epoch_inflation_rewards */
    fd_prev_epoch_inflation_rewards_t rewards;
    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    fd_slot_bank_t * slot_bank = &slot_ctx->slot_bank;
    calculate_previous_epoch_inflation_rewards( slot_ctx, epoch_bank, slot_bank->slot, slot_bank->capitalization, prev_epoch, &rewards);
    /* pay_validator_rewards_with_thread_pool */
    pay_validator_rewards(slot_ctx, prev_epoch, rewards.validator_rewards);
}

// begin_partitioned_rewards
/* Begin the process of calculating and distributing rewards. This process can take multiple slots. */

// https://github.com/anza-xyz/agave/blob/2d722719a2c74ec4e180b255124c7204ef98ee6c/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L35
void
begin_partitioned_rewards(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong parent_epoch
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L1613-L1651 */
    fd_calculate_rewards_and_distribute_vote_rewards_result_t rewards_result[1] = {0};
    calculate_rewards_and_distribute_vote_rewards(
        slot_ctx,
        parent_epoch,
        rewards_result
    );
    ulong credit_end_exclusive = slot_ctx->slot_bank.block_height + REWARD_CALCULATION_NUM_BLOCK + rewards_result->stake_rewards_by_partition->cnt;
    FD_LOG_DEBUG(("self->block_height=%lu, rewards_result->stake_rewards_by_parrition->cnt=%lu", slot_ctx->slot_bank.block_height, rewards_result->stake_rewards_by_partition->cnt));

    // self.set_epoch_reward_status_active(stake_rewards_by_partition);
    slot_ctx->epoch_reward_status = (fd_epoch_reward_status_t){
        .is_active = 1,
        .stake_rewards_by_partition = rewards_result->stake_rewards_by_partition,
        .start_block_height = slot_ctx->slot_bank.block_height
    };
    // create EpochRewards sysvar that holds the balance of undistributed rewards with
    // (total_rewards, distributed_rewards, credit_end_exclusive), total capital will increase by (total_rewards - distributed_rewards)
    fd_sysvar_epoch_rewards_init( slot_ctx, rewards_result->total_rewards, rewards_result->distributed_rewards, credit_end_exclusive);
}

/* Process reward distribution for the block if it is inside reward interval. */
void
distribute_partitioned_epoch_rewards(
    fd_exec_slot_ctx_t * slot_ctx
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L1654-L1687 */
    /* make sure we are inside the reward interval */
    if ( !slot_ctx->epoch_reward_status.is_active ) {
        return;
    }

    ulong validator_rewards_paid = 0;

    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    fd_slot_bank_t * slot_bank = &slot_ctx->slot_bank;

    ulong credit_start = slot_ctx->epoch_reward_status.start_block_height + REWARD_CALCULATION_NUM_BLOCK;
    ulong credit_end_exclusive = credit_start + slot_ctx->epoch_reward_status.stake_rewards_by_partition->cnt;
    if (slot_bank->block_height >= credit_start && slot_bank->block_height < credit_end_exclusive) {
        ulong partition_index = slot_bank->block_height - credit_start;
        ulong total_rewards_in_lamports = 0UL;
        fd_stake_rewards_t this_partition_stake_rewards = slot_ctx->epoch_reward_status.stake_rewards_by_partition->elems[partition_index];
        for (uint i = 0; i < this_partition_stake_rewards.cnt; ++i) {
            total_rewards_in_lamports = fd_ulong_sat_add(total_rewards_in_lamports, this_partition_stake_rewards.elems[i]->reward_info.lamports);
            // store rewards into accounts
            fd_pubkey_t const * stake_acc = &this_partition_stake_rewards.elems[i]->stake_pubkey;
            FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);
            FD_TEST( 0==fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, 0, 0UL, stake_acc_rec ) );
            stake_acc_rec->meta->info.lamports += this_partition_stake_rewards.elems[i]->reward_info.lamports;
            validator_rewards_paid = fd_ulong_sat_add(validator_rewards_paid, this_partition_stake_rewards.elems[i]->reward_info.lamports);

            fd_stake_state_v2_t stake_state = {0};
            int rc = fd_stake_get_state(stake_acc_rec, &slot_ctx->valloc, &stake_state);
            if ( rc != 0 ) {
               FD_LOG_ERR(("failed to read stake state for %32J", &this_partition_stake_rewards.elems[i]->stake_pubkey ));
            }
            // fd_stake_state_t stake_state;
            // read_stake_state( global, stake_acc_rec->meta, &stake_state );
            // if (!fd_stake_state_is_stake( &stake_state)) {
            //    FD_LOG_ERR(("failed to read stake state for %32J", &this_partition_stake_rewards.elems[i]->stake_pubkey ));
            // }

            /* implements the `redeem_stake_rewards` solana function */
            stake_state.inner.stake.stake.credits_observed = this_partition_stake_rewards.elems[i]->reward_info.new_credits_observed;
            stake_state.inner.stake.stake.delegation.stake += this_partition_stake_rewards.elems[i]->reward_info.staker_rewards;
            fd_delegation_pair_t_mapnode_t query_node;
            fd_memcpy(&query_node.elem.account, stake_acc, sizeof(fd_pubkey_t));
            fd_delegation_pair_t_mapnode_t * node = fd_delegation_pair_t_map_find(epoch_bank->stakes.stake_delegations_pool, epoch_bank->stakes.stake_delegations_root, &query_node);
            if (node != NULL) {
                node->elem.delegation.stake += this_partition_stake_rewards.elems[i]->reward_info.staker_rewards;
            }

            /* write_stake_state */
            int err = write_stake_state( slot_ctx, stake_acc, &stake_state, 0);
            FD_TEST( err == 0 );

        }

        // increase total capitalization by the distributed rewards
        slot_bank->capitalization = fd_ulong_sat_add(slot_bank->capitalization, total_rewards_in_lamports);

        // decrease distributed capital from epoch rewards sysvar
        fd_sysvar_epoch_rewards_update( slot_ctx, total_rewards_in_lamports );

        // update reward history for this partitioned distribution
        // self.update_reward_history_in_partition(this_partition_stake_rewards);
    }

    if ( fd_ulong_sat_add(slot_bank->block_height, 1) >= credit_end_exclusive ) {
        // deactivate epoch reward status
        slot_ctx->epoch_reward_status.is_active = 0;
        // burn and purge EpochRewards sysvar account
        fd_sysvar_epoch_rewards_burn_and_purge( slot_ctx );
        // fixing leaks
        for ( ulong i = 0; i < slot_ctx->epoch_reward_status.stake_rewards_by_partition->cnt; ++i ) {
            fd_stake_rewards_destroy( &slot_ctx->epoch_reward_status.stake_rewards_by_partition->elems[i] );
        }
        fd_stake_rewards_vector_destroy(slot_ctx->epoch_reward_status.stake_rewards_by_partition);
        fd_valloc_free( slot_ctx->valloc, slot_ctx->epoch_reward_status.stake_rewards_by_partition );
    }

    slot_ctx->slot_bank.capitalization = fd_ulong_sat_add(slot_ctx->slot_bank.capitalization, validator_rewards_paid);
}

void
calculate_inflation_rates( fd_exec_slot_ctx_t * slot_ctx, fd_inflation_rates_t * rates ) {
  fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  ulong slot_idx = 0;
  rates->epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot, &slot_idx );
  ulong num_slots = get_inflation_num_slots( slot_ctx, &epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot );
  double slot_in_year = (double)num_slots / epoch_bank->slots_per_year;
  rates->validator = validator( &epoch_bank->inflation, slot_in_year );
  rates->foundation = foundation(&epoch_bank->inflation, slot_in_year);
  rates->total = total(&epoch_bank->inflation, slot_in_year);
}
