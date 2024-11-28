#include "fd_rewards.h"
#include <math.h>

#include "../runtime/fd_executor_err.h"
#include "../runtime/fd_system_ids.h"
#include "../runtime/context/fd_exec_epoch_ctx.h"
#include "../runtime/context/fd_exec_slot_ctx.h"
#include "../../ballet/siphash13/fd_siphash13.h"
#include "../runtime/program/fd_program_util.h"

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/sdk/program/src/native_token.rs#L6 */
#define LAMPORTS_PER_SOL   ( 1000000000UL )

/* Number of blocks for reward calculation and storing vote accounts.
   Distributing rewards to stake accounts begins AFTER this many blocks.
   
   https://github.com/anza-xyz/agave/blob/9a7bf72940f4b3cd7fc94f54e005868ce707d53d/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L27 */
#define REWARD_CALCULATION_NUM_BLOCKS ( 1UL )

/* stake accounts to store in one block during partitioned reward interval. Target to store 64 rewards per entry/tick in a block. A block has a minimum of 64 entries/tick. This gives 4096 total rewards to store in one block. */
#define STAKE_ACCOUNT_STORES_PER_BLOCK          ( 4096UL )

/* https://github.com/anza-xyz/agave/blob/2316fea4c0852e59c071f72d72db020017ffd7d0/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L219 */
#define MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH    ( 10UL ) 

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/sdk/src/inflation.rs#L85 */
static double
total( fd_inflation_t const * inflation, double year ) {
    if ( FD_UNLIKELY( year == 0.0 ) ) {
        FD_LOG_ERR(( "inflation year 0" ));
    }
    double tapered = inflation->initial * pow((1.0 - inflation->taper), year);
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
get_inflation_start_slot( fd_exec_slot_ctx_t * slot_ctx ) {
    ulong devnet_and_testnet = FD_FEATURE_ACTIVE(slot_ctx, devnet_and_testnet) ? slot_ctx->epoch_ctx->features.devnet_and_testnet : ULONG_MAX;

    ulong enable = ULONG_MAX;
    if ( FD_FEATURE_ACTIVE( slot_ctx, full_inflation_vote ) && FD_FEATURE_ACTIVE(slot_ctx, full_inflation_enable ) ) {
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

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank.rs#L2110 */
static ulong
get_inflation_num_slots( fd_exec_slot_ctx_t * slot_ctx,
                         fd_epoch_schedule_t const * epoch_schedule,
                         ulong slot ) {
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

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank.rs#L2121 */
static double
slot_in_year_for_inflation( fd_exec_slot_ctx_t * slot_ctx ) {
    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    ulong num_slots = get_inflation_num_slots( slot_ctx, &epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot );
    return (double)num_slots / (double)epoch_bank->slots_per_year;
}

/* For a given stake and vote_state, calculate how many points were earned (credits * stake) and new value
   for credits_observed were the points paid
    
    https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L109 */
static void
calculate_stake_points_and_credits (
  fd_stake_history_t const *     stake_history,
  fd_stake_t *                   stake,
  fd_vote_state_versioned_t *    vote_state_versioned,
  fd_calculated_stake_points_t * result
) {

    ulong credits_in_stake = stake->credits_observed;
    
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
            FD_LOG_ERR(( "invalid vote account, should never happen" ));
    }
    ulong credits_in_vote = 0UL;
    if ( FD_LIKELY( !deq_fd_vote_epoch_credits_t_empty( epoch_credits ) ) ) {
        credits_in_vote = deq_fd_vote_epoch_credits_t_peek_tail_const( epoch_credits )->credits;
    }

    /* If the Vote account has less credits observed than the Stake account,
       something is wrong and we need to force an update.
       
       https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L142 */
    if ( FD_UNLIKELY( credits_in_vote < credits_in_stake ) ) {
        result->points = 0;
        result->new_credits_observed = credits_in_vote;
        result->force_credits_update_with_skipped_reward = 1;
        return;
    }

    /* If the Vote account has the same amount of credits observed as the Stake account,
       then the Vote account hasn't earnt any credits and so there is nothing to update.
       
       https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L148 */
    if ( FD_UNLIKELY( credits_in_vote == credits_in_stake ) ) {
        result->points = 0;
        result->new_credits_observed = credits_in_vote;
        result->force_credits_update_with_skipped_reward = 0;
        return;
    }

    /* Calculate the points for each epoch credit */
    uint128 points = 0;
    ulong new_credits_observed = credits_in_stake;
    for ( deq_fd_vote_epoch_credits_t_iter_t iter = deq_fd_vote_epoch_credits_t_iter_init( epoch_credits );
          !deq_fd_vote_epoch_credits_t_iter_done( epoch_credits, iter );
          iter = deq_fd_vote_epoch_credits_t_iter_next( epoch_credits, iter ) ) {

        fd_vote_epoch_credits_t * ele = deq_fd_vote_epoch_credits_t_iter_ele( epoch_credits, iter );
        ulong final_epoch_credits = ele->credits;
        ulong initial_epoch_credits = ele->prev_credits;
        uint128 earned_credits = 0;
        if ( FD_LIKELY( credits_in_stake < initial_epoch_credits ) ) {
            earned_credits = (uint128)(final_epoch_credits - initial_epoch_credits);
        } else if ( FD_UNLIKELY( credits_in_stake < final_epoch_credits ) ) {
            earned_credits = (uint128)(final_epoch_credits - new_credits_observed);
        }

        new_credits_observed = fd_ulong_max( new_credits_observed, final_epoch_credits );

        ulong stake_amount = fd_stake_activating_and_deactivating( &stake->delegation, ele->epoch, stake_history, NULL ).effective;

        points += (uint128)stake_amount * earned_credits;
    }

    result->points = points;
    result->new_credits_observed = new_credits_observed;
    result->force_credits_update_with_skipped_reward = 0;
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/rewards.rs#L127 */
static int
calculate_stake_rewards(
  fd_stake_history_t const *      stake_history,
  fd_stake_state_v2_t *           stake_state,
  fd_vote_state_versioned_t *     vote_state_versioned,
  ulong                           rewarded_epoch,
  fd_point_value_t *              point_value,
  fd_calculated_stake_rewards_t * result
) {
    fd_calculated_stake_points_t stake_points_result = {0};
    calculate_stake_points_and_credits( stake_history, &stake_state->inner.stake.stake, vote_state_versioned, &stake_points_result);

    // Drive credits_observed forward unconditionally when rewards are disabled
    // or when this is the stake's activation epoch
    if ( ( point_value->rewards == 0 ) ||
         ( stake_state->inner.stake.stake.delegation.activation_epoch == rewarded_epoch ) ) {
        stake_points_result.force_credits_update_with_skipped_reward |= 1;
    }

    if (stake_points_result.force_credits_update_with_skipped_reward) {
        result->staker_rewards = 0;
        result->voter_rewards = 0;
        result->new_credits_observed = stake_points_result.new_credits_observed;
        return 0;
    }
    if ( stake_points_result.points == 0 || point_value->points == 0 ) {
        return 1;
    }

    /* FIXME: need to error out if the conversion from uint128 to u64 fails, also use 128 checked mul and div */
    ulong rewards = (ulong)(stake_points_result.points * (uint128)(point_value->rewards) / (uint128) point_value->points);
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
    return 0;
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/rewards.rs#L33 */
static int
redeem_rewards( fd_stake_history_t const *      stake_history,
                fd_stake_state_v2_t *           stake_state,
                fd_vote_state_versioned_t *     vote_state_versioned,
                ulong                           rewarded_epoch,
                fd_point_value_t *              point_value,
                fd_calculated_stake_rewards_t * calculated_stake_rewards) {

    int rc = calculate_stake_rewards( stake_history, stake_state, vote_state_versioned, rewarded_epoch, point_value, calculated_stake_rewards );
    if ( FD_UNLIKELY( rc != 0 ) ) {
        return rc;
    }

    return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L70 */
int
calculate_points(
    fd_stake_state_v2_t *       stake_state,
    fd_vote_state_versioned_t * vote_state_versioned,
    fd_stake_history_t const *  stake_history,
    uint128 *                   result
) {
    if ( FD_UNLIKELY( !fd_stake_state_v2_is_stake( stake_state ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    fd_calculated_stake_points_t stake_point_result;
    calculate_stake_points_and_credits( stake_history, &stake_state->inner.stake.stake, vote_state_versioned, &stake_point_result );
    *result = stake_point_result.points;

    return FD_EXECUTOR_INSTR_SUCCESS;
}

/* Returns the length of the given epoch in slots

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/sdk/program/src/epoch_schedule.rs#L103 */
static ulong
get_slots_in_epoch(
    ulong epoch,
    fd_epoch_bank_t const * epoch_bank
) {
    return (epoch < epoch_bank->epoch_schedule.first_normal_epoch) ?
        1UL << fd_ulong_sat_add(epoch, FD_EPOCH_LEN_MIN_TRAILING_ZERO) :
        epoch_bank->epoch_schedule.slots_per_epoch;
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank.rs#L2082 */
static double
epoch_duration_in_years(
    fd_epoch_bank_t const * epoch_bank,
    ulong prev_epoch
) {
    ulong slots_in_epoch = get_slots_in_epoch( prev_epoch, epoch_bank );
    return (double)slots_in_epoch / (double) epoch_bank->slots_per_year;
}

/* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank.rs#L2128 */
static void
calculate_previous_epoch_inflation_rewards(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong prev_epoch_capitalization,
    ulong prev_epoch,
    fd_prev_epoch_inflation_rewards_t * rewards
) {
    double slot_in_year = slot_in_year_for_inflation( slot_ctx );

    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    rewards->validator_rate = validator( &epoch_bank->inflation, slot_in_year );
    rewards->foundation_rate = foundation( &epoch_bank->inflation, slot_in_year );
    rewards->prev_epoch_duration_in_years = epoch_duration_in_years(epoch_bank, prev_epoch);
    rewards->validator_rewards = (ulong)(rewards->validator_rate * (double)prev_epoch_capitalization * rewards->prev_epoch_duration_in_years);
    FD_LOG_DEBUG(("Rewards %lu, Rate %.16f, Duration %.18f Capitalization %lu Slot in year %.16f", rewards->validator_rewards, rewards->validator_rate, rewards->prev_epoch_duration_in_years, prev_epoch_capitalization, slot_in_year));
}

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/lib.rs#L29 */
static ulong
get_minimum_stake_delegation( fd_exec_slot_ctx_t * slot_ctx ) {
    if ( !FD_FEATURE_ACTIVE( slot_ctx, stake_minimum_delegation_for_rewards ) ) {
        return 0UL;
    }

    if ( !FD_FEATURE_ACTIVE( slot_ctx, stake_raise_minimum_delegation_to_1_sol ) ) {
        return LAMPORTS_PER_SOL;
    }

    return 1;
}

/* Calculates epoch reward points from stake/vote accounts. 

    https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L472 */
static void
calculate_reward_points_partitioned(
    fd_exec_slot_ctx_t *       slot_ctx,
    fd_stake_history_t const * stake_history,
    ulong                      rewards,
    fd_point_value_t *         result
) {
    /* There is a cache of vote account keys stored in the slot context */
    /* TODO: check this cache is correct */

    uint128 points = 0;
    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );

    ulong minimum_stake_delegation = get_minimum_stake_delegation( slot_ctx );

    /* Calculate the points for each stake delegation */
    for( fd_delegation_pair_t_mapnode_t const * n = fd_delegation_pair_t_map_minimum_const( epoch_bank->stakes.stake_delegations_pool, epoch_bank->stakes.stake_delegations_root );
         n;
         n = fd_delegation_pair_t_map_successor_const( epoch_bank->stakes.stake_delegations_pool, n )
    ) {
        FD_SCRATCH_SCOPE_BEGIN {
            fd_valloc_t valloc = fd_scratch_virtual();

            /* Fetch the stake account */
            FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);
            fd_pubkey_t const * stake_acc = &n->elem.account;
            int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, stake_acc_rec);
            if ( err != FD_ACC_MGR_SUCCESS && err != FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
                FD_LOG_ERR(( "failed to read stake account from funk" ));
                continue;
            }
            if ( err == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
                FD_LOG_DEBUG(( "stake account not found %s", FD_BASE58_ENC_32_ALLOCA( stake_acc->uc ) ));
                continue;
            }
            if ( stake_acc_rec->const_meta->info.lamports == 0 ) {
                FD_LOG_DEBUG(( "stake acc with zero lamports %s", FD_BASE58_ENC_32_ALLOCA( stake_acc->uc ) ));
                continue;
            }

            /* Check the minimum stake delegation */
            fd_stake_state_v2_t stake_state[1] = {0};
            err = fd_stake_get_state( stake_acc_rec, &valloc, stake_state );
            if ( err != 0 ) {
                FD_LOG_DEBUG(( "get stake state failed" ));
                continue;
            }
            if ( FD_UNLIKELY( stake_state->inner.stake.stake.delegation.stake < minimum_stake_delegation ) ) {
                continue;
            }

            /* Check that the vote account is present in our cache */
            fd_vote_accounts_pair_t_mapnode_t key;
            fd_pubkey_t const * voter_acc = &n->elem.delegation.voter_pubkey;
            fd_memcpy( &key.elem.key, voter_acc, sizeof(fd_pubkey_t) );
            fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( 
                slot_ctx->epoch_ctx );
            if ( FD_UNLIKELY( fd_vote_accounts_pair_t_map_find( 
                epoch_bank->stakes.vote_accounts.vote_accounts_pool,
                epoch_bank->stakes.vote_accounts.vote_accounts_root,
                &key ) == NULL ) ) {
                FD_LOG_DEBUG(( "vote account missing from cache" ));
                continue;
            }

            /* Check that the vote account is valid and has the correct owner */
            FD_BORROWED_ACCOUNT_DECL(voter_acc_rec);
            err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, voter_acc, voter_acc_rec );
            if ( FD_UNLIKELY( err ) ) {
                FD_LOG_DEBUG(( "failed to read vote account from funk" ));
                continue;
            }
            if( FD_UNLIKELY( memcmp( &voter_acc_rec->const_meta->info.owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) != 0 ) ) {
                FD_LOG_DEBUG(( "vote account has wrong owner" ));
                continue;
            }
            fd_bincode_decode_ctx_t decode = {
                .data    = voter_acc_rec->const_data,
                .dataend = voter_acc_rec->const_data + voter_acc_rec->const_meta->dlen,
                .valloc  = valloc,
            };
            fd_vote_state_versioned_t vote_state[1] = {0};
            if( FD_UNLIKELY( 0!=fd_vote_state_versioned_decode( vote_state, &decode ) ) ) {
                FD_LOG_DEBUG(( "vote_state_versioned_decode failed" ));
                continue;
            }

            uint128 account_points;
            err = calculate_points( stake_state, vote_state, stake_history, &account_points );
            if ( FD_UNLIKELY( err ) ) {
                FD_LOG_DEBUG(( "failed to calculate points" ));
                continue;
            }

            points += account_points;
        } FD_SCRATCH_SCOPE_END;
    }

    /* TODO: factor this out */
    /* Calculate points for each stake account in slot_bank.stake_account_keys.stake_accounts_pool */
    for ( fd_stake_accounts_pair_t_mapnode_t const * n = fd_stake_accounts_pair_t_map_minimum_const( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root );
          n;
          n = fd_stake_accounts_pair_t_map_successor_const( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, n ) ) {

        FD_SCRATCH_SCOPE_BEGIN {
            fd_valloc_t valloc = fd_scratch_virtual();

            /* Fetch the stake account */
            FD_BORROWED_ACCOUNT_DECL(stake_acc_rec);
            fd_pubkey_t const * stake_acc = &n->elem.key;
            int err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, stake_acc_rec);
            if ( err != FD_ACC_MGR_SUCCESS && err != FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
                FD_LOG_ERR(( "failed to read stake account from funk" ));
            }
            if ( err == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
                FD_LOG_DEBUG(( "stake account not found %s", FD_BASE58_ENC_32_ALLOCA( stake_acc->uc ) ));
                continue;
            }
            if ( stake_acc_rec->const_meta->info.lamports == 0 ) {
                FD_LOG_DEBUG(( "stake acc with zero lamports %s", FD_BASE58_ENC_32_ALLOCA( stake_acc->uc ) ));
                continue;
            }

            /* Check the minimum stake delegation */
            fd_stake_state_v2_t stake_state[1] = {0};
            err = fd_stake_get_state( stake_acc_rec, &valloc, stake_state );
            if ( err != 0 ) {
                FD_LOG_DEBUG(( "get stake state failed" ));
                continue;
            }
            if ( FD_UNLIKELY( stake_state->inner.stake.stake.delegation.stake < minimum_stake_delegation ) ) {
                continue;
            }

            /* Check that the vote account is present in our cache */
            fd_vote_accounts_pair_t_mapnode_t key;
            fd_pubkey_t const * voter_acc = &stake_state->inner.stake.stake.delegation.voter_pubkey;
            fd_memcpy( &key.elem.key, voter_acc, sizeof(fd_pubkey_t) );
            fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( 
                slot_ctx->epoch_ctx );
            if ( FD_UNLIKELY( fd_vote_accounts_pair_t_map_find( 
                epoch_bank->stakes.vote_accounts.vote_accounts_pool,
                epoch_bank->stakes.vote_accounts.vote_accounts_root,
                &key ) == NULL ) ) {
                FD_LOG_DEBUG(( "vote account missing from cache" ));
                continue;
            }

            /* Check that the vote account is valid and has the correct owner */
            FD_BORROWED_ACCOUNT_DECL(voter_acc_rec);
            err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, voter_acc, voter_acc_rec );
            if ( FD_UNLIKELY( err ) ) {
                FD_LOG_DEBUG(( "failed to read vote account from funk" ));
                continue;
            }
            if( FD_UNLIKELY( memcmp( &voter_acc_rec->const_meta->info.owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) != 0 ) ) {
                FD_LOG_DEBUG(( "vote account has wrong owner" ));
                continue;
            }
            fd_bincode_decode_ctx_t decode = {
                .data    = voter_acc_rec->const_data,
                .dataend = voter_acc_rec->const_data + voter_acc_rec->const_meta->dlen,
                .valloc  = valloc,
            };
            fd_vote_state_versioned_t vote_state[1] = {0};
            if( FD_UNLIKELY( 0!=fd_vote_state_versioned_decode( vote_state, &decode ) ) ) {
                FD_LOG_DEBUG(( "vote_state_versioned_decode failed" ));
                continue;
            }

            uint128 account_points;
            err = calculate_points( stake_state, vote_state, stake_history, &account_points );
            if ( FD_UNLIKELY( err ) ) {
                FD_LOG_DEBUG(( "failed to calculate points" ));
                continue;
            }

            points += account_points;
        } FD_SCRATCH_SCOPE_END;
    }

    if (points > 0) {
        result->points = points;
        result->rewards = rewards;
    }
}

/* Calculate the partitioned stake rewards for a single stake/vote account pair, updates result with these. */
static void
calculate_stake_vote_rewards_account(
    fd_exec_slot_ctx_t *                        slot_ctx,
    fd_stake_history_t const *                  stake_history,
    ulong                                       rewarded_epoch,
    fd_point_value_t *                          point_value,
    fd_pubkey_t const *                         stake_acc,
    fd_calculate_stake_vote_rewards_result_t *  result
) {
    FD_SCRATCH_SCOPE_BEGIN {

        fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
        ulong minimum_stake_delegation = get_minimum_stake_delegation( slot_ctx );

        FD_BORROWED_ACCOUNT_DECL( stake_acc_rec );
        if( fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_acc, stake_acc_rec) != 0 ) {
            FD_LOG_DEBUG(( "Stake acc not found %s", FD_BASE58_ENC_32_ALLOCA( stake_acc->uc ) ));
            return;
        }

        fd_stake_state_v2_t stake_state[1] = {0};
        if ( fd_stake_get_state( stake_acc_rec, &slot_ctx->valloc, stake_state ) != 0 ) {
            FD_LOG_DEBUG(( "Failed to read stake state from stake account %s", FD_BASE58_ENC_32_ALLOCA( stake_acc ) ));
            return;
        }
        if ( !fd_stake_state_v2_is_stake( stake_state ) ) {
            FD_LOG_DEBUG(( "stake account does not have active delegation" ));
            return;
        }
        fd_pubkey_t const * voter_acc = &stake_state->inner.stake.stake.delegation.voter_pubkey;

        if ( FD_FEATURE_ACTIVE(slot_ctx, stake_minimum_delegation_for_rewards )) {
            if ( stake_state->inner.stake.stake.delegation.stake < minimum_stake_delegation ) {
                return;
            }
        }

        fd_vote_accounts_pair_t_mapnode_t key;
        fd_memcpy( &key.elem.key, voter_acc, sizeof(fd_pubkey_t) );
        if ( fd_vote_accounts_pair_t_map_find( epoch_bank->stakes.vote_accounts.vote_accounts_pool, epoch_bank->stakes.vote_accounts.vote_accounts_root, &key ) == NULL
            && fd_vote_accounts_pair_t_map_find( slot_ctx->slot_bank.vote_account_keys.vote_accounts_pool, slot_ctx->slot_bank.vote_account_keys.vote_accounts_root, &key ) == NULL) {
        return;
        }

        FD_BORROWED_ACCOUNT_DECL( voter_acc_rec );
        int read_err = fd_acc_mgr_view( slot_ctx->acc_mgr, slot_ctx->funk_txn, voter_acc, voter_acc_rec );
        if( read_err!=0 || memcmp( &voter_acc_rec->const_meta->info.owner, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) != 0 ) {
        return;
        }

        fd_valloc_t valloc = fd_scratch_virtual();
        fd_bincode_decode_ctx_t decode = {
            .data    = voter_acc_rec->const_data,
            .dataend = voter_acc_rec->const_data + voter_acc_rec->const_meta->dlen,
            .valloc  = valloc,
        };
        fd_vote_state_versioned_t vote_state_versioned[1] = {0};
        if( fd_vote_state_versioned_decode( vote_state_versioned, &decode ) != 0 ) {
            FD_LOG_ERR(( "failed to decode vote state" ));
        }

        /* Note, this doesn't actually redeem any rewards.. this is a misnomer. */
        fd_calculated_stake_rewards_t calculated_stake_rewards[1] = {0};
        int err = redeem_rewards( stake_history, stake_state, vote_state_versioned, rewarded_epoch, point_value, calculated_stake_rewards );
        if ( err != 0) {
            FD_LOG_DEBUG(( "redeem_rewards failed for %s with error %d", FD_BASE58_ENC_32_ALLOCA( stake_acc->key ), err ));
            return;
        }

        /* Fetch the comission for the vote account */
        uchar commission = 0;
        switch (vote_state_versioned->discriminant) {
            case fd_vote_state_versioned_enum_current:
                commission = vote_state_versioned->inner.current.commission;
                break;
            case fd_vote_state_versioned_enum_v0_23_5:
                commission = vote_state_versioned->inner.v0_23_5.commission;
                break;
            case fd_vote_state_versioned_enum_v1_14_11:
                commission = vote_state_versioned->inner.v1_14_11.commission;
                break;
            default:
                FD_LOG_DEBUG(( "unsupported vote account" ));
                return;
        }

        /* Update the vote reward in the map */
        fd_vote_reward_t_mapnode_t vote_map_key[1];
        fd_memcpy( &vote_map_key->elem.pubkey, voter_acc, sizeof(fd_pubkey_t) );
        fd_vote_reward_t_mapnode_t * vote_reward_node = fd_vote_reward_t_map_find( result->vote_reward_map_pool, result->vote_reward_map_root, vote_map_key );
        if ( vote_reward_node == NULL ) {
            vote_reward_node = fd_vote_reward_t_map_acquire( result->vote_reward_map_pool );
            fd_memcpy( &vote_reward_node->elem.pubkey, voter_acc, sizeof(fd_pubkey_t) );
            vote_reward_node->elem.commission = commission;
            vote_reward_node->elem.vote_rewards = calculated_stake_rewards->voter_rewards;
            vote_reward_node->elem.needs_store = 1;
            fd_vote_reward_t_map_insert( result->vote_reward_map_pool, &result->vote_reward_map_root, vote_reward_node );
        } else {
            vote_reward_node->elem.needs_store = 1;
            vote_reward_node->elem.vote_rewards = fd_ulong_sat_add(
                vote_reward_node->elem.vote_rewards, calculated_stake_rewards->voter_rewards
            );
        }

        /* Add the stake reward to list of all stake rewards */
        fd_stake_reward_t * stake_reward = fd_stake_reward_pool_ele_acquire( result->stake_reward_calculation.pool );
        fd_memcpy( &stake_reward->stake_pubkey, stake_acc, FD_PUBKEY_FOOTPRINT );
        stake_reward->lamports = calculated_stake_rewards->staker_rewards;
        stake_reward->credits_observed = calculated_stake_rewards->new_credits_observed;

        fd_stake_reward_dlist_ele_push_tail( 
            &result->stake_reward_calculation.stake_rewards,
            stake_reward,
            result->stake_reward_calculation.pool );
        result->stake_reward_calculation.stake_rewards_len += 1;

        /* Update the total stake rewards */
        result->stake_reward_calculation.total_stake_rewards_lamports += calculated_stake_rewards->staker_rewards;
    } FD_SCRATCH_SCOPE_END;
}

/* Calculates epoch rewards for stake/vote accounts.
   Returns vote rewards, stake rewards, and the sum of all stake rewards in lamports.

   This uses a pool to allocate the stake rewards, which means that we can use dlists to
   distribute these into partitions of variable size without copying them or over-allocating
   the partitions.
   - We use a single dlist to put all the stake rewards during the calculation phase.
   - We then distribute these into partitions (whose size cannot be known in advance), where each
     partition is a seperate dlist.
   - The dlist elements are all backed by the same pool, and allocated once.
   This approach optimizes memory usage and reduces copying.

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L334 */
static void
calculate_stake_vote_rewards(
    fd_exec_slot_ctx_t *                       slot_ctx,
    fd_stake_history_t const *                 stake_history,
    ulong                                      rewarded_epoch,
    fd_point_value_t *                         point_value,
    fd_calculate_stake_vote_rewards_result_t * result
) {
    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
    ulong rewards_max_count = fd_ulong_sat_add( 
        fd_delegation_pair_t_map_size( epoch_bank->stakes.stake_delegations_pool, epoch_bank->stakes.stake_delegations_root ),
        fd_stake_accounts_pair_t_map_size( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root ) );

    /* Create the stake rewards pool and dlist. The pool will be destoyed after the stake rewards have been distributed. */
    result->stake_reward_calculation.pool = fd_stake_reward_pool_join(
        fd_stake_reward_pool_new(
            fd_valloc_malloc( 
                slot_ctx->valloc,
                fd_stake_reward_pool_align(),
                fd_stake_reward_pool_footprint( rewards_max_count ) ), rewards_max_count ) );
    fd_stake_reward_dlist_new( &result->stake_reward_calculation.stake_rewards );
    result->stake_reward_calculation.stake_rewards_len = 0UL;

    /* Create the vote rewards map. This will be destroyed after the vote rewards have been distributed. */
    result->vote_reward_map_pool = fd_vote_reward_t_map_join( fd_vote_reward_t_map_new( fd_valloc_malloc( 
        slot_ctx->valloc,
        fd_vote_reward_t_map_align(),
        fd_vote_reward_t_map_footprint( rewards_max_count )), rewards_max_count ) );
    result->vote_reward_map_root = NULL;

    /* Loop over all the delegations
    
        https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L367  */
    for( fd_delegation_pair_t_mapnode_t const * n = fd_delegation_pair_t_map_minimum_const(
         epoch_bank->stakes.stake_delegations_pool, epoch_bank->stakes.stake_delegations_root );
         n;
         n = fd_delegation_pair_t_map_successor_const( epoch_bank->stakes.stake_delegations_pool, n )
    ) {        
        fd_pubkey_t const * stake_acc = &n->elem.account;

        calculate_stake_vote_rewards_account(
            slot_ctx,
            stake_history,
            rewarded_epoch,
            point_value,
            stake_acc,
            result );
    }

    /* Loop over all the stake accounts in the slot bank pool */
    for ( fd_stake_accounts_pair_t_mapnode_t const * n = 
        fd_stake_accounts_pair_t_map_minimum_const( 
            slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, slot_ctx->slot_bank.stake_account_keys.stake_accounts_root );
         n;
         n = fd_stake_accounts_pair_t_map_successor_const( slot_ctx->slot_bank.stake_account_keys.stake_accounts_pool, n) ) {

        fd_pubkey_t const * stake_acc = &n->elem.key;
        calculate_stake_vote_rewards_account(
            slot_ctx,
            stake_history,
            rewarded_epoch,
            point_value,
            stake_acc,
            result );
    }
}

/* Calculate epoch reward and return vote and stake rewards.

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L273 */
static void
calculate_validator_rewards(
    fd_exec_slot_ctx_t * slot_ctx,
    ulong rewarded_epoch,
    ulong rewards,
    fd_calculate_validator_rewards_result_t * result
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L2759-L2786 */
    fd_stake_history_t const * stake_history = fd_sysvar_cache_stake_history( slot_ctx->sysvar_cache );
    if( FD_UNLIKELY( !stake_history ) ) {
        FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));
    }

    /* Calculate the epoch reward points from stake/vote accounts */
    calculate_reward_points_partitioned( slot_ctx, stake_history, rewards, &result->point_value );

    /* Calculate the stake and vote rewards for each account */
    calculate_stake_vote_rewards(
        slot_ctx,
        stake_history,
        rewarded_epoch,
        &result->point_value,
        &result->calculate_stake_vote_rewards_result );
}

/* Calculate the number of blocks required to distribute rewards to all stake accounts.

    https://github.com/anza-xyz/agave/blob/9a7bf72940f4b3cd7fc94f54e005868ce707d53d/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L214
 */
static ulong
get_reward_distribution_num_blocks(
    fd_epoch_schedule_t const * epoch_schedule,
    ulong slot,
    ulong total_stake_accounts
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L1250-L1267 */
    if ( epoch_schedule->warmup &&
         fd_slot_to_epoch( epoch_schedule, slot, NULL ) < epoch_schedule->first_normal_epoch ) {
        return 1UL;
    }

    ulong num_chunks = total_stake_accounts / (ulong)STAKE_ACCOUNT_STORES_PER_BLOCK + (total_stake_accounts % STAKE_ACCOUNT_STORES_PER_BLOCK != 0);
    num_chunks = fd_ulong_max( num_chunks, 1 );
    num_chunks = fd_ulong_min(
        num_chunks,
        fd_ulong_max(
            epoch_schedule->slots_per_epoch / (ulong)MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH,
            1) );
    return num_chunks;
}

static void
hash_rewards_into_partitions(
    fd_exec_slot_ctx_t *                        slot_ctx,
    fd_stake_reward_calculation_t *             stake_reward_calculation,
    const fd_hash_t *                           parent_blockhash,
    fd_stake_reward_calculation_partitioned_t * result
) {
    /* Initialize a dlist for every partition.
       These will all use the same pool - we do not re-allocate the stake rewards, only move them into partitions. */
    result->partitioned_stake_rewards.pool = stake_reward_calculation->pool;
    ulong num_partitions = get_reward_distribution_num_blocks( 
        &fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx )->epoch_schedule,
        slot_ctx->slot_bank.slot,
        stake_reward_calculation->stake_rewards_len);
    result->partitioned_stake_rewards.partitions_len = num_partitions;
    result->partitioned_stake_rewards.partitions = fd_valloc_malloc( 
        slot_ctx->valloc,
        fd_stake_reward_dlist_align(),
        fd_stake_reward_dlist_footprint() * num_partitions
    );

    /* Ownership of these dlist's and the pool gets transferred to stake_rewards_by_partition, which then gets transferred to epoch_reward_status.
       These are eventually cleaned up when epoch_reward_status_inactive is called. */
    for ( ulong i = 0; i < num_partitions; ++i ) {
        fd_stake_reward_dlist_new( &result->partitioned_stake_rewards.partitions[ i ] );
    }

    /* Iterate over all the stake rewards, moving references to them into the appropiate partitions.
       IMPORTANT: after this, we cannot use the original stake rewards dlist anymore. */
    fd_stake_reward_dlist_iter_t next_iter;
    for ( fd_stake_reward_dlist_iter_t iter = fd_stake_reward_dlist_iter_fwd_init( 
            &stake_reward_calculation->stake_rewards, stake_reward_calculation->pool );
          !fd_stake_reward_dlist_iter_done( iter, &stake_reward_calculation->stake_rewards, stake_reward_calculation->pool );
        iter = next_iter
    ) {
        fd_stake_reward_t * stake_reward = fd_stake_reward_dlist_iter_ele( iter, &stake_reward_calculation->stake_rewards, stake_reward_calculation->pool );
        /* Cache the next iter here, as we will overwrite the DLIST_NEXT value further down in the loop iteration. */
        next_iter = fd_stake_reward_dlist_iter_fwd_next( iter, &stake_reward_calculation->stake_rewards, stake_reward_calculation->pool );

        /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/epoch_rewards_hasher.rs#L43C31-L61 */
        fd_siphash13_t  _sip[1] = {0};
        fd_siphash13_t * hasher = fd_siphash13_init( _sip, 0UL, 0UL );

        hasher = fd_siphash13_append( hasher, parent_blockhash->hash, sizeof(fd_hash_t) );
        fd_siphash13_append( hasher, (const uchar *) stake_reward->stake_pubkey.key, sizeof(fd_pubkey_t) );

        ulong hash64 = fd_siphash13_fini( hasher );
        /* hash_to_partition */
        /* FIXME: should be saturating add */
        ulong partition_index = (ulong)(
            (uint128) num_partitions *
            (uint128) hash64 /
            ((uint128)ULONG_MAX + 1)
        );

        /* Move the stake reward to the partition's dlist */
        fd_stake_reward_dlist_t * partition = &result->partitioned_stake_rewards.partitions[ partition_index ];
        fd_stake_reward_dlist_ele_push_tail( partition, stake_reward, stake_reward_calculation->pool );
    }
}

/* Calculate rewards from previous epoch to prepare for partitioned distribution.

   https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L214 */
static void
calculate_rewards_for_partitioning(
    fd_exec_slot_ctx_t *                   slot_ctx,
    ulong                                  prev_epoch,
    const fd_hash_t *                      parent_blockhash,
    fd_partitioned_rewards_calculation_t * result
) {
    /* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L227 */
    fd_prev_epoch_inflation_rewards_t rewards;
    calculate_previous_epoch_inflation_rewards( slot_ctx, slot_ctx->slot_bank.capitalization, prev_epoch, &rewards );

    fd_slot_bank_t const * slot_bank = &slot_ctx->slot_bank;

    fd_calculate_validator_rewards_result_t validator_result[1] = {0};
    calculate_validator_rewards( slot_ctx, prev_epoch, rewards.validator_rewards, validator_result );

    hash_rewards_into_partitions(
        slot_ctx,
        &validator_result->calculate_stake_vote_rewards_result.stake_reward_calculation,
        parent_blockhash,
        &result->stake_rewards_by_partition );
    result->stake_rewards_by_partition.total_stake_rewards_lamports = 
        validator_result->calculate_stake_vote_rewards_result.stake_reward_calculation.total_stake_rewards_lamports;

    result->vote_reward_map_pool = validator_result->calculate_stake_vote_rewards_result.vote_reward_map_pool;
    result->vote_reward_map_root = validator_result->calculate_stake_vote_rewards_result.vote_reward_map_root;
    result->validator_rewards = rewards.validator_rewards;
    result->validator_rate = rewards.validator_rate;
    result->foundation_rate = rewards.foundation_rate;
    result->prev_epoch_duration_in_years = rewards.prev_epoch_duration_in_years;
    result->capitalization = slot_bank->capitalization;
    fd_memcpy( &result->point_value, &validator_result->point_value, FD_POINT_VALUE_FOOTPRINT );
}

/* Calculate rewards from previous epoch and distribute vote rewards 
   
   https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L97 */
static void
calculate_rewards_and_distribute_vote_rewards(
    fd_exec_slot_ctx_t *                                        slot_ctx,
    ulong                                                       prev_epoch,
    const fd_hash_t *                                           parent_blockhash,
    fd_calculate_rewards_and_distribute_vote_rewards_result_t * result
) {
    /* https://github.com/firedancer-io/solana/blob/dab3da8e7b667d7527565bddbdbecf7ec1fb868e/runtime/src/bank.rs#L2406-L2492 */
    fd_partitioned_rewards_calculation_t rewards_calc_result[1] = {0};
    calculate_rewards_for_partitioning( slot_ctx, prev_epoch, parent_blockhash, rewards_calc_result );

    /* Iterate over all the vote reward nodes */
    for ( fd_vote_reward_t_mapnode_t* vote_reward_node = fd_vote_reward_t_map_minimum(
            rewards_calc_result->vote_reward_map_pool,
            rewards_calc_result->vote_reward_map_root);
            vote_reward_node;
            vote_reward_node = fd_vote_reward_t_map_successor( rewards_calc_result->vote_reward_map_pool, vote_reward_node ) ) {

        fd_pubkey_t const * vote_pubkey = &vote_reward_node->elem.pubkey;
        FD_BORROWED_ACCOUNT_DECL( vote_rec );
        FD_TEST( fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, vote_pubkey, 1, 0UL, vote_rec ) == FD_ACC_MGR_SUCCESS );
        vote_rec->meta->slot = slot_ctx->slot_bank.slot;

        FD_TEST( fd_borrowed_account_checked_add_lamports( vote_rec, vote_reward_node->elem.vote_rewards ) == 0 );
        result->distributed_rewards = fd_ulong_sat_add( result->distributed_rewards, vote_reward_node->elem.vote_rewards );
    }

    /* Free the vote reward map */
    fd_valloc_free( slot_ctx->valloc, 
        fd_vote_reward_t_map_delete( 
            fd_vote_reward_t_map_leave( rewards_calc_result->vote_reward_map_pool ) ) );

    /* Verify that we didn't pay any more than we expected to */
    result->total_rewards = fd_ulong_sat_add( result->distributed_rewards, rewards_calc_result->stake_rewards_by_partition.total_stake_rewards_lamports );
    FD_TEST( rewards_calc_result->validator_rewards >= result->total_rewards );

    slot_ctx->slot_bank.capitalization += result->distributed_rewards;

    /* Cheap because this doesn't copy all the rewards, just pointers to the dlist */
    fd_memcpy( &result->stake_rewards_by_partition, &rewards_calc_result->stake_rewards_by_partition, FD_STAKE_REWARD_CALCULATION_PARTITIONED_FOOTPRINT );
    fd_memcpy( &result->point_value, &rewards_calc_result->point_value, FD_POINT_VALUE_FOOTPRINT );
}

/* Distributes a single partitioned reward to a single stake account */
static int
distribute_epoch_reward_to_stake_acc( 
    fd_exec_slot_ctx_t * slot_ctx,
    fd_pubkey_t *        stake_pubkey,
    ulong                reward_lamports,
    ulong                new_credits_observed
 ) {

    FD_BORROWED_ACCOUNT_DECL( stake_acc_rec );
    FD_TEST( fd_acc_mgr_modify( slot_ctx->acc_mgr, slot_ctx->funk_txn, stake_pubkey, 0, 0UL, stake_acc_rec ) == FD_ACC_MGR_SUCCESS );
    stake_acc_rec->meta->slot = slot_ctx->slot_bank.slot;

    fd_stake_state_v2_t stake_state[1] = {0};
    if ( fd_stake_get_state(stake_acc_rec, &slot_ctx->valloc, stake_state) != 0 ) {
        FD_LOG_DEBUG(( "failed to read stake state for %s", FD_BASE58_ENC_32_ALLOCA( stake_pubkey ) ));
        return 1;
    }

    if ( !fd_stake_state_v2_is_stake( stake_state ) ) {
        FD_LOG_DEBUG(( "non-stake stake account, this should never happen" ));
        return 1;
    }

    if( fd_borrowed_account_checked_add_lamports( stake_acc_rec, reward_lamports ) ) {
        FD_LOG_DEBUG(( "failed to add lamports to stake account" ));
        return 1;
    }

    stake_state->inner.stake.stake.credits_observed = new_credits_observed;
    stake_state->inner.stake.stake.delegation.stake = fd_ulong_sat_add(
        stake_state->inner.stake.stake.delegation.stake,
        reward_lamports
    );

    if ( FD_UNLIKELY( write_stake_state( stake_acc_rec, stake_state ) != 0 ) ) {
        FD_LOG_ERR(( "write_stake_state failed" ));
    }

    return 0;
}

/* Sets the epoch reward status to inactive, and destroys any allocated state associated with the active state. */
void
set_epoch_reward_status_inactive(
    fd_exec_slot_ctx_t * slot_ctx
) {
    if ( slot_ctx->epoch_reward_status.discriminant == fd_epoch_reward_status_enum_Active ) {
        fd_partitioned_stake_rewards_t * partitioned_rewards = &slot_ctx->epoch_reward_status.inner.Active.partitioned_stake_rewards;
        /* Destroy the partitions */
        fd_valloc_free( slot_ctx->valloc, 
            fd_stake_reward_dlist_delete( 
                fd_stake_reward_dlist_leave( partitioned_rewards->partitions ) ) );

        /* Destroy the underlying pool */
        fd_valloc_free(
            slot_ctx->valloc, 
                fd_stake_reward_pool_delete(
                    fd_stake_reward_pool_leave( partitioned_rewards->pool ) ) );
    }
    slot_ctx->epoch_reward_status.discriminant = fd_epoch_reward_status_enum_Inactive;
}

/* Sets the epoch reward status to active.

    Takes ownership of the given stake_rewards_by_partition data structure,
    which will be destroyed when set_epoch_reward_status_inactive is called. */
void
set_epoch_reward_status_active( 
    fd_exec_slot_ctx_t * slot_ctx,
    ulong distribution_starting_block_height,
    fd_partitioned_stake_rewards_t * partitioned_rewards ) {

    slot_ctx->epoch_reward_status.discriminant = fd_epoch_reward_status_enum_Active;
    slot_ctx->epoch_reward_status.inner.Active.distribution_starting_block_height = distribution_starting_block_height;
    
    fd_memcpy( &slot_ctx->epoch_reward_status.inner.Active.partitioned_stake_rewards, partitioned_rewards, FD_PARTITIONED_STAKE_REWARDS_FOOTPRINT );
}

/*  Process reward credits for a partition of rewards.
    Store the rewards to AccountsDB, update reward history record and total capitalization
    
    https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L88 */
static void
distribute_epoch_rewards_in_partition(
    fd_stake_reward_dlist_t * partition,
    fd_stake_reward_t *pool,
    fd_exec_slot_ctx_t * slot_ctx
) {

    ulong lamports_distributed = 0UL;
    ulong lamports_burned = 0UL;

    for ( fd_stake_reward_dlist_iter_t iter = fd_stake_reward_dlist_iter_fwd_init( partition, pool );
          !fd_stake_reward_dlist_iter_done( iter, partition, pool );
        iter = fd_stake_reward_dlist_iter_fwd_next( iter, partition, pool )
    ) {
        fd_stake_reward_t * stake_reward = fd_stake_reward_dlist_iter_ele( iter, partition, pool );

        if ( distribute_epoch_reward_to_stake_acc( 
            slot_ctx,
            &stake_reward->stake_pubkey,
            stake_reward->lamports,
            stake_reward->credits_observed ) == 0 ) {
            lamports_distributed += stake_reward->lamports;
        } else {
            lamports_burned += stake_reward->lamports;
        }

    }

    /* Update the epoch rewards sysvar with the amount distributed and burnt */
    if ( FD_LIKELY( ( 
        FD_FEATURE_ACTIVE( slot_ctx, enable_partitioned_epoch_reward ) ||
        FD_FEATURE_ACTIVE( slot_ctx, partitioned_epoch_rewards_superfeature ) ) ) ) {
        fd_sysvar_epoch_rewards_distribute( slot_ctx, lamports_distributed + lamports_burned );
    }

    FD_LOG_DEBUG(( "lamports burned: %lu, lamports distributed: %lu", lamports_burned, lamports_distributed ));

    slot_ctx->slot_bank.capitalization += lamports_distributed;
}

/* Process reward distribution for the block if it is inside reward interval.

   https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/runtime/src/bank/partitioned_epoch_rewards/distribution.rs#L42 */
void
fd_distribute_partitioned_epoch_rewards(
    fd_exec_slot_ctx_t * slot_ctx
) {
    if ( slot_ctx->epoch_reward_status.discriminant == fd_epoch_reward_status_enum_Inactive ) {
        return;
    }
    fd_start_block_height_and_rewards_t * status = &slot_ctx->epoch_reward_status.inner.Active;

    fd_slot_bank_t * slot_bank = &slot_ctx->slot_bank;
    ulong height = slot_bank->block_height;
    fd_epoch_bank_t const * epoch_bank = fd_exec_epoch_ctx_epoch_bank_const( slot_ctx->epoch_ctx );

    ulong distribution_starting_block_height = status->distribution_starting_block_height;
    ulong distribution_end_exclusive = distribution_starting_block_height + status->partitioned_stake_rewards.partitions_len;

    /* TODO: track current epoch in epoch ctx? */
    ulong epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, slot_bank->slot, NULL );
    FD_TEST( get_slots_in_epoch( epoch, epoch_bank ) > status->partitioned_stake_rewards.partitions_len );

    if ( ( height >= distribution_starting_block_height ) && ( height < distribution_end_exclusive ) ) {
        ulong partition_index = height - distribution_starting_block_height;
        distribute_epoch_rewards_in_partition(
            &status->partitioned_stake_rewards.partitions[ partition_index ],
            status->partitioned_stake_rewards.pool,
            slot_ctx
        );
    }

    /* If we have finished distributing rewards, set the status to inactive */
    if ( fd_ulong_sat_add( height, 1UL ) >= distribution_end_exclusive ) {
        set_epoch_reward_status_inactive( slot_ctx );
        fd_sysvar_epoch_rewards_set_inactive( slot_ctx );
    }
}

/* Non-partitioned epoch rewards entry-point. This uses the same logic as the partitioned epoch rewards code, 
   but distributes the rewards in one go.  */
void
fd_update_rewards(
    fd_exec_slot_ctx_t * slot_ctx,
    const fd_hash_t *    parent_blockhash,
    ulong                parent_epoch
) {

    /* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L55 */
    fd_calculate_rewards_and_distribute_vote_rewards_result_t rewards_result[1] = {0};
    calculate_rewards_and_distribute_vote_rewards(
        slot_ctx,
        parent_epoch,
        parent_blockhash,
        rewards_result
    );

    /* Distribute all of the partitioned epoch rewards in one go */
    for ( ulong i = 0UL; i < rewards_result->stake_rewards_by_partition.partitioned_stake_rewards.partitions_len; i++ ) {
        distribute_epoch_rewards_in_partition(
            &rewards_result->stake_rewards_by_partition.partitioned_stake_rewards.partitions[ i ],
            rewards_result->stake_rewards_by_partition.partitioned_stake_rewards.pool,
            slot_ctx
        );
    }
}

/* Partitioned epoch rewards entry-point.

   https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L41
*/
void
fd_begin_partitioned_rewards(
    fd_exec_slot_ctx_t * slot_ctx,
    const fd_hash_t *    parent_blockhash,
    ulong                parent_epoch
) {
    /* https://github.com/anza-xyz/agave/blob/7117ed9653ce19e8b2dea108eff1f3eb6a3378a7/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L55 */
    fd_calculate_rewards_and_distribute_vote_rewards_result_t rewards_result[1] = {0};
    calculate_rewards_and_distribute_vote_rewards(
        slot_ctx,
        parent_epoch,
        parent_blockhash,
        rewards_result
    );

    /* https://github.com/anza-xyz/agave/blob/9a7bf72940f4b3cd7fc94f54e005868ce707d53d/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L62 */
    ulong distribution_starting_block_height = slot_ctx->slot_bank.block_height + REWARD_CALCULATION_NUM_BLOCKS;
    
    /* Set the epoch reward status to be active */
    set_epoch_reward_status_active( slot_ctx, distribution_starting_block_height, &rewards_result->stake_rewards_by_partition.partitioned_stake_rewards );

    /* Initialise the epoch rewards sysvar
     
        https://github.com/anza-xyz/agave/blob/9a7bf72940f4b3cd7fc94f54e005868ce707d53d/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L78 */
    fd_sysvar_epoch_rewards_init( 
        slot_ctx,
        rewards_result->total_rewards,
        rewards_result->distributed_rewards,
        distribution_starting_block_height,
        rewards_result->stake_rewards_by_partition.partitioned_stake_rewards.partitions_len,
        rewards_result->point_value,
        parent_blockhash
     );
}

/* 
    Re-calculates partitioned stake rewards.
    This updates the slot context's epoch reward status with the recalculated partitioned rewards.

    https://github.com/anza-xyz/agave/blob/2316fea4c0852e59c071f72d72db020017ffd7d0/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L536 */
void
fd_rewards_recalculate_partitioned_rewards(
    fd_exec_slot_ctx_t * slot_ctx
) {
    fd_sysvar_epoch_rewards_t epoch_rewards[1];
    if ( FD_UNLIKELY( fd_sysvar_epoch_rewards_read( epoch_rewards, slot_ctx ) == NULL ) ) {
      FD_LOG_NOTICE(( "failed to read sysvar epoch rewards - the sysvar may not have been created yet" ));
      set_epoch_reward_status_inactive( slot_ctx );
      return;
    }

    if ( FD_UNLIKELY( epoch_rewards->active ) ) {
        /* If partitioned rewards are active, the rewarded epoch is always the immediately
           preceeding epoch.
           
           https://github.com/anza-xyz/agave/blob/2316fea4c0852e59c071f72d72db020017ffd7d0/runtime/src/bank/partitioned_epoch_rewards/calculation.rs#L566 */
        fd_epoch_schedule_t * epoch_schedule = &fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx )->epoch_schedule;
        ulong epoch = fd_slot_to_epoch( epoch_schedule, slot_ctx->slot_bank.slot, NULL );
        ulong rewarded_epoch = fd_ulong_sat_sub( epoch, 1UL );

        fd_stake_history_t const * stake_history = fd_sysvar_cache_stake_history( slot_ctx->sysvar_cache );
        if( FD_UNLIKELY( !stake_history ) ) {
            FD_LOG_ERR(( "StakeHistory sysvar is missing from sysvar cache" ));
        }

        fd_point_value_t point_value = {
            .points = epoch_rewards->total_points,
            .rewards = epoch_rewards->total_rewards
        };

        /* In future, the calculation will be cached in the snapshot, but for now we just re-calculate it
           (as Agave does). */
        fd_calculate_stake_vote_rewards_result_t calculate_stake_vote_rewards_result[1];
        calculate_stake_vote_rewards(
            slot_ctx,
            stake_history,
            rewarded_epoch,
            &point_value,
            calculate_stake_vote_rewards_result
        );

        /* Free the vote reward map, as this isn't actually used in this code path. */
        fd_valloc_free( slot_ctx->valloc, 
            fd_vote_reward_t_map_delete( 
                fd_vote_reward_t_map_leave( calculate_stake_vote_rewards_result->vote_reward_map_pool ) ) );

        fd_stake_reward_calculation_partitioned_t stake_rewards_by_partition[1];
        hash_rewards_into_partitions(
            slot_ctx,
            &calculate_stake_vote_rewards_result->stake_reward_calculation,
            &epoch_rewards->parent_blockhash,
            stake_rewards_by_partition );

        /* Update the epoch reward status with the newly re-calculated partitions. */
        set_epoch_reward_status_active( 
            slot_ctx,
            epoch_rewards->distribution_starting_block_height,
            &stake_rewards_by_partition->partitioned_stake_rewards );
    } else {
        set_epoch_reward_status_inactive( slot_ctx );
    }

}
