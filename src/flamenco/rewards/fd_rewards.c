#include "fd_rewards.h"
#include "math.h"

static double total(fd_inflation_t* inflation, double year) {
    double tapered = inflation->initial * pow((1.0 - inflation->taper), year);
    return (tapered > inflation->terminal) ? tapered : inflation->terminal;
}
static double foundation(fd_inflation_t* inflation, double year) {
    return (year < inflation->foundation_term) ? inflation->foundation * total(inflation, year) : 0.0;
}

static double validator(fd_inflation_t *inflation, double year) {
    return total(inflation, year) - foundation(inflation, year);
}

static ulong get_inflation_start_slot() {
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

static ulong get_inflation_num_slots(fd_firedancer_banks_t * bank) {
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



static double epoch_duration_in_years(
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
void calculate_reward_points_partitioned() {

}

/// Calculate epoch reward and return vote and stake rewards.
void calculate_validator_rewards() {

}

/// Calculate rewards from previous epoch to prepare for partitioned distribution.
// void calculate_rewards_for_partitioning(
//     fd_firedancer_banks_t * bank,
//     ulong prev_epoch,
//     partitioned_rewards_calculation_t * partitioned_rewards
// ) {
//     ulong prev_epoch_capitalization;
//     prev_epoch_inflation_rewards_t rewards; 
//     calculate_previous_epoch_inflation_rewards(bank, prev_epoch_capitalization, prev_epoch, &rewards);
// }

//calculate_rewards_for_partitioning

//calculate_rewards_and_distribute_vote_rewards

// update_rewards_with_thread_pool
