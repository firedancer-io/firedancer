#ifndef HEADER_fd_src_flamenco_runtime_program_fd_reward_h
#define HEADER_fd_src_flamenco_runtime_program_fd_reward_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../runtime/sysvar/fd_sysvar.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"

FD_PROTOTYPES_BEGIN

#define MINIMUM_SLOTS_PER_EPOCH 32
#define MINIMUM_SLOTS_PER_EPOCH_BIT 5

struct prev_epoch_inflation_rewards {
    ulong validator_rewards;
    double prev_epoch_duration_in_years;
    double validator_rate;
    double foundation_rate;
};
typedef struct prev_epoch_inflation_rewards prev_epoch_inflation_rewards_t;

struct partitioned_rewards_calculation {

    ulong old_vote_balance_and_staked;
    ulong validator_rewards;
    double validator_rate;
    double foundation_rate;
    double prev_epoch_duration_in_years;
    ulong capitalization;
};
typedef struct partitioned_rewards_calculation partitioned_rewards_calculation_t;

FD_PROTOTYPES_END

#endif