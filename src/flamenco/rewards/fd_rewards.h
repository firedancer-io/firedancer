#ifndef HEADER_fd_src_flamenco_runtime_program_fd_reward_h
#define HEADER_fd_src_flamenco_runtime_program_fd_reward_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../runtime/sysvar/fd_sysvar.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../stakes/fd_stakes.h"

FD_PROTOTYPES_BEGIN

struct prev_epoch_inflation_rewards {
    ulong validator_rewards;
    double prev_epoch_duration_in_years;
    double validator_rate;
    double foundation_rate;
};
typedef struct prev_epoch_inflation_rewards prev_epoch_inflation_rewards_t;

struct fd_reward_info {
    fd_reward_type_t reward_type;
    long lamports;
    ulong post_balance;
    short commission;
};
typedef struct fd_reward_info fd_reward_info_t;

struct fd_stake_rewards {
    fd_pubkey_t * stake_pubkey;
    fd_reward_info_t * reward_info;
    fd_solana_account_t * account_shared_data;
};
typedef struct fd_stake_rewards fd_stake_rewards_t;

struct fd_stake_reward_calculation {
    ulong total_stake_rewards_lamports;
    fd_stake_rewards_t * stake_rewards;
};

typedef struct fd_stake_reward_calculation fd_stake_reward_calculation_t;

struct partitioned_rewards_calculation {
    /* VoteRewardsAccount */
    fd_stake_reward_calculation_t * stake_rewards_by_partition; 
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
