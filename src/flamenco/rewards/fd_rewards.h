#ifndef HEADER_fd_src_flamenco_runtime_program_fd_reward_h
#define HEADER_fd_src_flamenco_runtime_program_fd_reward_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../runtime/sysvar/fd_sysvar.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../stakes/fd_stakes.h"
#include "../stakes/fd_stake_program.h"
#include "../runtime/program/fd_vote_program.h"

FD_PROTOTYPES_BEGIN

struct fd_vote_reward {
  fd_pubkey_t * vote_acc;
  uchar commission;
  ulong vote_rewards;
};
typedef struct fd_vote_reward fd_vote_reward_t;

struct prev_epoch_inflation_rewards {
    ulong validator_rewards;
    double prev_epoch_duration_in_years;
    double validator_rate;
    double foundation_rate;
};
typedef struct prev_epoch_inflation_rewards prev_epoch_inflation_rewards_t;

struct fd_reward_info {
    fd_reward_type_t reward_type;
    ulong lamports;
    ulong post_balance;
    short commission;
};
typedef struct fd_reward_info fd_reward_info_t;

struct fd_stake_reward {
    fd_pubkey_t * stake_pubkey;
    fd_reward_info_t * reward_info;
};
typedef struct fd_stake_reward fd_stake_reward_t;

struct fd_stake_reward_calculation {
    ulong total_stake_rewards_lamports;
    fd_stake_reward_t * stake_rewards;
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

struct fd_point_value {
  ulong rewards;
  __uint128_t points;
};
typedef struct fd_point_value fd_point_value_t;

struct fd_calculated_stake_rewards{
  ulong staker_rewards;
  ulong voter_rewards;
  ulong new_credits_observed;
};
typedef struct fd_calculated_stake_rewards fd_calculated_stake_rewards_t;

struct fd_calculate_stake_points {
  __uint128_t points;
  ulong new_credits_observed;
  uint force_credits_update_with_skipped_reward;
};
typedef struct fd_calculate_stake_points fd_calculate_stake_points_t;

FD_PROTOTYPES_END

#endif
