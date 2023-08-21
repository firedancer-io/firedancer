#ifndef HEADER_fd_src_flamenco_runtime_program_fd_reward_h
#define HEADER_fd_src_flamenco_runtime_program_fd_reward_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../runtime/sysvar/fd_sysvar.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../stakes/fd_stakes.h"
#include "../stakes/fd_stake_program.h"
#include "../runtime/program/fd_vote_program.h"
#include "../../ballet/siphash13/fd_siphash13.h"

/* reward calculation happens synchronously during the first block of the epoch boundary.
 So, # blocks for reward calculation is 1. */
#define REWARD_CALCULATION_NUM_BLOCK            1
/* stake accounts to store in one block during partitioned reward interval Target to store 64 rewards per entry/tick in a block. A block has a minimum of 64 entries/tick. This gives 4096 total rewards to store in one block. This constant affects consensus. */
#define STAKE_ACCOUNT_STORES_PER_BLOCK          4096
#define TEST_ENABLE_PARTITIONED_REWARDS         0
#define TEST_COMPARE_PARTITIONED_EPOCH_REWARDS  0
#define MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH    10

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

struct fd_vote_reward_t_mapnode {
  fd_pubkey_t * vote_pubkey;
  ulong vote_rewards;
  uchar commission;
};

typedef struct fd_vote_reward_t_mapnode fd_vote_reward_t_mapnode_t;

#define MAP_NAME              fd_vote_reward_t_map
#define MAP_T                 fd_vote_reward_t_mapnode_t
// #define MAP_LG_SLOT_CNT       9
#define MAP_MEMOIZE           0
#define MAP_KEY               vote_pubkey
#define MAP_KEY_T             fd_pubkey_t *
#define MAP_KEY_NULL          NULL
#define MAP_KEY_INVAL(k)      !(k)
#define MAP_KEY_EQUAL(a,b)    (memcmp((a), (b), sizeof(fd_pubkey_t))==0)
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     fd_uint_load_4( (key) )
#define MAP_KEY_MOVE(kd,ks) memcpy((kd),(ks),sizeof(fd_pubkey_t))
#include "../../util/tmpl/fd_map_dynamic.c"
static inline fd_vote_reward_t_mapnode_t *
fd_vote_reward_t_map_alloc( fd_valloc_t valloc, int len ) {
  void * mem = fd_valloc_malloc( valloc, fd_vote_reward_t_map_align(), fd_vote_reward_t_map_footprint(len));
  return fd_vote_reward_t_map_join(fd_vote_reward_t_map_new(mem, len));
}

struct fd_stake_reward {
    fd_pubkey_t * stake_pubkey;
    fd_reward_info_t * reward_info;
};
typedef struct fd_stake_reward fd_stake_reward_t;

#define VECT_NAME fd_stake_rewards
#define VECT_ELEMENT fd_stake_reward_t*
#include "../runtime/fd_vector.h"
#undef VECT_NAME
#undef VECT_ELEMENT

#define VECT_NAME fd_stake_rewards_vector
#define VECT_ELEMENT fd_stake_rewards_t
#include "../runtime/fd_vector.h"
#undef VECT_NAME
#undef VECT_ELEMENT

#define DEQUE_NAME deq_fd_stake_reward_t
#define DEQUE_T    fd_stake_reward_t
#define DEQUE_MAX  1000UL
#include "../../util/tmpl/fd_deque.c"
static inline fd_stake_reward_t *
deq_fd_stake_reward_t_alloc( fd_valloc_t valloc ) {
  void * mem = fd_valloc_malloc( valloc, deq_fd_stake_reward_t_align(), deq_fd_stake_reward_t_footprint());
  return deq_fd_stake_reward_t_join( deq_fd_stake_reward_t_new( mem ) );
}

struct fd_validator_reward_calculation {
    fd_acc_lamports_t total_stake_rewards_lamports;
    fd_stake_reward_t * stake_reward_deq;
    fd_vote_reward_t_mapnode_t * vote_reward_map;
};
typedef struct fd_validator_reward_calculation fd_validator_reward_calculation_t;

struct fd_partitioned_rewards_calculation {
    /* VoteRewardsAccount */
    fd_vote_reward_t_mapnode_t * vote_account_rewards;
    fd_stake_rewards_vector_t * stake_rewards_by_partition;
    ulong total_stake_rewards_lamports;
    ulong old_vote_balance_and_staked;
    ulong validator_rewards;
    double validator_rate;
    double foundation_rate;
    double prev_epoch_duration_in_years;
    ulong capitalization;
};
typedef struct fd_partitioned_rewards_calculation fd_partitioned_rewards_calculation_t;

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

struct fd_calculate_rewards_and_distribute_vote_rewards_result {
  ulong total_rewards;
  ulong distributed_rewards;
  fd_stake_rewards_vector_t * stake_rewards_by_partition;
};
typedef struct fd_calculate_rewards_and_distribute_vote_rewards_result fd_calculate_rewards_and_distribute_vote_rewards_result_t;

FD_PROTOTYPES_BEGIN

void
begin_partitioned_rewards(
    fd_global_ctx_t * global,
    ulong parent_epoch,
    ulong parent_slot,
    ulong parent_height
);

void
update_rewards(
    fd_global_ctx_t * global,
    ulong prev_epoch
);

FD_PROTOTYPES_END

#endif
