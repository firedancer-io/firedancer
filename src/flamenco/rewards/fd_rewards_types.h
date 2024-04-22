#ifndef HEADER_fd_src_flamenco_runtime_program_fd_rewards_types_h
#define HEADER_fd_src_flamenco_runtime_program_fd_rewards_types_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"

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

/* reward calculation happens synchronously during the first block of the epoch boundary.
 So, # blocks for reward calculation is 1. */
#define REWARD_CALCULATION_NUM_BLOCK            1
/* stake accounts to store in one block during partitioned reward interval Target to store 64 rewards per entry/tick in a block. A block has a minimum of 64 entries/tick. This gives 4096 total rewards to store in one block. This constant affects consensus. */
#define STAKE_ACCOUNT_STORES_PER_BLOCK          4096
#define TEST_ENABLE_PARTITIONED_REWARDS         0
#define TEST_COMPARE_PARTITIONED_EPOCH_REWARDS  0
#define MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH    10

struct fd_vote_reward_t_mapnode {
  fd_pubkey_t vote_pubkey;
  ulong vote_rewards;
  uchar commission;
  uchar needs_store;
};

typedef struct fd_vote_reward_t_mapnode fd_vote_reward_t_mapnode_t;

#define MAP_NAME              fd_vote_reward_t_map
#define MAP_T                 fd_vote_reward_t_mapnode_t
#define MAP_MEMOIZE           0
#define MAP_KEY               vote_pubkey
#define MAP_KEY_T             fd_pubkey_t
#define MAP_KEY_NULL          (fd_pubkey_t){0}
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL((k),MAP_KEY_NULL)
#define MAP_KEY_EQUAL(k0,k1)    (!memcmp((k0).key, (k1).key, sizeof( fd_pubkey_t ) ))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     ((uint)fd_ulong_hash( fd_ulong_load_8( (key).key ) ))
#define MAP_KEY_MOVE(kd,ks) memcpy( &(kd), &(ks),sizeof(fd_pubkey_t))
#include "../../util/tmpl/fd_map_dynamic.c"
static inline fd_vote_reward_t_mapnode_t *
fd_vote_reward_t_map_alloc( fd_valloc_t valloc, int lg_slot_cnt ) {
  void * mem = fd_valloc_malloc( valloc, fd_vote_reward_t_map_align(), fd_vote_reward_t_map_footprint( lg_slot_cnt ));
  return fd_vote_reward_t_map_join(fd_vote_reward_t_map_new(mem, lg_slot_cnt));
}


#define DEQUE_NAME deq_fd_stake_reward_t
#define DEQUE_T    fd_stake_reward_t
#define DEQUE_MAX  1000000UL
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
  uint128 points;
};
typedef struct fd_point_value fd_point_value_t;

struct fd_calculated_stake_rewards{
  ulong staker_rewards;
  ulong voter_rewards;
  ulong new_credits_observed;
};
typedef struct fd_calculated_stake_rewards fd_calculated_stake_rewards_t;

struct fd_calculate_stake_points {
  uint128 points;
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

struct fd_epoch_reward_status {
  uint is_active;
  ulong start_block_height;
  fd_stake_rewards_vector_t * stake_rewards_by_partition;
};
typedef struct fd_epoch_reward_status fd_epoch_reward_status_t;

#endif /* HEADER_fd_src_flamenco_runtime_program_fd_rewards_types_h */
