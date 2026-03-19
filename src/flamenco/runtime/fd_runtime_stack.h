#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h

#include "../types/fd_types_custom.h"
#include "sysvar/fd_sysvar_clock.h"
#include "program/fd_builtin_programs.h"
#include "fd_runtime_const.h"

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L27 */
struct fd_calculated_stake_points {
  fd_w_u128_t points;
  ulong       new_credits_observed;
  uchar       force_credits_update_with_skipped_reward;
};
typedef struct fd_calculated_stake_points fd_calculated_stake_points_t;

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/rewards.rs#L24 */
struct fd_calculated_stake_rewards {
  ulong staker_rewards;
  ulong voter_rewards;
  ulong new_credits_observed;
  uchar success;
};
typedef struct fd_calculated_stake_rewards fd_calculated_stake_rewards_t;

/* fd_vote_ele and fd_vote_ele_map are used to temporarily cache
   computed fields for vote accounts during epoch boundary stake
   and rewards calculations. */

struct fd_epoch_credits {
  ulong  cnt;
  ushort epoch       [ FD_EPOCH_CREDITS_MAX ];
  ulong  credits     [ FD_EPOCH_CREDITS_MAX ];
  ulong  prev_credits[ FD_EPOCH_CREDITS_MAX ];
};
typedef struct fd_epoch_credits fd_epoch_credits_t;

struct fd_vote_rewards {
  fd_pubkey_t        pubkey;
  ulong              vote_rewards;
  ulong              stake;        /* accumulated effective stake for this vote account,
                                      computed during fd_refresh_vote_accounts */
  uint               next;
  uchar              commission;
};
typedef struct fd_vote_rewards fd_vote_rewards_t;

#define MAP_NAME               fd_vote_rewards_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_vote_rewards_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

#define FD_VOTE_ELE_MAP_ALIGN     (128UL)

FD_FN_PURE static inline ulong
fd_vote_ele_map_footprint( ulong max_vote_accounts ) {
  return sizeof(fd_vote_rewards_map_t) + max_vote_accounts * sizeof(uint);
}

/* fd_runtime_stack_t serves as stack memory to store temporary data
   for the runtime.  This object should only be used and owned by the
   replay tile and is used for short-lived allocations for the runtime,
   more specifically, for slot level calculations. */
struct fd_runtime_stack {

  ulong max_vote_accounts;
  ulong expected_vote_accounts;
  ulong expected_stake_accounts;

  struct {
    /* Staging memory to sort vote accounts by last vote timestamp for
       clock sysvar calculation. */
    ts_est_ele_t * staked_ts;
  } clock_ts;

  struct {
    /* Staging memory for bpf migration.  This is used to store and
       stage various accounts which is required for deploying a new BPF
       program at the epoch boundary. */
    fd_tmp_account_t source;
    fd_tmp_account_t program_account;
    fd_tmp_account_t new_target_program;
    fd_tmp_account_t new_target_program_data;
    fd_tmp_account_t empty;
  } bpf_migration;

  struct {
    fd_calculated_stake_points_t *  stake_points_result;

    fd_calculated_stake_rewards_t * stake_rewards_result;

    ulong       total_rewards;
    ulong       distributed_rewards;
    fd_w_u128_t total_points;

    ulong stake_rewards_cnt;

    /* Staging memory used for calculating and sorting vote account
       stake weights for the leader schedule calculation. */
    fd_vote_stake_weight_t * stake_weights;

    fd_vote_rewards_t * vote_ele;
    void *              vote_map_mem;

    fd_epoch_credits_t * epoch_credits;

  } stakes;
};
typedef struct fd_runtime_stack fd_runtime_stack_t;

FD_FN_CONST static inline ulong
fd_runtime_stack_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
fd_runtime_stack_footprint( ulong max_vote_accounts,
                            ulong expected_vote_accounts,
                            ulong expected_stake_accounts ) {
  ulong chain_cnt = fd_vote_rewards_map_chain_cnt_est( expected_vote_accounts );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_runtime_stack_t),           sizeof(fd_runtime_stack_t) );
  l = FD_LAYOUT_APPEND( l, alignof(ts_est_ele_t),                 sizeof(ts_est_ele_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, alignof(fd_vote_stake_weight_t),       sizeof(fd_vote_stake_weight_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, 128UL,                                 sizeof(fd_vote_rewards_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, FD_VOTE_ELE_MAP_ALIGN,                 fd_vote_ele_map_footprint( chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_epoch_credits_t),           sizeof(fd_epoch_credits_t) * expected_vote_accounts );
  l = FD_LAYOUT_APPEND( l, alignof(fd_calculated_stake_points_t), sizeof(fd_calculated_stake_points_t) * expected_stake_accounts );
  l = FD_LAYOUT_APPEND( l, alignof(fd_calculated_stake_rewards_t),sizeof(fd_calculated_stake_rewards_t) * expected_stake_accounts );
  return FD_LAYOUT_FINI( l, fd_runtime_stack_align() );
}

static inline void *
fd_runtime_stack_new( void * shmem,
                      ulong  max_vote_accounts,
                      ulong  expected_vote_accounts,
                      ulong  expected_stake_accounts,
                      ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) return NULL;
  ulong chain_cnt = fd_vote_rewards_map_chain_cnt_est( expected_vote_accounts );
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_runtime_stack_t *            runtime_stack        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_runtime_stack_t),            sizeof(fd_runtime_stack_t) );
  ts_est_ele_t *                  staked_ts            = FD_SCRATCH_ALLOC_APPEND( l, alignof(ts_est_ele_t),                  sizeof(ts_est_ele_t) * max_vote_accounts );
  fd_vote_stake_weight_t *        stake_weights        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vote_stake_weight_t),        sizeof(fd_vote_stake_weight_t) * max_vote_accounts );
  fd_vote_rewards_t *             vote_ele             = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  sizeof(fd_vote_rewards_t) * max_vote_accounts );
  void *                          vote_map_mem         = FD_SCRATCH_ALLOC_APPEND( l, FD_VOTE_ELE_MAP_ALIGN,                  fd_vote_ele_map_footprint( chain_cnt ) );
  fd_epoch_credits_t *            epoch_credits        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_epoch_credits_t),            sizeof(fd_epoch_credits_t) * expected_vote_accounts );
  fd_calculated_stake_points_t *  stake_points_result  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_calculated_stake_points_t),  sizeof(fd_calculated_stake_points_t) * expected_stake_accounts );
  fd_calculated_stake_rewards_t * stake_rewards_result = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_calculated_stake_rewards_t), sizeof(fd_calculated_stake_rewards_t) * expected_stake_accounts );
  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_runtime_stack_align() )!=(ulong)shmem + fd_runtime_stack_footprint( max_vote_accounts, expected_vote_accounts, expected_stake_accounts ) ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: bad layout" ));
    return NULL;
  }

  runtime_stack->max_vote_accounts           = max_vote_accounts;
  runtime_stack->expected_vote_accounts      = expected_vote_accounts;
  runtime_stack->expected_stake_accounts     = expected_stake_accounts;
  runtime_stack->clock_ts.staked_ts          = staked_ts;
  runtime_stack->stakes.stake_weights        = stake_weights;
  runtime_stack->stakes.vote_ele             = vote_ele;
  runtime_stack->stakes.vote_map_mem         = vote_map_mem;
  runtime_stack->stakes.epoch_credits        = epoch_credits;
  runtime_stack->stakes.stake_points_result  = stake_points_result;
  runtime_stack->stakes.stake_rewards_result = stake_rewards_result;

  if( FD_UNLIKELY( !fd_vote_rewards_map_join( fd_vote_rewards_map_new( runtime_stack->stakes.vote_map_mem, chain_cnt, seed ) ) ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: bad map" ));
    return NULL;
  }
  return shmem;
}

FD_FN_CONST static inline fd_runtime_stack_t *
fd_runtime_stack_join( void * shruntime_stack ) {
  return (fd_runtime_stack_t *)shruntime_stack;
}

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h */
