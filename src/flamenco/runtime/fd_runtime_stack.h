#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h

#include "sysvar/fd_sysvar_clock.h"
#include "program/fd_builtin_programs.h"
#include "../leaders/fd_leaders_base.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"

/* https://github.com/anza-xyz/agave/blob/cbc8320d35358da14d79ebcada4dfb6756ffac79/programs/stake/src/points.rs#L27 */
struct fd_calculated_stake_points {
  fd_w_u128_t points;
  ulong       new_credits_observed;
  uint        vote_idx; /* Caches this delegation's vote_rewards_map index.  UINT_MAX if the
                           vote account is not in the rewards map.  Not populated during
                           recalculation due to lack of the points phase. */
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

struct fd_vote_rewards {
  fd_pubkey_t pubkey;
  ulong       vote_rewards;
  uint        next;
  ushort      commission;
};
typedef struct fd_vote_rewards fd_vote_rewards_t;

#define MAP_NAME               fd_vote_rewards_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_vote_rewards_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (seed)^FD_LOAD( ulong, ((uchar const *)(key))+24UL ) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

struct fd_stake_accum {
  fd_pubkey_t pubkey;
  ulong       stake;        /* effective stake in the current epoch */
  ulong       reward_stake; /* effective stake in the rewarded epoch */
  uint        next;
};
typedef struct fd_stake_accum fd_stake_accum_t;

#define MAP_NAME               fd_stake_accum_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_accum_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_ulong_hash( (seed)^FD_LOAD( ulong, ((uchar const *)(key))+24UL ) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

/* fd_bpf_migration_stack_t is staging memory for bpf migration.  This
   is used to store and stage various accounts which is required for
   deploying a new BPF program at the epoch boundary.

   It does not get dedicated memory: it overlays the stakes
   points/rewards result arrays.  Migrations run at an epoch boundary
   strictly before those arrays are (re)filled by the rewards
   calculation at the same boundary, and rewards distribution
   (which re-derives from those arrays) completes within the first
   num_partitions blocks of an epoch, long before another boundary can
   run a migration.  The migration entry points FD_TEST that no
   distribution is in flight. */
struct fd_bpf_migration_stack {
  fd_tmp_account_t source;
  fd_tmp_account_t program_account;
  fd_tmp_account_t new_target_program;
  fd_tmp_account_t new_target_program_data;
  fd_tmp_account_t empty;

  /* Staging memory for ELF validation during BPF program
     migrations. */
  struct {
    uchar rodata        [ FD_RUNTIME_ACC_SZ_MAX     ] __attribute__((aligned(FD_SBPF_PROG_RODATA_ALIGN)));
    uchar sbpf_footprint[ FD_SBPF_PROGRAM_FOOTPRINT ] __attribute__((aligned(alignof(fd_sbpf_program_t))));
    uchar programdata   [ FD_RUNTIME_ACC_SZ_MAX     ] __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
  } progcache_validate;
};
typedef struct fd_bpf_migration_stack fd_bpf_migration_stack_t;

/* fd_runtime_stack_t serves as stack memory to store temporary data
   for the runtime.  This object should only be used and owned by the
   replay tile and is used for short-lived allocations for the runtime,
   more specifically, for slot level calculations. */
struct fd_runtime_stack {

  ulong max_vote_accounts;
  ulong max_staked_vote_accounts;
  ulong max_stake_accounts;

  struct {
    /* Staging memory to sort vote accounts by last vote timestamp for
       clock sysvar calculation. */
    ts_est_ele_t * staked_ts;
  } clock_ts;

  /* Overlays stakes.stake_points_result/stake_rewards_result, see
     above. */
  fd_bpf_migration_stack_t * bpf_migration;

  struct {
    fd_calculated_stake_points_t *  stake_points_result;

    fd_calculated_stake_rewards_t * stake_rewards_result;

    fd_stake_accum_t *     stake_accum;
    fd_stake_accum_map_t * stake_accum_map;

    fd_vote_rewards_t *     vote_ele;
    fd_vote_rewards_map_t * vote_map;

    ulong       total_rewards;
    ulong       distributed_rewards;
    fd_w_u128_t total_points;

    ulong stake_rewards_cnt;

    /* Staging memory used for calculating and sorting vote account
       stake weights for the leader schedule calculation. */
    fd_vote_stake_weight_t * stake_weights;
    fd_stake_weight_t *      id_weights;

  } stakes;

  struct {
    fd_vote_stake_weight_t stake_weights[ MAX_STAKE_WEIGHTS ];
    ulong                  stake_weights_cnt;

    fd_stake_weight_t      id_weights[ MAX_STAKE_WEIGHTS ];
    ulong                  id_weights_cnt;

    fd_vote_stake_weight_t next_stake_weights[ MAX_STAKE_WEIGHTS ];
    ulong                  next_stake_weights_cnt;

    fd_stake_weight_t      next_id_weights[ MAX_STAKE_WEIGHTS ];
    ulong                  next_id_weights_cnt;
  } epoch_weights;
};
typedef struct fd_runtime_stack fd_runtime_stack_t;

FD_FN_CONST static inline ulong
fd_runtime_stack_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
fd_runtime_stack_points_rewards_overlay_sz( ulong max_stake_accounts ) {
  /* bpf_migration staging shares memory with the points/rewards result
     arrays (see fd_bpf_migration_stack_t).  The max() keeps small
     configurations (test harnesses with few stake accounts) safe: the
     region is never smaller than the migration staging. */
  ulong points_sz  = sizeof(fd_calculated_stake_points_t) * max_stake_accounts;
  ulong rewards_sz = sizeof(fd_calculated_stake_rewards_t) * max_stake_accounts;
  return fd_ulong_max( points_sz + rewards_sz, sizeof(fd_bpf_migration_stack_t) );
}

FD_FN_PURE static inline ulong
fd_runtime_stack_footprint( ulong max_vote_accounts,
                            ulong max_staked_vote_accounts,
                            ulong max_stake_accounts ) {
  ulong vote_chain_cnt  = fd_vote_rewards_map_chain_cnt_est( max_vote_accounts );
  ulong stake_chain_cnt = fd_stake_accum_map_chain_cnt_est( max_staked_vote_accounts );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_runtime_stack_t),           sizeof(fd_runtime_stack_t) );
  l = FD_LAYOUT_APPEND( l, alignof(ts_est_ele_t),                 sizeof(ts_est_ele_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, alignof(fd_vote_stake_weight_t),       sizeof(fd_vote_stake_weight_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, alignof(fd_stake_weight_t),            sizeof(fd_stake_weight_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, 128UL,                                 sizeof(fd_vote_rewards_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, fd_vote_rewards_map_align(),           fd_vote_rewards_map_footprint( vote_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, 128UL,                                 sizeof(fd_stake_accum_t) * max_staked_vote_accounts );
  l = FD_LAYOUT_APPEND( l, fd_stake_accum_map_align(),            fd_stake_accum_map_footprint( stake_chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, 128UL,                                 fd_runtime_stack_points_rewards_overlay_sz( max_stake_accounts ) );
  return FD_LAYOUT_FINI( l, fd_runtime_stack_align() );
}

static inline void *
fd_runtime_stack_new( void * shmem,
                      ulong  max_vote_accounts,
                      ulong  max_staked_vote_accounts,
                      ulong  max_stake_accounts,
                      ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) return NULL;
  ulong vote_chain_cnt  = fd_vote_rewards_map_chain_cnt_est( max_vote_accounts );
  ulong stake_chain_cnt = fd_stake_accum_map_chain_cnt_est( max_staked_vote_accounts );
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_runtime_stack_t *            runtime_stack        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_runtime_stack_t),            sizeof(fd_runtime_stack_t) );
  ts_est_ele_t *                  staked_ts            = FD_SCRATCH_ALLOC_APPEND( l, alignof(ts_est_ele_t),                  sizeof(ts_est_ele_t) * max_vote_accounts );
  fd_vote_stake_weight_t *        stake_weights        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_vote_stake_weight_t),        sizeof(fd_vote_stake_weight_t) * max_vote_accounts );
  fd_stake_weight_t *             id_weights           = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stake_weight_t),             sizeof(fd_stake_weight_t) * max_vote_accounts );
  fd_vote_rewards_t *             vote_ele             = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  sizeof(fd_vote_rewards_t) * max_vote_accounts );
  void *                          vote_map_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_rewards_map_align(),            fd_vote_rewards_map_footprint( vote_chain_cnt ) );
  fd_stake_accum_t *              stake_accum          = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  sizeof(fd_stake_accum_t) * max_staked_vote_accounts );
  void *                          stake_accum_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_accum_map_align(),             fd_stake_accum_map_footprint( stake_chain_cnt ) );
  uchar *                         overlay_mem          = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  fd_runtime_stack_points_rewards_overlay_sz( max_stake_accounts ) );
  fd_calculated_stake_points_t *  stake_points_result  = (fd_calculated_stake_points_t *)overlay_mem;
  fd_calculated_stake_rewards_t * stake_rewards_result = (fd_calculated_stake_rewards_t *)(overlay_mem + sizeof(fd_calculated_stake_points_t)*max_stake_accounts);
  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_runtime_stack_align() )!=(ulong)shmem + fd_runtime_stack_footprint( max_vote_accounts, max_staked_vote_accounts, max_stake_accounts ) ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: bad layout" ));
    return NULL;
  }

  runtime_stack->bpf_migration               = (fd_bpf_migration_stack_t *)overlay_mem;
  runtime_stack->max_vote_accounts           = max_vote_accounts;
  runtime_stack->max_staked_vote_accounts    = max_staked_vote_accounts;
  runtime_stack->max_stake_accounts          = max_stake_accounts;
  runtime_stack->clock_ts.staked_ts          = staked_ts;
  runtime_stack->stakes.stake_weights        = stake_weights;
  runtime_stack->stakes.id_weights           = id_weights;
  runtime_stack->stakes.vote_ele             = vote_ele;
  runtime_stack->stakes.stake_points_result  = stake_points_result;
  runtime_stack->stakes.stake_rewards_result = stake_rewards_result;
  runtime_stack->stakes.stake_accum          = stake_accum;

  runtime_stack->stakes.stake_accum_map = fd_stake_accum_map_join( fd_stake_accum_map_new( stake_accum_map_mem, stake_chain_cnt, seed ) );
  if( FD_UNLIKELY( !runtime_stack->stakes.stake_accum_map ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: bad map" ));
    return NULL;
  }

  runtime_stack->stakes.vote_map = fd_vote_rewards_map_join( fd_vote_rewards_map_new( vote_map_mem, vote_chain_cnt, seed ) );
  if( FD_UNLIKELY( !runtime_stack->stakes.vote_map ) ) {
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
