#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h

#include "../types/fd_types_custom.h"
#include "../leaders/fd_leaders_base.h"
#include "sysvar/fd_sysvar_clock.h"
#include "program/fd_builtin_programs.h"
#include "fd_runtime_const.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"

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
  ulong  base_credits;
  ushort epoch             [ FD_EPOCH_CREDITS_MAX ];
  uint   credits_delta     [ FD_EPOCH_CREDITS_MAX ];
  uint   prev_credits_delta[ FD_EPOCH_CREDITS_MAX ];
};
typedef struct fd_epoch_credits fd_epoch_credits_t;

struct fd_vote_rewards {
  fd_pubkey_t pubkey;
  ulong       vote_rewards;
  uint        next;
  uchar       commission_t_1;
  uchar       commission_t_2;
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

struct fd_stake_accum {
  fd_pubkey_t pubkey;
  ulong       stake;
  uint        next;
};
typedef struct fd_stake_accum fd_stake_accum_t;

#define MAP_NAME               fd_stake_accum_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stake_accum_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

/* fd_runtime_stack_t serves as stack memory to store temporary data
   for the runtime.  This object lives in shared topology memory and
   is used by both the snapin tile (during snapshot loading) and the
   replay tile (during block execution) for short-lived allocations,
   more specifically, for slot level calculations. */
struct fd_runtime_stack {

  ulong max_vote_accounts;
  ulong expected_vote_accounts;
  ulong expected_stake_accounts;

  struct {
    /* Staging memory to sort vote accounts by last vote timestamp for
       clock sysvar calculation. */
    ulong staked_ts_off;
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

    /* Staging memory for ELF validation during BPF program
       migrations. */
    struct {
      uchar rodata        [ FD_RUNTIME_ACC_SZ_MAX     ] __attribute__((aligned(FD_SBPF_PROG_RODATA_ALIGN)));
      uchar sbpf_footprint[ FD_SBPF_PROGRAM_FOOTPRINT ] __attribute__((aligned(alignof(fd_sbpf_program_t))));
      uchar programdata   [ FD_RUNTIME_ACC_SZ_MAX     ] __attribute__((aligned(FD_ACCOUNT_REC_ALIGN)));
    } progcache_validate;
  } bpf_migration;

  struct {
    ulong stake_points_result_off;
    ulong stake_rewards_result_off;

    ulong stake_accum_off;
    ulong stake_accum_map_off;

    ulong vote_ele_off;
    ulong vote_map_off;

    ulong       total_rewards;
    ulong       distributed_rewards;
    fd_w_u128_t total_points;

    ulong stake_rewards_cnt;

    /* Staging memory used for calculating and sorting vote account
       stake weights for the leader schedule calculation. */
    ulong stake_weights_off;
    ulong id_weights_off;

    ulong epoch_credits_off;

  } stakes;

  struct {
    fd_vote_stake_weight_t stake_weights[ MAX_COMPRESSED_STAKE_WEIGHTS ];
    ulong                  stake_weights_cnt;

    fd_stake_weight_t      id_weights[ MAX_SHRED_DESTS ];
    ulong                  id_weights_cnt;
    ulong                  id_weights_excluded;

    fd_vote_stake_weight_t next_stake_weights[ MAX_COMPRESSED_STAKE_WEIGHTS ];
    ulong                  next_stake_weights_cnt;

    fd_stake_weight_t      next_id_weights[ MAX_SHRED_DESTS ];
    ulong                  next_id_weights_cnt;
    ulong                  next_id_weights_excluded;
  } epoch_weights;
};
typedef struct fd_runtime_stack fd_runtime_stack_t;

/* Accessor functions to resolve offsets to pointers.  These are
   position-independent: each tile computes absolute pointers from
   its own mapping of the shared workspace. */

static inline ts_est_ele_t *
fd_runtime_stack_staked_ts( fd_runtime_stack_t * rs ) {
  return (ts_est_ele_t *)((uchar *)rs + rs->clock_ts.staked_ts_off);
}

static inline fd_calculated_stake_points_t *
fd_runtime_stack_stake_points_result( fd_runtime_stack_t * rs ) {
  return (fd_calculated_stake_points_t *)((uchar *)rs + rs->stakes.stake_points_result_off);
}

static inline fd_calculated_stake_rewards_t *
fd_runtime_stack_stake_rewards_result( fd_runtime_stack_t * rs ) {
  return (fd_calculated_stake_rewards_t *)((uchar *)rs + rs->stakes.stake_rewards_result_off);
}

static inline fd_stake_accum_t *
fd_runtime_stack_stake_accum( fd_runtime_stack_t * rs ) {
  return (fd_stake_accum_t *)((uchar *)rs + rs->stakes.stake_accum_off);
}

static inline fd_stake_accum_map_t *
fd_runtime_stack_stake_accum_map( fd_runtime_stack_t * rs ) {
  return (fd_stake_accum_map_t *)((uchar *)rs + rs->stakes.stake_accum_map_off);
}

static inline fd_vote_rewards_t *
fd_runtime_stack_vote_ele( fd_runtime_stack_t * rs ) {
  return (fd_vote_rewards_t *)((uchar *)rs + rs->stakes.vote_ele_off);
}

static inline fd_vote_rewards_map_t *
fd_runtime_stack_vote_map( fd_runtime_stack_t * rs ) {
  return (fd_vote_rewards_map_t *)((uchar *)rs + rs->stakes.vote_map_off);
}

static inline fd_vote_stake_weight_t *
fd_runtime_stack_stake_weights( fd_runtime_stack_t * rs ) {
  return (fd_vote_stake_weight_t *)((uchar *)rs + rs->stakes.stake_weights_off);
}

static inline fd_stake_weight_t *
fd_runtime_stack_id_weights( fd_runtime_stack_t * rs ) {
  return (fd_stake_weight_t *)((uchar *)rs + rs->stakes.id_weights_off);
}

static inline fd_epoch_credits_t *
fd_runtime_stack_epoch_credits( fd_runtime_stack_t * rs ) {
  return (fd_epoch_credits_t *)((uchar *)rs + rs->stakes.epoch_credits_off);
}

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
  l = FD_LAYOUT_APPEND( l, alignof(fd_stake_weight_t),            sizeof(fd_stake_weight_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, 128UL,                                 sizeof(fd_vote_rewards_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, fd_vote_rewards_map_align(),           fd_vote_rewards_map_footprint( chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, 128UL,                                 sizeof(fd_stake_accum_t) * max_vote_accounts );
  l = FD_LAYOUT_APPEND( l, fd_stake_accum_map_align(),            fd_stake_accum_map_footprint( chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_epoch_credits_t),           sizeof(fd_epoch_credits_t) * max_vote_accounts );
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
  fd_stake_weight_t *             id_weights           = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stake_weight_t),             sizeof(fd_stake_weight_t) * max_vote_accounts );
  fd_vote_rewards_t *             vote_ele             = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  sizeof(fd_vote_rewards_t) * max_vote_accounts );
  void *                          vote_map_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_rewards_map_align(),            fd_vote_rewards_map_footprint( chain_cnt ) );
  fd_stake_accum_t *              stake_accum          = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                                  sizeof(fd_stake_accum_t) * max_vote_accounts );
  void *                          stake_accum_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_stake_accum_map_align(),             fd_stake_accum_map_footprint( chain_cnt ) );
  fd_epoch_credits_t *            epoch_credits        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_epoch_credits_t),            sizeof(fd_epoch_credits_t) * max_vote_accounts );
  fd_calculated_stake_points_t *  stake_points_result  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_calculated_stake_points_t),  sizeof(fd_calculated_stake_points_t) * expected_stake_accounts );
  fd_calculated_stake_rewards_t * stake_rewards_result = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_calculated_stake_rewards_t), sizeof(fd_calculated_stake_rewards_t) * expected_stake_accounts );
  if( FD_UNLIKELY( FD_SCRATCH_ALLOC_FINI( l, fd_runtime_stack_align() )!=(ulong)shmem + fd_runtime_stack_footprint( max_vote_accounts, expected_vote_accounts, expected_stake_accounts ) ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: bad layout" ));
    return NULL;
  }

  runtime_stack->max_vote_accounts           = max_vote_accounts;
  runtime_stack->expected_vote_accounts      = expected_vote_accounts;
  runtime_stack->expected_stake_accounts     = expected_stake_accounts;

  /* Store position-independent offsets from the struct base.  These
     remain valid regardless of the virtual address at which the
     workspace is mapped. */

  runtime_stack->clock_ts.staked_ts_off          = (ulong)((uchar *)staked_ts            - (uchar *)runtime_stack);
  runtime_stack->stakes.stake_weights_off        = (ulong)((uchar *)stake_weights        - (uchar *)runtime_stack);
  runtime_stack->stakes.id_weights_off           = (ulong)((uchar *)id_weights           - (uchar *)runtime_stack);
  runtime_stack->stakes.vote_ele_off             = (ulong)((uchar *)vote_ele             - (uchar *)runtime_stack);
  runtime_stack->stakes.epoch_credits_off        = (ulong)((uchar *)epoch_credits        - (uchar *)runtime_stack);
  runtime_stack->stakes.stake_points_result_off  = (ulong)((uchar *)stake_points_result  - (uchar *)runtime_stack);
  runtime_stack->stakes.stake_rewards_result_off = (ulong)((uchar *)stake_rewards_result - (uchar *)runtime_stack);
  runtime_stack->stakes.stake_accum_off          = (ulong)((uchar *)stake_accum          - (uchar *)runtime_stack);
  runtime_stack->stakes.stake_accum_map_off      = (ulong)((uchar *)stake_accum_map_mem  - (uchar *)runtime_stack);
  runtime_stack->stakes.vote_map_off             = (ulong)((uchar *)vote_map_mem         - (uchar *)runtime_stack);

  /* Initialize the map data structures in-place. */

  if( FD_UNLIKELY( !fd_stake_accum_map_new( stake_accum_map_mem, chain_cnt, seed ) ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: bad map" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_vote_rewards_map_new( vote_map_mem, chain_cnt, seed ) ) ) {
    FD_LOG_WARNING(( "fd_runtime_stack_new: bad map" ));
    return NULL;
  }

  return shmem;
}

FD_FN_CONST static inline fd_runtime_stack_t *
fd_runtime_stack_join( void * shmem ) {
  return (fd_runtime_stack_t *)shmem;
}

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h */
