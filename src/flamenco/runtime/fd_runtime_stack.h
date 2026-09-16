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
  uchar       inactive;
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

struct fd_vote_rewards_map_private;
typedef struct fd_vote_rewards_map_private fd_vote_rewards_map_t;

struct fd_stake_accum {
  fd_pubkey_t pubkey;
  ulong       stake;        /* effective stake in the current epoch */
  ulong       reward_stake; /* effective stake in the rewarded epoch */
  uint        next;
};
typedef struct fd_stake_accum fd_stake_accum_t;

/* fd_map_chain over fd_stake_accum_t, instantiated in fd_runtime_stack_tmpl.h */

struct fd_stake_accum_map_private;
typedef struct fd_stake_accum_map_private fd_stake_accum_map_t;

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

  struct {
    /* Staging memory for bpf migration.  This is used to store and
       stage various accounts which is required for deploying a new BPF
       program at the epoch boundary.

       TODO: These are only used by the replay tile on epoch boundaries
       and don't need to be in the per-exec stacks.  Additionally, we
       could just acquire these buffers out of the account database
       directly to share them across tiles using the existing flexible
       buffer management. */
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

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h */
