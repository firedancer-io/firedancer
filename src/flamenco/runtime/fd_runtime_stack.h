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
  ulong block_reward; /* SIMD-0123 share of the vote account pending delegator rewards */
  uchar success;
};
typedef struct fd_calculated_stake_rewards fd_calculated_stake_rewards_t;

/* A delegation's points are only read while computing its rewards,
   which then overwrite them. */
union fd_calculated_stake_result {
  fd_calculated_stake_points_t  points;
  fd_calculated_stake_rewards_t rewards;
};
typedef union fd_calculated_stake_result fd_calculated_stake_result_t;

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

/* Voters beyond the stake_accum RAM map spill to this unlinked file
   (pread/pwrite, replay only). */

#define FD_STAKE_ACCUM_FD (123448)

struct fd_stake_accum_map_private;
typedef struct fd_stake_accum_map_private fd_stake_accum_map_t;

/* Staging memory for bpf migration.  This is used to store and stage
   various accounts which is required for deploying a new BPF program at
   the epoch boundary.

   TODO: We could just acquire these buffers out of the account database
   directly to share them across tiles using the existing flexible
   buffer management. */

struct fd_runtime_stack_bpf_migration {
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
typedef struct fd_runtime_stack_bpf_migration fd_runtime_stack_bpf_migration_t;

/* fd_runtime_stack_t serves as stack memory to store temporary data
   for the runtime.  This object should only be used and owned by the
   replay tile and is used for short-lived allocations for the runtime,
   more specifically, for slot level calculations. */
struct fd_runtime_stack {

  ulong max_vote_accounts;
  ulong max_staked_vote_accounts;
  ulong max_stake_accounts;

  /* Overlaps stakes.stake_accum and stakes.stake_results.  Migrations
     finish at the epoch boundary before either is filled.  Every user
     of stake_accum resets its map first, and stake_results is written
     before it is read within each rewards call. */
  fd_runtime_stack_bpf_migration_t * bpf_migration;

  struct {
    fd_calculated_stake_result_t * stake_results;

    fd_stake_accum_t *     stake_accum;
    fd_stake_accum_map_t * stake_accum_map;

    ulong stake_accum_cnt; /* RAM pool entries in use */

    /* stake_accum overflow table in stake_accum_fd: bucket_cnt buckets
       then spill_max dense records.  fd -1: no spill. */
    int   stake_accum_fd;
    uint  stake_accum_spill_gen;
    ulong stake_accum_spill_max;
    ulong stake_accum_spill_cnt;
    ulong stake_accum_spill_bucket_cnt;

    fd_vote_rewards_t *     vote_ele;
    fd_vote_rewards_map_t * vote_map;

    ulong       total_rewards;
    ulong       distributed_rewards;
    ulong       block_rewards; /* SIMD-0123 pending delegator rewards swept out of vote accounts at the boundary */

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

FD_PROTOTYPES_BEGIN

/* Out-of-line spill paths of the stake accumulator (see
   fd_runtime_stack_tmpl.h).  Only reached once more than the RAM map's
   capacity of distinct voters were accumulated. */

fd_stake_accum_t *
fd_runtime_stack_stake_accum_spill_query( fd_runtime_stack_t * runtime_stack,
                                          fd_pubkey_t const *  key,
                                          fd_stake_accum_t *   scratch );

void
fd_runtime_stack_stake_accum_spill_add( fd_runtime_stack_t * runtime_stack,
                                        fd_pubkey_t const *  key,
                                        ulong                stake,
                                        ulong                reward_stake );

void
fd_runtime_stack_stake_accum_spill_read( fd_runtime_stack_t const * runtime_stack,
                                         ulong                      idx,
                                         fd_stake_accum_t *         out,
                                         ulong                      cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h */
