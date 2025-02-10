#ifndef HEADER_fd_src_flamenco_runtime_program_fd_reward_h
#define HEADER_fd_src_flamenco_runtime_program_fd_reward_h

#include "../fd_flamenco_base.h"
#include "../runtime/context/fd_exec_instr_ctx.h"
#include "../runtime/program/fd_stake_program.h"
#include "../runtime/program/fd_vote_program.h"
#include "../runtime/sysvar/fd_sysvar.h"
#include "../runtime/sysvar/fd_sysvar_epoch_rewards.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../stakes/fd_stakes.h"

FD_PROTOTYPES_BEGIN

struct fd_calculate_points_task_args {
  fd_stake_history_t const *      stake_history;
  ulong *                         new_warmup_cooldown_rate_epoch;
  ulong                           minimum_stake_delegation;
  fd_vote_info_pair_t_mapnode_t * vote_states_root;
  fd_vote_info_pair_t_mapnode_t * vote_states_pool;
  uint128 *                       total_points; // out field
};
typedef struct fd_calculate_points_task_args fd_calculate_points_task_args_t;

struct fd_calculate_stake_vote_rewards_task_args {
  fd_exec_slot_ctx_t *                       slot_ctx;
  fd_stake_history_t const *                 stake_history;
  ulong                                      rewarded_epoch;
  ulong *                                    new_warmup_cooldown_rate_epoch;
  fd_point_value_t *                         point_value;
  fd_calculate_stake_vote_rewards_result_t * result;
  fd_spad_t * *                              exec_spads;
  ulong                                      exec_spad_cnt;
};
typedef struct fd_calculate_stake_vote_rewards_task_args fd_calculate_stake_vote_rewards_task_args_t;

void
fd_update_rewards( fd_exec_slot_ctx_t * slot_ctx,
                   fd_hash_t const *    parent_blockhash,
                   ulong                parent_epoch,
                   fd_epoch_info_t *    temp_info,
                   fd_tpool_t *         tpool,
                   fd_spad_t * *        exec_spads,
                   ulong                exec_spad_cnt,
                   fd_spad_t *          runtime_spad );

void
fd_begin_partitioned_rewards( fd_exec_slot_ctx_t * slot_ctx,
                              fd_hash_t const *    parent_blockhash,
                              ulong                parent_epoch,
                              fd_epoch_info_t *    temp_info,
                              fd_tpool_t *         tpool,
                              fd_spad_t * *        exec_spads,
                              ulong                exec_spad_cnt,
                              fd_spad_t *          runtime_spad );

void
fd_rewards_recalculate_partitioned_rewards( fd_exec_slot_ctx_t * slot_ctx,
                                            fd_tpool_t *         tpool,
                                            fd_spad_t * *        exec_spads,
                                            ulong                exec_spad_cnt,
                                            fd_spad_t *          runtime_spad );

void
fd_distribute_partitioned_epoch_rewards( fd_exec_slot_ctx_t * slot_ctx,
                                         fd_tpool_t *         tpool,
                                         fd_spad_t * *        exec_spads,
                                         ulong                exec_spad_cnt,
                                         fd_spad_t *          runtime_spad );

FD_PROTOTYPES_END

#endif
