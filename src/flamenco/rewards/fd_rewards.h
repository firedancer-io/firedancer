#ifndef HEADER_fd_src_flamenco_runtime_program_fd_reward_h
#define HEADER_fd_src_flamenco_runtime_program_fd_reward_h

#include "../fd_flamenco_base.h"
#include "fd_rewards_base.h"
#include "../types/fd_types.h"

FD_PROTOTYPES_BEGIN

void
fd_begin_partitioned_rewards( fd_exec_slot_ctx_t * slot_ctx,
                              fd_hash_t const *    parent_blockhash,
                              ulong                parent_epoch,
                              fd_epoch_info_t *    temp_info,
                              fd_spad_t *          runtime_spad );

void
fd_rewards_recalculate_partitioned_rewards( fd_exec_slot_ctx_t * slot_ctx,
                                            fd_spad_t *          runtime_spad );

void
fd_distribute_partitioned_epoch_rewards( fd_exec_slot_ctx_t * slot_ctx );

FD_PROTOTYPES_END

#endif
