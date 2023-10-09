#ifndef HEADER_fd_src_flamenco_runtime_program_fd_reward_h
#define HEADER_fd_src_flamenco_runtime_program_fd_reward_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include "../runtime/sysvar/fd_sysvar.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../runtime/sysvar/fd_sysvar_epoch_rewards.h"
#include "../stakes/fd_stakes.h"
#include "../stakes/fd_stake_program.h"
#include "../runtime/program/fd_vote_program.h"
#include "../../ballet/siphash13/fd_siphash13.h"
#include "../runtime/context/fd_exec_instr_ctx.h"


FD_PROTOTYPES_BEGIN

void
update_rewards(
  fd_exec_slot_ctx_t * slot_ctx,
  ulong prev_epoch
);

void
begin_partitioned_rewards(
    fd_firedancer_banks_t * self,
    fd_exec_slot_ctx_t * slot_ctx,
    ulong parent_epoch
);

void
distribute_partitioned_epoch_rewards(
    fd_firedancer_banks_t * self,
    fd_exec_slot_ctx_t * slot_ctx
);

FD_PROTOTYPES_END

#endif
