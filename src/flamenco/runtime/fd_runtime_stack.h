#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h

#include "../types/fd_types_custom.h"
#include "../stakes/fd_vote_states.h"
#include "sysvar/fd_sysvar_clock.h"
#include "program/fd_builtin_programs.h"
#include "fd_runtime_const.h"

/* fd_runtime_stack_t serves as stack memory to store temporary data
   for the runtime.  This object should only be used and owned by the
   replay tile and is used for short-lived allocations for the runtime,
   more specifically, for slot level calculations. */
union fd_runtime_stack {

  struct {
    /* Staging memory to sort vote accounts by last vote timestamp for
       clock sysvar calculation. */
    ts_est_ele_t staked_ts[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];
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

    /* Vote state credits as of the end of the previous epoch.  This
       only used at boot to recalculate partitioned epoch rewards if
       needed and is not updated after. */
    int                     prev_vote_credits_used;
    fd_vote_state_credits_t vote_credits[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];

    /* Staging memory for vote rewards as they are accumulated. */
    ulong                   vote_rewards[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];

    /* Staging memory used for calculating and sorting vote account
       stake weights for the leader schedule calculation. */
    fd_vote_stake_weight_t  stake_weights[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];
  } stakes;
};
typedef union fd_runtime_stack fd_runtime_stack_t;

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h */
