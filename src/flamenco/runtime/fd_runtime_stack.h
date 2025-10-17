#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h

#include "fd_runtime_const.h"
#include "../types/fd_types_custom.h"
#include "sysvar/fd_sysvar_clock.h"

FD_PROTOTYPES_BEGIN


/* fd_runtime_stack_t serves as stack memory to store temporary data
   for the runtime.  This object should only be used and owned by the
   replay tile and is used for short-lived allocations for the runtime,
   more specifically, for slot level calculations. */
union fd_runtime_stack {
  struct {
    /* Staging memory used for calculating and sorting vote account
       stake weights for the leader schedule calculation. */
    fd_vote_stake_weight_t mem[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];
  } leader_weights;

  struct {
    /* Staging memory to sort vote accounts by last vote timestamp for
       clock sysvar calculation. */
    ts_est_ele_t mem[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];
  } clock_ts;

  struct {
    /* Staging memory for bpf migration. */
    #define MIGRATION_ACCOUNT_FOOTPRINT (10485856UL)
    #define MIGRATION_ACCOUNT_ALIGN     (8UL)
    uchar source                 [ MIGRATION_ACCOUNT_FOOTPRINT ]__attribute__((aligned(MIGRATION_ACCOUNT_ALIGN)));
    uchar program_account        [ MIGRATION_ACCOUNT_FOOTPRINT ]__attribute__((aligned(MIGRATION_ACCOUNT_ALIGN)));
    uchar new_target_program     [ MIGRATION_ACCOUNT_FOOTPRINT ]__attribute__((aligned(MIGRATION_ACCOUNT_ALIGN)));
    uchar new_target_program_data[ MIGRATION_ACCOUNT_FOOTPRINT ]__attribute__((aligned(MIGRATION_ACCOUNT_ALIGN)));
    uchar empty                  [ MIGRATION_ACCOUNT_FOOTPRINT ]__attribute__((aligned(MIGRATION_ACCOUNT_ALIGN)));
  } bpf_migration;

  /* TODO: Move epoch credits for recalculation into this struct.
     TODO: Move rewards staging into this struct.
     This is not being done at the moment because there is an in-flight
     PR that refactors these fields for rewards calculation. */
};
typedef union fd_runtime_stack fd_runtime_stack_t;

union fd_exec_stack {
  struct {
    uchar mem[ FD_RUNTIME_WRITABLE_ACCOUNTS_MAX ][ FD_RUNTIME_ACC_SZ_MAX ]__attribute__((aligned(8UL)));
  } accounts;
};
typedef union fd_exec_stack fd_exec_stack_t;

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h */
