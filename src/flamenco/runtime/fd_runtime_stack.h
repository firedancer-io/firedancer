#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h

#include "../types/fd_types_custom.h"
#include "../stakes/fd_vote_states.h"
#include "sysvar/fd_sysvar_clock.h"
#include "program/fd_builtin_programs.h"
#include "fd_runtime_const.h"

struct fd_stakes_staging {
  fd_pubkey_t pubkey;
  ulong       stake;
  uint        next;
  uchar       invalid;
};
typedef struct fd_stakes_staging fd_stakes_staging_t;

#define MAP_NAME               fd_stakes_staging_map
#define MAP_KEY_T              fd_pubkey_t
#define MAP_ELE_T              fd_stakes_staging_t
#define MAP_KEY                pubkey
#define MAP_KEY_EQ(k0,k1)      (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( seed, key, sizeof(fd_pubkey_t) ))
#define MAP_NEXT               next
#define MAP_IDX_T              uint
#include "../../util/tmpl/fd_map_chain.c"

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

    /* Staging memory for the epoch credits and the commission for each
       vote account.  This is populated during snapshot loading in case
       of reward recalculation or during the epoch boundary. */
    fd_vote_state_credits_t vote_credits[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];

    /* Staging memory for vote rewards as they are accumulated. */
    ulong                   vote_rewards[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];

    /* Staging memory used for calculating and sorting vote account
       stake weights for the leader schedule calculation. */
    fd_vote_stake_weight_t  stake_weights[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];

    ulong                   stakes_staging_cnt;
    fd_stakes_staging_t     stakes_staging[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];
    uchar                   stakes_staging_map[ 8216 ] __attribute__((aligned(128)));

  } stakes;

  struct {
    /* List of vote state pool pubkeys that correspond to vote accounts
       that are stale entries.  The vote states cache is originally
       populated from the snapshot manifest and can't check against the
       accounts database so it may contain stale entries.  These vote
       accounts must be removed from the vote states cache. */
    fd_pubkey_t stale_accs[ FD_RUNTIME_MAX_VOTE_ACCOUNTS ];
  } vote_accounts;
};
typedef union fd_runtime_stack fd_runtime_stack_t;

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_stack_h */
