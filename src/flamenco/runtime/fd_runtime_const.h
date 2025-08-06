#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_const_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_const_h

#include "../types/fd_types.h"
#include "../leaders/fd_leaders.h"

FD_PROTOTYPES_BEGIN

/* All of the variable bounds in the bank should be deteremined by the
   max number of vote accounts and stake accounts that the system
   supports. These are not protocol-level bounds, but rather bounds
   that are used to determine the max amount of memory that various
   data structures require. */
#define FD_RUNTIME_MAX_VOTE_ACCOUNTS      (40200UL)   /* ~40k vote accounts */
#define FD_RUNTIME_MAX_STAKE_ACCOUNTS     (3000000UL) /* 3M stake accounts */
/* There can be 8192 stake account modifications per slot. This is
   because there can be up to STAKE_ACCOUNT_STORES_PER_BLOCK (4096)
   stake accounts in a rewards partition and there can be up to
   FD_WRITABLE_ACCOUNTS_PER_BLOCK (4096) writable accounts per slot.
   So in the worst case, a slot can have 4096 stake accounts recieving
   rewards and all 4096 writable accounts in a slot are stake accounts
   being written to. */
#define FD_RUNTIME_MAX_STAKE_ACCS_IN_SLOT (8192UL)

#define FD_RUNTIME_SLOTS_PER_EPOCH        (432000UL)  /* 432k slots per epoch */

#define FD_RUNTIME_MAX_EPOCH_LEADERS      (FD_EPOCH_LEADERS_FOOTPRINT(FD_RUNTIME_MAX_VOTE_ACCOUNTS, FD_RUNTIME_SLOTS_PER_EPOCH))

/* The initial block id hash is a dummy value for the initial block id
   as one is not provided in snapshots. This does not have an
   equivalent in Agave.

   TODO: This should be removed in favor of repairing the last shred of
   the snapshot slot to get the actual block id of the snapshot slot. */
#define FD_RUNTIME_INITIAL_BLOCK_ID       (0xF17EDA2CE7B1DUL)

#define FD_RUNTIME_ACC_SZ_MAX             (10UL<<20) /* Account data is bounded by 10MiB */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_const_h */
