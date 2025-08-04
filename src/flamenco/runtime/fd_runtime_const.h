#ifndef HEADER_fd_src_flamenco_runtime_fd_runtime_const_h
#define HEADER_fd_src_flamenco_runtime_fd_runtime_const_h

#include "../types/fd_types.h"
#include "../leaders/fd_leaders.h"

FD_PROTOTYPES_BEGIN

/* All of the variable bounds in the bank should be deteremined by the
   max number of vote accounts and stake accounts that the system
   supports. */
#define FD_RUNTIME_MAX_VOTE_ACCOUNTS  (100000UL)  /* 100k vote accounts */
#define FD_RUNTIME_MAX_STAKE_ACCOUNTS (3000000UL) /* 3M stake accounts */

#define FD_RUNTIME_SLOTS_PER_EPOCH    (432000UL)  /* 432k slots per epoch */

#define FD_RUNTIME_MAX_EPOCH_LEADERS (FD_EPOCH_LEADERS_FOOTPRINT(FD_RUNTIME_MAX_VOTE_ACCOUNTS, FD_RUNTIME_SLOTS_PER_EPOCH))

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_runtime_const_h */
