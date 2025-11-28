#ifndef HEADER_fd_src_choreo_tower_fd_tower_accts_h
#define HEADER_fd_src_choreo_tower_fd_tower_accts_h

#include "../fd_choreo_base.h"

#define FD_VOTE_STATE_DATA_MAX 3762UL

/* fd_tower_accts describes the set of vote accounts that feed into
   TowerBFT rules.  This is fixed for each epoch, and each acct is
   associated with a 3-tuple of (vote account address, vote account
   stake, and vote account data).  All the accts in the deque are
   intended to be as of the same slot. */

struct fd_tower_accts {
  fd_pubkey_t addr;                         /* vote account address */
  ulong       stake;                        /* vote account stake */
  uchar       data[FD_VOTE_STATE_DATA_MAX]; /* vote account data (max 3762 bytes) */
};
typedef struct fd_tower_accts fd_tower_accts_t;

#define DEQUE_NAME fd_tower_accts
#define DEQUE_T    fd_tower_accts_t
#include "../../util/tmpl/fd_deque_dynamic.c"

#endif /* HEADER_fd_src_choreo_tower_fd_tower_accts_h */
