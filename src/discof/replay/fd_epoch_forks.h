#ifndef HEADER_fd_src_discof_store_fd_epoch_forks_h
#define HEADER_fd_src_discof_store_fd_epoch_forks_h

#include "../../disco/fd_disco_base.h"
#include "../../choreo/ghost/fd_ghost.h"

#define MAX_EPOCH_FORKS 8

/* fd_epoch_forks is a map which manages forking across an epoch
   boundary. It is based on the idea that we need a new epoch_ctx
   for every unique subtree of forks spanning across a boundary.
   An example fork tree, assuming new epoch starts at slot 100:
                     98
                     | ----------
                     |          |
                     99         |
               -----   -----    104
              |             |
              |             |
              100           102
   For this example, we hit the epoch boundary for 100, 102 and 104 in
   the respective forks. However, since the epoch context is updated based
   on parent slot ctx, and remains the same across an epoch, it will be
   the same for 100 and 102. Therefore, we allocate 2 epoch fork entries,
   one for parent slot 98 (leading to 104), and one for parent slot 99
   (leading to 100 or 102). While we are unrooted in the epoch starting at
   100, we maintain these epoch fork entries, but as soon as we root at any
   of these slots, we can publish the correct entruy and prune the epoch ctx
   entries for the other forks.

   The API is straightforward and initializes a small cache for epoch_ctx
   entries and accepts a base pointer to a pre-allocated memory region for
   epoch_ctx objects. It allows for preparing a new epoch fork, publishing
   the forks, and getting the correct epoch ctx for the current slot. */
struct fd_epoch_fork_elem {
  ulong parent_slot;
  ulong epoch;
  fd_exec_epoch_ctx_t * epoch_ctx;
};

typedef struct fd_epoch_fork_elem fd_epoch_fork_elem_t;

struct fd_epoch_forks {
  fd_epoch_fork_elem_t forks[MAX_EPOCH_FORKS];
  ulong curr_epoch_idx;
  uchar * epoch_ctx_base;
};

typedef struct fd_epoch_forks fd_epoch_forks_t;

FD_PROTOTYPES_BEGIN

/* epoch_forks_new initializes the fork elements and stores the base pointer for
   the epoch_ctx allocations. */
void
fd_epoch_forks_new( fd_epoch_forks_t * epoch_forks, void * epoch_ctx_base );

/* epoch_forks_publish checks for whether we have rooted into a new epoch and
   clears out the fork entries which can be pruned at that point. It also picks
   the correct entry to use for the new epoch. */
void
fd_epoch_forks_publish( fd_epoch_forks_t * epoch_forks, ulong root );

/* epoch_forks_prepare creates a new entry for the fork crossing the epoch boundary,
   or returns the existing entry associated with the fork crossing the epoch boundary.
   Crashes with CRIT if we have exceeded max forks. */
uint
fd_epoch_forks_prepare( fd_epoch_forks_t *      epoch_forks,
                        ulong                   parent_slot,
                        ulong                   new_epoch,
                        fd_epoch_fork_elem_t ** out_fork,
                        ulong                   vote_accounts_max );

/* epoch_forks_get_epoch_ctx returns the correct entry index for the current epoch, or
   in the case of a new epoch fork, the correct entry index related to the fork. */
ulong
fd_epoch_forks_get_epoch_ctx( fd_epoch_forks_t * epoch_forks, ulong root, ulong curr_slot, ulong * opt_prev_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_store_fd_epoch_forks_h */
