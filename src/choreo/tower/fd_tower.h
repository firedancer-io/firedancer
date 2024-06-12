#ifndef HEADER_fd_src_choreo_tower_fd_tower_h
#define HEADER_fd_src_choreo_tower_fd_tower_h

#include "../../flamenco/runtime/fd_blockstore.h"
#include "../fd_choreo_base.h"
#include "../forks/fd_forks.h"
#include "../ghost/fd_ghost.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

#define FD_TOWER_EQV_SAFE ( 0.52 )
#define FD_TOWER_OPT_CONF ( 2.0 / 3.0 )

/* FD_TOWER_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_TOWER_USE_HANDHOLDING
#define FD_TOWER_USE_HANDHOLDING 1
#endif

/* fd_tower implements the TowerBFT algorithm and associated functionality. */

struct fd_tower {

  /* Always valid. Initialized to 0 if loading from genesis, snapshot slot otherwise. */

  ulong root;

  /* Local vote tower */

  ulong vote_slots[32];
  ulong vote_slot_cnt;

  /* Total amount of stake in the current epoch. */

  ulong total_stake;

  /* External joins */

  fd_acc_mgr_t *    acc_mgr;
  fd_blockstore_t * blockstore;
  fd_forks_t *      forks;
  fd_ghost_t *      ghost;
  fd_valloc_t       valloc;
};
typedef struct fd_tower fd_tower_t;

/* fd_tower_{align,footprint} return the required alignment and footprint of a memory region
   suitable for use as tower with up to node_max nodes and vote_max votes. */

FD_FN_CONST static inline ulong
fd_tower_align( void ) {
  return alignof( fd_tower_t );
}

FD_FN_CONST static inline ulong
fd_tower_footprint( void ) {
  return sizeof( fd_tower_t );
}

/* fd_tower_new formats an unused memory region for use as a tower. mem is a non-NULL
   pointer to this region in the local address space with the required footprint and alignment. */

void *
fd_tower_new( void * mem );

/* fd_tower_join joins the caller to the tower. tower points to the first byte of the
   memory region backing the tower in the caller's address space.

   Returns a pointer in the local address space to tower on success. */

fd_tower_t *
fd_tower_join( void * tower );

/* fd_tower_leave leaves a current local join. Returns a pointer to the underlying shared memory
   region on success and NULL on failure (logs details). Reasons for failure include tower is
   NULL. */

void *
fd_tower_leave( fd_tower_t const * tower );

/* fd_tower_delete unformats a memory region used as a tower. Assumes only the local process
   is joined to the region. Returns a pointer to the underlying shared memory region or NULL if used
   obviously in error (e.g. tower is obviously not a tower ... logs details). The ownership
   of the memory region is transferred to the caller. */

void *
fd_tower_delete( void * tower );


/* fd_tower_epoch_update performs tower-related updates after crossing
   epoch boundary. */

void
fd_tower_epoch_update( fd_tower_t * tower, fd_exec_epoch_ctx_t * epoch_ctx );

/* fd_tower_fork_update performs tower-related updates after executing
   the fork's head. */

void
fd_tower_fork_update( fd_tower_t * tower, fd_fork_t * fork );

/* fd_tower_best_fork_select picks which fork to best PoH to for our next
   leader slot. Returns a non-NULL fork. Note that this is not
   necessarily the same fork as the one we vote on, as we do not always
   vote for the fork we best to. */

fd_fork_t *
fd_tower_best_fork_select( fd_tower_t * tower );

/* fd_tower_reset_fork_select picks which fork to reset PoH to for our next
   leader slot. Returns a non-NULL fork. Note that this is not
   necessarily the same fork as the one we vote on, as we do not always
   vote for the fork we reset to. */

fd_fork_t *
fd_tower_reset_fork_select( fd_tower_t * tower );

/* fd_tower_vote_fork_select picks which frontier fork to vote on. Returns NULL
   if we cannot vote because we are locked out, do not meet switch
   threshold, or fail the threshold check. */

fd_fork_t *
fd_tower_vote_fork_select( fd_tower_t * tower );

/* fd_tower_lockout_check checks if we are locked out from voting for
   a given fork. Returns 1 if we can vote without violating lockout,
   0 if not.

   After voting for a slot n, we are locked out for 2^k slots,
   where k is the confirmation count of that vote. Once locked out,
   we cannot vote for a different fork until that fork reaches slot
   n+2^k. This implies the earliest slot in which we can vote for
   a different fork is (n+2^k)+1. */

int
fd_tower_lockout_check( fd_tower_t * tower, fd_fork_t * fork );

/* fd_tower_switch_check checks if we satisfy the stake percentage required to switch forks.
   Returns 1 if we can switch, 0 if not.

   The requirement is that at least FD_TOWER_SWITCH_PCT of stake is locked out from voting for our
   current fork.

   This switch check is used to safeguard optimistic confirmation. It should be invariant that
   FD_TOWER_OPT_CONF_PCT + FD_TOWER_SWITCH_PCT >= 1. */

int
fd_tower_switch_check( fd_tower_t * tower, fd_fork_t * fork );

/* fd_tower_threshold_check checks if we pass the threshold required to
   continue voting along the  same fork as our last vote. Returns 1 if
   we pass the threshold check, 0 if not.

   The threshold check requires that the ancestor at
   FD_TOWER_THRESHOLD_DEPTH in the tower has reached at least
   FD_TOWER_THRESHOLD_PCT stake. */

int
fd_tower_threshold_check( fd_tower_t * tower );

#endif /* HEADER_fd_src_choreo_tower_fd_tower_h */
