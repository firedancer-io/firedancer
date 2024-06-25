#ifndef HEADER_fd_src_choreo_tower_fd_tower_h
#define HEADER_fd_src_choreo_tower_fd_tower_h

#include "../../flamenco/runtime/fd_blockstore.h"
#include "../fd_choreo_base.h"
#include "../forks/fd_forks.h"
#include "../ghost/fd_ghost.h"

#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

#define FD_TOWER_EQV_SAFE       ( 0.52 )
#define FD_TOWER_OPT_CONF       ( 2.0 / 3.0 )
#define FD_TOWER_VOTE_SLOTS_MAX ( 32UL )

/* FD_TOWER_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_TOWER_USE_HANDHOLDING
#define FD_TOWER_USE_HANDHOLDING 1
#endif

struct fd_tower_vote_acc {
  fd_pubkey_t const * addr;
  ulong               stake;
};
typedef struct fd_tower_vote_acc fd_tower_vote_acc_t;

/* fd_tower implements the TowerBFT algorithm and related consensus
   rules. */

struct fd_tower {

  /* The root is a non-NULL pointer to an fseq that always contains a
     valid root slot.  The root is initialized to 0 if loading from
     genesis, snapshot slot otherwise.

     Do not read or modify outside of the fseq API. */

  ulong root;

  /* Local vote tower */

  ulong vote_slots[FD_TOWER_VOTE_SLOTS_MAX];
  ulong vote_slot_cnt;

  /* Total amount of stake in the current epoch. */

  ulong total_stake;

  /* Vote accounts in the current epoch.

     Lifetimes of the vote account addresses (pubkeys) are valid for the
     epoch (the pubkey memory is owned by the epoch bank.) */

  fd_tower_vote_acc_t vote_accs[FD_VOTER_MAX];
  ulong               vote_acc_cnt;
};
typedef struct fd_tower fd_tower_t;

/* fd_tower_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as tower with up to
   node_max nodes and vote_max votes. */

FD_FN_CONST static inline ulong
fd_tower_align( void ) {
  return alignof( fd_tower_t );
}

FD_FN_CONST static inline ulong
fd_tower_footprint( void ) {
  return sizeof( fd_tower_t );
}

/* fd_tower_new formats an unused memory region for use as a tower.  mem
   is a non-NULL pointer to this region in the local address space with
   the required footprint and alignment. */

void *
fd_tower_new( void * mem );

/* fd_tower_join joins the caller to the tower.  tower points to the
   first byte of the memory region backing the tower in the caller's
   address space.

   Returns a pointer in the local address space to tower on success. */

fd_tower_t *
fd_tower_join( void * tower );

/* fd_tower_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include tower is NULL. */

void *
fd_tower_leave( fd_tower_t const * tower );

/* fd_tower_delete unformats a memory region used as a tower.  Assumes
   only the local process is joined to the region.  Returns a pointer to
   the underlying shared memory region or NULL if used obviously in
   error (e.g.  tower is obviously not a tower ...  logs details).  The
   ownership of the memory region is transferred to the caller. */

void *
fd_tower_delete( void * tower );

/* fd_tower_init initializes a tower.  Assumes tower is a valid local
   join and no other processes are joined. root is the initial root that
   tower will use. This is the snapshot slot if booting from a snapshot,
   genesis slot otherwise.

   In general, this should be called by the same process that formatted
   tower's memory, ie. the caller of fd_tower_new. */
void
fd_tower_init( fd_tower_t * tower, fd_exec_epoch_ctx_t const * epoch_ctx, ulong root );

/* fd_tower_lockout_check checks if we are locked out from voting for
   a given fork.  Returns 1 if we can vote without violating lockout,
   0 otherwise.

   After voting for a slot n, we are locked out for 2^k slots,
   where k is the confirmation count of that vote.  Once locked out,
   we cannot vote for a different fork until that fork reaches slot
   n+2^k.  This implies the earliest slot in which we can vote for
   a different fork is (n+2^k)+1. */

int
fd_tower_lockout_check( fd_tower_t const * tower, fd_fork_t const * fork );

/* fd_tower_switch_check checks if we can switch forks based on the
   percentage of validators locked out from voting for our latest vote
   fork.  Returns 1 if we can switch, 0 otherwise.

   The following pseudocode describes the algorithm:

   ```
   for all validators v
      if v is locked out[1] from voting for our latest vote slot
         add v's stake to switch stake
   return switch stake >= FD_TOWER_SWITCH_PCT
   ```

   [1]: locked out is defined as v's latest vote slot is not on the same
        fork as our latest vote slot and v's latest vote slot's
        expiration > fork->slot

   The switch check is used to safeguard optimistic confirmation.
   Invariant: FD_TOWER_OPT_CONF_PCT + FD_TOWER_SWITCH_PCT >= 1. */

int
fd_tower_switch_check( fd_tower_t const * tower, fd_fork_t const * fork );

/* fd_tower_threshold_check checks if we pass the threshold required to
   continue voting along the  same fork as our last vote.  Returns 1 if
   we pass the threshold check, 0 otherwise.

   The following psuedocode describes the algorithm:

   ```
   for all vote accounts on the current fork

      simulate that the validator has voted on the current slot (the
      fork head)

      pop all votes expired by that simulated vote

      if validator's latest tower vote after expiry >= our threshold
      slot ie. our vote from FD_TOWER_THRESHOLD_DEPTH back (after
      simulating a vote on our own tower the same way)

         add validator's stake to threshold_stake.

   return threshold_stake >= FD_TOWER_THRESHOLD_PCT
   ```

   The threshold check simulates voting for the current slot to expire
   stale votes. This is to prevent validators that haven't voted in a
   long time from counting towards the threshold stake. */

int
fd_tower_threshold_check( fd_tower_t const * tower,
                          fd_fork_t const *  fork,
                          fd_acc_mgr_t *     acc_mgr );

/* fd_tower_best_fork_select picks the best fork, where best is defined
   as the fork head containing the highest stake-weight in its ancestry. 
   Returns a non-NULL fork.  Assumes forks->frontier is non-empty.  Note
   that this is not necessarily the same fork as the one we vote on, as
   we might be locked out on a different fork.

   Does not modify tower. */

fd_fork_t *
fd_tower_best_fork_select( fd_tower_t const * tower, fd_forks_t * forks, fd_ghost_t * ghost );

/* fd_tower_reset_fork_select picks which fork to reset PoH to for our
   next leader slot.  Returns a non-NULL fork.  Note that this is not
   necessarily the same fork as the one we vote on, as we do not always
   vote for the fork we reset to.

   Does not modify tower. */

fd_fork_t *
fd_tower_reset_fork_select( fd_tower_t const * tower, fd_forks_t * forks );

/* fd_tower_vote_fork_select picks which frontier fork to vote on.
   Returns NULL if we cannot vote because we are locked out, do not meet
   switch threshold, or fail the threshold check.

   Modifies the tower to record the vote slot of the fork we select. */

fd_fork_t *
fd_tower_vote_fork_select( fd_tower_t *   tower,
                           fd_forks_t *   forks,
                           fd_acc_mgr_t * acc_mgr,
                           fd_ghost_t *   ghost );

/* fd_tower_epoch_update updates the tower after with a new epoch ctx.
   This should only be called on startup and when crossing an epoch
   boundary. */

void
fd_tower_epoch_update( fd_tower_t * tower, fd_exec_epoch_ctx_t const * epoch_ctx );

/* fd_tower_fork_update performs tower-related updates after executing
   fork's latest slot (head).  Important: this should be called after
   execution of fork->slot, not before. */

void
fd_tower_fork_update( fd_tower_t *      tower,
                      fd_fork_t *       fork,
                      fd_acc_mgr_t *    acc_mgr,
                      fd_blockstore_t * blockstore,
                      fd_ghost_t *      ghost );

#endif /* HEADER_fd_src_choreo_tower_fd_tower_h */
