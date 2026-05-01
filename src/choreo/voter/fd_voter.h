#ifndef HEADER_fd_src_choreo_voter_fd_voter_h
#define HEADER_fd_src_choreo_voter_fd_voter_h

/* fd_voter maintains two snapshots of the epoch stake-weighted voter
   set: one for the current root epoch ("curr") and one for the next
   epoch ("next").  This is used during vote counting to look up the
   stake and authorized voter pubkey for a given vote account.

   Each snapshot is populated from the bank's top_votes and the vote
   account data in accdb.  The curr snapshot uses top_votes_t_2 (the
   epoch two before the current one) and the next snapshot uses
   top_votes_t_1 (the epoch one before the current one), matching
   Solana's stake activation delay.

   fd_voter_query uses the internally stored epoch_schedule (copied from
   the bank during update) to convert a slot to an epoch, then selects
   the curr or next snapshot based on whether the epoch matches
   root_epoch or root_epoch+1. */

#include "../../flamenco/accdb/fd_accdb_base.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/types/fd_types_custom.h"

struct fd_voter_vtr {
  fd_pubkey_t vote_acc;
  struct {
    ulong prev;
    ulong next;
  } map;
  struct {
    ulong prev;
    ulong next;
  } dlist;
  ulong       stake;
  fd_pubkey_t authorized_voter;
};
typedef struct fd_voter_vtr fd_voter_vtr_t;

struct fd_voter;
typedef struct fd_voter fd_voter_t;

#define FD_VOTER_ALIGN (128UL)

FD_PROTOTYPES_BEGIN

/* fd_voter_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a voter.  align
   returns FD_VOTER_ALIGN.  vtr_max is the maximum number of voters
   tracked per epoch snapshot. */

ulong
fd_voter_align( void );

ulong
fd_voter_footprint( ulong vtr_max );

/* fd_voter_new formats an unused memory region for use as a voter.
   shmem is a non-NULL pointer to this region in the local address space
   with the required footprint and alignment.  vtr_max is the maximum
   number of voters per snapshot.  seed is a hash seed for the internal
   maps.  Returns shmem on success. */

void *
fd_voter_new( void * shmem,
              ulong  vtr_max,
              ulong  seed );

/* fd_voter_join joins the caller to the voter.  shvoter points to the
   first byte of the memory region backing the voter in the caller's
   address space.

   Returns a pointer in the local address space to the voter on
   success. */

fd_voter_t *
fd_voter_join( void * shvoter );

/* fd_voter_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success. */

void *
fd_voter_leave( fd_voter_t const * voter );

/* fd_voter_delete unformats a memory region used as a voter.  Assumes
   only the local process is joined to the region.  Returns a pointer to
   the underlying shared memory region. */

void *
fd_voter_delete( void * shvoter );

/* fd_voter_query looks up a voter by vote account address for the given
   slot.  Uses the internally stored epoch_schedule to convert slot to
   an epoch, then compares against root_epoch (set during update) to
   select the curr or next snapshot.  Returns a pointer to the voter
   entry if found, or NULL if the epoch is not root_epoch or
   root_epoch+1, or if the vote account is not in the snapshot. */

fd_voter_vtr_t const *
fd_voter_query( fd_voter_t        * voter,
                fd_pubkey_t const * vote_acc,
                ulong               slot );

/* fd_voter_update clears both epoch snapshots and repopulates them from
   the bank's top_votes (t-2 for curr, t-1 for next).  Reads vote
   account data from accdb to fill the authorized_voter field for each
   entry.  Copies the bank's epoch_schedule for use by future query
   calls.  Derives epoch from slot via epoch_schedule and sets
   root_epoch accordingly.  Should be called on initialization and on
   each epoch boundary when the root advances to a new epoch. */

void
fd_voter_update( fd_voter_t      * voter,
                 fd_accdb_user_t * accdb,
                 fd_banks_t      * banks,
                 ulong             slot,
                 ulong             bank_idx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_voter_fd_voter_h */
