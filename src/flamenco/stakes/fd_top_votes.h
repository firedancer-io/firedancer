#ifndef HEADER_fd_src_flamenco_stakes_fd_top_votes_h
#define HEADER_fd_src_flamenco_stakes_fd_top_votes_h

#include "../../util/fd_util_base.h"
#include "../types/fd_types_custom.h"

/* With the introduction of VAT, the set of vote accounts that receive
   epoch rewards, participate in clock calculation, and are eligible for
   becoming leader becomes the top 2000 staked validators.
   fd_top_votes_t allows for efficiently populating and querying the
   set of top staked validators.  This data structure is intended to be
   CoW-able and maintained by the banks.

   Under the hood, fd_top_votes_t uses a heap, map, and pool to track
   the top set of vote accounts as they are being added.  The map allows
   for O(1) lookup of a vote account by its public key.

   An important tiebreaking rule is that if the minimum stake value has
   a tie, all accounts with that stake value will be excluded from the
   top voters set. */

struct fd_top_votes;
typedef struct fd_top_votes fd_top_votes_t;

#define FD_TOP_VOTES_ALIGN (128UL)

#define FD_TOP_VOTES_MAX_FOOTPRINT (1000000UL)

FD_PROTOTYPES_BEGIN

/* fd_top_votes_align returns the alignment of the fd_top_votes_t
   structure. */

ulong
fd_top_votes_align( void );

/* fd_top_votes_footprint returns the footprint of the fd_top_votes_t
   structure given a max number of vote accounts. */

ulong
fd_top_votes_footprint( ulong vote_accounts_max );

/* fd_top_votes_new creates a new fd_top_votes_t structure given a
   memory buffer, a max number of vote accounts, and a seed. */

void *
fd_top_votes_new( void * mem,
                  ushort vote_accounts_max,
                  ulong  seed );

/* fd_top_votes_join joins a fd_top_votes_t structure from a memory
   region that has been previously initialized with fd_top_votes_new.
   Returns a pointer to the fd_top_votes_t structure. */

fd_top_votes_t *
fd_top_votes_join( void * mem );

/* fd_top_votes_init is a runtime initialization function for a
   fd_top_votes_t structure given a pointer to the structure. */

void
fd_top_votes_init( fd_top_votes_t * top_votes );


/* fd_top_votes_update updates a fd_top_votes_t structure given a
   vote account, node account, and a stake.  The node account is just
   metadata for the structure. */

void
fd_top_votes_update( fd_top_votes_t *    top_votes,
                     fd_pubkey_t const * pubkey,
                     fd_pubkey_t const * node_account,
                     ulong               stake );


/* fd_top_votes_query queries a fd_top_votes_t structure given a
   vote account and returns 1 if the vote account is in the top voters
   set and 0 otherwise.  If the vote account is in the top voters set,
   the node account and stake are returned. */

int
fd_top_votes_query( fd_top_votes_t *    top_votes,
                    fd_pubkey_t const * pubkey,
                    fd_pubkey_t *       node_account_out_opt,
                    ulong *             stake_out_opt );

FD_PROTOTYPES_END

#endif
