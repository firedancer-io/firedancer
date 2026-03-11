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

/* FD_TOP_VOTES_MAX_FOOTPRINT is the footprint of the fd_top_votes_t
   structure when the max number of vote accounts is
   FD_RUNTIME_MAX_VOTE_ACCOUNTS_VAT (2000). */

#define FD_TOP_VOTES_MAX_FOOTPRINT (194432UL)

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


/* fd_top_votes_insert inserts a new vote account into the top votes set
   given a vote account, node account, last vote slot, last vote
   timestamp, and a stake.  The node account, last vote slot, and last
   vote timestamp are just metadata for the structure.  If the vote
   account isn't in the top max_vote_accounts in terms of stake, it is
   ignored and is treated as a no-op.  If the vote account ties the
   minimum stake and the struct is full, all elements with that stake
   are removed.  */

void
fd_top_votes_insert( fd_top_votes_t *    top_votes,
                     fd_pubkey_t const * pubkey,
                     fd_pubkey_t const * node_account,
                     ulong               stake,
                     ulong               last_vote_slot,
                     long                last_vote_timestamp );


/* fd_top_votes_update updates the last vote timestamp and slot for a
   given vote account in the top votes set.  If the vote account is not
   in the top votes set, the update is ignored and is treated as a
   no-op. */

void
fd_top_votes_update( fd_top_votes_t *    top_votes,
                     fd_pubkey_t const * pubkey,
                     ulong               last_vote_slot,
                     long                last_vote_timestamp );

/* fd_top_votes_invalidate invalidates a vote account in the top votes
   set.  This would be done in the case a vote account is withdrawn or
   becomes invalid.  An account that is invalid, will not be returned by
   fd_top_votes_query. */

void
fd_top_votes_invalidate( fd_top_votes_t *    top_votes,
                         fd_pubkey_t const * pubkey );

/* fd_top_votes_query queries a fd_top_votes_t structure given a
   vote account and returns 1 if the vote account is in the top voters
   set and 0 otherwise.  If the vote account is in the top voters set,
   the node account, stake, last vote slot, and last vote timestamp are
   all optionally returned via parameter pointers. */

int
fd_top_votes_query( fd_top_votes_t const * top_votes,
                    fd_pubkey_t const *    pubkey,
                    fd_pubkey_t *          node_account_out_opt,
                    ulong *                stake_out_opt,
                    ulong *                last_vote_slot_out_opt,
                    long *                 last_vote_timestamp_out_opt );

#define FD_TOP_VOTES_ITER_FOOTPRINT (16UL)
#define FD_TOP_VOTES_ITER_ALIGN     (8UL)
struct map_iter;
typedef struct map_iter fd_top_votes_iter_t;

/* A caller can iterate through the entries in the top votes set.  The
   iterator is initialized by a call to fd_top_votes_iter_init.  The
   caller is responsible for managing the memory for the iterator.
   It is safe to call fd_top_votes_iter_next if the result of
   fd_top_votes_iter_done() == 0.  It is safe to call
   fd_top_votes_iter_ele() to get the current entry if there is a valid
   initialized iterator.

   Example use:
   uchar __attribute__((aligned(FD_TOP_VOTES_ITER_ALIGN))) iter_mem[ FD_TOP_VOTES_ITER_FOOTPRINT ];
   for( fd_top_votes_iter_t * iter = fd_top_votes_iter_init( top_votes, iter_mem );
        !fd_top_votes_iter_done( top_votes, iter );
        fd_top_votes_iter_next( top_votes, iter ) ) {
     fd_top_votes_iter_ele( top_votes, iter, &pubkey, &node_account, &stake, &last_vote_slot, &last_vote_timestamp );
   } */

fd_top_votes_iter_t *
fd_top_votes_iter_init( fd_top_votes_t const * top_votes,
                        uchar                  iter_mem[ static FD_TOP_VOTES_ITER_FOOTPRINT ],
                        uchar                  include_invalid );

int
fd_top_votes_iter_done( fd_top_votes_t const * top_votes,
                        fd_top_votes_iter_t *  iter );

void
fd_top_votes_iter_next( fd_top_votes_t const * top_votes,
                        fd_top_votes_iter_t *  iter,
                        uchar                  include_invalid );

void
fd_top_votes_iter_ele( fd_top_votes_t const * top_votes,
                       fd_top_votes_iter_t *  iter,
                       fd_pubkey_t *          pubkey_out,
                       fd_pubkey_t *          node_account_out_opt,
                       ulong *                stake_out_opt,
                       ulong *                last_vote_slot_out_opt,
                       long *                 last_vote_timestamp_out_opt );

FD_PROTOTYPES_END

#endif
