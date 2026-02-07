#ifndef HEADER_fd_src_discof_replay_fd_vote_tracker_h
#define HEADER_fd_src_discof_replay_fd_vote_tracker_h

#include "../../util/fd_util_base.h"

FD_PROTOTYPES_BEGIN

/* fd_vote_tracker is a data structure that is used to track the
   latest votes seen for a given identity.  As votes are sent from the
   validator to the network, the vote tracker is used to track the votes
   for the identity.  As transactions are executed, the vote tracker can
   be queried to determine if the transaction is a valid vote for the
   identity.  This is useful for implementing waiting to become a leader
   until the identity vote is seen on the root bank.

   Under the hood, the vote tracker tracker is implemented as a map and
   a deque that keeps the most recent votes seen for each identity in a
   first-in-first-out order that can also be queried by signature. */

union fd_hash;
typedef union fd_hash fd_pubkey_t;

union fd_signature;
typedef union fd_signature fd_signature_t;

struct fd_vote_tracker;
typedef struct fd_vote_tracker fd_vote_tracker_t;

/* fd_vote_tracker_align returns the memory alignment of the
   fd_vote_tracker_t structure in bytes. */

ulong
fd_vote_tracker_align( void );

/* fd_vote_tracker_footprint returns the memory footprint of the
   fd_vote_tracker_t structure in bytes. */

ulong
fd_vote_tracker_footprint( void );

/* fd_vote_tracker_new creates a new fd_vote_tracker_t structure. */

void *
fd_vote_tracker_new( void * mem,
                     ulong  seed );

/* fd_vote_tracker_join joins a fd_vote_tracker_t structure to a
   valid vote tracker. */

fd_vote_tracker_t *
fd_vote_tracker_join( void * mem );

/* fd_vote_tracker_insert inserts a new vote into the vote tracker. */

void
fd_vote_tracker_insert( fd_vote_tracker_t *    vote_tracker,
                        fd_pubkey_t const    * identity_pubkey,
                        fd_signature_t const * vote_sig );

/* fd_vote_tracker_query_sig queries the vote tracker for a given vote
   signature and returns the identity public key that signed the
   vote.  If a vote is found, 1 is returned and identity_pubkey_out will
   be set.  Otherwise, 0 is returned and identity_pubkey_out will be
   NULL. */

int
fd_vote_tracker_query_sig( fd_vote_tracker_t *    vote_tracker,
                           fd_signature_t const * vote_sig,
                           fd_pubkey_t * *        identity_pubkey_out );

/* fd_vote_tracker_reset resets the vote tracker to its initial state. */

void
fd_vote_tracker_reset( fd_vote_tracker_t * vote_tracker );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_vote_states_h */
