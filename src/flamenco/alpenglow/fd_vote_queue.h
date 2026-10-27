#ifndef HEADER_fd_src_flamenco_alpenglow_fd_vote_queue_h
#define HEADER_fd_src_flamenco_alpenglow_fd_vote_queue_h

/* fd_vote_queue accumulates the lthash change of the footer vote
   accounts a footer stores, hashing images FD_BLAKE3_XN_MAX per blake3
   pass.  On a memo hit the prior image is not rehashed. */

#include "fd_footer_cache.h"
#include "../accdb/fd_accdb.h"

#define FD_VOTE_QUEUE_ALIGN     (64UL)
#define FD_VOTE_QUEUE_FOOTPRINT (35456UL)

struct fd_vote_queue;
typedef struct fd_vote_queue fd_vote_queue_t;

FD_PROTOTYPES_BEGIN

/* fd_vote_queue_init formats mem as an empty queue. */

fd_vote_queue_t *
fd_vote_queue_init( void * mem );

/* fd_vote_queue_store records acc's change from its prior image to its
   new one.  memo (NULL for none) is the account's slot and takes the
   new image.  Images in acc are hashed before return, so acc may be
   released after. */

void
fd_vote_queue_store( fd_vote_queue_t *        q,
                     fd_acc_t const *         acc,
                     fd_footer_cache_memo_t * memo );

/* fd_vote_queue_fini hashes what is left and returns the total lthash
   change. */

fd_lthash_value_t const *
fd_vote_queue_fini( fd_vote_queue_t * q );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_alpenglow_fd_vote_queue_h */
