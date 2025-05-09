#ifndef HEADER_fd_src_flamenco_gossip_fd_push_set_h
#define HEADER_fd_src_flamenco_gossip_fd_push_set_h

struct fd_push_set_private;
typedef struct fd_push_set_private fd_push_set_t;

#include "../../util/fd_util.h"

/* Get the list of nodes that a message originating from the origin
   pubkey, which was pushed to us, should be pushed to.  Peers which
   have pruned the origin pubkey will not be included in the list. */

void
fd_push_set_targets( fd_push_set_t const * push_set,
                     uchar const *         origin_pubkey,
                     ulong                 origin_stake );

/* Called every 25 milliseconds.  Picks a random push subset and rotates
   the oldest element out, and a new one in. */

void
fd_push_set_rotate( fd_push_set_t * push_set );

void
fd_push_set_add( fd_push_set_t * push_set,
                 uchar const *   pubkey,
                 ulong           stake );

void
fd_push_set_remove( fd_push_set_t * push_set,
                    uchar const *   pubkey );



#endif /* HEADER_fd_src_flamenco_gossip_fd_push_set_h */
