#ifndef HEADER_fd_src_discof_replay_fd_fwd_confirmed_h
#define HEADER_fd_src_discof_replay_fd_fwd_confirmed_h

#include "../../util/fd_util_base.h"

FD_PROTOTYPES_BEGIN

/* fd_fwd_confirmed buffers forward-confirmed block ids from tower
   that have not yet been inserted into reasm.  When reasm later inserts
   a FEC matching a buffered block id, we immediately confirm the chain.

   Internally a pool + map_chain + dlist.  The dlist maintains insertion
   order so the oldest entry can be evicted when the buffer is full.

   Note on eviction.  In the regular case, we shouldn't ever need to
   evict anything.  Entries should naturally be removed.  If a
   confirmation arrives and reasm has the FEC (and it is connected),
   we immediately confirm the chain, and do not need to buffer anything.
   If a confirmation arrives and reasm does not have the FEC connected,
   we buffer the block id. */

union fd_hash;
typedef union fd_hash fd_hash_t;

struct fd_fwd_confirmed;
typedef struct fd_fwd_confirmed fd_fwd_confirmed_t;

/* fd_fwd_confirmed_align returns the memory alignment of the
   fd_fwd_confirmed_t structure in bytes. */

ulong
fd_fwd_confirmed_align( void );

/* fd_fwd_confirmed_footprint returns the memory footprint of the
   fd_fwd_confirmed_t structure in bytes for a buffer with at most
   max entries. */

ulong
fd_fwd_confirmed_footprint( ulong max );

/* fd_fwd_confirmed_new formats a memory region as a new
   fd_fwd_confirmed_t with capacity for max entries.  Returns shmem
   on success, NULL on failure. */

void *
fd_fwd_confirmed_new( void * shmem,
                      ulong  max );

/* fd_fwd_confirmed_join joins a fd_fwd_confirmed_t. */

fd_fwd_confirmed_t *
fd_fwd_confirmed_join( void * shmem );

/* fd_fwd_confirmed_insert inserts a block id into the buffer.  If the
   buffer is full, the oldest entry is evicted. */

void
fd_fwd_confirmed_insert( fd_fwd_confirmed_t * buf,
                         fd_hash_t const *    block_id );

/* fd_fwd_confirmed_remove removes a block id from the buffer.  Returns
   1 if the block id was found and removed, 0 otherwise. */

int
fd_fwd_confirmed_remove( fd_fwd_confirmed_t * buf,
                         fd_hash_t const *    block_id );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_replay_fd_fwd_confirmed_h */
