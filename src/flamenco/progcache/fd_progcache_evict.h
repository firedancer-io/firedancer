#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_evict_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_evict_h

/* fd_progcache_evict.h provides internal cache eviction APIs for the
   on-chain program cache. */

#include "fd_progcache.h"
#include "../../funk/fd_funk_rec.h"

FD_PROTOTYPES_BEGIN

/* fd_progcache_rec_acquire acquires funk_rec and progcache_rec objects,
   evicting records from progcache as necessary.  rec_footprint is the
   size of the progcache_rec object.  Returns a pointer to the newly
   created funk_rec object (with uninitialized progcache_rec attached as
   val).  Terminates the app with FD_LOG_ERR if allocation failed after
   exhausting all possible eviction possibilities. */

fd_funk_rec_t *
fd_progcache_rec_acquire( fd_progcache_t * cache,
                          ulong            rec_footprint,
                          ulong            gen );

/* fd_progcache_rec_tombstone swaps out a prior allocation (from
   rec_acquire) for a tombstone. */

fd_funk_rec_t *
fd_progcache_rec_tombstone( fd_progcache_t * cache,
                            fd_funk_rec_t *  rec );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_evict_h */
