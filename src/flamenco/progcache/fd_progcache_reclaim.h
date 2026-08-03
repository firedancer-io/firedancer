#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_reclaim_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_reclaim_h

#include "../../util/fd_util_base.h"
#include "fd_progcache_base.h"
#include "fd_progcache_xid.h"

FD_PROTOTYPES_BEGIN

/* Remove record API */

/* fd_progcache_delete_rec removes a rec from the progcache index and then
   schedules a reclaim job (processed in a future fd_progcache_reclaim_work).
   Returns the record's program size in bytes (rodata_sz), or -1 if the
   record was not in the map. */

long
fd_progcache_delete_rec( fd_progcache_join_t * cache,
                         fd_progcache_rec_t *  rec );

/* Internal API */

/* fd_progcache_reclaim_enqueue enqueues a progcache_rec object for eventual
   reclamation/deallocation.  Transfers ownership of the rec to reclaim.
   The record must not exist in the map. */

void
fd_progcache_reclaim_enqueue( fd_progcache_join_t * cache,
                              fd_progcache_rec_t *  rec );

/* fd_progcache_reclaim_work opportunistically does record reclamation work.
   Returns number of reclaim operations done. */

ulong
fd_progcache_reclaim_work( fd_progcache_join_t * join );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_reclaim_h */
