#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_reclaim_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_reclaim_h

#include "fd_progcache_base.h"

FD_PROTOTYPES_BEGIN

/* Remove record API */

/* fd_prog_delete_rec removes a rec from the progcache index and then
   schedules a reclaim job (processed in a future fd_prog_reclaim_work).
   Takes lock on recm_chain, rec. */

long
fd_prog_delete_rec( fd_progcache_join_t * cache,
                    fd_progcache_rec_t *  rec );

/* fd_prog_delete_rec_imm is like fd_prog_delete_rec, but immediately
   performs the reclaim (removes rec from txn, frees rec).  This takes
   locks on recm_chain, rec, txn, and recp. */

_Bool
fd_prog_delete_rec_imm( fd_progcache_join_t *          cache,
                        fd_funk_xid_key_pair_t const * key );

/* Internal API */

/* fd_prog_reclaim_enqueue enqueues a progcache_rec object for eventual
   reclamation/deallocation.  Transfers ownership of the rec to reclaim.
   Requires an active write lock on the map chain that formerly
   contained this record.  The record must be removed from the map
   before unlocking. */

void
fd_prog_reclaim_enqueue( fd_progcache_join_t * cache,
                         fd_progcache_rec_t *  rec );

/* fd_prog_reclaim_work opportunistically does record reclamation work.
   Returns number of reclaim operations done. */

ulong
fd_prog_reclaim_work( fd_progcache_join_t * join );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_reclaim_h */
