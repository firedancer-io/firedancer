#ifndef HEADER_fd_src_flamenco_progcache_fd_progcache_reclaim_h
#define HEADER_fd_src_flamenco_progcache_fd_progcache_reclaim_h

#include "../../util/fd_util_base.h"
#include "fd_progcache_base.h"
#include "fd_progcache_xid.h"
#include "fd_progcache_rec.h"

FD_PROTOTYPES_BEGIN

/* Remove record API */

/* fd_prog_delete_rec removes a rec from the progcache index.  Returns rodata_sz,
   or -1 if rec was not mapped under its own key.  The record becomes a zombie:
   unmapped, still LIVE; once detached from its fork and unheld, an eviction
   sweep hands its slot over (or fd_prog_reclaim_work frees it).

   The key is re-read from rec, so the caller must hold the record stable
   against slot reuse: own it on a fork's record list, or hold txn.rwlock (a
   reused slot's key is zeroed until fd_progcache_push, which runs under
   txn.rwlock, republishes it -- a zeroed key is never mapped, so the delete is
   a -1 no-op).  A caller that decided on a key without holding the record
   stable must use fd_prog_delete_rec_claim and pass that key. */

long
fd_prog_delete_rec( fd_progcache_join_t * cache,
                    fd_progcache_rec_t *  rec );

/* fd_prog_delete_rec_claim removes rec from the index under the given key and
   hands it over outright: on success the record is write locked by the caller,
   ready for fd_progcache_rec_reinit.  pair must be the key the caller decided
   on, not re-read from rec, so a slot recycled meanwhile is a -1 no-op rather
   than the removal of the new owner's entry.  Also returns -1, with no side
   effects, if a reader holds the record, it is VISITED, or it is still attached
   to a fork (one on a fork's record list would need an unlink under that fork's
   lock, which cannot nest inside the chain lock held here). */

long
fd_prog_delete_rec_claim( fd_progcache_join_t *          cache,
                          fd_progcache_rec_t *           rec,
                          fd_progcache_rec_key_t const * pair );

/* fd_prog_reclaim_work sweeps the whole record array, collecting every zombie
   (unmapped, detached, unheld) to its class's free list.  O(rec_max): for
   teardown, reset and tests; the hot path reuses a zombie's slot when an
   eviction sweep draws it.  Returns the number collected. */

ulong
fd_prog_reclaim_work( fd_progcache_join_t * join );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_progcache_fd_progcache_reclaim_h */
