#include "fd_progcache_reclaim.h"
#include "fd_progcache_clock.h"
#include "fd_progcache_user.h"
#include "../../util/racesan/fd_racesan_target.h"


/* Shared body of the delete pair.  claim additionally takes the record's write
   lock inside the chain transaction, so the caller owns the slot outright instead
   of leaving a zombie.  The lock is taken here, not before, because the order is
   chain then rec.lock: fd_progcache_push holds a chain and then blocks on a
   winner's read lock, so the other order deadlocks. */

static long
delete_rec_inner( fd_progcache_join_t *          cache,
                  fd_progcache_rec_t *           rec,
                  fd_progcache_rec_key_t const * _pair,
                  int                            claim,
                  fd_progcache_txn_t *           owner ) {
  if( !rec ) return -1L;

  fd_progcache_rec_key_t pair = *_pair;

  /* Prepare index removal, and bail if rec is no longer present in map */
  struct {
    fd_prog_recm_txn_t txn[1];
    fd_prog_recm_txn_private_info_t info[1];
  } _map_txn;
  fd_prog_recm_txn_t * map_txn = fd_prog_recm_txn_init( _map_txn.txn, cache->rec.map, 1UL );
  fd_prog_recm_txn_add( map_txn, &pair, 1 );
  fd_racesan_hook( "prog_delete_rec:post_txn_add" );
  int txn_err = fd_prog_recm_txn_try( map_txn, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( txn_err!=FD_MAP_SUCCESS ) )
    FD_LOG_CRIT(( "fd_prog_recm_txn_try failed: %i-%s", txn_err, fd_map_strerror( txn_err ) ));
  fd_prog_recm_query_t query[1];
  int q_err = fd_prog_recm_txn_query( cache->rec.map, &pair, NULL, query, 0 );
  /* query->ele!=rec rejects a slot recycled under a different key. */
  int ok = !( q_err==FD_MAP_ERR_KEY || query->ele!=rec );

  if( ok && claim ) {
    ok = !!fd_rwlock_trywrite( &rec->lock );
    fd_racesan_hook( "prog_delete_rec:post_claim" );
    if( ok ) {
      /* The write lock freezes the record, so these reads decide: a rooted claim
         needs it detached, an owner claim needs it still owner's (xid rejects a
         recycled txn slot). */
      uchar st   = __atomic_load_n( &rec->state, __ATOMIC_RELAXED );
      uint  want = owner ? (uint)( owner - cache->txn.pool ) : UINT_MAX;
      ok = !!( st & FD_PROGCACHE_REC_LIVE ) & !( st & FD_PROGCACHE_REC_VISITED )
         & ( atomic_load_explicit( &rec->txn_idx, memory_order_relaxed )==want );
      if( owner ) ok &= ( owner->xid==rec->pair.xid );
      if( FD_UNLIKELY( !ok ) ) fd_rwlock_unwrite( &rec->lock );
    }
  }

  if( FD_UNLIKELY( !ok ) ) {
    fd_prog_recm_txn_test( map_txn );
    fd_prog_recm_txn_fini( map_txn );
    return -1L;
  }

  /* Splice an attached victim out of owner's list (owner->lock held by the
     caller), only now that the claim is certain. */
  if( owner ) {
    ulong rec_max = cache->rec.max;
    uint  p = rec->prev_idx;
    uint  n = rec->next_idx;
    if( n!=UINT_MAX ) {
      if( FD_UNLIKELY( (ulong)n>=rec_max ) ) FD_LOG_CRIT(( "progcache: corruption detected (evict unlink next_idx=%u rec_max=%lu)", n, rec_max ));
      cache->rec.ele[ n ].prev_idx = p;
    } else owner->rec_tail_idx = p;
    if( p!=UINT_MAX ) {
      if( FD_UNLIKELY( (ulong)p>=rec_max ) ) FD_LOG_CRIT(( "progcache: corruption detected (evict unlink prev_idx=%u rec_max=%lu)", p, rec_max ));
      cache->rec.ele[ p ].next_idx = n;
    } else owner->rec_head_idx = n;
    atomic_store_explicit( &rec->txn_idx, UINT_MAX, memory_order_release );
  }

  /* Drop record */
  int rm_err = fd_prog_recm_txn_remove( cache->rec.map, &pair, NULL, query, 0 );
  if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) )
    FD_LOG_CRIT(( "fd_prog_recm_txn_remove failed: %i-%s", rm_err, fd_map_strerror( rm_err ) ));
  /* Cleared inside the map txn that removed it, so it is serialized against any
     publish or lookup of this key. */
  __atomic_fetch_and( &rec->state, (uchar)~FD_PROGCACHE_REC_MAPPED, __ATOMIC_RELAXED );
  int test_err = fd_prog_recm_txn_test( map_txn );
  if( FD_UNLIKELY( test_err!=FD_MAP_SUCCESS ) )
    FD_LOG_CRIT(( "fd_prog_recm_txn_test failed: %i-%s", test_err, fd_map_strerror( test_err ) ));
  fd_prog_recm_txn_fini( map_txn );

  /* A claimed record is the caller's, write locked.  Otherwise it is now a
     zombie: unmapped, still LIVE, reused by a later sweep once it is detached
     from its fork and unheld. */
  return (long)rec->rodata_sz;
}

long
fd_prog_delete_rec( fd_progcache_join_t * cache,
                    fd_progcache_rec_t *  rec ) {
  if( !rec ) return -1L;
  fd_progcache_rec_key_t pair = rec->pair;
  return delete_rec_inner( cache, rec, &pair, 0, NULL );
}

long
fd_prog_delete_rec_claim( fd_progcache_join_t *          cache,
                          fd_progcache_rec_t *           rec,
                          fd_progcache_rec_key_t const * pair ) {
  return delete_rec_inner( cache, rec, pair, 1, NULL );
}

long
fd_prog_delete_rec_claim_txn( fd_progcache_join_t *          cache,
                              fd_progcache_rec_t *           rec,
                              fd_progcache_rec_key_t const * pair,
                              fd_progcache_txn_t *           owner ) {
  return delete_rec_inner( cache, rec, pair, 1, owner );
}

ulong
fd_prog_reclaim_work( fd_progcache_join_t * join ) {
  ulong cnt = 0UL;
  for( ulong i=0UL; i<join->rec.max; i++ ) {
    fd_progcache_rec_t * rec = join->rec.ele + i;

    /* Cheap pre-filter: only a zombie (LIVE, unmapped), detached and unheld,
       is a candidate. */
    uchar st = __atomic_load_n( &rec->state, __ATOMIC_RELAXED );
    if( FD_LIKELY( ( st & ( FD_PROGCACHE_REC_LIVE|FD_PROGCACHE_REC_MAPPED ) )!=FD_PROGCACHE_REC_LIVE ) ) continue;
    if( FD_UNLIKELY( atomic_load_explicit( &rec->txn_idx,    memory_order_relaxed )!=UINT_MAX ) ) continue;
    if( FD_UNLIKELY( atomic_load_explicit( &rec->lock.value, memory_order_relaxed )!=0        ) ) continue;

    /* The write lock freezes the record, so the re-check under it decides.  It
       is held only across the check and never while waiting, so nothing can
       deadlock against it. */
    if( FD_UNLIKELY( !fd_rwlock_trywrite( &rec->lock ) ) ) continue;
    uchar cur = __atomic_load_n( &rec->state, __ATOMIC_RELAXED );
    if( FD_UNLIKELY( ( ( cur & ( FD_PROGCACHE_REC_LIVE|FD_PROGCACHE_REC_MAPPED ) )!=FD_PROGCACHE_REC_LIVE ) |
                     ( atomic_load_explicit( &rec->txn_idx, memory_order_relaxed )!=UINT_MAX ) ) ) {
      fd_rwlock_unwrite( &rec->lock );
      continue;
    }
    /* Not unlocked: the write lock becomes the free-list state. */
    fd_progcache_rec_release( join, rec );
    cnt++;
  }
  return cnt;
}
