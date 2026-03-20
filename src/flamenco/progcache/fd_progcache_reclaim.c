#include "fd_progcache_reclaim.h"
#include "fd_progcache_clock.h"
#include "fd_progcache_user.h"
#include "../../util/racesan/fd_racesan_target.h"

void
fd_prog_reclaim_enqueue( fd_progcache_join_t * join,
                         fd_progcache_rec_t *  rec ) {
  uint idx = (uint)( rec - join->rec.pool->ele );
  ulong rec_max = fd_prog_recp_ele_max( join->rec.pool );
  if( FD_UNLIKELY( (ulong)idx >= rec_max ) )
    FD_LOG_CRIT(( "progcache: corruption detected (reclaim_enqueue rec_idx=%u rec_max=%lu)", idx, rec_max ));
  rec->reclaim_next = join->rec.reclaim_head;
  join->rec.reclaim_head = idx;
}

static _Bool
rec_reclaim( fd_progcache_join_t * join,
             fd_progcache_rec_t *  rec ) {

  /* Remove the record from a transaction */

  ulong txn_max = fd_prog_txnp_max( join->txn.pool );
  uint txn_idx = atomic_load_explicit( &rec->txn_idx, memory_order_acquire );
  if( txn_idx!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)txn_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (rec_reclaim txn_idx=%u txn_max=%lu)", txn_idx, txn_max ));
    fd_progcache_txn_t * txn = &join->txn.pool[ txn_idx ];
    fd_rwlock_write( &txn->lock );
    fd_racesan_hook( "prog_reclaim:pre_cas" );
    if( atomic_compare_exchange_strong_explicit( &rec->txn_idx, &txn_idx, UINT_MAX, memory_order_acq_rel, memory_order_acquire ) ) {
      /* A transaction may not be deallocated before all records are
         unlinked. */
      fd_progcache_rec_unlink( join->rec.pool->ele, rec, txn, join->rec.pool->ele_max );
    } else {
      /* Strong CAS failure implies that another thread is already
         unlinking the record (the rooting logic) */
      FD_CRIT( atomic_load_explicit( &rec->txn_idx, memory_order_relaxed )==UINT_MAX, "concurrency violation" );
    }
    fd_rwlock_unwrite( &txn->lock );
  }
  fd_racesan_hook( "prog_reclaim:post_unlink" );

  /* Drain existing users

     Records are removed from recm (index) before the record is selected
     for reclamation.  Therefore, it is not necessary to acquire a lock.
     It is fine to wait for existing users to drain. */

  if( FD_UNLIKELY( FD_VOLATILE_CONST( rec->lock.value ) ) ) return 0;

  /* All users are gone, deallocate record */

  rec->reclaim_next = UINT_MAX;
  fd_progcache_val_free( rec, join );
  rec->exists = 0;
  fd_prog_clock_remove( join->clock.bits, (ulong)( rec - join->rec.pool->ele ) );
  fd_prog_recp_release( join->rec.pool, rec, 1 );
  return 1;
}

ulong
fd_prog_reclaim_work( fd_progcache_join_t * join ) {
  ulong  rec_max = fd_prog_recp_ele_max( join->rec.pool );
  ulong  cnt     = 0UL;
  uint * prev_p  = &join->rec.reclaim_head;
  uint   cur     = join->rec.reclaim_head;
  while( cur!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)cur >= rec_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (reclaim_work rec_idx=%u rec_max=%lu)", cur, rec_max ));
    fd_progcache_rec_t * rec = &join->rec.pool->ele[ cur ];
    uint next = rec->reclaim_next;
    if( rec_reclaim( join, rec ) ) {
      *prev_p = next;
      cnt++;
    } else {
      prev_p = &rec->reclaim_next;
    }
    cur = next;
  }
  return cnt;
}

long
fd_prog_delete_rec( fd_progcache_join_t * cache,
                    fd_progcache_rec_t *  rec ) {
  if( !rec ) return -1L;
  fd_prog_recm_query_t query[1];
  int rm_err = fd_prog_recm_remove( cache->rec.map, &rec->pair, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( rm_err==FD_MAP_ERR_KEY ) return -1L;
  if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_remove failed: %i-%s", rm_err, fd_map_strerror( rm_err ) ));
  if( FD_UNLIKELY( query->ele!=rec ) ) FD_LOG_CRIT(( "record collision (rec=%p found=%p)", (void *)rec, (void *)query->ele ));
  fd_prog_reclaim_enqueue( cache, rec );
  return (long)rec->data_max;
}

long
fd_prog_delete_rec_by_key( fd_progcache_join_t *          cache,
                           fd_funk_xid_key_pair_t const * key,
                           _Bool                          lock ) {
  fd_prog_recm_query_t query[1];
  int rm_err;
  if( lock ) rm_err = fd_prog_recm_remove    ( cache->rec.map, key, NULL, query, FD_MAP_FLAG_BLOCKING );
  else       rm_err = fd_prog_recm_txn_remove( cache->rec.map, key, NULL, query, 0                    );
  if( rm_err==FD_MAP_ERR_KEY ) return -1L;
  if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_remove failed: %i-%s", rm_err, fd_map_strerror( rm_err ) ));
  fd_prog_reclaim_enqueue( cache, query->ele );
  return (long)query->ele->data_max;
}
