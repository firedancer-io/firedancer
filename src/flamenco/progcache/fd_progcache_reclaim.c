#include "fd_progcache_reclaim.h"
#include "fd_progcache_clock.h"
#include "fd_progcache_user.h"
#include "../../util/racesan/fd_racesan_target.h"

void
fd_progcache_reclaim_enqueue( fd_progcache_join_t * join,
                              fd_progcache_rec_t *  rec ) {
  uint idx = (uint)( rec - join->rec.ele );
  if( FD_UNLIKELY( (ulong)idx >= join->rec.max ) )
    FD_LOG_CRIT(( "progcache: corruption detected (reclaim_enqueue rec_idx=%u rec_max=%lu)", idx, join->rec.max ));
  /* Push onto the shared reclaim list.  Any join drains it, so the record is
     reclaimed even if a different tile becomes its final reader. */
  fd_progcache_shmem_t * shmem = join->shmem;
  fd_rwlock_write( &shmem->rec.reclaim_lock );
  rec->reclaim_next = shmem->rec.reclaim_head;
  /* Atomic store: fd_progcache_leave polls the head without the lock. */
  __atomic_store_n( &shmem->rec.reclaim_head, idx, __ATOMIC_RELEASE );
  fd_rwlock_unwrite( &shmem->rec.reclaim_lock );
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
      fd_progcache_rec_unlink( join->rec.ele, rec, txn, join->rec.max );
    } else {
      /* Strong CAS failure implies that another thread is already
         unlinking the record (the rooting logic) */
      FD_CHECK_CRIT( atomic_load_explicit( &rec->txn_idx, memory_order_relaxed )==UINT_MAX, "concurrency violation" );
    }
    fd_rwlock_unwrite( &txn->lock );
  }
  fd_racesan_hook( "prog_reclaim:post_unlink" );

  /* Drain existing users
     (record stays write-locked from here until it is re-acquired) */

  if( FD_UNLIKELY( !fd_rwlock_trywrite( &rec->lock ) ) ) return 0;

  /* All users are gone, free the record (returns it to its class) */

  rec->reclaim_next = UINT_MAX;
  fd_progcache_rec_release( join, rec );
  return 1;
}

ulong
fd_progcache_reclaim_work( fd_progcache_join_t * join ) {
  fd_progcache_shmem_t * shmem   = join->shmem;
  ulong                  rec_max = join->rec.max;

  if( FD_LIKELY( __atomic_load_n( &shmem->rec.reclaim_head, __ATOMIC_ACQUIRE )==UINT_MAX ) ) return 0UL;

  /* Detach the whole shared list under the lock, then process it lock-free:
     rec_reclaim takes per-record / per-class / per-txn locks that must not
     nest under reclaim_lock. */
  fd_rwlock_write( &shmem->rec.reclaim_lock );
  uint cur = shmem->rec.reclaim_head;
  __atomic_store_n( &shmem->rec.reclaim_head, UINT_MAX, __ATOMIC_RELEASE );
  fd_rwlock_unwrite( &shmem->rec.reclaim_lock );
  fd_racesan_hook( "prog_reclaim_work:post_detach" );

  /* Records whose readers are still active are collected on a private list
     and spliced back in one go, so a later drain retries them. */
  uint  retry_head = UINT_MAX;
  uint  retry_tail = UINT_MAX;
  ulong cnt        = 0UL;
  while( cur!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)cur >= rec_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (reclaim_work rec_idx=%u rec_max=%lu)", cur, rec_max ));
    fd_progcache_rec_t * rec = &join->rec.ele[ cur ];
    uint next = rec->reclaim_next;
    if( rec_reclaim( join, rec ) ) {
      cnt++;
    } else {
      rec->reclaim_next = retry_head;
      retry_head        = cur;
      if( FD_UNLIKELY( retry_tail==UINT_MAX ) ) retry_tail = cur;
    }
    cur = next;
  }

  if( FD_UNLIKELY( retry_head!=UINT_MAX ) ) {
    fd_racesan_hook( "prog_reclaim_work:pre_splice" );
    /* The private links are published by the release store on the head. */
    fd_rwlock_write( &shmem->rec.reclaim_lock );
    join->rec.ele[ retry_tail ].reclaim_next = shmem->rec.reclaim_head;
    __atomic_store_n( &shmem->rec.reclaim_head, retry_head, __ATOMIC_RELEASE );
    fd_rwlock_unwrite( &shmem->rec.reclaim_lock );
  }
  return cnt;
}

long
fd_progcache_delete_rec( fd_progcache_join_t * cache,
                         fd_progcache_rec_t *  rec ) {
  if( !rec ) return -1L;

  /* rec may be reclaimed and reused while this delete waits for the map
     chain.  Use a stable key for the entire transaction. */
  fd_progcache_rec_key_t pair = rec->pair;

  /* Prepare index removal, and bail if rec is absent from the map */
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
  if( q_err==FD_MAP_ERR_KEY || query->ele!=rec ) {
    fd_prog_recm_txn_test( map_txn );
    fd_prog_recm_txn_fini( map_txn );
    return -1L;
  }

  /* Drop record */
  int rm_err = fd_prog_recm_txn_remove( cache->rec.map, &pair, NULL, query, 0 );
  if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) )
    FD_LOG_CRIT(( "fd_prog_recm_txn_remove failed: %i-%s", rm_err, fd_map_strerror( rm_err ) ));
  int test_err = fd_prog_recm_txn_test( map_txn );
  if( FD_UNLIKELY( test_err!=FD_MAP_SUCCESS ) )
    FD_LOG_CRIT(( "fd_prog_recm_txn_test failed: %i-%s", test_err, fd_map_strerror( test_err ) ));
  fd_prog_recm_txn_fini( map_txn );

  /* Snapshot before enqueue: the shared reclaim list is drainable by any
     join, so the instant the record is enqueued another tile may reclaim
     and reuse it -- rec must not be read after this point.  rodata_sz is
     program bytes, consistent with FillBytes/SpillBytes. */
  long rodata_sz = (long)rec->rodata_sz;
  fd_progcache_reclaim_enqueue( cache, rec );
  return rodata_sz;
}
