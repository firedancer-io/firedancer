#include "fd_progcache_reclaim.h"
#include "fd_progcache_clock.h"
#include "fd_progcache_user.h"

void
fd_prog_reclaim_enqueue( fd_progcache_join_t * join,
                         fd_progcache_rec_t *  rec ) {
  FD_CRIT( rec->map_next==UINT_MAX, "rec is not free" );
  rec->map_next = join->rec.reclaim_head;
  join->rec.reclaim_head = (uint)( rec - join->rec.pool->ele );
}

static _Bool
rec_reclaim( fd_progcache_join_t * join,
             fd_progcache_rec_t *  rec ) {

  /* Remove the record from a transaction */

  uint txn_idx = atomic_load_explicit( &rec->txn_idx, memory_order_acquire );
  if( txn_idx!=UINT_MAX ) {
    fd_progcache_txn_t * txn = &join->txn.pool[ txn_idx ];
    fd_rwlock_write( &txn->lock );
    if( atomic_compare_exchange_strong_explicit( &rec->txn_idx, &txn_idx, UINT_MAX, memory_order_acq_rel, memory_order_acquire ) ) {
      /* A transaction may not be deallocated before all records are
         unlinked. */
      fd_progcache_rec_unlink( join->rec.pool->ele, rec, txn );
    } else {
      /* Strong CAS failure implies that another thread is already
         unlinking the record (the rooting logic) */
      FD_CRIT( atomic_load_explicit( &rec->txn_idx, memory_order_relaxed )==UINT_MAX, "concurrency violation" );
    }
    fd_rwlock_unwrite( &txn->lock );
  }

  /* Drain existing users

     Records are removed from recm (index) before the record is selected
     for reclamation.  Therefore, it is not necessary to acquire a lock.
     It is fine to wait for existing users to drain. */

  if( FD_UNLIKELY( atomic_load_explicit( (atomic_ushort *)&rec->lock.value, memory_order_relaxed ) ) ) return 0;

  /* All users are gone, deallocate record */

  rec->map_next = UINT_MAX;
  fd_progcache_val_free( rec, join );
  rec->exists = 0;
  fd_prog_clock_remove( join->clock.bits, (ulong)( rec - join->rec.pool->ele ) );
  fd_prog_recp_release( join->rec.pool, rec, 1 );
  return 1;
}

ulong
fd_prog_reclaim_work( fd_progcache_join_t * join ) {
  ulong  cnt    = 0UL;
  uint * prev_p = &join->rec.reclaim_head;
  uint   cur    = join->rec.reclaim_head;
  while( cur!=UINT_MAX ) {
    fd_progcache_rec_t * rec = &join->rec.pool->ele[ cur ];
    uint next = rec->map_next;
    if( rec_reclaim( join, rec ) ) {
      *prev_p = next;
      cnt++;
    } else {
      prev_p = &rec->map_next;
    }
    cur = next;
  }
  return cnt;
}

static fd_progcache_rec_t *
rec_hide( fd_progcache_join_t *          cache,
          fd_funk_xid_key_pair_t const * key,
          fd_progcache_rec_t *           rec ) {
  fd_prog_recm_query_t query[1];
  int rm_err = fd_prog_recm_remove( cache->rec.map, key, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( rm_err==FD_MAP_ERR_KEY ) return NULL;
  if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_remove failed: %i-%s", rm_err, fd_map_strerror( rm_err ) ));
  if( FD_UNLIKELY( rec && query->ele!=rec ) ) FD_LOG_CRIT(( "record collision (rec=%p found=%p)", (void *)rec, (void *)query->ele ));
  return query->ele;
}

long
fd_prog_delete_rec( fd_progcache_join_t * cache,
                    fd_progcache_rec_t *  rec ) {
  if( FD_UNLIKELY( !rec_hide( cache, &rec->pair, rec ) ) ) return -1L;
  fd_prog_reclaim_enqueue( cache, rec );
  return (long)rec->data_max;
}

_Bool
fd_prog_delete_rec_imm( fd_progcache_join_t *          cache,
                        fd_funk_xid_key_pair_t const * key ) {
  fd_progcache_rec_t * rec = rec_hide( cache, key, NULL );
  if( FD_UNLIKELY( !rec ) ) return 0;

  fd_rwlock_write( &rec->lock );

  memset( &rec->pair, 0, sizeof(fd_funk_xid_key_pair_t) ); /* invalidate */
  FD_COMPILER_MFENCE();

  rec->map_next = UINT_MAX;
  fd_progcache_val_free( rec, cache );
  rec->exists = 0;
  fd_rwlock_unwrite( &rec->lock );
  fd_prog_clock_remove( cache->clock.bits, (ulong)( rec - cache->rec.pool->ele ) );
  fd_prog_recp_release( cache->rec.pool, rec, 1 );
  return 1;
}
