#include "fd_progcache.h"
#include "fd_progcache_admin.h"
#include "fd_progcache_base.h"
#include "fd_progcache_clock.h"
#include "fd_progcache_rec.h"
#include "fd_progcache_reclaim.h"
#include "../../util/racesan/fd_racesan_target.h"
#include "../../util/wksp/fd_wksp_private.h"

/* FIXME get rid of this thread-local */
FD_TL fd_progcache_admin_metrics_t fd_progcache_admin_metrics_g;

/* Algorithm to estimate size of cache metadata structures (rec_pool
   object pool and rec_map hashchain table).

   FIXME Carefully balance this */

static ulong
fd_progcache_est_rec_max1( ulong wksp_footprint,
                           ulong mean_cache_entry_size ) {
  return wksp_footprint / mean_cache_entry_size;
}

ulong
fd_progcache_est_rec_max( ulong wksp_footprint,
                          ulong mean_cache_entry_size ) {
  ulong est = fd_progcache_est_rec_max1( wksp_footprint, mean_cache_entry_size );
  if( FD_UNLIKELY( est>(1UL<<31) ) ) FD_LOG_ERR(( "fd_progcache_est_rec_max(wksp_footprint=%lu,mean_cache_entry_size=%lu) failed: invalid parameters", wksp_footprint, mean_cache_entry_size ));
  return fd_ulong_max( est, 2048UL );
}

/* Begin transaction-level operations.  It is assumed that txn data
   structures are not concurrently modified.  This includes txn_pool and
   txn_map. */

void
fd_progcache_attach_child( fd_progcache_join_t * cache,
                           fd_xid_t const *      xid_parent,
                           fd_xid_t const *      xid_new ) {
  fd_rwlock_write( &cache->shmem->txn.rwlock );

  if( FD_UNLIKELY( fd_prog_txnm_idx_query_const( cache->txn.map, xid_new, ULONG_MAX, cache->txn.pool )!=ULONG_MAX ) ) {
    FD_LOG_ERR(( "fd_progcache_attach_child failed: xid %lu:%lu already in use",
                 xid_new->ul[0], xid_new->ul[1] ));
  }
  if( FD_UNLIKELY( fd_prog_txnp_free( cache->txn.pool )==0UL ) ) {
    FD_LOG_ERR(( "fd_progcache_attach_child failed: transaction object pool out of memory" ));
  }

  ulong  txn_max = fd_prog_txnp_max( cache->txn.pool );
  ulong  parent_idx;
  uint * _child_head_idx;
  uint * _child_tail_idx;

  if( FD_UNLIKELY( fd_funk_txn_xid_eq( xid_parent, cache->shmem->txn.last_publish ) ) ) {

    parent_idx = FD_FUNK_TXN_IDX_NULL;

    _child_head_idx = &cache->shmem->txn.child_head_idx;
    _child_tail_idx = &cache->shmem->txn.child_tail_idx;

  } else {

    parent_idx = fd_prog_txnm_idx_query( cache->txn.map, xid_parent, ULONG_MAX, cache->txn.pool );
    if( FD_UNLIKELY( parent_idx==ULONG_MAX ) ) {
      FD_LOG_CRIT(( "fd_progcache_attach_child failed: user provided invalid parent XID %lu:%lu",
                    xid_parent->ul[0], xid_parent->ul[1] ));
    }
    if( FD_UNLIKELY( parent_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (attach_child parent_idx=%lu txn_max=%lu)", parent_idx, txn_max ));

    _child_head_idx = &cache->txn.pool[ parent_idx ].child_head_idx;
    _child_tail_idx = &cache->txn.pool[ parent_idx ].child_tail_idx;

  }

  uint txn_idx = (uint)fd_prog_txnp_idx_acquire( cache->txn.pool );
  if( FD_UNLIKELY( txn_idx==UINT_MAX ) ) FD_LOG_ERR(( "fd_progcache_attach_child failed: transaction object pool out of memory" ));
  fd_progcache_txn_t * txn = &cache->txn.pool[ txn_idx ];
  fd_funk_txn_xid_copy( &txn->xid, xid_new );

  uint sibling_prev_idx = *_child_tail_idx;

  int first_born = sibling_prev_idx==UINT_MAX;
  if( FD_UNLIKELY( !first_born && (ulong)sibling_prev_idx >= txn_max ) )
    FD_LOG_CRIT(( "progcache: corruption detected (attach_child sibling_prev_idx=%u txn_max=%lu)", sibling_prev_idx, txn_max ));

  txn->parent_idx       = (uint)parent_idx;
  txn->child_head_idx   = UINT_MAX;
  txn->child_tail_idx   = UINT_MAX;
  txn->sibling_prev_idx = (uint)sibling_prev_idx;
  txn->sibling_next_idx = UINT_MAX;

  txn->rec_head_idx = UINT_MAX;
  txn->rec_tail_idx = UINT_MAX;

  /* TODO: consider branchless impl */
  if( FD_LIKELY( first_born ) ) *_child_head_idx            = (uint)txn_idx; /* opt for non-compete */
  else cache->txn.pool[ sibling_prev_idx ].sibling_next_idx = (uint)txn_idx;

  *_child_tail_idx = (uint)txn_idx;

  fd_prog_txnm_idx_insert( cache->txn.map, txn_idx, cache->txn.pool );

  fd_rwlock_unwrite( &cache->shmem->txn.rwlock );
}

static void
fd_progcache_cancel_one( fd_progcache_join_t * cache,
                         fd_progcache_txn_t *  txn ) {
  ulong rec_max = fd_prog_recp_ele_max( cache->rec.pool );
  ulong txn_max = fd_prog_txnp_max( cache->txn.pool );

  fd_rwlock_write( &txn->lock );

  if( FD_UNLIKELY( txn->child_head_idx!=UINT_MAX ||
                   txn->child_tail_idx!=UINT_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_cancel failed: txn at %p with xid %lu:%lu has children (data corruption?)",
                  (void *)txn, txn->xid.ul[0], txn->xid.ul[1] ));
  }

  /* Remove records */

  for( uint idx = txn->rec_head_idx; idx!=UINT_MAX; idx = cache->rec.pool->ele[ idx ].next_idx ) {
    if( FD_UNLIKELY( (ulong)idx >= rec_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_one rec_idx=%u rec_max=%lu)", idx, rec_max ));
    atomic_store_explicit( &cache->rec.pool->ele[ idx ].txn_idx, UINT_MAX, memory_order_release );
    fd_racesan_hook( "prog_cancel_one:post_orphan" );
    fd_prog_delete_rec( cache, &cache->rec.pool->ele[ idx ] );
  }

  txn->rec_head_idx = UINT_MAX;
  txn->rec_tail_idx = UINT_MAX;

  /* Remove transaction from fork graph */

  uint self_idx = (uint)( txn - cache->txn.pool );
  uint prev_idx = txn->sibling_prev_idx;
  uint next_idx = txn->sibling_next_idx;
  if( next_idx!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)next_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_one sibling_next_idx=%u txn_max=%lu)", next_idx, txn_max ));
    cache->txn.pool[ next_idx ].sibling_prev_idx = prev_idx;
  }
  if( prev_idx!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)prev_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_one sibling_prev_idx=%u txn_max=%lu)", prev_idx, txn_max ));
    cache->txn.pool[ prev_idx ].sibling_next_idx = next_idx;
  }
  if( txn->parent_idx!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)txn->parent_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_one parent_idx=%u txn_max=%lu)", txn->parent_idx, txn_max ));
    fd_progcache_txn_t * parent = &cache->txn.pool[ txn->parent_idx ];
    if( parent->child_head_idx==self_idx ) parent->child_head_idx = next_idx;
    if( parent->child_tail_idx==self_idx ) parent->child_tail_idx = prev_idx;
  } else {
    if( cache->shmem->txn.child_head_idx==self_idx ) cache->shmem->txn.child_head_idx = next_idx;
    if( cache->shmem->txn.child_tail_idx==self_idx ) cache->shmem->txn.child_tail_idx = prev_idx;
  }

  /* Remove transaction from index */

  if( FD_UNLIKELY( !fd_prog_txnm_ele_remove( cache->txn.map, &txn->xid, NULL, cache->txn.pool ) ) ) {
    FD_LOG_CRIT(( "fd_progcache_cancel failed: fd_funk_txn_map_remove(%lu:%lu) failed",
                  txn->xid.ul[0], txn->xid.ul[1] ));
  }

  /* Free transaction object */

  fd_rwlock_unwrite( &txn->lock );
  fd_prog_txnp_ele_release( cache->txn.pool, txn );
}

/* Cancels txn and all children */

static void
fd_progcache_cancel_tree( fd_progcache_join_t * cache,
                          fd_progcache_txn_t *  txn ) {
  ulong txn_max = fd_prog_txnp_max( cache->txn.pool );
  for(;;) {
    uint child_idx = txn->child_head_idx;
    if( child_idx==UINT_MAX ) break;
    if( FD_UNLIKELY( (ulong)child_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_tree child_idx=%u txn_max=%lu)", child_idx, txn_max ));
    fd_progcache_txn_t * child = &cache->txn.pool[ child_idx ];
    fd_progcache_cancel_tree( cache, child );
  }
  fd_progcache_cancel_one( cache, txn );
}

/* Cancels all left/right siblings */

static void
fd_progcache_cancel_prev_list( fd_progcache_join_t * cache,
                               fd_progcache_txn_t *  txn ) {
  ulong txn_max = fd_prog_txnp_max( cache->txn.pool );
  uint cur_idx = txn->sibling_prev_idx;
  while( cur_idx!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)cur_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_prev_list txn_idx=%u txn_max=%lu)", cur_idx, txn_max ));
    fd_progcache_txn_t * sibling = &cache->txn.pool[ cur_idx ];
    uint next = sibling->sibling_prev_idx;
    fd_progcache_cancel_tree( cache, sibling );
    cur_idx = next;
  }
}

static void
fd_progcache_cancel_next_list( fd_progcache_join_t * cache,
                               fd_progcache_txn_t *  txn ) {
  ulong txn_max = fd_prog_txnp_max( cache->txn.pool );
  uint cur_idx = txn->sibling_next_idx;
  while( cur_idx!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)cur_idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (cancel_next_list txn_idx=%u txn_max=%lu)", cur_idx, txn_max ));
    fd_progcache_txn_t * sibling = &cache->txn.pool[ cur_idx ];
    uint next = sibling->sibling_next_idx;
    fd_progcache_cancel_tree( cache, sibling );
    cur_idx = next;
  }
}

/* Move list of records to root txn (advance_root)

   For each record to be rooted:
   - gc_root to remove any shadowed rooted revision
   - drain readers
   - release if invalidation (which are now a no-op) */

static void
fd_progcache_txn_publish_release( fd_progcache_join_t * cache,
                                  uint                  head ) {
  ulong rec_max = fd_prog_recp_ele_max( cache->rec.pool );
  while( head!=UINT_MAX ) {
    if( FD_UNLIKELY( (ulong)head >= rec_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (publish_release rec_idx=%u rec_max=%lu)", head, rec_max ));
    fd_progcache_rec_t * rec = &cache->rec.pool->ele[ head ];
    uint next = rec->next_idx;

    /* Lock rec_map chain */
    struct {
      fd_prog_recm_txn_t txn[1];
      fd_prog_recm_txn_private_info_t info[1];
    } _map_txn;
    fd_prog_recm_txn_t * map_txn = fd_prog_recm_txn_init( _map_txn.txn, cache->rec.map, 1UL );
    fd_prog_recm_txn_add( map_txn, &rec->pair, 1 );
    int txn_err = fd_prog_recm_txn_try( map_txn, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( txn_err!=FD_MAP_SUCCESS ) ) {
      FD_LOG_CRIT(( "Failed to insert progcache record: cannot lock funk rec map chain: %i-%s", txn_err, fd_map_strerror( txn_err ) ));
    }

    /* Evict previous root value */
    fd_funk_xid_key_pair_t pair[1];
    fd_funk_rec_key_copy( pair->key, rec->pair.key );
    fd_funk_txn_xid_set_root( pair->xid );
    if( fd_prog_delete_rec_by_key( cache, pair, 0 )>=0 ) {
      fd_progcache_admin_metrics_g.gc_root_cnt++;
    }

    /* Migrate record to root */
    fd_rwlock_write( &rec->lock );
    fd_racesan_hook( "prog_publish_release:pre_retag" );
    rec->prev_idx = UINT_MAX;
    rec->next_idx = UINT_MAX;
    atomic_store_explicit( &rec->txn_idx, UINT_MAX, memory_order_release );
    fd_xid_t const root = { .ul = { ULONG_MAX, ULONG_MAX } };
    fd_funk_txn_xid_st_atomic( rec->pair.xid, &root );
    fd_rwlock_unwrite( &rec->lock );
    fd_progcache_admin_metrics_g.root_cnt++;

    /* Unlock rec_map chain */
    int test_err = fd_prog_recm_txn_test( map_txn );
    if( FD_UNLIKELY( test_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_txn_test failed: %i-%s", test_err, fd_map_strerror( test_err ) ));
    fd_prog_recm_txn_fini( map_txn );

    head = next;
  }
}

/* fd_progcache_txn_publish_one merges an in-prep transaction whose
   parent is the last published, into the parent. */

static uint
fd_progcache_txn_publish_one( fd_progcache_join_t * cache,
                              fd_progcache_txn_t *  txn ) {

  /* Phase 1: Mark transaction as "last published" */

  fd_xid_t const xid = txn->xid;
  if( FD_UNLIKELY( txn->parent_idx!=UINT_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_publish failed: txn with xid %lu:%lu is not a child of the last published txn", xid.ul[0], xid.ul[1] ));
  }
  fd_racesan_hook( "prog_publish_one:pre_xid_store" );
  fd_funk_txn_xid_st_atomic( cache->shmem->txn.last_publish, &xid );

  /* Phase 2: Drain inserters from transaction */

  fd_rwlock_write( &txn->lock );

  /* Phase 3: Detach records */

  ulong rec_max = fd_prog_recp_ele_max( cache->rec.pool );
  for( uint idx = txn->rec_head_idx; idx!=UINT_MAX; idx = cache->rec.pool->ele[ idx ].next_idx ) {
    if( FD_UNLIKELY( (ulong)idx >= rec_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (publish_one rec_idx=%u rec_max=%lu)", idx, rec_max ));
    atomic_store_explicit( &cache->rec.pool->ele[ idx ].txn_idx, UINT_MAX, memory_order_release );
  }

  uint rec_head = txn->rec_head_idx;
  txn->rec_head_idx = UINT_MAX;
  txn->rec_tail_idx = UINT_MAX;

  /* Phase 4: Remove transaction from fork graph */

  { /* Adjust the parent pointers of the children to point to "last published" */
    ulong txn_max = fd_prog_txnp_max( cache->txn.pool );
    ulong child_idx = txn->child_head_idx;
    while( child_idx!=UINT_MAX ) {
      if( FD_UNLIKELY( child_idx >= txn_max ) )
        FD_LOG_CRIT(( "progcache: corruption detected (publish_one child_idx=%lu txn_max=%lu)", child_idx, txn_max ));
      cache->txn.pool[ child_idx ].parent_idx = UINT_MAX;
      child_idx = cache->txn.pool[ child_idx ].sibling_next_idx;
    }
  }

  /* Phase 5: Remove transaction from index */

  if( FD_UNLIKELY( fd_prog_txnm_idx_remove( cache->txn.map, &txn->xid, ULONG_MAX, cache->txn.pool )==ULONG_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_publish failed: fd_funk_txn_map_remove(%lu:%lu) failed",
                  xid.ul[0], xid.ul[1] ));
  }

  /* Phase 6: Free transaction object */

  fd_rwlock_unwrite( &txn->lock );
  txn->parent_idx       = UINT_MAX;
  txn->sibling_prev_idx = UINT_MAX;
  txn->sibling_next_idx = UINT_MAX;
  txn->child_head_idx   = UINT_MAX;
  txn->child_tail_idx   = UINT_MAX;
  fd_prog_txnp_ele_release( cache->txn.pool, txn );

  return rec_head;
}

void
fd_progcache_advance_root( fd_progcache_join_t * cache,
                           fd_xid_t const *      xid ) {

  /* Detach records from txns without acquiring record locks */

  fd_rwlock_write( &cache->shmem->txn.rwlock );

  ulong txn_max = fd_prog_txnp_max( cache->txn.pool );
  uint txn_idx = (uint)fd_prog_txnm_idx_query( cache->txn.map, xid, UINT_MAX, cache->txn.pool );
  if( FD_UNLIKELY( txn_idx==UINT_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_advance_root failed: invalid XID %lu:%lu",
                  xid->ul[0], xid->ul[1] ));
  }
  if( FD_UNLIKELY( (ulong)txn_idx >= txn_max ) )
    FD_LOG_CRIT(( "progcache: corruption detected (advance_root txn_idx=%u txn_max=%lu)", txn_idx, txn_max ));
  fd_progcache_txn_t * txn = &cache->txn.pool[ txn_idx ];
  if( FD_UNLIKELY( txn->parent_idx!=UINT_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_advance_root: parent of txn %lu:%lu is not root", xid->ul[0], xid->ul[1] ));
  }

  fd_progcache_cancel_prev_list( cache, txn );
  fd_progcache_cancel_next_list( cache, txn );

  txn->sibling_prev_idx = UINT_MAX;
  txn->sibling_next_idx = UINT_MAX;
  cache->shmem->txn.child_head_idx = txn->child_head_idx;
  cache->shmem->txn.child_tail_idx = txn->child_tail_idx;

  uint publish_head = fd_progcache_txn_publish_one( cache, txn );

  fd_rwlock_unwrite( &cache->shmem->txn.rwlock );

  /* Update records */

  fd_prog_reclaim_work( cache );
  fd_progcache_txn_publish_release( cache, publish_head );
}

void
fd_progcache_cancel( fd_progcache_join_t * cache,
                     fd_xid_t const *      xid ) {

  fd_rwlock_write( &cache->shmem->txn.rwlock );
  fd_progcache_txn_t * txn = fd_prog_txnm_ele_query( cache->txn.map, xid, NULL, cache->txn.pool );
  if( FD_UNLIKELY( !txn ) ) {
    FD_LOG_CRIT(( "fd_progcache_cancel failed: invalid XID %lu:%lu",
                  xid->ul[0], xid->ul[1] ));
  }
  fd_progcache_cancel_tree( cache, txn );
  fd_rwlock_unwrite( &cache->shmem->txn.rwlock );
  fd_prog_reclaim_work( cache );
}

/* reset_txn_list does a depth-first traversal of the txn tree.
   Detaches all recs from txns by emptying rec linked lists. */

static void
reset_txn_list( fd_progcache_join_t * cache,
                uint                  txn_head_idx ) {
  ulong txn_max = fd_prog_txnp_max( cache->txn.pool );
  for( uint idx = txn_head_idx; idx!=UINT_MAX; ) {
    if( FD_UNLIKELY( (ulong)idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (reset_txn_list txn_idx=%u txn_max=%lu)", idx, txn_max ));
    fd_progcache_txn_t * txn = &cache->txn.pool[ idx ];
    txn->rec_head_idx = UINT_MAX;
    txn->rec_tail_idx = UINT_MAX;
    reset_txn_list( cache, txn->child_head_idx );
    idx = txn->sibling_next_idx;
  }
}

/* reset_rec_map frees all records in a funk instance. */

static void
reset_rec_map( fd_progcache_join_t * cache ) {
  fd_progcache_rec_t * rec0 = cache->rec.pool->ele;
  ulong chain_cnt = fd_prog_recm_chain_cnt( cache->rec.map );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    for(
        fd_prog_recm_iter_t iter = fd_prog_recm_iter( cache->rec.map, chain_idx );
        !fd_prog_recm_iter_done( iter );
    ) {
      fd_progcache_rec_t * rec = fd_prog_recm_iter_ele( iter );
      ulong next = fd_prog_recm_private_idx( rec->map_next );

      if( rec->exists ) {
        fd_prog_recm_query_t rec_query[1];
        int err = fd_prog_recm_remove( cache->rec.map, &rec->pair, NULL, rec_query, FD_MAP_FLAG_BLOCKING );
        if( FD_UNLIKELY( err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_remove failed (%i-%s)", err, fd_map_strerror( err ) ));
        fd_progcache_val_free( rec, cache );
      }

      rec->exists = 0;
      fd_prog_clock_remove( cache->clock.bits, (ulong)( rec-rec0 ) );
      fd_prog_recp_release( cache->rec.pool, rec, 1 );
      iter.ele_idx = next;
    }
  }
}

void
fd_progcache_reset( fd_progcache_join_t * cache ) {
  reset_txn_list( cache, cache->shmem->txn.child_head_idx );
  reset_rec_map( cache );
}

/* clear_txn_list does a depth-first traversal of the txn tree.
   Removes all txns. */

static void
clear_txn_list( fd_progcache_join_t * join,
                uint                  txn_head_idx ) {
  ulong txn_max = fd_prog_txnp_max( join->txn.pool );
  for( uint idx = txn_head_idx; idx!=UINT_MAX; ) {
    if( FD_UNLIKELY( (ulong)idx >= txn_max ) )
      FD_LOG_CRIT(( "progcache: corruption detected (clear_txn_list txn_idx=%u txn_max=%lu)", idx, txn_max ));
    fd_progcache_txn_t * txn = &join->txn.pool[ idx ];
    uint next_idx  = txn->sibling_next_idx;
    uint child_idx = txn->child_head_idx;
    txn->rec_head_idx     = UINT_MAX;
    txn->rec_tail_idx     = UINT_MAX;
    txn->child_head_idx   = UINT_MAX;
    txn->child_tail_idx   = UINT_MAX;
    txn->parent_idx       = UINT_MAX;
    txn->sibling_prev_idx = UINT_MAX;
    txn->sibling_next_idx = UINT_MAX;
    clear_txn_list( join, child_idx );
    if( FD_UNLIKELY( !fd_prog_txnm_ele_remove( join->txn.map, &txn->xid, NULL, join->txn.pool ) ) ) FD_LOG_CRIT(( "fd_prog_txnm_ele_remove failed" ));
    fd_prog_txnp_ele_release( join->txn.pool, txn );
    idx = next_idx;
  }
}

void
fd_progcache_clear( fd_progcache_join_t * cache ) {
  clear_txn_list( cache, cache->shmem->txn.child_head_idx );
  cache->shmem->txn.child_head_idx = UINT_MAX;
  cache->shmem->txn.child_tail_idx = UINT_MAX;
  reset_rec_map( cache );
}

static int
fd_progcache_verify_siblings( fd_progcache_txn_t * pool,
                              ulong                txn_max,
                              uint                 head_idx,
                              uint                 tail_idx,
                              uint                 expected_parent_idx,
                              uint *               stack,
                              ulong *              stack_top ) {

# define TEST(c) do {                                                    \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return -1; } \
  } while(0)

  TEST( (head_idx==UINT_MAX)==(tail_idx==UINT_MAX) );

  uint last_idx = UINT_MAX;
  for( uint idx = head_idx; idx!=UINT_MAX; ) {
    TEST( idx<txn_max );
    fd_progcache_txn_t * child = &pool[ idx ];
    TEST( !child->tag );
    TEST( child->parent_idx==expected_parent_idx );
    child->tag = 1;
    TEST( *stack_top<FD_PROGCACHE_DEPTH_MAX );
    stack[ (*stack_top)++ ] = idx;
    last_idx = idx;
    uint next_idx = child->sibling_next_idx;
    if( next_idx!=UINT_MAX ) {
      TEST( next_idx<txn_max );
      TEST( pool[ next_idx ].sibling_prev_idx==idx );
    }
    idx = next_idx;
  }
  TEST( last_idx==tail_idx );

# undef TEST

  return 0;
}

int
fd_progcache_verify( fd_progcache_join_t * join ) {

# define TEST(c) do {                                                    \
    if( FD_UNLIKELY( !(c) ) ) { FD_LOG_WARNING(( "FAIL: %s", #c )); return -1; } \
  } while(0)

  TEST( join );

  fd_progcache_shmem_t * shmem = join->shmem;
  TEST( shmem );
  TEST( shmem->magic==FD_PROGCACHE_SHMEM_MAGIC );
  TEST( shmem->wksp_tag );

  TEST( !fd_prog_recp_verify( join->rec.pool ) );
  TEST( !fd_prog_recm_verify( join->rec.map ) );

  ulong rec_max = fd_prog_recp_ele_max( join->rec.pool );
  fd_progcache_rec_t * rec0 = join->rec.pool->ele;

  ulong txn_max = fd_prog_txnp_max( join->txn.pool );
  TEST( !fd_prog_txnm_verify( join->txn.map, txn_max, join->txn.pool ) );

  for( ulong i=0UL; i<txn_max; i++ ) join->txn.pool[ i ].tag = 0;

  uint  stack[ FD_PROGCACHE_DEPTH_MAX ];
  ulong stack_top = 0UL;

  TEST( !fd_progcache_verify_siblings( join->txn.pool, txn_max,
      shmem->txn.child_head_idx, shmem->txn.child_tail_idx,
      UINT_MAX, stack, &stack_top ) );

  while( stack_top ) {
    uint txn_idx = stack[ --stack_top ];
    fd_progcache_txn_t * txn = &join->txn.pool[ txn_idx ];
    TEST( !fd_progcache_verify_siblings( join->txn.pool, txn_max,
        txn->child_head_idx, txn->child_tail_idx,
        txn_idx, stack, &stack_top ) );
  }

  for( ulong i=0UL; i<txn_max; i++ ) {
    if( !join->txn.pool[ i ].tag ) continue;
    fd_progcache_txn_t * txn = &join->txn.pool[ i ];

    TEST( (txn->rec_head_idx==UINT_MAX)==(txn->rec_tail_idx==UINT_MAX) );

    ulong rec_cnt = 0UL;
    uint  prev    = UINT_MAX;
    for( uint idx = txn->rec_head_idx; idx!=UINT_MAX; ) {
      TEST( idx<rec_max );
      TEST( rec_cnt<rec_max ); /* cycle detection */
      fd_progcache_rec_t * rec = &rec0[ idx ];
      TEST( rec->prev_idx==prev );
      TEST( rec->exists );
      prev = idx;
      idx  = rec->next_idx;
      rec_cnt++;
    }
    TEST( prev==txn->rec_tail_idx );
  }

  ulong chain_cnt = fd_prog_recm_chain_cnt( join->rec.map );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    for(
        fd_prog_recm_iter_t iter = fd_prog_recm_iter( join->rec.map, chain_idx );
        !fd_prog_recm_iter_done( iter );
        iter = fd_prog_recm_iter_next( iter )
    ) {
      fd_progcache_rec_t * rec = fd_prog_recm_iter_ele( iter );
      TEST( rec->exists );

      /* Verify clock exists bit is set for mapped records */
      ulong rec_idx = (ulong)( rec - rec0 );
      TEST( rec_idx<rec_max );
      atomic_ulong * slot_p = fd_prog_cbits_slot( join->clock.bits, rec_idx );
      ulong slot_val = atomic_load_explicit( slot_p, memory_order_relaxed );
      TEST( fd_ulong_extract_bit( slot_val, fd_prog_exists_bit( rec_idx ) ) );
    }
  }

  {
    ulong reclaim_cnt = 0UL;
    for( uint idx = join->rec.reclaim_head; idx!=UINT_MAX; ) {
      TEST( idx<rec_max );
      TEST( reclaim_cnt<rec_max ); /* cycle detection */
      idx = rec0[ idx ].reclaim_next;
      reclaim_cnt++;
    }
  }

# undef TEST

  return 0;
}

void
fd_progcache_wksp_metrics_update( fd_progcache_join_t * cache ) {
  fd_wksp_t * wksp = fd_wksp_containing( cache->shmem );
  if( FD_UNLIKELY( !wksp ) ) return;
  if( FD_UNLIKELY( fd_wksp_private_lock( wksp ) ) ) FD_LOG_CRIT(( "fd_wksp_private_lock failed" ));

  fd_wksp_private_pinfo_t * pinfo = fd_wksp_private_pinfo( wksp );
  ulong part_max  = wksp->part_max;
  ulong cycle_tag = wksp->cycle_tag++;

  ulong free_part_cnt    = 0UL;
  ulong free_sz     = 0UL;
  ulong total_sz    = 0UL;
  ulong free_part_max = 0UL;

  ulong i = fd_wksp_private_pinfo_idx( wksp->part_head_cidx );
  while( !fd_wksp_private_pinfo_idx_is_null( i ) ) {
    if( FD_UNLIKELY( i>=part_max ) || FD_UNLIKELY( pinfo[ i ].cycle_tag==cycle_tag ) ) {
      FD_LOG_CRIT(( "corrupt wksp detected" ));
    }
    pinfo[ i ].cycle_tag = cycle_tag; /* mark i as visited */
    ulong part_sz  = fd_wksp_private_pinfo_sz( pinfo + i );
    ulong part_tag = pinfo[ i ].tag;
    ulong free_psz = fd_ulong_if( !part_tag, part_sz, 0UL );
    free_part_cnt  += !part_tag;
    free_sz        += free_psz;
    total_sz       += part_sz;
    free_part_max   = fd_ulong_max( free_part_max, free_psz );
    i = fd_wksp_private_pinfo_idx( pinfo[ i ].next_cidx );
  }
  fd_wksp_private_unlock( wksp );

  fd_progcache_admin_metrics_t * m = &fd_progcache_admin_metrics_g;
  m->wksp.free_part_cnt = free_part_cnt;
  m->wksp.free_sz       = free_sz;
  m->wksp.total_sz      = total_sz;
  m->wksp.free_part_max = free_part_max;
}
