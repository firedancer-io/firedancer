#include "fd_progcache.h"
#include "fd_progcache_admin.h"
#include "fd_progcache_rec.h"
#include "fd_prog_load.h"
#include "../runtime/program/fd_bpf_loader_program.h"
#include "../runtime/program/fd_loader_v4_program.h"
#include "../runtime/fd_system_ids.h"
#include "../../util/wksp/fd_wksp_private.h"

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
fd_progcache_txn_attach_child( fd_progcache_join_t *      cache,
                               fd_progcache_xid_t const * xid_parent,
                               fd_progcache_xid_t const * xid_new ) {
  fd_rwlock_write( &cache->shmem->txn.rwlock );

  if( FD_UNLIKELY( fd_prog_txnm_idx_query_const( cache->txn.map, xid_new, ULONG_MAX, cache->txn.pool )!=ULONG_MAX ) ) {
    FD_LOG_ERR(( "fd_progcache_txn_attach_child failed: xid %lu:%lu already in use",
                 xid_new->ul[0], xid_new->ul[1] ));
  }
  if( FD_UNLIKELY( fd_prog_txnp_free( cache->txn.pool )==0UL ) ) {
    FD_LOG_ERR(( "fd_progcache_txn_attach_child failed: transaction object pool out of memory" ));
  }

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
      FD_LOG_CRIT(( "fd_funk_txn_prepare failed: user provided invalid parent XID %lu:%lu",
                    xid_parent->ul[0], xid_parent->ul[1] ));
    }

    _child_head_idx = &cache->txn.pool[ parent_idx ].child_head_idx;
    _child_tail_idx = &cache->txn.pool[ parent_idx ].child_tail_idx;

  }

  uint txn_idx = (uint)fd_prog_txnp_idx_acquire( cache->txn.pool );
  if( FD_UNLIKELY( txn_idx==UINT_MAX ) ) FD_LOG_ERR(( "fd_funk_txn_prepare failed: transaction object pool out of memory" ));
  fd_progcache_txn_t * txn = &cache->txn.pool[ txn_idx ];
  fd_funk_txn_xid_copy( &txn->xid, xid_new );

  uint sibling_prev_idx = *_child_tail_idx;

  int first_born = sibling_prev_idx==UINT_MAX;

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

  FD_LOG_INFO(( "progcache xid %lu:%lu: created with parent %lu:%lu",
                xid_new   ->ul[0], xid_new   ->ul[1],
                xid_parent->ul[0], xid_parent->ul[1] ));
}

static void
fd_progcache_rec_list_append( fd_progcache_rec_t * rec_pool,
                              uint *               list_head,
                              uint *               list_tail,
                              uint                 rec_head,
                              uint                 rec_tail ) {
  if( rec_head==UINT_MAX ) return;
  if( *list_tail!=UINT_MAX ) {
    rec_pool[ *list_tail ].next_idx = rec_head;
  } else {
    *list_head = rec_head;
  }
  *list_tail = rec_tail;
}

static void
fd_progcache_txn_cancel_one( fd_progcache_join_t * cache,
                             fd_progcache_txn_t *  txn,
                             uint *                cancel_head,
                             uint *                cancel_tail ) {
  FD_LOG_INFO(( "progcache txn laddr=%p xid %lu:%lu: cancel", (void *)txn, txn->xid.ul[0], txn->xid.ul[1] ));
  fd_rwlock_write( &txn->lock );

  if( FD_UNLIKELY( txn->child_head_idx!=UINT_MAX ||
                   txn->child_tail_idx!=UINT_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_txn_cancel failed: txn at %p with xid %lu:%lu has children (data corruption?)",
                  (void *)txn, txn->xid.ul[0], txn->xid.ul[1] ));
  }

  /* Remove records */

  for( uint idx = txn->rec_head_idx; idx!=UINT_MAX; idx = cache->rec.pool->ele[ idx ].next_idx ) {
    fd_progcache_rec_t * rec = &cache->rec.pool->ele[ idx ];
    if( rec->exists ) {
      fd_prog_recm_query_t query[1];
      int remove_err = fd_prog_recm_remove( cache->rec.map, &rec->pair, NULL, query, FD_MAP_FLAG_BLOCKING );
      if( FD_UNLIKELY( remove_err ) ) FD_LOG_CRIT(( "fd_funk_rec_map_remove failed: %i-%s", remove_err, fd_map_strerror( remove_err ) ));
    }
  }

  /* Detach record list from txn and append to cancel list */

  fd_progcache_rec_list_append( cache->rec.pool->ele,
                                cancel_head, cancel_tail,
                                txn->rec_head_idx, txn->rec_tail_idx );
  txn->rec_head_idx = UINT_MAX;
  txn->rec_tail_idx = UINT_MAX;

  /* Remove transaction from fork graph */

  uint self_idx = (uint)( txn - cache->txn.pool );
  uint prev_idx = txn->sibling_prev_idx;
  uint next_idx = txn->sibling_next_idx;
  if( next_idx!=UINT_MAX ) {
    cache->txn.pool[ next_idx ].sibling_prev_idx = prev_idx;
  }
  if( prev_idx!=UINT_MAX ) {
    cache->txn.pool[ prev_idx ].sibling_next_idx = next_idx;
  }
  if( txn->parent_idx!=UINT_MAX ) {
    fd_progcache_txn_t * parent = &cache->txn.pool[ txn->parent_idx ];
    if( parent->child_head_idx==self_idx ) parent->child_head_idx = next_idx;
    if( parent->child_tail_idx==self_idx ) parent->child_tail_idx = prev_idx;
  } else {
    if( cache->shmem->txn.child_head_idx==self_idx ) cache->shmem->txn.child_head_idx = next_idx;
    if( cache->shmem->txn.child_tail_idx==self_idx ) cache->shmem->txn.child_tail_idx = prev_idx;
  }

  /* Remove transaction from index */

  if( FD_UNLIKELY( !fd_prog_txnm_ele_remove( cache->txn.map, &txn->xid, NULL, cache->txn.pool ) ) ) {
    FD_LOG_CRIT(( "fd_progcache_txn_cancel failed: fd_funk_txn_map_remove(%lu:%lu) failed",
                  txn->xid.ul[0], txn->xid.ul[1] ));
  }

  /* Free transaction object */

  fd_rwlock_unwrite( &txn->lock );
  fd_prog_txnp_ele_release( cache->txn.pool, txn );
}

/* Cancels txn and all children */

static void
fd_progcache_txn_cancel_tree( fd_progcache_join_t * cache,
                              fd_progcache_txn_t *  txn,
                              uint *                cancel_head,
                              uint *                cancel_tail ) {
  for(;;) {
    uint child_idx = txn->child_head_idx;
    if( child_idx==UINT_MAX ) break;
    fd_progcache_txn_t * child = &cache->txn.pool[ child_idx ];
    fd_progcache_txn_cancel_tree( cache, child, cancel_head, cancel_tail );
  }
  fd_progcache_txn_cancel_one( cache, txn, cancel_head, cancel_tail );
}

/* Cancels all left/right siblings */

static void
fd_progcache_txn_cancel_prev_list( fd_progcache_join_t * cache,
                                   fd_progcache_txn_t *  txn,
                                   uint *                cancel_head,
                                   uint *                cancel_tail ) {
  uint self_idx = (uint)( txn - cache->txn.pool );
  for(;;) {
    uint prev_idx = txn->sibling_prev_idx;
    if( FD_UNLIKELY( prev_idx==self_idx ) ) FD_LOG_CRIT(( "detected cycle in fork graph" ));
    if( prev_idx==UINT_MAX ) break;
    fd_progcache_txn_t * sibling = &cache->txn.pool[ prev_idx ];
    fd_progcache_txn_cancel_tree( cache, sibling, cancel_head, cancel_tail );
  }
}

static void
fd_progcache_txn_cancel_next_list( fd_progcache_join_t * cache,
                                   fd_progcache_txn_t *  txn,
                                   uint *                cancel_head,
                                   uint *                cancel_tail ) {
  uint self_idx = (uint)( txn - cache->txn.pool );
  for(;;) {
    uint next_idx = txn->sibling_next_idx;
    if( FD_UNLIKELY( next_idx==self_idx ) ) FD_LOG_CRIT(( "detected cycle in fork graph" ));
    if( next_idx==UINT_MAX ) break;
    fd_progcache_txn_t * sibling = &cache->txn.pool[ next_idx ];
    fd_progcache_txn_cancel_tree( cache, sibling, cancel_head, cancel_tail );
  }
}

/* Drain readers and free cancelled records */

static void
fd_progcache_txn_cancel_release( fd_progcache_join_t * cache,
                                 uint                  head ) {
  while( head!=UINT_MAX ) {
    fd_progcache_rec_t * rec = &cache->rec.pool->ele[ head ];
    uint next = rec->next_idx;

    if( FD_LIKELY( rec->exists ) ) {
      fd_rwlock_write( &rec->lock );
      fd_progcache_val_free( rec, cache );
      rec->exists = 0;
      fd_rwlock_unwrite( &rec->lock );
    }
    fd_prog_recp_release( cache->rec.pool, rec, 1 );

    head = next;
  }
}

/* fd_progcache_gc_root cleans up a stale "rooted" version of a
   record. */

static void
fd_progcache_gc_root( fd_progcache_join_t *          cache,
                      fd_funk_xid_key_pair_t const * pair ) {
  /* Phase 1: Remove record from map if found */

  fd_prog_recm_query_t query[1];
  int rm_err = fd_prog_recm_remove( cache->rec.map, pair, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( rm_err==FD_MAP_ERR_KEY ) return;
  if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_remove failed: %i-%s", rm_err, fd_map_strerror( rm_err ) ));
  FD_COMPILER_MFENCE();

  /* Phase 2: Drain readers */

  fd_rwlock_write( &query->ele->lock );
  fd_progcache_rec_t * old_rec = query->ele;
  memset( &old_rec->pair, 0, sizeof(fd_funk_xid_key_pair_t) );
  FD_COMPILER_MFENCE();

  /* Phase 3: Free record */

  fd_progcache_val_free( old_rec, cache );
  old_rec->exists = 0;
  fd_rwlock_unwrite( &old_rec->lock );
  fd_prog_recp_release( cache->rec.pool, old_rec, 1 );
  fd_progcache_admin_metrics_g.gc_root_cnt++;
}

/* fd_progcache_gc_invalidation cleans up a "cache invalidate" record */

static void
fd_progcache_gc_invalidation( fd_progcache_join_t * cache,
                              fd_progcache_rec_t *  rec ) { /* no lock */

  /* Phase 1: Remove record from map if found */

  fd_funk_xid_key_pair_t pair = rec->pair;
  fd_prog_recm_query_t query[1];
  int rm_err = fd_prog_recm_remove( cache->rec.map, &pair, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( rm_err==FD_MAP_ERR_KEY ) return;
  if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_remove failed: %i-%s", rm_err, fd_map_strerror( rm_err ) ));
  if( FD_UNLIKELY( query->ele!=rec ) ) {
    FD_LOG_CRIT(( "Found record collision in program cache: xid=%lu:%lu key=%016lx%016lx%016lx%016lx ele0=%u ele1=%u",
                  pair.xid->ul[0], pair.xid->ul[1],
                  fd_ulong_bswap( pair.key->ul[0] ),
                  fd_ulong_bswap( pair.key->ul[1] ),
                  fd_ulong_bswap( pair.key->ul[2] ),
                  fd_ulong_bswap( pair.key->ul[3] ),
                  (uint)( query->ele - cache->rec.pool->ele ),
                  (uint)( rec        - cache->rec.pool->ele ) ));
  }

  /* Phase 2: Wait for readers to drain */

  fd_rwlock_write( &rec->lock );

  /* Phase 3: Invalidate and free record */

  memset( &rec->pair, 0, sizeof(fd_funk_xid_key_pair_t) );
  FD_COMPILER_MFENCE();

  rec->map_next = UINT_MAX;
  fd_progcache_val_free( rec, cache );
  rec->exists = 0;
  fd_rwlock_unwrite( &rec->lock );
  fd_prog_recp_release( cache->rec.pool, rec, 1 );
  fd_progcache_admin_metrics_g.gc_root_cnt++;
}

/* Move list of records to root txn (advance_root)

   For each record to be rooted:
   - gc_root to remove any shadowed rooted revision
   - drain readers
   - release if invalidation (which are now a no-op) */

static void
fd_progcache_txn_publish_release( fd_progcache_join_t * cache,
                                  uint                  head ) {
  while( head!=UINT_MAX ) {
    fd_progcache_rec_t * rec = &cache->rec.pool->ele[ head ];
    uint next = rec->next_idx;

    if( FD_UNLIKELY( !rec->exists ) ) {
      fd_prog_recp_release( cache->rec.pool, rec, 1 );
      head = next;
      continue;
    }

    /* Evict previous root value from hash chain */
    fd_funk_xid_key_pair_t pair[1];
    fd_funk_rec_key_copy( pair->key, rec->pair.key );
    fd_funk_txn_xid_set_root( pair->xid );
    fd_progcache_gc_root( cache, pair );

    /* Detach from txn list */
    rec->prev_idx = UINT_MAX;
    rec->next_idx = UINT_MAX;

    if( FD_UNLIKELY( rec->invalidate ) ) {
      /* Drop cache invalidate records */
      fd_progcache_gc_invalidation( cache, rec );
    } else {
      /* Migrate record to root */
      fd_rwlock_write( &rec->lock );
      fd_progcache_xid_t const root = { .ul = { ULONG_MAX, ULONG_MAX } };
      fd_funk_txn_xid_st_atomic( rec->pair.xid, &root );
      fd_rwlock_unwrite( &rec->lock );
      fd_progcache_admin_metrics_g.root_cnt++;
    }

    head = next;
  }
}

/* fd_progcache_txn_publish_one merges an in-prep transaction whose
   parent is the last published, into the parent. */

static uint
fd_progcache_txn_publish_one( fd_progcache_join_t * cache,
                              fd_progcache_txn_t *  txn ) {

  /* Phase 1: Mark transaction as "last published" */

  fd_progcache_xid_t const xid = txn->xid;
  FD_LOG_INFO(( "progcache txn laddr=%p xid %lu:%lu: publish", (void *)txn, xid.ul[0], xid.ul[1] ));
  if( FD_UNLIKELY( txn->parent_idx!=UINT_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_publish failed: txn with xid %lu:%lu is not a child of the last published txn", xid.ul[0], xid.ul[1] ));
  }
  fd_funk_txn_xid_st_atomic( cache->shmem->txn.last_publish, &xid );

  /* Phase 2: Drain inserters from transaction */

  fd_rwlock_write( &txn->lock );

  /* Phase 3: Detach records */

  uint rec_head = txn->rec_head_idx;
  txn->rec_head_idx = UINT_MAX;
  txn->rec_tail_idx = UINT_MAX;

  /* Phase 4: Remove transaction from fork graph */

  { /* Adjust the parent pointers of the children to point to "last published" */
    ulong child_idx = txn->child_head_idx;
    while( child_idx!=UINT_MAX ) {
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
fd_progcache_txn_advance_root( fd_progcache_join_t *     cache,
                               fd_funk_txn_xid_t const * xid ) {

  /* Detach records from txns without acquiring record locks */

  fd_rwlock_write( &cache->shmem->txn.rwlock );

  uint txn_idx = (uint)fd_prog_txnm_idx_query( cache->txn.map, xid, UINT_MAX, cache->txn.pool );
  if( FD_UNLIKELY( txn_idx==UINT_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_txn_advance_root failed: invalid XID %lu:%lu",
                  xid->ul[0], xid->ul[1] ));
  }
  fd_progcache_txn_t * txn = &cache->txn.pool[ txn_idx ];
  if( FD_UNLIKELY( txn->parent_idx!=UINT_MAX ) ) {
    FD_LOG_CRIT(( "fd_progcache_txn_advance_root: parent of txn %lu:%lu is not root", xid->ul[0], xid->ul[1] ));
  }

  uint cancel_head = UINT_MAX;
  uint cancel_tail = UINT_MAX;
  fd_progcache_txn_cancel_prev_list( cache, txn, &cancel_head, &cancel_tail );
  fd_progcache_txn_cancel_next_list( cache, txn, &cancel_head, &cancel_tail );

  txn->sibling_prev_idx = UINT_MAX;
  txn->sibling_next_idx = UINT_MAX;
  cache->shmem->txn.child_head_idx = txn->child_head_idx;
  cache->shmem->txn.child_tail_idx = txn->child_tail_idx;

  uint publish_head = fd_progcache_txn_publish_one( cache, txn );

  fd_rwlock_unwrite( &cache->shmem->txn.rwlock );

  /* Update records */

  fd_progcache_txn_cancel_release ( cache, cancel_head  );
  fd_progcache_txn_publish_release( cache, publish_head );
}

void
fd_progcache_txn_cancel( fd_progcache_join_t *      cache,
                         fd_progcache_xid_t const * xid ) {

  fd_rwlock_write( &cache->shmem->txn.rwlock );
  fd_progcache_txn_t * txn = fd_prog_txnm_ele_query( cache->txn.map, xid, NULL, cache->txn.pool );
  if( FD_UNLIKELY( !txn ) ) {
    FD_LOG_CRIT(( "fd_progcache_txn_cancel failed: invalid XID %lu:%lu",
                  xid->ul[0], xid->ul[1] ));
  }
  uint cancel_head = UINT_MAX;
  uint cancel_tail = UINT_MAX;
  fd_progcache_txn_cancel_tree( cache, txn, &cancel_head, &cancel_tail );
  fd_rwlock_unwrite( &cache->shmem->txn.rwlock );

  fd_progcache_txn_cancel_release( cache, cancel_head );
}

/* reset_txn_list does a depth-first traversal of the txn tree.
   Detaches all recs from txns by emptying rec linked lists. */

static void
reset_txn_list( fd_progcache_join_t * cache,
                uint                  txn_head_idx ) {
  for( uint idx = txn_head_idx; idx!=UINT_MAX; ) {
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
  ulong chain_cnt = fd_prog_recm_chain_cnt( cache->rec.map );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    for(
        fd_prog_recm_iter_t iter = fd_prog_recm_iter( cache->rec.map, chain_idx );
        !fd_prog_recm_iter_done( iter );
    ) {
      fd_progcache_rec_t * rec = fd_prog_recm_iter_ele( iter );
      ulong next = fd_prog_recm_private_idx( rec->map_next );;

      if( rec->exists ) {
        fd_prog_recm_query_t rec_query[1];
        int err = fd_prog_recm_remove( cache->rec.map, &rec->pair, NULL, rec_query, FD_MAP_FLAG_BLOCKING );
        fd_funk_rec_key_t key; fd_funk_rec_key_copy( &key, rec->pair.key );
        if( FD_UNLIKELY( err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_prog_recm_remove failed (%i-%s)", err, fd_map_strerror( err ) ));
        fd_progcache_val_free( rec, cache );
      }

      rec->exists = 0;
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
  for( uint idx = txn_head_idx; idx!=UINT_MAX; ) {
    fd_progcache_txn_t * txn = &join->txn.pool[ idx ];
    uint next_idx  = txn->sibling_next_idx;
    uint child_idx = txn->child_head_idx;
    txn->rec_head_idx      = UINT_MAX;
    txn->rec_tail_idx      = UINT_MAX;
    txn->child_head_idx    = UINT_MAX;
    txn->child_tail_idx    = UINT_MAX;
    txn->parent_idx        = UINT_MAX;
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

void
fd_progcache_inject_rec( fd_progcache_join_t *     cache,
                         void const *              prog_addr,
                         fd_account_meta_t const * progdata_meta,
                         fd_features_t const *     features,
                         ulong                     slot,
                         uchar *                   scratch,
                         ulong                     scratch_sz ) {

  /* XID overview:

     - load_xid:   tip of fork currently being executed
     - modify_xid: xid in which program was last modified / deployed
     - txn->xid:   xid in which program cache entry is inserted

     slot(load_xid) > slot(entry_xid) >= slot(txn->xid) */

  /* Acquire reference to ELF binary data */

  uchar const * elf_bin    = NULL;
  ulong         elf_bin_sz = progdata_meta->dlen;
  if( !memcmp( progdata_meta->owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {
    if( FD_UNLIKELY( elf_bin_sz<PROGRAMDATA_METADATA_SIZE ) ) return;

    elf_bin     = (uchar const *)fd_account_data( progdata_meta ) + PROGRAMDATA_METADATA_SIZE;
    elf_bin_sz -= PROGRAMDATA_METADATA_SIZE;
  } else if( !memcmp( progdata_meta->owner, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) {
    if( FD_UNLIKELY( elf_bin_sz<LOADER_V4_PROGRAM_DATA_OFFSET ) ) return;

    elf_bin     = (uchar const *)fd_account_data( progdata_meta ) + LOADER_V4_PROGRAM_DATA_OFFSET;
    elf_bin_sz -= LOADER_V4_PROGRAM_DATA_OFFSET;
  } else if( !memcmp( progdata_meta->owner, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) ||
             !memcmp( progdata_meta->owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) ) {
    elf_bin = (uchar const *)fd_account_data( progdata_meta );
  }
  if( FD_UNLIKELY( !elf_bin ) ) return;

  /* Allocate a rec */

  fd_progcache_rec_t * rec = fd_prog_recp_acquire( cache->rec.pool, NULL, 0, NULL );
  if( FD_UNLIKELY( !rec ) ) {
    FD_LOG_ERR(( "Program cache is out of memory: fd_funk_rec_pool_acquire failed (rec_max=%lu)",
                 fd_prog_recp_ele_max( cache->rec.pool ) ));
  }
  memset( rec, 0, sizeof(fd_progcache_rec_t) );
  rec->exists = 1;

  rec->prev_idx = UINT_MAX;
  rec->next_idx = UINT_MAX;
  memcpy( rec->pair.key, prog_addr, 32UL );
  fd_funk_txn_xid_set_root( rec->pair.xid );

  /* Load program */

  ulong const load_slot = slot;
  fd_prog_versions_t versions = fd_prog_versions( features, load_slot );
  fd_sbpf_loader_config_t config = {
    .sbpf_min_version = versions.min_sbpf_version,
    .sbpf_max_version = versions.max_sbpf_version,
  };
  fd_sbpf_elf_info_t elf_info[1];

  if( FD_LIKELY( fd_sbpf_elf_peek( elf_info, elf_bin, elf_bin_sz, &config )==FD_SBPF_ELF_SUCCESS ) ) {
    ulong val_sz = fd_progcache_val_footprint( elf_info );
    if( FD_UNLIKELY( !fd_progcache_val_alloc( rec, cache, fd_progcache_val_align(), val_sz ) ) ) {
      /* This is a test API, so no need to do cache eviction */
      FD_LOG_ERR(( "Program cache is out of memory: fd_alloc_malloc failed (requested sz=%lu)", val_sz ));
    }

    if( FD_UNLIKELY( !fd_progcache_rec_load( rec, cache->wksp, elf_info, &config, load_slot, features, elf_bin, elf_bin_sz, scratch, scratch_sz ) ) ) {
      fd_progcache_val_free( rec, cache );
      fd_progcache_rec_nx( rec, load_slot );
    }
  } else {
    fd_progcache_rec_nx( rec, load_slot );
  }

  /* Publish cache entry to funk index */

  int insert_err = fd_prog_recm_txn_insert( cache->rec.map, rec );
  if( FD_UNLIKELY( insert_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "fd_funk_rec_map_txn_insert failed: %i-%s", insert_err, fd_map_strerror( insert_err ) ));
  }
}

void
fd_progcache_verify( fd_progcache_join_t * cache ) {
  (void)cache;
}

void
fd_progcache_wksp_metrics_update( fd_progcache_join_t * cache ) {
  fd_wksp_t * wksp = cache->wksp;
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
