#include "fd_progcache_admin.h"

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

fd_progcache_admin_t *
fd_progcache_admin_join( fd_progcache_admin_t * ljoin,
                         void *                 shfunk ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }
  if( FD_UNLIKELY( !shfunk ) ) {
    FD_LOG_WARNING(( "NULL shfunk" ));
    return NULL;
  }

  memset( ljoin, 0, sizeof(fd_progcache_admin_t) );
  if( FD_UNLIKELY( !fd_funk_join( ljoin->funk, shfunk ) ) ) {
    FD_LOG_CRIT(( "fd_funk_join failed" ));
  }

  return ljoin;
}

void *
fd_progcache_admin_leave( fd_progcache_admin_t * ljoin,
                          void **                opt_shfunk ) {
  if( FD_UNLIKELY( !ljoin ) ) FD_LOG_CRIT(( "NULL ljoin" ));

  if( FD_UNLIKELY( !fd_funk_leave( ljoin->funk, opt_shfunk ) ) ) FD_LOG_CRIT(( "fd_funk_leave failed" ));

  return ljoin;
}

/* Begin transaction-level operations.  It is assumed that funk_txn data
   structures are not concurrently modified.  This includes txn_pool and
   txn_map. */

void
fd_progcache_txn_prepare( fd_progcache_admin_t *    cache,
                          fd_funk_txn_xid_t const * xid_parent,
                          fd_funk_txn_xid_t const * xid_new ) {
  fd_funk_txn_prepare( cache->funk, xid_parent, xid_new );
}

static void
fd_progcache_txn_cancel_one( fd_progcache_admin_t * cache,
                             fd_funk_txn_t *        txn ) {
  FD_LOG_INFO(( "progcache txn laddr=%p xid %lu:%lu: cancel", (void *)txn, txn->xid.ul[0], txn->xid.ul[1] ));

  fd_funk_t * funk = cache->funk;
  if( FD_UNLIKELY( !fd_funk_txn_idx_is_null( txn->child_head_cidx ) ||
                   !fd_funk_txn_idx_is_null( txn->child_tail_cidx ) ) ) {
    FD_LOG_CRIT(( "fd_progcache_txn_cancel failed: txn at %p with xid %lu:%lu has children (data corruption?)",
                  (void *)txn, txn->xid.ul[0], txn->xid.ul[1] ));
  }

  /* Phase 1: Drain users from transaction */

  fd_rwlock_write( txn->lock );
  FD_VOLATILE( txn->state ) = FD_FUNK_TXN_STATE_CANCEL;

  /* Phase 2: Remove records */

  while( !fd_funk_rec_idx_is_null( txn->rec_head_idx ) ) {
    fd_funk_rec_t * rec = &funk->rec_pool->ele[ txn->rec_head_idx ];
    uint next_idx = rec->next_idx;
    rec->next_idx = FD_FUNK_REC_IDX_NULL;
    if( FD_LIKELY( !fd_funk_rec_idx_is_null( next_idx ) ) ) {
      funk->rec_pool->ele[ next_idx ].prev_idx = FD_FUNK_REC_IDX_NULL;
    }

    fd_funk_val_flush( rec, funk->alloc, funk->wksp );

    fd_funk_rec_query_t query[1];
    int remove_err = fd_funk_rec_map_remove( funk->rec_map, &rec->pair, NULL, query, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( remove_err ) ) FD_LOG_CRIT(( "fd_funk_rec_map_remove failed: %i-%s", remove_err, fd_map_strerror( remove_err ) ));

    fd_funk_rec_pool_release( funk->rec_pool, rec, 1 );

    txn->rec_head_idx = next_idx;
    if( fd_funk_rec_idx_is_null( next_idx ) ) txn->rec_tail_idx = FD_FUNK_REC_IDX_NULL;
  }

  /* Phase 3: Remove transaction from fork graph */

  uint self_cidx = fd_funk_txn_cidx( (ulong)( txn-funk->txn_pool->ele ) );
  uint prev_cidx = txn->sibling_prev_cidx; ulong prev_idx = fd_funk_txn_idx( prev_cidx );
  uint next_cidx = txn->sibling_next_cidx; ulong next_idx = fd_funk_txn_idx( next_cidx );
  if( !fd_funk_txn_idx_is_null( next_idx ) ) {
    funk->txn_pool->ele[ next_idx ].sibling_prev_cidx = prev_cidx;
  }
  if( !fd_funk_txn_idx_is_null( prev_idx ) ) {
    funk->txn_pool->ele[ prev_idx ].sibling_next_cidx = next_cidx;
  }
  if( !fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->parent_cidx ) ) ) {
    fd_funk_txn_t * parent = &funk->txn_pool->ele[ fd_funk_txn_idx( txn->parent_cidx ) ];
    if( parent->child_head_cidx==self_cidx ) parent->child_head_cidx = next_cidx;
    if( parent->child_tail_cidx==self_cidx ) parent->child_tail_cidx = prev_cidx;
  } else {
    if( funk->shmem->child_head_cidx==self_cidx ) funk->shmem->child_head_cidx = next_cidx;
    if( funk->shmem->child_tail_cidx==self_cidx ) funk->shmem->child_tail_cidx = prev_cidx;
  }

  /* Phase 4: Remove transcation from index */

  fd_funk_txn_map_query_t query[1];
  int remove_err = fd_funk_txn_map_remove( funk->txn_map, &txn->xid, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( remove_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "fd_progcache_txn_cancel failed: fd_funk_txn_map_remove(%lu:%lu) failed: %i-%s",
                  txn->xid.ul[0], txn->xid.ul[1], remove_err, fd_map_strerror( remove_err ) ));
  }

  /* Phase 5: Free transaction object */

  fd_rwlock_unwrite( txn->lock );
  FD_VOLATILE( txn->state ) = FD_FUNK_TXN_STATE_FREE;
  fd_funk_txn_pool_release( funk->txn_pool, txn, 1 );
}

/* Cancels txn and all children */

static void
fd_progcache_txn_cancel_tree( fd_progcache_admin_t * cache,
                              fd_funk_txn_t *        txn ) {
  for(;;) {
    ulong child_idx = fd_funk_txn_idx( txn->child_head_cidx );
    if( fd_funk_txn_idx_is_null( child_idx ) ) break;
    fd_funk_txn_t * child = &cache->funk->txn_pool->ele[ child_idx ];
    fd_progcache_txn_cancel_tree( cache, child );
  }
  fd_progcache_txn_cancel_one( cache, txn );
}

/* Cancels all left/right siblings */

static void
fd_progcache_txn_cancel_prev_list( fd_progcache_admin_t * cache,
                                   fd_funk_txn_t *        txn ) {
  ulong self_idx = (ulong)( txn - cache->funk->txn_pool->ele );
  for(;;) {
    ulong prev_idx = fd_funk_txn_idx( txn->sibling_prev_cidx );
    if( FD_UNLIKELY( prev_idx==self_idx ) ) FD_LOG_CRIT(( "detected cycle in fork graph" ));
    if( fd_funk_txn_idx_is_null( prev_idx ) ) break;
    fd_funk_txn_t * sibling = &cache->funk->txn_pool->ele[ prev_idx ];
    fd_progcache_txn_cancel_tree( cache, sibling );
  }
}

static void
fd_progcache_txn_cancel_next_list( fd_progcache_admin_t * cache,
                                   fd_funk_txn_t *        txn ) {
  ulong self_idx = (ulong)( txn - cache->funk->txn_pool->ele );
  for(;;) {
    ulong next_idx = fd_funk_txn_idx( txn->sibling_next_cidx );
    if( FD_UNLIKELY( next_idx==self_idx ) ) FD_LOG_CRIT(( "detected cycle in fork graph" ));
    if( fd_funk_txn_idx_is_null( next_idx ) ) break;
    fd_funk_txn_t * sibling = &cache->funk->txn_pool->ele[ next_idx ];
    fd_progcache_txn_cancel_tree( cache, sibling );
  }
}

void
fd_progcache_txn_cancel( fd_progcache_admin_t * cache,
                         fd_funk_txn_xid_t const * xid ) {
  fd_funk_t * funk = cache->funk;

  fd_funk_txn_t * txn = fd_funk_txn_query( xid, funk->txn_map );
  if( FD_UNLIKELY( !txn ) ) {
    FD_LOG_CRIT(( "fd_progcache_txn_cancel failed: txn with xid %lu:%lu not found", xid->ul[0], xid->ul[1] ));
  }

  fd_progcache_txn_cancel_next_list( cache, txn );
  fd_progcache_txn_cancel_tree( cache, txn );
}

/* fd_progcache_publish_recs publishes all of a progcache's records.
   It is assumed at this point that the txn has no more concurrent
   users. */

static void
fd_progcache_publish_recs( fd_progcache_admin_t * cache,
                           fd_funk_txn_t *        txn ) {
  fd_funk_txn_xid_t const root = { .ul = { ULONG_MAX, ULONG_MAX } };
  /* Iterate record list */
  uint head = txn->rec_head_idx;
  txn->rec_head_idx = FD_FUNK_REC_IDX_NULL;
  txn->rec_tail_idx = FD_FUNK_REC_IDX_NULL;
  while( !fd_funk_rec_idx_is_null( head ) ) {
    fd_funk_rec_t * rec = &cache->funk->rec_pool->ele[ head ];
    uint next = rec->next_idx;
    rec->prev_idx = FD_FUNK_REC_IDX_NULL;
    rec->next_idx = FD_FUNK_REC_IDX_NULL;
    fd_funk_txn_xid_st_atomic( rec->pair.xid, &root );
    head = next;
  }
}

/* fd_progcache_txn_publish_one merges an in-prep transaction whose
   parent is the last published, into the parent. */

static void
fd_progcache_txn_publish_one( fd_progcache_admin_t *    cache,
                              fd_funk_txn_xid_t const * xid ) {
  fd_funk_t * funk = cache->funk;

  /* Phase 1: Mark transaction as "last published" */

  fd_funk_txn_t * txn = fd_funk_txn_query( xid, funk->txn_map );
  if( FD_UNLIKELY( !txn ) ) {
    FD_LOG_CRIT(( "fd_progcache_publish failed: txn with xid %lu:%lu not found", xid->ul[0], xid->ul[1] ));
  }
  FD_LOG_INFO(( "progcache txn laddr=%p xid %lu:%lu: publish", (void *)txn, txn->xid.ul[0], txn->xid.ul[1] ));
  if( FD_UNLIKELY( !fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->parent_cidx ) ) ) ) {
    FD_LOG_CRIT(( "fd_progcache_publish failed: txn with xid %lu:%lu is not a child of the last published txn", xid->ul[0], xid->ul[1] ));
  }
  fd_funk_txn_xid_st_atomic( funk->shmem->last_publish, xid );

  /* Phase 2: Drain users from transaction */

  fd_rwlock_write( txn->lock );
  FD_VOLATILE( txn->state ) = FD_FUNK_TXN_STATE_PUBLISH;

  /* Phase 3: Migrate records */

  fd_progcache_publish_recs( cache, txn );

  /* Phase 4: Remove transaction from fork graph

     Because the transaction has no more records, removing it from the
     fork graph has no visible side effects to concurrent query ops
     (always return "no found") or insert ops (refuse to write to a
     "publish" state txn). */

  { /* Adjust the parent pointers of the children to point to "last published" */
    ulong child_idx = fd_funk_txn_idx( txn->child_head_cidx );
    while( FD_UNLIKELY( !fd_funk_txn_idx_is_null( child_idx ) ) ) {
      funk->txn_pool->ele[ child_idx ].parent_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
      child_idx = fd_funk_txn_idx( funk->txn_pool->ele[ child_idx ].sibling_next_cidx );
    }
  }

  /* Phase 5: Remove transaction from index

     The transaction is now an orphan and won't get any new records. */

  fd_funk_txn_map_query_t query[1];
  int remove_err = fd_funk_txn_map_remove( funk->txn_map, xid, NULL, query, 0 );
  if( FD_UNLIKELY( remove_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "fd_progcache_publish failed: fd_funk_txn_map_remove failed: %i-%s", remove_err, fd_map_strerror( remove_err ) ));
  }

  /* Phase 6: Free transaction object */

  fd_rwlock_unwrite( txn->lock );
  FD_VOLATILE( txn->state ) = FD_FUNK_TXN_STATE_FREE;
  fd_funk_txn_pool_release( funk->txn_pool, txn, 1 );
}

static void
fd_progcache_txn_publish_parents( fd_progcache_admin_t * cache,
                                  fd_funk_txn_t *        txn ) {
  /* Recurse until all of txn's parents are published */
  fd_funk_t * funk = cache->funk;
  if( !fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->parent_cidx ) ) ) {
    ulong parent_idx = fd_funk_txn_idx( txn->parent_cidx );
    fd_funk_txn_t * parent = &funk->txn_pool->ele[ parent_idx ];
    if( FD_UNLIKELY( FD_VOLATILE_CONST( parent->state )!=FD_FUNK_TXN_STATE_PUBLISH ) ) {
      fd_progcache_txn_publish_parents( cache, parent );
    }
  } else {
    /* Root transaction */
    ulong idx = (uint)( txn - funk->txn_pool->ele );
    if( fd_funk_txn_idx( funk->shmem->child_head_cidx )==idx ) {
      funk->shmem->child_head_cidx = txn->sibling_next_cidx;
    }
    if( fd_funk_txn_idx( funk->shmem->child_tail_cidx )==idx ) {
      funk->shmem->child_tail_cidx = txn->sibling_prev_cidx;
    }
  }
  fd_progcache_txn_publish_one( cache, fd_funk_txn_xid( txn ) );
}

void
fd_progcache_txn_publish( fd_progcache_admin_t *    cache,
                          fd_funk_txn_xid_t const * xid ) {
  fd_funk_t * funk = cache->funk;

  fd_funk_txn_t * txn = fd_funk_txn_query( xid, funk->txn_map );
  if( FD_UNLIKELY( !txn ) ) {
    FD_LOG_CRIT(( "fd_progcache_publish failed: txn with xid %lu:%lu not found", xid->ul[0], xid->ul[1] ));
  }

  fd_progcache_txn_cancel_prev_list( cache, txn );
  fd_progcache_txn_cancel_next_list( cache, txn );
  { /* Cancel left siblings */
    ulong child_idx = fd_funk_txn_idx( txn->sibling_prev_cidx );
    while( FD_UNLIKELY( !fd_funk_txn_idx_is_null( child_idx ) ) ) {
      funk->txn_pool->ele[ child_idx ].parent_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
      child_idx = fd_funk_txn_idx( funk->txn_pool->ele[ child_idx ].sibling_next_cidx );
    }
  }
  { /* Cancel right siblings */
    ulong child_idx = fd_funk_txn_idx( txn->sibling_next_cidx );
    while( FD_UNLIKELY( !fd_funk_txn_idx_is_null( child_idx ) ) ) {
      funk->txn_pool->ele[ child_idx ].parent_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
      child_idx = fd_funk_txn_idx( funk->txn_pool->ele[ child_idx ].sibling_next_cidx );
    }
  }

  fd_progcache_txn_publish_parents( cache, txn );
  txn->child_head_cidx   = UINT_MAX;
  txn->child_tail_cidx   = UINT_MAX;
  txn->parent_cidx       = UINT_MAX;
  txn->sibling_prev_cidx = UINT_MAX;
  txn->sibling_next_cidx = UINT_MAX;
}

/* reset_txn_list does a depth-first traversal of the txn tree.
   Detaches all recs from txns by emptying rec linked lists. */

static void
reset_txn_list( fd_funk_t * funk,
                ulong       txn_head_idx ) {
  fd_funk_txn_pool_t * txn_pool = funk->txn_pool;
  for( ulong idx = txn_head_idx;
       !fd_funk_txn_idx_is_null( idx );
  ) {
    fd_funk_txn_t * txn = &txn_pool->ele[ idx ];
    fd_funk_txn_state_assert( txn, FD_FUNK_TXN_STATE_ACTIVE );
    txn->rec_head_idx = FD_FUNK_REC_IDX_NULL;
    txn->rec_tail_idx = FD_FUNK_REC_IDX_NULL;
    reset_txn_list( funk, txn->child_head_cidx );
    idx = fd_funk_txn_idx( txn->sibling_next_cidx );
  }
}

/* reset_rec_map frees all records in a funk instance. */

static void
reset_rec_map( fd_funk_t * funk ) {
  fd_wksp_t *          wksp     = funk->wksp;
  fd_alloc_t *         alloc    = funk->alloc;
  fd_funk_rec_map_t *  rec_map  = funk->rec_map;
  fd_funk_rec_pool_t * rec_pool = funk->rec_pool;

  ulong chain_cnt = fd_funk_rec_map_chain_cnt( rec_map );
  for( ulong chain_idx=0UL; chain_idx<chain_cnt; chain_idx++ ) {
    for(
        fd_funk_rec_map_iter_t iter = fd_funk_rec_map_iter( rec_map, chain_idx );
        !fd_funk_rec_map_iter_done( iter );
    ) {
      fd_funk_rec_t * rec = fd_funk_rec_map_iter_ele( iter );
      ulong next = fd_funk_rec_map_private_idx( rec->map_next );;

      /* Remove rec object from map */
      fd_funk_rec_map_query_t rec_query[1];
      int err = fd_funk_rec_map_remove( rec_map, fd_funk_rec_pair( rec ), NULL, rec_query, FD_MAP_FLAG_BLOCKING );
      fd_funk_rec_key_t key; fd_funk_rec_key_copy( &key, rec->pair.key );
      if( FD_UNLIKELY( err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_rec_map_remove failed (%i-%s)", err, fd_map_strerror( err ) ));

      /* Free rec resources */
      fd_funk_val_flush( rec, alloc, wksp );
      fd_funk_rec_pool_release( rec_pool, rec, 1 );
      iter.ele_idx = next;
    }
  }
}

void
fd_progcache_reset( fd_progcache_admin_t * cache ) {
  fd_funk_t * funk = cache->funk;
  reset_txn_list( funk, fd_funk_txn_idx( funk->shmem->child_head_cidx ) );
  reset_rec_map( funk );
}

void
fd_progcache_clear( fd_progcache_admin_t * cache ) {
  /* FIXME this descends the progcache txn tree multiple times */
  fd_progcache_reset( cache );
  fd_funk_txn_cancel_all( cache->funk );
}

void
fd_progcache_verify( fd_progcache_admin_t *       cache,
                     fd_progcache_verify_stat_t * out_stat ) {
  (void)cache; (void)out_stat;
}
