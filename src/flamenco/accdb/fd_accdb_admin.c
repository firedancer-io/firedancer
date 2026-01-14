#include "fd_accdb_admin.h"
#include "../fd_flamenco_base.h"

fd_accdb_admin_t *
fd_accdb_admin_join( fd_accdb_admin_t * ljoin,
                     void *             shfunk ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }
  if( FD_UNLIKELY( !shfunk ) ) {
    FD_LOG_WARNING(( "NULL shfunk" ));
    return NULL;
  }

  memset( ljoin, 0, sizeof(fd_accdb_admin_t) );
  if( FD_UNLIKELY( !fd_funk_join( ljoin->funk, shfunk ) ) ) {
    FD_LOG_CRIT(( "fd_funk_join failed" ));
  }

  return ljoin;
}

void *
fd_accdb_admin_leave( fd_accdb_admin_t * admin,
                      void **            opt_shfunk ) {
  if( FD_UNLIKELY( !admin ) ) FD_LOG_CRIT(( "NULL ljoin" ));

  if( FD_UNLIKELY( !fd_funk_leave( admin->funk, opt_shfunk ) ) ) FD_LOG_CRIT(( "fd_funk_leave failed" ));

  return admin;
}

/* Begin transaction-level operations.  It is assumed that funk_txn data
   structures are not concurrently modified.  This includes txn_pool and
   txn_map. */

void
fd_accdb_attach_child( fd_accdb_admin_t *        db,
                       fd_funk_txn_xid_t const * xid_parent,
                       fd_funk_txn_xid_t const * xid_new ) {
  FD_LOG_INFO(( "accdb txn xid %lu:%lu: created with parent %lu:%lu",
                xid_new   ->ul[0], xid_new   ->ul[1],
                xid_parent->ul[0], xid_parent->ul[1] ));
  fd_funk_txn_prepare( db->funk, xid_parent, xid_new );
}

static void
fd_accdb_txn_cancel_one( fd_accdb_admin_t * admin,
                         fd_funk_txn_t *    txn ) {
  FD_LOG_INFO(( "accdb txn laddr=%p xid %lu:%lu: cancel", (void *)txn, txn->xid.ul[0], txn->xid.ul[1] ));

  if( FD_UNLIKELY( txn->state!=FD_FUNK_TXN_STATE_ACTIVE ) ) {
    FD_LOG_CRIT(( "cannot cancel xid %lu:%lu: unxpected state %u-%s",
                  txn->xid.ul[0], txn->xid.ul[1],
                  txn->state, fd_funk_txn_state_str( txn->state ) ));
  }
  fd_funk_t * funk = admin->funk;
  if( FD_UNLIKELY( !fd_funk_txn_idx_is_null( txn->child_head_cidx ) ||
                   !fd_funk_txn_idx_is_null( txn->child_tail_cidx ) ) ) {
    FD_LOG_CRIT(( "fd_accdb_txn_cancel failed: txn at %p with xid %lu:%lu has children (data corruption?)",
                  (void *)txn, txn->xid.ul[0], txn->xid.ul[1] ));
  }

  /* Phase 1: Drain users from transaction */

  fd_rwlock_write( txn->lock );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( txn->state ) = FD_FUNK_TXN_STATE_CANCEL;

  /* Phase 2: Detach all records */

  FD_COMPILER_MFENCE();
  uint const rec_head_idx = txn->rec_head_idx;
  txn->rec_head_idx = FD_FUNK_REC_IDX_NULL;
  txn->rec_tail_idx = FD_FUNK_REC_IDX_NULL;
  FD_COMPILER_MFENCE();

  /* Phase 3: Remove records */

  ulong rec_cnt = 0UL;
  uint rec_idx = rec_head_idx;
  while( !fd_funk_rec_idx_is_null( rec_idx ) ) {
    fd_funk_rec_t * rec = &funk->rec_pool->ele[ rec_idx ];
    fd_funk_xid_key_pair_t pair = FD_VOLATILE_CONST( rec->pair );

    uint next_idx = rec->next_idx;
    if( FD_UNLIKELY( !fd_funk_txn_xid_eq( pair.xid, &txn->xid ) ) ) {
      FD_LOG_CRIT(( "Record does not belong to txn being cancelled (data corruption?): rec_idx=%u", rec_idx ));
    }

    /* Phase 3.1: Hide record */

    fd_funk_rec_query_t query[1];
    int remove_err = fd_funk_rec_map_remove( funk->rec_map, &pair, NULL, query, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( remove_err ) ) FD_LOG_CRIT(( "fd_funk_rec_map_remove failed: %i-%s", remove_err, fd_map_strerror( remove_err ) ));
    if( FD_UNLIKELY( query->ele!=rec ) ) FD_LOG_CRIT(( "Found duplicate record in map idx[0]=%p idx[1]=%p", (void *)query->ele, (void *)rec ));

    /* Phase 3.2: Mark record as invalid */

    FD_COMPILER_MFENCE();
    memset( &rec->pair, 0, sizeof(fd_funk_xid_key_pair_t) );
    FD_COMPILER_MFENCE();

    /* Phase 3.3: Free record */

    fd_funk_val_flush( rec, funk->alloc, funk->wksp );
    rec->next_idx = FD_FUNK_REC_IDX_NULL;
    rec->prev_idx = FD_FUNK_REC_IDX_NULL;
    fd_funk_rec_pool_release( funk->rec_pool, rec, 1 );
    rec_idx = next_idx;
    rec_cnt++;
  }
  admin->metrics.revert_cnt += rec_cnt;
  FD_LOG_INFO(( "accdb freed %lu records while cancelling txn %lu:%lu",
                rec_cnt, txn->xid.ul[0], txn->xid.ul[1] ));

  /* Phase 4: Remove transaction from fork graph */

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

  /* Phase 5: Remove transcation from index */

  fd_funk_txn_map_query_t query[1];
  int remove_err = fd_funk_txn_map_remove( funk->txn_map, &txn->xid, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( remove_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "fd_accdb_txn_cancel failed: fd_funk_txn_map_remove(%lu:%lu) failed: %i-%s",
                  txn->xid.ul[0], txn->xid.ul[1], remove_err, fd_map_strerror( remove_err ) ));
  }

  /* Phase 6: Free transaction object */

  txn->parent_cidx       = UINT_MAX;
  txn->sibling_prev_cidx = UINT_MAX;
  txn->sibling_next_cidx = UINT_MAX;
  fd_rwlock_unwrite( txn->lock );
  FD_VOLATILE( txn->state ) = FD_FUNK_TXN_STATE_FREE;
  fd_funk_txn_pool_release( funk->txn_pool, txn, 1 );
}

/* Cancels txn and all children */

static void
fd_accdb_txn_cancel_tree( fd_accdb_admin_t * accdb,
                          fd_funk_txn_t *    txn ) {
  for(;;) {
    ulong child_idx = fd_funk_txn_idx( txn->child_head_cidx );
    if( fd_funk_txn_idx_is_null( child_idx ) ) break;
    fd_funk_txn_t * child = &accdb->funk->txn_pool->ele[ child_idx ];
    fd_accdb_txn_cancel_tree( accdb, child );
  }
  fd_accdb_txn_cancel_one( accdb, txn );
}

/* Cancels all left/right siblings */

static void
fd_accdb_txn_cancel_prev_list( fd_accdb_admin_t * accdb,
                               fd_funk_txn_t *    txn ) {
  ulong self_idx = (ulong)( txn - accdb->funk->txn_pool->ele );
  for(;;) {
    ulong prev_idx = fd_funk_txn_idx( txn->sibling_prev_cidx );
    if( FD_UNLIKELY( prev_idx==self_idx ) ) FD_LOG_CRIT(( "detected cycle in fork graph" ));
    if( fd_funk_txn_idx_is_null( prev_idx ) ) break;
    fd_funk_txn_t * sibling = &accdb->funk->txn_pool->ele[ prev_idx ];
    fd_accdb_txn_cancel_tree( accdb, sibling );
  }
}

static void
fd_accdb_txn_cancel_next_list( fd_accdb_admin_t * accdb,
                               fd_funk_txn_t *    txn ) {
  ulong self_idx = (ulong)( txn - accdb->funk->txn_pool->ele );
  for(;;) {
    ulong next_idx = fd_funk_txn_idx( txn->sibling_next_cidx );
    if( FD_UNLIKELY( next_idx==self_idx ) ) FD_LOG_CRIT(( "detected cycle in fork graph" ));
    if( fd_funk_txn_idx_is_null( next_idx ) ) break;
    fd_funk_txn_t * sibling = &accdb->funk->txn_pool->ele[ next_idx ];
    fd_accdb_txn_cancel_tree( accdb, sibling );
  }
}

void
fd_accdb_cancel( fd_accdb_admin_t *        accdb,
                 fd_funk_txn_xid_t const * xid ) {
  fd_funk_t * funk = accdb->funk;

  /* Assume no concurrent access to txn_map */

  fd_funk_txn_map_query_t query[1];
  int query_err = fd_funk_txn_map_query_try( funk->txn_map, xid, NULL, query, 0 );
  if( FD_UNLIKELY( query_err ) ) {
    FD_LOG_CRIT(( "fd_accdb_cancel failed: fd_funk_txn_map_query_try(xid=%lu:%lu) returned (%i-%s)",
                   xid->ul[0], xid->ul[1], query_err, fd_map_strerror( query_err ) ));
  }
  fd_funk_txn_t * txn = fd_funk_txn_map_query_ele( query );

  fd_accdb_txn_cancel_next_list( accdb, txn );
  fd_accdb_txn_cancel_tree( accdb, txn );
}

/* fd_accdb_chain_reclaim "reclaims" a zero-lamport account by removing
   its underlying record. */

static void
fd_accdb_chain_reclaim( fd_accdb_admin_t * accdb,
                        fd_funk_rec_t *    rec ) {
  fd_funk_t * funk = accdb->funk;

  /* Phase 1: Remove record from map */

  fd_funk_xid_key_pair_t pair = rec->pair;
  fd_funk_rec_query_t query[1];
  int rm_err = fd_funk_rec_map_remove( funk->rec_map, &pair, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_rec_map_remove failed (%i-%s)", rm_err, fd_map_strerror( rm_err ) ));
  FD_COMPILER_MFENCE();

  /* Phase 2: Invalidate record */

  fd_funk_rec_t * old_rec = query->ele;
  memset( &old_rec->pair, 0, sizeof(fd_funk_xid_key_pair_t) );
  FD_COMPILER_MFENCE();

  /* Phase 3: Free record */

  old_rec->map_next = FD_FUNK_REC_IDX_NULL;
  fd_funk_val_flush( old_rec, funk->alloc, funk->wksp );
  fd_funk_rec_pool_release( funk->rec_pool, old_rec, 1 );
  accdb->metrics.reclaim_cnt++;
}

/* fd_accdb_chain_gc_root cleans up a stale "rooted" version of a
   record. */

static void
fd_accdb_chain_gc_root( fd_accdb_admin_t *             accdb,
                        fd_funk_xid_key_pair_t const * pair ) {
  fd_funk_t * funk = accdb->funk;

  /* Phase 1: Remove record from map if found */

  fd_funk_rec_query_t query[1];
  int rm_err = fd_funk_rec_map_remove( funk->rec_map, pair, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( rm_err==FD_MAP_ERR_KEY ) return;
  if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_rec_map_remove failed (%i-%s)", rm_err, fd_map_strerror( rm_err ) ));
  FD_COMPILER_MFENCE();

  /* Phase 2: Invalidate record */

  fd_funk_rec_t * old_rec = query->ele;
  memset( &old_rec->pair, 0, sizeof(fd_funk_xid_key_pair_t) );
  FD_COMPILER_MFENCE();

  /* Phase 3: Free record */

  old_rec->map_next = FD_FUNK_REC_IDX_NULL;
  fd_funk_val_flush( old_rec, funk->alloc, funk->wksp );
  fd_funk_rec_pool_release( funk->rec_pool, old_rec, 1 );
  accdb->metrics.gc_root_cnt++;
}

/* fd_accdb_publish_recs moves all records in a transaction to the DB
   root.  Currently, the DB root is stored by funk, which might change
   in the future.

   It is assumed at this point that the txn has no more concurrent
   users. */

static void
fd_accdb_publish_recs( fd_accdb_admin_t * accdb,
                       fd_funk_txn_t *    txn ) {
  /* Iterate record list */
  uint head = txn->rec_head_idx;
  txn->rec_head_idx = FD_FUNK_REC_IDX_NULL;
  txn->rec_tail_idx = FD_FUNK_REC_IDX_NULL;
  fd_wksp_t * funk_wksp = accdb->funk->wksp;
  while( !fd_funk_rec_idx_is_null( head ) ) {
    fd_funk_rec_t * rec = &accdb->funk->rec_pool->ele[ head ];

    /* Evict previous value from hash chain */
    fd_funk_xid_key_pair_t pair[1];
    fd_funk_rec_key_copy( pair->key, rec->pair.key );
    fd_funk_txn_xid_set_root( pair->xid );
    fd_accdb_chain_gc_root( accdb, pair );

    /* Root or reclaim record */
    uint next = rec->next_idx;
    fd_account_meta_t const * meta = fd_funk_val( rec, funk_wksp );
    FD_CRIT( meta && rec->val_sz>=sizeof(fd_account_meta_t), "invalid funk record value" );
    if( !meta->lamports && accdb->enable_reclaims ) {
      /* Remove record */
      fd_accdb_chain_reclaim( accdb, rec );
    } else {
      /* Migrate record to root */
      rec->prev_idx = FD_FUNK_REC_IDX_NULL;
      rec->next_idx = FD_FUNK_REC_IDX_NULL;
      fd_funk_txn_xid_t const root = { .ul = { ULONG_MAX, ULONG_MAX } };
      fd_funk_txn_xid_st_atomic( rec->pair.xid, &root );
      accdb->metrics.root_cnt++;
    }

    head = next; /* next record */
  }
}

/* fd_accdb_txn_publish_one merges an in-prep transaction whose
   parent is the last published, into the parent. */

static void
fd_accdb_txn_publish_one( fd_accdb_admin_t * accdb,
                          fd_funk_txn_t *    txn ) {
  fd_funk_t * funk = accdb->funk;

  /* Phase 1: Mark transaction as "last published" */

  fd_funk_txn_xid_t xid[1]; fd_funk_txn_xid_copy( xid, fd_funk_txn_xid( txn ) );
  if( FD_UNLIKELY( !fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->parent_cidx ) ) ) ) {
    FD_LOG_CRIT(( "fd_accdb_publish failed: txn with xid %lu:%lu is not a child of the last published txn", xid->ul[0], xid->ul[1] ));
  }
  fd_funk_txn_xid_st_atomic( funk->shmem->last_publish, xid );
  FD_LOG_INFO(( "accdb txn laddr=%p xid %lu:%lu: publish", (void *)txn, txn->xid.ul[0], txn->xid.ul[1] ));

  /* Phase 2: Drain users from transaction */

  fd_rwlock_write( txn->lock );
  FD_VOLATILE( txn->state ) = FD_FUNK_TXN_STATE_PUBLISH;

  /* Phase 3: Migrate records */

  fd_accdb_publish_recs( accdb, txn );

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
    FD_LOG_CRIT(( "fd_accdb_publish failed: fd_funk_txn_map_remove failed: %i-%s", remove_err, fd_map_strerror( remove_err ) ));
  }

  /* Phase 6: Free transaction object */

  fd_rwlock_unwrite( txn->lock );
  FD_VOLATILE( txn->state ) = FD_FUNK_TXN_STATE_FREE;
  txn->parent_cidx       = UINT_MAX;
  txn->sibling_prev_cidx = UINT_MAX;
  txn->sibling_next_cidx = UINT_MAX;
  txn->child_head_cidx   = UINT_MAX;
  txn->child_tail_cidx   = UINT_MAX;
  fd_funk_txn_pool_release( funk->txn_pool, txn, 1 );
}

void
fd_accdb_advance_root( fd_accdb_admin_t *        accdb,
                       fd_funk_txn_xid_t const * xid ) {
  fd_funk_t * funk = accdb->funk;

  /* Assume no concurrent access to txn_map */

  fd_funk_txn_map_query_t query[1];
  int query_err = fd_funk_txn_map_query_try( funk->txn_map, xid, NULL, query, 0 );
  if( FD_UNLIKELY( query_err ) ) {
    FD_LOG_CRIT(( "fd_accdb_advance_root failed: fd_funk_txn_map_query_try(xid=%lu:%lu) returned (%i-%s)",
                   xid->ul[0], xid->ul[1], query_err, fd_map_strerror( query_err ) ));
  }
  fd_funk_txn_t * txn = fd_funk_txn_map_query_ele( query );

  if( FD_UNLIKELY( !fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->parent_cidx ) ) ) ) {
    FD_LOG_CRIT(( "fd_accdb_txn_advance_root: parent of txn %lu:%lu is not root", xid->ul[0], xid->ul[1] ));
  }

  FD_LOG_INFO(( "accdb txn laddr=%p xid %lu:%lu: advancing root",
                (void *)txn,
                xid->ul[0], xid->ul[1] ));

  fd_accdb_txn_cancel_prev_list( accdb, txn );
  fd_accdb_txn_cancel_next_list( accdb, txn );
  txn->sibling_prev_cidx = UINT_MAX;
  txn->sibling_next_cidx = UINT_MAX;

  /* Children of transaction are now children of root */
  funk->shmem->child_head_cidx = txn->child_head_cidx;
  funk->shmem->child_tail_cidx = txn->child_tail_cidx;

  fd_accdb_txn_publish_one( accdb, txn );
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
      rec->map_next = FD_FUNK_REC_IDX_NULL;
      rec->next_idx = FD_FUNK_REC_IDX_NULL;
      rec->prev_idx = FD_FUNK_REC_IDX_NULL;
      memset( &rec->pair, 0, sizeof(fd_funk_xid_key_pair_t) );
      fd_funk_val_flush( rec, alloc, wksp );
      fd_funk_rec_pool_release( rec_pool, rec, 1 );
      iter.ele_idx = next;
    }
  }
}

/* clear_txn_list does a depth-first traversal of the txn tree.
   Removes all txns. */

static void
clear_txn_list( fd_funk_t * funk,
                ulong       txn_head_idx ) {
  fd_funk_txn_pool_t * txn_pool = funk->txn_pool;
  fd_funk_txn_map_t *  txn_map  = funk->txn_map;
  for( ulong idx = txn_head_idx;
       !fd_funk_txn_idx_is_null( idx );
  ) {
    fd_funk_txn_t * txn = &txn_pool->ele[ idx ];
    fd_funk_txn_state_assert( txn, FD_FUNK_TXN_STATE_ACTIVE );
    ulong next_idx  = fd_funk_txn_idx( txn->sibling_next_cidx );
    ulong child_idx = fd_funk_txn_idx( txn->child_head_cidx );
    txn->rec_head_idx      = FD_FUNK_REC_IDX_NULL;
    txn->rec_tail_idx      = FD_FUNK_REC_IDX_NULL;
    txn->child_head_cidx   = UINT_MAX;
    txn->child_tail_cidx   = UINT_MAX;
    txn->parent_cidx       = UINT_MAX;
    txn->sibling_prev_cidx = UINT_MAX;
    txn->sibling_next_cidx = UINT_MAX;
    clear_txn_list( funk, child_idx );
    fd_funk_txn_map_query_t query[1];
    int rm_err = fd_funk_txn_map_remove( txn_map, &txn->xid, NULL, query, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_txn_map_remove failed (%i-%s)", rm_err, fd_map_strerror( rm_err ) ));
    txn->state = FD_FUNK_TXN_STATE_FREE;
    int free_err = fd_funk_txn_pool_release( txn_pool, txn, 1 );
    if( FD_UNLIKELY( free_err!=FD_POOL_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_txn_pool_release failed (%i)", free_err ));
    idx = next_idx;
  }
  funk->shmem->child_head_cidx = UINT_MAX;
  funk->shmem->child_tail_cidx = UINT_MAX;
}

void
fd_accdb_clear( fd_accdb_admin_t * cache ) {
  fd_funk_t * funk = cache->funk;
  clear_txn_list( funk, fd_funk_txn_idx( funk->shmem->child_head_cidx ) );
  reset_rec_map( funk );
}

void
fd_accdb_verify( fd_accdb_admin_t * admin ) {
  FD_TEST( fd_funk_verify( admin->funk )==FD_FUNK_SUCCESS );
}
