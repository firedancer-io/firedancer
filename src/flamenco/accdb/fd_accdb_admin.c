#include "fd_accdb_admin.h"

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
  fd_funk_txn_prepare( db->funk, xid_parent, xid_new );
}

static void
fd_accdb_txn_cancel_one( fd_accdb_admin_t * admin,
                         fd_funk_txn_t *    txn ) {
  FD_LOG_INFO(( "accdb txn laddr=%p xid %lu:%lu: cancel", (void *)txn, txn->xid.ul[0], txn->xid.ul[1] ));

  fd_funk_t * funk = admin->funk;
  if( FD_UNLIKELY( !fd_funk_txn_idx_is_null( txn->child_head_cidx ) ||
                   !fd_funk_txn_idx_is_null( txn->child_tail_cidx ) ) ) {
    FD_LOG_CRIT(( "fd_accdb_txn_cancel failed: txn at %p with xid %lu:%lu has children (data corruption?)",
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
    FD_LOG_CRIT(( "fd_accdb_txn_cancel failed: fd_funk_txn_map_remove(%lu:%lu) failed: %i-%s",
                  txn->xid.ul[0], txn->xid.ul[1], remove_err, fd_map_strerror( remove_err ) ));
  }

  /* Phase 5: Free transaction object */

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

  fd_funk_txn_t * txn = fd_funk_txn_query( xid, funk->txn_map );
  if( FD_UNLIKELY( !txn ) ) {
    FD_LOG_CRIT(( "fd_accdb_txn_cancel failed: txn with xid %lu:%lu not found", xid->ul[0], xid->ul[1] ));
  }

  fd_accdb_txn_cancel_next_list( accdb, txn );
  fd_accdb_txn_cancel_tree( accdb, txn );
}

/* fd_accdb_publish_recs moves all records in a transaction to the DB
   root.  Currently, the DB root is stored by funk, which might change
   in the future.

   It is assumed at this point that the txn has no more concurrent
   users. */

static void
fd_accdb_publish_recs( fd_accdb_admin_t * accdb,
                       fd_funk_txn_t *    txn ) {
  fd_funk_txn_xid_t const root = { .ul = { ULONG_MAX, ULONG_MAX } };
  /* Iterate record list */
  uint head = txn->rec_head_idx;
  txn->rec_head_idx = FD_FUNK_REC_IDX_NULL;
  txn->rec_tail_idx = FD_FUNK_REC_IDX_NULL;
  while( !fd_funk_rec_idx_is_null( head ) ) {
    fd_funk_rec_t * rec = &accdb->funk->rec_pool->ele[ head ];
    uint next = rec->next_idx;
    rec->prev_idx = FD_FUNK_REC_IDX_NULL;
    rec->next_idx = FD_FUNK_REC_IDX_NULL;
    fd_funk_txn_xid_st_atomic( rec->pair.xid, &root );
    head = next;
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
  fd_funk_txn_pool_release( funk->txn_pool, txn, 1 );
}

void
fd_accdb_finalize_fork( fd_accdb_admin_t *        accdb,
                        fd_funk_txn_xid_t const * xid ) {
  (void)accdb; (void)xid;
  /* FIXME take a lock here */
}

void
fd_accdb_advance_root( fd_accdb_admin_t *        accdb,
                       fd_funk_txn_xid_t const * xid ) {
  fd_funk_t * funk = accdb->funk;

  fd_funk_txn_t * txn = fd_funk_txn_query( xid, funk->txn_map );
  if( FD_UNLIKELY( !txn ) ) {
    FD_LOG_CRIT(( "fd_accdb_txn_advance_root failed: txn with xid %lu:%lu not found", xid->ul[0], xid->ul[1] ));
  }

  if( FD_UNLIKELY( !fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->parent_cidx ) ) ) ) {
    FD_LOG_CRIT(( "fd_accdb_txn_advance_root: parent of txn %lu:%lu is not root", xid->ul[0], xid->ul[1] ));
  }

  fd_accdb_txn_cancel_prev_list( accdb, txn );
  fd_accdb_txn_cancel_next_list( accdb, txn );
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
  txn->sibling_prev_cidx = UINT_MAX;
  txn->sibling_next_cidx = UINT_MAX;

  /* Children of transaction are now children of root */
  funk->shmem->child_head_cidx = txn->child_head_cidx;
  funk->shmem->child_tail_cidx = txn->child_tail_cidx;

  fd_accdb_txn_publish_one( accdb, txn );
}
