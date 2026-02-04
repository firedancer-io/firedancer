#include "fd_accdb_admin_v2_private.h"

FD_STATIC_ASSERT( alignof(fd_accdb_admin_v2_t)<=alignof(fd_accdb_admin_t), layout );
FD_STATIC_ASSERT( sizeof (fd_accdb_admin_v2_t)<=sizeof(fd_accdb_admin_t),  layout );

fd_accdb_admin_t *
fd_accdb_admin_v2_init( fd_accdb_admin_t * accdb_,
                        void *             shfunk,
                        void *             vinyl_rq,
                        void *             vinyl_data,
                        void *             vinyl_req_pool,
                        ulong              vinyl_link_id ) {
  /* Call superclass constructor */
  if( FD_UNLIKELY( !fd_accdb_admin_v1_init( accdb_, shfunk ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !vinyl_data ) ) {
    FD_LOG_WARNING(( "NULL vinyl_data" ));
    return NULL;
  }

  fd_vinyl_rq_t *       rq       = fd_vinyl_rq_join( vinyl_rq );
  fd_vinyl_req_pool_t * req_pool = fd_vinyl_req_pool_join( vinyl_req_pool );
  if( FD_UNLIKELY( !rq || !req_pool ) ) {
    /* component joins log warning if this is reached */
    FD_LOG_WARNING(( "Failed to initialize database client" ));
    return NULL;
  }

  fd_accdb_admin_v2_t * accdb = fd_type_pun( accdb_ );
  accdb->vinyl_req_id    = 0UL;
  accdb->vinyl_rq        = rq;
  accdb->vinyl_link_id   = vinyl_link_id;
  accdb->vinyl_data_wksp = vinyl_data;
  accdb->vinyl_req_wksp  = fd_wksp_containing( req_pool );
  accdb->vinyl_req_pool  = req_pool;
  accdb->base.accdb_type = FD_ACCDB_TYPE_V2;
  accdb->base.vt         = &fd_accdb_admin_v2_vt;
  return accdb_;
}

static fd_accdb_admin_v2_t *
downcast( fd_accdb_admin_t * admin ) {
  if( FD_UNLIKELY( !admin ) ) {
    FD_LOG_CRIT(( "NULL admin" ));
  }
  if( FD_UNLIKELY( admin->base.accdb_type!=FD_ACCDB_TYPE_V2 ) ) {
    FD_LOG_CRIT(( "corrupt accdb_admin handle" ));
  }
  return (fd_accdb_admin_v2_t *)admin;
}

void
fd_accdb_admin_v2_fini( fd_accdb_admin_t * admin_ ) {
  fd_accdb_admin_v2_t * admin = downcast( admin_ );

  fd_vinyl_rq_leave( admin->vinyl_rq );

  /* superclass destructor */
  admin->base.accdb_type = FD_ACCDB_TYPE_V1;
  fd_accdb_admin_v1_fini( admin_ );
}

fd_funk_txn_xid_t
fd_accdb_v2_root_get( fd_accdb_admin_t const * admin ) {
  return fd_accdb_v1_root_get( admin );
}

void
fd_accdb_v2_attach_child( fd_accdb_admin_t *        admin_,
                          fd_funk_txn_xid_t const * xid_parent,
                          fd_funk_txn_xid_t const * xid_new ) {
  fd_accdb_admin_v1_t * db = downcast( admin_ )->v1;
  FD_LOG_INFO(( "accdb txn xid %lu:%lu: created with parent %lu:%lu",
                xid_new   ->ul[0], xid_new   ->ul[1],
                xid_parent->ul[0], xid_parent->ul[1] ));
  fd_funk_txn_prepare( db->funk, xid_parent, xid_new );
}

void
fd_accdb_v2_cancel( fd_accdb_admin_t *        admin,
                    fd_funk_txn_xid_t const * xid ) {
  fd_accdb_v1_cancel( admin, xid );
}

static void
publish_recs( fd_accdb_admin_v2_t * admin,
              fd_funk_txn_t *       txn ) {
  fd_funk_rec_t * rec_pool = admin->v1->funk->rec_pool->ele;
  fd_funk_rec_t * head = !fd_funk_rec_idx_is_null( txn->rec_head_idx ) ?
      &rec_pool[ txn->rec_head_idx ] : NULL;
  txn->rec_head_idx = FD_FUNK_REC_IDX_NULL;
  txn->rec_tail_idx = FD_FUNK_REC_IDX_NULL;
  while( head ) {
    head = fd_accdb_v2_root_batch( admin, head );
  }
}

static void
txn_unregister( fd_funk_t *     funk,
                fd_funk_txn_t * txn ) {
  ulong child_idx = fd_funk_txn_idx( txn->child_head_cidx );
  while( FD_UNLIKELY( !fd_funk_txn_idx_is_null( child_idx ) ) ) {
    funk->txn_pool->ele[ child_idx ].parent_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
    child_idx = fd_funk_txn_idx( funk->txn_pool->ele[ child_idx ].sibling_next_cidx );
  }

  fd_funk_txn_xid_t xid[1]; fd_funk_txn_xid_copy( xid, fd_funk_txn_xid( txn ) );
  fd_funk_txn_map_query_t query[1];
  int remove_err = fd_funk_txn_map_remove( funk->txn_map, xid, NULL, query, 0 );
  if( FD_UNLIKELY( remove_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "fd_accdb_publish failed: fd_funk_txn_map_remove failed: %i-%s", remove_err, fd_map_strerror( remove_err ) ));
  }
}

static void
txn_free( fd_funk_t *     funk,
          fd_funk_txn_t * txn ) {
  FD_VOLATILE( txn->state ) = FD_FUNK_TXN_STATE_FREE;
  txn->parent_cidx       = UINT_MAX;
  txn->sibling_prev_cidx = UINT_MAX;
  txn->sibling_next_cidx = UINT_MAX;
  txn->child_head_cidx   = UINT_MAX;
  txn->child_tail_cidx   = UINT_MAX;
  fd_funk_txn_pool_release( funk->txn_pool, txn, 1 );
}

static void
fd_accdb_txn_publish_one( fd_accdb_admin_v2_t * accdb,
                          fd_funk_txn_t *       txn ) {
  fd_funk_t * funk = accdb->v1->funk;

  /* Children of transaction are now children of root */
  funk->shmem->child_head_cidx = txn->child_head_cidx;
  funk->shmem->child_tail_cidx = txn->child_tail_cidx;

  /* Phase 1: Mark transaction as "last published" */

  fd_funk_txn_xid_t xid[1]; fd_funk_txn_xid_copy( xid, fd_funk_txn_xid( txn ) );
  if( FD_UNLIKELY( !fd_funk_txn_idx_is_null( fd_funk_txn_idx( txn->parent_cidx ) ) ) ) {
    FD_LOG_CRIT(( "fd_accdb_txn_advance_root: parent of txn %lu:%lu is not root", xid->ul[0], xid->ul[1] ));
  }
  fd_funk_txn_xid_st_atomic( funk->shmem->last_publish, xid );
  FD_LOG_INFO(( "accdb txn laddr=%p xid %lu:%lu: publish", (void *)txn, txn->xid.ul[0], txn->xid.ul[1] ));

  /* Phase 2: Drain users from transaction */

  fd_rwlock_write( txn->lock );
  FD_VOLATILE( txn->state ) = FD_FUNK_TXN_STATE_PUBLISH;

  /* Phase 3: Move records from funk to vinyl */

  publish_recs( accdb, txn );

  /* Phase 4: Unregister transaction */

  txn_unregister( funk, txn );

  /* Phase 5: Free transaction object */

  fd_rwlock_unwrite( txn->lock );
  txn_free( funk, txn );
}

void
fd_accdb_v2_advance_root( fd_accdb_admin_t *        accdb_,
                          fd_funk_txn_xid_t const * xid ) {
  fd_accdb_admin_v2_t * accdb = downcast( accdb_ );
  fd_funk_t *           funk  = accdb->v1->funk;

  fd_accdb_lineage_set_fork( accdb->root_lineage, funk, xid );

  /* Assume no concurrent access to txn_map */

  fd_funk_txn_map_query_t query[1];
  int query_err = fd_funk_txn_map_query_try( funk->txn_map, xid, NULL, query, 0 );
  if( FD_UNLIKELY( query_err ) ) {
    FD_LOG_CRIT(( "fd_accdb_advance_root failed: fd_funk_txn_map_query_try(xid=%lu:%lu) returned (%i-%s)",
                   xid->ul[0], xid->ul[1], query_err, fd_map_strerror( query_err ) ));
  }
  fd_funk_txn_t * txn = fd_funk_txn_map_query_ele( query );

  FD_LOG_INFO(( "accdb txn laddr=%p xid %lu:%lu: advancing root",
                (void *)txn,
                xid->ul[0], xid->ul[1] ));

  fd_accdb_txn_cancel_siblings( accdb->v1, txn );

  fd_accdb_lineage_t * lineage    = accdb->root_lineage;
  fd_funk_txn_xid_t    oldest_xid = lineage->fork[ lineage->fork_depth-1UL ];
  if( fd_funk_txn_xid_eq_root( &oldest_xid ) && lineage->fork_depth>1UL ) {
    oldest_xid = lineage->fork[ lineage->fork_depth-2UL ];
  }

  ulong delay = xid->ul[0] - oldest_xid.ul[0];
  if( delay >= accdb->slot_delay ) {
    FD_LOG_INFO(( "accdb xid %lu:%lu: pruning",
                  oldest_xid.ul[0], oldest_xid.ul[1] ));
    fd_funk_txn_t * oldest = &funk->txn_pool->ele[ funk->shmem->child_head_cidx ];
    FD_TEST( fd_funk_txn_xid_eq( &oldest_xid, &oldest->xid ) );
    fd_accdb_txn_publish_one( accdb, oldest );
  }
}

void
fd_accdb_admin_v2_delay_set( fd_accdb_admin_t * accdb_,
                             ulong              slot_delay ) {
  fd_accdb_admin_v2_t * accdb = downcast( accdb_ );
  if( FD_UNLIKELY( !slot_delay ) ) FD_LOG_CRIT(( "invalid slot_delay (%lu)", slot_delay ));
  accdb->slot_delay = slot_delay;
}

fd_accdb_admin_vt_t const fd_accdb_admin_v2_vt = {
  .fini         = fd_accdb_admin_v2_fini,
  .root_get     = fd_accdb_v2_root_get,
  .attach_child = fd_accdb_v2_attach_child,
  .advance_root = fd_accdb_v2_advance_root,
  .cancel       = fd_accdb_v2_cancel
};
