#include "fd_accdb_admin_v2.h"

FD_STATIC_ASSERT( alignof(fd_accdb_admin_v2_t)<=alignof(fd_accdb_admin_t), layout );
FD_STATIC_ASSERT( sizeof (fd_accdb_admin_v2_t)<=sizeof(fd_accdb_admin_t),  layout );

fd_accdb_admin_t *
fd_accdb_admin_v2_init( fd_accdb_admin_t * accdb_,
                        void *             shfunk,
                        void *             shlocks ) {
  /* Call superclass constructor */
  if( FD_UNLIKELY( !fd_accdb_admin_v1_init( accdb_, shfunk, shlocks ) ) ) {
    return NULL;
  }

  fd_accdb_admin_v2_t * accdb = fd_type_pun( accdb_ );
  accdb->base.accdb_type         = FD_ACCDB_TYPE_V2;
  accdb->base.vt                 = &fd_accdb_admin_v2_vt;
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
fd_accdb_txn_publish_one( fd_accdb_admin_v2_t * accdb,
                          fd_funk_txn_t *       txn ) {
  /* Send request to accdb tile */
}

void
fd_accdb_v2_advance_root( fd_accdb_admin_t *        accdb_,
                          fd_funk_txn_xid_t const * xid ) {
  fd_accdb_admin_v2_t * accdb = downcast( accdb_ );
  fd_funk_t *           funk  = accdb->v1->funk;

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

  fd_funk_txn_xid_t oldest_xid = lineage->fork[ lineage->fork_depth-1UL ];
  if( fd_funk_txn_xid_eq_root( &oldest_xid ) && lineage->fork_depth>1UL ) {
    oldest_xid = lineage->fork[ lineage->fork_depth-2UL ];
  }

  ulong delay = xid->ul[0] - oldest_xid.ul[0];
  /* genesis_override is necessary when bootstrapping from genesis,
     without requiring fd_accdb_admin_v2_delay_set to accept 0. */
  int genesis_override = !xid->ul[0];
  if( delay >= accdb->slot_delay || genesis_override ) {
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
