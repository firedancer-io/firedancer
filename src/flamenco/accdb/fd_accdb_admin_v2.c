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
  fd_accdb_admin_v2_t * accdb = downcast( admin_ );
  fd_accdb_admin_v1_t * db    = accdb->v1;
  fd_funk_t *           funk  = db->funk;

  /* Ensure fork depth stays within limits.  This thread is the only
     one that appends to the fork graph.  Other threads may concurrently
     remove from the graph (by advancing root), which can only decrease
     the depth.  Therefore we can safely spin until there is room. */

  ulong max_depth = accdb->max_depth;
  if( FD_LIKELY( max_depth ) ) {
    for(;;) {
      /* Compute depth of the new child = 1 (for the child itself)
         + number of ancestors from parent to root. */

      ulong depth = 1UL;

      if( !fd_funk_txn_xid_eq( xid_parent, funk->shmem->last_publish ) ) {
        /* Parent is not root -- walk the parent chain */

        fd_funk_txn_map_query_t query[1];
        int err;
        for(;;) {
          err = fd_funk_txn_map_query_try( funk->txn_map, xid_parent, NULL, query, 0 );
          if( FD_LIKELY( err!=FD_MAP_ERR_AGAIN ) ) break;
          FD_SPIN_PAUSE();
        }

        if( FD_LIKELY( err==FD_MAP_SUCCESS ) ) {
          fd_funk_txn_t const * txn = fd_funk_txn_map_query_ele( query );
          depth++; /* count parent */

          ulong parent_idx = fd_funk_txn_idx( txn->parent_cidx );
          while( !fd_funk_txn_idx_is_null( parent_idx ) ) {
            txn = &funk->txn_pool->ele[ parent_idx ];
            depth++;
            parent_idx = fd_funk_txn_idx( txn->parent_cidx );
          }
        }
        /* If err==FD_MAP_ERR_KEY, parent was concurrently rooted.
           depth stays at 1, which is always within limits. */
      }

      if( FD_LIKELY( depth<max_depth ) ) break;
      FD_SPIN_PAUSE();
    }
  }

  FD_LOG_INFO(( "accdb txn xid %lu:%lu: created with parent %lu:%lu",
                xid_new   ->ul[0], xid_new   ->ul[1],
                xid_parent->ul[0], xid_parent->ul[1] ));
  fd_funk_txn_prepare( funk, xid_parent, xid_new );
}

void
fd_accdb_v2_cancel( fd_accdb_admin_t *        admin,
                    fd_funk_txn_xid_t const * xid ) {
  fd_accdb_v1_cancel( admin, xid );
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

  /* Root message is sent to the accdb tile by the replay tile via
     the replay_accdb stem link (see fd_replay_tile.c). */
}

void
fd_accdb_admin_v2_delay_set( fd_accdb_admin_t * accdb_,
                             ulong              slot_delay ) {
  fd_accdb_admin_v2_t * accdb = downcast( accdb_ );
  if( FD_UNLIKELY( !slot_delay ) ) FD_LOG_CRIT(( "invalid slot_delay (%lu)", slot_delay ));
  accdb->slot_delay = slot_delay;
}

void
fd_accdb_admin_v2_max_depth_set( fd_accdb_admin_t * accdb_,
                                  ulong              max_depth ) {
  fd_accdb_admin_v2_t * accdb = downcast( accdb_ );
  accdb->max_depth = max_depth;
}

fd_accdb_admin_vt_t const fd_accdb_admin_v2_vt = {
  .fini         = fd_accdb_admin_v2_fini,
  .root_get     = fd_accdb_v2_root_get,
  .attach_child = fd_accdb_v2_attach_child,
  .advance_root = fd_accdb_v2_advance_root,
  .cancel       = fd_accdb_v2_cancel
};
