#include "fd_accdb_admin_v2.h"
#include "fd_accdb_admin_v1.h"
#include "fd_vinyl_req_pool.h"
#include "../fd_flamenco_base.h"
#include "../../vinyl/data/fd_vinyl_data.h"

/* FD_ACCDB_ROOT_BATCH_MAX controls how many accounts to write in
   batches to the vinyl DB server. */

#define FD_ACCDB_ROOT_BATCH_MAX (128UL)

struct fd_accdb_admin_v2 {
  union {
    fd_accdb_admin_base_t base;
    fd_accdb_admin_v1_t   v1[1];
  };

  /* Vinyl client */
  ulong                 vinyl_req_id;
  fd_vinyl_rq_t *       vinyl_rq;
  ulong                 vinyl_link_id;
  fd_wksp_t *           vinyl_data_wksp;
  fd_wksp_t *           vinyl_req_wksp;
  fd_vinyl_req_pool_t * vinyl_req_pool;
};

typedef struct fd_accdb_admin_v2 fd_accdb_admin_v2_t;

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
vinyl_push_rec( fd_accdb_admin_v2_t *     admin,
                void const *              addr,
                fd_account_meta_t const * src_meta ) {
  fd_vinyl_rq_t *       rq        = admin->vinyl_rq;        /* "request queue "*/
  fd_vinyl_req_pool_t * req_pool  = admin->vinyl_req_pool;  /* "request pool" */
  fd_wksp_t *           req_wksp  = admin->vinyl_req_wksp;  /* shm workspace containing request buffer */
  fd_wksp_t *           data_wksp = admin->vinyl_data_wksp; /* shm workspace containing vinyl data cache */
  ulong                 link_id   = admin->vinyl_link_id;   /* vinyl client ID */

  ulong batch_idx = fd_vinyl_req_pool_acquire( req_pool );
  /* req_pool_release called before returning */
  fd_vinyl_comp_t * comp          = fd_vinyl_req_batch_comp     ( req_pool, batch_idx );
  fd_vinyl_key_t *  req_key       = fd_vinyl_req_batch_key      ( req_pool, batch_idx );
  schar *           req_err       = fd_vinyl_req_batch_err      ( req_pool, batch_idx );
  ulong *           req_val_gaddr = fd_vinyl_req_batch_val_gaddr( req_pool, batch_idx );

  memset( comp, 0, sizeof(fd_vinyl_comp_t) );
  fd_vinyl_key_init( req_key, addr, 32UL );
  *req_err       = 0;
  *req_val_gaddr = 0UL;

  ulong val_sz = sizeof(fd_account_meta_t)+src_meta->dlen;
  ulong flags  = FD_VINYL_REQ_FLAG_MODIFY | FD_VINYL_REQ_FLAG_CREATE;
  ulong req_id = admin->vinyl_req_id++;
  fd_vinyl_req_send_batch( rq, req_pool, req_wksp, req_id, link_id, FD_VINYL_REQ_TYPE_ACQUIRE, flags, batch_idx, 1UL, val_sz );

  while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
  int comp_err = FD_VOLATILE_CONST( comp->err );
  if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile rejected my ACQUIRE request: %i-%s", comp_err, fd_vinyl_strerror( comp_err ) ));
  }
  int err = FD_VOLATILE_CONST( req_err[0] );
  if( FD_UNLIKELY( err!=FD_VINYL_SUCCESS ) ) {
    err = FD_VOLATILE_CONST( req_err[0] );
    FD_LOG_CRIT(( "vinyl tile ACQUIRE request failed: %i-%s", err, fd_vinyl_strerror( err ) ));
  }

  fd_account_meta_t * dst_meta = fd_wksp_laddr_fast( data_wksp, req_val_gaddr[0] );
  fd_vinyl_info_t *   val_info = fd_vinyl_data_info( dst_meta );
  fd_memcpy( dst_meta, src_meta, val_sz );
  val_info->val_sz = (uint)val_sz;

  memset( comp, 0, sizeof(fd_vinyl_comp_t) );
  *req_err = 0;
  flags  = FD_VINYL_REQ_FLAG_MODIFY;
  req_id = admin->vinyl_req_id++;
  fd_vinyl_req_send_batch( rq, req_pool, req_wksp, req_id, link_id, FD_VINYL_REQ_TYPE_RELEASE, FD_VINYL_REQ_FLAG_MODIFY, batch_idx, 1UL, val_sz );

  while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
  comp_err = FD_VOLATILE_CONST( comp->err );
  if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile rejected my RELEASE request: %i-%s", comp_err, fd_vinyl_strerror( comp_err ) ));
  }
  if( FD_UNLIKELY( req_err[0]!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile RELEASE request failed: %i-%s", req_err[0], fd_vinyl_strerror( req_err[0] ) ));
  }

  fd_vinyl_req_pool_release( req_pool, batch_idx );
}

static void
vinyl_remove_rec( fd_accdb_admin_v2_t * admin,
                  void const *          addr ) {
  fd_vinyl_rq_t *       rq       = admin->vinyl_rq;        /* "request queue "*/
  fd_vinyl_req_pool_t * req_pool = admin->vinyl_req_pool;  /* "request pool" */
  fd_wksp_t *           req_wksp = admin->vinyl_req_wksp;  /* shm workspace containing request buffer */
  ulong                 link_id  = admin->vinyl_link_id;   /* vinyl client ID */

  ulong batch_idx = fd_vinyl_req_pool_acquire( req_pool );
  /* req_pool_release called before returning */
  fd_vinyl_comp_t * comp    = fd_vinyl_req_batch_comp( req_pool, batch_idx );
  fd_vinyl_key_t *  req_key = fd_vinyl_req_batch_key ( req_pool, batch_idx );
  schar *           req_err = fd_vinyl_req_batch_err ( req_pool, batch_idx );

  memset( comp, 0, sizeof(fd_vinyl_comp_t) );
  fd_vinyl_key_init( req_key, addr, 32UL );
  *req_err = 0;

  ulong req_id = admin->vinyl_req_id++;
  fd_vinyl_req_send_batch( rq, req_pool, req_wksp, req_id, link_id, FD_VINYL_REQ_TYPE_ERASE, 0UL, batch_idx, 1UL, 0UL );

  while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
  int comp_err = FD_VOLATILE_CONST( comp->err );
  if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile rejected my ERASE request: %i-%s", comp_err, fd_vinyl_strerror( comp_err ) ));
  }
  int err = FD_VOLATILE_CONST( req_err[0] );
  if( FD_UNLIKELY( err!=FD_VINYL_SUCCESS && err!=FD_VINYL_ERR_KEY ) ) {
    err = FD_VOLATILE_CONST( req_err[0] );
    FD_LOG_CRIT(( "vinyl tile ERASE request failed: %i-%s", err, fd_vinyl_strerror( err ) ));
  }

  fd_vinyl_req_pool_release( req_pool, batch_idx );
}

/* funk_rec_write_lock spins until it gains a write lock for a record,
   increments the version number, and returns the updated ver_lock
   value. */

static ulong
fd_funk_rec_admin_lock( fd_funk_rec_t * rec ) {
  ulong * vl = &rec->ver_lock;
  for(;;) {
    ulong const ver_lock = FD_VOLATILE_CONST( *vl );
    ulong const ver      = fd_funk_rec_ver_bits ( ver_lock );
    ulong const lock     = fd_funk_rec_lock_bits( ver_lock );
    if( FD_UNLIKELY( lock ) ) {
      /* Spin while there are active readers */
      /* FIXME kill client after spinning for 30 seconds to prevent silent deadlock */
      FD_SPIN_PAUSE();
      continue;
    }
    ulong const new_ver = fd_funk_rec_ver_inc( ver );
    ulong const new_vl  = fd_funk_rec_ver_lock( new_ver, FD_FUNK_REC_LOCK_MASK );
    if( FD_UNLIKELY( FD_ATOMIC_CAS( vl, ver_lock, new_vl )!=ver_lock ) ) {
      FD_SPIN_PAUSE();
      continue;
    }
    return new_vl;
  }
}

static void
fd_funk_rec_admin_unlock( fd_funk_rec_t * rec,
                          ulong           ver_lock ) {
  FD_VOLATILE( rec->ver_lock ) = fd_funk_rec_ver_lock( fd_funk_rec_ver_bits( ver_lock ), 0UL );
}

static void
funk_remove_rec( fd_funk_t *     funk,
                 fd_funk_rec_t * rec ) {

  /* Step 1: Remove record from map */

  fd_funk_xid_key_pair_t pair = rec->pair;
  fd_funk_rec_query_t query[1];
  int rm_err = fd_funk_rec_map_remove( funk->rec_map, &pair, NULL, query, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_rec_map_remove failed (%i-%s)", rm_err, fd_map_strerror( rm_err ) ));
  FD_COMPILER_MFENCE();

  /* Step 2: Acquire admin lock (kick out readers)

     Note: At this point, well-behaving external readers will abandon a
     read-lock attempt if they observe this active write lock.  (An
     admin lock always implies the record is about to die) */

  ulong ver_lock = fd_funk_rec_admin_lock( rec );

  /* Step 3: Free record */

  memset( &rec->pair, 0, sizeof(fd_funk_xid_key_pair_t) );
  FD_COMPILER_MFENCE();
  rec->map_next = FD_FUNK_REC_IDX_NULL;
  fd_funk_val_flush( rec, funk->alloc, funk->wksp );
  fd_funk_rec_admin_unlock( rec, ver_lock );
  fd_funk_rec_pool_release( funk->rec_pool, rec, 1 );
}

static void
publish_recs( fd_accdb_admin_v2_t * admin,
              fd_funk_txn_t *       txn ) {
  fd_funk_t * funk      = admin->v1->funk;
  fd_wksp_t * funk_wksp = funk->wksp;

  /* Iterate record list */
  uint head = txn->rec_head_idx;
  txn->rec_head_idx = FD_FUNK_REC_IDX_NULL;
  txn->rec_tail_idx = FD_FUNK_REC_IDX_NULL;
  while( !fd_funk_rec_idx_is_null( head ) ) {
    fd_funk_rec_t * rec = &funk->rec_pool->ele[ head ];
    uint next = rec->next_idx;
    fd_account_meta_t const * meta = fd_funk_val( rec, funk_wksp );
    FD_CRIT( meta && rec->val_sz>=sizeof(fd_account_meta_t), "invalid funk record value" );

    /* Migrate records one-by-one.  This is slow and should be done in
       batches instead.  But it's simple and shippable for now. */
    if( meta->lamports ) {
      vinyl_push_rec( admin, rec->pair.key, meta );
    } else {
      vinyl_remove_rec( admin, rec->pair.key );
    }
    funk_remove_rec( funk,  rec );

    admin->base.root_cnt++;
    head = next; /* next record */
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

  fd_accdb_txn_cancel_siblings( accdb->v1, txn );

  /* Children of transaction are now children of root */
  funk->shmem->child_head_cidx = txn->child_head_cidx;
  funk->shmem->child_tail_cidx = txn->child_tail_cidx;

  fd_accdb_txn_publish_one( accdb, txn );
}

fd_accdb_admin_vt_t const fd_accdb_admin_v2_vt = {
  .fini         = fd_accdb_admin_v2_fini,
  .root_get     = fd_accdb_v2_root_get,
  .attach_child = fd_accdb_v2_attach_child,
  .advance_root = fd_accdb_v2_advance_root,
  .cancel       = fd_accdb_v2_cancel
};
