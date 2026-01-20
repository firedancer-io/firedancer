#include "fd_accdb_funk.h"
#include "../../funk/fd_funk.h"

void
fd_accdb_funk_copy_account( fd_account_meta_t *       out_meta,
                            void *                    out_data,
                            fd_account_meta_t const * src_meta,
                            void const *              src_data ) {
  memset( out_meta, 0, sizeof(fd_account_meta_t) );
  out_meta->lamports = src_meta->lamports;
  if( FD_LIKELY( out_meta->lamports ) ) {
    memcpy( out_meta->owner, src_meta->owner, 32UL );
    out_meta->executable = !!src_meta->executable;
    out_meta->dlen       = (uint)src_meta->dlen;
    fd_memcpy( out_data, src_data, out_meta->dlen );
  }
}

void
fd_accdb_funk_copy_truncated( fd_account_meta_t *       out_meta,
                              fd_account_meta_t const * src_meta ) {
  memset( out_meta, 0, sizeof(fd_account_meta_t) );
  out_meta->lamports = src_meta->lamports;
  if( FD_LIKELY( out_meta->lamports ) ) {
    memcpy( out_meta->owner, src_meta->owner, 32UL );
    out_meta->executable = !!src_meta->executable;
    out_meta->dlen       = 0;
  }
}

/* fd_accdb_v1_prep_create preps a writable handle for a newly created
   account. */

fd_accdb_rw_t *
fd_accdb_funk_prep_create( fd_accdb_rw_t *       rw,
                           fd_funk_t *           funk,
                           fd_funk_txn_t const * txn,
                           void const *          address,
                           void *                val,
                           ulong                 val_sz,
                           ulong                 val_max ) {
  FD_CRIT( val_sz >=sizeof(fd_account_meta_t), "invalid val_sz"  );
  FD_CRIT( val_max>=sizeof(fd_account_meta_t), "invalid val_max" );
  FD_CRIT( val_sz<=val_max, "invalid val_max" );

  fd_funk_rec_t * rec = fd_funk_rec_pool_acquire( funk->rec_pool, NULL, 1, NULL );
  if( FD_UNLIKELY( !rec ) ) FD_LOG_CRIT(( "Failed to modify account: DB record pool is out of memory" ));

  fd_funk_txn_xid_copy( rec->pair.xid, &txn->xid );
  memcpy( rec->pair.key->uc, address, 32UL );
  rec->map_next  = 0U;
  rec->ver_lock  = fd_funk_rec_ver_lock( fd_funk_rec_ver_inc( fd_funk_rec_ver_bits( rec->ver_lock ) ), FD_FUNK_REC_LOCK_MASK );
  rec->next_idx  = FD_FUNK_REC_IDX_NULL;
  rec->prev_idx  = FD_FUNK_REC_IDX_NULL;
  rec->val_sz    = (uint)( fd_ulong_min( val_sz,  FD_FUNK_REC_VAL_MAX ) & FD_FUNK_REC_VAL_MAX );
  rec->val_max   = (uint)( fd_ulong_min( val_max, FD_FUNK_REC_VAL_MAX ) & FD_FUNK_REC_VAL_MAX );
  rec->tag       = 0;
  rec->val_gaddr = fd_wksp_gaddr_fast( funk->wksp, val );

  fd_account_meta_t * meta = val;
  meta->slot = txn->xid.ul[0];

  *rw = (fd_accdb_rw_t){0};
  memcpy( rw->ref->address, address, 32UL );
  rw->ref->accdb_type = FD_ACCDB_TYPE_V1;
  rw->ref->user_data  = (ulong)rec;
  rw->ref->user_data2 = (ulong)txn;
  rw->ref->ref_type   = FD_ACCDB_REF_RW;
  rw->meta            = meta;
  return rw;
}

/* fd_accdb_prep_inplace preps a writable handle for a mutable record. */

fd_accdb_rw_t *
fd_accdb_funk_prep_inplace( fd_accdb_rw_t * rw,
                            fd_funk_t *     funk,
                            fd_funk_rec_t * rec ) {
  /* Take the opportunity to run some validation checks */
  if( FD_UNLIKELY( !rec->val_gaddr ) ) {
    FD_LOG_CRIT(( "Failed to prepare in-place account write: rec %p is not allocated", (void *)rec ));
  }

  *rw = (fd_accdb_rw_t) {0};
  memcpy( rw->ref->address, rec->pair.key->uc, 32UL );
  rw->ref->accdb_type = FD_ACCDB_TYPE_V1;
  rw->ref->user_data  = (ulong)rec;
  rw->ref->ref_type   = FD_ACCDB_REF_RW;
  rw->meta            = fd_funk_val( rec, funk->wksp );
  if( FD_UNLIKELY( !rw->meta->lamports ) ) {
    memset( rw->meta, 0, sizeof(fd_account_meta_t) );
  }
  return rw;
}

fd_accdb_rw_t *
fd_accdb_funk_create( fd_funk_t *           funk,
                      fd_accdb_rw_t *       rw,
                      fd_funk_txn_t const * txn,
                      void const *          address,
                      ulong                 data_max ) {
  ulong  val_sz_min = sizeof(fd_account_meta_t)+data_max;
  ulong  val_max    = 0UL;
  void * val        = fd_alloc_malloc_at_least( funk->alloc, 16UL, val_sz_min, &val_max );
  if( FD_UNLIKELY( !val ) ) {
    FD_LOG_CRIT(( "Failed to modify account: out of memory allocating %lu bytes", data_max ));
  }
  memset( val, 0, sizeof(fd_account_meta_t) );
  return fd_accdb_funk_prep_create( rw, funk, txn, address, val, sizeof(fd_account_meta_t), val_max );
}
