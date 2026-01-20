#include "fd_accdb_impl_v1.h"
#include "fd_accdb_lineage.h"
#include "fd_accdb_funk.h"

FD_STATIC_ASSERT( alignof(fd_accdb_user_v1_t)<=alignof(fd_accdb_user_t), layout );
FD_STATIC_ASSERT( sizeof (fd_accdb_user_v1_t)<=sizeof(fd_accdb_user_t),  layout );

static int
fd_accdb_search_chain( fd_accdb_user_v1_t const * accdb,
                       ulong                      chain_idx,
                       fd_funk_rec_key_t const *  key,
                       fd_funk_rec_t **           out_rec ) {
  *out_rec = NULL;

  fd_funk_rec_map_shmem_t const *               shmap     = accdb->funk->rec_map->map;
  fd_funk_rec_map_shmem_private_chain_t const * chain_tbl = fd_funk_rec_map_shmem_private_chain_const( shmap, 0UL );
  fd_funk_rec_map_shmem_private_chain_t const * chain     = chain_tbl + chain_idx;
  fd_funk_rec_t *                               rec_tbl   = accdb->funk->rec_pool->ele;
  ulong                                         rec_max   = fd_funk_rec_pool_ele_max( accdb->funk->rec_pool );
  ulong                                         ver_cnt   = FD_VOLATILE_CONST( chain->ver_cnt );

  /* Start a speculative transaction for the chain containing revisions
     of the account key we are looking for. */
  ulong cnt = fd_funk_rec_map_private_vcnt_cnt( ver_cnt );
  if( FD_UNLIKELY( fd_funk_rec_map_private_vcnt_ver( ver_cnt )&1 ) ) {
    return FD_MAP_ERR_AGAIN; /* chain is locked */
  }
  FD_COMPILER_MFENCE();
  uint ele_idx = chain->head_cidx;

  /* Walk the map chain, bail at the first entry
     (Each chain is sorted newest-to-oldest) */
  fd_funk_rec_t * best = NULL;
  for( ulong i=0UL; i<cnt; i++, ele_idx=rec_tbl[ ele_idx ].map_next ) {
    fd_funk_rec_t * rec = &rec_tbl[ ele_idx ];

    /* Skip over unrelated records (hash collision) */
    if( FD_UNLIKELY( !fd_funk_rec_key_eq( rec->pair.key, key ) ) ) continue;

    /* Confirm that record is part of the current fork */
    if( FD_UNLIKELY( !fd_accdb_lineage_has_xid( accdb->lineage, rec->pair.xid ) ) ) continue;

    if( FD_UNLIKELY( rec->map_next==ele_idx ) ) {
      FD_LOG_CRIT(( "fd_accdb_search_chain detected cycle" ));
    }
    if( rec->map_next > rec_max ) {
      if( FD_UNLIKELY( !fd_funk_rec_map_private_idx_is_null( rec->map_next ) ) ) {
        FD_LOG_CRIT(( "fd_accdb_search_chain detected memory corruption: rec->map_next %u is out of bounds (rec_max %lu)",
                      rec->map_next, rec_max ));
      }
    }
    best = rec;
    break;
  }

  /* Retry if we were overrun */
  if( FD_UNLIKELY( FD_VOLATILE_CONST( chain->ver_cnt )!=ver_cnt ) ) {
    return FD_MAP_ERR_AGAIN;
  }

  *out_rec = best;
  return FD_MAP_SUCCESS;
}

fd_accdb_ro_t *
fd_accdb_peek_funk( fd_accdb_user_v1_t *      accdb,
                    fd_accdb_ro_t *           ro,
                    fd_funk_txn_xid_t const * xid,
                    void const *              address ) {
  fd_funk_t const * funk = accdb->funk;
  fd_funk_rec_key_t key[1]; memcpy( key->uc, address, 32UL );

  /* Hash key to chain */
  fd_funk_xid_key_pair_t pair[1];
  fd_funk_txn_xid_copy( pair->xid, xid );
  fd_funk_rec_key_copy( pair->key, key );
  fd_funk_rec_map_t const * rec_map = funk->rec_map;
  ulong hash      = fd_funk_rec_map_key_hash( pair, rec_map->map->seed );
  ulong chain_idx = (hash & (rec_map->map->chain_cnt-1UL) );

  /* Traverse chain for candidate */
  fd_funk_rec_t * rec = NULL;
  for(;;) {
    int err = fd_accdb_search_chain( accdb, chain_idx, key, &rec );
    if( FD_LIKELY( err==FD_MAP_SUCCESS ) ) break;
    FD_SPIN_PAUSE();
    /* FIXME backoff */
  }
  if( !rec ) return NULL;

  memcpy( ro->ref->address, address, 32UL );
  ro->ref->accdb_type = FD_ACCDB_TYPE_V1;
  ro->ref->ref_type   = FD_ACCDB_REF_RO;
  ro->ref->user_data  = (ulong)rec;
  ro->ref->user_data2 = 0UL;
  ro->meta            = fd_funk_val( rec, funk->wksp );
  return ro;
}

static ulong
fd_accdb_user_v1_batch_max( fd_accdb_user_t * accdb ) {
  (void)accdb;
  return ULONG_MAX;
}

void
fd_accdb_user_v1_fini( fd_accdb_user_t * accdb ) {
  fd_accdb_user_v1_t * user = (fd_accdb_user_v1_t *)accdb;

  if( FD_UNLIKELY( !fd_funk_leave( user->funk, NULL ) ) ) FD_LOG_CRIT(( "fd_funk_leave failed" ));
}

void
fd_accdb_user_v1_open_ro_multi( fd_accdb_user_t *         accdb,
                                fd_accdb_ro_t *           ro,
                                fd_funk_txn_xid_t const * xid,
                                void const *              address,
                                ulong                     cnt ) {
  fd_accdb_user_v1_t * v1 = (fd_accdb_user_v1_t *)accdb;
  fd_accdb_lineage_set_fork( v1->lineage, v1->funk, xid );
  ulong addr_laddr = (ulong)address;
  for( ulong i=0UL; i<cnt; i++ ) {
    void const *    addr_i = (void const *)( (ulong)addr_laddr + i*32UL );
    if( !fd_accdb_peek_funk( v1, &ro[i], xid, addr_i ) ) {
      fd_accdb_ro_init_empty( &ro[i], addr_i );
    } else {
      v1->base.ro_active++;
    }
  }
}

static void
fd_accdb_user_v1_close_ro( fd_accdb_user_t * accdb,
                           fd_accdb_ro_t *   ro ) {
  fd_accdb_user_v1_t * v1 = (fd_accdb_user_v1_t *)accdb;

  v1->base.ro_active--;
  (void)ro;
}

fd_accdb_rw_t *
fd_accdb_user_v1_open_rw( fd_accdb_user_t *         accdb,
                          fd_accdb_rw_t *           rw,
                          fd_funk_txn_xid_t const * xid,
                          void const *              address,
                          ulong                     data_max,
                          int                       flags ) {
  fd_accdb_user_v1_t * v1  = (fd_accdb_user_v1_t *)accdb;

  int const flag_create    = !!( flags & FD_ACCDB_FLAG_CREATE   );
  int const flag_truncate  = !!( flags & FD_ACCDB_FLAG_TRUNCATE );
  if( FD_UNLIKELY( flags & ~(FD_ACCDB_FLAG_CREATE|FD_ACCDB_FLAG_TRUNCATE) ) ) {
    FD_LOG_CRIT(( "invalid flags for open_rw: %#02x", (uint)flags ));
  }

  /* Pivot to different fork */
  fd_accdb_lineage_set_fork( v1->lineage, v1->funk, xid );
  fd_funk_txn_t * txn = fd_accdb_lineage_write_check( v1->lineage, v1->funk );

  /* Query old record value */

  fd_accdb_ro_t ro[1];
  if( FD_UNLIKELY( !fd_accdb_peek_funk( v1, ro, xid, address ) ) ) {
    /* Record not found */
    if( flag_create ) return fd_accdb_funk_create( v1->funk, rw, txn, address, data_max );
    return NULL;
  }

  if( !ro->meta->lamports ) {
    /* Record previously deleted */
    if( !flag_create ) return NULL;
  }

  fd_funk_rec_t * rec = (fd_funk_rec_t *)ro->ref->user_data;
  if( fd_funk_txn_xid_eq( rec->pair.xid, xid ) ) {

    /* Mutable record found, modify in-place */
    ulong  acc_orig_sz = fd_accdb_ref_data_sz( ro );
    ulong  val_sz_min  = sizeof(fd_account_meta_t)+fd_ulong_max( data_max, acc_orig_sz );
    void * val         = fd_funk_val_truncate( rec, v1->funk->alloc, v1->funk->wksp, 16UL, val_sz_min, NULL );
    if( FD_UNLIKELY( !val ) ) {
      FD_LOG_CRIT(( "Failed to modify account: out of memory allocating %lu bytes", acc_orig_sz ));
    }
    fd_accdb_funk_prep_inplace( rw, v1->funk, rec );
    if( flag_truncate ) {
      rec->val_sz = sizeof(fd_account_meta_t);
      rw->meta->dlen = 0;
    }
    return rw;

  } else {

    /* Frozen record found, copy out to new object */
    ulong  acc_orig_sz = fd_accdb_ref_data_sz( ro );
    ulong  val_sz_min  = sizeof(fd_account_meta_t)+fd_ulong_max( data_max, acc_orig_sz );
    ulong  val_sz      = flag_truncate ? sizeof(fd_account_meta_t) : rec->val_sz;
    ulong  val_max     = 0UL;
    void * val         = fd_alloc_malloc_at_least( v1->funk->alloc, 16UL, val_sz_min, &val_max );
    if( FD_UNLIKELY( !val ) ) {
      FD_LOG_CRIT(( "Failed to modify account: out of memory allocating %lu bytes", acc_orig_sz ));
    }

    fd_account_meta_t * meta            = val;
    uchar *             data            = (uchar *)( meta+1 );
    ulong               data_max_actual = val_max - sizeof(fd_account_meta_t);
    if( flag_truncate ) fd_accdb_funk_copy_truncated( meta,       ro->meta );
    else                fd_accdb_funk_copy_account  ( meta, data, ro->meta, fd_account_data( ro->meta ) );
    if( acc_orig_sz<data_max_actual ) {
      /* Zero out trailing data */
      uchar * tail    = data           +acc_orig_sz;
      ulong   tail_sz = data_max_actual-acc_orig_sz;
      fd_memset( tail, 0, tail_sz );
    }

    return fd_accdb_funk_prep_create( rw, v1->funk, txn, address, val, val_sz, val_max );

  }
}

void
fd_accdb_user_v1_open_rw_multi( fd_accdb_user_t *         accdb,
                                fd_accdb_rw_t *           rw,
                                fd_funk_txn_xid_t const * xid,
                                void const *              address,
                                ulong const *             data_max,
                                int                       flags,
                                ulong                     cnt ) {
  ulong addr_laddr = (ulong)address;
  for( ulong i=0UL; i<cnt; i++ ) {
    void const *    addr_i = (void const *)( (ulong)addr_laddr + i*32UL );
    ulong           dmax_i = data_max[i];
    fd_accdb_rw_t * rw_i   = fd_accdb_user_v1_open_rw( accdb, &rw[i], xid, addr_i, dmax_i, flags );
    if( !rw_i ) memset( &rw[i], 0, sizeof(fd_accdb_rw_t) );
    else        accdb->base.rw_active++;
  }
}

void
fd_accdb_user_v1_close_rw( fd_accdb_user_t * accdb,
                           fd_accdb_rw_t *   write ) {
  if( FD_UNLIKELY( !accdb ) ) FD_LOG_CRIT(( "NULL accdb" ));
  fd_accdb_user_v1_t * v1  = (fd_accdb_user_v1_t *)accdb;
  fd_funk_rec_t *      rec = (fd_funk_rec_t *)write->ref->user_data;

  if( FD_UNLIKELY( write->ref->accdb_type!=FD_ACCDB_TYPE_V1 ) ) {
    FD_LOG_CRIT(( "invalid accdb_type %u in fd_accdb_user_v1_close_rw", (uint)write->ref->accdb_type ));
  }

  if( FD_UNLIKELY( !v1->base.rw_active ) ) {
    FD_LOG_CRIT(( "Failed to modify account: ref count underflow" ));
  }

  if( write->ref->user_data2 ) {
    fd_funk_txn_t * txn = (fd_funk_txn_t *)write->ref->user_data2;
    fd_funk_rec_prepare_t prepare = {
      .rec          = rec,
      .rec_head_idx = &txn->rec_head_idx,
      .rec_tail_idx = &txn->rec_tail_idx
    };
    fd_funk_rec_publish( v1->funk, &prepare );
  }

  memset( write, 0, sizeof(fd_accdb_rw_t) );
  v1->base.rw_active--;
}

void
fd_accdb_user_v1_close_ref_multi( fd_accdb_user_t * accdb,
                                  fd_accdb_ref_t *  ref0,
                                  ulong             cnt ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    if( ref0[ i ].accdb_type==FD_ACCDB_TYPE_NONE ) continue;
    switch( ref0[ i ].ref_type ) {
    case FD_ACCDB_REF_RO:
      fd_accdb_user_v1_close_ro( accdb, (fd_accdb_ro_t *)ref0+i );
      break;
    case FD_ACCDB_REF_RW:
      fd_accdb_user_v1_close_rw( accdb, (fd_accdb_rw_t *)ref0+i );
      break;
    default:
      FD_LOG_CRIT(( "invalid ref_type %u in fd_accdb_user_v1_close_ref", (uint)ref0[ i ].ref_type ));
    }
  }
}

ulong
fd_accdb_user_v1_rw_data_max( fd_accdb_user_t *     accdb,
                              fd_accdb_rw_t const * rw ) {
  (void)accdb;
  if( rw->ref->accdb_type==FD_ACCDB_TYPE_NONE ) {
    return rw->ref->user_data; /* data_max */
  }
  fd_funk_rec_t * rec = (fd_funk_rec_t *)rw->ref->user_data;
  return (ulong)( rec->val_max - sizeof(fd_account_meta_t) );
}

void
fd_accdb_user_v1_rw_data_sz_set( fd_accdb_user_t * accdb,
                                 fd_accdb_rw_t *   rw,
                                 ulong             data_sz,
                                 int               flags ) {
  int flag_dontzero = !!( flags & FD_ACCDB_FLAG_DONTZERO );
  if( FD_UNLIKELY( flags & ~(FD_ACCDB_FLAG_DONTZERO) ) ) {
    FD_LOG_CRIT(( "invalid flags for rw_data_sz_set: %#02x", (uint)flags ));
  }

  ulong prev_sz = rw->meta->dlen;
  if( data_sz>prev_sz ) {
    ulong data_max = fd_accdb_user_v1_rw_data_max( accdb, rw );
    if( FD_UNLIKELY( data_sz>data_max ) ) {
      FD_LOG_CRIT(( "attempted to write %lu bytes into a rec with only %lu bytes of data space",
                    data_sz, data_max ));
    }
    if( !flag_dontzero ) {
      void * tail = (uchar *)fd_accdb_ref_data( rw ) + prev_sz;
      fd_memset( tail, 0, data_sz-prev_sz );
    }
  }
  rw->meta->dlen = (uint)data_sz;

  if( rw->ref->accdb_type==FD_ACCDB_TYPE_V1 ) {
    fd_funk_rec_t * rec = (fd_funk_rec_t *)rw->ref->user_data;
    rec->val_sz = (uint)( sizeof(fd_account_meta_t)+data_sz ) & FD_FUNK_REC_VAL_MAX;
  }
}

fd_accdb_user_vt_t const fd_accdb_user_v1_vt = {
  .fini            = fd_accdb_user_v1_fini,
  .batch_max       = fd_accdb_user_v1_batch_max,
  .open_ro_multi   = fd_accdb_user_v1_open_ro_multi,
  .open_rw_multi   = fd_accdb_user_v1_open_rw_multi,
  .close_ref_multi = fd_accdb_user_v1_close_ref_multi,
  .rw_data_max     = fd_accdb_user_v1_rw_data_max,
  .rw_data_sz_set  = fd_accdb_user_v1_rw_data_sz_set
};

fd_accdb_user_t *
fd_accdb_user_v1_init( fd_accdb_user_t * accdb,
                       void *            shfunk ) {
  fd_accdb_user_v1_t * ljoin = (fd_accdb_user_v1_t *)accdb;

  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }
  if( FD_UNLIKELY( !shfunk ) ) {
    FD_LOG_WARNING(( "NULL shfunk" ));
    return NULL;
  }

  memset( ljoin, 0, sizeof(fd_accdb_user_v1_t) );
  if( FD_UNLIKELY( !fd_funk_join( ljoin->funk, shfunk ) ) ) {
    FD_LOG_CRIT(( "fd_funk_join failed" ));
  }

  accdb->base.accdb_type = FD_ACCDB_TYPE_V1;
  accdb->base.vt         = &fd_accdb_user_v1_vt;
  return accdb;
}

fd_funk_t *
fd_accdb_user_v1_funk( fd_accdb_user_t * accdb ) {
  fd_accdb_user_v1_t * v1 = (fd_accdb_user_v1_t *)accdb;
  uint accdb_type = accdb->base.accdb_type;
  if( FD_UNLIKELY( accdb_type!=FD_ACCDB_TYPE_V1 && accdb_type!=FD_ACCDB_TYPE_V2 ) ) {
    FD_LOG_CRIT(( "fd_accdb_user_v1_funk called on non-v1 accdb_user (type %u)", accdb->base.accdb_type ));
  }
  return v1->funk;
}
