#include "fd_accdb_impl_v2.h"
#include "fd_accdb_impl_v1.h"
#include "fd_vinyl_req_pool.h"

FD_STATIC_ASSERT( alignof(fd_accdb_user_v2_t)<=alignof(fd_accdb_user_t), layout );
FD_STATIC_ASSERT( sizeof (fd_accdb_user_v2_t)<=sizeof(fd_accdb_user_t),  layout );

void
fd_accdb_user_v2_fini( fd_accdb_user_t * accdb ) {
  fd_accdb_user_v2_t * user = (fd_accdb_user_v2_t *)accdb;

  fd_vinyl_rq_leave( user->vinyl_rq );

  /* superclass destructor */
  user->base.accdb_type = FD_ACCDB_TYPE_V1;
  fd_accdb_user_v1_fini( accdb );
}

ulong
fd_accdb_user_v2_batch_max( fd_accdb_user_t * accdb ) {
  fd_accdb_user_v2_t * user = (fd_accdb_user_v2_t *)accdb;
  return fd_vinyl_req_batch_key_max( user->vinyl_req_pool );
}

fd_accdb_peek_t *
fd_accdb_user_v2_peek( fd_accdb_user_t *         accdb,
                       fd_accdb_peek_t *         peek,
                       fd_funk_txn_xid_t const * xid,
                       void const *              address ) {
  /* FIXME this should query vinyl cache too (via vinyl_meta/vinyl_data) */
  return fd_accdb_user_v1_peek( accdb, peek, xid, address );
}

void
fd_accdb_user_v2_close_ref_multi( fd_accdb_user_t * accdb,
                                  fd_accdb_ref_t *  ref0,
                                  ulong             cnt );

void
fd_accdb_user_v2_open_ro_multi( fd_accdb_user_t *         accdb,
                                fd_accdb_ro_t *           ro0,
                                fd_funk_txn_xid_t const * xid0,
                                void const *              addr0,
                                ulong                     cnt ) {
  fd_accdb_user_v2_t *  v2        = (fd_accdb_user_v2_t *)accdb;
  fd_vinyl_rq_t *       rq        = v2->vinyl_rq;        /* "request queue "*/
  fd_vinyl_req_pool_t * req_pool  = v2->vinyl_req_pool;  /* "request pool" */
  fd_wksp_t *           req_wksp  = v2->vinyl_req_wksp;  /* shm workspace containing request buffer */
  fd_wksp_t *           data_wksp = v2->vinyl_data_wksp; /* shm workspace containing vinyl data cache */
  ulong                 link_id   = v2->vinyl_link_id;   /* vinyl client ID */

  if( FD_UNLIKELY( cnt>fd_vinyl_req_batch_key_max( req_pool ) ) ) {
    FD_LOG_CRIT(( "open_ro_multi cnt %lu exceeds vinyl request batch max %lu",
                  cnt, fd_vinyl_req_batch_key_max( req_pool ) ));
  }

  /* Open accounts from funk

     (FIXME this is a potentially slow operation, might want to fire off
     a 'prefetch' instruction to vinyl asynchronously before doing this,
     so that the vinyl data is in cache by the time v1_open_rw_multi
     finishes) */

  fd_accdb_user_v1_open_ro_multi( accdb, ro0, xid0, addr0, cnt );

  /* For the accounts that were not found in funk, open vinyl records */

  ulong batch_idx = fd_vinyl_req_pool_acquire( req_pool );
  /* req_pool_release called before returning */
  fd_vinyl_comp_t * comp           = fd_vinyl_req_batch_comp     ( req_pool, batch_idx );
  fd_vinyl_key_t *  req_key0       = fd_vinyl_req_batch_key      ( req_pool, batch_idx );
  schar *           req_err0       = fd_vinyl_req_batch_err      ( req_pool, batch_idx );
  ulong *           req_val_gaddr0 = fd_vinyl_req_batch_val_gaddr( req_pool, batch_idx );

  /* Create a read-only vinyl "ACQUIRE" batch */

  ulong req_cnt = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    if( ro0[i].ref->accdb_type!=FD_ACCDB_TYPE_NONE ) continue;
    /* At this point, addr0[i] not found in funk, load from vinyl */
    void const * addr_i = (void const *)( (ulong)addr0 + i*32UL );

    fd_vinyl_key_init( req_key0+req_cnt, addr_i, 32UL );
    req_err0      [ req_cnt ] = 0;
    req_val_gaddr0[ req_cnt ] = 0UL;
    req_cnt++;
  }
  if( !req_cnt ) {
    /* All records were found in funk, bail early */
    fd_vinyl_req_pool_release( req_pool, batch_idx );
    return;
  }

  /* Send read-only "ACQUIRE" batch to vinyl and wait for response */

  ulong req_id = v2->vinyl_req_id++;
  memset( comp, 0, sizeof(fd_vinyl_comp_t) );
  fd_vinyl_req_send_batch( rq, req_pool, req_wksp, req_id, link_id, FD_VINYL_REQ_TYPE_ACQUIRE, 0UL, batch_idx, req_cnt, 0UL );

  while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
  FD_COMPILER_MFENCE();
  int comp_err = FD_VOLATILE_CONST( comp->err );
  if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
    FD_LOG_CRIT(( "vinyl tile rejected my ACQUIRE request: %i-%s", comp_err, fd_vinyl_strerror( comp_err ) ));
  }

  /* For the accounts that were newly found in vinyl, create accdb
     handles */

  req_cnt = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    if( ro0[i].ref->accdb_type!=FD_ACCDB_TYPE_NONE ) continue;
    void const * addr_i = (void const *)( (ulong)addr0 + i*32UL );

    int   req_err   = FD_VOLATILE_CONST( req_err0      [ req_cnt ] );
    ulong val_gaddr = FD_VOLATILE_CONST( req_val_gaddr0[ req_cnt ] );

    fd_accdb_ro_t * ro = &ro0[ i ];
    if( req_err==0 ) {
      /* Record found in vinyl, create reference */
      fd_account_meta_t const * meta = fd_wksp_laddr_fast( data_wksp, val_gaddr );

      accdb->base.ro_active++;
      *ro = (fd_accdb_ro_t) {0};
      memcpy( ro->ref->address, addr_i, 32UL );
      ro->ref->accdb_type = FD_ACCDB_TYPE_V2;
      ro->ref->ref_type   = FD_ACCDB_REF_RO;
      ro->meta            = meta;
    } else if( FD_UNLIKELY( req_err!=FD_VINYL_ERR_KEY ) ) {
      FD_LOG_CRIT(( "vinyl tile ACQUIRE request failed: %i-%s", req_err, fd_vinyl_strerror( req_err ) ));
    }
    req_cnt++;
  }

  fd_vinyl_req_pool_release( req_pool, batch_idx );

  /* At this point, ownership of vinyl records transitions to caller.
     (Released using close_ro_multi) */
}

void
fd_accdb_user_v2_open_rw_multi( fd_accdb_user_t *         accdb,
                                fd_accdb_rw_t *           rw0,
                                fd_funk_txn_xid_t const * xid,
                                void const *              addr0,
                                ulong const *             data_max0,
                                int                       flags,
                                ulong                     cnt ) {
  fd_accdb_user_v2_t *  v2        = (fd_accdb_user_v2_t *)accdb;
  fd_accdb_user_v1_t *  v1        = &v2->v1;
  fd_vinyl_rq_t *       rq        = v2->vinyl_rq;        /* "request queue "*/
  fd_vinyl_req_pool_t * req_pool  = v2->vinyl_req_pool;  /* "request pool" */
  fd_wksp_t *           req_wksp  = v2->vinyl_req_wksp;  /* shm workspace containing request buffer */
  fd_wksp_t *           data_wksp = v2->vinyl_data_wksp; /* shm workspace containing vinyl data cache */
  ulong                 link_id   = v2->vinyl_link_id;   /* vinyl client ID */

  int const flag_truncate = !!( flags & FD_ACCDB_FLAG_TRUNCATE );
  int const flag_create   = !!( flags & FD_ACCDB_FLAG_CREATE   );
  if( FD_UNLIKELY( flags & ~(FD_ACCDB_FLAG_CREATE|FD_ACCDB_FLAG_TRUNCATE) ) ) {
    FD_LOG_CRIT(( "invalid flags for open_rw: %#02x", (uint)flags ));
  }

  if( FD_UNLIKELY( cnt>fd_vinyl_req_batch_key_max( req_pool ) ) ) {
    FD_LOG_CRIT(( "open_rw_multi cnt %lu exceeds vinyl request batch max %lu",
                  cnt, fd_vinyl_req_batch_key_max( req_pool ) ));
  }

  /* Upgrade existing funk records into writable records

     (FIXME this is a potentially slow operation, might want to fire off
     a 'prefetch' instruction to vinyl asynchronously before doing this,
     so that the vinyl data is in cache by the time v1_open_rw_multi
     finishes) */

  int peek_flags = (flags & ~FD_ACCDB_FLAG_CREATE) | FD_ACCDB_FLAG_V1_TOMBSTONE;
  fd_accdb_user_v1_open_rw_multi( accdb, rw0, xid, addr0, data_max0, peek_flags, cnt );

  /* For the accounts that were not found in funk, create writable funk
     records from elements in vinyl. */

  ulong batch_idx = fd_vinyl_req_pool_acquire( req_pool );
  /* req_pool_release called before returning */
  fd_vinyl_comp_t * comp           = fd_vinyl_req_batch_comp     ( req_pool, batch_idx );
  fd_vinyl_key_t *  req_key0       = fd_vinyl_req_batch_key      ( req_pool, batch_idx );
  schar *           req_err0       = fd_vinyl_req_batch_err      ( req_pool, batch_idx );
  ulong *           req_val_gaddr0 = fd_vinyl_req_batch_val_gaddr( req_pool, batch_idx );

  /* Create a read-only vinyl "ACQUIRE" batch */

  ulong req_cnt = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    if( rw0[i].ref->ref_type!=FD_ACCDB_REF_INVAL ) continue;
    /* At this point, addr0[i] not found in funk, load from vinyl */
    void const * addr_i = (void const *)( (ulong)addr0 + i*32UL );

    fd_vinyl_key_init( req_key0+req_cnt, addr_i, 32UL );
    req_err0      [ req_cnt ] = 0;
    req_val_gaddr0[ req_cnt ] = 0UL;
    req_cnt++;
  }

  /* Send read-only "ACQUIRE" batch to vinyl and wait for response */

  if( req_cnt ) {
    ulong req_id = v2->vinyl_req_id++;
    memset( fd_vinyl_req_batch_comp( req_pool, batch_idx ), 0, sizeof(fd_vinyl_comp_t) );
    fd_vinyl_req_send_batch( rq, req_pool, req_wksp, req_id, link_id, FD_VINYL_REQ_TYPE_ACQUIRE, 0UL, batch_idx, req_cnt, 0UL );

    while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
    FD_COMPILER_MFENCE();
    int comp_err = FD_VOLATILE_CONST( comp->err );
    if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
      FD_LOG_CRIT(( "vinyl tile rejected my ACQUIRE request: %i-%s", comp_err, fd_vinyl_strerror( comp_err ) ));
    }
  }

  /* For the accounts that were newly found in vinyl, copy the records
     to funk */

  req_cnt = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    void const *    addr_i = (void const *)( (ulong)addr0 + i*32UL );
    fd_accdb_rw_t * rw     = &rw0[ i ];

    if( rw->ref->ref_type!=FD_ACCDB_REF_INVAL ) {
      /* Account record found in funk */
      if( rw->ref->accdb_type==FD_ACCDB_TYPE_NONE ) {
        /* Account is a tombstone */
        if( flag_create ) {
          fd_accdb_user_v1_open_rw( accdb, rw, xid, addr_i, data_max0[ i ], flags );
        } else {
          memset( &rw0[ i ], 0, sizeof(fd_accdb_rw_t) );
        }
      }
      continue;
    }

    /* Record not found in funk */

    int req_err = req_err0[ req_cnt ];
    if( req_err ) {
      /* Record not found in vinyl either (truly does not exist)
         If CREATE flag was requested, create it in funk */
      if( FD_UNLIKELY( req_err!=FD_VINYL_ERR_KEY ) ) {
        FD_LOG_CRIT(( "vinyl tile ACQUIRE request failed: %i-%s", req_err, fd_vinyl_strerror( req_err ) ));
      }
not_found:
      if( flag_create ) {
        fd_accdb_user_v1_open_rw_multi( accdb, rw, xid, addr_i, &data_max0[i], flags, 1UL );
      }
      req_cnt++;
      continue;
    }

    /* Record found in vinyl */

    ulong               req_val_gaddr = req_val_gaddr0[ req_cnt ];
    fd_account_meta_t * src_meta      = fd_wksp_laddr_fast( data_wksp, req_val_gaddr );
    uchar const *       src_data      = (uchar *)( src_meta+1 );

    if( FD_UNLIKELY( src_meta->lamports==0UL ) ) goto not_found; /* tombstone */

    ulong  acc_orig_sz = src_meta->dlen;
    ulong  val_sz_min  = sizeof(fd_account_meta_t)+fd_ulong_max( data_max0[ i ], acc_orig_sz );
    ulong  acc_sz      = flag_truncate ? 0UL : acc_orig_sz;
    ulong  val_sz      = sizeof(fd_account_meta_t)+acc_sz;
    ulong  val_max     = 0UL;
    void * val         = fd_alloc_malloc_at_least( v1->funk->alloc, 16UL, val_sz_min, &val_max );
    if( FD_UNLIKELY( !val ) ) {
      FD_LOG_CRIT(( "Failed to modify account: out of memory allocating %lu bytes", acc_orig_sz ));
    }

    fd_account_meta_t * dst_meta        = val;
    uchar *             dst_data        = (uchar *)( dst_meta+1 );
    ulong               data_max_actual = val_max - sizeof(fd_account_meta_t);
    if( flag_truncate ) fd_accdb_v1_copy_truncated( dst_meta,           src_meta           );
    else                fd_accdb_v1_copy_account  ( dst_meta, dst_data, src_meta, src_data );
    if( acc_orig_sz<data_max_actual ) {
      /* Zero out trailing data */
      uchar * tail    = dst_data       +acc_orig_sz;
      ulong   tail_sz = data_max_actual-acc_orig_sz;
      fd_memset( tail, 0, tail_sz );
    }

    ulong txn_idx = v1->tip_txn_idx;
    fd_funk_txn_t * txn = &v1->funk->txn_pool->ele[ txn_idx ];
    fd_accdb_v1_prep_create( rw, v1, txn, addr_i, val, val_sz, val_max );

    req_cnt++;
  }

  /* Send "RELEASE" batch (reuse val_gaddr values),
     and wait for response */

  if( req_cnt ) {
    ulong req_id = v2->vinyl_req_id++;
    memset( fd_vinyl_req_batch_comp( req_pool, batch_idx ), 0, sizeof(fd_vinyl_comp_t) );
    fd_vinyl_req_send_batch( rq, req_pool, req_wksp, req_id, link_id, FD_VINYL_REQ_TYPE_RELEASE, 0UL, batch_idx, req_cnt, 0UL );

    while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
    FD_COMPILER_MFENCE();
    int comp_err = FD_VOLATILE_CONST( comp->err );
    if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
      FD_LOG_CRIT(( "vinyl tile rejected my RELEASE request: %i-%s", comp_err, fd_vinyl_strerror( comp_err ) ));
    }
  }

  fd_vinyl_req_pool_release( req_pool, batch_idx );
}

void
fd_accdb_user_v2_close_ref_multi( fd_accdb_user_t * accdb,
                                  fd_accdb_ref_t *  ref0,
                                  ulong             cnt ) {
  fd_accdb_user_v2_t *  v2        = (fd_accdb_user_v2_t *)accdb;
  fd_vinyl_rq_t *       rq        = v2->vinyl_rq;        /* "request queue "*/
  fd_vinyl_req_pool_t * req_pool  = v2->vinyl_req_pool;  /* "request pool" */
  fd_wksp_t *           req_wksp  = v2->vinyl_req_wksp;  /* shm workspace containing request buffer */
  fd_wksp_t *           data_wksp = v2->vinyl_data_wksp; /* shm workspace containing vinyl data cache */
  ulong                 link_id   = v2->vinyl_link_id;   /* vinyl client ID */

  if( FD_UNLIKELY( cnt>fd_vinyl_req_batch_key_max( req_pool ) ) ) {
    FD_LOG_CRIT(( "close_ref_multi cnt %lu exceeds vinyl request batch max %lu",
                  cnt, fd_vinyl_req_batch_key_max( req_pool ) ));
  }

  /* First, release all references to vinyl records
     (This is a prefetch friendly / fast loop) */

  ulong batch_idx = fd_vinyl_req_pool_acquire( req_pool );
  /* req_pool_release called before returning */
  fd_vinyl_comp_t * comp           = fd_vinyl_req_batch_comp     ( req_pool, batch_idx );
  schar *           req_err0       = fd_vinyl_req_batch_err      ( req_pool, batch_idx );
  ulong *           req_val_gaddr0 = fd_vinyl_req_batch_val_gaddr( req_pool, batch_idx );

  ulong ro_close_cnt = 0UL;
  ulong rw_close_cnt = 0UL;
  ulong req_cnt      = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    if( ref0[i].accdb_type!=FD_ACCDB_TYPE_V2 ) continue;
    ref0[i].ref_type==FD_ACCDB_REF_RO ? ro_close_cnt++ : rw_close_cnt++;
    req_err0      [ req_cnt ] = 0;
    req_val_gaddr0[ req_cnt ] = fd_wksp_gaddr_fast( data_wksp, (void *)ref0[i].meta_laddr );
    memset( &ref0[i], 0, sizeof(fd_accdb_ref_t) ); /* invalidate ref */
    req_cnt++;
  }
  if( req_cnt ) {
    if( FD_UNLIKELY( ro_close_cnt > accdb->base.ro_active ) ) {
      FD_LOG_CRIT(( "attempted to close more accdb_ro (%lu) than are open (%lu)",
                    ro_close_cnt, accdb->base.ro_active ));
    }
    if( FD_UNLIKELY( rw_close_cnt > accdb->base.rw_active ) ) {
      FD_LOG_CRIT(( "attempted to close more accdb_rw (%lu) than are open (%lu)",
                    rw_close_cnt, accdb->base.rw_active ));
    }
    ulong req_id = v2->vinyl_req_id++;
    memset( fd_vinyl_req_batch_comp( req_pool, batch_idx ), 0, sizeof(fd_vinyl_comp_t) );
    fd_vinyl_req_send_batch( rq, req_pool, req_wksp, req_id, link_id, FD_VINYL_REQ_TYPE_RELEASE, 0UL, batch_idx, req_cnt, 0UL );
  }

  /* While our vinyl request is inflight, release funk records
     (This does expensive DRAM accesses, which are convenient to do when
     we are waiting for the database to asynchronously respond) */

  fd_accdb_user_v1_close_ref_multi( accdb, ref0, cnt );

  /* Wait for response from vinyl */

  if( req_cnt ) {
    while( FD_VOLATILE_CONST( comp->seq )!=1UL ) FD_SPIN_PAUSE();
    FD_COMPILER_MFENCE();
    int comp_err = FD_VOLATILE_CONST( comp->err );
    if( FD_UNLIKELY( comp_err!=FD_VINYL_SUCCESS ) ) {
      FD_LOG_CRIT(( "vinyl tile rejected my RELEASE request: %i-%s", comp_err, fd_vinyl_strerror( comp_err ) ));
    }
    for( ulong i=0UL; i<req_cnt; i++ ) {
      int req_err = req_err0[ i ];
      if( FD_UNLIKELY( req_err!=FD_VINYL_SUCCESS ) ) {
        FD_LOG_CRIT(( "vinyl tile RELEASE request failed: %i-%s", req_err, fd_vinyl_strerror( req_err ) ));
      }
    }

    accdb->base.ro_active -= ro_close_cnt;
    accdb->base.rw_active -= rw_close_cnt;
  }

  fd_vinyl_req_pool_release( req_pool, batch_idx );
}

fd_accdb_user_vt_t const fd_accdb_user_v2_vt = {
  .fini            = fd_accdb_user_v2_fini,
  .batch_max       = fd_accdb_user_v2_batch_max,
  .peek            = fd_accdb_user_v2_peek,
  .open_ro_multi   = fd_accdb_user_v2_open_ro_multi,
  .open_rw_multi   = fd_accdb_user_v2_open_rw_multi,
  .close_ref_multi = fd_accdb_user_v2_close_ref_multi,
  .rw_data_max     = fd_accdb_user_v1_rw_data_max,
  .rw_data_sz_set  = fd_accdb_user_v1_rw_data_sz_set
};

fd_accdb_user_t *
fd_accdb_user_v2_init( fd_accdb_user_t * accdb_,
                       void *            funk,
                       void *            vinyl_rq,
                       void *            vinyl_data,
                       void *            vinyl_req_pool,
                       ulong             vinyl_link_id ) {
  /* Call superclass constructor */
  if( FD_UNLIKELY( !fd_accdb_user_v1_init( accdb_, funk ) ) ) {
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

  fd_accdb_user_v2_t * accdb = fd_type_pun( accdb_ );
  accdb->vinyl_req_id    = fd_vinyl_rq_seq( vinyl_rq );
  accdb->vinyl_rq        = rq;
  accdb->vinyl_link_id   = vinyl_link_id;
  accdb->vinyl_data_wksp = vinyl_data;
  accdb->vinyl_req_wksp  = fd_wksp_containing( req_pool );
  accdb->vinyl_req_pool  = req_pool;
  accdb->base.accdb_type = FD_ACCDB_TYPE_V2;
  accdb->base.vt         = &fd_accdb_user_v2_vt;
  return accdb_;
}
