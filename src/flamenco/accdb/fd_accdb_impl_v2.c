#include "fd_accdb_impl_v2.h"
#include "fd_accdb_funk.h"
#include "fd_vinyl_req_pool.h"

FD_STATIC_ASSERT( alignof(fd_accdb_user_v2_t)<=alignof(fd_accdb_user_t), layout );
FD_STATIC_ASSERT( sizeof (fd_accdb_user_v2_t)<=sizeof(fd_accdb_user_t),  layout );

/* Record synchronization *********************************************/

/* fd_funk_rec_write_{lock,unlock} acquire/release a record write lock.

   These are assumed to never fail because writes to accdb records are
   externally coordinated to be non-conflicting at the record level.
   In other words, it is assumed that, when the caller attempts to
   write to a record:
   - no admin attempts to root or cancel the DB txn this write targets
     (admin may only root/cancel txns after they are frozen, and users
     may only write to txns before they are frozen)
   - no other user attempts to read/write to the same record until the
     current thread is done writing.  (Other threads wait for the
     current thread to signal completion before attempting to access) */

static void
fd_funk_rec_write_lock( fd_funk_rec_t * rec ) {
  ulong volatile * vl = &rec->ver_lock;
  ulong val = FD_VOLATILE_CONST( *vl );
  if( FD_UNLIKELY( fd_funk_rec_lock_bits( val ) ) ) {
    FD_LOG_CRIT(( "fd_funk_rec_write_lock(" FD_FUNK_REC_PAIR_FMT ") failed: record has active readers",
                  FD_FUNK_REC_PAIR_FMT_ARGS( rec->pair ) ));
  }
  ulong val_new = fd_funk_rec_ver_lock( fd_funk_rec_ver_bits( val ), FD_FUNK_REC_LOCK_MASK );
  if( FD_UNLIKELY( FD_ATOMIC_CAS( vl, val, val_new )!=val ) ) {
    FD_LOG_CRIT(( "fd_funk_rec_write_lock(" FD_FUNK_REC_PAIR_FMT ") failed: data race detected",
                  FD_FUNK_REC_PAIR_FMT_ARGS( rec->pair ) ));
  }
}

static void
fd_funk_rec_write_lock_uncontended( fd_funk_rec_t * rec ) {
  ulong val     = rec->ver_lock;
  ulong val_ver = fd_funk_rec_ver_bits( val );
  rec->ver_lock = fd_funk_rec_ver_lock( val_ver, FD_FUNK_REC_LOCK_MASK );
}

static void
fd_funk_rec_write_unlock( fd_funk_rec_t * rec ) {
  ulong volatile * vl = &rec->ver_lock;
  ulong val = FD_VOLATILE_CONST( *vl );
  if( FD_UNLIKELY( fd_funk_rec_lock_bits( val )!=FD_FUNK_REC_LOCK_MASK ) ) {
    FD_LOG_CRIT(( "fd_funk_rec_write_unlock(" FD_FUNK_REC_PAIR_FMT ") failed: record is not write locked",
                  FD_FUNK_REC_PAIR_FMT_ARGS( rec->pair ) ));
  }
  ulong val_new = fd_funk_rec_ver_lock( fd_funk_rec_ver_bits( val ), 0UL );
  if( FD_UNLIKELY( FD_ATOMIC_CAS( vl, val, val_new )!=val ) ) {
    FD_LOG_CRIT(( "fd_funk_rec_write_unlock(" FD_FUNK_REC_PAIR_FMT ") failed: data race detected",
                  FD_FUNK_REC_PAIR_FMT_ARGS( rec->pair ) ));
  }
}

/* fd_funk_rec_read_{lock_try,unlock} try-acquire/release a record read
   lock.

   Read lock acquires may fail for frozen txn.  This is because an admin
   may concurrently root the txn as we are querying. */

static int
fd_funk_rec_read_lock( fd_funk_rec_t * rec ) {
  ulong volatile * vl = &rec->ver_lock;
  for(;;) {
    ulong val      = FD_VOLATILE_CONST( *vl );
    ulong val_ver  = fd_funk_rec_ver_bits ( val );
    ulong val_lock = fd_funk_rec_lock_bits( val );
    if( FD_UNLIKELY( !fd_funk_rec_ver_alive( val_ver ) ) ) {
      return FD_MAP_ERR_AGAIN;
    }
    if( FD_UNLIKELY( val_lock>=FD_FUNK_REC_LOCK_MASK-1 ) ) {
      FD_LOG_CRIT(( "fd_funk_rec_read_lock(" FD_FUNK_REC_PAIR_FMT ") failed: val_lock=%#lx (too many readers or already write locked)",
                    FD_FUNK_REC_PAIR_FMT_ARGS( rec->pair ), val_lock ));
    }
    ulong val_new = fd_funk_rec_ver_lock( val_ver, val_lock+1UL );
    if( FD_LIKELY( FD_ATOMIC_CAS( vl, val, val_new )==val ) ) {
      return FD_MAP_SUCCESS;
    }
  }
}

static void
fd_funk_rec_read_unlock( fd_funk_rec_t * rec ) {
  ulong volatile * vl = &rec->ver_lock;
  for(;;) {
    ulong val      = FD_VOLATILE_CONST( *vl );
    ulong val_ver  = fd_funk_rec_ver_bits ( val );
    ulong val_lock = fd_funk_rec_lock_bits( val );
    if( FD_UNLIKELY( val_lock==0UL || val_lock==FD_FUNK_REC_LOCK_MASK ) ) {
      FD_LOG_CRIT(( "fd_funk_rec_read_unlock(" FD_FUNK_REC_PAIR_FMT ") failed: val_lock=%#lx (cannot unlock)",
                    FD_FUNK_REC_PAIR_FMT_ARGS( rec->pair ), val_lock ));
    }
    ulong val_new = fd_funk_rec_ver_lock( val_ver, val_lock-1UL );
    if( FD_LIKELY( FD_ATOMIC_CAS( vl, val, val_new )==val ) ) {
      return;
    }
  }
}

/* Record acquisition *************************************************/

/* funk_rec_acquire finds the newest revision of 'key' in the funk hash
   chain at index chain_idx.  Only considers records on the current fork
   (fork nodes stored in accdb).

   On success, returns ACQUIRE_{READ,WRITE} and points *out_rec to the
   record found.  If is_write, a write-lock is acquired for this record,
   otherwise a read lock.  It is the caller's responsibility to release
   this lock.

   If no record was found, returns ACQUIRE_NOT_FOUND.

   Returns ACQUIRE_FAILED on index contention (hash map locks) or
   record contention (admin started deleting the record just as we were
   about to start the access).  The caller should retry in this case. */

#define ACQUIRE_READ      0
#define ACQUIRE_WRITE     1
#define ACQUIRE_NOT_FOUND 2
#define ACQUIRE_FAILED    3

static int
funk_rec_acquire( fd_accdb_user_v2_t const * accdb,
                  ulong                      chain_idx,
                  fd_funk_rec_key_t const *  key,
                  fd_funk_rec_t **           out_rec,
                  _Bool                      is_write ) {
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
    return ACQUIRE_FAILED; /* chain is locked */
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

    /* Confirm that record is part of the current fork
       FIXME this has bad performance / pointer-chasing */
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

  /* Found a record, acquire a lock */
  if( best ) {
    /* If the write does not target the current transaction, demote it */
    if( is_write && !fd_accdb_lineage_is_tip( accdb->lineage, best->pair.xid ) ) {
      is_write = 0;
    }
    if( is_write ) {
      fd_funk_rec_write_lock( best );
    } else {
      if( fd_funk_rec_read_lock( best )!=FD_MAP_SUCCESS ) {
        return ACQUIRE_FAILED; /* record about to be moved to vinyl */
      }
    }
  }

  /* Retry if there was contention at the hash map */
  if( FD_UNLIKELY( FD_VOLATILE_CONST( chain->ver_cnt )!=ver_cnt ) ) {
    if( best ) {
      if( is_write ) fd_funk_rec_write_unlock( best );
      else           fd_funk_rec_read_unlock ( best );
    }
    return ACQUIRE_FAILED;
  }

  *out_rec = best;
  return best ? ( is_write ? ACQUIRE_WRITE : ACQUIRE_READ ) : ACQUIRE_NOT_FOUND;
}

static int
funk_open_ref( fd_accdb_user_v2_t *      accdb,
               fd_accdb_ref_t *          ref,
               fd_funk_txn_xid_t const * xid,
               void const *              address,
               _Bool                     is_write ) {
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
  int err;
  for(;;) {
    err = funk_rec_acquire( accdb, chain_idx, key, &rec, is_write );
    if( FD_LIKELY( err!=ACQUIRE_FAILED ) ) break;
    FD_SPIN_PAUSE();
    /* FIXME backoff */
  }
  if( rec ) {
    memcpy( ref->address, address, 32UL );
    ref->accdb_type = FD_ACCDB_TYPE_V1;
    ref->ref_type   = err==ACQUIRE_WRITE ? FD_ACCDB_REF_RW : FD_ACCDB_REF_RO;
    ref->user_data  = (ulong)rec;
    ref->user_data2 = 0UL;
    ref->meta_laddr = (ulong)fd_funk_val( rec, funk->wksp );
  } else {
    memset( ref, 0, sizeof(fd_accdb_rw_t) );
  }
  return err;
}

/* Read method ********************************************************/

void
fd_accdb_user_v2_open_ro_multi( fd_accdb_user_t *         accdb,
                                fd_accdb_ro_t *           ro0,
                                fd_funk_txn_xid_t const * xid,
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

  fd_accdb_lineage_set_fork( v2->lineage, v2->funk, xid );
  ulong addr_laddr = (ulong)addr0;
  for( ulong i=0UL; i<cnt; i++ ) {
    void const * addr_i = (void const *)( (ulong)addr_laddr + i*32UL );
    if( funk_open_ref( v2, ro0[i].ref, xid, addr_i, 0 )==ACQUIRE_READ ) {
      v2->base.ro_active++;
    } else {
      fd_accdb_ro_init_empty( &ro0[i], addr_i );
    }
  }

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

/* Write method *******************************************************/

void
fd_accdb_user_v2_open_rw_multi( fd_accdb_user_t *         accdb,
                                fd_accdb_rw_t *           rw0,
                                fd_funk_txn_xid_t const * xid,
                                void const *              addr0,
                                ulong const *             data_max0,
                                int                       flags,
                                ulong                     cnt ) {
  fd_accdb_user_v2_t *  v2        = (fd_accdb_user_v2_t *)accdb;
  fd_funk_t *           funk      = v2->funk;
  fd_vinyl_rq_t *       rq        = v2->vinyl_rq;        /* "request queue "*/
  fd_vinyl_req_pool_t * req_pool  = v2->vinyl_req_pool;  /* "request pool" */
  fd_wksp_t *           req_wksp  = v2->vinyl_req_wksp;  /* shm workspace containing request buffer */
  fd_wksp_t *           data_wksp = v2->vinyl_data_wksp; /* shm workspace containing vinyl data cache */
  ulong                 link_id   = v2->vinyl_link_id;   /* vinyl client ID */

  fd_accdb_lineage_set_fork( v2->lineage, v2->funk, xid );
  fd_funk_txn_t * txn = fd_accdb_lineage_write_check( v2->lineage, v2->funk );

  int const flag_truncate = !!( flags & FD_ACCDB_FLAG_TRUNCATE );
  int const flag_create   = !!( flags & FD_ACCDB_FLAG_CREATE   );
  if( FD_UNLIKELY( flags & ~(FD_ACCDB_FLAG_CREATE|FD_ACCDB_FLAG_TRUNCATE) ) ) {
    FD_LOG_CRIT(( "invalid flags for open_rw: %#02x", (uint)flags ));
  }

  if( FD_UNLIKELY( cnt>fd_vinyl_req_batch_key_max( req_pool ) ) ) {
    FD_LOG_CRIT(( "open_rw_multi cnt %lu exceeds vinyl request batch max %lu",
                  cnt, fd_vinyl_req_batch_key_max( req_pool ) ));
  }

  /* Query for existing funk records

     (FIXME this is a potentially slow operation, might want to fire off
     a 'prefetch' instruction to vinyl asynchronously before doing this,
     so that the vinyl data is in cache by the time v1_open_rw_multi
     finishes) */

  ulong addr_laddr = (ulong)addr0;
  for( ulong i=0UL; i<cnt; i++ ) {
    void const * addr_i = (void const *)( (ulong)addr_laddr + i*32UL );
    funk_open_ref( v2, rw0[ i ].ref, xid, addr_i, 1 );
  }

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

  /* Promote any found accounts to writable accounts */

  req_cnt = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    void const *    addr_i   = (void const *)( (ulong)addr0 + i*32UL );
    fd_accdb_rw_t * rw       = &rw0[ i ];
    fd_funk_rec_t * rec      = (fd_funk_rec_t *)rw->ref->user_data;
    ulong           data_max = data_max0[ i ];

    if( rw->ref->ref_type==FD_ACCDB_REF_RW ) {
      /* Mutable record found, modify in-place */

      if( FD_UNLIKELY( !flag_create && fd_accdb_ref_lamports( rw->ro )==0UL ) ) {
        /* Tombstone */
        fd_funk_rec_write_unlock( rec );
        goto not_found;
      }

      ulong  acc_orig_sz = fd_accdb_ref_data_sz( rw->ro );
      ulong  val_sz_min  = sizeof(fd_account_meta_t)+fd_ulong_max( data_max, acc_orig_sz );
      void * val         = fd_funk_val_truncate( rec, funk->alloc, funk->wksp, 16UL, val_sz_min, NULL );
      if( FD_UNLIKELY( !val ) ) {
        FD_LOG_CRIT(( "Failed to modify account: out of memory allocating %lu bytes", acc_orig_sz ));
      }
      fd_accdb_funk_prep_inplace( rw, funk, rec );
      if( flag_truncate ) {
        rec->val_sz = sizeof(fd_account_meta_t);
        rw->meta->dlen = 0;
      }
      accdb->base.rw_active++;
      /* Retain write lock */

      continue; /* next account */
    }

    if( rw->ref->ref_type==FD_ACCDB_REF_RO ) {
      /* Frozen record found, copy out to new object */

      fd_accdb_ro_t * ro = rw->ro;
      if( FD_UNLIKELY( !flag_create && fd_accdb_ref_lamports( ro )==0UL ) ) {
        /* Tombstone */
        fd_funk_rec_read_unlock( rec );
        goto not_found;
      }

      ulong  acc_orig_sz = fd_accdb_ref_data_sz( ro );
      ulong  val_sz_min  = sizeof(fd_account_meta_t)+fd_ulong_max( data_max, acc_orig_sz );
      ulong  val_sz      = flag_truncate ? sizeof(fd_account_meta_t) : rec->val_sz;
      ulong  val_max     = 0UL;
      void * val         = fd_alloc_malloc_at_least( funk->alloc, 16UL, val_sz_min, &val_max );
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

      fd_accdb_funk_prep_create( rw, funk, txn, addr_i, val, val_sz, val_max );
      accdb->base.rw_active++;

      FD_COMPILER_MFENCE();
      fd_funk_rec_read_unlock( rec );

      continue; /* next account */
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
        fd_accdb_funk_create( v2->funk, rw, txn, addr_i, data_max0[ i ] );
        fd_funk_rec_write_lock_uncontended( (fd_funk_rec_t *)rw->ref->user_data );
        accdb->base.rw_active++;
      } else {
        memset( rw, 0, sizeof(fd_accdb_ref_t) );
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
    void * val         = fd_alloc_malloc_at_least( v2->funk->alloc, 16UL, val_sz_min, &val_max );
    if( FD_UNLIKELY( !val ) ) {
      FD_LOG_CRIT(( "Failed to modify account: out of memory allocating %lu bytes", acc_orig_sz ));
    }

    fd_account_meta_t * dst_meta        = val;
    uchar *             dst_data        = (uchar *)( dst_meta+1 );
    ulong               data_max_actual = val_max - sizeof(fd_account_meta_t);
    if( flag_truncate ) fd_accdb_funk_copy_truncated( dst_meta,           src_meta           );
    else                fd_accdb_funk_copy_account  ( dst_meta, dst_data, src_meta, src_data );
    if( acc_orig_sz<data_max_actual ) {
      /* Zero out trailing data */
      uchar * tail    = dst_data       +acc_orig_sz;
      ulong   tail_sz = data_max_actual-acc_orig_sz;
      fd_memset( tail, 0, tail_sz );
    }

    fd_accdb_funk_prep_create( rw, v2->funk, txn, addr_i, val, val_sz, val_max );
    fd_funk_rec_write_lock_uncontended( (fd_funk_rec_t *)rw->ref->user_data );

    req_cnt++;
    accdb->base.rw_active++;
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
funk_close_rw( fd_accdb_user_v2_t * accdb,
               fd_accdb_rw_t *      write ) {
  fd_funk_rec_t * rec = (fd_funk_rec_t *)write->ref->user_data;

  if( FD_UNLIKELY( !accdb->base.rw_active ) ) {
    FD_LOG_CRIT(( "Failed to modify account: ref count underflow" ));
  }

  if( write->ref->user_data2 ) {
    fd_funk_txn_t * txn = (fd_funk_txn_t *)write->ref->user_data2;
    fd_funk_rec_prepare_t prepare = {
      .rec          = rec,
      .rec_head_idx = &txn->rec_head_idx,
      .rec_tail_idx = &txn->rec_tail_idx
    };
    fd_funk_rec_publish( accdb->funk, &prepare );
  }

  fd_funk_rec_write_unlock( rec );
  accdb->base.rw_active--;
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
    fd_accdb_ref_t * ref = &ref0[ i ];
    if( ref->accdb_type!=FD_ACCDB_TYPE_V2 ) continue;
    ref->ref_type==FD_ACCDB_REF_RO ? ro_close_cnt++ : rw_close_cnt++;
    req_err0      [ req_cnt ] = 0;
    req_val_gaddr0[ req_cnt ] = fd_wksp_gaddr_fast( data_wksp, (void *)ref->meta_laddr );
    memset( ref, 0, sizeof(fd_accdb_ref_t) );
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

  for( ulong i=0UL; i<cnt; i++ ) {
    fd_accdb_ref_t * ref = &ref0[ i ];
    if( ref->accdb_type!=FD_ACCDB_TYPE_V1 ) continue;
    switch( ref0[ i ].ref_type ) {
    case FD_ACCDB_REF_RO:
      accdb->base.ro_active--;
      fd_funk_rec_read_unlock( (fd_funk_rec_t *)ref->user_data );
      break;
    case FD_ACCDB_REF_RW:
      funk_close_rw( v2, (fd_accdb_rw_t *)ref );
      break;
    default:
      FD_LOG_CRIT(( "invalid ref_type %u in fd_accdb_user_v1_close_ref", (uint)ref->ref_type ));
    }
    memset( ref, 0, sizeof(fd_accdb_ref_t) );
  }

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

ulong
fd_accdb_user_v2_rw_data_max( fd_accdb_user_t *     accdb,
                              fd_accdb_rw_t const * rw ) {
  (void)accdb;
  if( rw->ref->accdb_type==FD_ACCDB_TYPE_NONE ) {
    return rw->ref->user_data; /* data_max */
  }
  fd_funk_rec_t * rec = (fd_funk_rec_t *)rw->ref->user_data;
  return (ulong)( rec->val_max - sizeof(fd_account_meta_t) );
}

void
fd_accdb_user_v2_rw_data_sz_set( fd_accdb_user_t * accdb,
                                 fd_accdb_rw_t *   rw,
                                 ulong             data_sz,
                                 int               flags ) {
  int flag_dontzero = !!( flags & FD_ACCDB_FLAG_DONTZERO );
  if( FD_UNLIKELY( flags & ~(FD_ACCDB_FLAG_DONTZERO) ) ) {
    FD_LOG_CRIT(( "invalid flags for rw_data_sz_set: %#02x", (uint)flags ));
  }

  ulong prev_sz = rw->meta->dlen;
  if( data_sz>prev_sz ) {
    ulong data_max = fd_accdb_user_v2_rw_data_max( accdb, rw );
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

fd_accdb_user_t *
fd_accdb_user_v2_init( fd_accdb_user_t * accdb_,
                       void *            shfunk,
                       void *            vinyl_rq,
                       void *            vinyl_data,
                       void *            vinyl_req_pool,
                       ulong             vinyl_link_id ) {
  if( FD_UNLIKELY( !accdb_ ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }
  if( FD_UNLIKELY( !shfunk ) ) {
    FD_LOG_WARNING(( "NULL shfunk" ));
    return NULL;
  }
  if( FD_UNLIKELY( !vinyl_data ) ) {
    FD_LOG_WARNING(( "NULL vinyl_data" ));
    return NULL;
  }

  fd_accdb_user_v2_t * accdb = fd_type_pun( accdb_ );
  memset( accdb, 0, sizeof(fd_accdb_user_v2_t) );

  if( FD_UNLIKELY( !fd_funk_join( accdb->funk, shfunk ) ) ) {
    FD_LOG_CRIT(( "fd_funk_join failed" ));
  }

  fd_vinyl_rq_t *       rq       = fd_vinyl_rq_join( vinyl_rq );
  fd_vinyl_req_pool_t * req_pool = fd_vinyl_req_pool_join( vinyl_req_pool );
  if( FD_UNLIKELY( !rq || !req_pool ) ) {
    /* component joins log warning if this is reached */
    FD_LOG_WARNING(( "Failed to initialize database client" ));
    return NULL;
  }

  accdb->vinyl_req_id    = 0UL;
  accdb->vinyl_rq        = rq;
  accdb->vinyl_link_id   = vinyl_link_id;
  accdb->vinyl_data_wksp = vinyl_data;
  accdb->vinyl_req_wksp  = fd_wksp_containing( req_pool );
  accdb->vinyl_req_pool  = req_pool;
  accdb->base.accdb_type = FD_ACCDB_TYPE_V2;
  accdb->base.vt         = &fd_accdb_user_v2_vt;
  return accdb_;
}

void
fd_accdb_user_v2_fini( fd_accdb_user_t * accdb ) {
  fd_accdb_user_v2_t * user = (fd_accdb_user_v2_t *)accdb;

  fd_vinyl_rq_leave( user->vinyl_rq );

  if( FD_UNLIKELY( !fd_funk_leave( user->funk, NULL ) ) ) FD_LOG_CRIT(( "fd_funk_leave failed" ));
}

ulong
fd_accdb_user_v2_batch_max( fd_accdb_user_t * accdb ) {
  fd_accdb_user_v2_t * user = (fd_accdb_user_v2_t *)accdb;
  return fd_vinyl_req_batch_key_max( user->vinyl_req_pool );
}


fd_accdb_user_vt_t const fd_accdb_user_v2_vt = {
  .fini            = fd_accdb_user_v2_fini,
  .batch_max       = fd_accdb_user_v2_batch_max,
  .open_ro_multi   = fd_accdb_user_v2_open_ro_multi,
  .open_rw_multi   = fd_accdb_user_v2_open_rw_multi,
  .close_ref_multi = fd_accdb_user_v2_close_ref_multi,
  .rw_data_max     = fd_accdb_user_v2_rw_data_max,
  .rw_data_sz_set  = fd_accdb_user_v2_rw_data_sz_set
};
