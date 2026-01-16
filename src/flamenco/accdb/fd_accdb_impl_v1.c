#include "fd_accdb_impl_v1.h"
#include "fd_accdb_base.h"
#include "fd_accdb_sync.h"

FD_STATIC_ASSERT( alignof(fd_accdb_user_v1_t)<=alignof(fd_accdb_user_t), layout );
FD_STATIC_ASSERT( sizeof (fd_accdb_user_v1_t)<=sizeof(fd_accdb_user_t),  layout );

static int
fd_accdb_has_xid( fd_accdb_user_v1_t const * accdb,
                  fd_funk_txn_xid_t const *  rec_xid ) {
  ulong const fork_depth = accdb->fork_depth;
  for( ulong i=0UL; i<fork_depth; i++ ) {
    if( fd_funk_txn_xid_eq( &accdb->fork[i], rec_xid ) ) return 1;
  }
  return 0;
}

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

    /* Confirm that record is part of the current fork
       FIXME this has bad performance / pointer-chasing */
    if( FD_UNLIKELY( !fd_accdb_has_xid( accdb, rec->pair.xid ) ) ) continue;

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

void
fd_accdb_load_fork_slow( fd_accdb_user_v1_t *      accdb,
                         fd_funk_txn_xid_t const * xid ) {
  fd_funk_txn_xid_t     next_xid = *xid;
  fd_funk_txn_t const * tip      = NULL;

  /* Walk transaction graph, recovering from overruns on-the-fly */
  accdb->fork_depth = 0UL;

  ulong txn_max = fd_funk_txn_pool_ele_max( accdb->funk->txn_pool );
  ulong i;
  for( i=0UL; i<FD_ACCDB_DEPTH_MAX; i++ ) {
    fd_funk_txn_map_query_t query[1];
    fd_funk_txn_t const *   candidate;
    fd_funk_txn_xid_t       found_xid;
    ulong                   parent_idx;
    fd_funk_txn_xid_t       parent_xid;
retry:
    /* Speculatively look up transaction from map */
    for(;;) {
      int query_err = fd_funk_txn_map_query_try( accdb->funk->txn_map, &next_xid, NULL, query, 0 );
      if( FD_UNLIKELY( query_err==FD_MAP_ERR_AGAIN ) ) {
        /* FIXME random backoff */
        FD_SPIN_PAUSE();
        continue;
      }
      if( query_err==FD_MAP_ERR_KEY ) goto done;
      if( FD_UNLIKELY( query_err!=FD_MAP_SUCCESS ) ) {
        FD_LOG_CRIT(( "fd_funk_txn_map_query_try failed: %i-%s", query_err, fd_map_strerror( query_err ) ));
      }
      break;
    }

    /* Lookup parent transaction while recovering from overruns
       FIXME This would be a lot easier if transactions specified
             parent by XID instead of by pointer ... */
    candidate = fd_funk_txn_map_query_ele_const( query );
    FD_COMPILER_MFENCE();
    do {
      found_xid  = FD_VOLATILE_CONST( candidate->xid );
      parent_idx = fd_funk_txn_idx( FD_VOLATILE_CONST( candidate->parent_cidx ) );
      if( fd_funk_txn_idx_is_null( parent_idx ) ) break;
      if( FD_UNLIKELY( parent_idx>=txn_max ) ) FD_LOG_CRIT(( "corrupt txn parent idx %lu", parent_idx ));

      FD_COMPILER_MFENCE();
      fd_funk_txn_t const * parent = &accdb->funk->txn_pool->ele[ parent_idx ];
      parent_xid = FD_VOLATILE_CONST( parent->xid );
      FD_COMPILER_MFENCE();

      parent_idx = fd_funk_txn_idx( FD_VOLATILE_CONST( candidate->parent_cidx ) );
      if( fd_funk_txn_idx_is_null( parent_idx ) ) break;
      if( FD_UNLIKELY( parent_idx>=txn_max ) ) FD_LOG_CRIT(( "corrupt txn parent idx %lu", parent_idx ));
    } while(0);
    FD_COMPILER_MFENCE();

    /* Verify speculative loads by ensuring txn still exists in map */
    if( FD_UNLIKELY( fd_funk_txn_map_query_test( query )!=FD_MAP_SUCCESS ) ) {
      FD_SPIN_PAUSE();
      goto retry;
    }

    if( FD_UNLIKELY( !fd_funk_txn_xid_eq( &found_xid, &next_xid ) ) ) {
      FD_LOG_CRIT(( "fd_accdb_load_fork_slow detected memory corruption: expected xid %lu:%lu at %p, found %lu:%lu",
                    next_xid.ul[0], next_xid.ul[1],
                    (void *)candidate,
                    found_xid.ul[0], found_xid.ul[1] ));
    }

    if( !tip ) tip = candidate;  /* remember head of fork */
    accdb->fork[ i ] = next_xid;
    if( fd_funk_txn_idx_is_null( parent_idx ) ) {
      /* Reached root */
      i++;
      break;
    }
    next_xid = parent_xid;
  }

done:
  accdb->fork_depth = i;
  if( FD_UNLIKELY( accdb->fork_depth==FD_ACCDB_DEPTH_MAX ) ) {
    FD_LOG_CRIT(( "Account database fork depth exceeded max of %lu", FD_ACCDB_DEPTH_MAX ));
  }

  /* FIXME crash if fork depth greater than cache depth */
  if( accdb->fork_depth < FD_ACCDB_DEPTH_MAX ) {
    fd_funk_txn_xid_set_root( &accdb->fork[ accdb->fork_depth++ ] );
  }

  /* Remember head of fork */
  if( tip ) {
    accdb->tip_txn_idx = (ulong)( tip - accdb->funk->txn_pool->ele );
    fd_funk_txn_state_assert( tip, FD_FUNK_TXN_STATE_ACTIVE );
  } else {
    accdb->tip_txn_idx = ULONG_MAX;  /* XID is rooted */
  }
}

static inline void
fd_accdb_load_fork( fd_accdb_user_v1_t *      accdb,
                    fd_funk_txn_xid_t const * xid ) {
  /* Skip if already on the correct fork */
  if( FD_LIKELY( (!!accdb->fork_depth) & (!!fd_funk_txn_xid_eq( &accdb->fork[ 0 ], xid ) ) ) ) return;
  if( FD_UNLIKELY( accdb->base.rw_active ) ) {
    FD_LOG_CRIT(( "Invariant violation: all active account references of an accdb_user must be accessed through the same XID (active XID %lu:%lu, requested XID %lu:%lu)",
                  accdb->fork[0].ul[0], accdb->fork[0].ul[1],
                  xid          ->ul[0], xid          ->ul[1] ));
  }
  fd_accdb_load_fork_slow( accdb, xid ); /* switch fork */
}

fd_accdb_peek_t *
fd_accdb_peek_funk( fd_accdb_user_v1_t *      accdb,
                    fd_accdb_peek_t *         peek,
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

  *peek = (fd_accdb_peek_t) {
    .spec = {{
      .key  = *key,
      .keyp = rec->pair.key
    }}
  };
  memcpy( peek->acc->ref->address, address, 32UL );
  peek->acc->ref->accdb_type = FD_ACCDB_TYPE_V1;
  peek->acc->ref->ref_type   = FD_ACCDB_REF_RO;
  peek->acc->ref->user_data  = (ulong)rec;
  peek->acc->meta            = fd_funk_val( rec, funk->wksp );
  return peek;
}

static ulong
fd_accdb_user_v1_batch_max( fd_accdb_user_t * accdb ) {
  (void)accdb;
  return ULONG_MAX;
}

fd_accdb_peek_t *
fd_accdb_user_v1_peek( fd_accdb_user_t *         accdb,
                       fd_accdb_peek_t *         peek,
                       fd_funk_txn_xid_t const * xid,
                       void const *              address ) {
  if( FD_UNLIKELY( !accdb ) ) FD_LOG_CRIT(( "NULL accdb" ));
  fd_accdb_user_v1_t * v1 = (fd_accdb_user_v1_t *)accdb;
  if( FD_UNLIKELY( !v1->funk->shmem ) ) FD_LOG_CRIT(( "NULL funk shmem" ));
  fd_accdb_load_fork( v1, xid );
  if( !fd_accdb_peek_funk( v1, peek, xid, address ) ) return NULL;
  if( FD_UNLIKELY( !peek->acc->meta->lamports ) ) return NULL;
  return peek;
}

void
fd_accdb_v1_copy_account( fd_account_meta_t *       out_meta,
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
fd_accdb_v1_copy_truncated( fd_account_meta_t *       out_meta,
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
fd_accdb_v1_prep_create( fd_accdb_rw_t *           rw,
                         fd_accdb_user_v1_t *      accdb,
                         fd_funk_txn_xid_t const * xid,
                         void const *              address,
                         void *                    val,
                         ulong                     val_sz,
                         ulong                     val_max ) {
  FD_CRIT( val_sz >=sizeof(fd_account_meta_t), "invalid val_sz"  );
  FD_CRIT( val_max>=sizeof(fd_account_meta_t), "invalid val_max" );
  FD_CRIT( val_sz<=val_max, "invalid val_max" );

  fd_funk_rec_t * rec = fd_funk_rec_pool_acquire( accdb->funk->rec_pool, NULL, 1, NULL );
  if( FD_UNLIKELY( !rec ) ) FD_LOG_CRIT(( "Failed to modify account: DB record pool is out of memory" ));
  accdb->base.created_cnt++;

  memset( rec, 0, sizeof(fd_funk_rec_t) );
  rec->val_gaddr = fd_wksp_gaddr_fast( accdb->funk->wksp, val );
  rec->val_sz    = (uint)( fd_ulong_min( val_sz,  FD_FUNK_REC_VAL_MAX ) & FD_FUNK_REC_VAL_MAX );
  rec->val_max   = (uint)( fd_ulong_min( val_max, FD_FUNK_REC_VAL_MAX ) & FD_FUNK_REC_VAL_MAX );
  memcpy( rec->pair.key->uc, address, 32UL );
  fd_funk_txn_xid_copy( rec->pair.xid, xid );
  rec->tag      = 0;
  rec->pub      = 0;
  rec->prev_idx = FD_FUNK_REC_IDX_NULL;
  rec->next_idx = FD_FUNK_REC_IDX_NULL;

  fd_account_meta_t * meta = val;
  meta->slot = xid->ul[0];

  accdb->base.rw_active++;
  *rw = (fd_accdb_rw_t){0};
  memcpy( rw->ref->address, address, 32UL );
  rw->ref->accdb_type = FD_ACCDB_TYPE_V1;
  rw->ref->user_data  = (ulong)rec;
  rw->ref->ref_type   = FD_ACCDB_REF_RW;
  rw->meta            = meta;
  return rw;
}

/* fd_accdb_prep_inplace preps a writable handle for a mutable record. */

static fd_accdb_rw_t *
fd_accdb_prep_inplace( fd_accdb_rw_t *      rw,
                       fd_accdb_user_v1_t * accdb,
                       fd_funk_rec_t *      rec ) {
  /* Take the opportunity to run some validation checks */
  if( FD_UNLIKELY( !rec->val_gaddr ) ) {
    FD_LOG_CRIT(( "Failed to prepare in-place account write: rec %p is not allocated", (void *)rec ));
  }

  accdb->base.rw_active++;
  *rw = (fd_accdb_rw_t) {0};
  memcpy( rw->ref->address, rec->pair.key->uc, 32UL );
  rw->ref->accdb_type = FD_ACCDB_TYPE_V1;
  rw->ref->user_data  = (ulong)rec;
  rw->ref->ref_type   = FD_ACCDB_REF_RW;
  rw->meta            = fd_funk_val( rec, accdb->funk->wksp );
  if( FD_UNLIKELY( !rw->meta->lamports ) ) {
    memset( rw->meta, 0, sizeof(fd_account_meta_t) );
  }
  return rw;
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
  fd_accdb_load_fork( v1, xid );
  ulong addr_laddr = (ulong)address;
  for( ulong i=0UL; i<cnt; i++ ) {
    void const *    addr_i = (void const *)( (ulong)addr_laddr + i*32UL );
    fd_accdb_peek_t peek[1];
    if( !fd_accdb_peek_funk( v1, peek, xid, addr_i ) ) {
      fd_accdb_ro_init_empty( &ro[i], addr_i );
    } else {
      ro[i] = *peek->acc;
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

static fd_accdb_rw_t *
fd_accdb_v1_create( fd_accdb_user_v1_t *      v1,
                    fd_accdb_rw_t *           rw,
                    fd_funk_txn_xid_t const * xid,
                    void const *              address,
                    ulong                     data_max ) {
  ulong  val_sz_min = sizeof(fd_account_meta_t)+data_max;
  ulong  val_max    = 0UL;
  void * val        = fd_alloc_malloc_at_least( v1->funk->alloc, 16UL, val_sz_min, &val_max );
  if( FD_UNLIKELY( !val ) ) {
    FD_LOG_CRIT(( "Failed to modify account: out of memory allocating %lu bytes", data_max ));
  }
  memset( val, 0, sizeof(fd_account_meta_t) );
  return fd_accdb_v1_prep_create( rw, v1, xid, address, val, sizeof(fd_account_meta_t), val_max );
}

fd_accdb_rw_t *
fd_accdb_user_v1_open_rw( fd_accdb_user_t *         accdb,
                          fd_accdb_rw_t *           rw,
                          fd_funk_txn_xid_t const * xid,
                          void const *              address,
                          ulong                     data_max,
                          int                       flags ) {
  fd_accdb_user_v1_t * v1  = (fd_accdb_user_v1_t *)accdb;

  int const flag_create    = !!( flags & FD_ACCDB_FLAG_CREATE       );
  int const flag_truncate  = !!( flags & FD_ACCDB_FLAG_TRUNCATE     );
  int const flag_tombstone = !!( flags & FD_ACCDB_FLAG_V1_TOMBSTONE );
  if( FD_UNLIKELY( flags & ~(FD_ACCDB_FLAG_CREATE|FD_ACCDB_FLAG_TRUNCATE|FD_ACCDB_FLAG_V1_TOMBSTONE) ) ) {
    FD_LOG_CRIT(( "invalid flags for open_rw: %#02x", (uint)flags ));
  }

  /* Pivot to different fork */
  fd_accdb_load_fork( v1, xid );
  ulong txn_idx = v1->tip_txn_idx;
  if( FD_UNLIKELY( txn_idx==ULONG_MAX ) ) {
    FD_LOG_CRIT(( "fd_accdb_user_v1_open_rw failed: XID %lu:%lu is rooted", xid->ul[0], xid->ul[1] ));
  }
  if( FD_UNLIKELY( txn_idx >= fd_funk_txn_pool_ele_max( v1->funk->txn_pool ) ) ) {
    FD_LOG_CRIT(( "memory corruption detected: invalid txn_idx %lu (max %lu)",
                  txn_idx, fd_funk_txn_pool_ele_max( v1->funk->txn_pool ) ));
  }
  fd_funk_txn_t * txn = &v1->funk->txn_pool->ele[ txn_idx ];
  if( FD_UNLIKELY( !fd_funk_txn_xid_eq( &txn->xid, xid ) ) ) {
    FD_LOG_CRIT(( "Failed to modify account: data race detected on fork node (expected XID %lu:%lu, found %lu:%lu)",
                  xid->ul[0],     xid->ul[1],
                  txn->xid.ul[0], txn->xid.ul[1] ));
  }
  if( FD_UNLIKELY( fd_funk_txn_is_frozen( txn ) ) ) {
    FD_LOG_CRIT(( "Failed to modify account: XID %lu:%lu has children/is frozen", xid->ul[0], xid->ul[1] ));
  }

  /* Query old record value */

  fd_accdb_peek_t peek[1];
  if( FD_UNLIKELY( !fd_accdb_peek_funk( v1, peek, xid, address ) ) ) {
    /* Record not found */
    if( flag_create ) return fd_accdb_v1_create( v1, rw, xid, address, data_max );
    return NULL;
  }

  if( !peek->acc->meta->lamports ) {
    /* If the 'tombstone' flag was requested, treat non-existent
       accounts and zero-lamport accounts differently. */
    if( flag_tombstone ) return (fd_accdb_rw_t *)fd_accdb_ro_init_empty( rw->ro, address );
    /* Record previously deleted */
    if( !flag_create ) return NULL;
  }

  fd_funk_rec_t * rec = (fd_funk_rec_t *)peek->acc->ref->user_data;
  if( fd_funk_txn_xid_eq( rec->pair.xid, xid ) ) {

    /* Mutable record found, modify in-place */
    ulong  acc_orig_sz = fd_accdb_ref_data_sz( peek->acc );
    ulong  val_sz_min  = sizeof(fd_account_meta_t)+fd_ulong_max( data_max, acc_orig_sz );
    void * val         = fd_funk_val_truncate( rec, v1->funk->alloc, v1->funk->wksp, 16UL, val_sz_min, NULL );
    if( FD_UNLIKELY( !val ) ) {
      FD_LOG_CRIT(( "Failed to modify account: out of memory allocating %lu bytes", acc_orig_sz ));
    }
    fd_accdb_prep_inplace( rw, v1, rec );
    if( flag_truncate ) {
      rec->val_sz = sizeof(fd_account_meta_t);
      rw->meta->dlen  = 0;
    }
    return rw;

  } else {

    /* Frozen record found, copy out to new object */
    ulong  acc_orig_sz = fd_accdb_ref_data_sz( peek->acc );
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
    if( flag_truncate ) fd_accdb_v1_copy_truncated( meta,       peek->acc->meta );
    else                fd_accdb_v1_copy_account  ( meta, data, peek->acc->meta, fd_account_data( peek->acc->meta ) );
    if( acc_orig_sz<data_max_actual ) {
      /* Zero out trailing data */
      uchar * tail    = data           +acc_orig_sz;
      ulong   tail_sz = data_max_actual-acc_orig_sz;
      fd_memset( tail, 0, tail_sz );
    }
    if( FD_UNLIKELY( !fd_accdb_peek_test( peek ) ) ) {
      FD_LOG_CRIT(( "Failed to modify account: data race detected, account was removed while being read" ));
    }

    return fd_accdb_v1_prep_create( rw, v1, xid, address, val, val_sz, val_max );

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

  if( !rec->pub ) {
    if( FD_UNLIKELY( v1->tip_txn_idx==ULONG_MAX ) ) {
      FD_LOG_CRIT(( "accdb_user corrupt: not joined to a transaction" ));
    }
    fd_funk_txn_t * txn = v1->funk->txn_pool->ele + v1->tip_txn_idx;
    fd_funk_rec_prepare_t prepare = {
      .rec          = rec,
      .rec_head_idx = &txn->rec_head_idx,
      .rec_tail_idx = &txn->rec_tail_idx
    };
    fd_funk_rec_publish( v1->funk, &prepare );
    rec->pub = 1;
  }

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
  (void)accdb;
  int flag_dontzero = !!( flags & FD_ACCDB_FLAG_DONTZERO );
  if( FD_UNLIKELY( flags & ~(FD_ACCDB_FLAG_DONTZERO) ) ) {
    FD_LOG_CRIT(( "invalid flags for rw_data_sz_set: %#02x", (uint)flags ));
  }

  ulong prev_sz = rw->meta->dlen;
  if( data_sz>prev_sz ) {
    ulong data_max = fd_accdb_ref_data_max( accdb, rw );
    if( FD_UNLIKELY( data_sz>data_max ) ) {
      FD_LOG_CRIT(( "attempted to write %lu bytes into a rec with only %lu bytes of data space",
                    data_sz, data_max ));
    }
    if( !flag_dontzero ) {
      void * tail = (uchar *)fd_accdb_ref_data( rw ) + prev_sz;
      fd_memset( tail, 0, data_sz-prev_sz );
    }
  }
  rw->meta->dlen  = (uint)data_sz;

  if( rw->ref->accdb_type==FD_ACCDB_TYPE_V1 ) {
    fd_funk_rec_t * rec = (fd_funk_rec_t *)rw->ref->user_data;
    rec->val_sz = (uint)( sizeof(fd_account_meta_t)+data_sz ) & FD_FUNK_REC_VAL_MAX;
  }
}

fd_accdb_user_vt_t const fd_accdb_user_v1_vt = {
  .fini            = fd_accdb_user_v1_fini,
  .batch_max       = fd_accdb_user_v1_batch_max,
  .peek            = fd_accdb_user_v1_peek,
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
