#include "fd_accdb_sync.h"

fd_accdb_user_t *
fd_accdb_user_join( fd_accdb_user_t * ljoin,
                    void *            shfunk ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }
  if( FD_UNLIKELY( !shfunk ) ) {
    FD_LOG_WARNING(( "NULL shfunk" ));
    return NULL;
  }

  memset( ljoin, 0, sizeof(fd_accdb_user_t) );
  if( FD_UNLIKELY( !fd_funk_join( ljoin->funk, shfunk ) ) ) {
    FD_LOG_CRIT(( "fd_funk_join failed" ));
  }

  return ljoin;
}

void *
fd_accdb_user_leave( fd_accdb_user_t * user,
                      void **          opt_shfunk ) {
  if( FD_UNLIKELY( !user ) ) FD_LOG_CRIT(( "NULL ljoin" ));

  if( FD_UNLIKELY( !fd_funk_leave( user->funk, opt_shfunk ) ) ) FD_LOG_CRIT(( "fd_funk_leave failed" ));

  return user;
}

static int
fd_accdb_has_xid( fd_accdb_user_t const *   accdb,
                  fd_funk_txn_xid_t const * rec_xid ) {
  /* FIXME unroll this a little */
  ulong const fork_depth = accdb->fork_depth;
  for( ulong i=0UL; i<fork_depth; i++ ) {
    if( fd_funk_txn_xid_eq( &accdb->fork[i], rec_xid ) ) return 1;
  }
  return 0;
}

static int
fd_accdb_search_chain( fd_accdb_user_t const *   accdb,
                       ulong                     chain_idx,
                       fd_funk_rec_key_t const * key,
                       fd_funk_rec_t **          out_rec ) {
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

static void
fd_accdb_load_fork_slow( fd_accdb_user_t *         accdb,
                         fd_funk_txn_xid_t const * xid ) {
  fd_funk_txn_xid_t next_xid = *xid;

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
      if( parent_idx<txn_max ) {
        FD_COMPILER_MFENCE();
        fd_funk_txn_t const * parent = &accdb->funk->txn_pool->ele[ parent_idx ];
        parent_xid = FD_VOLATILE_CONST( parent->xid );
        FD_COMPILER_MFENCE();
      }
      parent_idx = fd_funk_txn_idx( FD_VOLATILE_CONST( candidate->parent_cidx ) );
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

  /* FIXME crash if fork depth greater than cache depth */
  if( accdb->fork_depth < FD_ACCDB_DEPTH_MAX ) {
    fd_funk_txn_xid_set_root( &accdb->fork[ accdb->fork_depth++ ] );
  }

  /* Remember tip fork */
  fd_funk_txn_t * tip = fd_funk_txn_query( xid, accdb->funk->txn_map );
  ulong tip_idx = tip ? (ulong)( tip-accdb->funk->txn_pool->ele ) : ULONG_MAX;
  accdb->tip_txn_idx = tip_idx;
  if( tip ) fd_funk_txn_state_assert( tip, FD_FUNK_TXN_STATE_ACTIVE );
}

static inline void
fd_accdb_load_fork( fd_accdb_user_t *         accdb,
                    fd_funk_txn_xid_t const * xid ) {
  /* Skip if already on the correct fork */
  if( FD_LIKELY( (!!accdb->fork_depth) & (!!fd_funk_txn_xid_eq( &accdb->fork[ 0 ], xid ) ) ) ) return;
  if( FD_UNLIKELY( accdb->rw_active ) ) {
    FD_LOG_CRIT(( "Invariant violation: all active account references of an accdb_user must be accessed through the same XID (active XID %lu:%lu, requested XID %lu:%lu)",
                  accdb->fork[0].ul[0], accdb->fork[0].ul[1],
                  xid          ->ul[0], xid          ->ul[1] ));
  }
  fd_accdb_load_fork_slow( accdb, xid ); /* switch fork */
}

static fd_accdb_peek_t *
fd_accdb_peek1( fd_accdb_user_t *         accdb,
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
    .acc = {{
      .rec  = rec,
      .meta = fd_funk_val( rec, funk->wksp )
    }},
    .spec = {{
      .key  = *key,
      .keyp = rec->pair.key
    }}
  };
  return peek;
}

fd_accdb_peek_t *
fd_accdb_peek( fd_accdb_user_t *         accdb,
               fd_accdb_peek_t *         peek,
               fd_funk_txn_xid_t const * xid,
               void const *              address ) {
  if( FD_UNLIKELY( !accdb || !accdb->funk->shmem ) ) FD_LOG_CRIT(( "NULL accdb" ));
  fd_accdb_load_fork( accdb, xid );
  return fd_accdb_peek1( accdb, peek, xid, address );
}

static void
fd_accdb_copy_account( fd_account_meta_t *   out_meta,
                       void *                out_data,
                       fd_accdb_ro_t const * acc ) {
  memset( out_meta, 0, sizeof(fd_account_meta_t) );
  out_meta->lamports = fd_accdb_ref_lamports( acc );
  if( FD_LIKELY( out_meta->lamports ) ) {
    memcpy( out_meta->owner, fd_accdb_ref_owner( acc ), 32UL );
    out_meta->executable = !!fd_accdb_ref_exec_bit( acc );
    out_meta->dlen       = (uint)fd_accdb_ref_data_sz( acc );
    fd_memcpy( out_data, fd_accdb_ref_data_const( acc ), out_meta->dlen );
  }
}

/* fd_accdb_prep_create preps a writable handle for a newly created
   account. */

static fd_accdb_rw_t *
fd_accdb_prep_create( fd_accdb_rw_t *           rw,
                      fd_accdb_user_t *         accdb,
                      fd_funk_txn_xid_t const * xid,
                      void const *              address,
                      void *                    val,
                      ulong                     val_sz,
                      ulong                     val_max ) {
  fd_funk_rec_t * rec = fd_funk_rec_pool_acquire( accdb->funk->rec_pool, NULL, 1, NULL );
  if( FD_UNLIKELY( !rec ) ) FD_LOG_CRIT(( "Failed to modify account: DB record pool is out of memory" ));

  memset( rec, 0, sizeof(fd_funk_rec_t) );
  rec->val_gaddr = fd_wksp_gaddr_fast( accdb->funk->wksp, val );
  rec->val_sz    = (uint)( fd_ulong_min( val_sz,  FD_FUNK_REC_VAL_MAX ) & FD_FUNK_REC_VAL_MAX );
  rec->val_max   = (uint)( fd_ulong_min( val_max, FD_FUNK_REC_VAL_MAX ) & FD_FUNK_REC_VAL_MAX );
  memcpy( rec->pair.key->uc, address, 32UL );
  fd_funk_txn_xid_copy( rec->pair.xid, xid );
  rec->tag      = 0;
  rec->prev_idx = FD_FUNK_REC_IDX_NULL;
  rec->next_idx = FD_FUNK_REC_IDX_NULL;

  fd_account_meta_t * meta = val;
  meta->slot = xid->ul[0];

  accdb->rw_active++;
  *rw = (fd_accdb_rw_t) {
    .rec       = rec,
    .meta      = meta,
    .published = 0
  };
  return rw;
}

/* fd_accdb_prep_inplace preps a writable handle for a mutable record. */

static fd_accdb_rw_t *
fd_accdb_prep_inplace( fd_accdb_rw_t *   rw,
                       fd_accdb_user_t * accdb,
                       fd_funk_rec_t *   rec ) {
  /* Take the opportunity to run some validation checks */
  if( FD_UNLIKELY( !rec->val_gaddr ) ) {
    FD_LOG_CRIT(( "Failed to prepare in-place account write: rec %p is not allocated", (void *)rec ));
  }

  accdb->rw_active++;
  *rw = (fd_accdb_rw_t) {
    .rec       = rec,
    .meta      = fd_funk_val( rec, accdb->funk->wksp ),
    .published = 1
  };
  if( FD_UNLIKELY( !rw->meta->lamports ) ) {
    memset( rw->meta, 0, sizeof(fd_account_meta_t) );
  }
  return rw;
}

fd_accdb_rw_t *
fd_accdb_modify_prepare( fd_accdb_user_t *         accdb,
                         fd_accdb_rw_t *           rw,
                         fd_funk_txn_xid_t const * xid,
                         void const *              address,
                         ulong const               data_min,
                         int                       do_create ) {
  /* Pivot to different fork */

  fd_accdb_load_fork( accdb, xid );
  ulong txn_idx = accdb->tip_txn_idx;
  if( FD_UNLIKELY( txn_idx==ULONG_MAX ) ) {
    FD_LOG_CRIT(( "fd_accdb_modify_prepare failed: XID %lu:%lu is rooted", xid->ul[0], xid->ul[1] ));
  }
  if( FD_UNLIKELY( txn_idx >= fd_funk_txn_pool_ele_max( accdb->funk->txn_pool ) ) ) {
    FD_LOG_CRIT(( "memory corruption detected: invalid txn_idx %lu (max %lu)",
                  txn_idx, fd_funk_txn_pool_ele_max( accdb->funk->txn_pool ) ));
  }
  fd_funk_txn_t * txn = &accdb->funk->txn_pool->ele[ txn_idx ];
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
  if( FD_UNLIKELY( !fd_accdb_peek1( accdb, peek, xid, address ) ) ) {

    /* Record not found */
    if( !do_create ) return NULL;
    ulong  val_sz_min = sizeof(fd_account_meta_t)+data_min;
    ulong  val_max = 0UL;
    void * val     = fd_alloc_malloc_at_least( accdb->funk->alloc, 16UL, val_sz_min, &val_max );
    if( FD_UNLIKELY( !val ) ) {
      FD_LOG_CRIT(( "Failed to modify account: out of memory allocating %lu bytes", data_min ));
    }
    fd_memset( val, 0, val_sz_min );
    return fd_accdb_prep_create( rw, accdb, xid, address, val, val_sz_min, val_max );

  } else if( fd_funk_txn_xid_eq( peek->acc->rec->pair.xid, xid ) ) {

    /* Mutable record found, modify in-place */
    fd_funk_rec_t * rec = (void *)( peek->acc->ref->rec_laddr );
    ulong  acc_orig_sz = fd_accdb_ref_data_sz( peek->acc );
    ulong  val_sz_min  = sizeof(fd_account_meta_t)+fd_ulong_max( data_min, acc_orig_sz );
    void * val         = fd_funk_val_truncate( rec, accdb->funk->alloc, accdb->funk->wksp, 16UL, val_sz_min, NULL );
    if( FD_UNLIKELY( !val ) ) {
      FD_LOG_CRIT(( "Failed to modify account: out of memory allocating %lu bytes", acc_orig_sz ));
    }
    return fd_accdb_prep_inplace( rw, accdb, rec );

  } else {

    /* Frozen record found, copy out to new object */
    ulong  acc_orig_sz = fd_accdb_ref_data_sz( peek->acc );
    ulong  val_sz_min  = sizeof(fd_account_meta_t)+fd_ulong_max( data_min, acc_orig_sz );
    ulong  val_sz      = peek->acc->rec->val_sz;
    ulong  val_max     = 0UL;
    void * val         = fd_alloc_malloc_at_least( accdb->funk->alloc, 16UL, val_sz_min, &val_max );
    if( FD_UNLIKELY( !val ) ) {
      FD_LOG_CRIT(( "Failed to modify account: out of memory allocating %lu bytes", acc_orig_sz ));
    }

    fd_account_meta_t * meta     = val;
    uchar *             data     = (uchar *)( meta+1 );
    ulong               data_max = val_max - sizeof(fd_account_meta_t);
    fd_accdb_copy_account( meta, data, peek->acc );
    if( acc_orig_sz<data_max ) {
      /* Zero out trailing data */
      uchar * tail    = data    +acc_orig_sz;
      ulong   tail_sz = data_max-acc_orig_sz;
      fd_memset( tail, 0, tail_sz );
    }
    if( FD_UNLIKELY( !fd_accdb_peek_test( peek ) ) ) {
      FD_LOG_CRIT(( "Failed to modify account: data race detected, account was removed while being read" ));
    }

    return fd_accdb_prep_create( rw, accdb, xid, address, val, val_sz, val_max );

  }
}

void
fd_accdb_write_publish( fd_accdb_user_t * accdb,
                        fd_accdb_rw_t *   write ) {
  if( FD_UNLIKELY( !accdb->rw_active ) ) {
    FD_LOG_CRIT(( "Failed to modify account: ref count underflow" ));
  }

  if( !write->published ) {
    if( FD_UNLIKELY( accdb->tip_txn_idx==ULONG_MAX ) ) {
      FD_LOG_CRIT(( "accdb_user corrupt: not joined to a transaction" ));
    }
    fd_funk_txn_t * txn = accdb->funk->txn_pool->ele + accdb->tip_txn_idx;
    fd_funk_rec_prepare_t prepare = {
      .rec          = write->rec,
      .rec_head_idx = &txn->rec_head_idx,
      .rec_tail_idx = &txn->rec_tail_idx
    };
    fd_funk_rec_publish( accdb->funk, &prepare );
  }

  accdb->rw_active--;
}
