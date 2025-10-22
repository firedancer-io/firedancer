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

  /* Walk the map chain, remember the best entry */
  fd_funk_rec_t * best      = NULL;
  long            best_slot = -1L;
  for( ulong i=0UL; i<cnt; i++, ele_idx=rec_tbl[ ele_idx ].map_next ) {
    fd_funk_rec_t * rec = &rec_tbl[ ele_idx ];

    /* Skip over unrelated records (hash collision) */
    if( FD_UNLIKELY( !fd_funk_rec_key_eq( rec->pair.key, key ) ) ) continue;

    /* Skip over records that are older than what we already have */
    ulong found_slot = rec->pair.xid->ul[0];
    if( FD_UNLIKELY( (long)found_slot<best_slot ) ) continue;

    /* Confirm that record is part of the current fork
       FIXME this has bad performance / pointer-chasing */
    if( FD_UNLIKELY( !fd_accdb_has_xid( accdb, rec->pair.xid ) ) ) continue;

    best      = rec;
    best_slot = (long)found_slot;
    if( FD_UNLIKELY( rec->map_next==ele_idx ) ) {
      FD_LOG_CRIT(( "fd_accdb_search_chain detected cycle" ));
    }
    if( rec->map_next > rec_max ) {
      if( FD_UNLIKELY( !fd_funk_rec_map_private_idx_is_null( rec->map_next ) ) ) {
        FD_LOG_CRIT(( "fd_accdb_search_chain detected memory corruption: rec->map_next %u is out of bounds (rec_max %lu)",
                      rec->map_next, rec_max ));
      }
    }
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
}

static inline void
fd_accdb_load_fork( fd_accdb_user_t *         accdb,
                    fd_funk_txn_xid_t const * xid ) {
  /* Skip if already on the correct fork */
  if( FD_LIKELY( (!!accdb->fork_depth) & (!!fd_funk_txn_xid_eq( &accdb->fork[ 0 ], xid ) ) ) ) return;
  fd_accdb_load_fork_slow( accdb, xid ); /* switch fork */
}

fd_accdb_peek_t *
fd_accdb_peek( fd_accdb_user_t *         accdb,
               fd_accdb_peek_t *         peek,
               fd_funk_txn_xid_t const * xid,
               void const *              address ) {
  if( FD_UNLIKELY( !accdb || !accdb->funk->shmem ) ) FD_LOG_CRIT(( "NULL accdb" ));
  fd_funk_t const * funk = accdb->funk;
  fd_accdb_load_fork( accdb, xid );
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
