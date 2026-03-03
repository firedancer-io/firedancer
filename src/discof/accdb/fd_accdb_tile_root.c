#include "fd_accdb_tile_private.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/fd_flamenco_base.h"

#define FD_ACCDB_ROOT_BATCH_MAX 16

/* fd_funk_rec_admin_lock attempts to gain a write lock for a record,
   increments the version number, and returns the updated ver_lock
   value.  Returns ULONG_MAX if the lock cannot be acquired immediately
   (e.g. active readers), allowing the caller to yield and retry later
   rather than spinning indefinitely. */

static ulong
fd_funk_rec_admin_lock( fd_funk_t const * funk,
                        fd_funk_rec_t *   rec ) {
  ulong            rec_idx = (ulong)( rec - funk->rec_pool->ele );
  ulong volatile * vl      = &funk->rec_lock[ rec_idx ];
  ulong const ver_lock = FD_VOLATILE_CONST( *vl );
  ulong const ver      = fd_funk_rec_ver_bits ( ver_lock );
  ulong const lock     = fd_funk_rec_lock_bits( ver_lock );
  if( FD_UNLIKELY( lock ) ) {
    /* Active readers — yield to caller */
    return ULONG_MAX;
  }
  ulong const new_ver = fd_funk_rec_ver_inc( ver );
  ulong const new_vl  = fd_funk_rec_ver_lock( new_ver, FD_FUNK_REC_LOCK_MASK );
  if( FD_UNLIKELY( FD_ATOMIC_CAS( vl, ver_lock, new_vl )!=ver_lock ) ) {
    /* CAS failed (race with another lock operation) — yield to caller */
    return ULONG_MAX;
  }
  return new_vl;
}

static void
fd_funk_rec_admin_unlock( fd_funk_t const * funk,
                          fd_funk_rec_t *   rec,
                          ulong             ver_lock ) {
  ulong            rec_idx = (ulong)( rec - funk->rec_pool->ele );
  ulong volatile * vl      = &funk->rec_lock[ rec_idx ];
  FD_VOLATILE( *vl ) = fd_funk_rec_ver_lock( fd_funk_rec_ver_bits( ver_lock ), 0UL );
}

/* funk_free_rec_locked frees a funk record that already has the admin
   lock held (ver_lock from fd_funk_rec_admin_lock). */

static void
funk_free_rec_locked( fd_funk_t *     funk,
                      fd_funk_rec_t * rec,
                      ulong           ver_lock ) {
  memset( &rec->pair, 0, sizeof(fd_funk_xid_key_pair_t) );
  FD_COMPILER_MFENCE();
  rec->map_next = FD_FUNK_REC_IDX_NULL;
  fd_funk_val_flush( rec, funk->alloc, funk->wksp );
  fd_funk_rec_admin_unlock( funk, rec, ver_lock );
  fd_funk_rec_pool_release( funk->rec_pool, rec, 1 );
}

/* funk_free_rec attempts to admin-lock and free a funk record.
   Returns 0 on success, 1 if the lock could not be acquired (active
   readers).  On failure the caller should retry later. */

static int
funk_free_rec( fd_funk_t *     funk,
               fd_funk_rec_t * rec ) {
  FD_COMPILER_MFENCE();
  ulong ver_lock = fd_funk_rec_admin_lock( funk, rec );
  if( FD_UNLIKELY( ver_lock==ULONG_MAX ) ) return 1;
  funk_free_rec_locked( funk, rec, ver_lock );
  return 0;
}

/* funk_gc_chain optimistically deletes all but the newest rooted
   revisions of rec.  This possibly deletes 'rec'.  Returns rec if rec
   is the only known rooted revision, otherwise returns NULL (if rec was
   deleted).  Note that due to edge cases, revisions that are not in the
   oldest tracked slot, may not reliably get cleaned up.  (The oldest
   tracked slot always gets cleaned up, though.) */

static fd_funk_rec_t *
funk_gc_chain( ulong                root_slot,
               fd_funk_t *          funk,
               fd_funk_rec_t *      const rec ) {

  fd_funk_rec_t *      rec_pool  = funk->rec_pool->ele;
  ulong                rec_max   = funk->rec_pool->ele_max;
  ulong                seed      = funk->rec_map->map->seed;
  ulong                chain_cnt = funk->rec_map->map->chain_cnt;

  ulong hash      = fd_funk_rec_map_key_hash( &rec->pair, seed );
  ulong chain_idx = (hash & (chain_cnt-1UL) );

  /* Lock rec_map chain */

  int lock_err = fd_funk_rec_map_iter_lock( funk->rec_map, &chain_idx, 1UL, FD_MAP_FLAG_BLOCKING );
  if( FD_UNLIKELY( lock_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "fd_funk_rec_map_iter_lock failed (%i-%s)", lock_err, fd_map_strerror( lock_err ) ));
  }

  fd_funk_rec_map_shmem_private_chain_t * chain =
      fd_funk_rec_map_shmem_private_chain( funk->rec_map->map, 0UL ) + chain_idx;
  ulong ver =
      fd_funk_rec_map_private_vcnt_ver( FD_VOLATILE_CONST( chain->ver_cnt ) );
  FD_CRIT( ver&1UL, "chain is not locked" );

  /* Walk map chain */

  fd_funk_rec_t * found_rec = NULL;
  uint *          pnext     = &chain->head_cidx;
  uint            cur       = *pnext;
  ulong           chain_len = 0UL;
  ulong           iter      = 0UL;
  while( cur!=FD_FUNK_REC_IDX_NULL ) {
    if( FD_UNLIKELY( iter++ > rec_max ) ) FD_LOG_CRIT(( "cycle detected in rec_map chain %lu", chain_idx ));

    /* Is this node garbage? */

    fd_funk_rec_t * node = &funk->rec_pool->ele[ cur ];
    if( FD_UNLIKELY( cur==node->map_next ) ) FD_LOG_CRIT(( "accdb corruption detected: cycle in rec_map chain %lu", chain_idx ));
    cur = node->map_next;
    if( !fd_funk_rec_key_eq( rec->pair.key, node->pair.key ) ) goto retain;
    if( node->pair.xid->ul[0]>root_slot ) goto retain;
    if( !found_rec ) {
      found_rec = node;
      goto retain;
    }

    /* No longer need this node */

    if( node->pair.xid->ul[0] > rec->pair.xid->ul[0] ) {
      /* If this node is newer than the to-be-deleted slot, need to
         remove it from the transaction's record list. */
      uint neigh_prev = node->prev_idx;
      uint neigh_next = node->next_idx;
      if( neigh_prev==FD_FUNK_REC_IDX_NULL ||
          neigh_next==FD_FUNK_REC_IDX_NULL ) {
        /* Node is first or last of transaction -- too bothersome to
           remove it from the transaction's record list */
        goto retain;
      }
      rec_pool[ neigh_next ].prev_idx = neigh_prev;
      rec_pool[ neigh_prev ].next_idx = neigh_next;
    }

    /* Destroy this node (skip if lock is contended — will retry
       on the next root batch) */

    if( FD_UNLIKELY( funk_free_rec( funk, node ) ) ) goto retain;
    *pnext = cur;
    continue;

  retain:
    pnext = &node->map_next;
    chain_len++;
  }

  /* Unlock rec_map chain */

  FD_COMPILER_MFENCE();
  FD_VOLATILE( chain->ver_cnt ) =
      fd_funk_rec_map_private_vcnt( ver+1UL, chain_len );
  FD_COMPILER_MFENCE();
  return found_rec==rec ? found_rec : NULL;
}

/* accdb_invalidate_line sets the EVICTING flag on a cached line,
   checks that all specread pins have drained, then frees the data obj,
   disconnects the line from meta, and bumps the version via CAS.
   Returns 0 on success, 1 if specread refs are still active (caller
   should retry later).  Caller must be the vinyl tile (single
   writer). */

static int
accdb_invalidate_line( fd_vinyl_line_t *     line,
                       fd_vinyl_meta_ele_t * ele0,
                       fd_vinyl_data_t *     data,
                       ulong                 line_idx,
                       ulong                 ele_idx ) {

  /* Must not be acquired for modify by a vinyl client.  Transient
     specread pins (ref > 0) are OK — the EVICTING flag below will
     cause them to bail. */
  FD_CRIT( fd_accdb_line_ctl_ref( line[ line_idx ].ctl ) >= 0L,
           "cannot invalidate line acquired for modify" );

  /* Set EVICTING — new specreaders will see it and bail */
  FD_ATOMIC_FETCH_AND_OR( &line[ line_idx ].ctl,
                          FD_ACCDB_LINE_CTL_EVICTING );

  /* Check if existing specread refs have drained.  If not, undo
     EVICTING and yield to caller so accdb can service requests. */
  if( FD_UNLIKELY( fd_accdb_line_ctl_ref( FD_VOLATILE_CONST( line[ line_idx ].ctl ) ) > 0L ) ) {
    FD_ATOMIC_FETCH_AND_AND( &line[ line_idx ].ctl,
                             ~FD_ACCDB_LINE_CTL_EVICTING );
    return 1;
  }

  /* Free data obj */
  ulong obj_gaddr = line[ line_idx ].obj_gaddr;
  if( FD_LIKELY( obj_gaddr ) ) {
    fd_vinyl_data_obj_t * obj = fd_vinyl_data_laddr( obj_gaddr, data->laddr0 );
    fd_vinyl_data_free( data, obj );
    line[ line_idx ].obj_gaddr = 0UL;
  }

  /* Disconnect line <-> meta */
  ele0[ ele_idx ].line_idx     = ULONG_MAX;
  line[ line_idx ].ele_idx     = ULONG_MAX;

  /* Bump version, clear EVICTING via CAS */
  fd_accdb_line_ctl_clear( line, line_idx, 0L );
  return 0;
}

/* accdb_populate_line evicts a cache line via CLOCK sweep, allocates
   a data object, copies the pair into it, and returns the new
   line_idx.  The line is inserted with least eviction priority (no
   CHANCE bit) so the CLOCK sweep will reclaim it first.  Returns
   ULONG_MAX if the data allocation fails (the evicted line is left
   disconnected).  Caller must set ele0[ele_idx].line_idx to the
   returned value. */

static ulong
accdb_populate_line( fd_accdb_tile_t *       ctx,
                     fd_vinyl_line_t *       line,
                     ulong                   line_cnt,
                     fd_vinyl_meta_ele_t *   ele0,
                     ulong                   ele_max,
                     fd_vinyl_data_t *       data,
                     ulong                   ele_idx,
                     fd_vinyl_key_t const *  key,
                     fd_vinyl_info_t const * info,
                     void const *            val,
                     ulong                   val_sz ) {

  void * data_laddr0 = data->laddr0;

  ulong new_line_idx = fd_accdb_clock_evict( ctx, line, line_cnt, ele0, ele_max, data );

  ulong szc = fd_vinyl_data_szc( val_sz );
  fd_vinyl_data_obj_t * obj = fd_vinyl_data_alloc( data, szc );
  if( FD_UNLIKELY( !obj ) ) return ULONG_MAX;

  line[ new_line_idx ].obj_gaddr = fd_vinyl_data_gaddr( obj, data_laddr0 );
  line[ new_line_idx ].ele_idx   = ele_idx;
  obj->line_idx  = new_line_idx;
  obj->rd_active = (short)0;

  fd_vinyl_bstream_phdr_t * phdr = fd_vinyl_data_obj_phdr( obj );
  phdr->ctl  = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR,
                                     FD_VINYL_BSTREAM_CTL_STYLE_RAW,
                                     val_sz );
  phdr->key  = *key;
  phdr->info = *info;
  fd_memcpy( fd_vinyl_data_obj_val( obj ), val, val_sz );

  /* No CHANCE bit — least eviction priority */
  return new_line_idx;
}

fd_funk_rec_t *
fd_accdb_v2_root_batch( fd_accdb_tile_t * accdb,
                        fd_funk_rec_t *   rec0 ) {
  fd_funk_t *     funk      = accdb->funk;
  fd_wksp_t *     funk_wksp = funk->wksp;             /* shm workspace containing unrooted accounts */
  fd_funk_rec_t * rec_pool  = funk->rec_pool->ele;    /* funk rec arena */

  fd_vinyl_t *      vinyl      = accdb->vinyl;
  fd_vinyl_io_t *   io         = vinyl->io;
  fd_vinyl_meta_t * meta       = vinyl->meta;
  fd_vinyl_line_t * line       = vinyl->line;
  fd_vinyl_data_t * data       = vinyl->data;

  fd_vinyl_meta_ele_t * ele0       = meta->ele;
  ulong                 ele_max    = meta->ele_max;
  ulong                 meta_seed  = meta->seed;
  ulong *               lock       = meta->lock;
  int                   lock_shift = meta->lock_shift;
  ulong                 line_cnt   = vinyl->line_cnt;

  ulong append_cnt = 0UL;
  ulong root_slot  = funk->shmem->last_publish->ul[0];

  /* Collect funk request batch */

  fd_funk_rec_t * recs[ FD_ACCDB_ROOT_BATCH_MAX ];
  ulong           rec_cnt;

  fd_funk_rec_t * next = rec0;
  for( rec_cnt=0UL; next && rec_cnt<FD_ACCDB_ROOT_BATCH_MAX; ) {
    fd_funk_rec_t * cur = next;
    if( fd_funk_rec_idx_is_null( cur->next_idx ) ) {
      next = NULL;
    } else {
      next = &rec_pool[ cur->next_idx ];
    }
    cur->prev_idx = FD_FUNK_REC_IDX_NULL;
    cur->next_idx = FD_FUNK_REC_IDX_NULL;

    if( funk_gc_chain( root_slot, funk, cur ) ) {
      recs[ rec_cnt++ ] = cur;
    }
  }

  for( ulong i=0UL; i<rec_cnt; i++ ) {
    fd_account_meta_t const * acct = fd_funk_val( recs[ i ], funk_wksp );
    FD_CRIT( acct && recs[ i ]->val_sz>=sizeof(fd_account_meta_t), "corrupt funk_rec" );

    fd_vinyl_key_t const * key =
        (fd_vinyl_key_t const *)fd_funk_rec_key( recs[ i ] );
    ulong memo = fd_vinyl_key_memo( meta_seed, key );

    ulong ele_idx;
    int   found = fd_vinyl_meta_query_fast( ele0, ele_max, key, memo,
                                            &ele_idx );

    if( acct->lamports ) {
      /* --- Append pair block --- */

      ulong val_sz = (ulong)recs[ i ]->val_sz;

      fd_vinyl_info_t info;
      memset( &info, 0, sizeof(fd_vinyl_info_t) );
      info.val_sz = (uint)val_sz;

      if( FD_LIKELY( !found ) ) {
        /* Existing key — overwrite */

        /* Invalidate cache if cached */
        ulong cur_line_idx = ele0[ ele_idx ].line_idx;
        if( FD_LIKELY( cur_line_idx!=ULONG_MAX ) ) {
          if( FD_UNLIKELY( accdb_invalidate_line( line, ele0, data, cur_line_idx, ele_idx ) ) )
            goto skip_rec;
        }

        /* Garbage accounting for old pair */
        ulong val_esz_before =
            fd_vinyl_bstream_ctl_sz( ele0[ ele_idx ].phdr.ctl );
        accdb->accum_garbage_cnt++;
        accdb->accum_garbage_sz +=
            fd_vinyl_bstream_pair_sz( val_esz_before );

        /* Append new pair to bstream */
        ulong seq = fd_vinyl_io_append_pair_raw( io, key, &info,
                                                 (void const *)acct );
        append_cnt++;

        /* Optionally copy into cache with least eviction priority */
        ulong new_line_idx = ULONG_MAX;
        if( FD_LIKELY( accdb->root_populate_cache ) ) {
          new_line_idx = accdb_populate_line( accdb, line, line_cnt,
                                             ele0, ele_max, data,
                                             ele_idx, key, &info,
                                             (void const *)acct, val_sz );
        }

        /* Update meta (prepare/publish for existing element) */
        fd_vinyl_meta_prepare_fast( lock, lock_shift, ele_idx );

        ele0[ ele_idx ].phdr.ctl  =
            fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR,
                                  FD_VINYL_BSTREAM_CTL_STYLE_RAW,
                                  val_sz );
        ele0[ ele_idx ].phdr.info = info;
        ele0[ ele_idx ].seq       = seq;
        ele0[ ele_idx ].line_idx  = new_line_idx;

        fd_vinyl_meta_publish_fast( lock, lock_shift, ele_idx );

      } else {
        /* New key — insert */

        /* Append to bstream first (need seq for meta) */
        ulong seq = fd_vinyl_io_append_pair_raw( io, key, &info,
                                                 (void const *)acct );
        append_cnt++;

        /* Optionally copy into cache with least eviction priority */
        ulong new_line_idx = ULONG_MAX;
        if( FD_LIKELY( accdb->root_populate_cache ) ) {
          new_line_idx = accdb_populate_line( accdb, line, line_cnt,
                                             ele0, ele_max, data,
                                             ele_idx, key, &info,
                                             (void const *)acct, val_sz );
        }

        /* Insert into meta at the empty slot.  Per meta.h safety tip:
           "Inserting without doing a prepare is fine so long as
           phdr.ctl becomes visible last." */

        ele0[ ele_idx ].memo       = memo;
        ele0[ ele_idx ].phdr.key   = *key;
        ele0[ ele_idx ].phdr.info  = info;
        ele0[ ele_idx ].seq        = seq;
        ele0[ ele_idx ].line_idx   = new_line_idx;
        FD_COMPILER_MFENCE();
        ele0[ ele_idx ].phdr.ctl   =
            fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR,
                                  FD_VINYL_BSTREAM_CTL_STYLE_RAW,
                                  val_sz );
        FD_COMPILER_MFENCE();

        vinyl->pair_cnt++;
      }

    } else {
      /* --- Append erase block --- */

      if( FD_LIKELY( !found ) ) {
        /* Key exists in meta — erase it */

        FD_CRIT( ele0[ ele_idx ].phdr.ctl!=ULONG_MAX,
                 "cannot erase key being created" );

        /* Invalidate cache if cached */
        ulong cur_line_idx = ele0[ ele_idx ].line_idx;
        if( FD_LIKELY( cur_line_idx!=ULONG_MAX ) ) {
          if( FD_UNLIKELY( accdb_invalidate_line( line, ele0, data, cur_line_idx, ele_idx ) ) )
            goto skip_rec;
        }

        /* Garbage: old pair + dead block itself */
        ulong val_esz_before =
            fd_vinyl_bstream_ctl_sz( ele0[ ele_idx ].phdr.ctl );
        accdb->accum_garbage_cnt += 2UL;
        accdb->accum_garbage_sz  +=
            fd_vinyl_bstream_pair_sz( val_esz_before )
            + FD_VINYL_BSTREAM_BLOCK_SZ;

        fd_vinyl_io_append_dead( io, &ele0[ ele_idx ].phdr, NULL, 0UL );
        append_cnt++;
        accdb->accum_dead_cnt++;

        /* Remove from meta (handles its own locking) */
        fd_vinyl_meta_remove_fast( ele0, ele_max, lock, lock_shift,
                                   line, line_cnt, ele_idx );
        vinyl->pair_cnt--;
      }
      /* else: erase of non-existent key — no-op */
    }
    continue;

  skip_rec:
    /* Cache line has active specread refs — re-chain record for
       next batch.  The vinyl write will be harmlessly re-done. */
    FD_LOG_NOTICE(( "vinyl data contention" ));
    recs[ i ]->next_idx = next ? (uint)(ulong)( next - rec_pool ) : FD_FUNK_REC_IDX_NULL;
    next    = recs[ i ];
    recs[ i ] = NULL;
  }

  /* Commit result */
  if( FD_LIKELY( append_cnt ) ) {
    fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING );
  }

  /* Remove funk records.  Try admin lock first — if contended
     (active readers), skip the record and re-chain it onto next for
     the next batch.  The vinyl write will be harmlessly re-done. */

  for( ulong i=0UL; i<rec_cnt; i++ ) {
    if( FD_UNLIKELY( !recs[ i ] ) ) continue; /* skipped by invalidate */
    FD_COMPILER_MFENCE();
    ulong ver_lock = fd_funk_rec_admin_lock( funk, recs[ i ] );
    if( FD_UNLIKELY( ver_lock==ULONG_MAX ) ) {
      FD_LOG_NOTICE(( "funk rec contention" ));
      recs[ i ]->next_idx = next ? (uint)(ulong)( next - rec_pool ) : FD_FUNK_REC_IDX_NULL;
      next = recs[ i ];
      continue;
    }
    fd_funk_xid_key_pair_t pair = recs[ i ]->pair;
    fd_funk_rec_query_t query[1];
    int rm_err = fd_funk_rec_map_remove( funk->rec_map, &pair, NULL, query, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_rec_map_remove failed (%i-%s)", rm_err, fd_map_strerror( rm_err ) ));
    funk_free_rec_locked( funk, recs[ i ], ver_lock );
  }

  return next;
}

/* fd_accdb_txn_root_start prepares a funk transaction for rooting on
   the accdb tile.  This does:
   1. Reparent children of the txn to root (shmem child_head/tail)
   2. Mark last_publish atomically
   3. Drain users (rwlock_write + set state=PUBLISH)
   4. Detach rec list from txn
   Returns the head of the detached record list, or NULL if the txn
   has no records.  Caller stores the returned head as root_rec and
   the txn pool index as root_txn_idx for later use. */

fd_funk_rec_t *
fd_accdb_txn_root_start( fd_accdb_tile_t * ctx,
                         fd_funk_txn_t *   txn ) {
  fd_funk_t * funk = ctx->funk;

  /* Phase 1: Reparent children to root */

  funk->shmem->child_head_cidx = txn->child_head_cidx;
  funk->shmem->child_tail_cidx = txn->child_tail_cidx;
  ulong child_idx = fd_funk_txn_idx( txn->child_head_cidx );
  while( !fd_funk_txn_idx_is_null( child_idx ) ) {
    funk->txn_pool->ele[ child_idx ].parent_cidx = fd_funk_txn_cidx( FD_FUNK_TXN_IDX_NULL );
    child_idx = fd_funk_txn_idx( funk->txn_pool->ele[ child_idx ].sibling_next_cidx );
  }

  /* Phase 2: Mark as last published */

  fd_funk_txn_xid_t xid[1];
  fd_funk_txn_xid_copy( xid, fd_funk_txn_xid( txn ) );
  fd_funk_txn_xid_st_atomic( funk->shmem->last_publish, xid );
  FD_LOG_INFO(( "accdb tile root_start xid %lu:%lu", xid->ul[0], xid->ul[1] ));

  /* Phase 3: Drain users */

  ulong txn_idx = (ulong)( txn - funk->txn_pool->ele );
  fd_rwlock_write( &funk->txn_lock[ txn_idx ] );
  FD_VOLATILE( txn->state ) = FD_FUNK_TXN_STATE_PUBLISH;

  /* Phase 4: Detach record list */

  fd_funk_rec_t * head = NULL;
  if( !fd_funk_rec_idx_is_null( txn->rec_head_idx ) ) {
    head = &funk->rec_pool->ele[ txn->rec_head_idx ];
  }
  txn->rec_head_idx = FD_FUNK_REC_IDX_NULL;
  txn->rec_tail_idx = FD_FUNK_REC_IDX_NULL;

  return head;
}

/* fd_accdb_txn_root_fini completes rooting of a funk transaction.
   Called after all record batches have been migrated.  Removes the
   txn from the txn_map, releases the rwlock, and frees the txn. */

void
fd_accdb_txn_root_fini( fd_accdb_tile_t * ctx,
                        fd_funk_txn_t *   txn,
                        ulong             txn_idx ) {
  fd_funk_t * funk = ctx->funk;

  /* Phase 5: Remove txn from txn_map */

  fd_funk_txn_xid_t xid[1];
  fd_funk_txn_xid_copy( xid, fd_funk_txn_xid( txn ) );
  fd_funk_txn_map_query_t query[1];
  int rm_err = fd_funk_txn_map_remove( funk->txn_map, xid, NULL, query, 0 );
  if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) {
    FD_LOG_CRIT(( "txn_map_remove failed xid=%lu:%lu: %i-%s",
                  xid->ul[0], xid->ul[1], rm_err, fd_map_strerror( rm_err ) ));
  }

  /* Phase 6: Free txn */

  fd_rwlock_unwrite( &funk->txn_lock[ txn_idx ] );
  FD_VOLATILE( txn->state ) = FD_FUNK_TXN_STATE_FREE;
  txn->parent_cidx       = UINT_MAX;
  txn->sibling_prev_cidx = UINT_MAX;
  txn->sibling_next_cidx = UINT_MAX;
  txn->child_head_cidx   = UINT_MAX;
  txn->child_tail_cidx   = UINT_MAX;
  fd_funk_txn_pool_release( funk->txn_pool, txn, 1 );

  FD_LOG_INFO(( "accdb tile root_fini xid %lu:%lu", xid->ul[0], xid->ul[1] ));
}
