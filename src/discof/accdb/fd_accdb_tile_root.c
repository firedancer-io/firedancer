#include "fd_accdb_tile_private.h"
#include "../../funk/fd_funk.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/accdb/fd_accdb_lineage.h"

#define FD_ACCDB_ROOT_BATCH_MAX 128

/* funk_rec_write_lock spins until it gains a write lock for a record,
   increments the version number, and returns the updated ver_lock
   value. */

static ulong
fd_funk_rec_admin_lock( fd_funk_t const * funk,
                        fd_funk_rec_t *   rec ) {
  ulong            rec_idx = (ulong)( rec - funk->rec_pool->ele );
  ulong volatile * vl      = &funk->rec_lock[ rec_idx ];
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
fd_funk_rec_admin_unlock( fd_funk_t const * funk,
                          fd_funk_rec_t *   rec,
                          ulong             ver_lock ) {
  ulong            rec_idx = (ulong)( rec - funk->rec_pool->ele );
  ulong volatile * vl      = &funk->rec_lock[ rec_idx ];
  FD_VOLATILE( *vl ) = fd_funk_rec_ver_lock( fd_funk_rec_ver_bits( ver_lock ), 0UL );
}

static void
funk_free_rec( fd_funk_t *     funk,
               fd_funk_rec_t * rec ) {
  /* Acquire admin lock (kick out readers)

     Note: At this point, well-behaving external readers will abandon a
     read-lock attempt if they observe this active write lock.  (An
     admin lock always implies the record is about to die) */

  FD_COMPILER_MFENCE();
  ulong ver_lock = fd_funk_rec_admin_lock( funk, rec );

  /* Free record */

  memset( &rec->pair, 0, sizeof(fd_funk_xid_key_pair_t) );
  FD_COMPILER_MFENCE();
  rec->map_next = FD_FUNK_REC_IDX_NULL;
  fd_funk_val_flush( rec, funk->alloc, funk->wksp );
  fd_funk_rec_admin_unlock( funk, rec, ver_lock );
  fd_funk_rec_pool_release( funk->rec_pool, rec, 1 );
}

/* funk_gc_chain optimistically deletes all but the newest rooted
   revisions of rec.  This possibly deletes 'rec'.  Returns rec if rec
   is the only known rooted revision, otherwise returns NULL (if rec was
   deleted).  Note that due to edge cases, revisions that are not in the
   oldest tracked slot, may not reliably get cleaned up.  (The oldest
   tracked slot always gets cleaned up, though.) */

static fd_funk_rec_t *
funk_gc_chain( fd_accdb_lineage_t * lineage,
               fd_funk_t *          funk,
               fd_funk_rec_t *      const rec ) {

  fd_funk_rec_t *      rec_pool  = funk->rec_pool->ele;
  ulong                rec_max   = funk->rec_pool->ele_max;
  ulong                seed      = funk->rec_map->map->seed;
  ulong                chain_cnt = funk->rec_map->map->chain_cnt;
  ulong                root_slot = lineage->fork[0].ul[0];

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

    /* Destroy this node */

    funk_free_rec( funk, node );
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
   spins until all specread pins drain, then frees the data obj,
   disconnects the line from meta, bumps the version, and clears
   specread_ctl.  Caller must be the vinyl tile (single writer). */

static void
accdb_invalidate_line( fd_vinyl_line_t *     line,
                       fd_vinyl_meta_ele_t * ele0,
                       fd_vinyl_data_t *     data,
                       ulong                 line_idx,
                       ulong                 ele_idx ) {

  /* Must not be acquired by a vinyl client */
  FD_CRIT( !fd_vinyl_line_ctl_ref( line[ line_idx ].ctl ),
           "cannot invalidate acquired line" );

  /* Set EVICTING — new specreaders will see it and bail */
  FD_ATOMIC_FETCH_AND_OR( &line[ line_idx ].specread_ctl,
                          FD_VINYL_LINE_SRC_EVICTING );

  /* Spin-drain existing specread refs */
  while( FD_VOLATILE_CONST( line[ line_idx ].specread_ctl )
         & FD_VINYL_LINE_SRC_REF_MASK ) {
    FD_SPIN_PAUSE();
  }

  /* Free data obj */
  fd_vinyl_data_obj_t * obj = line[ line_idx ].obj;
  if( FD_LIKELY( obj ) ) {
    fd_vinyl_data_free( data, obj );
    line[ line_idx ].obj = NULL;
  }

  /* Disconnect line <-> meta */
  ele0[ ele_idx ].line_idx     = ULONG_MAX;
  line[ line_idx ].ele_idx     = ULONG_MAX;

  /* Bump version, clear specread_ctl.
     On x86 TSO, stores above become globally visible in program order.
     Clearing specread_ctl last ensures any specreader that sees
     EVICTING cleared also sees the disconnect/version bump. */
  ulong ver = fd_vinyl_line_ctl_ver( line[ line_idx ].ctl );
  line[ line_idx ].ctl          = fd_vinyl_line_ctl( ver+1UL, 0L );
  line[ line_idx ].specread_ctl = 0U;
}

fd_funk_rec_t *
fd_accdb_v2_root_batch( fd_accdb_tile_t * accdb,
                        fd_funk_rec_t *   rec0 ) {
  fd_funk_t *     funk      = accdb->funk;
  fd_wksp_t *     funk_wksp = funk->wksp;             /* shm workspace containing unrooted accounts */
  fd_funk_rec_t * rec_pool  = funk->rec_pool->ele;    /* funk rec arena */
  fd_wksp_t *     data_wksp = accdb->vinyl->data->laddr0;

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

    if( funk_gc_chain( NULL, funk, cur ) ) {
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
          accdb_invalidate_line( line, ele0, data, cur_line_idx, ele_idx );
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

        /* Update meta (prepare/publish for existing element) */
        fd_vinyl_meta_prepare_fast( lock, lock_shift, ele_idx );

        ele0[ ele_idx ].phdr.ctl  =
            fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR,
                                  FD_VINYL_BSTREAM_CTL_STYLE_RAW,
                                  val_sz );
        ele0[ ele_idx ].phdr.info = info;
        ele0[ ele_idx ].seq       = seq;
      //ele0[ ele_idx ].line_idx    already ULONG_MAX (invalidated or was uncached)

        fd_vinyl_meta_publish_fast( lock, lock_shift, ele_idx );

      } else {
        /* New key — insert */

        /* Append to bstream first (need seq for meta) */
        ulong seq = fd_vinyl_io_append_pair_raw( io, key, &info,
                                                 (void const *)acct );
        append_cnt++;

        /* Insert into meta at the empty slot.  Per meta.h safety tip:
           "Inserting without doing a prepare is fine so long as
           phdr.ctl becomes visible last." */

        ele0[ ele_idx ].memo       = memo;
        ele0[ ele_idx ].phdr.key   = *key;
        ele0[ ele_idx ].phdr.info  = info;
        ele0[ ele_idx ].seq        = seq;
        ele0[ ele_idx ].line_idx   = ULONG_MAX;
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
          accdb_invalidate_line( line, ele0, data, cur_line_idx, ele_idx );
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
  }

  /* Commit result */
  if( FD_LIKELY( append_cnt ) ) {
    fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING );
  }

  /* Remove funk records */

  for( ulong i=0UL; i<rec_cnt; i++ ) {
    fd_funk_xid_key_pair_t pair = recs[ i ]->pair;
    fd_funk_rec_query_t query[1];
    int rm_err = fd_funk_rec_map_remove( funk->rec_map, &pair, NULL, query, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( rm_err!=FD_MAP_SUCCESS ) ) FD_LOG_CRIT(( "fd_funk_rec_map_remove failed (%i-%s)", rm_err, fd_map_strerror( rm_err ) ));
    funk_free_rec( funk, recs[ i ] );
  }

  return next;
}
