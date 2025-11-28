#include "fd_vinyl.h"
#include "fd_vinyl_recover_serial.c"

#define PEEK( seq ) ((fd_vinyl_bstream_block_t *)(mmio + ((seq) % mmio_sz)))

/* fd_vinyl_recover_test tests if parallel recovery is possible. */

static int
fd_vinyl_recover_test( fd_vinyl_io_t * io ) {

  uchar * mmio = (uchar *)fd_vinyl_mmio( io );

  if( FD_UNLIKELY( !mmio ) ) {
    FD_LOG_NOTICE(( "bstream io interface type does not support parallel memory mapped io"
                    "\n\tfalling back to serial recovery" ));
    return FD_VINYL_ERR_INVAL;
  }

  ulong mmio_sz = fd_vinyl_mmio_sz( io );

  ulong seq_past    = fd_vinyl_io_seq_past   ( io );
  ulong seq_present = fd_vinyl_io_seq_present( io );
  ulong io_seed     = fd_vinyl_io_seed       ( io );

//ulong tstone_req = 0UL;

  ulong seq1 = seq_present;
  while( fd_vinyl_seq_gt( seq1, seq_past ) ) {

    /* At this point, we've tested [seq1,seq_present) is suitable for
       parallel recovery.  Peek at the block just before seq1.  If it is
       not a valid partition block, we can't do parallel recovery. */

    ulong part_seq = seq1 - FD_VINYL_BSTREAM_BLOCK_SZ;

    fd_vinyl_bstream_block_t block[1];

    block[0] = *PEEK( part_seq );

    char const * _err = fd_vinyl_bstream_part_test( io_seed, part_seq, block ); /* testing changes the block */
    if( FD_UNLIKELY( _err ) ) {
      FD_LOG_WARNING(( "bstream past does not have a valid partitioning"
                       "\n\tseq %016lx: %s"
                       "\n\tprevious bstream writers probably did not terminate cleanly"
                       "\n\tfalling back to serial recovery", part_seq, _err ));
      return FD_VINYL_ERR_CORRUPT;
    }

    /* We got a valid partition block.  Determine the start of this
       partition. */

    ulong seq0 = block->part.seq0;
    seq0 = fd_vinyl_seq_gt( seq0, seq_past ) ? seq0 : seq_past;

#   if 0
    /* Compute the maximum number of deads the portion of this partition
       in the bstream's past that could produce as the lesser the number
       of deads reported in the partition and the number of blocks in
       the partition.  Similarly for move (note that each move makes two
       tombstone but also requires at least two blocks ... so moves also
       make, at most, 1 tombstone per block on average). */

    ulong part_sz  = seq1 - seq0 - FD_VINYL_BSTREAM_BLOCK_SZ; /* exclude trailing part block for below */

    ulong dead_max = fd_ulong_min( block->part.dead_cnt, part_sz );
    ulong move_max = fd_ulong_min( block->part.move_cnt, part_sz );

    tstone_req += fd_ulong_min( dead_max + 2UL*move_max, part_sz );
#   endif

    /* Move to the previous partition */

    seq1 = seq0;
  }

  /* We seem to have a valid partitioning for parallel recovery */

# if 0
  if( FD_UNLIKELY( tstone_req > tstone_max ) ) {
    FD_LOG_WARNING(( "insufficient scratch space for parallel recovery"
                     "\n\tincrease data cache size"
                     "\n\tfalling back to serial recovery" ));
    return FD_VINYL_ERR_FULL;
  }
# endif

  return FD_VINYL_SUCCESS;
}

/* fd_vinyl_recover_line_task tests parallel flushes all vinyl
   lines and resets the evicition priority sequence. */

static FD_FOR_ALL_BEGIN( fd_vinyl_recover_line_task, 1L ) {
  fd_vinyl_t * vinyl = (fd_vinyl_t *)arg[0];

  fd_vinyl_line_t * line     = vinyl->line;
  ulong             line_cnt = vinyl->line_cnt;

  ulong line0 = (ulong)block_i0;
  ulong line1 = (ulong)block_i1;

  for( ulong line_idx=line0; line_idx<line1; line_idx++ ) {
    line[ line_idx ].obj            = NULL;
    line[ line_idx ].ele_idx        = ULONG_MAX;
    line[ line_idx ].ctl            = fd_vinyl_line_ctl( 0UL, 0L);
    line[ line_idx ].line_idx_older = (uint)fd_ulong_if( line_idx!=0UL,          line_idx-1UL, line_cnt-1UL );
    line[ line_idx ].line_idx_newer = (uint)fd_ulong_if( line_idx!=line_cnt-1UL, line_idx+1UL, 0UL          );
  }

} FD_FOR_ALL_END

/* fd_vinyl_recover_reclaim_task parallel locks all the meta locks,
   reclaiming any that were locked from presumably dead writers that
   terminated uncleanly.  Returns the number of locks reclaimed. */

static FD_MAP_REDUCE_BEGIN( fd_vinyl_recover_reclaim_task, 1L, alignof(ulong), sizeof(ulong), 1UL ) {
  ulong      * _reclaim_cnt = (ulong *)     arg[0];
  fd_vinyl_t * vinyl        = (fd_vinyl_t *)arg[1];

  ulong * lock = vinyl->meta->lock;

  ulong reclaim_cnt = 0UL;

  for( long lock_idx=block_i0; lock_idx<block_i1; lock_idx++ ) {
#   if FD_HAS_ATOMIC
    ulong l = FD_ATOMIC_FETCH_AND_OR( &lock[ lock_idx ], 1UL );
#   else
    ulong l = lock[ lock_idx ];
    lock[ lock_idx ] |= 1UL;
#   endif
    reclaim_cnt += l & 1UL;
  }

  *_reclaim_cnt = reclaim_cnt;

} FD_MAP_END {

  *(ulong *)arg[0] += *(ulong const *)_r1;

} FD_REDUCE_END

/* fd_vinyl_recover_meta_flush_task tests parallel clears the meta
   element storage.  Assumes the meta is fully locked. */

static FD_FOR_ALL_BEGIN( fd_vinyl_recover_meta_flush_task, 1L ) {
  fd_vinyl_t * vinyl = (fd_vinyl_t *)arg[0];

  fd_vinyl_meta_ele_t * ele0 = vinyl->meta->ele;

  fd_vinyl_meta_ele_t init_ele[1];
  memset( init_ele, 0, sizeof(fd_vinyl_meta_ele_t) );
  init_ele->line_idx = ULONG_MAX;

  for( long ele_idx=block_i0; ele_idx<block_i1; ele_idx++ ) ele0[ ele_idx ] = init_ele[0];

} FD_FOR_ALL_END

/* fd_vinyl_recover_unlock_task tests parallel unlocks all the meta
   locks.  Assumes the meta is fully locked. */

static FD_FOR_ALL_BEGIN( fd_vinyl_recover_unlock_task, 1L ) {
  fd_vinyl_t * vinyl = (fd_vinyl_t *)arg[0];

  ulong * lock = vinyl->meta->lock;

  for( long lock_idx=block_i0; lock_idx<block_i1; lock_idx++ ) lock[ lock_idx ]++;

} FD_FOR_ALL_END

/* fd_vinyl_recover_tstone inserts a tstone for key at seq in the meta
   if there isn't anything beyond seq for key already.  Returns SUCCESS
   on success and FD_VINYL_ERR code on failure.  This will update the
   pair_cnt, garbage_sz and tstone_cnt counters appropriately. */

static int
fd_vinyl_recover_tstone( fd_vinyl_meta_t *      meta,
                         fd_vinyl_key_t const * key,
                         ulong                  seq,
                         ulong *                _pair_cnt,
                         ulong *                _garbage_sz,
                         ulong *                _tstone_cnt ) {

  /* Query meta for key */

  fd_vinyl_meta_query_t query[1];

  fd_vinyl_meta_prepare( meta, key, NULL, query, FD_MAP_FLAG_BLOCKING );

  fd_vinyl_meta_ele_t * ele = fd_vinyl_meta_query_ele( query );

  if( FD_UNLIKELY( !ele ) ) {
    FD_LOG_NOTICE(( "%016lx: increase meta cache size for parallel recovery or corruption", seq ));
    return FD_VINYL_ERR_FULL;
  }

  if( FD_LIKELY( !ele->phdr.ctl ) ) {

    /* There is no version or tstone for pair key in the meta currently.
       Insert a tstone at seq for key so any versions or tstone for pair
       key encountered later in parallel recovery can tell if they are
       before or after this tstone.  Because we don't know if there will
       version of key after this, we need to append key to the tstone
       array. */

   //pair_cnt   unchanged
   //garbage_sz unchanged
    (*_tstone_cnt)++;

    ele->memo      = fd_vinyl_meta_query_memo( query );
    ele->phdr.ctl  = 1UL;
    ele->phdr.key  = *key;
  //ele->phdr.info = d/c
    ele->line_idx  = ULONG_MAX - 1UL; // tstone
    ele->seq       = seq;

    fd_vinyl_meta_publish( query );

  } else if( FD_LIKELY( fd_vinyl_seq_lt( ele->seq, seq ) ) ) {

    /* The version (or tstone) for pair key in the meta is older than
       seq.  We append a key to the tstone array if we haven't already. */

    int old_ele_is_pair = (ele->line_idx==ULONG_MAX);

    (*_pair_cnt)   -= (ulong)old_ele_is_pair;
    (*_garbage_sz) +=        old_ele_is_pair ? fd_vinyl_bstream_pair_sz( fd_vinyl_bstream_ctl_sz( ele->phdr.ctl ) ) : 0UL;
    (*_tstone_cnt) += (ulong)old_ele_is_pair;

  //ele->memo      = already init
  //ele->phdr.ctl  = already init
  //ele->phdr.key  = already init
  //ele->phdr.info = d/c
    ele->line_idx  = ULONG_MAX - 1UL; // tstone
    ele->seq       = seq;

    fd_vinyl_meta_publish( query );

  } else {

    /* The meta entry (pair or tstone) for pair key in the meta is newer
       than seq.  We can skip this tstone. */

   //pair_cnt   unchanged
   //garbage_sz unchanged
   //tstone_cnt unchanged

    int corrupt = fd_vinyl_seq_eq( ele->seq, seq );

    fd_vinyl_meta_cancel( query );

    if( FD_UNLIKELY( corrupt ) ) {
      FD_LOG_WARNING(( "%016lx: probable corruption detected", seq ));
      return FD_VINYL_ERR_CORRUPT;
    }

  }

  return FD_VINYL_SUCCESS;
}

/* fd_vinyl_recover_part_task dynamically assigns the partitions of the
   bstream's past to threads for recovery and then recovers them in
   parallel.  The bstream past partition iteration is near identical
   to bstream past iteration in serial recovery.  See
   fd_vinyl_recover_serial.c for more details. */

/* FIXME: ADD MORE EXTENSIVE DATA INTEGRITY CHECKING LIKE SERIAL IMPL */

static FD_FN_UNUSED FD_MAP_REDUCE_BEGIN( fd_vinyl_recover_part_task, 1UL, alignof(ulong), sizeof(ulong), 4UL ) {
  ulong *          _rlocal    = (ulong *)         arg[0];
  fd_vinyl_t *     vinyl      = (fd_vinyl_t *)    arg[1];
  ulong *          _lock      = (ulong *)         arg[2];

  fd_vinyl_io_t *   io   = vinyl->io;
  fd_vinyl_meta_t * meta = vinyl->meta;

  ulong   io_seed  =          fd_vinyl_io_seed    ( io );
  ulong   seq_past =          fd_vinyl_io_seq_past( io );
  uchar * mmio     = (uchar *)fd_vinyl_mmio       ( io );
  ulong   mmio_sz  =          fd_vinyl_mmio_sz    ( io );

  ulong fail       = 1UL;
  ulong pair_cnt   = 0UL;
  ulong garbage_sz = 0UL;
  ulong tstone_cnt = 0UL;

  for(;;) {

    /* Determine the range of the bstream past we should process next. */

    ulong seq0;
    ulong seq1;

    /* Lock and fetch the task assignment cursor */

    FD_COMPILER_MFENCE();
#   if FD_HAS_ATOMIC
    while( FD_ATOMIC_CAS( _lock, 0UL, 1UL ) ) FD_SPIN_PAUSE();
#   else
    *_lock = 1UL;
#   endif
    FD_COMPILER_MFENCE();

    seq1 = _lock[1];

    /* At this point, the bstream range [seq_past,seq1) has not been
       assigned.  If seq1 is at seq_past, everything has been assigned
       already.  Otherwise, the block before cursor is a valid partition
       block (as per the test above) and we claim the range:

         [ the older of part_seq0 and seq_past, seq1 )

       to process. */

    if( FD_UNLIKELY( fd_vinyl_seq_le( seq1, seq_past ) ) ) seq0 = seq_past;
    else {
      fd_vinyl_bstream_block_t const * block = PEEK( seq1 - FD_VINYL_BSTREAM_BLOCK_SZ );
      seq0 = block->part.seq0;
      if( fd_vinyl_seq_lt( seq0, seq_past ) ) seq0 = seq_past;
    }

    /* Update and unlock the task assignment cursor */

    _lock[1] = seq0;
    FD_COMPILER_MFENCE();
    _lock[0] = 0UL;
    FD_COMPILER_MFENCE();

    if( FD_UNLIKELY( fd_vinyl_seq_le( seq1, seq_past ) ) ) break;

    /* At this point, we need to recover the range [seq0,seq1). */

    ulong seq = seq0;
    while( fd_vinyl_seq_lt( seq, seq1 ) ) {

      fd_vinyl_bstream_block_t block[1];

      block[0] = *(fd_vinyl_bstream_block_t *)PEEK( seq ); /* testing is destructive */

      ulong ctl = block->ctl;

      int type = fd_vinyl_bstream_ctl_type( ctl );

      switch( type ) {

      case FD_VINYL_BSTREAM_CTL_TYPE_PAIR: {

        ulong pair_val_esz = fd_vinyl_bstream_ctl_sz( ctl );

        ulong pair_sz = fd_vinyl_bstream_pair_sz( pair_val_esz );

        if( FD_UNLIKELY( pair_sz > (seq1-seq) ) ) { /* Wrapping safe */
          FD_LOG_WARNING(( "%016lx: truncated", seq ));
          goto done;
        }

        fd_vinyl_bstream_block_t ftr[1];

        ftr[0] = *PEEK( seq + pair_sz - FD_VINYL_BSTREAM_BLOCK_SZ );

        char const * _err = fd_vinyl_bstream_pair_test_fast( io_seed, seq, block, ftr );
        if( FD_UNLIKELY( _err ) ) {
          FD_LOG_WARNING(( "%016lx: %s", seq, _err ));
          goto done;
        }

        /* At this point, we appear to have valid completely written
           pair.  Prepare the meta to do an update for this key. */

        fd_vinyl_meta_query_t query[1];

        fd_vinyl_meta_prepare( meta, &block->phdr.key, NULL, query, FD_MAP_FLAG_BLOCKING );

        fd_vinyl_meta_ele_t * ele = fd_vinyl_meta_query_ele( query );

        if( FD_UNLIKELY( !ele ) ) {
          FD_LOG_WARNING(( "%016lx: corruption detected or meta cache too small for parallel recovery", seq ));
          goto done;
        }

        if( FD_LIKELY( (!ele->phdr.ctl) | fd_vinyl_seq_gt( seq, ele->seq ) ) ) {

          pair_cnt++;

          /* At this point, this is the first time any thread has seen
             pair key or this version of pair key is newer than the
             version (or tstone) of pair key has been seed */

          ele->memo     = fd_vinyl_meta_query_memo( query );
          ele->phdr     = block->phdr;
          ele->line_idx = ULONG_MAX;   // pair
          ele->seq      = seq;

          fd_vinyl_meta_publish( query );

        } else {

          /* At this point, this version of pair key is older than the
             version (or tstone) for pair key seen by all threads so
             far. */

          fd_vinyl_meta_cancel( query );

          garbage_sz += pair_sz;

        }

        seq += pair_sz;
        break;
      }

      case FD_VINYL_BSTREAM_CTL_TYPE_DEAD: {

        char const * _err = fd_vinyl_bstream_dead_test( io_seed, seq, block );
        if( FD_UNLIKELY( _err ) ) {
          FD_LOG_WARNING(( "%016lx: %s", seq, _err ));
          goto done;
        }

        int err = fd_vinyl_recover_tstone( meta, &block->dead.phdr.key, seq, &pair_cnt, &garbage_sz, &tstone_cnt );
        if( FD_UNLIKELY( err ) ) goto done; /* logs details */

        garbage_sz += FD_VINYL_BSTREAM_BLOCK_SZ;
        seq        += FD_VINYL_BSTREAM_BLOCK_SZ;
        break;
      }

      case FD_VINYL_BSTREAM_CTL_TYPE_MOVE: {

        if( FD_UNLIKELY( 2UL*FD_VINYL_BSTREAM_BLOCK_SZ > (seq1-seq) ) ) { /* Wrapping safe */
          FD_LOG_WARNING(( "%016lx: truncated", seq ));
          goto done;
        }

        fd_vinyl_bstream_block_t dst[1];

        dst[0] = *PEEK( seq + FD_VINYL_BSTREAM_BLOCK_SZ );

        char const * _err = fd_vinyl_bstream_move_test( io_seed, seq, block, dst );
        if( FD_UNLIKELY( _err ) ) {
          FD_LOG_WARNING(( "%016lx: %s", seq, _err ));
          goto done;
        }

        int  err = fd_vinyl_recover_tstone( meta, &block->move.src.key, seq, &pair_cnt, &garbage_sz, &tstone_cnt );
        if( FD_UNLIKELY( err ) ) goto done; /* logs details */

        /**/ err = fd_vinyl_recover_tstone( meta, &block->move.dst,     seq, &pair_cnt, &garbage_sz, &tstone_cnt );
        if( FD_UNLIKELY( err ) ) goto done; /* logs details */

        garbage_sz += FD_VINYL_BSTREAM_BLOCK_SZ;
        seq        += FD_VINYL_BSTREAM_BLOCK_SZ;
        break;
      }

      case FD_VINYL_BSTREAM_CTL_TYPE_PART: {

        char const * _err = fd_vinyl_bstream_part_test( io_seed, seq, block );
        if( FD_UNLIKELY( _err ) ) {
          FD_LOG_WARNING(( "%016lx: %s", seq, _err ));
          goto done;
        }

        garbage_sz += FD_VINYL_BSTREAM_BLOCK_SZ;
        seq        += FD_VINYL_BSTREAM_BLOCK_SZ;
        break;
      }

      case FD_VINYL_BSTREAM_CTL_TYPE_ZPAD: {

        char const * _err = fd_vinyl_bstream_zpad_test( io_seed, seq, block );
        if( FD_UNLIKELY( _err ) ) {
          FD_LOG_WARNING(( "%016lx: %s", seq, _err ));
          goto done;
        }

        seq += FD_VINYL_BSTREAM_BLOCK_SZ;
        break;
      }

      default:
        FD_LOG_WARNING(( "%016lx: unknown type (%x)", seq, (uint)type ));
        goto done;

      }
    }

    if( FD_UNLIKELY( fd_vinyl_seq_ne( seq, seq1 ) ) ) {
      FD_LOG_WARNING(( "%016lx: bad partitioning", seq ));
      goto done;
    }

  }

  fail = 0UL;

done:

  /* If we failed, tell all the other threads to not continue by
     setting the task assignment cursor to seq_past. */

  if( fail ) {
    FD_COMPILER_MFENCE();
#   if FD_HAS_ATOMIC
    while( FD_ATOMIC_CAS( _lock, 0UL, 1UL ) ) FD_SPIN_PAUSE();
#   else
    *_lock = 1UL;
#   endif
    FD_COMPILER_MFENCE();
    _lock[1]= seq_past;
    FD_COMPILER_MFENCE();
    _lock[0]= 0UL;
  }

  _rlocal[0] = fail;
  _rlocal[1] = pair_cnt;
  _rlocal[2] = garbage_sz;
  _rlocal[3] = tstone_cnt;

} FD_MAP_END {

  ulong       * _rlocal  = (ulong *)      arg[0];
  ulong const * _rremote = (ulong const *)_r1;

  _rlocal[0] |= _rremote[0];
  _rlocal[1] += _rremote[1];
  _rlocal[2] += _rremote[2];
  _rlocal[3] += _rremote[3];

} FD_REDUCE_END

static FD_FN_UNUSED FD_MAP_REDUCE_BEGIN( fd_vinyl_recover_meta_cleanup_task, 1L, alignof(ulong), sizeof(ulong), 1UL ) {
  ulong * _rlocal = (ulong *)arg[0];

  fd_vinyl_t * vinyl = (fd_vinyl_t *)arg[1];

  fd_vinyl_meta_t * meta = vinyl->meta;

  fd_vinyl_meta_ele_t * ele0       = meta->ele;
  ulong const         * lock       = meta->lock;
  int                   lock_shift = meta->lock_shift;

  ulong remove_cnt = 0UL;

  for( long ele_idx=block_i0; ele_idx<block_i1; ele_idx++ ) {
    long lock_idx = ele_idx >> lock_shift;

    fd_vinyl_key_t key;
    int            try_remove;

    /* Do a non-blocking query by ele_idx (not be key).  We have to do
       this direct because this is no standard API for this.  This is
       highly unlikely to ever block (but theoretically could if the
       remove in a different thread has locked a probe chain that
       touches elements in this thread). */

    for(;;) {
      FD_COMPILER_MFENCE();
      ulong ver0 = lock[ lock_idx ];
      FD_COMPILER_MFENCE();
      if( FD_LIKELY( !(ver0 & 1UL) ) ) {

        try_remove = (!!ele0[ ele_idx ].phdr.ctl) & (ele0[ ele_idx ].line_idx==(ULONG_MAX-1UL));
        key        = ele0[ ele_idx ].phdr.key;

        FD_COMPILER_MFENCE();
        ulong ver1 = lock[ lock_idx ];
        FD_COMPILER_MFENCE();
        if( FD_LIKELY( ver0==ver1 ) ) break;
      }
      FD_SPIN_PAUSE();
    }

    /* If try_remove is not set, ele_idx either had no key it in or
       had a pair entry.  So we continue to the next slot. */

    if( FD_LIKELY( !try_remove ) ) continue;

    /* At this point, we observed key had a tstone in the meta above.
       So we try to remove it.  It is possible (though extremely
       unlikely for big sparse maps and the vanilla thread partitioning
       here) that a remove on another thread got key first.  So it is
       okay if this fails.  We have to use the parallel version of this
       (even if it is highly unlikely to interfere with other threads)
       for the same reason we had to use a non-blocking query above. */

    fd_vinyl_meta_query_t query[1];
    remove_cnt += (ulong)!fd_vinyl_meta_remove( meta, &key, query, FD_MAP_FLAG_BLOCKING );
  }

  *_rlocal = remove_cnt;

} FD_MAP_END {

  ulong       * _rlocal  = (ulong *)      arg[0];
  ulong const * _rremote = (ulong const *)_r1;

  *_rlocal += *_rremote;

} FD_REDUCE_END

ulong
fd_vinyl_recover( fd_tpool_t * tpool, ulong t0, ulong t1, int level,
                  fd_vinyl_t * vinyl ) {

  fd_vinyl_meta_t * meta     = vinyl->meta;
  ulong             line_cnt = vinyl->line_cnt;

  ulong ele_max  = meta->ele_max;
  ulong lock_cnt = meta->lock_cnt;

  /* Using all avaialble threads, flush the lines and meta cache.  We do
     the meta flush locked so we don't confuse any concurrent meta
     readers.  This will claim any existing locks (e.g.  the previous
     meta writer died while holding a lock and the user didn't clean it
     up before calling this). */

  ulong reclaim_cnt;

  FD_FOR_ALL   ( fd_vinyl_recover_line_task,       tpool,t0,t1, 0L,(long)line_cnt,               vinyl );
  FD_MAP_REDUCE( fd_vinyl_recover_reclaim_task,    tpool,t0,t1, 0L,(long)lock_cnt, &reclaim_cnt, vinyl );
  FD_FOR_ALL   ( fd_vinyl_recover_meta_flush_task, tpool,t0,t1, 0L,(long)ele_max,                vinyl );
  FD_FOR_ALL   ( fd_vinyl_recover_unlock_task,     tpool,t0,t1, 0L,(long)lock_cnt,               vinyl );

  if( FD_UNLIKELY( reclaim_cnt ) ) FD_LOG_WARNING(( "reclaimed %lu locks (dead writer?); attempting to continue", reclaim_cnt ));

  /* FIXME: should this fail if it detects in progress io? */

  /* If there is only 1 thread provided or the bstream past doesn't
     have a valid partitioning, use the serial recovery algorithm */

t1 = t0 + 1UL; /* Turn off parallel recovery while it is untested */

  if( FD_UNLIKELY( (t1-t0)<=1UL                     ) ||
      FD_UNLIKELY( fd_vinyl_recover_test( vinyl->io ) ||
      !FD_HAS_ATOMIC ) ) {
    fd_vinyl_data_reset( tpool,t0,t1, level, vinyl->data );
    return fd_vinyl_recover_serial( vinyl );
  }

# if FD_HAS_ATOMIC

  /* The parallel recovery of bstream partition may leave tstones in the
     meta elements.  To clean this up, we have two options.

     Option 1 (simplest and most robust): we parallel scan all the meta
     elements in parallel for tstones and remove them.  We might have to
     do more than one pass because the removal of elements could mean
     some elements are not placed well.  This requires no scratch (and
     thus is more robust against arbitrary erase / move patterns in the
     recovery region).  While it isn't any less algo inefficient
     (because we paralllel scan all the elements already to clear them),
     it is pracitcally less efficient for applications access patterns
     that don't generate many tombstones and/or have pair_cnt<<pair_max.

     Option 2 (fastest but trickiest): we append the keys that might
     have tstones at the end of partition processing in a scratch memory
     during the parallel recovery.  The vinyl data cache region is huge,
     well aligned, not used at this point.  So it can handle all but the
     most extreme tstone generate application patterns.  We can store
     either the key directly in the scratch or the location in the
     bstream (faster but more scratch efficient) or the bstream seq of
     the dead / move that generated the tstone (slower but more scratch
     efficient).  We further can use the aux information in the
     partition to tighly bound the worst case number of tstones required
     up front.  But this is tricky because the srcatch array needs to
     have the partition processing tasks append to it in parallel.  So
     we either have to use atomic increments in the inner loop (yuck) or
     we have to partition the array up front (keeping fingers crossed
     that a uniform distribution assumption is valid) and then
     concatenate the partitions for parallel processing (yuck) or have
     the parallel cleanup processing work with non-compactly stored
     scratch (yuck).

     (There is a hybrid option where this tries to do option 2 but if
     scratch runs out on any thread, use option 1 to clean up tstones in
     meta.)

     We go with the simplest and robust implementation below.

     FIXME: regardless of the above, it is theoretically possible for
     the number of used meta elements that need to be tracked
     intermediate to exceed meta pair_max even if the final state at
     seq_present can be stored in pair_max.  We retry with a serial
     recovery if parallel recovery fails. */

  ulong seq = fd_vinyl_io_seq_present( vinyl->io );

  ulong rtmp[4];
  ulong lock[2];

  lock[0] = 0UL;
  lock[1] = seq;

  FD_MAP_REDUCE( fd_vinyl_recover_part_task, tpool,t0,t1, 0L,(long)(t1-t0), rtmp, vinyl, lock );

  ulong fail = rtmp[0];
  if( FD_UNLIKELY( fail ) ) {
    FD_LOG_WARNING(( "parallel recovery failed; attempting serial recovery" ));

    /* Reset the meta from whatever messy state failed parallel recovery
       left it */

    FD_MAP_REDUCE( fd_vinyl_recover_reclaim_task,    tpool,t0,t1, 0L,(long)lock_cnt, &reclaim_cnt, vinyl );
    FD_FOR_ALL   ( fd_vinyl_recover_meta_flush_task, tpool,t0,t1, 0L,(long)ele_max,                vinyl );
    FD_FOR_ALL   ( fd_vinyl_recover_unlock_task,     tpool,t0,t1, 0L,(long)lock_cnt,               vinyl );

    fd_vinyl_data_reset( tpool,t0,t1, level, vinyl->data );

    return fd_vinyl_recover_serial( vinyl );
  }

  vinyl->pair_cnt   = rtmp[1];
  vinyl->garbage_sz = rtmp[2];

  ulong tstone_rem = rtmp[3];

  while( tstone_rem ) {
    FD_FOR_ALL( fd_vinyl_recover_meta_cleanup_task, tpool,t0,t1, 0L,(long)ele_max, rtmp, vinyl );
    tstone_rem -= rtmp[0];
  }

  /* Reset the data cache to clean up any scratch usage (currently none
     but no reason to do earlier) */

  fd_vinyl_data_reset( tpool,t0,t1, level, vinyl->data );

  return seq;

# endif /* FD_HAS_ATOMIC */
}
