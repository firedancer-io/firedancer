/* This is included directly by fd_vinyl_recover.c */

ulong
fd_vinyl_recover_serial( fd_vinyl_t * vinyl ) {

  /* Iterate over the bstream's past to populate the meta.  Note that
     our caller flushed the meta cache, data cache and reset the cache
     line eviction priorities to their default. */

  fd_vinyl_meta_t * meta = vinyl->meta;
  fd_vinyl_line_t * line = vinyl->line;
  fd_vinyl_io_t *   io   = vinyl->io;

  ulong line_cnt = vinyl->line_cnt;
  ulong pair_max = vinyl->pair_max;

  ulong io_seed     = fd_vinyl_io_seed       ( io );
  ulong seq_past    = fd_vinyl_io_seq_past   ( io );
  ulong seq_present = fd_vinyl_io_seq_present( io );

  fd_vinyl_meta_ele_t * ele0       = meta->ele;
  ulong                 ele_max    = meta->ele_max;
  ulong                 meta_seed  = meta->seed;
  ulong *               lock       = meta->lock;
  int                   lock_shift = meta->lock_shift;

  ulong seq        = seq_past;
  ulong pair_cnt   = 0UL;
  ulong garbage_sz = 0UL;

  while( fd_vinyl_seq_lt( seq, seq_present ) ) {

    /* At this point, we've recovered [seq_past,seq) and still need
       recover [seq,seq_present) (non-empty).  Read the block at seq. */

    fd_vinyl_bstream_block_t block[1];

    fd_vinyl_io_read_imm( io, seq, block, FD_VINYL_BSTREAM_BLOCK_SZ );

    ulong ctl = block->ctl;

    int type = fd_vinyl_bstream_ctl_type( ctl );

    switch( type ) {

    case FD_VINYL_BSTREAM_CTL_TYPE_PAIR: {

      /* Notes:

         - It is okay if we are in a move (move block processing the
           previous iteration already confirmed this is the proper pair.

         - We could rewind the bstream to seq on truncation
           automatically but then we might have failed to recover the
           most recent pair and thus have recovered to a state that does
           not correspond to the bstream's past.  We instead kick this
           to the user to decide if they want to discard an incompletely
           written pair or not. */

      ulong pair_val_esz = fd_vinyl_bstream_ctl_sz( ctl );

      ulong pair_sz = fd_vinyl_bstream_pair_sz( pair_val_esz );

      if( FD_UNLIKELY( pair_sz > (seq_present-seq) ) ) { /* Wrapping safe */
        FD_LOG_WARNING(( "%016lx: truncated", seq ));
        goto done;
      }

      fd_vinyl_bstream_block_t   _ftr[1];
      fd_vinyl_bstream_block_t * ftr = _ftr;

      if( pair_sz <= FD_VINYL_BSTREAM_BLOCK_SZ ) ftr = block;
      else fd_vinyl_io_read_imm( io, seq + pair_sz - FD_VINYL_BSTREAM_BLOCK_SZ, ftr, FD_VINYL_BSTREAM_BLOCK_SZ );

      char const * _err = fd_vinyl_bstream_pair_test_fast( io_seed, seq, block, ftr );
      if( FD_UNLIKELY( _err ) ) {
        FD_LOG_WARNING(( "%016lx: %s", seq, _err ));
        goto done;
      }

      /* At this point, we appear to have valid completely written pair.
         Extract the pair metadata and determine if this replaces a
         version we've already seen.  Since this single threaded, we can
         use the single threaded optimized meta APIs here. */

      fd_vinyl_key_t const * pair_key = &block->phdr.key;

      ulong pair_memo = fd_vinyl_key_memo( meta_seed, pair_key );

      ulong _ele_idx; /* avoid pointer escape */
      int   err = fd_vinyl_meta_query_fast( ele0, ele_max, pair_key, pair_memo, &_ele_idx );
      ulong ele_idx = _ele_idx;

      if( FD_LIKELY( err==FD_VINYL_ERR_KEY ) ) {

        /* This is the first time we've seen pair key or pair key was
           erased in a previous iteration (e.g. we most recently
           processed an erase for pair key or we are in a move).  If we
           have room for pair key, insert it into the meta at ele_idx. */

        if( FD_UNLIKELY( pair_cnt>=pair_max ) ) {
          FD_LOG_WARNING(( "%016lx: increase pair_max", seq ));
          goto done;
        }

        ele0[ ele_idx ].memo     = pair_memo;
        ele0[ ele_idx ].phdr     = block->phdr;
        ele0[ ele_idx ].seq      = seq;
        ele0[ ele_idx ].line_idx = ULONG_MAX;   /* key-val not in cache */

        pair_cnt++;

      } else if( FD_LIKELY( !err ) ) {

        /* This is a more recent version of a pair we saw previously and
           meta element ele_idx currently maps pair key to this previous
           version.  Mark the old version as garbage to collect in the
           future and update the mapping to this version. */

        ulong old_pair_ctl = ele0[ ele_idx ].phdr.ctl;

        ulong old_pair_val_esz = fd_vinyl_bstream_ctl_sz( old_pair_ctl );

        garbage_sz += fd_vinyl_bstream_pair_sz( old_pair_val_esz );

      //ele0[ ele_idx ].memo     = pair_memo;   /* already current */
        ele0[ ele_idx ].phdr     = block->phdr;
        ele0[ ele_idx ].seq      = seq;
      //ele0[ ele_idx ].line_idx = ULONG_MAX;   /* already current */

      } else {

        FD_LOG_WARNING(( "%016lx: corrupt meta", seq ));
        goto done;

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

      /* At this point, we appear to have a valid DEAD block.  Look up
         the pair it erases. */

      ulong pair_val_esz = fd_vinyl_bstream_ctl_sz( block->dead.phdr.ctl );

      fd_vinyl_key_t const * pair_key = &block->dead.phdr.key;

      ulong pair_memo = fd_vinyl_key_memo( meta_seed, pair_key );

      ulong _ele_idx; /* avoid pointer escape */
      int   err = fd_vinyl_meta_query_fast( ele0, ele_max, pair_key, pair_memo, &_ele_idx );
      ulong ele_idx = _ele_idx;;

      if( FD_LIKELY( err==FD_VINYL_ERR_KEY ) ) {

        /* This erases the most recent version of pair key in the
           bstream's antiquity or is a redundant erase block (which is
           arguably an error but, as we can't tell the difference at
           this point, we assume the more likely antiquity case).  In
           short, there's nothing to do but mark this block as garbage
           to collect in the future. */

        garbage_sz += FD_VINYL_BSTREAM_BLOCK_SZ;

      } else {

        /* This erases the most recent version of pair key we've
           processed.  Validate the erasure target is correct.  If so,
           mark this block and that version of pair key as garbage for
           future collection and remove pair key from the meta. */

        int bad_order = fd_vinyl_seq_ge( ele0[ ele_idx ].seq, seq );
        int bad_phdr  = !!memcmp( &ele0[ ele_idx ].phdr, &block->dead.phdr, sizeof(fd_vinyl_bstream_phdr_t) );

        if( FD_UNLIKELY( bad_order | bad_phdr ) ) {
          FD_LOG_WARNING(( "%016lx: %s", seq, bad_order ? "unordered sequence" : "mismatched dead pair metadata" ));
          goto done;
        }

        garbage_sz += FD_VINYL_BSTREAM_BLOCK_SZ + fd_vinyl_bstream_pair_sz( pair_val_esz );

        fd_vinyl_meta_remove_fast( ele0, ele_max, lock, lock_shift, line, line_cnt, ele_idx );

        FD_CRIT( pair_cnt, "corruption detected" );
        pair_cnt--;

      }

      seq += FD_VINYL_BSTREAM_BLOCK_SZ;
      break;

    }

    case FD_VINYL_BSTREAM_CTL_TYPE_MOVE: {

      if( FD_UNLIKELY( 2UL*FD_VINYL_BSTREAM_BLOCK_SZ > (seq_present-seq) ) ) { /* Wrapping safe */
        FD_LOG_WARNING(( "%016lx: truncated", seq ));
        goto done;
      }

      fd_vinyl_bstream_block_t dst[1];

      fd_vinyl_io_read_imm( io, seq + FD_VINYL_BSTREAM_BLOCK_SZ, dst, FD_VINYL_BSTREAM_BLOCK_SZ );

      char const * _err = fd_vinyl_bstream_move_test( io_seed, seq, block, dst );
      if( FD_UNLIKELY( _err ) ) {
        FD_LOG_WARNING(( "%016lx: %s", seq, _err ));
        goto done;
      }

      /* At this point, we appear to have a valid move.  Technically, a
         move is an atomic "erase pair src_key if any, erase pair
         dst_key if any, insert pair dst_key with the info src_info_old
         and val src_val_new" where src_val_new is typically the same as
         src_val_old, but, strictly speaking, doesn't have to be.

         We do the "erase pair src_key if any" part of the move here.
         The next iteration will handle rest naturally (including doing
         more extensive validation on the new pair_dst).  Note that if
         the next iteration detects the new pair dst is invalid, it will
         fail recovery in the middle of the move.  So applications
         should be very wary of using a partial recovery as such can
         break move atomicity. */

      ulong                  src_val_esz = fd_vinyl_bstream_ctl_sz( block->move.src.ctl );
      fd_vinyl_key_t const * src_key     = &block->move.src.key;

      ulong src_memo = fd_vinyl_key_memo( meta_seed, src_key );

      ulong _ele_idx; /* avoid pointer escape */
      int   err = fd_vinyl_meta_query_fast( ele0, ele_max, src_key, src_memo, &_ele_idx );
      ulong ele_idx = _ele_idx;

      if( FD_LIKELY( err==FD_VINYL_ERR_KEY ) ) {

        /* This move erases the most recent version of pair src_key in
           the bstream's antiquity or is a redundant move block (which
           is arguably an error but, as we can't tell the difference at
           this point, we assume the more likely antiquity case).  In
           short, there's nothing to do but mark this block as garbage
           to collect in the future. */

        garbage_sz += FD_VINYL_BSTREAM_BLOCK_SZ;

      } else {

        /* This move erases the most recent version of pair src_key
           we've processed.  Validate the erasure target is correct.  If
           so, mark this block and this version of pair src_key as
           garbage for future collection and remove pair src_key from
           the meta. */

        int bad_order = fd_vinyl_seq_ge( ele0[ ele_idx ].seq, seq );
        int bad_cnt   = !pair_cnt;
        int bad_phdr  = !!memcmp( &ele0[ ele_idx ].phdr, &block->move.src, sizeof(fd_vinyl_bstream_phdr_t) );

        if( FD_UNLIKELY( bad_order | bad_cnt | bad_phdr ) ) {
          FD_LOG_WARNING(( "%016lx: %s", seq, bad_order ? "unordered sequence"           :
                                              bad_cnt   ? "corrupt meta"                 :
                                                          "mismatched move src metadata" ));
          goto done;
        }

        garbage_sz += FD_VINYL_BSTREAM_BLOCK_SZ + fd_vinyl_bstream_pair_sz( src_val_esz );

        fd_vinyl_meta_remove_fast( ele0, ele_max, lock, lock_shift, line, line_cnt, ele_idx );

        pair_cnt--;

      }

      /* At this point, we've handled the "erase old src if any" part of
         the move.  The next iteration will handle the "erase old dst if
         any" and the "insert new dst" part of the move.  We know there
         will be a next iteration for a type pair object with the
         appropriate mojo because of the checks we've already done.  So
         moves behave atomically from the point of view of the
         application when fully recovered. */

      seq += FD_VINYL_BSTREAM_BLOCK_SZ;
      break;

    }

    case FD_VINYL_BSTREAM_CTL_TYPE_PART: {

      if( FD_UNLIKELY( fd_vinyl_seq_ne( block->part.seq, seq ) ) ) {
        FD_LOG_WARNING(( "%016lx: unexpected part seq", seq ));
        goto done;
      }

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

      /* Note: zpad blocks aren't included in garbage_sz because we
         don't control when they get created (and thus can't easily
         update garbage_sz to account for them when they are created). */

      seq += FD_VINYL_BSTREAM_BLOCK_SZ;
      break;

    }

    default:
      FD_LOG_WARNING(( "%016lx: unknown type (%x)", seq, (uint)type ));
      goto done;
    }
  }

done:

  /* At this point, the meta is populated appropriately up to seq.
     Update the vinyl state and return.  If we did not get to
     seq_present, we log a warning. */

  vinyl->pair_cnt   = pair_cnt;
  vinyl->garbage_sz = garbage_sz;

  if( FD_UNLIKELY( fd_vinyl_seq_ne( seq, seq_present ) ) )
    FD_LOG_WARNING(( "recovery failed, recovered [%016lx,%016lx)/%lu, unrecovered [%016lx,%016lx)/%lu",
                     seq_past, seq, seq-seq_past, seq, seq_present, seq_present-seq ));

  return seq;
}
