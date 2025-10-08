#include <lz4.h>
#include "fd_vinyl.h"

void
fd_vinyl_compact( fd_vinyl_t * vinyl,
                  ulong        compact_max ) {

  fd_vinyl_io_t * io        = vinyl->io;
  ulong           gc_thresh = vinyl->gc_thresh;
  int             gc_eager  = vinyl->gc_eager;
  int             style     = vinyl->style;

  ulong io_seed     = fd_vinyl_io_seed       ( io ); (void)io_seed;
  ulong seq_past    = fd_vinyl_io_seq_past   ( io );
  ulong seq_present = fd_vinyl_io_seq_present( io );

  if( FD_UNLIKELY( (!compact_max) | ((seq_present-seq_past)<=gc_thresh) | (gc_eager<0) ) ) return;

  fd_vinyl_meta_t * meta       = vinyl->meta;
  fd_vinyl_line_t * line       = vinyl->line;
  ulong             line_cnt   = vinyl->line_cnt;
  ulong             garbage_sz = vinyl->garbage_sz;

  fd_vinyl_meta_ele_t * ele0      = meta->ele;
  ulong                 ele_max   = meta->ele_max;
  ulong                 meta_seed = meta->seed;

  fd_vinyl_data_t * data = vinyl->data;

  fd_vinyl_data_vol_t * vol     = data->vol;     (void)vol;
  ulong                 vol_cnt = data->vol_cnt; (void)vol_cnt;

  ulong seq = seq_past;

  for( ulong rem=compact_max; rem; rem-- ) {

    /* At this point, we've compacted [seq_past,seq) (cyclic), with
       items still needed in this range at [seq_present,seq_future)
       (cyclic).  We still have [seq,seq_present) (cyclic), containing
       garbage_sz bytes to compact.

       If the new past region is small enough or there is a relatively
       small amount of garbage in this region, we consider the bstream's
       past fully compacted. */

    ulong past_sz_new = fd_vinyl_io_seq_future( io ) - seq;
    if( FD_UNLIKELY( (past_sz_new <= gc_thresh                ) |
                     (garbage_sz  <= (past_sz_new >> gc_eager)) |
                     (fd_vinyl_seq_ge( seq, seq_present )     ) ) ) {
      FD_CRIT( fd_vinyl_seq_le( seq, seq_present ), "corruption detected" );
      if( FD_UNLIKELY( fd_vinyl_seq_eq( seq, seq_present ) ) ) FD_CRIT( !garbage_sz, "corruption detected" );
      break;
    }

    /* At this point, there is enough garbage to do some more
       compaction.  Load the leading block of the object at seq and
       determine if this object is needed to recover the bstream's state
       at seq_present.

       That is, we determine if the object at bstream_past_new is the
       version of a pair that exists at bstream seq_present.  If so, we
       append a copy to the bstream's present.

       When compacting is complete, we forget the region containing the
       copy at seq.  This then effectively moves the copy from seq to
       seq_future without any risk of losing data while allowing
       compaction to be done with large amounts of async I/O overlapped
       with compaction processing (metadata lookups, hash validation,
       etc).

       This move will not move the pair past any conflicting operations
       later in the bstream's past (almost definitionally so as the pair
       is the most recent version).  Thus set of pairs recovered at
       seq_future will be identical to the set of pairs recovered at
       seq_present. */

    fd_vinyl_bstream_block_t block[1];

    fd_vinyl_io_read_imm( io, seq, block, FD_VINYL_BSTREAM_BLOCK_SZ );

    ulong ctl = block->ctl;

    int   type = fd_vinyl_bstream_ctl_type( ctl );

    switch( type ) {

    case FD_VINYL_BSTREAM_CTL_TYPE_PAIR: {

      /* At this point, we've read a pair's leading block into block.
         Validate the pair was completely written.  It's okay if we are
         in a move (move block processing the previous iteration already
         confirmed this pair is the proper). */

      int                    pair_style   = fd_vinyl_bstream_ctl_style( ctl );
      ulong                  pair_val_esz = fd_vinyl_bstream_ctl_sz   ( ctl );
      fd_vinyl_key_t const * pair_key     =       &block->phdr.key;
      ulong                  pair_val_sz  = (ulong)block->phdr.info._val_sz;

      ulong pair_sz = fd_vinyl_bstream_pair_sz( pair_val_esz );

      int truncated = (pair_sz > (seq_present - seq)); /* Wrapping safe */
      int bad_esz   = (pair_val_esz > FD_VINYL_VAL_MAX);
      int bad_sz    = (pair_val_sz  > FD_VINYL_VAL_MAX);

      FD_CRIT( !(truncated | bad_esz | bad_sz), truncated ? "truncated pair"                     :
                                                bad_esz   ? "unexpected pair value encoded size" :
                                                            "pair value size too large" );

#     if FD_PARANOID
      fd_vinyl_bstream_block_t   _ftr[1];
      fd_vinyl_bstream_block_t * ftr = _ftr;

      if( FD_UNLIKELY( pair_sz <= FD_VINYL_BSTREAM_BLOCK_SZ ) ) ftr = block;
      else fd_vinyl_io_read_imm( io, seq + pair_sz - FD_VINYL_BSTREAM_BLOCK_SZ, ftr, FD_VINYL_BSTREAM_BLOCK_SZ );

      FD_ALERT( !fd_vinyl_bstream_pair_test_fast( io_seed, seq, block, ftr ), "corruption detected" );
#     endif

      /* At this point, we appear to have a valid pair.  Query the
         vinyl's meta to determine if this is the version of the pair at
         bstream seq_present.  Since this implementation is doing single
         threaded recovery, we can use the single threaded optimized
         meta APIs. */

      ulong pair_memo = fd_vinyl_key_memo( meta_seed, pair_key );

      ulong _ele_idx; /* avoid pointer escape */
      int   err = fd_vinyl_meta_query_fast( ele0, ele_max, pair_key, pair_memo, &_ele_idx );
      ulong ele_idx = _ele_idx;

      if( FD_LIKELY( !err ) ) {

        /* At this point, a version of pair key is mapped */

        if( FD_LIKELY( fd_vinyl_meta_ele_in_bstream( &ele0[ ele_idx ] ) ) ) {

          /* At this point, a version of pair key exists at bstream
             seq_present (i.e. is not in the process of being created by
             a client). */

          ulong pair_seq = ele0[ ele_idx ].seq;

          if( FD_LIKELY( fd_vinyl_seq_eq( pair_seq, seq ) ) ) {

            /* At this point, the version of pair key at seq is the
               version of pair key that exists at bstream seq_present.
               Validate the metadata. */

            FD_CRIT( !memcmp( &ele0[ ele_idx ].phdr, &block->phdr, sizeof(fd_vinyl_bstream_phdr_t) ), "corruption detected" );

            /* If the pair is cached and not acquired for modify, append
               the cached copy in the target style.  Otherwise, append a
               (possibly recoded) copy from the bstream. */

            int   pair_style_new;
            ulong pair_val_esz_new;
            ulong pair_seq_new;

            int do_copy = 1;

            ulong line_idx = ele0[ ele_idx ].line_idx;

            if( FD_LIKELY( line_idx!=ULONG_MAX )  ) { /* Pair is in cache */

              FD_CRIT( line_idx<line_cnt,                 "corruption detected" );
              FD_CRIT( line[ line_idx ].ele_idx==ele_idx, "corruption detected" );

              fd_vinyl_data_obj_t * obj = line[ line_idx ].obj;

              FD_ALERT( fd_vinyl_data_is_valid_obj( obj, vol, vol_cnt ), "corruption detected" );
              FD_CRIT ( obj->line_idx==line_idx,                         "corruption detected" );
              FD_CRIT ( !obj->rd_active,                                 "corruption detected" );

              ulong line_ctl = line[ line_idx ].ctl;

              if( FD_LIKELY( fd_vinyl_line_ctl_ref( line_ctl )>=0L ) ) { /* Pair cached and not acquired for modify */

                fd_vinyl_bstream_phdr_t * phdr = fd_vinyl_data_obj_phdr( obj );

                FD_ALERT( !memcmp( phdr, &block->phdr, sizeof(fd_vinyl_bstream_phdr_t) ), "corruption detected" );

                pair_seq_new = fd_vinyl_io_append_pair_inplace( io, style, phdr, &pair_style_new, &pair_val_esz_new );

                do_copy = 0;

              }

            }

            if( do_copy ) { /* Pair is either in cache or acquired for modify, append from the bstream */

              if( FD_LIKELY( (pair_style!=FD_VINYL_BSTREAM_CTL_STYLE_RAW) |
                             (style     ==FD_VINYL_BSTREAM_CTL_STYLE_RAW) |
                             (pair_sz   ==FD_VINYL_BSTREAM_BLOCK_SZ     ) ) ) {

                /* At this point, the pair is already stored in an
                   encoded format, the preferred format for storing
                   encoded pairs is raw and/or encoding the pair will
                   not make it any smaller in the bstream.  Copy the
                   pair as is from seq to seq_future.  The reason we
                   don't reencode the pair in the second case is that
                   this pair has likely not been touched since it last
                   got to the bstream's seq_past.  It would be waste to
                   compute and bstream storage to uncompress it as we
                   copy it. */

                pair_style_new   = pair_style;
                pair_val_esz_new = fd_vinyl_bstream_ctl_sz( ele0[ ele_idx ].phdr.ctl );
                pair_seq_new     = fd_vinyl_io_copy( io, pair_seq, pair_sz );

              } else {

                /* At this point, the pair is stored in a raw encoded
                   format, the preferred format is an encoded format and
                   there is a possibility that encoding it will make it
                   smaller.  Encode the pair as we copy it from seq to
                   seq_future.

                   To do this, we allocate enough scratch from the io
                   append spad to cover the worst case encoded pair and
                   the raw pair (this sets the lower bound on how large
                   the io append spad must be).  Then we read the raw
                   pair into the trailing part of the scratch and encode
                   from that into the leading part of the scratch.

                   We play some games with the spad_used so that the
                   append_pair_inplace will not invalidate the read and
                   so that we use scratch as efficiently as possible
                   when there is lots of stuff to compress. */

                ulong cpair_max   = fd_vinyl_bstream_pair_sz( (ulong)LZ4_COMPRESSBOUND( (int)pair_val_sz ) );
                ulong scratch_max = cpair_max + pair_sz;

                fd_vinyl_bstream_phdr_t * cphdr = (fd_vinyl_bstream_phdr_t *)
                  fd_vinyl_io_alloc( io, scratch_max, FD_VINYL_IO_FLAG_BLOCKING );

                fd_vinyl_bstream_phdr_t * phdr = (fd_vinyl_bstream_phdr_t *)((ulong)cphdr + cpair_max);

                fd_vinyl_io_read_imm( io, seq, phdr, pair_sz );

                fd_vinyl_io_trim( io, scratch_max );

                pair_seq_new = fd_vinyl_io_append_pair_inplace( io, style, phdr, &pair_style_new, &pair_val_esz_new );

                /* At this point, we either are appending the encoded
                   pair from the leading part of the scratch and
                   spad_used is correct or we are appending the pair
                   from the trailing part and spad_used does not include
                   it.  Adjust the spad used for the later case.  In
                   this second case, we end up with a temporary hole in
                   the scratch when we decided not to copy into an
                   encoded form.  This just scratch is used less
                   efficiently in the unlikely case in order to use it
                   more efficiently in the likely case (the correct
                   tradeoff). */

                if( FD_UNLIKELY( pair_style_new==FD_VINYL_BSTREAM_CTL_STYLE_RAW ) ) io->spad_used += scratch_max;

              }
            }

            /* Note: we don't need to prepare here because we aren't
               modifying shared fields. */

            ele0[ ele_idx ].phdr.ctl = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, pair_style_new, pair_val_esz_new );
            ele0[ ele_idx ].seq      = pair_seq_new;

          } else {

            /* The version of the pair at bstream seq was replaced.  The
               most recent version of this pair is at pair_seq. */

            FD_CRIT( fd_vinyl_seq_gt( pair_seq, seq ), "corruption detected" );

            garbage_sz -= pair_sz;

          }

        } else {

          /* The pair at bstream seq does not exist in the bstream at
             bstream seq_present.  It is in the vinyl meta because it is
             being created.  We wouldn't be in the process of creating
             it unless this pair (or a subsequent version of it) was
             erased or moved before seq_present.  So this pair is
             garbage. */

          garbage_sz -= pair_sz;

        }

      } else {

          /* The pair at bstream seq does not exist in the bstream at
             bstream seq_present.  This pair (or a subsequent version of
             it) was erased or moved before seq_present.  So this pair
             is garbage. */

          garbage_sz -= pair_sz;

      }

      seq += pair_sz;
      break;

    }

    case FD_VINYL_BSTREAM_CTL_TYPE_DEAD:
    case FD_VINYL_BSTREAM_CTL_TYPE_MOVE:
    case FD_VINYL_BSTREAM_CTL_TYPE_PART: {

      /* DEAD blocks can always be compacted out because the version of
         the pair they reference is not in the current view of the
         bstream (because that version was unmapped when the DEAD was
         written), that version was located at an earlier location than
         the DEAD (because blocks are appended sequentially) and thus
         that version has already been compacted out (because a previous
         iteration of this would have encountered it before getting this
         DEAD block, would have detecting that version was no longer
         needed and compacted it at that time instead of moving it to a
         higher sequence number).

         MOVE blocks can always be compacted out for the same reasons as
         the above with the twist that, compacting the move block makes
         the pair following look like a create from the point of view of
         a recovery starting at the pair.  This is immaterial though
         because doesn't change the recovered view if recovery starts
         on the block after the move.

         PART blocks can always be compacted because they are just
         informational (to help partition the bstream past in parallel
         recovery) and this partition ends bstream blocks that have
         already been compacted out.

         We validate the block because we already have the data anyway.  */

      FD_ALERT( !fd_vinyl_bstream_block_test( io_seed, block ), "corruption detected" );

      garbage_sz -= FD_VINYL_BSTREAM_BLOCK_SZ;
      seq        += FD_VINYL_BSTREAM_BLOCK_SZ;
      break;

    }

    case FD_VINYL_BSTREAM_CTL_TYPE_ZPAD: {

      /* ZPAD blocks can always be compacted out because they are no-ops
         from the point of view of bstream processing (the underlying
         I/O layer can insert these so that, for example, a multi-block
         pair is never split across two different physical volumes).
         Note that zpad blocks aren't included in garbage_sz because we
         don't control when they get created (and thus can't easily
         update garbage_sz to account for them when they are created). */

      FD_ALERT( !fd_vinyl_bstream_zpad_test( io_seed, seq, block ), "corruption detected" );

      seq += FD_VINYL_BSTREAM_BLOCK_SZ;
      break;

    }

    default: FD_LOG_CRIT(( "%016lx: unknown type (%x)", seq, (uint)type ));

    }

  }

  /* At this point, we've made copies of all info in [seq_past,seq)
     (cyclic) to [seq_present,seq_future) (cyclic) needed to recover the
     bstream's state at seq_present.  We commit the new, forget the old
     and update the garbage size to finish this compaction. */

  fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING );
  fd_vinyl_io_forget( io, seq );

  vinyl->garbage_sz = garbage_sz;
}
