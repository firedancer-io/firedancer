/* fd_accdb_compact is the accdb tile's version of fd_vinyl_compact.

   It is functionally identical except:
   - Lines use obj_gaddr (ulong) instead of obj (pointer).
     Resolved via fd_vinyl_data_laddr( gaddr, data->laddr0 ).
   - Lines use fd_accdb_line_ctl_ref (24-bit ref with CHANCE/EVICTING
     bits) instead of fd_vinyl_line_ctl_ref (32-bit ref). */

FD_FN_UNUSED static void
fd_accdb_compact( fd_vinyl_t * vinyl,
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

  void * data_laddr0 = data->laddr0;

  ulong seq = seq_past;

  for( ulong rem=compact_max; rem; rem-- ) {

    ulong past_sz_new = fd_vinyl_io_seq_future( io ) - seq;
    if( FD_UNLIKELY( (past_sz_new <= gc_thresh                ) |
                     (garbage_sz  <= (past_sz_new >> gc_eager)) |
                     (fd_vinyl_seq_ge( seq, seq_present )     ) ) ) {
      FD_CRIT( fd_vinyl_seq_le( seq, seq_present ), "corruption detected" );
      if( FD_UNLIKELY( fd_vinyl_seq_eq( seq, seq_present ) ) ) FD_CRIT( !garbage_sz, "corruption detected" );
      break;
    }

    fd_vinyl_bstream_block_t block[1];

    fd_vinyl_io_read_imm( io, seq, block, FD_VINYL_BSTREAM_BLOCK_SZ );

    ulong ctl = block->ctl;

    int   type = fd_vinyl_bstream_ctl_type( ctl );

    switch( type ) {

    case FD_VINYL_BSTREAM_CTL_TYPE_PAIR: {

      int                    pair_style   = fd_vinyl_bstream_ctl_style( ctl );
      ulong                  pair_val_esz = fd_vinyl_bstream_ctl_sz   ( ctl );
      fd_vinyl_key_t const * pair_key     =       &block->phdr.key;
      ulong                  pair_val_sz  = (ulong)block->phdr.info.val_sz;

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

      ulong pair_memo = fd_vinyl_key_memo( meta_seed, pair_key );

      ulong _ele_idx; /* avoid pointer escape */
      int   err = fd_vinyl_meta_query_fast( ele0, ele_max, pair_key, pair_memo, &_ele_idx );
      ulong ele_idx = _ele_idx;

      if( FD_LIKELY( !err ) ) {

        if( FD_LIKELY( fd_vinyl_meta_ele_in_bstream( &ele0[ ele_idx ] ) ) ) {

          ulong pair_seq = ele0[ ele_idx ].seq;

          if( FD_LIKELY( fd_vinyl_seq_eq( pair_seq, seq ) ) ) {

            FD_CRIT( !memcmp( &ele0[ ele_idx ].phdr, &block->phdr, sizeof(fd_vinyl_bstream_phdr_t) ), "corruption detected" );

            int   pair_style_new;
            ulong pair_val_esz_new;
            ulong pair_seq_new;

            int do_copy = 1;

            ulong line_idx = ele0[ ele_idx ].line_idx;

            if( FD_LIKELY( line_idx!=ULONG_MAX )  ) { /* Pair is in cache */

              FD_CRIT( line_idx<line_cnt,                 "corruption detected" );
              FD_CRIT( line[ line_idx ].ele_idx==ele_idx, "corruption detected" );

              fd_vinyl_data_obj_t * obj = fd_vinyl_data_laddr( line[ line_idx ].obj_gaddr, data_laddr0 );

              FD_ALERT( fd_vinyl_data_is_valid_obj( obj, vol, vol_cnt ), "corruption detected" );
              FD_CRIT ( obj->line_idx==line_idx,                         "corruption detected" );
              FD_CRIT ( !obj->rd_active,                                 "corruption detected" );

              ulong line_ctl = line[ line_idx ].ctl;

              if( FD_LIKELY( fd_accdb_line_ctl_ref( line_ctl )>=0L ) ) { /* Pair cached and not acquired for modify */

                fd_vinyl_bstream_phdr_t * phdr = fd_vinyl_data_obj_phdr( obj );

                FD_ALERT( !memcmp( phdr, &block->phdr, sizeof(fd_vinyl_bstream_phdr_t) ), "corruption detected" );

                pair_seq_new = fd_vinyl_io_append_pair_inplace( io, style, phdr, &pair_style_new, &pair_val_esz_new );

                do_copy = 0;

              }

            }

            if( do_copy ) { /* Pair is either not in cache or acquired for modify, append from the bstream */

              if( FD_LIKELY( (pair_style!=FD_VINYL_BSTREAM_CTL_STYLE_RAW) |
                             (style     ==FD_VINYL_BSTREAM_CTL_STYLE_RAW) |
                             (pair_sz   ==FD_VINYL_BSTREAM_BLOCK_SZ     ) ) ) {

                pair_style_new   = pair_style;
                pair_val_esz_new = fd_vinyl_bstream_ctl_sz( ele0[ ele_idx ].phdr.ctl );
                pair_seq_new     = fd_vinyl_io_copy( io, pair_seq, pair_sz );

              } else {

                ulong cpair_max   = fd_vinyl_bstream_pair_sz( (ulong)LZ4_COMPRESSBOUND( (int)pair_val_sz ) );
                ulong scratch_max = cpair_max + pair_sz;

                fd_vinyl_bstream_phdr_t * cphdr = (fd_vinyl_bstream_phdr_t *)
                  fd_vinyl_io_alloc( io, scratch_max, FD_VINYL_IO_FLAG_BLOCKING );

                fd_vinyl_bstream_phdr_t * phdr = (fd_vinyl_bstream_phdr_t *)((ulong)cphdr + cpair_max);

                fd_vinyl_io_read_imm( io, seq, phdr, pair_sz );

                fd_vinyl_io_trim( io, scratch_max );

                pair_seq_new = fd_vinyl_io_append_pair_inplace( io, style, phdr, &pair_style_new, &pair_val_esz_new );

                if( FD_UNLIKELY( pair_style_new==FD_VINYL_BSTREAM_CTL_STYLE_RAW ) ) io->spad_used += scratch_max;

              }
            }

            ele0[ ele_idx ].phdr.ctl = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, pair_style_new, pair_val_esz_new );
            ele0[ ele_idx ].seq      = pair_seq_new;

          } else {

            FD_CRIT( fd_vinyl_seq_gt( pair_seq, seq ), "corruption detected" );

            garbage_sz -= pair_sz;

          }

        } else {

          garbage_sz -= pair_sz;

        }

      } else {

          garbage_sz -= pair_sz;

      }

      seq += pair_sz;
      break;

    }

    case FD_VINYL_BSTREAM_CTL_TYPE_DEAD:
    case FD_VINYL_BSTREAM_CTL_TYPE_MOVE:
    case FD_VINYL_BSTREAM_CTL_TYPE_PART: {

      FD_ALERT( !fd_vinyl_bstream_block_test( io_seed, block ), "corruption detected" );

      garbage_sz -= FD_VINYL_BSTREAM_BLOCK_SZ;
      seq        += FD_VINYL_BSTREAM_BLOCK_SZ;
      break;

    }

    case FD_VINYL_BSTREAM_CTL_TYPE_ZPAD: {

      FD_ALERT( !fd_vinyl_bstream_zpad_test( io_seed, seq, block ), "corruption detected" );

      seq += FD_VINYL_BSTREAM_BLOCK_SZ;
      break;

    }

    default: FD_LOG_CRIT(( "%016lx: unknown type (%x)", seq, (uint)type ));

    }

  }

  fd_vinyl_io_commit( io, FD_VINYL_IO_FLAG_BLOCKING );
  fd_vinyl_io_forget( io, seq );

  vinyl->garbage_sz = garbage_sz;
}
