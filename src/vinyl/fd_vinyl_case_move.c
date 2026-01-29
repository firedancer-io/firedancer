  case FD_VINYL_REQ_TYPE_MOVE: {

    fd_vinyl_key_t const * req_key_src = MAP_REQ_GADDR( req->key_gaddr,       fd_vinyl_key_t, batch_cnt );
    fd_vinyl_key_t const * req_key_dst = MAP_REQ_GADDR( req->val_gaddr_gaddr, fd_vinyl_key_t, batch_cnt );
    schar *                req_err     = MAP_REQ_GADDR( req->err_gaddr,       schar,          batch_cnt );

    if( FD_UNLIKELY( (!!batch_cnt) & ((!req_key_src) | (!req_key_dst) | (!req_err)) ) ) {
      comp_err = FD_VINYL_ERR_INVAL;
      break;
    }

    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {

#     define DONE(err) do {                                \
        int _err = (err);                                  \
        FD_COMPILER_MFENCE();                              \
        req_err[ batch_idx ] = (schar)_err;                \
        FD_COMPILER_MFENCE();                              \
        fail_cnt += (ulong)!!_err;                         \
        goto next_move;  /* sigh ... can't use continue */ \
      } while(0)

      /* If the input and output keys are the same, this is a no-op. */

      fd_vinyl_key_t const * key_src = req_key_src + batch_idx;
      fd_vinyl_key_t const * key_dst = req_key_dst + batch_idx;

      if( FD_UNLIKELY( fd_vinyl_key_eq( key_src, key_dst ) ) ) DONE( FD_VINYL_SUCCESS );

      /* At this point, key_src and key_dst are distinct.  Query meta
         for pair key_dst.  If key_dst is acquired, fail with again. */

      ulong memo_dst = fd_vinyl_key_memo( meta_seed, key_dst );

      ulong _ele_idx_dst; /* Avoid pointer escape */
      int   err_dst = fd_vinyl_meta_query_fast( ele0, ele_max, key_dst, memo_dst, &_ele_idx_dst );
      ulong ele_idx_dst = _ele_idx_dst; /* In [0,ele_max) */

      ulong line_idx_dst = ULONG_MAX; /* Fix spurious compiler warning */

      if( FD_UNLIKELY( !err_dst ) ) { /* dst exists at bstream seq_present or is being created */

        line_idx_dst = ele0[ ele_idx_dst ].line_idx;

        if( FD_UNLIKELY( line_idx_dst<line_cnt ) ) { /* dst is in cache */

          FD_CRIT( line[ line_idx_dst ].ele_idx==ele_idx_dst, "corruption detected" );

          ulong line_ctl_dst = line[ line_idx_dst ].ctl;

          long ref_dst = fd_vinyl_line_ctl_ref( line_ctl_dst );

          if( FD_UNLIKELY( ref_dst ) ) DONE( FD_VINYL_ERR_AGAIN ); /* dst is acquired */

        } else {

          FD_CRIT( line_idx_dst==ULONG_MAX, "corruption detected" );

        }

      }

      /* At this point, pair key dst might exist but is not acquired.
         Query meta for key_src.  If it doesn't exist (KEY) or is
         acquired (AGAIN), fail.  Otherwise, if it is not cached, cache
         it in the LRU position.

         (Note: if we want to overlap this IO maximally, we would do the
         caching of these lines async but then we'd need to be able to
         guarantee at least move batch_cnt lines are evictable ... this
         gets quite tricky.  So we just do blocking I/O here as we know
         at least 1 line is evictable.) */

      ulong memo_src = fd_vinyl_key_memo( meta_seed, key_src );

      ulong _ele_idx_src; /* Avoid pointer escape */
      int   err_src = fd_vinyl_meta_query_fast( ele0, ele_max, key_src, memo_src, &_ele_idx_src );
      ulong ele_idx_src = _ele_idx_src; /* In [0,ele_max) */

      if( FD_UNLIKELY( err_src ) ) DONE( FD_VINYL_ERR_KEY );

      ulong val_sz = (ulong)ele0[ ele_idx_src ].phdr.info.val_sz;

      FD_CRIT( val_sz<=FD_VINYL_VAL_MAX, "corruption detected" );

      ulong seq_src      = ele0[ ele_idx_src ].seq;
      ulong line_idx_src = ele0[ ele_idx_src ].line_idx;

      fd_vinyl_data_obj_t *     obj_src;
      fd_vinyl_bstream_phdr_t * phdr_src;

      if( FD_LIKELY( line_idx_src<line_cnt ) ) {

        ulong line_ctl_src = line[ line_idx_src ].ctl;

        long ref_src = fd_vinyl_line_ctl_ref( line_ctl_src );

        if( FD_UNLIKELY( ref_src ) ) DONE( FD_VINYL_ERR_AGAIN );

        ulong ver_src = fd_vinyl_line_ctl_ver( line_ctl_src );

        FD_CRIT( line[ line_idx_src ].ele_idx==ele_idx_src, "corruption detected" );

        obj_src = line[ line_idx_src ].obj;

        FD_ALERT( fd_vinyl_data_is_valid_obj( obj_src, vol, vol_cnt ), "corruption detected" );
        FD_CRIT ( obj_src->line_idx==line_idx_src,                     "corruption detected" );

        phdr_src = fd_vinyl_data_obj_phdr( obj_src );

        line[ line_idx_src ].ctl = fd_vinyl_line_ctl( ver_src+1UL, 0L );

      } else {

        FD_CRIT( line_idx_src==ULONG_MAX, "corruption detected" );

        /* Read the encoded pair from the bstream */

        ulong ctl = ele0[ ele_idx_src ].phdr.ctl;

        int   type    = fd_vinyl_bstream_ctl_type ( ctl );
        int   style   = fd_vinyl_bstream_ctl_style( ctl );
        ulong val_esz = fd_vinyl_bstream_ctl_sz   ( ctl );

        FD_CRIT( type==FD_VINYL_BSTREAM_CTL_TYPE_PAIR,                                              "corruption detected" );
        FD_CRIT( (style==FD_VINYL_BSTREAM_CTL_STYLE_RAW) | (style==FD_VINYL_BSTREAM_CTL_STYLE_LZ4), "corruption detected" );
        FD_CRIT( val_esz<=FD_VINYL_VAL_MAX,                                                         "corruption detected" );

        fd_vinyl_data_obj_t * cobj = fd_vinyl_data_alloc( data, fd_vinyl_data_szc( val_esz ) );
        if( FD_UNLIKELY( !cobj ) ) FD_LOG_CRIT(( "increase data cache size" ));

        fd_vinyl_bstream_phdr_t * cphdr    = fd_vinyl_data_obj_phdr( cobj );
        ulong                     cpair_sz = fd_vinyl_bstream_pair_sz( val_esz );

        fd_vinyl_io_read_imm( io, seq_src, cphdr, cpair_sz );
        /* not an async read (so no read_cnt increment) */

        /* Verify data integrity */

        FD_ALERT( !fd_vinyl_bstream_pair_test( io_seed, seq_src, (fd_vinyl_bstream_block_t *)cphdr, cpair_sz ),
                  "corruption detected" );

        /* Decode the pair */

        if( FD_LIKELY( style==FD_VINYL_BSTREAM_CTL_STYLE_RAW ) ) {

          FD_CRIT( val_esz==val_sz, "corruption detected" );

          obj_src  = cobj;
          phdr_src = cphdr;

        } else {

          obj_src = fd_vinyl_data_alloc( data, fd_vinyl_data_szc( val_sz ) );
          if( FD_UNLIKELY( !obj_src ) ) FD_LOG_CRIT(( "increase data cache size" ));

          char const * cval = (char const *)fd_vinyl_data_obj_val( cobj    );
          char *       val  = (char *)      fd_vinyl_data_obj_val( obj_src );
          if( FD_UNLIKELY( (ulong)LZ4_decompress_safe( cval,  val, (int)val_esz, (int)val_sz )!=val_sz ) )
            FD_LOG_CRIT(( "LZ4_decompress_safe failed" ));

          phdr_src = fd_vinyl_data_obj_phdr( obj_src );

          phdr_src->ctl  = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz );
          phdr_src->key  = cphdr->key;
          phdr_src->info = cphdr->info;

          fd_vinyl_data_free( data, cobj );

        }

        line_idx_src = fd_vinyl_line_evict_lru( &vinyl->line_idx_lru, line, line_cnt, ele0, ele_max, data );

        ulong line_ctl_src = line[ line_idx_src ].ctl;

        ulong ver_src = fd_vinyl_line_ctl_ver( line_ctl_src );

        line[ line_idx_src ].obj     = obj_src; obj_src->line_idx = line_idx_src; obj_src->rd_active = (short)0;
        line[ line_idx_src ].ele_idx = ele_idx_src; ele0[ ele_idx_src ].line_idx = line_idx_src;
        line[ line_idx_src ].ctl     = fd_vinyl_line_ctl( ver_src+1UL, 0L );

        fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx_src, FD_VINYL_LINE_EVICT_PRIO_LRU );

        if( line_idx_src==line_idx_dst ) line_idx_dst = ULONG_MAX; /* Handle evict_lru evicting the dst */

      }

      /* At this point, pair key_src is cached but not acquired and pair
         key_dst is not acquired.  We are clear to move.  If pair
         key_dst exists, we are replacing pair key_dst with pair
         key_src.  In this case, we remove pair key_dst from cache and
         remove pair key_dst from the meta.  This remove might move the
         location of pair key_src's meta element.  So we reload if
         necessary. */

      FD_CRIT( fd_vinyl_bstream_ctl_type( phdr_src->ctl )==fd_vinyl_bstream_ctl_type( ele0[ ele_idx_src ].phdr.ctl ),
                                                                                                    "corruption detected" );
      FD_CRIT( fd_vinyl_key_eq( &phdr_src->key, &ele0[ ele_idx_src ].phdr.key ),                    "corruption detected" );
      FD_CRIT( !memcmp( &phdr_src->info, &ele0[ ele_idx_src ].phdr.info, sizeof(fd_vinyl_info_t) ), "corruption detected" );

      accum_garbage_cnt += 2UL; /* old src and new move block */
      accum_garbage_sz  += fd_vinyl_bstream_pair_sz( fd_vinyl_bstream_ctl_sz( ele0[ ele_idx_src ].phdr.ctl ) ) +
                           FD_VINYL_BSTREAM_BLOCK_SZ;

      if( FD_UNLIKELY( !err_dst ) ) {

        accum_garbage_cnt++; /* old dst */
        accum_garbage_sz += fd_vinyl_bstream_pair_sz( fd_vinyl_bstream_ctl_sz( ele0[ ele_idx_dst ].phdr.ctl ) );

        if( FD_UNLIKELY( line_idx_dst < line_cnt ) ) {

          FD_CRIT( line[ line_idx_dst ].ele_idx==ele_idx_dst, "corruption detected" );

          fd_vinyl_data_obj_t * obj_dst = line[ line_idx_dst ].obj;

          FD_ALERT( fd_vinyl_data_is_valid_obj( obj_dst, vol, vol_cnt ), "corruption detected" );
          FD_CRIT ( obj_dst->line_idx==line_idx_dst,                     "corruption detected" );

          ulong line_ctl_dst = line[ line_idx_dst ].ctl;

          ulong ver_dst = fd_vinyl_line_ctl_ver( line_ctl_dst );

          fd_vinyl_data_free( data, obj_dst );

          line[ line_idx_dst ].obj     = NULL;
          line[ line_idx_dst ].ele_idx = ULONG_MAX; // ele0[ ele_idx_dst ].line_idx = ULONG_MAX; /* Technically not necessary given below */
          line[ line_idx_dst ].ctl     = fd_vinyl_line_ctl( ver_dst+1UL, 0L );

          fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx_dst, FD_VINYL_LINE_EVICT_PRIO_LRU );
        }

        fd_vinyl_meta_remove_fast( ele0, ele_max, lock, lock_shift, line, line_cnt, ele_idx_dst ); /* See note below about atomicity for concurrent meta readers */

        ulong pair_cnt = vinyl->pair_cnt;
        FD_CRIT( pair_cnt, "corruption detected" );
        vinyl->pair_cnt = pair_cnt - 1UL;

        err_src = fd_vinyl_meta_query_fast( ele0, ele_max, key_src, memo_src, &_ele_idx_src );
        ele_idx_src = _ele_idx_src; /* In [0,ele_max) */
        FD_CRIT( !err_src, "corruption detected" );
        /* Note: could test other fields post move too */

      }

      /* At this point, pair key_src is cached but not acquired and pair
         key_dst is not cached and not in the meta (the move block that
         will official erase if it already exists will be written
         below).  Update the cached phdr to reflect the move.  Remove
         the meta entry for pair key_src and insert a meta entry for
         pair key_dst.

         Note: this means from the point of view of concurrent meta
         queries, there will be a brief time interval when pair key_src
         and pair key_dst are both reported as not existing.

         As an alternative with more overhead we could instead insert
         the meta element for key_dst, remove the meta element for
         key_src and requery meta for key_dst (as the remove could move
         it).  In this case, there will be a gap where both key_src and
         key_dst are both reported as available (and they will point to
         the same cache entry during this interval).

         With even more complexity and overhead, we could eliminate the
         gap and overhead and make this atomic from the point of view of
         concurrent meta readers.  (Would have compute a lock set that
         cover the target key_dst insert location and the key_src probe
         sequence assuming key_dst has been inserted, lock the locks, do
         the insert, do the remove without any locking behavior, free
         the lock set and then requery where key_dst ended up.)  Also
         note that, if we are replacing pair key_dst, at this point,
         pair key_dst is already reported to concurrent meta readers as
         not existing.  Would need to extend this to the above.

         But it isn't clear that concurrent meta readers care at all.
         So we go with the fast simple method below (it still is atomic
         from the point of view of clients and the bstream). */

      ulong pair_sz  = fd_vinyl_bstream_pair_sz( val_sz );
      ulong seq_move = fd_vinyl_io_hint( io, FD_VINYL_BSTREAM_BLOCK_SZ + pair_sz );
      ulong seq_dst  = seq_move + FD_VINYL_BSTREAM_BLOCK_SZ;

    //phdr_src->ctl  = ... already init
      phdr_src->key = *key_dst;
    //phdr_src->info = ... already init

      fd_vinyl_meta_remove_fast( ele0, ele_max, lock, lock_shift, line, line_cnt, ele_idx_src );

      err_dst = fd_vinyl_meta_query_fast( ele0, ele_max, key_dst, memo_dst, &_ele_idx_dst );
      ele_idx_dst = _ele_idx_dst; /* In [0,ele_max) */

      FD_CRIT( err_dst==FD_VINYL_ERR_KEY, "corruption detected" );

      ele0[ ele_idx_dst ].memo      = memo_dst;
    //ele0[ ele_idx_dst ].phdr.ctl  = ... init below for concurrent safe insert
      ele0[ ele_idx_dst ].phdr.key  = phdr_src->key;
      ele0[ ele_idx_dst ].phdr.info = phdr_src->info;
      ele0[ ele_idx_dst ].line_idx  = line_idx_src;
      ele0[ ele_idx_dst ].seq       = seq_dst;

      FD_COMPILER_MFENCE();
      ele0[ ele_idx_dst ].phdr.ctl = phdr_src->ctl;
      FD_COMPILER_MFENCE();

      line[ line_idx_src ].ele_idx = ele_idx_dst;

      fd_vinyl_io_append_move( io, phdr_src, key_dst );
      append_cnt++;
      accum_move_cnt++;

      fd_vinyl_bstream_pair_hash( io_seed, (fd_vinyl_bstream_block_t *)phdr_src );

      ulong seq = fd_vinyl_io_append( io, phdr_src, pair_sz );
      append_cnt++;
      FD_CRIT( fd_vinyl_seq_eq( seq, seq_dst ), "unexpected append location" );

      DONE( FD_VINYL_SUCCESS );

    next_move: /* silly language restriction */;

#     undef DONE

    }

    comp_err = FD_VINYL_SUCCESS;
    break;
  }
