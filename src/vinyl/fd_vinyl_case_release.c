  case FD_VINYL_REQ_TYPE_RELEASE: {

    ulong                  req_flags     = (ulong)req->flags;
    fd_vinyl_key_t const * req_key       = MAP_REQ_GADDR( req->key_gaddr,       fd_vinyl_key_t const, batch_cnt );
    ulong *                req_val_gaddr = MAP_REQ_GADDR( req->val_gaddr_gaddr, ulong,                batch_cnt );
    schar *                req_err       = MAP_REQ_GADDR( req->err_gaddr,       schar,                batch_cnt );

    int req_flag_modify = fd_vinyl_req_flag_modify( req_flags );
    int req_flag_ignore = fd_vinyl_req_flag_ignore( req_flags );
    int req_flag_erase  = fd_vinyl_req_flag_erase ( req_flags );
    int req_flag_by_key = fd_vinyl_req_flag_by_key( req_flags );
    int req_evict_prio  = fd_vinyl_req_evict_prio ( req_flags );

    if( FD_UNLIKELY( (!!batch_cnt) & ( ((!req_key      ) &   req_flag_by_key ) |
                                       ((!req_val_gaddr) & (!req_flag_by_key)) |
                                       ( !req_err                            ) ) ) ) {
      comp_err = FD_VINYL_ERR_INVAL;
      break;
    }

    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {

#     define DONE(err) do {                                  \
        int _err = (err);                                    \
        FD_COMPILER_MFENCE();                                \
        req_err[ batch_idx ] = (schar)_err;                  \
        FD_COMPILER_MFENCE();                                \
        quota_rem += (ulong) !_err;                          \
        fail_cnt  += (ulong)!!_err;                          \
        goto next_release; /* sigh ... can't use continue */ \
      } while(0)

      /* If a pair has been acquired, there is a non-zero ref count line
         holding it.  This line connects the meta element (with the
         bstream state at seq_present) to the data object (with the
         cached pair data).  Determine the line, meta element and data
         object associated with the acquire to release. */

      fd_vinyl_data_obj_t * obj;
      ulong                 line_idx;
      ulong                 ele_idx;
      ulong                 ver;
      long                  ref;

      if( FD_LIKELY( !req_flag_by_key ) ) { /* Release by val_gaddr */

        void * _obj = (void *)( req_val_gaddr[ batch_idx ]
                              + data_laddr0 - sizeof(fd_vinyl_bstream_phdr_t) - sizeof(fd_vinyl_data_obj_t) );

        if( FD_UNLIKELY( !fd_vinyl_data_is_valid_obj( _obj, vol, vol_cnt ) ) ) DONE( FD_VINYL_ERR_INVAL );
        obj = (fd_vinyl_data_obj_t *)_obj;

        if( FD_UNLIKELY( obj->rd_active ) ) DONE( FD_VINYL_ERR_INVAL );

        line_idx = obj->line_idx;
        if( FD_UNLIKELY( line_idx>=line_cnt ) || FD_UNLIKELY( obj!=line[ line_idx ].obj ) ) DONE( FD_VINYL_ERR_INVAL );

        ele_idx = line[ line_idx ].ele_idx;
        if( FD_UNLIKELY( ele_idx>=ele_max ) || FD_UNLIKELY( ele0[ ele_idx ].line_idx!=line_idx ) ) DONE( FD_VINYL_ERR_INVAL );
        /* FIXME: MAKE SURE ELE0[ ELE_IDX ] IS IN USE FOR DATA INTEGRITY! */

        ulong ctl = line[ line_idx ].ctl;

        ver = fd_vinyl_line_ctl_ver( ctl );
        ref = fd_vinyl_line_ctl_ref( ctl );

        if( FD_UNLIKELY( !ref ) ) DONE( FD_VINYL_ERR_INVAL ); /* Pair key exists and is cached ... but not acquired */

      } else { /* Release by key */

        fd_vinyl_key_t const * key = req_key + batch_idx;

        ulong memo = fd_vinyl_key_memo( meta_seed, key ); /* This can be slow which is why releasing by val_gaddr is preferred */

        ulong _ele_idx; /* avoid pointer escape */
        int   err     = fd_vinyl_meta_query_fast( ele0, ele_max, key, memo, &_ele_idx );
        ele_idx = _ele_idx; /* in [0,ele_max) */

        if( FD_UNLIKELY( err ) ) DONE( FD_VINYL_ERR_INVAL ); /* Pair key does not exist ... can't have been acquired */

        line_idx = ele0[ ele_idx ].line_idx;

        if( FD_UNLIKELY( line_idx>=line_cnt ) ) { /* Pair key exists but is not cached ... can't have been acquired */
          FD_CRIT( line_idx==ULONG_MAX, "corruption detected" );
          DONE( FD_VINYL_ERR_INVAL );
        }

        FD_CRIT( ele_idx==line[ line_idx ].ele_idx, "corruption detected" );

        obj = line[ line_idx ].obj;

        FD_ALERT( fd_vinyl_data_is_valid_obj( obj, vol, vol_cnt ), "corruption detected" );
        FD_CRIT ( obj->line_idx==line_idx,                         "corruption detected" );
        FD_CRIT ( !obj->rd_active,                                 "corruption detected" );

        ulong ctl = line[ line_idx ].ctl;

        ver = fd_vinyl_line_ctl_ver( ctl );
        ref = fd_vinyl_line_ctl_ref( ctl );

        if( FD_UNLIKELY( !ref ) ) DONE( FD_VINYL_ERR_INVAL ); /* Pair key exists and is cached ... but not acquired */

      }

      /* At this point, we are releasing an acquire of the object obj,
         cached at line line_idx with metadata at ele_idx. */

      fd_vinyl_bstream_phdr_t * phdr = fd_vinyl_data_obj_phdr( obj );

      if( FD_LIKELY( ref>0L ) ) {

        /* At this point, we are releasing an acquire for read.  If
           the client indicated they modified pair key, we don't have
           data integrity anymore and we CRIT.  Otherwise, we update
           line eviction priority and ref count to do the release. */

        if( FD_UNLIKELY( req_flag_modify ) ) FD_LOG_CRIT(( "client modified read only acquire" ));

        FD_CRIT( phdr->ctl==fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR,
                                                  FD_VINYL_BSTREAM_CTL_STYLE_RAW,
                                                  (ulong)ele0[ ele_idx ].phdr.info._val_sz ), "corruption detected" );
        FD_CRIT( fd_vinyl_key_eq( &phdr->key, &ele0[ ele_idx ].phdr.key ),                    "corruption detected" );
        FD_CRIT( !memcmp( &phdr->info, &ele0[ ele_idx ].phdr.info, sizeof(fd_vinyl_info_t) ), "corruption detected" );

        fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx, req_evict_prio );

        line[ line_idx ].ctl = fd_vinyl_line_ctl( ver, ref-1L ); /* don't bump ver */

        DONE( FD_VINYL_SUCCESS );
      }

      /* At this point, we are releasing an acquire for modify */

      ulong phdr_ctl = phdr->ctl;

      int modifying_existing = (phdr_ctl!=ULONG_MAX);

      if( FD_LIKELY( req_flag_modify & (!req_flag_erase) ) ) {

        /* At this point, we are either finishing up modifying an
           existing pair (modifying_existing 1) or finishing up creating
           a new pair (modifying_existing 0).  Cache the object in the
           smallest size class that supports it.  Note that the client
           could have modified info so we only validate ctl and key
           (FIXME: consider validating memo too?). */

        FD_CRIT( (!modifying_existing) |
                 (phdr_ctl==fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR,
                                                  FD_VINYL_BSTREAM_CTL_STYLE_RAW,
                                                  (ulong)ele0[ ele_idx ].phdr.info._val_sz )), "corruption detected" );
        FD_CRIT( fd_vinyl_key_eq( &phdr->key, &ele0[ ele_idx ].phdr.key ),                     "corruption detected" );

        ulong val_sz_after = (ulong)phdr->info._val_sz;

        if( FD_UNLIKELY( val_sz_after > fd_vinyl_data_obj_val_max( obj ) ) ) FD_LOG_CRIT(( "client overran memory" ));

        ulong szc_before = (ulong)obj->szc;
        ulong szc_after  = fd_vinyl_data_szc( val_sz_after );

        if( FD_UNLIKELY( szc_before!=szc_after ) ) {

          FD_CRIT( szc_after<szc_before, "corruption detected" );

          fd_vinyl_data_obj_t * obj_after = fd_vinyl_data_alloc( data, szc_after );
          if( FD_UNLIKELY( !obj_after ) ) FD_LOG_CRIT(( "increase data cache size" ));

          fd_vinyl_bstream_phdr_t * phdr_after = fd_vinyl_data_obj_phdr( obj_after );

          memcpy( phdr_after, phdr, sizeof(fd_vinyl_bstream_phdr_t) + val_sz_after );

          fd_vinyl_data_free( data, obj );

          obj  = obj_after;
          phdr = phdr_after;

        }

        /* Append to the updated pair key to the bstream.  If we are
           finishing up modifying an existing pair, this will create 1
           item of bstream garbage (the old version of the pair).  If we
           are finishing up creating a new pair, this will not create
           any garbage.  Note that this will zero out any pair zero
           padding region and populate footer hashes. */

        if( FD_LIKELY( modifying_existing ) ) {

          ulong val_esz_before = fd_vinyl_bstream_ctl_sz( ele0[ ele_idx ].phdr.ctl );

          accum_garbage_cnt++;
          accum_garbage_sz += fd_vinyl_bstream_pair_sz( val_esz_before );

        }

        phdr->ctl = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz_after );
      /*phdr->key  already init */
      /*phdr->info already init */

        int   style_after;
        ulong val_esz_after;
        ulong seq_after = fd_vinyl_io_append_pair_inplace( io, vinyl->style, phdr, &style_after, &val_esz_after );
        append_cnt++;

        /* Update the line and meta to match.  Note that setting meta
           element ele_idx phdr.ctl to something other than ULONG_MAX
           marks a pair that was being created as no longer being
           created.  For a pair that already existed, we also need to
           update phdr.ctl to reflect that we might be storing this in
           the stream in a different format than it was stored in
           bstream before.  Since we are changing shared fields of meta
           element ele_idx, we need to use prepare / publish semantics. */

        line[ line_idx ].obj     = obj;             obj->line_idx = line_idx; obj->rd_active = (short)0;
      //line[ line_idx ].ele_idx ... already init
        line[ line_idx ].ctl     = fd_vinyl_line_ctl( ver+1L, 0L ); /* bump ver */

        fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx, req_evict_prio );

        fd_vinyl_meta_prepare_fast( lock, lock_shift, ele_idx );

      //ele0[ ele_idx ].memo      = already init
        ele0[ ele_idx ].phdr.ctl  = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, style_after, val_esz_after );
      //ele0[ ele_idx ].phdr.key  = already init
        ele0[ ele_idx ].phdr.info = phdr->info;
        ele0[ ele_idx ].seq       = seq_after;
      //ele0[ ele_idx ].line_idx  = already init

        fd_vinyl_meta_publish_fast( lock, lock_shift, ele_idx );

        DONE( FD_VINYL_SUCCESS );

      }

      /* At this point, we are either canceling a modification (modify
         0, erase d/c) or the modification is to erase the pair (modify
         1, erase 1).  If we are canceling the modification of an
         existing pair and the client indicated the cached pair info and
         cached pair val are still valid, (i.e. release-cancel of an
         acquire-for-modify of an existing pair), we revert the line
         state and adjust the line evict priority.  (This code path can
         be omitted if we don't trust the clients to report correctly.
         We do test at least the client is correctly reporting the info
         is not modified.)  Note that we might have put this in a larged
         sized obj when we acquired it for modify.  So we also move the
         object to the tightest location. */

      if( FD_LIKELY( modifying_existing & (!req_flag_modify) & (!req_flag_ignore) ) ) {

        /* FIXME: consider allowing the client to always clobber the
           pair info and just restore info from the meta cache? */

        if( FD_UNLIKELY( !( (phdr->ctl==fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR,
                                                              FD_VINYL_BSTREAM_CTL_STYLE_RAW,
                                                              (ulong)ele0[ ele_idx ].phdr.info._val_sz )) &
                            (fd_vinyl_key_eq( &phdr->key, &ele0[ ele_idx ].phdr.key )                   ) &
                            (!memcmp( &phdr->info, &ele0[ ele_idx ].phdr.info, sizeof(fd_vinyl_info_t) )) ) ) )
          FD_LOG_CRIT(( "client clobbered pair info" ));

        ulong val_sz_before = (ulong)phdr->info._val_sz;

        ulong szc_after  = (ulong)obj->szc;
        ulong szc_before = fd_vinyl_data_szc( val_sz_before );

        if( FD_UNLIKELY( szc_before!=szc_after ) ) {

          FD_CRIT( szc_before<szc_after, "corruption detected" );

          fd_vinyl_data_obj_t * obj_before = fd_vinyl_data_alloc( data, szc_before );
          if( FD_UNLIKELY( !obj_before ) ) FD_LOG_CRIT(( "increase data cache size" ));

          fd_vinyl_bstream_phdr_t * phdr_before = fd_vinyl_data_obj_phdr( obj_before );

          memcpy( phdr_before, phdr, sizeof(fd_vinyl_bstream_phdr_t) + val_sz_before );

          fd_vinyl_data_free( data, obj );

          line[ line_idx ].obj = obj_before; obj_before->line_idx = line_idx; obj_before->rd_active = (short)0;

        }

        line[ line_idx ].ctl = fd_vinyl_line_ctl( ver-1UL, 0L ); /* revert ver */

        fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx, req_evict_prio );

        DONE( FD_VINYL_SUCCESS );

      }

      /* At this point, we are canceling a modification of an existing
         pair that no longer has valid cached pair info or cached pair
         val, erasing an existing pair, canceling the creation of a new
         pair or erasing a pair in the process of being created (which
         we treat the same as cancelling the creation).

         Since there was nothing cached originally (canceling / erasing
         a pair being created), the cached data is no longer valid
         (cancel with ignore of an existing pair) or the the cached data
         is no longer needed (erase of an existing pair), we free the
         data obj, mark the line as empty, move the line to LRU
         position. */

      /* FIXME: INTEGRITY CHECKS ON PHDR HERE?  (TRICKY AS WE'D HAVE TO
         MAP OUT EXACTLY WHICH FIELDS CAN BE TRUSTED AT THIS POINT AND
         IT ISN'T OBVIOUS IT MATTERS) */

      fd_vinyl_data_free( data, obj );

      line[ line_idx ].obj     = NULL;
      line[ line_idx ].ele_idx = ULONG_MAX;                        ele0[ ele_idx ].line_idx = ULONG_MAX;
      line[ line_idx ].ctl     = fd_vinyl_line_ctl( ver+1UL, 0L ); /* bump ver */

      fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx, FD_VINYL_LINE_EVICT_PRIO_LRU );

      /* If we are erasing an existing pair, append a dead block to
         the bstream.  This generates two pieces of bstream garbage (the
         old pair and the dead block itself).  Likewise, if we are
         erasing an existing pair or cancelling / erasing a pair
         creation, remove the element from the meta.  Note that
         req_flag_modify==1 implies req_flag_erase==1 but not vice versa
         at this point. */

      if( FD_LIKELY( req_flag_modify & modifying_existing ) ) {

        ulong val_esz_before = fd_vinyl_bstream_ctl_sz( ele0[ ele_idx ].phdr.ctl );

        accum_garbage_cnt += 2UL;
        accum_garbage_sz  += fd_vinyl_bstream_pair_sz( val_esz_before ) + FD_VINYL_BSTREAM_BLOCK_SZ;

        fd_vinyl_io_append_dead( io, &ele0[ ele_idx ].phdr, NULL, 0UL );
        append_cnt++;
        accum_dead_cnt++;

      }

      if( FD_LIKELY( req_flag_modify | (!modifying_existing) ) ) {
        fd_vinyl_meta_remove_fast( ele0, ele_max, lock, lock_shift, line, line_cnt, ele_idx );

        ulong pair_cnt = vinyl->pair_cnt;
        FD_CRIT( (0UL<pair_cnt) & (pair_cnt<=pair_max), "corruption detected" );
        vinyl->pair_cnt = pair_cnt - 1UL;
      }

      DONE( FD_VINYL_SUCCESS );

    next_release: /* silly language restriction */;

#     undef DONE

    } /* for batch_idx */

    comp_err = FD_VINYL_SUCCESS;
    break;
  }
