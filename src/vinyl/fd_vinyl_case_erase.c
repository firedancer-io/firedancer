  case FD_VINYL_REQ_TYPE_ERASE: {

    fd_vinyl_key_t const * req_key = MAP_REQ_GADDR( req->key_gaddr, fd_vinyl_key_t, batch_cnt );
    schar *                req_err = MAP_REQ_GADDR( req->err_gaddr, schar,          batch_cnt );

    if( FD_UNLIKELY( (!!batch_cnt) & ((!req_key) | (!req_err)) ) ) {
      comp_err = FD_VINYL_ERR_INVAL;
      break;
    }

    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {

      /* Query vinyl meta for key.  If pair key does not exist, fail
         with KEY. */

      fd_vinyl_key_t const * key = req_key + batch_idx;

      ulong memo = fd_vinyl_key_memo( meta_seed, key );

      ulong _ele_idx; /* avoid pointer escape */
      int   err = fd_vinyl_meta_query_fast( ele0, ele_max, key, memo, &_ele_idx );
      ulong ele_idx = _ele_idx; /* In [0,ele_max) */

      if( FD_UNLIKELY( err ) ) {
        FD_COMPILER_MFENCE();
        req_err[ batch_idx ] = (schar)FD_VINYL_ERR_KEY;
        FD_COMPILER_MFENCE();
        fail_cnt++;
        continue;
      }

      /* At this point, pair key exists. */

      ulong line_idx = ele0[ ele_idx ].line_idx;

      if( FD_LIKELY( line_idx<line_cnt ) ) {

        /* At this point, pair key is cached.  If it is currently
           acquired for read or modify, fail with AGAIN.  Otherwise,
           evict it. */

        FD_CRIT( line[ line_idx ].ele_idx==ele_idx, "corruption detected" );

        fd_vinyl_data_obj_t * obj = line[ line_idx ].obj;

        FD_ALERT( fd_vinyl_data_is_valid_obj( obj, vol, vol_cnt ), "corruption detected" );
        FD_CRIT ( obj->line_idx==line_idx,                         "corruption detected" );
        FD_CRIT ( !obj->rd_active,                                 "corruption detected" );

        ulong ctl = line[ line_idx ].ctl;

        ulong ver = fd_vinyl_line_ctl_ver( ctl );
        long  ref = fd_vinyl_line_ctl_ref( ctl );

        if( FD_UNLIKELY( ref ) ) {
          FD_COMPILER_MFENCE();
          req_err[ batch_idx ] = (schar)FD_VINYL_ERR_AGAIN;
          FD_COMPILER_MFENCE();
          fail_cnt++;
          continue;
        }

        line[ line_idx ].obj     = NULL;
        line[ line_idx ].ele_idx = ULONG_MAX; //ele0[ ele_idx ].line_idx = ULONG_MAX; /* Technically not necessary given below */
        line[ line_idx ].ctl     = fd_vinyl_line_ctl( ver+1UL, 0L ); /* bump version */

        fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx, FD_VINYL_LINE_EVICT_PRIO_LRU );

        fd_vinyl_data_free( data, obj );

      } else {

        FD_CRIT( line_idx==ULONG_MAX, "corruption detected" );

      }

      /* At this point, pair key exists and is not cached.  Append a
         dead block and remove it from the meta.  This generates two
         pieces of bstream garbage: the old pair and the dead block
         itself (the dead block is only needed for recovery and then
         only while the old pair is in the bstream's past). */

      /* FIXME: COMPACT SEQUENTIAL DEADS IN THE BSTREAM TO BE MORE
         SPACE EFFICIENT? */

      ulong val_esz = fd_vinyl_bstream_ctl_sz( ele0[ ele_idx ].phdr.ctl );

      accum_garbage_cnt += 2UL;
      accum_garbage_sz  += fd_vinyl_bstream_pair_sz( val_esz ) + FD_VINYL_BSTREAM_BLOCK_SZ;

      fd_vinyl_io_append_dead( io, &ele0[ ele_idx ].phdr, NULL, 0UL );
      append_cnt++;
      accum_dead_cnt++;

      fd_vinyl_meta_remove_fast( ele0, ele_max, lock, lock_shift, line, line_cnt, ele_idx );

      ulong pair_cnt = vinyl->pair_cnt;
      FD_CRIT( pair_cnt, "corruption detected" );
      vinyl->pair_cnt = pair_cnt - 1UL;

      FD_COMPILER_MFENCE();
      req_err[ batch_idx ] = (schar)FD_VINYL_SUCCESS;
      FD_COMPILER_MFENCE();
    }

    comp_err = FD_VINYL_SUCCESS;
    break;
  }
