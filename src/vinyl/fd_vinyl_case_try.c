  case FD_VINYL_REQ_TYPE_TRY: {

    FD_STATIC_ASSERT( FD_VINYL_LINE_VER_MAX==((1UL<<32)-1UL), update_impl_for_ver_max );

    ulong                  req_flags     = (ulong)req->flags;
    fd_vinyl_key_t const * req_key       = MAP_REQ_GADDR( req->key_gaddr,       fd_vinyl_key_t,     batch_cnt );
    ulong *                req_val_gaddr = MAP_REQ_GADDR( req->val_gaddr_gaddr, ulong,          2UL*batch_cnt );
    schar *                req_err       = MAP_REQ_GADDR( req->err_gaddr,       schar,              batch_cnt );

    int req_evict_prio = fd_vinyl_req_evict_prio( req_flags );

    if( FD_UNLIKELY( (!!batch_cnt) & ((!req_key) | (!req_val_gaddr) | (!req_err)) ) ) {
      comp_err = FD_VINYL_ERR_INVAL;
      break;
    }

    ulong * req_try = req_val_gaddr + batch_cnt;

    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {

#     define DONE(err,try) do {                          \
        int _err = (err);                                \
        req_try[ batch_idx ] = (try);                    \
        FD_COMPILER_MFENCE();                            \
        req_err[ batch_idx ] = (schar)_err;              \
        FD_COMPILER_MFENCE();                            \
        fail_cnt += (ulong)!!_err;                       \
        goto next_try; /* sigh ... can't use continue */ \
      } while(0)

      /* Query vinyl meta for key.  If pair key does not exist at
         bstream seq_present and is not being created, there's nothing
         to try and fail with KEY.  If it is being created (which
         implies it is also acquired for modify), fail with AGAIN. */

      fd_vinyl_key_t const * key = req_key + batch_idx;

      ulong memo = fd_vinyl_key_memo( meta_seed, key );

      ulong _ele_idx; /* avoid pointer escape */
      int   err = fd_vinyl_meta_query_fast( ele0, ele_max, key, memo, &_ele_idx );
      ulong ele_idx = _ele_idx; /* In [0,ele_max) */

      if( FD_UNLIKELY( err ) ) DONE( FD_VINYL_ERR_KEY,   ULONG_MAX );

      ulong pair_ctl = ele0[ ele_idx ].phdr.ctl;

      if( FD_UNLIKELY( pair_ctl==ULONG_MAX ) ) DONE( FD_VINYL_ERR_AGAIN, ULONG_MAX );

      FD_CRIT( fd_vinyl_bstream_ctl_type( pair_ctl )==FD_VINYL_BSTREAM_CTL_TYPE_PAIR, "corruption detected" );

      ulong val_sz = (ulong)ele0[ ele_idx ].phdr.info.val_sz;

      FD_CRIT( val_sz<=FD_VINYL_VAL_MAX, "corruption detected" );

      /* At this point, pair key exists at bstream seq_present */

      ulong line_idx = ele0[ ele_idx ].line_idx;

      FD_CRIT( (line_idx<line_cnt) | (line_idx==ULONG_MAX), "corruption detected" );

      if( FD_LIKELY( line_idx<line_cnt ) ) {

        /* At this point, pair key is already cached.  If pair key is
           currently acquired for modify or is a redundant try with
           in-progress IO, fail with AGAIN.  Otherwise, we are clear to
           try. */

        FD_CRIT( line[ line_idx ].ele_idx==ele_idx, "corruption detected" );

        fd_vinyl_data_obj_t * obj = line[ line_idx ].obj;

        FD_ALERT( fd_vinyl_data_is_valid_obj( obj, vol, vol_cnt ), "corruption detected" );
        FD_CRIT ( obj->line_idx==line_idx,                         "corruption detected" );

        ulong line_ctl = line[ line_idx ].ctl;

        ulong ver = fd_vinyl_line_ctl_ver( line_ctl );
        long  ref = fd_vinyl_line_ctl_ref( line_ctl );

        if( FD_UNLIKELY( ref<0L ) ) DONE( FD_VINYL_ERR_AGAIN, ULONG_MAX );

        if( FD_LIKELY( !obj->rd_active ) ) {
          fd_vinyl_bstream_phdr_t * phdr = fd_vinyl_data_obj_phdr( obj );

          FD_CRIT( fd_vinyl_data_obj_val_max( obj ) >= val_sz,                                  "corruption detected" );
          FD_CRIT( phdr->ctl==fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR,
                                                    FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz ),   "corruption detected" );
          FD_CRIT( fd_vinyl_key_eq( &phdr->key, key ),                                          "corruption detected" );
          FD_CRIT( !memcmp( &phdr->info, &ele0[ ele_idx ].phdr.info, sizeof(fd_vinyl_info_t) ), "corruption detected" );
        }

        fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx, req_evict_prio );

        req_val_gaddr[ batch_idx ] = (ulong)fd_vinyl_data_obj_val( obj ) - data_laddr0;

        DONE( FD_VINYL_SUCCESS, (ver<<32) | line_idx );

      }

      /* At this point, pair key exists but is not cached.  Evict the
         least recently used evictable line to make room to cache this
         pair.  Connect this line to meta element ele_idx, set the
         line's reference count to zero, bump the line's version and set
         the eviction priority as desired.  We don't modify any shared
         fields in meta element ele_idx so we can do the modification
         fast.

         We do this upfront to free data cache for the alloc if the LRU
         line is in use and to handle the same pair appearing multiple
         times in an acquire.

         The mechanics for try requests with redundant keys are the same
         as acquire-for-read requests. */

      line_idx = fd_vinyl_line_evict_lru( &vinyl->line_idx_lru, line, line_cnt, ele0, ele_max, data );

      ulong line_ctl = line[ line_idx ].ctl;

      ulong ver = fd_vinyl_line_ctl_ver( line_ctl );

      line[ line_idx ].ele_idx = ele_idx; ele0[ ele_idx ].line_idx = line_idx;
      line[ line_idx ].ctl     = fd_vinyl_line_ctl( ver+1UL, 0L );

      fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx, req_evict_prio );

      /* Allocate an appropriately sized object to hold this pair,
         connect it to this line and report the location to the client. */

      ulong szc = fd_vinyl_data_szc( val_sz );

      fd_vinyl_data_obj_t * obj = fd_vinyl_data_alloc( data, szc );
      if( FD_UNLIKELY( !obj ) ) FD_LOG_CRIT(( "increase data cache size" ));

      line[ line_idx ].obj = obj; obj->line_idx = line_idx;

      void * val = fd_vinyl_data_obj_val( obj );

      req_val_gaddr[ batch_idx ] = (ulong)val - data_laddr0;
      req_try      [ batch_idx ] = ((ver+1UL)<<32) | line_idx;

      /* Start reading encoded pair data and defer validation and
         decoding to later (and then in whatever order the I/O layer
         sees fit). */

      obj->rd_active = (short)1;

      int   style   = fd_vinyl_bstream_ctl_style( pair_ctl );
      ulong val_esz = fd_vinyl_bstream_ctl_sz   ( pair_ctl );

      FD_CRIT( val_esz<=FD_VINYL_VAL_MAX,                                   "corruption detected" );
      FD_CRIT( (style!=FD_VINYL_BSTREAM_CTL_STYLE_RAW) | (val_sz==val_esz), "corruption detected" );

      fd_vinyl_data_obj_t * cobj;

      if( FD_LIKELY( style==FD_VINYL_BSTREAM_CTL_STYLE_RAW ) ) cobj = obj;
      else {
        cobj = fd_vinyl_data_alloc( data, fd_vinyl_data_szc( val_esz ) );
        if( FD_UNLIKELY( !cobj ) ) FD_LOG_CRIT(( "increase data cache size" ));
      }

      cobj->rd->ctx = (ulong)obj;
      cobj->rd->seq = ele0[ ele_idx ].seq;
      cobj->rd->dst = fd_vinyl_data_obj_phdr( cobj );
      cobj->rd->sz  = fd_vinyl_bstream_pair_sz( val_esz );

      cobj->rd_err = req_err + batch_idx;

      fd_vinyl_io_read( io, cobj->rd );
      read_cnt++;

    next_try: /* silly language restriction */;

#     undef DONE

    } /* for batch_idx */

    comp_err = FD_VINYL_SUCCESS;
    break;
  }
