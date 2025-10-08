  case FD_VINYL_REQ_TYPE_FETCH: {
    fd_vinyl_key_t const * req_key = MAP_REQ_GADDR( req->key_gaddr, fd_vinyl_key_t, batch_cnt );

    if( FD_UNLIKELY( (!!batch_cnt) & (!req_key) ) ) break;

    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {

      /* Query vinyl meta for key */

      fd_vinyl_key_t const * key = req_key + batch_idx;

      ulong memo = fd_vinyl_key_memo( meta_seed, key );

      ulong _ele_idx; /* avoid pointer escape */
      int   err = fd_vinyl_meta_query_fast( ele0, ele_max, key, memo, &_ele_idx );
      ulong ele_idx = _ele_idx; /* In [0,ele_max) */

      if( FD_UNLIKELY( err                                 ) ||
          FD_UNLIKELY( ele0[ ele_idx ].phdr.ctl==ULONG_MAX ) ) continue; /* Nothing to fetch */

      /* At this point, pair key exists at seq_present.  If pair key is
         already cached, we set the priority to MRU (to reflect the
         handling when the key is not cached). */

      ulong line_idx = ele0[ ele_idx ].line_idx;

      FD_CRIT( (line_idx<line_cnt) | (line_idx==ULONG_MAX), "corruption detected" );

      if( FD_LIKELY( line_idx<line_cnt ) ) {

        FD_CRIT( line[ line_idx ].ele_idx==ele_idx, "corruption detected" );

        fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx, FD_VINYL_LINE_EVICT_PRIO_MRU );

        continue;
      }

      /* At this point, pair key existsat seq_present but is not cached.
         Evict the least recently used evictable line to make room to
         cache this pair.  Connect this line to meta element ele_idx,
         set the line's reference count to zero, bump the line's version
         and set the eviction priority to MRU.  We don't modify any
         shared fields in meta element ele_idx so we can do the
         modification fast.

         We do this upfront to free data cache for the alloc if the LRU
         line is in use and to handle the same pair appearing multiple
         times in an acquire.

         The mechanics for fetch requests with redundant keys are
         similar to acquire-for-read requests.  In this case, trailing
         redundant fetches will see the pair as cached (due to the first
         redundant fetch ... this one), set the eviction priority to MRU
         (again) and then continue. */

      ulong pair_ctl =        ele0[ ele_idx ].phdr.ctl;
      ulong val_sz   = (ulong)ele0[ ele_idx ].phdr.info.val_sz;

      FD_CRIT( fd_vinyl_bstream_ctl_type( pair_ctl )==FD_VINYL_BSTREAM_CTL_TYPE_PAIR, "corruption detected" );
      FD_CRIT( val_sz<=FD_VINYL_VAL_MAX,                                              "corruption detected" );

      line_idx = fd_vinyl_line_evict_lru( &vinyl->line_idx_lru, line, line_cnt, ele0, ele_max, data );

      ulong line_ctl = line[ line_idx ].ctl;

      ulong ver = fd_vinyl_line_ctl_ver( line_ctl );

      line[ line_idx ].ele_idx = ele_idx; ele0[ ele_idx ].line_idx = line_idx;
      line[ line_idx ].ctl     = fd_vinyl_line_ctl( ver+1UL, 0L );

      fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx, FD_VINYL_LINE_EVICT_PRIO_MRU );

      /* Allocate an appropriately sized object to hold this pair,
         connect it to this line and start reading the encoded pair data
         into obj. */

      ulong szc = fd_vinyl_data_szc( val_sz );

      fd_vinyl_data_obj_t * obj = fd_vinyl_data_alloc( data, szc );
      if( FD_UNLIKELY( !obj ) ) FD_LOG_CRIT(( "increase data cache size" ));

      line[ line_idx ].obj = obj; obj->line_idx = line_idx;

      /* Start reading encoded pair data and defer the validation and
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

      cobj->rd_err = (schar *)cobj->unused;

      fd_vinyl_io_read( io, cobj->rd );
      read_cnt++;
    }

    break;
  }
