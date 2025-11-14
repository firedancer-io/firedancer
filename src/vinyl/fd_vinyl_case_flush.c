  case FD_VINYL_REQ_TYPE_FLUSH: {

    fd_vinyl_key_t const * req_key = MAP_REQ_GADDR( req->key_gaddr, fd_vinyl_key_t, batch_cnt );

    if( FD_UNLIKELY( (!!batch_cnt) & (!req_key) ) ) break; /* flushes don't generate completions */

    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {

      /* Query vinyl meta for key */

      fd_vinyl_key_t const * key = req_key + batch_idx;

      ulong memo = fd_vinyl_key_memo( meta_seed, key );

      ulong _ele_idx; /* avoid pointer escape */
      int   err = fd_vinyl_meta_query_fast( ele0, ele_max, key, memo, &_ele_idx );
      ulong ele_idx = _ele_idx; /* In [0,ele_max) */

      if( FD_UNLIKELY( err ) ) continue; /* Nothing to flush */

      /* At this point, pair key exists at bstream seq_present or is
         in the process of being created.  If pair key is not cached,
         there's nothing to flush. */

      ulong line_idx = ele0[ ele_idx ].line_idx;

      if( FD_UNLIKELY( line_idx==ULONG_MAX ) ) continue;

      /* At this point, pair key is cached at line line_idx.  Make this
         line the LRU.  If pair key is currently acquired, that's as
         much as we can do now. */

      FD_CRIT( line_idx<line_cnt,                 "corruption detected" );
      FD_CRIT( line[ line_idx ].ele_idx==ele_idx, "corruption detected" );

      fd_vinyl_data_obj_t * obj = line[ line_idx ].obj;

      FD_ALERT( fd_vinyl_data_is_valid_obj( obj, vol, vol_cnt ), "corruption detected" );
      FD_CRIT ( obj->line_idx==line_idx,                         "corruption detected" );
      FD_CRIT ( !obj->rd_active,                                 "corruption detected" );

      fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx, FD_VINYL_LINE_EVICT_PRIO_LRU );

      ulong ctl = line[ line_idx ].ctl;

      ulong ver = fd_vinyl_line_ctl_ver( ctl );
      long  ref = fd_vinyl_line_ctl_ref( ctl );

      if( FD_UNLIKELY( ref ) ) continue;

      /* At this point, pair key is cached, not acquired and the line
         is at LRU position.  Flush the cached data.  We don't modify
         any shared fields of meta element ele_idx so we can do this
         fast. */

      line[ line_idx ].obj     = NULL;
      line[ line_idx ].ele_idx = ULONG_MAX;
      line[ line_idx ].ctl     = fd_vinyl_line_ctl( ver+1UL, 0UL );
      /* evict prio updated above */

      ele0[ ele_idx ].line_idx = ULONG_MAX;

      fd_vinyl_data_free( data, obj );

    }

    break;
  }
