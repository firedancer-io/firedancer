  case FD_VINYL_REQ_TYPE_ACQUIRE: {
    ulong                  req_flags     = (ulong)req->flags;
    ulong                  req_val_max   = (ulong)req->val_max;
    fd_vinyl_key_t const * req_key       = MAP_REQ_GADDR( req->key_gaddr,       fd_vinyl_key_t, batch_cnt );
    ulong *                req_val_gaddr = MAP_REQ_GADDR( req->val_gaddr_gaddr, ulong,          batch_cnt );
    schar *                req_err       = MAP_REQ_GADDR( req->err_gaddr,       schar,          batch_cnt );

    int req_flag_modify = fd_vinyl_req_flag_modify( req_flags );
    int req_flag_ignore = fd_vinyl_req_flag_ignore( req_flags );
    int req_flag_create = fd_vinyl_req_flag_create( req_flags );
    int req_flag_excl   = fd_vinyl_req_flag_excl  ( req_flags );
    int req_evict_prio  = fd_vinyl_req_evict_prio ( req_flags );

    int bad_gaddr   = (!!batch_cnt) & ((!req_key) | (!req_val_gaddr) | (!req_err));
    int bad_val_max = req_flag_modify & (req_val_max>FD_VINYL_VAL_MAX);
    int bad_quota   = quota_rem<batch_cnt;

    if( FD_UNLIKELY( bad_gaddr | bad_val_max | bad_quota ) ) {
      comp_err = (bad_gaddr | bad_val_max) ? FD_VINYL_ERR_INVAL : FD_VINYL_ERR_FULL;
      break;
    }

    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {

#     define DONE(err) do {                                  \
        int _err = (err);                                    \
        FD_COMPILER_MFENCE();                                \
        req_err[ batch_idx ] = (schar)_err;                  \
        FD_COMPILER_MFENCE();                                \
        quota_rem -= (ulong) !_err;                          \
        fail_cnt  += (ulong)!!_err;                          \
        goto next_acquire; /* sigh ... can't use continue */ \
      } while(0)

      /* Query vinyl meta for key */

      fd_vinyl_key_t const * key = req_key + batch_idx;

      ulong memo = fd_vinyl_key_memo( meta_seed, key );

      ulong _ele_idx; /* avoid pointer escape */
      int   err = fd_vinyl_meta_query_fast( ele0, ele_max, key, memo, &_ele_idx );
      ulong ele_idx = _ele_idx; /* In [0,ele_max) */

      if( FD_LIKELY( !err ) ) { /* pair key meta cached */

        /* At this point, pair key either exists at bstream seq_present
           or is in the process of being created.  If pair key is being
           created, fail with AGAIN (it must be acquired for modify). */

        ulong pair_ctl = ele0[ ele_idx ].phdr.ctl;

        FD_CRIT( (fd_vinyl_bstream_ctl_type( pair_ctl )==FD_VINYL_BSTREAM_CTL_TYPE_PAIR) | (pair_ctl==ULONG_MAX),
                 "corruption detected" );

        if( FD_UNLIKELY( pair_ctl==ULONG_MAX ) ) DONE( FD_VINYL_ERR_AGAIN );

        /* At this point, pair key exists at bstream seq_present. */

        ulong val_sz   = (ulong)ele0[ ele_idx ].phdr.info._val_sz;
        ulong line_idx = ele0[ ele_idx ].line_idx;

        FD_CRIT( val_sz<=FD_VINYL_VAL_MAX,                    "corruption detected" );
        FD_CRIT( (line_idx<line_cnt) | (line_idx==ULONG_MAX), "corruption detected" );

        if( FD_LIKELY( line_idx<line_cnt ) ) {

          /* At this point, pair key is cached.  Get the cache info for
             line line_idx. */

          FD_CRIT( line[ line_idx ].ele_idx==ele_idx, "corruption detected" );

          fd_vinyl_data_obj_t * obj = line[ line_idx ].obj;

          FD_ALERT( fd_vinyl_data_is_valid_obj( obj, vol, vol_cnt ), "corruption detected" );
          FD_CRIT ( obj->line_idx==line_idx,                         "corruption detected" );

          ulong line_ctl = line[ line_idx ].ctl;

          ulong ver = fd_vinyl_line_ctl_ver( line_ctl );
          long  ref = fd_vinyl_line_ctl_ref( line_ctl );

          if( FD_LIKELY( !req_flag_modify ) ) {

            /* At this point, we are acquiring a cached pair for read.
               If the line is acquired for modify, fail with AGAIN.  If
               there are too many acquires for read on this pair, CRIT
               (could consider AGAIN here).  Otherwise, we update the
               ref count (don't change the ver), point the client at the
               line caching pair key to finish the acquire.  Note that
               we don't validate the pair header if we detect that an
               earlier acquire in this batch started fetching the pair
               because the read might still be in progress (see note
               below for more details). */

            if( FD_UNLIKELY( ref<0L                     ) ) DONE( FD_VINYL_ERR_AGAIN );
            if( FD_UNLIKELY( ref>=FD_VINYL_LINE_REF_MAX ) ) FD_LOG_CRIT(( "too many acquires for read on this pair" ));

            if( FD_LIKELY( !obj->rd_active ) ) {
              fd_vinyl_bstream_phdr_t * phdr = fd_vinyl_data_obj_phdr( obj );

              FD_CRIT( fd_vinyl_data_obj_val_max( obj ) >= val_sz,                                  "corruption detected" );
              FD_CRIT( phdr->ctl==fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR,
                                                        FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz ),   "corruption detected" );
              FD_CRIT( fd_vinyl_key_eq( &phdr->key, key ),                                          "corruption detected" );
              FD_CRIT( !memcmp( &phdr->info, &ele0[ ele_idx ].phdr.info, sizeof(fd_vinyl_info_t) ), "corruption detected" );
            }

            line[ line_idx ].ctl = fd_vinyl_line_ctl( ver, ref+1L ); /* don't bump ver */

            req_val_gaddr[ batch_idx ] = (ulong)fd_vinyl_data_obj_val( obj ) - data_laddr0;

            DONE( FD_VINYL_SUCCESS );

          }

          /* At this point, we are acquiring a cached pair for modify.
             If we are not allowed to acquire an existing pair for
             modify (INVAL) or if the line line_idx is already acquired
             for anything (AGAIN), fail. */

          if( FD_UNLIKELY( ref           ) ) DONE( FD_VINYL_ERR_AGAIN );
          if( FD_UNLIKELY( req_flag_excl ) ) DONE( FD_VINYL_ERR_INVAL );

          fd_vinyl_bstream_phdr_t * phdr = fd_vinyl_data_obj_phdr( obj );

          FD_CRIT( !obj->rd_active,                                                             "corruption detected" );
          FD_CRIT( fd_vinyl_data_obj_val_max( obj ) >= val_sz,                                  "corruption detected" );
          FD_CRIT( phdr->ctl==fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR,
                                                    FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz ),   "corruption detected" );
          FD_CRIT( fd_vinyl_key_eq( &phdr->key, key ),                                          "corruption detected" );
          FD_CRIT( !memcmp( &phdr->info, &ele0[ ele_idx ].phdr.info, sizeof(fd_vinyl_info_t) ), "corruption detected" );

          /* If the ignore flag is set, set the cached value size to 0. */

          if( req_flag_ignore ) {
            phdr->info._val_sz = 0U;
            val_sz            = 0UL;
          }

          /* If the current location for the pair key's data isn't
             sufficient to hold the worst case val_sz that the client
             might modify the pair's value into, adjust the space
             available for the pair to the user's val_max.  Because we
             might be ignoring the existing value, this could be smaller
             than the current object.  (We could chose to not trim in
             this case because it will get trimmed again on release.
             But doing so makes a more consistent guarantee to the
             client and makes testing easier.) */

          ulong csz = sizeof(fd_vinyl_bstream_phdr_t) + val_sz;

          ulong szc_new = fd_vinyl_data_szc( fd_ulong_max( val_sz, req_val_max ) );
          ulong szc_old = (ulong)obj->szc;

          if( FD_UNLIKELY( szc_new != szc_old ) ) {

            fd_vinyl_data_obj_t * obj_new = fd_vinyl_data_alloc( data, szc_new );
            if( FD_UNLIKELY( !obj_new ) ) FD_LOG_CRIT(( "increase data cache size" ));

            fd_vinyl_bstream_phdr_t * phdr_new = fd_vinyl_data_obj_phdr( obj_new );

            memcpy( phdr_new, phdr, csz );

            fd_vinyl_data_free( data, obj );

            phdr = phdr_new;
            obj  = obj_new;

            line[ line_idx ].obj = obj; obj->line_idx = line_idx; obj->rd_active = (short)0;
          }

          /* Zero out any remaining space in the pair. */

          ulong zsz = fd_vinyl_bstream_pair_sz( fd_vinyl_data_szc_val_max( szc_new ) ) - csz;
          memset( ((uchar *)phdr) + csz, 0, zsz );

          /* Finish up acquiring for modify */

        //line[ line_idx ].obj     = ... already init;
        //line[ line_idx ].ele_idx = ... already init;
          line[ line_idx ].ctl     = fd_vinyl_line_ctl( ver+1UL, -1L ); /* bump ver */

          fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx, req_evict_prio );

        //phdr->ctl  = ... already init
        //phdr->key  = ... already init
        //phdr->info = ... already init

        //ele0[ ele_idx ] = ... already init

          req_val_gaddr[ batch_idx ] = (ulong)fd_vinyl_data_obj_val( obj ) - data_laddr0;

          DONE( FD_VINYL_SUCCESS );

        } /* pair key data cached */

        /* At this point, pair key is not cached.  If we are not allowed
           to acquire this pair, fail.  Otherwise, evict the least
           recently used evictable line (this should always be possible
           if quotas are confiured correctly) to make room to cache this
           pair.  Connect this line to meta element ele_idx, set the
           line's reference count appropriately, bump the line's version
           and move the line to the desired location in the eviction
           sequence.  We don't modify any shared fields in meta element
           ele_idx so we can do the modification fast.

           We do this upfront to free data cache for the alloc if the
           LRU line is in use and to handle the same pair appearing
           multiple times in an acquire.

           That is, if req_key appears multiple times in an acquire to
           modify, the trailing redundant acquires will see the object
           as cached with ref==-1 and fail with AGAIN.  If the key
           appears multiple times in an acquire for read, the trailing
           redundant acquires will see the object as cached with ref>0
           and rd_active==1, conclude that the first redundant acquire
           is in the process of reading the pair into cache, skip any
           racy metadata checks, increase the ref count and succeed.

           IMPORTANT SAFETY TIP!  Note that this implies that client
           doing an acquire-for-read with redundant keys and with
           speculative processing will see req_err transition to success
           for the trailing redundant items for a key before the leading
           item of that key transitions to success (and thus before the
           object is fully read / verified and/or decoded).  It is up to
           the client doing speculative cut through processing to avoid
           redundant keys or react accordingly. */

        if( FD_UNLIKELY( req_flag_modify & req_flag_excl ) ) DONE( FD_VINYL_ERR_INVAL );

        line_idx = fd_vinyl_line_evict_lru( &vinyl->line_idx_lru, line, line_cnt, ele0, ele_max, data );

        ulong line_ctl = line[ line_idx ].ctl;

        ulong ver = fd_vinyl_line_ctl_ver( line_ctl );

        line[ line_idx ].ele_idx = ele_idx; ele0[ ele_idx ].line_idx = line_idx;
        line[ line_idx ].ctl     = fd_vinyl_line_ctl( ver+1UL, req_flag_modify ? -1L : 1L );

        fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx, req_evict_prio );

        /* Allocate an appropriately sized object to hold this pair,
           connect it to this line and report the location to the client. */

        ulong val_max = fd_ulong_if( !req_flag_modify, val_sz,
                        fd_ulong_if( !req_flag_ignore, fd_ulong_max( val_sz, req_val_max ),
                                                       req_val_max ) );

        ulong szc = fd_vinyl_data_szc( val_max );

        fd_vinyl_data_obj_t * obj = fd_vinyl_data_alloc( data, szc );
        if( FD_UNLIKELY( !obj ) ) FD_LOG_CRIT(( "increase data cache size" ));

        line[ line_idx ].obj = obj; obj->line_idx = line_idx;

        void * val = fd_vinyl_data_obj_val( obj );

        req_val_gaddr[ batch_idx ] = (ulong)val - data_laddr0;

        /* If we need to do I/O, start reading encoded pair data and
           defer the data integrity and decoding to later (and then in
           whatever order the I/O layer sees fit). */

        if( FD_LIKELY( !(req_flag_modify & req_flag_ignore) ) ) {
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

          quota_rem--;
          goto next_acquire;
        }

        /* At this point, we are acquiring to modify but we don't need
           the existing value.  We populate the cached pair header
           appropriately for the modify and zero the rest to complete
           this request immediately. */

        obj->rd_active = (short)0;

        fd_vinyl_bstream_phdr_t * phdr = fd_vinyl_data_obj_phdr( obj );

        phdr->ctl  = fd_vinyl_bstream_ctl( FD_VINYL_BSTREAM_CTL_TYPE_PAIR, FD_VINYL_BSTREAM_CTL_STYLE_RAW, val_sz );
        phdr->key  = *key;
        phdr->info = ele0[ ele_idx ].phdr.info;

        phdr->info._val_sz = 0U;

        memset( val, 0, fd_vinyl_data_szc_obj_footprint( szc ) - sizeof(fd_vinyl_data_obj_t) - sizeof(fd_vinyl_bstream_phdr_t) );

        DONE( FD_VINYL_SUCCESS );

      } /* pair key meta cached */

      /* At this point, pair key does not exist at bstream seq_present
         and is not in the process of being created.  If we aren't
         allowed to create pair key, fail.  Otherwise, evict the least
         recently used evictable line (this should always be possible if
         quotas are confiured correctly) to make room to cache this
         pair, set the line's reference count appropriately, bump the
         version and move the line to the desired location in the
         eviction sequence.  We do this upfront to free data cache for
         the alloc if the LRU line is in use. */

      if( FD_UNLIKELY( !(req_flag_modify & req_flag_create) ) ) DONE( FD_VINYL_ERR_KEY );

      ulong line_idx = fd_vinyl_line_evict_lru( &vinyl->line_idx_lru, line, line_cnt, ele0, ele_max, data );

      ulong line_ctl = line[ line_idx ].ctl;

      ulong ver = fd_vinyl_line_ctl_ver( line_ctl );

      line[ line_idx ].ctl = fd_vinyl_line_ctl( ver+1UL, -1L );

      fd_vinyl_line_evict_prio( &vinyl->line_idx_lru, line, line_cnt, line_idx, req_evict_prio );

      /* Allocate an appropriately sized object to hold this pair and
         connect it to this line. */

      ulong szc = fd_vinyl_data_szc( req_val_max );

      fd_vinyl_data_obj_t * obj = fd_vinyl_data_alloc( data, szc );
      if( FD_UNLIKELY( !obj ) ) FD_LOG_CRIT(( "increase data cache size" ));

      line[ line_idx ].obj = obj; obj->line_idx = line_idx; obj->rd_active = (short)0;

      /* Allocate a meta element to hold metadata for this pair and
         connect it to this line.  Since we are inserting at meta
         element ele_idx, we don't need to lock anything so long as we
         mark the element as in use very last. */

      ulong pair_cnt = vinyl->pair_cnt;
      if( FD_UNLIKELY( pair_cnt>=pair_max ) ) FD_LOG_CRIT(( "increase meta cache size" ));
      vinyl->pair_cnt = pair_cnt + 1UL;

      ele0[ ele_idx ].memo     = memo;
    //ele0[ ele_idx ].phdr.ctl init below
      ele0[ ele_idx ].phdr.key = *key;
      memset( &ele0[ ele_idx ].phdr.info, 0, sizeof(fd_vinyl_info_t) ); /* sets val_sz to 0 */
      ele0[ ele_idx ].line_idx = line_idx;
      ele0[ ele_idx ].seq      = 0UL; /* Will be init on release */

      FD_COMPILER_MFENCE();
      ele0[ ele_idx ].phdr.ctl = ULONG_MAX; /* Mark as being created */
      FD_COMPILER_MFENCE();

      line[ line_idx ].ele_idx = ele_idx;

      /* Initialize the data region for a new pair */

      *fd_vinyl_data_obj_phdr( obj ) = ele0[ ele_idx ].phdr;

      uchar * val = (uchar *)fd_vinyl_data_obj_val( obj );

      memset( val, 0, fd_vinyl_data_szc_obj_footprint( szc ) - sizeof(fd_vinyl_data_obj_t) - sizeof(fd_vinyl_bstream_phdr_t) );

      req_val_gaddr[ batch_idx ] = (ulong)val - data_laddr0;

      DONE( FD_VINYL_SUCCESS );

    next_acquire: /* silly language restriction */;

#     undef DONE

    } /* for batch_idx */

    FD_CRIT( (!read_cnt) | (!(req_flag_modify & req_flag_ignore)), "corruption detected" );

    comp_err = FD_VINYL_SUCCESS;
    break;
  }
