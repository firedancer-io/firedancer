  case FD_VINYL_REQ_TYPE_ACQUIRE: {
    ulong                  req_flags     = (ulong)req->flags;
    fd_vinyl_key_t const * req_key       = MAP_REQ_GADDR( req->key_gaddr,       fd_vinyl_key_t, batch_cnt );
    ulong *                req_val_gaddr = MAP_REQ_GADDR( req->val_gaddr_gaddr, ulong,          batch_cnt );
    schar *                req_err       = MAP_REQ_GADDR( req->err_gaddr,       schar,          batch_cnt );

    int req_evict_prio = fd_vinyl_req_evict_prio( req_flags );

    int bad_gaddr = (!!batch_cnt) & ((!req_key) | (!req_val_gaddr) | (!req_err));
    int bad_quota = quota_rem<batch_cnt;

    if( FD_UNLIKELY( bad_gaddr | bad_quota ) ) {
      comp_err = bad_gaddr ? FD_VINYL_ERR_INVAL : FD_VINYL_ERR_FULL;
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

        ulong val_sz   = (ulong)ele0[ ele_idx ].phdr.info.val_sz;
        ulong line_idx = ele0[ ele_idx ].line_idx;

        FD_CRIT( val_sz<=FD_VINYL_VAL_MAX,                    "corruption detected" );
        FD_CRIT( (line_idx<line_cnt) | (line_idx==ULONG_MAX), "corruption detected" );

        if( FD_LIKELY( line_idx<line_cnt ) ) {

          /* At this point, pair key is cached.  Get the cache info for
             line line_idx. */

          FD_MCNT_INC( ACCDB, READ_OPS_SHARED_CACHE, 1UL );

          FD_CRIT( line[ line_idx ].ele_idx==ele_idx, "corruption detected" );

          FD_ATOMIC_FETCH_AND_OR( &line[ line_idx ].specread_ctl,
                                  FD_VINYL_LINE_SRC_CHANCE );

          fd_vinyl_data_obj_t * obj = line[ line_idx ].obj;

          FD_ALERT( fd_vinyl_data_is_valid_obj( obj, vol, vol_cnt ), "corruption detected" );
          FD_CRIT ( obj->line_idx==line_idx,                         "corruption detected" );

          ulong line_ctl = line[ line_idx ].ctl;

          ulong ver = fd_vinyl_line_ctl_ver( line_ctl );
          long  ref = fd_vinyl_line_ctl_ref( line_ctl );

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

        line_idx = fd_accdb_clock_evict( ctx, line, line_cnt, ele0, ele_max, data );

        ulong line_ctl = line[ line_idx ].ctl;
        ulong ver      = fd_vinyl_line_ctl_ver( line_ctl );

        line[ line_idx ].ele_idx = ele_idx; ele0[ ele_idx ].line_idx = line_idx;
        line[ line_idx ].ctl     = fd_vinyl_line_ctl( ver+1UL, 1L );

        line[ line_idx ].specread_ctl =
            fd_uint_if( req_evict_prio<=FD_VINYL_LINE_EVICT_PRIO_MRU,
                        FD_VINYL_LINE_SRC_CHANCE, 0U );

        /* Allocate an appropriately sized object to hold this pair,
           connect it to this line and report the location to the client. */

        ulong val_max = val_sz;

        ulong szc = fd_vinyl_data_szc( val_max );

        fd_vinyl_data_obj_t * obj = fd_vinyl_data_alloc( data, szc );
        if( FD_UNLIKELY( !obj ) ) FD_LOG_CRIT(( "increase data cache size" ));

        line[ line_idx ].obj = obj; obj->line_idx = line_idx;

        void * val = fd_vinyl_data_obj_val( obj );

        req_val_gaddr[ batch_idx ] = (ulong)val - data_laddr0;

        /* If we need to do I/O, start reading encoded pair data and
           defer the data integrity and decoding to later (and then in
           whatever order the I/O layer sees fit). */

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

      } /* pair key meta cached */

      /* At this point, pair key does not exist at bstream seq_present
         and is not in the process of being created. */

      DONE( FD_VINYL_ERR_KEY );

    next_acquire: /* silly language restriction */;

#   undef DONE

    } /* for batch_idx */

    FD_CRIT( !read_cnt, "corruption detected" );

    comp_err = FD_VINYL_SUCCESS;
    break;
  }
