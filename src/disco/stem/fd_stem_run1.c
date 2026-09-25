static inline __attribute__((always_inline)) void
STEM_(STEM_RUN1_NAME)( ulong                        in_cnt,
                       fd_frag_meta_t const **      in_mcache,
                       ulong **                     in_fseq,
                       ulong                        out_cnt,
                       fd_frag_meta_t **            out_mcache,
                       ulong                        cons_cnt,
                       ulong *                      _cons_out,
                       ulong **                     _cons_fseq,
                       volatile ulong **            _cons_slow,
                       ulong                        burst,
                       long                         lazy,
                       fd_rng_t *                   rng,
                       void *                       scratch,
                       STEM_CALLBACK_CONTEXT_TYPE * ctx,
                       fd_stem_sleep_t const *      sleep ) {
  (void)sleep; /* unread by a tile with no publish context and no park code */
  /* in frag stream state */
  ulong               in_seq; /* current position in input poll sequence, in [0,in_cnt) */
  fd_stem_tile_in_t * in;     /* in[in_seq] for in_seq in [0,in_cnt) has information about input fragment stream currently at
                                 position in_seq in the in_idx polling sequence.  The ordering of this array is continuously
                                 shuffled to avoid lighthousing effects in the output fragment stream at extreme fan-in and load */

  /* out frag stream state */
  ulong *        out_depth; /* ==fd_mcache_depth( out_mcache[out_idx] ) for out_idx in [0, out_cnt) */
  ulong *        out_seq;  /* next mux frag sequence number to publish for out_idx in [0, out_cnt) ]*/
  int *          out_reliable; /* out_reliable[out_idx] is 1 if out_idx has at least one reliable consumer, else 0 */

  /* out flow control state */
  ulong *        cr_avail;     /* number of flow control credits available to publish downstream across all outs */
  ulong          min_cr_avail; /* minimum number of flow control credits available to publish downstream */
  ulong const ** cons_fseq;    /* cons_fseq[cons_idx] for cons_idx in [0,cons_cnt) is where to receive fctl credits from consumers */
  volatile ulong ** cons_slow; /* cons_slow[cons_idx] for cons_idx in [0,cons_cnt) is where to accumulate slow events */
  ulong *        cons_out;     /* cons_out[cons_idx] for cons_idx in [0,cons_ct) is which out the consumer consumes from */
  ulong *        cons_seq;     /* cons_seq [cons_idx] is the most recent observation of cons_fseq[cons_idx] */

  /* housekeeping state */
  ulong    event_cnt; /* ==in_cnt+cons_cnt+1, total number of housekeeping events */
  ulong    event_seq; /* current position in housekeeping event sequence, in [0,event_cnt) */
  ushort * event_map; /* current mapping of event_seq to event idx, event_map[ event_seq ] is next event to process */
  ulong    async_min; /* minimum number of ticks between processing a housekeeping event, positive integer power of 2 */

  /* performance metrics */
  ulong metric_in_backp;  /* is the run loop currently backpressured by one or more of the outs, in [0,1] */
  ulong metric_backp_cnt; /* Accumulates number of transitions of tile to backpressured between housekeeping events */

  ulong metric_regime_ticks[ FD_METRICS_ENUM_TILE_REGIME_CNT ]; /* How many ticks the tile has spent in each regime */

#if STEM_SLEEP_PARKS
  double sleep_tick_per_ns    = fd_tempo_tick_per_ns( NULL );
  long   sleep_linger_ticks   = (long)((double)FD_SLEEP_LINGER_NS  *sleep_tick_per_ns);
  long   sleep_cap_ticks      = (long)((double)FD_SLEEP_PARK_CAP_NS*sleep_tick_per_ns);
  long   sleep_min_ticks      = (long)((double)FD_SLEEP_PARK_MIN_NS*sleep_tick_per_ns);
  ulong  sleep_idle_streak    = 0UL;
#endif

  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "NULL scratch" ));
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch, STEM_(scratch_align)() ) ) ) FD_LOG_ERR(( "misaligned scratch" ));

  /* in_backp==1, backp_cnt==0 indicates waiting for initial credits,
      cleared during first housekeeping if credits available */
  metric_in_backp  = 1UL;
  metric_backp_cnt = 0UL;
  memset( metric_regime_ticks, 0, sizeof( metric_regime_ticks ) );

  /* in frag stream init */

  in_seq = 0UL; /* First in to poll */
#ifdef STEM_STICKY_POLL_MAX
  fd_stem_tile_in_t * sticky_in  = NULL;
  ulong               sticky_rem = 0UL;
#endif

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  in = (fd_stem_tile_in_t *)FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_stem_tile_in_t), in_cnt*sizeof(fd_stem_tile_in_t) );

  if( FD_UNLIKELY( !!in_cnt && !in_mcache ) ) FD_LOG_ERR(( "NULL in_mcache" ));
  if( FD_UNLIKELY( !!in_cnt && !in_fseq   ) ) FD_LOG_ERR(( "NULL in_fseq"   ));
  if( FD_UNLIKELY( in_cnt > UINT_MAX ) )      FD_LOG_ERR(( "in_cnt too large" ));
  for( ulong in_idx=0UL; in_idx<in_cnt; in_idx++ ) {

    if( FD_UNLIKELY( !in_mcache[ in_idx ] ) ) FD_LOG_ERR(( "NULL in_mcache[%lu]", in_idx ));
    if( FD_UNLIKELY( !in_fseq  [ in_idx ] ) ) FD_LOG_ERR(( "NULL in_fseq[%lu]",   in_idx ));

    fd_stem_tile_in_t * this_in = &in[ in_idx ];

    this_in->mcache = in_mcache[ in_idx ];
    this_in->fseq   = in_fseq  [ in_idx ];

    ulong depth    = fd_mcache_depth( this_in->mcache );
    if( FD_UNLIKELY( depth > UINT_MAX ) ) FD_LOG_ERR(( "in_mcache[%lu] too deep", in_idx ));
    this_in->depth = (uint)depth;
    this_in->idx   = (uint)in_idx;
    this_in->seq   = 0UL;
    this_in->mline = this_in->mcache + fd_mcache_line_idx( this_in->seq, this_in->depth );

    this_in->accum[0] = 0U; this_in->accum[1] = 0U; this_in->accum[2] = 0U;
    this_in->accum[3] = 0U; this_in->accum[4] = 0U; this_in->accum[5] = 0U;
  }

  /* out frag stream init */

  cr_avail     = (ulong *)FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), out_cnt*sizeof(ulong) );
  min_cr_avail = fd_ulong_if( cons_cnt>0UL, 0UL, ULONG_MAX );

  out_depth  = (ulong *)FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), out_cnt*sizeof(ulong) );
  out_seq    = (ulong *)FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), out_cnt*sizeof(ulong) );
  out_reliable = (int *)FD_SCRATCH_ALLOC_APPEND( l, alignof(int),   out_cnt*sizeof(int)   );

  ulong cr_max = fd_ulong_if( !out_cnt || !cons_cnt, 128UL, ULONG_MAX );

  for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {

    if( FD_UNLIKELY( !out_mcache[ out_idx ] ) ) FD_LOG_ERR(( "NULL out_mcache[%lu]", out_idx ));

    out_depth[ out_idx ] = fd_mcache_depth( out_mcache[ out_idx ] );
    out_seq[ out_idx ] = 0UL;

    cr_avail[ out_idx ] = out_depth[ out_idx ];
    out_reliable[ out_idx ] = 0;
  }

  cons_fseq = (ulong const **)FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong const *), cons_cnt*sizeof(ulong const *) );
  cons_slow = (volatile ulong **)FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong *),       cons_cnt*sizeof(ulong *)       );
  cons_out  = (ulong *)       FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),         cons_cnt*sizeof(ulong)         );
  cons_seq  = (ulong *)       FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),         cons_cnt*sizeof(ulong)         );

  if( FD_UNLIKELY( !!cons_cnt && !_cons_fseq ) ) FD_LOG_ERR(( "NULL cons_fseq" ));
  if( FD_UNLIKELY( !!cons_cnt && !_cons_slow ) ) FD_LOG_ERR(( "NULL cons_slow" ));
  for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
    if( FD_UNLIKELY( !_cons_fseq[ cons_idx ] ) ) FD_LOG_ERR(( "NULL cons_fseq[%lu]", cons_idx ));
    if( FD_UNLIKELY( !_cons_slow[ cons_idx ] ) ) FD_LOG_ERR(( "NULL cons_slow[%lu]", cons_idx ));
    cons_fseq[ cons_idx ] = _cons_fseq[ cons_idx ];
    cons_out [ cons_idx ] = _cons_out [ cons_idx ];
    cons_slow[ cons_idx ] = _cons_slow[ cons_idx ];
    cons_seq [ cons_idx ] = __atomic_load_n( _cons_fseq[ cons_idx ], __ATOMIC_ACQUIRE );

    out_reliable[ cons_out[ cons_idx ] ] = 1;
    cr_max = fd_ulong_min( cr_max, out_depth[ cons_out[ cons_idx ] ] );
  }

  if( FD_UNLIKELY( cons_cnt>0UL && burst>cr_max ) ) FD_LOG_ERR(( "one or more out links have insufficient depth for STEM_BURST %lu. cr_max is %lu", burst, cr_max ));

  /* housekeeping init */

  if( lazy<=0L ) lazy = fd_tempo_lazy_default( cr_max );
  if( FD_UNLIKELY( lazy>(long)1e9 ) ) FD_LOG_ERR(( "excessive stem lazy value: %li", lazy ));
  FD_LOG_INFO(( "Configuring housekeeping (lazy %li ns)", lazy ));

  /* Initialize the initial event sequence to immediately update
     cr_avail on the first run loop iteration and then update all the
     ins accordingly. */

  event_cnt = in_cnt + 1UL + cons_cnt;
  event_map = (ushort *)FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort), event_cnt*sizeof(ushort) );
  event_seq = 0UL;                                         event_map[ event_seq++ ] = (ushort)cons_cnt;
  for( ulong   in_idx=0UL;   in_idx< in_cnt;  in_idx++   ) event_map[ event_seq++ ] = (ushort)(in_idx+cons_cnt+1UL);
  for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) event_map[ event_seq++ ] = (ushort)cons_idx;
  event_seq = 0UL;

  async_min = fd_tempo_async_min( lazy, event_cnt, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy %lu %lu", (ulong)lazy, event_cnt ));

  FD_LOG_INFO(( "Running stem, cr_max = %lu", cr_max ));
  FD_MGAUGE_SET( TILE, STATUS, 1UL );
  long then = fd_tickcount();
  long now  = then;
#if STEM_SLEEP_PARKS
  long linger_start = then;
#endif
  for(;;) {

#ifdef STEM_CALLBACK_SHOULD_SHUTDOWN
    if( FD_UNLIKELY( STEM_CALLBACK_SHOULD_SHUTDOWN( ctx ) ) ) break;
#endif

    /* Do housekeeping at a low rate in the background */

    ulong housekeeping_ticks = 0UL;
    if( FD_UNLIKELY( (now-then)>=0L ) ) {
      ulong event_idx = (ulong)event_map[ event_seq ];

      /* Do the next async event.  event_idx:
            <out_cnt - receive credits from out event_idx
           ==out_cnt - housekeeping
            >out_cnt - send credits to in event_idx - out_cnt - 1.
         Branch hints and order are optimized for the case:
           out_cnt >~ in_cnt >~ 1. */

      if( FD_LIKELY( event_idx<cons_cnt ) ) { /* cons fctl for cons cons_idx */
        ulong cons_idx = event_idx;

        /* Receive flow control credits from this out. */
        ulong this_cons_seq = __atomic_load_n( cons_fseq[ cons_idx ], __ATOMIC_ACQUIRE );
        cons_seq[ cons_idx ] = this_cons_seq;
#ifdef STEM_CALLBACK_RECV_CREDIT
        STEM_CALLBACK_RECV_CREDIT( ctx, cons_out[ cons_idx ], out_seq[ cons_out[ cons_idx ] ], this_cons_seq );
#endif

      } else if( FD_LIKELY( event_idx>cons_cnt ) ) { /* in fctl for in in_idx */
        ulong in_idx = event_idx - cons_cnt - 1UL;

        /* Send flow control credits and drain flow control diagnostics
           for in_idx. */

        STEM_(in_update)( &in[ in_idx ] );
        if( FD_UNLIKELY( sleep->shmem ) ) STEM_(credit_ring)( sleep, in[ in_idx ].idx );

      } else { /* event_idx==cons_cnt, housekeeping event */

        /* Update metrics counters to external viewers */
        FD_COMPILER_MFENCE();
        FD_MGAUGE_SET( TILE, HEARTBEAT_TIMESTAMP_NANOS,           (ulong)fd_log_wallclock() );
        FD_MGAUGE_SET( TILE, IN_BACKPRESSURE,           metric_in_backp );
        FD_MCNT_INC  ( TILE, BACKPRESSURE,              metric_backp_cnt );
        FD_MCNT_ENUM_COPY( TILE, REGIME_DURATION_NANOS, metric_regime_ticks );
#ifdef STEM_CALLBACK_METRICS_WRITE
        STEM_CALLBACK_METRICS_WRITE( ctx );
#endif
        FD_COMPILER_MFENCE();
        metric_backp_cnt = 0UL;

        /* Receive flow control credits */
        if( FD_LIKELY( cons_cnt ) ) {
          ulong slowest_cons = ULONG_MAX;
          min_cr_avail = cr_max;
          for( ulong out_idx=0; out_idx<out_cnt; out_idx++ ) {
            cr_avail[ out_idx ] = out_depth[ out_idx ];
          }

          for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
            ulong out_idx = cons_out[ cons_idx ];

            /* Read the fseq boot value (ULONG_MAX) as sequence 0, not
               -1, else the producer is one credit short until the
               consumer boots. */
            ulong cseq = fd_ulong_if( cons_seq[ cons_idx ]==ULONG_MAX, 0UL, cons_seq[ cons_idx ] );
            ulong cons_cr_avail = (ulong)fd_long_max( (long)out_depth[ out_idx ]-fd_long_max( fd_seq_diff( out_seq[ out_idx ], cseq ), 0L ), 0L );

            /* If a reliable consumer exits, they can set the credit
               return fseq to STEM_SHUTDOWN_SEQ to indicate they are no
               longer actively consuming. */
            cons_cr_avail = fd_ulong_if( cons_seq[ cons_idx ]==STEM_SHUTDOWN_SEQ, out_depth[ out_idx ], cons_cr_avail );
            slowest_cons = fd_ulong_if( cons_cr_avail<min_cr_avail, cons_idx, slowest_cons );

            cr_avail[ out_idx ] = fd_ulong_min( cr_avail[ out_idx ], cons_cr_avail );
            min_cr_avail        = fd_ulong_min( cons_cr_avail, min_cr_avail );
          }

          /* See notes above about use of quasi-atomic diagnostic accum */
          if( FD_LIKELY( slowest_cons!=ULONG_MAX ) ) {
            FD_COMPILER_MFENCE();
            (*cons_slow[ slowest_cons ]) += metric_in_backp;
            FD_COMPILER_MFENCE();
          }
        }

        /* Publish producer progress sync word */
        for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {
          fd_mcache_seq_update( fd_mcache_seq_laddr( out_mcache[ out_idx ] ), out_seq[ out_idx ] );
          if( FD_UNLIKELY( sleep->shmem ) ) STEM_(mirror)( &sleep->shmem->seq_mirror[ sleep->out_link_id[ out_idx ] ], out_seq[ out_idx ] );
        }

#ifdef STEM_CALLBACK_DURING_HOUSEKEEPING
        STEM_CALLBACK_DURING_HOUSEKEEPING( ctx );
#else
        (void)ctx;
#endif
      }

      /* Select which event to do next (randomized round robin) and
         reload the housekeeping timer. */

      event_seq++;
      if( FD_UNLIKELY( event_seq>=event_cnt ) ) {
        event_seq = 0UL;

        /* Randomize the order of event processing for the next event
           event_cnt events to avoid lighthousing effects causing input
           credit starvation at extreme fan in/fan out, extreme in load
           and high credit return laziness. */

        ulong  swap_idx = (ulong)fd_rng_uint_roll( rng, (uint)event_cnt );
        ushort map_tmp        = event_map[ swap_idx ];
        event_map[ swap_idx ] = event_map[ 0        ];
        event_map[ 0        ] = map_tmp;

        /* We also do the same with the ins to prevent there being a
           correlated order frag origins from different inputs
           downstream at extreme fan in and extreme in load. */

        if( FD_LIKELY( in_cnt>1UL ) ) {
          swap_idx = (ulong)fd_rng_uint_roll( rng, (uint)in_cnt );
          fd_stem_tile_in_t in_tmp;
          in_tmp         = in[ swap_idx ];
          in[ swap_idx ] = in[ 0        ];
          in[ 0        ] = in_tmp;
#ifdef STEM_STICKY_POLL_MAX
          sticky_rem = 0UL; /* sticky_in is a slot, not a link */
#endif
        }
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
      long next = fd_tickcount();
      housekeeping_ticks = (ulong)(next - now);
      now = next;
    }

#if defined(STEM_CALLBACK_BEFORE_CREDIT) || defined(STEM_CALLBACK_AFTER_CREDIT) || defined(STEM_CALLBACK_AFTER_FRAG) || defined(STEM_CALLBACK_RETURNABLE_FRAG)
    fd_stem_context_t stem = {
      .mcaches             = out_mcache,
      .depths              = out_depth,
      .seqs                = out_seq,

      .cr_avail            = cr_avail,
      .min_cr_avail        = &min_cr_avail,
      .cr_decrement_amount = fd_ulong_if( out_cnt>0UL, 1UL, 0UL ),
      .out_reliable        = out_reliable,
      .cons_seq            = cons_seq,
      .in                  = in,

      .sleep               = sleep->shmem,
      .wake                = sleep->wake,
      .wake_off            = sleep->wake_off,
      .in_fseq             = in_fseq,
      .in_producer         = sleep->in_producer,
    };
#endif

    int charge_busy_before = 0;
#ifdef STEM_CALLBACK_BEFORE_CREDIT
    STEM_CALLBACK_BEFORE_CREDIT( ctx, &stem, &charge_busy_before );
#endif

  /* Check if we are backpressured.  If so, count any transition into
     a backpressured regime and spin to wait for flow control credits
     to return.  We don't do a fully atomic update here as it is only
     diagnostic and it will still be correct in the usual case where
     individual diagnostic counters aren't used by writers in
     different threads of execution.  We only count the transition
     from not backpressured to backpressured. */

    int is_backpressured = min_cr_avail<burst;
#ifdef STEM_CALLBACK_CHECK_CREDIT
    STEM_CALLBACK_CHECK_CREDIT( ctx, &stem, &charge_busy_before, &is_backpressured );
#endif
    if( FD_UNLIKELY( is_backpressured ) ) {
      metric_backp_cnt += (ulong)!metric_in_backp;
      metric_in_backp   = 1UL;
      FD_SPIN_PAUSE();
      metric_regime_ticks[2] += housekeeping_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[5] += (ulong)(next - now);
      now = next;
#if STEM_SLEEP_PARKS
      sleep_idle_streak++;
      if( FD_UNLIKELY( sleep_idle_streak>=in_cnt && (now-linger_start)>sleep_linger_ticks ) ) {
        sleep_idle_streak = 0UL;
        STEM_(park_attempt)( ctx, sleep, in, in_cnt, out_mcache, out_cnt, out_seq, cons_cnt, cons_fseq, cons_seq, cons_out,
                             event_cnt, event_map, &event_seq, async_min,
                             sleep_cap_ticks, sleep_min_ticks, sleep_tick_per_ns, metric_regime_ticks, &now, &then,
                             FD_METRICS_ENUM_TILE_REGIME_V_BACKPRESSURE_SLEEPING_IDX, 1, then );
      }
#endif
      continue;
    }
    metric_in_backp = 0UL;

    int charge_busy_after = 0;
#ifdef STEM_CALLBACK_AFTER_CREDIT
    int poll_in = 1;
    STEM_CALLBACK_AFTER_CREDIT( ctx, &stem, &poll_in, &charge_busy_after );
    if( FD_UNLIKELY( !poll_in ) ) {
      metric_regime_ticks[1] += housekeeping_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[4] += (ulong)(next - now);
      now = next;
#if STEM_SLEEP_PARKS
      sleep_idle_streak = 0UL;
      linger_start = now;
#endif
      continue;
    }
#endif

    /* Select which in to poll next (randomized round robin) */

    if( FD_UNLIKELY( !in_cnt ) ) {
      int was_busy = charge_busy_before+charge_busy_after;
      metric_regime_ticks[0] += housekeeping_ticks;
      long next = fd_tickcount();
      if( FD_UNLIKELY( was_busy ) ) metric_regime_ticks[3] += (ulong)(next - now);
      else                          metric_regime_ticks[6] += (ulong)(next - now);
      now = next;
#if STEM_SLEEP_PARKS
      if( FD_UNLIKELY( was_busy ) ) {
        sleep_idle_streak  = 0UL;
        linger_start = now;
      } else {
        if( FD_UNLIKELY( (now-linger_start)>sleep_linger_ticks ) ) {
          sleep_idle_streak = 0UL;
          STEM_(park_attempt)( ctx, sleep, in, in_cnt, out_mcache, out_cnt, out_seq, cons_cnt, cons_fseq, cons_seq, cons_out,
                               event_cnt, event_map, &event_seq, async_min,
                               sleep_cap_ticks, sleep_min_ticks, sleep_tick_per_ns, metric_regime_ticks, &now, &then,
                               FD_METRICS_ENUM_TILE_REGIME_V_CAUGHT_UP_SLEEPING_IDX, 0, LONG_MAX );
        }
      }
#endif
      continue;
    }

    ulong prefrag_ticks = 0UL;
#if defined(STEM_CALLBACK_BEFORE_CREDIT) && defined(STEM_CALLBACK_AFTER_CREDIT)
    if( FD_LIKELY( charge_busy_before || charge_busy_after ) ) {
#elif defined(STEM_CALLBACK_BEFORE_CREDIT)
    if( FD_LIKELY( charge_busy_before ) ) {
#elif defined(STEM_CALLBACK_AFTER_CREDIT)
    if( FD_LIKELY( charge_busy_after ) ) {
#endif

#if defined(STEM_CALLBACK_BEFORE_CREDIT) || defined(STEM_CALLBACK_AFTER_CREDIT)
      long prefrag_next = fd_tickcount();
      prefrag_ticks = (ulong)(prefrag_next - now);
      now = prefrag_next;
    }
#endif

    fd_stem_tile_in_t * this_in;
#ifdef STEM_STICKY_POLL_MAX
    int this_in_rr = 0;
    if( FD_LIKELY( sticky_rem ) ) {
      this_in = sticky_in;
      sticky_rem--;
    } else {
      this_in = &in[ in_seq ];
      this_in_rr = 1;
      in_seq++;
      if( in_seq>=in_cnt ) in_seq = 0UL; /* cmov */
    }
#else
    this_in = &in[ in_seq ];
    in_seq++;
    if( in_seq>=in_cnt ) in_seq = 0UL; /* cmov */
#endif

    /* Check if this in has any new fragments to mux */

    ulong                  this_in_seq   = this_in->seq;
    fd_frag_meta_t const * this_in_mline = this_in->mline; /* Already at appropriate line for this_in_seq */

#if FD_HAS_AVX
    fd_frag_meta_v256_t yline = FD_VOLATILE_CONST( this_in_mline->avx );
    ulong seq_found = fd_frag_meta_avx_seq( yline );
    ulong sig       = fd_frag_meta_avx_sig( yline );
#elif FD_HAS_SSE
    __m128i seq_sig = fd_frag_meta_seq_sig_query( this_in_mline );
    ulong seq_found = fd_frag_meta_sse0_seq( seq_sig );
    ulong sig       = fd_frag_meta_sse0_sig( seq_sig );
#elif FD_HAS_ARM || FD_HAS_RISCV
    ulong seq_found = __atomic_load_n( &this_in_mline->seq, __ATOMIC_ACQUIRE );
    ulong sig;
#else
    /* Without 128-bit atomic load, seq and sig might be read from
       different frags (due to overrun), which results in a before_frag
       and during_frag being issued with incorrect arguments, but not
       after_frag. */
    ulong seq_found = FD_VOLATILE_CONST( this_in_mline->seq );
    ulong sig       = FD_VOLATILE_CONST( this_in_mline->sig );
#endif
    long diff = fd_seq_diff( this_in_seq, seq_found );
    if( FD_UNLIKELY( diff ) ) { /* Caught up or overrun, optimize for new frag case */
#ifdef STEM_STICKY_POLL_MAX
      sticky_rem = 0UL;
#endif
      ulong * housekeeping_regime = &metric_regime_ticks[0];
      ulong * prefrag_regime = &metric_regime_ticks[3];
      ulong * finish_regime = &metric_regime_ticks[6];
      if( FD_UNLIKELY( diff<0L ) ) { /* Overrun (impossible if in is honoring our flow control) */
        this_in->seq = seq_found; /* Resume from here (probably reasonably current, could query in mcache sync directly instead) */
        housekeeping_regime = &metric_regime_ticks[1];
        prefrag_regime = &metric_regime_ticks[4];
        finish_regime = &metric_regime_ticks[7];
        this_in->accum[ FD_METRICS_COUNTER_LINK_LINK_POLLING_OVERRUN_OFF ]++;
        this_in->accum[ FD_METRICS_COUNTER_LINK_FRAG_POLLING_OVERRUN_OFF ] += (uint)(-diff);

#ifdef STEM_CALLBACK_AFTER_POLL_OVERRUN
        STEM_CALLBACK_AFTER_POLL_OVERRUN( ctx );
#endif
      }

      /* Don't bother with spin as polling multiple locations */
      *housekeeping_regime += housekeeping_ticks;
      *prefrag_regime += prefrag_ticks;
      long next = fd_tickcount();
      *finish_regime += (ulong)(next - now);
      now = next;
#if STEM_SLEEP_PARKS
      if( FD_UNLIKELY( (diff<0L) || (charge_busy_before+charge_busy_after)>0L ) ) {
        sleep_idle_streak  = 0UL;
        linger_start = now;
      } else {
        sleep_idle_streak++;
        if( FD_UNLIKELY( sleep_idle_streak>=in_cnt && (now-linger_start)>sleep_linger_ticks ) ) {
          sleep_idle_streak = 0UL;
          STEM_(park_attempt)( ctx, sleep, in, in_cnt, out_mcache, out_cnt, out_seq, cons_cnt, cons_fseq, cons_seq, cons_out,
                               event_cnt, event_map, &event_seq, async_min,
                               sleep_cap_ticks, sleep_min_ticks, sleep_tick_per_ns, metric_regime_ticks, &now, &then,
                               FD_METRICS_ENUM_TILE_REGIME_V_CAUGHT_UP_SLEEPING_IDX, 0, LONG_MAX );
        }
      }
#endif
      continue;
    }

#if FD_HAS_ARM || FD_HAS_RISCV
    /* On weakly ordered CPUs, acquire publication before reading sig,
       then confirm the sequence before allowing before_frag to filter. */
    sig = __atomic_load_n( &this_in_mline->sig, __ATOMIC_ACQUIRE );
    ulong seq_confirm = __atomic_load_n( &this_in_mline->seq, __ATOMIC_ACQUIRE );
    if( FD_UNLIKELY( fd_seq_ne( seq_confirm, seq_found ) ) ) {
      metric_regime_ticks[1] += housekeeping_ticks;
      metric_regime_ticks[4] += prefrag_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[7] += (ulong)(next - now);
      now = next;
      continue;
    }
#endif
    (void)sig;

#ifdef STEM_CALLBACK_BEFORE_FRAG
    int filter = STEM_CALLBACK_BEFORE_FRAG( ctx, (ulong)this_in->idx, seq_found, sig );
    if( FD_UNLIKELY( filter<0 ) ) {
#if STEM_SLEEP_PARKS
      sleep_idle_streak = 0UL;
      linger_start = now;
#endif
      metric_regime_ticks[1] += housekeeping_ticks;
      metric_regime_ticks[4] += prefrag_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[7] += (ulong)(next - now);
      now = next;
      continue;
    } else if( FD_UNLIKELY( filter>0 ) ) {
#if STEM_SLEEP_PARKS
      linger_start = now;
#endif
      this_in->accum[ FD_METRICS_COUNTER_LINK_FRAG_FILTERED_OFF ]++;
      this_in->accum[ FD_METRICS_COUNTER_LINK_FRAG_FILTERED_BYTES_OFF ] += (uint)this_in_mline->sz; /* TODO: This might be overrun ... ? Not loaded atomically */

      this_in_seq    = fd_seq_inc( this_in_seq, 1UL );
      this_in->seq   = this_in_seq;
      this_in->mline = this_in->mcache + fd_mcache_line_idx( this_in_seq, this_in->depth );

      metric_regime_ticks[1] += housekeeping_ticks;
      metric_regime_ticks[4] += prefrag_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[7] += (ulong)(next - now);
      now = next;
      continue;
    }
#endif

#if STEM_SLEEP_PARKS
    sleep_idle_streak = 0UL;
    linger_start = now;
#endif

    /* We have a new fragment to mux.  Try to load it.  This attempt
       should always be successful if in producers are honoring our flow
       control.  Since we can cheaply detect if there are
       misconfigurations (should be an L1 cache hit / predictable branch
       in the properly configured case), we do so anyway. */
    FD_COMPILER_MFENCE();
#if FD_HAS_AVX
    ulong chunk    = fd_frag_meta_avx_chunk ( yline ); (void)chunk;
    ulong sz       = fd_frag_meta_avx_sz    ( yline ); (void)sz;
    ulong ctl      = fd_frag_meta_avx_ctl   ( yline ); (void)ctl;
    ulong tsorig   = fd_frag_meta_avx_tsorig( yline ); (void)tsorig;
    ulong tspub    = fd_frag_meta_avx_tspub ( yline ); (void)tspub;
#elif FD_HAS_ARM
    ulong ul2, ul3;
    fd_arm_ldp16( this_in_mline->ul+2, ul2, ul3 );
    ulong chunk    = fd_frag_meta_ul2_chunk ( ul2 ); (void)chunk;
    ulong sz       = fd_frag_meta_ul2_sz    ( ul2 ); (void)sz;
    ulong ctl      = fd_frag_meta_ul2_ctl   ( ul2 ); (void)ctl;
    ulong tsorig   = fd_frag_meta_ul3_tsorig( ul3 ); (void)tsorig;
    ulong tspub    = fd_frag_meta_ul3_tspub ( ul3 ); (void)tspub;
#else
    ulong chunk    = (ulong)this_in_mline->chunk;  (void)chunk;
    ulong sz       = (ulong)this_in_mline->sz;     (void)sz;
    ulong ctl      = (ulong)this_in_mline->ctl;    (void)ctl;
    ulong tsorig   = (ulong)this_in_mline->tsorig; (void)tsorig;
    ulong tspub    = (ulong)this_in_mline->tspub;  (void)tspub;
#endif

#ifdef STEM_CALLBACK_DURING_FRAG
    STEM_CALLBACK_DURING_FRAG( ctx, (ulong)this_in->idx, seq_found, sig, chunk, sz, ctl );
#endif

    FD_HW_MFENCE_LD();
    ulong seq_test = FD_VOLATILE_CONST( this_in_mline->seq );
    FD_COMPILER_MFENCE();

    if( FD_UNLIKELY( fd_seq_ne( seq_test, seq_found ) ) ) { /* Overrun while reading (impossible if this_in honoring our fctl) */
      this_in->seq = seq_test; /* Resume from here (probably reasonably current, could query in mcache sync instead) */
      fd_metrics_link_in( fd_metrics_base_tl, this_in->idx )[ FD_METRICS_COUNTER_LINK_LINK_READING_OVERRUN_OFF ]++; /* No local accum since extremely rare, faster to use smaller cache line */
      fd_metrics_link_in( fd_metrics_base_tl, this_in->idx )[ FD_METRICS_COUNTER_LINK_FRAG_READING_OVERRUN_OFF ] += (uint)fd_seq_diff( seq_test, seq_found ); /* No local accum since extremely rare, faster to use smaller cache line */
      /* Don't bother with spin as polling multiple locations */
      metric_regime_ticks[1] += housekeeping_ticks;
      metric_regime_ticks[4] += prefrag_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[7] += (ulong)(next - now);
      now = next;
      continue;
    }

#ifdef STEM_CALLBACK_RETURNABLE_FRAG
    int return_frag = STEM_CALLBACK_RETURNABLE_FRAG( ctx, (ulong)this_in->idx, seq_found, sig, chunk, sz, ctl, tsorig, tspub, &stem );
    if( FD_UNLIKELY( return_frag ) ) {
      metric_regime_ticks[1] += housekeeping_ticks;
      metric_regime_ticks[4] += prefrag_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[7] += (ulong)(next - now);
      now = next;
      continue;
    }
#endif

#ifdef STEM_CALLBACK_AFTER_FRAG
    STEM_CALLBACK_AFTER_FRAG( ctx, (ulong)this_in->idx, seq_found, sig, sz, tsorig, tspub, &stem );
#endif

    /* Windup for the next in poll and accumulate diagnostics */

    this_in_seq    = fd_seq_inc( this_in_seq, 1UL );
    this_in->seq   = this_in_seq;
    this_in->mline = this_in->mcache + fd_mcache_line_idx( this_in_seq, this_in->depth );

    this_in->accum[ FD_METRICS_COUNTER_LINK_FRAG_CONSUMED_OFF ]++;
    this_in->accum[ FD_METRICS_COUNTER_LINK_FRAG_CONSUMED_BYTES_OFF ] += (uint)sz;

#ifdef STEM_STICKY_POLL_MAX
    sticky_in  = this_in_rr ? this_in : sticky_in; /* cmov */
    sticky_rem = fd_ulong_if( this_in_rr, STEM_STICKY_POLL_MAX, sticky_rem );
#endif

    metric_regime_ticks[1] += housekeeping_ticks;
    metric_regime_ticks[4] += prefrag_ticks;
    long next = fd_tickcount();
    metric_regime_ticks[7] += (ulong)(next - now);
    now = next;
  }

  for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {
    fd_mcache_seq_update( fd_mcache_seq_laddr( out_mcache[ out_idx ] ), out_seq[ out_idx ] );
    if( FD_UNLIKELY( sleep->shmem ) ) STEM_(mirror)( &sleep->shmem->seq_mirror[ sleep->out_link_id[ out_idx ] ], out_seq[ out_idx ] );
  }
}
