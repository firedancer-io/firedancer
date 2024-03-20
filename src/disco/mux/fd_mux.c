#include "fd_mux.h"

/* A fd_mux_tile_in has all the state needed for muxing frags from an
   in.  It fits on exactly one cache line. */

struct __attribute__((aligned(64))) fd_mux_tile_in {
  fd_frag_meta_t const * mcache;   /* local join to this in's mcache */
  uint                   depth;    /* == fd_mcache_depth( mcache ), depth of this in's cache (const) */
  uint                   idx;      /* index of this in in the list of providers, [0, in_cnt) */
  ulong                  seq;      /* sequence number of next frag expected from the upstream producer,
                                      updated when frag from this in is published / filtered */
  fd_frag_meta_t const * mline;    /* == mcache + fd_mcache_line_idx( seq, depth ), location to poll next */
  ulong *                fseq;     /* local join to the fseq used to return flow control credits to the in */
  uint                   accum[6]; /* local diagnostic accumulators.  These are drained during in housekeeping. */
                                   /* Assumes FD_FSEQ_DIAG_{PUB_CNT,PUB_SZ,FILT_CNT,FILT_SZ,OVRNP_CNT,OVRNR_CONT} are 0:5 */
};

typedef struct fd_mux_tile_in fd_mux_tile_in_t;

/* fd_mux_tile_in_update returns flow control credits to the in assuming
   that there are at most exposed_cnt frags currently exposed to
   reliable outs and drains the run-time diagnostics accumulated since
   the last update.  Note that, once an in sequence number has been
   confirmed to have been consumed downstream, it will remain consumed.
   So, we can optimize this (and guarantee a monotonically increasing
   fseq from the in's point of view) by only sending when
   this_in_seq-exposed_cnt ends up ahead of this_in_fseq.  We still
   drain diagnostics every update as we might still have diagnostic
   accumulated since last update even when we don't need to update
   this_in_fseq.  See note below about quasi-atomic draining.

   For a simple example in normal operation of this, consider the case
   where, at last update for this in, outs were caught up, and since
   then, the mux forwarded 1 frag from this in, the mux forwarded 1 frag
   from another in, and the outs didn't make any progress on the
   forwarded frags.  At this point then, for the implementation below,
   exposed_cnt will be 2 but this_in_seq will have advanced only 1 such
   that this_in_seq-exposed_cnt will be before this_in_fseq.  Thus, we
   will have diagnostics to accumulate for this in but no update needed
   for this_in_fseq. */

static inline void
fd_mux_tile_in_update( fd_mux_tile_in_t * in,
                       ulong              exposed_cnt ) {

  /* Technically we don't need to use fd_fseq_query here as *in_fseq
     is not volatile from the mux's point of view.  But we are paranoid,
     it won't affect performance in this case and it is consistent with
     typical fseq usages. */

  ulong * in_fseq = in->fseq;
  ulong seq = fd_seq_dec( in->seq, exposed_cnt );
  if( FD_LIKELY( fd_seq_gt( seq, fd_fseq_query( in_fseq ) ) ) ) fd_fseq_update( in_fseq, seq );

  ulong * metrics = fd_metrics_link_in( fd_metrics_base_tl, in->idx );

  uint *  accum = in->accum;
  ulong a0 = (ulong)accum[0]; ulong a1 = (ulong)accum[1]; ulong a2 = (ulong)accum[2];
  ulong a3 = (ulong)accum[3]; ulong a4 = (ulong)accum[4]; ulong a5 = (ulong)accum[5];
  FD_COMPILER_MFENCE();
  metrics[0] += a0;           metrics[1] += a1;           metrics[2] += a2;
  metrics[3] += a3;           metrics[4] += a4;           metrics[5] += a5;
  FD_COMPILER_MFENCE();
  accum[0] = 0U;              accum[1] = 0U;              accum[2] = 0U;
  accum[3] = 0U;              accum[4] = 0U;              accum[5] = 0U;
}

FD_STATIC_ASSERT( alignof(fd_mux_tile_in_t)<=FD_MUX_TILE_SCRATCH_ALIGN, packing );

ulong
fd_mux_tile_scratch_align( void ) {
  return FD_MUX_TILE_SCRATCH_ALIGN;
}

ulong
fd_mux_tile_scratch_footprint( ulong in_cnt,
                               ulong out_cnt ) {
  if( FD_UNLIKELY( in_cnt >FD_MUX_TILE_IN_MAX  ) ) return 0UL;
  if( FD_UNLIKELY( out_cnt>FD_MUX_TILE_OUT_MAX ) ) return 0UL;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_mux_tile_in_t), in_cnt*sizeof(fd_mux_tile_in_t)     ); /* in */
  l = FD_LAYOUT_APPEND( l, alignof(ulong const *),    out_cnt*sizeof(ulong const *)       ); /* out_fseq */
  l = FD_LAYOUT_APPEND( l, alignof(ulong *),          out_cnt*sizeof(ulong *)             ); /* out_slow */
  l = FD_LAYOUT_APPEND( l, alignof(ulong),            out_cnt*sizeof(ulong)               ); /* out_seq */
  l = FD_LAYOUT_APPEND( l, alignof(ushort),           (in_cnt+out_cnt+1UL)*sizeof(ushort) ); /* event_map */
  return FD_LAYOUT_FINI( l, fd_mux_tile_scratch_align() );
}

int
fd_mux_tile( fd_cnc_t *              cnc,
             ulong                   flags,
             ulong                   in_cnt,
             fd_frag_meta_t const ** in_mcache,
             ulong **                in_fseq,
             fd_frag_meta_t *        mcache,
             ulong                   out_cnt,
             ulong **                _out_fseq,
             ulong                   burst,
             ulong                   cr_max,
             long                    lazy,
             fd_rng_t *              rng,
             void *                  scratch,
             void *                  ctx,
             fd_mux_callbacks_t *    callbacks ) {
  /* in frag stream state */
  ulong              in_seq; /* current position in input poll sequence, in [0,in_cnt) */
  fd_mux_tile_in_t * in;     /* in[in_seq] for in_seq in [0,in_cnt) has information about input fragment stream currently at
                                position in_seq in the in_idx polling sequence.  The ordering of this array is continuously
                                shuffled to avoid lighthousing effects in the output fragment stream at extreme fan-in and load */

  /* out frag stream state */
  ulong   depth; /* ==fd_mcache_depth( mcache ), depth of the mcache / positive integer power of 2 */
  ulong   _sync; /* local sync for mcache if mcache is NULL */
  ulong * sync;  /* ==fd_mcache_seq_laddr( mcache ), local addr where mux mcache sync info is published */
  ulong   seq;   /* next mux frag sequence number to publish */

  /* out flow control state */
  ulong          cr_avail; /* number of flow control credits available to publish downstream, in [0,cr_max] */
  ulong          cr_filt;  /* number of filtered fragments we need to account for in the flow control state */
  ulong const ** out_fseq; /* out_fseq[out_idx] for out_idx in [0,out_cnt) is where to receive fctl credits from outs */
  ulong **       out_slow; /* out_slow[out_idx] for out_idx in [0,out_cnt) is where to accumulate slow events */
  ulong *        out_seq;  /* out_seq [out_idx] is the most recent observation of out_fseq[out_idx] */

  /* housekeeping state */
  ulong    event_cnt; /* ==in_cnt+out_cnt+1, total number of housekeeping events */
  ulong    event_seq; /* current position in housekeeping event sequence, in [0,event_cnt) */
  ushort * event_map; /* current mapping of event_seq to event idx, event_map[ event_seq ] is next event to process */
  ulong    async_min; /* minimum number of ticks between processing a housekeeping event, positive integer power of 2 */

  /* performance histograms */
  ulong metric_in_backp;  /* is the run loop currently backpressured by one or more of the outs, in [0,1] */
  ulong metric_backp_cnt; /* Accumulates number of transitions of tile to backpressured between housekeeping events */

  fd_histf_t hist_housekeeping_ticks[1];
  fd_histf_t hist_backp_ticks[1];
  fd_histf_t hist_caught_up_ticks[1];
  fd_histf_t hist_ovrnp_ticks[1];
  fd_histf_t hist_ovrnr_ticks[1];
  fd_histf_t hist_filter1_ticks[1];
  fd_histf_t hist_filter2_ticks[1];
  fd_histf_t hist_filter2_frag_sz[1];
  fd_histf_t hist_fin_ticks[1];
  fd_histf_t hist_fin_frag_sz[1];

  do {

    FD_LOG_INFO(( "Booting mux (in-cnt %lu, out-cnt %lu)", in_cnt, out_cnt ));
    if( FD_UNLIKELY( in_cnt >FD_MUX_TILE_IN_MAX  ) ) { FD_LOG_WARNING(( "in_cnt too large"  )); return 1; }
    if( FD_UNLIKELY( out_cnt>FD_MUX_TILE_OUT_MAX ) ) { FD_LOG_WARNING(( "out_cnt too large" )); return 1; }

    if( FD_UNLIKELY( !scratch ) ) {
      FD_LOG_WARNING(( "NULL scratch" ));
      return 1;
    }

    if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch, fd_mux_tile_scratch_align() ) ) ) {
      FD_LOG_WARNING(( "misaligned scratch" ));
      return 1;
    }

    FD_SCRATCH_ALLOC_INIT( l, scratch );

    /* cnc state init */

    if( FD_UNLIKELY( !cnc ) ) { FD_LOG_WARNING(( "NULL cnc" )); return 1; }
    if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) { FD_LOG_WARNING(( "already booted" )); return 1; }

    /* in_backp==1, backp_cnt==0 indicates waiting for initial credits,
       cleared during first housekeeping if credits available */
    metric_in_backp  = 1UL;
    metric_backp_cnt = 0UL;

    /* in frag stream init */

    in_seq = 0UL; /* First in to poll */
    in = (fd_mux_tile_in_t *)FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_mux_tile_in_t), in_cnt*sizeof(fd_mux_tile_in_t) );

    ulong min_in_depth = (ulong)LONG_MAX;

    if( FD_UNLIKELY( !!in_cnt && !in_mcache ) ) { FD_LOG_WARNING(( "NULL in_mcache" )); return 1; }
    if( FD_UNLIKELY( !!in_cnt && !in_fseq   ) ) { FD_LOG_WARNING(( "NULL in_fseq"   )); return 1; }
    if( FD_UNLIKELY( in_cnt > UINT_MAX ) ) { FD_LOG_WARNING(( "in_cnt too large" )); return 1; }
    for( ulong in_idx=0UL; in_idx<in_cnt; in_idx++ ) {

      /* FIXME: CONSIDER NULL OR EMPTY CSTR IN_FCTL[ IN_IDX ] TO SPECIFY
         NO FLOW CONTROL FOR A PARTICULAR IN? */
      if( FD_UNLIKELY( !in_mcache[ in_idx ] ) ) { FD_LOG_WARNING(( "NULL in_mcache[%lu]", in_idx )); return 1; }
      if( FD_UNLIKELY( !in_fseq  [ in_idx ] ) ) { FD_LOG_WARNING(( "NULL in_fseq[%lu]",   in_idx )); return 1; }

      fd_mux_tile_in_t * this_in = &in[ in_idx ];

      this_in->mcache = in_mcache[ in_idx ];
      this_in->fseq   = in_fseq  [ in_idx ];
      ulong const * this_in_sync = fd_mcache_seq_laddr_const( this_in->mcache );

      ulong depth    = fd_mcache_depth( this_in->mcache ); min_in_depth = fd_ulong_min( min_in_depth, depth );
      if( FD_UNLIKELY( depth > UINT_MAX ) ) { FD_LOG_WARNING(( "in_mcache[%lu] too deep", in_idx )); return 1; }
      this_in->depth = (uint)depth;
      this_in->idx   = (uint)in_idx;
      this_in->seq   = fd_mcache_seq_query( this_in_sync ); /* FIXME: ALLOW OPTION FOR MANUAL SPECIFICATION? */
      this_in->mline = this_in->mcache + fd_mcache_line_idx( this_in->seq, this_in->depth );

      this_in->accum[0] = 0U; this_in->accum[1] = 0U; this_in->accum[2] = 0U;
      this_in->accum[3] = 0U; this_in->accum[4] = 0U; this_in->accum[5] = 0U;
    }

    /* out frag stream init */

    if( FD_LIKELY( mcache ) ) {
      depth = fd_mcache_depth    ( mcache );
      sync  = fd_mcache_seq_laddr( mcache );

      seq = fd_mcache_seq_query( sync ); /* FIXME: ALLOW OPTION FOR MANUAL SPECIFICATION */
    } else {
      depth = 128UL;
      _sync = 0UL;
      sync  = &_sync;
      seq = 0UL;
    }

    /* out flow control init */

    /* Since cr_avail is decremented everytime a frag is exposed to the
       outs by the mux, exposed_cnt=cr_max-cr_avail is the number frags
       that are currently exposed.  Similarly there might be up to
       cr_filt duplicate frags that were filtered.  Exposed frags can be
       arbitrarily distributed over all ins and, in the worst case,
       could all be from just one particular in.

       When the mux sends flow control credits to an in, the mux
       decrements the actual mux's position in sequence space by this
       upper bound.  This guarantees, even in the worst case (all frags
       exposed downstream and filtered came from the smallest depth in),
       the ins will never overrun any outs.  It also means that the mux
       tile doesn't have to keep track of how these frags are
       distributed over the ins (simplifying the implementation and
       increasing performance).

       This also implies that cr_max must be at most
       min(in_mcache[*].depth) such that the mux cannot expose a frag
       from further back than the in itself can cache.  It also can't be
       larger than depth such that at most_depth frags will ever be
       exposed to outs.

       This further implies that the mux should continuously replenish
       its credits from the outs whenever it has less than cr_max
       credits.  To see this:

       Note that the we require (as is typically the case) an out is to
       continuously advertise, via the out's fseq, a recent position in
       mux's sequence space (such that, in the absence of incoming
       fragments, the out's advertised sequence number will eventually
       exactly match the mux's sequence number).  The mux similarly
       continuously advertises to each in its position in the in's
       sequence space.

       Let there be range of credits where the mux will not bother to
       replenish cr_avail to minimize what, in typical situations, would
       be wasteful cache coherence traffic from the outs to the mux on
       the CPU NOC (e.g. cr_avail in [cr_resume,cr_max) for the fctl
       state machine).  An in will stop sending to the mux if its
       in_cr_avail is zero (i.e. it cannot prove it is safe to send).
       If this happens when the mux thinks it doesn't need to replenish
       flow control credits for outs (i.e. cr_avail is large enough) the
       ins and the mux will permanently stall.

       An in will think it has no credits available to send when:

         mux_in_seq - exposed_cnt = in_seq - in_cr_max

       or:

         mux_in_seq - (cr_max - cr_avail) = in_seq - in_cr_max

       Note that:

         mux_in_seq = in_seq - mux_lag

       where mux lag is the number of frags behind the mux is from the
       in and, because of in<>mux flow control, this is in
       [0,in_cr_max].  Simplifying, we need to insure:

         (in_cr_max - mux_lag) - (cr_max - cr_avail) = 0

       never happens when cr_avail is in [cr_resume,cr_max).

       Given the range of mux_lag, the first term is in [0,in_cr_max].
       Given the range of cr_avail, the second term is in
       [1,cr_max-cr_resume].  Thus we require
       [-(cr_max-cr_resume),in_cr_max-1] does not contain 0.  Since
       in_cr_max is positive though, this can never be true.

       With continuous replenishing, exposed_cnt will always improve as
       the outs make progress and filt_cnt can always be cleared
       whenever exposed_cnt gets to 0.  This improvement will then
       always be reflected all the way to all the ins, preventing
       deadlock / livelock situations.  (Note this also handles the
       situation like mux_lag==in_cr_max and cr_filt==0 as, when exposed
       count improves, it will make credits available for publication
       that the mux can use because it will see there are fragments
       ready for publication in the in's mcache given the positive
       mux_lag and will advance mux_in_seq accordingly when it publishes
       them).

       Since we need to continuously replenish our credits when all the
       outs aren't full caught up and we want to optimize for the common
       scenario of very deep buffers and large number of outputs, we do
       not use the fctl object (we would need to turn off its state
       machine and we would like to avoid the bursts of reads it would
       do when replenishing).  Instead, we use a customized flow control
       algorithm here to lazily and stochastically observe, without
       bursts, the fseqs continuously.

       Note that the default value for cr_max assumes that
       in[*].depth==in[*].cr_max and out[*].lag_max==mux.depth.  The
       user can override cr_max to handle more general application
       specific situations. */

    ulong cr_max_max = fd_ulong_min( min_in_depth, depth );
    if( !cr_max ) cr_max = cr_max_max; /* use default */
    FD_LOG_INFO(( "Using cr_max %lu", cr_max ));
    if( FD_UNLIKELY( !((1UL<=cr_max) & (cr_max<=cr_max_max)) ) ) {
      FD_LOG_WARNING(( "cr_max %lu must be in [1,%lu] for these mcaches", cr_max, cr_max_max ));
      return 1;
    }

    cr_avail = 0UL; /* Will be initialized by run loop */
    cr_filt  = 0UL;

    out_fseq = (ulong const **)FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong const *), out_cnt*sizeof(ulong const *) );
    out_slow = (ulong **)      FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong *),       out_cnt*sizeof(ulong *)       );
    out_seq  = (ulong *)       FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),         out_cnt*sizeof(ulong)         );

    if( FD_UNLIKELY( !!out_cnt && !_out_fseq ) ) { FD_LOG_WARNING(( "NULL out_fseq" )); return 1; }
    for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {
      if( FD_UNLIKELY( !_out_fseq[ out_idx ] ) ) { FD_LOG_WARNING(( "NULL out_fseq[%lu]", out_idx )); return 1; }
      out_fseq[ out_idx ] = _out_fseq[ out_idx ];
      out_slow[ out_idx ] = fd_metrics_link_out( fd_metrics_base_tl, out_idx ) + FD_METRICS_COUNTER_LINK_SLOW_COUNT_OFF;
      out_seq [ out_idx ] = fd_fseq_query( out_fseq[ out_idx ] );
    }

    /* housekeeping init */

    if( lazy<=0L ) lazy = fd_tempo_lazy_default( cr_max );
    FD_LOG_INFO(( "Configuring housekeeping (lazy %li ns)", lazy ));

    /* Initialize the initial event sequence to immediately update
       cr_avail on the first run loop iteration and then update all the
       ins accordingly. */

    event_cnt = in_cnt + 1UL + out_cnt;
    event_map = (ushort *)FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort), event_cnt*sizeof(ushort) );
    event_seq = 0UL;                                     event_map[ event_seq++ ] = (ushort)out_cnt;
    for( ulong  in_idx=0UL;  in_idx< in_cnt;  in_idx++ ) event_map[ event_seq++ ] = (ushort)(in_idx+out_cnt+1UL);
    for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) event_map[ event_seq++ ] = (ushort)out_idx;
    event_seq = 0UL;

    async_min = fd_tempo_async_min( lazy, event_cnt, (float)fd_tempo_tick_per_ns( NULL ) );
    if( FD_UNLIKELY( !async_min ) ) { FD_LOG_WARNING(( "bad lazy" )); return 1; }

    /* Initialize performance histograms. */

    fd_histf_join( fd_histf_new( hist_housekeeping_ticks, FD_MHIST_SECONDS_MIN( STEM, LOOP_HOUSEKEEPING_DURATION_SECONDS),           FD_MHIST_SECONDS_MAX( STEM, LOOP_HOUSEKEEPING_DURATION_SECONDS ) ) );
    fd_histf_join( fd_histf_new( hist_backp_ticks,        FD_MHIST_SECONDS_MIN( STEM, LOOP_BACKPRESSURE_DURATION_SECONDS),           FD_MHIST_SECONDS_MAX( STEM, LOOP_BACKPRESSURE_DURATION_SECONDS ) ) );
    fd_histf_join( fd_histf_new( hist_caught_up_ticks,    FD_MHIST_SECONDS_MIN( STEM, LOOP_CAUGHT_UP_DURATION_SECONDS),              FD_MHIST_SECONDS_MAX( STEM, LOOP_CAUGHT_UP_DURATION_SECONDS ) ) );
    fd_histf_join( fd_histf_new( hist_ovrnp_ticks,        FD_MHIST_SECONDS_MIN( STEM, LOOP_OVERRUN_POLLING_DURATION_SECONDS),        FD_MHIST_SECONDS_MAX( STEM, LOOP_OVERRUN_POLLING_DURATION_SECONDS ) ) );
    fd_histf_join( fd_histf_new( hist_ovrnr_ticks,        FD_MHIST_SECONDS_MIN( STEM, LOOP_OVERRUN_READING_DURATION_SECONDS),        FD_MHIST_SECONDS_MAX( STEM, LOOP_OVERRUN_READING_DURATION_SECONDS ) ) );
    fd_histf_join( fd_histf_new( hist_filter1_ticks,      FD_MHIST_SECONDS_MIN( STEM, LOOP_FILTER_BEFORE_FRAGMENT_DURATION_SECONDS), FD_MHIST_SECONDS_MAX( STEM, LOOP_FILTER_BEFORE_FRAGMENT_DURATION_SECONDS ) ) );
    fd_histf_join( fd_histf_new( hist_filter2_ticks,      FD_MHIST_SECONDS_MIN( STEM, LOOP_FILTER_AFTER_FRAGMENT_DURATION_SECONDS),  FD_MHIST_SECONDS_MAX( STEM, LOOP_FILTER_AFTER_FRAGMENT_DURATION_SECONDS ) ) );
    fd_histf_join( fd_histf_new( hist_filter2_frag_sz,    FD_MHIST_MIN( STEM, FRAGMENT_FILTERED_SIZE_BYTES),                         FD_MHIST_MAX( STEM, FRAGMENT_FILTERED_SIZE_BYTES ) ) );
    fd_histf_join( fd_histf_new( hist_fin_ticks,          FD_MHIST_SECONDS_MIN( STEM, LOOP_FINISH_DURATION_SECONDS),                 FD_MHIST_SECONDS_MAX( STEM, LOOP_FINISH_DURATION_SECONDS ) ) );
    fd_histf_join( fd_histf_new( hist_fin_frag_sz,        FD_MHIST_MIN( STEM, FRAGMENT_HANDLED_SIZE_BYTES),                          FD_MHIST_MAX( STEM, FRAGMENT_HANDLED_SIZE_BYTES ) ) );

  } while(0);

  FD_LOG_INFO(( "Running mux" ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  long then = fd_tickcount();
  long now  = then;
  for(;;) {

    /* Do housekeeping at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {
      ulong event_idx = (ulong)event_map[ event_seq ];

      /* Do the next async event.  event_idx:
            <out_cnt - receive credits from out event_idx
           ==out_cnt - housekeeping
            >out_cnt - send credits to in event_idx - out_cnt - 1.
         Branch hints and order are optimized for the case:
           out_cnt >~ in_cnt >~ 1. */

      if( FD_LIKELY( event_idx<out_cnt ) ) { /* out fctl for out out_idx */
        ulong out_idx = event_idx;

        /* Receive flow control credits from this out. */
        out_seq[ out_idx ] = fd_fseq_query( out_fseq[ out_idx ] );

      } else if( FD_LIKELY( event_idx>out_cnt ) ) { /* in fctl for in in_idx */
        ulong in_idx = event_idx - out_cnt - 1UL;

        /* Send flow control credits and drain flow control diagnostics
           for in_idx.  At this point, there are at most
           exposed_cnt=cr_max-cr_avail frags exposed to reliable
           consumers mixed with up to cr_filt frags that got filtered by
           the mux.  We don't know how these frags were distributed
           across all ins but, in the worst case, they all might have
           come from the this in.  The sequence number of the oldest
           exposed frag then is at least cr_max-cr_avail+cr_filt before
           the next sequence number the mux expects to receive from
           that in (e.g. the mux might have received cr_max-cr_avail
           exposed frags first followed by cr_filt frags that got
           filtered). */

        fd_mux_tile_in_update( &in[ in_idx ], cr_max - cr_avail + cr_filt );

      } else { /* event_idx==out_cnt, housekeeping event */

        /* Send synchronization info */
        fd_mcache_seq_update( sync, seq );

        /* Send diagnostic info */
        /* When we drain, we don't do a fully atomic update of the
           diagnostics as it is only diagnostic and it will still be
           correct the usual case where individual diagnostic counters
           aren't used by multiple writers spread over different threads
           of execution. */
        fd_cnc_heartbeat( cnc, now );

        /* Update metrics counters to external viewers */
        FD_COMPILER_MFENCE();
        FD_MGAUGE_SET( STEM, IN_BACKPRESSURE,                              metric_in_backp );
        FD_MCNT_INC  ( STEM, BACKPRESSURE_COUNT,                           metric_backp_cnt );
        FD_MHIST_COPY( STEM, LOOP_HOUSEKEEPING_DURATION_SECONDS,           hist_housekeeping_ticks );
        FD_MHIST_COPY( STEM, LOOP_BACKPRESSURE_DURATION_SECONDS,           hist_backp_ticks );
        FD_MHIST_COPY( STEM, LOOP_CAUGHT_UP_DURATION_SECONDS,              hist_caught_up_ticks );
        FD_MHIST_COPY( STEM, LOOP_OVERRUN_POLLING_DURATION_SECONDS,        hist_ovrnp_ticks );
        FD_MHIST_COPY( STEM, LOOP_OVERRUN_READING_DURATION_SECONDS,        hist_ovrnr_ticks );
        FD_MHIST_COPY( STEM, LOOP_FILTER_BEFORE_FRAGMENT_DURATION_SECONDS, hist_filter1_ticks );
        FD_MHIST_COPY( STEM, LOOP_FILTER_AFTER_FRAGMENT_DURATION_SECONDS,  hist_filter2_ticks );
        FD_MHIST_COPY( STEM, FRAGMENT_FILTERED_SIZE_BYTES,                 hist_filter2_frag_sz );
        FD_MHIST_COPY( STEM, LOOP_FINISH_DURATION_SECONDS,                 hist_fin_ticks );
        FD_MHIST_COPY( STEM, FRAGMENT_HANDLED_SIZE_BYTES,                  hist_fin_frag_sz );
        if( FD_LIKELY( callbacks->metrics_write ) ) callbacks->metrics_write( ctx );
        FD_COMPILER_MFENCE();
        metric_backp_cnt = 0UL;

        /* Receive command-and-control signals */
        ulong s = fd_cnc_signal_query( cnc );
        if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
          if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
          if( FD_UNLIKELY( s!=FD_MUX_CNC_SIGNAL_ACK ) ) {
            char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
            FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
          }
          fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
        }

        /* Receive flow control credits */
        if( FD_LIKELY( cr_avail<cr_max ) ) {
          ulong slowest_out = ULONG_MAX;
          cr_avail = cr_max;
          for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {
            ulong out_cr_avail = (ulong)fd_long_max( (long)cr_max-fd_long_max( fd_seq_diff( seq, out_seq[ out_idx ] ), 0L ), 0L );
            slowest_out = fd_ulong_if( out_cr_avail<cr_avail, out_idx, slowest_out );
            cr_avail    = fd_ulong_min( out_cr_avail, cr_avail );
          }
          /* See notes above about use of quasi-atomic diagnostic accum */
          if( FD_LIKELY( slowest_out!=ULONG_MAX ) ) {
            FD_COMPILER_MFENCE();
            (*out_slow[ slowest_out ])++;
            FD_COMPILER_MFENCE();
          }

          /* If we are fully caught up, we know the cr_filt filter frags
             aren't interspersed with any exposed frags downstream so we
             reset the cr_filt counter. */
          cr_filt = fd_ulong_if( cr_avail==cr_max, 0UL, cr_filt );
        }

        /* user callback */
        if( FD_UNLIKELY( callbacks->during_housekeeping ) ) callbacks->during_housekeeping( ctx );
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
          fd_mux_tile_in_t in_tmp;
          in_tmp         = in[ swap_idx ];
          in[ swap_idx ] = in[ 0        ];
          in[ 0        ] = in_tmp;
        }
      }

      /* Reload housekeeping timer */
      long next = fd_tickcount();
      fd_histf_sample( hist_housekeeping_ticks, (ulong)(next - now) );
      then = now + (long)fd_tempo_async_reload( rng, async_min );
      now = next;
    }

    fd_mux_context_t mux = {
      .mcache = mcache,
      .depth = depth,
      .cr_avail = &cr_avail,
      .seq = &seq,
      .cr_decrement_amount = fd_ulong_if( out_cnt>0UL, 1UL, 0UL ),
    };

    if( FD_LIKELY( callbacks->before_credit ) ) callbacks->before_credit( ctx, &mux );

    /* Check if we are backpressured.  If so, count any transition into
       a backpressured regime and spin to wait for flow control credits
       to return.  We don't do a fully atomic update here as it is only
       diagnostic and it will still be correct in the usual case where
       individual diagnostic counters aren't used by writers in
       different threads of execution.  We only count the transition
       from not backpressured to backpressured. */

    if( FD_UNLIKELY( cr_avail<cr_filt+burst ) ) {
      metric_backp_cnt += (ulong)!metric_in_backp;
      metric_in_backp   = 1UL;
      FD_SPIN_PAUSE();
      long next = fd_tickcount();
      fd_histf_sample( hist_backp_ticks, (ulong)(next - now) );
      now = next;
      continue;
    }
    metric_in_backp = 0UL;

    if( FD_LIKELY( callbacks->after_credit ) ) callbacks->after_credit( ctx, &mux );

    /* Select which in to poll next (randomized round robin) */

    if( FD_UNLIKELY( !in_cnt ) ) { now = fd_tickcount(); continue; }
    fd_mux_tile_in_t * this_in = &in[ in_seq ];
    in_seq++;
    if( in_seq>=in_cnt ) in_seq = 0UL; /* cmov */

    /* Check if this in has any new fragments to mux */

    ulong                  this_in_seq   = this_in->seq;
    fd_frag_meta_t const * this_in_mline = this_in->mline; /* Already at appropriate line for this_in_seq */

    __m128i seq_sig = fd_frag_meta_seq_sig_query( this_in_mline );
#if FD_USING_CLANG
    /* TODO: Clang optimizes extremely aggressively which breaks the
       atomicity expected by seq_sig_query.  In particular, it replaces
       the sequence query with a second load (immediately following
       vector load).  The signature query a few lines down is still an
       extract from the vector which then means that effectively the
       signature is loaded before the sequence number.
       Adding this clobbers of the vector prevents this optimization by
       forcing the seq query to be an extract, but we probably want a
       better long term solution. */
    __asm__( "" : "+x"(seq_sig) );
#endif
    ulong seq_found = fd_frag_meta_sse0_seq( seq_sig );

    long diff = fd_seq_diff( this_in_seq, seq_found );
    if( FD_UNLIKELY( diff ) ) { /* Caught up or overrun, optimize for new frag case */
      fd_histf_t * hist = hist_caught_up_ticks;
      if( FD_UNLIKELY( diff<0L ) ) { /* Overrun (impossible if in is honoring our flow control) */
        this_in->seq = seq_found; /* Resume from here (probably reasonably current, could query in mcache sync directly instead) */
        hist = hist_ovrnp_ticks;
        this_in->accum[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_OFF ]++;
        this_in->accum[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] += (uint)(-diff);
      }
      /* Don't bother with spin as polling multiple locations */
      long next = fd_tickcount();
      fd_histf_sample( hist, (ulong)(next - now) );
      now = next;
      continue;
    }

    ulong sig = fd_frag_meta_sse0_sig( seq_sig );
    if( FD_UNLIKELY( callbacks->before_frag ) ) {
      int filter = 0;
      callbacks->before_frag( ctx, (ulong)this_in->idx, seq_found, sig, &filter );
      if( FD_UNLIKELY( filter ) ) {
        if( FD_UNLIKELY( !(flags & FD_MUX_FLAG_COPY) ) ) cr_filt += (ulong)(cr_avail<cr_max);
        this_in_seq    = fd_seq_inc( this_in_seq, 1UL );
        this_in->seq   = this_in_seq;
        this_in->mline = this_in->mcache + fd_mcache_line_idx( this_in_seq, this_in->depth );
        long next = fd_tickcount();
        fd_histf_sample( hist_filter1_ticks, (ulong)(next - now) );
        now = next;
        continue;
      }
    }

    /* We have a new fragment to mux.  Try to load it.  This attempt
      should always be successful if in producers are honoring our flow
      control.  Since we can cheaply detect if there are
      misconfigurations (should be an L1 cache hit / predictable branch
      in the properly configured case), we do so anyway.  Note that if
      we are on a platform where AVX is atomic, this could be replaced
      by a flat AVX load of the metadata and an extraction of the found
      sequence number for higher performance. */
    FD_COMPILER_MFENCE();
    ulong chunk    = (ulong)this_in_mline->chunk;
    ulong sz       = (ulong)this_in_mline->sz;
    ulong ctl      = (ulong)this_in_mline->ctl;
    ulong tsorig   = (ulong)this_in_mline->tsorig;
    FD_COMPILER_MFENCE();
    ulong seq_test =        this_in_mline->seq;
    FD_COMPILER_MFENCE();

    int filter = 0;
    if( FD_LIKELY( callbacks->during_frag ) ) callbacks->during_frag( ctx, (ulong)this_in->idx, seq_found, sig, chunk, sz, &filter );

    if( FD_UNLIKELY( fd_seq_ne( seq_test, seq_found ) ) ) { /* Overrun while reading (impossible if this_in honoring our fctl) */
      this_in->seq = seq_test; /* Resume from here (probably reasonably current, could query in mcache sync instead) */
      this_in->accum[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_COUNT_OFF ]++;
      /* Don't bother with spin as polling multiple locations */
      long next = fd_tickcount();
      fd_histf_sample( hist_ovrnr_ticks, (ulong)(next - now) );
      now = next;
      continue;
    }

    ulong out_sz = sz;
    ulong out_tsorig = tsorig;
    if( FD_LIKELY( !filter ) ) {
      /* We have successfully loaded the metadata.  Decide whether it
          is interesting downstream and publish or filter accordingly. */

      if( FD_LIKELY( callbacks->after_frag ) ) callbacks->after_frag( ctx, (ulong)this_in->idx, seq_found, &sig, &chunk, &out_sz, &out_tsorig, &filter, &mux );
    }

    long next = fd_tickcount();
    if( FD_UNLIKELY( filter ) ) {
      /* If there are any frags from this in that are currently exposed
         downstream, this frag needs to be taken into account in the flow
         control info we send to this in (see note above).  Since we do
         not track the distribution of the source of exposed frags (or
         how filtered frags might be interspersed with them), we do not
         know this exactly.  But we do not need to for flow control
         purposes.  If cr_avail==cr_max, we are guaranteed nothing is
         exposed at all from this in (because nothing is exposed from
         any in).  If cr_avail<cr_max, we assume the worst (that all
         exposed_frags are from this in) and increment cr_filt. */
      if( FD_UNLIKELY( !(flags & FD_MUX_FLAG_COPY) ) ) cr_filt += (ulong)(cr_avail<cr_max);
    } else if( FD_LIKELY( !(flags & FD_MUX_FLAG_MANUAL_PUBLISH ) ) ) {
      ulong tspub = (ulong)fd_frag_meta_ts_comp( next );
      fd_mux_publish( &mux, sig, chunk, out_sz, ctl, tsorig, tspub );
    }

    /* Windup for the next in poll and accumulate diagnostics */

    this_in_seq    = fd_seq_inc( this_in_seq, 1UL );
    this_in->seq   = this_in_seq;
    this_in->mline = this_in->mcache + fd_mcache_line_idx( this_in_seq, this_in->depth );

    ulong diag_idx = FD_METRICS_COUNTER_LINK_PUBLISHED_COUNT_OFF + 2UL*(ulong)filter;
    this_in->accum[ diag_idx     ]++;
    this_in->accum[ diag_idx+1UL ] += (uint)sz;
    
    fd_histf_t * hist_ticks = fd_ptr_if( filter, (fd_histf_t*)hist_filter2_ticks,   (fd_histf_t*)hist_fin_ticks );
    fd_histf_t * hist_sz    = fd_ptr_if( filter, (fd_histf_t*)hist_filter2_frag_sz, (fd_histf_t*)hist_fin_frag_sz );
    fd_histf_sample( hist_ticks, (ulong)(next - now) );
    fd_histf_sample( hist_sz,    sz );
    now = next;
  }

  do {

    FD_LOG_INFO(( "Halting mux" ));

    while( in_cnt ) {
      ulong in_idx = --in_cnt;
      fd_mux_tile_in_t * this_in = &in[ in_idx ];
      fd_mux_tile_in_update( this_in, 0UL ); /* exposed_cnt 0 assumes all reliable consumers caught up or shutdown */
    }

    FD_LOG_INFO(( "Halted mux" ));
    fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );

  } while(0);

  return 0;
}
