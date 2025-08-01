#include "fd_stem.h"

/* fd_stem provides services to multiplex multiple streams of input
   fragments and present them to a mix of reliable and unreliable
   consumers as though they were generated by multiple different
   multi-stream producers.  The code can be included to generate
   a definition of stem_run which can be called as a tile main run
   loop.

   The template supports various callback functions which can be
   defined like #define STEM_CALLBACK_BEFORE_FRAG before_frag to
   tune the behavior of the stem_run loop.  The callbacks are:

     SHOULD_SHUTDOWN
   It is called at the beginning of each iteration of the stem run loop,
   and if it returns non-zero, the stem will exit the run loop and
   return from the stem_run function.  This is useful for shutting down
   the tile.

     DURING_HOUSEKEEPING
   Is called during the housekeeping routine, which happens infrequently
   on a schedule determined by the stem (based on the lazy parameter,
   see fd_tempo.h for more information).  It is appropriate to do
   slightly expensive things here that wouldn't be OK to do in the main
   loop, like updating sequence numbers that are shared with other tiles
   (e.g. synchronization information), or sending batched information
   somewhere.  The ctx is a user-provided context object from when the
   stem was initialized.

     METRICS_WRITE
   By convention, tiles may wish to accumulate high traffic metrics
   locally so they don't cause a lot of cache coherency traffic, and
   then periodically publish them to external observers.  This callback
   is here to support that use case.  It occurs infrequently during the
   housekeeping loop, and is called inside a compiler fence to ensure
   the writes do not get reordered, which may be important for observers
   or monitoring tools.  The ctx is a user-provided context object from
   when the stem tile was initialized.

     BEFORE_CREDIT
   Is called every iteration of the stem run loop, whether there is a
   new frag ready to receive or not.  This callback is also still
   invoked even if the stem is backpressured and cannot read any new
   fragments while waiting for downstream consumers to catch up.  This
   callback is useful for things that need to occur even if no new frags
   are being handled.  For example, servicing network connections could
   happen here.  The ctx is a user-provided context object from when the
   stem tile was initialized.  The stem is the stem which is invoking
   this callback. The stem should only be used for calling
   fd_stem_publish to publish a fragment to downstream consumers.

   The charge_busy argument is 0 by default, and should be set to 1 if
   the before_credit function is doing work that should be accounted for
   as part of the tiles busy indicator.

      AFTER_CREDIT
   Is called every iteration of the stem run loop, whether there is a
   new frag ready to receive or not, except in cases where the stem is
   backpressured by a downstream consumer and would not be able to
   publish.  The callback might be used for publishing new fragments to
   downstream consumers in the main loop which are not in response to an
   incoming fragment.  For example, code that collects incoming
   fragments over a period of 1 second and joins them together before
   publishing a large block fragment downstream, would publish the block
   here. The ctx is a user-provided context object from when the stem
   tile was initialized.  The stem is the stem which is invoking this
   callback. The stem should only be used for calling fd_stem_publish to
   publish a fragment to downstream consumers.

   The opt_poll_in argument determines if the stem should proceed with
   checking for new fragments to consumer, or should `continue` the main
   stem loop to do credit checking again.  This could be used if the
   after_credit function publishes, and the flow control needs to be
   checked again.  By default, opt_poll_in is true and the stem will
   poll for fragments right away without rerunning the loop or checking
   for credits.

   The charge_busy argument is 0 by default, and should be set to 1 if
   the after_credit function is doing work that should be accounted for
   as part of the tiles busy indicator.

      BEFORE_FRAG
   Is called immediately whenever a new fragment has been detected that
   was published by an upstream producer.  The signature and sequence
   number (sig and seq) provided as arguments are read atomically from
   shared memory, so must both match each other from the published
   fragment (aka. they will not be torn or partially overwritten).
   in_idx is an index in [0, num_ins) indicating which producer
   published the fragment. No fragment data has been read yet here, nor
   has other metadata, for example the size or timestamps of the
   fragment.  Mainly this callback is useful for deciding whether to
   filter the fragment based on its signature.  If the return value is
   non-zero, the frag will be skipped completely, no fragment data will
   be read, and the in will be advanced so that we now wait for the next
   fragment.  If the return value is -1, then the frag is returned back
   to the message queue and will be reprocessed.  The ctx is a
   user-provided context object from when the stem tile was initialized.

      DURING_FRAG
   Is called after the stem has received a new frag from an in, but
   before the stem has checked that it was overrun.  This callback is
   not invoked if the stem is backpressured, as it would not try and
   read a frag from an in in the first place (instead, leaving it on the
   in mcache to backpressure the upstream producer).  in_idx will be the
   index of the in that the frag was received from. If the producer of
   the frags is respecting flow control, it is safe to read frag data in
   any of the callbacks, but it is suggested to copy or read frag data
   within this callback, as if the producer does not respect flow
   control, the frag may be torn or corrupt due to an overrun by the
   reader.  If the frag being read from has been overwritten while this
   callback is running, the frag will be ignored and the stem will not
   call the after_frag function. Instead it will recover from the
   overrun and continue with new frags.  This function cannot fail.  The
   ctx is a user-provided context object from when the stem tile was
   initialized. seq, sig, chunk, and sz are the respective fields from
   the mcache fragment that was received.  If the producer is not
   respecting flow control, these may be corrupt or torn and should not
   be trusted, except for seq which is read atomically.

      RETURNABLE_FRAG
   Is called after the stem has received a new frag from an in, and
   assumes that the stem cannot be overrun.  This special callback can
   instruct the stem not to advance the input sequence number, and
   instead return the fragment to the stem to be processed again.  This
   is useful for processing partial data from fragments without copying
   it.  This callback is unsafe in general contexts, since it assumes
   that the frag will not be overwritten while the callback is running,
   and that the frag data is valid throughout the function call.  It
   should only be used when the stem is guaranteed to not be overrun.
   This callback is not invoked if the stem is backpressured, as it
   would not try and read a frag from an in in the first place (instead,
   leaving it on the in mcache to backpressure the upstream producer).
   in_idx will be the index of the in that the frag was received from.
   seq, sig, chunk, and sz are the respective fields from the mcache
   fragment that was received.  tsorig and tspub are the timestamps of
   the fragment that was received, and are read atomically from shared
   memory, so must both match each other from the published fragment
   (aka. they will not be torn or partially overwritten).  The ctx is a
   user-provided context object from when the stem tile was initialized.
   The callback should return 1 if the fragment was not fully processed
   and should be returned to the stem for further processing, or 0 if
   the fragment was fully processed and the consumer link should be
   advanced.

      AFTER_FRAG
   Is called immediately after the DURING_FRAG, along with an additional
   check that the reader was not overrun while handling the frag.  If
   the reader was overrun, the frag is abandoned and this function is
   not called.  This callback is not invoked if the stem is
   backpressured, as it would not read a frag in the first place.
   in_idx will be the index of the in that the frag was received from.
   You should not read the frag data directly here, as it might still
   get overrun, instead it should be copied out of the frag during the
   read callback if needed later. This function cannot fail. The ctx is
   a user-provided context object from when the stem tile was
   initialized.  stem should only be used for calling fd_stem_publish to
   publish a fragment to downstream consumers.  seq is the sequence
   number of the fragment that was read from the input mcache. sig,
   chunk, sz, tsorig, and tspub are the respective fields from the
   mcache fragment that was received.  If the producer is not respecting
   flow control, these may be corrupt or torn and should not be trusted.

      AFTER_POLL_OVERRUN
   Is called when an overrun is detected while polling for new frags.
   This callback is not called when an overrun is detected in
   during_frag. */

#if !FD_HAS_ALLOCA
#error "fd_stem requires alloca"
#endif

#include "../topo/fd_topo.h"
#include "../metrics/fd_metrics.h"
#include "../../tango/fd_tango.h"

#ifndef STEM_NAME
#define STEM_NAME stem
#endif
#define STEM_(n) FD_EXPAND_THEN_CONCAT3(STEM_NAME,_,n)

#ifndef STEM_BURST
#error "STEM_BURST must be defined"
#endif

#ifndef STEM_CALLBACK_CONTEXT_TYPE
#error "STEM_CALLBACK_CONTEXT_TYPE must be defined"
#endif

#ifndef STEM_LAZY
#define STEM_LAZY (0L)
#endif

static inline void
STEM_(in_update)( fd_stem_tile_in_t * in ) {
  fd_fseq_update( in->fseq, in->seq );

  volatile ulong * metrics = fd_metrics_link_in( fd_metrics_base_tl, in->idx );

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

FD_FN_PURE static inline ulong
STEM_(scratch_align)( void ) {
  return FD_STEM_SCRATCH_ALIGN;
}

FD_FN_PURE static inline ulong
STEM_(scratch_footprint)( ulong in_cnt,
                          ulong out_cnt,
                          ulong cons_cnt ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_stem_tile_in_t), in_cnt*sizeof(fd_stem_tile_in_t)     );  /* in */
  l = FD_LAYOUT_APPEND( l, alignof(ulong),             out_cnt*sizeof(ulong)                ); /* cr_avail */
  l = FD_LAYOUT_APPEND( l, alignof(ulong),             out_cnt*sizeof(ulong)                ); /* out_depth */
  l = FD_LAYOUT_APPEND( l, alignof(ulong),             out_cnt*sizeof(ulong)                ); /* out_seq */
  l = FD_LAYOUT_APPEND( l, alignof(ulong const *),     cons_cnt*sizeof(ulong const *)       ); /* cons_fseq */
  l = FD_LAYOUT_APPEND( l, alignof(ulong *),           cons_cnt*sizeof(ulong *)             ); /* cons_slow */
  l = FD_LAYOUT_APPEND( l, alignof(ulong),             cons_cnt*sizeof(ulong)               ); /* cons_out */
  l = FD_LAYOUT_APPEND( l, alignof(ulong),             cons_cnt*sizeof(ulong)               ); /* cons_seq */
  const ulong event_cnt = in_cnt + 1UL + cons_cnt;
  l = FD_LAYOUT_APPEND( l, alignof(ushort),            event_cnt*sizeof(ushort)             ); /* event_map */
  return FD_LAYOUT_FINI( l, STEM_(scratch_align)() );
}

static inline void
STEM_(run1)( ulong                        in_cnt,
             fd_frag_meta_t const **      in_mcache,
             ulong **                     in_fseq,
             ulong                        out_cnt,
             fd_frag_meta_t **            out_mcache,
             ulong                        cons_cnt,
             ulong *                      _cons_out,
             ulong **                     _cons_fseq,
             ulong                        burst,
             long                         lazy,
             fd_rng_t *                   rng,
             void *                       scratch,
             STEM_CALLBACK_CONTEXT_TYPE * ctx ) {
  /* in frag stream state */
  ulong               in_seq; /* current position in input poll sequence, in [0,in_cnt) */
  fd_stem_tile_in_t * in;     /* in[in_seq] for in_seq in [0,in_cnt) has information about input fragment stream currently at
                                 position in_seq in the in_idx polling sequence.  The ordering of this array is continuously
                                 shuffled to avoid lighthousing effects in the output fragment stream at extreme fan-in and load */

  /* out frag stream state */
  ulong *        out_depth; /* ==fd_mcache_depth( out_mcache[out_idx] ) for out_idx in [0, out_cnt) */
  ulong *        out_seq;  /* next mux frag sequence number to publish for out_idx in [0, out_cnt) ]*/

  /* out flow control state */
  ulong *        cr_avail;     /* number of flow control credits available to publish downstream across all outs */
  ulong          min_cr_avail; /* minimum number of flow control credits available to publish downstream */
  ulong const ** cons_fseq;    /* cons_fseq[cons_idx] for cons_idx in [0,cons_cnt) is where to receive fctl credits from consumers */
  ulong **       cons_slow;    /* cons_slow[cons_idx] for cons_idx in [0,cons_cnt) is where to accumulate slow events */
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

  ulong metric_regime_ticks[9];    /* How many ticks the tile has spent in each regime */

  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "NULL scratch" ));
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch, STEM_(scratch_align)() ) ) ) FD_LOG_ERR(( "misaligned scratch" ));

  /* in_backp==1, backp_cnt==0 indicates waiting for initial credits,
      cleared during first housekeeping if credits available */
  metric_in_backp  = 1UL;
  metric_backp_cnt = 0UL;
  memset( metric_regime_ticks, 0, sizeof( metric_regime_ticks ) );

  /* in frag stream init */

  in_seq = 0UL; /* First in to poll */

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
  min_cr_avail = 0UL;

  out_depth  = (ulong *)FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), out_cnt*sizeof(ulong) );
  out_seq    = (ulong *)FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong), out_cnt*sizeof(ulong) );

  ulong cr_max = fd_ulong_if( !out_cnt, 128UL, ULONG_MAX );

  for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {

    if( FD_UNLIKELY( !out_mcache[ out_idx ] ) ) FD_LOG_ERR(( "NULL out_mcache[%lu]", out_idx ));

    out_depth[ out_idx ] = fd_mcache_depth( out_mcache[ out_idx ] );
    out_seq[ out_idx ] = 0UL;

    cr_max = fd_ulong_min( cr_max, out_depth[ out_idx ] );
    cr_avail[ out_idx ] = out_depth[ out_idx ];
  }

  cons_fseq = (ulong const **)FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong const *), cons_cnt*sizeof(ulong const *) );
  cons_slow = (ulong **)      FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong *),       cons_cnt*sizeof(ulong *)       );
  cons_out  = (ulong *)       FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),         cons_cnt*sizeof(ulong)         );
  cons_seq  = (ulong *)       FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),         cons_cnt*sizeof(ulong)         );

  if( FD_UNLIKELY( !!cons_cnt && !_cons_fseq ) ) FD_LOG_ERR(( "NULL cons_fseq" ));
  for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
    if( FD_UNLIKELY( !_cons_fseq[ cons_idx ] ) ) FD_LOG_ERR(( "NULL cons_fseq[%lu]", cons_idx ));
    cons_fseq[ cons_idx ] = _cons_fseq[ cons_idx ];
    cons_out [ cons_idx ] = _cons_out [ cons_idx ];
    cons_slow[ cons_idx ] = (ulong*)(fd_metrics_link_out( fd_metrics_base_tl, cons_idx ) + FD_METRICS_COUNTER_LINK_SLOW_COUNT_OFF);
    cons_seq [ cons_idx ] = fd_fseq_query( _cons_fseq[ cons_idx ] );
  }

  /* housekeeping init */

  if( lazy<=0L ) lazy = fd_tempo_lazy_default( cr_max );
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
        cons_seq[ cons_idx ] = fd_fseq_query( cons_fseq[ cons_idx ] );

      } else if( FD_LIKELY( event_idx>cons_cnt ) ) { /* in fctl for in in_idx */
        ulong in_idx = event_idx - cons_cnt - 1UL;

        /* Send flow control credits and drain flow control diagnostics
           for in_idx. */

        STEM_(in_update)( &in[ in_idx ] );

      } else { /* event_idx==cons_cnt, housekeeping event */

        /* Update metrics counters to external viewers */
        FD_COMPILER_MFENCE();
        FD_MGAUGE_SET( TILE, HEARTBEAT,                 (ulong)now );
        FD_MGAUGE_SET( TILE, IN_BACKPRESSURE,           metric_in_backp );
        FD_MCNT_INC  ( TILE, BACKPRESSURE_COUNT,        metric_backp_cnt );
        FD_MCNT_ENUM_COPY( TILE, REGIME_DURATION_NANOS, metric_regime_ticks );
#ifdef STEM_CALLBACK_METRICS_WRITE
        STEM_CALLBACK_METRICS_WRITE( ctx );
#endif
        FD_COMPILER_MFENCE();
        metric_backp_cnt = 0UL;

        /* Receive flow control credits */
        if( FD_LIKELY( min_cr_avail<cr_max ) ) {
          ulong slowest_cons = ULONG_MAX;
          min_cr_avail = cr_max;
          for( ulong out_idx=0; out_idx<out_cnt; out_idx++ ) {
            cr_avail[ out_idx ] = out_depth[ out_idx ];
          }

          for( ulong cons_idx=0UL; cons_idx<cons_cnt; cons_idx++ ) {
            ulong out_idx = cons_out[ cons_idx ];
            ulong cons_cr_avail = (ulong)fd_long_max( (long)out_depth[ out_idx ]-fd_long_max( fd_seq_diff( out_seq[ out_idx ], cons_seq[ cons_idx ] ), 0L ), 0L );

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

    if( FD_UNLIKELY( min_cr_avail<burst ) ) {
      metric_backp_cnt += (ulong)!metric_in_backp;
      metric_in_backp   = 1UL;
      FD_SPIN_PAUSE();
      metric_regime_ticks[2] += housekeeping_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[5] += (ulong)(next - now);
      now = next;
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
      continue;
    }
#endif

    /* Select which in to poll next (randomized round robin) */

    if( FD_UNLIKELY( !in_cnt ) ) {
      int was_busy = 0;
      was_busy |= !!charge_busy_before;
      was_busy |= !!charge_busy_after;
      metric_regime_ticks[ 0+was_busy ] += housekeeping_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[ 3+was_busy ] += (ulong)(next - now);
      now = next;
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

    fd_stem_tile_in_t * this_in = &in[ in_seq ];
    in_seq++;
    if( in_seq>=in_cnt ) in_seq = 0UL; /* cmov */

    /* Check if this in has any new fragments to mux */

    ulong                  this_in_seq   = this_in->seq;
    fd_frag_meta_t const * this_in_mline = this_in->mline; /* Already at appropriate line for this_in_seq */

#if FD_HAS_SSE
    __m128i seq_sig = fd_frag_meta_seq_sig_query( this_in_mline );
    ulong seq_found = fd_frag_meta_sse0_seq( seq_sig );
    ulong sig       = fd_frag_meta_sse0_sig( seq_sig );
#else
    /* Without SSE, seq and sig might be read from different frags (due
       to overrun), which results in a before_frag and during_frag being
       issued with incorrect arguments, but not after_frag. */
    ulong seq_found = FD_VOLATILE_CONST( this_in_mline->seq );
    ulong sig       = FD_VOLATILE_CONST( this_in_mline->sig );
#endif
    (void)sig;

    long diff = fd_seq_diff( this_in_seq, seq_found );
    if( FD_UNLIKELY( diff ) ) { /* Caught up or overrun, optimize for new frag case */
      ulong * housekeeping_regime = &metric_regime_ticks[0];
      ulong * prefrag_regime = &metric_regime_ticks[3];
      ulong * finish_regime = &metric_regime_ticks[6];
      if( FD_UNLIKELY( diff<0L ) ) { /* Overrun (impossible if in is honoring our flow control) */
        this_in->seq = seq_found; /* Resume from here (probably reasonably current, could query in mcache sync directly instead) */
        housekeeping_regime = &metric_regime_ticks[1];
        prefrag_regime = &metric_regime_ticks[4];
        finish_regime = &metric_regime_ticks[7];
        this_in->accum[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_COUNT_OFF ]++;
        this_in->accum[ FD_METRICS_COUNTER_LINK_OVERRUN_POLLING_FRAG_COUNT_OFF ] += (uint)(-diff);

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
      continue;
    }

#ifdef STEM_CALLBACK_BEFORE_FRAG
    int filter = STEM_CALLBACK_BEFORE_FRAG( ctx, (ulong)this_in->idx, seq_found, sig );
    if( FD_UNLIKELY( filter<0 ) ) {
      metric_regime_ticks[1] += housekeeping_ticks;
      metric_regime_ticks[4] += prefrag_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[7] += (ulong)(next - now);
      now = next;
      continue;
    } else if( FD_UNLIKELY( filter>0 ) ) {
      this_in->accum[ FD_METRICS_COUNTER_LINK_FILTERED_COUNT_OFF ]++;
      this_in->accum[ FD_METRICS_COUNTER_LINK_FILTERED_SIZE_BYTES_OFF ] += (uint)this_in_mline->sz; /* TODO: This might be overrun ... ? Not loaded atomically */

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

    /* We have a new fragment to mux.  Try to load it.  This attempt
       should always be successful if in producers are honoring our flow
       control.  Since we can cheaply detect if there are
       misconfigurations (should be an L1 cache hit / predictable branch
       in the properly configured case), we do so anyway.  Note that if
       we are on a platform where AVX is atomic, this could be replaced
       by a flat AVX load of the metadata and an extraction of the found
       sequence number for higher performance. */
    FD_COMPILER_MFENCE();
    ulong chunk    = (ulong)this_in_mline->chunk;  (void)chunk;
    ulong sz       = (ulong)this_in_mline->sz;     (void)sz;
    ulong ctl      = (ulong)this_in_mline->ctl;    (void)ctl;
    ulong tsorig   = (ulong)this_in_mline->tsorig; (void)tsorig;
    ulong tspub    = (ulong)this_in_mline->tspub;  (void)tspub;

#ifdef STEM_CALLBACK_DURING_FRAG
    STEM_CALLBACK_DURING_FRAG( ctx, (ulong)this_in->idx, seq_found, sig, chunk, sz, ctl );
#endif

    FD_COMPILER_MFENCE();
    ulong seq_test =        this_in_mline->seq;
    FD_COMPILER_MFENCE();

    if( FD_UNLIKELY( fd_seq_ne( seq_test, seq_found ) ) ) { /* Overrun while reading (impossible if this_in honoring our fctl) */
      this_in->seq = seq_test; /* Resume from here (probably reasonably current, could query in mcache sync instead) */
      fd_metrics_link_in( fd_metrics_base_tl, this_in->idx )[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_COUNT_OFF ]++; /* No local accum since extremely rare, faster to use smaller cache line */
      fd_metrics_link_in( fd_metrics_base_tl, this_in->idx )[ FD_METRICS_COUNTER_LINK_OVERRUN_READING_FRAG_COUNT_OFF ] += (uint)fd_seq_diff( seq_test, seq_found ); /* No local accum since extremely rare, faster to use smaller cache line */
      /* Don't bother with spin as polling multiple locations */
      metric_regime_ticks[1] += housekeeping_ticks;
      metric_regime_ticks[4] += prefrag_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[7] += (ulong)(next - now);
      now = next;
      continue;
    }

#ifdef STEM_CALLBACK_RETURNABLE_FRAG
    int return_frag = STEM_CALLBACK_RETURNABLE_FRAG( ctx, (ulong)this_in->idx, seq_found, sig, chunk, sz, tsorig, tspub, &stem );
    if( FD_UNLIKELY( return_frag ) ) {
      metric_regime_ticks[1] += housekeeping_ticks;
      long next = fd_tickcount();
      metric_regime_ticks[4] += (ulong)(next - now);
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

    this_in->accum[ FD_METRICS_COUNTER_LINK_CONSUMED_COUNT_OFF ]++;
    this_in->accum[ FD_METRICS_COUNTER_LINK_CONSUMED_SIZE_BYTES_OFF ] += (uint)sz;

    metric_regime_ticks[1] += housekeeping_ticks;
    metric_regime_ticks[4] += prefrag_ticks;
    long next = fd_tickcount();
    metric_regime_ticks[7] += (ulong)(next - now);
    now = next;
  }
}

FD_FN_UNUSED static void
STEM_(run)( fd_topo_t *      topo,
            fd_topo_tile_t * tile ) {
  const fd_frag_meta_t * in_mcache[ FD_TOPO_MAX_LINKS ];
  ulong * in_fseq[ FD_TOPO_MAX_TILE_IN_LINKS ];

  ulong polled_in_cnt = 0UL;
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;

    in_mcache[ polled_in_cnt ] = topo->links[ tile->in_link_id[ i ] ].mcache;
    FD_TEST( in_mcache[ polled_in_cnt ] );
    in_fseq[ polled_in_cnt ]   = tile->in_link_fseq[ i ];
    FD_TEST( in_fseq[ polled_in_cnt ] );
    polled_in_cnt += 1;
  }

  fd_frag_meta_t * out_mcache[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    out_mcache[ i ] = topo->links[ tile->out_link_id[ i ] ].mcache;
    FD_TEST( out_mcache[ i ] );
  }

  ulong   reliable_cons_cnt = 0UL;
  ulong   cons_out[ FD_TOPO_MAX_LINKS ];
  ulong * cons_fseq[ FD_TOPO_MAX_LINKS ];
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * consumer_tile = &topo->tiles[ i ];
    for( ulong j=0UL; j<consumer_tile->in_cnt; j++ ) {
      for( ulong k=0UL; k<tile->out_cnt; k++ ) {
        if( FD_UNLIKELY( consumer_tile->in_link_id[ j ]==tile->out_link_id[ k ] && consumer_tile->in_link_reliable[ j ] ) ) {
          cons_out[ reliable_cons_cnt ] = k;
          cons_fseq[ reliable_cons_cnt ] = consumer_tile->in_link_fseq[ j ];
          FD_TEST( cons_fseq[ reliable_cons_cnt ] );
          reliable_cons_cnt++;
          /* Need to test this, since each link may connect to many outs,
             you could construct a topology which has more than this
             consumers of links. */
          FD_TEST( reliable_cons_cnt<FD_TOPO_MAX_LINKS );
        }
      }
    }
  }

  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, 0, 0UL ) ) );

  STEM_CALLBACK_CONTEXT_TYPE * ctx = (STEM_CALLBACK_CONTEXT_TYPE*)fd_ulong_align_up( (ulong)fd_topo_obj_laddr( topo, tile->tile_obj_id ), STEM_CALLBACK_CONTEXT_ALIGN );

  STEM_(run1)( polled_in_cnt,
               in_mcache,
               in_fseq,
               tile->out_cnt,
               out_mcache,
               reliable_cons_cnt,
               cons_out,
               cons_fseq,
               STEM_BURST,
               STEM_LAZY,
               rng,
               fd_alloca( FD_STEM_SCRATCH_ALIGN, STEM_(scratch_footprint)( polled_in_cnt, tile->out_cnt, reliable_cons_cnt ) ),
               ctx );

  if( FD_LIKELY( tile->allow_shutdown ) ) {
    for( ulong i=0UL; i<tile->in_cnt; i++ ) {
      if( FD_UNLIKELY( !tile->in_link_poll[ i ] || !tile->in_link_reliable[ i ] ) ) continue;

      /* Return infinite credits on any reliable consumer links so that
         producers now no longer expect us to consume. */
      ulong fseq_id = tile->in_link_fseq_obj_id[ i ];
      ulong * fseq = fd_fseq_join( fd_topo_obj_laddr( topo, fseq_id ) );
      FD_TEST( fseq );
      fd_fseq_update( fseq, ULONG_MAX );
    }
  }
}

#undef STEM_NAME
#undef STEM_
#undef STEM_BURST
#undef STEM_CALLBACK_CONTEXT_TYPE
#undef STEM_LAZY
#undef STEM_CALLBACK_SHOULD_SHUTDOWN
#undef STEM_CALLBACK_DURING_HOUSEKEEPING
#undef STEM_CALLBACK_METRICS_WRITE
#undef STEM_CALLBACK_BEFORE_CREDIT
#undef STEM_CALLBACK_AFTER_CREDIT
#undef STEM_CALLBACK_BEFORE_FRAG
#undef STEM_CALLBACK_DURING_FRAG
#undef STEM_CALLBACK_RETURNABLE_FRAG
#undef STEM_CALLBACK_AFTER_FRAG
