#include "fd_mux.h"

#if FD_HAS_HOSTED && FD_HAS_X86

/* A fd_mux_tile_in has all the state needed for muxing frags from an
   in.  It fits on exactly one cache line. */

struct __attribute__((aligned(64))) fd_mux_tile_in {
  fd_frag_meta_t const * mcache;   /* local join to this in's mcache */
  ulong                  depth;    /* == fd_mcache_depth( mcache ), depth of this in's cache (const) */
  ulong                  seq;      /* sequence number of next frag expected from the upstream producer,
                                      updated when frag from this in published/filtered */
  fd_frag_meta_t const * meta;     /* == mcache + fd_mcache_line_idx( seq, depth ), location to poll next */
  ulong *                fseq;     /* local join to the fseq used to return flow control credits the in */
  uint                   accum[6]; /* local diagnostic accumualtors.  These are drained during in housekeeping. */
};

typedef struct fd_mux_tile_in fd_mux_tile_in_t;

/* fd_mux_tile_in_update returns flow control credits to the in assuming
   that there are at most exposed_cnt frags currently exposed to
   reliable outs and drains the run-time diagnostics accumulated since
   the last update.  When we drain, we don't do a fully atomic update as
   it is only diagnostic and it will still be correct the usual case
   where individual diagnostic counters aren't used by multiple writers
   spread over different threads of execution.
   
   (In principle, we could only drain diagnostics when in->seq has
   changed since last update but this is probably not worth the effort
   as these will be remotely polled infrequently and thus the draining
   is likely an L1 cache hit.  Even if in->seq hasn't changed, we still
   need to return cr upstream because exposed_cnt might have changed.
   We could in principle only do the credit return in->seq-exposed_cnt
   is unchanged but this too is probably more trouble than it is worth
   for similar reasons.) */

static inline void
fd_mux_tile_in_update( fd_mux_tile_in_t * in,
                       ulong              exposed_cnt ) {
  ulong * in_fseq = in->fseq;
  fd_fctl_rx_cr_return( in_fseq, fd_seq_dec( in->seq, exposed_cnt ) );
  ulong * diag  = (ulong *)fd_fseq_app_laddr( in_fseq );
  uint *  accum = in->accum;
# define DRAIN( idx ) FD_VOLATILE( diag[idx] ) = FD_VOLATILE_CONST( diag[idx] ) + (ulong)accum[idx]; accum[idx] = 0U
  DRAIN( FD_MUX_FSEQ_DIAG_PUB_CNT   );
  DRAIN( FD_MUX_FSEQ_DIAG_PUB_SZ    );
  DRAIN( FD_MUX_FSEQ_DIAG_FILT_CNT  );
  DRAIN( FD_MUX_FSEQ_DIAG_FILT_SZ   );
  DRAIN( FD_MUX_FSEQ_DIAG_OVRNP_CNT );
  DRAIN( FD_MUX_FSEQ_DIAG_OVRNR_CNT );
# undef DRAIN
}

#define SCRATCH_ALLOC( a, s ) (__extension__({                    \
    ulong _scratch_alloc = fd_ulong_align_up( scratch_top, (a) ); \
    scratch_top = _scratch_alloc + (s);                           \
    (void *)_scratch_alloc;                                       \
  }))

FD_STATIC_ASSERT( alignof(fd_mux_tile_in_t)<=FD_MUX_TILE_SCRATCH_ALIGN, packing );
FD_STATIC_ASSERT( FD_RNG_ALIGN             <=FD_MUX_TILE_SCRATCH_ALIGN, packing );

ulong
fd_mux_tile_scratch_align( void ) {
  return FD_MUX_TILE_SCRATCH_ALIGN;
}

ulong
fd_mux_tile_scratch_footprint( ulong in_cnt,
                               ulong out_cnt ) {
  if( FD_UNLIKELY( in_cnt >FD_MUX_TILE_IN_MAX  ) ) return 0UL;
  if( FD_UNLIKELY( out_cnt>FD_MUX_TILE_OUT_MAX ) ) return 0UL;
  ulong scratch_top = 0UL;
  SCRATCH_ALLOC( alignof(fd_mux_tile_in_t), in_cnt*sizeof(fd_mux_tile_in_t)     ); /* in */
  SCRATCH_ALLOC( alignof(ulong *),          out_cnt*sizeof(ulong *)             ); /* out_fseq */
  SCRATCH_ALLOC( alignof(ulong *),          out_cnt*sizeof(ulong *)             ); /* out_slow */
  SCRATCH_ALLOC( alignof(ulong),            out_cnt*sizeof(ulong)               ); /* out_seq */
  SCRATCH_ALLOC( alignof(ushort),           (in_cnt+out_cnt+1UL)*sizeof(ushort) ); /* event_map */
  SCRATCH_ALLOC( fd_rng_align(),            fd_rng_footprint()                  ); /* rng */
  return fd_ulong_align_up( scratch_top, fd_mux_tile_scratch_align() );
}

int
fd_mux_tile( ulong         in_cnt,
             ulong         out_cnt,
             char const *  _cnc,
             char const ** _in_mcache,
             char const ** _in_fseq,
             char const *  _mux_mcache,
             ulong         mux_cr_max, /* holds the maximum number of flow control credits for publishing downstream (const) */
             char const ** _out_fseq,
             long          lazy,
             uint          seed,
             void *        scratch ) {

  /* cnc state */
  fd_cnc_t * cnc;      /* Local join to the mux's cnc */
  ulong *    cnc_diag; /* ==fd_cnc_app_laddr( cnc ), local address of the mux tile cnc diagnostic region */

  /* in state */
  fd_mux_tile_in_t * in; /* in[in_idx] for in_idx in [0,in_cnt) has information about input fragment stream in_idx */

  /* mux state */
  fd_frag_meta_t * mux_mcache;   /* Local join to the mcache where input fragment metadata will be multiplexed */
  ulong            mux_depth;    /* ==fd_mcache_depth( mcache ), depth of the mcache / positive integer power of 2 */
  ulong *          mux_sync;     /* ==fd_mcache_seq_laddr( mcache ), local addr where mux mcache sync info is published */
  ulong            mux_seq;      /* next mux frag sequence number to publish */
  ulong            mux_cr_avail; /* number of flow control credits available to publish downstream, in [0,mux_cr_max] */

  /* out state */
  ulong ** out_fseq; /* out_fseq[out_idx] for out_idx in [0,out_cnt) is where to receive fctl credits from outs */
  ulong ** out_slow; /* out_slow[out_idx] for out_idx in [0,out_cnt) is where to accumulate slow events */
  ulong *  out_seq;  /* out_seq [out_idx] is the most recent observation of out_fseq[out_idx] */

  /* event state */
  ulong      event_cnt;   /* ==in_cnt+out_cnt+1, total number of housekeeping events */
  ulong      event_seq;   /* current position in housekeeping event sequence, in [0,event_cnt) */
  ushort *   event_map;   /* current mapping of event sequence to event idx, event_map[ event_seq ] is next event to process */
  fd_rng_t * rng;         /* local join to local random number generator */
  ulong      async_min;   /* minimum number of run loop iterations between processing a housekeeping event, power of 2 */

  /* run loop state */
  ulong in_poll;  /* in mcache to poll next, in [0,in_cnt) */
  int   in_backp; /* is the run loop currently backpressured by one or more of the outs, in [0,1] */

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

    ulong scratch_top = (ulong)scratch;

    /* cnc state init */

    if( FD_UNLIKELY( !_cnc ) ) { FD_LOG_WARNING(( "NULL cnc" )); return 1; }
    FD_LOG_INFO(( "Joining cnc %s", _cnc ));
    cnc = fd_cnc_join( fd_wksp_map( _cnc ) );

    if( FD_UNLIKELY( !cnc ) ) { FD_LOG_WARNING(( "join failed" )); return 1; }
    if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) { FD_LOG_WARNING(( "already booted" )); return 1; }

    cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );

    /* in state init */

    in = (fd_mux_tile_in_t *)SCRATCH_ALLOC( alignof(fd_mux_tile_in_t), in_cnt*sizeof(fd_mux_tile_in_t) );

    ulong min_in_depth = (ulong)LONG_MAX;

    if( FD_UNLIKELY( !!in_cnt && !_in_mcache ) ) { FD_LOG_WARNING(( "NULL in_mcache" )); return 1; }
    if( FD_UNLIKELY( !!in_cnt && !_in_fseq   ) ) { FD_LOG_WARNING(( "NULL in_fseq"   )); return 1; }
    for( ulong in_idx=0UL; in_idx<in_cnt; in_idx++ ) {
      fd_mux_tile_in_t * this_in = &in[ in_idx ];

      if( FD_UNLIKELY( !_in_mcache[ in_idx ] ) ) { FD_LOG_WARNING(( "NULL in%lu mcache", in_idx )); return 1; }
      FD_LOG_INFO(( "Joining in%lu mcache %s", in_idx, _in_mcache[ in_idx ] ));
      this_in->mcache = fd_mcache_join( fd_wksp_map( _in_mcache[ in_idx ] ) );
      if( FD_UNLIKELY( !this_in->mcache ) ) { FD_LOG_WARNING(( "join failed" )); return 1; }

      ulong const * this_in_sync = fd_mcache_seq_laddr_const( this_in->mcache );

      this_in->depth = fd_mcache_depth( this_in->mcache ); min_in_depth = fd_ulong_min( min_in_depth, this_in->depth );
      this_in->seq   = fd_mcache_seq_query( this_in_sync ); /* FIXME: ALLOW OPTION FOR MANUAL SPECIFICATION? */
      this_in->meta  = this_in->mcache + fd_mcache_line_idx( this_in->seq, this_in->depth );

      /* FIXME: CONSIDER NULL OR EMPTY CSTR IN_FCTL[ IN_IDX ] TO SPECIFY
         NO FLOW CONTROL FOR A PARTICULAR IN? */
      if( FD_UNLIKELY( !_in_fseq[ in_idx ] ) ) { FD_LOG_WARNING(( "NULL in%lu fseq", in_idx )); return 1; }
      FD_LOG_INFO(( "Joining in%lu fseq %s", in_idx, _in_fseq[ in_idx ] ));
      this_in->fseq = fd_fseq_join( fd_wksp_map( _in_fseq[ in_idx ] ) );
      if( FD_UNLIKELY( !this_in->fseq ) ) { FD_LOG_WARNING(( "join failed" )); return 1; }

      this_in->accum[0] = 0U; this_in->accum[1] = 0U; this_in->accum[2] = 0U;
      this_in->accum[3] = 0U; this_in->accum[4] = 0U; this_in->accum[5] = 0U;
    }

    if( FD_UNLIKELY( !_mux_mcache ) ) { FD_LOG_WARNING(( "NULL mux_mcache" )); return 1; }
    FD_LOG_INFO(( "Joining mux-mcache %s", _mux_mcache ));

    /* mux state init */

    mux_mcache = fd_mcache_join( fd_wksp_map( _mux_mcache ) );
    if( FD_UNLIKELY( !mux_mcache ) ) { FD_LOG_WARNING(( "join failed" )); return 1; }

    mux_depth = fd_mcache_depth    ( mux_mcache );
    mux_sync  = fd_mcache_seq_laddr( mux_mcache );

    mux_seq = fd_mcache_seq_query( mux_sync ); /* FIXME: ALLOW OPTION FOR MANUAL SPECIFICATION */

    /* Since mux_cr_avail is decremented everytime a frag is exposed to
       the outs by the mux, exposed_cnt=mux_cr_max-mux_cr_avail is the
       number frags that are currently exposed.  Exposed frags can be
       arbitrarily distributed over all ins and, in the worst case,
       could all be from just one particular in.

       When the mux sends flow control credits to an in, the mux
       decrements the actual mux's position in sequence space by this
       upper bound.  This guarantees, even in the worst case (all frags
       exposed downstream came from the smallest depth in), the ins will
       never overrun any outs.  It also means that the mux tile doesn't
       have to keep track of how exposed frags are distributed over the
       ins (simplifying the implementation and increasing performance).

       This also implies that mux_cr_max must be at most
       min(in_mcache[*].depth) such that the mux cannot never expose
       more frags from an in than the in itself can cache.  It also
       can't be larger than mux_depth such that at most mux_depth frags
       will ever be exposed to outs.

       This further implies that the mux should continuously replenish
       its credits from the outs whenever it has less than mux_cr_max
       credits.  To see this:

       Note that the we require (as is typically the case) an out is to
       continuously advertise, via the out's fseq, a recent position in
       mux's sequence space (such that, in the absence of incoming
       fragments, the out's advertised sequence number will eventually
       exactly match the mux's sequence number).  The mux similarly
       continuously advertises to each in its position in the in's
       sequence space.

       Let there be range of credits where the mux will not bother to
       replenish mux_cr_avail to minimize what, in typical situations,
       would be wasteful cache coherence traffic from the outs to the
       mux on the CPU NOC (e.g. mux_cr_avail in
       [mux_cr_resume,mux_cr_max) for the fctl state machine).  An in
       will stop sending to the mux if its in_cr_avail is zero (i.e. it
       cannot prove it is safe to send).  If this happens when the mux
       thinks it doesn't need to replenish flow control credits for outs
       (i.e. mux_cr_avail is large enough) the ins and the mux will
       permanently stall.

       An in will think has no credits available to send when:

         mux_seq - exposed_cnt = in_seq - in_cr_max

       or:

         mux_seq - (mux_cr_max - mux_cr_avail) = in_seq - in_cr_max

       Note that:

         mux_seq = in_seq - mux_lag
         
       where mux lag is the number of frags behind the mux is from the
       in and, because of in<>mux flow control, this is in
       [0,in_cr_max].  Simplifying, we need to insure:

         (in_cr_max - mux_lag) - (mux_cr_max - mux_cr_avail) = 0

       never happens when mux_cr_avail is in [mux_cr_resume,mux_cr_max).

       Given the range of mux_lag, the first term is in [0,in_cr_max].
       Given the range of mux_cr_avail, the second term is in
       [1,mux_cr_max-mux_cr_resume].  Thus we require
       [-(mux_cr_max-mux_cr_resume),in_cr_max-1] does not contain 0
       Since in_cr_max is positive though, this can never be true.

       With continuous replenishing, exposed_cnt will alwasy improve as
       the outs make progress and this improvement will then always be
       reflected all the ways to the ins, preventing deadlock / livelock
       situations.

       Since we need to continuously replenish our credits when all the
       outs aren't full caught up and we want to optimize for the common
       scenario of very deep buffers and large number of outputs, to
       avoid bursts of correlated traffic on the NOC, we do not use
       fctl (we would need to turn off state machine and and we would
       like to avoid the bursts of fseq reads it would do when
       replenishing).  Instead, we use a customized flow control
       algortihm here to lazy and stochastically receive observe the
       outs without bursts. */

    /* Note that the default value requires that
       in[*].depth==in[*].cr_max and out[*].lag_max==mux.depth.  More
       general situations can override this value to taste. */

    ulong mux_cr_max_max = fd_ulong_min( min_in_depth, mux_depth );
    if( !mux_cr_max ) mux_cr_max = mux_cr_max_max; /* use default */
    FD_LOG_INFO(( "Using mux_cr_max %lu", mux_cr_max ));
    if( FD_UNLIKELY( !((1UL<=mux_cr_max) & (mux_cr_max<=mux_cr_max_max)) ) ) {
      FD_LOG_WARNING(( "cr_max %lu must be in [1,%lu] for these mcaches", mux_cr_max, mux_cr_max_max ));
      return 1;
    }

    mux_cr_avail = 0UL; /* Will be initialized by run loop */

    /* out state init */

    out_fseq = SCRATCH_ALLOC( alignof(ulong *), out_cnt*sizeof(ulong *) );
    out_slow = SCRATCH_ALLOC( alignof(ulong *), out_cnt*sizeof(ulong *) );
    out_seq  = SCRATCH_ALLOC( alignof(ulong),   out_cnt*sizeof(ulong)   );

    if( FD_UNLIKELY( !!out_cnt && !_out_fseq ) ) { FD_LOG_WARNING(( "NULL out_fseq" )); return 1; }
    for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {
      if( FD_UNLIKELY( !_out_fseq[ out_idx ] ) ) { FD_LOG_WARNING(( "NULL out%lu fseq", out_idx )); return 1; }
      FD_LOG_INFO(( "Joining out%lu fseq %s", out_idx, _out_fseq[ out_idx ] ));
      out_fseq[ out_idx ] = fd_fseq_join( fd_wksp_map( _out_fseq[ out_idx ] ) );
      if( FD_UNLIKELY( !out_fseq[out_idx] ) ) { FD_LOG_WARNING(( "join failed" )); return 1; }
      out_slow[ out_idx ] = (ulong *)fd_fseq_app_laddr( out_fseq[ out_idx ] ) + FD_MUX_FSEQ_DIAG_SLOW_CNT;
      out_seq [ out_idx ] = fd_fseq_query( out_fseq[ out_idx ] );
    }

    /* For the lazy default, given a 100G link line-rating minimal sized
       Ethernet frames (672 bits) into a mcache / dcache and consumers
       that are keeping up (both highly unrealistically harsh situations
       in the real world as this implies the consumer is processing
       packets every 6.72 ns and the UDP payload of a minimal sized
       Ethernet frame is much much smaller than real world frames), we'd
       ideally be returning credits at least in the time it takes the
       producer to fill up the mcache (and ideally a little more for
       safety).  This implies we need to cycle through all housekeeping
       events more often than:

         ~(mux_cr_max pkt)(672 bit/pkt/100 Gbit/ns)

       and given that the typical cycle time is at most ~1.5 lazy (from
       below), we have:

         lazy < ~mux_cr_max*672/100e9/1.5 ~ 4.48 mux_cr_max

       We go with 2.25 to keep things simple. */

    if( lazy<=0L ) lazy = (9L*(long)mux_cr_max) >> 2;
    FD_LOG_INFO(( "Configuring housekeeping (lazy %li ns, seed %u)", lazy, seed ));

    /* event state init */
    /* Initialize the initial event sequence to immediately update
       cr_avail on the first run loop iteration and then update all the
       ins accordingly. */

    event_cnt = in_cnt + 1UL + out_cnt;
    event_map = SCRATCH_ALLOC( alignof(ushort), event_cnt*sizeof(ushort) );
    event_seq = 0UL;                                     event_map[ event_seq++ ] = (ushort) out_cnt;
    for( ulong  in_idx=0UL;  in_idx< in_cnt;  in_idx++ ) event_map[ event_seq++ ] = (ushort)( in_idx+out_cnt+1UL);
    for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) event_map[ event_seq++ ] = (ushort) out_idx;
    event_seq = 0UL;

    /* Pick a range of async_min such that the run loop will cycle
       through all the housekeeping events every ~lazy ns.  More
       precisely, the typical cycle time will be
       ~1.5*async_min*event_cnt where async_min is at least
       ~0.5*lazy/event_cnt and at most ~lazy/event_cnt.  As such, the
       typical cycle time is at least ~0.75*lazy and at most ~1.5*lazy. */

    rng = fd_rng_join( fd_rng_new( SCRATCH_ALLOC( fd_rng_align(), fd_rng_footprint() ), seed, 0UL ) );
    long async_target = (long)(0.5 + fd_tempo_tick_per_ns( NULL )*(double)lazy / (double)event_cnt);
    if( FD_UNLIKELY( async_target<=0L ) ) { FD_LOG_WARNING(( "bad lazy" )); return 1; }
    async_min = 1UL << fd_ulong_find_msb( (ulong)async_target );

    /* run loop state init */

    in_poll  = 0UL; /* First in to poll */
    in_backp = 1;   /* Is the run loop currently backpressured due to slow reliable consumers */
                    /* Cleared after initial polls of output sources */
    FD_VOLATILE( cnc_diag[ FD_MUX_CNC_DIAG_IN_BACKP ] ) = 1UL; /* Cleared on first iteration if credits available */

  } while(0);

  FD_LOG_INFO(( "Running mux" ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  long next = fd_tickcount();
  long now  = next;
  for(;;) {

    /* Do housekeeping in the background; async_rem is checked and
       decremented every iteration to insure no starvation effects occur
       under heavy load conditions. */

    if( FD_UNLIKELY( (now-next)>=0L ) ) {
      ulong event_idx = (ulong)event_map[ event_seq ];

      /* Do the next async event.  async idx:
            <out_cnt - receive credits from out event_idx
           ==out_cnt - mux housekeeping
            >out_cnt - send credits to in event_idx - out_cnt - 1.
         Branch hints and order are optimized for the case:
           out_cnt >~ in_cnt >~ 1. */

      if( FD_LIKELY( event_idx<out_cnt ) ) {

        /* out fctl event for out event_idx.  Receive flow control
           credits from this out. */

        ulong out_idx = event_idx;
        out_seq[ out_idx ] = fd_fseq_query( out_fseq[ out_idx ] );

      } else if( FD_LIKELY( event_idx>out_cnt ) ) {

        /* in fctl event for in event_idx-out_cnt-1.  Send flow control
           credits to this in.  Note that there are at most
           mux_cr_max-mux_cr_avail frags exposed downstream.  We don't
           know how this is distributed so we conservatively assume they
           all from this in.  FIXME: COULD DO A NUMBER OF TRICKS FOR AN
           EVEN TIGHTER BOUND HERE (E.G. EXPLICITLY TRACKING THE NUMBER
           OF FRAGS EXPOSED PER UPSTREAM CONSUMER FOR EXAMPLE). */

        ulong in_idx = event_idx - out_cnt - 1UL;
        fd_mux_tile_in_update( &in[ in_idx ], mux_cr_max-mux_cr_avail );

      } else { /* event_idx==out_cnt */

        /* mux housekeeping event.  Send synchronization info to
           downstream consumers / monitors, update mux_cr_avail,
           heartbeat for monitors and handle any pending
           command-and-control signals. */

        fd_mcache_seq_update( mux_sync, mux_seq );

        if( FD_LIKELY( mux_cr_avail<mux_cr_max ) ) {
          ulong slowest_out  = ULONG_MAX;
          mux_cr_avail = mux_cr_max;
          for( ulong out_idx=0UL; out_idx<out_cnt; out_idx++ ) {
            ulong out_cr_avail = (ulong)
              fd_long_max( (long)mux_cr_max - fd_long_max( fd_seq_diff( mux_seq, out_seq[ out_idx ] ), 0L ), 0L );
            slowest_out  = fd_ulong_if( out_cr_avail<mux_cr_avail, out_idx, slowest_out );
            mux_cr_avail = fd_ulong_min( out_cr_avail, mux_cr_avail );
          }
          /* See notes about use of non-fully atomic diagnostic
             updates above. */
          if( FD_LIKELY( slowest_out!=ULONG_MAX ) )
            FD_VOLATILE( out_slow[slowest_out] ) = FD_VOLATILE_CONST( out_slow[slowest_out] ) + 1UL;
        }

        if( FD_UNLIKELY( (in_backp) & (!!mux_cr_avail) ) ) {
          FD_VOLATILE( cnc_diag[ FD_MUX_CNC_DIAG_IN_BACKP ] ) = 0UL;
          in_backp = 0;
        }

        fd_cnc_heartbeat( cnc, fd_log_wallclock() );

        ulong s = fd_cnc_signal_query( cnc );
        if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
          if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
          if( FD_UNLIKELY( s!=FD_MUX_CNC_SIGNAL_ACK ) ) {
            char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
            FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
          }
          /* FIXME: CONSIDER A DIAGNOSTIC DUMP COMMAND? */
          fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
        }
      }

      /* Select which event to do next (round robin) and reload the
         housekeeping timer. */

      event_seq++;
      if( event_seq>=event_cnt ) {
        event_seq = 0UL; /* cmov */
        /* Randomize the order of event processing for the next event
           cnt to avoid lighthousing effects causing input credit
           starvation at extreme fan in, extreme in load and high credit
           return laziness. */
        ulong  swap_idx = (ulong)fd_rng_uint_roll( rng, (uint)event_cnt );
        ushort swap_tmp     = event_map[swap_idx];
        event_map[swap_idx] = event_map[0       ];
        event_map[0       ] = swap_tmp;
      }

      next = now + (long)fd_async_reload( rng, async_min );
    }

    /* Check if we are backpressured.  If so, count any transition into
       a backpressured regime and spin to wait for flow control credits
       to return.  We don't do a fully atomic update here as it is only
       diagnostic and it will still be correct the usual case where
       individual diagnostic counters aren't used by writers in
       different threads of execution.  We only count the transition
       from not backpressured to backpressured. */

    if( FD_UNLIKELY( !mux_cr_avail ) ) {
      if( FD_UNLIKELY( !in_backp ) ) {
        FD_VOLATILE( cnc_diag[ FD_MUX_CNC_DIAG_IN_BACKP  ] ) = 1UL;
        FD_VOLATILE( cnc_diag[ FD_MUX_CNC_DIAG_BACKP_CNT ] ) = FD_VOLATILE_CONST( cnc_diag[ FD_MUX_CNC_DIAG_BACKP_CNT ] ) + 1UL;
        in_backp = 1;
      }
      FD_SPIN_PAUSE();
      now = fd_tickcount();
      continue;
    }

    /* Select which in to poll next (round robin) */

    if( FD_UNLIKELY( !in_cnt ) ) { now = fd_tickcount(); continue; }
    fd_mux_tile_in_t * this_in = &in[ in_poll ];
    in_poll++;
    if( in_poll>=in_cnt ) in_poll = 0UL; /* cmov */

    /* Check if this in has any new fragments to mux */

    ulong                  this_in_seq  = this_in->seq;
    fd_frag_meta_t const * this_in_meta = this_in->meta;  /* Already at appropriate line for this_in_seq */

    FD_COMPILER_MFENCE();
    ulong seq_found = this_in_meta->seq;
    FD_COMPILER_MFENCE();

    long diff = fd_seq_diff( this_in_seq, seq_found );
    if( FD_UNLIKELY( diff ) ) { /* Caught up or overrun, optimize for new frag case */
      if( FD_UNLIKELY( diff<0L ) ) { /* Overrun (impossible if in is honoring our flow control) */
        this_in->seq = seq_found; /* Resume from here (probably reasonably current, could query in mcache sync directly instead) */
        this_in->accum[ FD_MUX_FSEQ_DIAG_OVRNP_CNT ]++;
      }
      /* Don't bother with spin as polling multiple locations */
      now = fd_tickcount();
      continue;
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
    ulong sig      =        this_in_meta->sig;
    ulong chunk    = (ulong)this_in_meta->chunk;
    ulong sz       = (ulong)this_in_meta->sz;
    ulong ctl      = (ulong)this_in_meta->ctl;
    ulong tsorig   = (ulong)this_in_meta->tsorig;
    FD_COMPILER_MFENCE();
    ulong seq_test =        this_in_meta->seq;
    FD_COMPILER_MFENCE();

    if( FD_UNLIKELY( fd_seq_ne( seq_test, seq_found ) ) ) { /* Overrun while reading (impossible if this_in honoring our fctl) */
      this_in->seq = seq_test; /* Resume from here (probably reasonably current, could query in mcache sync instead) */
      this_in->accum[ FD_MUX_FSEQ_DIAG_OVRNR_CNT ]++;
      /* Don't bother with spin as polling multiple locations */
      now = fd_tickcount();
      continue;
    }

    /* We have successfully loaded the metadata.  Decide whether it
       is interesting downstream.  If so, publish it. */

    ulong should_filter = 0UL; /* FIXME: FILTERING LOGIC HERE */

    if( FD_UNLIKELY( should_filter ) ) now = fd_tickcount(); /* Optimize for forwarding path */
    else {
      now = fd_tickcount();
      ulong tspub = (ulong)fd_frag_meta_ts_comp( now );
      fd_mcache_publish( mux_mcache, mux_depth, mux_seq, sig, chunk, sz, ctl, tsorig, tspub );
      mux_cr_avail--;
      mux_seq = fd_seq_inc( mux_seq, 1UL );
    }

    /* Windup for the next in poll and accumulate diagnostics */

    this_in_seq   = fd_seq_inc( this_in_seq, 1UL );
    this_in->seq  = this_in_seq;
    this_in->meta = this_in->mcache + fd_mcache_line_idx( this_in_seq, this_in->depth );

    ulong diag_idx = FD_MUX_FSEQ_DIAG_PUB_CNT + should_filter*2UL;
    this_in->accum[ diag_idx     ]++;
    this_in->accum[ diag_idx+1UL ] += (uint)sz;
  }

  do {

    FD_LOG_INFO(( "Halting mux" ));

    FD_LOG_INFO(( "Destroying rng" ));
    fd_rng_delete( fd_rng_leave( rng ) );

    while( out_cnt ) {
      ulong out_idx = --out_cnt;
      FD_LOG_INFO(( "Leaving out%lu fseq", out_idx ));
      fd_wksp_unmap( fd_fseq_leave( out_fseq[ out_idx ] ) );
    }

    FD_LOG_INFO(( "Leaving mux mcache" ));
    fd_wksp_unmap( fd_mcache_leave( mux_mcache ) );

    while( in_cnt ) {
      ulong in_idx = --in_cnt;
      fd_mux_tile_in_t * this_in = &in[ in_idx ];
      fd_mux_tile_in_update( this_in, 0UL ); /* exposed_cnt 0 assumes all reliable consumers caught up or shutdown */

      FD_LOG_INFO(( "Leaving in%lu fseq", in_idx ));
      fd_wksp_unmap( this_in->fseq );

      FD_LOG_INFO(( "Leaving in%lu mcache", in_idx ));
      fd_wksp_unmap( fd_mcache_leave( this_in->mcache ) );
    }

    FD_LOG_INFO(( "Halted mux" ));
    fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );

    FD_LOG_INFO(( "Leaving cnc" ));
    fd_wksp_unmap( fd_cnc_leave( cnc ) );

  } while(0);

  return 0;
}

#undef SCRATCH_ALLOC

#endif
