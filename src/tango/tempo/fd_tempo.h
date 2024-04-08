#ifndef HEADER_fd_src_tango_tempo_fd_tempo_h
#define HEADER_fd_src_tango_tempo_fd_tempo_h

/* APIs for measuring time and tick intervals */

#include "../fd_tango_base.h"

FD_PROTOTYPES_BEGIN

/* fd_tempo_wallclock_model returns an estimate of t0, the minimum cost
   of fd_log_wallclock() in ticks.  If opt_tau is non_NULL, on return,
   *opt_tau will contain an estimate of typical jitter associated with
   fd_log_wallclock() (such that fd_log_wallclock() can be roughly
   modeled as a shifted exponential distribution with minimum of t0 and
   wait time of tau, average cost of t0 + tau, rms of tau).  The first
   call of this in a thread group will be slow and all subsequent calls
   in the thread group will be fast and return the identical parameters
   to the first call.  t0 will be finite and positive and the tau will
   be finite and non-negative.  If the fd_log_wallclock() cannot be
   sanely parameterized on the first call, logs a warning and uses a
   fallback parameterization. */

double
fd_tempo_wallclock_model( double * opt_tau );

/* fd_tempo_tickcount_model does the same as fd_tempo_wallclock model
   for fd_tickcount().  The model parameter units will be in ticks
   instead of nanoseconds. */

double
fd_tempo_tickcount_model( double * opt_tau );

/* fd_tempo_set_tick_per_ns explicitly sets the return values of
   fd_tempo_tick_per_ns below, subsequent calls to that function will
   return the values given here.
   
   These should not be arbitrarily provided, and this function is here
   primarily to enable different processes to synchronize their
   tick_per_ns value. */

void
fd_tempo_set_tick_per_ns( double _mu,
                          double _sigma );

/* fd_tempo_tick_per_ns is the same as the above but gives an estimate
   of the rate fd_tickcount() ticks relative to fd_log_wallclock() (this
   is in Ghz).  The returned value is the observed rate when
   fd_tempo_tick_per_ns was first called in the thread group (this call
   will take around ~0.5 s).  If opt_sigma is non-NULL, on return,
   *opt_sigma will have an estimate how much the rate was fluctuating
   when observed during the first call.
   
   IMPORTANT!  Though fd_tickcount() is meant to tick at a constant rate
   relative to fd_log_wallclock(), the instantaneous rate it ticks can
   fluctuate for the usual of clock synchronization reasons (e.g.
   thermal and electrical effects from CPU load, CPU clock timing
   jitter, similar for the wallclock, etc).  As this is an invariant
   counter, reasons for it to fluctuate do _NOT_ include directly things
   like turbo mode cpu clock frequency changes (it might slightly
   indirectly impact it due to correlated changes to system thermal and
   electric conditions from the changed power draw).  As such, this is
   mostly meant for useful for getting a thread group wide consistent
   estimate of the number of ticks in a short interval of ns.

   TL;DR This returns an estimate of fd_tickcount()'s clock speed in
   GHz.  This is _NOT_ the current clock speed of the processor though
   it will usually superficially look like it.  This is _NOT_ the
   instantaneous rate the tickcounter is ticking relative to the
   wallclock though it will usually superficially look like it. */

double
fd_tempo_tick_per_ns( double * opt_sigma );

/* fd_tempo_observe_pair observes the fd_log_wallclock() and
   fd_tickcount() at the "same time".  More precisely, it alternately
   observes both a few times and estimates from the "best" wallclock
   read what tickcount would have been observed at that time had
   fd_tickcount() been called instead.  Returns a non-negative measure
   of the jitter in ticks in the sense observed tickcount is within
   +/-0.5 jitter ticks of the time the wallclock was observed.  On
   return, if opt_now is non-NULL, *opt_now will contain the actual
   fd_log_wallclock() observation and, if opt_tic is non-NULL, *opt_tic
   will contain the estimated simultaneous fd_tickcount() observation.

   If anything wonky is detected in the measurement, logs a warning and
   returns a best effort.  As this does multiple reads under the hood
   and uses only one of them, the observed value should be interpreted
   as at some point in time between when the the call was made and when
   the call returned but not always at the same point (can be roughly
   modeled as uniformly distributed between when the call was made and
   when it returned).

   While this isn't particularly expensive, it isn't particularly cheap
   either.  Cost is on the order of a few calls to fd_wallclock plus a
   few calls to fd_tickcount().  This is mostly meant for doing
   precision timing calibrations. */

long
fd_tempo_observe_pair( long * opt_now,
                       long * opt_tic );

/* fd_tempo_lazy_default returns a target interval between housekeeping
   events in ns (laziness) for a producer / consumer that has a maximum
   credits of cr_max / lag behind the producer of lag_max.

   To understand this default, note that a producer should receive / a
   consumer should transmit complete flow control credits least as often
   as the time it takes a producer to exhaust all its credits / a slow
   consumer to process a worst case backlog of lag_max credits.
   Otherwise, the communications throughput will be limited by the rate
   credits can flow from consumer to producer rather than the rate the
   producer can publish / consumer can receive.  At the same time, we
   don't want to be too eager to return credits to avoid consumer to
   producer credit communications competing for NOC resources with
   producer to consumer communications.

   This implies we need to update all flow control information on a tile
   somewhat faster than:

     cr_max max( typical time it takes a producer to consume a credit,
                 typical time it takes a consumer to produce a credit )

   Practical considerations applied to this yield a useful conservative
   lower bound:

   Assume credits are network packets (as is often the case), the above
   times are the typical time it takes a producer / consumer to generate
   / process a packet.  Given a producer line-rating minimal sized
   Ethernet frames (672 bits) at 100G into a mcache / dcache and
   consumers that are keeping up with this producer (both highly
   unrealistically harsh situations in the real world as this implies
   Ethernet payloads much much smaller than typical real world payloads
   and a consumer that can process packets in just a handful of ns), the
   above suggests housekeeping done somewhat than:

     ~(cr_max pkt)(672 bit/pkt/100 Gbit/ns)

   will be adequate for all practical purposes. Given that the typical
   randomized housekeeping event will be at most ~1.5 lazy, we have:

     lazy < ~cr_max*672/100e9/1.5 ~ 4.48 cr_max

   We use 1+floor( 9*cr_max/4 )) ~ 2.25 cr_max to keep things simple.
   Note that that while this might seem aggressive per credit, since
   cr_max is typically values in thousands to hundreds of thousands,
   this corresponds to default laziness in the tens microseconds to
   milliseconds.  We also saturate cr_max to keep the returned value in
   [1,2^31] ns for all cr_max. */

FD_FN_CONST static inline long
fd_tempo_lazy_default( ulong cr_max ) {
  return fd_long_if( cr_max>954437176UL, (long)INT_MAX, (long)(1UL+((9UL*cr_max)>>2)) );
}

/* fd_tempo_async_min picks a reasonable minimum interval in ticks
   between housekeeping events.  On success, returns positive integer
   power of two in [1,2^31].  On failure, returns zero (logs details).
   Reasons for failure include lazy is not in [1,2^31), event_cnt is not
   in [1,2^31), tick_per_ns is not in (0,~1.5e29), the combination would
   require an unreasonably small (sub-tick) or large (more than 2^31)
   async_min.

   More precisely, consider a run loop where event_cnt out-of-band
   housekeeping events are cyclicly scheduled to be done with a IID
   uniform random interval between events in [async_min,2*async_min]
   ticks (as is commonly the case).  A suppose we need to housekeeping
   to complete an event cycle roughly every lazy ns for system
   considerations.

   If we were to use a regularly scheduled interval between events (which
   is a stunningly bad idea in an distributed system and all too
   commonly done), we'd space housekeeping events by:

     async_target ~ tick_per_ns*lazy/event_cnt ticks

   where tick_per_ns is the conversion ratio to use between the
   wallclock and the tickrate of whatever counter is used to schedule
   housekeeping events.

   Consider using the largest integer power of two less than or equal to
   async_target for async_min.  In ns then, async_min will be at least
   ~0.5*lazy/event_cnt and at most lazy/event_cnt.  And since it takes,
   on average, 1.5*async_min*event_cnt to process a cycle, this value
   for async min will yield an average cycle time of at least ~0.75*lazy
   in ns and at most ~1.5*lazy ns. */

ulong
fd_tempo_async_min( long  lazy,
                    ulong event_cnt,
                    float tick_per_ns );

/* fd_tempo_async_reload returns a quality random number very quickly in
   [async_min,2*async_min).  Assumes async_min is an integer power of 2
   in [1,2^31].  Consumes exactly 1 rng slot.  This is typically used to
   randomize the timing of background task processing to avoid auto
   synchronization anomalies while providing given strong lower and
   upper bounds on the interval between between processing background
   tasks. */

static inline ulong
fd_tempo_async_reload( fd_rng_t * rng,
                       ulong      async_min ) {
  return async_min + (((ulong)fd_rng_uint( rng )) & (async_min-1UL));
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_tempo_fd_tempo_h */
