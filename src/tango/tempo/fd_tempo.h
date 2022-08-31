#ifndef HEADER_fd_src_tango_tempo_fd_tempo_h
#define HEADER_fd_src_tango_tempo_fd_tempo_h

/* APIs for measuring time and tick intervals */

#include "../fd_tango_base.h"

#if FD_HAS_X86 && FD_HAS_DOUBLE

FD_PROTOTYPES_BEGIN

/* fd_tempo_tickcount_model returns an estimate of t0, the minimum cost
   of fd_tickcount() in ticks.  If opt_tau is non_NULL, on return,
   *opt_tau will contain an estimate of typical jitter associated with a
   tickcount call (such that the tickcount call can be modeled as a
   shifted exponential distribution with minimum of t0 and wait time of
   tau, average cost of t0 + tau, rms of tau).  The first call of this
   in a thread group will be slow and all subsequent calls in the thread
   group will be fast and return the identical parameters to the first
   call.  t0 will be finite and positive and the tau will be finite and
   non-negative.  If the tickcount cannot be sanely parameterized on the
   first call, logs a warning and uses a fallback parameterization. */

double
fd_tempo_tickcount_model( double * opt_tau );

/* Same as the above but for fd_log_wallclock().  The model parameters
   are units of nanoseconds instead of ticks */

double
fd_tempo_wallclock_model( double * opt_tau );

/* Same as the above but gives an estimate of the rate fd_tickcount()
   ticks relative to fd_log_wallclock() (this is in ghz).  The returned
   value is the observed rate when fd_tempo_tick_per_ns was first called
   in the thread group (this call will take around ~0.5 s).  If
   opt_sigma is non-NULL, on return, *opt_sigma will have an estimate
   how much the rate was fluctuating when observed during the first
   call.
   
   IMPORTANT!  Though fd_tickcount() is meant to tick at a constant rate
   relative to the wallclock, the instantaneous rate it ticks can
   fluctuate for the usual of clock synchronization reasons (e.g.
   thermal and electrical effects from CPU load, CPU clock timing
   jitter, similar for the wallclock, etc).  As this is an invariant
   counter, reasons for it to fluctuate do _NOT_ include directly things
   like turbo mode cpu clock frequency changes (it might be slightly
   indirectly impact it  due to correlated changes to system thermal and
   electric conditions from the changed power draw).  As such, this is
   mostly meant for useful for getting a thread group wide consistent
   estimate of the number of ticks in a short interval of ns.

   TL;DR This returns an estimate of fd_tickcount()'s clock speed in
   GHz.  This is _NOT_ the current clock speed of the processor though
   it will usually superficially look like it.  This is _NOT_ the
   current rate the tickcounter is ticking relative to the wallclock
   though it will usually superficially look like it. */

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
   either (cost is on the order of a few calls to fd_wallclock plus a
   few calls to fd_tickcount).  This is mostly meant for doing precision
   timing calibrations. */

long
fd_tempo_observe_pair( long * opt_now,
                       long * opt_tic );

FD_PROTOTYPES_END

#endif

#endif /* HEADER_fd_src_tango_tempo_fd_tempo_h */
