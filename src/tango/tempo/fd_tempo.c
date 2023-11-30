#include "../fd_tango.h"

#if FD_HAS_DOUBLE

double
fd_tempo_wallclock_model( double * opt_tau ) {
  static double t0;
  static double tau;

  FD_ONCE_BEGIN {

    /* Assuming fd_log_wallclock() observes the application wallclock at
       a consistent point between when the call was made and when it
       returns, the difference between two adjacent calls is an estimate
       of the number of ns required for a call.  We expect this
       difference to have a well defined minimum time with sporadic
       delays due to various sources of jitter.  The natural approach is
       to model call overhead then as a shifted exponential random
       variable.  To parameterize the model, we repeatedly measure how
       long a call takes.  The minimum of a bunch of IID samples is very
       fast converging for estimating the minimum but easily corrupted
       if there are weird outliers on the negative side.  As such, we
       use a robust estimator to estimate the minimal overhead and
       jitter. */

    ulong iter = 0UL;
    for(;;) { 
#     define TRIAL_CNT 512UL
#     define TRIM_CNT  64UL
      double trial[ TRIAL_CNT ]; 
      for( ulong trial_idx=0UL; trial_idx<TRIAL_CNT; trial_idx++ ) {
        FD_COMPILER_MFENCE();
        long tic = fd_log_wallclock();
        FD_COMPILER_MFENCE();
        long toc = fd_log_wallclock();
        FD_COMPILER_MFENCE();
        trial[ trial_idx ] = (double)(toc - tic);
        FD_COMPILER_MFENCE();
      }
      double * sample     = trial + TRIM_CNT;
      ulong    sample_cnt = TRIAL_CNT - 2UL*TRIM_CNT;
      ulong    thresh     = sample_cnt >> 1;
      if( FD_LIKELY( fd_stat_robust_exp_fit_double( &t0, &tau, sample, sample_cnt, sample )>thresh ) && FD_LIKELY( t0>0. ) ) break;
#     undef TRIM_CNT
#     undef TRIAL_CNT
      iter++;
      if( iter==3UL ) {
        FD_LOG_WARNING(( "unable to model fd_log_wallclock() performance; using fallback and attempting to continue" ));
        t0 = 27.; tau = 1.;
        break;
      }
    }

  } FD_ONCE_END;

  if( opt_tau ) opt_tau[0] = tau;
  return t0;
}

double
fd_tempo_tickcount_model( double * opt_tau ) {
  static double t0;
  static double tau;

  FD_ONCE_BEGIN {

    /* Same as the above but for fd_tickcount(). */

    ulong iter = 0UL;
    for(;;) { 
#     define TRIAL_CNT 512UL
#     define TRIM_CNT  64UL
      double trial[ TRIAL_CNT ]; 
      for( ulong trial_idx=0UL; trial_idx<TRIAL_CNT; trial_idx++ ) {
        FD_COMPILER_MFENCE();
        long tic = fd_tickcount();
        FD_COMPILER_MFENCE();
        long toc = fd_tickcount();
        FD_COMPILER_MFENCE();
        trial[ trial_idx ] = (double)(toc - tic);
        FD_COMPILER_MFENCE();
      }
      double * sample     = trial + TRIM_CNT;
      ulong    sample_cnt = TRIAL_CNT - 2UL*TRIM_CNT;
      ulong    thresh     = sample_cnt >> 1;
      if( FD_LIKELY( fd_stat_robust_exp_fit_double( &t0, &tau, sample, sample_cnt, sample )>thresh ) && FD_LIKELY( t0>0. ) ) break;
#     undef TRIM_CNT
#     undef TRIAL_CNT
      iter++;
      if( iter==3UL ) {
        FD_LOG_WARNING(( "unable to model fd_tickcount() performance; using fallback and attempting to continue" ));
        t0 = 24.; tau = 4.;
        break;
      }
    }

  } FD_ONCE_END;

  if( opt_tau ) opt_tau[0] = tau;
  return t0;
}

static double mu;
static double sigma;
static int explicit_set;

void
fd_tempo_set_tick_per_ns( double _mu,
                          double _sigma ) {
  explicit_set = 1;
  mu    = _mu;
  sigma = _sigma;
}

double
fd_tempo_tick_per_ns( double * opt_sigma ) {

  FD_ONCE_BEGIN {

    /* If the value has already been set explicitly, no need to sample. */

    if( FD_LIKELY( !explicit_set ) ) {

      /* We measure repeatedly how much the tickcount and wallclock change
         over the same approximately constant time interval.  We do a pair
         observations to minimize errors in computing the interval (note
         that any remaining jitters should be zero mean such that they
         should statistically cancel in the rate calculation).  We use a
         robust estimate to get the avg and rms in the face of random
         sources of noise, assuming the sample distribution is reasonably
         well modeled as normal. */

      ulong iter = 0UL;
      for(;;) { 
  #     define TRIAL_CNT 32UL
  #     define TRIM_CNT   4UL
        double trial[ TRIAL_CNT ]; 
        for( ulong trial_idx=0UL; trial_idx<TRIAL_CNT; trial_idx++ ) {
          long then; long toc; fd_tempo_observe_pair( &then, &toc );
          fd_log_sleep( 16777216L ); /* ~16.8 ms */
          long now; long tic; fd_tempo_observe_pair( &now, &tic );
          trial[ trial_idx ] = (double)(tic-toc) / (double)(now-then);
        }
        double * sample     = trial + TRIM_CNT;
        ulong    sample_cnt = TRIAL_CNT - 2UL*TRIM_CNT;
        ulong    thresh     = sample_cnt >> 1;
        if( FD_LIKELY( fd_stat_robust_norm_fit_double( &mu, &sigma, sample, sample_cnt, sample )>thresh ) && FD_LIKELY( mu>0. ) )
          break;
  #     undef TRIM_CNT
  #     undef TRIAL_CNT
        iter++;
        if( iter==3UL ) {
          FD_LOG_WARNING(( "unable to measure tick_per_ns accurately; using fallback and attempting to continue" ));
          mu = 3.; sigma = 1e-7;
          break;
        }
      }
    }

  } FD_ONCE_END;

  if( opt_sigma ) opt_sigma[0] = sigma;
  return mu;
}

#endif

long
fd_tempo_observe_pair( long * opt_now,
                       long * opt_tic ) {
  long best_wc;
  long best_tc;
  long best_jt;

  do {

    /* Do an alternating series of:

         tickcount
         wallclock
         tickcount
         wallclock
         tickcount
         ...
         wallclock
         tickcount

       observations and pick the wallclock observation that had the
       smallest elapsed number of ticks between adjacent tickcount
       observations.

       Since the wallclock / tickcounter returns a monotonically
       non-decreasing observation of the wallclock / tickcount at a
       point in time between when the call was made and when it
       returned, we know that this wallclock observation is the one we
       made that we know best when it was made in the tickcount stream.
       Further, we have lower and upper bounds of the value of the
       tickcounter in this read.  We start the alternation with the
       tickcount because that is typically the lower overhead, more
       deterministic one and less likely to get jerked around behind our
       back.
       
       Theoretically, this exploits how the minimum of a shifted
       exponential random variable converges.  Since the time to read
       the various clocks is expected to be reasonably modeled as a
       shifted exponential random variable, it doesn't take many trials
       to get something close to the minimum (estimating the minimum of
       a shifted exponential random variable takes way fewer samples and
       is way more accurate than say the estimating the average of a
       normally distributed random variable). */

#   define TRIAL_CNT (4) /* 1 "warmup", 3 real reads */

    long wc[ TRIAL_CNT+1 ];
    long tc[ TRIAL_CNT+1 ];
    FD_COMPILER_MFENCE();
    tc[0] = fd_tickcount();
    FD_COMPILER_MFENCE();
    for( ulong trial_idx=0UL; trial_idx<TRIAL_CNT; trial_idx++ ) {
      wc[ trial_idx+1UL ] = fd_log_wallclock();
      FD_COMPILER_MFENCE();
      tc[ trial_idx+1UL ] = fd_tickcount();
      FD_COMPILER_MFENCE();
    }

    best_wc = wc[1];
    best_tc = tc[1];
    best_jt = best_tc - tc[0];
    for( ulong trial_idx=1UL; trial_idx<TRIAL_CNT; trial_idx++ ) {
      long wci = wc[ trial_idx+1UL ];
      long tci = tc[ trial_idx+1UL ];
      long jti = tci - tc[ trial_idx ];
      int  c   = (jti<=best_jt);
      best_wc  = fd_long_if( c, wci, best_wc );
      best_tc  = fd_long_if( c, tci, best_tc );
      best_jt  = fd_long_if( c, jti, best_jt );
    }

#   undef TRIAL_CNT

  } while(0);

  if( FD_UNLIKELY( best_jt<0L ) ) { /* paranoia */
    FD_LOG_WARNING(( "fd_tickcount() does not appear to be monotonic; joint read may not be accurate; attempting to continue" ));
    best_jt = 0L;
  }

  if( opt_now ) opt_now[0] = best_wc;
  if( opt_tic ) opt_tic[0] = best_tc - (best_jt>>1); /* Use lower and upper bound midpoint (could be improved statistically) */
  return best_jt;
}

ulong
fd_tempo_async_min( long  lazy,
                    ulong event_cnt,
                    float tick_per_ns ) {
  if( FD_UNLIKELY( !((1L<=lazy) & (lazy<(1L<<31))) ) ) {
    FD_LOG_WARNING(( "lazy should be in [1,2^31)" ));
    return 0UL;
  }

  if( FD_UNLIKELY( !((1UL<=event_cnt) & (event_cnt<(1UL<<31)) ) ) ) {
    FD_LOG_WARNING(( "event_cnt should be in [1,2^31)" ));
    return 0UL;
  }

  float tick_per_ns_max = FLT_MAX / (float)(1L<<31); /* exact, compile time, ~1.5e29 */
  if( FD_UNLIKELY( !((0.f<tick_per_ns) & (tick_per_ns<=tick_per_ns_max)) ) ) { /* robust against nan */
    FD_LOG_WARNING(( "tick_per_ns should in (0,~1.5e29)" ));
    return 0UL;
  }

  float _lazy         = (float)lazy;      /* typically exact, up to 0.5 ulp error if >~ 2^24 */
  float _event_cnt    = (float)event_cnt; /* typically exact, up to 0.5 ulp error if >~ 2^24 */
  float _async_target = (tick_per_ns*_lazy) / _event_cnt; /* non-negative finite result, O(1) ulp error typically */

  if( FD_UNLIKELY( !(1.f<=_async_target) ) ) {
    FD_LOG_WARNING(( "lazy, event_cnt and tick_per_ns imply an unreasonably small async_min" ));
    return 0UL;
  }

  if( FD_UNLIKELY( !(_async_target<((float)(1UL<<32))) ) ) {
    FD_LOG_WARNING(( "lazy, event_cnt and tick_per_ns imply an unreasonably large async_min" ));
    return 0UL;
  }

  ulong async_target = (ulong)_async_target;       /* in [1,2^32), O(1) ulp error typically (biased conservative) */
  return 1UL << fd_ulong_find_msb( async_target ); /* guaranteed power of 2 in [1,2^31] */
}

