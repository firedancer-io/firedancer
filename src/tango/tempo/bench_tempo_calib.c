/* bench_tempo_calib measures the accuracy and wall-clock cost of the
   tick_per_ns calibration loop in fd_tempo_tick_per_ns for different
   (trial_cnt, trim_cnt, sleep_ns) parameterizations.  Because the real
   fd_tempo_tick_per_ns is FD_ONCE-guarded (only samples once per
   process), this harness re-implements the identical sampling logic so
   it can be run many times and compared against a high-precision
   reference.  Used to validate that the "Tier 1" parameter reduction
   (fewer/shorter trials) does not degrade the rate estimate. */

#include "../fd_tango.h"
#include "../../util/math/fd_stat.h"
#include <math.h>

#if FD_HAS_DOUBLE

/* calib runs ONE calibration with the given parameters and returns
   mu (tick_per_ns) in *opt_mu and sigma in *opt_sigma.  Identical
   algorithm to fd_tempo_tick_per_ns. */

static int
calib( double * opt_mu,
       double * opt_sigma,
       ulong    trial_cnt,
       ulong    trim_cnt,
       long     sleep_ns ) {
  double mu, sigma;
  int retries = 0;
  ulong iter = 0UL;
  for(;;) {
    double trial[ 4096 ];
    if( trial_cnt>4096UL ) trial_cnt = 4096UL;
    for( ulong trial_idx=0UL; trial_idx<trial_cnt; trial_idx++ ) {
      long then; long toc; fd_tempo_observe_pair( &then, &toc );
      fd_log_sleep( sleep_ns );
      long now; long tic; fd_tempo_observe_pair( &now, &tic );
      trial[ trial_idx ] = (double)(tic-toc) / (double)(now-then);
    }
    double * sample     = trial + trim_cnt;
    ulong    sample_cnt = trial_cnt - 2UL*trim_cnt;
    ulong    thresh     = sample_cnt >> 1;
    if( FD_LIKELY( fd_stat_robust_norm_fit_double( &mu, &sigma, sample, sample_cnt, sample )>thresh ) && FD_LIKELY( mu>0. ) ) break;
    iter++;
    retries++;
    if( iter==3UL ) { mu = 3.; sigma = 1e-7; break; }
  }
  if( opt_mu    ) *opt_mu    = mu;
  if( opt_sigma ) *opt_sigma = sigma;
  return retries;
}

/* run_config repeats calib() rep_cnt times, printing the spread of mu
   (relative to ref) and the wall-clock cost per calibration. */

static void
run_config( char const * label,
            ulong        trial_cnt,
            ulong        trim_cnt,
            long         sleep_ns,
            ulong        rep_cnt,
            double       ref ) {
  if( rep_cnt>256UL ) rep_cnt = 256UL;
  if( rep_cnt<1UL   ) rep_cnt = 1UL;
  double mus[ 256 ];
  double sigmas[ 256 ];
  long   t_total = 0L;
  int    retry_total = 0;

  for( ulong r=0UL; r<rep_cnt; r++ ) {
    long t0 = fd_log_wallclock();
    retry_total += calib( &mus[r], &sigmas[r], trial_cnt, trim_cnt, sleep_ns );
    t_total += fd_log_wallclock() - t0;
  }

  /* mean / stddev / min / max of mu */
  double sum=0., sum2=0., lo=mus[0], hi=mus[0];
  double maxabserr=0.;
  for( ulong r=0UL; r<rep_cnt; r++ ) {
    double m = mus[r];
    sum += m;
    sum2 += m*m;
    if( m<lo ) lo=m;
    if( m>hi ) hi=m;
    double e = (m-ref)/ref;
    if( e<0. ) e=-e;
    if( e>maxabserr ) maxabserr = e;
  }
  double mean = sum/(double)rep_cnt;
  double var  = sum2/(double)rep_cnt - mean*mean;
  if( var<0. ) var=0.;
  double sd   = sqrt( var );
  double bias = (mean-ref)/ref;
  double spread = (hi-lo)/ref;

  double sig_sum=0.; for( ulong r=0UL; r<rep_cnt; r++ ) sig_sum += sigmas[r];
  double sig_mean = sig_sum/(double)rep_cnt;

  FD_LOG_NOTICE(( "%-26s  wall/calib %7.1f ms | mu mean %10.6f ghz  bias %+9.2e  jitter(sd) %8.2e (%.2f ppm)  spread %8.2e  maxerr %8.2e  sigma_out %8.2e  retries %d",
                  label,
                  (double)t_total/(double)rep_cnt/1e6,
                  mean, bias, sd/mean, sd/mean*1e6, spread, maxabserr, sig_mean, retry_total ));
}

#endif

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# if FD_HAS_DOUBLE
  ulong rep_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--reps", NULL, 30UL );

  FD_LOG_NOTICE(( "building high-precision reference (large trial_cnt, long sleep)..." ));

  /* Reference: a single very long, high-trial calibration.  Average a
     few of these to pin down "truth" as well as we can on this host. */
  double ref_sum = 0.;
  ulong  ref_cnt = 5UL;
  for( ulong r=0UL; r<ref_cnt; r++ ) {
    double m;
    calib( &m, NULL, 64UL, 8UL, 33554432L /* ~33.6 ms */ );
    ref_sum += m;
  }
  double ref = ref_sum/(double)ref_cnt;
  FD_LOG_NOTICE(( "reference mu = %.6f ghz (%lu reps of 64 x 33.6ms)", ref, ref_cnt ));
  FD_LOG_NOTICE(( "comparing %lu reps per config:", rep_cnt ));

  /* The two configs that actually landed:
       - "prod"     : fd_tempo_tick_per_ns       (32 x 16.8ms)
       - "dev"      : fd_tempo_tick_per_ns_dev   (4 x 0.25ms)
     "candidate (16 x 8.4ms)" is an intermediate parameterization that was
     evaluated but NOT deployed (production kept the conservative 32-trial
     config); it is kept here for comparison only. */
  run_config( "prod (32 x 16.8ms)",      32UL,  4UL, 16777216L, rep_cnt, ref );
  run_config( "candidate (16 x 8.4ms)",  16UL,  2UL,  8388608L, rep_cnt, ref );
  run_config( "dev (4 x 0.25ms)",         4UL,  0UL,   262144L, rep_cnt, ref );

  /* A few neighbours around the dev floor, for reference / re-tuning.
     The robust fit needs > sample_cnt/2 valid points where
     sample_cnt = trial-2*trim, so trim must stay small at low trials.
     At trial_cnt==1 sigma collapses to 0, so >=2 trials is the floor
     if a meaningful sigma is required. */
  run_config( "dev-alt (8 x 0.25ms)",    8UL,  1UL,   262144L, rep_cnt, ref );
  run_config( "dev-alt (4 x 0.5ms)",     4UL,  0UL,   524288L, rep_cnt, ref );
  run_config( "dev-alt (2 x 0.5ms)",     2UL,  0UL,   524288L, rep_cnt, ref );

# else
  FD_LOG_WARNING(( "skip: no double" ));
# endif

  FD_LOG_NOTICE(( "done" ));
  fd_halt();
  return 0;
}
