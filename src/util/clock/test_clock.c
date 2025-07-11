#include "../fd_util.h"
#include <math.h>
#include "fd_clock.h"

FD_STATIC_ASSERT( FD_CLOCK_SUCCESS== 0, unit_test );
FD_STATIC_ASSERT( FD_CLOCK_ERR_X  ==-1, unit_test );
FD_STATIC_ASSERT( FD_CLOCK_ERR_Y  ==-2, unit_test );

FD_STATIC_ASSERT( alignof(fd_clock_shmem_t)==FD_CLOCK_ALIGN,     unit_test );
FD_STATIC_ASSERT( sizeof (fd_clock_shmem_t)==FD_CLOCK_FOOTPRINT, unit_test );

FD_STATIC_ASSERT( FD_CLOCK_ALIGN    ==128UL, unit_test );
FD_STATIC_ASSERT( FD_CLOCK_FOOTPRINT==640UL, unit_test );

static fd_clock_shmem_t shmem[1];
static fd_clock_t       lmem[1];

static long bad_clock_x( void const * _ ) { return -_fd_tickcount    ( _ ); }
static long bad_clock_y( void const * _ ) { return -_fd_log_wallclock( _ ); }

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  long   recal_avg  = fd_env_strip_cmdline_long  ( &argc, &argv, "--recal-avg",  NULL, (long)10e6 );
  long   recal_jit  = fd_env_strip_cmdline_long  ( &argc, &argv, "--recal-jit",  NULL, 0L         ); /* 0 -> use default */
  double recal_hist = fd_env_strip_cmdline_double( &argc, &argv, "--recal-hist", NULL, 0.         ); /* 0 -> use default */
  double recal_frac = fd_env_strip_cmdline_double( &argc, &argv, "--recal-frac", NULL, 0.         ); /* 0 -> use default */
  double tau_meas   = fd_env_strip_cmdline_double( &argc, &argv, "--tau-meas",   NULL, 1e5        );
  long   tau_stat   = fd_env_strip_cmdline_long  ( &argc, &argv, "--tau-stat",   NULL, (long) 1e9 );
  long   tau_run    = fd_env_strip_cmdline_long  ( &argc, &argv, "--tau-run",    NULL, (long)10e9 );

  FD_LOG_NOTICE(( "Testing (--recal-avg %li ns --recal-jit %li ns --recal-hist %e --recal-frac %e --tau-meas %e ns --tau-stat %li ns --tau-run %li ns)",
                  recal_avg, recal_jit, recal_hist, recal_frac, tau_meas, tau_stat, tau_run ));

  FD_LOG_NOTICE(( "Testing fd_clock_joint_read" ));

  fd_clock_func_t clock_x = _fd_tickcount;     void const * args_x = NULL;
  fd_clock_func_t clock_y = _fd_log_wallclock; void const * args_y = NULL;

  long   init_x0 = -1L;
  long   init_y0 = -2L;
  long   init_dx = -3L;
  double init_w  = 1234.;

  FD_TEST( fd_clock_joint_read( bad_clock_x,args_x, clock_y,args_y, &init_x0, &init_y0, &init_dx )==FD_CLOCK_ERR_X );
  FD_TEST( fd_clock_joint_read( clock_x,args_x, bad_clock_y,args_y, &init_x0, &init_y0, &init_dx )==FD_CLOCK_ERR_Y );

  FD_TEST( init_x0==-1L );
  FD_TEST( init_y0==-2L );
  FD_TEST( init_dx==-3L );

  FD_TEST( !fd_clock_joint_read( clock_x,args_x, clock_y,args_y, NULL,     &init_y0, &init_dx  ) );
  FD_TEST( !fd_clock_joint_read( clock_x,args_x, clock_y,args_y, &init_x0, NULL,     &init_dx  ) );
  FD_TEST( !fd_clock_joint_read( clock_x,args_x, clock_y,args_y, &init_x0, &init_y0, NULL      ) );

  FD_LOG_NOTICE(( "Starting initial calibration" ));

  FD_TEST( !fd_clock_joint_read( clock_x,args_x, clock_y,args_y, &init_x0, &init_y0, &init_dx  ) );

  FD_LOG_NOTICE(( "Joint read 0 (x %li ticks, y %li ns, dx %li ticks)", init_x0, init_y0, init_dx ));

  FD_LOG_NOTICE(( "Testing doing initial calibration" ));

  FD_TEST( fd_clock_align()    ==FD_CLOCK_ALIGN     );
  FD_TEST( fd_clock_footprint()==FD_CLOCK_FOOTPRINT );

  FD_TEST( !fd_clock_new( NULL,        recal_avg, recal_jit, recal_hist, recal_frac, init_x0, init_y0, init_w ) );
  FD_TEST( !fd_clock_new( (void *)1UL, recal_avg, recal_jit, recal_hist, recal_frac, init_x0, init_y0, init_w ) );
  FD_TEST( !fd_clock_new( shmem,       0L,        recal_jit, recal_hist, recal_frac, init_x0, init_y0, init_w ) );
  FD_TEST( !fd_clock_new( shmem,       recal_avg, -1L,       recal_hist, recal_frac, init_x0, init_y0, init_w ) );
  FD_TEST( !fd_clock_new( shmem,       recal_avg, LONG_MAX,  recal_hist, recal_frac, init_x0, init_y0, init_w ) );
  FD_TEST( !fd_clock_new( shmem,       recal_avg, recal_jit, -1.,        recal_frac, init_x0, init_y0, init_w ) );
  FD_TEST( !fd_clock_new( shmem,       recal_avg, recal_jit, recal_hist, -1,         init_x0, init_y0, init_w ) );
  FD_TEST( !fd_clock_new( shmem,       recal_avg, recal_jit, recal_hist, recal_frac, init_x0, init_y0, 0.     ) );

  void * shclock = fd_clock_new( shmem, recal_avg, recal_jit, recal_hist, recal_frac, init_x0, init_y0, init_w );
  FD_TEST( shclock==shmem );

  FD_TEST( !fd_clock_join( NULL,        shclock,     clock_x, args_x ) );
  FD_TEST( !fd_clock_join( (void *)1UL, shclock,     clock_x, args_x ) );
  FD_TEST( !fd_clock_join( lmem,        NULL,        clock_x, args_x ) );
  FD_TEST( !fd_clock_join( lmem,        (void *)1UL, clock_x, args_x ) );
  FD_TEST( !fd_clock_join( lmem,        shclock,     NULL,    args_x ) );

  fd_clock_t * clock = fd_clock_join( lmem, shclock, clock_x, args_x );
  FD_TEST( clock==lmem );

  FD_TEST( fd_clock_recal_avg ( clock )== recal_avg                                            );
  FD_TEST( fd_clock_recal_jit ( clock )==(!recal_jit     ? ((recal_avg+127L)>>7) : recal_jit ) );
  FD_TEST( fd_clock_recal_hist( clock )==(recal_hist==0. ? 3.                    : recal_hist) );
  FD_TEST( fd_clock_recal_frac( clock )==(recal_frac==0. ? 1.                    : recal_frac) );
  FD_TEST( fd_clock_init_x0   ( clock )==init_x0                                               );
  FD_TEST( fd_clock_init_y0   ( clock )==init_y0                                               );
  FD_TEST( fd_clock_init_w    ( clock )==init_w                                                );

  FD_TEST( fd_clock_shclock_const( clock )==shclock );
  FD_TEST( fd_clock_clock_x      ( clock )==clock_x );
  FD_TEST( fd_clock_args_x       ( clock )==args_x  );

  FD_TEST( fd_clock_shclock      ( clock )==shclock );

  FD_TEST( !fd_clock_leave( NULL ) );
  FD_TEST( fd_clock_leave( clock )==lmem );

  FD_TEST( !fd_clock_delete( NULL        ) );
  FD_TEST( !fd_clock_delete( (void *)1UL ) );
  FD_TEST( fd_clock_delete( shclock )==shmem );

  FD_TEST( !fd_clock_join  ( lmem, shclock, clock_x, args_x ) );
  FD_TEST( !fd_clock_delete( shclock ) );

  FD_LOG_NOTICE(( "fd_clock_strerror( 1                ) %i-%s", 1,                fd_clock_strerror( 1                ) ));
  FD_LOG_NOTICE(( "fd_clock_strerror( FD_CLOCK_SUCCESS ) %i-%s", FD_CLOCK_SUCCESS, fd_clock_strerror( FD_CLOCK_SUCCESS ) ));
  FD_LOG_NOTICE(( "fd_clock_strerror( FD_CLOCK_ERR_X   ) %i-%s", FD_CLOCK_ERR_X,   fd_clock_strerror( FD_CLOCK_ERR_X   ) ));
  FD_LOG_NOTICE(( "fd_clock_strerror( FD_CLOCK_ERR_Y   ) %i-%s", FD_CLOCK_ERR_Y,   fd_clock_strerror( FD_CLOCK_ERR_Y   ) ));

  FD_LOG_NOTICE(( "Finishing initial calibration" ));

  fd_log_wait_until( init_y0 + 3L*recal_avg ); /* Make sure a reasonable amount of time has elapsed since start */

  long init_x1;
  long init_y1;

  FD_TEST( !fd_clock_joint_read( clock_x,args_x, clock_y,args_y, &init_x1, &init_y1, &init_dx ) );
  FD_TEST( (init_x1-init_x0)>0L );
  FD_TEST( (init_y1-init_y0)>0L );

  init_w = (double)(init_x1-init_x0) / (double)(init_y1-init_y0);

  FD_LOG_NOTICE(( "Joint read 1 (x %li ticks, y %li ns, dx %li ticks) w %e GHz", init_x1, init_y1, init_dx, init_w ));

  FD_LOG_NOTICE(( "Creating clock" ));

  shclock = fd_clock_new( shmem, recal_avg, recal_jit, recal_hist, recal_frac, init_x1, init_y1, init_w );
  FD_TEST( shclock==shmem );

  clock = fd_clock_join( lmem, shclock, clock_x, args_x );
  FD_TEST( clock==lmem );

  FD_LOG_NOTICE(( "Running basic API" ));

  long now_est_last = fd_clock_now( clock );
  long recal_next   = fd_clock_recal_next( clock );
  long stat_next    = now_est_last + tau_stat;
  long stop         = now_est_last + tau_run;

  long sum_cost_tickcount = 0L; long sum_cost_tickcount_sq = 0L;
  long sum_cost_now_est   = 0L; long sum_cost_now_est_sq   = 0L;
  long sum_cost_now_wc    = 0L; long sum_cost_now_wc_sq    = 0L;
  long sum_sync_err       = 0L; long sum_sync_err_sq       = 0L;
  long cnt                = 0L;

# define HIST_MIN (-20L)
# define HIST_MAX ( 20L)
# define HIST_BIN ((ulong)(HIST_MAX-HIST_MIN+1L))

  long hist[ HIST_BIN ]; memset( hist, 0, HIST_BIN*sizeof(long) );

  double avg_cost_tickcount = 0.;
  double rms_cost_tickcount = 0.;

  long tic = fd_tickcount();
  for(;;) {

    /* Wait until the next measurement */

    long toc;
    long dt = (long)(0.5+(tau_meas*init_w)*fd_rng_double_exp( rng )); /* Poisson process like */
    for(;;) {
      toc = fd_tickcount();
      if( FD_LIKELY( (toc-tic)>=dt ) ) break;
    }
    tic = toc;

    /* Make a measurement */

    /* Note that the system wallclock return time is best interpreted as
       the time when the function returned.  On typical x86 Linux
       (clock_gettime / CLOCK_REALTIME under the hood) it is also
       sporadically really slow, especially when called after a longish
       pause.  This in turn can corrupt the now_est measurement bracket
       below because now_est_before will have been taken before it
       normally would have.  To avoid this, we do warm up calls to
       before the measurement. */

    fd_clock_now( clock );
    fd_log_wallclock();

    long t0             = fd_tickcount();
    long now_est_before = fd_clock_now( clock );
    long t1             = fd_tickcount();
    long now_wc         = fd_log_wallclock();
    long t2             = fd_tickcount();
    long now_est_after  = fd_clock_now( clock );
    long t3             = fd_tickcount();
    long t4             = fd_tickcount();

    long now_est = now_est_before + ((now_est_after-now_est_before)>>1);

    /* Test monotonicity */

    FD_TEST( now_est_before >= now_est_last   );
    FD_TEST( now_est_after  >= now_est_before );
    now_est_last = now_est_after;

    /* Accumulate statistics */

    long cost_tickcount      = t4-t3;
    long cost_now_est_before = t1-t0;
    long cost_now_wc         = t2-t1;
    long cost_now_est_after  = t3-t2;
    long sync_err            = now_wc - now_est;

    sum_cost_tickcount += cost_tickcount;      sum_cost_tickcount_sq += cost_tickcount     *cost_tickcount;
    sum_cost_now_est   += cost_now_est_before; sum_cost_now_est_sq   += cost_now_est_before*cost_now_est_before;
    sum_cost_now_wc    += cost_now_wc;         sum_cost_now_wc_sq    += cost_now_wc        *cost_now_wc;
    sum_cost_now_est   += cost_now_est_after;  sum_cost_now_est_sq   += cost_now_est_after *cost_now_est_after;
    sum_sync_err       += sync_err;            sum_sync_err_sq       += sync_err           *sync_err;
    cnt++;

    hist[ fd_long_min( fd_long_max( sync_err-HIST_MIN, 0L ), (long)(HIST_BIN-1UL) ) ]++;

    /* See if time to print statistics */

    if( FD_UNLIKELY( now_est>=stat_next ) ) {

      /* Compute the avg and rms costs measured above */

      double one_cnt = 1. / (double)cnt;

      /**/   avg_cost_tickcount =      one_cnt *(double)sum_cost_tickcount;
      double avg_cost_now_est   = (0.5*one_cnt)*(double)sum_cost_now_est;
      double avg_cost_now_wc    =      one_cnt *(double)sum_cost_now_wc;
      double avg_sync_err       =      one_cnt *(double)sum_sync_err;

      /**/   rms_cost_tickcount = sqrt( fmax(      one_cnt *(double)sum_cost_tickcount_sq - avg_cost_tickcount*avg_cost_tickcount, 0. ) );
      double rms_cost_now_est   = sqrt( fmax( (0.5*one_cnt)*(double)sum_cost_now_est_sq   - avg_cost_now_est  *avg_cost_now_est,   0. ) );
      double rms_cost_now_wc    = sqrt( fmax(      one_cnt *(double)sum_cost_now_wc_sq    - avg_cost_now_wc   *avg_cost_now_wc,    0. ) );
      double rms_sync_err       = sqrt( fmax(      one_cnt *(double)sum_sync_err_sq       - avg_sync_err      *avg_sync_err,       0. ) );

      /* Try to correct for the overhead of the tickcount from the
         fd_clock_now and fd_log_wallclock measurements */

      avg_cost_now_est -= avg_cost_tickcount;
      avg_cost_now_wc  -= avg_cost_tickcount;

      rms_cost_now_est = sqrt( fmax( rms_cost_now_est*rms_cost_now_est - rms_cost_tickcount*rms_cost_tickcount, 0. ) );
      rms_cost_now_wc  = sqrt( fmax( rms_cost_now_wc *rms_cost_now_wc  - rms_cost_tickcount*rms_cost_tickcount, 0. ) );

      FD_LOG_NOTICE(( "Statistics" ));
      FD_LOG_NOTICE(( "sync_err (ns) |      pct |  cum_pct" ));
      double cum_pct = 0.;
      for( ulong idx=0L; idx<HIST_BIN; idx++ ) {
        double pct = (100.*one_cnt)*(double)hist[idx];
        cum_pct += pct;
        if( pct>0. ) {
          if(      idx==0UL          ) FD_LOG_NOTICE(( "<=%11li | %7.3f%% | %7.3f%%", HIST_MIN+(long)idx, pct, cum_pct ));
          else if( idx==HIST_BIN-1UL ) FD_LOG_NOTICE(( ">=%11li | %7.3f%% | %7.3f%%", HIST_MIN+(long)idx, pct, cum_pct ));
          else                         FD_LOG_NOTICE((   "%13li | %7.3f%% | %7.3f%%", HIST_MIN+(long)idx, pct, cum_pct ));
        }
      }
      FD_LOG_NOTICE(( "recal err_cnt          %lu",                 fd_clock_err_cnt( clock )              ));
      FD_LOG_NOTICE(( "wallclock obs          %li",                 cnt                                    ));
      FD_LOG_NOTICE(( "fd_tickcount     cost  %.3e +/- %.3e ticks", avg_cost_tickcount, rms_cost_tickcount ));
      FD_LOG_NOTICE(( "fd_clock_now     cost  %.3e +/- %.3e ticks", avg_cost_now_est,   rms_cost_now_est   ));
      FD_LOG_NOTICE(( "fd_log_wallclock cost  %.3e +/- %.3e ticks", avg_cost_now_wc,    rms_cost_now_wc    ));
      FD_LOG_NOTICE(( "sync_err               %.3e +/- %.3e ns",    avg_sync_err,       rms_sync_err       ));

      fd_clock_reset_err_cnt( clock ); FD_TEST( !fd_clock_err_cnt( clock ) );

      sum_cost_tickcount = 0L; sum_cost_tickcount_sq = 0L;
      sum_cost_now_est   = 0L; sum_cost_now_est_sq   = 0L;
      sum_cost_now_wc    = 0L; sum_cost_now_wc_sq    = 0L;
      sum_sync_err       = 0L; sum_sync_err_sq       = 0L;
      cnt                = 0L;

      memset( hist, 0, HIST_BIN*sizeof(long) );

      stat_next += tau_stat; /* FIXME: JITTER? */
    }

    /* See if we are done */

    if( FD_UNLIKELY( now_est>=stop ) ) break;

    /* See if time to recal */

    if( FD_UNLIKELY( now_est>=recal_next ) ) {
      long x1;
      long y1;
      FD_TEST( !fd_clock_joint_read( clock_x,args_x, clock_y,args_y, &x1, &y1, NULL ) );
      recal_next = fd_clock_recal( clock, x1, y1 );
    }
  }

  FD_LOG_NOTICE(( "Running advanced API" ));

  fd_clock_shmem_t const * _shclock = fd_clock_shclock_const( clock );

  fd_clock_epoch_t epoch[1];

  FD_TEST( fd_clock_epoch_init( epoch, _shclock )==epoch );
  FD_TEST( fd_clock_seq( _shclock )==epoch->seq0         );
  FD_TEST( epoch->seq0==epoch->seq1                      );

  FD_TEST( fd_clock_x0    ( epoch )==epoch->x0           );
  FD_TEST( fd_clock_y0    ( epoch )==epoch->y0           );
  FD_TEST( fd_clock_w     ( epoch )==epoch->w            );
  FD_TEST( fd_clock_y0_eff( epoch )==epoch->y0_eff       );
  FD_TEST( fd_clock_m     ( epoch )==epoch->m            );

  now_est_last = fd_clock_now( clock );
  stat_next    = now_est_last + tau_stat;
  stop         = now_est_last + tau_run;

  sum_cost_now_est = 0L; sum_cost_now_est_sq = 0L;
  sum_sync_err     = 0L; sum_sync_err_sq     = 0L;
  cnt              = 0L;

  memset( hist, 0, HIST_BIN*sizeof(long) );

  tic = fd_tickcount();
  for(;;) {

    /* Wait until the next measurement */

    long toc;
    long dt = (long)(0.5+(tau_meas*init_w)*fd_rng_double_exp( rng )); /* Poisson process like */
    for(;;) {
      toc = fd_tickcount();
      if( FD_LIKELY( (toc-tic)>=dt ) ) break;
    }
    tic = toc;

    /* Make a measurement */

    fd_log_wallclock(); /* See note above about warmup */

    long t0      = fd_tickcount();
    long now_wc  = fd_log_wallclock();
    long t1      = fd_tickcount();
    long now_est = fd_clock_y( epoch, t0 + ((t1-t0)>>1) );
    long t2      = fd_tickcount();

    /* Test monotonicity */

    FD_TEST( now_est >= now_est_last );
    now_est_last = now_est;

    /* Accumulate statistics */

    long cost_now_est = t2-t1;
    long sync_err     = now_wc - now_est;

    sum_cost_now_est += cost_now_est; sum_cost_now_est_sq += cost_now_est*cost_now_est;
    sum_sync_err     += sync_err;     sum_sync_err_sq     += sync_err    *sync_err;
    cnt++;

    hist[ fd_long_min( fd_long_max( sync_err-HIST_MIN, 0L ), (long)(HIST_BIN-1UL) ) ]++;

    /* See if time to print statistics */

    if( FD_UNLIKELY( now_est>=stat_next ) ) {

      /* Compute the avg and rms costs measured above */

      double one_cnt = 1. / (double)cnt;

      double avg_cost_now_est = one_cnt*(double)sum_cost_now_est;
      double avg_sync_err     = one_cnt*(double)sum_sync_err;

      double rms_cost_now_est = sqrt( fmax( one_cnt*(double)sum_cost_now_est_sq - avg_cost_now_est*avg_cost_now_est, 0. ) );
      double rms_sync_err     = sqrt( fmax( one_cnt*(double)sum_sync_err_sq     - avg_sync_err    *avg_sync_err,     0. ) );

      /* Try to correct for the overhead of the tickcount from the
         fd_clock_now and fd_log_wallclock measurements.  Note that a
         negative value is possible because we aren't being very precise
         and the CPU and compiler might reorder a lot of the operations.
         Thus, a negative value here should be interpreted as
         "negligible" cost. */

      avg_cost_now_est -= avg_cost_tickcount;

      rms_cost_now_est = sqrt( fmax( rms_cost_now_est*rms_cost_now_est - rms_cost_tickcount*rms_cost_tickcount, 0. ) );

      FD_LOG_NOTICE(( "Statistics" ));
      FD_LOG_NOTICE(( "sync_err (ns) |      pct |  cum_pct" ));
      double cum_pct = 0.;
      for( ulong idx=0L; idx<HIST_BIN; idx++ ) {
        double pct = (100.*one_cnt)*(double)hist[idx];
        cum_pct += pct;
        if( pct>0. ) {
          if(      idx==0UL          ) FD_LOG_NOTICE(( "<=%11li | %7.3f%% | %7.3f%%", HIST_MIN+(long)idx, pct, cum_pct ));
          else if( idx==HIST_BIN-1UL ) FD_LOG_NOTICE(( ">=%11li | %7.3f%% | %7.3f%%", HIST_MIN+(long)idx, pct, cum_pct ));
          else                         FD_LOG_NOTICE((   "%13li | %7.3f%% | %7.3f%%", HIST_MIN+(long)idx, pct, cum_pct ));
        }
      }
      FD_LOG_NOTICE(( "recal err_cnt   %lu",                 fd_clock_err_cnt( clock )          ));
      FD_LOG_NOTICE(( "wallclock obs   %li",                 cnt                                ));
      FD_LOG_NOTICE(( "fd_clock_y cost %.3e +/- %.3e ticks", avg_cost_now_est, rms_cost_now_est ));
      FD_LOG_NOTICE(( "sync_err        %.3e +/- %.3e ns",    avg_sync_err,     rms_sync_err     ));

      fd_clock_reset_err_cnt( clock ); FD_TEST( !fd_clock_err_cnt( clock ) );

      sum_cost_now_est   = 0L; sum_cost_now_est_sq   = 0L;
      sum_cost_now_wc    = 0L; sum_cost_now_wc_sq    = 0L;
      sum_cost_tickcount = 0L; sum_cost_tickcount_sq = 0L;
      sum_sync_err       = 0L; sum_sync_err_sq       = 0L;
      cnt                = 0L;

      memset( hist, 0, HIST_BIN*sizeof(long) );

      stat_next += tau_stat; /* FIXME: JITTER? */
    }

    /* See if we are done */

    if( FD_UNLIKELY( now_est>=stop ) ) break;

    /* See if time to recal */

    if( FD_UNLIKELY( now_est>=recal_next ) ) {
      long x1;
      long y1;
      FD_TEST( !fd_clock_joint_read( clock_x,args_x, clock_y,args_y, &x1, &y1, NULL ) );
      recal_next = fd_clock_recal( clock, x1, y1 );

      FD_TEST( fd_clock_epoch_refresh( epoch, _shclock )==epoch );
      FD_TEST( fd_clock_seq( _shclock )==epoch->seq0            );
      FD_TEST( epoch->seq0==epoch->seq1                         );
    }
  }

  /* FIXME: Test fd_clock_step */

  FD_LOG_NOTICE(( "Cleaning up" ));

  FD_TEST( fd_clock_leave( clock )==lmem  );

  FD_TEST( fd_clock_delete( shclock )==shmem );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
