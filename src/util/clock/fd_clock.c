#include "fd_clock.h"

/* Let x denote x-clock observations, y denote y-clock observations and
   y_est denote estimates of the y-clock from the x-clock.  During a
   clock epoch, we use a linear approximation for y_est:

     y_est(now) = y_eff(epoch_start) + m(epoch)*( x(now) - x(epoch_start) )

   Given a short enough epoch, the jointly observed values of x-clock
   and y-clock at the epoch start and stop are well approximated as
   linearly related:

     x_actual(epoch_end) ~ x_actual(epoch_start) + w_actual(epoch)( y_actual(epoch_end) - y_actual(epoch_start) )

   where w_actual gives the x-tick per y-tick rate between the clocks
   during the epoch.  Unfortunately, we can't jointly observe the two
   clocks infinitely precisely.  We assume that:

     x_actual(sample) = x_obs(sample) + delta_x(sample)
     y_actual(sample) = y_obs(sample)

   where delta_x(sample) represent the effects of quantization error
   (due to finite x-tick size) and synchronization error (due to not
   observing x_obs(sample) at the exact time the y_obs(sample) was
   observed on the y-clock).  That is, we assume:

     x_obs(epoch_end) + delta_x(epoch_end) = x_obs(epoch_start) + delta_x(epoch_start)
                                           + w_actual(epoch)( y_obs(epoch_end) - y_obs(epoch_start) )

   Then w_actual(epoch) = w_obs(epoch) + delta_w(epoch) where:

                    x_obs(epoch_end) - x_obs(epoch_start)
     w_obs(epoch) = -------------------------------------
                    y_obs(epoch_end) - y_obs(epoch_start)

   and:

                      delta_x(epoch_end) - delta_x(epoch_start)
     delta_w(epoch) = -----------------------------------------
                        y_obs(epoch_end) - y_obs(epoch_start)

   Assuming quitely reasonably delta_x(sample) all have the same mean
   (or, even stronger but still reasonable, are IID), w_obs(epoch) is an
   unbiased estimate of w_actual(epoch).

   We expect w_actual(epoch) to be nearly constant from epoch to epoch
   (i.e. these are clocks), we can use a decaying average filter to
   compute an estimate of w(next_epoch) given an estimate for this epoch
   w_est(epoch) and w_obs(epoch):

     w_est(next_epoch) = w_est(epoch) + alpha ( w_obs(epoch) - w_est(epoch) )

   Here:

     alpha = 1 / (1 + hist)

   is in [0,1] and hist is non-negative.  hist can be thought of as the
   number of previous observations to include in the w_est(next_epoch).

   If w_actual is strictly constant from epoch to epoch,
   w_est(next_epoch) is an unbiased estimate of w_actual assuming
   w_est(epoch) is also an unbiased estimate.

   In practice, we expect w_actual(epoch) to slowly vary from epoch to
   epoch.  The more epochs we include in the average (i.e. the larger
   hist), the more accurate w_est(epoch) will be but the less quickly
   w_est(epoch) will adapt to changes in w_actual(epoch).

   Given a reasonably accurate w_est(next_epoch), we want to create a
   relationship between the x-clock and y-clock that preserves
   monotonicity of y_est from epoch to epoch while having no asymptotic
   clock drift estimates between y_est and y.

   To that end, if y_est(epoch_end) is less than or equal to
   y_obs(epoch_end), we can correct for all accumulated clock drift
   immediately without breaking monotonicity by simply forward stepping
   y_eff(next_epoch_start) to y_obs(epoch_end) and using
   1/w_est(next_epoch) directly for m(next_epoch):

     y_eff(next_epoch_start) = y_obs(epoch_end)
     m(next_epoch)           = 1 / w_est(next_epoch)

   Unfortunately, this can break monotonicity when y_est(epoch_end) is
   greater than y_obs(epoch_end).  In this case, let frac be the
   fraction of this clock drift we want to absorb during the next epoch.
   If we know the next clock epoch will be at most epoch_max y-ticks
   long, we can reduce m(next_epoch) to absorb the bias:

     y_eff(next_epoch_start) = y_est(epoch_end)

                     1 - beta ( y_est(epoch_end) - y_obs(epoch_end) )
     m(next_epoch) = ------------------------------------------------
                                 w_est(next_epoch)

   where:

     beta = frac / epoch_max

   To insure m(next_epoch) as always positive (and thus preserve
   monotonicity), we tweak the above into:

                                                      1
     m(next_epoch) = --------------------------------------------------------------------
                     w_est(next_epoch) ( 1 + beta ( y_est(epoch_end) - y_obs(epoch_end) )

   This is asymptotically identical to the the above in the (common
   case) limit:

     beta (y_est-y_obs) << 1.

   and asymptotes to zero when:

     beta (y_est-y_obs) >> 1.

   These all be combined into a branchless implementation via:

                    x_obs(epoch_end) - x_obs(epoch_start)
     w_obs(epoch) = -------------------------------------
                    y_obs(epoch_end) - y_obs(epoch_start)

     w_est(next_epoch) = w_est(epoch) + alpha ( w_obs(epoch) - w_est(epoch) )

     y_est(epoch_end) = y_eff(epoch_start) + m(epoch) ( x_obs(epoch_end) - x_obs(epoch_start) )

     y_eff(next_epoch_start) = max( y_obs(epoch_end), y_est(epoch_end) )

                                                          1
     m(next_epoch) = ---------------------------------------------------------------------------
                     w_est(next_epoch) ( 1 + beta ( y_eff(next_epoch_start) - y_obs(epoch_end) )

   This is the basic recalibration update used below. */

ulong
fd_clock_align( void ) {
  return alignof( fd_clock_shmem_t );
}

ulong
fd_clock_footprint( void ) {
  return sizeof( fd_clock_shmem_t );
}

void *
fd_clock_new( void * shmem,
              long   recal_avg,
              long   recal_jit,
              double recal_hist,
              double recal_frac,
              long   init_x0,
              long   init_y0,
              double init_w ) {
  fd_clock_shmem_t * shclock = (fd_clock_shmem_t *)shmem;

  if( FD_UNLIKELY( !recal_jit     ) ) recal_jit  = (recal_avg>>7) + (long)!!(recal_avg & 127L); /* ceil( recal_avg / 128 ) */
  if( FD_UNLIKELY( recal_hist==0. ) ) recal_hist = 3.;
  if( FD_UNLIKELY( recal_frac==0. ) ) recal_frac = 1.;

  if( FD_UNLIKELY( !shclock ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shclock, fd_clock_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !((1L<=recal_jit) & (recal_jit<=recal_avg) & (recal_avg<=(LONG_MAX-recal_jit))) ) ) {
    FD_LOG_WARNING(( "bad recal_avg / recal_jit" ));
    return NULL;
  }

  if( FD_UNLIKELY( !(recal_hist>0.) ) ) {
    FD_LOG_WARNING(( "bad recal_hist" ));
    return NULL;
  }

  if( FD_UNLIKELY( !(recal_frac>0.) ) ) {
    FD_LOG_WARNING(( "bad recal_frac" ));
    return NULL;
  }

  double init_m = 1./init_w;
  if( FD_UNLIKELY( !((init_w>0.) & (init_m>0.)) ) ) {
    FD_LOG_WARNING(( "bad w" ));
    return NULL;
  }

  ulong footprint = fd_clock_footprint();
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad footprint" ));
    return NULL;
  }

  memset( shclock, 0, footprint );

  long  recal_jit_eff = (long)fd_ulong_pow2_dn( (ulong)recal_jit );
  long  recal_min     = recal_avg - recal_jit_eff;
  ulong recal_mask    = 2UL*(ulong)recal_jit_eff - 1UL;

  shclock->seq        = 0UL;
  shclock->recal_next = init_y0 + recal_min + (long)(fd_ulong_hash( FD_CLOCK_MAGIC ^ (ulong)init_x0 ) & recal_mask);
  shclock->err_cnt    = 0UL;

  shclock->recal_alpha = 1. / (1. + recal_hist);
  shclock->recal_beta  = recal_frac / (double)(recal_avg + recal_jit_eff);
  shclock->recal_min   = recal_min;
  shclock->recal_mask  = recal_mask;

  shclock->recal_avg  = recal_avg;
  shclock->recal_jit  = recal_jit;
  shclock->recal_hist = recal_hist;
  shclock->recal_frac = recal_frac;

  shclock->init_x0 = init_x0;
  shclock->init_y0 = init_y0;
  shclock->init_w  = init_w;

  fd_clock_epoch_t * epoch = shclock->epoch;

  for( ulong idx=0UL; idx<FD_CLOCK_EPOCH_CNT; idx++ ) {
    epoch[ idx ].seq0   = 0UL;
    epoch[ idx ].x0     = init_x0;
    epoch[ idx ].y0     = init_y0;
    epoch[ idx ].w      = init_w;
    epoch[ idx ].y0_eff = init_y0;
    epoch[ idx ].m      = init_m;
    epoch[ idx ].seq1   = 0UL;
  }

  FD_COMPILER_MFENCE();
  shclock->magic = FD_CLOCK_MAGIC;
  FD_COMPILER_MFENCE();

  return shclock;
}

fd_clock_t *
fd_clock_join( void *          _lmem,
               void *          _shclock,
               fd_clock_func_t clock_x,
               void const *    args_x ) {
  fd_clock_t       * clock   = (fd_clock_t       *)_lmem;
  fd_clock_shmem_t * shclock = (fd_clock_shmem_t *)_shclock;

  if( FD_UNLIKELY( !clock ) ) {
    FD_LOG_WARNING(( "NULL lmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)clock, alignof(fd_clock_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned lmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !shclock ) ) {
    FD_LOG_WARNING(( "NULL shclock" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shclock, fd_clock_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shclock" ));
    return NULL;
  }

  if( FD_UNLIKELY( shclock->magic!=FD_CLOCK_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  if( FD_UNLIKELY( !clock_x ) ) {
    FD_LOG_WARNING(( "NULL clock_x" ));
    return NULL;
  }

  clock->shclock = shclock;
  clock->clock_x = clock_x;
  clock->args_x  = args_x;

  return clock;
}

void *
fd_clock_leave( fd_clock_t * clock ) {

  if( FD_UNLIKELY( !clock ) ) {
    FD_LOG_WARNING(( "NULL clock" ));
    return NULL;
  }

  return clock;
}

void *
fd_clock_delete( void * _shclock ) {
  fd_clock_shmem_t * shclock = (fd_clock_shmem_t *)_shclock;

  if( FD_UNLIKELY( !shclock ) ) {
    FD_LOG_WARNING(( "NULL shclock" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shclock, fd_clock_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shclock" ));
    return NULL;
  }

  if( FD_UNLIKELY( shclock->magic!=FD_CLOCK_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  shclock->magic = 0UL;
  FD_COMPILER_MFENCE();

  return shclock;
}

long
fd_clock_now( void const * _clock ) {
  fd_clock_t       const * clock   = (fd_clock_t const *)_clock;
  fd_clock_shmem_t const * shclock = clock->shclock;
  fd_clock_func_t          clock_x = clock->clock_x;
  void const *             args_x  = clock->args_x;

  fd_clock_epoch_t epoch[1];
  long             x_obs;
  for(;;) {
    ulong seq0 = fd_clock_seq( shclock );        /* likely l1 cache hit */
    fd_clock_epoch_read( shclock, seq0, epoch ); /* likely l1 cache hit */
    x_obs = clock_x( args_x );                   /* after seq0 read, as close to return as possible */
    ulong seq1 = fd_clock_seq( shclock );        /* likely l1 cache hit */
    if( FD_LIKELY( (seq0==seq1) & (epoch->seq0==seq0) & (epoch->seq1==seq0) ) ) break;
    FD_SPIN_PAUSE();
  }
  return fd_clock_y( epoch, x_obs );
}

int
fd_clock_joint_read( fd_clock_func_t clock_x, void const * args_x,
                     fd_clock_func_t clock_y, void const * args_y,
                     long *          opt_x,
                     long *          opt_y,
                     long *          opt_dx ) {

  long x[ FD_CLOCK_JOINT_READ_CNT+1UL ];
  long y[ FD_CLOCK_JOINT_READ_CNT     ];

  for( ulong idx=0UL; idx<FD_CLOCK_JOINT_READ_CNT; idx++ ) {
    x[ idx ] = clock_x( args_x );
    y[ idx ] = clock_y( args_y );
  }

  x[ FD_CLOCK_JOINT_READ_CNT ] = clock_x( args_x );

  ulong best_idx = 0UL;
  long  best_dx  = x[1] - x[0]; if( FD_UNLIKELY( best_dx<=0L ) ) return FD_CLOCK_ERR_X;

  for( ulong idx=1UL; idx<FD_CLOCK_JOINT_READ_CNT; idx++ ) {
    long dy  = y[ idx ] - y[ idx-1UL ]; if( FD_UNLIKELY( dy<=0L ) ) return FD_CLOCK_ERR_Y;
    long dx  = x[ idx+1UL ] - x[ idx ]; if( FD_UNLIKELY( dx<=0L ) ) return FD_CLOCK_ERR_X;
    best_idx = fd_ulong_if( best_dx<dx, best_idx, idx );
    best_dx  = fd_long_min( best_dx, dx );
  }

  best_dx = (best_dx+1L) >> 1; /* ceil( (x[best_idx+1]-x[best_idx])/2 ) */

  fd_long_store_if( !!opt_x,  opt_x,  x[ best_idx ] + best_dx );
  fd_long_store_if( !!opt_y,  opt_y,  y[ best_idx ]           );
  fd_long_store_if( !!opt_dx, opt_dx, best_dx                 );

  return FD_CLOCK_SUCCESS;
}

static inline long
fd_clock_epoch_next( fd_clock_shmem_t * shclock,
                     long               x0,
                     long               y0,
                     double             w,
                     long               y0_eff,
                     double             m,
                     int                err ) {

  ulong seq        = shclock->seq     + 1UL;
  long  recal_next = (y0_eff + shclock->recal_min) + (long)(fd_ulong_hash( FD_CLOCK_MAGIC ^ (ulong)x0 ) & shclock->recal_mask);
  ulong err_cnt    = shclock->err_cnt + (ulong)!!err;

  fd_clock_epoch_t * epoch = shclock->epoch + (seq & (FD_CLOCK_EPOCH_CNT-1UL));

  FD_COMPILER_MFENCE();
  epoch->seq1         = seq;     /* Mark entry as unsafe to read */
  FD_COMPILER_MFENCE();
  epoch->x0           = x0;
  epoch->y0           = y0;
  epoch->w            = w;
  epoch->y0_eff       = y0_eff;
  epoch->m            = m;
  FD_COMPILER_MFENCE();
  epoch->seq0         = seq;     /* Mark entry as safe to read */
  FD_COMPILER_MFENCE();
  shclock->seq        = seq;
  shclock->recal_next = recal_next;
  shclock->err_cnt    = err_cnt;
  FD_COMPILER_MFENCE();

  return recal_next;
}

long
fd_clock_recal( fd_clock_t * clock,
                long         x1,
                long         y1 ) {

  fd_clock_shmem_t * shclock = clock->shclock;

  fd_clock_epoch_t const * epoch = shclock->epoch + (shclock->seq & (FD_CLOCK_EPOCH_CNT-1UL));

  long   x0     = epoch->x0;
  long   y0     = epoch->y0;
  double w0     = epoch->w;
  long   y0_eff = epoch->y0_eff;
  double m0     = epoch->m;

  long   dx = x1 - x0;
  long   dy = y1 - y0;

  double w_obs = ((double)dx) / ((double)dy);

  double w1;
  long   y1_eff;
  double m1;
  int    err;

  if( FD_UNLIKELY( !((dx>0L) & (dy>0L) & ((0.5*w0)<w_obs) & (w_obs<(2.0*w0))) ) ) {

    /* At this point, the x-clock didn't step forward between recals,
       the y-clock didn't step forward between recals, the observed rate
       this epoch slowed dramatically and/or the observed rate this
       epoch increased dramatically.  This is typically a sign that an
       operator stepped the x-clock backward (dx<<0), y-clock backward
       (dy<<0), x-clock forward (w_obs>>w0) and/or y-clock forward
       (w_obs<<w0) by a large amount out-of-band.  We start the new
       epoch at (x1,y1) with the current epoch's tick rate estimates and
       log a recal error.  This allows near immediate recovery all
       manners of clock jankiness.  It also can break monotonicity of
       y-clock predictions but there's not a lot of choice given janky
       clocks. */

    w1     = w0;
    y1_eff = y1;
    m1     = 1./w0;
    err    = 1;

  } else {

    /* At this point, x1 / y1 are in the future of the current epoch
       start on the x-clock / y-clock and the observed tick rate this
       epoch is plausible.  We average the observed tick rate with the
       current epoch's rate estimate to get the next epoch's rate
       estimate.

       To preserve y-clock prediction monotonicity, the effective y1
       for the next epoch will be at the later of the observation y1 and
       this epoch's estimate for y1 given the obsevration x1.

       If y1_eff == y1 (i.e. we are microstepping the fd_clock forward
       to correct immediately and fully an underestimate at the end of
       this epoch without breaking monotonicity), we just use 1/w1 for
       the y-ticks per x-ticks conversion rate m1 this epoch.

       Otherwise, we can't microstep the fd_clock backward while
       preserving monotonicity.  To correct an overestimate at this
       epoch, we reduce the conversion rate to approximately absorb
       recal_frac the overestimate over the coming epoch.  The reduction
       is such that, asymptotically, the resulting conversion should
       always be positive.

       See more detailed derivation above. */

    w1     = w0 + shclock->recal_alpha*(w_obs-w0);
    y1_eff = fd_long_max( y1, y0_eff + (long)(0.5 + m0*(double)dx) );
    m1     = 1. / (w1 + (shclock->recal_beta*w1)*(double)(y1_eff-y1));
    err    = 0;

  }

  return fd_clock_epoch_next( shclock, x1, y1, w1, y1_eff, m1, err );
}

long
fd_clock_step( fd_clock_t * clock,
               long         x0,
               long         y0,
               double       w ) {
  return fd_clock_epoch_next( clock->shclock, x0, y0, w, y0, 1./w, 0 );
}

char const *
fd_clock_strerror( int err ) {
  switch( err ) {
  case FD_CLOCK_SUCCESS: return "success";
  case FD_CLOCK_ERR_X:   return "x-clock not well-behaved";
  case FD_CLOCK_ERR_Y:   return "y-clock not well-behaved";
  default: break;
  }
  return "unknown";
}
