#include "../fd_util.h"

/* This are uniform in [-0.5,+0.5] */

static float  fd_rng_float ( fd_rng_t * rng ) { return fd_rng_float_c ( rng ) - 0.5f; }
#if FD_HAS_DOUBLE
static double fd_rng_double( fd_rng_t * rng ) { return fd_rng_double_c( rng ) - 0.5;  }
#endif

#include <math.h>

int
main( int     argc,
      char ** argv ) {

  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# define AVG2_INT_TEST(T) do {                          \
    FD_TEST( fd_stat_avg2_##T( (T)  0, (T)0 )==(T) 0 );  \
    FD_TEST( fd_stat_avg2_##T( (T)  1, (T)2 )==(T) 1 );  \
    FD_TEST( fd_stat_avg2_##T( (T)  1, (T)0 )==(T) 0 );  \
    FD_TEST( fd_stat_avg2_##T( (T)110, (T)0 )==(T)55 );  \
  } while(0)

  AVG2_INT_TEST( schar  );
  AVG2_INT_TEST( uchar  );
  AVG2_INT_TEST( short  );
  AVG2_INT_TEST( ushort );
  AVG2_INT_TEST( int    );
  AVG2_INT_TEST( uint   );
  AVG2_INT_TEST( long   );
  AVG2_INT_TEST( ulong  );
# undef AVG2_INT_TEST


# define FILT_TEST(T,UT)                             \
  for( ulong iter=0UL; iter<1000000UL; iter++ ) {    \
    uint  r = fd_rng_uint( rng );                    \
    ulong n = (ulong)(r & 15U); r >>= 4;             \
    int   c = (int)  (r &  1U); r >>= 1;             \
    T     t = fd_rng_##T( rng );                     \
                                                     \
    T x[16];                                         \
    T y[16];                                         \
    ulong j = 0UL;                                   \
    for( ulong i=0UL; i<n; i++ ) {                   \
      T xi = (T)fd_rng_##UT( rng );                  \
      x[i] = xi;                                     \
      if( fd_##T##_abs( xi )<=(UT)t ) y[j++] = xi;   \
    }                                                \
                                                     \
    T w[16];                                         \
    T * z = c ? x : w; /* in place vs out place */   \
                                                     \
    FD_TEST( fd_stat_filter_##T( z, x, n, t )==j );  \
    if( j ) FD_TEST( !memcmp( y, z, j*sizeof(T) ) ); \
  }

  FILT_TEST( schar,   uchar   )
  FILT_TEST( short,   ushort  )
  FILT_TEST( int,     uint    )
  FILT_TEST( long,    ulong   )
  FILT_TEST( uchar,   uchar   )
  FILT_TEST( ushort,  ushort  )
  FILT_TEST( uint,    uint    )
  FILT_TEST( ulong,   ulong   )
  FILT_TEST( float,   float   )
# if FD_HAS_INT128
  FILT_TEST( int128,  uint128 )
  FILT_TEST( uint128, uint128 )
# endif
# if FD_HAS_DOUBLE
  FILT_TEST( double,  double  )
# endif

# undef FILT_TEST

  for( ulong iter=0UL; iter<1000L; iter++ ) {
    float x      [128];
    float scratch[128];
    ulong cnt   = fd_rng_ulong_roll( rng, 129UL );
    float mu    = fd_rng_float_norm( rng );
    float sigma = fd_rng_float_exp ( rng );
    for( ulong idx=0UL; idx<cnt; idx++ ) x[idx] = mu + sigma*fd_rng_float_norm( rng );

    float mu_est;
    float sigma_est;
    ulong cnt_est = fd_stat_robust_norm_fit_float( &mu_est, &sigma_est, x, cnt, scratch );
    FD_TEST( cnt_est==cnt );
    if(      FD_UNLIKELY( cnt==0UL ) ) FD_TEST( mu_est==0.f  && sigma_est==0.f );
    else if( FD_UNLIKELY( cnt==1UL ) ) FD_TEST( mu_est==x[0] && sigma_est==0.f );
    else {
      FD_TEST( fd_float_abs( mu_est    - mu    )*sqrtf((float)cnt) < 6.f*sigma );
      FD_TEST( fd_float_abs( sigma_est - sigma )*sqrtf((float)cnt) < 6.f*sigma );
    }

    for( ulong idx=0UL; idx<cnt; idx++ ) x[idx] = mu + sigma*fd_rng_float_exp( rng );
    cnt_est = fd_stat_robust_exp_fit_float( &mu_est, &sigma_est, x, cnt, scratch );
    FD_TEST( cnt_est==cnt );
    if(      FD_UNLIKELY( cnt==0UL ) ) FD_TEST( mu_est==0.f  && sigma_est==0.f );
    else if( FD_UNLIKELY( cnt==1UL ) ) FD_TEST( mu_est==x[0] && sigma_est==0.f );
    else {
      FD_TEST( fd_float_abs( mu_est    - mu    ) < 6.f*sigma );
      FD_TEST( fd_float_abs( sigma_est - sigma ) < 6.f*sigma );
    }
  }

# if FD_HAS_DOUBLE
  for( ulong iter=0UL; iter<1000L; iter++ ) {
    double x      [128];
    double scratch[128];
    ulong cnt    = fd_rng_ulong_roll( rng, 129UL );
    double mu    = fd_rng_double_norm( rng );
    double sigma = fd_rng_double_exp ( rng );
    for( ulong idx=0UL; idx<cnt; idx++ ) x[idx] = mu + sigma*fd_rng_double_norm( rng );

    double mu_est;
    double sigma_est;
    ulong cnt_est = fd_stat_robust_norm_fit_double( &mu_est, &sigma_est, x, cnt, scratch );
    FD_TEST( cnt_est==cnt );
    if(      FD_UNLIKELY( cnt==0UL ) ) FD_TEST( mu_est==0.   && sigma_est==0. );
    else if( FD_UNLIKELY( cnt==1UL ) ) FD_TEST( mu_est==x[0] && sigma_est==0. );
    else {
      FD_TEST( fd_double_abs( mu_est    - mu    )*sqrt((double)cnt) < 6.*sigma );
      FD_TEST( fd_double_abs( sigma_est - sigma )*sqrt((double)cnt) < 6.*sigma );
    }

    for( ulong idx=0UL; idx<cnt; idx++ ) x[idx] = mu + sigma*fd_rng_double_exp( rng );
    cnt_est = fd_stat_robust_exp_fit_double( &mu_est, &sigma_est, x, cnt, scratch );
    FD_TEST( cnt_est==cnt );
    if(      FD_UNLIKELY( cnt==0UL ) ) FD_TEST( mu_est==0.   && sigma_est==0. );
    else if( FD_UNLIKELY( cnt==1UL ) ) FD_TEST( mu_est==x[0] && sigma_est==0. );
    else {
      FD_TEST( fd_double_abs( mu_est    - mu    ) < 6.*sigma );
      FD_TEST( fd_double_abs( sigma_est - sigma ) < 6.*sigma );
    }
  }
# endif

  /* Note that we already have a unit tester for the sorts in the form
     of the template unit tester. */

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

