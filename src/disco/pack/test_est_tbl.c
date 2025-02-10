#include <math.h>
#include "fd_est_tbl.h"

#define TBL_SZ 8UL
static uchar scratch[ FD_EST_TBL_FOOTPRINT( TBL_SZ ) ] __attribute__((aligned(FD_EST_TBL_ALIGN)));

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_TEST( fd_est_tbl_align( ) == FD_EST_TBL_ALIGN );
  FD_TEST( fd_est_tbl_footprint( TBL_SZ ) == sizeof(scratch) );

  const uint default_val = 1234;
  void *         _tbl = fd_est_tbl_new( scratch, TBL_SZ, 1000UL, default_val ); FD_TEST( _tbl );
  fd_est_tbl_t *  tbl = fd_est_tbl_join( _tbl );                                FD_TEST(  tbl );
  double out_var = 1.0;
  FD_LOG_NOTICE(( "testing empty query gives default value" )); /* in bin 0 */
  FD_TEST( fd_est_tbl_estimate( tbl, 0UL, &out_var ) == default_val );
  FD_TEST( out_var == 0.0 );
  for( uint i=0U; i<9U; i++ ) {
    fd_est_tbl_update( tbl, 0UL, i );
    out_var = 1.0;
    FD_TEST( fd_est_tbl_estimate( tbl, 0UL, &out_var ) < 9.0 );
  }
  FD_TEST( fd_est_tbl_estimate( tbl, 0UL, &out_var ) < 5.0 );

  FD_LOG_NOTICE(( "testing single entry normal distribution" )); /* in bin 1 */
  for( ulong i=0UL; i<2000UL; i++ ) {
    /* Distribution is N(mu=1000, sigma=100) */
    double val = 1000.5 + 100.0*fd_rng_double_norm( rng );
    fd_est_tbl_update( tbl, 1UL, (uint)val );
  }
  double mean = fd_est_tbl_estimate( tbl, 1UL, &out_var );
  /* It's like we have 1000 samples, so the sample mean has variance
     1/sqrt(1000) that of the distribution mean */
  double stdev_mean = 1.0 / sqrt( 1000.0 );
  mean -= 1000.0;
  FD_LOG_NOTICE(( "var=%f", out_var ));
  out_var *= 1.0/100.0;
  out_var *= 1.0/100.0;
  FD_TEST( (-6.0*100.0*stdev_mean < mean) & (mean < 6.0*100.0*stdev_mean) );
  FD_TEST( (0.9 < out_var) & (out_var < 1.1) );
  FD_LOG_NOTICE(( "pass. mean=%f, var=%f", mean, out_var ));

  FD_LOG_NOTICE(( "testing exponential distribution" )); /* in bin 2 */
  for( ulong i=0UL; i<6000UL; i++ ) {
    fd_est_tbl_update( tbl, 2UL, (uint)( 0.5 + 500.0*fd_rng_double_exp( rng ) ) );
  }
  /* Distribution has mean=500, variance=500^2. Sample mean is approximately
     N(mu=500, sigma=500/sqrt(1000)).  Then (sample mean)/500 is distributed
     N(mu=1, sigma=1/sqrt(1000)) */
  mean = fd_est_tbl_estimate( tbl, 2UL, &out_var );
  mean    *= (1.0/500.0);
  out_var *= (1.0/500.0);
  out_var *= (1.0/500.0);
  FD_TEST( (1.0-6.0*stdev_mean < mean) & (mean < 1.0+6.0*stdev_mean) );
  FD_TEST( (0.9 < out_var) & (out_var < 1.1) );
  FD_LOG_NOTICE(( "pass. mean=%f, var=%f", mean, out_var ));

  FD_LOG_NOTICE(( "testing mixed distributions" )); /* in bins 3-7 */
  /* Let:
       X1 ~ Normal( mean=60, std=10 )
       X2 ~ Normal( mean=200, std=30 )
       X3 ~ Uniform( {70, 80} )
     In bin j (for j in [3,7]), j/12 chance of drawing from X1, j^2/144 chance
     of drawing from X2, and 1-j/12-j^2/144 chance of drawing from X3. */
  for( ulong i=0UL; i<500000UL; i++ ) {
    ulong bin = 3UL+fd_rng_uint_roll( rng, 5U );
    ulong distr = fd_rng_uint_roll( rng, 144U );
    uint val = 0;
    if( distr<12*bin ) {
      /* P(negative) is 1e-9, so prob that none are negative is 0.9995 */
      val =  (uint)(60.5 + 10*fd_rng_double_norm( rng ));
    } else if ( distr-12*bin < bin*bin ) {
      val = (uint)(200.0 + 30.0*fd_rng_double_norm( rng ));
    } else {
      val = 70U + 10U*fd_rng_uint_roll( rng, 2U );
    }

    fd_est_tbl_update( tbl, bin, val );
  }
  for( ulong j=3UL; j<=7UL; j++ ) {
    double p_x1 = (double)j/12.0;
    double p_x2 = (double)(j*j)/144.0;
    double p_x3 = 1.0 - p_x1 - p_x2;
    double analytic_mean = p_x1*60.0 + p_x2*200.0 + p_x3*75.0;
    double analytic_var  = p_x1*3700.0 + p_x2*40900.0 + p_x3*5650.0 - analytic_mean*analytic_mean;
    double m = fd_est_tbl_estimate( tbl, j, &out_var );

    FD_LOG_NOTICE(( "j=%lu. mean=%f (analytic=%f); variance=%f (analytic=%f)", j, m, analytic_mean, out_var, analytic_var ));
    FD_TEST( ((-6.0*stdev_mean*sqrt(analytic_var)) < (m-analytic_mean)) );
    FD_TEST( ((m-analytic_mean) < ( 6.0*stdev_mean*sqrt(analytic_var))) );
    FD_TEST( -0.15<(out_var-analytic_var)/analytic_var );
    FD_TEST( (out_var-analytic_var)/analytic_var<0.15 );
  }


  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

