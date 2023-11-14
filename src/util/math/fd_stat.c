#include "fd_stat.h"

#define FD_STAT_IMPL( T, UT )                                     \
ulong                                                             \
fd_stat_filter_##T( T *       y,                                  \
                    T const * x,                                  \
                    ulong     n,                                  \
                    T         thresh ) { /* assumed positive */   \
  ulong j = 0UL;                                                  \
  for( ulong i=0UL; i<n; i++ ) {                                  \
    T xi = x[i];                                                  \
    y[j] = xi;                                    /* speculate */ \
    j += (ulong)(fd_##T##_abs( xi )<=(UT)thresh); /* commit */    \
  }                                                               \
  return j;                                                       \
}                                                                 \
                                                                  \
T                                                                 \
fd_stat_median_##T( T *   x,                                      \
                    ulong cnt ) {                                 \
  if( FD_UNLIKELY( !cnt ) ) return (T)0;                          \
  ulong i1 = cnt >> 1;                                            \
  T m1 = fd_sort_up_##T##_select( x, cnt, i1 )[ i1 ];             \
  if( (cnt & 1UL) ) return m1;                                    \
  ulong i0 = i1-1UL;                                              \
  T m0 = fd_sort_up_##T##_select( x, cnt, i0 )[ i0 ];             \
  return fd_stat_avg2_##T( m0, m1 );                              \
}

FD_STAT_IMPL( schar,   uchar   )
FD_STAT_IMPL( short,   ushort  )
FD_STAT_IMPL( int,     uint    )
FD_STAT_IMPL( long,    ulong   )
FD_STAT_IMPL( uchar,   uchar   )
FD_STAT_IMPL( ushort,  ushort  )
FD_STAT_IMPL( uint,    uint    )
FD_STAT_IMPL( ulong,   ulong   )
#if FD_HAS_INT128
FD_STAT_IMPL( int128,  uint128 )
FD_STAT_IMPL( uint128, uint128 )
#endif
FD_STAT_IMPL( float,   float   )
#if FD_HAS_DOUBLE
FD_STAT_IMPL( double,  double  )
#endif

#undef FD_STAT_FILTER_IMPL

ulong
fd_stat_robust_norm_fit_float( float *       opt_mu,
                               float *       opt_sigma,
                               float const * x,
                               ulong         cnt,
                               void  *       scratch ) {
  float * y = (float *)scratch;

  /* Filter out weird data points.  The threshold is such the sigma
     calculation cannot overflow.  Specifically consider an x whose
     elements are +/-thresh.  The median would end being exactly
     +/-thresh.  The absolute deviations from the median then would then
     be either 0,2*thresh.  Such that the median absolute deviation
     could be 2*thresh.  And normalizing such like a normal would be
     sigma 2*1.48... thresh <= FLT_MAX.  We use a slightly more
     conservative FLT_MAX/5 to keep things simple to explain and
     consistent with the thresh used by the robust exp fit below. */

  cnt = fd_stat_filter_float( y, x, cnt, FLT_MAX/5.f );
  if( FD_LIKELY( opt_mu || opt_sigma ) ) {

    /* Compute the median.  This is an unbiased and maximally robust
       estimator of the average in the presence of corruption.  It is
       not the most accurate estimator if the data is clean though.  If
       cnt is zero post filtering, mu (and sigma) will be zero. */

    float mu = fd_stat_median_float( y, cnt );
    if( opt_mu ) *opt_mu = mu;

    if( opt_sigma ) {
      for( ulong i=0UL; i<cnt; i++ ) y[i] = fd_float_abs( y[i] - mu );
      *opt_sigma = 1.48260221850560f*fd_stat_median_float( y, cnt ); /* 1 / inv_cdf(0.75) */
    }
  }

  return cnt;
}

ulong
fd_stat_robust_exp_fit_float( float *       opt_x0,
                              float *       opt_tau,
                              float const * x,
                              ulong         cnt,
                              void *        scratch ) {
  float * y = (float *)scratch;

  /* Filter out weird data points.  The threshold is such the x0
     and tau calculations cannot overflow.  Specifically consider an x
     whose elements are +/-thresh.  The magnitude of the median is at
     most thresh and the median absolute deviation is at most 2*thresh.
     x0 then is at most (1+2*1.44...)*thresh and tau is at most 2*2.07
     thresh.  We use a slightly more conservative FLT_MAX/5 for thresh
     to keep things simple. */

  cnt = fd_stat_filter_float( y, x, cnt, FLT_MAX/5.f );
  if( FD_LIKELY( opt_x0 || opt_tau ) ) {

    /* Compute the median and median absolute deviation from the median. */
    float med = fd_stat_median_float( y, cnt );
    for( ulong i=0UL; i<cnt; i++ ) y[i] = fd_float_abs( y[i] - med );
    float mad = fd_stat_median_float( y, cnt );

    /* Estimate the parameters from the distribution */
    if( opt_x0  ) *opt_x0  = med - mad*1.44042009041256f; /* (ln 2) / asinh(1/2) */
    if( opt_tau ) *opt_tau = mad*2.07808692123503f;       /* 1 / asinh(1/2) */

  }
  return cnt;
}

#if FD_HAS_DOUBLE /* See above for details */

ulong
fd_stat_robust_norm_fit_double( double *       opt_mu,
                                double *       opt_sigma,
                                double const * x,
                                ulong          cnt,
                                void  *        scratch ) {
  double * y = (double *)scratch;
  cnt = fd_stat_filter_double( y, x, cnt, DBL_MAX/5. );
  if( FD_LIKELY( opt_mu || opt_sigma ) ) {
    double mu = fd_stat_median_double( y, cnt );
    if( opt_mu ) *opt_mu = mu;
    if( opt_sigma ) {
      for( ulong i=0UL; i<cnt; i++ ) y[i] = fd_double_abs( y[i] - mu );
      *opt_sigma = 1.48260221850560*fd_stat_median_double( y, cnt );
    }
  }

  return cnt;
}

ulong
fd_stat_robust_exp_fit_double( double *       opt_x0,
                               double *       opt_tau,
                               double const * x,
                               ulong          cnt,
                               void *         scratch ) {
  double * y = (double *)scratch;
  cnt = fd_stat_filter_double( y, x, cnt, DBL_MAX/5. );
  if( FD_LIKELY( opt_x0 || opt_tau ) ) {
    double med = fd_stat_median_double( y, cnt );
    for( ulong i=0UL; i<cnt; i++ ) y[i] = fd_double_abs( y[i] - med );
    double mad = fd_stat_median_double( y, cnt );
    if( opt_x0  ) *opt_x0  = med - mad*1.44042009041256;
    if( opt_tau ) *opt_tau = mad*2.07808692123503;
  }
  return cnt;
}

#endif

/* ascending sorts */

#define SORT_NAME       fd_sort_up_schar
#define SORT_KEY_T      schar
#define SORT_IMPL_STYLE 2
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_short
#define SORT_KEY_T      short
#define SORT_IMPL_STYLE 2
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_int
#define SORT_KEY_T      int
#define SORT_IMPL_STYLE 2
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_long
#define SORT_KEY_T      long
#define SORT_IMPL_STYLE 2
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_uchar
#define SORT_KEY_T      uchar
#define SORT_IMPL_STYLE 2
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_ushort
#define SORT_KEY_T      ushort
#define SORT_IMPL_STYLE 2
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_uint
#define SORT_KEY_T      uint
#define SORT_IMPL_STYLE 2
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_ulong
#define SORT_KEY_T      ulong
#define SORT_IMPL_STYLE 2
#include "../tmpl/fd_sort.c"

#if FD_HAS_INT128
#define SORT_NAME       fd_sort_up_int128
#define SORT_KEY_T      int128
#define SORT_IMPL_STYLE 2
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_uint128
#define SORT_KEY_T      uint128
#define SORT_IMPL_STYLE 2
#include "../tmpl/fd_sort.c"
#endif

#define SORT_NAME       fd_sort_up_float
#define SORT_KEY_T      float
#define SORT_IMPL_STYLE 2
#include "../tmpl/fd_sort.c"

#if FD_HAS_DOUBLE
#define SORT_NAME       fd_sort_up_double
#define SORT_KEY_T      double
#define SORT_IMPL_STYLE 2
#include "../tmpl/fd_sort.c"
#endif

/* descending sorts */

#define SORT_NAME        fd_sort_dn_schar
#define SORT_KEY_T       schar
#define SORT_BEFORE(a,b) ((a)>(b))
#define SORT_IMPL_STYLE  2
#include "../tmpl/fd_sort.c"

#define SORT_NAME        fd_sort_dn_short
#define SORT_KEY_T       short
#define SORT_BEFORE(a,b) ((a)>(b))
#define SORT_IMPL_STYLE 2
#include "../tmpl/fd_sort.c"

#define SORT_NAME        fd_sort_dn_int
#define SORT_KEY_T       int
#define SORT_BEFORE(a,b) ((a)>(b))
#define SORT_IMPL_STYLE  2
#include "../tmpl/fd_sort.c"

#define SORT_NAME        fd_sort_dn_long
#define SORT_KEY_T       long
#define SORT_BEFORE(a,b) ((a)>(b))
#define SORT_IMPL_STYLE  2
#include "../tmpl/fd_sort.c"

#define SORT_NAME        fd_sort_dn_uchar
#define SORT_KEY_T       uchar
#define SORT_BEFORE(a,b) ((a)>(b))
#define SORT_IMPL_STYLE  2
#include "../tmpl/fd_sort.c"

#define SORT_NAME        fd_sort_dn_ushort
#define SORT_KEY_T       ushort
#define SORT_BEFORE(a,b) ((a)>(b))
#define SORT_IMPL_STYLE  2
#include "../tmpl/fd_sort.c"

#define SORT_NAME        fd_sort_dn_uint
#define SORT_KEY_T       uint
#define SORT_BEFORE(a,b) ((a)>(b))
#define SORT_IMPL_STYLE  2
#include "../tmpl/fd_sort.c"

#define SORT_NAME        fd_sort_dn_ulong
#define SORT_KEY_T       ulong
#define SORT_BEFORE(a,b) ((a)>(b))
#define SORT_IMPL_STYLE  2
#include "../tmpl/fd_sort.c"

#if FD_HAS_INT128
#define SORT_NAME        fd_sort_dn_int128
#define SORT_KEY_T       int128
#define SORT_BEFORE(a,b) ((a)>(b))
#define SORT_IMPL_STYLE  2
#include "../tmpl/fd_sort.c"

#define SORT_NAME        fd_sort_dn_uint128
#define SORT_KEY_T       uint128
#define SORT_BEFORE(a,b) ((a)>(b))
#define SORT_IMPL_STYLE  2
#include "../tmpl/fd_sort.c"
#endif

#define SORT_NAME        fd_sort_dn_float
#define SORT_KEY_T       float
#define SORT_BEFORE(a,b) ((a)>(b))
#define SORT_IMPL_STYLE  2
#include "../tmpl/fd_sort.c"

#if FD_HAS_DOUBLE
#define SORT_NAME        fd_sort_dn_double
#define SORT_KEY_T       double
#define SORT_BEFORE(a,b) ((a)>(b))
#define SORT_IMPL_STYLE  2
#include "../tmpl/fd_sort.c"
#endif

