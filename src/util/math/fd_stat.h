#ifndef HEADER_fd_src_util_math_fd_stat_h
#define HEADER_fd_src_util_math_fd_stat_h

#include "../bits/fd_bits.h"

FD_PROTOTYPES_BEGIN

/* fd_stat_avg2_T computes the average of two numbers of type T without
   risk of intermediate overflow.  For integer types, the value is
   computed in a round toward negative infinity sense.  For floating
   point types, assuming the CPU good floating point handling and the
   floating point rounding mode has not been mucked with, the average is
   computed in a round to nearest even sense. */

static inline schar   fd_stat_avg2_schar  ( schar   x, schar   y ) { return (schar )(((long )x + (long )y) >> 1);   }
static inline short   fd_stat_avg2_short  ( short   x, short   y ) { return (short )(((long )x + (long )y) >> 1);   }
static inline int     fd_stat_avg2_int    ( int     x, int     y ) { return (int   ) ((long )x + (long )y) >> 1;    }
static inline uchar   fd_stat_avg2_uchar  ( uchar   x, uchar   y ) { return (uchar )(((ulong)x + (ulong)y) >> 1);   }
static inline ushort  fd_stat_avg2_ushort ( ushort  x, ushort  y ) { return (ushort)(((ulong)x + (ulong)y) >> 1);   }
static inline uint    fd_stat_avg2_uint   ( uint    x, uint    y ) { return (uint  ) ((ulong)x + (ulong)y) >> 1;    }
static inline long    fd_stat_avg2_long   ( long    x, long    y ) { return (x>>1) + (y>>1) + (x & y & 1L );        }
static inline ulong   fd_stat_avg2_ulong  ( ulong   x, ulong   y ) { return (x>>1) + (y>>1) + (x & y & 1UL);        }
#if FD_HAS_INT128
static inline int128  fd_stat_avg2_int128 ( int128  x, int128  y ) { return (x>>1) + (y>>1) + (x & y & (int128) 1); }
static inline uint128 fd_stat_avg2_uint128( uint128 x, uint128 y ) { return (x>>1) + (y>>1) + (x & y & (uint128)1); }
#endif
static inline float   fd_stat_avg2_float  ( float   x, float   y ) { return 0.5f*x + 0.5f*y;                        }
#if FD_HAS_DOUBLE
static inline double  fd_stat_avg2_double ( double  x, double  y ) { return 0.5*x + 0.5*y;                          }
#endif

/* fd_stat_filter_float computes y = x( |x| <= thresh ) where x is an
   array of cnt floats.  thresh is assumed to be non-negative and finite
   (UB if not).  |x| will be computed by fd_float_abs.  Returns the
   number of elements found (will be in [0,cnt]).  NaN elements of x
   will be filtered out.  In place operation is fine.  If running out of
   place, x and y should not overlap.  Uses stream compaction for
   branchless implementation (high and predictable performance
   regardless of the density or distribution of values to filter); as
   such y must have room for up to n elements.

   fd_stat_median_float computes the median of the elements of x.
   Undefined behavior any x is NaN.  Returns 0 if cnt is zero.  The
   current implementation is O(cnt) (and not the fastest algorithmically
   possible when cnt is even ... should use a quick multiselect instead
   of two quick selects).

   Similarly for the other types.  For even cnt and integral types, the
   returned median will be rounded toward negative infinity. */

#define FD_STAT_DECL( T )               \
ulong                                   \
fd_stat_filter_##T( T *       y,        \
                    T const * x,        \
                    ulong     cnt,      \
                    T         thresh ); \
                                        \
T                                       \
fd_stat_median_##T( T *   x,            \
                    ulong cnt )

FD_STAT_DECL( schar   );
FD_STAT_DECL( short   );
FD_STAT_DECL( int     );
FD_STAT_DECL( long    );
FD_STAT_DECL( uchar   );
FD_STAT_DECL( ushort  );
FD_STAT_DECL( uint    );
FD_STAT_DECL( ulong   );
#if FD_HAS_INT128
FD_STAT_DECL( int128  );
FD_STAT_DECL( uint128 );
#endif
FD_STAT_DECL( float   );
#if FD_HAS_DOUBLE
FD_STAT_DECL( double  );
#endif

#undef FD_STAT_DECL

/* fd_stat_robust_norm_fit_float estimates the mean and rms of the
   cnt samples of x, indexed [0,cnt), assuming that most x are IID
   samples drawn from a normal distribution and the remainder are
   potentially arbitrarily corrupted.  The method used here tries to
   optimize for robustness against data corruption as opposed to the
   more typical maximum likelihood (which is more accurate for clean
   data but much less robust to outliers corrupting the estimates).

   Only samples with magnitude less than FLT_MAX/5 will be included in
   this estimate (i.e. NaN, inf and/or inordinately large sample values
   will be ignored).  Returns the number of data points used to form
   the estimate.  On return, if opt_mu is non-NULL, *opt_mu will have
   the mean estimate (this is guaranteed to be a finite representation)
   and, if opt_sigma is non-NULL, *opt_sigma will have the rms estimate
   (this is guaranteed to be a finite representation).  For pathological
   cases, if there were no valid samples, mu=sigma=0 and, if the
   majority of the samples are equal, mu=mode,sigma=0.

   scratch points to a float aligned region with space for up to cnt
   float.  It will be clobbered on return.  It is fine to pass x as
   scratch if destructive operation is fine. */

ulong
fd_stat_robust_norm_fit_float( float *       opt_mu,
                               float *       opt_sigma,
                               float const * x,
                               ulong         cnt,
                               void  *       scratch );

/* fd_stat_robust_exp_fit_float is same as the above with a shifted
   exponential distribution.  x0 is the estimated minimum of this
   distribution and tau is the estimated decay length.  For pathological
   cases, if there were no valid samples, x0=tau=0 and, if the majority
   of the samples are equal, x0=mode,tau=0. */

ulong
fd_stat_robust_exp_fit_float( float *       opt_x0,
                              float *       opt_tau,
                              float const * x,
                              ulong         cnt,
                              void  *       scratch );

/* These are double precision versions of the above.  (The ignored
   threshold is accordingly increased to DBL_MAX/5.) */

#if FD_HAS_DOUBLE
ulong
fd_stat_robust_norm_fit_double( double *       opt_mu,
                                double *       opt_sigma,
                                double const * x,
                                ulong          cnt,
                                void  *        scratch );

ulong
fd_stat_robust_exp_fit_double( double *       opt_x0,
                               double *       opt_tau,
                               double const * x,
                               ulong          cnt,
                               void  *        scratch );
#endif

/* Declare ascending and descending sorts for all the primitive types.
   For floating point sorts, the resulting order if NaNs are present is
   undefined (as they are not well ordered with anything).  If there is
   a mixture of signed zeros and unsigned zeros, their exact order in
   the region of zeros will be undefined (as they are not well ordered
   amongst themselves).  In short, don't pass arrays with NaN and ignore
   the sign of zero when using floating point sorts. */

/* ascending */

#define SORT_NAME       fd_sort_up_schar
#define SORT_KEY_T      schar
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_short
#define SORT_KEY_T      short
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_int
#define SORT_KEY_T      int
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_long
#define SORT_KEY_T      long
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_uchar
#define SORT_KEY_T      uchar
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_ushort
#define SORT_KEY_T      ushort
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_uint
#define SORT_KEY_T      uint
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_ulong
#define SORT_KEY_T      ulong
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#if FD_HAS_INT128
#define SORT_NAME       fd_sort_up_int128
#define SORT_KEY_T      int128
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_up_uint128
#define SORT_KEY_T      uint128
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"
#endif

#define SORT_NAME       fd_sort_up_float
#define SORT_KEY_T      float
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#if FD_HAS_DOUBLE
#define SORT_NAME       fd_sort_up_double
#define SORT_KEY_T      double
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"
#endif

/* descending */

#define SORT_NAME       fd_sort_dn_schar
#define SORT_KEY_T      schar
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_dn_short
#define SORT_KEY_T      short
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_dn_int
#define SORT_KEY_T      int
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_dn_long
#define SORT_KEY_T      long
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_dn_uchar
#define SORT_KEY_T      uchar
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_dn_ushort
#define SORT_KEY_T      ushort
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_dn_uint
#define SORT_KEY_T      uint
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_dn_ulong
#define SORT_KEY_T      ulong
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#if FD_HAS_INT128
#define SORT_NAME       fd_sort_dn_int128
#define SORT_KEY_T      int128
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#define SORT_NAME       fd_sort_dn_uint128
#define SORT_KEY_T      uint128
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"
#endif

#define SORT_NAME       fd_sort_dn_float
#define SORT_KEY_T      float
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"

#if FD_HAS_DOUBLE
#define SORT_NAME       fd_sort_dn_double
#define SORT_KEY_T      double
#define SORT_IMPL_STYLE 1
#include "../tmpl/fd_sort.c"
#endif

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_math_fd_stat_h */

