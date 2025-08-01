#ifndef HEADER_fd_src_util_hist_fd_histf_h
#define HEADER_fd_src_util_hist_fd_histf_h

/* Simple fast fixed-size exponential histograms.  Histograms are
   bucketed exponentially up to a maximum value, with an overflow bucket
   for any other measurements. */

#include <math.h> /* FIXME: HMMM */
#include "../log/fd_log.h"
#if FD_HAS_AVX
#include "../simd/fd_avx.h"
#endif

#define FD_HISTF_BUCKET_CNT 16UL

#define FD_HISTF_ALIGN      (32UL)
#define FD_HISTF_FOOTPRINT  (FD_ULONG_ALIGN_UP( FD_HISTF_BUCKET_CNT*sizeof(ulong)+(FD_HISTF_BUCKET_CNT+1UL)*sizeof(long), FD_HISTF_ALIGN ))
/* Static assertion FOOTPRINT==sizeof in test */

struct __attribute__((aligned(FD_HISTF_ALIGN))) fd_histf_private {
  ulong counts[ FD_HISTF_BUCKET_CNT ];
  /* A value x belongs to bucket i if
     left_edge[i] <= x - 2^63 < left_edge[i+1].

     For AVX2, there's no unsiged comparison instruction.  We follow
     what wv_gt does and implement it by subtracting 2^63 from each
     operand.  Rather than perform the subtraction at each comparison,
     we pre-subtract here. */
  long  left_edge[ FD_HISTF_BUCKET_CNT+1 ];
  ulong sum; /* the sum of all the samples, useful for computing mean */
};

typedef struct fd_histf_private fd_histf_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong fd_histf_align    ( void ) { return FD_HISTF_ALIGN;     }
FD_FN_CONST static inline ulong fd_histf_footprint( void ) { return FD_HISTF_FOOTPRINT; }

/* fd_histf_new takes ownership of the memory region pointed to by mem
   (which is assumed to be non-NULL with the appropriate alignment and
   footprint) and formats it as a fd_hist.  The histogram will be
   initialized with buckets roughly exponentially spaced between
   min_value and max_value.  min_value must be > 0. Returns mem (which
   will be formatted for use).

   Every histogram has special buckets for underflow values (strictly
   less than min_val) and overflow values (larger than or equal to the
   max_value).

      [ 0, min_value )
      [ min_value,             approx. min_value * z   )
      [ approx. min_value * z, approx. min_value * z^2 )
      ...
      [ approx. min_value * z^13, max_value )
      [ max_value, inf )

   z is chosen so that max_value is approximately min_value * z^14 The
   approximations come from the fact that all bucket edges are integers,
   and no bucket is empty.

   If max_value < min_value+14, then max_value will be increased to
   min_value+14 so that no buckets are empty.  Note that this histogram
   contains strictly more information than what was requested, so an
   end-user could postprocess and reduce the number of bins again
   without losing any information.

   For example, if min_value is 1 and max_value is 100, the buckets
   will be

       0: [  0,   1)
       1: [  1,   2)
       2: [  2,   3)
       3: [  3,   4)
       4: [  4,   5)
       5: [  5,   7)
       6: [  7,   9)
       7: [  9,  12)
       8: [ 12,  16)
       9: [ 16,  22)
      10: [ 22,  30)
      11: [ 30,  41)
      12: [ 41,  55)
      13: [ 55,  74)
      14: [ 74, 100)
      15: [100, inf) */

static inline void *
fd_histf_new( void * mem,
              ulong  min_value,
              ulong  max_value ) {
  if( FD_UNLIKELY( max_value<=min_value ) ) return NULL;

  min_value = fd_ulong_max( min_value, 1UL );
  max_value = fd_ulong_max( max_value, min_value + FD_HISTF_BUCKET_CNT - 2UL );

  fd_histf_t * hist = (fd_histf_t*)mem;
  fd_memset( hist->counts, 0, FD_HISTF_BUCKET_CNT*sizeof(ulong) );
  hist->sum = 0UL;
  ulong left_edge[ FD_HISTF_BUCKET_CNT ]; /* without the -2^63 shift */
  left_edge[ 0 ] = 0;
  left_edge[ 1 ] = min_value;
  for( ulong i=2UL; i<(FD_HISTF_BUCKET_CNT-1UL); i++ ) {
#if FD_HAS_DOUBLE
    ulong le = (ulong)(0.5  + (double)left_edge[ i-1UL ] * pow ( (double)max_value / (double)left_edge[ i-1UL ], 1.0 /(double)(FD_HISTF_BUCKET_CNT - i) ) );
#else
    ulong le = (ulong)(0.5f + (float )left_edge[ i-1UL ] * powf( (float )max_value / (float )left_edge[ i-1UL ], 1.0f/(float )(FD_HISTF_BUCKET_CNT - i) ) );
#endif
    le = fd_ulong_max( le, left_edge[ i-1UL ] + 1UL ); /* Make sure bucket is not empty */
    left_edge[ i ] = le;
  }
  left_edge[ FD_HISTF_BUCKET_CNT - 1UL ] = max_value;

  for( ulong i=0UL; i<FD_HISTF_BUCKET_CNT; i++ ) hist->left_edge[ i ] = (long)(left_edge[ i ] - (1UL<<63));
  hist->left_edge[ FD_HISTF_BUCKET_CNT ] = LONG_MAX;

  return (void*)hist;
}

static inline fd_histf_t * fd_histf_join  ( void       * _hist ) { return (fd_histf_t *)_hist; }
static inline void       * fd_histf_leave ( fd_histf_t * _hist ) { return (void       *)_hist; }
static inline void       * fd_histf_delete( void       * _hist ) { return (void       *)_hist; }

/* Return the number of buckets in the histogram, including the overflow
   bucket. */
FD_FN_PURE static inline ulong fd_histf_bucket_cnt( fd_histf_t * hist ) { (void)hist; return FD_HISTF_BUCKET_CNT; }

/* Add a sample to the histogram.  If the sample is larger than or equal
   to the max_value it will be added to a special overflow bucket. */
static inline void
fd_histf_sample( fd_histf_t * hist,
                 ulong        value ) {
  hist->sum += value;
  long shifted_v = (long)(value - (1UL<<63));
#if FD_HAS_AVX
  wl_t x = wl_bcast( shifted_v );
  /* !(x-2^63 < left_edge[i]) & (x-2^63 < left_edge[i+1])  <=>
     left_edge[i] <= x-2^63 < left_edge[i+1] */
  wc_t select0 = wc_andnot( wl_lt( x, wl_ld ( hist->left_edge      ) ),
                            wl_lt( x, wl_ldu( hist->left_edge+ 1UL ) ) );
  wc_t select1 = wc_andnot( wl_lt( x, wl_ld ( hist->left_edge+ 4UL ) ),
                            wl_lt( x, wl_ldu( hist->left_edge+ 5UL ) ) );
  wc_t select2 = wc_andnot( wl_lt( x, wl_ld ( hist->left_edge+ 8UL ) ),
                            wl_lt( x, wl_ldu( hist->left_edge+ 9UL ) ) );
  wc_t select3 = wc_andnot( wl_lt( x, wl_ld ( hist->left_edge+12UL ) ),
                            wl_lt( x, wl_ldu( hist->left_edge+13UL ) ) );
  /* In exactly one of these, we have a -1 (aka ULONG_MAX).  We'll
     subtract that from the counts, effectively adding 1. */
  wv_st( hist->counts,       wv_sub( wv_ld( hist->counts      ), wc_to_wv_raw( select0 ) ) );
  wv_st( hist->counts+ 4UL,  wv_sub( wv_ld( hist->counts+ 4UL ), wc_to_wv_raw( select1 ) ) );
  wv_st( hist->counts+ 8UL,  wv_sub( wv_ld( hist->counts+ 8UL ), wc_to_wv_raw( select2 ) ) );
  wv_st( hist->counts+12UL,  wv_sub( wv_ld( hist->counts+12UL ), wc_to_wv_raw( select3 ) ) );
#else
  for( ulong i=0UL; i<16UL; i++ ) hist->counts[ i ] += (ulong)( (hist->left_edge[ i ] <= shifted_v) & (shifted_v < hist->left_edge[ i+1UL ]) );
#endif
}

/* fd_histf_cnt gets the count of samples in a particular bucket of the
   histogram.

   fd_histf_{left,right} get the sample values that map to bucket b,
   with a half-open interval [left, right).

   fd_histf_sum gets the sum of all samples that have been added.  I.e.
   fd_histf_sum() / sum(fd_histf_cnt(j) for j in [0, 16)) is the average
   sample value.

   For these functions, b, the bucket index is in [0, 16). */
FD_FN_PURE static inline ulong fd_histf_cnt  ( fd_histf_t const * hist, ulong b ) { return        hist->counts   [ b     ];           }
FD_FN_PURE static inline ulong fd_histf_left ( fd_histf_t const * hist, ulong b ) { return (ulong)hist->left_edge[ b     ]+(1UL<<63); }
FD_FN_PURE static inline ulong fd_histf_right( fd_histf_t const * hist, ulong b ) { return (ulong)hist->left_edge[ b+1UL ]+(1UL<<63); }
FD_FN_PURE static inline ulong fd_histf_sum  ( fd_histf_t const * hist          ) { return        hist->sum;                          }

/* fd_histf_percentile computes a percentile estimate.  Note that for
   tail-end percentiles, its possible that samples will have landed in
   the overflow/underflow bucket.  Since these are "catch-all" buckets,
   we don't know how their samples are distributed.  For the underflow
   bucket, since its bounds are known a linear interpolation is used to
   estimate percentile.  For the overflow bucket, its bounds are
   unknown, so the sentinel is returned */
FD_FN_PURE static inline ulong
fd_histf_percentile( fd_histf_t const * hist, uchar percentile, ulong sentinel ) {
   if( FD_UNLIKELY( percentile > 100 ) ) FD_LOG_ERR(( "fd_histf_percentile: percentile must be in [0, 100]. got %u", percentile ));

  ulong total_sample_cnt = 0UL;
  for( ulong b=0UL; b<FD_HISTF_BUCKET_CNT; b++ )  total_sample_cnt += fd_histf_cnt( hist, b );
  if( FD_UNLIKELY( !total_sample_cnt ) ) return sentinel;

#define MAP(x, in_min, in_max, out_min, out_max) \
    ((in_min == in_max) ? ((out_min + out_max) / 2) : (((x) - (in_min)) * ((out_max) - (out_min)) / ((in_max) - (in_min)) + (out_min)))

  ulong rank = MAP((ulong)percentile, 0UL, 100UL, 0UL, total_sample_cnt-1UL);
  ulong sum  = 0UL;

  for( ulong b=0UL; b<FD_HISTF_BUCKET_CNT; b++ ) {
    ulong count = fd_histf_cnt  ( hist, b );
    sum += count;
    if( sum > rank ) {
      ulong left  = fd_histf_left ( hist, b );
      ulong right = fd_histf_right( hist, b );
      ulong prev  = sum - count; /* the number of samples in previous buckets */

      if( FD_UNLIKELY( b==0 ) ) {
         /* for the underflow bucket, use linear interpolation */
         return MAP(rank - prev, 0UL, count-1UL, left, right);
      } else if( FD_UNLIKELY( b==(FD_HISTF_BUCKET_CNT - 1UL) )) {
         /* for the overflow bucket, return sentinel */
         return sentinel;
      } else {
         /* max_value is the right value for the bucket before the
            overflow bucket */
         ulong max_value = fd_histf_right( hist, FD_HISTF_BUCKET_CNT - 2UL );

         /* interpolate using the same equation used to construct bucket
            sizes */
#if FD_HAS_DOUBLE
         return (ulong)(0.5  + (double)left * pow ( (double)max_value / (double)left, MAP((double)(rank - prev),  0.0, (double)(count-1UL),  0.0,  1.0)/(double)(FD_HISTF_BUCKET_CNT - b - 1UL) ) );
#else
         return (ulong)(0.5f + (float )left * powf( (float )max_value / (float )left, MAP((float )(rank - prev), 0.0f, (float )(count-1UL), 0.0f, 1.0f)/(float )(FD_HISTF_BUCKET_CNT - b - 1UL) ) );
#endif
      }
    }
  }

#undef MAP

  FD_LOG_ERR(( "unreachable" ));
}

/* fd_histf_subtract subtracts other_hist from hist and stores the
   resulting histogram in hist.  In order to coherently subtract two
   histograms, the sample history of other_hist must be a prefix to the
   sample history of hist.  This effectively "erases" all the samples
   from hist that were taken at or before the last sample in other_hist. */
static inline void
fd_histf_subtract( fd_histf_t const * hist, fd_histf_t const * prefix_hist, fd_histf_t * out ) {
   out->sum = hist->sum - prefix_hist->sum;
   for( ulong b=0UL; b<FD_HISTF_BUCKET_CNT; b++ ) out->counts[ b ]    = hist->counts[ b ] - prefix_hist->counts[ b ];
   for( ulong b=0UL; b<FD_HISTF_BUCKET_CNT; b++ ) out->left_edge[ b ] = hist->left_edge[ b ];
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_hist_fd_histf_h */
