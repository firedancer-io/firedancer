#ifndef HEADER_fd_src_util_hist_fd_hist_h
#define HEADER_fd_src_util_hist_fd_hist_h

/* Simple fast linear histograms.  Histograms are evenly bucketed up to
   a maximum value, with an overflow bucket for any other measurements. */

#include "../bits/fd_bits.h"

#define FD_HIST_ALIGN (8UL)
#define FD_HIST_FOOTPRINT( bucket_cnt )                               \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT, \
    FD_HIST_ALIGN, sizeof(struct fd_hist_private) ),                  \
    8UL,           (bucket_cnt) * sizeof(ulong) ),                    \
    FD_HIST_ALIGN )

struct __attribute__((aligned(8UL))) fd_hist_private {
  ulong shift;
  ulong max_value;
  ulong buckets[];
};

typedef struct fd_hist_private fd_hist_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong fd_hist_align    ( void             ) { return FD_HIST_ALIGN; }
FD_FN_CONST static inline ulong fd_hist_footprint( ulong bucket_cnt ) { return FD_HIST_FOOTPRINT( bucket_cnt ); }

/* fd_hist_new takes ownership of the memory region pointed to by mem
   (which is assumed to be non-NULL with the appropriate alignment and
   footprint) and formats it as a fd_hist.  The histogram will be
   initialized with the given number of buckets.  Returns mem (which
   will be formatted for use).
   
   Every histogram has one special bucket for overflow values (larger
   than or equal to the max_value).  The bucket_cnt must include this
   bucket, so it should always be more than one.  Buckets will be sized
   like,
   
      [ 0, max_value/(bucket_cnt-1)) )
      [ max_value/(bucket_cnt-1), 2*max_value/(bucket_cnt-1)) )
      ...
      [ (bucket_cnt-2)*max_value/(bucket_cnt-1), max_value ) )
      [ overflow ]

    For example, if max_value is 12 and bucket_cnt is 4, the buckets
    will be
      
      [0, 4)
      [4, 8)
      [8, 12)
      [overflow]

   Since one of the buckets is reserved for overflow, and the range of
   values we are storing in the remaining buckets is [0, max_value)
   max_value must be an integer power of two multiple of (bucket_cnt-1). */
static inline void *
fd_hist_new( void * mem,
             ulong  bucket_cnt,
             ulong  max_value ) {
  if( FD_UNLIKELY( bucket_cnt<2 ) ) return NULL;
  if( FD_UNLIKELY( max_value<bucket_cnt-1 ) ) return NULL;
  if( FD_UNLIKELY( max_value % (bucket_cnt-1) ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_pow2( max_value / (bucket_cnt-1) ) ) ) return NULL;

  fd_hist_t * hist = (fd_hist_t*)mem;
  hist->max_value = max_value;
  hist->shift     = (ulong)fd_ulong_find_msb( max_value / (bucket_cnt-1) );
  fd_memset( hist->buckets, 0, bucket_cnt * sizeof(ulong) );
  return (void*)hist;
}

static inline fd_hist_t * fd_hist_join  ( void      * _hist ) { return (fd_hist_t *)_hist; }
static inline void      * fd_hist_leave ( fd_hist_t * _hist ) { return (void      *)_hist; }
static inline void      * fd_hist_delete( void      * _hist ) { return (void      *)_hist; }

/* Return the number of buckets in the histogram, including the overflow
   bucket. */
FD_FN_PURE static inline ulong
fd_hist_bucket_cnt( fd_hist_t * hist ) { return 1UL << hist->shift; }

/* Add a sample to the histogram.  If the sample is larger than or equal
   to the max_value it will be added to a special overflow bucket. */
static inline void
fd_hist_sample( fd_hist_t * hist,
                ulong       _value ) {
  ulong value = fd_ulong_min( _value, hist->max_value );
  ulong * buckets = (ulong *)hist->buckets;
  buckets[ value>>hist->shift ]++;
}

/* Get the count of samples in a particular bucket of the historgram. */
FD_FN_PURE static inline ulong
fd_hist_cnt( fd_hist_t * hist,
             ulong       bucket ) {
  return hist->buckets[ bucket ];
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_hist_fd_hist_h */
