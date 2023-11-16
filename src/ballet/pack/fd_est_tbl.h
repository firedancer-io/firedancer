#ifndef HEADER_fd_src_ballet_pack_fd_est_tbl_h
#define HEADER_fd_src_ballet_pack_fd_est_tbl_h

#include "../fd_ballet_base.h"

#if FD_HAS_DOUBLE

/* This header defines a data structure for estimating the sliding-window mean
   and variance of tagged data.  It takes in real-valued input, with each value
   tagged with an opaque tag.  The data structure gives an estimated answer to
   queries of the form "what is the mean and variance of recent data with tag
   X" for a given value of X.  For best use, the tag should correspond to the
   distribution that the random variable comes from, although there's no
   specific need for this to be true, and no assumptions are made about
   normality etc.
   The answers this data structure gives are approximate because tags are
   mapped to an array of bins that is much smaller than the universe of tags
   and thus tags can alias.  This is actually desirable behavior because it
   means that if you have inserted lots of data but then query for a brand-new
   tag, the expected value of the returned data is close to the overall mean of
   all values that have been inserted. */

#define FD_EST_TBL_MAGIC (0xF17EDA2C37E57B10UL) /* F17E=FIRE,DA2C/37=DANCER,E5/7B1=ESTBL,0=V0 / FIREDANCER EST TBL V0 */

#define FD_EST_TBL_ALIGN                   (32UL)
#define FD_EST_TBL_FOOTPRINT( bin_cnt ) ( sizeof(fd_est_tbl_t) + ((bin_cnt)-1UL)*sizeof(fd_est_tbl_bin_t) )

/* Internal table bin structure used to accumulate statistics about tags that
   map to this bin index */
/* FIXME: With doubles, this struct is 32B. With floats, it is 16B, which means
   that reads and writes to it can be atomic if done carefully.  That will make
   updating the table while it's in use much easier.  On some platforms, 32B
   reads and writes will also be atomic. */
struct fd_private_est_tbl_bin {
  /* x: The numerator of the EMA of the values that have mapped to this
     bin */
  double x;
  /* x2: The numerator of the EMA of the square of values that have mapped
     to this bin */
  double x2;
  /* d: The denominator for EMA(x), paired with the numerator from above.
     */
  double d;
  double d2;
};
typedef struct fd_private_est_tbl_bin fd_est_tbl_bin_t;

/* The main data structure described in the overall header comment */
struct __attribute__((aligned(FD_EST_TBL_ALIGN))) fd_private_est_tbl {
  /* magic: set to FD_EST_TBL_MAGIC */
  ulong  magic;
  /* bin_cnt_mask: (bin_cnt_mask+1) is the number of bins in the table, a power
     of two */
  ulong  bin_cnt_mask;
  /* ema_coeff: the decay coefficient used in EMA computations. Near 1.0. */
  double ema_coeff;
  /* default_val: the value to return as mean when the query maps to a bin with
     very few values */
  double default_val;
  /* 32 byte aligned at this point */
  /* bins: the array of (bin_cnt_mask+1) bins follows.  The array size of 1 is
     just convention. */
  fd_est_tbl_bin_t bins[1];
};
typedef struct fd_private_est_tbl fd_est_tbl_t;


FD_PROTOTYPES_BEGIN
/* fd_est_tbl_{align, footprint} given the needed alignment and footprint for a
   memory region suitable to hold fd_est_tbl's state.  bin_cnt specifies the
   number of bins that the estimation table stores.  bin_cnt must be a
   power-of-two greater than 0.  Increasing the number of bins increases the
   footprint requirements but also increases the accuracy slightly (by reducing
   collisions).  fd_est_tbl_{align, footprint} return the same value as
   FD_EST_TBL_{ALIGN, FOOTPRINT}.

   fd_est_tbl_new takes ownership of the memory region pointed to by mem (which
   is assumed to be non-NULL and have the appropriate alignment and footprint)
   and formats it as a fd_est_tbl.  The estimation table will use bin_cnt bins,
   and each bin's EMA will be tuned for an a window size of history.  history
   must be positive.  The table will use a default value of default_val for the
   mean whenever a query indicates a bin has had no data.  Returns mem (which
   will be formatted for use) on success and NULL on failure (bad inputs).  The
   caller will not be joined to the region on return.

   fd_est_tbl_join joins the caller to a memory region holding the state of a
   fd_est_tbl.

   fd_est_tbl_leave leaves the current join.  Returns a pointer in the local
   address space to the memory region holding the table state.  The join should
   not be used after calling _leave.

   fd_est_tbl_delete unformats the memory region used to hold the state of an
   fd_est_tbl and returns ownership of the underlying memory region to the
   caller.  There should be no joins in the system on the fd_est_tbl.  Returns
   a pointer to the underlying memory region. */

FD_FN_CONST static inline ulong fd_est_tbl_align    ( void ) { return FD_EST_TBL_ALIGN; }
FD_FN_CONST static inline ulong fd_est_tbl_footprint( ulong bin_cnt ) {
  if( FD_UNLIKELY( !bin_cnt || !fd_ulong_is_pow2( bin_cnt )                                 ) ) return 0UL;
  if( FD_UNLIKELY(  bin_cnt > ((ULONG_MAX - sizeof(fd_est_tbl_t))/sizeof(fd_est_tbl_bin_t)) ) ) return 0UL;
  return sizeof(fd_est_tbl_t) + (bin_cnt-1UL)*sizeof(fd_est_tbl_bin_t);
}

static inline void *
fd_est_tbl_new( void * mem,
                ulong  bin_cnt,
                ulong  history,
                uint   default_val ) {
  if( FD_UNLIKELY( !bin_cnt || !fd_ulong_is_pow2( bin_cnt )                                 ) ) return NULL;
  if( FD_UNLIKELY(  bin_cnt > ((ULONG_MAX - sizeof(fd_est_tbl_t))/sizeof(fd_est_tbl_bin_t)) ) ) return NULL;
  if( FD_UNLIKELY( !history                                                                 ) ) return NULL;
  /* The largest ema_d can get is around history, and the largest the value can
     get is UINT_MAX.  Their product is then less than 2^96 approx 8*10^28,
     which is comfortably in the range of a double. */
  fd_est_tbl_t * tbl  = (fd_est_tbl_t *)mem;
  tbl->bin_cnt_mask   = bin_cnt-1UL;
  tbl->ema_coeff      = 1.0 - 1.0/(double)history;
  tbl->default_val    = default_val;

  fd_memset( tbl->bins, 0, bin_cnt*sizeof(fd_est_tbl_bin_t) );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( tbl->magic ) = FD_EST_TBL_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)tbl;
}

static inline fd_est_tbl_t *
fd_est_tbl_join  ( void         * _tbl ) {
  fd_est_tbl_t * tbl = (fd_est_tbl_t *)_tbl;
  if( FD_UNLIKELY( tbl->magic != FD_EST_TBL_MAGIC ) ) return NULL;
  return tbl;
}
static inline void         * fd_est_tbl_leave ( fd_est_tbl_t *  tbl ) { return (void         *) tbl; }
static inline void         * fd_est_tbl_delete( fd_est_tbl_t *  tbl ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( tbl->magic ) = 0UL;
  FD_COMPILER_MFENCE();
  return (void         *) tbl;
}

/* fd_est_tbl_estimate: estimate the mean and variance of the distribution from
   which data tagged with tag is drawn.  Since this function cannot return two
   doubles, if variance_out is non-NULL, it will be set to the variance.  If 0
   values have been inserted with the specified tag (or a tag that aliases to
   it), this function will return a mean of default_val and a variance of 0. */
static inline double
fd_est_tbl_estimate( fd_est_tbl_t const * tbl,
                     ulong                tag,
                     double *             variance_out ) {
  fd_est_tbl_bin_t const * bin = tbl->bins + (tag & tbl->bin_cnt_mask);
  double mean, var;
  if( FD_UNLIKELY( !(bin->d > 0.0) ) ) {
    mean = tbl->default_val;
    var  = 0.0;
  } else {
    mean = bin->x / bin->d;
    var  = (bin->d * bin->x2 - (bin->x*bin->x)) / ( bin->d * bin->d - bin->d2 );
  }
  var  = fd_double_if( var>0.0, var, 0.0 );
  if( FD_LIKELY( variance_out ) ) *variance_out = var;
  return mean;
}

/* fd_est_tbl_update: inserts a new tagged value into this data structure */
static inline void
fd_est_tbl_update( fd_est_tbl_t * tbl,
                   ulong          tag,
                   uint           value ) {
  fd_est_tbl_bin_t * bin = tbl->bins + (tag & tbl->bin_cnt_mask);
#ifdef FD_EST_TBL_ADAPTIVE
  double mean, variance;
  mean = fd_est_tbl_estimate( tbl, tag, &variance );
  double dev_sq = (value - mean)*(value - mean) / variance; /* Normalized squared deviation */
  double alpha = 0.25;
  double C = fd_double_if( dev_sq<log(DBL_MAX)/alpha, 1.0/(1.0 + exp(alpha*dev_sq)*tbl->ema_coeff), 0.0 );
#else
  double C = tbl->ema_coeff;
#endif
  bin->x  = value       + fd_double_if( C*bin->x >DBL_MIN, C*bin->x , 0.0 );
  bin->x2 = value*value + fd_double_if( C*bin->x2>DBL_MIN, C*bin->x2, 0.0 );
  bin->d  = 1.0         +   C*bin->d ; /* Can't go denormal */
  bin->d2 = 1.0         + C*C*bin->d2; /* Can't go denormal */
}

#endif /* FD_HAS_DOUBLE */

#endif /* HEADER_fd_src_ballet_pack_fd_est_tbl_h */
