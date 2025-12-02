#ifndef HEADER_fd_src_flamenco_gossip_fd_bloom_h
#define HEADER_fd_src_flamenco_gossip_fd_bloom_h

#include "../../util/rng/fd_rng.h"

#include <math.h>

#define FD_BLOOM_ALIGN     (64UL)
#define FD_BLOOM_FOOTPRINT (128UL)

#define FD_BLOOM_MAGIC (0xF17EDA2CE8100800) /* FIREDANCE BLOOM V0 */

struct __attribute__((aligned(FD_BLOOM_ALIGN))) fd_bloom_private {
  ulong * keys;
  ulong   keys_len;  /* ulong count */

  ulong * bits;
  ulong   bits_len;  /* bit count */

  ulong   hash_seed;
  fd_rng_t * rng;

  ulong   max_bits;
  double  false_positive_rate;

  ulong magic; /* ==FD_BLOOM_MAGIC */
};

typedef struct fd_bloom_private fd_bloom_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_bloom_align( void );

FD_FN_CONST ulong
fd_bloom_footprint( double false_positive_rate,
                    ulong  max_bits );

void *
fd_bloom_new( void *     shmem,
              fd_rng_t * rng,
              double     false_positive_rate,
              ulong      max_bits );

fd_bloom_t *
fd_bloom_join( void * shbloom );

void
fd_bloom_initialize( fd_bloom_t * bloom,
                     ulong        num_items );

void
fd_bloom_insert( fd_bloom_t *  bloom,
                 uchar const * key,
                 ulong         key_sz );

int
fd_bloom_contains( fd_bloom_t *  bloom,
                   uchar const * key,
                   ulong         key_sz );

int
fd_bloom_init_inplace( ulong *      keys,
                       ulong *      bits,
                       ulong        keys_len,
                       ulong        bits_len,
                       ulong        hash_seed,
                       fd_rng_t *   rng,
                       double       false_positive_rate,
                       fd_bloom_t * out_bloom );

static inline double
fd_bloom_max_items( double max_bits,
                    double num_keys,
                    double false_positive_rate ) {
  return ceil( max_bits / ( -num_keys / log( 1.0 - exp( log( false_positive_rate ) / num_keys ) )));
}

static inline ulong
fd_bloom_num_bits( double num_items,
                   double false_positive_rate,
                   double max_bits ) {
  double num_bits = ceil( ((double)num_items * log( false_positive_rate )) / log( 1.0 / pow( 2.0, log( 2.0 ) )));
  return (ulong)fmax( 1.0, fmin( max_bits, num_bits ) );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_gossip_fd_bloom_h */
