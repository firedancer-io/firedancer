#include "../types/fd_types.h"

/* Number of bloom filter bits in a chunk */
#define FD_BLOOM_NUM_BITS (512U*8U) /* 0.5 Kbyte, within MTU bounds */
/* Max number of chunks to form a counting bloom filter */
#define FD_BLOOM_MAX_CHUNKS 32U
/* Max number of bloom filter keys */
#define FD_BLOOM_MAX_KEYS 32U


typedef struct {
    ulong keys[FD_BLOOM_MAX_KEYS];
    ulong nkeys;

    uint count_filter_chunks[FD_BLOOM_MAX_CHUNKS][FD_BLOOM_NUM_BITS];
    ulong nchunks;
    uint nmaskbits; /* should be log(npackets) */
} fd_gossip_counting_bloom_t;

/* Convert a hash to a bloom filter bit position
  https://github.com/anza-xyz/agave/blob/v2.1.7/bloom/src/bloom.rs#L136 */
static ulong
fd_bloom_pos( fd_hash_t const * hash, ulong key, ulong nbits) {
  for ( ulong i = 0; i < 32U; ++i) {
      key ^= (ulong)(hash->uc[i]);
      key *= 1099511628211UL; // FNV prime
  }
  return key % nbits;
}

/* Get the bloom filter chunk id for a given key */
FD_FN_PURE static ulong
fd_bloom_get_chunk_id( uint nmaskbits, fd_hash_t const * key ) {
  return (nmaskbits == 0 ? 0UL : ( key->ul[0] >> (64U - nmaskbits) ));
}

static void
fd_bloom_insert( fd_gossip_counting_bloom_t * b, fd_hash_t const * key ) {
  uint * chunk = b->count_filter_chunks[ fd_bloom_get_chunk_id( b->nmaskbits, key ) ];

  for( ulong i = 0 ; i < b->nkeys; i++ ){
    ulong pos = fd_bloom_pos( key, b->keys[i], FD_BLOOM_NUM_BITS );
    chunk[ pos ] = fd_uint_sat_add( chunk[pos], 1UL );
  }
}

static void
fd_bloom_remove( fd_gossip_counting_bloom_t * b, fd_hash_t const * key ) {
  uint * chunk = b->count_filter_chunks[ fd_bloom_get_chunk_id( b->nmaskbits, key ) ];

  for( ulong i = 0 ; i < b->nkeys; i++ ){
    ulong pos = fd_bloom_pos( key, b->keys[i], FD_BLOOM_NUM_BITS );
    if( FD_UNLIKELY( chunk[ pos ] == 0UL ) ) {
      FD_LOG_ERR(( "Bloom filter corrupted, likely due to removal of an element (not necessarily this one) that was not in filter." ));
    }
    chunk[ pos ] = fd_uint_sat_sub( chunk[pos], 1UL );
  }
}

static void
fd_bloom_setup( fd_gossip_counting_bloom_t * b, fd_rng_t * rng, ulong nitems ) {
  fd_memset( b , 0, sizeof(fd_gossip_counting_bloom_t) );

  b->nkeys = 1U;
  b->nchunks = 1U;
  b->nmaskbits = 0U;

  /* Compute the number of packets needed for all the bloom filter parts
    with a desired false positive rate <0.1% (upper bounded by FD_BLOOM_MAX_CHUNKS ) */
  double e = 0;
  if (nitems > 0) {
    do {
      double n = ((double)nitems)/((double)b->nchunks); /* Assume even division of values */
      double m = (double)FD_BLOOM_NUM_BITS;
      b->nkeys = fd_ulong_max(1U, (ulong)((m/n)*0.69314718055994530941723212145818 /* ln(2) */));
      b->nkeys = fd_ulong_min(b->nkeys, FD_BLOOM_MAX_KEYS);
      if (b->nchunks == FD_BLOOM_MAX_CHUNKS)
        break;
      double k = (double)b->nkeys;
      e = pow(1.0 - exp(-k*n/m), k);
      if (e < 0.001)
        break;
      b->nmaskbits++;
      b->nchunks = 1U<<b->nmaskbits;
    } while (1);
  }

  /* Generate random keys */
  for (ulong i = 0; i < b->nkeys; ++i)
    b->keys[i] = fd_rng_ulong( rng );

  FD_LOG_DEBUG(( "making bloom filter for %lu items with %lu packets, %u maskbits and %lu keys %g error", nitems, b->nchunks, b->nmaskbits, b->nkeys, e ));
}
