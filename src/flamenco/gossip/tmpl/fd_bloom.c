#ifndef BLOOM_NAME
#define "Define BLOOM_NAME"
#endif

#include "../../../util/fd_util.h"

static ulong
fnv_hasher( uchar const * ele,
            ulong         ele_sz,
            ulong         key ) {
  for( ulong i=0UL; i<ele_sz; i++ ) {
    key ^= (ulong)ele[i];
    key *= 1099511628211UL; /* FNV prime */
  }
  return key;
}

#ifndef BLOOM_HASH_FN
#define BLOOM_HASH_FN(ele,ele_sz,key) fnv_hasher( ele, ele_sz, key )
#endif


#define BLOOM_(n) FD_EXPAND_THEN_CONCAT3(BLOOM_NAME,_,n)

struct BLOOM_(private) {
  ulong *       keys;
  ulong         keys_len;

  ulong *       bits;
  ulong         bits_len;


  fd_rng_t *    rng;

  ulong         max_bits;
  double        false_positive_rate;

  ulong         magic; /* ==BLOOM_MAGIC */
};

typedef struct BLOOM_(private) BLOOM_(t);


#define FD_BLOOM_ALIGN     (64UL)
#define FD_BLOOM_FOOTPRINT (128UL)
static const double FD_BLOOM_LN_2 = 0.69314718055994530941723212145818;


FD_FN_CONST static ulong
BLOOM_(align)( void ) {
  return FD_BLOOM_ALIGN;
}

FD_FN_CONST static ulong
BLOOM_(footprint)( double false_positive_rate,
                     ulong  max_bits ) {
  if( FD_UNLIKELY( false_positive_rate<=0.0 ) ) return 0UL;
  if( FD_UNLIKELY( false_positive_rate>=1.0 ) ) return 0UL;

  if( FD_UNLIKELY( max_bits<1UL || max_bits>32768UL ) ) return 0UL;

  ulong num_keys = (ulong)( (double)max_bits*FD_BLOOM_LN_2 );

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_BLOOM_ALIGN, sizeof(BLOOM_(t)) );
  l = FD_LAYOUT_APPEND( l, 8UL,            num_keys           );
  l = FD_LAYOUT_APPEND( l, sizeof(ulong), (max_bits+7UL)/8UL );
  return FD_LAYOUT_FINI( l, FD_BLOOM_ALIGN );
}

static void *
BLOOM_(new)( void * shmem,
             fd_rng_t * rng,
             double false_positive_rate,
             ulong  max_bits ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, BLOOM_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( false_positive_rate<=0.0 ) ) return NULL;
  if( FD_UNLIKELY( false_positive_rate>=1.0 ) ) return NULL;

  if( FD_UNLIKELY( max_bits<1UL || max_bits>32768UL ) ) return NULL;

  if( FD_UNLIKELY( !rng ) ) return NULL;

  ulong num_keys = (ulong)( (double)max_bits*FD_BLOOM_LN_2 );
  FD_SCRATCH_ALLOC_INIT( l, shmem );
  BLOOM_(t) * bloom = FD_SCRATCH_ALLOC_APPEND( l, BLOOM_(align)(), sizeof(BLOOM_(t)) );
  void * _keys = FD_SCRATCH_ALLOC_APPEND( l, 8UL, num_keys );
  void * _bits = FD_SCRATCH_ALLOC_APPEND( l, sizeof(ulong), (max_bits+7UL)/8UL );

  bloom->keys                = (ulong *)_keys;
  bloom->keys_len            = 0UL;
  bloom->bits                = (ulong *)_bits;
  bloom->bits_len            = 0UL;

  bloom->rng                 = rng;

  bloom->false_positive_rate = false_positive_rate;
  bloom->max_bits            = max_bits;

  return (void *)bloom;
}

static BLOOM_(t) *
BLOOM_(join)( void * shbloom ) {
  if( FD_UNLIKELY( !shbloom ) ) {
    FD_LOG_WARNING(( "NULL shbloom" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shbloom, BLOOM_(align)() ) ) ) {
    FD_LOG_WARNING(( "misaligned shbloom" ));
    return NULL;
  }

  BLOOM_(t) * bloom = (BLOOM_(t) *)shbloom;

  // if( FD_UNLIKELY( bloom->magic!=FD_BLOOM_MAGIC ) ) {
  //   FD_LOG_WARNING(( "bad magic" ));
  //   return NULL;
  // }

  return bloom;
}

static void
BLOOM_(initialize)( BLOOM_(t) * bloom,
                    ulong       num_items ) {
  double num_bits = ceil( ((double)num_items * log( bloom->false_positive_rate )) / log( 1.0 / pow( 2.0, log( 2.0 ) ) ) );
  num_bits = fmax( 1.0, fmin( (double)bloom->max_bits, num_bits ) );

  ulong num_keys = fd_ulong_if( num_items==0UL, 0UL, fd_ulong_max( 1UL, (ulong)( round( ((double)num_bits/(double)num_items) * FD_BLOOM_LN_2 ) ) ) );
  for( ulong i=0UL; i<num_keys; i++ ) bloom->keys[ i ] = fd_rng_ulong( bloom->rng );

  bloom->keys_len = num_keys;
  bloom->bits_len = (ulong)num_bits;
  fd_memset( bloom->bits, 0, (ulong)((num_bits+7UL)/8UL) );
}

static void
BLOOM_(insert)( BLOOM_(t) *   bloom,
                uchar const * key,
                ulong         key_sz ) {
  for( ulong i=0UL; i<bloom->keys_len; i++ ) {
    ulong bit = BLOOM_HASH_FN( key, key_sz, bloom->keys[i] ) % bloom->bits_len;
    bloom->bits[ bit / 64UL ] |= (1UL << (bit % 64UL));
  }
}

static int
BLOOM_(contains)( BLOOM_(t) *   bloom,
                  uchar const * key,
                  ulong         key_sz ) {
  for( ulong i=0UL; i<bloom->keys_len; i++ ) {
    ulong bit = BLOOM_HASH_FN( key, key_sz, bloom->keys[i] ) % bloom->bits_len;
    if( !(bloom->bits[ bit / 64UL ] & (1UL << (bit % 64UL))) ) return 0;
  }
  return 1;
}

#undef BLOOM_
#undef BLOOM_HASH_FN
#undef BLOOM_ELE_T
#undef BLOOM_NAME
