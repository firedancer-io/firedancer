#include "fd_bloom.h"

#include "../../util/log/fd_log.h"
#if FD_HAS_AVX512
#include "../../util/simd/fd_avx512.h"
#endif

#include <math.h>

static const double FD_BLOOM_LN_2 = 0.69314718055994530941723212145818;
FD_FN_CONST ulong
fd_bloom_align( void ) {
  return FD_BLOOM_ALIGN;
}

FD_FN_CONST ulong
fd_bloom_footprint( double false_positive_rate,
                    ulong  max_bits ) {
  if( FD_UNLIKELY( false_positive_rate<=0.0 ) ) return 0UL;
  if( FD_UNLIKELY( false_positive_rate>=1.0 ) ) return 0UL;

  if( FD_UNLIKELY( max_bits<1UL || max_bits>32768UL ) ) return 0UL;

  ulong num_keys = (ulong)( round( (double)max_bits*FD_BLOOM_LN_2 ) );

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_BLOOM_ALIGN, sizeof(fd_bloom_t) );
  l = FD_LAYOUT_APPEND( l, 8UL,            num_keys*sizeof(ulong) );
  l = FD_LAYOUT_APPEND( l, 8UL,            (max_bits+7UL)/8UL );
  return FD_LAYOUT_FINI( l, FD_BLOOM_ALIGN );
}

void *
fd_bloom_new( void *     shmem,
              fd_rng_t * rng,
              double     false_positive_rate,
              ulong      max_bits ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_bloom_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( false_positive_rate<=0.0 ) ) return NULL;
  if( FD_UNLIKELY( false_positive_rate>=1.0 ) ) return NULL;

  if( FD_UNLIKELY( max_bits<1UL || max_bits>32768UL ) ) return NULL;

  if( FD_UNLIKELY( !rng ) ) return NULL;

  ulong num_keys = (ulong)( round( (double)max_bits*FD_BLOOM_LN_2 ) );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_bloom_t * bloom = FD_SCRATCH_ALLOC_APPEND( l, FD_BLOOM_ALIGN, sizeof(fd_bloom_t) );
  void * _keys       = FD_SCRATCH_ALLOC_APPEND( l, 8UL, num_keys*sizeof(ulong) );
  void * _bits       = FD_SCRATCH_ALLOC_APPEND( l, 8UL, (max_bits+7UL)/8UL );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, FD_BLOOM_ALIGN ) == (ulong)shmem + fd_bloom_footprint( false_positive_rate, max_bits ) );

  bloom->keys      = (ulong *)_keys;
  bloom->keys_len  = 0UL;
  bloom->bits      = (ulong *)_bits;
  bloom->bits_len  = 0UL;

  bloom->hash_seed = 0UL;
  bloom->rng       = rng;

  bloom->false_positive_rate = false_positive_rate;
  bloom->max_bits = max_bits;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( bloom->magic ) = FD_BLOOM_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)bloom;
}

fd_bloom_t *
fd_bloom_join( void * shbloom ) {
  if( FD_UNLIKELY( !shbloom ) ) {
    FD_LOG_WARNING(( "NULL shbloom" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shbloom, fd_bloom_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shbloom" ));
    return NULL;
  }

  fd_bloom_t * bloom = (fd_bloom_t *)shbloom;

  if( FD_UNLIKELY( bloom->magic!=FD_BLOOM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return bloom;
}

void
fd_bloom_initialize( fd_bloom_t * bloom,
                     ulong        num_items ) {
  double num_bits = ceil( ((double)num_items * log( bloom->false_positive_rate )) / log( 1.0 / pow( 2.0, log( 2.0 ) ) ) );
  num_bits = fmax( 1.0, fmin( (double)bloom->max_bits, num_bits ) );

  ulong num_keys;
  if( FD_UNLIKELY( num_items == 0UL ) ) {
    num_keys = 0UL;
  } else {
    num_keys = fd_ulong_max( 1UL, (ulong)( round( ((double)num_bits/(double)num_items) * FD_BLOOM_LN_2 ) ) );
  }
  for( ulong i=0UL; i<num_keys; i++ ) bloom->keys[ i ] = fd_rng_ulong( bloom->rng );

  bloom->keys_len = num_keys;
  bloom->bits_len = (ulong)num_bits;
  fd_memset( bloom->bits, 0, (ulong)((num_bits+7UL)/8UL) );
}

static inline ulong
fnv_hasher( uchar const * ele,
            ulong         ele_sz,
            ulong         key ) {
  for( ulong i=0UL; i<ele_sz; i++ ) key = (key^(ulong)ele[i])*1099511628211UL;
  return key;
}

static inline void
fnv_hasher4( uchar const * ele,
             ulong         ele_sz,
             ulong const * keys,
             ulong         key_cnt,
             ulong         out[ static 4 ] ) {
  ulong h0 = keys[ 0 ];
  ulong h1 = keys[ fd_ulong_if( key_cnt>1UL, 1UL, 0UL ) ];
  ulong h2 = keys[ fd_ulong_if( key_cnt>2UL, 2UL, 0UL ) ];
  ulong h3 = keys[ fd_ulong_if( key_cnt>3UL, 3UL, 0UL ) ];
  for( ulong i=0UL; i<ele_sz; i++ ) {
    ulong b = (ulong)ele[i];
    h0 = (h0^b)*1099511628211UL;
    h1 = (h1^b)*1099511628211UL;
    h2 = (h2^b)*1099511628211UL;
    h3 = (h3^b)*1099511628211UL;
  }
  out[0] = h0; out[1] = h1; out[2] = h2; out[3] = h3;
}

void
fd_bloom_insert( fd_bloom_t *  bloom,
                 uchar const * key,
                 ulong         key_sz ) {
  if( FD_UNLIKELY( !bloom->bits_len ) ) return;
  if( FD_UNLIKELY( bloom->keys_len==1UL ) ) { /* one chain, not four */
    ulong bit = fnv_hasher( key, key_sz, bloom->keys[ 0 ] ) % bloom->bits_len;
    bloom->bits[ bit / 64UL ] |= (1UL << (bit % 64UL));
    return;
  }
  for( ulong i=0UL; i<bloom->keys_len; i+=4UL ) {
    ulong cnt = fd_ulong_min( bloom->keys_len-i, 4UL );
    ulong h[4];
    fnv_hasher4( key, key_sz, bloom->keys+i, cnt, h );
    for( ulong j=0UL; j<cnt; j++ ) {
      ulong bit = h[ j ] % bloom->bits_len;
      bloom->bits[ bit / 64UL ] |= (1UL << (bit % 64UL));
    }
  }
}

#if FD_HAS_AVX512 && FD_HAS_INT128

/* bloom_set sets bit h%bits_len.  magic is floor((2^64-1)/bits_len),
   which makes q floor(h/bits_len) or one less. */

static inline void
bloom_set( ulong * bits,
           ulong   bits_len,
           ulong   magic,
           ulong   h ) {
  ulong q   = (ulong)(((uint128)h*(uint128)magic)>>64);
  ulong bit = h - q*bits_len;
  bit = fd_ulong_if( bit>=bits_len, bit-bits_len, bit );
  bits[ bit/64UL ] |= 1UL<<(bit%64UL);
}

void
fd_bloom_insert8( fd_bloom_t *  bloom,
                  uchar const * ele,
                  uint          lanes ) {
  ulong bits_len = bloom->bits_len;
  if( FD_UNLIKELY( !bits_len || !lanes ) ) return;
  ulong magic = ULONG_MAX/bits_len;

  /* Transpose so wq[k] lane j holds the k-th 8 byte word of an element.
     The lane to element map is 0,2,1,3,4,6,5,7. */
  wwv_t r0 = wwv_ldu( ele       ); wwv_t r1 = wwv_ldu( ele+ 64UL );
  wwv_t r2 = wwv_ldu( ele+128UL ); wwv_t r3 = wwv_ldu( ele+192UL );
  wwv_t t0 = _mm512_unpacklo_epi64( r0, r1 ); wwv_t t1 = _mm512_unpackhi_epi64( r0, r1 );
  wwv_t t2 = _mm512_unpacklo_epi64( r2, r3 ); wwv_t t3 = _mm512_unpackhi_epi64( r2, r3 );
  wwv_t lo = wwv( 0UL, 1UL, 4UL, 5UL,  8UL,  9UL, 12UL, 13UL );
  wwv_t hi = wwv( 2UL, 3UL, 6UL, 7UL, 10UL, 11UL, 14UL, 15UL );
  wwv_t wq[4];
  wq[0] = wwv_select( lo, t0, t2 ); wq[1] = wwv_select( lo, t1, t3 );
  wq[2] = wwv_select( hi, t0, t2 ); wq[3] = wwv_select( hi, t1, t3 );
  uint lane_mask = (lanes&0x99U) | ((lanes&0x22U)<<1) | ((lanes&0x44U)>>1);

  wwv_t prime = wwv_bcast( 1099511628211UL );
  for( ulong i=0UL; i<bloom->keys_len; i+=4UL ) {
    ulong cnt = fd_ulong_min( bloom->keys_len-i, 4UL );
    ulong const * keys = bloom->keys+i;
    wwv_t h0 = wwv_bcast( keys[ 0 ] );
    wwv_t h1 = wwv_bcast( keys[ fd_ulong_if( cnt>1UL, 1UL, 0UL ) ] );
    wwv_t h2 = wwv_bcast( keys[ fd_ulong_if( cnt>2UL, 2UL, 0UL ) ] );
    wwv_t h3 = wwv_bcast( keys[ fd_ulong_if( cnt>3UL, 3UL, 0UL ) ] );
    for( ulong k=0UL; k<4UL; k++ ) {
      for( ulong b=0UL; b<8UL; b++ ) {
        wwv_t x = wwv_and( wwv_shr( wq[ k ], 8UL*b ), wwv_bcast( 0xffUL ) );
        h0 = wwv_mul( wwv_xor( h0, x ), prime );
        h1 = wwv_mul( wwv_xor( h1, x ), prime );
        h2 = wwv_mul( wwv_xor( h2, x ), prime );
        h3 = wwv_mul( wwv_xor( h3, x ), prime );
      }
    }
    ulong h[4][8] __attribute__((aligned(64)));
    wwv_st( h[0], h0 ); wwv_st( h[1], h1 ); wwv_st( h[2], h2 ); wwv_st( h[3], h3 );
    for( uint m=lane_mask; m; m&=m-1U ) {
      ulong j = (ulong)fd_uint_find_lsb( m );
      for( ulong c=0UL; c<cnt; c++ ) bloom_set( bloom->bits, bits_len, magic, h[ c ][ j ] );
    }
  }
}

#else

void
fd_bloom_insert8( fd_bloom_t *  bloom,
                  uchar const * ele,
                  uint          lanes ) {
  for( ulong i=0UL; i<8UL; i++ ) {
    if( lanes & (1U<<i) ) fd_bloom_insert( bloom, ele+32UL*i, 32UL );
  }
}

#endif

int
fd_bloom_contains( fd_bloom_t *  bloom,
                   uchar const * key,
                   ulong         key_sz ) {
  if( FD_UNLIKELY( !bloom->keys_len || !bloom->bits_len ) ) return 0;
  if( FD_UNLIKELY( bloom->keys_len==1UL ) ) {
    ulong bit = fnv_hasher( key, key_sz, bloom->keys[ 0 ] ) % bloom->bits_len;
    return !!(bloom->bits[ bit / 64UL ] & (1UL << (bit % 64UL)));
  }
  for( ulong i=0UL; i<bloom->keys_len; i+=4UL ) {
    ulong cnt = fd_ulong_min( bloom->keys_len-i, 4UL );
    ulong h[4];
    fnv_hasher4( key, key_sz, bloom->keys+i, cnt, h );
    for( ulong j=0UL; j<cnt; j++ ) {
      ulong bit = h[ j ] % bloom->bits_len;
      if( !(bloom->bits[ bit / 64UL ] & (1UL << (bit % 64UL))) ) {
        return 0;
      }
    }
  }
  return 1;
}

int
fd_bloom_init_inplace( ulong *      keys,
                       ulong *      bits,
                       ulong        keys_len,
                       ulong        bits_len,
                       ulong        hash_seed,
                       fd_rng_t *   rng,
                       double       false_positive_rate,
                       fd_bloom_t * out_bloom ) {
  if( FD_UNLIKELY( !keys || !bits || !out_bloom ) ) {
    FD_LOG_ERR(( "NULL keys, bits or out_bloom" ));
    return -1;
  }
  out_bloom->keys                = keys;
  for( ulong i=0UL; i<keys_len; i++ ) out_bloom->keys[ i ] = fd_rng_ulong( rng );

  out_bloom->keys_len            = keys_len;
  out_bloom->bits                = bits;
  out_bloom->bits_len            = bits_len;
  out_bloom->hash_seed           = hash_seed;
  out_bloom->rng                 = rng;
  out_bloom->false_positive_rate = false_positive_rate;
  out_bloom->max_bits            = bits_len;

  return 0;
}
