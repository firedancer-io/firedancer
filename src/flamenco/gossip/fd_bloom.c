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

#if FD_HAS_AVX512 && FD_HAS_INT128

/* bloom_bit is h%bits_len.  magic is floor((2^64-1)/bits_len), which
   makes q floor(h/bits_len) or one less. */

static inline ulong
bloom_bit( ulong bits_len,
           ulong magic,
           ulong h ) {
  ulong q   = (ulong)(((uint128)h*(uint128)magic)>>64);
  ulong bit = h - q*bits_len;
  return fd_ulong_if( bit>=bits_len, bit-bits_len, bit );
}

static inline void
bloom_set( ulong * bits,
           ulong   bits_len,
           ulong   magic,
           ulong   h ) {
  ulong bit = bloom_bit( bits_len, magic, h );
  bits[ bit/64UL ] |= 1UL<<(bit%64UL);
}

static inline int
bloom_test( ulong const * bits,
            ulong         bits_len,
            ulong         magic,
            ulong         h ) {
  ulong bit = bloom_bit( bits_len, magic, h );
  return (int)((bits[ bit/64UL ]>>(bit%64UL)) & 1UL);
}

/* bloom_transpose8 loads the 8 contiguous 32 byte elements at ele so
   that wq[k] lane j holds the k-th 8 byte word of element ele8_lane(j).
   The lane to element map, 0,2,1,3,4,6,5,7, is an involution, so
   bloom_lane_mask converts a bit set both ways. */

static inline void
bloom_transpose8( uchar const * ele,
                  wwv_t         wq[ static 4 ] ) {
  wwv_t r0 = wwv_ldu( ele       ); wwv_t r1 = wwv_ldu( ele+ 64UL );
  wwv_t r2 = wwv_ldu( ele+128UL ); wwv_t r3 = wwv_ldu( ele+192UL );
  wwv_t t0 = _mm512_unpacklo_epi64( r0, r1 ); wwv_t t1 = _mm512_unpackhi_epi64( r0, r1 );
  wwv_t t2 = _mm512_unpacklo_epi64( r2, r3 ); wwv_t t3 = _mm512_unpackhi_epi64( r2, r3 );
  wwv_t lo = wwv( 0UL, 1UL, 4UL, 5UL,  8UL,  9UL, 12UL, 13UL );
  wwv_t hi = wwv( 2UL, 3UL, 6UL, 7UL, 10UL, 11UL, 14UL, 15UL );
  wq[0] = wwv_select( lo, t0, t2 ); wq[1] = wwv_select( lo, t1, t3 );
  wq[2] = wwv_select( hi, t0, t2 ); wq[3] = wwv_select( hi, t1, t3 );
}

static inline uint
bloom_lane_mask( uint m ) {
  return (m&0x99U) | ((m&0x22U)<<1) | ((m&0x44U)>>1);
}

/* bloom_fnv8x4 is fnv_hasher4 of the 8 transposed elements in wq: h[c]
   lane j is the FNV of element ele8_lane(j) under keys[c], one zmm
   chain per key.  Lanes past cnt repeat key 0. */

static inline void
bloom_fnv8x4( wwv_t const * wq,
              ulong const * keys,
              ulong         cnt,
              ulong         h[ static 4 ][ 8 ] ) {
  wwv_t prime = wwv_bcast( 1099511628211UL );
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
  wwv_st( h[0], h0 ); wwv_st( h[1], h1 ); wwv_st( h[2], h2 ); wwv_st( h[3], h3 );
}

/* bloom_fnv8x4x2 is bloom_fnv8x4 of two transposed 8 element blocks
   under the same keys, 8 chains interleaved: 4 dependent multiplies
   per byte do not fill the multiplier's pipeline, 8 nearly do. */

static inline void
bloom_fnv8x4x2( wwv_t const * wqa,
                wwv_t const * wqb,
                ulong const * keys,
                ulong         cnt,
                ulong         ha[ static 4 ][ 8 ],
                ulong         hb[ static 4 ][ 8 ] ) {
  wwv_t prime = wwv_bcast( 1099511628211UL );
  wwv_t k0 = wwv_bcast( keys[ 0 ] );
  wwv_t k1 = wwv_bcast( keys[ fd_ulong_if( cnt>1UL, 1UL, 0UL ) ] );
  wwv_t k2 = wwv_bcast( keys[ fd_ulong_if( cnt>2UL, 2UL, 0UL ) ] );
  wwv_t k3 = wwv_bcast( keys[ fd_ulong_if( cnt>3UL, 3UL, 0UL ) ] );
  wwv_t a0 = k0; wwv_t a1 = k1; wwv_t a2 = k2; wwv_t a3 = k3;
  wwv_t b0 = k0; wwv_t b1 = k1; wwv_t b2 = k2; wwv_t b3 = k3;
  for( ulong k=0UL; k<4UL; k++ ) {
    for( ulong b=0UL; b<8UL; b++ ) {
      wwv_t xa = wwv_and( wwv_shr( wqa[ k ], 8UL*b ), wwv_bcast( 0xffUL ) );
      wwv_t xb = wwv_and( wwv_shr( wqb[ k ], 8UL*b ), wwv_bcast( 0xffUL ) );
      a0 = wwv_mul( wwv_xor( a0, xa ), prime ); b0 = wwv_mul( wwv_xor( b0, xb ), prime );
      a1 = wwv_mul( wwv_xor( a1, xa ), prime ); b1 = wwv_mul( wwv_xor( b1, xb ), prime );
      a2 = wwv_mul( wwv_xor( a2, xa ), prime ); b2 = wwv_mul( wwv_xor( b2, xb ), prime );
      a3 = wwv_mul( wwv_xor( a3, xa ), prime ); b3 = wwv_mul( wwv_xor( b3, xb ), prime );
    }
  }
  wwv_st( ha[0], a0 ); wwv_st( ha[1], a1 ); wwv_st( ha[2], a2 ); wwv_st( ha[3], a3 );
  wwv_st( hb[0], b0 ); wwv_st( hb[1], b1 ); wwv_st( hb[2], b2 ); wwv_st( hb[3], b3 );
}

static inline void
bloom_set8( ulong *       bits,
            ulong         bits_len,
            ulong         magic,
            ulong         h[ static 4 ][ 8 ],
            ulong         cnt,
            uint          lane_mask ) {
  for( uint m=lane_mask; m; m&=m-1U ) {
    ulong j = (ulong)fd_uint_find_lsb( m );
    for( ulong c=0UL; c<cnt; c++ ) bloom_set( bits, bits_len, magic, h[ c ][ j ] );
  }
}

void
fd_bloom_insert8( fd_bloom_t *  bloom,
                  uchar const * ele,
                  uint          lanes ) {
  ulong bits_len = bloom->bits_len;
  if( FD_UNLIKELY( !bits_len || !lanes ) ) return;
  ulong magic = ULONG_MAX/bits_len;

  wwv_t wq[4];
  bloom_transpose8( ele, wq );
  uint lane_mask = bloom_lane_mask( lanes );

  for( ulong i=0UL; i<bloom->keys_len; i+=4UL ) {
    ulong cnt = fd_ulong_min( bloom->keys_len-i, 4UL );
    ulong h[4][8] __attribute__((aligned(64)));
    bloom_fnv8x4( wq, bloom->keys+i, cnt, h );
    bloom_set8( bloom->bits, bits_len, magic, h, cnt, lane_mask );
  }
}

void
fd_bloom_insert16( fd_bloom_t *  bloom,
                   uchar const * ele_a,
                   uint          lanes_a,
                   uchar const * ele_b,
                   uint          lanes_b ) {
  ulong bits_len = bloom->bits_len;
  if( FD_UNLIKELY( !bits_len ) ) return;
  if( FD_UNLIKELY( !lanes_a ) ) { fd_bloom_insert8( bloom, ele_b, lanes_b ); return; }
  if( FD_UNLIKELY( !lanes_b ) ) { fd_bloom_insert8( bloom, ele_a, lanes_a ); return; }
  ulong magic = ULONG_MAX/bits_len;

  wwv_t wqa[4]; wwv_t wqb[4];
  bloom_transpose8( ele_a, wqa );
  bloom_transpose8( ele_b, wqb );
  uint lane_mask_a = bloom_lane_mask( lanes_a );
  uint lane_mask_b = bloom_lane_mask( lanes_b );

  for( ulong i=0UL; i<bloom->keys_len; i+=4UL ) {
    ulong cnt = fd_ulong_min( bloom->keys_len-i, 4UL );
    ulong ha[4][8] __attribute__((aligned(64)));
    ulong hb[4][8] __attribute__((aligned(64)));
    bloom_fnv8x4x2( wqa, wqb, bloom->keys+i, cnt, ha, hb );
    bloom_set8( bloom->bits, bits_len, magic, ha, cnt, lane_mask_a );
    bloom_set8( bloom->bits, bits_len, magic, hb, cnt, lane_mask_b );
  }
}

uint
fd_bloom_contains8( fd_bloom_t const * bloom,
                    uchar const *      ele ) {
  ulong bits_len = bloom->bits_len;
  ulong keys_len = bloom->keys_len;
  if( FD_UNLIKELY( !keys_len || !bits_len ) ) return 0U;
  ulong magic = ULONG_MAX/bits_len;

  wwv_t wq[4];
  bloom_transpose8( ele, wq );

  /* Lanes whose element has had every key so far set; a lane leaves
     on its first clear bit, as fd_bloom_contains returns there. */
  uint alive = 0xffU;
  for( ulong i=0UL; i<keys_len && alive; i+=4UL ) {
    ulong cnt = fd_ulong_min( keys_len-i, 4UL );
    ulong h[4][8] __attribute__((aligned(64)));
    bloom_fnv8x4( wq, bloom->keys+i, cnt, h );
    for( uint m=alive; m; m&=m-1U ) {
      ulong j = (ulong)fd_uint_find_lsb( m );
      for( ulong c=0UL; c<cnt; c++ ) {
        if( !bloom_test( bloom->bits, bits_len, magic, h[ c ][ j ] ) ) { alive &= ~(1U<<j); break; }
      }
    }
  }
  return bloom_lane_mask( alive );
}

#define BLOOM_MULTI_CHAIN_CNT (5UL) /* 40 lanes: 12 active set peers with 3 keys each */

uint
fd_bloom_contains_multi( fd_bloom_t * const * blooms,
                         ulong                cnt,
                         uchar const *        key,
                         ulong                key_sz ) {
  /* One lane per (bloom, key) pair.  A bloom with no keys or bits
     contains nothing (fd_bloom_contains) and takes no lane. */
  ulong keys[ 8UL*BLOOM_MULTI_CHAIN_CNT ];
  ulong off [ 32UL ];
  ulong tot = 0UL;
  for( ulong b=0UL; b<cnt; b++ ) {
    fd_bloom_t const * bloom = blooms[ b ];
    off[ b ] = tot;
    if( FD_UNLIKELY( !bloom->keys_len || !bloom->bits_len ) ) continue;
    if( FD_UNLIKELY( tot+bloom->keys_len>8UL*BLOOM_MULTI_CHAIN_CNT ) ) {
      uint hit = 0U;
      for( ulong i=0UL; i<cnt; i++ ) hit |= (uint)fd_bloom_contains( blooms[ i ], key, key_sz )<<i;
      return hit;
    }
    for( ulong k=0UL; k<bloom->keys_len; k++ ) keys[ tot++ ] = bloom->keys[ k ];
  }
  if( FD_UNLIKELY( !tot ) ) return 0U;
  for( ulong i=tot; i<8UL*BLOOM_MULTI_CHAIN_CNT; i++ ) keys[ i ] = 0UL;

  /* The key bytes go into every lane; the chains are independent so
     the multiply latency is hidden across them. */
  wwv_t prime = wwv_bcast( 1099511628211UL );
  wwv_t h[ BLOOM_MULTI_CHAIN_CNT ];
  for( ulong c=0UL; c<BLOOM_MULTI_CHAIN_CNT; c++ ) h[ c ] = wwv_ldu( keys+8UL*c );
  for( ulong i=0UL; i<key_sz; i++ ) {
    wwv_t x = wwv_bcast( (ulong)key[ i ] );
    for( ulong c=0UL; c<BLOOM_MULTI_CHAIN_CNT; c++ ) h[ c ] = wwv_mul( wwv_xor( h[ c ], x ), prime );
  }
  ulong hash[ 8UL*BLOOM_MULTI_CHAIN_CNT ] __attribute__((aligned(64)));
  for( ulong c=0UL; c<BLOOM_MULTI_CHAIN_CNT; c++ ) wwv_st( hash+8UL*c, h[ c ] );

  uint hit = 0U;
  for( ulong b=0UL; b<cnt; b++ ) {
    fd_bloom_t const * bloom = blooms[ b ];
    if( FD_UNLIKELY( !bloom->keys_len || !bloom->bits_len ) ) continue;
    ulong k=0UL;
    for( ; k<bloom->keys_len; k++ ) {
      ulong bit = hash[ off[ b ]+k ] % bloom->bits_len;
      if( !(bloom->bits[ bit/64UL ] & (1UL<<(bit%64UL))) ) break;
    }
    hit |= (uint)(k==bloom->keys_len)<<b;
  }
  return hit;
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

void
fd_bloom_insert16( fd_bloom_t *  bloom,
                   uchar const * ele_a,
                   uint          lanes_a,
                   uchar const * ele_b,
                   uint          lanes_b ) {
  fd_bloom_insert8( bloom, ele_a, lanes_a );
  fd_bloom_insert8( bloom, ele_b, lanes_b );
}

uint
fd_bloom_contains8( fd_bloom_t const * bloom,
                    uchar const *      ele ) {
  uint hit = 0U;
  for( ulong i=0UL; i<8UL; i++ ) hit |= (uint)fd_bloom_contains( (fd_bloom_t *)bloom, ele+32UL*i, 32UL )<<i;
  return hit;
}

uint
fd_bloom_contains_multi( fd_bloom_t * const * blooms,
                         ulong                cnt,
                         uchar const *        key,
                         ulong                key_sz ) {
  uint hit = 0U;
  for( ulong i=0UL; i<cnt; i++ ) hit |= (uint)fd_bloom_contains( blooms[ i ], key, key_sz )<<i;
  return hit;
}

#endif

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
