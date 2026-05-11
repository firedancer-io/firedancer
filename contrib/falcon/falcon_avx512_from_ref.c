/* falcon_avx512_from_ref.c - Falcon-512 verification, AVX-512.
 *
 * Same NTT structure as falcon_avx512 (Barrett) and falcon_avx512
 * (Shoup), but with Pornin's reference Montgomery multiplication --
 * SIMD-vectorised to AVX-512 16-wide u32.  The point is to compare the
 * three reduction strategies on the same NTT skeleton.
 *
 * Pornin's Montgomery (R = 2^16 mod Q):
 *
 *     mq_montymul(x, y):
 *         z = x * y                              // mullo, 32-bit
 *         w = ((z * Q0I) & 0xFFFF) * Q          // 2 mullos
 *         s = (z + w) >> 16
 *         r = s - Q;  if (r < 0) r += Q;
 *         return r                                // result is x*y/R mod Q
 *
 * Three serialized mullos in the critical path -- expected to be a hair
 * slower than Barrett (~25 cycles) and noticeably slower than Shoup (~15
 * cycles) on Skylake-X+.  We pay this to keep the whole pipeline in
 * Pornin's algebra: twiddles precomputed in Montgomery form (= twid*R
 * mod Q), h converted to Montgomery upfront, and a final R/N scaling
 * factor at the end of the iNTT.  Stays in u32 lanes throughout.
 *
 * Stays-in-range (always-reduced) add/sub: monty_mul requires both
 * operands in [0, Q), so we cannot use lazy reduction the way Barrett
 * does.  The per-butterfly cost is therefore: 1 mul + 1 always-reduced
 * add + 1 always-reduced sub vs Barrett's 1 mul + 1 lazy add + 1 lazy
 * sub.  Each always-reduced op adds ~2 ops over a lazy one.
 *
 * Public domain. */

#include "falcon_avx512_common.h"
#include "falcon_twiddle.h"

#if HAVE_AVX512

#include <immintrin.h>

#define Q0I_VAL 12287U   /* -Q^{-1} mod 2^16 */
#define R_VAL    4091U   /* 2^16 mod Q */
#define R2_VAL  10952U   /* 2^32 mod Q */
/* N^{-1} mod Q in regular form, scaled to /N via Pornin's recipe.  We
 * want monty_mul(x, NI) = x / N mod Q.  So NI = R/N mod Q in regular.
 * R = 4091, 1/N = 1/512 mod Q = 12265.  4091 * 12265 mod 12289 = 128. */
#define NI_VAL    128U

/* ---------- Pornin Montgomery field multiplication, AVX-512 16-wide u32. */

static inline __m512i
fq_mul_monty_v( __m512i x, __m512i y ) {
  const __m512i Qv     = _mm512_set1_epi32( (int)Q );
  const __m512i Q0Iv   = _mm512_set1_epi32( (int)Q0I_VAL );
  const __m512i mask16 = _mm512_set1_epi32( 0xFFFF );

  __m512i z = _mm512_mullo_epi32( x, y );                            /* z = x*y          */
  __m512i k = _mm512_and_si512( _mm512_mullo_epi32( z, Q0Iv ),
                                mask16 );                            /* k = (z*Q0I)&0xFF */
  __m512i w = _mm512_mullo_epi32( k, Qv );                           /* w = k * Q       */
  __m512i s = _mm512_srli_epi32( _mm512_add_epi32( z, w ), 16 );     /* s = (z+w)>>16   */
  __m512i d    = _mm512_sub_epi32( s, Qv );
  __m512i sign = _mm512_srai_epi32( d, 31 );
  return _mm512_add_epi32( d, _mm512_and_si512( Qv, sign ) );        /* r in [0, Q)     */
}

/* ---------- Always-reduced add / sub (Pornin's mq_add / mq_sub). */

static inline __m512i
fq_add_v( __m512i a, __m512i b ) {
  const __m512i Qv = _mm512_set1_epi32( (int)Q );
  __m512i s    = _mm512_add_epi32( a, b );
  __m512i d    = _mm512_sub_epi32( s, Qv );
  __m512i sign = _mm512_srai_epi32( d, 31 );
  return _mm512_add_epi32( d, _mm512_and_si512( Qv, sign ) );
}

static inline __m512i
fq_sub_v( __m512i a, __m512i b ) {
  const __m512i Qv = _mm512_set1_epi32( (int)Q );
  __m512i d    = _mm512_sub_epi32( a, b );
  __m512i sign = _mm512_srai_epi32( d, 31 );
  return _mm512_add_epi32( d, _mm512_and_si512( Qv, sign ) );
}

/* AVX2 (256-bit, 8 lanes) and SSE (128-bit, 4 lanes) variants for the
 * small-stride passes (t = 8 / t = 4 respectively).  Pornin Monty is
 * algorithmically the same; just narrower SIMD. */

static inline __m256i
fq_mul_monty_avx2( __m256i x, __m256i y ) {
  const __m256i Qv     = _mm256_set1_epi32( (int)Q );
  const __m256i Q0Iv   = _mm256_set1_epi32( (int)Q0I_VAL );
  const __m256i mask16 = _mm256_set1_epi32( 0xFFFF );
  __m256i z = _mm256_mullo_epi32( x, y );
  __m256i k = _mm256_and_si256( _mm256_mullo_epi32( z, Q0Iv ), mask16 );
  __m256i w = _mm256_mullo_epi32( k, Qv );
  __m256i s = _mm256_srli_epi32( _mm256_add_epi32( z, w ), 16 );
  __m256i d    = _mm256_sub_epi32( s, Qv );
  __m256i sign = _mm256_srai_epi32( d, 31 );
  return _mm256_add_epi32( d, _mm256_and_si256( Qv, sign ) );
}

static inline __m256i
fq_add_avx2( __m256i a, __m256i b ) {
  const __m256i Qv = _mm256_set1_epi32( (int)Q );
  __m256i s    = _mm256_add_epi32( a, b );
  __m256i d    = _mm256_sub_epi32( s, Qv );
  __m256i sign = _mm256_srai_epi32( d, 31 );
  return _mm256_add_epi32( d, _mm256_and_si256( Qv, sign ) );
}

static inline __m256i
fq_sub_avx2( __m256i a, __m256i b ) {
  const __m256i Qv = _mm256_set1_epi32( (int)Q );
  __m256i d    = _mm256_sub_epi32( a, b );
  __m256i sign = _mm256_srai_epi32( d, 31 );
  return _mm256_add_epi32( d, _mm256_and_si256( Qv, sign ) );
}

static inline __m128i
fq_mul_monty_sse( __m128i x, __m128i y ) {
  const __m128i Qv     = _mm_set1_epi32( (int)Q );
  const __m128i Q0Iv   = _mm_set1_epi32( (int)Q0I_VAL );
  const __m128i mask16 = _mm_set1_epi32( 0xFFFF );
  __m128i z = _mm_mullo_epi32( x, y );
  __m128i k = _mm_and_si128( _mm_mullo_epi32( z, Q0Iv ), mask16 );
  __m128i w = _mm_mullo_epi32( k, Qv );
  __m128i s = _mm_srli_epi32( _mm_add_epi32( z, w ), 16 );
  __m128i d    = _mm_sub_epi32( s, Qv );
  __m128i sign = _mm_srai_epi32( d, 31 );
  return _mm_add_epi32( d, _mm_and_si128( Qv, sign ) );
}

static inline __m128i
fq_add_sse( __m128i a, __m128i b ) {
  const __m128i Qv = _mm_set1_epi32( (int)Q );
  __m128i s    = _mm_add_epi32( a, b );
  __m128i d    = _mm_sub_epi32( s, Qv );
  __m128i sign = _mm_srai_epi32( d, 31 );
  return _mm_add_epi32( d, _mm_and_si128( Qv, sign ) );
}

static inline __m128i
fq_sub_sse( __m128i a, __m128i b ) {
  const __m128i Qv = _mm_set1_epi32( (int)Q );
  __m128i d    = _mm_sub_epi32( a, b );
  __m128i sign = _mm_srai_epi32( d, 31 );
  return _mm_add_epi32( d, _mm_and_si128( Qv, sign ) );
}

/* Scalar fallback for t == 1, 2 (where SSE needs special transposes). */
static inline falcon_fq_t fq_add( falcon_fq_t a, falcon_fq_t b ) {
  uint32_t s = a + b;
  uint32_t d = s - (uint32_t)Q;
  return d + ( (uint32_t)Q & (uint32_t)( (int32_t)d >> 31 ) );
}
static inline falcon_fq_t fq_sub( falcon_fq_t a, falcon_fq_t b ) {
  uint32_t d = a - b;
  return d + ( (uint32_t)Q & (uint32_t)( (int32_t)d >> 31 ) );
}
static inline falcon_fq_t fq_mul_monty( falcon_fq_t x, falcon_fq_t y ) {
  uint32_t z = x * y;
  uint32_t w = ( ( z * Q0I_VAL ) & 0xFFFFU ) * (uint32_t)Q;
  uint32_t s = ( z + w ) >> 16;
  uint32_t d = s - (uint32_t)Q;
  return d + ( (uint32_t)Q & (uint32_t)( (int32_t)d >> 31 ) );
}

/* ---------- Twiddle tables, in Montgomery form (= twid * R mod Q). */

static falcon_fq_t psi_pos_monty[ N ] __attribute__((aligned(64)));
static falcon_fq_t psi_neg_monty[ N ] __attribute__((aligned(64)));

__attribute__((constructor))
static void
init_psi_monty( void ) {
  for( int i=0; i<N; i++ ) {
    /* twid * R mod Q, computed via Pornin's monty_mul(twid, R2) which
     * yields twid * R^2 / R = twid * R. */
    psi_pos_monty[ i ] = fq_mul_monty( falcon_psi_positive[ i ], R2_VAL );
    psi_neg_monty[ i ] = fq_mul_monty( falcon_psi_negative[ i ], R2_VAL );
  }
}

/* ---------- Forward NTT, Pornin Montgomery, always-reduced add/sub. */

static void
ntt_fwd_monty_avx512( falcon_fq_t * out, falcon_fq_t const * in ) {
  memcpy( out, in, sizeof(falcon_fq_t) * N );

  uint32_t t = N;
  uint32_t m = 1;
  while( m < N ) {
    t >>= 1;

    if( t >= 16 ) {
      for( uint32_t i=0; i<m; i++ ) {
        uint32_t j1 = 2 * i * t;
        __m512i sv = _mm512_set1_epi32( (int)psi_pos_monty[ m + i ] );
        for( uint32_t j=j1; j<j1+t; j+=16 ) {
          __m512i u = _mm512_loadu_si512( (void const *)( out + j ) );
          __m512i v = fq_mul_monty_v( _mm512_loadu_si512( (void const *)( out + j + t ) ), sv );
          _mm512_storeu_si512( (void *)( out + j     ), fq_add_v( u, v ) );
          _mm512_storeu_si512( (void *)( out + j + t ), fq_sub_v( u, v ) );
        }
      }
    } else if( t == 8 ) {
      for( uint32_t i=0; i<m; i++ ) {
        uint32_t j1 = 2 * i * t;
        __m256i sv = _mm256_set1_epi32( (int)psi_pos_monty[ m + i ] );
        __m256i u  = _mm256_loadu_si256( (void const *)( out + j1 ) );
        __m256i v  = fq_mul_monty_avx2( _mm256_loadu_si256( (void const *)( out + j1 + t ) ), sv );
        _mm256_storeu_si256( (void *)( out + j1     ), fq_add_avx2( u, v ) );
        _mm256_storeu_si256( (void *)( out + j1 + t ), fq_sub_avx2( u, v ) );
      }
    } else if( t == 4 ) {
      for( uint32_t i=0; i<m; i++ ) {
        uint32_t j1 = 8 * i;
        __m128i sv = _mm_set1_epi32( (int)psi_pos_monty[ m + i ] );
        __m128i u  = _mm_loadu_si128( (void const *)( out + j1 ) );
        __m128i v  = fq_mul_monty_sse( _mm_loadu_si128( (void const *)( out + j1 + 4 ) ), sv );
        _mm_storeu_si128( (void *)( out + j1     ), fq_add_sse( u, v ) );
        _mm_storeu_si128( (void *)( out + j1 + 4 ), fq_sub_sse( u, v ) );
      }
    } else { /* t == 1 or 2 -- scalar; small enough cost not to matter. */
      for( uint32_t i=0; i<m; i++ ) {
        uint32_t j1 = 2 * i * t;
        falcon_fq_t s = psi_pos_monty[ m + i ];
        for( uint32_t j=j1; j<j1+t; j++ ) {
          falcon_fq_t u = out[ j     ];
          falcon_fq_t v = fq_mul_monty( out[ j + t ], s );
          out[ j     ] = fq_add( u, v );
          out[ j + t ] = fq_sub( u, v );
        }
      }
    }
    m <<= 1;
  }
}

/* ---------- Inverse NTT, Pornin Montgomery.  Final pass folds in the
 * 1/N normalisation via monty_mul(., NI) where NI = R/N mod Q. */

static void
ntt_inv_monty_avx512( falcon_fq_t * out, falcon_fq_t const * in ) {
  memcpy( out, in, sizeof(falcon_fq_t) * N );

  uint32_t t = 1;
  uint32_t m = N;
  while( m > 1 ) {
    uint32_t h = m >> 1;
    uint32_t dt = t << 1;

    if( t >= 16 ) {
      for( uint32_t i=0; i<h; i++ ) {
        uint32_t j1 = i * dt;
        __m512i sv = _mm512_set1_epi32( (int)psi_neg_monty[ h + i ] );
        for( uint32_t j=j1; j<j1+t; j+=16 ) {
          __m512i u = _mm512_loadu_si512( (void const *)( out + j ) );
          __m512i v = _mm512_loadu_si512( (void const *)( out + j + t ) );
          _mm512_storeu_si512( (void *)( out + j     ), fq_add_v( u, v ) );
          _mm512_storeu_si512( (void *)( out + j + t ),
                               fq_mul_monty_v( fq_sub_v( u, v ), sv ) );
        }
      }
    } else if( t == 8 ) {
      for( uint32_t i=0; i<h; i++ ) {
        uint32_t j1 = i * dt;
        __m256i sv = _mm256_set1_epi32( (int)psi_neg_monty[ h + i ] );
        __m256i u  = _mm256_loadu_si256( (void const *)( out + j1 ) );
        __m256i v  = _mm256_loadu_si256( (void const *)( out + j1 + t ) );
        _mm256_storeu_si256( (void *)( out + j1     ), fq_add_avx2( u, v ) );
        _mm256_storeu_si256( (void *)( out + j1 + t ),
                             fq_mul_monty_avx2( fq_sub_avx2( u, v ), sv ) );
      }
    } else if( t == 4 ) {
      for( uint32_t i=0; i<h; i++ ) {
        uint32_t j1 = 8 * i;
        __m128i sv = _mm_set1_epi32( (int)psi_neg_monty[ h + i ] );
        __m128i u  = _mm_loadu_si128( (void const *)( out + j1 ) );
        __m128i v  = _mm_loadu_si128( (void const *)( out + j1 + 4 ) );
        _mm_storeu_si128( (void *)( out + j1     ), fq_add_sse( u, v ) );
        _mm_storeu_si128( (void *)( out + j1 + 4 ),
                          fq_mul_monty_sse( fq_sub_sse( u, v ), sv ) );
      }
    } else { /* t == 1 or 2 */
      for( uint32_t i=0; i<h; i++ ) {
        uint32_t j1 = i * dt;
        falcon_fq_t s = psi_neg_monty[ h + i ];
        for( uint32_t j=j1; j<j1+t; j++ ) {
          falcon_fq_t u = out[ j     ];
          falcon_fq_t v = out[ j + t ];
          out[ j     ] = fq_add( u, v );
          out[ j + t ] = fq_mul_monty( fq_sub( u, v ), s );
        }
      }
    }
    t = dt;
    m = h;
  }

  /* Final 1/N scaling: monty_mul(out[i], NI) = out[i] * (R/N) / R = out[i] / N mod Q. */
  __m512i niv = _mm512_set1_epi32( (int)NI_VAL );
  for( uint32_t j=0; j<(uint32_t)N; j+=16 ) {
    __m512i x = _mm512_loadu_si512( (void const *)( out + j ) );
    _mm512_storeu_si512( (void *)( out + j ), fq_mul_monty_v( x, niv ) );
  }
}

/* ---------- verify (NIST API). */

enum { NONCELEN = 40, PK_HEADER = 0x09, SIG_HEADER = 0x29 };

int
falcon_avx512_from_ref_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                 uint8_t const * sm, size_t   smlen,
                                 uint8_t const * pk ) {
  if( UNLIKELY( pk[ 0 ] != PK_HEADER ) ) return -1;
  if( UNLIKELY( smlen < 2 + NONCELEN + 1 ) ) return -1;

  size_t sig_field_len = ( (size_t)sm[ 0 ] << 8 ) | (size_t)sm[ 1 ];
  if( UNLIKELY( sig_field_len < 1 ) ) return -1;
  if( UNLIKELY( sig_field_len > smlen - 2 - NONCELEN ) ) return -1;

  size_t          msg_len = smlen - 2 - NONCELEN - sig_field_len;
  uint8_t const * nonce   = sm + 2;
  uint8_t const * msg     = sm + 2 + NONCELEN;
  uint8_t const * esig    = sm + 2 + NONCELEN + msg_len;

  if( UNLIKELY( esig[ 0 ] != SIG_HEADER ) ) return -1;

  falcon_pubkey_t    pubk[1];
  falcon_signature_t sig [1];
  if( UNLIKELY( fa512_parse_pk(      pubk,    pk + 1                  ) ) ) return -1;
  if( UNLIKELY( fa512_parse_comp_s2( sig->s2, esig + 1, sig_field_len-1 ) ) ) return -1;

  falcon_fq_t c[ N + 16 ] __attribute__((aligned(64)));
  fa512_hash_to_point( c, nonce, msg, msg_len );

  /* Convert h to Montgomery form: h_monty[i] = monty_mul(h[i], R2)
   *                                          = h[i] * R^2 / R = h[i] * R. */
  falcon_fq_t h_monty[ N ] __attribute__((aligned(64)));
  __m512i r2v = _mm512_set1_epi32( (int)R2_VAL );
  for( int i=0; i<N; i+=16 ) {
    __m512i x = _mm512_loadu_si512( (void const *)( pubk->h + i ) );
    _mm512_storeu_si512( (void *)( h_monty + i ), fq_mul_monty_v( x, r2v ) );
  }

  /* NTT both halves. */
  falcon_fq_t s2_ntt   [ N ] __attribute__((aligned(64)));
  falcon_fq_t h_ntt_m  [ N ] __attribute__((aligned(64)));
  falcon_fq_t prod     [ N ] __attribute__((aligned(64)));
  ntt_fwd_monty_avx512( s2_ntt,  sig->s2 );        /* s2 stays in regular form */
  ntt_fwd_monty_avx512( h_ntt_m, h_monty  );        /* h stays in Monty form */

  /* Hadamard: prod[i] = monty_mul(s2_ntt[i], h_ntt_m[i])
   *                   = s2_ntt[i] * (h_ntt_m[i]) / R
   *                   = s2_ntt[i] * h_ntt[i]   (regular).  */
  for( int i=0; i<N; i+=16 ) {
    __m512i a = _mm512_loadu_si512( (void const *)( s2_ntt  + i ) );
    __m512i b = _mm512_loadu_si512( (void const *)( h_ntt_m + i ) );
    _mm512_storeu_si512( (void *)( prod + i ), fq_mul_monty_v( a, b ) );
  }

  falcon_fq_t pmm[ N ] __attribute__((aligned(64)));
  ntt_inv_monty_avx512( pmm, prod );

  if( !fa512_norm_check_ok( c, pmm, sig ) ) return -1;

  if( m && msg_len ) memmove( m, msg, msg_len );
  if( mlen ) *mlen = msg_len;
  return 0;
}

#else /* !HAVE_AVX512 */

int
falcon_avx512_from_ref_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                 uint8_t const * sm, size_t   smlen,
                                 uint8_t const * pk ) {
  return falcon_ref_xkcp_crypto_sign_open( m, mlen, sm, smlen, pk );
}

#endif /* HAVE_AVX512 */
