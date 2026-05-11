/* falcon_avx512.c - AVX-512 implementation of Falcon-512 verification.
 *
 * Direct port of the Firedancer src/ballet/falcon code with all SIMD
 * intrinsics inlined and all internal Firedancer macros removed.  The
 * public entry point matches the NIST PQC API:
 *
 *   int falcon_avx512_barrett_crypto_sign_open( uint8_t *m, size_t *mlen,
 *                                       const uint8_t *sm, size_t smlen,
 *                                       const uint8_t *pk );
 *
 * SHAKE256 inside hash-to-point is delegated to the SHAKE implementation
 * shipped with the vendored reference (vendor/falcon-round3/.../shake.c)
 * via its `inner_shake256_*` API; the reference and the AVX-512 build
 * therefore use exactly the same SHAKE.  When compiled on a host without
 * AVX-512, this file's entry point delegates to the vendored reference.
 *
 * Public domain. */

#include "falcon_avx512_common.h"
#include "falcon_twiddle.h"

#if HAVE_AVX512

/* ---------- Barrett reduction (4-wide SSE u32) ----------
 *
 * Same algorithm as the AVX-512 version below, in 128-bit lanes. */

#define BARRETT_M 43687U
#define BARRETT_K 29

static inline __m128i
fq_mul_sse( __m128i a, __m128i b ) {
  const __m128i Mv        = _mm_set1_epi32( (int)BARRETT_M );
  const __m128i Qv        = _mm_set1_epi32( FALCON_Q );
  const __m128i mask_even = _mm_set1_epi64x( 0xFFFFFFFFLL );

  __m128i product = _mm_mullo_epi32( a, b );

  __m128i wide_e = _mm_mul_epu32( product, Mv );
  __m128i qest_e = _mm_srli_epi64( wide_e, BARRETT_K );

  __m128i prod_o = _mm_srli_epi64( product, 32 );
  __m128i wide_o = _mm_mul_epu32( prod_o, Mv );
  __m128i qest_o = _mm_srli_epi64( wide_o, BARRETT_K );
  __m128i qest_o_shifted = _mm_slli_epi64( qest_o, 32 );

  __m128i qest = _mm_or_si128( _mm_and_si128( qest_e, mask_even ),
                               qest_o_shifted );

  __m128i r = _mm_sub_epi32( product, _mm_mullo_epi32( qest, Qv ) );

  __m128i d    = _mm_sub_epi32( r, Qv );
  __m128i sign = _mm_srai_epi32( d, 31 );
  return _mm_add_epi32( d, _mm_and_si128( Qv, sign ) );
}

/* ---------- Barrett reduction (8-wide AVX2 u32) ---------- */

static inline __m256i
fq_mul_avx2( __m256i a, __m256i b ) {
  const __m256i Mv        = _mm256_set1_epi32( (int)BARRETT_M );
  const __m256i Qv        = _mm256_set1_epi32( FALCON_Q );
  const __m256i mask_even = _mm256_set1_epi64x( 0xFFFFFFFFLL );

  __m256i product = _mm256_mullo_epi32( a, b );

  __m256i wide_e = _mm256_mul_epu32( product, Mv );
  __m256i qest_e = _mm256_srli_epi64( wide_e, BARRETT_K );

  __m256i prod_o = _mm256_srli_epi64( product, 32 );
  __m256i wide_o = _mm256_mul_epu32( prod_o, Mv );
  __m256i qest_o = _mm256_srli_epi64( wide_o, BARRETT_K );
  __m256i qest_o_shifted = _mm256_slli_epi64( qest_o, 32 );

  __m256i qest = _mm256_or_si256( _mm256_and_si256( qest_e, mask_even ),
                                  qest_o_shifted );

  __m256i r = _mm256_sub_epi32( product, _mm256_mullo_epi32( qest, Qv ) );

  __m256i d    = _mm256_sub_epi32( r, Qv );
  __m256i sign = _mm256_srai_epi32( d, 31 );
  return _mm256_add_epi32( d, _mm256_and_si256( Qv, sign ) );
}

/* ---------- Barrett reduction (AVX-512 16-wide u32) ----------
 *
 *   M       = floor(2^29 / Q) = 43687
 *   q_hat   = floor( p * M / 2^29 )
 *   r       = p - q_hat * Q
 *
 * AVX-512 has no 32-bit multiply-high, so the wide multiply is split into
 * even and odd lanes via vpmuludq (low) and a 32-bit shift to align odd
 * lanes for a second vpmuludq.  The two halves are then recombined. */

static inline __m512i
fq_mul_v( __m512i a, __m512i b ) {
  const __m512i Mv = _mm512_set1_epi32( (int)BARRETT_M );
  const __m512i Qv = _mm512_set1_epi32( Q );
  const __m512i mask_even = _mm512_set1_epi64( 0xFFFFFFFFLL );

  __m512i product = _mm512_mullo_epi32( a, b );

  __m512i wide_e = _mm512_mul_epu32( product, Mv );          /* even-lane wide product */
  __m512i qest_e = _mm512_srli_epi64( wide_e, BARRETT_K );

  __m512i prod_o = _mm512_srli_epi64( product, 32 );          /* odd lanes -> even */
  __m512i wide_o = _mm512_mul_epu32( prod_o, Mv );
  __m512i qest_o = _mm512_srli_epi64( wide_o, BARRETT_K );
  __m512i qest_o_shifted = _mm512_slli_epi64( qest_o, 32 );

  __m512i qest = _mm512_or_si512( _mm512_and_si512( qest_e, mask_even ),
                                  qest_o_shifted );

  __m512i r = _mm512_sub_epi32( product, _mm512_mullo_epi32( qest, Qv ) );

  __m512i d    = _mm512_sub_epi32( r, Qv );
  __m512i sign = _mm512_srai_epi32( d, 31 );
  return _mm512_add_epi32( d, _mm512_and_si512( Qv, sign ) );
}

/* ---------- NTT (forward), lazy reduction ----------
 *
 * Each butterfly:  u' = u + v*s,    v' = u - v*s + Q
 * After k passes, all elements satisfy 0 <= x < (k+1)*Q. */

static void
ntt_fwd_avx512( falcon_fq_t * out, falcon_fq_t const * in ) {
  memcpy( out, in, sizeof(falcon_fq_t) * N );

  const __m512i Qv512 = _mm512_set1_epi32( Q );
  const __m128i Qv128 = _mm_set1_epi32( Q );

  uint32_t t = N;
  uint32_t m = 1;
  while( m < N ) {
    t >>= 1;

    if( t >= 16 ) {
      /* AVX-512: 16 lanes per butterfly. */
      for( uint32_t i=0; i<m; i++ ) {
        uint32_t j1 = 2 * i * t;
        __m512i sv = _mm512_set1_epi32( (int)falcon_psi_positive[ m + i ] );
        for( uint32_t j=j1; j<j1+t; j+=16 ) {
          __m512i u  = _mm512_loadu_si512( (void const *)( out + j ) );
          __m512i v  = fq_mul_v( _mm512_loadu_si512( (void const *)( out + j + t ) ), sv );
          _mm512_storeu_si512( (void *)( out + j     ), _mm512_add_epi32( u, v ) );
          _mm512_storeu_si512( (void *)( out + j + t ),
                               _mm512_add_epi32( _mm512_sub_epi32( u, v ), Qv512 ) );
        }
      }
    } else if( t == 8 ) {
      /* AVX2: 8 lanes per butterfly. */
      const __m256i Qv256 = _mm256_set1_epi32( Q );
      for( uint32_t i=0; i<m; i++ ) {
        uint32_t j1 = 2 * i * t;
        __m256i sv = _mm256_set1_epi32( (int)falcon_psi_positive[ m + i ] );
        __m256i u  = _mm256_loadu_si256( (void const *)( out + j1 ) );
        __m256i v  = fq_mul_avx2( _mm256_loadu_si256( (void const *)( out + j1 + t ) ), sv );
        _mm256_storeu_si256( (void *)( out + j1     ), _mm256_add_epi32( u, v ) );
        _mm256_storeu_si256( (void *)( out + j1 + t ),
                             _mm256_add_epi32( _mm256_sub_epi32( u, v ), Qv256 ) );
      }
    } else if( t == 4 ) {
      /* SSE: 4 lanes, one butterfly per iteration. */
      for( uint32_t i=0; i<m; i++ ) {
        uint32_t j1 = 8 * i;
        __m128i sv = _mm_set1_epi32( (int)falcon_psi_positive[ m + i ] );
        __m128i u  = _mm_loadu_si128( (void const *)( out + j1 ) );
        __m128i v  = fq_mul_sse( _mm_loadu_si128( (void const *)( out + j1 + 4 ) ), sv );
        _mm_storeu_si128( (void *)( out + j1     ), _mm_add_epi32( u, v ) );
        _mm_storeu_si128( (void *)( out + j1 + 4 ),
                          _mm_add_epi32( _mm_sub_epi32( u, v ), Qv128 ) );
      }
    } else if( t == 2 ) {
      /* SSE: load two registers (8 elements = two butterflies), transpose
         into u and v halves, butterfly, transpose back. */
      for( uint32_t i=0; i<m; i+=2 ) {
        uint32_t j1 = 4 * i;
        __m128i d0 = _mm_loadu_si128( (void const *)( out + j1     ) );
        __m128i d1 = _mm_loadu_si128( (void const *)( out + j1 + 4 ) );
        __m128i u  = _mm_unpacklo_epi64( d0, d1 );
        __m128i v  = _mm_unpackhi_epi64( d0, d1 );
        uint32_t s0 = falcon_psi_positive[ m + i     ];
        uint32_t s1 = falcon_psi_positive[ m + i + 1 ];
        __m128i sv = _mm_setr_epi32( (int)s0, (int)s0, (int)s1, (int)s1 );
        __m128i vs   = fq_mul_sse( v, sv );
        __m128i ru   = _mm_add_epi32( u, vs );
        __m128i rv   = _mm_add_epi32( _mm_sub_epi32( u, vs ), Qv128 );
        __m128i o0   = _mm_unpacklo_epi64( ru, rv );
        __m128i o1   = _mm_unpackhi_epi64( ru, rv );
        _mm_storeu_si128( (void *)( out + j1     ), o0 );
        _mm_storeu_si128( (void *)( out + j1 + 4 ), o1 );
      }
    } else { /* t == 1 */
      /* SSE: load 8 elements = 4 butterflies; deinterleave with permute and transpose. */
      for( uint32_t i=0; i<m; i+=4 ) {
        __m128i d0  = _mm_loadu_si128( (void const *)( out + 2*i     ) );
        __m128i d1  = _mm_loadu_si128( (void const *)( out + 2*i + 4 ) );
        __m128i d0s = _mm_shuffle_epi32( d0, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        __m128i d1s = _mm_shuffle_epi32( d1, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        __m128i u   = _mm_unpacklo_epi64( d0s, d1s );
        __m128i v   = _mm_unpackhi_epi64( d0s, d1s );
        __m128i sv  = _mm_loadu_si128( (void const *)( falcon_psi_positive + m + i ) );
        __m128i vs   = fq_mul_sse( v, sv );
        __m128i ru   = _mm_add_epi32( u, vs );
        __m128i rv   = _mm_add_epi32( _mm_sub_epi32( u, vs ), Qv128 );
        __m128i o0   = _mm_unpacklo_epi64( ru, rv );
        __m128i o1   = _mm_unpackhi_epi64( ru, rv );
        o0 = _mm_shuffle_epi32( o0, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        o1 = _mm_shuffle_epi32( o1, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        _mm_storeu_si128( (void *)( out + 2*i     ), o0 );
        _mm_storeu_si128( (void *)( out + 2*i + 4 ), o1 );
      }
    }
    m <<= 1;
  }

  /* Final pass: reduce all elements to [0, Q) by multiplying by 1. */
  __m512i one = _mm512_set1_epi32( 1 );
  for( uint32_t j=0; j<(uint32_t)N; j+=16 ) {
    __m512i x = _mm512_loadu_si512( (void const *)( out + j ) );
    _mm512_storeu_si512( (void *)( out + j ), fq_mul_v( x, one ) );
  }
}

/* ---------- inverse NTT, lazy reduction ----------
 *
 * Inverse butterfly:  u' = u + v,    v' = (u - v + off) * s
 * off = off_q * Q ensures positivity.  The bound on u' doubles every pass,
 * so off_q reaches 8 after 3 passes; we then reduce u' explicitly and
 * reset off_q to 1.  This triggers at passes 3 and 7 of 9. */

static void
ntt_inv_avx512( falcon_fq_t * out, falcon_fq_t const * in ) {
  memcpy( out, in, sizeof(falcon_fq_t) * N );

  const __m512i one512 = _mm512_set1_epi32( 1 );
  const __m256i one256 = _mm256_set1_epi32( 1 );
  const __m128i one128 = _mm_set1_epi32( 1 );

  uint32_t t     = 1;
  uint32_t m     = N;
  uint32_t off_q = 1;
  while( m > 1 ) {
    uint32_t h          = m >> 1;
    uint32_t off        = off_q * Q;
    int      reduce_add = ( off_q >= 8 );

    if( t >= 16 ) {
      __m512i offv = _mm512_set1_epi32( (int)off );
      uint32_t j1 = 0;
      for( uint32_t i=0; i<h; i++ ) {
        __m512i sv = _mm512_set1_epi32( (int)falcon_psi_negative[ h + i ] );
        for( uint32_t j=j1; j<j1+t; j+=16 ) {
          __m512i u    = _mm512_loadu_si512( (void const *)( out + j ) );
          __m512i v    = _mm512_loadu_si512( (void const *)( out + j + t ) );
          __m512i sum  = _mm512_add_epi32( u, v );
          __m512i diff = fq_mul_v(
              _mm512_add_epi32( _mm512_sub_epi32( u, v ), offv ), sv );
          _mm512_storeu_si512( (void *)( out + j     ),
                               reduce_add ? fq_mul_v( sum, one512 ) : sum );
          _mm512_storeu_si512( (void *)( out + j + t ), diff );
        }
        j1 += 2 * t;
      }
    } else if( t == 8 ) {
      __m256i offv = _mm256_set1_epi32( (int)off );
      uint32_t j1 = 0;
      for( uint32_t i=0; i<h; i++ ) {
        __m256i sv = _mm256_set1_epi32( (int)falcon_psi_negative[ h + i ] );
        __m256i u  = _mm256_loadu_si256( (void const *)( out + j1 ) );
        __m256i v  = _mm256_loadu_si256( (void const *)( out + j1 + t ) );
        __m256i sum  = _mm256_add_epi32( u, v );
        __m256i diff = fq_mul_avx2( _mm256_add_epi32( _mm256_sub_epi32( u, v ), offv ), sv );
        _mm256_storeu_si256( (void *)( out + j1     ),
                             reduce_add ? fq_mul_avx2( sum, one256 ) : sum );
        _mm256_storeu_si256( (void *)( out + j1 + t ), diff );
        j1 += 2 * t;
      }
    } else if( t == 4 ) {
      __m128i offv = _mm_set1_epi32( (int)off );
      uint32_t j1 = 0;
      for( uint32_t i=0; i<h; i++ ) {
        __m128i sv = _mm_set1_epi32( (int)falcon_psi_negative[ h + i ] );
        __m128i u  = _mm_loadu_si128( (void const *)( out + j1     ) );
        __m128i v  = _mm_loadu_si128( (void const *)( out + j1 + 4 ) );
        __m128i sum  = _mm_add_epi32( u, v );
        __m128i diff = fq_mul_sse( _mm_add_epi32( _mm_sub_epi32( u, v ), offv ), sv );
        _mm_storeu_si128( (void *)( out + j1     ),
                          reduce_add ? fq_mul_sse( sum, one128 ) : sum );
        _mm_storeu_si128( (void *)( out + j1 + 4 ), diff );
        j1 += 8;
      }
    } else if( t == 2 ) {
      __m128i offv = _mm_set1_epi32( (int)off );
      uint32_t j1 = 0;
      for( uint32_t i=0; i<h; i+=2 ) {
        __m128i d0 = _mm_loadu_si128( (void const *)( out + j1     ) );
        __m128i d1 = _mm_loadu_si128( (void const *)( out + j1 + 4 ) );
        __m128i u  = _mm_unpacklo_epi64( d0, d1 );
        __m128i v  = _mm_unpackhi_epi64( d0, d1 );
        uint32_t s0 = falcon_psi_negative[ h + i     ];
        uint32_t s1 = falcon_psi_negative[ h + i + 1 ];
        __m128i sv = _mm_setr_epi32( (int)s0, (int)s0, (int)s1, (int)s1 );
        __m128i sum  = _mm_add_epi32( u, v );
        __m128i diff = fq_mul_sse( _mm_add_epi32( _mm_sub_epi32( u, v ), offv ), sv );
        if( reduce_add ) sum = fq_mul_sse( sum, one128 );
        __m128i o0 = _mm_unpacklo_epi64( sum, diff );
        __m128i o1 = _mm_unpackhi_epi64( sum, diff );
        _mm_storeu_si128( (void *)( out + j1     ), o0 );
        _mm_storeu_si128( (void *)( out + j1 + 4 ), o1 );
        j1 += 8;
      }
    } else { /* t == 1 */
      __m128i offv = _mm_set1_epi32( (int)off );
      for( uint32_t i=0; i<h; i+=4 ) {
        __m128i d0  = _mm_loadu_si128( (void const *)( out + 2*i     ) );
        __m128i d1  = _mm_loadu_si128( (void const *)( out + 2*i + 4 ) );
        __m128i d0s = _mm_shuffle_epi32( d0, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        __m128i d1s = _mm_shuffle_epi32( d1, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        __m128i u   = _mm_unpacklo_epi64( d0s, d1s );
        __m128i v   = _mm_unpackhi_epi64( d0s, d1s );
        __m128i sv  = _mm_loadu_si128( (void const *)( falcon_psi_negative + h + i ) );
        __m128i sum  = _mm_add_epi32( u, v );
        __m128i diff = fq_mul_sse( _mm_add_epi32( _mm_sub_epi32( u, v ), offv ), sv );
        if( reduce_add ) sum = fq_mul_sse( sum, one128 );
        __m128i o0 = _mm_unpacklo_epi64( sum, diff );
        __m128i o1 = _mm_unpackhi_epi64( sum, diff );
        o0 = _mm_shuffle_epi32( o0, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        o1 = _mm_shuffle_epi32( o1, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        _mm_storeu_si128( (void *)( out + 2*i     ), o0 );
        _mm_storeu_si128( (void *)( out + 2*i + 4 ), o1 );
      }
    }
    if( reduce_add ) off_q = 1; else off_q <<= 1;
    t <<= 1;
    m >>= 1;
  }

  /* Final normalization by N^{-1} mod Q.  512^{-1} mod 12289 = 12265. */
  __m512i n_inv = _mm512_set1_epi32( 12265 );
  for( uint32_t j=0; j<(uint32_t)N; j+=16 ) {
    __m512i x = _mm512_loadu_si512( (void const *)( out + j ) );
    _mm512_storeu_si512( (void *)( out + j ), fq_mul_v( x, n_inv ) );
  }
}

/* ---------- verify (NIST API).  Public-key parsing, compressed-s2
 * parsing, and hash-to-point are shared with falcon_avx512 via
 * falcon_avx512_common.h.  The two verifier flavors share parse and
 * finish via a local helper, differing only in the hash-to-point
 * called between them. */

enum { NONCELEN = 40, PK_HEADER = 0x09, SIG_HEADER = 0x29 };

static inline int
falcon_avx512_barrett_parse( uint8_t const *      sm,   size_t smlen,
                     uint8_t const *      pk,
                     falcon_pubkey_t    * pubk,
                     falcon_signature_t * sig,
                     uint8_t const **     out_nonce,
                     uint8_t const **     out_msg,
                     size_t *             out_msg_len ) {
  if( UNLIKELY( pk[ 0 ] != PK_HEADER ) )            return -1;
  if( UNLIKELY( smlen < 2 + NONCELEN + 1 ) )        return -1;

  size_t sig_field_len = ( (size_t)sm[ 0 ] << 8 ) | (size_t)sm[ 1 ];
  if( UNLIKELY( sig_field_len < 1 ) )                       return -1;
  if( UNLIKELY( sig_field_len > smlen - 2 - NONCELEN ) )    return -1;

  size_t          msg_len = smlen - 2 - NONCELEN - sig_field_len;
  uint8_t const * esig    = sm + 2 + NONCELEN + msg_len;
  if( UNLIKELY( esig[ 0 ] != SIG_HEADER ) )                 return -1;

  if( UNLIKELY( fa512_parse_pk(      pubk,    pk + 1                  ) ) ) return -1;
  if( UNLIKELY( fa512_parse_comp_s2( sig->s2, esig + 1, sig_field_len-1 ) ) ) return -1;

  *out_nonce   = sm + 2;
  *out_msg     = sm + 2 + NONCELEN;
  *out_msg_len = msg_len;
  return 0;
}

static inline int
falcon_avx512_barrett_finish( falcon_fq_t        const * c,
                      falcon_pubkey_t    const * pubk,
                      falcon_signature_t const * sig ) {
  falcon_fq_t s2_ntt[ N ] __attribute__((aligned(64)));
  falcon_fq_t h_ntt [ N ] __attribute__((aligned(64)));
  falcon_fq_t prod  [ N ] __attribute__((aligned(64)));
  ntt_fwd_avx512( s2_ntt, sig->s2 );
  ntt_fwd_avx512( h_ntt,  pubk->h );
  for( int i=0; i<N; i+=16 ) {
    __m512i a = _mm512_loadu_si512( (void const *)( s2_ntt + i ) );
    __m512i b = _mm512_loadu_si512( (void const *)( h_ntt  + i ) );
    _mm512_storeu_si512( (void *)( prod + i ), fq_mul_v( a, b ) );
  }

  falcon_fq_t pmm[ N ] __attribute__((aligned(64)));
  ntt_inv_avx512( pmm, prod );

  return fa512_norm_check_ok( c, pmm, sig );
}

int
falcon_avx512_barrett_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                uint8_t const * sm, size_t   smlen,
                                uint8_t const * pk ) {
  falcon_pubkey_t    pubk[1];
  falcon_signature_t sig [1];
  uint8_t const *    nonce;
  uint8_t const *    msg;
  size_t             msg_len;
  if( UNLIKELY( falcon_avx512_barrett_parse( sm, smlen, pk, pubk, sig,
                                     &nonce, &msg, &msg_len ) ) ) return -1;

  falcon_fq_t c[ N + 16 ] __attribute__((aligned(64)));
  fa512_hash_to_point( c, nonce, msg, msg_len );

  if( !falcon_avx512_barrett_finish( c, pubk, sig ) ) return -1;

  if( m && msg_len ) memmove( m, msg, msg_len );
  if( mlen ) *mlen = msg_len;
  return 0;
}

/* Same pipeline as `falcon_avx512_barrett_crypto_sign_open` but with the
 * SHAKE256 hash-to-point swapped for the TurboSHAKE12 + 8-way
 * parallel-squeeze variant (see falcon_ref_turbopar.c).  The resulting
 * `c` differs from standard SHAKE256 hash-to-point, so the variant
 * cannot verify Falcon round 3 signatures; it is provided so the
 * benchmark can report parallel-squeeze cost on top of the AVX-512
 * NTT pipeline. */
int
falcon_avx512_barrett_turbopar_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                         uint8_t const * sm, size_t   smlen,
                                         uint8_t const * pk ) {
  falcon_pubkey_t    pubk[1];
  falcon_signature_t sig [1];
  uint8_t const *    nonce;
  uint8_t const *    msg;
  size_t             msg_len;
  if( UNLIKELY( falcon_avx512_barrett_parse( sm, smlen, pk, pubk, sig,
                                     &nonce, &msg, &msg_len ) ) ) return -1;

  /* The turbopar hash writes 16-bit coefficients; the AVX-512 NTT
   * pipeline consumes 32-bit ones.  Hash into a 16-bit scratch then
   * zero-extend.  nonce and msg are contiguous in the signed-message
   * buffer. */
  uint16_t    c16[ N + 32 ] __attribute__((aligned(64)));
  falcon_fq_t c  [ N + 16 ] __attribute__((aligned(64)));
  fa512_hash_to_point_turbopar( c16, nonce, NONCELEN + msg_len );
  for( int i=0; i<N; i+=32 ) {
    __m512i lo = _mm512_cvtepu16_epi32( _mm256_loadu_si256( (__m256i const *)( c16 + i      ) ) );
    __m512i hi = _mm512_cvtepu16_epi32( _mm256_loadu_si256( (__m256i const *)( c16 + i + 16 ) ) );
    _mm512_storeu_si512( (void *)( c + i      ), lo );
    _mm512_storeu_si512( (void *)( c + i + 16 ), hi );
  }

  int ok = falcon_avx512_barrett_finish( c, pubk, sig );

  /* Always memmove and report msg_len -- like falcon_ref_turbopar, the
   * full pipeline runs to completion and the caller distinguishes by
   * the return code. */
  if( m && msg_len ) memmove( m, msg, msg_len );
  if( mlen ) *mlen = msg_len;
  return ok ? 0 : -1;
}

#else /* !HAVE_AVX512 */

/* Without AVX-512, delegate to the vendored reference (which uses the
 * same NIST API). */
int
falcon_avx512_barrett_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                uint8_t const * sm, size_t   smlen,
                                uint8_t const * pk ) {
  return falcon_ref_xkcp_crypto_sign_open( m, mlen, sm, smlen, pk );
}

int
falcon_avx512_barrett_turbopar_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                         uint8_t const * sm, size_t   smlen,
                                         uint8_t const * pk ) {
  return falcon_ref_xkcp_crypto_sign_open( m, mlen, sm, smlen, pk );
}

#endif /* HAVE_AVX512 */
