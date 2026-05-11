/* falcon_avx512.c - AVX-512 Falcon-512 verification, Shoup variant.
 *
 * Identical pipeline to `falcon_avx512` (parse_pk + parse_comp_s2 +
 * hash_to_point + 2 NTTs + Hadamard + 1 iNTT + norm check).  The only
 * difference is the modular multiplication used inside the NTT
 * butterflies: Barrett (one extra sequential mul on the critical path)
 * is replaced by the Shoup / Harvey precomputed-twiddle reduction.
 *
 * The reduction:
 *   - Precompute s' = floor( s * 2^32 / Q ) alongside each twiddle s.
 *   - In the butterfly, compute
 *       q_hat = (v * s') >> 32   (mul-high)
 *       r     = v * s - q_hat * Q   (mod 2^32)
 *     and one conditional subtract gives v*s mod Q in [0, Q).  See
 *     Harvey, "Faster arithmetic for NTT-based multiplication", 2014.
 *
 * Critical-path comparison per butterfly (Skylake-SP latencies):
 *
 *   Barrett (this work):  vpmullo[10] -> vpmuludq[5] -> shift+combine
 *                         -> vpmullo[10] -> sub -> cond_sub  ≈ 32 cycles
 *
 *   Shoup   (this file):  vpmuludq[5] -> shift+combine -> vpmullo[10]
 *                         -> sub -> cond_sub             ≈ 22 cycles
 *                         vpmullo(v,s)[10] runs in parallel
 *
 * The Shoup variant trades one extra twiddle-table load (s' alongside s)
 * for ~10 cycles less critical-path latency per butterfly.  Twiddle
 * tables are 4 KB total (2 KB s + 2 KB s' for each of the +/- tables),
 * comfortably in L1.
 *
 * Public domain.
 */

#include "falcon_avx512_common.h"
#include "falcon_twiddle.h"

#if HAVE_AVX512

/* Forward decl for falcon_ref to use as a fallback. */
int falcon_ref_xkcp_crypto_sign_open( uint8_t * m, size_t * mlen,
                                 uint8_t const * sm, size_t smlen,
                                 uint8_t const * pk );

/* ---------- Shoup precomputed-multiplier tables.
 *
 * s_prime_*[i] = floor( falcon_psi_*[i] * 2^32 / Q ).  These live next
 * to the original twiddles in cache (~2 KB each table). */

static falcon_fq_t s_prime_pos[ N ] __attribute__((aligned(64)));
static falcon_fq_t s_prime_neg[ N ] __attribute__((aligned(64)));

#define S_PRIME_ONE   ( (uint32_t)( ( (uint64_t)1     << 32 ) / Q ) )  /* 349525 */
#define S_PRIME_NINV  ( (uint32_t)( ( (uint64_t)12265 << 32 ) / Q ) )  /* (12265<<32)/Q */

__attribute__((constructor))
static void
init_shoup_tables( void ) {
  for( int i=0; i<N; i++ ) {
    s_prime_pos[ i ] = (uint32_t)(
        ( (uint64_t)falcon_psi_positive[ i ] << 32 ) / Q );
    s_prime_neg[ i ] = (uint32_t)(
        ( (uint64_t)falcon_psi_negative[ i ] << 32 ) / Q );
  }
}

/* ---------- Shoup field multiplication (4-wide SSE u32). */

static inline __m128i
fq_mul_shoup_sse( __m128i v, __m128i s, __m128i s_prime ) {
  const __m128i Qv      = _mm_set1_epi32( Q );
  const __m128i mask_lo = _mm_set1_epi64x( 0x00000000FFFFFFFFLL );

  __m128i wide_e = _mm_mul_epu32( v, s_prime );
  __m128i v_o    = _mm_srli_epi64( v,       32 );
  __m128i sp_o   = _mm_srli_epi64( s_prime, 32 );
  __m128i wide_o = _mm_mul_epu32( v_o, sp_o );

  __m128i q_hat_e = _mm_srli_epi64( wide_e, 32 );
  __m128i q_hat_o = _mm_andnot_si128( mask_lo, wide_o );
  __m128i q_hat   = _mm_or_si128( q_hat_e, q_hat_o );

  __m128i vs  = _mm_mullo_epi32( v, s );
  __m128i qq  = _mm_mullo_epi32( q_hat, Qv );
  __m128i r   = _mm_sub_epi32(   vs, qq );

  __m128i d    = _mm_sub_epi32( r, Qv );
  __m128i sign = _mm_srai_epi32( d, 31 );
  return _mm_add_epi32( d, _mm_and_si128( Qv, sign ) );
}

/* ---------- Shoup field multiplication (8-wide AVX2 u32). */

static inline __m256i
fq_mul_shoup_avx2( __m256i v, __m256i s, __m256i s_prime ) {
  const __m256i Qv      = _mm256_set1_epi32( Q );
  const __m256i mask_lo = _mm256_set1_epi64x( 0x00000000FFFFFFFFLL );

  __m256i wide_e = _mm256_mul_epu32( v, s_prime );
  __m256i v_o    = _mm256_srli_epi64( v,       32 );
  __m256i sp_o   = _mm256_srli_epi64( s_prime, 32 );
  __m256i wide_o = _mm256_mul_epu32( v_o, sp_o );

  __m256i q_hat_e = _mm256_srli_epi64( wide_e, 32 );
  __m256i q_hat_o = _mm256_andnot_si256( mask_lo, wide_o );
  __m256i q_hat   = _mm256_or_si256( q_hat_e, q_hat_o );

  __m256i vs  = _mm256_mullo_epi32( v, s );
  __m256i qq  = _mm256_mullo_epi32( q_hat, Qv );
  __m256i r   = _mm256_sub_epi32(   vs, qq );

  __m256i d    = _mm256_sub_epi32( r, Qv );
  __m256i sign = _mm256_srai_epi32( d, 31 );
  return _mm256_add_epi32( d, _mm256_and_si256( Qv, sign ) );
}

/* ---------- Shoup field multiplication (16-wide AVX-512 u32). */

static inline __m512i
fq_mul_shoup_v( __m512i v, __m512i s, __m512i s_prime ) {
  const __m512i Qv      = _mm512_set1_epi32( Q );
  const __m512i mask_lo = _mm512_set1_epi64( 0x00000000FFFFFFFFLL );

  __m512i wide_e = _mm512_mul_epu32( v, s_prime );
  __m512i v_o    = _mm512_srli_epi64( v,       32 );
  __m512i sp_o   = _mm512_srli_epi64( s_prime, 32 );
  __m512i wide_o = _mm512_mul_epu32( v_o, sp_o );

  __m512i q_hat_e = _mm512_srli_epi64( wide_e, 32 );
  __m512i q_hat_o = _mm512_andnot_si512( mask_lo, wide_o );
  __m512i q_hat   = _mm512_or_si512( q_hat_e, q_hat_o );

  __m512i vs  = _mm512_mullo_epi32( v, s );
  __m512i qq  = _mm512_mullo_epi32( q_hat, Qv );
  __m512i r   = _mm512_sub_epi32(   vs, qq );

  /* r in [0, 2Q); fold to [0, Q) via masked subtract.  Equivalent to
   * `d=r-Q; r=d>=0?d:r` but emits one cmp + one masked vpsubd, which
   * is faster than the arithmetic-shift correction on both clang and
   * gcc (Zen4/5, AVX-512). */
  __mmask16 ge = _mm512_cmpge_epu32_mask( r, Qv );
  return _mm512_mask_sub_epi32( r, ge, r, Qv );
}

/* ---------- forward NTT, Shoup multiplication. */

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
      for( uint32_t i=0; i<m; i++ ) {
        uint32_t j1 = 2 * i * t;
        __m512i sv  = _mm512_set1_epi32( (int)falcon_psi_positive[ m + i ] );
        __m512i spv = _mm512_set1_epi32( (int)s_prime_pos        [ m + i ] );
        for( uint32_t j=j1; j<j1+t; j+=16 ) {
          __m512i u = _mm512_loadu_si512( (void const *)( out + j ) );
          __m512i v = fq_mul_shoup_v( _mm512_loadu_si512( (void const *)( out + j + t ) ), sv, spv );
          _mm512_storeu_si512( (void *)( out + j     ), _mm512_add_epi32( u, v ) );
          _mm512_storeu_si512( (void *)( out + j + t ),
                               _mm512_add_epi32( _mm512_sub_epi32( u, v ), Qv512 ) );
        }
      }
    } else if( t == 8 ) {
      const __m256i Qv256 = _mm256_set1_epi32( Q );
      for( uint32_t i=0; i<m; i++ ) {
        uint32_t j1 = 2 * i * t;
        __m256i sv  = _mm256_set1_epi32( (int)falcon_psi_positive[ m + i ] );
        __m256i spv = _mm256_set1_epi32( (int)s_prime_pos        [ m + i ] );
        __m256i u   = _mm256_loadu_si256( (void const *)( out + j1 ) );
        __m256i v   = fq_mul_shoup_avx2( _mm256_loadu_si256( (void const *)( out + j1 + t ) ), sv, spv );
        _mm256_storeu_si256( (void *)( out + j1     ), _mm256_add_epi32( u, v ) );
        _mm256_storeu_si256( (void *)( out + j1 + t ),
                             _mm256_add_epi32( _mm256_sub_epi32( u, v ), Qv256 ) );
      }
    } else if( t == 4 ) {
      for( uint32_t i=0; i<m; i++ ) {
        uint32_t j1 = 8 * i;
        __m128i sv  = _mm_set1_epi32( (int)falcon_psi_positive[ m + i ] );
        __m128i spv = _mm_set1_epi32( (int)s_prime_pos        [ m + i ] );
        __m128i u   = _mm_loadu_si128( (void const *)( out + j1 ) );
        __m128i v   = fq_mul_shoup_sse( _mm_loadu_si128( (void const *)( out + j1 + 4 ) ), sv, spv );
        _mm_storeu_si128( (void *)( out + j1     ), _mm_add_epi32( u, v ) );
        _mm_storeu_si128( (void *)( out + j1 + 4 ),
                          _mm_add_epi32( _mm_sub_epi32( u, v ), Qv128 ) );
      }
    } else if( t == 2 ) {
      for( uint32_t i=0; i<m; i+=2 ) {
        uint32_t j1 = 4 * i;
        __m128i d0 = _mm_loadu_si128( (void const *)( out + j1     ) );
        __m128i d1 = _mm_loadu_si128( (void const *)( out + j1 + 4 ) );
        __m128i u  = _mm_unpacklo_epi64( d0, d1 );
        __m128i v  = _mm_unpackhi_epi64( d0, d1 );
        uint32_t s0  = falcon_psi_positive[ m + i     ];
        uint32_t s1  = falcon_psi_positive[ m + i + 1 ];
        uint32_t sp0 = s_prime_pos        [ m + i     ];
        uint32_t sp1 = s_prime_pos        [ m + i + 1 ];
        __m128i sv  = _mm_setr_epi32( (int)s0,  (int)s0,  (int)s1,  (int)s1 );
        __m128i spv = _mm_setr_epi32( (int)sp0, (int)sp0, (int)sp1, (int)sp1 );
        __m128i vs  = fq_mul_shoup_sse( v, sv, spv );
        __m128i ru  = _mm_add_epi32( u, vs );
        __m128i rv  = _mm_add_epi32( _mm_sub_epi32( u, vs ), Qv128 );
        __m128i o0  = _mm_unpacklo_epi64( ru, rv );
        __m128i o1  = _mm_unpackhi_epi64( ru, rv );
        _mm_storeu_si128( (void *)( out + j1     ), o0 );
        _mm_storeu_si128( (void *)( out + j1 + 4 ), o1 );
      }
    } else { /* t == 1 */
      for( uint32_t i=0; i<m; i+=4 ) {
        __m128i d0  = _mm_loadu_si128( (void const *)( out + 2*i     ) );
        __m128i d1  = _mm_loadu_si128( (void const *)( out + 2*i + 4 ) );
        __m128i d0s = _mm_shuffle_epi32( d0, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        __m128i d1s = _mm_shuffle_epi32( d1, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        __m128i u   = _mm_unpacklo_epi64( d0s, d1s );
        __m128i v   = _mm_unpackhi_epi64( d0s, d1s );
        __m128i sv  = _mm_loadu_si128( (void const *)( falcon_psi_positive + m + i ) );
        __m128i spv = _mm_loadu_si128( (void const *)( s_prime_pos         + m + i ) );
        __m128i vs  = fq_mul_shoup_sse( v, sv, spv );
        __m128i ru  = _mm_add_epi32( u, vs );
        __m128i rv  = _mm_add_epi32( _mm_sub_epi32( u, vs ), Qv128 );
        __m128i o0  = _mm_unpacklo_epi64( ru, rv );
        __m128i o1  = _mm_unpackhi_epi64( ru, rv );
        o0 = _mm_shuffle_epi32( o0, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        o1 = _mm_shuffle_epi32( o1, _MM_SHUFFLE( 3, 1, 2, 0 ) );
        _mm_storeu_si128( (void *)( out + 2*i     ), o0 );
        _mm_storeu_si128( (void *)( out + 2*i + 4 ), o1 );
      }
    }
    m <<= 1;
  }

  /* Final reduction by 1 (Shoup with s'=floor(2^32/Q)). */
  __m512i one  = _mm512_set1_epi32( 1 );
  __m512i pone = _mm512_set1_epi32( (int)S_PRIME_ONE );
  for( uint32_t j=0; j<(uint32_t)N; j+=16 ) {
    __m512i x = _mm512_loadu_si512( (void const *)( out + j ) );
    _mm512_storeu_si512( (void *)( out + j ), fq_mul_shoup_v( x, one, pone ) );
  }
}

/* ---------- inverse NTT, Shoup multiplication. */

static void
ntt_inv_avx512( falcon_fq_t * out, falcon_fq_t const * in ) {
  memcpy( out, in, sizeof(falcon_fq_t) * N );

  const __m512i one512  = _mm512_set1_epi32( 1 );
  const __m256i one256  = _mm256_set1_epi32( 1 );
  const __m128i one128  = _mm_set1_epi32( 1 );
  const __m512i pone512 = _mm512_set1_epi32( (int)S_PRIME_ONE );
  const __m256i pone256 = _mm256_set1_epi32( (int)S_PRIME_ONE );
  const __m128i pone128 = _mm_set1_epi32(    (int)S_PRIME_ONE );

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
        __m512i sv  = _mm512_set1_epi32( (int)falcon_psi_negative[ h + i ] );
        __m512i spv = _mm512_set1_epi32( (int)s_prime_neg        [ h + i ] );
        for( uint32_t j=j1; j<j1+t; j+=16 ) {
          __m512i u    = _mm512_loadu_si512( (void const *)( out + j ) );
          __m512i v    = _mm512_loadu_si512( (void const *)( out + j + t ) );
          __m512i sum  = _mm512_add_epi32( u, v );
          __m512i diff = fq_mul_shoup_v(
              _mm512_add_epi32( _mm512_sub_epi32( u, v ), offv ), sv, spv );
          _mm512_storeu_si512( (void *)( out + j     ),
                               reduce_add ? fq_mul_shoup_v( sum, one512, pone512 ) : sum );
          _mm512_storeu_si512( (void *)( out + j + t ), diff );
        }
        j1 += 2 * t;
      }
    } else if( t == 8 ) {
      __m256i offv = _mm256_set1_epi32( (int)off );
      uint32_t j1 = 0;
      for( uint32_t i=0; i<h; i++ ) {
        __m256i sv  = _mm256_set1_epi32( (int)falcon_psi_negative[ h + i ] );
        __m256i spv = _mm256_set1_epi32( (int)s_prime_neg        [ h + i ] );
        __m256i u    = _mm256_loadu_si256( (void const *)( out + j1 ) );
        __m256i v    = _mm256_loadu_si256( (void const *)( out + j1 + t ) );
        __m256i sum  = _mm256_add_epi32( u, v );
        __m256i diff = fq_mul_shoup_avx2( _mm256_add_epi32( _mm256_sub_epi32( u, v ), offv ), sv, spv );
        _mm256_storeu_si256( (void *)( out + j1     ),
                             reduce_add ? fq_mul_shoup_avx2( sum, one256, pone256 ) : sum );
        _mm256_storeu_si256( (void *)( out + j1 + t ), diff );
        j1 += 2 * t;
      }
    } else if( t == 4 ) {
      __m128i offv = _mm_set1_epi32( (int)off );
      uint32_t j1 = 0;
      for( uint32_t i=0; i<h; i++ ) {
        __m128i sv  = _mm_set1_epi32( (int)falcon_psi_negative[ h + i ] );
        __m128i spv = _mm_set1_epi32( (int)s_prime_neg        [ h + i ] );
        __m128i u    = _mm_loadu_si128( (void const *)( out + j1     ) );
        __m128i v    = _mm_loadu_si128( (void const *)( out + j1 + 4 ) );
        __m128i sum  = _mm_add_epi32( u, v );
        __m128i diff = fq_mul_shoup_sse( _mm_add_epi32( _mm_sub_epi32( u, v ), offv ), sv, spv );
        _mm_storeu_si128( (void *)( out + j1     ),
                          reduce_add ? fq_mul_shoup_sse( sum, one128, pone128 ) : sum );
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
        uint32_t s0  = falcon_psi_negative[ h + i     ];
        uint32_t s1  = falcon_psi_negative[ h + i + 1 ];
        uint32_t sp0 = s_prime_neg        [ h + i     ];
        uint32_t sp1 = s_prime_neg        [ h + i + 1 ];
        __m128i sv  = _mm_setr_epi32( (int)s0,  (int)s0,  (int)s1,  (int)s1 );
        __m128i spv = _mm_setr_epi32( (int)sp0, (int)sp0, (int)sp1, (int)sp1 );
        __m128i sum  = _mm_add_epi32( u, v );
        __m128i diff = fq_mul_shoup_sse( _mm_add_epi32( _mm_sub_epi32( u, v ), offv ), sv, spv );
        if( reduce_add ) sum = fq_mul_shoup_sse( sum, one128, pone128 );
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
        __m128i spv = _mm_loadu_si128( (void const *)( s_prime_neg         + h + i ) );
        __m128i sum  = _mm_add_epi32( u, v );
        __m128i diff = fq_mul_shoup_sse( _mm_add_epi32( _mm_sub_epi32( u, v ), offv ), sv, spv );
        if( reduce_add ) sum = fq_mul_shoup_sse( sum, one128, pone128 );
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

  /* Final normalization by N^{-1} = 12265, with its precomputed s'. */
  __m512i n_inv  = _mm512_set1_epi32( 12265 );
  __m512i n_invp = _mm512_set1_epi32( (int)S_PRIME_NINV );
  for( uint32_t j=0; j<(uint32_t)N; j+=16 ) {
    __m512i x = _mm512_loadu_si512( (void const *)( out + j ) );
    _mm512_storeu_si512( (void *)( out + j ), fq_mul_shoup_v( x, n_inv, n_invp ) );
  }
}

/* ---------- verify (NIST API).  Same shell as falcon_avx512; only the
 * fq multiplication used inside the NTTs and Hadamard differs.  The
 * standard and KTP256 variants share parse + finish via local
 * helpers, differing only in the hash-to-point call between them. */

enum { NONCELEN = 40, PK_HEADER = 0x09, SIG_HEADER = 0x29 };

int
falcon_avx512_parse( uint8_t const *      sm,   size_t smlen,
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

int
falcon_avx512_finish( falcon_fq_t        const * c,
                      falcon_pubkey_t    const * pubk,
                      falcon_signature_t const * sig ) {
  falcon_fq_t s2_ntt[ N ] __attribute__((aligned(64)));
  falcon_fq_t h_ntt [ N ] __attribute__((aligned(64)));
  falcon_fq_t prod  [ N ] __attribute__((aligned(64)));
  ntt_fwd_avx512( s2_ntt, sig->s2 );
  ntt_fwd_avx512( h_ntt,  pubk->h );
  /* Hadamard: a*b mod Q.  Neither operand has a precomputed s', so we
     materialize one for b on the fly.  Use plain Barrett mul here --
     just for the Hadamard, NOT inside the NTT.  Three NTT passes
     contain ~6912 butterflies while the Hadamard is only 512 lane
     multiplies. */
  for( int i=0; i<N; i+=16 ) {
    __m512i a = _mm512_loadu_si512( (void const *)( s2_ntt + i ) );
    __m512i b = _mm512_loadu_si512( (void const *)( h_ntt  + i ) );
    __m512i Mv  = _mm512_set1_epi32( (int)43687U );
    __m512i Qv  = _mm512_set1_epi32( Q );
    __m512i mask_e = _mm512_set1_epi64( 0xFFFFFFFFLL );
    __m512i product = _mm512_mullo_epi32( a, b );
    __m512i wide_e = _mm512_mul_epu32( product, Mv );
    __m512i qest_e = _mm512_srli_epi64( wide_e, 29 );
    __m512i prod_o = _mm512_srli_epi64( product, 32 );
    __m512i wide_o = _mm512_mul_epu32( prod_o, Mv );
    __m512i qest_o = _mm512_srli_epi64( wide_o, 29 );
    __m512i qest_o_s = _mm512_slli_epi64( qest_o, 32 );
    __m512i qest = _mm512_or_si512( _mm512_and_si512( qest_e, mask_e ), qest_o_s );
    __m512i r = _mm512_sub_epi32( product, _mm512_mullo_epi32( qest, Qv ) );
    __m512i d    = _mm512_sub_epi32( r, Qv );
    __m512i sign = _mm512_srai_epi32( d, 31 );
    _mm512_storeu_si512( (void *)( prod + i ),
                         _mm512_add_epi32( d, _mm512_and_si512( Qv, sign ) ) );
  }

  falcon_fq_t pmm[ N ] __attribute__((aligned(64)));
  ntt_inv_avx512( pmm, prod );

  return fa512_norm_check_ok( c, pmm, sig );
}

int
falcon_avx512_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                 uint8_t const * sm, size_t   smlen,
                                 uint8_t const * pk ) {
  falcon_pubkey_t    pubk[1];
  falcon_signature_t sig [1];
  uint8_t const *    nonce;
  uint8_t const *    msg;
  size_t             msg_len;
  if( UNLIKELY( falcon_avx512_parse( sm, smlen, pk, pubk, sig,
                                      &nonce, &msg, &msg_len ) ) ) return -1;

  falcon_fq_t c[ N + 16 ] __attribute__((aligned(64)));
  fa512_hash_to_point( c, nonce, msg, msg_len );

  if( !falcon_avx512_finish( c, pubk, sig ) ) return -1;

  if( m && msg_len ) memmove( m, msg, msg_len );
  if( mlen ) *mlen = msg_len;
  return 0;
}

/* Same pipeline as `falcon_avx512_crypto_sign_open` but with the
 * SHAKE256 hash-to-point swapped for the TurboSHAKE12 + 8-way
 * parallel-squeeze variant.  Cannot verify standard Falcon round 3
 * signatures; provided for parallel-squeeze benchmarking on top of the
 * Shoup AVX-512 NTT pipeline. */
int
falcon_avx512_ktp256_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk ) {
  falcon_pubkey_t    pubk[1];
  falcon_signature_t sig [1];
  uint8_t const *    nonce;
  uint8_t const *    msg;
  size_t             msg_len;
  if( UNLIKELY( falcon_avx512_parse( sm, smlen, pk, pubk, sig,
                                      &nonce, &msg, &msg_len ) ) ) return -1;

  /* See falcon_avx512_barrett_ktp256_crypto_sign_open for the rationale on
   * the uint16->uint32 expansion. */
  uint16_t    c16[ N + 32 ] __attribute__((aligned(64)));
  falcon_fq_t c  [ N + 16 ] __attribute__((aligned(64)));
  fa512_hash_to_point_ktp256( c16, nonce, NONCELEN + msg_len );
  for( int i=0; i<N; i+=32 ) {
    __m512i lo = _mm512_cvtepu16_epi32( _mm256_loadu_si256( (__m256i const *)( c16 + i      ) ) );
    __m512i hi = _mm512_cvtepu16_epi32( _mm256_loadu_si256( (__m256i const *)( c16 + i + 16 ) ) );
    _mm512_storeu_si512( (void *)( c + i      ), lo );
    _mm512_storeu_si512( (void *)( c + i + 16 ), hi );
  }

  int ok = falcon_avx512_finish( c, pubk, sig );

  if( m && msg_len ) memmove( m, msg, msg_len );
  if( mlen ) *mlen = msg_len;
  return ok ? 0 : -1;
}

/* ---------- bench helpers.  Public wrappers around the file-local
 * AVX-512 primitives so the subcomponent benchmark can time each
 * piece (FFT, iFFT, mul-and-norm) in isolation. */

void
falcon_avx512_bench_fft( falcon_fq_t * out, falcon_fq_t const * in ) {
  ntt_fwd_avx512( out, in );
}

void
falcon_avx512_bench_ifft( falcon_fq_t * out, falcon_fq_t const * in ) {
  ntt_inv_avx512( out, in );
}

int
falcon_avx512_bench_mul( falcon_fq_t        const * c,
                          falcon_pubkey_t    const * pubk,
                          falcon_signature_t const * sig ) {
  return falcon_avx512_finish( c, pubk, sig );
}

#else /* !HAVE_AVX512 */

int
falcon_avx512_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                 uint8_t const * sm, size_t   smlen,
                                 uint8_t const * pk ) {
  return falcon_ref_xkcp_crypto_sign_open( m, mlen, sm, smlen, pk );
}

int
falcon_avx512_ktp256_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                          uint8_t const * sm, size_t   smlen,
                                          uint8_t const * pk ) {
  return falcon_ref_xkcp_crypto_sign_open( m, mlen, sm, smlen, pk );
}

/* No-AVX-512 stubs for the bench helpers.  They simply do nothing so
 * the harness still links; the bench output will then reflect the cost
 * of an empty call (which is a clear signal something is off). */
void falcon_avx512_bench_fft ( void * out, void const * in ) { (void)out; (void)in; }
void falcon_avx512_bench_ifft( void * out, void const * in ) { (void)out; (void)in; }
int  falcon_avx512_bench_mul ( void const * c, void const * pubk, void const * sig ) {
  (void)c; (void)pubk; (void)sig; return 0;
}

#endif /* HAVE_AVX512 */
