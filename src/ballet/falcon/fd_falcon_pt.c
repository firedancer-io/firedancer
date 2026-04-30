/* falcon-pt: experimental Falcon-512 verify variant where the SHAKE256
   used by hash_to_point is replaced by Keccak-p[1600,12] (= KangarooTwelve
   round count) with COUNTER-MODE PARALLEL squeeze (lthash2-style).

   This is NOT a standards-compatible Falcon — it changes the hash that
   produces the challenge polynomial c, so signatures generated with
   stock Falcon won't verify.  Built only to measure the speedup we'd get
   from K12 + AVX-512 parallel squeeze on the hash_to_point inner loop. */

#include "fd_falcon.h"

/* fd_falcon.c keeps these as TU-local macros; mirror them (must match). */
#define Q    12289
#define N    512
#define K    5                       /* (1 << 16) / Q */

#include "fd_falcon_fq.h"            /* static-inline fd_falcon_fq_fft / _ifft */
#include "../keccak256/fd_keccak256.h"

#if FD_HAS_AVX512
#include "../keccak256/fd_keccak256_avx512_internal.h"
#include <immintrin.h>
#endif

#include <string.h>

extern ulong const fd_keccak256_rc[24];

#if FD_HAS_AVX512

/* ---- Absorb (scalar K12 perms, like lthash2's fd_lthash2_absorb_1) ----- */

#define PT_RATE_LANES    17UL          /* 1088 bits = 17 * 64 */
#define PT_RATE_BYTES   136UL
#define PT_PAD_DSBYTE   0x07           /* K12 domain separator */

static void
falcon_pt_absorb( ulong         state[25],
                  uchar const * data1, ulong len1,
                  uchar const * data2, ulong len2 ) {
  /* Accumulate two contiguous spans (nonce, msg) into the rate buffer. */
  uchar buf[ PT_RATE_BYTES ] __attribute__((aligned(64)));
  ulong off = 0;

  /* Helper: feed `n` bytes from `p` into the absorb state. */
  uchar const * srcs[2] = { data1, data2 };
  ulong         lens[2] = { len1,  len2  };
  for( int s=0; s<2; s++ ) {
    uchar const * p = srcs[s];
    ulong rem = lens[s];
    while( rem > 0 ) {
      ulong take = PT_RATE_BYTES - off;
      if( take > rem ) take = rem;
      memcpy( buf + off, p, take );
      off += take;
      p   += take;
      rem -= take;
      if( off == PT_RATE_BYTES ) {
        for( ulong z=0; z<PT_RATE_LANES; z++ ) {
          ulong w; memcpy( &w, buf + 8*z, 8 );
          state[ z ] ^= w;
        }
        fd_keccak256_avx512_keccak1_f1600_12r( state, fd_keccak256_rc );
        off = 0;
      }
    }
  }
  /* Final partial block: zero-pad, dom-sep, trailing bit. */
  memset( buf + off, 0, PT_RATE_BYTES - off );
  buf[ off                  ] ^= PT_PAD_DSBYTE;
  buf[ PT_RATE_BYTES - 1    ] ^= 0x80;
  for( ulong z=0; z<PT_RATE_LANES; z++ ) {
    ulong w; memcpy( &w, buf + 8*z, 8 );
    state[ z ] ^= w;
  }
  fd_keccak256_avx512_keccak1_f1600_12r( state, fd_keccak256_rc );
}

/* ---- Parallel counter-mode squeeze (8-wide via keccak8 batch) -----------
   Squeezes 8 rate-blocks (8 * 136 = 1088 B) in one keccak8 12r call.
   Counter goes into capacity lane 17 (analogous to lthash2). */

#define PT_CTR_LANE     17

static void
falcon_pt_squeeze_8( ulong const   base_state[25],
                     ulong         ctr_base,
                     uchar       * out_concat   /* 8 * 136 = 1088 bytes contig */ ) {
  ulong soa[ 200 ] __attribute__((aligned(64)));
  fd_keccak256_avx512_keccak8_broadcast_state( soa, base_state );

  ulong ctrs[ 8 ];
  for( int s=0; s<8; s++ ) ctrs[ s ] = ctr_base + (ulong)s;
  fd_keccak256_avx512_keccak8_xor_into_lane( soa, PT_CTR_LANE, ctrs );

  fd_keccak256_avx512_keccak8_f1600_12r_raw( soa, fd_keccak256_rc );

  void * outs[ 8 ];
  for( int s=0; s<8; s++ ) outs[ s ] = out_concat + (ulong)s * PT_RATE_BYTES;
  fd_keccak256_avx512_keccak8_extract_rate( outs, soa, PT_RATE_BYTES );
}

/* ---- hash_to_point (falcon-pt variant) ----------------------------------
   Same interface as fd_falcon_hash_to_point.  Uses K12 absorb +
   counter-mode parallel squeeze of 8 blocks at a time (= 1088 B per call).
   Rejection-sampling consumes ~6% of values; 1088 B ≈ 544 16-bit words ≈
   510 accepted, so we usually need 2 batches (≈ 1020 accepted) to fill 512. */

#define C_LEN_PT (N + 16)

void
fd_falcon_pt_hash_to_point( fd_falcon_fq_t * c,
                            uchar const *    msg,
                            ulong            len,
                            uchar const *    r /* 40 bytes nonce */ ) {

  /* Absorb. */
  ulong state[ 25 ] __attribute__((aligned(64)));
  memset( state, 0, sizeof(state) );
  falcon_pt_absorb( state, r, 40UL, msg, len );

  /* Parallel-squeeze 8 blocks at a time. */
  uchar sample[ 8 * PT_RATE_BYTES ] __attribute__((aligned(64)));
  ulong  offset = sizeof(sample);
  ulong  ctr    = 0;

  for( int i=0; i<N; ) {
    if( FD_UNLIKELY( offset >= sizeof(sample) ) ) {
      falcon_pt_squeeze_8( state, ctr, sample );
      ctr    += 8;
      offset  = 0;
    }
    /* Same AVX-512 vectorized rejection-sampling kernel as the SHAKE256
       version in fd_falcon.c (16 u16's at a time, mask + compress + Barrett
       reduce mod Q).  We have the EXACT same AVX-512 setup so reuse it. */
    typedef __m512i ws_t;
    typedef __m512i wwu_t;
    ws_t s = _mm512_loadu_si512( (__m512i const *)( sample + offset ) );
    ws_t a = _mm512_srli_epi16( s, 8 );
    ws_t b = _mm512_slli_epi16( s, 8 );
    wwu_t batch = _mm512_cvtepu16_epi32( _mm512_castsi512_si256( _mm512_or_si512( a, b ) ) );

    wwu_t kv = _mm512_set1_epi32( (int)(K * Q) );
    __mmask16 mask = _mm512_cmplt_epu32_mask( batch, kv );
    wwu_t compressed = _mm512_maskz_compress_epi32( mask, batch );

    /* Barrett reduce mod Q (same constants as upstream). */
    wwu_t q = _mm512_srli_epi32( _mm512_mullo_epi32( compressed, _mm512_set1_epi32( K ) ), 16 );
    wwu_t rr = _mm512_sub_epi32( compressed, _mm512_mullo_epi32( q, _mm512_set1_epi32( Q ) ) );
    __mmask16 ov = _mm512_cmpge_epu32_mask( rr, _mm512_set1_epi32( Q ) );
    wwu_t corrected = _mm512_mask_sub_epi32( rr, ov, rr, _mm512_set1_epi32( Q ) );

    _mm512_storeu_si512( (__m512i *)(c + i), corrected );
    offset += 32;  /* consumed 16 u16's = 32 bytes */
    i += __builtin_popcount( mask );
  }
}

/* ---- Verify wrapper that uses falcon-pt hash_to_point ------------------- */

int
fd_falcon_pt_verify( uchar const *                 msg,
                     ulong                         len,
                     fd_falcon_signature_t const * sig,
                     fd_falcon_pubkey_t    const * pk ) {
  fd_falcon_fq_t c[ C_LEN_PT ] __attribute__((aligned(64)));
  fd_falcon_pt_hash_to_point( c, msg, len, sig->nonce );

  fd_falcon_fq_t s2_ntt[ N ];
  fd_falcon_fq_t h_ntt [ N ];
  fd_falcon_fq_t m_ntt [ N ];
  fd_falcon_fq_fft( s2_ntt, sig->s2 );
  fd_falcon_fq_fft( h_ntt,  pk->h );
  for( int i=0; i<N; i++ ) m_ntt[ i ] = fd_falcon_fq_mul( s2_ntt[ i ], h_ntt[ i ] );
  fd_falcon_fq_t m[ N ];
  fd_falcon_fq_ifft( m, m_ntt );

  fd_falcon_fq_t s1[ N ];
  for( int i=0; i<N; i++ ) s1[ i ] = fd_falcon_fq_sub( c[ i ], m[ i ] );

  long norm = 0L;
  for( int i=0; i<N; i++ ) {
    int v1 = (int)s1[ i ];        if( v1 > Q/2 ) v1 -= Q;
    int v2 = (int)sig->s2[ i ];   if( v2 > Q/2 ) v2 -= Q;
    norm += (long)v1 * v1 + (long)v2 * v2;
  }
  if( FD_UNLIKELY( norm > 34034726L ) ) return -1;
  return 0;
}

#endif /* FD_HAS_AVX512 */
