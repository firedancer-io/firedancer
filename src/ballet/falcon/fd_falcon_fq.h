#ifndef HEADER_fd_src_ballet_falcon_fd_falcon_fq_h
#define HEADER_fd_src_ballet_falcon_fd_falcon_fq_h

/* Implements field arithmetics over Fq = Z/12289Z.

   The FFT/IFFT use lazy reduction. The add/sub skip any modular
   reduction for most passes where the bit-width guarantee they will
   never overflow the 32-bit integer. A final Barrett reduction pass
   normalizes all elements before they are returned. */

#include "../fd_ballet_base.h"
#if FD_HAS_AVX512
#include "../../util/simd/fd_avx512.h"
#endif
#if FD_HAS_AVX
#include "../../util/simd/fd_avx.h"
#include "../../util/simd/fd_sse.h"
#endif

#include "fd_falcon_twiddle.h"

static inline fd_falcon_fq_t
fd_falcon_fq_add( fd_falcon_fq_t a,
                  fd_falcon_fq_t b ) {
  uint s = a + b;
  uint d;
  int n = __builtin_sub_overflow( s, Q, &d );
  return d + (Q * (uint)n);
}

static inline fd_falcon_fq_t
fd_falcon_fq_neg( fd_falcon_fq_t a ) {
  uint r = Q - a;
  return r * (uint)(a != 0);
}

static inline fd_falcon_fq_t
fd_falcon_fq_sub( fd_falcon_fq_t a,
                  fd_falcon_fq_t b ) {
  return fd_falcon_fq_add( a, fd_falcon_fq_neg( b ) );
}

static inline fd_falcon_fq_t
fd_falcon_fq_mul( fd_falcon_fq_t a,
                  fd_falcon_fq_t b ) {
  return (a * b) % Q;
}

#define FQ_BARRETT_M  43687U
#define FQ_BARRETT_K  29

#define FD_FALCON_FFT_BUTTERFLY(VEC, W, fq_mul) do {                  \
    VEC##_t Qv_    = VEC##_bcast( Q );                                \
    VEC##_t s_vec_ = VEC##_bcast( s );                                \
    for( uint j_=j1; j_<j1+t; j_+=(W) ) {                             \
      VEC##_t u_ = VEC##_ldu( out+j_ );                               \
      VEC##_t v_ = fq_mul( VEC##_ldu( out+j_+t ), s_vec_ );           \
      VEC##_stu( out+j_,   VEC##_add( u_, v_ ) );                     \
      VEC##_stu( out+j_+t, VEC##_add( VEC##_sub( u_, v_ ), Qv_ ) );   \
    }                                                                 \
  } while(0)

#define FD_FALCON_IFFT_BUTTERFLY(VEC, W, fq_mul) do {                                    \
    VEC##_t s_vec_ = VEC##_bcast( s );                                                   \
    VEC##_t off_v_ = VEC##_bcast( off );                                                 \
    VEC##_t one_   = VEC##_bcast( 1U );                                                  \
    for( uint j_=j1; j_<j1+t; j_+=(W) ) {                                                \
      VEC##_t u_ = VEC##_ldu( out+j_ );                                                  \
      VEC##_t v_ = VEC##_ldu( out+j_+t );                                                \
      VEC##_t sum_ = VEC##_add( u_, v_ );                                                \
      VEC##_stu( out+j_,   reduce_add ? fq_mul( sum_, one_ ) : sum_ );                   \
      VEC##_stu( out+j_+t, fq_mul( VEC##_add( VEC##_sub( u_, v_ ), off_v_ ), s_vec_ ) ); \
    }                                                                                    \
  } while(0)

#define FD_FALCON_FQ_MAP(VEC, W, fq_mul, factor) do {           \
    VEC##_t fac_ = VEC##_bcast( (factor) );                     \
    for( uint j_=0; j_<(uint)N; j_+=(W) )                       \
      VEC##_stu( out+j_, fq_mul( VEC##_ldu( out+j_ ), fac_ ) ); \
  } while(0)

#define FD_FALCON_FQ_MUL(VEC, WIDE, SIGN, NAME)                                                  \
  static inline VEC##_t                                                                          \
  fd_falcon_fq_##NAME##_add( VEC##_t a, VEC##_t b ) {                                            \
    VEC##_t s = VEC##_add( a, b );                                                               \
    VEC##_t d = VEC##_sub( s, VEC##_bcast( Q ) );                                                \
    VEC##_t mask = SIGN##_shr( d, 31 );                                                          \
    return VEC##_add( d, VEC##_and( VEC##_bcast( Q ), mask ) );                                  \
  }                                                                                              \
                                                                                                 \
  static inline VEC##_t                                                                          \
  fd_falcon_fq_##NAME##_mul( VEC##_t a, VEC##_t b ) {                                            \
    VEC##_t Mv = VEC##_bcast( FQ_BARRETT_M );                                                    \
    VEC##_t Qv = VEC##_bcast( Q );                                                               \
                                                                                                 \
    VEC##_t product = VEC##_mul( a, b );                                                         \
                                                                                                 \
    WIDE##_t wide_e = WIDE##_mul_ll( product, Mv );                                              \
    WIDE##_t qest_e = WIDE##_shr( wide_e, FQ_BARRETT_K );                                        \
                                                                                                 \
    WIDE##_t prod_odd = WIDE##_shr( product, 32 );                                               \
    WIDE##_t wide_o   = WIDE##_mul_ll( prod_odd, Mv );                                           \
    WIDE##_t qest_o   = WIDE##_shr( wide_o, FQ_BARRETT_K );                                      \
                                                                                                 \
    WIDE##_t qest_o_shifted = WIDE##_shl( qest_o, 32 );                                          \
    WIDE##_t qest = VEC##_or( VEC##_and( qest_e, WIDE##_bcast( 0xFFFFFFFF ) ), qest_o_shifted ); \
                                                                                                 \
    VEC##_t r = VEC##_sub( product, VEC##_mul( qest, Qv ) );                                     \
                                                                                                 \
    VEC##_t d    = VEC##_sub( r, Qv );                                                           \
    VEC##_t mask = SIGN##_shr( d, 31 );                                                          \
    return VEC##_add( d, VEC##_and( Qv, mask ) );                                                \
  }                                                                                              \

#if FD_HAS_AVX
FD_FALCON_FQ_MUL( vu, vv, vi, sse )
FD_FALCON_FQ_MUL( wu, wv, wi, avx )
#endif
#if FD_HAS_AVX512
FD_FALCON_FQ_MUL( wwu, wwv, wwi, avx512 )
#endif


#if FD_HAS_AVX

static inline vu_t
fd_falcon_fq_sse_neg( vu_t a ) {
  vu_t r    = vu_sub( vu_bcast( Q ), a );
  vu_t nz   = vu_xor( vu_bcast( -1 ), vu_eq( a, vu_zero() ) );
  return vu_and( r, nz );
}

static inline vu_t
fd_falcon_fq_sse_sub( vu_t a, vu_t b ) {
  return fd_falcon_fq_sse_add( a, fd_falcon_fq_sse_neg( b ) );
}

static inline wu_t
fd_falcon_fq_avx_neg( wu_t a ) {
  wu_t r  = wu_sub( wu_bcast( Q ), a );
  wu_t nz = wu_ne( a, wu_zero() );
  return wu_if( nz, r, wu_zero() );
}

static inline wu_t
fd_falcon_fq_avx_sub( wu_t a, wu_t b ) {
  return fd_falcon_fq_avx_add( a, fd_falcon_fq_avx_neg( b ) );
}

#endif /* FD_HAS_AVX */

#if FD_HAS_AVX512

static inline wwu_t
fd_falcon_fq_avx512_neg( wwu_t a ) {
  wwu_t r    = wwu_sub( wwu_bcast( Q ), a );
  int nonzero = wwu_ne( a, wwu_zero() );
  return wwu_if( nonzero, r, wwu_zero() );
}

static inline wwu_t
fd_falcon_fq_avx512_sub( wwu_t a, wwu_t b ) {
  return fd_falcon_fq_avx512_add( a, fd_falcon_fq_avx512_neg( b ) );
}

#endif /* FD_HAS_AVX512 */

/* Forward NTT. Evaluates the polynomial on the roots of X^n + 1.

   All 9 (log2(N)) butterfly passes use lazy add/sub, with the Barrett
   multiplication reducing the twiddle product to [0, Q), then unreduced
   u+vs and u-vs+Q accumulate at most +Q per pass, giving us a max of ~10Q
   after 9 passes.  The final Barrett reduction loop reduces every element
   to [0, Q).

   Algorithm 1 from https://eprint.iacr.org/2016/504.pdf. */
FD_FN_UNUSED static void
fd_falcon_fq_fft( fd_falcon_fq_t       out[ N ],
                  fd_falcon_fq_t const in [ N ] ) {
  memcpy( out, in, sizeof(fd_falcon_fq_t) * N );

  uint t = N;
  uint m = 1;
  while( m<N ) {
    t >>= 1;

    switch( t ) {
#if FD_HAS_AVX
    case 1: {
      vu_t Qv = vu_bcast( Q );
      for( uint i=0; i<m; i+=4 ) {
        vu_t d0 = vu_ldu( out + 2*i );
        vu_t d1 = vu_ldu( out + 2*i + 4 );

        vu_t d0s = vu_permute( d0, 0,2,1,3 );
        vu_t d1s = vu_permute( d1, 0,2,1,3 );

        vu_t u, v;
        vl_transpose_2x2( d0s, d1s, u, v );

        vu_t sv  = vu_ldu( fd_falcon_psi_positive + m + i );
        vu_t vs  = fd_falcon_fq_sse_mul( v, sv );

        vu_t res_u = vu_add( u, vs );
        vu_t res_v = vu_add( vu_sub( u, vs ), Qv );

        vu_t r0, r1;
        vl_transpose_2x2( res_u, res_v, r0, r1 );
        r0 = vu_permute( r0, 0,2,1,3 );
        r1 = vu_permute( r1, 0,2,1,3 );

        vu_stu( out + 2*i,     r0 );
        vu_stu( out + 2*i + 4, r1 );
      }
      break;
    }
    case 2: {
      vu_t Qv = vu_bcast( Q );
      for( uint i=0; i<m; i+=2 ) {
        uint j1 = 4 * i;
        vu_t d0 = vu_ldu( out + j1 );
        vu_t d1 = vu_ldu( out + j1 + 4 );

        vu_t u, v;
        vl_transpose_2x2( d0, d1, u, v );

        uint s0 = fd_falcon_psi_positive[ m+i ];
        uint s1 = fd_falcon_psi_positive[ m+i+1 ];
        vu_t sv = vu( s0, s0, s1, s1 );

        vu_t vs  = fd_falcon_fq_sse_mul( v, sv );
        vu_t res_u = vu_add( u, vs );
        vu_t res_v = vu_add( vu_sub( u, vs ), Qv );

        vu_t out0, out1;
        vl_transpose_2x2( res_u, res_v, out0, out1 );
        vu_stu( out + j1,     out0 );
        vu_stu( out + j1 + 4, out1 );
      }
      break;
    }
    case 4: {
      vu_t Qv = vu_bcast( Q );
      for( uint i=0; i<m; i++ ) {
        uint j1 = 8 * i;
        vu_t sv = vu_bcast( fd_falcon_psi_positive[ m+i ] );
        vu_t u  = vu_ldu( out + j1 );
        vu_t v  = vu_ldu( out + j1 + 4 );
        vu_t vs = fd_falcon_fq_sse_mul( v, sv );
        vu_stu( out + j1,     vu_add( u, vs ) );
        vu_stu( out + j1 + 4, vu_add( vu_sub( u, vs ), Qv ) );
      }
      break;
    }
#endif /* FD_HAS_AVX */
    default: {
      for( uint i=0; i<m; i++ ) {
        uint j1 = 2 * i * t;
        fd_falcon_fq_t s = fd_falcon_psi_positive[ m+i ];

        switch( t ) {
#if FD_HAS_AVX512
        case 256: case 128: case 64: case 32: case 16:
          FD_FALCON_FFT_BUTTERFLY( wwu, 16, fd_falcon_fq_avx512_mul );
          break;
#endif
#if FD_HAS_AVX
#if !FD_HAS_AVX512
        case 256: case 128: case 64: case 32: case 16:
#endif
        case 8:
          FD_FALCON_FFT_BUTTERFLY( wu, 8, fd_falcon_fq_avx_mul );
          break;
#endif
        default:
          for( uint j=j1; j<j1+t; j++ ) {
            fd_falcon_fq_t u = out[ j ];
            fd_falcon_fq_t v = fd_falcon_fq_mul( out[ j+t ], s );
            out[ j ]   = u + v;
            out[ j+t ] = u - v + Q;
          }
          break;
        }
      }
      break;
    }
    }
    m <<= 1;
  }

  /* Reduce all elements to [0, Q) */
#if FD_HAS_AVX512
  FD_FALCON_FQ_MAP( wwu, 16, fd_falcon_fq_avx512_mul, 1U );
#elif FD_HAS_AVX
  FD_FALCON_FQ_MAP( wu, 8, fd_falcon_fq_avx_mul, 1U );
#else
  for( int j=0; j<N; j++ ) {
    out[ j ] = fd_falcon_fq_mul( out[ j ], 1U );
  }
#endif
}

/* Inverse NTT. Recovers coefficients from evaluations on the roots
   of X^n + 1.

   Uses a similar lazy trick as the Forward NTT, but requires a few
   reductions in the middle. When off_q >= 8, the add could overflow
   the 32-bit product on the next pass, so we reduce the add and reset
   off_q to 1. This will trigger for passes 3 and 7, with the final
   N^{-1} normalization handling the remaining lazy values.

   Algorithm 2 from https://eprint.iacr.org/2016/504.pdf. */
FD_FN_UNUSED static void
fd_falcon_fq_ifft( fd_falcon_fq_t       out[ N ],
                   fd_falcon_fq_t const in [ N ] ) {
  memcpy( out, in, sizeof(fd_falcon_fq_t) * N );

  uint t = 1;
  uint m = N;
  uint off_q = 1;
  while( m>1 ) {
    uint h = m >> 1;

    switch( t ) {
#if FD_HAS_AVX
    case 1: {
      vu_t offv = vu_bcast( off_q * Q );
      for( uint i=0; i<h; i+=4 ) {
        vu_t d0 = vu_ldu( out + 2*i );
        vu_t d1 = vu_ldu( out + 2*i + 4 );

        vu_t d0s = vu_permute( d0, 0,2,1,3 );
        vu_t d1s = vu_permute( d1, 0,2,1,3 );

        vu_t u, v;
        vl_transpose_2x2( d0s, d1s, u, v );

        vu_t sv   = vu_ldu( fd_falcon_psi_negative + h + i );
        vu_t sum  = vu_add( u, v );
        vu_t diff = fd_falcon_fq_sse_mul( vu_add( vu_sub( u, v ), offv ), sv );

        vu_t r0, r1;
        vl_transpose_2x2( sum, diff, r0, r1 );
        r0 = vu_permute( r0, 0,2,1,3 );
        r1 = vu_permute( r1, 0,2,1,3 );

        vu_stu( out + 2*i,     r0 );
        vu_stu( out + 2*i + 4, r1 );
      }
      off_q <<= 1;
      break;
    }
    case 2: {
      vu_t offv = vu_bcast( off_q * Q );
      uint j1 = 0;
      for( uint i=0; i<h; i+=2 ) {
        vu_t d0 = vu_ldu( out + j1 );
        vu_t d1 = vu_ldu( out + j1 + 4 );

        vu_t u, v;
        vl_transpose_2x2( d0, d1, u, v );

        uint s0 = fd_falcon_psi_negative[ h+i ];
        uint s1 = fd_falcon_psi_negative[ h+i+1 ];
        vu_t sv = vu( s0, s0, s1, s1 );

        vu_t sum  = vu_add( u, v );
        vu_t diff = fd_falcon_fq_sse_mul( vu_add( vu_sub( u, v ), offv ), sv );

        vu_t out0, out1;
        vl_transpose_2x2( sum, diff, out0, out1 );
        vu_stu( out + j1,     out0 );
        vu_stu( out + j1 + 4, out1 );
        j1 += 8;
      }
      off_q <<= 1;
      break;
    }
    case 4: {
      vu_t offv = vu_bcast( off_q * Q );
      uint j1 = 0;
      for( uint i=0; i<h; i++ ) {
        vu_t sv = vu_bcast( fd_falcon_psi_negative[ h+i ] );
        vu_t u  = vu_ldu( out + j1 );
        vu_t v  = vu_ldu( out + j1 + 4 );
        vu_stu( out + j1,     vu_add( u, v ) );
        vu_stu( out + j1 + 4, fd_falcon_fq_sse_mul( vu_add( vu_sub( u, v ), offv ), sv ) );
        j1 += 8;
      }
      off_q <<= 1;
      break;
    }
#endif /* FD_HAS_AVX */
    default: {
      uint off = off_q * Q;
      int reduce_add = (off_q >= 8);
      uint j1 = 0;
      for( uint i=0; i<h; i++ ) {
        fd_falcon_fq_t s = fd_falcon_psi_negative[ h+i ];

        switch( t ) {
#if FD_HAS_AVX512
        case 256: case 128: case 64: case 32: case 16:
          FD_FALCON_IFFT_BUTTERFLY( wwu, 16, fd_falcon_fq_avx512_mul );
          break;
#endif
#if FD_HAS_AVX
#if !FD_HAS_AVX512
        case 256: case 128: case 64: case 32: case 16:
#endif
        case 8:
          FD_FALCON_IFFT_BUTTERFLY( wu, 8, fd_falcon_fq_avx_mul );
          break;
#endif
        default:
          for( uint j=j1; j<j1+t; j++ ) {
            fd_falcon_fq_t u = out[ j ];
            fd_falcon_fq_t v = out[ j+t ];
            uint sum = u + v;
            out[ j ]   = reduce_add ? (sum % Q) : sum;
            out[ j+t ] = fd_falcon_fq_mul( u - v + off, s );
          }
          break;
        }
        j1 += 2 * t;
      }
      if( reduce_add ) off_q = 1; else off_q <<= 1;
      break;
    }
    }
    t <<= 1;
    m >>= 1;
  }

  /* Normalize by N^{-1} mod Q.  512^{-1} mod 12289 = 12265. */
#if FD_HAS_AVX512
  FD_FALCON_FQ_MAP( wwu, 16, fd_falcon_fq_avx512_mul, 12265U );
#elif FD_HAS_AVX
  FD_FALCON_FQ_MAP( wu, 8, fd_falcon_fq_avx_mul, 12265U );
#else
  for( int j=0; j<N; j++ ) {
    out[ j ] = fd_falcon_fq_mul( out[ j ], 12265U );
  }
#endif
}

#endif /* HEADER_fd_src_ballet_falcon_fd_falcon_fq_h */
