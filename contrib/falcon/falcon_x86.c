/* falcon_x86.c - Falcon-512 verification, auto-vectorisable scalar C.
 *
 * Vectoriser-friendly C: peeled small-stride NTT passes, __restrict__-
 * annotated pointers, generic large-stride pass that the compiler
 * specialises per call site.  No SIMD intrinsics; gcc and clang both
 * widen the inner butterfly loop to AVX-512 zmm at -O3 -march=native.
 *
 * Field arithmetic uses Shoup / Harvey precomputed-twiddle reduction
 * for the NTT passes (s' = floor(s*2^32/Q) is tabulated per twiddle),
 * and a one-shot Barrett reduction for the Hadamard product (each
 * coefficient is multiplied exactly once, so Shoup's precomputation
 * would require a per-element 64-bit divide that clang refuses to
 * vectorise).  Same lazy-reduction schedule and same Pornin parsers /
 * XKCP plain64 SHAKE256 backend as `falcon_ref_xkcp`; verifies the
 * same set of signatures.
 *
 * To prevent clang from emitting `vpgather`/`vpscatter` for the NTT
 * passes (very slow on Skylake-X / Ice Lake), the outer `i` loop of
 * each pass is annotated with `clang loop vectorize(disable)` so that
 * only the unit-stride inner loop is widened.  No effect on gcc.
 *
 * Public domain.
 */

#include "falcon.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define NONCELEN     40
#define N            FALCON_N
#define LOGN         FALCON_LOGN
#define Q            FALCON_Q
#define BETA2        FALCON_BETA2
#define K_REJ        ( ( 1 << 16 ) / Q )
#define SHAKE_RATE   136

/* clang's loop vectoriser, when handed the outer loop of these NTT
 * passes (`for i=0..m`), tries to widen across i and ends up emitting
 * `vpgather`/`vpscatter` for the resulting strided `buf` accesses.
 * Gathers/scatters are very slow on Skylake-X / Ice Lake (~7c
 * throughput each), and the cost dominated full verify by ~4 us.
 * Disable outer-loop vectorisation on the NTT passes so clang
 * vectorises only the unit-stride inner loop, matching gcc's natural
 * choice.  No effect on gcc (unknown pragma is silently ignored). */
#ifdef __clang__
#define NTT_NO_OUTER_VEC _Pragma("clang loop vectorize(disable)")
#else
#define NTT_NO_OUTER_VEC
#endif

typedef uint32_t fq_t;
typedef uint32_t falcon_fq_t;
#include "falcon_twiddle.h"

extern size_t falcon_inner_modq_decode( uint16_t * x, unsigned logn,
                                        void const * in, size_t max_in_len );
extern size_t falcon_inner_comp_decode( int16_t  * x, unsigned logn,
                                        void const * in, size_t max_in_len );

typedef struct { uint64_t A[ 25 ]; } kp1600_state_t;
extern void KeccakP1600_plain64_Initialize       ( kp1600_state_t * st );
extern void KeccakP1600_plain64_AddBytes         ( kp1600_state_t * st,
                                                   unsigned char const * data,
                                                   unsigned int offset,
                                                   unsigned int length );
extern void KeccakP1600_plain64_Permute_24rounds ( kp1600_state_t * st );
extern void KeccakP1600_plain64_ExtractBytes     ( kp1600_state_t const * st,
                                                   unsigned char * data,
                                                   unsigned int offset,
                                                   unsigned int length );

/* ---------- Shoup precomputed-twiddle reduction.
 *   For each twiddle s in [0, Q), s' = floor(s * 2^32 / Q).  Then
 *     q_hat = (v * s') >> 32
 *     r     = v * s - q_hat * Q
 *     return r >= Q ? r - Q : r
 *   For v in [0, 16Q) (the lazy-reduction bound) the result is in
 *   [0, Q+1) so a single conditional sub normalises to [0, Q). */

static fq_t s_prime_pos[ N ] __attribute__((aligned(64)));
static fq_t s_prime_neg[ N ] __attribute__((aligned(64)));

#define S_PRIME_ONE   ( (uint32_t)( ( (uint64_t)1     << 32 ) / Q ) )
#define S_PRIME_NINV  ( (uint32_t)( ( (uint64_t)12265 << 32 ) / Q ) )

__attribute__((constructor))
static void
init_shoup_tables( void ) {
  for( int i=0; i<N; i++ ) {
    s_prime_pos[ i ] = (uint32_t)( ( (uint64_t)falcon_psi_positive[ i ] << 32 ) / Q );
    s_prime_neg[ i ] = (uint32_t)( ( (uint64_t)falcon_psi_negative[ i ] << 32 ) / Q );
  }
}

static inline fq_t
fq_mul_shoup( fq_t v, fq_t s, fq_t s_prime ) {
  uint32_t q_hat = (uint32_t)( ( (uint64_t)v * (uint64_t)s_prime ) >> 32 );
  uint32_t r     = v * s - q_hat * (uint32_t)Q;
  uint32_t d     = r - (uint32_t)Q;
  return d + ( (uint32_t)Q & (uint32_t)( (int32_t)d >> 31 ) );
}

/* Hadamard product of two arbitrary fq values.  Shoup needs a
 * precomputed s' = floor(b*2^32/Q) per coefficient, which costs a
 * 64-bit integer division.  Clang refuses to vectorise that loop, and
 * the per-element divide alone consumes several thousand ns/verify.
 * Since each (a, b) is multiplied exactly once here, Shoup buys
 * nothing over a one-shot Barrett reduction.  We use Barrett for the
 * Hadamard (vectorisable u32*u32->u64 via vpmuludq) and keep Shoup for
 * the NTT passes, where each twiddle is reused t times and s' is
 * tabulated. */
static inline fq_t
fq_mul_barrett_h( fq_t a, fq_t b ) {
  uint32_t product = a * b;
  uint64_t wide    = (uint64_t)product * 43687ULL;       /* BARRETT_M */
  uint32_t qest    = (uint32_t)( wide >> 29 );           /* BARRETT_K */
  uint32_t r       = product - qest * (uint32_t)Q;
  uint32_t d       = r - (uint32_t)Q;
  return d + ( (uint32_t)Q & (uint32_t)( (int32_t)d >> 31 ) );
}

/* ---------- Forward NTT ---------- */

static inline void
ntt_fwd_pass( fq_t * __restrict__ buf, uint32_t m, uint32_t t,
              falcon_fq_t const * __restrict__ twiddle,
              falcon_fq_t const * __restrict__ twiddle_p ) {
  NTT_NO_OUTER_VEC
  for( uint32_t i=0; i<m; i++ ) {
    fq_t   s  = twiddle  [ m + i ];
    fq_t   sp = twiddle_p[ m + i ];
    fq_t * __restrict__ pu = buf + 2*i*t;
    fq_t * __restrict__ pv = pu + t;
    for( uint32_t j=0; j<t; j++ ) {
      fq_t u = pu[ j ];
      fq_t v = fq_mul_shoup( pv[ j ], s, sp );
      pu[ j ] = u + v;
      pv[ j ] = u - v + (uint32_t)Q;
    }
  }
}

static inline void
ntt_fwd_pass_t4( fq_t * __restrict__ buf,
                 falcon_fq_t const * __restrict__ twiddle,
                 falcon_fq_t const * __restrict__ twiddle_p ) {
  NTT_NO_OUTER_VEC
  for( uint32_t i=0; i<64; i++ ) {
    fq_t s  = twiddle  [ 64 + i ];
    fq_t sp = twiddle_p[ 64 + i ];
    fq_t * __restrict__ p = buf + 8*i;
    fq_t u0 = p[0], u1 = p[1], u2 = p[2], u3 = p[3];
    fq_t v0 = fq_mul_shoup( p[4], s, sp );
    fq_t v1 = fq_mul_shoup( p[5], s, sp );
    fq_t v2 = fq_mul_shoup( p[6], s, sp );
    fq_t v3 = fq_mul_shoup( p[7], s, sp );
    p[0] = u0 + v0;             p[1] = u1 + v1;
    p[2] = u2 + v2;             p[3] = u3 + v3;
    p[4] = u0 - v0 + (uint32_t)Q; p[5] = u1 - v1 + (uint32_t)Q;
    p[6] = u2 - v2 + (uint32_t)Q; p[7] = u3 - v3 + (uint32_t)Q;
  }
}

static inline void
ntt_fwd_pass_t2( fq_t * __restrict__ buf,
                 falcon_fq_t const * __restrict__ twiddle,
                 falcon_fq_t const * __restrict__ twiddle_p ) {
  NTT_NO_OUTER_VEC
  for( uint32_t i=0; i<128; i+=4 ) {
    fq_t s0 = twiddle  [ 128 + i + 0 ], sp0 = twiddle_p[ 128 + i + 0 ];
    fq_t s1 = twiddle  [ 128 + i + 1 ], sp1 = twiddle_p[ 128 + i + 1 ];
    fq_t s2 = twiddle  [ 128 + i + 2 ], sp2 = twiddle_p[ 128 + i + 2 ];
    fq_t s3 = twiddle  [ 128 + i + 3 ], sp3 = twiddle_p[ 128 + i + 3 ];
    fq_t * __restrict__ p = buf + 4*i;
    fq_t u00 = p[ 0], u01 = p[ 1], v00 = fq_mul_shoup( p[ 2], s0, sp0 ), v01 = fq_mul_shoup( p[ 3], s0, sp0 );
    fq_t u10 = p[ 4], u11 = p[ 5], v10 = fq_mul_shoup( p[ 6], s1, sp1 ), v11 = fq_mul_shoup( p[ 7], s1, sp1 );
    fq_t u20 = p[ 8], u21 = p[ 9], v20 = fq_mul_shoup( p[10], s2, sp2 ), v21 = fq_mul_shoup( p[11], s2, sp2 );
    fq_t u30 = p[12], u31 = p[13], v30 = fq_mul_shoup( p[14], s3, sp3 ), v31 = fq_mul_shoup( p[15], s3, sp3 );
    p[ 0] = u00 + v00;             p[ 1] = u01 + v01;
    p[ 2] = u00 - v00 + (uint32_t)Q; p[ 3] = u01 - v01 + (uint32_t)Q;
    p[ 4] = u10 + v10;             p[ 5] = u11 + v11;
    p[ 6] = u10 - v10 + (uint32_t)Q; p[ 7] = u11 - v11 + (uint32_t)Q;
    p[ 8] = u20 + v20;             p[ 9] = u21 + v21;
    p[10] = u20 - v20 + (uint32_t)Q; p[11] = u21 - v21 + (uint32_t)Q;
    p[12] = u30 + v30;             p[13] = u31 + v31;
    p[14] = u30 - v30 + (uint32_t)Q; p[15] = u31 - v31 + (uint32_t)Q;
  }
}

static inline void
ntt_fwd_pass_t1( fq_t * __restrict__ buf,
                 falcon_fq_t const * __restrict__ twiddle,
                 falcon_fq_t const * __restrict__ twiddle_p ) {
  NTT_NO_OUTER_VEC
  for( uint32_t i=0; i<256; i+=8 ) {
    falcon_fq_t const * __restrict__ s  = twiddle   + 256 + i;
    falcon_fq_t const * __restrict__ sp = twiddle_p + 256 + i;
    fq_t * __restrict__ p = buf + 2*i;
    fq_t u0 = p[ 0], v0 = fq_mul_shoup( p[ 1], s[0], sp[0] );
    fq_t u1 = p[ 2], v1 = fq_mul_shoup( p[ 3], s[1], sp[1] );
    fq_t u2 = p[ 4], v2 = fq_mul_shoup( p[ 5], s[2], sp[2] );
    fq_t u3 = p[ 6], v3 = fq_mul_shoup( p[ 7], s[3], sp[3] );
    fq_t u4 = p[ 8], v4 = fq_mul_shoup( p[ 9], s[4], sp[4] );
    fq_t u5 = p[10], v5 = fq_mul_shoup( p[11], s[5], sp[5] );
    fq_t u6 = p[12], v6 = fq_mul_shoup( p[13], s[6], sp[6] );
    fq_t u7 = p[14], v7 = fq_mul_shoup( p[15], s[7], sp[7] );
    p[ 0] = u0 + v0; p[ 1] = u0 - v0 + (uint32_t)Q;
    p[ 2] = u1 + v1; p[ 3] = u1 - v1 + (uint32_t)Q;
    p[ 4] = u2 + v2; p[ 5] = u2 - v2 + (uint32_t)Q;
    p[ 6] = u3 + v3; p[ 7] = u3 - v3 + (uint32_t)Q;
    p[ 8] = u4 + v4; p[ 9] = u4 - v4 + (uint32_t)Q;
    p[10] = u5 + v5; p[11] = u5 - v5 + (uint32_t)Q;
    p[12] = u6 + v6; p[13] = u6 - v6 + (uint32_t)Q;
    p[14] = u7 + v7; p[15] = u7 - v7 + (uint32_t)Q;
  }
}

static void
ntt_fwd_scalar( fq_t * __restrict__ out, fq_t const * __restrict__ in ) {
  fq_t buf[ N ] __attribute__((aligned(64)));
  memcpy( buf, in, sizeof buf );

  ntt_fwd_pass   ( buf,  1, 256, falcon_psi_positive, s_prime_pos );
  ntt_fwd_pass   ( buf,  2, 128, falcon_psi_positive, s_prime_pos );
  ntt_fwd_pass   ( buf,  4,  64, falcon_psi_positive, s_prime_pos );
  ntt_fwd_pass   ( buf,  8,  32, falcon_psi_positive, s_prime_pos );
  ntt_fwd_pass   ( buf, 16,  16, falcon_psi_positive, s_prime_pos );
  ntt_fwd_pass   ( buf, 32,   8, falcon_psi_positive, s_prime_pos );
  ntt_fwd_pass_t4( buf,         falcon_psi_positive, s_prime_pos );
  ntt_fwd_pass_t2( buf,         falcon_psi_positive, s_prime_pos );
  ntt_fwd_pass_t1( buf,         falcon_psi_positive, s_prime_pos );

  /* Final reduction pass: multiply by 1 to land in [0, Q). */
  for( uint32_t j=0; j<(uint32_t)N; j++ )
    out[ j ] = fq_mul_shoup( buf[ j ], 1, S_PRIME_ONE );
}

/* ---------- Inverse NTT ---------- */

static inline void
ntt_inv_pass( fq_t * __restrict__ buf, uint32_t h, uint32_t t,
              uint32_t off, int reduce_add,
              falcon_fq_t const * __restrict__ twiddle,
              falcon_fq_t const * __restrict__ twiddle_p ) {
  uint32_t j1 = 0;
  NTT_NO_OUTER_VEC
  for( uint32_t i=0; i<h; i++ ) {
    fq_t   s  = twiddle  [ h + i ];
    fq_t   sp = twiddle_p[ h + i ];
    fq_t * __restrict__ pu = buf + j1;
    fq_t * __restrict__ pv = pu + t;
    for( uint32_t j=0; j<t; j++ ) {
      fq_t u    = pu[ j ];
      fq_t v    = pv[ j ];
      fq_t sum  = u + v;
      fq_t diff = fq_mul_shoup( u - v + off, s, sp );
      pu[ j ] = reduce_add ? fq_mul_shoup( sum, 1, S_PRIME_ONE ) : sum;
      pv[ j ] = diff;
    }
    j1 += 2*t;
  }
}

static inline void
ntt_inv_pass_t1( fq_t * __restrict__ buf, uint32_t off,
                 falcon_fq_t const * __restrict__ twiddle,
                 falcon_fq_t const * __restrict__ twiddle_p ) {
  NTT_NO_OUTER_VEC
  for( uint32_t i=0; i<256; i+=8 ) {
    falcon_fq_t const * __restrict__ s  = twiddle   + 256 + i;
    falcon_fq_t const * __restrict__ sp = twiddle_p + 256 + i;
    fq_t * __restrict__ p = buf + 2*i;
    fq_t u0 = p[ 0], v0 = p[ 1];
    fq_t u1 = p[ 2], v1 = p[ 3];
    fq_t u2 = p[ 4], v2 = p[ 5];
    fq_t u3 = p[ 6], v3 = p[ 7];
    fq_t u4 = p[ 8], v4 = p[ 9];
    fq_t u5 = p[10], v5 = p[11];
    fq_t u6 = p[12], v6 = p[13];
    fq_t u7 = p[14], v7 = p[15];
    p[ 0] = u0 + v0;  p[ 1] = fq_mul_shoup( u0 - v0 + off, s[0], sp[0] );
    p[ 2] = u1 + v1;  p[ 3] = fq_mul_shoup( u1 - v1 + off, s[1], sp[1] );
    p[ 4] = u2 + v2;  p[ 5] = fq_mul_shoup( u2 - v2 + off, s[2], sp[2] );
    p[ 6] = u3 + v3;  p[ 7] = fq_mul_shoup( u3 - v3 + off, s[3], sp[3] );
    p[ 8] = u4 + v4;  p[ 9] = fq_mul_shoup( u4 - v4 + off, s[4], sp[4] );
    p[10] = u5 + v5;  p[11] = fq_mul_shoup( u5 - v5 + off, s[5], sp[5] );
    p[12] = u6 + v6;  p[13] = fq_mul_shoup( u6 - v6 + off, s[6], sp[6] );
    p[14] = u7 + v7;  p[15] = fq_mul_shoup( u7 - v7 + off, s[7], sp[7] );
  }
}

static inline void
ntt_inv_pass_t2( fq_t * __restrict__ buf, uint32_t off,
                 falcon_fq_t const * __restrict__ twiddle,
                 falcon_fq_t const * __restrict__ twiddle_p ) {
  NTT_NO_OUTER_VEC
  for( uint32_t i=0; i<128; i+=4 ) {
    fq_t s0 = twiddle  [ 128 + i + 0 ], sp0 = twiddle_p[ 128 + i + 0 ];
    fq_t s1 = twiddle  [ 128 + i + 1 ], sp1 = twiddle_p[ 128 + i + 1 ];
    fq_t s2 = twiddle  [ 128 + i + 2 ], sp2 = twiddle_p[ 128 + i + 2 ];
    fq_t s3 = twiddle  [ 128 + i + 3 ], sp3 = twiddle_p[ 128 + i + 3 ];
    fq_t * __restrict__ p = buf + 4*i;
    fq_t u00=p[ 0],u01=p[ 1],v00=p[ 2],v01=p[ 3];
    fq_t u10=p[ 4],u11=p[ 5],v10=p[ 6],v11=p[ 7];
    fq_t u20=p[ 8],u21=p[ 9],v20=p[10],v21=p[11];
    fq_t u30=p[12],u31=p[13],v30=p[14],v31=p[15];
    p[ 0]=u00+v00;p[ 1]=u01+v01;p[ 2]=fq_mul_shoup(u00-v00+off,s0,sp0);p[ 3]=fq_mul_shoup(u01-v01+off,s0,sp0);
    p[ 4]=u10+v10;p[ 5]=u11+v11;p[ 6]=fq_mul_shoup(u10-v10+off,s1,sp1);p[ 7]=fq_mul_shoup(u11-v11+off,s1,sp1);
    p[ 8]=u20+v20;p[ 9]=u21+v21;p[10]=fq_mul_shoup(u20-v20+off,s2,sp2);p[11]=fq_mul_shoup(u21-v21+off,s2,sp2);
    p[12]=u30+v30;p[13]=u31+v31;p[14]=fq_mul_shoup(u30-v30+off,s3,sp3);p[15]=fq_mul_shoup(u31-v31+off,s3,sp3);
  }
}

static inline void
ntt_inv_pass_t4( fq_t * __restrict__ buf, uint32_t off,
                 falcon_fq_t const * __restrict__ twiddle,
                 falcon_fq_t const * __restrict__ twiddle_p ) {
  NTT_NO_OUTER_VEC
  for( uint32_t i=0; i<64; i++ ) {
    fq_t s  = twiddle  [ 64 + i ];
    fq_t sp = twiddle_p[ 64 + i ];
    fq_t * __restrict__ p = buf + 8*i;
    fq_t u0=p[0],u1=p[1],u2=p[2],u3=p[3];
    fq_t v0=p[4],v1=p[5],v2=p[6],v3=p[7];
    p[0] = u0 + v0;
    p[1] = u1 + v1;
    p[2] = u2 + v2;
    p[3] = u3 + v3;
    p[4] = fq_mul_shoup( u0 - v0 + off, s, sp );
    p[5] = fq_mul_shoup( u1 - v1 + off, s, sp );
    p[6] = fq_mul_shoup( u2 - v2 + off, s, sp );
    p[7] = fq_mul_shoup( u3 - v3 + off, s, sp );
  }
}

static void
ntt_inv_scalar( fq_t * __restrict__ out, fq_t const * __restrict__ in ) {
  fq_t buf[ N ] __attribute__((aligned(64)));
  memcpy( buf, in, sizeof buf );

  ntt_inv_pass_t1( buf, 1*Q,                falcon_psi_negative, s_prime_neg );
  ntt_inv_pass_t2( buf, 2*Q,                falcon_psi_negative, s_prime_neg );
  ntt_inv_pass_t4( buf, 4*Q,                falcon_psi_negative, s_prime_neg );
  ntt_inv_pass   ( buf, 32,    8, 8*Q, 1,   falcon_psi_negative, s_prime_neg );
  ntt_inv_pass   ( buf, 16,   16, 1*Q, 0,   falcon_psi_negative, s_prime_neg );
  ntt_inv_pass   ( buf,  8,   32, 2*Q, 0,   falcon_psi_negative, s_prime_neg );
  ntt_inv_pass   ( buf,  4,   64, 4*Q, 0,   falcon_psi_negative, s_prime_neg );
  ntt_inv_pass   ( buf,  2,  128, 8*Q, 1,   falcon_psi_negative, s_prime_neg );
  ntt_inv_pass   ( buf,  1,  256, 1*Q, 0,   falcon_psi_negative, s_prime_neg );

  /* Final normalisation by N^{-1} = 12265 mod Q. */
  for( uint32_t j=0; j<(uint32_t)N; j++ )
    out[ j ] = fq_mul_shoup( buf[ j ], 12265, S_PRIME_NINV );
}

/* ---------- hash-to-point: identical to falcon_x86 / falcon_ref_xkcp. */

static void
hash_to_point_xkcp( fq_t * out, uint8_t const * in, size_t in_len ) {
  kp1600_state_t st;
  KeccakP1600_plain64_Initialize( &st );
  while( in_len >= SHAKE_RATE ) {
    KeccakP1600_plain64_AddBytes( &st, in, 0, SHAKE_RATE );
    KeccakP1600_plain64_Permute_24rounds( &st );
    in += SHAKE_RATE; in_len -= SHAKE_RATE;
  }
  if( in_len ) KeccakP1600_plain64_AddBytes( &st, in, 0, (unsigned)in_len );
  unsigned char ds  = 0x1F;
  unsigned char fin = 0x80;
  KeccakP1600_plain64_AddBytes( &st, &ds,  (unsigned)in_len,    1 );
  KeccakP1600_plain64_AddBytes( &st, &fin, SHAKE_RATE - 1,       1 );
  KeccakP1600_plain64_Permute_24rounds( &st );

  unsigned remaining = N;
  uint8_t  blk[ SHAKE_RATE ];
  for( ;; ) {
    KeccakP1600_plain64_ExtractBytes( &st, blk, 0, SHAKE_RATE );
    for( unsigned j=0; j+1 < SHAKE_RATE && remaining > 0; j += 2 ) {
      uint32_t w = ( (uint32_t)blk[ j ] << 8 ) | (uint32_t)blk[ j+1 ];
      if( w < (uint32_t)( K_REJ * Q ) ) {
        while( w >= (uint32_t)Q ) w -= (uint32_t)Q;
        *out++ = (fq_t)w;
        remaining--;
      }
    }
    if( !remaining ) break;
    KeccakP1600_plain64_Permute_24rounds( &st );
  }
}

/* AVX-512-only KTP256 hash: declared by falcon_avx512_common.h, but
 * we don't want to pull in that whole header here, so spell out the
 * declaration with the matching guard. */
#if defined(__AVX512F__) && defined(__AVX512BW__) && defined(__AVX512DQ__)
#define HAVE_AVX512 1
extern void fa512_hash_to_point_ktp256( uint16_t * out,
                                          uint8_t const * in, size_t in_len );
#else
#define HAVE_AVX512 0
#endif

/* Verify body shared by `falcon_x86_crypto_sign_open` and
 * `falcon_x86_ktp256_crypto_sign_open`.  The hash is performed
 * inline based on `use_ktp256_hash`; everything else (parse, NTT
 * pipeline, Hadamard, iNTT, norm check) is identical between the two
 * entry points. */
static int
falcon_x86_verify_with_c( uint8_t       * m,  size_t * mlen,
                          uint8_t const * sm, size_t   smlen,
                          uint8_t const * pk,
                          int             use_ktp256_hash ) {
  if( pk[ 0 ] != 0x00 + LOGN ) return -1;
  uint16_t h_u16[ N ];
  if( falcon_inner_modq_decode( h_u16, LOGN, pk + 1,
                                FALCON_PUBKEY_SIZE - 1 )
      != FALCON_PUBKEY_SIZE - 1 ) return -1;

  if( smlen < 2 + NONCELEN ) return -1;
  size_t sig_len = ( (size_t)sm[ 0 ] << 8 ) | (size_t)sm[ 1 ];
  if( sig_len > smlen - 2 - NONCELEN ) return -1;
  size_t msg_len = smlen - 2 - NONCELEN - sig_len;

  uint8_t const * esig = sm + 2 + NONCELEN + msg_len;
  if( sig_len < 1 || esig[ 0 ] != 0x20 + LOGN ) return -1;

  int16_t sig_i16[ N ];
  if( falcon_inner_comp_decode( sig_i16, LOGN, esig + 1,
                                sig_len - 1 ) != sig_len - 1 ) return -1;

  fq_t c[ N ];
#if HAVE_AVX512
  if( use_ktp256_hash ) {
    uint16_t c16[ N ];
    fa512_hash_to_point_ktp256( c16, sm + 2, NONCELEN + msg_len );
    for( int i=0; i<N; i++ ) c[ i ] = (fq_t)c16[ i ];
  } else
#else
  (void)use_ktp256_hash;
#endif
  hash_to_point_xkcp( c, sm + 2, NONCELEN + msg_len );

  fq_t h[ N ], s2[ N ];
  for( int i=0; i<N; i++ ) {
    h[ i ]  = (fq_t)h_u16[ i ];
    int32_t v = (int32_t)sig_i16[ i ];
    s2[ i ] = (fq_t)( v + ( (int32_t)Q & (v >> 31) ) );
  }

  fq_t h_ntt [ N ] __attribute__((aligned(64)));
  fq_t s2_ntt[ N ] __attribute__((aligned(64)));
  fq_t prod  [ N ] __attribute__((aligned(64)));
  fq_t pmm   [ N ] __attribute__((aligned(64)));
  ntt_fwd_scalar( h_ntt,  h  );
  ntt_fwd_scalar( s2_ntt, s2 );
  for( int i=0; i<N; i++ ) prod[ i ] = fq_mul_barrett_h( h_ntt[ i ], s2_ntt[ i ] );
  ntt_inv_scalar( pmm, prod );

  long norm = 0L;
  for( int i=0; i<N; i++ ) {
    uint32_t a    = c  [ i ];
    uint32_t b    = pmm[ i ];
    int      s1   = (int)( ( a >= b ) ? ( a - b ) : ( (uint32_t)Q - b + a ) );
    if( s1 > Q/2 ) s1 -= Q;
    int      s2_s = (int)sig_i16[ i ];
    norm += (long)s1 * s1 + (long)s2_s * s2_s;
  }
  if( norm > BETA2 ) return -1;

  if( m && msg_len ) memmove( m, sm + 2 + NONCELEN, msg_len );
  if( mlen ) *mlen = msg_len;
  return 0;
}

int
falcon_x86_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                             uint8_t const * sm, size_t   smlen,
                             uint8_t const * pk ) {
  return falcon_x86_verify_with_c( m, mlen, sm, smlen, pk, 0 );
}

/* ---------- bench helpers.  Public wrappers around the file-local
 * scalar primitives so the subcomponent benchmark can time each
 * piece (FFT, iFFT) in isolation. */

void
falcon_x86_bench_fft( fq_t * out, fq_t const * in ) {
  ntt_fwd_scalar( out, in );
}

void
falcon_x86_bench_ifft( fq_t * out, fq_t const * in ) {
  ntt_inv_scalar( out, in );
}

/* Full multiplication step: 2 fwd NTTs + Hadamard + inv NTT + norm.
 * Mirrors what `falcon_x86_crypto_sign_open` does between the hash
 * output `c` and the final `return`.  Returns 1 on accept, 0 on
 * reject (norm > BETA2). */
int
falcon_x86_bench_mul( uint32_t const * c,
                      uint16_t const * h_u16,
                      int16_t  const * sig_i16 ) {
  fq_t h[ N ], s2[ N ];
  for( int i=0; i<N; i++ ) {
    h[ i ]  = (fq_t)h_u16[ i ];
    int32_t v = (int32_t)sig_i16[ i ];
    s2[ i ] = (fq_t)( v + ( (int32_t)Q & (v >> 31) ) );
  }
  fq_t h_ntt [ N ] __attribute__((aligned(64)));
  fq_t s2_ntt[ N ] __attribute__((aligned(64)));
  fq_t prod  [ N ] __attribute__((aligned(64)));
  fq_t pmm   [ N ] __attribute__((aligned(64)));
  ntt_fwd_scalar( h_ntt,  h  );
  ntt_fwd_scalar( s2_ntt, s2 );
  for( int i=0; i<N; i++ ) prod[ i ] = fq_mul_barrett_h( h_ntt[ i ], s2_ntt[ i ] );
  ntt_inv_scalar( pmm, prod );

  long norm = 0L;
  for( int i=0; i<N; i++ ) {
    uint32_t a    = c  [ i ];
    uint32_t b    = pmm[ i ];
    int      s1   = (int)( ( a >= b ) ? ( a - b ) : ( (uint32_t)Q - b + a ) );
    if( s1 > Q/2 ) s1 -= Q;
    int      s2_s = (int)sig_i16[ i ];
    norm += (long)s1 * s1 + (long)s2_s * s2_s;
  }
  return norm <= BETA2;
}

/* Same Shoup pipeline but with the SHAKE256 hash-to-point swapped for
 * the TurboSHAKE12 + 8-way parallel-squeeze variant.  Cannot verify
 * standard Falcon round 3 signatures (the produced `c` differs);
 * provided for benchmarking the parallel-squeeze cost on top of the
 * scalar pipeline.  Falls back to standard SHAKE on hosts without
 * AVX-512. */
int
falcon_x86_ktp256_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                      uint8_t const * sm, size_t   smlen,
                                      uint8_t const * pk ) {
#if HAVE_AVX512
  return falcon_x86_verify_with_c( m, mlen, sm, smlen, pk, 1 );
#else
  return falcon_x86_verify_with_c( m, mlen, sm, smlen, pk, 0 );
#endif
}
