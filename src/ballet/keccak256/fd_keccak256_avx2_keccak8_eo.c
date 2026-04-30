/* Keccak-f[1600] x8 batched on AVX2 with EVEN/ODD bit-interleaved limbs.

   Each logical 64-bit Keccak lane w is split as:
     E = bits w[0],  w[2],  w[4],  ..., w[62]   packed into a uint32
     O = bits w[1],  w[3],  w[5],  ..., w[63]   packed into a uint32
   (i.e. E_bit_k = w[2k], O_bit_k = w[2k+1].)

   SoA over 8 instances: each __m256i holds the E (or O) limb of one Keccak
   index across 8 independent instances.  All bitwise ops (XOR/AND/ANDNOT)
   commute with the bit-interleave, so they apply per-half identically.

   The win over the lo/hi limb model:
     - rotl64 by d=1 (Theta D step + rho table entry 0):
         E' = rol32(O, 1)         (3 ops: vpslld + vpsrld + vpor)
         O' = E                   (free register relabel)
       Total 3 ops vs 6 ops for lo/hi.  Saves (5 + 1) * 3 = 18 ops per round.
     - Other rotation amounts cost the same 6 ops as lo/hi (two rol32 per pair,
       with a free register swap for odd d).

   Boundary conversion uses BMI2 pext/pdep to split a uint64 into (E,O) (one
   1-cycle scalar op per direction per half). */

#include "../fd_ballet_base.h"
#include <immintrin.h>

typedef __m256i v256u;

/* rol32 by compile-time constant N in [0,31]; N=0 collapses to the input. */
#define K8EO_ROL32_C( X, N ) (                                                     \
    (N) == 0 ? (X) :                                                               \
    _mm256_or_si256( _mm256_slli_epi32( (X), (N)    ),                             \
                     _mm256_srli_epi32( (X), 32-(N) ) ) )

/* Logical 64-bit rotl by D (compile-time constant) on a (E,O) pair.
   Special-cases:
     d=0          : free
     d even = 2k  : rol32 each half by k
     d odd  = 2k+1: E' = rol32(O, k+1); O' = rol32(E, k)
                    when k=0 (d=1) the O' = rol32(E,0) collapses to a relabel
                    (3 ops total).  k+1=32 (d=63) collapses E' similarly,
                    though d=63 is not in the rho table. */
#define K8EO_ROL64_C( EOUT, OOUT, EIN, OIN, D ) do {                               \
    if(       (D) == 0       ) { (EOUT) = (EIN); (OOUT) = (OIN); }                 \
    else if ( ((D) & 1) == 0 ) { /* even */                                        \
      (EOUT) = K8EO_ROL32_C( (EIN), ((D)/2)         );                             \
      (OOUT) = K8EO_ROL32_C( (OIN), ((D)/2)         );                             \
    } else {                       /* odd  */                                      \
      (EOUT) = K8EO_ROL32_C( (OIN), (((D)-1)/2) + 1 );                             \
      (OOUT) = K8EO_ROL32_C( (EIN), (((D)-1)/2)     );                             \
    }                                                                              \
  } while(0)

/* Fused step: compute (a^D) at source (X,Y), rotl by RHO_D, store to b[PI_XY]. */
#define K8EO_THETA_RHO_PI( BE, BO, AE, AO, DE, DO, X, Y, PI_XY, RHO_D ) do {       \
    v256u _te = _mm256_xor_si256( (AE)[ (X) + 5*(Y) ], (DE)[ (X) ] );              \
    v256u _to = _mm256_xor_si256( (AO)[ (X) + 5*(Y) ], (DO)[ (X) ] );              \
    K8EO_ROL64_C( (BE)[ (PI_XY) ], (BO)[ (PI_XY) ], _te, _to, RHO_D );             \
  } while(0)

/* Bit deinterleave a u64 into (E, O) with BMI2 pext (1-cycle each).
   Used for the iota round-constant pre-deinterleave (one-shot per call). */
static inline void
fd_k8eo_pack( ulong w, uint * e, uint * o ) {
  *e = (uint)_pext_u64( w, 0x5555555555555555UL );
  *o = (uint)_pext_u64( w, 0xAAAAAAAAAAAAAAAAUL );
}

__attribute__((unused)) static inline ulong
fd_k8eo_unpack( uint e, uint o ) {
  return _pdep_u64( (ulong)e, 0x5555555555555555UL )
       | _pdep_u64( (ulong)o, 0xAAAAAAAAAAAAAAAAUL );
}

/* Vectorized 5-step bit deinterleave on 4 u64 lanes simultaneously (AVX2).
   Output: each u64 lane has even bits in its low 32, odd bits in its high 32.
   25 ymm ops; serial chain of 5 stages but 4 lanes processed in parallel. */
static inline v256u
fd_k8eo_dei_4u64( v256u x ) {
  v256u const m1 = _mm256_set1_epi64x( (long long)0x2222222222222222LL );
  v256u const m2 = _mm256_set1_epi64x( (long long)0x0C0C0C0C0C0C0C0CLL );
  v256u const m3 = _mm256_set1_epi64x( (long long)0x00F000F000F000F0LL );
  v256u const m4 = _mm256_set1_epi64x( (long long)0x0000FF000000FF00LL );
  v256u const m5 = _mm256_set1_epi64x( (long long)0x00000000FFFF0000LL );
  v256u t;
  t = _mm256_and_si256( _mm256_xor_si256( x, _mm256_srli_epi64( x, 1  ) ), m1 );
  x = _mm256_xor_si256( x, _mm256_xor_si256( t, _mm256_slli_epi64( t, 1  ) ) );
  t = _mm256_and_si256( _mm256_xor_si256( x, _mm256_srli_epi64( x, 2  ) ), m2 );
  x = _mm256_xor_si256( x, _mm256_xor_si256( t, _mm256_slli_epi64( t, 2  ) ) );
  t = _mm256_and_si256( _mm256_xor_si256( x, _mm256_srli_epi64( x, 4  ) ), m3 );
  x = _mm256_xor_si256( x, _mm256_xor_si256( t, _mm256_slli_epi64( t, 4  ) ) );
  t = _mm256_and_si256( _mm256_xor_si256( x, _mm256_srli_epi64( x, 8  ) ), m4 );
  x = _mm256_xor_si256( x, _mm256_xor_si256( t, _mm256_slli_epi64( t, 8  ) ) );
  t = _mm256_and_si256( _mm256_xor_si256( x, _mm256_srli_epi64( x, 16 ) ), m5 );
  x = _mm256_xor_si256( x, _mm256_xor_si256( t, _mm256_slli_epi64( t, 16 ) ) );
  return x;
}

/* Inverse: each u64 lane has E in low 32, O in high 32 -> reinterleave bits. */
static inline v256u
fd_k8eo_int_4u64( v256u x ) {
  v256u const m1 = _mm256_set1_epi64x( (long long)0x2222222222222222LL );
  v256u const m2 = _mm256_set1_epi64x( (long long)0x0C0C0C0C0C0C0C0CLL );
  v256u const m3 = _mm256_set1_epi64x( (long long)0x00F000F000F000F0LL );
  v256u const m4 = _mm256_set1_epi64x( (long long)0x0000FF000000FF00LL );
  v256u const m5 = _mm256_set1_epi64x( (long long)0x00000000FFFF0000LL );
  v256u t;
  t = _mm256_and_si256( _mm256_xor_si256( x, _mm256_srli_epi64( x, 16 ) ), m5 );
  x = _mm256_xor_si256( x, _mm256_xor_si256( t, _mm256_slli_epi64( t, 16 ) ) );
  t = _mm256_and_si256( _mm256_xor_si256( x, _mm256_srli_epi64( x, 8  ) ), m4 );
  x = _mm256_xor_si256( x, _mm256_xor_si256( t, _mm256_slli_epi64( t, 8  ) ) );
  t = _mm256_and_si256( _mm256_xor_si256( x, _mm256_srli_epi64( x, 4  ) ), m3 );
  x = _mm256_xor_si256( x, _mm256_xor_si256( t, _mm256_slli_epi64( t, 4  ) ) );
  t = _mm256_and_si256( _mm256_xor_si256( x, _mm256_srli_epi64( x, 2  ) ), m2 );
  x = _mm256_xor_si256( x, _mm256_xor_si256( t, _mm256_slli_epi64( t, 2  ) ) );
  t = _mm256_and_si256( _mm256_xor_si256( x, _mm256_srli_epi64( x, 1  ) ), m1 );
  x = _mm256_xor_si256( x, _mm256_xor_si256( t, _mm256_slli_epi64( t, 1  ) ) );
  return x;
}

/* Vectorized AoS -> SoA(E, O) for one Keccak index.  Loads 8 strided ulongs
   from state[base], state[base+25], ..., state[base+175], deinterleaves their
   bits in parallel, and produces (E, O) ymm-lane SoA.
   Note: vpgatherqq is OK on Zen 4 (~10 cyc), but a manual scalar-load + insert
   sequence is comparable; we use the gather form for code clarity. */
static inline void
fd_k8eo_pack_ymm( ulong const * state, int z, v256u * out_e, v256u * out_o ) {
  /* Manual gather of 8 strided ulongs into 2 ymm.  vpgatherqq is slow on
     Zen 4 (~14 cyc); the manual sequence pipelines better. */
  ulong const * p = state + z;
  __m128i a0 = _mm_loadl_epi64( (__m128i const *)( p +   0 ) );  /* lo64 */
  a0 = _mm_insert_epi64( a0, (long long)p[ 25 ], 1 );
  __m128i a1 = _mm_loadl_epi64( (__m128i const *)( p +  50 ) );
  a1 = _mm_insert_epi64( a1, (long long)p[ 75 ], 1 );
  v256u w_lo = _mm256_inserti128_si256( _mm256_castsi128_si256( a0 ), a1, 1 );
  __m128i b0 = _mm_loadl_epi64( (__m128i const *)( p + 100 ) );
  b0 = _mm_insert_epi64( b0, (long long)p[ 125 ], 1 );
  __m128i b1 = _mm_loadl_epi64( (__m128i const *)( p + 150 ) );
  b1 = _mm_insert_epi64( b1, (long long)p[ 175 ], 1 );
  v256u w_hi = _mm256_inserti128_si256( _mm256_castsi128_si256( b0 ), b1, 1 );

  /* Per-lane bit deinterleave: each u64 lane gets E in its low 32, O in its high 32. */
  w_lo = fd_k8eo_dei_4u64( w_lo );
  w_hi = fd_k8eo_dei_4u64( w_hi );

  /* Transpose to SoA: gather all 8 E's into one ymm, all 8 O's into another.
     Within each ymm, lanes 0,2,4,6 (32-bit) are E0,E1,E2,E3 (in lo half) and
     E4,E5,E6,E7 (in hi half).  vpermd with index [0,2,4,6,1,3,5,7] permutes
     to [E0..E3, O0..O3] in each ymm; then vperm2i128 merges the halves. */
  v256u const perm_idx = _mm256_set_epi32( 7,5,3,1, 6,4,2,0 );
  v256u const p_lo = _mm256_permutevar8x32_epi32( w_lo, perm_idx );  /* E0..E3, O0..O3 */
  v256u const p_hi = _mm256_permutevar8x32_epi32( w_hi, perm_idx );  /* E4..E7, O4..O7 */
  *out_e = _mm256_permute2x128_si256( p_lo, p_hi, 0x20 );  /* E0..E3, E4..E7 */
  *out_o = _mm256_permute2x128_si256( p_lo, p_hi, 0x31 );  /* O0..O3, O4..O7 */
}

/* Inverse: SoA (E, O) ymm -> 8 strided ulongs scattered into state[base + 25*k]. */
static inline void
fd_k8eo_unpack_ymm( v256u in_e, v256u in_o, ulong * state, int z ) {
  /* Inverse of the SoA transpose.
     in_e = [E0..E3 | E4..E7], in_o = [O0..O3 | O4..O7].
     After vpunpckldq(E, O): per-128 lane: (E0, O0, E1, O1) | (E4, O4, E5, O5).
     After vpunpckhdq(E, O): per-128 lane: (E2, O2, E3, O3) | (E6, O6, E7, O7).
     Reading those 32-bit groups as u64: the four u64 are ordered
       (E0|O0, E1|O1, E4|O4, E5|O5)  and  (E2|O2, E3|O3, E6|O6, E7|O7)
     so vperm2i128 merges to get
       (E0|O0, E1|O1, E2|O2, E3|O3)  and  (E4|O4, E5|O5, E6|O6, E7|O7). */
  v256u const u_lo = _mm256_unpacklo_epi32( in_e, in_o );
  v256u const u_hi = _mm256_unpackhi_epi32( in_e, in_o );
  v256u w_lo = _mm256_permute2x128_si256( u_lo, u_hi, 0x20 );
  v256u w_hi = _mm256_permute2x128_si256( u_lo, u_hi, 0x31 );

  /* Inverse bit interleave: u64 lane (E in low 32, O in high 32) -> bit-interleaved u64. */
  w_lo = fd_k8eo_int_4u64( w_lo );
  w_hi = fd_k8eo_int_4u64( w_hi );

  /* Scatter (manual; AVX2 has no scatter). */
  ulong tmp_lo[ 4 ] __attribute__((aligned(32)));
  ulong tmp_hi[ 4 ] __attribute__((aligned(32)));
  _mm256_store_si256( (v256u *)tmp_lo, w_lo );
  _mm256_store_si256( (v256u *)tmp_hi, w_hi );
  state[ z +   0 ] = tmp_lo[ 0 ];
  state[ z +  25 ] = tmp_lo[ 1 ];
  state[ z +  50 ] = tmp_lo[ 2 ];
  state[ z +  75 ] = tmp_lo[ 3 ];
  state[ z + 100 ] = tmp_hi[ 0 ];
  state[ z + 125 ] = tmp_hi[ 1 ];
  state[ z + 150 ] = tmp_hi[ 2 ];
  state[ z + 175 ] = tmp_hi[ 3 ];
}

/* Inner permutation: state already in (E,O) SoA form across 8 instances.
   Operates in-place on alo[25]+ahi[25] (caller-owned) so we can skip the
   bit-interleave at sponge boundaries when state stays packed across blocks.
   rc_eo points to 48 uint32: [rc[0].e, rc[0].o, rc[1].e, ...]. */
static void
fd_k8eo_perm( v256u * ae, v256u * ao, uint const * rc_eo ) {

  for( int round=0; round<24; round++ ) {

    v256u be[ 25 ] __attribute__((aligned(32)));
    v256u bo[ 25 ] __attribute__((aligned(32)));

    /* Theta column parities: C[x] = XOR over y of A[x,y] (per half). */
    v256u Ce0 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ae[ 0], ae[ 5] ), ae[10] ), ae[15] ), ae[20] );
    v256u Ce1 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ae[ 1], ae[ 6] ), ae[11] ), ae[16] ), ae[21] );
    v256u Ce2 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ae[ 2], ae[ 7] ), ae[12] ), ae[17] ), ae[22] );
    v256u Ce3 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ae[ 3], ae[ 8] ), ae[13] ), ae[18] ), ae[23] );
    v256u Ce4 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ae[ 4], ae[ 9] ), ae[14] ), ae[19] ), ae[24] );
    v256u Co0 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ao[ 0], ao[ 5] ), ao[10] ), ao[15] ), ao[20] );
    v256u Co1 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ao[ 1], ao[ 6] ), ao[11] ), ao[16] ), ao[21] );
    v256u Co2 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ao[ 2], ao[ 7] ), ao[12] ), ao[17] ), ao[22] );
    v256u Co3 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ao[ 3], ao[ 8] ), ao[13] ), ao[18] ), ao[23] );
    v256u Co4 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ao[ 4], ao[ 9] ), ao[14] ), ao[19] ), ao[24] );

    /* Theta D[x] = C[x-1] ^ rotl1(C[x+1]).  In (E,O):
         D[x].E = C[x-1].E XOR rol32(C[x+1].O, 1)   (3 + 1 = 4 ops)
         D[x].O = C[x-1].O XOR C[x+1].E             (1 op) */
    v256u D_e[ 5 ];
    v256u D_o[ 5 ];
    D_e[0] = _mm256_xor_si256( Ce4, K8EO_ROL32_C( Co1, 1 ) );
    D_o[0] = _mm256_xor_si256( Co4, Ce1                  );
    D_e[1] = _mm256_xor_si256( Ce0, K8EO_ROL32_C( Co2, 1 ) );
    D_o[1] = _mm256_xor_si256( Co0, Ce2                  );
    D_e[2] = _mm256_xor_si256( Ce1, K8EO_ROL32_C( Co3, 1 ) );
    D_o[2] = _mm256_xor_si256( Co1, Ce3                  );
    D_e[3] = _mm256_xor_si256( Ce2, K8EO_ROL32_C( Co4, 1 ) );
    D_o[3] = _mm256_xor_si256( Co2, Ce4                  );
    D_e[4] = _mm256_xor_si256( Ce3, K8EO_ROL32_C( Co0, 1 ) );
    D_o[4] = _mm256_xor_si256( Co3, Ce0                  );

    /* Fused Theta-XOR + Rho + Pi. */
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 0, 0,  0,  0 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 1, 0, 10,  1 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 0, 2,  7,  3 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 2, 1, 11,  6 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 1, 2, 17, 10 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 2, 3, 18, 15 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 3, 3,  3, 21 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 3, 0,  5, 28 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 0, 1, 16, 36 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 1, 3,  8, 45 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 3, 1, 21, 55 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 1, 4, 24,  2 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 4, 4,  4, 14 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 4, 0, 15, 27 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 0, 3, 23, 41 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 3, 4, 19, 56 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 4, 3, 13,  8 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 3, 2, 12, 25 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 2, 2,  2, 43 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 2, 0, 20, 62 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 0, 4, 14, 18 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 4, 2, 22, 39 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 2, 4,  9, 61 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 4, 1,  6, 20 );
    K8EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 1, 1,  1, 44 );

    /* Chi: bitwise gates apply identically to E and O halves. */
    for( int y=0; y<5; y++ ) {
      int const r = 5*y;
      v256u const b0e = be[r+0], b0o = bo[r+0];
      v256u const b1e = be[r+1], b1o = bo[r+1];
      v256u const b2e = be[r+2], b2o = bo[r+2];
      v256u const b3e = be[r+3], b3o = bo[r+3];
      v256u const b4e = be[r+4], b4o = bo[r+4];
      ae[r+0] = _mm256_xor_si256( b0e, _mm256_andnot_si256( b1e, b2e ) );
      ao[r+0] = _mm256_xor_si256( b0o, _mm256_andnot_si256( b1o, b2o ) );
      ae[r+1] = _mm256_xor_si256( b1e, _mm256_andnot_si256( b2e, b3e ) );
      ao[r+1] = _mm256_xor_si256( b1o, _mm256_andnot_si256( b2o, b3o ) );
      ae[r+2] = _mm256_xor_si256( b2e, _mm256_andnot_si256( b3e, b4e ) );
      ao[r+2] = _mm256_xor_si256( b2o, _mm256_andnot_si256( b3o, b4o ) );
      ae[r+3] = _mm256_xor_si256( b3e, _mm256_andnot_si256( b4e, b0e ) );
      ao[r+3] = _mm256_xor_si256( b3o, _mm256_andnot_si256( b4o, b0o ) );
      ae[r+4] = _mm256_xor_si256( b4e, _mm256_andnot_si256( b0e, b1e ) );
      ao[r+4] = _mm256_xor_si256( b4o, _mm256_andnot_si256( b0o, b1o ) );
    }

    /* Iota: lane 0; rc_eo holds pre-deinterleaved (E,O) round constants. */
    ae[ 0 ] = _mm256_xor_si256( ae[ 0 ], _mm256_set1_epi32( (int)rc_eo[ 2*round   ] ) );
    ao[ 0 ] = _mm256_xor_si256( ao[ 0 ], _mm256_set1_epi32( (int)rc_eo[ 2*round+1 ] ) );
  }
}

void
fd_keccak256_avx2_keccak8_eo_f1600( ulong *       state,
                                    ulong const * rc ) {

  v256u ae[ 25 ] __attribute__((aligned(32)));
  v256u ao[ 25 ] __attribute__((aligned(32)));

  /* Pre-deinterleave round constants once. */
  uint rc_eo[ 48 ] __attribute__((aligned(32)));
  for( int r=0; r<24; r++ ) fd_k8eo_pack( rc[ r ], &rc_eo[ 2*r ], &rc_eo[ 2*r+1 ] );

  /* AoS -> SoA(E,O) using vectorized 4-u64-parallel deinterleave. */
  for( int z=0; z<25; z++ ) {
    fd_k8eo_pack_ymm( state, z, &ae[ z ], &ao[ z ] );
  }

  fd_k8eo_perm( ae, ao, rc_eo );

  /* SoA(E,O) -> AoS using vectorized 4-u64-parallel reinterleave. */
  for( int z=0; z<25; z++ ) {
    fd_k8eo_unpack_ymm( ae[ z ], ao[ z ], state, z );
  }
}

/* Raw entry point: state is ALREADY in (E,O) SoA form (50 ymm slots, see
   fd_k8eo_perm signature).  No boundary conversion.  Useful when the sponge
   keeps state in (E,O) form across multiple f1600 calls.  rc_eo must be the
   pre-deinterleaved 48 uint32 round-constant table. */
void
fd_keccak256_avx2_keccak8_eo_f1600_raw( void *       state_eo,
                                        uint const * rc_eo ) {
  v256u * ae = (v256u *)state_eo;
  v256u * ao = ae + 25;
  fd_k8eo_perm( ae, ao, rc_eo );
}

/* Build the pre-deinterleaved RC table at runtime (pdep cost is negligible). */
void
fd_keccak256_avx2_keccak8_eo_rc_pack( ulong const * rc, uint * rc_eo ) {
  for( int r=0; r<24; r++ ) fd_k8eo_pack( rc[ r ], &rc_eo[ 2*r ], &rc_eo[ 2*r+1 ] );
}

/* XOR a "block" of input bytes into the rate of the (E,O) state.
   blocks: 8 instances of 17 contiguous u64 each (instance k at &blocks[k*17]).
   stride between instance bases is 17 u64.
   Used as a Keccak-256 / SHA-3-256 sponge absorb step (rate = 1088 bits = 17 u64). */
void
fd_keccak256_avx2_keccak8_eo_absorb_block( void const * blocks,
                                           void *       state_eo ) {
  ulong const * p  = (ulong const *)blocks;
  v256u *       ae = (v256u *)state_eo;
  v256u *       ao = ae + 25;
  v256u const perm_idx = _mm256_set_epi32( 7, 5, 3, 1, 6, 4, 2, 0 );
  for( int z=0; z<17; z++ ) {
    /* Gather z-th u64 from each of 8 instances (stride = 17 u64 = 136 B). */
    ulong const * pp = p + z;
    __m128i a0 = _mm_loadl_epi64( (__m128i const *)( pp + 0*17 ) );
    a0 = _mm_insert_epi64( a0, (long long)pp[ 1*17 ], 1 );
    __m128i a1 = _mm_loadl_epi64( (__m128i const *)( pp + 2*17 ) );
    a1 = _mm_insert_epi64( a1, (long long)pp[ 3*17 ], 1 );
    v256u w_lo = _mm256_inserti128_si256( _mm256_castsi128_si256( a0 ), a1, 1 );
    __m128i b0 = _mm_loadl_epi64( (__m128i const *)( pp + 4*17 ) );
    b0 = _mm_insert_epi64( b0, (long long)pp[ 5*17 ], 1 );
    __m128i b1 = _mm_loadl_epi64( (__m128i const *)( pp + 6*17 ) );
    b1 = _mm_insert_epi64( b1, (long long)pp[ 7*17 ], 1 );
    v256u w_hi = _mm256_inserti128_si256( _mm256_castsi128_si256( b0 ), b1, 1 );

    w_lo = fd_k8eo_dei_4u64( w_lo );
    w_hi = fd_k8eo_dei_4u64( w_hi );
    v256u const p_lo = _mm256_permutevar8x32_epi32( w_lo, perm_idx );
    v256u const p_hi = _mm256_permutevar8x32_epi32( w_hi, perm_idx );
    v256u const in_e = _mm256_permute2x128_si256( p_lo, p_hi, 0x20 );
    v256u const in_o = _mm256_permute2x128_si256( p_lo, p_hi, 0x31 );

    ae[ z ] = _mm256_xor_si256( ae[ z ], in_e );
    ao[ z ] = _mm256_xor_si256( ao[ z ], in_o );
  }
}
