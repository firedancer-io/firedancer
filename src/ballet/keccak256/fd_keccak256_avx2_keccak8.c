/* Keccak-f[1600] x8 batched on AVX2.

   SoA layout: each __m256i holds the 32-bit lo (or hi) limb at one Keccak
   index across 8 independent instances; logical 64-bit lane = (lo,hi) pair
   (LE), matching fd_keccak256_interleaved.c and plonky2-crypto's
   [[U32Target;2];25].

   Round structure (XKCP-style fused pass):
     1) Theta column parities C[x] = XOR of column x across 5 rows
     2) Theta D[x] = C[x-1] ^ rotl1(C[x+1])
     3) Fused Theta-XOR + Rho + Pi: for each (x,y),
          B[ pi(x,y) ] = rotl64( A[x,y] ^ D[x], rho(x,y) )
        — each B slot is independent (no rho serial chain).
     4) Chi: A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y])  (per row)
     5) Iota: A[0,0] ^= rc[round]

   All Rho rotations are emitted with compile-time-constant shift counts so
   AVX2 lowers to vpslld/vpsrld with imm8 (vs vpsll xmm,xmm form for runtime
   counts). The 24 rho rotations are unrolled inline. */

#include "../fd_ballet_base.h"
#include <immintrin.h>

typedef __m256i v256u;

/* 64-bit rotate-left on a (lo,hi) limb pair, all 8 SIMD lanes share the
   compile-time-constant amount D. Outputs assigned to LO_OUT/HI_OUT.
   Branches collapse at compile time when D is a literal. */
#define K8_ROL64_C( LO_OUT, HI_OUT, LO_IN, HI_IN, D ) do {                                       \
    if(       (D) == 0  ) { (LO_OUT) = (LO_IN); (HI_OUT) = (HI_IN); }                            \
    else if ( (D) == 32 ) { (LO_OUT) = (HI_IN); (HI_OUT) = (LO_IN); }                            \
    else if ( (D) <  32 ) {                                                                      \
      (LO_OUT) = _mm256_or_si256( _mm256_slli_epi32( (LO_IN), (D)    ),                          \
                                  _mm256_srli_epi32( (HI_IN), 32-(D) ) );                        \
      (HI_OUT) = _mm256_or_si256( _mm256_slli_epi32( (HI_IN), (D)    ),                          \
                                  _mm256_srli_epi32( (LO_IN), 32-(D) ) );                        \
    } else {                                                                                     \
      (LO_OUT) = _mm256_or_si256( _mm256_slli_epi32( (HI_IN), (D)-32 ),                          \
                                  _mm256_srli_epi32( (LO_IN), 64-(D) ) );                        \
      (HI_OUT) = _mm256_or_si256( _mm256_slli_epi32( (LO_IN), (D)-32 ),                          \
                                  _mm256_srli_epi32( (HI_IN), 64-(D) ) );                        \
    }                                                                                            \
  } while(0)

/* Apply Theta XOR (a ^ D[x]) and rho rotate to the (lo,hi) value at a[x,y],
   writing to b[ pi_xy ]. The macro takes the destination index, source x,y
   and rotation amount as compile-time literals. */
#define K8_THETA_RHO_PI( BLO, BHI, ALO, AHI, DLO, DHI, X, Y, PI_XY, RHO_D ) do {                 \
    v256u _tlo = _mm256_xor_si256( (ALO)[ (X) + 5*(Y) ], (DLO)[ (X) ] );                         \
    v256u _thi = _mm256_xor_si256( (AHI)[ (X) + 5*(Y) ], (DHI)[ (X) ] );                         \
    K8_ROL64_C( (BLO)[ (PI_XY) ], (BHI)[ (PI_XY) ], _tlo, _thi, RHO_D );                         \
  } while(0)

void
fd_keccak256_avx2_keccak8_f1600( ulong *       state,
                                 ulong const * rc ) {

  v256u alo[ 25 ] __attribute__((aligned(32)));
  v256u ahi[ 25 ] __attribute__((aligned(32)));

  /* AoS -> SoA: gather 8 instances' lo/hi at each Keccak index z. */
  for( int z=0; z<25; z++ ) {
    uint sl[ 8 ] __attribute__((aligned(32)));
    uint sh[ 8 ] __attribute__((aligned(32)));
    for( int k=0; k<8; k++ ) {
      ulong const wv = state[ (ulong)k*25UL + (ulong)z ];
      sl[ k ] = (uint)( wv         & 0xffffffffu );
      sh[ k ] = (uint)((wv >> 32U) & 0xffffffffu );
    }
    alo[ z ] = _mm256_load_si256( (v256u const *)sl );
    ahi[ z ] = _mm256_load_si256( (v256u const *)sh );
  }

  for( int round=0; round<24; round++ ) {

    v256u blo[ 25 ] __attribute__((aligned(32)));
    v256u bhi[ 25 ] __attribute__((aligned(32)));

    /* --- Theta: column parities C[x] = XOR over y of A[x,y] --- */
    v256u C_lo0 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( alo[ 0], alo[ 5] ), alo[10] ), alo[15] ), alo[20] );
    v256u C_lo1 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( alo[ 1], alo[ 6] ), alo[11] ), alo[16] ), alo[21] );
    v256u C_lo2 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( alo[ 2], alo[ 7] ), alo[12] ), alo[17] ), alo[22] );
    v256u C_lo3 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( alo[ 3], alo[ 8] ), alo[13] ), alo[18] ), alo[23] );
    v256u C_lo4 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( alo[ 4], alo[ 9] ), alo[14] ), alo[19] ), alo[24] );

    v256u C_hi0 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ahi[ 0], ahi[ 5] ), ahi[10] ), ahi[15] ), ahi[20] );
    v256u C_hi1 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ahi[ 1], ahi[ 6] ), ahi[11] ), ahi[16] ), ahi[21] );
    v256u C_hi2 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ahi[ 2], ahi[ 7] ), ahi[12] ), ahi[17] ), ahi[22] );
    v256u C_hi3 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ahi[ 3], ahi[ 8] ), ahi[13] ), ahi[18] ), ahi[23] );
    v256u C_hi4 = _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( _mm256_xor_si256( ahi[ 4], ahi[ 9] ), ahi[14] ), ahi[19] ), ahi[24] );

    /* --- Theta: D[x] = C[x-1] ^ rotl1(C[x+1]) --- */
    /* rotl1 on (lo,hi): lo' = lo<<1 | hi>>31; hi' = hi<<1 | lo>>31 */
    v256u D_lo[ 5 ];
    v256u D_hi[ 5 ];
#define K8_ROL1_LO( IN_LO, IN_HI ) _mm256_or_si256( _mm256_slli_epi32( (IN_LO), 1 ), _mm256_srli_epi32( (IN_HI), 31 ) )
#define K8_ROL1_HI( IN_LO, IN_HI ) _mm256_or_si256( _mm256_slli_epi32( (IN_HI), 1 ), _mm256_srli_epi32( (IN_LO), 31 ) )
    D_lo[ 0 ] = _mm256_xor_si256( C_lo4, K8_ROL1_LO( C_lo1, C_hi1 ) );
    D_hi[ 0 ] = _mm256_xor_si256( C_hi4, K8_ROL1_HI( C_lo1, C_hi1 ) );
    D_lo[ 1 ] = _mm256_xor_si256( C_lo0, K8_ROL1_LO( C_lo2, C_hi2 ) );
    D_hi[ 1 ] = _mm256_xor_si256( C_hi0, K8_ROL1_HI( C_lo2, C_hi2 ) );
    D_lo[ 2 ] = _mm256_xor_si256( C_lo1, K8_ROL1_LO( C_lo3, C_hi3 ) );
    D_hi[ 2 ] = _mm256_xor_si256( C_hi1, K8_ROL1_HI( C_lo3, C_hi3 ) );
    D_lo[ 3 ] = _mm256_xor_si256( C_lo2, K8_ROL1_LO( C_lo4, C_hi4 ) );
    D_hi[ 3 ] = _mm256_xor_si256( C_hi2, K8_ROL1_HI( C_lo4, C_hi4 ) );
    D_lo[ 4 ] = _mm256_xor_si256( C_lo3, K8_ROL1_LO( C_lo0, C_hi0 ) );
    D_hi[ 4 ] = _mm256_xor_si256( C_hi3, K8_ROL1_HI( C_lo0, C_hi0 ) );
#undef K8_ROL1_LO
#undef K8_ROL1_HI

    /* --- Fused Theta-XOR + Rho + Pi: B[pi(x,y)] = rol64( A[x,y]^D[x], rho(x,y) ) ---
       The chain `t = state[1]; for i: state[pi[i]] = rol(t, rho[i]); t = old`
       starts from (x,y)=(1,0) and walks the pi cycle. We unroll it explicitly,
       writing each B target with a literal rho amount so AVX2 emits immediate
       shifts. (x,y) = (0,0) maps to itself with rho=0 — handled separately. */

    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 0, 0,  0,  0 );

    /* Walk the rho/pi chain: each source (x,y) -> destination pi(x,y), rho. */

    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 1, 0, 10,  1 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 0, 2,  7,  3 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 2, 1, 11,  6 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 1, 2, 17, 10 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 2, 3, 18, 15 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 3, 3,  3, 21 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 3, 0,  5, 28 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 0, 1, 16, 36 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 1, 3,  8, 45 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 3, 1, 21, 55 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 1, 4, 24,  2 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 4, 4,  4, 14 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 4, 0, 15, 27 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 0, 3, 23, 41 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 3, 4, 19, 56 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 4, 3, 13,  8 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 3, 2, 12, 25 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 2, 2,  2, 43 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 2, 0, 20, 62 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 0, 4, 14, 18 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 4, 2, 22, 39 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 2, 4,  9, 61 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 4, 1,  6, 20 );
    K8_THETA_RHO_PI( blo, bhi, alo, ahi, D_lo, D_hi, 1, 1,  1, 44 );

    /* --- Chi: A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y]) --- */
    for( int y=0; y<5; y++ ) {
      int const r = 5*y;
      v256u const b0_lo = blo[ r+0 ], b0_hi = bhi[ r+0 ];
      v256u const b1_lo = blo[ r+1 ], b1_hi = bhi[ r+1 ];
      v256u const b2_lo = blo[ r+2 ], b2_hi = bhi[ r+2 ];
      v256u const b3_lo = blo[ r+3 ], b3_hi = bhi[ r+3 ];
      v256u const b4_lo = blo[ r+4 ], b4_hi = bhi[ r+4 ];
      alo[ r+0 ] = _mm256_xor_si256( b0_lo, _mm256_andnot_si256( b1_lo, b2_lo ) );
      ahi[ r+0 ] = _mm256_xor_si256( b0_hi, _mm256_andnot_si256( b1_hi, b2_hi ) );
      alo[ r+1 ] = _mm256_xor_si256( b1_lo, _mm256_andnot_si256( b2_lo, b3_lo ) );
      ahi[ r+1 ] = _mm256_xor_si256( b1_hi, _mm256_andnot_si256( b2_hi, b3_hi ) );
      alo[ r+2 ] = _mm256_xor_si256( b2_lo, _mm256_andnot_si256( b3_lo, b4_lo ) );
      ahi[ r+2 ] = _mm256_xor_si256( b2_hi, _mm256_andnot_si256( b3_hi, b4_hi ) );
      alo[ r+3 ] = _mm256_xor_si256( b3_lo, _mm256_andnot_si256( b4_lo, b0_lo ) );
      ahi[ r+3 ] = _mm256_xor_si256( b3_hi, _mm256_andnot_si256( b4_hi, b0_hi ) );
      alo[ r+4 ] = _mm256_xor_si256( b4_lo, _mm256_andnot_si256( b0_lo, b1_lo ) );
      ahi[ r+4 ] = _mm256_xor_si256( b4_hi, _mm256_andnot_si256( b0_hi, b1_hi ) );
    }

    /* --- Iota: lane 0 only; same rc broadcast across the 8 batched lanes --- */
    ulong const rct = rc[ round ];
    alo[ 0 ] = _mm256_xor_si256( alo[ 0 ], _mm256_set1_epi32( (int)( (uint)( rct          & 0xffffffffu) ) ) );
    ahi[ 0 ] = _mm256_xor_si256( ahi[ 0 ], _mm256_set1_epi32( (int)( (uint)((rct >> 32U)  & 0xffffffffu) ) ) );
  }

  /* SoA -> AoS */
  for( int z=0; z<25; z++ ) {
    uint sl[ 8 ] __attribute__((aligned(32)));
    uint sh[ 8 ] __attribute__((aligned(32)));
    _mm256_store_si256( (v256u *)sl, alo[ z ] );
    _mm256_store_si256( (v256u *)sh, ahi[ z ] );
    for( int k=0; k<8; k++ ) {
      state[ (ulong)k*25UL + (ulong)z ] = ((ulong)sh[ k ] << 32) | (ulong)sl[ k ];
    }
  }
}
