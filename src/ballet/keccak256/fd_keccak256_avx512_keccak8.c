/* Keccak-f[1600] x8 batched on AVX-512 with native 64-bit lanes.

   Each __m512i holds the same Keccak lane index across 8 independent
   instances (lane-major SoA).  No EO bit-interleave is used — AVX-512F
   provides native vprolq (64-bit rotate) so the EO trick that buys us
   `vrolq` simulation on AVX2 is unnecessary here.

   Per-round op budget vs the AVX2 keccak8 EO path:
     - Theta C parities:  20 vpxor (was 20)
     - Theta D:            5 vprolq + 5 vpxor       (was 5*3 + 5 = 20)
     - Fused theta+rho+pi: 25 vpxor + 24 vprolq     (was 25 vpxor + 24*3 vp{sl,sr,or})
     - Chi:               25 vpternlogq             (was 25 vpandn + 25 vpxor)
     - Iota:               1 vpxor (broadcast RC)
   Total ~150 ops/round vs ~498 ops/round on AVX2 EO. ~3x fewer instructions.

   State register pressure: A (25 zmm) fits with room to spare in 32 zmm
   regs.  We use a stack-resident B[25] for theta-rho-pi destinations
   because keeping both A and B live during the fused step would push us
   over 32 regs; the chi step then loads B 5 lanes at a time per row. */

#include "../fd_ballet_base.h"
#include <immintrin.h>
#include <string.h>

#if FD_HAS_AVX512

typedef __m512i v512u;

/* Theta-XOR + Rho + Pi: B[pi(x,y)] = vprolq( A[x+5y] XOR D[x], rho ). */
#define K8_THETA_RHO_PI( B, A, D, X, Y, PI_XY, RHO_D ) do {                        \
    v512u _t = _mm512_xor_si512( (A)[ (X) + 5*(Y) ], (D)[ (X) ] );                 \
    (B)[ (PI_XY) ] = _mm512_rol_epi64( _t, (RHO_D) );                              \
  } while(0)

/* Inner permutation: n_rounds rounds of Keccak-p[1600] over 8 parallel
   states in lane-major SoA.  Rounds run from `start_round` (inclusive)
   to start_round+n_rounds (exclusive), reading rc[start_round..].

   Standard Keccak-f[1600] = (start_round=0, n_rounds=24).
   KangarooTwelve / Keccak-p[1600,12] = (start_round=12, n_rounds=12).

   Marked `inline` so the compiler can specialize and unroll the loop
   when start_round/n_rounds are compile-time constants. */
static inline __attribute__((always_inline)) void
fd_k8_perm_n( v512u *       a,
              ulong const * rc,
              int           start_round,
              int           n_rounds ) {

  for( int round=start_round; round<start_round+n_rounds; round++ ) {

    v512u b[ 25 ] __attribute__((aligned(64)));

    /* ===== Theta column parities: C[x] = XOR over y of A[x,y]. ============ */
    v512u C0 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( a[ 0], a[ 5] ), a[10] ), a[15] ), a[20] );
    v512u C1 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( a[ 1], a[ 6] ), a[11] ), a[16] ), a[21] );
    v512u C2 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( a[ 2], a[ 7] ), a[12] ), a[17] ), a[22] );
    v512u C3 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( a[ 3], a[ 8] ), a[13] ), a[18] ), a[23] );
    v512u C4 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( a[ 4], a[ 9] ), a[14] ), a[19] ), a[24] );

    /* ===== Theta D: D[x] = C[x-1] XOR rotl1(C[x+1]) (vprolq is 1 op). ===== */
    v512u D[ 5 ];
    D[0] = _mm512_xor_si512( C4, _mm512_rol_epi64( C1, 1 ) );
    D[1] = _mm512_xor_si512( C0, _mm512_rol_epi64( C2, 1 ) );
    D[2] = _mm512_xor_si512( C1, _mm512_rol_epi64( C3, 1 ) );
    D[3] = _mm512_xor_si512( C2, _mm512_rol_epi64( C4, 1 ) );
    D[4] = _mm512_xor_si512( C3, _mm512_rol_epi64( C0, 1 ) );

    /* ===== Fused Theta-XOR + Rho + Pi (24 lanes + the identity). ========== */
    K8_THETA_RHO_PI( b, a, D, 0, 0,  0,  0 );
    K8_THETA_RHO_PI( b, a, D, 1, 0, 10,  1 );
    K8_THETA_RHO_PI( b, a, D, 0, 2,  7,  3 );
    K8_THETA_RHO_PI( b, a, D, 2, 1, 11,  6 );
    K8_THETA_RHO_PI( b, a, D, 1, 2, 17, 10 );
    K8_THETA_RHO_PI( b, a, D, 2, 3, 18, 15 );
    K8_THETA_RHO_PI( b, a, D, 3, 3,  3, 21 );
    K8_THETA_RHO_PI( b, a, D, 3, 0,  5, 28 );
    K8_THETA_RHO_PI( b, a, D, 0, 1, 16, 36 );
    K8_THETA_RHO_PI( b, a, D, 1, 3,  8, 45 );
    K8_THETA_RHO_PI( b, a, D, 3, 1, 21, 55 );
    K8_THETA_RHO_PI( b, a, D, 1, 4, 24,  2 );
    K8_THETA_RHO_PI( b, a, D, 4, 4,  4, 14 );
    K8_THETA_RHO_PI( b, a, D, 4, 0, 15, 27 );
    K8_THETA_RHO_PI( b, a, D, 0, 3, 23, 41 );
    K8_THETA_RHO_PI( b, a, D, 3, 4, 19, 56 );
    K8_THETA_RHO_PI( b, a, D, 4, 3, 13,  8 );
    K8_THETA_RHO_PI( b, a, D, 3, 2, 12, 25 );
    K8_THETA_RHO_PI( b, a, D, 2, 2,  2, 43 );
    K8_THETA_RHO_PI( b, a, D, 2, 0, 20, 62 );
    K8_THETA_RHO_PI( b, a, D, 0, 4, 14, 18 );
    K8_THETA_RHO_PI( b, a, D, 4, 2, 22, 39 );
    K8_THETA_RHO_PI( b, a, D, 2, 4,  9, 61 );
    K8_THETA_RHO_PI( b, a, D, 4, 1,  6, 20 );
    K8_THETA_RHO_PI( b, a, D, 1, 1,  1, 44 );

    /* ===== Chi: A[r+x] = B[r+x] XOR (NOT B[r+x+1] AND B[r+x+2]).
       vpternlogq(b0, b1, b2, 0xD2) computes b0 ^ (~b1 & b2) in one op.
       Truth table for 0xD2 = 11010010b:
         b0 b1 b2 -> 0
          0  0  0    0
          0  0  1    1     (~b1 & b2 = 1, 0 ^ 1 = 1)
          0  1  0    0
          0  1  1    0
          1  0  0    1
          1  0  1    0     (~b1 & b2 = 1, 1 ^ 1 = 0)
          1  1  0    1
          1  1  1    1
    ====================================================================== */
    for( int y=0; y<5; y++ ) {
      int const r = 5*y;
      v512u const b0 = b[r+0], b1 = b[r+1], b2 = b[r+2], b3 = b[r+3], b4 = b[r+4];
      a[r+0] = _mm512_ternarylogic_epi64( b0, b1, b2, 0xD2 );
      a[r+1] = _mm512_ternarylogic_epi64( b1, b2, b3, 0xD2 );
      a[r+2] = _mm512_ternarylogic_epi64( b2, b3, b4, 0xD2 );
      a[r+3] = _mm512_ternarylogic_epi64( b3, b4, b0, 0xD2 );
      a[r+4] = _mm512_ternarylogic_epi64( b4, b0, b1, 0xD2 );
    }

    /* ===== Iota: A[0] ^= broadcast(rc[round]). =========================== */
    a[ 0 ] = _mm512_xor_si512( a[ 0 ], _mm512_set1_epi64( (long long)rc[ round ] ) );
  }
}

/* Convenience wrapper: full 24-round Keccak-f[1600]. */
static void
fd_k8_perm( v512u *       a,
            ulong const * rc ) {
  fd_k8_perm_n( a, rc, 0, 24 );
}

/* AoS -> SoA(64-bit) for one Keccak lane index z.  Loads 8 strided u64s
   from state[z + s*25] for s=0..7 and packs them into a single zmm.
   Uses a manual gather + permute sequence; vpgatherqq exists but is slow
   on Zen 4 / Sapphire Rapids. */
static inline v512u
fd_k8_pack_zmm( ulong const * state, int z ) {
  ulong const * p = state + z;
  /* Gather 8 strided u64 (stride 25 u64 = 200 B) into a single zmm. */
  return _mm512_set_epi64( (long long)p[ 7*25 ], (long long)p[ 6*25 ],
                           (long long)p[ 5*25 ], (long long)p[ 4*25 ],
                           (long long)p[ 3*25 ], (long long)p[ 2*25 ],
                           (long long)p[ 1*25 ], (long long)p[ 0*25 ] );
}

static inline void
fd_k8_unpack_zmm( v512u in, ulong * state, int z ) {
  ulong tmp[ 8 ] __attribute__((aligned(64)));
  _mm512_store_si512( (v512u *)tmp, in );
  state[ z + 0*25 ] = tmp[ 0 ];
  state[ z + 1*25 ] = tmp[ 1 ];
  state[ z + 2*25 ] = tmp[ 2 ];
  state[ z + 3*25 ] = tmp[ 3 ];
  state[ z + 4*25 ] = tmp[ 4 ];
  state[ z + 5*25 ] = tmp[ 5 ];
  state[ z + 6*25 ] = tmp[ 6 ];
  state[ z + 7*25 ] = tmp[ 7 ];
}

/* AoS-in/out boundary entry point: state is 8 contiguous Keccak-f[1600]
   states, state[s*25 + z] for s in 0..7, z in 0..24.  rc is the 24 native
   u64 round constants (the standard Keccak round-constant table). */
void
fd_keccak256_avx512_keccak8_f1600( ulong *       state,
                                   ulong const * rc ) {
  v512u a[ 25 ] __attribute__((aligned(64)));

  for( int z=0; z<25; z++ ) a[ z ] = fd_k8_pack_zmm( state, z );

  fd_k8_perm( a, rc );

  for( int z=0; z<25; z++ ) fd_k8_unpack_zmm( a[ z ], state, z );
}

/* Raw entry point: state is ALREADY in lane-major SoA form (25 zmm slots,
   1600 B contiguous, zmm[z] holds lane z across 8 instances).  No boundary
   conversion.  Useful for sponge use where state stays packed across blocks. */
void
fd_keccak256_avx512_keccak8_f1600_raw( void *        state_soa,
                                       ulong const * rc ) {
  fd_k8_perm( (v512u *)state_soa, rc );
}

/* Raw 12-round entry (Keccak-p[1600,12], KangarooTwelve convention):
   uses round constants rc[12..23] (the LAST 12 of the 24).  Same SoA
   layout as the 24-round raw entry.  Exists for fd_lthash2 and other
   K12-based constructions. */
void
fd_keccak256_avx512_keccak8_f1600_12r_raw( void *        state_soa,
                                           ulong const * rc ) {
  fd_k8_perm_n( (v512u *)state_soa, rc, 12, 12 );
}

/* ===== Helpers for fd_lthash2 squeeze counter-mode ====================== */

void
fd_keccak256_avx512_keccak8_broadcast_state( void *        state_soa,
                                             ulong const * base ) {
  v512u * a = (v512u *)state_soa;
  for( int z=0; z<25; z++ ) a[ z ] = _mm512_set1_epi64( (long long)base[ z ] );
}

void
fd_keccak256_avx512_keccak8_xor_into_lane( void *        state_soa,
                                           int           lane_idx,
                                           ulong const * ctrs ) {
  v512u * a = (v512u *)state_soa;
  v512u   c = _mm512_loadu_si512( (v512u const *)ctrs );
  a[ lane_idx ] = _mm512_xor_si512( a[ lane_idx ], c );
}

void
fd_keccak256_avx512_keccak8_extract_lane( ulong        dest[25],
                                          void const * state_soa,
                                          int          lane_idx ) {
  ulong const * a = (ulong const *)state_soa;  /* 25 zmm * 8 u64 = 200 u64 */
  for( int z=0; z<25; z++ ) dest[ z ] = a[ z*8 + lane_idx ];
}

void
fd_keccak256_avx512_keccak8_inject_lane( void *        state_soa,
                                         int           lane_idx,
                                         ulong const * src ) {
  ulong * a = (ulong *)state_soa;
  for( int z=0; z<25; z++ ) a[ z*8 + lane_idx ] = src[ z ];
}

void
fd_keccak256_avx512_keccak8_xor_block_into_state( void *       state_soa,
                                                  void const * blocks[8],
                                                  ulong        rate_lanes ) {
  v512u * a = (v512u *)state_soa;
  for( ulong z=0UL; z<rate_lanes; z++ ) {
    ulong vals[ 8 ] __attribute__((aligned(64)));
    for( int s=0; s<8; s++ ) memcpy( &vals[ s ], (uchar const *)blocks[ s ] + 8*z, 8 );
    v512u v = _mm512_load_si512( (v512u const *)vals );
    a[ z ] = _mm512_xor_si512( a[ z ], v );
  }
}

void
fd_keccak256_avx512_keccak8_extract_rate( void *       out[8],
                                          void const * state_soa,
                                          ulong        rate_bytes ) {
  v512u const * a = (v512u const *)state_soa;
  ulong const   nlanes = rate_bytes >> 3;   /* assumed multiple of 8 */

  /* Per-lane scratch: dump each used zmm to a 64-byte buffer once, then
     copy 8 bytes per state per lane.  Cheaper than gather/scatter. */
  ulong tmp[ 25 ][ 8 ] __attribute__((aligned(64)));
  for( ulong z=0UL; z<nlanes; z++ ) {
    _mm512_store_si512( (v512u *)tmp[ z ], a[ z ] );
  }
  for( int s=0; s<8; s++ ) {
    ulong * dst = (ulong *)out[ s ];
    for( ulong z=0UL; z<nlanes; z++ ) dst[ z ] = tmp[ z ][ s ];
  }
}

/* XOR a "block" of input bytes into the rate of the SoA state.
   blocks: 8 instances of 17 contiguous u64 each (instance s at &blocks[s*17]).
   Used as a Keccak-256 / SHA-3-256 sponge absorb step (rate = 1088 bits). */
void
fd_keccak256_avx512_keccak8_absorb_block( void const * blocks,
                                          void *       state_soa ) {
  ulong const * p = (ulong const *)blocks;
  v512u *       a = (v512u *)state_soa;
  for( int z=0; z<17; z++ ) {
    /* Gather z-th u64 from each of 8 instances (stride 17 u64 = 136 B). */
    v512u const in = _mm512_set_epi64( (long long)p[ 7*17 + z ], (long long)p[ 6*17 + z ],
                                       (long long)p[ 5*17 + z ], (long long)p[ 4*17 + z ],
                                       (long long)p[ 3*17 + z ], (long long)p[ 2*17 + z ],
                                       (long long)p[ 1*17 + z ], (long long)p[ 0*17 + z ] );
    a[ z ] = _mm512_xor_si512( a[ z ], in );
  }
}

#endif /* FD_HAS_AVX512 */
