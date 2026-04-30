/* Single-state Keccak-p[1600,N] for fd_lthash2 absorb.
 *
 * IMPLEMENTATION NOTES
 * --------------------
 * Currently uses scalar 64-bit GPR with native `rorq`/`rolq`.  Estimated
 * ~150 ns/state for 12 rounds on Zen 4.  This is the absorb cost in
 * fd_lthash2_compute (sequential mode).
 *
 * A future optimization could use an AVX-512 "5-pack" layout (5 zmm * 5
 * lanes-per-zmm, 3 padding) for ~25-30% speedup, but the complexity is
 * not justified by the small absolute savings (absorb is ~150 ns vs the
 * ~650 ns squeeze cost that dominates the lthash2 wall time).
 *
 * For now we trust the compiler with a clean inline implementation. */

#include "../fd_ballet_base.h"
#include "fd_keccak256_avx512_internal.h"

#if FD_HAS_AVX512

/* Keccak-f[1600] rho amounts r[x][y] (= rho table). */
static const uint fd_k1_rho[ 25 ] = {
   0,  1, 62, 28, 27,
  36, 44,  6, 55, 20,
   3, 10, 43, 25, 39,
  41, 45, 15, 21,  8,
  18,  2, 61, 56, 14
};

/* Pi mapping: pi[i] tells us which source lane goes to destination i,
   computed as: B[(2x+3y)%5][x] = rotl(A[x,y], r[x,y]).
   Equivalently, src_at_dest[2x+3y mod 5 + 5*x] = (x + 5*y).  Precomputed. */
static const uchar fd_k1_pi[ 25 ] = {
   0,  6, 12, 18, 24,
   3,  9, 10, 16, 22,
   1,  7, 13, 19, 20,
   4,  5, 11, 17, 23,
   2,  8, 14, 15, 21
};

static inline ulong rotl64( ulong x, int n ) {
  /* Compiler emits a single `rolq $n, %reg` for compile-time `n`. */
  return ( x << (n & 63) ) | ( x >> ((64 - n) & 63) );
}

static inline void
fd_k1_perm( ulong *       a,
            ulong const * rc,
            int           start_round,
            int           n_rounds ) {
  for( int r=start_round; r<start_round+n_rounds; r++ ) {
    /* Theta: C[x] = XOR_y A[x,y] */
    ulong C0 = a[ 0] ^ a[ 5] ^ a[10] ^ a[15] ^ a[20];
    ulong C1 = a[ 1] ^ a[ 6] ^ a[11] ^ a[16] ^ a[21];
    ulong C2 = a[ 2] ^ a[ 7] ^ a[12] ^ a[17] ^ a[22];
    ulong C3 = a[ 3] ^ a[ 8] ^ a[13] ^ a[18] ^ a[23];
    ulong C4 = a[ 4] ^ a[ 9] ^ a[14] ^ a[19] ^ a[24];

    /* Theta D: D[x] = C[x-1] ^ rotl(C[x+1], 1) */
    ulong D0 = C4 ^ rotl64( C1, 1 );
    ulong D1 = C0 ^ rotl64( C2, 1 );
    ulong D2 = C1 ^ rotl64( C3, 1 );
    ulong D3 = C2 ^ rotl64( C4, 1 );
    ulong D4 = C3 ^ rotl64( C0, 1 );

    /* Theta XOR + Rho + Pi (fused) into B[]. */
    ulong B[ 25 ];
    ulong A;
    A = a[ 0] ^ D0;  B[ 0] = rotl64( A,  0 );
    A = a[ 5] ^ D0;  B[16] = rotl64( A, 36 );
    A = a[10] ^ D0;  B[ 7] = rotl64( A,  3 );
    A = a[15] ^ D0;  B[23] = rotl64( A, 41 );
    A = a[20] ^ D0;  B[14] = rotl64( A, 18 );
    A = a[ 1] ^ D1;  B[10] = rotl64( A,  1 );
    A = a[ 6] ^ D1;  B[ 1] = rotl64( A, 44 );
    A = a[11] ^ D1;  B[17] = rotl64( A, 10 );
    A = a[16] ^ D1;  B[ 8] = rotl64( A, 45 );
    A = a[21] ^ D1;  B[24] = rotl64( A,  2 );
    A = a[ 2] ^ D2;  B[20] = rotl64( A, 62 );
    A = a[ 7] ^ D2;  B[11] = rotl64( A,  6 );
    A = a[12] ^ D2;  B[ 2] = rotl64( A, 43 );
    A = a[17] ^ D2;  B[18] = rotl64( A, 15 );
    A = a[22] ^ D2;  B[ 9] = rotl64( A, 61 );
    A = a[ 3] ^ D3;  B[ 5] = rotl64( A, 28 );
    A = a[ 8] ^ D3;  B[21] = rotl64( A, 55 );
    A = a[13] ^ D3;  B[12] = rotl64( A, 25 );
    A = a[18] ^ D3;  B[ 3] = rotl64( A, 21 );
    A = a[23] ^ D3;  B[19] = rotl64( A, 56 );
    A = a[ 4] ^ D4;  B[15] = rotl64( A, 27 );
    A = a[ 9] ^ D4;  B[ 6] = rotl64( A, 20 );
    A = a[14] ^ D4;  B[22] = rotl64( A, 39 );
    A = a[19] ^ D4;  B[13] = rotl64( A,  8 );  /* (4,3) */
    A = a[24] ^ D4;  B[ 4] = rotl64( A, 14 );  /* (4,4) */

    /* Chi: A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y]). */
    for( int y=0; y<5; y++ ) {
      int const k = 5*y;
      ulong b0 = B[k+0], b1 = B[k+1], b2 = B[k+2], b3 = B[k+3], b4 = B[k+4];
      a[k+0] = b0 ^ (~b1 & b2);
      a[k+1] = b1 ^ (~b2 & b3);
      a[k+2] = b2 ^ (~b3 & b4);
      a[k+3] = b3 ^ (~b4 & b0);
      a[k+4] = b4 ^ (~b0 & b1);
    }

    /* Iota: A[0,0] ^= rc[r]. */
    a[ 0 ] ^= rc[ r ];
  }
  (void)fd_k1_rho; (void)fd_k1_pi;  /* tables kept for documentation */
}

void
fd_keccak256_avx512_keccak1_f1600_12r( ulong         state[25],
                                       ulong const * rc ) {
  fd_k1_perm( state, rc, 12, 12 );
}

#endif /* FD_HAS_AVX512 */
