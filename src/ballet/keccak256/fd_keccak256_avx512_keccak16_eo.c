/* Keccak-f[1600] x16 batched on AVX-512 with EVEN/ODD bit-interleaved limbs.

   Each 64-bit Keccak lane w of one of 16 parallel states decomposes as:
     E_k = w[2k]      for k in 0..31    (the even bits, packed into a u32)
     O_k = w[2k+1]    for k in 0..31    (the odd  bits, packed into a u32)

   Each __m512i holds the same (E or O) half of one Keccak lane index across
   16 independent instances (lane-major SoA over 16 instances of u32 halves).
   All bitwise ops commute with the bit-interleave so they apply per-half.

   State layout: 25 zmm of E halves followed by 25 zmm of O halves = 50 zmm
   = 3200 B.  Doesn't fit in 32 zmm registers; the compiler spills the
   colder lanes to stack.

   Per-round op budget vs the AVX2 keccak8 EO path:
     - Theta C parities:  20 vpxor       (was 20)
     - Theta D:            5 vprold + 10 vpxor          (was 5*3 + 10 = 25)
     - Fused theta+rho+pi: 50 vpxor + ~47 vprold         (was 50 vpxor + ~47*3 vp{sl,sr,or})
     - Chi:               50 vpternlogd                  (was 50 vpandn + 50 vpxor)
     - Iota:               2 vpxor (broadcast E,O halves)
   ~180 ops/round, processing 16 states in parallel = ~11 ops/state/round. */

#include "../fd_ballet_base.h"
#include <immintrin.h>

#if FD_HAS_AVX512

typedef __m512i v512u;

/* Logical 64-bit rotl by D (compile-time const) on a (E,O) zmm pair.
   Even D = 2k:  rotate each half by k (vprold, 1 op each).
   Odd  D = 2k+1: SWAP halves, then E' = rotl32(O, k+1), O' = rotl32(E, k).
   D = 0 collapses to register relabel. */
#define K16EO_ROL64_C( EOUT, OOUT, EIN, OIN, D ) do {                              \
    if(       (D) == 0       ) { (EOUT) = (EIN); (OOUT) = (OIN); }                 \
    else if ( ((D) & 1) == 0 ) { /* even */                                        \
      (EOUT) = _mm512_rol_epi32( (EIN), ((D)/2)         );                         \
      (OOUT) = _mm512_rol_epi32( (OIN), ((D)/2)         );                         \
    } else {                       /* odd */                                       \
      (EOUT) = _mm512_rol_epi32( (OIN), (((D)-1)/2) + 1 );                         \
      (OOUT) = _mm512_rol_epi32( (EIN), (((D)-1)/2)     );                         \
    }                                                                              \
  } while(0)

/* Fused step: (a^D) at source (X,Y), rotl by RHO_D, store to b[PI_XY]. */
#define K16EO_THETA_RHO_PI( BE, BO, AE, AO, DE, DO, X, Y, PI_XY, RHO_D ) do {      \
    v512u _te = _mm512_xor_si512( (AE)[ (X) + 5*(Y) ], (DE)[ (X) ] );              \
    v512u _to = _mm512_xor_si512( (AO)[ (X) + 5*(Y) ], (DO)[ (X) ] );              \
    K16EO_ROL64_C( (BE)[ (PI_XY) ], (BO)[ (PI_XY) ], _te, _to, RHO_D );            \
  } while(0)

/* Inner permutation: 16 parallel states already in (E,O) SoA form.
   `ae`/`ao` are 25 zmm each (lane 0..24 of E and O respectively).
   `rc_eo` is 48 u32: pre-deinterleaved (E,O) for each of 24 round constants. */
static void
fd_k16eo_perm( v512u *      ae,
               v512u *      ao,
               uint const * rc_eo ) {

  for( int round=0; round<24; round++ ) {

    v512u be[ 25 ] __attribute__((aligned(64)));
    v512u bo[ 25 ] __attribute__((aligned(64)));

    /* ===== Theta column parities ============================================ */
    v512u Ce0 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( ae[ 0], ae[ 5] ), ae[10] ), ae[15] ), ae[20] );
    v512u Ce1 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( ae[ 1], ae[ 6] ), ae[11] ), ae[16] ), ae[21] );
    v512u Ce2 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( ae[ 2], ae[ 7] ), ae[12] ), ae[17] ), ae[22] );
    v512u Ce3 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( ae[ 3], ae[ 8] ), ae[13] ), ae[18] ), ae[23] );
    v512u Ce4 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( ae[ 4], ae[ 9] ), ae[14] ), ae[19] ), ae[24] );
    v512u Co0 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( ao[ 0], ao[ 5] ), ao[10] ), ao[15] ), ao[20] );
    v512u Co1 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( ao[ 1], ao[ 6] ), ao[11] ), ao[16] ), ao[21] );
    v512u Co2 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( ao[ 2], ao[ 7] ), ao[12] ), ao[17] ), ao[22] );
    v512u Co3 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( ao[ 3], ao[ 8] ), ao[13] ), ao[18] ), ao[23] );
    v512u Co4 = _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( _mm512_xor_si512( ao[ 4], ao[ 9] ), ao[14] ), ao[19] ), ao[24] );

    /* ===== Theta D: (E,O)-encoded =========================================
       D[x].E = C[xm].E ^ rotl32(C[xp].O, 1)     (vprold, 1 op)
       D[x].O = C[xm].O ^         C[xp].E       (no rotation) */
    v512u D_e[ 5 ];
    v512u D_o[ 5 ];
    D_e[0] = _mm512_xor_si512( Ce4, _mm512_rol_epi32( Co1, 1 ) );
    D_o[0] = _mm512_xor_si512( Co4, Ce1                       );
    D_e[1] = _mm512_xor_si512( Ce0, _mm512_rol_epi32( Co2, 1 ) );
    D_o[1] = _mm512_xor_si512( Co0, Ce2                       );
    D_e[2] = _mm512_xor_si512( Ce1, _mm512_rol_epi32( Co3, 1 ) );
    D_o[2] = _mm512_xor_si512( Co1, Ce3                       );
    D_e[3] = _mm512_xor_si512( Ce2, _mm512_rol_epi32( Co4, 1 ) );
    D_o[3] = _mm512_xor_si512( Co2, Ce4                       );
    D_e[4] = _mm512_xor_si512( Ce3, _mm512_rol_epi32( Co0, 1 ) );
    D_o[4] = _mm512_xor_si512( Co3, Ce0                       );

    /* ===== Fused Theta-XOR + Rho + Pi ====================================== */
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 0, 0,  0,  0 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 1, 0, 10,  1 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 0, 2,  7,  3 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 2, 1, 11,  6 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 1, 2, 17, 10 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 2, 3, 18, 15 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 3, 3,  3, 21 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 3, 0,  5, 28 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 0, 1, 16, 36 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 1, 3,  8, 45 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 3, 1, 21, 55 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 1, 4, 24,  2 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 4, 4,  4, 14 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 4, 0, 15, 27 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 0, 3, 23, 41 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 3, 4, 19, 56 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 4, 3, 13,  8 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 3, 2, 12, 25 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 2, 2,  2, 43 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 2, 0, 20, 62 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 0, 4, 14, 18 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 4, 2, 22, 39 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 2, 4,  9, 61 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 4, 1,  6, 20 );
    K16EO_THETA_RHO_PI( be, bo, ae, ao, D_e, D_o, 1, 1,  1, 44 );

    /* ===== Chi: vpternlogd(b0, b1, b2, 0xD2) = b0 ^ (~b1 & b2) ============= */
    for( int y=0; y<5; y++ ) {
      int const r = 5*y;
      v512u const b0e = be[r+0], b0o = bo[r+0];
      v512u const b1e = be[r+1], b1o = bo[r+1];
      v512u const b2e = be[r+2], b2o = bo[r+2];
      v512u const b3e = be[r+3], b3o = bo[r+3];
      v512u const b4e = be[r+4], b4o = bo[r+4];
      ae[r+0] = _mm512_ternarylogic_epi32( b0e, b1e, b2e, 0xD2 );
      ao[r+0] = _mm512_ternarylogic_epi32( b0o, b1o, b2o, 0xD2 );
      ae[r+1] = _mm512_ternarylogic_epi32( b1e, b2e, b3e, 0xD2 );
      ao[r+1] = _mm512_ternarylogic_epi32( b1o, b2o, b3o, 0xD2 );
      ae[r+2] = _mm512_ternarylogic_epi32( b2e, b3e, b4e, 0xD2 );
      ao[r+2] = _mm512_ternarylogic_epi32( b2o, b3o, b4o, 0xD2 );
      ae[r+3] = _mm512_ternarylogic_epi32( b3e, b4e, b0e, 0xD2 );
      ao[r+3] = _mm512_ternarylogic_epi32( b3o, b4o, b0o, 0xD2 );
      ae[r+4] = _mm512_ternarylogic_epi32( b4e, b0e, b1e, 0xD2 );
      ao[r+4] = _mm512_ternarylogic_epi32( b4o, b0o, b1o, 0xD2 );
    }

    /* ===== Iota: lane 0 (E,O); rc_eo holds pre-deinterleaved (E,O) RCs. ===== */
    ae[ 0 ] = _mm512_xor_si512( ae[ 0 ], _mm512_set1_epi32( (int)rc_eo[ 2*round   ] ) );
    ao[ 0 ] = _mm512_xor_si512( ao[ 0 ], _mm512_set1_epi32( (int)rc_eo[ 2*round+1 ] ) );
  }
}

/* Bit deinterleave a u64 -> (E, O) using BMI2 pext (1-cycle each). */
static inline void
fd_k16eo_pack( ulong w, uint * e, uint * o ) {
  *e = (uint)_pext_u64( w, 0x5555555555555555UL );
  *o = (uint)_pext_u64( w, 0xAAAAAAAAAAAAAAAAUL );
}

static inline ulong
fd_k16eo_unpack( uint e, uint o ) {
  return _pdep_u64( (ulong)e, 0x5555555555555555UL )
       | _pdep_u64( (ulong)o, 0xAAAAAAAAAAAAAAAAUL );
}

/* AoS -> SoA(E,O) for one Keccak lane index z.  Loads 16 strided u64s,
   bit-deinterleaves each into (E, O), and packs the 16 E's into one zmm
   and the 16 O's into another. */
static inline void
fd_k16eo_pack_zmm( ulong const * state, int z, v512u * out_e, v512u * out_o ) {
  ulong const * p = state + z;
  uint e[ 16 ] __attribute__((aligned(64)));
  uint o[ 16 ] __attribute__((aligned(64)));
  for( int s=0; s<16; s++ ) fd_k16eo_pack( p[ s*25 ], &e[ s ], &o[ s ] );
  *out_e = _mm512_load_si512( (v512u const *)e );
  *out_o = _mm512_load_si512( (v512u const *)o );
}

/* Inverse of pack_zmm: SoA(E,O) -> AoS scatter back into state. */
static inline void
fd_k16eo_unpack_zmm( v512u in_e, v512u in_o, ulong * state, int z ) {
  uint e[ 16 ] __attribute__((aligned(64)));
  uint o[ 16 ] __attribute__((aligned(64)));
  _mm512_store_si512( (v512u *)e, in_e );
  _mm512_store_si512( (v512u *)o, in_o );
  ulong * p = state + z;
  for( int s=0; s<16; s++ ) p[ s*25 ] = fd_k16eo_unpack( e[ s ], o[ s ] );
}

/* AoS-in/out boundary entry point.  state = 16 contiguous Keccak states
   (16 * 25 = 400 u64 = 3200 B), state[s*25 + z] is lane z of state s.
   rc is the standard 24 native u64 round constants (we'll deinterleave). */
void
fd_keccak256_avx512_keccak16_eo_f1600( ulong *       state,
                                       ulong const * rc ) {
  v512u ae[ 25 ] __attribute__((aligned(64)));
  v512u ao[ 25 ] __attribute__((aligned(64)));

  uint rc_eo[ 48 ] __attribute__((aligned(64)));
  for( int r=0; r<24; r++ ) fd_k16eo_pack( rc[ r ], &rc_eo[ 2*r ], &rc_eo[ 2*r+1 ] );

  for( int z=0; z<25; z++ ) fd_k16eo_pack_zmm( state, z, &ae[ z ], &ao[ z ] );

  fd_k16eo_perm( ae, ao, rc_eo );

  for( int z=0; z<25; z++ ) fd_k16eo_unpack_zmm( ae[ z ], ao[ z ], state, z );
}

/* Raw entry: state already in (E,O) SoA over 16 instances.  Layout:
   50 zmm = 25 E lanes followed by 25 O lanes, 3200 B contiguous.
   rc_eo: pre-deinterleaved 48 uint32 (build via ..._rc_pack below). */
void
fd_keccak256_avx512_keccak16_eo_f1600_raw( void *       state_eo,
                                           uint const * rc_eo ) {
  v512u * ae = (v512u *)state_eo;
  v512u * ao = ae + 25;
  fd_k16eo_perm( ae, ao, rc_eo );
}

/* Build the pre-deinterleaved RC table at runtime. */
void
fd_keccak256_avx512_keccak16_eo_rc_pack( ulong const * rc, uint * rc_eo ) {
  for( int r=0; r<24; r++ ) fd_k16eo_pack( rc[ r ], &rc_eo[ 2*r ], &rc_eo[ 2*r+1 ] );
}

#endif /* FD_HAS_AVX512 */
