/* Keccak-f[1600] x8 batched on AVX-512 with native 64-bit lanes.

   Each __m512i holds the same Keccak lane index across 8 independent
   instances (lane-major SoA).  No EO bit-interleave is used — AVX-512F
   provides native vprolq (64-bit rotate) so the EO trick that buys us
   `vrolq` simulation on AVX2 is unnecessary here.

   The permutation keeps all 25 state lanes live in zmm registers across
   every round.  Pi (the lane permutation) is realized as compile-time
   register renaming rather than data movement: the 4-round macro reads
   and writes a different set of named registers each round, so the lanes
   "rotate through names" and return to canonical positions after every 4
   rounds.  This eliminates both the pi data shuffle and any spill of a
   scratch lane array to the stack.

   Per-round op budget:
     - Theta C parities:  10 vpternlogq (XOR5 = 2 ternarylogic / column)
     - Theta D:            5 vprolq + 5 vpxor
     - Theta-XOR + Rho:   25 vpxor + 24 vprolq (fused into the chi groups)
     - Chi:               25 vpternlogq
     - Iota:               1 vpxor (broadcast RC)

   This mirrors the structure of XKCP's KeccakP-1600-times8 AVX-512
   permutation (public domain); the round-constant table and SoA lane
   layout are ours.  25 state + 5 B + 5 D = 35 V512; the renaming keeps
   the simultaneously-live set within the 32 zmm registers. */

#include "../fd_ballet_base.h"
#include <immintrin.h>
#include <string.h>

#if FD_HAS_AVX512

typedef __m512i v512u;

#define XOR(a,b)        _mm512_xor_si512( (a), (b) )
#define XOR3(a,b,c)     _mm512_ternarylogic_epi64( (a), (b), (c), 0x96 )
#define XOR5(a,b,c,d,e) XOR3( XOR3( (a), (b), (c) ), (d), (e) )
#define ROL(a,o)        _mm512_rol_epi64( (a), (o) )
/* Chi: a ^ (~b & c) in a single op (truth table 0xD2). */
#define Chi(a,b,c)      _mm512_ternarylogic_epi64( (a), (b), (c), 0xD2 )
#define CONST8_64(a)    _mm512_set1_epi64( (long long)(a) )

#define KeccakP_DeclareVars \
    v512u _Ba, _Be, _Bi, _Bo, _Bu; \
    v512u _Da, _De, _Di, _Do, _Du; \
    v512u _ba, _be, _bi, _bo, _bu; \
    v512u _ga, _ge, _gi, _go, _gu; \
    v512u _ka, _ke, _ki, _ko, _ku; \
    v512u _ma, _me, _mi, _mo, _mu; \
    v512u _sa, _se, _si, _so, _su

#define KeccakP_ThetaRhoPiChi( _L1, _L2, _L3, _L4, _L5, _Bb1, _Bb2, _Bb3, _Bb4, _Bb5, _Rr1, _Rr2, _Rr3, _Rr4, _Rr5 ) \
    _Bb1 = XOR(_L1, _Da); \
    _Bb2 = XOR(_L2, _De); \
    _Bb3 = XOR(_L3, _Di); \
    _Bb4 = XOR(_L4, _Do); \
    _Bb5 = XOR(_L5, _Du); \
    if (_Rr1 != 0) _Bb1 = ROL(_Bb1, _Rr1); \
    _Bb2 = ROL(_Bb2, _Rr2); \
    _Bb3 = ROL(_Bb3, _Rr3); \
    _Bb4 = ROL(_Bb4, _Rr4); \
    _Bb5 = ROL(_Bb5, _Rr5); \
    _L1 = Chi( _Ba, _Be, _Bi); \
    _L2 = Chi( _Be, _Bi, _Bo); \
    _L3 = Chi( _Bi, _Bo, _Bu); \
    _L4 = Chi( _Bo, _Bu, _Ba); \
    _L5 = Chi( _Bu, _Ba, _Be);

#define KeccakP_ThetaRhoPiChiIota0( _L1, _L2, _L3, _L4, _L5, _rc ) \
    _Ba = XOR5( _ba, _ga, _ka, _ma, _sa ); /* Theta effect */ \
    _Be = XOR5( _be, _ge, _ke, _me, _se ); \
    _Bi = XOR5( _bi, _gi, _ki, _mi, _si ); \
    _Bo = XOR5( _bo, _go, _ko, _mo, _so ); \
    _Bu = XOR5( _bu, _gu, _ku, _mu, _su ); \
    _Da = ROL( _Be, 1 ); \
    _De = ROL( _Bi, 1 ); \
    _Di = ROL( _Bo, 1 ); \
    _Do = ROL( _Bu, 1 ); \
    _Du = ROL( _Ba, 1 ); \
    _Da = XOR( _Da, _Bu ); \
    _De = XOR( _De, _Ba ); \
    _Di = XOR( _Di, _Be ); \
    _Do = XOR( _Do, _Bi ); \
    _Du = XOR( _Du, _Bo ); \
    KeccakP_ThetaRhoPiChi( _L1, _L2, _L3, _L4, _L5, _Ba, _Be, _Bi, _Bo, _Bu,  0, 44, 43, 21, 14 ); \
    _L1 = XOR(_L1, _rc) /* Iota */

#define KeccakP_ThetaRhoPiChi1( _L1, _L2, _L3, _L4, _L5 ) \
    KeccakP_ThetaRhoPiChi( _L1, _L2, _L3, _L4, _L5, _Bi, _Bo, _Bu, _Ba, _Be,  3, 45, 61, 28, 20 )

#define KeccakP_ThetaRhoPiChi2( _L1, _L2, _L3, _L4, _L5 ) \
    KeccakP_ThetaRhoPiChi( _L1, _L2, _L3, _L4, _L5, _Bu, _Ba, _Be, _Bi, _Bo, 18,  1,  6, 25,  8 )

#define KeccakP_ThetaRhoPiChi3( _L1, _L2, _L3, _L4, _L5 ) \
    KeccakP_ThetaRhoPiChi( _L1, _L2, _L3, _L4, _L5, _Be, _Bi, _Bo, _Bu, _Ba, 36, 10, 15, 56, 27 )

#define KeccakP_ThetaRhoPiChi4( _L1, _L2, _L3, _L4, _L5 ) \
    KeccakP_ThetaRhoPiChi( _L1, _L2, _L3, _L4, _L5, _Bo, _Bu, _Ba, _Be, _Bi, 41,  2, 62, 55, 39 )

/* Four rounds starting at round constant index `i`.  After the block the
   lane->register mapping returns to canonical, so blocks chain directly. */
#define KeccakP_4rounds( i ) \
    KeccakP_ThetaRhoPiChiIota0(_ba, _ge, _ki, _mo, _su, CONST8_64(rc[(i)+0]) ); \
    KeccakP_ThetaRhoPiChi1(    _ka, _me, _si, _bo, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _sa, _be, _gi, _ko, _mu ); \
    KeccakP_ThetaRhoPiChi3(    _ga, _ke, _mi, _so, _bu ); \
    KeccakP_ThetaRhoPiChi4(    _ma, _se, _bi, _go, _ku ); \
\
    KeccakP_ThetaRhoPiChiIota0(_ba, _me, _gi, _so, _ku, CONST8_64(rc[(i)+1]) ); \
    KeccakP_ThetaRhoPiChi1(    _sa, _ke, _bi, _mo, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _ma, _ge, _si, _ko, _bu ); \
    KeccakP_ThetaRhoPiChi3(    _ka, _be, _mi, _go, _su ); \
    KeccakP_ThetaRhoPiChi4(    _ga, _se, _ki, _bo, _mu ); \
\
    KeccakP_ThetaRhoPiChiIota0(_ba, _ke, _si, _go, _mu, CONST8_64(rc[(i)+2]) ); \
    KeccakP_ThetaRhoPiChi1(    _ma, _be, _ki, _so, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _ga, _me, _bi, _ko, _su ); \
    KeccakP_ThetaRhoPiChi3(    _sa, _ge, _mi, _bo, _ku ); \
    KeccakP_ThetaRhoPiChi4(    _ka, _se, _gi, _mo, _bu ); \
\
    KeccakP_ThetaRhoPiChiIota0(_ba, _be, _bi, _bo, _bu, CONST8_64(rc[(i)+3]) ); \
    KeccakP_ThetaRhoPiChi1(    _ga, _ge, _gi, _go, _gu ); \
    KeccakP_ThetaRhoPiChi2(    _ka, _ke, _ki, _ko, _ku ); \
    KeccakP_ThetaRhoPiChi3(    _ma, _me, _mi, _mo, _mu ); \
    KeccakP_ThetaRhoPiChi4(    _sa, _se, _si, _so, _su )

/* Load 25 SoA lanes (canonical a[x+5y]) into the named registers. */
#define KeccakP_LoadState( a ) \
    _ba=(a)[ 0]; _be=(a)[ 1]; _bi=(a)[ 2]; _bo=(a)[ 3]; _bu=(a)[ 4]; \
    _ga=(a)[ 5]; _ge=(a)[ 6]; _gi=(a)[ 7]; _go=(a)[ 8]; _gu=(a)[ 9]; \
    _ka=(a)[10]; _ke=(a)[11]; _ki=(a)[12]; _ko=(a)[13]; _ku=(a)[14]; \
    _ma=(a)[15]; _me=(a)[16]; _mi=(a)[17]; _mo=(a)[18]; _mu=(a)[19]; \
    _sa=(a)[20]; _se=(a)[21]; _si=(a)[22]; _so=(a)[23]; _su=(a)[24]

#define KeccakP_StoreState( a ) \
    (a)[ 0]=_ba; (a)[ 1]=_be; (a)[ 2]=_bi; (a)[ 3]=_bo; (a)[ 4]=_bu; \
    (a)[ 5]=_ga; (a)[ 6]=_ge; (a)[ 7]=_gi; (a)[ 8]=_go; (a)[ 9]=_gu; \
    (a)[10]=_ka; (a)[11]=_ke; (a)[12]=_ki; (a)[13]=_ko; (a)[14]=_ku; \
    (a)[15]=_ma; (a)[16]=_me; (a)[17]=_mi; (a)[18]=_mo; (a)[19]=_mu; \
    (a)[20]=_sa; (a)[21]=_se; (a)[22]=_si; (a)[23]=_so; (a)[24]=_su

/* Full 24-round Keccak-f[1600] over 8 parallel states (SoA). */
static void
fd_k8_perm24( v512u *       a,
              ulong const * rc ) {
  KeccakP_DeclareVars;
  KeccakP_LoadState( a );
  KeccakP_4rounds(  0 );
  KeccakP_4rounds(  4 );
  KeccakP_4rounds(  8 );
  KeccakP_4rounds( 12 );
  KeccakP_4rounds( 16 );
  KeccakP_4rounds( 20 );
  KeccakP_StoreState( a );
}

/* Keccak-p[1600,12] (KangarooTwelve convention): the last 12 rounds,
   using round constants rc[12..23]. */
static void
fd_k8_perm12( v512u *       a,
              ulong const * rc ) {
  KeccakP_DeclareVars;
  KeccakP_LoadState( a );
  KeccakP_4rounds( 12 );
  KeccakP_4rounds( 16 );
  KeccakP_4rounds( 20 );
  KeccakP_StoreState( a );
}

/* Convenience wrapper: full 24-round Keccak-f[1600]. */
static void
fd_k8_perm( v512u *       a,
            ulong const * rc ) {
  fd_k8_perm24( a, rc );
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
  fd_k8_perm12( (v512u *)state_soa, rc );
}

void fd_keccak256_avx512_keccak8_extract_rate( void * out[8], void const * state_soa, ulong rate_bytes );

/* Fused counter-mode squeeze for fd_lthash2 (KTP12, capacity 256: counter
   lane = 21).  Loads the read-only absorbed base SoA into registers, XORs
   the 8 per-state counters into the counter lane register *during* the
   load (so the base is never cloned), runs Keccak-p[1600,12], and extracts
   the first rate_bytes of each state into out[8].  This replaces the
   clone-base + xor_into_lane + permute + extract sequence with a single
   pass — the 1600-byte state copy collapses to one vpxorq. */
void
fd_keccak256_avx512_keccak8_squeeze_ctr21( void const *  base_soa,
                                           ulong const * ctrs,
                                           void *        out[8],
                                           ulong         rate_bytes,
                                           ulong const * rc ) {
  v512u const * base = (v512u const *)base_soa;
  KeccakP_DeclareVars;
  KeccakP_LoadState( base );
  _se = _mm512_xor_si512( _se, _mm512_loadu_si512( (v512u const *)ctrs ) ); /* lane 21 */
  KeccakP_4rounds( 12 );
  KeccakP_4rounds( 16 );
  KeccakP_4rounds( 20 );
  v512u soa[ 25 ] __attribute__((aligned(64)));
  KeccakP_StoreState( soa );
  fd_keccak256_avx512_keccak8_extract_rate( out, soa, rate_bytes );
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

/* AVX-512 8x8 u64 transpose: in[i] = row i = (M[i][0..7]); writes
   out[j] = column j = (M[0..7][j]).  ~24 vector ops, no memory.  Shared
   by the absorb transpose-in (xor_block_into_state) and the squeeze
   transpose-out (extract_rate). */
#define T8X8( i0,i1,i2,i3,i4,i5,i6,i7, o0,o1,o2,o3,o4,o5,o6,o7 ) do {     \
    v512u _u0=_mm512_unpacklo_epi64(i0,i1), _u1=_mm512_unpackhi_epi64(i0,i1); \
    v512u _u2=_mm512_unpacklo_epi64(i2,i3), _u3=_mm512_unpackhi_epi64(i2,i3); \
    v512u _u4=_mm512_unpacklo_epi64(i4,i5), _u5=_mm512_unpackhi_epi64(i4,i5); \
    v512u _u6=_mm512_unpacklo_epi64(i6,i7), _u7=_mm512_unpackhi_epi64(i6,i7); \
    v512u _s0=_mm512_shuffle_i64x2(_u0,_u2,0x88), _s1=_mm512_shuffle_i64x2(_u1,_u3,0x88); \
    v512u _s2=_mm512_shuffle_i64x2(_u0,_u2,0xdd), _s3=_mm512_shuffle_i64x2(_u1,_u3,0xdd); \
    v512u _s4=_mm512_shuffle_i64x2(_u4,_u6,0x88), _s5=_mm512_shuffle_i64x2(_u5,_u7,0x88); \
    v512u _s6=_mm512_shuffle_i64x2(_u4,_u6,0xdd), _s7=_mm512_shuffle_i64x2(_u5,_u7,0xdd); \
    o0=_mm512_shuffle_i64x2(_s0,_s4,0x88); o1=_mm512_shuffle_i64x2(_s1,_s5,0x88);          \
    o2=_mm512_shuffle_i64x2(_s2,_s6,0x88); o3=_mm512_shuffle_i64x2(_s3,_s7,0x88);          \
    o4=_mm512_shuffle_i64x2(_s0,_s4,0xdd); o5=_mm512_shuffle_i64x2(_s1,_s5,0xdd);          \
    o6=_mm512_shuffle_i64x2(_s2,_s6,0xdd); o7=_mm512_shuffle_i64x2(_s3,_s7,0xdd);          \
  } while(0)

/* Absorb 8 per-state input blocks into the SoA state via a transpose-in.
   rate_lanes must be <= the per-block buffer capacity in u64 rounded up to
   a multiple of 8 for the full chunks; the final partial chunk uses a
   masked load so it never reads past a block buffer. */
void
fd_keccak256_avx512_keccak8_xor_block_into_state( void *       state_soa,
                                                  void const * blocks[8],
                                                  ulong        rate_lanes ) {
  v512u * a = (v512u *)state_soa;
  v512u o0,o1,o2,o3,o4,o5,o6,o7;
  ulong z = 0UL;
  for( ; z+8UL<=rate_lanes; z+=8UL ) {
    v512u i0=_mm512_loadu_si512((char const*)blocks[0]+z*8), i1=_mm512_loadu_si512((char const*)blocks[1]+z*8);
    v512u i2=_mm512_loadu_si512((char const*)blocks[2]+z*8), i3=_mm512_loadu_si512((char const*)blocks[3]+z*8);
    v512u i4=_mm512_loadu_si512((char const*)blocks[4]+z*8), i5=_mm512_loadu_si512((char const*)blocks[5]+z*8);
    v512u i6=_mm512_loadu_si512((char const*)blocks[6]+z*8), i7=_mm512_loadu_si512((char const*)blocks[7]+z*8);
    T8X8( i0,i1,i2,i3,i4,i5,i6,i7, o0,o1,o2,o3,o4,o5,o6,o7 );
    a[z+0]=_mm512_xor_si512(a[z+0],o0); a[z+1]=_mm512_xor_si512(a[z+1],o1);
    a[z+2]=_mm512_xor_si512(a[z+2],o2); a[z+3]=_mm512_xor_si512(a[z+3],o3);
    a[z+4]=_mm512_xor_si512(a[z+4],o4); a[z+5]=_mm512_xor_si512(a[z+5],o5);
    a[z+6]=_mm512_xor_si512(a[z+6],o6); a[z+7]=_mm512_xor_si512(a[z+7],o7);
  }
  ulong const rem = rate_lanes - z;
  if( rem ) {
    __mmask8 const m = (__mmask8)((1u<<rem)-1u);
    v512u in[8];
    for( ulong s=0; s<8; s++ ) in[s] = _mm512_maskz_loadu_epi64( m, (char const*)blocks[s]+z*8 );
    T8X8( in[0],in[1],in[2],in[3],in[4],in[5],in[6],in[7], o0,o1,o2,o3,o4,o5,o6,o7 );
    v512u const ov[8] = { o0,o1,o2,o3,o4,o5,o6,o7 };
    for( ulong i=0; i<rem; i++ ) a[z+i] = _mm512_xor_si512( a[z+i], ov[i] );
  }
}

void
fd_keccak256_avx512_keccak8_extract_rate( void *       out[8],
                                          void const * state_soa,
                                          ulong        rate_bytes ) {
  v512u const * a = (v512u const *)state_soa;
  ulong const   nlanes = (rate_bytes + 7UL) >> 3;        /* lanes touched */

  /* Transpose the (nlanes x 8) SoA rate matrix into 8 state-major rows,
     a chunk of 8 lanes at a time; the final partial chunk (rem<8 lanes)
     is masked so we never write past each state's rate buffer. */
  v512u o0,o1,o2,o3,o4,o5,o6,o7;
  ulong z = 0UL;
  for( ; z+8UL<=nlanes; z+=8UL ) {
    T8X8( a[z+0],a[z+1],a[z+2],a[z+3],a[z+4],a[z+5],a[z+6],a[z+7],
          o0,o1,o2,o3,o4,o5,o6,o7 );
    _mm512_storeu_si512( (char*)out[0]+z*8, o0 ); _mm512_storeu_si512( (char*)out[1]+z*8, o1 );
    _mm512_storeu_si512( (char*)out[2]+z*8, o2 ); _mm512_storeu_si512( (char*)out[3]+z*8, o3 );
    _mm512_storeu_si512( (char*)out[4]+z*8, o4 ); _mm512_storeu_si512( (char*)out[5]+z*8, o5 );
    _mm512_storeu_si512( (char*)out[6]+z*8, o6 ); _mm512_storeu_si512( (char*)out[7]+z*8, o7 );
  }
  ulong const rem = nlanes - z;
  if( rem ) {
    v512u zr = _mm512_setzero_si512();
    v512u in[8];
    for( ulong i=0; i<8; i++ ) in[i] = (z+i<nlanes) ? a[z+i] : zr;
    T8X8( in[0],in[1],in[2],in[3],in[4],in[5],in[6],in[7],
          o0,o1,o2,o3,o4,o5,o6,o7 );
    __mmask8 const m = (__mmask8)((1u<<rem)-1u);
    v512u const ov[8] = { o0,o1,o2,o3,o4,o5,o6,o7 };
    for( int s=0; s<8; s++ ) _mm512_mask_storeu_epi64( (char*)out[s]+z*8, m, ov[s] );
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
