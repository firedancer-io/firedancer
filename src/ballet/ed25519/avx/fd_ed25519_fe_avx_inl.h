#ifndef HEADER_fd_src_ballet_ed25519_fd_ed25519_private_h
#error "Do not include this; use fd_ed25519_private.h"
#endif

/* FE_AVX_INL_DECL declares 10 wl_ts named f0, f1, ... f9 for holding 4
   field elements as a 10x4 long matrix in the local scope.  Each lane
   of the wl_t holds the 10 limbs of a field element. */

#define FE_AVX_INL_DECL(f) wl_t f##0; wl_t f##1; wl_t f##2; wl_t f##3; wl_t f##4; \
                           wl_t f##5; wl_t f##6; wl_t f##7; wl_t f##8; wl_t f##9

/* FE_AVX_INL memory operations ***************************************/

/* FIXME: ADD SWIZZLE IN1/OUT1 VARIANTS TOO? */

/* FE_AVX_INL_LD loads into h the 4 field elements in the 40 long
   (32-byte aligned) memory region pointed to by p.  The memory region
   layout is:
     ha0 hb0 hc0 hd0
     ha1 hb1 hc1 hd1
     ...
     ha9 hb9 hc9 hd9 */

#define FE_AVX_INL_LD( h, p ) do {                     \
   long const * _p = (p);                              \
   h##0 = wl_ld( _p + 4*0 ); h##1 = wl_ld( _p + 4*1 ); \
   h##2 = wl_ld( _p + 4*2 ); h##3 = wl_ld( _p + 4*3 ); \
   h##4 = wl_ld( _p + 4*4 ); h##5 = wl_ld( _p + 4*5 ); \
   h##6 = wl_ld( _p + 4*6 ); h##7 = wl_ld( _p + 4*7 ); \
   h##8 = wl_ld( _p + 4*8 ); h##9 = wl_ld( _p + 4*9 ); \
 } while(0)

/* FE_AVX_INL_ST stores the 4 field elements in f into the 40 long
   (32-byte aligned) memory region pointed by p.  The memory region
   layout is:
      fa0 fb0 fc0 fd0
      fa1 fb1 fc1 fd1
      ...
      fa9 fb9 fc9 fd9 */

#define FE_AVX_INL_ST( p, f ) do {                     \
   long * _p = (p);                                    \
   wl_st( _p + 4*0, f##0 ); wl_st( _p + 4*1, f##1 );   \
   wl_st( _p + 4*2, f##2 ); wl_st( _p + 4*3, f##3 );   \
   wl_st( _p + 4*4, f##4 ); wl_st( _p + 4*5, f##5 );   \
   wl_st( _p + 4*6, f##6 ); wl_st( _p + 4*7, f##7 );   \
   wl_st( _p + 4*8, f##8 ); wl_st( _p + 4*9, f##9 );   \
 } while(0)

/* FE_AVX_INL_SWIZZLE_IN4 loads 4 field elements pointed to by a,b,c,d
   into a 10x4 long matrix stored in 10 wl_ts declared via
   FE_AVX_DECL_INL.

   Does limbs 0:7 as a 8x8->8x8 int matrix transpose (recursive top down
   implementation) optimized for the case where input row 1,3,5,7 are zero.
   Result can be treated as a 8x4 long matrix with no additional operations.

   Does limbs 8:9 as a 8x2->2x8 int matrix transpose (recursive top down
   implementation) optimized for the case where input rows 1,3,5,7 are
   zero.  Result can be treated as a 2x4 long matrix with no additional
   operations.

   These two tranposes are then interleaved for lots of ILP. */

#define FE_AVX_INL_SWIZZLE_IN4( v, a,b,c,d ) do {                      \
    int const * _a = (a)->limb;                                        \
    int const * _b = (b)->limb;                                        \
    int const * _c = (c)->limb;                                        \
    int const * _d = (d)->limb;                                        \
    wi_t _z  = wi_zero();                                              \
    wi_t _r0 = wi_ld( _a   );                                          \
    wi_t _r8 = wi_ld( _a+8 );                                          \
    wi_t _r2 = wi_ld( _b   );                                          \
    wi_t _ra = wi_ld( _b+8 );                                          \
    wi_t _r4 = wi_ld( _c   );                                          \
    wi_t _rc = wi_ld( _c+8 );                                          \
    wi_t _r6 = wi_ld( _d   );                                          \
    wi_t _re = wi_ld( _d+8 );                                          \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _r4, 0x20 ); \
    /**/            _r4 = _mm256_permute2f128_si256( _ta, _r4, 0x31 ); \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _r6, 0x20 ); \
    /**/            _r6 = _mm256_permute2f128_si256( _tc, _r6, 0x31 ); \
    wi_t _ti = _r8; _r8 = _mm256_permute2f128_si256( _ti, _rc, 0x20 ); \
    /**/            _rc = _mm256_permute2f128_si256( _ti, _rc, 0x31 ); \
    wi_t _tk = _ra; _ra = _mm256_permute2f128_si256( _tk, _re, 0x20 ); \
    /**/            _re = _mm256_permute2f128_si256( _tk, _re, 0x31 ); \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       ); \
    /**/            _r2 = _mm256_unpackhi_epi32    ( _te, _r2       ); \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       ); \
    /**/            _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       ); \
    /**/            _r8 = _mm256_unpacklo_epi32    ( _r8, _ra       ); \
    v##0 = _mm256_unpacklo_epi32( _r0, _z );                           \
    v##1 = _mm256_unpackhi_epi32( _r0, _z );                           \
    v##2 = _mm256_unpacklo_epi32( _r2, _z );                           \
    v##3 = _mm256_unpackhi_epi32( _r2, _z );                           \
    v##4 = _mm256_unpacklo_epi32( _r4, _z );                           \
    v##5 = _mm256_unpackhi_epi32( _r4, _z );                           \
    v##6 = _mm256_unpacklo_epi32( _r6, _z );                           \
    v##7 = _mm256_unpackhi_epi32( _r6, _z );                           \
    v##8 = _mm256_unpacklo_epi32( _r8, _z );                           \
    v##9 = _mm256_unpackhi_epi32( _r8, _z );                           \
  } while(0)

/* FE_AVX_INL_SWIZZLE_IN3 is FE_AVX_INL_SWIZZLE_IN4 optimized for a zero
   d column. */

#define FE_AVX_INL_SWIZZLE_IN3( v, a,b,c ) do {                        \
    int const * _a = (a)->limb;                                        \
    int const * _b = (b)->limb;                                        \
    int const * _c = (c)->limb;                                        \
    wi_t _z  = wi_zero();                                              \
    wi_t _r0 = wi_ld( _a   );                                          \
    wi_t _r8 = wi_ld( _a+8 );                                          \
    wi_t _r2 = wi_ld( _b   );                                          \
    wi_t _ra = wi_ld( _b+8 );                                          \
    wi_t _r4 = wi_ld( _c   );                                          \
    wi_t _rc = wi_ld( _c+8 );                                          \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _r4, 0x20 ); \
    /**/            _r4 = _mm256_permute2f128_si256( _ta, _r4, 0x31 ); \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _z,  0x20 ); \
    wi_t            _r6 = _mm256_permute2f128_si256( _tc, _z,  0x31 ); \
    wi_t _ti = _r8; _r8 = _mm256_permute2f128_si256( _ti, _rc, 0x20 ); \
    /**/            _rc = _mm256_permute2f128_si256( _ti, _rc, 0x31 ); \
    wi_t _tk = _ra; _ra = _mm256_permute2f128_si256( _tk, _z,  0x20 ); \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       ); \
    /**/            _r2 = _mm256_unpackhi_epi32    ( _te, _r2       ); \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       ); \
    /**/            _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       ); \
    /**/            _r8 = _mm256_unpacklo_epi32    ( _r8, _ra       ); \
    v##0 = _mm256_unpacklo_epi32( _r0, _z );                           \
    v##1 = _mm256_unpackhi_epi32( _r0, _z );                           \
    v##2 = _mm256_unpacklo_epi32( _r2, _z );                           \
    v##3 = _mm256_unpackhi_epi32( _r2, _z );                           \
    v##4 = _mm256_unpacklo_epi32( _r4, _z );                           \
    v##5 = _mm256_unpackhi_epi32( _r4, _z );                           \
    v##6 = _mm256_unpacklo_epi32( _r6, _z );                           \
    v##7 = _mm256_unpackhi_epi32( _r6, _z );                           \
    v##8 = _mm256_unpacklo_epi32( _r8, _z );                           \
    v##9 = _mm256_unpackhi_epi32( _r8, _z );                           \
  } while(0)

/* FE_AVX_INL_SWIZZLE_IN2 is FE_AVX_INL_SWIZZLE_IN3 optimized for a zero
   c column. */

#define FE_AVX_INL_SWIZZLE_IN2( v, a,b ) do {                          \
    int const * _a = (a)->limb;                                        \
    int const * _b = (b)->limb;                                        \
    wi_t _z  = wi_zero();                                              \
    wi_t _r0 = wi_ld( _a   );                                          \
    wi_t _r8 = wi_ld( _a+8 );                                          \
    wi_t _r2 = wi_ld( _b   );                                          \
    wi_t _ra = wi_ld( _b+8 );                                          \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _z,  0x20 ); \
    wi_t            _r4 = _mm256_permute2f128_si256( _ta, _z,  0x31 ); \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _z,  0x20 ); \
    wi_t            _r6 = _mm256_permute2f128_si256( _tc, _z,  0x31 ); \
    wi_t _ti = _r8; _r8 = _mm256_permute2f128_si256( _ti, _z,  0x20 ); \
    wi_t _tk = _ra; _ra = _mm256_permute2f128_si256( _tk, _z,  0x20 ); \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       ); \
    /**/            _r2 = _mm256_unpackhi_epi32    ( _te, _r2       ); \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       ); \
    /**/            _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       ); \
    /**/            _r8 = _mm256_unpacklo_epi32    ( _r8, _ra       ); \
    v##0 = _mm256_unpacklo_epi32( _r0, _z );                           \
    v##1 = _mm256_unpackhi_epi32( _r0, _z );                           \
    v##2 = _mm256_unpacklo_epi32( _r2, _z );                           \
    v##3 = _mm256_unpackhi_epi32( _r2, _z );                           \
    v##4 = _mm256_unpacklo_epi32( _r4, _z );                           \
    v##5 = _mm256_unpackhi_epi32( _r4, _z );                           \
    v##6 = _mm256_unpacklo_epi32( _r6, _z );                           \
    v##7 = _mm256_unpackhi_epi32( _r6, _z );                           \
    v##8 = _mm256_unpacklo_epi32( _r8, _z );                           \
    v##9 = _mm256_unpackhi_epi32( _r8, _z );                           \
  } while(0)

/* FE_AVX_INL_SWIZZLE_OUT4 writes a 10x4 long matrix (where every
   element is fits into 32-bits) in 10 wl_t into 4 field elements.  The
   input 10x4 long matrix can be reinterpreted for free as a 10x8 int
   matrix where columns 1,3,5,7.

   This then does a 8x8 int matrix transpose (recursive bottom up
   implementation) for the first 8 rows.  As the first step does
   transposes for 2x2 subblocks, the zeros in columns 1,3,5,7
   immediately get compacted into the rows 1,3,5,7 and thus can be
   immediately discarded.

   Similar, the last two rows are done as an 2x8 int matrix transpose in
   the same matter and the operations are interleaved for lots of ILP. */

#define FE_AVX_INL_SWIZZLE_OUT4( a,b,c,d, v ) do {                                                                  \
    wf_t _z  = wf_zero();                                                                                           \
    wf_t _r0 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##0 ), _mm256_castsi256_ps( v##1 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r2 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##2 ), _mm256_castsi256_ps( v##3 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r4 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##4 ), _mm256_castsi256_ps( v##5 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r6 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##6 ), _mm256_castsi256_ps( v##7 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r8 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##8 ), _mm256_castsi256_ps( v##9 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _ta = _r0; _r0 = _mm256_shuffle_ps( _ta, _r2, _MM_SHUFFLE(2,0,2,0) );                                      \
                    _r2 = _mm256_shuffle_ps( _ta, _r2, _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _tb = _r4; _r4 = _mm256_shuffle_ps( _tb, _r6, _MM_SHUFFLE(2,0,2,0) );                                      \
                    _r6 = _mm256_shuffle_ps( _tb, _r6, _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _tc = _r8; _r8 = _mm256_shuffle_ps( _tc, _z,  _MM_SHUFFLE(2,0,2,0) );                                      \
    wf_t            _ra = _mm256_shuffle_ps( _tc, _z,  _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _td = _r0; _r0 = _mm256_permute2f128_ps( _td, _r4, 0x20 );                                                 \
                    _r4 = _mm256_permute2f128_ps( _td, _r4, 0x31 );                                                 \
    wf_t _te = _r2; _r2 = _mm256_permute2f128_ps( _te, _r6, 0x20 );                                                 \
                    _r6 = _mm256_permute2f128_ps( _te, _r6, 0x31 );                                                 \
    wf_t _tf = _r8; _r8 = _mm256_permute2f128_ps( _tf, _z,  0x20 );                                                 \
    wf_t            _rc = _mm256_permute2f128_ps( _tf, _z,  0x31 );                                                 \
    wf_t _tg = _ra; _ra = _mm256_permute2f128_ps( _tg, _z,  0x20 );                                                 \
    wf_t            _re = _mm256_permute2f128_ps( _tg, _z,  0x31 );                                                 \
    int * _a = (a)->limb;                                                                                           \
    int * _b = (b)->limb;                                                                                           \
    int * _c = (c)->limb;                                                                                           \
    int * _d = (d)->limb;                                                                                           \
    wi_st( _a,   _mm256_castps_si256( _r0 ) );                                                                      \
    wi_st( _a+8, _mm256_castps_si256( _r8 ) );                                                                      \
    wi_st( _b,   _mm256_castps_si256( _r2 ) );                                                                      \
    wi_st( _b+8, _mm256_castps_si256( _ra ) );                                                                      \
    wi_st( _c,   _mm256_castps_si256( _r4 ) );                                                                      \
    wi_st( _c+8, _mm256_castps_si256( _rc ) );                                                                      \
    wi_st( _d,   _mm256_castps_si256( _r6 ) );                                                                      \
    wi_st( _d+8, _mm256_castps_si256( _re ) );                                                                      \
  } while(0)

/* FE_AVX_INL_SWIZZLE_OUT3 is FE_AVX_INL_SWIZZLE_OUT4 optimized to
   discard the d column */

#define FE_AVX_INL_SWIZZLE_OUT3( a,b,c, v ) do {                                                                    \
    wf_t _z  = wf_zero();                                                                                           \
    wf_t _r0 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##0 ), _mm256_castsi256_ps( v##1 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r2 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##2 ), _mm256_castsi256_ps( v##3 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r4 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##4 ), _mm256_castsi256_ps( v##5 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r6 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##6 ), _mm256_castsi256_ps( v##7 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r8 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##8 ), _mm256_castsi256_ps( v##9 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _ta = _r0; _r0 = _mm256_shuffle_ps( _ta, _r2, _MM_SHUFFLE(2,0,2,0) );                                      \
                    _r2 = _mm256_shuffle_ps( _ta, _r2, _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _tb = _r4; _r4 = _mm256_shuffle_ps( _tb, _r6, _MM_SHUFFLE(2,0,2,0) );                                      \
                    _r6 = _mm256_shuffle_ps( _tb, _r6, _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _ra = _r8; _r8 = _mm256_shuffle_ps( _ra, _z,  _MM_SHUFFLE(2,0,2,0) );                                      \
    /**/            _ra = _mm256_shuffle_ps( _ra, _z,  _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _tc = _r0; _r0 = _mm256_permute2f128_ps( _tc, _r4, 0x20 );                                                 \
                    _r4 = _mm256_permute2f128_ps( _tc, _r4, 0x31 );                                                 \
    /**/            _r2 = _mm256_permute2f128_ps( _r2, _r6, 0x20 );                                                 \
    wf_t _rc = _r8; _r8 = _mm256_permute2f128_ps( _rc, _z,  0x20 );                                                 \
    /**/            _rc = _mm256_permute2f128_ps( _rc, _z,  0x31 );                                                 \
    /**/            _ra = _mm256_permute2f128_ps( _ra, _z,  0x20 );                                                 \
    int * _a = (a)->limb;                                                                                           \
    int * _b = (b)->limb;                                                                                           \
    int * _c = (c)->limb;                                                                                           \
    wi_st( _a,   _mm256_castps_si256( _r0 ) );                                                                      \
    wi_st( _a+8, _mm256_castps_si256( _r8 ) );                                                                      \
    wi_st( _b,   _mm256_castps_si256( _r2 ) );                                                                      \
    wi_st( _b+8, _mm256_castps_si256( _ra ) );                                                                      \
    wi_st( _c,   _mm256_castps_si256( _r4 ) );                                                                      \
    wi_st( _c+8, _mm256_castps_si256( _rc ) );                                                                      \
  } while(0)

/* FE_AVX_INL_SWIZZLE_OUT2 is FE_AVX_INL_SWIZZLE_OUT3 optimized to
   discard the c column */

#define FE_AVX_INL_SWIZZLE_OUT2( a,b, v ) do {                                                                      \
    wf_t _z  = wf_zero();                                                                                           \
    wf_t _r0 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##0 ), _mm256_castsi256_ps( v##1 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r2 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##2 ), _mm256_castsi256_ps( v##3 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r4 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##4 ), _mm256_castsi256_ps( v##5 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r6 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##6 ), _mm256_castsi256_ps( v##7 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r8 = _mm256_shuffle_ps( _mm256_castsi256_ps( v##8 ), _mm256_castsi256_ps( v##9 ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _ta = _r0; _r0 = _mm256_shuffle_ps( _ta, _r2, _MM_SHUFFLE(2,0,2,0) );                                      \
                    _r2 = _mm256_shuffle_ps( _ta, _r2, _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _tb = _r4; _r4 = _mm256_shuffle_ps( _tb, _r6, _MM_SHUFFLE(2,0,2,0) );                                      \
                    _r6 = _mm256_shuffle_ps( _tb, _r6, _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _ra = _r8; _r8 = _mm256_shuffle_ps( _ra, _z,  _MM_SHUFFLE(2,0,2,0) );                                      \
    /**/            _ra = _mm256_shuffle_ps( _ra, _z,  _MM_SHUFFLE(3,1,3,1) );                                      \
    /**/            _r0 = _mm256_permute2f128_ps( _r0, _r4, 0x20 );                                                 \
    /**/            _r2 = _mm256_permute2f128_ps( _r2, _r6, 0x20 );                                                 \
    /**/            _r8 = _mm256_permute2f128_ps( _r8, _z,  0x20 );                                                 \
    /**/            _ra = _mm256_permute2f128_ps( _ra, _z,  0x20 );                                                 \
    int * _a = (a)->limb;                                                                                           \
    int * _b = (b)->limb;                                                                                           \
    wi_st( _a,   _mm256_castps_si256( _r0 ) );                                                                      \
    wi_st( _a+8, _mm256_castps_si256( _r8 ) );                                                                      \
    wi_st( _b,   _mm256_castps_si256( _r2 ) );                                                                      \
    wi_st( _b+8, _mm256_castps_si256( _ra ) );                                                                      \
  } while(0)

/* FE_AVX_INL_PAIR_SWIZZLE_IN4 is an optimized implementation of:
     FE_AVX_INL_SWIZZLE_IN4( v, a,b,c,d )
     FE_AVX_INL_SWIZZLE_IN4( w, e,f,g,h )
   Basically, the 2 8x8 transposes are done as before but the 2 2x8
   transposes are merged into 1 2x4 transpose. */

#define FE_AVX_INL_PAIR_SWIZZLE_IN4( v, a,b,c,d, w, e,f,g,h ) do {                                                                \
    wi_t _z  = wi_zero();                                                                                                         \
    int const * _a = (a)->limb;                                         int const * _e = (e)->limb;                               \
    int const * _b = (b)->limb;                                         int const * _f = (f)->limb;                               \
    int const * _c = (c)->limb;                                         int const * _g = (g)->limb;                               \
    int const * _d = (d)->limb;                                         int const * _h = (h)->limb;                               \
    wi_t _r0 = wi_ld( _a   );                                           wi_t _s0 = wi_ld( _e   );                                 \
    wi_t _r8 = wi_ld( _a+8 );                                           wi_t _s8 = wi_ld( _e+8 );                                 \
    wi_t _r2 = wi_ld( _b   );                                           wi_t _s2 = wi_ld( _f   );                                 \
    wi_t _ra = wi_ld( _b+8 );                                           wi_t _sa = wi_ld( _f+8 );                                 \
    wi_t _r4 = wi_ld( _c   );                                           wi_t _s4 = wi_ld( _g   );                                 \
    wi_t _rc = wi_ld( _c+8 );                                           wi_t _sc = wi_ld( _g+8 );                                 \
    wi_t _r6 = wi_ld( _d   );                                           wi_t _s6 = wi_ld( _h   );                                 \
    wi_t _re = wi_ld( _d+8 );                                           wi_t _se = wi_ld( _h+8 );                                 \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _r4, 0x20 );  wi_t _ua = _s0; _s0 = _mm256_permute2f128_si256( _ua, _s4, 0x20 ); \
    /**/            _r4 = _mm256_permute2f128_si256( _ta, _r4, 0x31 );  /**/            _s4 = _mm256_permute2f128_si256( _ua, _s4, 0x31 ); \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _r6, 0x20 );  wi_t _uc = _s2; _s2 = _mm256_permute2f128_si256( _uc, _s6, 0x20 ); \
    /**/            _r6 = _mm256_permute2f128_si256( _tc, _r6, 0x31 );  /**/            _s6 = _mm256_permute2f128_si256( _uc, _s6, 0x31 ); \
    /**/            _r8 = _mm256_permute2f128_si256( _r8, _s8, 0x20 );  /**/            _ra = _mm256_permute2f128_si256( _ra, _sa, 0x20 ); \
    /**/            _rc = _mm256_permute2f128_si256( _rc, _sc, 0x20 );  /**/            _re = _mm256_permute2f128_si256( _re, _se, 0x20 ); \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       );  wi_t _ue = _s0; _s0 = _mm256_unpacklo_epi32    ( _ue, _s2       ); \
    /**/            _r2 = _mm256_unpackhi_epi32    ( _te, _r2       );  /**/            _s2 = _mm256_unpackhi_epi32    ( _ue, _s2       ); \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       );  wi_t _ug = _s4; _s4 = _mm256_unpacklo_epi32    ( _ug, _s6       ); \
    /**/            _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       );  /**/            _s6 = _mm256_unpackhi_epi32    ( _ug, _s6       ); \
    wi_t _ti = _r8; _r8 = _mm256_permute2f128_si256( _ti, _rc, 0x20 );  /**/            _rc = _mm256_permute2f128_si256( _ti, _rc, 0x31 ); \
    wi_t _tk = _ra; _ra = _mm256_permute2f128_si256( _tk, _re, 0x20 );  /**/            _re = _mm256_permute2f128_si256( _tk, _re, 0x31 ); \
    /**/            _r8 = _mm256_unpacklo_epi32    ( _r8, _ra       );  /**/            _rc = _mm256_unpacklo_epi32    ( _rc, _re       ); \
    v##0 = _mm256_unpacklo_epi32( _r0, _z );                            w##0 = _mm256_unpacklo_epi32( _s0, _z );                  \
    v##1 = _mm256_unpackhi_epi32( _r0, _z );                            w##1 = _mm256_unpackhi_epi32( _s0, _z );                  \
    v##2 = _mm256_unpacklo_epi32( _r2, _z );                            w##2 = _mm256_unpacklo_epi32( _s2, _z );                  \
    v##3 = _mm256_unpackhi_epi32( _r2, _z );                            w##3 = _mm256_unpackhi_epi32( _s2, _z );                  \
    v##4 = _mm256_unpacklo_epi32( _r4, _z );                            w##4 = _mm256_unpacklo_epi32( _s4, _z );                  \
    v##5 = _mm256_unpackhi_epi32( _r4, _z );                            w##5 = _mm256_unpackhi_epi32( _s4, _z );                  \
    v##6 = _mm256_unpacklo_epi32( _r6, _z );                            w##6 = _mm256_unpacklo_epi32( _s6, _z );                  \
    v##7 = _mm256_unpackhi_epi32( _r6, _z );                            w##7 = _mm256_unpackhi_epi32( _s6, _z );                  \
    v##8 = _mm256_unpacklo_epi32( _r8, _z );                            w##8 = _mm256_unpacklo_epi32( _rc, _z );                  \
    v##9 = _mm256_unpackhi_epi32( _r8, _z );                            w##9 = _mm256_unpackhi_epi32( _rc, _z );                  \
  } while(0)

/* FE_AVX_INL_PAIR_SWIZZLE_IN3 is FE_AVX_INL_PAIR_SWIZZLE_IN4 optimized
   for zero d and h columns. */

#define FE_AVX_INL_PAIR_SWIZZLE_IN3( v, a,b,c, w, e,f,g ) do {                                                                    \
    wi_t _z  = wi_zero();                                                                                                         \
    int const * _a = (a)->limb;                                         int const * _e = (e)->limb;                               \
    int const * _b = (b)->limb;                                         int const * _f = (f)->limb;                               \
    int const * _c = (c)->limb;                                         int const * _g = (g)->limb;                               \
    wi_t _r0 = wi_ld( _a   );                                           wi_t _s0 = wi_ld( _e   );                                 \
    wi_t _r8 = wi_ld( _a+8 );                                           wi_t _s8 = wi_ld( _e+8 );                                 \
    wi_t _r2 = wi_ld( _b   );                                           wi_t _s2 = wi_ld( _f   );                                 \
    wi_t _ra = wi_ld( _b+8 );                                           wi_t _sa = wi_ld( _f+8 );                                 \
    wi_t _r4 = wi_ld( _c   );                                           wi_t _s4 = wi_ld( _g   );                                 \
    wi_t _rc = wi_ld( _c+8 );                                           wi_t _sc = wi_ld( _g+8 );                                 \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _r4, 0x20 );  wi_t _ua = _s0; _s0 = _mm256_permute2f128_si256( _ua, _s4, 0x20 ); \
    /**/            _r4 = _mm256_permute2f128_si256( _ta, _r4, 0x31 );  /**/            _s4 = _mm256_permute2f128_si256( _ua, _s4, 0x31 ); \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _z,  0x20 );  wi_t _uc = _s2; _s2 = _mm256_permute2f128_si256( _uc, _z,  0x20 ); \
    wi_t            _r6 = _mm256_permute2f128_si256( _tc, _z,  0x31 );  wi_t            _s6 = _mm256_permute2f128_si256( _uc, _z,  0x31 ); \
    /**/            _r8 = _mm256_permute2f128_si256( _r8, _s8, 0x20 );  /**/            _ra = _mm256_permute2f128_si256( _ra, _sa, 0x20 ); \
    /**/            _rc = _mm256_permute2f128_si256( _rc, _sc, 0x20 );                                                                     \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       );  wi_t _ue = _s0; _s0 = _mm256_unpacklo_epi32    ( _ue, _s2       ); \
    /**/            _r2 = _mm256_unpackhi_epi32    ( _te, _r2       );  /**/            _s2 = _mm256_unpackhi_epi32    ( _ue, _s2       ); \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       );  wi_t _ug = _s4; _s4 = _mm256_unpacklo_epi32    ( _ug, _s6       ); \
    /**/            _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       );  /**/            _s6 = _mm256_unpackhi_epi32    ( _ug, _s6       ); \
    wi_t _ti = _r8; _r8 = _mm256_permute2f128_si256( _ti, _rc, 0x20 );  /**/            _rc = _mm256_permute2f128_si256( _ti, _rc, 0x31 ); \
    wi_t _tk = _ra; _ra = _mm256_permute2f128_si256( _tk, _z,  0x20 );  wi_t            _re = _mm256_permute2f128_si256( _tk, _z,  0x31 ); \
    /**/            _r8 = _mm256_unpacklo_epi32    ( _r8, _ra       );  /**/            _rc = _mm256_unpacklo_epi32    ( _rc, _re       ); \
    v##0 = _mm256_unpacklo_epi32( _r0, _z );                            w##0 = _mm256_unpacklo_epi32( _s0, _z );                  \
    v##1 = _mm256_unpackhi_epi32( _r0, _z );                            w##1 = _mm256_unpackhi_epi32( _s0, _z );                  \
    v##2 = _mm256_unpacklo_epi32( _r2, _z );                            w##2 = _mm256_unpacklo_epi32( _s2, _z );                  \
    v##3 = _mm256_unpackhi_epi32( _r2, _z );                            w##3 = _mm256_unpackhi_epi32( _s2, _z );                  \
    v##4 = _mm256_unpacklo_epi32( _r4, _z );                            w##4 = _mm256_unpacklo_epi32( _s4, _z );                  \
    v##5 = _mm256_unpackhi_epi32( _r4, _z );                            w##5 = _mm256_unpackhi_epi32( _s4, _z );                  \
    v##6 = _mm256_unpacklo_epi32( _r6, _z );                            w##6 = _mm256_unpacklo_epi32( _s6, _z );                  \
    v##7 = _mm256_unpackhi_epi32( _r6, _z );                            w##7 = _mm256_unpackhi_epi32( _s6, _z );                  \
    v##8 = _mm256_unpacklo_epi32( _r8, _z );                            w##8 = _mm256_unpacklo_epi32( _rc, _z );                  \
    v##9 = _mm256_unpackhi_epi32( _r8, _z );                            w##9 = _mm256_unpackhi_epi32( _rc, _z );                  \
  } while(0)

/* FE_AVX_INL_PAIR_SWIZZLE_IN2 is FE_AVX_INL_PAIR_SWIZZLE_IN2 optimized
   for zero c and g columns. */

#define FE_AVX_INL_PAIR_SWIZZLE_IN2( v, a,b, w, e,f ) do {                                                                        \
    wi_t _z  = wi_zero();                                                                                                         \
    int const * _a = (a)->limb;                                         int const * _e = (e)->limb;                               \
    int const * _b = (b)->limb;                                         int const * _f = (f)->limb;                               \
    wi_t _r0 = wi_ld( _a   );                                           wi_t _s0 = wi_ld( _e   );                                 \
    wi_t _r8 = wi_ld( _a+8 );                                           wi_t _s8 = wi_ld( _e+8 );                                 \
    wi_t _r2 = wi_ld( _b   );                                           wi_t _s2 = wi_ld( _f   );                                 \
    wi_t _ra = wi_ld( _b+8 );                                           wi_t _sa = wi_ld( _f+8 );                                 \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _z,  0x20 );  wi_t _ua = _s0; _s0 = _mm256_permute2f128_si256( _ua, _z,  0x20 ); \
    wi_t            _r4 = _mm256_permute2f128_si256( _ta, _z,  0x31 );  wi_t            _s4 = _mm256_permute2f128_si256( _ua, _z,  0x31 ); \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _z,  0x20 );  wi_t _uc = _s2; _s2 = _mm256_permute2f128_si256( _uc, _z,  0x20 ); \
    wi_t            _r6 = _mm256_permute2f128_si256( _tc, _z,  0x31 );  wi_t            _s6 = _mm256_permute2f128_si256( _uc, _z,  0x31 ); \
    /**/            _r8 = _mm256_permute2f128_si256( _r8, _s8, 0x20 );  /**/            _ra = _mm256_permute2f128_si256( _ra, _sa, 0x20 ); \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       );  wi_t _ue = _s0; _s0 = _mm256_unpacklo_epi32    ( _ue, _s2       ); \
    /**/            _r2 = _mm256_unpackhi_epi32    ( _te, _r2       );  /**/            _s2 = _mm256_unpackhi_epi32    ( _ue, _s2       ); \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       );  wi_t _ug = _s4; _s4 = _mm256_unpacklo_epi32    ( _ug, _s6       ); \
    /**/            _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       );  /**/            _s6 = _mm256_unpackhi_epi32    ( _ug, _s6       ); \
    wi_t _ti = _r8; _r8 = _mm256_permute2f128_si256( _ti, _z,  0x20 );  wi_t            _rc = _mm256_permute2f128_si256( _ti, _z,  0x31 ); \
    wi_t _tk = _ra; _ra = _mm256_permute2f128_si256( _tk, _z,  0x20 );  wi_t            _re = _mm256_permute2f128_si256( _tk, _z,  0x31 ); \
    /**/            _r8 = _mm256_unpacklo_epi32    ( _r8, _ra       );  /**/            _rc = _mm256_unpacklo_epi32    ( _rc, _re       ); \
    v##0 = _mm256_unpacklo_epi32( _r0, _z );                            w##0 = _mm256_unpacklo_epi32( _s0, _z );                  \
    v##1 = _mm256_unpackhi_epi32( _r0, _z );                            w##1 = _mm256_unpackhi_epi32( _s0, _z );                  \
    v##2 = _mm256_unpacklo_epi32( _r2, _z );                            w##2 = _mm256_unpacklo_epi32( _s2, _z );                  \
    v##3 = _mm256_unpackhi_epi32( _r2, _z );                            w##3 = _mm256_unpackhi_epi32( _s2, _z );                  \
    v##4 = _mm256_unpacklo_epi32( _r4, _z );                            w##4 = _mm256_unpacklo_epi32( _s4, _z );                  \
    v##5 = _mm256_unpackhi_epi32( _r4, _z );                            w##5 = _mm256_unpackhi_epi32( _s4, _z );                  \
    v##6 = _mm256_unpacklo_epi32( _r6, _z );                            w##6 = _mm256_unpacklo_epi32( _s6, _z );                  \
    v##7 = _mm256_unpackhi_epi32( _r6, _z );                            w##7 = _mm256_unpackhi_epi32( _s6, _z );                  \
    v##8 = _mm256_unpacklo_epi32( _r8, _z );                            w##8 = _mm256_unpacklo_epi32( _rc, _z );                  \
    v##9 = _mm256_unpackhi_epi32( _r8, _z );                            w##9 = _mm256_unpackhi_epi32( _rc, _z );                  \
  } while(0)

/* FE_AVX_INL arithmetic operations ***********************************/

/* FE_AVX_INL_ZERO sets the 4 field elements stored in 10 wl_ts declared
   via FE_AVX_INL_DECL to zero. */

#define FE_AVX_INL_ZERO( h ) do { \
    wl_t _z = wl_zero();          \
    h##0 = _z; h##1 = _z;         \
    h##2 = _z; h##3 = _z;         \
    h##4 = _z; h##5 = _z;         \
    h##6 = _z; h##7 = _z;         \
    h##8 = _z; h##9 = _z;         \
  } while(0)

/* FE_AVX_INL_PERMUTE permutes the lanes of the f and stores the results
   in g.  imm_l* should be compile time and in 0:3.  In place operation
   is fine. */

#define FE_AVX_INL_PERMUTE( h, f, imm_l0,imm_l1,imm_l2,imm_l3 ) do {   \
    h##0 = wl_permute( f##0, (imm_l0), (imm_l1), (imm_l2), (imm_l3) ); \
    h##1 = wl_permute( f##1, (imm_l0), (imm_l1), (imm_l2), (imm_l3) ); \
    h##2 = wl_permute( f##2, (imm_l0), (imm_l1), (imm_l2), (imm_l3) ); \
    h##3 = wl_permute( f##3, (imm_l0), (imm_l1), (imm_l2), (imm_l3) ); \
    h##4 = wl_permute( f##4, (imm_l0), (imm_l1), (imm_l2), (imm_l3) ); \
    h##5 = wl_permute( f##5, (imm_l0), (imm_l1), (imm_l2), (imm_l3) ); \
    h##6 = wl_permute( f##6, (imm_l0), (imm_l1), (imm_l2), (imm_l3) ); \
    h##7 = wl_permute( f##7, (imm_l0), (imm_l1), (imm_l2), (imm_l3) ); \
    h##8 = wl_permute( f##8, (imm_l0), (imm_l1), (imm_l2), (imm_l3) ); \
    h##9 = wl_permute( f##9, (imm_l0), (imm_l1), (imm_l2), (imm_l3) ); \
  } while(0)

/* FE_AVX_INL_COPY does h = f.  In place operation is fine. */

#define FE_AVX_INL_COPY( h, f ) do { \
   h##0 = f##0; h##1 = f##1;         \
   h##2 = f##2; h##3 = f##3;         \
   h##4 = f##4; h##5 = f##5;         \
   h##6 = f##6; h##7 = f##7;         \
   h##8 = f##8; h##9 = f##9;         \
 } while(0)

/* FE_AVX_INL_ADD does a simple add of the corresponding lanes of f and
   g (with no reduction) and stores the result in h.  In place operation
   is fine. */

#define FE_AVX_INL_ADD( h, f, g ) do { \
    h##0 = wl_add( f##0, g##0 );       \
    h##1 = wl_add( f##1, g##1 );       \
    h##2 = wl_add( f##2, g##2 );       \
    h##3 = wl_add( f##3, g##3 );       \
    h##4 = wl_add( f##4, g##4 );       \
    h##5 = wl_add( f##5, g##5 );       \
    h##6 = wl_add( f##6, g##6 );       \
    h##7 = wl_add( f##7, g##7 );       \
    h##8 = wl_add( f##8, g##8 );       \
    h##9 = wl_add( f##9, g##9 );       \
  } while(0)

/* FE_AVX_INL_SUB does a simple subtract of the corresponding lanes of f
   and g (with no reduction) and stores the result in h.  In place
   operation is fine. */

#define FE_AVX_INL_SUB( h, f, g ) do { \
    h##0 = wl_sub( f##0, g##0 );       \
    h##1 = wl_sub( f##1, g##1 );       \
    h##2 = wl_sub( f##2, g##2 );       \
    h##3 = wl_sub( f##3, g##3 );       \
    h##4 = wl_sub( f##4, g##4 );       \
    h##5 = wl_sub( f##5, g##5 );       \
    h##6 = wl_sub( f##6, g##6 );       \
    h##7 = wl_sub( f##7, g##7 );       \
    h##8 = wl_sub( f##8, g##8 );       \
    h##9 = wl_sub( f##9, g##9 );       \
  } while(0)

/* FE_AVX_INL_MUL does a multiply of the corresponding lanes of f and g
   (with partial reduction) and stores the result in h.  In place
   operation is fine. */

#define FE_AVX_INL_MUL( h, f, g ) do {                                                                                          \
    wl_t _19      = wl_bcast( 19L );                                                                                            \
                                                                                                                                \
    wl_t _g1_19   = wl_mul_ll( _19, g##1 );    wl_t _g2_19   = wl_mul_ll( _19, g##2 );                                          \
    wl_t _g3_19   = wl_mul_ll( _19, g##3 );    wl_t _g4_19   = wl_mul_ll( _19, g##4 );                                          \
    wl_t _g5_19   = wl_mul_ll( _19, g##5 );    wl_t _g6_19   = wl_mul_ll( _19, g##6 );                                          \
    wl_t _g7_19   = wl_mul_ll( _19, g##7 );    wl_t _g8_19   = wl_mul_ll( _19, g##8 );                                          \
    wl_t _g9_19   = wl_mul_ll( _19, g##9 );                                                                                     \
                                                                                                                                \
    wl_t _f1_2    = wl_add( f##1, f##1 );      wl_t _f3_2    = wl_add( f##3, f##3 );                                            \
    wl_t _f5_2    = wl_add( f##5, f##5 );      wl_t _f7_2    = wl_add( f##7, f##7 );                                            \
    wl_t _f9_2    = wl_add( f##9, f##9 );                                                                                       \
                                                                                                                                \
    wl_t _f0g0    = wl_mul_ll( f##0, g##0   ); wl_t _f0g1    = wl_mul_ll( f##0,  g##1   );                                      \
    wl_t _f0g2    = wl_mul_ll( f##0, g##2   ); wl_t _f0g3    = wl_mul_ll( f##0,  g##3   );                                      \
    wl_t _f0g4    = wl_mul_ll( f##0, g##4   ); wl_t _f0g5    = wl_mul_ll( f##0,  g##5   );                                      \
    wl_t _f0g6    = wl_mul_ll( f##0, g##6   ); wl_t _f0g7    = wl_mul_ll( f##0,  g##7   );                                      \
    wl_t _f0g8    = wl_mul_ll( f##0, g##8   ); wl_t _f0g9    = wl_mul_ll( f##0,  g##9   );                                      \
                                                                                                                                \
    wl_t _f1g0    = wl_mul_ll( f##1, g##0   ); wl_t _f1g1_2  = wl_mul_ll( _f1_2, g##1   );                                      \
    wl_t _f1g2    = wl_mul_ll( f##1, g##2   ); wl_t _f1g3_2  = wl_mul_ll( _f1_2, g##3   );                                      \
    wl_t _f1g4    = wl_mul_ll( f##1, g##4   ); wl_t _f1g5_2  = wl_mul_ll( _f1_2, g##5   );                                      \
    wl_t _f1g6    = wl_mul_ll( f##1, g##6   ); wl_t _f1g7_2  = wl_mul_ll( _f1_2, g##7   );                                      \
    wl_t _f1g8    = wl_mul_ll( f##1, g##8   ); wl_t _f1g9_38 = wl_mul_ll( _f1_2, _g9_19 );                                      \
                                                                                                                                \
    wl_t _f2g0    = wl_mul_ll( f##2, g##0   ); wl_t _f2g1    = wl_mul_ll( f##2,  g##1   );                                      \
    wl_t _f2g2    = wl_mul_ll( f##2, g##2   ); wl_t _f2g3    = wl_mul_ll( f##2,  g##3   );                                      \
    wl_t _f2g4    = wl_mul_ll( f##2, g##4   ); wl_t _f2g5    = wl_mul_ll( f##2,  g##5   );                                      \
    wl_t _f2g6    = wl_mul_ll( f##2, g##6   ); wl_t _f2g7    = wl_mul_ll( f##2,  g##7   );                                      \
    wl_t _f2g8_19 = wl_mul_ll( f##2, _g8_19 ); wl_t _f2g9_19 = wl_mul_ll( f##2,  _g9_19 );                                      \
                                                                                                                                \
    wl_t _f3g0    = wl_mul_ll( f##3, g##0   ); wl_t _f3g1_2  = wl_mul_ll( _f3_2, g##1   );                                      \
    wl_t _f3g2    = wl_mul_ll( f##3, g##2   ); wl_t _f3g3_2  = wl_mul_ll( _f3_2, g##3   );                                      \
    wl_t _f3g4    = wl_mul_ll( f##3, g##4   ); wl_t _f3g5_2  = wl_mul_ll( _f3_2, g##5   );                                      \
    wl_t _f3g6    = wl_mul_ll( f##3, g##6   ); wl_t _f3g7_38 = wl_mul_ll( _f3_2, _g7_19 );                                      \
    wl_t _f3g8_19 = wl_mul_ll( f##3, _g8_19 ); wl_t _f3g9_38 = wl_mul_ll( _f3_2, _g9_19 );                                      \
                                                                                                                                \
    wl_t _f4g0    = wl_mul_ll( f##4, g##0   ); wl_t _f4g1    = wl_mul_ll( f##4,  g##1   );                                      \
    wl_t _f4g2    = wl_mul_ll( f##4, g##2   ); wl_t _f4g3    = wl_mul_ll( f##4,  g##3   );                                      \
    wl_t _f4g4    = wl_mul_ll( f##4, g##4   ); wl_t _f4g5    = wl_mul_ll( f##4,  g##5   );                                      \
    wl_t _f4g6_19 = wl_mul_ll( f##4, _g6_19 ); wl_t _f4g7_19 = wl_mul_ll( f##4,  _g7_19 );                                      \
    wl_t _f4g8_19 = wl_mul_ll( f##4, _g8_19 ); wl_t _f4g9_19 = wl_mul_ll( f##4,  _g9_19 );                                      \
                                                                                                                                \
    wl_t _f5g0    = wl_mul_ll( f##5, g##0   ); wl_t _f5g1_2  = wl_mul_ll( _f5_2, g##1   );                                      \
    wl_t _f5g2    = wl_mul_ll( f##5, g##2   ); wl_t _f5g3_2  = wl_mul_ll( _f5_2, g##3   );                                      \
    wl_t _f5g4    = wl_mul_ll( f##5, g##4   ); wl_t _f5g5_38 = wl_mul_ll( _f5_2, _g5_19 );                                      \
    wl_t _f5g6_19 = wl_mul_ll( f##5, _g6_19 ); wl_t _f5g7_38 = wl_mul_ll( _f5_2, _g7_19 );                                      \
    wl_t _f5g8_19 = wl_mul_ll( f##5, _g8_19 ); wl_t _f5g9_38 = wl_mul_ll( _f5_2, _g9_19 );                                      \
                                                                                                                                \
    wl_t _f6g0    = wl_mul_ll( f##6, g##0   ); wl_t _f6g1    = wl_mul_ll( f##6,  g##1   );                                      \
    wl_t _f6g2    = wl_mul_ll( f##6, g##2   ); wl_t _f6g3    = wl_mul_ll( f##6,  g##3   );                                      \
    wl_t _f6g4_19 = wl_mul_ll( f##6, _g4_19 ); wl_t _f6g5_19 = wl_mul_ll( f##6,  _g5_19 );                                      \
    wl_t _f6g6_19 = wl_mul_ll( f##6, _g6_19 ); wl_t _f6g7_19 = wl_mul_ll( f##6,  _g7_19 );                                      \
    wl_t _f6g8_19 = wl_mul_ll( f##6, _g8_19 ); wl_t _f6g9_19 = wl_mul_ll( f##6,  _g9_19 );                                      \
                                                                                                                                \
    wl_t _f7g0    = wl_mul_ll( f##7, g##0   ); wl_t _f7g1_2  = wl_mul_ll( _f7_2, g##1   );                                      \
    wl_t _f7g2    = wl_mul_ll( f##7, g##2   ); wl_t _f7g3_38 = wl_mul_ll( _f7_2, _g3_19 );                                      \
    wl_t _f7g4_19 = wl_mul_ll( f##7, _g4_19 ); wl_t _f7g5_38 = wl_mul_ll( _f7_2, _g5_19 );                                      \
    wl_t _f7g6_19 = wl_mul_ll( f##7, _g6_19 ); wl_t _f7g7_38 = wl_mul_ll( _f7_2, _g7_19 );                                      \
    wl_t _f7g8_19 = wl_mul_ll( f##7, _g8_19 ); wl_t _f7g9_38 = wl_mul_ll( _f7_2, _g9_19 );                                      \
                                                                                                                                \
    wl_t _f8g0    = wl_mul_ll( f##8, g##0   ); wl_t _f8g1    = wl_mul_ll( f##8,  g##1   );                                      \
    wl_t _f8g2_19 = wl_mul_ll( f##8, _g2_19 ); wl_t _f8g3_19 = wl_mul_ll( f##8,  _g3_19 );                                      \
    wl_t _f8g4_19 = wl_mul_ll( f##8, _g4_19 ); wl_t _f8g5_19 = wl_mul_ll( f##8,  _g5_19 );                                      \
    wl_t _f8g6_19 = wl_mul_ll( f##8, _g6_19 ); wl_t _f8g7_19 = wl_mul_ll( f##8,  _g7_19 );                                      \
    wl_t _f8g8_19 = wl_mul_ll( f##8, _g8_19 ); wl_t _f8g9_19 = wl_mul_ll( f##8,  _g9_19 );                                      \
                                                                                                                                \
    wl_t _f9g0    = wl_mul_ll( f##9, g##0   ); wl_t _f9g1_38 = wl_mul_ll( _f9_2, _g1_19 );                                      \
    wl_t _f9g2_19 = wl_mul_ll( f##9, _g2_19 ); wl_t _f9g3_38 = wl_mul_ll( _f9_2, _g3_19 );                                      \
    wl_t _f9g4_19 = wl_mul_ll( f##9, _g4_19 ); wl_t _f9g5_38 = wl_mul_ll( _f9_2, _g5_19 );                                      \
    wl_t _f9g6_19 = wl_mul_ll( f##9, _g6_19 ); wl_t _f9g7_38 = wl_mul_ll( _f9_2, _g7_19 );                                      \
    wl_t _f9g8_19 = wl_mul_ll( f##9, _g8_19 ); wl_t _f9g9_38 = wl_mul_ll( _f9_2, _g9_19 );                                      \
                                                                                                                                \
    h##0 = wl_add10( _f0g0, _f1g9_38, _f2g8_19, _f3g7_38, _f4g6_19, _f5g5_38, _f6g4_19, _f7g3_38, _f8g2_19, _f9g1_38 );         \
    h##1 = wl_add10( _f0g1, _f1g0   , _f2g9_19, _f3g8_19, _f4g7_19, _f5g6_19, _f6g5_19, _f7g4_19, _f8g3_19, _f9g2_19 );         \
    h##2 = wl_add10( _f0g2, _f1g1_2 , _f2g0   , _f3g9_38, _f4g8_19, _f5g7_38, _f6g6_19, _f7g5_38, _f8g4_19, _f9g3_38 );         \
    h##3 = wl_add10( _f0g3, _f1g2   , _f2g1   , _f3g0   , _f4g9_19, _f5g8_19, _f6g7_19, _f7g6_19, _f8g5_19, _f9g4_19 );         \
    h##4 = wl_add10( _f0g4, _f1g3_2 , _f2g2   , _f3g1_2 , _f4g0   , _f5g9_38, _f6g8_19, _f7g7_38, _f8g6_19, _f9g5_38 );         \
    h##5 = wl_add10( _f0g5, _f1g4   , _f2g3   , _f3g2   , _f4g1   , _f5g0   , _f6g9_19, _f7g8_19, _f8g7_19, _f9g6_19 );         \
    h##6 = wl_add10( _f0g6, _f1g5_2 , _f2g4   , _f3g3_2 , _f4g2   , _f5g1_2 , _f6g0   , _f7g9_38, _f8g8_19, _f9g7_38 );         \
    h##7 = wl_add10( _f0g7, _f1g6   , _f2g5   , _f3g4   , _f4g3   , _f5g2   , _f6g1   , _f7g0   , _f8g9_19, _f9g8_19 );         \
    h##8 = wl_add10( _f0g8, _f1g7_2 , _f2g6   , _f3g5_2 , _f4g4   , _f5g3_2 , _f6g2   , _f7g1_2 , _f8g0   , _f9g9_38 );         \
    h##9 = wl_add10( _f0g9, _f1g8   , _f2g7   , _f3g6   , _f4g5   , _f5g4   , _f6g3   , _f7g2   , _f8g1   , _f9g0    );         \
                                                                                                                                \
    wl_t _m38u = wl_bcast( (long)FD_ULONG_MASK_MSB(38) );                                                                       \
    wl_t _m39u = wl_bcast( (long)FD_ULONG_MASK_MSB(39) );                                                                       \
    wl_t _b24  = wl_bcast( 1L << 24 );                                                                                          \
    wl_t _b25  = wl_bcast( 1L << 25 );                                                                                          \
                                                                                                                                \
    wl_t _c0 = wl_add( h##0, _b25 ); h##1 = wl_add( h##1, wl_shr    ( _c0, 26 ) ); h##0 = wl_sub( h##0, wl_and( _c0, _m38u ) ); \
    wl_t _c4 = wl_add( h##4, _b25 ); h##5 = wl_add( h##5, wl_shr    ( _c4, 26 ) ); h##4 = wl_sub( h##4, wl_and( _c4, _m38u ) ); \
    wl_t _c1 = wl_add( h##1, _b24 ); h##2 = wl_add( h##2, wl_shr    ( _c1, 25 ) ); h##1 = wl_sub( h##1, wl_and( _c1, _m39u ) ); \
    wl_t _c5 = wl_add( h##5, _b24 ); h##6 = wl_add( h##6, wl_shr    ( _c5, 25 ) ); h##5 = wl_sub( h##5, wl_and( _c5, _m39u ) ); \
    wl_t _c2 = wl_add( h##2, _b25 ); h##3 = wl_add( h##3, wl_shr    ( _c2, 26 ) ); h##2 = wl_sub( h##2, wl_and( _c2, _m38u ) ); \
    wl_t _c6 = wl_add( h##6, _b25 ); h##7 = wl_add( h##7, wl_shr    ( _c6, 26 ) ); h##6 = wl_sub( h##6, wl_and( _c6, _m38u ) ); \
    wl_t _c3 = wl_add( h##3, _b24 ); h##4 = wl_add( h##4, wl_shr    ( _c3, 25 ) ); h##3 = wl_sub( h##3, wl_and( _c3, _m39u ) ); \
    wl_t _c7 = wl_add( h##7, _b24 ); h##8 = wl_add( h##8, wl_shr    ( _c7, 25 ) ); h##7 = wl_sub( h##7, wl_and( _c7, _m39u ) ); \
    /**/ _c4 = wl_add( h##4, _b25 ); h##5 = wl_add( h##5, wl_shr    ( _c4, 26 ) ); h##4 = wl_sub( h##4, wl_and( _c4, _m38u ) ); \
    wl_t _c8 = wl_add( h##8, _b25 ); h##9 = wl_add( h##9, wl_shr    ( _c8, 26 ) ); h##8 = wl_sub( h##8, wl_and( _c8, _m38u ) ); \
    wl_t _c9 = wl_add( h##9, _b24 ); h##0 = wl_add( h##0, wl_shr_x19( _c9, 25 ) ); h##9 = wl_sub( h##9, wl_and( _c9, _m39u ) ); \
    /**/ _c0 = wl_add( h##0, _b25 ); h##1 = wl_add( h##1, wl_shr    ( _c0, 26 ) ); h##0 = wl_sub( h##0, wl_and( _c0, _m38u ) ); \
  } while(0)

/* FE_AVX_INL_SQN squares the lanes of f and then scales each lane by
   either 1 or 2 (per lane specified, n* should be compile time constant
   in 1:2) with partial reduction and stores the result in h.  In place
   operation is fine. */

#define FE_AVX_INL_SQN( h, f, na,nb,nc,nd ) do {                                                                                \
    wl_t _f0_2    = wl_add( f##0, f##0 );       wl_t _f1_2    = wl_add( f##1, f##1 );                                           \
    wl_t _f2_2    = wl_add( f##2, f##2 );       wl_t _f3_2    = wl_add( f##3, f##3 );                                           \
    wl_t _f4_2    = wl_add( f##4, f##4 );       wl_t _f5_2    = wl_add( f##5, f##5 );                                           \
    wl_t _f6_2    = wl_add( f##6, f##6 );       wl_t _f7_2    = wl_add( f##7, f##7 );                                           \
                                                                                                                                \
    wl_t _38      = wl_bcast( 38L );            wl_t _19      = wl_bcast( 19L );                                                \
                                                                                                                                \
    wl_t _f5_38   = wl_mul_ll( _38, f##5 );     wl_t _f6_19   = wl_mul_ll( _19, f##6 );                                         \
    wl_t _f7_38   = wl_mul_ll( _38, f##7 );     wl_t _f8_19   = wl_mul_ll( _19, f##8 );                                         \
    wl_t _f9_38   = wl_mul_ll( _38, f##9 );                                                                                     \
                                                                                                                                \
    wl_t _f0f0    = wl_mul_ll( f##0,  f##0   ); wl_t _f0f1_2  = wl_mul_ll( _f0_2, f##1   );                                     \
    wl_t _f0f2_2  = wl_mul_ll( _f0_2, f##2   ); wl_t _f0f3_2  = wl_mul_ll( _f0_2, f##3   );                                     \
    wl_t _f0f4_2  = wl_mul_ll( _f0_2, f##4   ); wl_t _f0f5_2  = wl_mul_ll( _f0_2, f##5   );                                     \
    wl_t _f0f6_2  = wl_mul_ll( _f0_2, f##6   ); wl_t _f0f7_2  = wl_mul_ll( _f0_2, f##7   );                                     \
    wl_t _f0f8_2  = wl_mul_ll( _f0_2, f##8   ); wl_t _f0f9_2  = wl_mul_ll( _f0_2, f##9   );                                     \
                                                                                                                                \
    wl_t _f1f1_2  = wl_mul_ll( _f1_2, f##1   ); wl_t _f1f2_2  = wl_mul_ll( _f1_2, f##2   );                                     \
    wl_t _f1f3_4  = wl_mul_ll( _f1_2, _f3_2  ); wl_t _f1f4_2  = wl_mul_ll( _f1_2, f##4   );                                     \
    wl_t _f1f5_4  = wl_mul_ll( _f1_2, _f5_2  ); wl_t _f1f6_2  = wl_mul_ll( _f1_2, f##6   );                                     \
    wl_t _f1f7_4  = wl_mul_ll( _f1_2, _f7_2  ); wl_t _f1f8_2  = wl_mul_ll( _f1_2, f##8   );                                     \
    wl_t _f1f9_76 = wl_mul_ll( _f1_2, _f9_38 );                                                                                 \
                                                                                                                                \
    wl_t _f2f2    = wl_mul_ll( f##2,  f##2   ); wl_t _f2f3_2  = wl_mul_ll( _f2_2, f##3   );                                     \
    wl_t _f2f4_2  = wl_mul_ll( _f2_2, f##4   ); wl_t _f2f5_2  = wl_mul_ll( _f2_2, f##5   );                                     \
    wl_t _f2f6_2  = wl_mul_ll( _f2_2, f##6   ); wl_t _f2f7_2  = wl_mul_ll( _f2_2, f##7   );                                     \
    wl_t _f2f8_38 = wl_mul_ll( _f2_2, _f8_19 ); wl_t _f2f9_38 = wl_mul_ll( f##2 , _f9_38 );                                     \
                                                                                                                                \
    wl_t _f3f3_2  = wl_mul_ll( _f3_2, f##3   ); wl_t _f3f4_2  = wl_mul_ll( _f3_2, f##4   );                                     \
    wl_t _f3f5_4  = wl_mul_ll( _f3_2, _f5_2  ); wl_t _f3f6_2  = wl_mul_ll( _f3_2, f##6   );                                     \
    wl_t _f3f7_76 = wl_mul_ll( _f3_2, _f7_38 ); wl_t _f3f8_38 = wl_mul_ll( _f3_2, _f8_19 );                                     \
    wl_t _f3f9_76 = wl_mul_ll( _f3_2, _f9_38 );                                                                                 \
                                                                                                                                \
    wl_t _f4f4    = wl_mul_ll( f##4,  f##4   ); wl_t _f4f5_2  = wl_mul_ll( _f4_2, f##5   );                                     \
    wl_t _f4f6_38 = wl_mul_ll( _f4_2, _f6_19 ); wl_t _f4f7_38 = wl_mul_ll( f##4,  _f7_38 );                                     \
    wl_t _f4f8_38 = wl_mul_ll( _f4_2, _f8_19 ); wl_t _f4f9_38 = wl_mul_ll( f##4,  _f9_38 );                                     \
                                                                                                                                \
    wl_t _f5f5_38 = wl_mul_ll( f##5,  _f5_38 ); wl_t _f5f6_38 = wl_mul_ll( _f5_2, _f6_19 );                                     \
    wl_t _f5f7_76 = wl_mul_ll( _f5_2, _f7_38 ); wl_t _f5f8_38 = wl_mul_ll( _f5_2, _f8_19 );                                     \
    wl_t _f5f9_76 = wl_mul_ll( _f5_2, _f9_38 );                                                                                 \
                                                                                                                                \
    wl_t _f6f6_19 = wl_mul_ll( f##6,  _f6_19 ); wl_t _f6f7_38 = wl_mul_ll( f##6,  _f7_38 );                                     \
    wl_t _f6f8_38 = wl_mul_ll( _f6_2, _f8_19 ); wl_t _f6f9_38 = wl_mul_ll( f##6,  _f9_38 );                                     \
                                                                                                                                \
    wl_t _f7f7_38 = wl_mul_ll( f##7,  _f7_38 ); wl_t _f7f8_38 = wl_mul_ll( _f7_2, _f8_19 );                                     \
    wl_t _f7f9_76 = wl_mul_ll( _f7_2, _f9_38 );                                                                                 \
                                                                                                                                \
    wl_t _f8f8_19 = wl_mul_ll( f##8,  _f8_19 ); wl_t _f8f9_38 = wl_mul_ll( f##8,  _f9_38 );                                     \
                                                                                                                                \
    wl_t _f9f9_38 = wl_mul_ll( f##9,  _f9_38 );                                                                                 \
                                                                                                                                \
    wl_t _m = wl( 1L-na, 1L-nb, 1L-nc, 1L-nd );                                                                                 \
                                                                                                                                \
    h##0 = wl_add6( _f0f0  , _f1f9_76, _f2f8_38, _f3f7_76, _f4f6_38, _f5f5_38 ); h##0 = wl_add( h##0, wl_and( h##0, _m ) );     \
    h##1 = wl_add5( _f0f1_2, _f2f9_38, _f3f8_38, _f4f7_38, _f5f6_38           ); h##1 = wl_add( h##1, wl_and( h##1, _m ) );     \
    h##2 = wl_add6( _f0f2_2, _f1f1_2 , _f3f9_76, _f4f8_38, _f5f7_76, _f6f6_19 ); h##2 = wl_add( h##2, wl_and( h##2, _m ) );     \
    h##3 = wl_add5( _f0f3_2, _f1f2_2 , _f4f9_38, _f5f8_38, _f6f7_38           ); h##3 = wl_add( h##3, wl_and( h##3, _m ) );     \
    h##4 = wl_add6( _f0f4_2, _f1f3_4 , _f2f2   , _f5f9_76, _f6f8_38, _f7f7_38 ); h##4 = wl_add( h##4, wl_and( h##4, _m ) );     \
    h##5 = wl_add5( _f0f5_2, _f1f4_2 , _f2f3_2 , _f6f9_38, _f7f8_38           ); h##5 = wl_add( h##5, wl_and( h##5, _m ) );     \
    h##6 = wl_add6( _f0f6_2, _f1f5_4 , _f2f4_2 , _f3f3_2 , _f7f9_76, _f8f8_19 ); h##6 = wl_add( h##6, wl_and( h##6, _m ) );     \
    h##7 = wl_add5( _f0f7_2, _f1f6_2 , _f2f5_2 , _f3f4_2 , _f8f9_38           ); h##7 = wl_add( h##7, wl_and( h##7, _m ) );     \
    h##8 = wl_add6( _f0f8_2, _f1f7_4 , _f2f6_2 , _f3f5_4 , _f4f4   , _f9f9_38 ); h##8 = wl_add( h##8, wl_and( h##8, _m ) );     \
    h##9 = wl_add5( _f0f9_2, _f1f8_2 , _f2f7_2 , _f3f6_2 , _f4f5_2            ); h##9 = wl_add( h##9, wl_and( h##9, _m ) );     \
                                                                                                                                \
    wl_t _m38u = wl_bcast( (long)FD_ULONG_MASK_MSB(38) );                                                                       \
    wl_t _m39u = wl_bcast( (long)FD_ULONG_MASK_MSB(39) );                                                                       \
    wl_t _b24  = wl_bcast( 1L << 24 );                                                                                          \
    wl_t _b25  = wl_bcast( 1L << 25 );                                                                                          \
                                                                                                                                \
    wl_t _c0 = wl_add( h##0, _b25 ); h##1 = wl_add( h##1, wl_shr    ( _c0, 26 ) ); h##0 = wl_sub( h##0, wl_and( _c0, _m38u ) ); \
    wl_t _c4 = wl_add( h##4, _b25 ); h##5 = wl_add( h##5, wl_shr    ( _c4, 26 ) ); h##4 = wl_sub( h##4, wl_and( _c4, _m38u ) ); \
    wl_t _c1 = wl_add( h##1, _b24 ); h##2 = wl_add( h##2, wl_shr    ( _c1, 25 ) ); h##1 = wl_sub( h##1, wl_and( _c1, _m39u ) ); \
    wl_t _c5 = wl_add( h##5, _b24 ); h##6 = wl_add( h##6, wl_shr    ( _c5, 25 ) ); h##5 = wl_sub( h##5, wl_and( _c5, _m39u ) ); \
    wl_t _c2 = wl_add( h##2, _b25 ); h##3 = wl_add( h##3, wl_shr    ( _c2, 26 ) ); h##2 = wl_sub( h##2, wl_and( _c2, _m38u ) ); \
    wl_t _c6 = wl_add( h##6, _b25 ); h##7 = wl_add( h##7, wl_shr    ( _c6, 26 ) ); h##6 = wl_sub( h##6, wl_and( _c6, _m38u ) ); \
    wl_t _c3 = wl_add( h##3, _b24 ); h##4 = wl_add( h##4, wl_shr    ( _c3, 25 ) ); h##3 = wl_sub( h##3, wl_and( _c3, _m39u ) ); \
    wl_t _c7 = wl_add( h##7, _b24 ); h##8 = wl_add( h##8, wl_shr    ( _c7, 25 ) ); h##7 = wl_sub( h##7, wl_and( _c7, _m39u ) ); \
    /**/ _c4 = wl_add( h##4, _b25 ); h##5 = wl_add( h##5, wl_shr    ( _c4, 26 ) ); h##4 = wl_sub( h##4, wl_and( _c4, _m38u ) ); \
    wl_t _c8 = wl_add( h##8, _b25 ); h##9 = wl_add( h##9, wl_shr    ( _c8, 26 ) ); h##8 = wl_sub( h##8, wl_and( _c8, _m38u ) ); \
    wl_t _c9 = wl_add( h##9, _b24 ); h##0 = wl_add( h##0, wl_shr_x19( _c9, 25 ) ); h##9 = wl_sub( h##9, wl_and( _c9, _m39u ) ); \
    /**/ _c0 = wl_add( h##0, _b25 ); h##1 = wl_add( h##1, wl_shr    ( _c0, 26 ) ); h##0 = wl_sub( h##0, wl_and( _c0, _m38u ) ); \
  } while(0)

/* FE_AVX_INL_SQ does a square of the corresponding lanes (with partial
   reduction) and stores the result in h.  In place operation is fine. */

#define FE_AVX_INL_SQ( h, f ) do {                                                                                              \
    wl_t _f0_2    = wl_add( f##0, f##0 );       wl_t _f1_2    = wl_add( f##1, f##1 );                                           \
    wl_t _f2_2    = wl_add( f##2, f##2 );       wl_t _f3_2    = wl_add( f##3, f##3 );                                           \
    wl_t _f4_2    = wl_add( f##4, f##4 );       wl_t _f5_2    = wl_add( f##5, f##5 );                                           \
    wl_t _f6_2    = wl_add( f##6, f##6 );       wl_t _f7_2    = wl_add( f##7, f##7 );                                           \
                                                                                                                                \
    wl_t _38      = wl_bcast( 38L );            wl_t _19      = wl_bcast( 19L );                                                \
                                                                                                                                \
    wl_t _f5_38   = wl_mul_ll( _38, f##5 );     wl_t _f6_19   = wl_mul_ll( _19, f##6 );                                         \
    wl_t _f7_38   = wl_mul_ll( _38, f##7 );     wl_t _f8_19   = wl_mul_ll( _19, f##8 );                                         \
    wl_t _f9_38   = wl_mul_ll( _38, f##9 );                                                                                     \
                                                                                                                                \
    wl_t _f0f0    = wl_mul_ll( f##0,  f##0   ); wl_t _f0f1_2  = wl_mul_ll( _f0_2, f##1   );                                     \
    wl_t _f0f2_2  = wl_mul_ll( _f0_2, f##2   ); wl_t _f0f3_2  = wl_mul_ll( _f0_2, f##3   );                                     \
    wl_t _f0f4_2  = wl_mul_ll( _f0_2, f##4   ); wl_t _f0f5_2  = wl_mul_ll( _f0_2, f##5   );                                     \
    wl_t _f0f6_2  = wl_mul_ll( _f0_2, f##6   ); wl_t _f0f7_2  = wl_mul_ll( _f0_2, f##7   );                                     \
    wl_t _f0f8_2  = wl_mul_ll( _f0_2, f##8   ); wl_t _f0f9_2  = wl_mul_ll( _f0_2, f##9   );                                     \
                                                                                                                                \
    wl_t _f1f1_2  = wl_mul_ll( _f1_2, f##1   ); wl_t _f1f2_2  = wl_mul_ll( _f1_2, f##2   );                                     \
    wl_t _f1f3_4  = wl_mul_ll( _f1_2, _f3_2  ); wl_t _f1f4_2  = wl_mul_ll( _f1_2, f##4   );                                     \
    wl_t _f1f5_4  = wl_mul_ll( _f1_2, _f5_2  ); wl_t _f1f6_2  = wl_mul_ll( _f1_2, f##6   );                                     \
    wl_t _f1f7_4  = wl_mul_ll( _f1_2, _f7_2  ); wl_t _f1f8_2  = wl_mul_ll( _f1_2, f##8   );                                     \
    wl_t _f1f9_76 = wl_mul_ll( _f1_2, _f9_38 );                                                                                 \
                                                                                                                                \
    wl_t _f2f2    = wl_mul_ll( f##2,  f##2   ); wl_t _f2f3_2  = wl_mul_ll( _f2_2, f##3   );                                     \
    wl_t _f2f4_2  = wl_mul_ll( _f2_2, f##4   ); wl_t _f2f5_2  = wl_mul_ll( _f2_2, f##5   );                                     \
    wl_t _f2f6_2  = wl_mul_ll( _f2_2, f##6   ); wl_t _f2f7_2  = wl_mul_ll( _f2_2, f##7   );                                     \
    wl_t _f2f8_38 = wl_mul_ll( _f2_2, _f8_19 ); wl_t _f2f9_38 = wl_mul_ll( f##2 , _f9_38 );                                     \
                                                                                                                                \
    wl_t _f3f3_2  = wl_mul_ll( _f3_2, f##3   ); wl_t _f3f4_2  = wl_mul_ll( _f3_2, f##4   );                                     \
    wl_t _f3f5_4  = wl_mul_ll( _f3_2, _f5_2  ); wl_t _f3f6_2  = wl_mul_ll( _f3_2, f##6   );                                     \
    wl_t _f3f7_76 = wl_mul_ll( _f3_2, _f7_38 ); wl_t _f3f8_38 = wl_mul_ll( _f3_2, _f8_19 );                                     \
    wl_t _f3f9_76 = wl_mul_ll( _f3_2, _f9_38 );                                                                                 \
                                                                                                                                \
    wl_t _f4f4    = wl_mul_ll( f##4,  f##4   ); wl_t _f4f5_2  = wl_mul_ll( _f4_2, f##5   );                                     \
    wl_t _f4f6_38 = wl_mul_ll( _f4_2, _f6_19 ); wl_t _f4f7_38 = wl_mul_ll( f##4,  _f7_38 );                                     \
    wl_t _f4f8_38 = wl_mul_ll( _f4_2, _f8_19 ); wl_t _f4f9_38 = wl_mul_ll( f##4,  _f9_38 );                                     \
                                                                                                                                \
    wl_t _f5f5_38 = wl_mul_ll( f##5,  _f5_38 ); wl_t _f5f6_38 = wl_mul_ll( _f5_2, _f6_19 );                                     \
    wl_t _f5f7_76 = wl_mul_ll( _f5_2, _f7_38 ); wl_t _f5f8_38 = wl_mul_ll( _f5_2, _f8_19 );                                     \
    wl_t _f5f9_76 = wl_mul_ll( _f5_2, _f9_38 );                                                                                 \
                                                                                                                                \
    wl_t _f6f6_19 = wl_mul_ll( f##6,  _f6_19 ); wl_t _f6f7_38 = wl_mul_ll( f##6,  _f7_38 );                                     \
    wl_t _f6f8_38 = wl_mul_ll( _f6_2, _f8_19 ); wl_t _f6f9_38 = wl_mul_ll( f##6,  _f9_38 );                                     \
                                                                                                                                \
    wl_t _f7f7_38 = wl_mul_ll( f##7,  _f7_38 ); wl_t _f7f8_38 = wl_mul_ll( _f7_2, _f8_19 );                                     \
    wl_t _f7f9_76 = wl_mul_ll( _f7_2, _f9_38 );                                                                                 \
                                                                                                                                \
    wl_t _f8f8_19 = wl_mul_ll( f##8,  _f8_19 ); wl_t _f8f9_38 = wl_mul_ll( f##8,  _f9_38 );                                     \
                                                                                                                                \
    wl_t _f9f9_38 = wl_mul_ll( f##9,  _f9_38 );                                                                                 \
                                                                                                                                \
    h##0 = wl_add6( _f0f0  , _f1f9_76, _f2f8_38, _f3f7_76, _f4f6_38, _f5f5_38 );                                                \
    h##1 = wl_add5( _f0f1_2, _f2f9_38, _f3f8_38, _f4f7_38, _f5f6_38           );                                                \
    h##2 = wl_add6( _f0f2_2, _f1f1_2 , _f3f9_76, _f4f8_38, _f5f7_76, _f6f6_19 );                                                \
    h##3 = wl_add5( _f0f3_2, _f1f2_2 , _f4f9_38, _f5f8_38, _f6f7_38           );                                                \
    h##4 = wl_add6( _f0f4_2, _f1f3_4 , _f2f2   , _f5f9_76, _f6f8_38, _f7f7_38 );                                                \
    h##5 = wl_add5( _f0f5_2, _f1f4_2 , _f2f3_2 , _f6f9_38, _f7f8_38           );                                                \
    h##6 = wl_add6( _f0f6_2, _f1f5_4 , _f2f4_2 , _f3f3_2 , _f7f9_76, _f8f8_19 );                                                \
    h##7 = wl_add5( _f0f7_2, _f1f6_2 , _f2f5_2 , _f3f4_2 , _f8f9_38           );                                                \
    h##8 = wl_add6( _f0f8_2, _f1f7_4 , _f2f6_2 , _f3f5_4 , _f4f4   , _f9f9_38 );                                                \
    h##9 = wl_add5( _f0f9_2, _f1f8_2 , _f2f7_2 , _f3f6_2 , _f4f5_2            );                                                \
                                                                                                                                \
    wl_t _m38u = wl_bcast( (long)FD_ULONG_MASK_MSB(38) );                                                                       \
    wl_t _m39u = wl_bcast( (long)FD_ULONG_MASK_MSB(39) );                                                                       \
    wl_t _b24  = wl_bcast( 1L << 24 );                                                                                          \
    wl_t _b25  = wl_bcast( 1L << 25 );                                                                                          \
                                                                                                                                \
    wl_t _c0 = wl_add( h##0, _b25 ); h##1 = wl_add( h##1, wl_shr    ( _c0, 26 ) ); h##0 = wl_sub( h##0, wl_and( _c0, _m38u ) ); \
    wl_t _c4 = wl_add( h##4, _b25 ); h##5 = wl_add( h##5, wl_shr    ( _c4, 26 ) ); h##4 = wl_sub( h##4, wl_and( _c4, _m38u ) ); \
    wl_t _c1 = wl_add( h##1, _b24 ); h##2 = wl_add( h##2, wl_shr    ( _c1, 25 ) ); h##1 = wl_sub( h##1, wl_and( _c1, _m39u ) ); \
    wl_t _c5 = wl_add( h##5, _b24 ); h##6 = wl_add( h##6, wl_shr    ( _c5, 25 ) ); h##5 = wl_sub( h##5, wl_and( _c5, _m39u ) ); \
    wl_t _c2 = wl_add( h##2, _b25 ); h##3 = wl_add( h##3, wl_shr    ( _c2, 26 ) ); h##2 = wl_sub( h##2, wl_and( _c2, _m38u ) ); \
    wl_t _c6 = wl_add( h##6, _b25 ); h##7 = wl_add( h##7, wl_shr    ( _c6, 26 ) ); h##6 = wl_sub( h##6, wl_and( _c6, _m38u ) ); \
    wl_t _c3 = wl_add( h##3, _b24 ); h##4 = wl_add( h##4, wl_shr    ( _c3, 25 ) ); h##3 = wl_sub( h##3, wl_and( _c3, _m39u ) ); \
    wl_t _c7 = wl_add( h##7, _b24 ); h##8 = wl_add( h##8, wl_shr    ( _c7, 25 ) ); h##7 = wl_sub( h##7, wl_and( _c7, _m39u ) ); \
    /**/ _c4 = wl_add( h##4, _b25 ); h##5 = wl_add( h##5, wl_shr    ( _c4, 26 ) ); h##4 = wl_sub( h##4, wl_and( _c4, _m38u ) ); \
    wl_t _c8 = wl_add( h##8, _b25 ); h##9 = wl_add( h##9, wl_shr    ( _c8, 26 ) ); h##8 = wl_sub( h##8, wl_and( _c8, _m38u ) ); \
    wl_t _c9 = wl_add( h##9, _b24 ); h##0 = wl_add( h##0, wl_shr_x19( _c9, 25 ) ); h##9 = wl_sub( h##9, wl_and( _c9, _m39u ) ); \
    /**/ _c0 = wl_add( h##0, _b25 ); h##1 = wl_add( h##1, wl_shr    ( _c0, 26 ) ); h##0 = wl_sub( h##0, wl_and( _c0, _m38u ) ); \
  } while(0)

/* FE_AVX_INL_SQ_ITER squares of the lanes (with partial reduction) of x
   n times and stores the result in h.  In place operation is fine. */

#define FE_AVX_INL_SQ_ITER( h, f, n ) do {               \
    FD_AVX_COPY( h, f );                                 \
    for( ulong _n=(n); _n; _n-- ) FD_AVX_SQ_INL( h, h ); \
  } while(0)

/* FE_AVX_INL_POW22523 applies fd_ed25519_pow22523 to the lanes of f and
   stores the result in h.  In place operation is fine.  Note that we
   actually implement this one out of line even in inline contexts to
   keep instruction footprint resonable. */

#define FE_AVX_INL_POW22523( h, f ) do {           \
    long _f[ 40 ] __attribute__((aligned(64)));    \
    FE_AVX_INL_ST( _f, f );                        \
    FE_AVX_INL_LD( h, fe_avx_pow22523( _f, _f ) ); \
  } while(0)

/* FE_AVX_INL miscellaneous *******************************************/

/* FE_AVX_INL_LANE_SELECT does
     h(n) = f(n) if cn is non-zero and 0 otherwise
   for n in 0:3.  In-place operation fine.  Recommended that cn be
   compile time constants. */

#define FE_AVX_INL_LANE_SELECT( h, f, c0,c1,c2,c3 ) do {                           \
    wl_t _mask = wl( -(long)!!(c0), -(long)!!(c1), -(long)!!(c2), -(long)!!(c3) ); \
    h##0 = wl_and( f##0, _mask );                                                  \
    h##1 = wl_and( f##1, _mask );                                                  \
    h##2 = wl_and( f##2, _mask );                                                  \
    h##3 = wl_and( f##3, _mask );                                                  \
    h##4 = wl_and( f##4, _mask );                                                  \
    h##5 = wl_and( f##5, _mask );                                                  \
    h##6 = wl_and( f##6, _mask );                                                  \
    h##7 = wl_and( f##7, _mask );                                                  \
    h##8 = wl_and( f##8, _mask );                                                  \
    h##9 = wl_and( f##9, _mask );                                                  \
  } while(0)

/* FE_AVX_INL_DBL_MIX( h, f ) does
     [ha hb hc hd] = [fa-fb-fc fb+fc fc-fc fd-fb+fc].
   In place operation fine. */

#define FE_AVX_INL_DBL_MIX( h, f ) do {                   \
    h##0 = wl_dbl_mix( f##0 ); h##1 = wl_dbl_mix( f##1 ); \
    h##2 = wl_dbl_mix( f##2 ); h##3 = wl_dbl_mix( f##3 ); \
    h##4 = wl_dbl_mix( f##4 ); h##5 = wl_dbl_mix( f##5 ); \
    h##6 = wl_dbl_mix( f##6 ); h##7 = wl_dbl_mix( f##7 ); \
    h##8 = wl_dbl_mix( f##8 ); h##9 = wl_dbl_mix( f##9 ); \
  } while(0)

/* FE_AVX_INL_SUB_MIX( h, f ) does
     [ha hb hc hd] = [fc-fb fc+fb 2*fa-fd 2*fa-fc]
   In place operation fine. */

#define FE_AVX_INL_SUB_MIX( h, f ) do {                   \
    h##0 = wl_sub_mix( f##0 ); h##1 = wl_sub_mix( f##1 ); \
    h##2 = wl_sub_mix( f##2 ); h##3 = wl_sub_mix( f##3 ); \
    h##4 = wl_sub_mix( f##4 ); h##5 = wl_sub_mix( f##5 ); \
    h##6 = wl_sub_mix( f##6 ); h##7 = wl_sub_mix( f##7 ); \
    h##8 = wl_sub_mix( f##8 ); h##9 = wl_sub_mix( f##9 ); \
  } while(0)

/* FE_AVX_INL_SUBADD_12( h, f ) does
     [ha hb hc hd] = [fa fb-fc fb+fc fd]
   In place operation fine. */

#define FE_AVX_INL_SUBADD_12( h, f ) do {                     \
    h##0 = wl_subadd_12( f##0 ); h##1 = wl_subadd_12( f##1 ); \
    h##2 = wl_subadd_12( f##2 ); h##3 = wl_subadd_12( f##3 ); \
    h##4 = wl_subadd_12( f##4 ); h##5 = wl_subadd_12( f##5 ); \
    h##6 = wl_subadd_12( f##6 ); h##7 = wl_subadd_12( f##7 ); \
    h##8 = wl_subadd_12( f##8 ); h##9 = wl_subadd_12( f##9 ); \
  } while(0)

/* FE_AVX_INL_ADDSUB_12( h, f ) does
     [ha hb hc hd] = [fa fb+fc fb-fc fd]
   In place operation fine. */

#define FE_AVX_INL_ADDSUB_12( h, f ) do {                     \
    h##0 = wl_addsub_12( f##0 ); h##1 = wl_addsub_12( f##1 ); \
    h##2 = wl_addsub_12( f##2 ); h##3 = wl_addsub_12( f##3 ); \
    h##4 = wl_addsub_12( f##4 ); h##5 = wl_addsub_12( f##5 ); \
    h##6 = wl_addsub_12( f##6 ); h##7 = wl_addsub_12( f##7 ); \
    h##8 = wl_addsub_12( f##8 ); h##9 = wl_addsub_12( f##9 ); \
  } while(0)
