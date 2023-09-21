#ifndef HEADER_fd_src_util_simd_fd_avx512_h
#error "Do not include this directly; use fd_avx512.h"
#endif

/* Vector long API ****************************************************/

/* A wwl_t is a vector where each adjacent pair of 32-bit wide lanes
   (e.g. 0-1 / 2-3 / 4-5 / 6-7) holds a signed 64-bit twos-complement
   integer (a "long").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

/* TODO: Fill this out more (this is enough to get AVX-512 ED25519
   acceleration going) (SPLATS? EXTRACTS? MASKED ADD/SUB? ETC) */

#define wwl_t __m512i

/* wwl(x0,x1,x2,x3,x4,x5,x6,x7) returns the wwl_t [x0 x1 ... x7] where
   x* are longs */

#define wwl(x0,x1,x2,x3,x4,x5,x6,x7) _mm512_setr_epi64( (x0), (x1), (x2), (x3), (x4), (x5), (x6), (x7) )

/* wwl_permute(p,x) returns:
     wwl( x(p(0)), x(p(1)), ... x(p(i)) ).
   As such p(*) should be longs in [0,7]. */

#define wwl_permute(p,x)     _mm512_permutexvar_epi64( (p), (x) )

/* wwl_select(s,x,y) concatenates the wwl_t's x and y into
     z = [ x0 x1 ... x7 y0 y1 ... y7 ]
   and then returns:
     wwl( z(p(0)), z(p(1)), ... z(p(7)) ).
   As such p(*) should be longs in [0,15]. */

#define wwl_select(p,x,y)    _mm512_permutex2var_epi64( (x), (p), (y) )

#define wwl_bcast(x)         _mm512_set1_epi64( (x) ) /* wwl(x,      x,       ... x      ) */
#define wwl_zero()           _mm512_setzero_si512()   /* wwl(0,      0,       ... 0      ) */
#define wwl_one()            _mm512_set1_epi64( 1L )  /* wwl(1,      1,       ... 1      ) */

/* These assume m is 64-byte aligned */
#define wwl_ld(m)            _mm512_load_epi64( (m) )       /* wwl(m[0],   m[1],    ... m[7]   ) */
#define wwl_st(m,x)          _mm512_store_epi64( (m), (x) ) /* does m[0] = x0, m[1] = x1, ... m[7] = x7  */

/* Arithmetic operations */

#define wwl_neg(x)           _mm512_sub_epi64( _mm512_setzero_si512(), (x) ) /* wwl(-x0, -x1, ...-x7 ), twos complement */
#define wwl_abs(x)           _mm512_abs_epi64( (x) )                         /* wwl(|x0|,|x1|,...|x7|), twos complement */

#define wwl_min(x,y)         _mm512_min_epi64  ( (x), (y) ) /* wwl( min(x0,y0), min(x1,y1), ... min(x7,y7) ) */
#define wwl_max(x,y)         _mm512_max_epi64  ( (x), (y) ) /* wwl( max(x0,y0), max(x1,y1), ... max(x7,y7) ) */
#define wwl_add(x,y)         _mm512_add_epi64  ( (x), (y) ) /* wwl( x0+y0,      x1+y1,      ... x7+y7      ) */
#define wwl_sub(x,y)         _mm512_sub_epi64  ( (x), (y) ) /* wwl( x0-y0,      x1-y1,      ... x7-y7      ) */
#define wwl_mul(x,y)         _mm512_mullo_epi64( (x), (y) ) /* wwl( x0*y0,      x1*y1,      ... x7*y7      ) */
#define wwl_mul_ll(x,y)      _mm512_mul_epi32  ( (x), (y) ) /* wwl( x0l*y0l,    x1l*y1l,    ... x7l*y7l    ) */

/* Binary operations */
/* shifts assumes n and or y* in [0,63] */

#define wwl_not(x)           _mm512_xor_epi64( _mm512_set1_epi64( -1L ), (x) )

#define wwl_shl(x,n)         _mm512_slli_epi64  ( (x), (uint)(n) ) /* wwl( x0<<n,  x1<<n,  ... x7<<n  ) */
#define wwl_shr(x,n)         _mm512_srai_epi64  ( (x), (uint)(n) ) /* wwl( x0>>n,  x1>>n,  ... x7>>n  ) */
#define wwl_shru(x,n)        _mm512_srli_epi64  ( (x), (uint)(n) ) /* wwl( x0>>n,  x1>>n,  ... x7>>n  ) (unsigned right shift) */
#define wwl_shl_vector(x,y)  _mm512_sllv_epi64  ( (x), (y)       ) /* wwl( x0<<y0, x1<<y1, ... x7<<y7 ) */
#define wwl_shr_vector(x,y)  _mm512_srav_epi64  ( (x), (y)       ) /* wwl( x0>>y0, x1>>y1, ... x7>>y7 ) */
#define wwl_shru_vector(x,y) _mm512_srlv_epi64  ( (x), (y)       ) /* wwl( x0>>y0, x1>>y1, ... x7>>y7 ) (unsigned right shift) */
#define wwl_and(x,y)         _mm512_and_epi64   ( (x), (y)       ) /* wwl( x0&y0,  x1&y1,  ... x7&y7  ) */
#define wwl_andnot(x,y)      _mm512_andnot_epi64( (x), (y)       ) /* wwl( ~x0&y0, ~x1&y1, ... ~x7&y7 ) */
#define wwl_or(x,y)          _mm512_or_epi64    ( (x), (y)       ) /* wwl( x0|y0,  x1|y1,  ... x7|y7  ) */
#define wwl_xor(x,y)         _mm512_xor_epi64   ( (x), (y)       ) /* wwl( x0^y0,  x1^y1,  ... x7^y7  ) */

/* TODO: ROTATES, LOGICALS, CONDITIONS, CONVERSIONS, REDUCTIONS */

/* Misc operations */
/* TODO: Many of the below are arguably too specific to the fd_r43x6 use
   case ... consider moving into fd_r43x6 world or making these more
   general. */

/* wwl_blend returns wwl( m0?y0:x0, m1?y1:x1, ... m7?y7:x7 ) where
   mn is the n-th bit of m. */

#define wwl_blend( m, x, y ) _mm512_mask_blend_epi64( (__mmask8)(m), (x), (y) )

/* wwl_pack_halves(x,imm0,y,imm1) packs half of x and half of y into a
   wwl.  imm0/imm1 select which half of x and y to pack.  imm0 / imm1
   should be in [0,1].  That is, this returns:

     [ if( imm0, x(4:7), x(0:3) ) if( imm1, y(4:7), y(0:3) ) ]

   wwl_pack_h0_h1(x,y) does the wwl_pack_halves(x,0,y,1) case faster.
   Hat tip to Philip Taffet for pointing this out. */

#define wwl_pack_halves(x,imm0,y,imm1) _mm512_shuffle_i64x2( (x), (y), 68+10*(imm0)+160*(imm1) )
#define wwl_pack_h0_h1(x,y) _mm512_mask_blend_epi64( (__mmask8)0xF0, (x), (y) )

/* wwl_madd52lo(a,b,c) returns LO64( a + LO52( LO52(b)*LO52(c) )
   wwl_madd52hi(a,b,c) returns LO64( a + HI52( LO52(b)*LO52(c) ) */

#define wwl_madd52lo(a,b,c) _mm512_madd52lo_epu64( (a), (b), (c) )
#define wwl_madd52hi(a,b,c) _mm512_madd52hi_epu64( (a), (b), (c) )

/* wwl_slide(x,y,imm) treats as a x FIFO with the oldest / newest
   element at lane 0 / 7.  Returns the result of dequeing x imm times
   and enqueing the values y0 ... y{imm-1} in that order.  imm should be
   in [0,7].  For example, with imm==5 case, returns:
     [ x5 x6 x7 y0 y1 y2 y3 y4 ]. */

#define wwl_slide(x,y,imm) _mm512_alignr_epi64( (y), (x), (imm) )
