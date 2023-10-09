#ifndef HEADER_fd_src_util_simd_fd_avx512_h
#error "Do not include this directly; use fd_avx512.h"
#endif

/* TODO: REDUCE, EXTRACT, ADDITIONAL LANE OPS, ... */

/* Vector long API ****************************************************/

/* A wwl_t is a vector where each adjacent pair of 32-bit wide lanes
   (e.g. 0-1 / 2-3 / 4-5 / 6-7) holds a signed 64-bit twos-complement
   integer (a "long").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wwl_t __m512i

/* wwl(x0,x1,x2,x3,x4,x5,x6,x7) returns the wwl_t [x0 x1 ... x7] where
   x* are longs */

#define wwl(x0,x1,x2,x3,x4,x5,x6,x7) _mm512_setr_epi64( (x0), (x1), (x2), (x3), (x4), (x5), (x6), (x7) )

#define wwl_bcast(x)         _mm512_set1_epi64( (x) ) /* wwl(x, x, ... x) */

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

/* Predefined constants */

#define wwl_zero()           _mm512_setzero_si512()  /* wwl(0, 0, ... 0) */
#define wwl_one()            _mm512_set1_epi64( 1L ) /* wwl(1, 1, ... 1) */

/* Memory operations */
/* Note: wwl_{ld,st} assume m is 64-byte aligned while wwl_{ldu,stu}
   allow m to have arbitrary alignment */

static inline wwl_t wwl_ld( long const * m ) { return _mm512_load_epi64( m ); }  /* wwl( m[0], m[1], ... m[7] ) */
static inline void  wwl_st( long * m, wwl_t x ) { _mm512_store_epi64( m, x ); }  /* does m[0] = x0, m[1] = x1, ... m[7] = x7 */

static inline wwl_t wwl_ldu( void const * m ) { return _mm512_loadu_epi64( m ); } /* wwl( m[0], m[1], ... m[7]) */
static inline void  wwl_stu( void * m, wwl_t x ) { _mm512_storeu_epi64( m, x ); } /* does m[0] = x0, m[1] = x1, ... m[7] = x7 */

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
/* Note: shifts assumes n and or y* in [0,63].  Rotates work for
   arbitrary values. */

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

/* wwl_rol(x,n)        returns wwl( rotate_left (x0,n ), rotate_left (x1,n ), ... )
   wwl_ror(x,n)        returns wwl( rotate_right(x0,n ), rotate_right(x1,n ), ... )
   wwl_rol_vector(x,y) returns wwl( rotate_left (x0,y0), rotate_left (x1,y1), ... )
   wwl_ror_vector(x,y) returns wwl( rotate_right(x0,y0), rotate_right(x1,y1), ... ) */

static inline wwl_t wwl_rol( wwl_t a, long n ) { return wwl_or( wwl_shl ( a, n & 63L ), wwl_shru( a, (-n) & 63L ) ); }
static inline wwl_t wwl_ror( wwl_t a, long n ) { return wwl_or( wwl_shru( a, n & 63L ), wwl_shl ( a, (-n) & 63L ) ); }

static inline wwl_t wwl_rol_vector( wwl_t a, wwl_t b ) {
  wwl_t m = wwl_bcast( 63L );
  return wwl_or( wwl_shl_vector ( a, wwl_and( b, m ) ), wwl_shru_vector( a, wwl_and( wwl_neg( b ), m ) ) );
}

static inline wwl_t wwl_ror_vector( wwl_t a, wwl_t b ) {
  wwl_t m = wwl_bcast( 63L );
  return wwl_or( wwl_shru_vector( a, wwl_and( b, m ) ), wwl_shl_vector ( a, wwl_and( wwl_neg( b ), m ) ) );
}

/* Comparison operations */
/* mask(c0,c1,...) means (((int)c0)<<0) | (((int)c1)<<1) | ... */

#define wwl_eq(x,y) ((int)_mm512_cmpeq_epi64_mask(  (x), (y) )) /* mask( x0==y0, x1==y1, ... ) */
#define wwl_gt(x,y) ((int)_mm512_cmpgt_epi64_mask(  (x), (y) )) /* mask( x0> y0, x1> y1, ... ) */
#define wwl_lt(x,y) ((int)_mm512_cmplt_epi64_mask(  (x), (y) )) /* mask( x0< y0, x1< y1, ... ) */
#define wwl_ne(x,y) ((int)_mm512_cmpneq_epi64_mask( (x), (y) )) /* mask( x0!=y0, x1!=y1, ... ) */
#define wwl_ge(x,y) ((int)_mm512_cmpge_epi64_mask(  (x), (y) )) /* mask( x0>=y0, x1>=y1, ... ) */
#define wwl_le(x,y) ((int)_mm512_cmple_epi64_mask(  (x), (y) )) /* mask( x0<=y0, x1<=y1, ... ) */

#define wwl_lnot(x)    wwl_eq( (x), wwl_zero() )                /* mask(  !x0,  !x1, ... ) */
#define wwl_lnotnot(x) wwl_ne( (x), wwl_zero() )                /* mask( !!x0, !!x1, ... ) */

/* Conditional operations */
/* cn means bit n of c */

#define wwl_if(c,x,y)       _mm512_mask_blend_epi64( (__mmask8)(c), (y), (x) )    /* wwl( c0? x0    :y0, ... ) */
#define wwl_add_if(c,x,y,z) _mm512_mask_add_epi64( (z), (__mmask8)(c), (x), (y) ) /* wwl( c0?(x0+y0):z0, ... ) */
#define wwl_sub_if(c,x,y,z) _mm512_mask_sub_epi64( (z), (__mmask8)(c), (x), (y) ) /* wwl( c0?(x0-y0):z0, ... ) */

/* Conversions */

#define wwl_to_wwv(x)     (x) /* wwv( (ulong)x0, (ulong)x1, ... (ulong)x7 ) */
#define wwl_to_wwv_raw(x) (x) /* reinterp raw bits as a wwv */

#define wwl_blend(m,x,y) wwl_if((m),(y),(x)) /* TODO: DEPRECATE */

/* Misc operations */

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

/* wwl_transpose_8x8 sets wwl_t's c0,c1,...c7 to the columns of an 8x8
   ulong matrix given the rows of the matrix in wwl_t's r0,r1,...r7.
   In-place operation fine. */

#define wwl_transpose_8x8( r0,r1,r2,r3,r4,r5,r6,r7, c0,c1,c2,c3,c4,c5,c6,c7 ) do {            \
    wwl_t _r0 = (r0);                            wwl_t _r1 = (r1);                            \
    wwl_t _r2 = (r2);                            wwl_t _r3 = (r3);                            \
    wwl_t _r4 = (r4);                            wwl_t _r5 = (r5);                            \
    wwl_t _r6 = (r6);                            wwl_t _r7 = (r7);                            \
                                                                                              \
    /* Transpose 4x4 blocks */                                                                \
    wwl_t _t0 = wwl_pack_halves( _r0,0, _r4,0 ); wwl_t _t4 = wwl_pack_halves( _r0,1, _r4,1 ); \
    wwl_t _t1 = wwl_pack_halves( _r1,0, _r5,0 ); wwl_t _t5 = wwl_pack_halves( _r1,1, _r5,1 ); \
    wwl_t _t2 = wwl_pack_halves( _r2,0, _r6,0 ); wwl_t _t6 = wwl_pack_halves( _r2,1, _r6,1 ); \
    wwl_t _t3 = wwl_pack_halves( _r3,0, _r7,0 ); wwl_t _t7 = wwl_pack_halves( _r3,1, _r7,1 ); \
                                                                                              \
    /* Transpose 2x2 blocks */                                                                \
    wwl_t const _pa = wwl(0L,1L, 8L, 9L,4L,5L,12L,13L);                                       \
    wwl_t const _pb = wwl(2L,3L,10L,11L,6L,7L,14L,15L);                                       \
    _r0 = wwl_select( _pa, _t0, _t2 );           _r2 = wwl_select( _pb, _t0, _t2 );           \
    _r1 = wwl_select( _pa, _t1, _t3 );           _r3 = wwl_select( _pb, _t1, _t3 );           \
    _r4 = wwl_select( _pa, _t4, _t6 );           _r6 = wwl_select( _pb, _t4, _t6 );           \
    _r5 = wwl_select( _pa, _t5, _t7 );           _r7 = wwl_select( _pb, _t5, _t7 );           \
                                                                                              \
    /* Transpose 1x1 blocks */                                                                \
    (c0) = _mm512_unpacklo_epi64( _r0, _r1 );    (c1) = _mm512_unpackhi_epi64( _r0, _r1 );    \
    (c2) = _mm512_unpacklo_epi64( _r2, _r3 );    (c3) = _mm512_unpackhi_epi64( _r2, _r3 );    \
    (c4) = _mm512_unpacklo_epi64( _r4, _r5 );    (c5) = _mm512_unpackhi_epi64( _r4, _r5 );    \
    (c6) = _mm512_unpacklo_epi64( _r6, _r7 );    (c7) = _mm512_unpackhi_epi64( _r6, _r7 );    \
  } while(0)
