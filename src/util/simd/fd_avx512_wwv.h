#ifndef HEADER_fd_src_util_simd_fd_avx512_h
#error "Do not include this directly; use fd_avx512.h"
#endif

/* TODO: REDUCE, EXTRACT, ADDITIONAL LANE OPS, ... */

/* Vector ulong API ***************************************************/

/* A wwv_t is a vector where each adjacent pair of 32-bit wide lanes
   (e.g. 0-1 / 2-3 / 4-5 / 6-7) holds an unsigned 64-bit integer (a
   "ulong").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wwv_t __m512i

/* Constructors */

/* wwv(x0,x1,x2,x3,x4,x5,x6,x7) returns the wwv_t [x0 x1 ... x7] where
   x* are ulongs */

#define wwv(x0,x1,x2,x3,x4,x5,x6,x7) \
  _mm512_setr_epi64( (long)(x0), (long)(x1), (long)(x2), (long)(x3), (long)(x4), (long)(x5), (long)(x6), (long)(x7) )

#define wwv_bcast(x)         _mm512_set1_epi64( (long)(x) ) /* wwv(x, x, ... x) */

/* wwv_permute(p,x) returns:
     wwv( x(p(0)), x(p(1)), ... x(p(i)) ).
   As such p(*) should be ulongs in [0,7]. */

#define wwv_permute(p,x)     _mm512_permutexvar_epi64( (p), (x) )

/* wwv_select(s,x,y) concatenates the wwv_t's x and y into
     z = [ x0 x1 ... x7 y0 y1 ... y7 ]
   and then returns:
     wwv( z(p(0)), z(p(1)), ... z(p(7)) ).
   As such p(*) should be ulongs in [0,15]. */

#define wwv_select(p,x,y)    _mm512_permutex2var_epi64( (x), (p), (y) )

/* Predefined constants */

#define wwv_zero()           _mm512_setzero_si512()  /* wwv(0, 0, ... 0) */
#define wwv_one()            _mm512_set1_epi64( 1L ) /* wwv(1, 1, ... 1) */

/* Memory operations */
/* Note: wwv_{ld,st} assume m is 64-byte aligned while wwv_{ldu,stu}
   allow m to have arbitrary alignment */

static inline wwv_t wwv_ld( ulong const * m ) { return _mm512_load_epi64( m ); }  /* wwv( m[0], m[1], ... m[7] ) */
static inline void  wwv_st( ulong * m, wwv_t x ) { _mm512_store_epi64( m, x ); }  /* does m[0] = x0, m[1] = x1, ... m[7] = x7 */

static inline wwv_t wwv_ldu( void const * m ) { return _mm512_loadu_epi64( m ); } /* wwv( m[0], m[1], ... m[7]) */
static inline void  wwv_stu( void * m, wwv_t x ) { _mm512_storeu_epi64( m, x ); } /* does m[0] = x0, m[1] = x1, ... m[7] = x7 */

/* Arithmetic operations */

#define wwv_neg(x)           _mm512_sub_epi64( _mm512_setzero_si512(), (x) ) /* wwv( -x0, -x1, ... -x7 ) */
#define wwv_abs(x)           (x)                                             /* wwv(  x0,  x1, ...  x7 ) */

#define wwv_min(x,y)         _mm512_min_epu64  ( (x), (y) ) /* wwv( min(x0,y0), min(x1,y1), ... min(x7,y7) ) */
#define wwv_max(x,y)         _mm512_max_epu64  ( (x), (y) ) /* wwv( max(x0,y0), max(x1,y1), ... max(x7,y7) ) */
#define wwv_add(x,y)         _mm512_add_epi64  ( (x), (y) ) /* wwv( x0+y0,      x1+y1,      ... x7+y7      ) */
#define wwv_sub(x,y)         _mm512_sub_epi64  ( (x), (y) ) /* wwv( x0-y0,      x1-y1,      ... x7-y7      ) */
#define wwv_mul(x,y)         _mm512_mullo_epi64( (x), (y) ) /* wwv( x0*y0,      x1*y1,      ... x7*y7      ) */
#define wwv_mul_ll(x,y)      _mm512_mul_epu32  ( (x), (y) ) /* wwv( x0l*y0l,    x1l*y1l,    ... x7l*y7l    ) */

/* Binary operations */
/* Note: shifts assumes n and or y* in [0,63].  Rotates work for
   arbitrary values */

#define wwv_not(x)           _mm512_xor_epi64( _mm512_set1_epi64( -1L ), (x) )

#define wwv_shl(x,n)         _mm512_slli_epi64  ( (x), (uint)(n) ) /* wwv( x0<<n,  x1<<n,  ... x7<<n  ) */
#define wwv_shr(x,n)         _mm512_srli_epi64  ( (x), (uint)(n) ) /* wwv( x0>>n,  x1>>n,  ... x7>>n  ) */
#define wwv_shl_vector(x,y)  _mm512_sllv_epi64  ( (x), (y)       ) /* wwv( x0<<y0, x1<<y1, ... x7<<y7 ) */
#define wwv_shr_vector(x,y)  _mm512_srlv_epi64  ( (x), (y)       ) /* wwv( x0>>y0, x1>>y1, ... x7>>y7 ) */
#define wwv_and(x,y)         _mm512_and_epi64   ( (x), (y)       ) /* wwv( x0&y0,  x1&y1,  ... x7&y7  ) */
#define wwv_andnot(x,y)      _mm512_andnot_epi64( (x), (y)       ) /* wwv( ~x0&y0, ~x1&y1, ... ~x7&y7 ) */
#define wwv_or(x,y)          _mm512_or_epi64    ( (x), (y)       ) /* wwv( x0|y0,  x1|y1,  ... x7|y7  ) */
#define wwv_xor(x,y)         _mm512_xor_epi64   ( (x), (y)       ) /* wwv( x0^y0,  x1^y1,  ... x7^y7  ) */

/* wwv_rol(x,n)          returns wwv( rotate_left (x0,n ), rotate_left (x1,n ), ... )
   wwv_ror(x,n)          returns wwv( rotate_right(x0,n ), rotate_right(x1,n ), ... )
   wwv_rol_variable(x,n) returns wwv( rotate_left (x0,n ), rotate_left (x1,n ), ... )
   wwv_ror_variable(x,n) returns wwv( rotate_right(x0,n ), rotate_right(x1,n ), ... )
   wwv_rol_vector(x,y)   returns wwv( rotate_left (x0,y0), rotate_left (x1,y1), ... )
   wwv_ror_vector(x,y)   returns wwv( rotate_right(x0,y0), rotate_right(x1,y1), ... )

   The variable variants are slower but do not require the shift amount
   to be known at compile time. */

#define wwv_rol(a,imm)  _mm512_rol_epi64( (a), (imm)&63 )
#define wwv_ror(a,imm)  _mm512_ror_epi64( (a), (imm)&63 )

static inline wwv_t wwv_rol_variable( wwv_t a, ulong n ) { return wwv_or( wwv_shl( a, n & 63UL ), wwv_shr( a, (-n) & 63UL ) ); }
static inline wwv_t wwv_ror_variable( wwv_t a, ulong n ) { return wwv_or( wwv_shr( a, n & 63UL ), wwv_shl( a, (-n) & 63UL ) ); }

static inline wwv_t wwv_rol_vector( wwv_t a, wwv_t b ) {
  wwv_t m = wwv_bcast( 63UL );
  return wwv_or( wwv_shl_vector( a, wwv_and( b, m ) ), wwv_shr_vector( a, wwv_and( wwv_neg( b ), m ) ) );
}

static inline wwv_t wwv_ror_vector( wwv_t a, wwv_t b ) {
  wwv_t m = wwv_bcast( 63UL );
  return wwv_or( wwv_shr_vector( a, wwv_and( b, m ) ), wwv_shl_vector( a, wwv_and( wwv_neg( b ), m ) ) );
}

/* wwv_bswap(x) returns wwv( bswap(x0), bswap(x1), ... ) */

#define wwv_bswap( x ) _mm512_shuffle_epi8( (x), _mm512_set_epi8(  8, 9,10,11,12,13,14,15, 0, 1, 2, 3, 4, 5, 6, 7, \
                                                                   8, 9,10,11,12,13,14,15, 0, 1, 2, 3, 4, 5, 6, 7, \
                                                                   8, 9,10,11,12,13,14,15, 0, 1, 2, 3, 4, 5, 6, 7, \
                                                                   8, 9,10,11,12,13,14,15, 0, 1, 2, 3, 4, 5, 6, 7 ) )

/* Comparison operations */
/* mask(c0,c1,...) means (((int)c0)<<0) | (((int)c1)<<1) | ... */

#define wwv_eq(x,y) ((int)_mm512_cmpeq_epu64_mask(  (x), (y) )) /* mask( x0==y0, x1==y1, ... ) */
#define wwv_gt(x,y) ((int)_mm512_cmpgt_epu64_mask(  (x), (y) )) /* mask( x0> y0, x1> y1, ... ) */
#define wwv_lt(x,y) ((int)_mm512_cmplt_epu64_mask(  (x), (y) )) /* mask( x0< y0, x1< y1, ... ) */
#define wwv_ne(x,y) ((int)_mm512_cmpneq_epu64_mask( (x), (y) )) /* mask( x0!=y0, x1!=y1, ... ) */
#define wwv_ge(x,y) ((int)_mm512_cmpge_epu64_mask(  (x), (y) )) /* mask( x0>=y0, x1>=y1, ... ) */
#define wwv_le(x,y) ((int)_mm512_cmple_epu64_mask(  (x), (y) )) /* mask( x0<=y0, x1<=y1, ... ) */

#define wwv_lnot(x)    wwv_eq( (x), wwv_zero() )                /* mask(  !x0,  !x1, ... ) */
#define wwv_lnotnot(x) wwv_ne( (x), wwv_zero() )                /* mask( !!x0, !!x1, ... ) */

/* Conditional operations */
/* cn means bit n of c */

#define wwv_if(c,x,y)       _mm512_mask_blend_epi64( (__mmask8)(c), (y), (x) )    /* wwv( c0? x0    :y0, ... ) */
#define wwv_add_if(c,x,y,z) _mm512_mask_add_epi64( (z), (__mmask8)(c), (x), (y) ) /* wwv( c0?(x0+y0):z0, ... ) */
#define wwv_sub_if(c,x,y,z) _mm512_mask_sub_epi64( (z), (__mmask8)(c), (x), (y) ) /* wwv( c0?(x0-y0):z0, ... ) */

/* Conversions */

/* wwv_to_wwi(x) returns [  (int)x0,0,  (int)x1,0, ...  (int)x7,0 ]
   wwv_to_wwu(x) returns [ (uint)x0,0, (uint)x1,0, ... (uint)x7,0 ]
   wwv_to_wwv(x) returns [ (ulong)x0,  (ulong)x1,  ... (ulong)x7  ] */

#define wwv_to_wwi(x) wwv_and( (x), wwv_bcast( (ulong)UINT_MAX ) )
#define wwv_to_wwu(x) wwv_and( (x), wwv_bcast( (ulong)UINT_MAX ) )
#define wwv_to_wwl(x) (x)

#define wwv_to_wwi_raw(x) (x)
#define wwv_to_wwu_raw(x) (x)
#define wwv_to_wwl_raw(x) (x)

/* Misc operations */

/* wwv_pack_halves(x,imm0,y,imm1) packs half of x and half of y into a
   wwv.  imm0/imm1 select which half of x and y to pack.  imm0 / imm1
   should be in [0,1].  That is, this returns:

     [ if( imm0, x(4:7), x(0:3) ) if( imm1, y(4:7), y(0:3) ) ]

   wwv_pack_h0_h1(x,y) does the wwv_pack_halves(x,0,y,1) case faster.
   Hat tip to Philip Taffet for pointing this out. */

#define wwv_pack_halves(x,imm0,y,imm1) _mm512_shuffle_i64x2( (x), (y), 68+10*(imm0)+160*(imm1) )
#define wwv_pack_h0_h1(x,y)            _mm512_mask_blend_epi64( (__mmask8)0xF0, (x), (y) )

/* wwv_madd52lo(a,b,c) returns LO64( a + LO52( LO52(b)*LO52(c) )
   wwv_madd52hi(a,b,c) returns LO64( a + HI52( LO52(b)*LO52(c) ) */

#define wwv_madd52lo(a,b,c) _mm512_madd52lo_epu64( (a), (b), (c) )
#define wwv_madd52hi(a,b,c) _mm512_madd52hi_epu64( (a), (b), (c) )

/* wwv_slide(x,y,imm) treats as a x FIFO with the oldest / newest
   element at lane 0 / 7.  Returns the result of dequeing x imm times
   and enqueing the values y0 ... y{imm-1} in that order.  imm should be
   in [0,7].  For example, with imm==5 case, returns:
     [ x5 x6 x7 y0 y1 y2 y3 y4 ]. */

#define wwv_slide(x,y,imm) _mm512_alignr_epi64( (y), (x), (imm) )

/* wwv_unpack unpacks the wwv x into its ulong components x0,x1,...x7. */

#define wwv_unpack( x, x0,x1,x2,x3,x4,x5,x6,x7 ) do {                       \
    __m512i _wwv_unpack_x  = (x);                                           \
    __m256i _wwv_unpack_xl = _mm512_extracti64x4_epi64( _wwv_unpack_x, 0 ); \
    __m256i _wwv_unpack_xh = _mm512_extracti64x4_epi64( _wwv_unpack_x, 1 ); \
    (x0) = (ulong)_mm256_extract_epi64( _wwv_unpack_xl, 0 );                \
    (x1) = (ulong)_mm256_extract_epi64( _wwv_unpack_xl, 1 );                \
    (x2) = (ulong)_mm256_extract_epi64( _wwv_unpack_xl, 2 );                \
    (x3) = (ulong)_mm256_extract_epi64( _wwv_unpack_xl, 3 );                \
    (x4) = (ulong)_mm256_extract_epi64( _wwv_unpack_xh, 0 );                \
    (x5) = (ulong)_mm256_extract_epi64( _wwv_unpack_xh, 1 );                \
    (x6) = (ulong)_mm256_extract_epi64( _wwv_unpack_xh, 2 );                \
    (x7) = (ulong)_mm256_extract_epi64( _wwv_unpack_xh, 3 );                \
  } while(0)

/* wwv_transpose_8x8 sets wwv_t's c0,c1,...c7 to the columns of an 8x8
   ulong matrix given the rows of the matrix in wwv_t's r0,r1,...r7.
   In-place operation fine. */

#define wwv_transpose_8x8( r0,r1,r2,r3,r4,r5,r6,r7, c0,c1,c2,c3,c4,c5,c6,c7 ) do {                \
    wwv_t _wwv_transpose_r0 = (r0); wwv_t _wwv_transpose_r1 = (r1);                               \
    wwv_t _wwv_transpose_r2 = (r2); wwv_t _wwv_transpose_r3 = (r3);                               \
    wwv_t _wwv_transpose_r4 = (r4); wwv_t _wwv_transpose_r5 = (r5);                               \
    wwv_t _wwv_transpose_r6 = (r6); wwv_t _wwv_transpose_r7 = (r7);                               \
                                                                                                  \
    /* Outer 4x4 transpose of 2x2 blocks */                                                       \
    wwv_t _wwv_transpose_t0 = _mm512_shuffle_i64x2( _wwv_transpose_r0, _wwv_transpose_r2, 0x88 ); \
    wwv_t _wwv_transpose_t1 = _mm512_shuffle_i64x2( _wwv_transpose_r1, _wwv_transpose_r3, 0x88 ); \
    wwv_t _wwv_transpose_t2 = _mm512_shuffle_i64x2( _wwv_transpose_r0, _wwv_transpose_r2, 0xdd ); \
    wwv_t _wwv_transpose_t3 = _mm512_shuffle_i64x2( _wwv_transpose_r1, _wwv_transpose_r3, 0xdd ); \
    wwv_t _wwv_transpose_t4 = _mm512_shuffle_i64x2( _wwv_transpose_r4, _wwv_transpose_r6, 0x88 ); \
    wwv_t _wwv_transpose_t5 = _mm512_shuffle_i64x2( _wwv_transpose_r5, _wwv_transpose_r7, 0x88 ); \
    wwv_t _wwv_transpose_t6 = _mm512_shuffle_i64x2( _wwv_transpose_r4, _wwv_transpose_r6, 0xdd ); \
    wwv_t _wwv_transpose_t7 = _mm512_shuffle_i64x2( _wwv_transpose_r5, _wwv_transpose_r7, 0xdd ); \
                                                                                                  \
    /**/  _wwv_transpose_r0 = _mm512_shuffle_i64x2( _wwv_transpose_t0, _wwv_transpose_t4, 0x88 ); \
    /**/  _wwv_transpose_r1 = _mm512_shuffle_i64x2( _wwv_transpose_t1, _wwv_transpose_t5, 0x88 ); \
    /**/  _wwv_transpose_r2 = _mm512_shuffle_i64x2( _wwv_transpose_t2, _wwv_transpose_t6, 0x88 ); \
    /**/  _wwv_transpose_r3 = _mm512_shuffle_i64x2( _wwv_transpose_t3, _wwv_transpose_t7, 0x88 ); \
    /**/  _wwv_transpose_r4 = _mm512_shuffle_i64x2( _wwv_transpose_t0, _wwv_transpose_t4, 0xdd ); \
    /**/  _wwv_transpose_r5 = _mm512_shuffle_i64x2( _wwv_transpose_t1, _wwv_transpose_t5, 0xdd ); \
    /**/  _wwv_transpose_r6 = _mm512_shuffle_i64x2( _wwv_transpose_t2, _wwv_transpose_t6, 0xdd ); \
    /**/  _wwv_transpose_r7 = _mm512_shuffle_i64x2( _wwv_transpose_t3, _wwv_transpose_t7, 0xdd ); \
                                                                                                  \
    /* Inner 2x2 transpose of 1x1 blocks */                                                       \
    /**/  (c0)              = _mm512_unpacklo_epi64( _wwv_transpose_r0, _wwv_transpose_r1 );      \
    /**/  (c1)              = _mm512_unpackhi_epi64( _wwv_transpose_r0, _wwv_transpose_r1 );      \
    /**/  (c2)              = _mm512_unpacklo_epi64( _wwv_transpose_r2, _wwv_transpose_r3 );      \
    /**/  (c3)              = _mm512_unpackhi_epi64( _wwv_transpose_r2, _wwv_transpose_r3 );      \
    /**/  (c4)              = _mm512_unpacklo_epi64( _wwv_transpose_r4, _wwv_transpose_r5 );      \
    /**/  (c5)              = _mm512_unpackhi_epi64( _wwv_transpose_r4, _wwv_transpose_r5 );      \
    /**/  (c6)              = _mm512_unpacklo_epi64( _wwv_transpose_r6, _wwv_transpose_r7 );      \
    /**/  (c7)              = _mm512_unpackhi_epi64( _wwv_transpose_r6, _wwv_transpose_r7 );      \
  } while(0)
