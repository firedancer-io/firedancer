#ifndef HEADER_fd_src_util_simd_fd_avx512_h
#error "Do not include this directly; use fd_avx512.h"
#endif

/* TODO: REDUCE, EXTRACT, ADDITIONAL LANE OPS, ... */

/* Vector int API ****************************************************/

/* A wwi_t is a vector where each 32-bit wide lane holds an signed twos
   complement 32-bit integer (an "int").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wwi_t __m512i

/* Constructors */

/* wwi(x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf)
   returns the wwi_t [x0 x1 ... xf] where x* are ints */

#define wwi(x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf) \
  _mm512_setr_epi32( (x0), (x1), (x2), (x3), (x4), (x5), (x6), (x7), (x8), (x9), (xa), (xb), (xc), (xd), (xe), (xf) )

#define wwi_bcast(x)         _mm512_set1_epi32( (x) ) /* wwi(x, x, ... x) */

/* wwi_permute(p,x) returns:
     wwi( x(p(0)), x(p(1)), ... x(p(15)) ).
   As such p(*) should be ints in [0,15]. */

#define wwi_permute(p,x)     _mm512_permutexvar_epi32( (p), (x) )

/* wwi_select(s,x,y) concatenates the wwi_t's x and y into
     z = [ x0 x1 ... xf y0 y1 ... yf ]
   and then returns:
     wwi( z(p(0)), z(p(1)), ... z(p(15)) ).
   As such p(*) should be ints in [0,31]. */

#define wwi_select(p,x,y)    _mm512_permutex2var_epi32( (x), (p), (y) )

/* Predefined constants */

#define wwi_zero()           _mm512_setzero_si512()  /* wwi(0, 0, ... 0) */
#define wwi_one()            _mm512_set1_epi32( 1 )  /* wwi(1, 1, ... 1) */

/* Memory operations */
/* Note: wwi_{ld,st} assume m is 64-byte aligned while wwi_{ldu,stu}
   allow m to have arbitrary alignment */

static inline wwi_t wwi_ld( int const * m ) { return _mm512_load_epi32( m ); }  /* wwi( m[0], m[1], ... m[15] ) */
static inline void  wwi_st( int * m, wwi_t x ) { _mm512_store_epi32( m, x ); }  /* does m[0] = x0, m[1] = x1, ... m[15] = xf */

static inline wwi_t wwi_ldu( void const * m ) { return _mm512_loadu_epi32( m ); } /* wwi( m[0], m[1], ... m[15]) */
static inline void  wwi_stu( void * m, wwi_t x ) { _mm512_storeu_epi32( m, x ); } /* does m[0] = x0, m[1] = x1, ... m[15] = xf */

/* Arithmetic operations */

#define wwi_neg(x)           _mm512_sub_epi32( _mm512_setzero_si512(), (x) ) /* wwi( -x0,  -x1,  ... -xf  ) */
#define wwi_abs(x)           _mm512_abs_epi32( (x) )                         /* wwi( |x0|, |x1|, ... |xf| ) */

#define wwi_min(x,y)         _mm512_min_epi32  ( (x), (y) ) /* wwi( min(x0,y0), min(x1,y1), ... min(xf,yf) ) */
#define wwi_max(x,y)         _mm512_max_epi32  ( (x), (y) ) /* wwi( max(x0,y0), max(x1,y1), ... max(xf,yf) ) */
#define wwi_add(x,y)         _mm512_add_epi32  ( (x), (y) ) /* wwi( x0+y0,      x1+y1,      ... xf+yf      ) */
#define wwi_sub(x,y)         _mm512_sub_epi32  ( (x), (y) ) /* wwi( x0-y0,      x1-y1,      ... xf-yf      ) */
#define wwi_mul(x,y)         _mm512_mullo_epi32( (x), (y) ) /* wwi( x0*y0,      x1*y1,      ... xf*yf      ) */

/* Binary operations */
/* Note: shifts assumes n and or y* in [0,31].  Rotates work for
   arbitrary values */

#define wwi_not(x)           _mm512_xor_epi32( _mm512_set1_epi32( -1 ), (x) )

#define wwi_shl(x,n)         _mm512_slli_epi32  ( (x), (uint)(n) ) /* wwi( x0<<n,  x1<<n,  ... xf<<n  ) */
#define wwi_shr(x,n)         _mm512_srai_epi32  ( (x), (uint)(n) ) /* wwi( x0>>n,  x1>>n,  ... xf>>n  ) */
#define wwi_shru(x,n)        _mm512_srli_epi32  ( (x), (uint)(n) ) /* wwi( x0>>n,  x1>>n,  ... xf>>n  ) (unsigned right shift) */
#define wwi_shl_vector(x,y)  _mm512_sllv_epi32  ( (x), (y) )       /* wwi( x0<<y0, x1<<y1, ... xf<<yf ) */
#define wwi_shr_vector(x,y)  _mm512_srav_epi32  ( (x), (y) )       /* wwi( x0>>y0, x1>>y1, ... xf>>yf ) */
#define wwi_shru_vector(x,y) _mm512_srlv_epi32  ( (x), (y) )       /* wwi( x0>>y0, x1>>y1, ... xf>>yf ) (unsigned right shift) */
#define wwi_and(x,y)         _mm512_and_epi32   ( (x), (y) )       /* wwi( x0&y0,  x1&y1,  ... xf&yf  ) */
#define wwi_andnot(x,y)      _mm512_andnot_epi32( (x), (y) )       /* wwi( ~x0&y0, ~x1&y1, ... ~xf&yf ) */
#define wwi_or(x,y)          _mm512_or_epi32    ( (x), (y) )       /* wwi( x0|y0,  x1|y1,  ... xf|yf  ) */
#define wwi_xor(x,y)         _mm512_xor_epi32   ( (x), (y) )       /* wwi( x0^y0,  x1^y1,  ... xf^yf  ) */

/* wwi_rol(x,n)          returns wwi( rotate_left (x0,n ), rotate_left (x1,n ), ... )
   wwi_ror(x,n)          returns wwi( rotate_right(x0,n ), rotate_right(x1,n ), ... )
   wwi_rol_variable(x,n) returns wwi( rotate_left (x0,n ), rotate_left (x1,n ), ... )
   wwi_ror_variable(x,n) returns wwi( rotate_right(x0,n ), rotate_right(x1,n ), ... )
   wwi_rol_vector(x,y)   returns wwi( rotate_left (x0,y0), rotate_left (x1,y1), ... )
   wwi_ror_vector(x,y)   returns wwi( rotate_right(x0,y0), rotate_right(x1,y1), ... )

   The variable variants are slower but do not require the shift amount
   to be known at compile time. */

#define wwi_rol(a,imm)       _mm512_rol_epi32( (a), (imm)&31 )
#define wwi_ror(a,imm)       _mm512_ror_epi32( (a), (imm)&31 )

static inline wwi_t wwi_rol_variable( wwi_t a, int n ) { return wwi_or( wwi_shl ( a, n & 31 ), wwi_shru( a, (-n) & 31 ) ); }
static inline wwi_t wwi_ror_variable( wwi_t a, int n ) { return wwi_or( wwi_shru( a, n & 31 ), wwi_shl ( a, (-n) & 31 ) ); }


static inline wwi_t wwi_rol_vector( wwi_t a, wwi_t b ) {
  wwi_t m = wwi_bcast( 31 );
  return wwi_or( wwi_shl_vector ( a, wwi_and( b, m ) ), wwi_shru_vector( a, wwi_and( wwi_neg( b ), m ) ) );
}

static inline wwi_t wwi_ror_vector( wwi_t a, wwi_t b ) {
  wwi_t m = wwi_bcast( 31 );
  return wwi_or( wwi_shru_vector( a, wwi_and( b, m ) ), wwi_shl_vector ( a, wwi_and( wwi_neg( b ), m ) ) );
}

/* Comparison operations */
/* mask(c0,c1,...) means (((int)c0)<<0) | (((int)c1)<<1) | ... */

#define wwi_eq(x,y) ((int)_mm512_cmpeq_epi32_mask(  (x), (y) )) /* mask( x0==y0, x1==y1, ... ) */
#define wwi_gt(x,y) ((int)_mm512_cmpgt_epi32_mask(  (x), (y) )) /* mask( x0> y0, x1> y1, ... ) */
#define wwi_lt(x,y) ((int)_mm512_cmplt_epi32_mask(  (x), (y) )) /* mask( x0< y0, x1< y1, ... ) */
#define wwi_ne(x,y) ((int)_mm512_cmpneq_epi32_mask( (x), (y) )) /* mask( x0!=y0, x1!=y1, ... ) */
#define wwi_ge(x,y) ((int)_mm512_cmpge_epi32_mask(  (x), (y) )) /* mask( x0>=y0, x1>=y1, ... ) */
#define wwi_le(x,y) ((int)_mm512_cmple_epi32_mask(  (x), (y) )) /* mask( x0<=y0, x1<=y1, ... ) */

#define wwi_lnot(x)    wwi_eq( (x), wwi_zero() )                /* mask(  !x0,  !x1, ... ) */
#define wwi_lnotnot(x) wwi_ne( (x), wwi_zero() )                /* mask( !!x0, !!x1, ... ) */

/* Conditional operations */
/* cn means bit n of c */

#define wwi_if(c,x,y)       _mm512_mask_blend_epi32( (__mmask16)(c), (y), (x) )    /* wwi( c0? x0    :y0, ... ) */
#define wwi_add_if(c,x,y,z) _mm512_mask_add_epi32( (z), (__mmask16)(c), (x), (y) ) /* wwi( c0?(x0+y0):z0, ... ) */
#define wwi_sub_if(c,x,y,z) _mm512_mask_sub_epi32( (z), (__mmask16)(c), (x), (y) ) /* wwi( c0?(x0-y0):z0, ... ) */

/* Conversions */

/* wwi_to_wwu( x )    returns wwi(  (uint)x0,  (uint)x1, ...  (uint)x15 )

   wwi_to_wwl( x, 0 ) returns wwl(  (long)x0,  (long)x2, ...  (long)x14 )
   wwi_to_wwl( x, 1 ) returns wwl(  (long)x1,  (long)x3, ...  (long)x15 )

   wwi_to_wwv( x, 0 ) returns wwv( (ulong)x0, (ulong)x2, ... (ulong)x14 )
   wwi_to_wwv( x, 1 ) returns wwv( (ulong)x1, (ulong)x3, ... (ulong)x15 )

   TODO: consider _mm512_cvtepi32_* intrinsics? */

#define wwi_to_wwu( x ) (x)
#define wwi_to_wwl( x, odd ) /* trinary should be compile time */ \
  (__extension__({ wwl_t _wwi_to_wwl_tmp = (x); wwl_shr( (odd) ? _wwi_to_wwl_tmp : wwl_shl( _wwi_to_wwl_tmp, 32 ), 32 ); }))
#define wwi_to_wwv( x, odd ) /* trinary should be compile time (yes, wwl_shr) */ \
  (__extension__({ wwv_t _wwi_to_wwv_tmp = (x); wwl_shr( (odd) ? _wwi_to_wwv_tmp : wwv_shl( _wwi_to_wwv_tmp, 32 ), 32 ); }))

#define wwi_to_wwu_raw(x) (x)
#define wwi_to_wwl_raw(x) (x)
#define wwi_to_wwv_raw(x) (x)

/* Misc operations */

/* wwi_pack_halves(x,imm0,y,imm1) packs half of x and half of y into a
   wwi.  imm0/imm1 select which half of x and y to pack.  imm0 / imm1
   should be in [0,1].  That is, this returns:

     [ if( imm0, x(8:15), x(0:7) ) if( imm1, y(8:15), y(0:7) ) ]

   wwi_pack_h0_h1(x,y) does the wwi_pack_halves(x,0,y,1) case faster.
   Hat tip to Philip Taffet for pointing this out. */

#define wwi_pack_halves(x,imm0,y,imm1) _mm512_shuffle_i32x4( (x), (y), 68+10*(imm0)+160*(imm1) )
#define wwi_pack_h0_h1(x,y)            _mm512_mask_blend_epi32( (__mmask16)0xFF00, (x), (y) )

/* wwi_slide(x,y,imm) treats as a x FIFO with the oldest / newest
   element at lane 0 / 15.  Returns the result of dequeing x imm times
   and enqueing the values y0 ... y{imm-1} in that order.  imm should be
   in [0,15].  For example, with imm==5 case, returns:
     [ x5 x6 ... xf y0 y1 y2 y3 y4 ]. */

#define wwi_slide(x,y,imm) _mm512_alignr_epi32( (y), (x), (imm) )

/* wwv_unpack unpacks the wwv x into its int components x0,x1,...xf. */

#define wwi_unpack( x, x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf ) do { \
    __m512i _wwi_unpack_x  = (x);                                             \
    __m256i _wwi_unpack_xl = _mm512_extracti32x8_epi32( _wwi_unpack_x, 0 );   \
    __m256i _wwi_unpack_xh = _mm512_extracti32x8_epi32( _wwi_unpack_x, 1 );   \
    (x0) = _mm256_extract_epi32( _wwi_unpack_xl, 0 );                         \
    (x1) = _mm256_extract_epi32( _wwi_unpack_xl, 1 );                         \
    (x2) = _mm256_extract_epi32( _wwi_unpack_xl, 2 );                         \
    (x3) = _mm256_extract_epi32( _wwi_unpack_xl, 3 );                         \
    (x4) = _mm256_extract_epi32( _wwi_unpack_xl, 4 );                         \
    (x5) = _mm256_extract_epi32( _wwi_unpack_xl, 5 );                         \
    (x6) = _mm256_extract_epi32( _wwi_unpack_xl, 6 );                         \
    (x7) = _mm256_extract_epi32( _wwi_unpack_xl, 7 );                         \
    (x8) = _mm256_extract_epi32( _wwi_unpack_xh, 0 );                         \
    (x9) = _mm256_extract_epi32( _wwi_unpack_xh, 1 );                         \
    (xa) = _mm256_extract_epi32( _wwi_unpack_xh, 2 );                         \
    (xb) = _mm256_extract_epi32( _wwi_unpack_xh, 3 );                         \
    (xc) = _mm256_extract_epi32( _wwi_unpack_xh, 4 );                         \
    (xd) = _mm256_extract_epi32( _wwi_unpack_xh, 5 );                         \
    (xe) = _mm256_extract_epi32( _wwi_unpack_xh, 6 );                         \
    (xf) = _mm256_extract_epi32( _wwi_unpack_xh, 7 );                         \
  } while(0)

/* wwi_transpose_16x16 sets wwi_t's c0,c1,...cf to the columns of a
   16x16 int matrix given the rows of the matrix in wwi_t's r0,r1,...rf.
   In-place operation fine. */

#define wwi_transpose_16x16( r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,ra,rb,rc,rd,re,rf,                      \
                             c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf ) do {                \
    wwi_t _wwi_transpose_r0 = (r0); wwi_t _wwi_transpose_r1 = (r1);                                \
    wwi_t _wwi_transpose_r2 = (r2); wwi_t _wwi_transpose_r3 = (r3);                                \
    wwi_t _wwi_transpose_r4 = (r4); wwi_t _wwi_transpose_r5 = (r5);                                \
    wwi_t _wwi_transpose_r6 = (r6); wwi_t _wwi_transpose_r7 = (r7);                                \
    wwi_t _wwi_transpose_r8 = (r8); wwi_t _wwi_transpose_r9 = (r9);                                \
    wwi_t _wwi_transpose_ra = (ra); wwi_t _wwi_transpose_rb = (rb);                                \
    wwi_t _wwi_transpose_rc = (rc); wwi_t _wwi_transpose_rd = (rd);                                \
    wwi_t _wwi_transpose_re = (re); wwi_t _wwi_transpose_rf = (rf);                                \
                                                                                                   \
    /* Outer 4x4 transpose of 4x4 blocks */                                                        \
    wwi_t _wwi_transpose_t0  = _mm512_shuffle_i32x4( _wwi_transpose_r0, _wwi_transpose_r4, 0x88 ); \
    wwi_t _wwi_transpose_t1  = _mm512_shuffle_i32x4( _wwi_transpose_r1, _wwi_transpose_r5, 0x88 ); \
    wwi_t _wwi_transpose_t2  = _mm512_shuffle_i32x4( _wwi_transpose_r2, _wwi_transpose_r6, 0x88 ); \
    wwi_t _wwi_transpose_t3  = _mm512_shuffle_i32x4( _wwi_transpose_r3, _wwi_transpose_r7, 0x88 ); \
    wwi_t _wwi_transpose_t4  = _mm512_shuffle_i32x4( _wwi_transpose_r0, _wwi_transpose_r4, 0xdd ); \
    wwi_t _wwi_transpose_t5  = _mm512_shuffle_i32x4( _wwi_transpose_r1, _wwi_transpose_r5, 0xdd ); \
    wwi_t _wwi_transpose_t6  = _mm512_shuffle_i32x4( _wwi_transpose_r2, _wwi_transpose_r6, 0xdd ); \
    wwi_t _wwi_transpose_t7  = _mm512_shuffle_i32x4( _wwi_transpose_r3, _wwi_transpose_r7, 0xdd ); \
    wwi_t _wwi_transpose_t8  = _mm512_shuffle_i32x4( _wwi_transpose_r8, _wwi_transpose_rc, 0x88 ); \
    wwi_t _wwi_transpose_t9  = _mm512_shuffle_i32x4( _wwi_transpose_r9, _wwi_transpose_rd, 0x88 ); \
    wwi_t _wwi_transpose_ta  = _mm512_shuffle_i32x4( _wwi_transpose_ra, _wwi_transpose_re, 0x88 ); \
    wwi_t _wwi_transpose_tb  = _mm512_shuffle_i32x4( _wwi_transpose_rb, _wwi_transpose_rf, 0x88 ); \
    wwi_t _wwi_transpose_tc  = _mm512_shuffle_i32x4( _wwi_transpose_r8, _wwi_transpose_rc, 0xdd ); \
    wwi_t _wwi_transpose_td  = _mm512_shuffle_i32x4( _wwi_transpose_r9, _wwi_transpose_rd, 0xdd ); \
    wwi_t _wwi_transpose_te  = _mm512_shuffle_i32x4( _wwi_transpose_ra, _wwi_transpose_re, 0xdd ); \
    wwi_t _wwi_transpose_tf  = _mm512_shuffle_i32x4( _wwi_transpose_rb, _wwi_transpose_rf, 0xdd ); \
                                                                                                   \
    /**/  _wwi_transpose_r0  = _mm512_shuffle_i32x4( _wwi_transpose_t0, _wwi_transpose_t8, 0x88 ); \
    /**/  _wwi_transpose_r1  = _mm512_shuffle_i32x4( _wwi_transpose_t1, _wwi_transpose_t9, 0x88 ); \
    /**/  _wwi_transpose_r2  = _mm512_shuffle_i32x4( _wwi_transpose_t2, _wwi_transpose_ta, 0x88 ); \
    /**/  _wwi_transpose_r3  = _mm512_shuffle_i32x4( _wwi_transpose_t3, _wwi_transpose_tb, 0x88 ); \
    /**/  _wwi_transpose_r4  = _mm512_shuffle_i32x4( _wwi_transpose_t4, _wwi_transpose_tc, 0x88 ); \
    /**/  _wwi_transpose_r5  = _mm512_shuffle_i32x4( _wwi_transpose_t5, _wwi_transpose_td, 0x88 ); \
    /**/  _wwi_transpose_r6  = _mm512_shuffle_i32x4( _wwi_transpose_t6, _wwi_transpose_te, 0x88 ); \
    /**/  _wwi_transpose_r7  = _mm512_shuffle_i32x4( _wwi_transpose_t7, _wwi_transpose_tf, 0x88 ); \
    /**/  _wwi_transpose_r8  = _mm512_shuffle_i32x4( _wwi_transpose_t0, _wwi_transpose_t8, 0xdd ); \
    /**/  _wwi_transpose_r9  = _mm512_shuffle_i32x4( _wwi_transpose_t1, _wwi_transpose_t9, 0xdd ); \
    /**/  _wwi_transpose_ra  = _mm512_shuffle_i32x4( _wwi_transpose_t2, _wwi_transpose_ta, 0xdd ); \
    /**/  _wwi_transpose_rb  = _mm512_shuffle_i32x4( _wwi_transpose_t3, _wwi_transpose_tb, 0xdd ); \
    /**/  _wwi_transpose_rc  = _mm512_shuffle_i32x4( _wwi_transpose_t4, _wwi_transpose_tc, 0xdd ); \
    /**/  _wwi_transpose_rd  = _mm512_shuffle_i32x4( _wwi_transpose_t5, _wwi_transpose_td, 0xdd ); \
    /**/  _wwi_transpose_re  = _mm512_shuffle_i32x4( _wwi_transpose_t6, _wwi_transpose_te, 0xdd ); \
    /**/  _wwi_transpose_rf  = _mm512_shuffle_i32x4( _wwi_transpose_t7, _wwi_transpose_tf, 0xdd ); \
                                                                                                   \
    /* Inner 4x4 transpose of 1x1 blocks */                                                        \
    /**/  _wwi_transpose_t0  = _mm512_unpacklo_epi32( _wwi_transpose_r0, _wwi_transpose_r2 );      \
    /**/  _wwi_transpose_t1  = _mm512_unpacklo_epi32( _wwi_transpose_r1, _wwi_transpose_r3 );      \
    /**/  _wwi_transpose_t2  = _mm512_unpackhi_epi32( _wwi_transpose_r0, _wwi_transpose_r2 );      \
    /**/  _wwi_transpose_t3  = _mm512_unpackhi_epi32( _wwi_transpose_r1, _wwi_transpose_r3 );      \
    /**/  _wwi_transpose_t4  = _mm512_unpacklo_epi32( _wwi_transpose_r4, _wwi_transpose_r6 );      \
    /**/  _wwi_transpose_t5  = _mm512_unpacklo_epi32( _wwi_transpose_r5, _wwi_transpose_r7 );      \
    /**/  _wwi_transpose_t6  = _mm512_unpackhi_epi32( _wwi_transpose_r4, _wwi_transpose_r6 );      \
    /**/  _wwi_transpose_t7  = _mm512_unpackhi_epi32( _wwi_transpose_r5, _wwi_transpose_r7 );      \
    /**/  _wwi_transpose_t8  = _mm512_unpacklo_epi32( _wwi_transpose_r8, _wwi_transpose_ra );      \
    /**/  _wwi_transpose_t9  = _mm512_unpacklo_epi32( _wwi_transpose_r9, _wwi_transpose_rb );      \
    /**/  _wwi_transpose_ta  = _mm512_unpackhi_epi32( _wwi_transpose_r8, _wwi_transpose_ra );      \
    /**/  _wwi_transpose_tb  = _mm512_unpackhi_epi32( _wwi_transpose_r9, _wwi_transpose_rb );      \
    /**/  _wwi_transpose_tc  = _mm512_unpacklo_epi32( _wwi_transpose_rc, _wwi_transpose_re );      \
    /**/  _wwi_transpose_td  = _mm512_unpacklo_epi32( _wwi_transpose_rd, _wwi_transpose_rf );      \
    /**/  _wwi_transpose_te  = _mm512_unpackhi_epi32( _wwi_transpose_rc, _wwi_transpose_re );      \
    /**/  _wwi_transpose_tf  = _mm512_unpackhi_epi32( _wwi_transpose_rd, _wwi_transpose_rf );      \
                                                                                                   \
    /**/  (c0)               = _mm512_unpacklo_epi32( _wwi_transpose_t0, _wwi_transpose_t1 );      \
    /**/  (c1)               = _mm512_unpackhi_epi32( _wwi_transpose_t0, _wwi_transpose_t1 );      \
    /**/  (c2)               = _mm512_unpacklo_epi32( _wwi_transpose_t2, _wwi_transpose_t3 );      \
    /**/  (c3)               = _mm512_unpackhi_epi32( _wwi_transpose_t2, _wwi_transpose_t3 );      \
    /**/  (c4)               = _mm512_unpacklo_epi32( _wwi_transpose_t4, _wwi_transpose_t5 );      \
    /**/  (c5)               = _mm512_unpackhi_epi32( _wwi_transpose_t4, _wwi_transpose_t5 );      \
    /**/  (c6)               = _mm512_unpacklo_epi32( _wwi_transpose_t6, _wwi_transpose_t7 );      \
    /**/  (c7)               = _mm512_unpackhi_epi32( _wwi_transpose_t6, _wwi_transpose_t7 );      \
    /**/  (c8)               = _mm512_unpacklo_epi32( _wwi_transpose_t8, _wwi_transpose_t9 );      \
    /**/  (c9)               = _mm512_unpackhi_epi32( _wwi_transpose_t8, _wwi_transpose_t9 );      \
    /**/  (ca)               = _mm512_unpacklo_epi32( _wwi_transpose_ta, _wwi_transpose_tb );      \
    /**/  (cb)               = _mm512_unpackhi_epi32( _wwi_transpose_ta, _wwi_transpose_tb );      \
    /**/  (cc)               = _mm512_unpacklo_epi32( _wwi_transpose_tc, _wwi_transpose_td );      \
    /**/  (cd)               = _mm512_unpackhi_epi32( _wwi_transpose_tc, _wwi_transpose_td );      \
    /**/  (ce)               = _mm512_unpacklo_epi32( _wwi_transpose_te, _wwi_transpose_tf );      \
    /**/  (cf)               = _mm512_unpackhi_epi32( _wwi_transpose_te, _wwi_transpose_tf );      \
  } while(0)

/* wwi_transpose_2x8x8 transposes the 2 8x8 matrices whose rows are
   held in the lower and upper halves of wwi_t's r0,r1...r7 and
   stores the result in c0,c1...c7.  In-place operation fine. */

#define wwi_transpose_2x8x8( r0,r1,r2,r3,r4,r5,r6,r7,                                                \
                             c0,c1,c2,c3,c4,c5,c6,c7 ) {                                             \
    wwi_t _wwi_transpose_r0 = (r0); wwi_t _wwi_transpose_r1 = (r1);                                  \
    wwi_t _wwi_transpose_r2 = (r2); wwi_t _wwi_transpose_r3 = (r3);                                  \
    wwi_t _wwi_transpose_r4 = (r4); wwi_t _wwi_transpose_r5 = (r5);                                  \
    wwi_t _wwi_transpose_r6 = (r6); wwi_t _wwi_transpose_r7 = (r7);                                  \
                                                                                                     \
    /* Outer 2x2 transpose of 4x4 blocks */                                                          \
    /* No _mm256_permute2f128_si128 equiv? sigh ... probably a better method possible here */        \
    wwi_t _wwi_transpose_p   = wwi( 0, 1, 2, 3,16,17,18,19, 8, 9,10,11,24,25,26,27);                 \
    wwi_t _wwi_transpose_q   = wwi( 4, 5, 6, 7,20,21,22,23,12,13,14,15,28,29,30,31);                 \
    wwi_t _wwi_transpose_t0  = wwi_select( _wwi_transpose_p, _wwi_transpose_r0, _wwi_transpose_r4 ); \
    wwi_t _wwi_transpose_t1  = wwi_select( _wwi_transpose_p, _wwi_transpose_r1, _wwi_transpose_r5 ); \
    wwi_t _wwi_transpose_t2  = wwi_select( _wwi_transpose_p, _wwi_transpose_r2, _wwi_transpose_r6 ); \
    wwi_t _wwi_transpose_t3  = wwi_select( _wwi_transpose_p, _wwi_transpose_r3, _wwi_transpose_r7 ); \
    wwi_t _wwi_transpose_t4  = wwi_select( _wwi_transpose_q, _wwi_transpose_r0, _wwi_transpose_r4 ); \
    wwi_t _wwi_transpose_t5  = wwi_select( _wwi_transpose_q, _wwi_transpose_r1, _wwi_transpose_r5 ); \
    wwi_t _wwi_transpose_t6  = wwi_select( _wwi_transpose_q, _wwi_transpose_r2, _wwi_transpose_r6 ); \
    wwi_t _wwi_transpose_t7  = wwi_select( _wwi_transpose_q, _wwi_transpose_r3, _wwi_transpose_r7 ); \
                                                                                                     \
    /* Inner 4x4 transpose of 1x1 blocks */                                                          \
    /**/  _wwi_transpose_r0  = _mm512_unpacklo_epi32( _wwi_transpose_t0, _wwi_transpose_t2 );        \
    /**/  _wwi_transpose_r1  = _mm512_unpacklo_epi32( _wwi_transpose_t1, _wwi_transpose_t3 );        \
    /**/  _wwi_transpose_r2  = _mm512_unpackhi_epi32( _wwi_transpose_t0, _wwi_transpose_t2 );        \
    /**/  _wwi_transpose_r3  = _mm512_unpackhi_epi32( _wwi_transpose_t1, _wwi_transpose_t3 );        \
    /**/  _wwi_transpose_r4  = _mm512_unpacklo_epi32( _wwi_transpose_t4, _wwi_transpose_t6 );        \
    /**/  _wwi_transpose_r5  = _mm512_unpacklo_epi32( _wwi_transpose_t5, _wwi_transpose_t7 );        \
    /**/  _wwi_transpose_r6  = _mm512_unpackhi_epi32( _wwi_transpose_t4, _wwi_transpose_t6 );        \
    /**/  _wwi_transpose_r7  = _mm512_unpackhi_epi32( _wwi_transpose_t5, _wwi_transpose_t7 );        \
                                                                                                     \
    /**/  (c0)               = _mm512_unpacklo_epi32( _wwi_transpose_r0, _wwi_transpose_r1 );        \
    /**/  (c1)               = _mm512_unpackhi_epi32( _wwi_transpose_r0, _wwi_transpose_r1 );        \
    /**/  (c2)               = _mm512_unpacklo_epi32( _wwi_transpose_r2, _wwi_transpose_r3 );        \
    /**/  (c3)               = _mm512_unpackhi_epi32( _wwi_transpose_r2, _wwi_transpose_r3 );        \
    /**/  (c4)               = _mm512_unpacklo_epi32( _wwi_transpose_r4, _wwi_transpose_r5 );        \
    /**/  (c5)               = _mm512_unpackhi_epi32( _wwi_transpose_r4, _wwi_transpose_r5 );        \
    /**/  (c6)               = _mm512_unpacklo_epi32( _wwi_transpose_r6, _wwi_transpose_r7 );        \
    /**/  (c7)               = _mm512_unpackhi_epi32( _wwi_transpose_r6, _wwi_transpose_r7 );        \
  } while(0)
