#ifndef HEADER_fd_src_util_simd_fd_avx512_h
#error "Do not include this directly; use fd_avx512.h"
#endif

/* TODO: REDUCE, EXTRACT, ADDITIONAL LANE OPS, ... */
/* TODO: USE INT FOR THS SCALAR N ROL/ROR (AND IN OTHER ROL/ROR)? */
/* TODO: BACKPORT UNPACKS TO AVX AND SSE? */

/* Vector uint API ***************************************************/

/* A wwu_t is a vector where each 32-bit wide lane holds an unsigned
   32-bit integer (a "uint").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wwu_t __m512i

/* Constructors */

/* wwu(x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf)
   returns the wwu_t [x0 x1 ... xf] where x* are uints */

#define wwu(x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf)                                                 \
  _mm512_setr_epi32( (int)(x0), (int)(x1), (int)(x2), (int)(x3), (int)(x4), (int)(x5), (int)(x6), (int)(x7), \
                     (int)(x8), (int)(x9), (int)(xa), (int)(xb), (int)(xc), (int)(xd), (int)(xe), (int)(xf) )

#define wwu_bcast(x)         _mm512_set1_epi32( (int)(x) ) /* wwu(x, x, ... x) */

/* wwu_permute(p,x) returns:
     wwu( x(p(0)), x(p(1)), ... x(p(15)) ).
   As such p(*) should be uints in [0,15]. */

#define wwu_permute(p,x)     _mm512_permutexvar_epi32( (p), (x) )

/* wwu_select(s,x,y) concatenates the wwu_t's x and y into
     z = [ x0 x1 ... xf y0 y1 ... yf ]
   and then returns:
     wwu( z(p(0)), z(p(1)), ... z(p(15)) ).
   As such p(*) should be uints in [0,31]. */

#define wwu_select(p,x,y)    _mm512_permutex2var_epi32( (x), (p), (y) )

/* Predefined constants */

#define wwu_zero()           _mm512_setzero_si512()  /* wwu(0, 0, ... 0) */
#define wwu_one()            _mm512_set1_epi32( 1 )  /* wwu(1, 1, ... 1) */

/* Memory operations */
/* Note: wwu_{ld,st} assume m is 64-byte aligned while wwu_{ldu,stu}
   allow m to have arbitrary alignment */

static inline wwu_t wwu_ld( uint const * m ) { return _mm512_load_epi32( m ); }  /* wwu( m[0], m[1], ... m[15] ) */
static inline void  wwu_st( uint * m, wwu_t x ) { _mm512_store_epi32( m, x ); }  /* does m[0] = x0, m[1] = x1, ... m[15] = xf */

static inline wwu_t wwu_ldu( void const * m ) { return _mm512_loadu_epi32( m ); } /* wwu( m[0], m[1], ... m[15]) */
static inline void  wwu_stu( void * m, wwu_t x ) { _mm512_storeu_epi32( m, x ); } /* does m[0] = x0, m[1] = x1, ... m[15] = xf */

/* Arithmetic operations */

#define wwu_neg(x)           _mm512_sub_epi32( _mm512_setzero_si512(), (x) ) /* wwu( -x0, -x1, ... -xf ) */
#define wwu_abs(x)           (x)                                             /* wwu(  x0,  x1, ...  xf ) */

#define wwu_min(x,y)         _mm512_min_epu32  ( (x), (y) ) /* wwu( min(x0,y0), min(x1,y1), ... min(xf,yf) ) */
#define wwu_max(x,y)         _mm512_max_epu32  ( (x), (y) ) /* wwu( max(x0,y0), max(x1,y1), ... max(xf,yf) ) */
#define wwu_add(x,y)         _mm512_add_epi32  ( (x), (y) ) /* wwu( x0+y0,      x1+y1,      ... xf+yf      ) */
#define wwu_sub(x,y)         _mm512_sub_epi32  ( (x), (y) ) /* wwu( x0-y0,      x1-y1,      ... xf-yf      ) */
#define wwu_mul(x,y)         _mm512_mullo_epi32( (x), (y) ) /* wwu( x0*y0,      x1*y1,      ... xf*yf      ) */

/* Binary operations */
/* Note: shifts assumes n and or y* in [0,31].  Rotates work for
   arbitrary values */

#define wwu_not(x)           _mm512_xor_epi32( _mm512_set1_epi32( -1 ), (x) )

#define wwu_shl(x,n)         _mm512_slli_epi32  ( (x), (uint)(n) ) /* wwu( x0<<n,  x1<<n,  ... xf<<n  ) */
#define wwu_shr(x,n)         _mm512_srli_epi32  ( (x), (uint)(n) ) /* wwu( x0>>n,  x1>>n,  ... xf>>n  ) */
#define wwu_shl_vector(x,y)  _mm512_sllv_epi32  ( (x), (y)       ) /* wwu( x0<<y0, x1<<y1, ... xf<<yf ) */
#define wwu_shr_vector(x,y)  _mm512_srlv_epi32  ( (x), (y)       ) /* wwu( x0>>y0, x1>>y1, ... xf>>yf ) */
#define wwu_and(x,y)         _mm512_and_epi32   ( (x), (y)       ) /* wwu( x0&y0,  x1&y1,  ... xf&yf  ) */
#define wwu_andnot(x,y)      _mm512_andnot_epi32( (x), (y)       ) /* wwu( ~x0&y0, ~x1&y1, ... ~xf&yf ) */
#define wwu_or(x,y)          _mm512_or_epi32    ( (x), (y)       ) /* wwu( x0|y0,  x1|y1,  ... xf|yf  ) */
#define wwu_xor(x,y)         _mm512_xor_epi32   ( (x), (y)       ) /* wwu( x0^y0,  x1^y1,  ... xf^yf  ) */

/* wwu_rol(x,n)        returns wwu( rotate_left (x0,n ), rotate_left (x1,n ), ... )
   wwu_ror(x,n)        returns wwu( rotate_right(x0,n ), rotate_right(x1,n ), ... )
   wwu_rol_vector(x,y) returns wwu( rotate_left (x0,y0), rotate_left (x1,y1), ... )
   wwu_ror_vector(x,y) returns wwu( rotate_right(x0,y0), rotate_right(x1,y1), ... ) */

static inline wwu_t wwu_rol( wwu_t a, uint n ) { return wwu_or( wwu_shl( a, n & 31U ), wwu_shr( a, (-n) & 31U ) ); }
static inline wwu_t wwu_ror( wwu_t a, uint n ) { return wwu_or( wwu_shr( a, n & 31U ), wwu_shl( a, (-n) & 31U ) ); }

static inline wwu_t wwu_rol_vector( wwu_t a, wwu_t b ) {
  wwu_t m = wwu_bcast( 31U );
  return wwu_or( wwu_shl_vector( a, wwu_and( b, m ) ), wwu_shr_vector( a, wwu_and( wwu_neg( b ), m ) ) );
}

static inline wwu_t wwu_ror_vector( wwu_t a, wwu_t b ) {
  wwu_t m = wwu_bcast( 31U );
  return wwu_or( wwu_shr_vector( a, wwu_and( b, m ) ), wwu_shl_vector( a, wwu_and( wwu_neg( b ), m ) ) );
}

/* wwu_bswap(x) returns wwu( bswap(x0), bswap(x1), ... ) */

#define wwu_bswap( x ) _mm512_shuffle_epi8( (x), _mm512_set_epi8( 12,13,14,15, 8, 9,10,11, 4, 5, 6, 7, 0, 1, 2, 3, \
                                                                  12,13,14,15, 8, 9,10,11, 4, 5, 6, 7, 0, 1, 2, 3, \
                                                                  12,13,14,15, 8, 9,10,11, 4, 5, 6, 7, 0, 1, 2, 3, \
                                                                  12,13,14,15, 8, 9,10,11, 4, 5, 6, 7, 0, 1, 2, 3 ) )

/* Comparison operations */
/* mask(c0,c1,...) means (((int)c0)<<0) | (((int)c1)<<1) | ... */

#define wwu_eq(x,y) ((int)_mm512_cmpeq_epu32_mask(  (x), (y) )) /* mask( x0==y0, x1==y1, ... ) */
#define wwu_gt(x,y) ((int)_mm512_cmpgt_epu32_mask(  (x), (y) )) /* mask( x0> y0, x1> y1, ... ) */
#define wwu_lt(x,y) ((int)_mm512_cmplt_epu32_mask(  (x), (y) )) /* mask( x0< y0, x1< y1, ... ) */
#define wwu_ne(x,y) ((int)_mm512_cmpneq_epu32_mask( (x), (y) )) /* mask( x0!=y0, x1!=y1, ... ) */
#define wwu_ge(x,y) ((int)_mm512_cmpge_epu32_mask(  (x), (y) )) /* mask( x0>=y0, x1>=y1, ... ) */
#define wwu_le(x,y) ((int)_mm512_cmple_epu32_mask(  (x), (y) )) /* mask( x0<=y0, x1<=y1, ... ) */

#define wwu_lnot(x)    wwu_eq( (x), wwu_zero() )                /* mask(  !x0,  !x1, ... ) */
#define wwu_lnotnot(x) wwu_ne( (x), wwu_zero() )                /* mask( !!x0, !!x1, ... ) */

/* Conditional operations */
/* cn means bit n of c */

#define wwu_if(c,x,y)       _mm512_mask_blend_epi32( (__mmask16)(c), (y), (x) )    /* wwu( c0? x0    :y0, ... ) */
#define wwu_add_if(c,x,y,z) _mm512_mask_add_epi32( (z), (__mmask16)(c), (x), (y) ) /* wwu( c0?(x0+y0):z0, ... ) */
#define wwu_sub_if(c,x,y,z) _mm512_mask_sub_epi32( (z), (__mmask16)(c), (x), (y) ) /* wwu( c0?(x0-y0):z0, ... ) */

/* Conversions */

/* wwu_to_wwi( x )    returns wwi(   (int)x0,   (int)x1, ...   (int)x15 )

   wwu_to_wwl( x, 0 ) returns wwl(  (long)x0,  (long)x2, ...  (long)x14 )
   wwu_to_wwl( x, 1 ) returns wwl(  (long)x1,  (long)x3, ...  (long)x15 )

   wwu_to_wwv( x, 0 ) returns wwv( (ulong)x0, (ulong)x2, ... (ulong)x14 )
   wwu_to_wwv( x, 1 ) returns wwv( (ulong)x1, (ulong)x3, ... (ulong)x15 )

   TODO: consider _mm512_cvtepu32_* intrinsics? */

#define wwu_to_wwi( x ) (x)
#define wwu_to_wwl( x, odd ) /* trinary should be compile time */ \
  (__extension__({ wwl_t _wwu_to_wwl_tmp = (x); wwl_shru( (odd) ? _wwu_to_wwl_tmp : wwl_shl( _wwu_to_wwl_tmp, 32 ), 32 ); }))
#define wwu_to_wwv( x, odd ) /* trinary should be compile time */ \
  (__extension__({ wwv_t _wwu_to_wwv_tmp = (x); wwv_shr ( (odd) ? _wwu_to_wwv_tmp : wwv_shl( _wwu_to_wwv_tmp, 32 ), 32 ); }))

#define wwu_to_wwi_raw(x) (x)
#define wwu_to_wwl_raw(x) (x)
#define wwu_to_wwv_raw(x) (x)

/* Misc operations */

/* wwu_pack_halves(x,imm0,y,imm1) packs half of x and half of y into a
   wwu.  imm0/imm1 select which half of x and y to pack.  imm0 / imm1
   should be in [0,1].  That is, this returns:

     [ if( imm0, x(8:15), x(0:7) ) if( imm1, y(8:15), y(0:7) ) ]

   wwu_pack_h0_h1(x,y) does the wwu_pack_halves(x,0,y,1) case faster.
   Hat tip to Philip Taffet for pointing this out. */

#define wwu_pack_halves(x,imm0,y,imm1) _mm512_shuffle_i32x4( (x), (y), 68+10*(imm0)+160*(imm1) )
#define wwu_pack_h0_h1(x,y)            _mm512_mask_blend_epi32( (__mmask16)0xFF00, (x), (y) )

/* wwu_slide(x,y,imm) treats as a x FIFO with the oldest / newest
   element at lane 0 / 15.  Returns the result of dequeing x imm times
   and enqueing the values y0 ... y{imm-1} in that order.  imm should be
   in [0,15].  For example, with imm==5 case, returns:
     [ x5 x6 ... xf y0 y1 y2 y3 y4 ]. */

#define wwu_slide(x,y,imm) _mm512_alignr_epi32( (y), (x), (imm) )

/* wwv_unpack unpacks the wwv x into its uint components x0,x1,...xf. */

#define wwu_unpack( x, x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf ) do { \
    __m512i _wwu_unpack_x  = (x);                                             \
    __m256i _wwu_unpack_xl = _mm512_extracti32x8_epi32( _wwu_unpack_x, 0 );   \
    __m256i _wwu_unpack_xh = _mm512_extracti32x8_epi32( _wwu_unpack_x, 1 );   \
    (x0) = (uint)_mm256_extract_epi32( _wwu_unpack_xl, 0 );                   \
    (x1) = (uint)_mm256_extract_epi32( _wwu_unpack_xl, 1 );                   \
    (x2) = (uint)_mm256_extract_epi32( _wwu_unpack_xl, 2 );                   \
    (x3) = (uint)_mm256_extract_epi32( _wwu_unpack_xl, 3 );                   \
    (x4) = (uint)_mm256_extract_epi32( _wwu_unpack_xl, 4 );                   \
    (x5) = (uint)_mm256_extract_epi32( _wwu_unpack_xl, 5 );                   \
    (x6) = (uint)_mm256_extract_epi32( _wwu_unpack_xl, 6 );                   \
    (x7) = (uint)_mm256_extract_epi32( _wwu_unpack_xl, 7 );                   \
    (x8) = (uint)_mm256_extract_epi32( _wwu_unpack_xh, 0 );                   \
    (x9) = (uint)_mm256_extract_epi32( _wwu_unpack_xh, 1 );                   \
    (xa) = (uint)_mm256_extract_epi32( _wwu_unpack_xh, 2 );                   \
    (xb) = (uint)_mm256_extract_epi32( _wwu_unpack_xh, 3 );                   \
    (xc) = (uint)_mm256_extract_epi32( _wwu_unpack_xh, 4 );                   \
    (xd) = (uint)_mm256_extract_epi32( _wwu_unpack_xh, 5 );                   \
    (xe) = (uint)_mm256_extract_epi32( _wwu_unpack_xh, 6 );                   \
    (xf) = (uint)_mm256_extract_epi32( _wwu_unpack_xh, 7 );                   \
  } while(0)

/* wwu_transpose_16x16 sets wwu_t's c0,c1,...cf to the columns of a
   16x16 uint matrix given the rows of the matrix in wwu_t's
   r0,r1,...rf.  In-place operation fine. */

#define wwu_transpose_16x16( r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,ra,rb,rc,rd,re,rf,                      \
                             c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf ) do {                \
    wwu_t _wwu_transpose_r0 = (r0); wwu_t _wwu_transpose_r1 = (r1);                                \
    wwu_t _wwu_transpose_r2 = (r2); wwu_t _wwu_transpose_r3 = (r3);                                \
    wwu_t _wwu_transpose_r4 = (r4); wwu_t _wwu_transpose_r5 = (r5);                                \
    wwu_t _wwu_transpose_r6 = (r6); wwu_t _wwu_transpose_r7 = (r7);                                \
    wwu_t _wwu_transpose_r8 = (r8); wwu_t _wwu_transpose_r9 = (r9);                                \
    wwu_t _wwu_transpose_ra = (ra); wwu_t _wwu_transpose_rb = (rb);                                \
    wwu_t _wwu_transpose_rc = (rc); wwu_t _wwu_transpose_rd = (rd);                                \
    wwu_t _wwu_transpose_re = (re); wwu_t _wwu_transpose_rf = (rf);                                \
                                                                                                   \
    /* Outer 4x4 transpose of 4x4 blocks */                                                        \
    wwu_t _wwu_transpose_t0  = _mm512_shuffle_i32x4( _wwu_transpose_r0, _wwu_transpose_r4, 0x88 ); \
    wwu_t _wwu_transpose_t1  = _mm512_shuffle_i32x4( _wwu_transpose_r1, _wwu_transpose_r5, 0x88 ); \
    wwu_t _wwu_transpose_t2  = _mm512_shuffle_i32x4( _wwu_transpose_r2, _wwu_transpose_r6, 0x88 ); \
    wwu_t _wwu_transpose_t3  = _mm512_shuffle_i32x4( _wwu_transpose_r3, _wwu_transpose_r7, 0x88 ); \
    wwu_t _wwu_transpose_t4  = _mm512_shuffle_i32x4( _wwu_transpose_r0, _wwu_transpose_r4, 0xdd ); \
    wwu_t _wwu_transpose_t5  = _mm512_shuffle_i32x4( _wwu_transpose_r1, _wwu_transpose_r5, 0xdd ); \
    wwu_t _wwu_transpose_t6  = _mm512_shuffle_i32x4( _wwu_transpose_r2, _wwu_transpose_r6, 0xdd ); \
    wwu_t _wwu_transpose_t7  = _mm512_shuffle_i32x4( _wwu_transpose_r3, _wwu_transpose_r7, 0xdd ); \
    wwu_t _wwu_transpose_t8  = _mm512_shuffle_i32x4( _wwu_transpose_r8, _wwu_transpose_rc, 0x88 ); \
    wwu_t _wwu_transpose_t9  = _mm512_shuffle_i32x4( _wwu_transpose_r9, _wwu_transpose_rd, 0x88 ); \
    wwu_t _wwu_transpose_ta  = _mm512_shuffle_i32x4( _wwu_transpose_ra, _wwu_transpose_re, 0x88 ); \
    wwu_t _wwu_transpose_tb  = _mm512_shuffle_i32x4( _wwu_transpose_rb, _wwu_transpose_rf, 0x88 ); \
    wwu_t _wwu_transpose_tc  = _mm512_shuffle_i32x4( _wwu_transpose_r8, _wwu_transpose_rc, 0xdd ); \
    wwu_t _wwu_transpose_td  = _mm512_shuffle_i32x4( _wwu_transpose_r9, _wwu_transpose_rd, 0xdd ); \
    wwu_t _wwu_transpose_te  = _mm512_shuffle_i32x4( _wwu_transpose_ra, _wwu_transpose_re, 0xdd ); \
    wwu_t _wwu_transpose_tf  = _mm512_shuffle_i32x4( _wwu_transpose_rb, _wwu_transpose_rf, 0xdd ); \
                                                                                                   \
    /**/  _wwu_transpose_r0  = _mm512_shuffle_i32x4( _wwu_transpose_t0, _wwu_transpose_t8, 0x88 ); \
    /**/  _wwu_transpose_r1  = _mm512_shuffle_i32x4( _wwu_transpose_t1, _wwu_transpose_t9, 0x88 ); \
    /**/  _wwu_transpose_r2  = _mm512_shuffle_i32x4( _wwu_transpose_t2, _wwu_transpose_ta, 0x88 ); \
    /**/  _wwu_transpose_r3  = _mm512_shuffle_i32x4( _wwu_transpose_t3, _wwu_transpose_tb, 0x88 ); \
    /**/  _wwu_transpose_r4  = _mm512_shuffle_i32x4( _wwu_transpose_t4, _wwu_transpose_tc, 0x88 ); \
    /**/  _wwu_transpose_r5  = _mm512_shuffle_i32x4( _wwu_transpose_t5, _wwu_transpose_td, 0x88 ); \
    /**/  _wwu_transpose_r6  = _mm512_shuffle_i32x4( _wwu_transpose_t6, _wwu_transpose_te, 0x88 ); \
    /**/  _wwu_transpose_r7  = _mm512_shuffle_i32x4( _wwu_transpose_t7, _wwu_transpose_tf, 0x88 ); \
    /**/  _wwu_transpose_r8  = _mm512_shuffle_i32x4( _wwu_transpose_t0, _wwu_transpose_t8, 0xdd ); \
    /**/  _wwu_transpose_r9  = _mm512_shuffle_i32x4( _wwu_transpose_t1, _wwu_transpose_t9, 0xdd ); \
    /**/  _wwu_transpose_ra  = _mm512_shuffle_i32x4( _wwu_transpose_t2, _wwu_transpose_ta, 0xdd ); \
    /**/  _wwu_transpose_rb  = _mm512_shuffle_i32x4( _wwu_transpose_t3, _wwu_transpose_tb, 0xdd ); \
    /**/  _wwu_transpose_rc  = _mm512_shuffle_i32x4( _wwu_transpose_t4, _wwu_transpose_tc, 0xdd ); \
    /**/  _wwu_transpose_rd  = _mm512_shuffle_i32x4( _wwu_transpose_t5, _wwu_transpose_td, 0xdd ); \
    /**/  _wwu_transpose_re  = _mm512_shuffle_i32x4( _wwu_transpose_t6, _wwu_transpose_te, 0xdd ); \
    /**/  _wwu_transpose_rf  = _mm512_shuffle_i32x4( _wwu_transpose_t7, _wwu_transpose_tf, 0xdd ); \
                                                                                                   \
    /* Inner 4x4 transpose of 1x1 blocks */                                                        \
    /**/  _wwu_transpose_t0  = _mm512_unpacklo_epi32( _wwu_transpose_r0, _wwu_transpose_r2 );      \
    /**/  _wwu_transpose_t1  = _mm512_unpacklo_epi32( _wwu_transpose_r1, _wwu_transpose_r3 );      \
    /**/  _wwu_transpose_t2  = _mm512_unpackhi_epi32( _wwu_transpose_r0, _wwu_transpose_r2 );      \
    /**/  _wwu_transpose_t3  = _mm512_unpackhi_epi32( _wwu_transpose_r1, _wwu_transpose_r3 );      \
    /**/  _wwu_transpose_t4  = _mm512_unpacklo_epi32( _wwu_transpose_r4, _wwu_transpose_r6 );      \
    /**/  _wwu_transpose_t5  = _mm512_unpacklo_epi32( _wwu_transpose_r5, _wwu_transpose_r7 );      \
    /**/  _wwu_transpose_t6  = _mm512_unpackhi_epi32( _wwu_transpose_r4, _wwu_transpose_r6 );      \
    /**/  _wwu_transpose_t7  = _mm512_unpackhi_epi32( _wwu_transpose_r5, _wwu_transpose_r7 );      \
    /**/  _wwu_transpose_t8  = _mm512_unpacklo_epi32( _wwu_transpose_r8, _wwu_transpose_ra );      \
    /**/  _wwu_transpose_t9  = _mm512_unpacklo_epi32( _wwu_transpose_r9, _wwu_transpose_rb );      \
    /**/  _wwu_transpose_ta  = _mm512_unpackhi_epi32( _wwu_transpose_r8, _wwu_transpose_ra );      \
    /**/  _wwu_transpose_tb  = _mm512_unpackhi_epi32( _wwu_transpose_r9, _wwu_transpose_rb );      \
    /**/  _wwu_transpose_tc  = _mm512_unpacklo_epi32( _wwu_transpose_rc, _wwu_transpose_re );      \
    /**/  _wwu_transpose_td  = _mm512_unpacklo_epi32( _wwu_transpose_rd, _wwu_transpose_rf );      \
    /**/  _wwu_transpose_te  = _mm512_unpackhi_epi32( _wwu_transpose_rc, _wwu_transpose_re );      \
    /**/  _wwu_transpose_tf  = _mm512_unpackhi_epi32( _wwu_transpose_rd, _wwu_transpose_rf );      \
                                                                                                   \
    /**/  (c0)               = _mm512_unpacklo_epi32( _wwu_transpose_t0, _wwu_transpose_t1 );      \
    /**/  (c1)               = _mm512_unpackhi_epi32( _wwu_transpose_t0, _wwu_transpose_t1 );      \
    /**/  (c2)               = _mm512_unpacklo_epi32( _wwu_transpose_t2, _wwu_transpose_t3 );      \
    /**/  (c3)               = _mm512_unpackhi_epi32( _wwu_transpose_t2, _wwu_transpose_t3 );      \
    /**/  (c4)               = _mm512_unpacklo_epi32( _wwu_transpose_t4, _wwu_transpose_t5 );      \
    /**/  (c5)               = _mm512_unpackhi_epi32( _wwu_transpose_t4, _wwu_transpose_t5 );      \
    /**/  (c6)               = _mm512_unpacklo_epi32( _wwu_transpose_t6, _wwu_transpose_t7 );      \
    /**/  (c7)               = _mm512_unpackhi_epi32( _wwu_transpose_t6, _wwu_transpose_t7 );      \
    /**/  (c8)               = _mm512_unpacklo_epi32( _wwu_transpose_t8, _wwu_transpose_t9 );      \
    /**/  (c9)               = _mm512_unpackhi_epi32( _wwu_transpose_t8, _wwu_transpose_t9 );      \
    /**/  (ca)               = _mm512_unpacklo_epi32( _wwu_transpose_ta, _wwu_transpose_tb );      \
    /**/  (cb)               = _mm512_unpackhi_epi32( _wwu_transpose_ta, _wwu_transpose_tb );      \
    /**/  (cc)               = _mm512_unpacklo_epi32( _wwu_transpose_tc, _wwu_transpose_td );      \
    /**/  (cd)               = _mm512_unpackhi_epi32( _wwu_transpose_tc, _wwu_transpose_td );      \
    /**/  (ce)               = _mm512_unpacklo_epi32( _wwu_transpose_te, _wwu_transpose_tf );      \
    /**/  (cf)               = _mm512_unpackhi_epi32( _wwu_transpose_te, _wwu_transpose_tf );      \
  } while(0)

/* wwu_transpose_2x8x8 transposes the 2 8x8 matrices whos rows are in
   held in the lower and upper halves of wwu_t's r0,r1...r7 and
   stores the result in c0,c1...c7.  In-place operation fine. */

#define wwu_transpose_2x8x8( r0,r1,r2,r3,r4,r5,r6,r7,                                                \
                             c0,c1,c2,c3,c4,c5,c6,c7 ) {                                             \
    wwu_t _wwu_transpose_r0 = (r0); wwu_t _wwu_transpose_r1 = (r1);                                  \
    wwu_t _wwu_transpose_r2 = (r2); wwu_t _wwu_transpose_r3 = (r3);                                  \
    wwu_t _wwu_transpose_r4 = (r4); wwu_t _wwu_transpose_r5 = (r5);                                  \
    wwu_t _wwu_transpose_r6 = (r6); wwu_t _wwu_transpose_r7 = (r7);                                  \
                                                                                                     \
    /* Outer 2x2 transpose of 4x4 blocks */                                                          \
    /* No _mm256_permute2f128_si128 equiv? sigh ... probably a better method possible here */        \
    wwu_t _wwu_transpose_p   = wwu( 0U, 1U, 2U, 3U,16U,17U,18U,19U, 8U, 9U,10U,11U,24U,25U,26U,27U); \
    wwu_t _wwu_transpose_q   = wwu( 4U, 5U, 6U, 7U,20U,21U,22U,23U,12U,13U,14U,15U,28U,29U,30U,31U); \
    wwu_t _wwu_transpose_t0  = wwu_select( _wwu_transpose_p, _wwu_transpose_r0, _wwu_transpose_r4 ); \
    wwu_t _wwu_transpose_t1  = wwu_select( _wwu_transpose_p, _wwu_transpose_r1, _wwu_transpose_r5 ); \
    wwu_t _wwu_transpose_t2  = wwu_select( _wwu_transpose_p, _wwu_transpose_r2, _wwu_transpose_r6 ); \
    wwu_t _wwu_transpose_t3  = wwu_select( _wwu_transpose_p, _wwu_transpose_r3, _wwu_transpose_r7 ); \
    wwu_t _wwu_transpose_t4  = wwu_select( _wwu_transpose_q, _wwu_transpose_r0, _wwu_transpose_r4 ); \
    wwu_t _wwu_transpose_t5  = wwu_select( _wwu_transpose_q, _wwu_transpose_r1, _wwu_transpose_r5 ); \
    wwu_t _wwu_transpose_t6  = wwu_select( _wwu_transpose_q, _wwu_transpose_r2, _wwu_transpose_r6 ); \
    wwu_t _wwu_transpose_t7  = wwu_select( _wwu_transpose_q, _wwu_transpose_r3, _wwu_transpose_r7 ); \
                                                                                                     \
    /* Inner 4x4 transpose of 1x1 blocks */                                                          \
    /**/  _wwu_transpose_r0  = _mm512_unpacklo_epi32( _wwu_transpose_t0, _wwu_transpose_t2 );        \
    /**/  _wwu_transpose_r1  = _mm512_unpacklo_epi32( _wwu_transpose_t1, _wwu_transpose_t3 );        \
    /**/  _wwu_transpose_r2  = _mm512_unpackhi_epi32( _wwu_transpose_t0, _wwu_transpose_t2 );        \
    /**/  _wwu_transpose_r3  = _mm512_unpackhi_epi32( _wwu_transpose_t1, _wwu_transpose_t3 );        \
    /**/  _wwu_transpose_r4  = _mm512_unpacklo_epi32( _wwu_transpose_t4, _wwu_transpose_t6 );        \
    /**/  _wwu_transpose_r5  = _mm512_unpacklo_epi32( _wwu_transpose_t5, _wwu_transpose_t7 );        \
    /**/  _wwu_transpose_r6  = _mm512_unpackhi_epi32( _wwu_transpose_t4, _wwu_transpose_t6 );        \
    /**/  _wwu_transpose_r7  = _mm512_unpackhi_epi32( _wwu_transpose_t5, _wwu_transpose_t7 );        \
                                                                                                     \
    /**/  (c0)               = _mm512_unpacklo_epi32( _wwu_transpose_r0, _wwu_transpose_r1 );        \
    /**/  (c1)               = _mm512_unpackhi_epi32( _wwu_transpose_r0, _wwu_transpose_r1 );        \
    /**/  (c2)               = _mm512_unpacklo_epi32( _wwu_transpose_r2, _wwu_transpose_r3 );        \
    /**/  (c3)               = _mm512_unpackhi_epi32( _wwu_transpose_r2, _wwu_transpose_r3 );        \
    /**/  (c4)               = _mm512_unpacklo_epi32( _wwu_transpose_r4, _wwu_transpose_r5 );        \
    /**/  (c5)               = _mm512_unpackhi_epi32( _wwu_transpose_r4, _wwu_transpose_r5 );        \
    /**/  (c6)               = _mm512_unpacklo_epi32( _wwu_transpose_r6, _wwu_transpose_r7 );        \
    /**/  (c7)               = _mm512_unpackhi_epi32( _wwu_transpose_r6, _wwu_transpose_r7 );        \
  } while(0)
