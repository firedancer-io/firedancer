#ifndef HEADER_fd_src_util_simd_fd_avx_h
#error "Do not include this directly; use fd_avx.h"
#endif

/* Vector int API *****************************************************/

/* A wi_t is a vector where each 32-bit wide lane holds a signed 32-bit
   twos-complement integer (an "int").  These mirror wc and wf as much
   as possible.

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wi_t __m256i

/* Constructors */

/* Given the int values, return ... */

#define wi(i0,i1,i2,i3,i4,i5,i6,i7) /* [ i0 i1 i2 i3 i4 i5 i6 i7 ] */ \
  _mm256_setr_epi32( (i0), (i1), (i2), (i3), (i4), (i5), (i6), (i7) )

#define wi_bcast(i0) _mm256_set1_epi32( (i0) ) /* [ i0 i0 i0 i0 i0 i0 i0 i0 ] */

static inline wi_t /* [ i0 i1 i0 i1 i0 i1 i0 i1 ] */
wi_bcast_pair( int i0, int i1 ) {
  return _mm256_setr_epi32( i0, i1, i0, i1, i0, i1, i0, i1 );
}

static inline wi_t /* [ i0 i0 i0 i0 i1 i1 i1 i1 ] */
wi_bcast_lohi( int i0, int i1 ) {
  return _mm256_setr_epi32( i0, i0, i0, i0, i1, i1, i1, i1 );
}

static inline wi_t /* [ i0 i1 i2 i3 i0 i1 i2 i3 ] */
wi_bcast_quad( int i0, int i1, int i2, int i3 ) {
  return _mm256_setr_epi32( i0, i1, i2, i3, i0, i1, i2, i3 );
}

static inline wi_t /* [ i0 i0 i1 i1 i2 i2 i3 i3 ] */
wi_bcast_wide( int i0, int i1, int i2, int i3 ) {
  return _mm256_setr_epi32( i0, i0, i1, i1, i2, i2, i3, i3 );
}

/* No general vf_permute due to cross-128-bit lane limitations in AVX.
   Useful cases are provided below.  Given [ i0 i1 i2 i3 i4 i5 i6 i7 ],
   return ... */

#define wi_bcast_even(x)      /* [ i0 i0 i2 i2 i4 i4 i6 i6 ] */ \
  _mm256_castps_si256( _mm256_permute_ps( _mm256_castsi256_ps( (x) ), _MM_SHUFFLE(2,2,0,0) ) )

#define wi_bcast_odd(x)       /* [ i1 i1 i3 i3 i5 i5 i7 i7 ] */ \
  _mm256_castps_si256( _mm256_permute_ps( _mm256_castsi256_ps( (x) ), _MM_SHUFFLE(3,3,1,1) ) )

#define wi_exch_adj(x)        /* [ i1 i0 i3 i2 i5 i4 i7 i6 ] */ \
  _mm256_castps_si256( _mm256_permute_ps( _mm256_castsi256_ps( (x) ), _MM_SHUFFLE(2,3,0,1) ) )

#define wi_exch_adj_pair(x)   /* [ i2 i3 i0 i1 i6 i7 i4 i5 ] */ \
  _mm256_castps_si256( _mm256_permute_ps( _mm256_castsi256_ps( (x) ), _MM_SHUFFLE(1,0,3,2) ) )

static inline wi_t
wi_exch_adj_quad( wi_t x ) { /* [ i4 i5 i6 i7 i0 i1 i2 i3 ] */
  return _mm256_permute2f128_si256( x, x, 1 );
}

/* Predefined constants */

#define wi_zero() _mm256_setzero_si256() /* Return [ 0 0 0 0 0 0 0 0 ] */
#define wi_one()  _mm256_set1_epi32( 1 ) /* Return [ 1 1 1 1 1 1 1 1 ] */

/* Memory operations */

/* wi_ld return the 8 ints at the 32-byte aligned / 32-byte sized
   location p as a vector int.  wi_ldu is the same but p does not have
   to be aligned.  wi_st writes the vector int to the 32-byte aligned /
   32-byte sized location p as 8 ints.  wi_stu is the same but p does
   not have to be aligned.  In all these lane l will be at p[l].  FIXME:
   USE ATTRIBUTES ON P PASSED TO THESE?

   Note: gcc knows a __m256i may alias. */

static inline wi_t wi_ld( int const * p ) { return _mm256_load_si256(  (__m256i const *)p ); }
static inline void wi_st( int * p, wi_t i ) { _mm256_store_si256(  (__m256i *)p, i ); }

static inline wi_t wi_ldu( void const * p ) { return _mm256_loadu_si256( (__m256i const *)p ); }
static inline void wi_stu( void * p, wi_t i ) { _mm256_storeu_si256( (__m256i *)p, i ); }

/* wi_ldif is an optimized equivalent to wi_notczero(c,wi_ldu(p)) (may
   have different behavior if c is not a proper vector conditional).  It
   is provided for symmetry with the wi_stif operation.  wi_stif stores
   x(n) to p[n] if c(n) is true and leaves p[n] unchanged otherwise.
   Undefined behavior if c is not a proper vector conditional. */

#define wi_ldif(c,p)   _mm256_maskload_epi32( (p),(c))
#define wi_stif(c,p,x) _mm256_maskstore_epi32((p),(c),(x))

/* Element operations */

/* wi_extract extracts the int in lane imm from the vector int as an int.
   wi_insert returns the vector int formed by replacing the value in
   lane imm of a with the provided int.  imm should be a compile time
   constant in 0:7.  wi_extract_variable and wi_insert_variable are the
   slower but the lane n does not have to be known at compile time
   (should still be in 0:7).

   Note: C99 TC3 allows type punning through a union. */

#define wi_extract(a,imm)  _mm256_extract_epi32( (a), (imm) )
#define wi_insert(a,imm,v) _mm256_insert_epi32( (a), (v), (imm) )

static inline int
wi_extract_variable( wi_t a, int n ) {
  union { __m256i m[1]; int i[8]; } t[1];
  _mm256_store_si256( t->m, a );
  return t->i[n];
}

static inline wi_t
wi_insert_variable( wi_t a, int n, int v ) {
  union { __m256i m[1]; int i[8]; } t[1];
  _mm256_store_si256( t->m, a );
  t->i[n] = v;
  return _mm256_load_si256( t->m );
}

/* Given [a0 a1 a2 a3 a4 a5 a6 a7] and/or [b0 b1 b2 b3 b4 b5 b6 b7],
   return ... */

/* Arithmetic operations */

#define wi_neg(a) _mm256_sub_epi32( _mm256_setzero_si256(), (a) ) /* [ -a0  -a1  ... -a7  ] (twos complement handling) */
#define wi_abs(a) _mm256_abs_epi32( (a) )                         /* [ |a0| |a1| ... |a7| ] (twos complement handling) */

#define wi_min(a,b) _mm256_min_epi32(   (a), (b) ) /* [ min(a0,b0) min(a1,b1) ... min(a7,b7) ] */
#define wi_max(a,b) _mm256_max_epi32(   (a), (b) ) /* [ max(a0,b0) max(a1,b1) ... max(a7,b7) ] */
#define wi_add(a,b) _mm256_add_epi32(   (a), (b) ) /* [ a0 +b0     a1 +b1     ... a7 +b7     ] */
#define wi_sub(a,b) _mm256_sub_epi32(   (a), (b) ) /* [ a0 -b0     a1 -b1     ... a7 -b7     ] */
#define wi_mul(a,b) _mm256_mullo_epi32( (a), (b) ) /* [ a0 *b0     a1 *b1     ... a7 *b7     ] */

/* Binary operations */

/* Note: wi_shl/wi_shr/wi_shru is a left/signed right/unsigned right
   shift by imm bits; imm must be a compile time constant in 0:63.  The
   variable variants are slower but do not require the shift amount to
   be known at compile time (should still be in 0:63). */

#define wi_not(a) _mm256_xor_si256( _mm256_set1_epi32( -1 ), (a) ) /* [ ~a0 ~a1 ... ~a7 ] */

#define wi_shl(a,imm)  _mm256_slli_epi32( (a), (imm) ) /* [ a0<<imm a1<<imm ... a7<<imm ] */
#define wi_shr(a,imm)  _mm256_srai_epi32( (a), (imm) ) /* [ a0>>imm a1>>imm ... a7>>imm ] (treat a as signed)*/
#define wi_shru(a,imm) _mm256_srli_epi32( (a), (imm) ) /* [ a0>>imm a1>>imm ... a7>>imm ] (treat a as unsigned) */

#define wi_shl_variable(a,n)  _mm256_sll_epi32( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
#define wi_shr_variable(a,n)  _mm256_sra_epi32( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
#define wi_shru_variable(a,n) _mm256_srl_epi32( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )

#define wi_shl_vector(a,b)  _mm256_sllv_epi32( (a), (b) ) /* [ a0<<b0 a1<<b1 ... a7<<b7 ] */
#define wi_shr_vector(a,b)  _mm256_srav_epi32( (a), (b) ) /* [ a0>>b0 a1>>b1 ... a7>>b7 ] (treat a as signed) */
#define wi_shru_vector(a,b) _mm256_srlv_epi32( (a), (b) ) /* [ a0>>b0 a1>>b1 ... a7>>b7 ] (treat a as unsigned) */

#define wi_and(a,b)    _mm256_and_si256(    (a), (b) ) /* [   a0 &b0    a1& b1 ...   a7& b7 ] */
#define wi_andnot(a,b) _mm256_andnot_si256( (a), (b) ) /* [ (~a0)&b0  (~a1)&b1 ... (~a7)&b7 ] */
#define wi_or(a,b)     _mm256_or_si256(     (a), (b) ) /* [   a0 |b0    a1 |b1 ...   a7 |b7 ] */
#define wi_xor(a,b)    _mm256_xor_si256(    (a), (b) ) /* [   a0 ^b0    a1 ^b1 ...   a7 ^b7 ] */

static inline wi_t wi_rol( wi_t a, int imm ) { return wi_or( wi_shl(  a, imm & 31 ), wi_shru( a, (-imm) & 31 ) ); }
static inline wi_t wi_ror( wi_t a, int imm ) { return wi_or( wi_shru( a, imm & 31 ), wi_shl(  a, (-imm) & 31 ) ); }

static inline wi_t wi_rol_variable( wi_t a, int n ) { return wi_or( wi_shl_variable(  a, n&31 ), wi_shru_variable( a, (-n)&31 ) ); }
static inline wi_t wi_ror_variable( wi_t a, int n ) { return wi_or( wi_shru_variable( a, n&31 ), wi_shl_variable(  a, (-n)&31 ) ); }

static inline wi_t wi_rol_vector( wi_t a, wi_t b ) {
  wi_t m = wi_bcast( 31 );
  return wi_or( wi_shl_vector(  a, wi_and( b, m ) ), wi_shru_vector( a, wi_and( wi_neg( b ), m ) ) );
}

static inline wi_t wi_ror_vector( wi_t a, wi_t b ) {
  wi_t m = wi_bcast( 31 );
  return wi_or( wi_shru_vector( a, wi_and( b, m ) ), wi_shl_vector(  a, wi_and( wi_neg( b ), m ) ) );
}

/* Logical operations */

#define wi_lnot(a)    _mm256_cmpeq_epi32( (a), _mm256_setzero_si256() ) /* [  !a0  !a1 ...  !a7 ] */
#define wi_lnotnot(a)                                                   /* [ !!a0 !!a1 ... !!a7 ] */ \
  _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_cmpeq_epi32( (a), _mm256_setzero_si256() ) )

#define wi_eq(a,b) _mm256_cmpeq_epi32( (a), (b) )                                              /* [ a0==b0 a1==b1 ... a7==b7 ] */
#define wi_gt(a,b) _mm256_cmpgt_epi32( (a), (b) )                                              /* [ a0> b0 a1> b1 ... a7> b7 ] */
#define wi_lt(a,b) _mm256_cmpgt_epi32( (b), (a) )                                              /* [ a0< b0 a1< b1 ... a7< b7 ] */
#define wi_ne(a,b) _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_cmpeq_epi32( (a), (b) ) ) /* [ a0!=b0 a1!=b1 ... a7!=b7 ] */
#define wi_ge(a,b) _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_cmpgt_epi32( (b), (a) ) ) /* [ a0>=b0 a1>=b1 ... a7>=b7 ] */
#define wi_le(a,b) _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_cmpgt_epi32( (a), (b) ) ) /* [ a0<=b0 a1<=b1 ... a7<=b7 ] */

/* Conditional operations */

#define wi_czero(c,f)    _mm256_andnot_si256( (c), (f) ) /* [ c0? 0:f0 c1? 0:f1 ... c7? 0:f7 ] */
#define wi_notczero(c,f) _mm256_and_si256(    (c), (f) ) /* [ c0?f0: 0 c1?f1: 0 ... c7?f7: 0 ] */

#define wi_if(c,t,f) _mm256_blendv_epi8(  (f), (t), (c) ) /* [ c0?t0:f0 c1?t1:f1 ... c7?t7:f7 ] */

/* Conversion operations */

/* Summarizing:

   wi_to_wc(a)   returns [ !!a0 !!a1 ... !!a7 ]

   wi_to_wu(a)   returns [ (uint)a0 (uint)a1 ... (uint)a7 ]

   wi_to_wf(a)   returns [ (float)a0 (float)a1 ... (float)a7 ]

   wi_to_wd(a,0) returns [ (double)a0 (double)a1 (double)a2 (double)a3 ]
   wi_to_wd(a,1) returns [ (double)a4 (double)a5 (double)a6 (double)a7 ]

   wi_to_wl(a,0) returns [ (long)a0   (long)a1   (long)a2   (long)a3   ]
   wi_to_wl(a,1) returns [ (long)a4   (long)a5   (long)a6   (long)a7   ]

   wi_to_wv(a,0) returns [ (ulong)a0  (ulong)a1  (ulong)a2  (ulong)a3  ]
   wi_to_wv(a,1) returns [ (ulong)a4  (ulong)a5  (ulong)a6  (ulong)a7  ]

   where imm_hi should be a compile time constant.

   For wi_to_{wd,wl}, the permutation used for the conversion is less
   flexible due to cross 128-bit lane limitations in AVX.  If imm_hi==0,
   the conversion is done to lanes 0:3.  Otherwise, the conversion is
   done to lanes 4:7.

   The raw variants just treat the raw bits as the corresponding vector
   type.  For wi_to_wc_raw, the user promises wi contains a proper
   vector conditional (e.g. 0 or -1 in each lane).  wi_to_wf_raw is
   useful for doing advanced bit tricks on floating point values.  The
   others are probably dubious but are provided for completness. */

#define wi_to_wc(a)        _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_cmpeq_epi32( (a), _mm256_setzero_si256() ) )
#define wi_to_wf(a)        _mm256_cvtepi32_ps( (a) )
#define wi_to_wu(a)        (a)
#define wi_to_wd(a,imm_hi) _mm256_cvtepi32_pd(    _mm256_extractf128_si256( (a), !!(imm_hi) ) )
#define wi_to_wl(a,imm_hi) _mm256_cvtepi32_epi64( _mm256_extractf128_si256( (a), !!(imm_hi) ) )
#define wi_to_wv(a,imm_hi) _mm256_cvtepi32_epi64( _mm256_extractf128_si256( (a), !!(imm_hi) ) )

#define wi_to_wc_raw(a) (a)
#define wi_to_wf_raw(a) _mm256_castsi256_ps( (a) )
#define wi_to_wu_raw(a) (a)
#define wi_to_wd_raw(a) _mm256_castsi256_pd( (a) )
#define wi_to_wl_raw(a) (a)
#define wi_to_wv_raw(a) (a)

/* Reduction operations */

static inline wi_t
wi_sum_all( wi_t x ) { /* Returns wi_bcast( sum( x ) ) */
  x = _mm256_add_epi32( x, _mm256_permute2f128_si256( x, x, 1 ) ); /* x04   x15   x26   x37   ... */
  x = _mm256_hadd_epi32( x, x );                                   /* x0145 x2367 ... */
  return _mm256_hadd_epi32( x, x );                                /* xsum  ... */
}

static inline wi_t
wi_min_all( wi_t x ) { /* Returns wi_bcast( min( x ) ) */
  __m256i y = _mm256_permute2f128_si256( x, x, 1 );         /* x4    x5    x6   x7    x0    x1   x2    x3   */
  x = _mm256_min_epi32( x, y );                             /* x04   x15   x26  x37   ... */
  y = _mm256_shuffle_epi32( x, _MM_SHUFFLE( 1, 0, 3, 2 ) ); /* x26   x37   x04  x15   ... */
  x = _mm256_min_epi32( x, y );                             /* x0246 x1357 ... */
  y = _mm256_shuffle_epi32( x, _MM_SHUFFLE( 2, 3, 0, 1 ) ); /* x1357 x0246 ... */
  x = _mm256_min_epi32( x, y );                             /* xmin  ... */
  return x;
}

static inline wi_t
wi_max_all( wi_t x ) { /* Returns wi_bcast( max( x ) ) */
  __m256i y = _mm256_permute2f128_si256( x, x, 1 );         /* x4    x5    x6   x7    x0    x1   x2    x3   */
  x = _mm256_max_epi32( x, y );                             /* x04   x15   x26  x37   ... */
  y = _mm256_shuffle_epi32( x, _MM_SHUFFLE( 1, 0, 3, 2 ) ); /* x26   x37   x04  x15   ... */
  x = _mm256_max_epi32( x, y );                             /* x0246 x1357 ... */
  y = _mm256_shuffle_epi32( x, _MM_SHUFFLE( 2, 3, 0, 1 ) ); /* x1357 x0246 ... */
  x = _mm256_max_epi32( x, y );                             /* xmax  ... */
  return x;
}

/* Misc operations */

/* wi_gather(b,i) returns [ b[i(0)] b[i(1)] ... b[i(7)] ] where b is a
   "int const *" and i is a wi_t. */

#define wi_gather(b,i) _mm256_i32gather_epi32( (b), (i), 4 )

/* wi_transpose_8x8 transposes the 8x8 matrix stored in wi_t r0,r1,...r7
   and stores the result in 8x8 matrix wi_t c0,c1,...c7.  All
   c0,c1,...c7 should be different for a well defined result.
   Otherwise, in-place operation and/or using the same wi_t to specify
   multiple rows of r is fine. */

#define wi_transpose_8x8( r0,r1,r2,r3,r4,r5,r6,r7, c0,c1,c2,c3,c4,c5,c6,c7 ) do {                                                 \
    wi_t _wi_transpose_r0 = (r0); wi_t _wi_transpose_r1 = (r1); wi_t _wi_transpose_r2 = (r2); wi_t _wi_transpose_r3 = (r3);       \
    wi_t _wi_transpose_r4 = (r4); wi_t _wi_transpose_r5 = (r5); wi_t _wi_transpose_r6 = (r6); wi_t _wi_transpose_r7 = (r7);       \
    wi_t _wi_transpose_t;                                                                                                         \
    /* Transpose 4x4 blocks */                                                                                                    \
    _wi_transpose_t = _wi_transpose_r0; _wi_transpose_r0 = _mm256_permute2f128_si256( _wi_transpose_t,  _wi_transpose_r4, 0x20 ); \
    /**/                                _wi_transpose_r4 = _mm256_permute2f128_si256( _wi_transpose_t,  _wi_transpose_r4, 0x31 ); \
    _wi_transpose_t = _wi_transpose_r1; _wi_transpose_r1 = _mm256_permute2f128_si256( _wi_transpose_t,  _wi_transpose_r5, 0x20 ); \
    /**/                                _wi_transpose_r5 = _mm256_permute2f128_si256( _wi_transpose_t,  _wi_transpose_r5, 0x31 ); \
    _wi_transpose_t = _wi_transpose_r2; _wi_transpose_r2 = _mm256_permute2f128_si256( _wi_transpose_t,  _wi_transpose_r6, 0x20 ); \
    /**/                                _wi_transpose_r6 = _mm256_permute2f128_si256( _wi_transpose_t,  _wi_transpose_r6, 0x31 ); \
    _wi_transpose_t = _wi_transpose_r3; _wi_transpose_r3 = _mm256_permute2f128_si256( _wi_transpose_t,  _wi_transpose_r7, 0x20 ); \
    /**/                                _wi_transpose_r7 = _mm256_permute2f128_si256( _wi_transpose_t,  _wi_transpose_r7, 0x31 ); \
    /* Transpose 2x2 blocks */                                                                                                    \
    _wi_transpose_t = _wi_transpose_r0; _wi_transpose_r0 = _mm256_unpacklo_epi32(     _wi_transpose_t,  _wi_transpose_r2 );       \
    /**/                                _wi_transpose_r2 = _mm256_unpackhi_epi32(     _wi_transpose_t,  _wi_transpose_r2 );       \
    _wi_transpose_t = _wi_transpose_r1; _wi_transpose_r1 = _mm256_unpacklo_epi32(     _wi_transpose_t,  _wi_transpose_r3 );       \
    /**/                                _wi_transpose_r3 = _mm256_unpackhi_epi32(     _wi_transpose_t,  _wi_transpose_r3 );       \
    _wi_transpose_t = _wi_transpose_r4; _wi_transpose_r4 = _mm256_unpacklo_epi32(     _wi_transpose_t,  _wi_transpose_r6 );       \
    /**/                                _wi_transpose_r6 = _mm256_unpackhi_epi32(     _wi_transpose_t,  _wi_transpose_r6 );       \
    _wi_transpose_t = _wi_transpose_r5; _wi_transpose_r5 = _mm256_unpacklo_epi32(     _wi_transpose_t,  _wi_transpose_r7 );       \
    /**/                                _wi_transpose_r7 = _mm256_unpackhi_epi32(     _wi_transpose_t,  _wi_transpose_r7 );       \
    /* Transpose 1x1 blocks */                                                                                                    \
    /**/                                (c0)             = _mm256_unpacklo_epi32(     _wi_transpose_r0, _wi_transpose_r1 );       \
    /**/                                (c1)             = _mm256_unpackhi_epi32(     _wi_transpose_r0, _wi_transpose_r1 );       \
    /**/                                (c2)             = _mm256_unpacklo_epi32(     _wi_transpose_r2, _wi_transpose_r3 );       \
    /**/                                (c3)             = _mm256_unpackhi_epi32(     _wi_transpose_r2, _wi_transpose_r3 );       \
    /**/                                (c4)             = _mm256_unpacklo_epi32(     _wi_transpose_r4, _wi_transpose_r5 );       \
    /**/                                (c5)             = _mm256_unpackhi_epi32(     _wi_transpose_r4, _wi_transpose_r5 );       \
    /**/                                (c6)             = _mm256_unpacklo_epi32(     _wi_transpose_r6, _wi_transpose_r7 );       \
    /**/                                (c7)             = _mm256_unpackhi_epi32(     _wi_transpose_r6, _wi_transpose_r7 );       \
  } while(0)
