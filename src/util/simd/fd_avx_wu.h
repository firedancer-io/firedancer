#ifndef HEADER_fd_src_util_simd_fd_avx_h
#error "Do not include this directly; use fd_avx.h"
#endif

/* Vector uint API ****************************************************/

/* A wu_t is a vector where each 32-bit wide lane holds an unsigned
   32-bit integer (a "uint").  These mirror wc and wf as much as
   possible.

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wu_t __m256i

/* Constructors */

/* Given the uint values, return ... */

#define wu(u0,u1,u2,u3,u4,u5,u6,u7) /* [ u0 u1 u2 u3 u4 u5 u6 u7 ] */ \
  _mm256_setr_epi32( (int)(u0), (int)(u1), (int)(u2), (int)(u3), (int)(u4), (int)(u5), (int)(u6), (int)(u7) )

#define wu_bcast(u0) _mm256_set1_epi32( (int)(u0) ) /* [ u0 u0 u0 u0 u0 u0 u0 u0 ] */

static inline wu_t /* [ u0 u1 u0 u1 u0 u1 u0 u1 ] */
wu_bcast_pair( uint u0, uint u1 ) {
  int i0 = (int)u0; int i1 = (int)u1;
  return _mm256_setr_epi32( i0, i1, i0, i1, i0, i1, i0, i1 );
}

static inline wu_t /* [ u0 u0 u0 u0 u1 u1 u1 u1 ] */
wu_bcast_lohi( uint u0, uint u1 ) {
  int i0 = (int)u0; int i1 = (int)u1;
  return _mm256_setr_epi32( i0, i0, i0, i0, i1, i1, i1, i1 );
}

static inline wu_t /* [ u0 u1 u2 u3 u0 u1 u2 u3 ] */
wu_bcast_quad( uint u0, uint u1, uint u2, uint u3 ) {
  int i0 = (int)u0; int i1 = (int)u1; int i2 = (int)u2; int i3 = (int)u3;
  return _mm256_setr_epi32( i0, i1, i2, i3, i0, i1, i2, i3 );
}

static inline wu_t /* [ u0 u0 u1 u1 u2 u2 u3 u3 ] */
wu_bcast_wide( uint u0, uint u1, uint u2, uint u3 ) {
  int i0 = (int)u0; int i1 = (int)u1; int i2 = (int)u2; int i3 = (int)u3;
  return _mm256_setr_epi32( i0, i0, i1, i1, i2, i2, i3, i3 );
}

/* No general wu_permute due to cross-128-bit lane limitations in AVX.
   Useful cases are provided below.  Given [ u0 u1 u2 u3 u4 u5 u6 u7 ],
   return ... */

#define wu_bcast_even(x)      /* [ u0 u0 u2 u2 u4 u4 u6 u6 ] */ \
  _mm256_castps_si256( _mm256_permute_ps( _mm256_castsi256_ps( (x) ), _MM_SHUFFLE(2,2,0,0) ) )

#define wu_bcast_odd(x)       /* [ u1 u1 u3 u3 u5 u5 u7 u7 ] */ \
  _mm256_castps_si256( _mm256_permute_ps( _mm256_castsi256_ps( (x) ), _MM_SHUFFLE(3,3,1,1) ) )

#define wu_exch_adj(x)        /* [ u1 u0 u3 u2 u5 u4 u7 u6 ] */ \
  _mm256_castps_si256( _mm256_permute_ps( _mm256_castsi256_ps( (x) ), _MM_SHUFFLE(2,3,0,1) ) )

#define wu_exch_adj_pair(x)   /* [ u2 u3 u0 u1 u6 u7 u4 u5 ] */ \
  _mm256_castps_si256( _mm256_permute_ps( _mm256_castsi256_ps( (x) ), _MM_SHUFFLE(1,0,3,2) ) )

static inline wu_t
wu_exch_adj_quad( wu_t x ) { /* [ u4 u5 u6 u7 u0 u1 u2 u3 ] */
  return _mm256_permute2f128_si256( x, x, 1 );
}

/* Predefined constants */

#define wu_zero() _mm256_setzero_si256() /* Return [ 0U 0U 0U 0U 0U 0U 0U 0U ] */
#define wu_one()  _mm256_set1_epi32( 1 ) /* Return [ 1U 1U 1U 1U 1U 1U 1U 1U ] */

/* Memory operations */

/* wu_ld return the 8 uints at the 32-byte aligned / 32-byte sized
   location p as a vector uint.  wu_ldu is the same but p does not have
   to be aligned.  wu_st writes the vector uint to the 32-byte aligned /
   32-byte sized location p as 8 uints.  wu_stu is the same but p does
   not have to be aligned.  In all these lane l will be at p[l].  FIXME:
   USE ATTRIBUTES ON P PASSED TO THESE?

   Note: gcc knows a __m256i may alias. */

static inline wu_t wu_ld( uint const * p ) { return _mm256_load_si256(  (__m256i const *)p ); }
static inline void wu_st( uint * p, wu_t i ) { _mm256_store_si256(  (__m256i *)p, i ); }

static inline wu_t wu_ldu( void const * p ) { return _mm256_loadu_si256( (__m256i const *)p ); }
static inline void wu_stu( void * p, wu_t i ) { _mm256_storeu_si256( (__m256i *)p, i ); }

/* wu_ldif is an optimized equivalent to wu_notczero(c,wu_ldu(p)) (may
   have different behavior if c is not a proper vector conditional).  It
   is provided for symmetry with the wu_stif operation.  wu_stif stores
   x(n) to p[n] if c(n) is true and leaves p[n] unchanged otherwise.
   Undefined behavior if c is not a proper vector conditional. */

#define wu_ldif(c,p)   _mm256_maskload_epi32( (p),(c))
#define wu_stif(c,p,x) _mm256_maskstore_epi32((p),(c),(x))

/* Element operations */

/* wu_extract extracts the uint in lane imm from the vector uint.
   wu_insert returns the vector uint formed by replacing the value in
   lane imm of a with the provided uint.  imm should be a compile time
   constant in 0:7.  wu_extract_variable and wu_insert_variable are the
   slower but the lane n does not have to be known at compile time
   (should still be in 0:7).

   Note: C99 TC3 allows type punning through a union. */

#define wu_extract(a,imm)  ((uint)_mm256_extract_epi32( (a), (imm) ))
#define wu_insert(a,imm,v) _mm256_insert_epi32( (a), (int)(v), (imm) )

static inline uint
wu_extract_variable( wu_t a, int n ) {
  union { __m256i m[1]; uint u[8]; } t[1];
  _mm256_store_si256( t->m, a );
  return t->u[n];
}

static inline wu_t
wu_insert_variable( wu_t a, int n, uint v ) {
  union { __m256i m[1]; uint u[8]; } t[1];
  _mm256_store_si256( t->m, a );
  t->u[n] = v;
  return _mm256_load_si256( t->m );
}

/* Given [a0 a1 a2 a3 a4 a5 a6 a7] and/or [b0 b1 b2 b3 b4 b5 b6 b7],
   return ... */

/* Arithmetic operations */

#define wu_neg(a) _mm256_sub_epi32( _mm256_setzero_si256(), (a) ) /* [ -a0  -a1  ... -a7  ] (twos complement handling) */
#define wu_abs(a) (a)                                             /* [ |a0| |a1| ... |a7| ] (twos complement handling) */

#define wu_min(a,b) _mm256_min_epu32(   (a), (b) ) /* [ min(a0,b0) min(a1,b1) ... min(a7,b7) ] */
#define wu_max(a,b) _mm256_max_epu32(   (a), (b) ) /* [ max(a0,b0) max(a1,b1) ... max(a7,b7) ] */
#define wu_add(a,b) _mm256_add_epi32(   (a), (b) ) /* [ a0 +b0     a1 +b1     ... a7 +b7     ] */
#define wu_sub(a,b) _mm256_sub_epi32(   (a), (b) ) /* [ a0 -b0     a1 -b1     ... a7 -b7     ] */
#define wu_mul(a,b) _mm256_mullo_epi32( (a), (b) ) /* [ a0 *b0     a1 *b1     ... a7 *b7     ] */

/* Binary operations */

/* Note: wu_shl/wu_shr is an unsigned left/right shift by imm bits; imm
   must be a compile time constant in 0:63.  The variable variants are
   slower but do not require the shift amount to be known at compile
   time (should still be in 0:63). */

#define wu_not(a) _mm256_xor_si256( _mm256_set1_epi32( -1 ), (a) ) /* [ ~a0 ~a1 ... ~a7 ] */

#define wu_shl(a,imm)  _mm256_slli_epi32( (a), (imm) ) /* [ a0<<imm a1<<imm ... a7<<imm ] */
#define wu_shr(a,imm)  _mm256_srli_epi32( (a), (imm) ) /* [ a0>>imm a1>>imm ... a7>>imm ] */

#define wu_shl_variable(a,n) _mm256_sll_epi32( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
#define wu_shr_variable(a,n) _mm256_srl_epi32( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )

#define wu_shl_vector(a,b)   _mm256_sllv_epi32( (a), (b) ) /* [ a0<<b0 a1<<b1 ... a7<<b7 ] */
#define wu_shr_vector(a,b)   _mm256_srlv_epi32( (a), (b) ) /* [ a0>>b0 a1>>b1 ... a7>>b7 ] */

#define wu_and(a,b)    _mm256_and_si256(    (a), (b) ) /* [   a0 &b0    a1& b1 ...   a7& b7 ] */
#define wu_andnot(a,b) _mm256_andnot_si256( (a), (b) ) /* [ (~a0)&b0  (~a1)&b1 ... (~a7)&b7 ] */
#define wu_or(a,b)     _mm256_or_si256(     (a), (b) ) /* [   a0 |b0    a1 |b1 ...   a7 |b7 ] */
#define wu_xor(a,b)    _mm256_xor_si256(    (a), (b) ) /* [   a0 ^b0    a1 ^b1 ...   a7 ^b7 ] */

/* wu_rol(x,n) returns wu( rotate_left (x0,n), rotate_left (x1,n), ... )
   wu_ror(x,n) returns wu( rotate_right(x0,n), rotate_right(x1,n), ... ) */

#if FD_HAS_AVX512
#define wu_rol(a,imm)  _mm256_rol_epi32( (a), (imm) )
#define wu_ror(a,imm)  _mm256_ror_epi32( (a), (imm) )
#else
static inline wu_t wu_rol( wu_t a, int imm ) { return wu_or( wu_shl( a, imm & 31 ), wu_shr( a, (-imm) & 31 ) ); }
static inline wu_t wu_ror( wu_t a, int imm ) { return wu_or( wu_shr( a, imm & 31 ), wu_shl( a, (-imm) & 31 ) ); }
#endif

static inline wu_t wu_rol_variable( wu_t a, int n ) { return wu_or( wu_shl_variable( a, n&31 ), wu_shr_variable( a, (-n)&31 ) ); }
static inline wu_t wu_ror_variable( wu_t a, int n ) { return wu_or( wu_shr_variable( a, n&31 ), wu_shl_variable( a, (-n)&31 ) ); }

static inline wu_t wu_rol_vector( wu_t a, wi_t b ) {
  wi_t m = wi_bcast( 31 );
  return wu_or( wu_shl_vector( a, wi_and( b, m ) ), wu_shr_vector( a, wi_and( wi_neg( b ), m ) ) );
}

static inline wu_t wu_ror_vector( wu_t a, wi_t b ) {
  wi_t m = wi_bcast( 31 );
  return wu_or( wu_shr_vector( a, wi_and( b, m ) ), wu_shl_vector( a, wi_and( wi_neg( b ), m ) ) );
}

static inline wu_t wu_bswap( wu_t a ) {
  wu_t m = wu_bcast( 0x00FF00FFU );                                            /* Probably hoisted */
  wu_t t = wu_rol( a, 16 );                                                    /* Swap E/O 16-bit pairs */
  return wu_or( wu_andnot( m, wu_shl( t, 8 ) ), wu_and( m, wu_shr( t, 8 ) ) ); /* Swap E/O  8-bit pairs */
}

/* Logical operations */

/* Like noted below in the wu_to_{wf,wd} converters, Intel clearly has
   the hardware to do a _mm256_cmpgt_epu32 given that _mm256_cmpgt_epi32
   exists but doesn't expose it in the ISA pre AVX-512.  Sigh ... twos
   complement bit tricks to the rescue for wu_{gt,lt,ge,le}. */

#define wu_lnot(a)    _mm256_cmpeq_epi32( (a), _mm256_setzero_si256() ) /* [  !a0  !a1 ...  !a7 ] */
#define wu_lnotnot(a)                                                   /* [ !!a0 !!a1 ... !!a7 ] */ \
  _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_cmpeq_epi32( (a), _mm256_setzero_si256() ) )

#define wu_eq(a,b) _mm256_cmpeq_epi32( (a), (b) )                                              /* [ a0==b0 a1==b1 ... a7==b7 ] */
#define wu_gt(a,b)                                                                             /* [ a0> b0 a1> b1 ... a7> b7 ] */ \
  _mm256_cmpgt_epi32( _mm256_sub_epi32( (a), _mm256_set1_epi32( (int)(1U<<31) ) ),                                                \
                      _mm256_sub_epi32( (b), _mm256_set1_epi32( (int)(1U<<31) ) ) )
#define wu_lt(a,b) wu_gt( (b), (a) )                                                           /* [ a0< b0 a1< b1 ... a7< b7 ] */
#define wu_ne(a,b) _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_cmpeq_epi32( (a), (b) ) ) /* [ a0!=b0 a1!=b1 ... a7!=b7 ] */
#define wu_ge(a,b) _mm256_xor_si256( _mm256_set1_epi32( -1 ), wu_gt( (b), (a) ) )              /* [ a0>=b0 a1>=b1 ... a7>=b7 ] */
#define wu_le(a,b) _mm256_xor_si256( _mm256_set1_epi32( -1 ), wu_gt( (a), (b) ) )              /* [ a0<=b0 a1<=b1 ... a7<=b7 ] */

/* Conditional operations */

#define wu_czero(c,f)    _mm256_andnot_si256( (c), (f) ) /* [ c0?0U:f0 c1?0U:f1 ... c7?0U:f7 ] */
#define wu_notczero(c,f) _mm256_and_si256(    (c), (f) ) /* [ c0?f0:0U c1?f1:0U ... c7?f7:0U ] */

#define wu_if(c,t,f) _mm256_blendv_epi8( (f), (t), (c) ) /* [ c0?t0:f0 c1?t1:f1 ... c7?t7:f7 ] */

/* Conversion operations */

/* Summarizing:

   wu_to_wc(a)   returns [ !!a0 !!a1 ... !!a7 ]

   wu_to_wf(a)   returns [ (float)a0 (float)a1 ... (float)a7 ]

   wu_to_wi(a)   returns [ (int)a0 (int)a1 ... (int)a7 ]

   wu_to_wd(a,0) returns [ (double)a0 (double)a1 (double)a2 (double)a3 ]
   wu_to_wd(a,1) returns [ (double)a4 (double)a5 (double)a6 (double)a7 ]

   wu_to_wl(a,0) returns [ (long)a0   (long)a1   (long)a2   (long)a3   ]
   wu_to_wl(a,1) returns [ (long)a4   (long)a5   (long)a6   (long)a7   ]

   wu_to_wv(a,0) returns [ (ulong)a0  (ulong)a1  (ulong)a2  (ulong)a3  ]
   wu_to_wv(a,1) returns [ (ulong)a4  (ulong)a5  (ulong)a6  (ulong)a7  ]

   where imm_hi should be a compile time constant.

   For wu_to_{wd,wl}, the permutation used for the conversion is less
   flexible due to cross 128-bit lane limitations in AVX.  If imm_hi==0,
   the conversion is done to lanes 0:3.  Otherwise, the conversion is
   done to lanes 4:7.

   The raw variants just treat the raw bits as the corresponding vector
   type.  For wu_to_wc_raw, the user promises wu contains a proper
   vector conditional (e.g. 0 or -1 in each lane).  wu_to_wf_raw is
   useful for doing advanced bit tricks on floating point values.  The
   others are probably dubious but are provided for completness. */

#define wu_to_wc(a) _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_cmpeq_epi32( (a), _mm256_setzero_si256() ) )

#define wu_to_wi(a) (a)

static inline __m256d wu_to_wd( wu_t u, int imm_hi ) { /* FIXME: workaround wd_t isn't declared at this point */

  /* Note: Given that _mm256_cvtepi32_pd exists, Intel clearly has the
     hardware under the hood to support a _mm256_cvtepu32_pd but didn't
     bother to expose it pre AVX-512 ... sigh (all too typical
     unfortunately).  We can do a mix of twos complement and floating
     point hacks to emulate it without spilling. */

  __m128i i  = imm_hi ? _mm256_extractf128_si256( u, 1 ) : _mm256_extractf128_si256( u, 0 ); // u      if u<2^31, u-2^32 o.w
  __m128i c  = _mm_cmpgt_epi32( _mm_setzero_si128(), i );                                    // 0      if u<2^31, -1     o.w
  __m256d d  = _mm256_cvtepi32_pd( i );                                                      // u      if u<2^31, u-2^32 o.w, exact
  __m256d ds = _mm256_add_pd( d, _mm256_set1_pd( (double)(1UL<<32) ) );                      // u+2^32 if u<2^31, u      o.w, exact
  __m256i cl = _mm256_cvtepi32_epi64( c );                                                   // 0L     if u<2^31, -1L    o.w
  return _mm256_blendv_pd( d, ds, _mm256_castsi256_pd( cl ) );                               // u
}

static inline wf_t wu_to_wf( wu_t a ) {

  /* See note above re ISA dubiousness.  Note that we can't do the same
     trick as wu_to_wd due to single precision roundoff limitations (the
     _mm256_cvtepi32_pd equivalent would not be exact such that add to
     correct the twos complement mangling would add a possible second
     roundoff error ... this would result in slightly different values
     occasionally when u is >~ 2^31).  We instead convert the two
     halves to double (exact), convert the double to float (single
     roundoff error) and then concat the two float halves to make a
     correctly rounded implementation. */

  return _mm256_setr_m128( _mm256_cvtpd_ps( wu_to_wd( a, 0 ) ), _mm256_cvtpd_ps( wu_to_wd( a, 1 ) ) );
}

#define wu_to_wl(a,imm_hi) _mm256_cvtepu32_epi64( _mm256_extractf128_si256( (a), !!(imm_hi) ) )
#define wu_to_wv(a,imm_hi) _mm256_cvtepu32_epi64( _mm256_extractf128_si256( (a), !!(imm_hi) ) )

#define wu_to_wc_raw(a) (a)
#define wu_to_wf_raw(a) _mm256_castsi256_ps( (a) )
#define wu_to_wi_raw(a) (a)
#define wu_to_wd_raw(a) _mm256_castsi256_pd( (a) )
#define wu_to_wl_raw(a) (a)
#define wu_to_wv_raw(a) (a)

/* Reduction operations */

static inline wu_t
wu_sum_all( wu_t x ) { /* Returns wu_bcast( sum( x ) ) */
  x = _mm256_add_epi32( x, _mm256_permute2f128_si256( x, x, 1 ) ); /* x04   x15   x26   x37   ... */
  x = _mm256_hadd_epi32( x, x );                                   /* x0145 x2367 ... */
  return _mm256_hadd_epi32( x, x );                                /* xsum  ... */
}

static inline wu_t
wu_min_all( wu_t x ) { /* Returns wu_bcast( min( x ) ) */
  __m256i y = _mm256_permute2f128_si256( x, x, 1 );         /* x4    x5    x6   x7    x0    x1   x2    x3   */
  x = _mm256_min_epu32( x, y );                             /* x04   x15   x26  x37   ... */
  y = _mm256_shuffle_epi32( x, _MM_SHUFFLE( 1, 0, 3, 2 ) ); /* x26   x37   x04  x15   ... */
  x = _mm256_min_epu32( x, y );                             /* x0246 x1357 ... */
  y = _mm256_shuffle_epi32( x, _MM_SHUFFLE( 2, 3, 0, 1 ) ); /* x1357 x0246 ... */
  x = _mm256_min_epu32( x, y );                             /* xmin  ... */
  return x;
}

static inline wu_t
wu_max_all( wu_t x ) { /* Returns wu_bcast( max( x ) ) */
  __m256i y = _mm256_permute2f128_si256( x, x, 1 );         /* x4    x5    x6   x7    x0    x1   x2    x3   */
  x = _mm256_max_epu32( x, y );                             /* x04   x15   x26  x37   ... */
  y = _mm256_shuffle_epi32( x, _MM_SHUFFLE( 1, 0, 3, 2 ) ); /* x26   x37   x04  x15   ... */
  x = _mm256_max_epu32( x, y );                             /* x0246 x1357 ... */
  y = _mm256_shuffle_epi32( x, _MM_SHUFFLE( 2, 3, 0, 1 ) ); /* x1357 x0246 ... */
  x = _mm256_max_epu32( x, y );                             /* xmax  ... */
  return x;
}

/* Misc operations */

/* wu_gather(b,i) returns [ b[i(0)] b[i(1)] ... b[i(7)] ] where b is a
   "uint const *" and i is a wi_t.  We use a static inline here instead
   of a define to keep strict type checking while working around yet
   another Intel intrinsic type mismatch issue. */

static inline wu_t wu_gather( uint const * b, wi_t i ) {
  return _mm256_i32gather_epi32( (int const *)b, (i), 4 );
}

/* wu_transpose_8x8 transposes the 8x8 matrix stored in wu_t r0,r1,...r7
   and stores the result in 8x8 matrix wu_t c0,c1,...c7.  All
   c0,c1,...c7 should be different for a well defined result.
   Otherwise, in-place operation and/or using the same wu_t to specify
   multiple rows of r is fine. */

#define wu_transpose_8x8( r0,r1,r2,r3,r4,r5,r6,r7, c0,c1,c2,c3,c4,c5,c6,c7 ) do {                                                 \
    wu_t _wu_transpose_r0 = (r0); wu_t _wu_transpose_r1 = (r1); wu_t _wu_transpose_r2 = (r2); wu_t _wu_transpose_r3 = (r3);       \
    wu_t _wu_transpose_r4 = (r4); wu_t _wu_transpose_r5 = (r5); wu_t _wu_transpose_r6 = (r6); wu_t _wu_transpose_r7 = (r7);       \
    wu_t _wu_transpose_t;                                                                                                         \
    /* Transpose 4x4 blocks */                                                                                                    \
    _wu_transpose_t = _wu_transpose_r0; _wu_transpose_r0 = _mm256_permute2f128_si256( _wu_transpose_t,  _wu_transpose_r4, 0x20 ); \
    /**/                                _wu_transpose_r4 = _mm256_permute2f128_si256( _wu_transpose_t,  _wu_transpose_r4, 0x31 ); \
    _wu_transpose_t = _wu_transpose_r1; _wu_transpose_r1 = _mm256_permute2f128_si256( _wu_transpose_t,  _wu_transpose_r5, 0x20 ); \
    /**/                                _wu_transpose_r5 = _mm256_permute2f128_si256( _wu_transpose_t,  _wu_transpose_r5, 0x31 ); \
    _wu_transpose_t = _wu_transpose_r2; _wu_transpose_r2 = _mm256_permute2f128_si256( _wu_transpose_t,  _wu_transpose_r6, 0x20 ); \
    /**/                                _wu_transpose_r6 = _mm256_permute2f128_si256( _wu_transpose_t,  _wu_transpose_r6, 0x31 ); \
    _wu_transpose_t = _wu_transpose_r3; _wu_transpose_r3 = _mm256_permute2f128_si256( _wu_transpose_t,  _wu_transpose_r7, 0x20 ); \
    /**/                                _wu_transpose_r7 = _mm256_permute2f128_si256( _wu_transpose_t,  _wu_transpose_r7, 0x31 ); \
    /* Transpose 2x2 blocks */                                                                                                    \
    _wu_transpose_t = _wu_transpose_r0; _wu_transpose_r0 = _mm256_unpacklo_epi32(     _wu_transpose_t,  _wu_transpose_r2 );       \
    /**/                                _wu_transpose_r2 = _mm256_unpackhi_epi32(     _wu_transpose_t,  _wu_transpose_r2 );       \
    _wu_transpose_t = _wu_transpose_r1; _wu_transpose_r1 = _mm256_unpacklo_epi32(     _wu_transpose_t,  _wu_transpose_r3 );       \
    /**/                                _wu_transpose_r3 = _mm256_unpackhi_epi32(     _wu_transpose_t,  _wu_transpose_r3 );       \
    _wu_transpose_t = _wu_transpose_r4; _wu_transpose_r4 = _mm256_unpacklo_epi32(     _wu_transpose_t,  _wu_transpose_r6 );       \
    /**/                                _wu_transpose_r6 = _mm256_unpackhi_epi32(     _wu_transpose_t,  _wu_transpose_r6 );       \
    _wu_transpose_t = _wu_transpose_r5; _wu_transpose_r5 = _mm256_unpacklo_epi32(     _wu_transpose_t,  _wu_transpose_r7 );       \
    /**/                                _wu_transpose_r7 = _mm256_unpackhi_epi32(     _wu_transpose_t,  _wu_transpose_r7 );       \
    /* Transpose 1x1 blocks */                                                                                                    \
    /**/                                (c0)             = _mm256_unpacklo_epi32(     _wu_transpose_r0, _wu_transpose_r1 );       \
    /**/                                (c1)             = _mm256_unpackhi_epi32(     _wu_transpose_r0, _wu_transpose_r1 );       \
    /**/                                (c2)             = _mm256_unpacklo_epi32(     _wu_transpose_r2, _wu_transpose_r3 );       \
    /**/                                (c3)             = _mm256_unpackhi_epi32(     _wu_transpose_r2, _wu_transpose_r3 );       \
    /**/                                (c4)             = _mm256_unpacklo_epi32(     _wu_transpose_r4, _wu_transpose_r5 );       \
    /**/                                (c5)             = _mm256_unpackhi_epi32(     _wu_transpose_r4, _wu_transpose_r5 );       \
    /**/                                (c6)             = _mm256_unpacklo_epi32(     _wu_transpose_r6, _wu_transpose_r7 );       \
    /**/                                (c7)             = _mm256_unpackhi_epi32(     _wu_transpose_r6, _wu_transpose_r7 );       \
  } while(0)
