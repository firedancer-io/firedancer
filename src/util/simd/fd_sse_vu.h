#ifndef HEADER_fd_src_util_simd_fd_sse_h
#error "Do not include this directly; use fd_sse.h"
#endif

/* Vector uint API ****************************************************/

/* A vu_t is a vector where each 32-bit wide lane holds an unsigned
   32-bit integer (an "uint").  These mirror vc and vf as much as
   possible.

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define vu_t __m128i

/* Constructors */

/* Given the uint values, return ... */

#define vu(u0,u1,u2,u3) _mm_setr_epi32( (int)(u0), (int)(u1), (int)(u2), (int)(u3) ) /* [ u0 u1 u2 u3 ] */

#define vu_bcast(u0) _mm_set1_epi32( (int)(u0) ) /* [ u0 u0 u0 u0 ] */

static inline vu_t /* [ u0 u1 u0 u1 ] */
vu_bcast_pair( uint u0, uint u1 ) {
  int i0 = (int)u0; int i1 = (int)u1;
  return _mm_setr_epi32( i0, i1, i0, i1 );
}

static inline vu_t /* [ u0 u0 u1 u1 ] */
vu_bcast_wide( uint u0, uint u1 ) {
  int i0 = (int)u0; int i1 = (int)u1;
  return _mm_setr_epi32( i0, i0, i1, i1 );
}

/* vu_permute returns [ i(imm_i0) i(imm_i1) i(imm_i2) i(imm_i3) ].
   imm_i* should be compile time constants in 0:3. */

#define vu_permute(x,imm_i0,imm_i1,imm_i2,imm_i3) _mm_shuffle_epi32( (x), _MM_SHUFFLE( (imm_i3), (imm_i2), (imm_i1), (imm_i0) ) )

/* Predefined constants */

#define vu_zero() _mm_setzero_si128() /* Return [ 0U 0U 0U 0U ] */
#define vu_one()  _mm_set1_epi32( 1 ) /* Return [ 1U 1U 1U 1U ] */

/* Memory operations */

/* vu_ld return the 4 uints at the 16-byte aligned / 16-byte sized
   location p as a vector uint.  vu_ldu is the same but p does not have
   to be aligned.  vu_st writes the vector uint to the 16-byte aligned /
   16-byte sized location p as 4 uints.  vu_stu is the same but p does
   not have to be aligned.  In all these lane l will be at p[l].  FIXME:
   USE ATTRIBUTES ON P PASSED TO THESE?

   Note: gcc knows a __m128i may alias. */

static inline vu_t vu_ld( uint const * p ) { return _mm_load_si128(  (__m128i const *)p ); }
static inline void vu_st( uint * p, vu_t i ) { _mm_store_si128(  (__m128i *)p, i ); }

static inline vu_t vu_ldu( void const * p ) { return _mm_loadu_si128( (__m128i const *)p ); }
static inline void vu_stu( void * p, vu_t i ) { _mm_storeu_si128( (__m128i *)p, i ); }

/* vu_ldif is an optimized equivalent to vu_notczero(c,vu_ldu(p)) (may
   have different behavior if c is not a proper vector conditional).  It
   is provided for symmetry with the vu_stif operation.  vu_stif stores
   x(n) to p[n] if c(n) is true and leaves p[n] unchanged otherwise.
   Undefined behavior if c is not a proper vector conditional. */

#define vu_ldif(c,p)   _mm_maskload_epi32( (p),(c))
#define vu_stif(c,p,x) _mm_maskstore_epi32((p),(c),(x))

/* Element operations */

/* vu_extract extracts the uint in lane imm from the vector uint as an
   uint.  vu_insert returns the vector uint formed by replacing the
   value in lane imm of a with the provided uint.  imm should be a
   compile time constant in 0:3.  vu_extract_variable and
   vu_insert_variable are the slower but the lane n does not have to be
   known at compile time (should be in 0:3).

   Note: C99 TC3 allows type punning through a union. */

#define vu_extract(a,imm)  ((uint)_mm_extract_epi32( (a), (imm) ))
#define vu_insert(a,imm,v) _mm_insert_epi32( (a), (int)(v), (imm) )

static inline uint
vu_extract_variable( vu_t a, int n ) {
  union { __m128i m[1]; uint u[4]; } t[1];
  _mm_store_si128( t->m, a );
  return t->u[n];
}

static inline vu_t
vu_insert_variable( vu_t a, int n, uint v ) {
  union { __m128i m[1]; uint u[4]; } t[1];
  _mm_store_si128( t->m, a );
  t->u[n] = v;
  return _mm_load_si128( t->m );
}

/* Given [a0 a1 a2 a3] and/or [b0 b1 b2 b3], return ... */

/* Arithmetic operations */

#define vu_neg(a) _mm_sub_epi32( _mm_setzero_si128(), (a) ) /* [ -a0  -a1  ... -a3  ] (twos complement handling) */
#define vu_abs(a) (a)                                       /* [ |a0| |a1| ... |a3| ] (twos complement handling) */

#define vu_min(a,b) _mm_min_epu32(   (a), (b) ) /* [ min(a0,b0) min(a1,b1) ... min(a3,b3) ] */
#define vu_max(a,b) _mm_max_epu32(   (a), (b) ) /* [ max(a0,b0) max(a1,b1) ... max(a3,b3) ] */
#define vu_add(a,b) _mm_add_epi32(   (a), (b) ) /* [ a0 +b0     a1 +b1     ... a3 +b3     ] */
#define vu_sub(a,b) _mm_sub_epi32(   (a), (b) ) /* [ a0 -b0     a1 -b1     ... a3 -b3     ] */
#define vu_mul(a,b) _mm_mullo_epi32( (a), (b) ) /* [ a0 *b0     a1 *b1     ... a3 *b3     ] */

/* Binary operations */

/* Note: vu_shl/vu_shr/vu_shru is a left/signed right/unsigned right
   shift by imm bits; imm should be a compile time constant in 0:31.
   The variable variants are slower but do not require the shift amount
   to be known at compile time (should still be in 0:31). */

#define vu_not(a) _mm_xor_si128( _mm_set1_epi32( -1 ), (a) ) /* [ ~a0 ~a1 ... ~a3 ] */

#define vu_shl(a,imm) _mm_slli_epi32( (a), (imm) ) /* [ a0<<imm a1<<imm ... a3<<imm ] */
#define vu_shr(a,imm) _mm_srli_epi32( (a), (imm) ) /* [ a0>>imm a1>>imm ... a3>>imm ] */

#define vu_shl_variable(a,n) _mm_sll_epi32( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
#define vu_shr_variable(a,n) _mm_srl_epi32( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )

#define vu_shl_vector(a,b) _mm_sllv_epi32( (a), (b) ) /* [ a0<<b0 a1<<b1 ... a3<<b3 ] */
#define vu_shr_vector(a,b) _mm_srlv_epi32( (a), (b) ) /* [ a0>>b0 a1>>b1 ... a3>>b3 ] */

#define vu_and(a,b)    _mm_and_si128(    (a), (b) ) /* [   a0 &b0    a1& b1 ...   a3& b3 ] */
#define vu_andnot(a,b) _mm_andnot_si128( (a), (b) ) /* [ (~a0)&b0  (~a1)&b1 ... (~a3)&b3 ] */
#define vu_or(a,b)     _mm_or_si128(     (a), (b) ) /* [   a0 |b0    a1 |b1 ...   a3 |b3 ] */
#define vu_xor(a,b)    _mm_xor_si128(    (a), (b) ) /* [   a0 ^b0    a1 ^b1 ...   a3 ^b3 ] */

static inline vu_t vu_rol( vu_t a, int imm ) { return vu_or( vu_shl( a, imm & 31 ), vu_shr( a, (-imm) & 31 ) ); }
static inline vu_t vu_ror( vu_t a, int imm ) { return vu_or( vu_shr( a, imm & 31 ), vu_shl( a, (-imm) & 31 ) ); }

static inline vu_t vu_rol_variable( vu_t a, int n ) { return vu_or( vu_shl_variable( a, n&31 ), vu_shr_variable( a, (-n)&31 ) ); }
static inline vu_t vu_ror_variable( vu_t a, int n ) { return vu_or( vu_shr_variable( a, n&31 ), vu_shl_variable( a, (-n)&31 ) ); }

static inline vu_t vu_rol_vector( vu_t a, vi_t b ) {
  vi_t m = vi_bcast( 31 );
  return vu_or( vu_shl_vector( a, vi_and( b, m ) ), vu_shr_vector( a, vi_and( vi_neg( b ), m ) ) );
}

static inline vu_t vu_ror_vector( vu_t a, vi_t b ) {
  vi_t m = vi_bcast( 31 );
  return vu_or( vu_shr_vector( a, vi_and( b, m ) ), vu_shl_vector( a, vi_and( vi_neg( b ), m ) ) );
}

static inline vu_t vu_bswap( vu_t a ) {
  vu_t m = vu_bcast( 0x00FF00FFU );                                            /* Probably hoisted */
  vu_t t = vu_rol( a, 16 );                                                    /* Swap E/O 16-bit pairs */
  return vu_or( vu_andnot( m, vu_shl( t, 8 ) ), vu_and( m, vu_shr( t, 8 ) ) ); /* Swap E/O  8-bit pairs */
}

/* Logical operations */

/* Like noted below in the vu_to_{vf,vd} converters, Intel clearly has
   the hardware to do a _mm_cmpgt_epu32 given that _mm_cmpgt_epi32
   exists but doesn't expose it in the ISA pre AVX-512.  Sigh ... twos
   complement bit tricks to the rescue for vu_{gt,lt,ge,le}. */

#define vu_lnot(a)     _mm_cmpeq_epi32( (a), _mm_setzero_si128() ) /* [  !a0  !a1 ...  !a3 ] */
#define vu_lnotnot(a)                                              /* [ !!a0 !!a1 ... !!a3 ] */ \
  _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_cmpeq_epi32( (a), _mm_setzero_si128() ) )

#define vu_eq(a,b) _mm_cmpeq_epi32( (a), (b) )                                        /* [ a0==b0 a1==b1 ... a3==b3 ] */
#define vu_gt(a,b)                                                                    /* [ a0> b0 a1> b1 ... a3> b3 ] */ \
  _mm_cmpgt_epi32( _mm_sub_epi32( (a), _mm_set1_epi32( (int)(1U<<31) ) ),                                                \
                   _mm_sub_epi32( (b), _mm_set1_epi32( (int)(1U<<31) ) ) )
#define vu_lt(a,b) vu_gt( (b), (a) )                                                  /* [ a0< b0 a1< b1 ... a3> b3 ] */
#define vu_ne(a,b) _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_cmpeq_epi32( (a), (b) ) ) /* [ a0!=b0 a1!=b1 ... a3!=b3 ] */
#define vu_ge(a,b) _mm_xor_si128( _mm_set1_epi32( -1 ), vu_gt( (b), (a) ) )           /* [ a0>=b0 a1>=b1 ... a3>=b3 ] */
#define vu_le(a,b) _mm_xor_si128( _mm_set1_epi32( -1 ), vu_gt( (a), (b) ) )           /* [ a0<=b0 a1<=b1 ... a3<=b3 ] */

/* Conditional operations */

#define vu_czero(c,f)    _mm_andnot_si128( (c), (f) ) /* [ c0?0U:f0 c1?0U:f1 ... c3?0U:f3 ] */
#define vu_notczero(c,f) _mm_and_si128(    (c), (f) ) /* [ c0?f0:0U c1?f1:0U ... c3?f3:0U ] */

#define vu_if(c,t,f) _mm_blendv_epi8(  (f), (t), (c) ) /* [ c0?t0:f0 c1?t1:f1 ... c3?t3:f3 ] */

/* Conversion operations */

/* Summarizing:

   vu_to_vc(a)               returns [ !!a0 !!a1 ... a3 ]

   vu_to_vf(a)               returns [ (float)a0 (float)a1 ... (float)a3 ]

   vu_to_vi(a)               returns [ (int)a0 (int)a1 ... (int)a3 ]

   vu_to_vd(a,imm_i0,imm_i1) returns [ (double)a(imm_i0) (double)a(imm_i1) ]

   vu_to_vl(a,imm_i0,imm_i1) returns [ (long)a(imm_i0) (long)a(imm_i1) ]

   vu_to_vv(a,imm_i0,imm_i1) returns [ (ulong)a(imm_i0) (ulong)a(imm_i1) ]

   where imm_i* should be a compile time constant in 0:3.

   The raw variants just treat the raw bits as the corresponding vector
   type.  For vu_to_vc_raw, the user promises vu contains a proper
   vector conditional (i.e. 0 or -1 in each lane).  vu_to_vf_raw is
   useful for doing advanced bit tricks on floating point values.  The
   others are probably dubious but are provided for completness. */

#define vu_to_vc(a)               _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_cmpeq_epi32( (a), _mm_setzero_si128() ) )
#define vu_to_vi(a)               (a)

static inline __m128d vu_to_vd_core( vu_t u ) { /* FIXME: workaround vd_t isn't declared at this point */

  /* Note: Given that _mm_cvtepi32_pd exists, Intel clearly has the
     hardware under the hood to support a _mm_cvtepu32_pd but didn't
     bother to expose it pre AVX-512 ... sigh (all too typical
     unfortunately).  We can do a mix of twos complement and floating
     point hacks to emulate it without spilling. */

  __m128i c  = _mm_cmpgt_epi32( _mm_setzero_si128(), u );         // 0      if u<2^31, -1     o.w
  __m128d d  = _mm_cvtepi32_pd( u );                              // u      if u<2^31, u-2^32 o.w, exact
  __m128d ds = _mm_add_pd( d, _mm_set1_pd( (double)(1UL<<32) ) ); // u+2^32 if u<2^31, u      o.w, exact
  __m128i cl = _mm_cvtepi32_epi64( c );                           // 0L     if u<2^31, -1L    o.w
  return _mm_blendv_pd( d, ds, _mm_castsi128_pd( cl ) );          // u

}

#define vu_to_vd(a,imm_i0,imm_i1) vu_to_vd_core( _mm_shuffle_epi32( (a), _MM_SHUFFLE(3,2,(imm_i1),(imm_i0)) ) )

static inline vf_t vu_to_vf( vu_t u ) {

  /* See note above re ISA dubiousness.  Note that we can't do the same
     trick as vu_to_vd due to single precision roundoff limitations (the
     _mm_cvtepi32_pd equivalent would not be exact such that add to
     correct the twos complement mangling would add a possible second
     roundoff error ... this would result in slightly different values
     occassionally when u is >~ 2^31).  We instead convert the two
     halves to double (exact), convert the double to float (single
     roundoff error) and then concat the two float halves to make a
     correctly rounded implementation. */

  return _mm_shuffle_ps( _mm_cvtpd_ps( vu_to_vd_core(u) ), _mm_cvtpd_ps( vu_to_vd(u,2,3) ), _MM_SHUFFLE(1,0,1,0) );
}

#define vu_to_vl(a,imm_i0,imm_i1) _mm_cvtepu32_epi64( _mm_shuffle_epi32( (a), _MM_SHUFFLE(3,2,(imm_i1),(imm_i0)) ) )
#define vu_to_vv(a,imm_i0,imm_i1) _mm_cvtepu32_epi64( _mm_shuffle_epi32( (a), _MM_SHUFFLE(3,2,(imm_i1),(imm_i0)) ) )

#define vu_to_vc_raw(a) (a)
#define vu_to_vf_raw(a) _mm_castsi128_ps( (a) )
#define vu_to_vi_raw(a) (a)
#define vu_to_vd_raw(a) _mm_castsi128_pd( (a) )
#define vu_to_vl_raw(a) (a)
#define vu_to_vv_raw(a) (a)

/* Reduction operations */

static inline vu_t
vu_sum_all( vu_t x ) { /* Returns vu_bcast( sum( x ) ) */
  x = _mm_hadd_epi32( x, x );    /* x01 x23 ... */
  return _mm_hadd_epi32( x, x ); /* xsum ...    */
}

static inline vu_t
vu_min_all( vu_t x ) { /* Returns vu_bcast( min( x ) ) */
  __m128i y;
  y = _mm_shuffle_epi32( x, _MM_SHUFFLE( 1, 0, 3, 2 ) ); /* x2  x3  x0  x1 */
  x = _mm_min_epu32( x, y );                             /* x02 x13 ...    */
  y = _mm_shuffle_epi32( x, _MM_SHUFFLE( 2, 3, 0, 1 ) ); /* x13 x02 ...    */
  x = _mm_min_epu32( x, y );                             /* xmin ...       */
  return x;
}

static inline vu_t
vu_max_all( vu_t x ) { /* Returns vu_bcast( max( x ) ) */
  __m128i y;
  y = _mm_shuffle_epi32( x, _MM_SHUFFLE( 1, 0, 3, 2 ) ); /* x2  x3  x0  x1 */
  x = _mm_max_epu32( x, y );                             /* x02 x13 ...    */
  y = _mm_shuffle_epi32( x, _MM_SHUFFLE( 2, 3, 0, 1 ) ); /* x13 x02 ...    */
  x = _mm_max_epu32( x, y );                             /* xmax ...       */
  return x;
}

/* Misc operations */

/* vu_gather(b,i) returns [ b[i(0)] b[i(1)] ... b[i(3)] ] where b is a
   "uint const *"  and i is a vi_t.  We use a static inline here instead
   of a define to keep strict type checking while working around yet
   another Intel intrinsic type mismatch issue. */

static inline vu_t vu_gather( uint const * b, vi_t i ) {
  return _mm_i32gather_epi32( (int const *)b, (i), 4 );
}

/* vu_transpose_4x4 transposes the 4x4 matrix stored in vu_t r0,r1,r2,r3
   and stores the result in 4x4 matrix vu_t c0,c1,c2,c3.  All
   c0,c1,c2,c3 should be different for a well defined result.
   Otherwise, in-place operation and/or using the same vu_t to specify
   multiple rows of r is fine. */

#define vu_transpose_4x4( r0,r1,r2,r3, c0,c1,c2,c3 ) do {                                                                   \
    vu_t _vu_transpose_r0 = (r0); vu_t _vu_transpose_r1 = (r1); vu_t _vu_transpose_r2 = (r2); vu_t _vu_transpose_r3 = (r3); \
    vu_t _vu_transpose_t;                                                                                                   \
    /* Transpose 2x2 blocks */                                                                                              \
    _vu_transpose_t = _vu_transpose_r0; _vu_transpose_r0 = _mm_unpacklo_epi32( _vu_transpose_t,  _vu_transpose_r2 );        \
    /**/                                _vu_transpose_r2 = _mm_unpackhi_epi32( _vu_transpose_t,  _vu_transpose_r2 );        \
    _vu_transpose_t = _vu_transpose_r1; _vu_transpose_r1 = _mm_unpacklo_epi32( _vu_transpose_t,  _vu_transpose_r3 );        \
    /**/                                _vu_transpose_r3 = _mm_unpackhi_epi32( _vu_transpose_t,  _vu_transpose_r3 );        \
    /* Transpose 1x1 blocks */                                                                                              \
    /**/                                (c0)             = _mm_unpacklo_epi32( _vu_transpose_r0, _vu_transpose_r1 );        \
    /**/                                (c1)             = _mm_unpackhi_epi32( _vu_transpose_r0, _vu_transpose_r1 );        \
    /**/                                (c2)             = _mm_unpacklo_epi32( _vu_transpose_r2, _vu_transpose_r3 );        \
    /**/                                (c3)             = _mm_unpackhi_epi32( _vu_transpose_r2, _vu_transpose_r3 );        \
  } while(0)
