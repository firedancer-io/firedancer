#ifndef HEADER_fd_src_util_simd_fd_sse_h
#error "Do not include this directly; use fd_sse.h"
#endif

/* Vector float API ***************************************************/

/* A vf_t is a vector where each 32-bit wide lane holds a single
   precision IEEE 754 floating point value (a "float").

   Inputs to all operations assume that the values aren't exotic (no
   NaNs, no +/-Infs, no denorms) and, if the output of an operation
   would produce an exotic value in the IEEE 754 standard, the results
   of that operation are undefined.  Additionally, correct handling of
   signed zero is not guaranteed.  Lastly, these will not raise floating
   point exceptions or set math errno's.

   Basically, handling of exotics and signed zero will generally be
   reasonable but most of that relies on the underlying compiler and
   hardware having conformant behavior and this is flaky at the best of
   times.  So it is best for developers not to assume conformant
   behavior.

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define vf_t __m128

/* Constructors */

/* Given the float values, return ... */

#define vf(f0,f1,f2,f3) _mm_setr_ps( (f0), (f1), (f2), (f3) ) /* [ f0 f1 f2 f3 ] */

#define vf_bcast(f0) _mm_set1_ps( (f0) ) /* [ f0 f0 f0 f0 ] */

static inline vf_t /* [ f0 f1 f0 f1 ] */
vf_bcast_pair( float f0, float f1 ) {
  return _mm_setr_ps( f0, f1, f0, f1 );
}

static inline vf_t /* [ f0 f0 f1 f1 ] */
vf_bcast_wide( float f0, float f1 ) {
  return _mm_setr_ps( f0, f0, f1, f1 );
}

/* vf_permute returns [ f(imm_l0) f(imm_l1) f(imm_l2) f(imm_l3) ].
   imm_l* should be compile time constants in 0:3. */

#define vf_permute(f,imm_l0,imm_l1,imm_l2,imm_l3) _mm_permute_ps( (f), _MM_SHUFFLE( (imm_l3), (imm_l2), (imm_l1), (imm_l0) ) )

/* Predefined constants */

#define vf_zero() _mm_setzero_ps()   /* Return [ 0.f 0.f 0.f 0.f ] */
#define vf_one()  _mm_set1_ps( 1.f ) /* Return [ 1.f 1.f 1.f 1.f ] */

/* Memory operations */

/* vf_ld return the 4 floats at the 16-byte aligned / 16-byte sized
   location p as a vector float.  vf_ldu is the same but p does not have
   to be aligned.  vf_st writes the vector float to the 16-byte aligned
   / 16-byte sized location p as 4 floats.  vf_stu is the same but p
   does not have to be aligned.  In all these lane l will be at p[l].
   FIXME: USE ATTRIBUTES ON P PASSED TO THESE? */

#define vf_ld(p)    _mm_load_ps( (p) )
#define vf_ldu(p)   _mm_loadu_ps( (p) )
#define vf_st(p,x)  _mm_store_ps( (p), (x) )
#define vf_stu(p,x) _mm_storeu_ps( (p), (x) )

/* vf_ldif is an optimized equivalent to vf_notczero(c,vf_ldu(p)) (may
   have different behavior if c is not a proper vector conditional).  It
   is provided for symmetry with the vf_stif operation.  vf_stif stores
   x(n) to p[n] if c(n) is true and leaves p[n] unchanged otherwise.
   Undefined behavior if c is not a proper vector conditional. */

#define vf_ldif(c,p)   _mm_maskload_ps( (p),(c))
#define vf_stif(c,p,x) _mm_maskstore_ps((p),(c),(x))

/* Element operations */

/* vf_extract extracts the float in lane imm from the vector float
   as a float.  vf_insert returns the vector float formed by replacing
   the value in lane imm of a with the provided float.  imm should be a
   compile time constant in 0:3.  vf_extract_variable and
   vf_insert_variable are the slower but the lane n does not have to be
   known at compile time (should still be in 0:3). */

/* FIXME: ARE THESE BETTER IMPLEMENTED VIA BOUNCING OF THE STACK?  (IT
   SEEMS PRETTY CLEAR THAT INTEL DIDN'T INTEND THIS TO BE POSSIBLE) */

#define vf_extract(a,imm)  _mm_cvtss_f32( _mm_permute_ps( (a), _MM_SHUFFLE(3,2,1,(imm)) ) )

#define vf_insert(a,imm,v)                                     \
  _mm_castsi128_ps( _mm_insert_epi32( _mm_castps_si128( (a) ), \
                    _mm_extract_epi32( _mm_castps_si128( _mm_set_ss( (v) ) ), 0 ), (imm) ) )

static inline float
vf_extract_variable( vf_t a, int n ) {
  float f[4] V_ATTR;
  _mm_store_ps( f, a );
  return f[n];
}

static inline vf_t
vf_insert_variable( vf_t a, int n, float v ) {
  float f[4] V_ATTR;
  _mm_store_ps( f, a );
  f[n] = v;
  return _mm_load_ps( f );
}

/* Given [a0 a1 a2 a3], [b0 b1 b2 b3] and/or [c0 c1 c2 c3], return ... */

/* Arithmetic operations */

/* vf_neg(a)        returns [        -a0         -a1  ...        -a3  ] (i.e.       -a )
   vf_sign(a)       returns [   signf(a0)   signf(a1) ...   signf(a3) ]
   vf_abs(a)        returns [   fabsf(a0)   fabsf(a1) ...   fabsf(a3) ] (i.e.    abs(a))
   vf_negabs(a)     returns [  -fabsf(a0)  -fabsf(a1) ...  -fabsf(a3) ] (i.e.   -abs(a))
   vf_ceil(a)       returns [   ceilf(a0)   ceilf(a1) ...   ceilf(a3) ] (i.e.   ceil(a))
   vf_floor(a)      returns [  floorf(a0)  floorf(a1) ...  floorf(a3) ] (i.e.  floor(a))
   vf_rint(a)       returns [   rintf(a0)   rintf(a1) ...   rintf(a3) ] (i.e. roundb(a))
   vf_trunc(a)      returns [  truncf(a0)  truncf(a1) ...  truncf(a3) ] (i.e.    fix(a))
   vf_sqrt(a)       returns [   sqrtf(a0)   sqrtf(a1) ...   sqrtf(a3) ] (i.e.   sqrt(a))
   vf_rcp_fast(a)   returns [   ~rcpf(a0)   ~rcpf(a1) ...   ~rcpf(a3) ]
   vf_rsqrt_fast(a) returns [ ~rsqrtf(a0) ~rsqrtf(a1) ... ~rsqrtf(a3) ]

   vf_add(a,b)      returns [           a0+b0            a1+b1  ...           a3+b3  ] (i.e. a +b)
   vf_sub(a,b)      returns [           a0-b0            a1-b1  ...           a3-b3  ] (i.e. a -b)
   vf_mul(a,b)      returns [           a0*b0            a1*b1  ...           a3*b3  ] (i.e. a.*b)
   vf_div(a,b)      returns [           a0/b0            a1/b1  ...           a3/b3  ] (i.e. a./b)
   vf_min(a,b)      returns [     fminf(a0,b0)     fminf(a1,b1) ...     fminf(a3,b3) ] (i.e. min([a;b]) (a and b are 1x4)
   vf_max(a,b)      returns [     fmaxf(a0,b0)     fmaxf(a1,b1) ...     fmaxf(a3,b3) ] (i.e. max([a;b]) (a and b are 1x4)
   vf_copysign(a,b) returns [ copysignf(a0,b0) copysignf(a1,b1) ... copysignf(a3,b3) ]
   vf_flipsign(a,b) returns [ flipsignf(a0,b0) flipsignf(a1,b1) ... flipsignf(a3,b3) ]

   vf_fma(a,b,c)    returns [  fmaf(a0,b0, c0)  fmaf(a1,b1, c1) ...  fmaf(a3,b3, c3) ] (i.e.  a.*b+c) 
   vf_fms(a,b,c)    returns [  fmaf(a0,b0,-c0)  fmaf(a1,b1,-c1) ...  fmaf(a3,b3,-c3) ] (i.e.  a.*b-c)
   vf_fnma(a,b,c)   returns [ -fmaf(a0,b0,-c0) -fmaf(a1,b1,-c1) ... -fmaf(a3,b3,-c3) ] (i.e. -a.*b+c)

   where sign(a) is -1. if a's sign bit is set and +1. otherwise, rcp(a)
   is 1./a and rsqrt(a) is 1./sqrt(a), and flipsign(a,b) returns -a if b
   signbit is set and a otherwise.

   rint is in round-to-nearest-even rounding mode (note rint and
   nearbyint are identical once floating point exceptions are ignored).

   sqrt should typically be full accuracy.

   rcp_fast and rsqrt_fast should typically be ~12 bits or more bits
   accurate (~3 or more decimal digits) such that (nearly) full accuracy
   can be achieved with two to three rounds of Newton-Raphson polishing.
   Bit level replicable code should avoid rcp_fast and rsqrt_fast though
   as the approximations used can vary between various generations /
   steppings / microcode updates of x86 processors (including Intel and
   AMD). */

#define vf_neg(a)        _mm_xor_ps(    _mm_set1_ps( -0.f ), (a) )
#define vf_sign(a)       _mm_xor_ps(    _mm_set1_ps(  1.f ), _mm_and_ps( _mm_set1_ps( -0.f ), (a) ) )
#define vf_abs(a)        _mm_andnot_ps( _mm_set1_ps( -0.f ), (a) )
#define vf_negabs(a)     _mm_or_ps(     _mm_set1_ps( -0.f ), (a) )
#define vf_ceil(a)       _mm_ceil_ps(  (a) )
#define vf_floor(a)      _mm_floor_ps( (a) )
#define vf_rint(a)       _mm_round_ps( (a), _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC )
#define vf_trunc(a)      _mm_round_ps( (a), _MM_FROUND_TO_ZERO        | _MM_FROUND_NO_EXC )
#define vf_sqrt(a)       _mm_sqrt_ps(  (a) )
#define vf_rcp_fast(a)   _mm_rcp_ps(   (a) )
#define vf_rsqrt_fast(a) _mm_rsqrt_ps( (a) )

#define vf_add(a,b)      _mm_add_ps( (a), (b) )
#define vf_sub(a,b)      _mm_sub_ps( (a), (b) )
#define vf_mul(a,b)      _mm_mul_ps( (a), (b) )
#define vf_div(a,b)      _mm_div_ps( (a), (b) )
#define vf_min(a,b)      _mm_min_ps( (a), (b) )
#define vf_max(a,b)      _mm_max_ps( (a), (b) )
#define vf_copysign(a,b) _mm_or_ps( _mm_andnot_ps( _mm_set1_ps( -0.f ), (a) ), _mm_and_ps( _mm_set1_ps( -0.f ), (b) ) )
#define vf_flipsign(a,b) _mm_xor_ps( (a), _mm_and_ps( _mm_set1_ps( -0.f ), (b) ) )

#define vf_fma(a,b,c)    _mm_fmadd_ps(  (a), (b), (c) )
#define vf_fms(a,b,c)    _mm_fmsub_ps(  (a), (b), (c) )
#define vf_fnma(a,b,c)   _mm_fnmadd_ps( (a), (b), (c) )

/* Binary operations */

/* Note: binary operations are not well defined on vector floats.
   If doing tricks with floating point binary representations, the user
   should use vf_to_vi_raw as necessary. */

/* Logical operations */

/* These all return proper vector conditionals */

#define vf_lnot(a)    _mm_castps_si128( _mm_cmp_ps( (a), _mm_setzero_ps(), _CMP_EQ_OQ  ) ) /* [  !a0  !a1 ...  !a3 ] */
#define vf_lnotnot(a) _mm_castps_si128( _mm_cmp_ps( (a), _mm_setzero_ps(), _CMP_NEQ_OQ ) ) /* [ !!a0 !!a1 ... !!a3 ] */
#define vf_signbit(a) _mm_srai_epi32( _mm_castps_si128( (a) ), 31 ) /* [ signbit(a0) signbit(a1) ... signbit(a3) ] */

#define vf_eq(a,b) _mm_castps_si128( _mm_cmp_ps( (a), (b), _CMP_EQ_OQ  ) ) /* [ a0==b0 a1==b1 ... a3==b3 ] */
#define vf_gt(a,b) _mm_castps_si128( _mm_cmp_ps( (a), (b), _CMP_GT_OQ  ) ) /* [ a0> b0 a1> b1 ... a3> b3 ] */
#define vf_lt(a,b) _mm_castps_si128( _mm_cmp_ps( (a), (b), _CMP_LT_OQ  ) ) /* [ a0< b0 a1< b1 ... a3< b3 ] */
#define vf_ne(a,b) _mm_castps_si128( _mm_cmp_ps( (a), (b), _CMP_NEQ_OQ ) ) /* [ a0==b0 a1==b1 ... a3==b3 ] */
#define vf_ge(a,b) _mm_castps_si128( _mm_cmp_ps( (a), (b), _CMP_GE_OQ  ) ) /* [ a0==b0 a1==b1 ... a3==b3 ] */
#define vf_le(a,b) _mm_castps_si128( _mm_cmp_ps( (a), (b), _CMP_LE_OQ  ) ) /* [ a0==b0 a1==b1 ... a3==b3 ] */

/* Conditional operations */

#define vf_czero(c,f)    _mm_andnot_ps( _mm_castsi128_ps( (c) ), (f) ) /* [ c0?0.f:f0 c1?0.f:f1 ... c3?0.f:f3 ] */
#define vf_notczero(c,f) _mm_and_ps(    _mm_castsi128_ps( (c) ), (f) ) /* [ c0?f0:0.f c1?f1:0.f ... c3?f3:0.f ] */

#define vf_if(c,t,f) _mm_blendv_ps( (f), (t), _mm_castsi128_ps( (c) ) ) /* [ c0?t0:f0 c1?t1:f1 ... c3?t3:f3 ] */

/* Conversion operations */

/* Summarizing:

   vf_to_vc(a)               returns [ !!a0 !!a1 ... !!a3 ]

   vf_to_vi(a)               returns [ (int)a0        (int)a1          ... (int)a3         ]
   vf_to_vi_fast(a)          returns [ (int)rintf(a0) (int)rintf(a1)   ... (int)rintf(a3)  ]

   vf_to_vu(a)               returns [ (uint)a0        (uint)a1        ... (uint)a3        ]
   vf_to_vu_fast(a)          returns [ (uint)rintf(a0) (uint)rintf(a1) ... (uint)rintf(a3) ]

   vf_to_vd(a,imm_l0,imm_l1) returns [ (double)a(imm_l0) (double)a(imm_l1) ]

   vf_to_vl(a,imm_l0,imm_l1) returns [ (long)a(imm_l0) (long)a(imm_l1) ]

   where rintf is configured for round-to-nearest-even rounding (Intel
   architecture defaults to round-nearest-even here ... sigh, they still
   don't fully get it) and imm_l* should be a compile time constant in
   0:3.

   The raw variants return just raw bits as the corresponding vector
   type.  vf_to_vi_raw in particular allows doing advanced bit tricks on
   a vector float.  The others are probably dubious but are provided for
   completeness. */

#define vf_to_vc(a)               _mm_castps_si128( _mm_cmp_ps( (a), _mm_setzero_ps(), _CMP_NEQ_OQ ) )
#define vf_to_vi(a)               vf_to_vi_fast(  _mm_round_ps( (a), _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC ) )
#define vf_to_vu(a)               vf_to_vu_fast(  _mm_round_ps( (a), _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC ) )
#define vf_to_vd(a,imm_l0,imm_l1) _mm_cvtps_pd( _mm_permute_ps( (a), _MM_SHUFFLE(3,2,(imm_l1),(imm_l0)) ) )

#if FD_USING_CLANG /* Sigh ... clang is sad and can't handle passing compile time const expressions through a static inline */

#define vf_to_vl(f,imm_l0,imm_l1) (__extension__({                                                \
    vf_t _vf_to_vl_tmp = _mm_permute_ps( (f), _MM_SHUFFLE(3,2,(imm_l1),(imm_l0)) );               \
    _mm_set_epi64x( (long)vf_extract( _vf_to_vl_tmp, 1 ), (long)vf_extract( _vf_to_vl_tmp, 0 ) ); \
  }))

#else

static inline __m128i vf_to_vl( vf_t f, int imm_l0, int imm_l1 ) { /* FIXME: workaround vl_t isn't declared at this point */
  vf_t t = _mm_permute_ps( f, _MM_SHUFFLE(3,2,imm_l1,imm_l0) );
  return _mm_set_epi64x( (long)vf_extract( t, 1 ), (long)vf_extract( t, 0 ) ); /* Sigh ... backwards Intel */
}

#endif

#define vf_to_vi_fast(a)          _mm_cvtps_epi32(  (a) )

static inline __m128i vf_to_vu_fast( vf_t a ) { /* FIXME: workaround vu_t isn't declared at this point */

  /* Note: Given that _mm_cvtps_epi32 exists, Intel clearly has the
     hardware under the hood to support a _mm_cvtps_epu32 but didn't
     bother to expose it pre-AVX512 ... sigh (all too typical
     unfortunately).  We note that floats in [2^31,2^32) are already
     integers and we can exactly subtract 2^31 from them.  This allows
     us to use _mm_cvtps_epi32 to exactly convert to an integer.  We
     then add back in any shift we had to apply. */

  /**/                                                              /* Assumes a is integer in [0,2^32) */
  vf_t    s  = vf_bcast( (float)(1U<<31) );                         /* 2^31 */
  vc_t    c  = vf_lt ( a, s );                                      /* -1 if a<2^31, 0 o.w. */
  vf_t    as = vf_sub( a, s );                                      /* a-2^31 */
  __m128i u  = _mm_cvtps_epi32( vf_if( c, a, as ) );                /* (uint)(a      if a<2^31, a-2^31 o.w.) */
  __m128i us = _mm_add_epi32( u, _mm_set1_epi32( (int)(1U<<31) ) ); /* (uint)(a+2^31 if a<2^31, a      o.w.) */
  return _mm_castps_si128( _mm_blendv_ps( _mm_castsi128_ps( us ), _mm_castsi128_ps( u ), _mm_castsi128_ps( c ) ) );

}

#define vf_to_vc_raw(a) _mm_castps_si128( (a) )
#define vf_to_vi_raw(a) _mm_castps_si128( (a) )
#define vf_to_vu_raw(a) _mm_castps_si128( (a) )
#define vf_to_vd_raw(a) _mm_castps_pd(    (a) )
#define vf_to_vl_raw(a) _mm_castps_si128( (a) )

/* Reduction operations */

static inline vf_t
vf_sum_all( vf_t x ) { /* Returns vf_bcast( sum( x ) ) */
  x = _mm_hadd_ps( x, x );    /* x01 x23 ... */
  return _mm_hadd_ps( x, x ); /* xsum ...    */
}

static inline vf_t
vf_min_all( vf_t x ) { /* Returns vf_bcast( min( x ) ) */
  __m128 y;
  y = _mm_permute_ps( x, _MM_SHUFFLE( 1, 0, 3, 2 ) ); /* x2  x3  x0  x1 */
  x = _mm_min_ps( x, y );                             /* x02 x13 ...    */
  y = _mm_permute_ps( x, _MM_SHUFFLE( 2, 3, 0, 1 ) ); /* x13 x02 ...    */
  x = _mm_min_ps( x, y );                             /* xmin ...       */
  return x;
}

static inline vf_t
vf_max_all( vf_t x ) { /* Returns vf_bcast( max( x ) ) */
  __m128 y;
  y = _mm_permute_ps( x, _MM_SHUFFLE( 1, 0, 3, 2 ) ); /* x2  x3  x0  x1 */
  x = _mm_max_ps( x, y );                             /* x02 x13 ...    */
  y = _mm_permute_ps( x, _MM_SHUFFLE( 2, 3, 0, 1 ) ); /* x13 x02 ...    */
  x = _mm_max_ps( x, y );                             /* xmax ...       */
  return x;
}

/* Misc operations */

/* vf_gather(b,i) returns [ b[i(0)] b[i(1)] ... b[i(3)] ] where b is a
   "float const *" and i is a vi_t. */

#define vf_gather(b,i) _mm_i32gather_ps( (b), (i), 4 )

