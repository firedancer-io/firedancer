#ifndef HEADER_fd_src_util_simd_fd_avx_h
#error "Do not include this directly; use fd_avx.h"
#endif

/* Vector float API ***************************************************/

/* A wf_t is a vector where each 32-bit wide lane holds a single
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

#define wf_t  __m256

/* Constructors */

/* Given the float values, return ... */

#define wf(f0,f1,f2,f3,f4,f5,f6,f7) /* [ f0 f1 f2 f3 f4 f5 f6 f7 ] */ \
  _mm256_setr_ps( (f0), (f1), (f2), (f3), (f4), (f5), (f6), (f7) )

#define wf_bcast(f0) _mm256_set1_ps( (f0) ) /* [ f0 f0 f0 f0 f0 f0 f0 f0 ] */

static inline wf_t /* [ f0 f1 f0 f1 f0 f1 f0 f1 ] */
wf_bcast_pair( float f0, float f1 ) {
  return _mm256_setr_ps( f0, f1, f0, f1, f0, f1, f0, f1 );
}

static inline wf_t /* [ f0 f0 f0 f0 f1 f1 f1 f1 ] */
wf_bcast_lohi( float f0, float f1 ) {
  return _mm256_setr_ps( f0, f0, f0, f0, f1, f1, f1, f1 );
}

static inline wf_t /* [ f0 f1 f2 f3 f0 f1 f2 f3 ] */
wf_bcast_quad( float f0, float f1, float f2, float f3 ) {
  return _mm256_setr_ps( f0, f1, f2, f3, f0, f1, f2, f3 );
}

static inline wf_t /* [ f0 f0 f1 f1 f2 f2 f3 f3 ] */
wf_bcast_wide( float f0, float f1, float f2, float f3 ) {
  return _mm256_setr_ps( f0, f0, f1, f1, f2, f2, f3, f3 );
}

/* No general vf_permute due to cross-128-bit lane limitations in AVX.
   Useful cases are provided below.  Given [ f0 f1 f2 f3 f4 f5 f6 f7 ],
   return ... */

#define wf_bcast_even(f)    _mm256_permute_ps( (f), _MM_SHUFFLE(2,2,0,0) ) /* [ f0 f0 f2 f2 f4 f4 f6 f6 ] */
#define wf_bcast_odd(f)     _mm256_permute_ps( (f), _MM_SHUFFLE(3,3,1,1) ) /* [ f1 f1 f3 f3 f5 f5 f7 f7 ] */
#define wf_exch_adj(f)      _mm256_permute_ps( (f), _MM_SHUFFLE(2,3,0,1) ) /* [ f1 f0 f3 f2 f5 f4 f7 f6 ] */
#define wf_exch_adj_pair(f) _mm256_permute_ps( (f), _MM_SHUFFLE(1,0,3,2) ) /* [ f2 f3 f0 f1 f6 f7 f4 f5 ] */

static inline wf_t
wf_exch_adj_quad( wf_t f ) { /* [ f4 f5 f6 f7 f0 f1 f2 f3 ] */
  return _mm256_permute2f128_ps( f, f, 1 );
}

/* Predefined constants */

#define wf_zero() _mm256_setzero_ps()   /* Return [ 0.f 0.f 0.f 0.f 0.f 0.f 0.f 0.f ] */
#define wf_one()  _mm256_set1_ps( 1.f ) /* Return [ 1.f 1.f 1.f 1.f 1.f 1.f 1.f 1.f ] */

/* Memory operations */

/* wf_ld return the 8 floats at the 32-byte aligned / 32-byte sized
   location p as a vector float.  wf_ldu is the same but p does not have
   to be aligned.  wf_st writes the vector float to the 32-byte aligned
   / 32-byte sized location p as 8 floats.  wf_stu is the same but p
   does not have to be aligned.  In all these lane l will be at p[l].
   FIXME: USE ATTRIBUTES ON P PASSED TO THESE? */

#define wf_ld(p)    _mm256_load_ps( (p) )
#define wf_ldu(p)   _mm256_loadu_ps( (p) )
#define wf_st(p,x)  _mm256_store_ps( (p), (x) )
#define wf_stu(p,x) _mm256_storeu_ps( (p), (x) )

/* wf_ldif is an optimized equivalent to wf_notczero(c,wf_ldu(p)) (may
   have different behavior if c is not a proper vector conditional).  It
   is provided for symmetry with the wf_stif operation.  wf_stif stores
   x(n) to p[n] if c(n) is true and leaves p[n] unchanged otherwise.
   Undefined behavior if c is not a proper vector conditional. */

#define wf_ldif(c,p)   _mm256_maskload_ps( (p),(c))
#define wf_stif(c,p,x) _mm256_maskstore_ps((p),(c),(x))

/* Element operations */

/* wf_extract extracts the float in lane imm from the vector float
   as a float.  wf_insert returns the vector float formed by replacing
   the value in lane imm of a with the provided float.  imm should be a
   compile time constant in 0:7.  wf_extract_variable and
   wf_insert_variable are the slower but the lane n does not have to be
   known at compile time (should still be in 0:7). */

/* FIXME: ARE THESE BETTER IMPLEMENTED VIA BOUNCING OF THE STACK (IT
   SEEMS PRETTY CLEAR THAT INTEL DIDN'T INTEND THIS TO BE POSSIBLE,
   ESPECIALLY GIVEN THE _MM256_CVTSS_F32 IS MISSING GCC)?
   ALTERNATIVELY, IT IS WORTHWHILE TO SPECIAL CASE 0 AND 4 EXTRACTION AS
   PER THE BELOW? */

#if FD_USING_CLANG || !FD_HAS_OPTIMIZATION

/* Sigh ... clang is sad and can't handle passing compile time const
   expressions through a static inline */
static inline float
wf_extract( wf_t a, int imm ) {
  union { float f[8]; __m256 v[1]; } t[1];
  _mm256_store_ps( t->f, a );
  return t->f[ imm ];
}

#else

static inline float
wf_extract( wf_t a, int imm ) {
  int avx_lane = imm >> 2; /* compile time eval */
  int sse_lane = imm & 3;  /* compile time eval */
  __m128 t = _mm256_extractf128_ps( a, avx_lane );
  if( sse_lane ) /* compile time eval */
    t = _mm_castsi128_ps( _mm_insert_epi32( _mm_setzero_si128(), _mm_extract_epi32( _mm_castps_si128( t ), sse_lane ), 0 ) );
  return _mm_cvtss_f32( t );
}

#endif

#define wf_insert(a,imm,v)                                              \
  _mm256_castsi256_ps( _mm256_insert_epi32( _mm256_castps_si256( (a) ), \
                                            _mm_extract_epi32( _mm_castps_si128( _mm_set_ss( (v) ) ), 0 ), (imm) ) )

static inline float
wf_extract_variable( wf_t a, int n ) {
  float f[8] W_ATTR;
  _mm256_store_ps( f, a );
  return f[n];
}

static inline wf_t
wf_insert_variable( wf_t a, int n, float v ) {
  float f[8] W_ATTR;
  _mm256_store_ps( f, a );
  f[n] = v;
  return _mm256_load_ps( f );
}

/* Given [a0 a1 a2 a3 a4 a5 a6 a7], [b0 b1 b2 b3 b4 b5 b6 b7] and/or
   [c0 c1 c2 c3 c4 c5 c6 c7], return ... */

/* Arithmetic operations */

/* wf_neg(a)        returns [        -a0         -a1  ...        -a7  ] (i.e.       -a )
   wf_sign(a)       returns [   signf(a0)   signf(a1) ...   signf(a7) ]
   wf_abs(a)        returns [   fabsf(a0)   fabsf(a1) ...   fabsf(a7) ] (i.e.    abs(a))
   wf_negabs(a)     returns [  -fabsf(a0)  -fabsf(a1) ...  -fabsf(a7) ] (i.e.   -abs(a))
   wf_ceil(a)       returns [   ceilf(a0)   ceilf(a1) ...   ceilf(a7) ] (i.e.   ceil(a))
   wf_floor(a)      returns [  floorf(a0)  floorf(a1) ...  floorf(a7) ] (i.e.  floor(a))
   wf_rint(a)       returns [   rintf(a0)   rintf(a1) ...   rintf(a7) ] (i.e. roundb(a))
   wf_trunc(a)      returns [  truncf(a0)  truncf(a1) ...  truncf(a7) ] (i.e.    fix(a))
   wf_sqrt(a)       returns [   sqrtf(a0)   sqrtf(a1) ...   sqrtf(a7) ] (i.e.   sqrt(a))
   wf_rcp_fast(a)   returns [   ~rcpf(a0)   ~rcpf(a1) ...   ~rcpf(a7) ]
   wf_rsqrt_fast(a) returns [ ~rsqrtf(a0) ~rsqrtf(a1) ... ~rsqrtf(a7) ]

   wf_add(a,b)      returns [           a0+b0            a1+b1  ...           a7+b7  ] (i.e. a +b)
   wf_sub(a,b)      returns [           a0-b0            a1-b1  ...           a7-b7  ] (i.e. a -b)
   wf_mul(a,b)      returns [           a0*b0            a1*b1  ...           a7*b7  ] (i.e. a.*b)
   wf_div(a,b)      returns [           a0/b0            a1/b1  ...           a7/b7  ] (i.e. a./b)
   wf_min(a,b)      returns [     fminf(a0,b0)     fminf(a1,b1) ...     fminf(a7,b7) ] (i.e. min([a;b]) (a and b are 1x8)
   wf_max(a,b)      returns [     fmaxf(a0,b0)     fmaxf(a1,b1) ...     fmaxf(a7,b7) ] (i.e. max([a;b]) (a and b are 1x8)
   wf_copysign(a,b) returns [ copysignf(a0,b0) copysignf(a1,b1) ... copysignf(a7,b7) ]
   wf_flipsign(a,b) returns [ flipsignf(a0,b0) flipsignf(a1,b1) ... flipsignf(a7,b7) ]

   wf_fma(a,b,c)    returns [  fmaf(a0,b0, c0)  fmaf(a1,b1, c1) ...  fmaf(a7,b7, c7) ] (i.e.  a.*b+c)
   wf_fms(a,b,c)    returns [  fmaf(a0,b0,-c0)  fmaf(a1,b1,-c1) ...  fmaf(a7,b7,-c7) ] (i.e.  a.*b-c)
   wf_fnma(a,b,c)   returns [ -fmaf(a0,b0,-c0) -fmaf(a1,b1,-c1) ... -fmaf(a7,b7,-c7) ] (i.e. -a.*b+c)

   where sign(a) is -1. if a's sign bit is set and +1. otherwise, rcp(a)
   is 1./a and rsqrt(a) is 1./sqrt(a), and flipsign(a,b) returns -a if b
   signbit is set and a otherwise.

   rintf is in round-to-nearest-even rounding mode (note rintf and
   nearbyintf are identical once floating point exceptions are ignored).

   sqrtf should typically be full accuracy.

   rcp_fast and rsqrt_fast should typically be ~12 bits or more bits
   accurate (~3 or more decimal digits) such that (nearly) full accuracy
   can be achieved with two to three rounds of Newton-Raphson polishing.
   Bit level replicable code should avoid rcp_fast and rsqrt_fast though
   as the approximations used can vary between various generations /
   steppings / microcode updates of x86 processors (including Intel and
   AMD). */

#define wf_neg(a)        _mm256_xor_ps(    _mm256_set1_ps( -0.f ), (a) )
#define wf_sign(a)       _mm256_xor_ps(    _mm256_set1_ps(  1.f ), _mm256_and_ps( _mm256_set1_ps( -0.f ), (a) ) )
#define wf_abs(a)        _mm256_andnot_ps( _mm256_set1_ps( -0.f ), (a) )
#define wf_negabs(a)     _mm256_or_ps(     _mm256_set1_ps( -0.f ), (a) )
#define wf_ceil(a)       _mm256_ceil_ps(  (a) )
#define wf_floor(a)      _mm256_floor_ps( (a) )
#define wf_rint(a)       _mm256_round_ps( (a), _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC )
#define wf_trunc(a)      _mm256_round_ps( (a), _MM_FROUND_TO_ZERO        | _MM_FROUND_NO_EXC )
#define wf_sqrt(a)       _mm256_sqrt_ps(  (a) )
#define wf_rcp_fast(a)   _mm256_rcp_ps(   (a) )
#define wf_rsqrt_fast(a) _mm256_rsqrt_ps( (a) )

#define wf_add(a,b)      _mm256_add_ps( (a), (b) )
#define wf_sub(a,b)      _mm256_sub_ps( (a), (b) )
#define wf_mul(a,b)      _mm256_mul_ps( (a), (b) )
#define wf_div(a,b)      _mm256_div_ps( (a), (b) )
#define wf_min(a,b)      _mm256_min_ps( (a), (b) )
#define wf_max(a,b)      _mm256_max_ps( (a), (b) )
#define wf_copysign(a,b) _mm256_or_ps( _mm256_andnot_ps( _mm256_set1_ps( -0.f ), (a) ), \
                                       _mm256_and_ps(    _mm256_set1_ps( -0.f ), (b) ) )
#define wf_flipsign(a,b) _mm256_xor_ps( (a), _mm256_and_ps( _mm256_set1_ps( -0.f ), (b) ) )

#define wf_fma(a,b,c)  _mm256_fmadd_ps(  (a), (b), (c) )
#define wf_fms(a,b,c)  _mm256_fmsub_ps(  (a), (b), (c) )
#define wf_fnma(a,b,c) _mm256_fnmadd_ps( (a), (b), (c) )

/* Binary operations */

/* Note: binary operations are not well defined on vector floats.
   If doing tricks with floating point binary representations, the user
   should use wf_to_wi_raw as necessary. */

/* Logical operations */

/* These all return proper vector conditionals */

#define wf_lnot(a)    _mm256_castps_si256( _mm256_cmp_ps( (a), _mm256_setzero_ps(), _CMP_EQ_OQ  ) ) /* [  !a0  !a1 ...  !a7 ] */
#define wf_lnotnot(a) _mm256_castps_si256( _mm256_cmp_ps( (a), _mm256_setzero_ps(), _CMP_NEQ_OQ ) ) /* [ !!a0 !!a1 ... !!a7 ] */
#define wf_signbit(a) _mm256_srai_epi32( _mm256_castps_si256( (a) ), 31 )

#define wf_eq(a,b) _mm256_castps_si256( _mm256_cmp_ps( (a), (b), _CMP_EQ_OQ  ) ) /* [ a0==b0 a1==b1 ... a7==b7 ] */
#define wf_gt(a,b) _mm256_castps_si256( _mm256_cmp_ps( (a), (b), _CMP_GT_OQ  ) ) /* [ a0> b0 a1> b1 ... a7> b7 ] */
#define wf_lt(a,b) _mm256_castps_si256( _mm256_cmp_ps( (a), (b), _CMP_LT_OQ  ) ) /* [ a0< b0 a1< b1 ... a7< b7 ] */
#define wf_ne(a,b) _mm256_castps_si256( _mm256_cmp_ps( (a), (b), _CMP_NEQ_OQ ) ) /* [ a0==b0 a1==b1 ... a7==b7 ] */
#define wf_ge(a,b) _mm256_castps_si256( _mm256_cmp_ps( (a), (b), _CMP_GE_OQ  ) ) /* [ a0==b0 a1==b1 ... a7==b7 ] */
#define wf_le(a,b) _mm256_castps_si256( _mm256_cmp_ps( (a), (b), _CMP_LE_OQ  ) ) /* [ a0==b0 a1==b1 ... a7==b7 ] */

/* Conditional operations */

#define wf_czero(c,f)    _mm256_andnot_ps( _mm256_castsi256_ps( (c) ), (f) ) /* [ c0?0.f:f0 c1?0.f:f1 ... c7?0.f:f7 ] */
#define wf_notczero(c,f) _mm256_and_ps(    _mm256_castsi256_ps( (c) ), (f) ) /* [ c0?f0:0.f c1?f1:0.f ... c7?f7:0.f ] */

#define wf_if(c,t,f) _mm256_blendv_ps( (f), (t), _mm256_castsi256_ps( (c) ) ) /* [ c0?t0:f0 c1?t1:f1 ... c7?t7:f7 ] */

/* Conversion operations */

/* Summarizing:

   wf_to_wc(a)      returns [ !!a0 !!a1 ... !!a7 ]

   wf_to_wi(a)      returns [ (int)a0        (int)a1        ... (int)a7        ]
   wf_to_wi_fast(a) returns [ (int)rintf(a0) (int)rintf(a1) ... (int)rintf(a7) ]

   wf_to_wu(a)      returns [ (uint)a0        (uint)a1        ... (uint)a7        ]
   wf_to_wu_fast(a) returns [ (uint)rintf(a0) (uint)rintf(a1) ... (uint)rintf(a7) ]

   wf_to_wd(a,0)    returns [ (double)a0 (double)a1 (double)a2 (double)a3 ]
   wf_to_wd(a,1)    returns [ (double)a4 (double)a5 (double)a6 (double)a7 ]

   wf_to_wl(a,0)    returns [ (long)a0 (long)a1 (long)a2 (long)a3 ]
   wf_to_wl(a,1)    returns [ (long)a4 (long)a5 (long)a6 (long)a7 ]

   wf_to_wv(a,0)    returns [ (ulong)a0 (ulong)a1 (ulong)a2 (ulong)a3 ]
   wf_to_wv(a,1)    returns [ (ulong)a4 (ulong)a5 (ulong)a6 (ulong)a7 ]

   where rintf is configured for round-to-nearest-even rounding (Intel
   architecture defaults to round-nearest-even here ... sigh, they still
   don't fully get it) and imm_hi should be a compile time constant.
   That is, the fast variants assume that float point inputs are already
   integral value in the appropriate range for the output type.

   For wf_to_{wd,wl}, the permutation used for the conversion is less
   flexible due to cross 128-bit lane limitations in AVX.  If imm_hi==0,
   the conversion is done to lanes 0:3.  Otherwise, the conversion is
   done to lanes 4:7.

   The raw variants return just raw bits as the corresponding vector
   type.  wf_to_wi_raw in particular allows doing advanced bit tricks on
   a vector float.  The others are probably dubious but they are
   provided for completeness. */

#define wf_to_wc(a)        _mm256_castps_si256( _mm256_cmp_ps( (a), _mm256_setzero_ps(), _CMP_NEQ_OQ ) )
#define wf_to_wi(a)        wf_to_wi_fast( _mm256_round_ps( (a), _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC ) )
#define wf_to_wu(a)        wf_to_wu_fast( _mm256_round_ps( (a), _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC ) )
#define wf_to_wd(a,imm_hi) _mm256_cvtps_pd( _mm256_extractf128_ps( (a), !!(imm_hi) ) )

/* FIXME: IS IT FASTER TO USE INSERT / EXTRACT FOR THESE? */

static inline __m256i wf_to_wl( wf_t f, int imm_hi ) { /* FIXME: workaround wl_t isn't declared at this point */
  union { float f[4]; __m128  v[1]; } t[1];
  union { long  l[4]; __m256i v[1]; } u[1];
  _mm_store_ps( t->f, imm_hi ? _mm256_extractf128_ps( f, 1 ) : _mm256_extractf128_ps( f, 0 ) /* compile time */ );
  u->l[0] = (long)t->f[0];
  u->l[1] = (long)t->f[1];
  u->l[2] = (long)t->f[2];
  u->l[3] = (long)t->f[3];
  return _mm256_load_si256( u->v );
}

static inline __m256i wf_to_wv( wf_t f, int imm_hi ) { /* FIXME: workaround wv_t isn't declared at this point */
  union { float f[4]; __m128  v[1]; } t[1];
  union { ulong u[4]; __m256i v[1]; } u[1];
  _mm_store_ps( t->f, imm_hi ? _mm256_extractf128_ps( f, 1 ) : _mm256_extractf128_ps( f, 0 ) /* compile time */ );
  u->u[0] = (ulong)t->f[0];
  u->u[1] = (ulong)t->f[1];
  u->u[2] = (ulong)t->f[2];
  u->u[3] = (ulong)t->f[3];
  return _mm256_load_si256( u->v );
}

#define wf_to_wi_fast(a) _mm256_cvtps_epi32( (a) )

/* Note: Given that _mm256_cvtps_epi32 existed for a long time, Intel
   clearly had the hardware under the hood for _mm256_cvtps_epu32 but
   didn't bother to expose it pre-Skylake-X ... sigh (all too typical
   unfortunately).  We use _mm256_cvtps_epu32 where supported because
   it is faster and it replicates the same IB behaviors as the compiler
   generated scalar ASM for float to uint casts on these targets.

   Pre-Skylake-X, we emulate it by noting that subtracting 2^31 from
   a float holding an integer in [2^31,2^32) is exact and the result can
   be exactly converted to a signed integer by _mm256_cvtps_epi32.  We
   then use twos complement hacks to add back any shift.  This also
   replicates the compiler's IB behaviors on these ISAs for float to
   int casts. */

#if defined(__AVX512F__) && defined(__AVX512VL__)
#define wf_to_wu_fast( a ) _mm256_cvtps_epu32( (a) )
#else
static inline __m256i wf_to_wu_fast( wf_t a ) { /* FIXME: workaround wu_t isn't declared at this point */

  /* Note: Given that _mm256_cvtps_epi32 exists, Intel clearly has the
     hardware under the hood to support a _mm256_cvtps_epu32 but didn't
     bother to expose it pre-AVX512 ... sigh (all too typical
     unfortunately).  We note that floats in [2^31,2^32) are already
     integers and we can exactly subtract 2^31 from them.  This allows
     us to use _mm256_cvtps_epi32 to exactly convert to an integer.  We
     then add back in any shift we had to apply. */

  /**/                                                                    /* Assumes a is integer in [0,2^32) */
  wf_t    s  = wf_bcast( (float)(1U<<31) );                               /* 2^31 */
  wc_t    c  = wf_lt ( a, s );                                            /* -1 if a<2^31, 0 o.w. */
  wf_t    as = wf_sub( a, s );                                            /* a-2^31 */
  __m256i u  = _mm256_cvtps_epi32( wf_if( c, a, as ) );                   /* (uint)(a      if a<2^31, a-2^31 o.w.) */
  __m256i us = _mm256_add_epi32( u, _mm256_set1_epi32( (int)(1U<<31) ) ); /* (uint)(a+2^31 if a<2^31, a      o.w.) */
  return _mm256_castps_si256( _mm256_blendv_ps( _mm256_castsi256_ps( us ), _mm256_castsi256_ps( u ), _mm256_castsi256_ps( c ) ) );
}

#define wf_to_wc_raw(a) _mm256_castps_si256( (a) )
#define wf_to_wi_raw(a) _mm256_castps_si256( (a) )
#define wf_to_wu_raw(a) _mm256_castps_si256( (a) )
#define wf_to_wd_raw(a) _mm256_castps_pd(    (a) )
#define wf_to_wl_raw(a) _mm256_castps_si256( (a) )
#define wf_to_wv_raw(a) _mm256_castps_si256( (a) )

/* Reduction operations */

static inline wf_t
wf_sum_all( wf_t x ) { /* Returns wf_bcast( sum( x ) ) */
  x = _mm256_add_ps( x, _mm256_permute2f128_ps( x, x, 1 ) ); /* x04   x15   x26   x37   ... */
  x = _mm256_hadd_ps( x, x );                                /* x0145 x2367 ... */
  return _mm256_hadd_ps( x, x );                             /* xsum  ... */
}

static inline wf_t
wf_min_all( wf_t x ) { /* Returns wf_bcast( min( x ) ) */
  __m256 y = _mm256_permute2f128_ps( x, x, 1 );          /* x4    x5    x6   x7    x0    x1   x2    x3   */
  x = _mm256_min_ps( x, y );                             /* x04   x15   x26  x37   ... */
  y = _mm256_permute_ps( x, _MM_SHUFFLE( 1, 0, 3, 2 ) ); /* x26   x37   x04  x15   ... */
  x = _mm256_min_ps( x, y );                             /* x0246 x1357 ... */
  y = _mm256_permute_ps( x, _MM_SHUFFLE( 2, 3, 0, 1 ) ); /* x1357 x0246 ... */
  x = _mm256_min_ps( x, y );                             /* xmin  ... */
  return x;
}

static inline wf_t
wf_max_all( wf_t x ) { /* Returns wf_bcast( max( x ) ) */
  __m256 y = _mm256_permute2f128_ps( x, x, 1 );          /* x4    x5    x6   x7    x0    x1   x2    x3   */
  x = _mm256_max_ps( x, y );                             /* x04   x15   x26  x37   ... */
  y = _mm256_permute_ps( x, _MM_SHUFFLE( 1, 0, 3, 2 ) ); /* x26   x37   x04  x15   ... */
  x = _mm256_max_ps( x, y );                             /* x0246 x1357 ... */
  y = _mm256_permute_ps( x, _MM_SHUFFLE( 2, 3, 0, 1 ) ); /* x1357 x0246 ... */
  x = _mm256_max_ps( x, y );                             /* xmax  ... */
  return x;
}

/* Misc operations */

/* wf_gather(b,i) returns [ b[i(0)] b[i(1)] ... b[i(7)] ] where b is a
   "float const *" and i is a wi_t. */

#define wf_gather(b,i) _mm256_i32gather_ps( (b), (i), 4 )

/* wf_transpose_8x8 transposes the 8x8 matrix stored in wf_t r0,r1,...r7
   and stores the result in 8x8 matrix wf_t c0,c1,...c7.  All
   c0,c1,...c7 should be different for a well defined result.
   Otherwise, in-place operation and/or using the same wf_t to specify
   multiple rows of r is fine. */

#define wf_transpose_8x8( r0,r1,r2,r3,r4,r5,r6,r7, c0,c1,c2,c3,c4,c5,c6,c7 ) do {                                              \
    wf_t _wf_transpose_r0 = (r0); wf_t _wf_transpose_r1 = (r1); wf_t _wf_transpose_r2 = (r2); wf_t _wf_transpose_r3 = (r3);    \
    wf_t _wf_transpose_r4 = (r4); wf_t _wf_transpose_r5 = (r5); wf_t _wf_transpose_r6 = (r6); wf_t _wf_transpose_r7 = (r7);    \
    wf_t _wf_transpose_t;                                                                                                      \
    /* Transpose 4x4 blocks */                                                                                                 \
    _wf_transpose_t = _wf_transpose_r0; _wf_transpose_r0 = _mm256_permute2f128_ps( _wf_transpose_t,  _wf_transpose_r4, 0x20 ); \
    /**/                                _wf_transpose_r4 = _mm256_permute2f128_ps( _wf_transpose_t,  _wf_transpose_r4, 0x31 ); \
    _wf_transpose_t = _wf_transpose_r1; _wf_transpose_r1 = _mm256_permute2f128_ps( _wf_transpose_t,  _wf_transpose_r5, 0x20 ); \
    /**/                                _wf_transpose_r5 = _mm256_permute2f128_ps( _wf_transpose_t,  _wf_transpose_r5, 0x31 ); \
    _wf_transpose_t = _wf_transpose_r2; _wf_transpose_r2 = _mm256_permute2f128_ps( _wf_transpose_t,  _wf_transpose_r6, 0x20 ); \
    /**/                                _wf_transpose_r6 = _mm256_permute2f128_ps( _wf_transpose_t,  _wf_transpose_r6, 0x31 ); \
    _wf_transpose_t = _wf_transpose_r3; _wf_transpose_r3 = _mm256_permute2f128_ps( _wf_transpose_t,  _wf_transpose_r7, 0x20 ); \
    /**/                                _wf_transpose_r7 = _mm256_permute2f128_ps( _wf_transpose_t,  _wf_transpose_r7, 0x31 ); \
    /* Transpose 2x2 blocks */                                                                                                 \
    _wf_transpose_t = _wf_transpose_r0; _wf_transpose_r0 = _mm256_unpacklo_ps(     _wf_transpose_t,  _wf_transpose_r2 );       \
    /**/                                _wf_transpose_r2 = _mm256_unpackhi_ps(     _wf_transpose_t,  _wf_transpose_r2 );       \
    _wf_transpose_t = _wf_transpose_r1; _wf_transpose_r1 = _mm256_unpacklo_ps(     _wf_transpose_t,  _wf_transpose_r3 );       \
    /**/                                _wf_transpose_r3 = _mm256_unpackhi_ps(     _wf_transpose_t,  _wf_transpose_r3 );       \
    _wf_transpose_t = _wf_transpose_r4; _wf_transpose_r4 = _mm256_unpacklo_ps(     _wf_transpose_t,  _wf_transpose_r6 );       \
    /**/                                _wf_transpose_r6 = _mm256_unpackhi_ps(     _wf_transpose_t,  _wf_transpose_r6 );       \
    _wf_transpose_t = _wf_transpose_r5; _wf_transpose_r5 = _mm256_unpacklo_ps(     _wf_transpose_t,  _wf_transpose_r7 );       \
    /**/                                _wf_transpose_r7 = _mm256_unpackhi_ps(     _wf_transpose_t,  _wf_transpose_r7 );       \
    /* Transpose 1x1 blocks */                                                                                                 \
    /**/                                (c0)             = _mm256_unpacklo_ps(     _wf_transpose_r0, _wf_transpose_r1 );       \
    /**/                                (c1)             = _mm256_unpackhi_ps(     _wf_transpose_r0, _wf_transpose_r1 );       \
    /**/                                (c2)             = _mm256_unpacklo_ps(     _wf_transpose_r2, _wf_transpose_r3 );       \
    /**/                                (c3)             = _mm256_unpackhi_ps(     _wf_transpose_r2, _wf_transpose_r3 );       \
    /**/                                (c4)             = _mm256_unpacklo_ps(     _wf_transpose_r4, _wf_transpose_r5 );       \
    /**/                                (c5)             = _mm256_unpackhi_ps(     _wf_transpose_r4, _wf_transpose_r5 );       \
    /**/                                (c6)             = _mm256_unpacklo_ps(     _wf_transpose_r6, _wf_transpose_r7 );       \
    /**/                                (c7)             = _mm256_unpackhi_ps(     _wf_transpose_r6, _wf_transpose_r7 );       \
  } while(0)
