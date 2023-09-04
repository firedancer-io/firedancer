#ifndef HEADER_fd_src_util_simd_fd_avx_h
#error "Do not include this directly; use fd_avx.h"
#endif

/* Vector double API **************************************************/

/* A vd_t is a vector where each adjacent pair of 32-bit wide lanes
   (e.g. 0-1 / 2-3 / 4-5 / 6-7) hold a double precision IEEE 754
   floating point value (a "double").

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

   Note that, when doing conditional operations on a vector double, the
   vector conditional should be identical values in adjacent pairs of
   lanes.  Results are be undefined otherwise.

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wd_t __m256d

/* Constructors */

/* Given the double values, return ... */

#define wd(d0,d1,d2,d3) _mm256_setr_pd( (d0), (d1), (d2), (d3) ) /* [ d0 d1 d2 d3 ] */

#define wd_bcast(d0) _mm256_set1_pd( (d0) ) /* [ d0 d0 d0 d0 ] */

static inline wd_t /* [ d0 d1 d0 d1 ] */
wd_bcast_pair( double d0, double d1 ) {
  return _mm256_setr_pd( d0, d1, d0, d1 );
}

static inline wd_t /* [ d0 d0 d1 d1 ] */
wd_bcast_wide( double d0, double d1 ) {
  return _mm256_setr_pd( d0, d0, d1, d1 );
}

/* wd_permute returns [ d(imm_i0) d(imm_i1) d(imm_i2) d(imm_i3) ].
   imm_i* should be compile time constants in 0:3. */

#define wd_permute(x,imm_i0,imm_i1,imm_i2,imm_i3) _mm256_permute4x64_pd( (x), (imm_i0)+4*(imm_i1)+16*(imm_i2)+64*(imm_i3) )

/* Predefined constants */

#define wd_zero() _mm256_setzero_pd() /* Return [ 0. 0. 0. 0. ] */
#define wd_one()  _mm256_set1_pd(1.)  /* Return [ 1. 1. 1. 1. ] */

/* Memory operations */

/* wd_ld return the 4 doubles at the 32-byte aligned / 32-byte sized
   location p as a vector double.  wd_ldu is the same but p does not have
   to be aligned.  wd_st writes the vector double to the 32-byte aligned
   / 32-byte sized location p as 4 doubles.  wd_stu is the same but p
   does not have to be aligned.  In all these 64-bit lane l will be at
   p[l].  FIXME: USE ATTRIBUTES ON P PASSED TO THESE? */

#define wd_ld(p)    _mm256_load_pd( (p) )
#define wd_ldu(p)   _mm256_loadu_pd( (p) )
#define wd_st(p,d)  _mm256_store_pd( (p), (d) )
#define wd_stu(p,d) _mm256_storeu_pd( (p), (d) )

/* wd_ldif is an optimized equivalent to wd_notczero(c,wd_ldu(p)) (may
   have different behavior if c is not a proper vector conditional).  It
   is provided for symmetry with the wd_stif operation.  wd_stif stores
   x(n) to p[n] if c(n) is true and leaves p[n] unchanged otherwise.
   Undefined behavior if c(n) is not a proper paired lane vector
   conditional. */

#define wd_ldif(c,p)   _mm256_maskload_pd( (p),(c))
#define wd_stif(c,p,x) _mm256_maskstore_pd((p),(c),(x))

/* Element operations */

/* wd_extract extracts the double in 64-bit lane imm (e.g. indexed
   0,1,2,3, corresponding to 32-bit pairs of lines 0-1, 2-3, 4-5, 6-7
   respectively) from the vector double as a double.  wd_insert returns
   the vector double formed by replacing the value in 64-bit lane imm of
   a with the provided double.  imm should be a compile time constant in
   0:3.  wd_extract_variable and wd_insert_variable are the slower but
   the 64-bit lane n does not have to be known at compile time (should
   still be in 0:3). */

static inline double
wd_extract( wd_t a, int imm ) { /* FIXME: USE EPI64 HACKS? */
  double d[4] W_ATTR;
  _mm256_store_pd( d, a );
  return d[imm];
}

#if FD_USING_CLANG || !FD_HAS_OPTIMIZATION

/* Sigh ... clang is sad and can't handle passing compile time const
   expressions through a static inline */
#define wd_insert( a, imm, v ) (__extension__({                                                      \
    union { double v; long i; } _wd_insert_t;                                                        \
    _wd_insert_t.v = v;                                                                              \
    _mm256_castsi256_pd( _mm256_insert_epi64( _mm256_castpd_si256( (a) ), _wd_insert_t.i, (imm) ) ); \
  }))

#else

static inline wd_t
wd_insert( wd_t a, int imm, double v ) {
  union { double v; long i; } t;
  t.v = v;
  return _mm256_castsi256_pd( _mm256_insert_epi64( _mm256_castpd_si256( a ), t.i, imm ) );
}

#endif

static inline double
wd_extract_variable( wd_t a, int n ) {
  double d[4] W_ATTR;
  _mm256_store_pd( d, a );
  return d[n];
}

static inline wd_t
wd_insert_variable( wd_t a, int n, double v ) {
  double d[4] W_ATTR;
  _mm256_store_pd( d, a );
  d[n] = v;
  return _mm256_load_pd( d );
}

/* Arithmetic operations */

/* wd_neg(a)        returns [       -a0        -a1  ...       -a3  ] (i.e.       -a )
   wd_sign(a)       returns [   sign(a0)   sign(a1) ...   sign(a3) ]
   wd_abs(a)        returns [   fabs(a0)   fabs(a1) ...   fabs(a3) ] (i.e.    abs(a))
   wd_negabs(a)     returns [  -fabs(a0)  -fabs(a1) ...  -fabs(a3) ] (i.e.   -abs(a))
   wd_ceil(a)       returns [   ceil(a0)   ceil(a1) ...   ceil(a3) ] (i.e.   ceil(a))
   wd_floor(a)      returns [  floor(a0)  floor(a1) ...  floor(a3) ] (i.e.  floor(a))
   wd_rint(a)       returns [   rint(a0)   rint(a1) ...   rint(a3) includi roundb(a))
   wd_trunc(a)      returns [  trunc(a0)  trunc(a1) ...  trunc(a3) ] (i.e.    fix(a))
   wd_sqrt(a)       returns [   sqrt(a0)   sqrt(a1) ...   sqrt(a3) ] (i.e.   sqrt(a))
   wd_rcp_fast(a)   returns [   ~rcp(a0)   ~rcp(a1) ...   ~rcp(a3) ]
   wd_rsqrt_fast(a) returns [ ~rsqrt(a0) ~rsqrt(a1) ... ~rsqrt(a3) ]

   wd_add(     a,b) returns [          a0+b0           a1+b1  ...          a3+b3  ] (i.e. a +b)
   wd_sub(     a,b) returns [          a0-b0           a1-b1  ...          a3-b3  ] (i.e. a -b)
   wd_mul(     a,b) returns [          a0*b0           a1*b1  ...          a3*b3  ] (i.e. a.*b)
   wd_div(     a,b) returns [          a0/b0           a1/b1  ...          a3/b3  ] (i.e. a./b)
   wd_min(     a,b) returns [     fmin(a0,b0)     fmin(a1,b1) ...     fmin(a3,b3) ] (i.e. min([a;b]) (a and b are 1x4)
   wd_max(     a,b) returns [     fmax(a0,b0)     fmax(a1,b1) ...     fmax(a3,b3) ] (i.e. max([a;b]) (a and b are 1x4)
   wd_copysign(a,b) returns [ copysign(a0,b0) copysign(a1,b1) ... copysign(a3,b3) ]
   wd_flipsign(a,b) returns [ flipsign(a0,b0) flipsign(a1,b1) ... flipsign(a3,b3) ]

   wd_fma( a,b,c)   returns [  fma(a0,b0, c0)  fma(a1,b1, c1) ...  fma(a3,b3, c3) ] (i.e.  a.*b+c)
   wd_fms( a,b,c)   returns [  fma(a0,b0,-c0)  fma(a1,b1,-c1) ...  fma(a3,b3,-c3) ] (i.e.  a.*b-c)
   wd_fnma(a,b,c)   returns [ -fma(a0,b0,-c0) -fma(a1,b1,-c1) ... -fma(a3,b3,-c3) ] (i.e. -a.*b+c)

   where sign(a) is -1. if a's sign bit is set and +1. otherwise, rcp(a)
   is 1./a, rsqrt(a) is 1./sqrt(a), and flipsign(a,b) returns -a if b
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

#define wd_neg(a)        _mm256_xor_pd(    _mm256_set1_pd( -0. ), (a) )
#define wd_sign(a)       _mm256_xor_pd(    _mm256_set1_pd(  1. ), _mm256_and_pd( _mm256_set1_pd( -0. ), (a) ) )
#define wd_abs(a)        _mm256_andnot_pd( _mm256_set1_pd( -0. ), (a) )
#define wd_negabs(a)     _mm256_or_pd(     _mm256_set1_pd( -0. ), (a) )
#define wd_ceil(a)       _mm256_ceil_pd(  (a) )
#define wd_floor(a)      _mm256_floor_pd( (a) )
#define wd_rint(a)       _mm256_round_pd( (a), _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC )
#define wd_trunc(a)      _mm256_round_pd( (a), _MM_FROUND_TO_ZERO        | _MM_FROUND_NO_EXC )
#define wd_sqrt(a)       _mm256_sqrt_pd(  (a) )
#define wd_rcp_fast(a)   _mm256_cvtps_pd( _mm_rcp_ps(   _mm256_cvtpd_ps( (a) ) ) )
#define wd_rsqrt_fast(a) _mm256_cvtps_pd( _mm_rsqrt_ps( _mm256_cvtpd_ps( (a) ) ) )

#define wd_add(a,b)      _mm256_add_pd( (a), (b) )
#define wd_sub(a,b)      _mm256_sub_pd( (a), (b) )
#define wd_mul(a,b)      _mm256_mul_pd( (a), (b) )
#define wd_div(a,b)      _mm256_div_pd( (a), (b) )
#define wd_min(a,b)      _mm256_min_pd( (a), (b) )
#define wd_max(a,b)      _mm256_max_pd( (a), (b) )
#define wd_copysign(a,b) _mm256_or_pd( _mm256_andnot_pd( _mm256_set1_pd( -0. ), (a) ), \
                                       _mm256_and_pd(    _mm256_set1_pd( -0. ), (b) ) )
#define wd_flipsign(a,b) _mm256_xor_pd( (a), _mm256_and_pd( _mm256_set1_pd( -0. ), (b) ) )

#define wd_fma(a,b,c)  _mm256_fmadd_pd(  (a), (b), (c) )
#define wd_fms(a,b,c)  _mm256_fmsub_pd(  (a), (b), (c) )
#define wd_fnma(a,b,c) _mm256_fnmadd_pd( (a), (b), (c) )

/* Binary operations */

/* Note: binary operations are not well defined on vector doubles.
   If doing tricks with floating point binary representations, the user
   should use wd_to_wl_raw as necessary. */

/* Logical operations */

/* These all return proper paired lane vector conditionals */

#define wd_lnot(a)    /* [  !a0  !a0  !a1  !a1 ...  !a3  !a3 ] */ \
  _mm256_castpd_si256( _mm256_cmp_pd( (a), _mm256_setzero_pd(), _CMP_EQ_OQ  ) )
#define wd_lnotnot(a) /* [ !!a0 !!a0 !!a1 !!a1 ... !!a3 !!a3 ] */ \
  _mm256_castpd_si256( _mm256_cmp_pd( (a), _mm256_setzero_pd(), _CMP_NEQ_OQ ) )
#define wd_signbit(a) /* [ signbit(a0) signbit(a0) signbit(a1) signbit(a1) ... signbit(a3) signbit(a3) ] */ \
  _mm256_castps_si256( _mm256_permute_ps( _mm256_castsi256_ps( _mm256_srai_epi32( _mm256_castpd_si256( (a) ), 31 ) ), \
                                          _MM_SHUFFLE(3,3,1,1) ) )

#define wd_eq(a,b) _mm256_castpd_si256( _mm256_cmp_pd( (a), (b), _CMP_EQ_OQ  ) ) /* [ a0==b0 a0==b0 a1==b1 a1==b1 ... a3==b3 a3==b3 ] */
#define wd_gt(a,b) _mm256_castpd_si256( _mm256_cmp_pd( (a), (b), _CMP_GT_OQ  ) ) /* [ a0> b0 a0> b0 a1> b1 a1> b1 ... a3> b3 a3> b3 ] */
#define wd_lt(a,b) _mm256_castpd_si256( _mm256_cmp_pd( (a), (b), _CMP_LT_OQ  ) ) /* [ a0< b0 a0< b0 a1< b1 a1< b1 ... a3< b3 a3< b3 ] */
#define wd_ne(a,b) _mm256_castpd_si256( _mm256_cmp_pd( (a), (b), _CMP_NEQ_OQ ) ) /* [ a0!=b0 a0!=b0 a1!=b1 a1!=b1 ... a3!=b3 a3!=b3 ] */
#define wd_ge(a,b) _mm256_castpd_si256( _mm256_cmp_pd( (a), (b), _CMP_GE_OQ  ) ) /* [ a0>=b0 a0>=b0 a1>=b1 a1>=b1 ... a3>=b3 a3>=b3 ] */
#define wd_le(a,b) _mm256_castpd_si256( _mm256_cmp_pd( (a), (b), _CMP_LE_OQ  ) ) /* [ a0<=b0 a0<=b0 a1<=b1 a1<=b1 ... a3<=b3 a3<=b3 ] */

/* Conditional operations */

/* c should be a proper paired lane vector conditional for these */

#define wd_czero(c,a)    _mm256_andnot_pd( _mm256_castsi256_pd( (c) ), (a) )  /* [ c01?0.:a0 c23?0.:a1 c45?0.:a2 c67?0.:a3 ] */
#define wd_notczero(c,a) _mm256_and_pd(    _mm256_castsi256_pd( (c) ), (a) )  /* [ c01?a0:0. c23?a1:0. c45?a2:0. c67?a3:0. ] */

#define wd_if(c,t,f) _mm256_blendv_pd( (f), (t), _mm256_castsi256_pd( (c) ) ) /* [ c01?t0:f0 c23?t1:f1 c45?t2:f2 c67?t3:f3 ] */

/* Conversion operations */

/* Summarizing:

   wd_to_wc(d)          returns [ !!d0 !!d0 !!d1 !!d1 ... !!d3 !!d3 ] ... proper paired lane

   wd_to_wf(d,f,0)      returns [ (float)d0 (float)d1 (float)d2 (float)d3 f4 f5 f6 f7 ]
   wd_to_wf(d,f,1)      returns [ f0 f1 f2 f3 (float)d0 (float)d1 (float)d2 (float)d3 ]

   wd_to_wi(d,i,0)      returns [ (int)d0 (int)d1 (int)d2 (int)d3 i4 i5 i6 i7 ]
   wd_to_wi(d,i,1)      returns [ i0 i1 i2 i3 (int)d0 (int)d1 (int)d2 (int)d3 ]

   wd_to_wi_fast(d,i,0) returns [ (int)rint(d0) (int)rint(d1) (int)rint(d2) (int)rint(d3) i4 i5 i6 i7 ]
   wd_to_wi_fast(d,i,1) returns [ i0 i1 i2 i3 (int)rint(d0) (int)rint(d1) (int)rint(d2) (int)rint(d3) ]

   wd_to_wu(d,u,0)      returns [ (uint)d0 (uint)d1 (uint)d2 (uint)d3 u4 u5 u6 u7 ]
   wd_to_wu(d,u,1)      returns [ u0 u1 u2 u3 (uint)d0 (uint)d1 (uint)d2 (uint)d3 ]

   wd_to_wu_fast(d,u,0) returns [ (uint)rint(d0) (uint)rint(d1) (uint)rint(d2) (uint)rint(d3) u4 u5 u6 u7 ]
   wd_to_wu_fast(d,u,1) returns [ u0 u1 u2 u3 (uint)rint(d0) (uint)rint(d1) (uint)rint(d2) (uint)rint(d3) ]

   wd_to_wl(d)          returns [ (long)d0 (long)d1 (long)d2 (long)d3 ]

   wd_to_wv(d)          returns [ (ulong)d0 (ulong)d1 (ulong)d2 (ulong)d3 ]

   where rint is configured for round-to-nearest-even rounding (Intel
   architecture defaults to round-nearest-even here ... sigh, they still
   don't fully get it) and imm_hi should be a compile time constant.
   That is, the fast variants assume that float point inputs are already
   integral value in the appropriate range for the output type.

   Note that wd_to_{wf,wi,wi_fast} insert the converted values into
   lanes 0:3 (imm_hi==0) or 4:7 (imm_hi!=0) of the provided vector.

   The raw variants return just the raw bits as the corresponding vector
   type.  wd_to_wl_raw allows doing advanced bit tricks on a vector
   double.  The others are probably dubious but are provided for
   completeness. */

#define wd_to_wc(d)          _mm256_castpd_si256( _mm256_cmp_pd( (d), _mm256_setzero_pd(), _CMP_NEQ_OQ ) )

#define wd_to_wf(d,f,imm_hi) _mm256_insertf128_ps( (f), _mm256_cvtpd_ps( (d) ), !!(imm_hi) )

#define wd_to_wi(d,i,imm_hi) wd_to_wi_fast( _mm256_round_pd( (d), _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC ), (i), (imm_hi) )
#define wd_to_wu(d,u,imm_hi) wd_to_wu_fast( _mm256_round_pd( (d), _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC ), (u), (imm_hi) )

/* FIXME: IS IT FASTER TO USE INSERT / EXTRACT FOR THESE? */

static inline __m256i wd_to_wl( wd_t d ) { /* FIXME: workaround wl_t isn't declared at this point */
  union { double d[4]; __m256d v[1]; } t[1];
  union { long   l[4]; __m256i v[1]; } u[1];
  _mm256_store_pd( t->d, d );
  u->l[0] = (long)t->d[0];
  u->l[1] = (long)t->d[1];
  u->l[2] = (long)t->d[2];
  u->l[3] = (long)t->d[3];
  return _mm256_load_si256( u->v );
}

static inline __m256i wd_to_wv( wd_t d ) { /* FIXME: workaround wv_t isn't declared at this point */
  union { double d[4]; __m256d v[1]; } t[1];
  union { ulong  u[4]; __m256i v[1]; } u[1];
  _mm256_store_pd( t->d, d );
  u->u[0] = (ulong)t->d[0];
  u->u[1] = (ulong)t->d[1];
  u->u[2] = (ulong)t->d[2];
  u->u[3] = (ulong)t->d[3];
  return _mm256_load_si256( u->v );
}

#define wd_to_wi_fast(d,i,imm_hi) _mm256_insertf128_si256( (i), _mm256_cvtpd_epi32( (d) ), !!(imm_hi) )

static inline wu_t wd_to_wu_fast( wd_t d, wu_t u, int imm_hi ) {

  /* Note: Given that _mm256_cvtpd_epi32 existed for a long time, Intel
     clearly had the hardware under the hood for _mm256_cvtpd_epu32 but
     didn't bother to expose it pre-Cascade Lake ... sigh (all too
     typical unfortunately).  We use _mm256_cvtpd_epu32 where supported
     because it is faster and it replicates the same IB behaviors as the
     compiler generated scalar ASM for float to uint casts on these
     targets.

     Pre-Cascade Lake, we emulate it by noting that subtracting 2^31
     from a double holding an integer in [0,2^32) is exact and the
     result can be exactly converted to a signed integer by
     _mm256_cvtpd_epi32.  We then use twos complement hacks to add back
     any shift.  This also replicates the compiler's IB behaviors on
     these ISAs for float to int casts. */

# if defined(__AVX512F__) && defined(__AVX512VL__)
  __m128i v = _mm256_cvtpd_epu32( d );
# else
  /**/                                                                                     // Assumes d is integer in [0,2^32)
  wd_t    s  = wd_bcast( (double)(1UL<<31) );                                              // (double)2^31
  wc_t    c  = wd_lt ( d, s );                                                             // -1L if d<2^31, 0L o.w.
  wd_t    ds = wd_sub( d, s );                                                             // (double)(d-2^31)
  __m128  b  = _mm_shuffle_ps( _mm_castsi128_ps( _mm256_extractf128_si256( c, 0 ) ),
                               _mm_castsi128_ps( _mm256_extractf128_si256( c, 1 ) ),
                               _MM_SHUFFLE(2,0,2,0) );                                     // -1 if d<2^31, 0 if o.w.
  __m128i v0 = _mm256_cvtpd_epi32( wd_if( c, d, ds ) );                                    // (uint)(d      if d<2^31, d-2^31 o.w.)
  __m128i v1 = _mm_add_epi32( v0, _mm_set1_epi32( (int)(1U<<31) ) );                       // (uint)(d+2^31 if d<2^31, d      o.w.)
  __m128i v  = _mm_castps_si128( _mm_blendv_ps( _mm_castsi128_ps( v1 ),
                                                _mm_castsi128_ps( v0 ), b ) );             // (uint)d
# endif
  return imm_hi ? _mm256_insertf128_si256( u, v, 1 ) : _mm256_insertf128_si256( u, v, 0 ); // compile time

}

#define wd_to_wc_raw(a) _mm256_castpd_si256( (a) )
#define wd_to_wf_raw(a) _mm256_castpd_ps(    (a) )
#define wd_to_wi_raw(a) _mm256_castpd_si256( (a) )
#define wd_to_wu_raw(a) _mm256_castpd_si256( (a) )
#define wd_to_wl_raw(a) _mm256_castpd_si256( (a) )
#define wd_to_wv_raw(a) _mm256_castpd_si256( (a) )

/* Reduction operations */

static inline wd_t
wd_sum_all( wd_t x ) { /* Returns wd_bcast( sum( x ) ) */
  x = _mm256_add_pd( x, _mm256_permute2f128_pd( x, x, 1 ) ); /* x02   x13   ... */
  return _mm256_hadd_pd( x, x );                             /* xsum  ... */
}

static inline wd_t
wd_min_all( wd_t a ) { /* Returns wd_bcast( min( x ) ) */
  a = _mm256_min_pd( a, _mm256_permute2f128_pd( a, a, 1 ) );
  return _mm256_min_pd( a, _mm256_permute_pd( a, 5 ) );
}

static inline wd_t
wd_max_all( wd_t a ) { /* Returns wd_bcast( max( x ) ) */
  a = _mm256_max_pd( a, _mm256_permute2f128_pd( a, a, 1 ) );
  return _mm256_max_pd( a, _mm256_permute_pd( a, 5 ) );
}

/* Misc operations */

/* wd_gather(b,i,imm_hi) returns
     [ b[i(0)] b[i(1)] b[i(2)] b[i(3)] ] if imm_hi is 0 and
     [ b[i(4)] b[i(5)] b[i(6)] b[i(7)] ] o.w.
   where b is a "double const*", i is wi_t and imm_hi is a compile time
   constant. */

#define wd_gather(b,i,imm_hi) _mm256_i32gather_pd( (b), _mm256_extractf128_si256( (i), !!(imm_hi) ), 8 )

/* wd_transpose_4x4 transposes the 4x4 matrix stored in wd_t r0,r1,r2,r3
   and stores the result in 4x4 matrix wd_t c0,c1,c2,c3.  All
   c0,c1,c2,c3 should be different for a well defined result.
   Otherwise, in-place operation and/or using the same wd_t to specify
   multiple rows of r is fine. */

#define wd_transpose_4x4( r0,r1,r2,r3, c0,c1,c2,c3 ) do {                                                                      \
    wd_t _wd_transpose_r0 = (r0); wd_t _wd_transpose_r1 = (r1); wd_t _wd_transpose_r2 = (r2); wd_t _wd_transpose_r3 = (r3);    \
    wd_t _wd_transpose_t;                                                                                                      \
    /* Transpose 2x2 blocks */                                                                                                 \
    _wd_transpose_t = _wd_transpose_r0; _wd_transpose_r0 = _mm256_permute2f128_pd( _wd_transpose_t,  _wd_transpose_r2, 0x20 ); \
    /**/                                _wd_transpose_r2 = _mm256_permute2f128_pd( _wd_transpose_t,  _wd_transpose_r2, 0x31 ); \
    _wd_transpose_t = _wd_transpose_r1; _wd_transpose_r1 = _mm256_permute2f128_pd( _wd_transpose_t,  _wd_transpose_r3, 0x20 ); \
    /**/                                _wd_transpose_r3 = _mm256_permute2f128_pd( _wd_transpose_t,  _wd_transpose_r3, 0x31 ); \
    /* Transpose 1x1 blocks */                                                                                                 \
    /**/                                (c0)             = _mm256_unpacklo_pd(     _wd_transpose_r0, _wd_transpose_r1 );       \
    /**/                                (c1)             = _mm256_unpackhi_pd(     _wd_transpose_r0, _wd_transpose_r1 );       \
    /**/                                (c2)             = _mm256_unpacklo_pd(     _wd_transpose_r2, _wd_transpose_r3 );       \
    /**/                                (c3)             = _mm256_unpackhi_pd(     _wd_transpose_r2, _wd_transpose_r3 );       \
  } while(0)
