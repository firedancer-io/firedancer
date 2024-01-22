#ifndef HEADER_fd_src_util_simd_fd_sse_h
#error "Do not include this directly; use fd_sse.h"
#endif

/* Vector double API **************************************************/

/* A vd_t is a vector where each adjacent pair of 32-bit wide lanes
   (e.g. 0-1 / 2-3) hold a double precision IEEE 754 floating point
   value (a "double").

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
   vector conditional should have identical values in adjacent pairs of
   lanes.  Results are undefined otherwise.

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define vd_t __m128d

/* Constructors */

/* Given the double values, return ... */

#define vd(d0,d1) _mm_setr_pd( (d0), (d1) ) /* [ d0 d1 ] */

#define vd_bcast(d0) _mm_set1_pd( (d0) ) /* [ d0 d0 ] */

/* vd_permute returns [ d(imm_i0) d(imm_i1) ].  imm_i* should be compile
   time constants in 0:1. */

#define vd_permute( d, imm_i0, imm_i1 ) _mm_permute_pd( (d), (imm_i0) + 2*(imm_i1) )

/* Predefined constants */

#define vd_zero() _mm_setzero_pd() /* Return [ 0. 0. ] */
#define vd_one()  _mm_set1_pd(1.)  /* Return [ 1. 1. ] */

/* Memory operations */

/* vd_ld return the 2 doubles at the 16-byte aligned / 16-byte sized
   location p as a vector double.  vd_ldu is the same but p does not have
   to be aligned.  vd_st writes the vector double to the 16-byte aligned
   / 16-byte sized location p as 2 doubles.  vd_stu is the same but p
   does not have to be aligned.  In all these 64-bit lane l will be at
   p[l].  FIXME: USE ATTRIBUTES ON P PASSED TO THESE? */

#define vd_ld(p)    _mm_load_pd( (p) )
#define vd_ldu(p)   _mm_loadu_pd( (p) )
#define vd_st(p,d)  _mm_store_pd( (p), (d) )
#define vd_stu(p,d) _mm_storeu_pd( (p), (d) )

/* vd_ldif is an optimized equivalent to vd_notczero(c,vd_ldu(p)) (may
   have different behavior if c is not a proper vector conditional).  It
   is provided for symmetry with the vd_stif operation.  vd_stif stores
   x(n) to p[n] if c(n) is true and leaves p[n] unchanged otherwise.
   Undefined behavior if c(n) is not a proper paired lane vector
   conditional. */

#define vd_ldif(c,p)   _mm_maskload_pd( (p),(c))
#define vd_stif(c,p,x) _mm_maskstore_pd((p),(c),(x))

/* Element operations */

/* vd_extract extracts the double in 64-bit lane imm (e.g. indexed
   0 and 1 corresponding to 32-bit pairs of lanes 0-1 and 2-3
   respectively) from the vector double as a double.  vd_insert returns
   the vector double formed by replacing the value in 64-bit lane imm of
   a with the provided double.  imm should be a compile time constant in
   0:1.  vd_extract_variable and vd_insert_variable are the slower but
   the 64-bit lane n does not have to be known at compile time (should
   still be in 0:1). */

static inline double
vd_extract( vd_t a, int imm ) { /* FIXME: USE EPI64 HACKS? */
  double d[2] V_ATTR;
  _mm_store_pd( d, a );
  return d[imm];
}

static inline vd_t
vd_insert( vd_t a, int imm, double v ) { /* FIXME: USE EPI64 HACKS? */
  double d[2] V_ATTR;
  _mm_store_pd( d, a );
  d[imm] = v;
  return _mm_load_pd( d );
}

static inline double
vd_extract_variable( vd_t a, int n ) {
  double d[2] V_ATTR;
  _mm_store_pd( d, a );
  return d[n];
}

static inline vd_t
vd_insert_variable( vd_t a, int n, double v ) {
  double d[2] V_ATTR;
  _mm_store_pd( d, a );
  d[n] = v;
  return _mm_load_pd( d );
}

/* Arithmetic operations */

/* vd_neg(a)        returns [       -a0        -a1  ] (i.e.       -a )
   vd_sign(a)       returns [   sign(a0)   sign(a1) ]
   vd_abs(a)        returns [   fabs(a0)   fabs(a1) ] (i.e.    abs(a))
   vd_negabs(a)     returns [  -fabs(a0)  -fabs(a1) ] (i.e.   -abs(a))
   vd_ceil(a)       returns [   ceil(a0)   ceil(a1) ] (i.e.   ceil(a))
   vd_floor(a)      returns [  floor(a0)  floor(a1) ] (i.e.  floor(a))
   vd_rint(a)       returns [   rint(a0)   rint(a1) ] (i.e. roundb(a))
   vd_trunc(a)      returns [  trunc(a0)  trunc(a1) ] (i.e.    fix(a))
   vd_sqrt(a)       returns [   sqrt(a0)   sqrt(a1) ] (i.e.   sqrt(a))
   vd_rcp_fast(a)   returns [   ~rcp(a0)   ~rcp(a1) ]
   vd_rsqrt_fast(a) returns [ ~rsqrt(a0) ~rsqrt(a1) ]

   vd_add(     a,b) returns [          a0+b0           a1+b1  ] (i.e. a +b)
   vd_sub(     a,b) returns [          a0-b0           a1-b1  ] (i.e. a -b)
   vd_mul(     a,b) returns [          a0*b0           a1*b1  ] (i.e. a.*b)
   vd_div(     a,b) returns [          a0/b0           a1/b1  ] (i.e. a./b)
   vd_min(     a,b) returns [     fmin(a0,b0)     fmin(a1,b1) ] (i.e. min([a;b]) (a and b are 1x2)
   vd_max(     a,b) returns [     fmax(a0,b0)     fmax(a1,b1) ] (i.e. max([a;b]) (a and b are 1x2)
   vd_copysign(a,b) returns [ copysign(a0,b0) copysign(a1,b1) ]
   vd_flipsign(a,b) returns [ flipsign(a0,b0) flipsign(a1,b1) ]

   vd_fma( a,b,c)   returns [  fma(a0,b0, c0)  fma(a1,b1, c1) ] (i.e.  a.*b+c)
   vd_fms( a,b,c)   returns [  fma(a0,b0,-c0)  fma(a1,b1,-c1) ] (i.e.  a.*b-c)
   vd_fnma(a,b,c)   returns [ -fma(a0,b0,-c0) -fma(a1,b1,-c1) ] (i.e. -a.*b+c)

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

#define vd_neg(a)        _mm_xor_pd(    _mm_set1_pd( -0. ), (a) )
#define vd_sign(a)       _mm_xor_pd(    _mm_set1_pd(  1. ), _mm_and_pd( _mm_set1_pd( -0. ), (a) ) )
#define vd_abs(a)        _mm_andnot_pd( _mm_set1_pd( -0. ), (a) )
#define vd_negabs(a)     _mm_or_pd(     _mm_set1_pd( -0. ), (a) )
#define vd_ceil(a)       _mm_ceil_pd(  (a) )
#define vd_floor(a)      _mm_floor_pd( (a) )
#define vd_rint(a)       _mm_round_pd( (a), _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC )
#define vd_trunc(a)      _mm_round_pd( (a), _MM_FROUND_TO_ZERO        | _MM_FROUND_NO_EXC )
#define vd_sqrt(a)       _mm_sqrt_pd(  (a) )
#define vd_rcp_fast(a)   _mm_cvtps_pd( _mm_rcp_ps(   _mm_cvtpd_ps( (a) ) ) )
#define vd_rsqrt_fast(a) _mm_cvtps_pd( _mm_rsqrt_ps( _mm_cvtpd_ps( (a) ) ) )

#define vd_add(a,b)      _mm_add_pd( (a), (b) )
#define vd_sub(a,b)      _mm_sub_pd( (a), (b) )
#define vd_mul(a,b)      _mm_mul_pd( (a), (b) )
#define vd_div(a,b)      _mm_div_pd( (a), (b) )
#define vd_min(a,b)      _mm_min_pd( (a), (b) )
#define vd_max(a,b)      _mm_max_pd( (a), (b) )
#define vd_copysign(a,b) _mm_or_pd( _mm_andnot_pd( _mm_set1_pd( -0. ), (a) ), _mm_and_pd( _mm_set1_pd( -0. ), (b) ) )
#define vd_flipsign(a,b) _mm_xor_pd( (a), _mm_and_pd( _mm_set1_pd( -0. ), (b) ) )

#define vd_fma(a,b,c)  _mm_fmadd_pd(  (a), (b), (c) )
#define vd_fms(a,b,c)  _mm_fmsub_pd(  (a), (b), (c) )
#define vd_fnma(a,b,c) _mm_fnmadd_pd( (a), (b), (c) )

/* Binary operations */

/* Note: binary operations are not well defined on vector doubles.
   If doing tricks with floating point binary representations, the user
   should use vd_to_vi_raw as necessary. */

/* Logical operations */

/* These all return proper paired lane vector conditionals */

#define vd_lnot(a)    /* [  !a0  !a0  !a1  !a1 ] */ \
  _mm_castpd_si128( _mm_cmp_pd( (a), _mm_setzero_pd(), _CMP_EQ_OQ  ) )
#define vd_lnotnot(a) /* [ !!a0 !!a0 !!a1 !!a1 ] */ \
  _mm_castpd_si128( _mm_cmp_pd( (a), _mm_setzero_pd(), _CMP_NEQ_OQ ) )
#define vd_signbit(a) /* [ signbit(a0) signbit(a0) signbit(a1) signbit(a1) ] */ \
  _mm_castps_si128( _mm_permute_ps( _mm_castsi128_ps( _mm_srai_epi32( _mm_castpd_si128( (a) ), 31 ) ), _MM_SHUFFLE(3,3,1,1) ) )

#define vd_eq(a,b) _mm_castpd_si128( _mm_cmp_pd( (a), (b), _CMP_EQ_OQ  ) ) /* [ a0==b0 a0==b0 a1==b1 a1==b1 ] */
#define vd_gt(a,b) _mm_castpd_si128( _mm_cmp_pd( (a), (b), _CMP_GT_OQ  ) ) /* [ a0> b0 a0> b0 a1> b1 a1> b1 ] */
#define vd_lt(a,b) _mm_castpd_si128( _mm_cmp_pd( (a), (b), _CMP_LT_OQ  ) ) /* [ a0< b0 a0< b0 a1< b1 a1< b1 ] */
#define vd_ne(a,b) _mm_castpd_si128( _mm_cmp_pd( (a), (b), _CMP_NEQ_OQ ) ) /* [ a0!=b0 a0!=b0 a1!=b1 a1!=b1 ] */
#define vd_ge(a,b) _mm_castpd_si128( _mm_cmp_pd( (a), (b), _CMP_GE_OQ  ) ) /* [ a0>=b0 a0>=b0 a1>=b1 a1>=b1 ] */
#define vd_le(a,b) _mm_castpd_si128( _mm_cmp_pd( (a), (b), _CMP_LE_OQ  ) ) /* [ a0<=b0 a0<=b0 a1<=b1 a1<=b1 ] */

/* Conditional operations */

/* c should be a proper paired lane vector conditional for these */

#define vd_czero(c,a)    _mm_andnot_pd( _mm_castsi128_pd( (c) ), (a) )  /* [ c01?0.:a0 c23?0.:a1 ] */
#define vd_notczero(c,a) _mm_and_pd(    _mm_castsi128_pd( (c) ), (a) )  /* [ c01?a0:0. c23?a1:0. ] */

#define vd_if(c,t,f) _mm_blendv_pd( (f), (t), _mm_castsi128_pd( (c) ) ) /* [ c01?t0:f0 c23?t1:f1 ] */

/* Conversion operations */

/* Summarizing:

   vd_to_vc(d)          returns [ !!d0 !!d0 !!d1 !!d1 ] ... proper paired lane

   vd_to_vf(d,f,0)      returns [ (float)d0 (float)d1 f2 f3 ]
   vd_to_vf(d,f,1)      returns [ f0 f1 (float)d0 (float)d1 ]

   vd_to_vi(d,i,0)      returns [ (int)d0 (int)d1 i2 i3 ]
   vd_to_vi(d,i,1)      returns [ i0 i1 (int)d0 (int)d1 ]

   vd_to_vi_fast(d,i,0) returns [ (int)rint(d0) (int)rint(d1) i2 i3 ]
   vd_to_vi_fast(d,i,1) returns [ i0 i1 (int)rint(d0) (int)rint(d1) ]

   vd_to_vu(d,u,0)      returns [ (uint)d0 (uint)d1 u2 u3 ]
   vd_to_vu(d,u,1)      returns [ u0 u1 (uint)d0 (uint)d1 ]

   vd_to_vu_fast(d,u,0) returns [ (uint)rint(d0) (uint)rint(d1) u2 u3 ]
   vd_to_vu_fast(d,u,1) returns [ u0 u1 (uint)rint(d0) (uint)rint(d1) ]

   vd_to_vl(d)          returns [ (long)d0 (long)d1 ]

   vd_to_vv(v)          returns [ (ulong)d0 (ulong)d1 ]

   where rint is configured for round-to-nearest-even rounding (Intel
   architecture defaults to round-nearest-even here ... sigh, they still
   don't fully get it) and imm_hi should be a compile time constant.
   That is, the fast variants assume that float point inputs are already
   integral value in the appropriate range for the output type.

   Note that vd_to_{vf,vi,vi_fast} insert the converted values into
   lanes 0:1 (imm_hi==0) or 2:3 (imm_hi!=0) of the provided vector.

   The raw variants return just the raw bits as the corresponding vector
   type.  vd_to_vl_raw allows doing advanced bit tricks on a vector
   double.  The others are probably dubious but are provided for
   completeness. */

#define vd_to_vc(d) _mm_castpd_si128( _mm_cmp_pd( (d), _mm_setzero_pd(), _CMP_NEQ_OQ ) )

static inline vf_t vd_to_vf( vd_t d, vf_t f, int imm_hi ) {
  vf_t _d = _mm_cvtpd_ps( d ); /* [ d0 d1  0  0 ] */
  if( imm_hi ) _d = _mm_shuffle_ps( f, _d, _MM_SHUFFLE(1,0,1,0) ); /* Compile time */ /* mm_movelh_ps? */
  else         _d = _mm_shuffle_ps( _d, f, _MM_SHUFFLE(3,2,1,0) );
  return _d;
}

#define vd_to_vi(d,i,imm_hi) vd_to_vi_fast( _mm_round_pd( (d), _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC ), (i), (imm_hi) )
#define vd_to_vu(d,i,imm_hi) vd_to_vu_fast( _mm_round_pd( (d), _MM_FROUND_TO_ZERO | _MM_FROUND_NO_EXC ), (i), (imm_hi) )

static inline vi_t vd_to_vi_fast( vd_t d, vi_t i, int imm_hi ) {
  vf_t _d = _mm_castsi128_ps( _mm_cvtpd_epi32( d ) ); /* [ d0 d1  0  0 ] */
  vf_t _i = _mm_castsi128_ps( i );
  if( imm_hi ) _d = _mm_shuffle_ps( _i, _d, _MM_SHUFFLE(1,0,1,0) ); /* Compile time */
  else         _d = _mm_shuffle_ps( _d, _i, _MM_SHUFFLE(3,2,1,0) );
  return _mm_castps_si128( _d );
}

static inline vu_t vd_to_vu_fast( vd_t d, vu_t u, int imm_hi ) {

/* Note: Given that _mm_cvtpd_epi32 existed for a long time, Intel
   clearly had the hardware under the hood for _mm_cvtpd_epu32 but
   didn't bother to expose it pre-Skylake-X ... sigh (all too typical
   unfortunately).  We use _mm_cvtpd_epu32 where supported because it
   is faster and it replicates the same IB behaviors as the compiler
   generated scalar ASM for float to uint casts on these targets.

   Pre-Skylake-X, we emulate it by noting that subtracting 2^31
   from a double holding an integer in [0,2^32) is exact and the
   result can be exactly converted to a signed integer by
   _mm_cvtpd_epi32.  We then use twos complement hacks to add back
   any shift.  This also replicates the compiler's IB behaviors on
   these ISAs for float to int casts. */

# if defined(__AVX512F__) && defined(__AVX512VL__)
  vu_t v = _mm_cvtpd_epu32( d );
# else
  /**/                                                 // Assumes d is integer in [0,2^32)
  vd_t s  = vd_bcast( (double)(1UL<<31) );             // (double)2^31
  vc_t c  = vd_lt ( d, s );                            // -1L if d<2^31, 0L o.w.
  vd_t ds = vd_sub( d, s );                            // (double)(d-2^31)
  vu_t v0 = _mm_cvtpd_epi32( vd_if( c, d, ds ) );      // (uint)(d      if d<2^31, d-2^31 o.w.), d/c lanes 2,3
  vu_t v1 = vu_add( v0, vu_bcast( 1U<<31) );           // (uint)(d+2^31 if d<2^31, d      o.w.), d/c lanes 2,3
  vu_t v  = vu_if( vc_permute( c, 0,2,0,2 ), v0, v1 ); // (uint)d, d/c lanes 2,3
# endif
  /* Compile time */
  return imm_hi ? _mm_castps_si128( _mm_shuffle_ps( _mm_castsi128_ps( u ), _mm_castsi128_ps( v ), _MM_SHUFFLE(1,0,1,0) ) )
                : _mm_castps_si128( _mm_shuffle_ps( _mm_castsi128_ps( v ), _mm_castsi128_ps( u ), _MM_SHUFFLE(3,2,1,0) ) );
}

/* FIXME: IS IT FASTER TO USE INSERT / EXTRACT FOR THESE? */

static inline __m128i vd_to_vl( vd_t d ) { /* FIXME: workaround vl_t isn't declared at this point */
  union { double d[2]; __m128d v[1]; } t[1];
  union { long   l[2]; __m128i v[1]; } u[1];
  _mm_store_pd( t->d, d );
  u->l[0] = (long)t->d[0];
  u->l[1] = (long)t->d[1];
  return _mm_load_si128( u->v );
}

static inline __m128i vd_to_vv( vd_t d ) { /* FIXME: workaround vv_t isn't declared at this point */
  union { double d[2]; __m128d v[1]; } t[1];
  union { ulong  u[2]; __m128i v[1]; } u[1];
  _mm_store_pd( t->d, d );
  u->u[0] = (ulong)t->d[0];
  u->u[1] = (ulong)t->d[1];
  return _mm_load_si128( u->v );
}

#define vd_to_vc_raw(a) _mm_castpd_si128( (a) )
#define vd_to_vf_raw(a) _mm_castpd_ps(    (a) )
#define vd_to_vi_raw(a) _mm_castpd_si128( (a) )
#define vd_to_vu_raw(a) _mm_castpd_si128( (a) )
#define vd_to_vl_raw(a) _mm_castpd_si128( (a) )
#define vd_to_vv_raw(a) _mm_castpd_si128( (a) )

/* Reduction operations */

static inline vd_t
vd_sum_all( vd_t x ) { /* Returns vd_bcast( sum( x ) ) */
  return _mm_hadd_pd( x, x ); /* xsum  ... */
}

static inline vd_t
vd_min_all( vd_t a ) { /* Returns vd_bcast( min( x ) ) */
  return _mm_min_pd( a, _mm_permute_pd( a, 1 ) );
}

static inline vd_t
vd_max_all( vd_t a ) { /* Returns vd_bcast( max( x ) ) */
  return _mm_max_pd( a, _mm_permute_pd( a, 1 ) );
}

/* Misc operations */

/* vd_gather(b,i,imm_i0,imm_i1) returns [ b[i(imm_i0)] b[i(imm_i1)] ]
   where b is a  "double const *" and i is a vi_t and imm_i0,imm_i1 are
   compile time constants in 0:3. */

#define vd_gather(b,i,imm_i0,imm_i1) _mm_i32gather_pd( (b), _mm_shuffle_epi32( (i), _MM_SHUFFLE(3,2,(imm_i1),(imm_i0))), 8 )

/* vd_transpose_2x2 transposes the 2x2 matrix stored in vd_t r0,r1
   and stores the result in 2x2 matrix vd_t c0,c1.  All c0,c1 should be
   different for a well defined result.  Otherwise, in-place operation
   and/or using the same vd_t to specify multiple rows of r is fine. */

#define vd_transpose_2x2( r0,r1, c0,c1 ) do {                     \
    vd_t _vd_transpose_r0 = (r0); vd_t _vd_transpose_r1 = (r1);   \
    (c0) = _mm_unpacklo_pd( _vd_transpose_r0, _vd_transpose_r1 ); \
    (c1) = _mm_unpackhi_pd( _vd_transpose_r0, _vd_transpose_r1 ); \
  } while(0)
