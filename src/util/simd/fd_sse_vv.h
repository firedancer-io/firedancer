#ifndef HEADER_fd_src_util_simd_fd_sse_h
#error "Do not include this directly; use fd_sse.h"
#endif

/* Vector ulong API ***************************************************/

/* A vv_t is a vector where each adjacent pair of 32-bit wide lanes
   (e.g. 0-1 / 2-3) holds an unsigned 64-bit twos-complement integer (a
   "ulong").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define vv_t __m128i

/* Constructors */

/* Given the long values, return ... */

#define vv(v0,v1) _mm_set_epi64x( (long)(v1), (long)(v0) ) /* [ v0 v1 ] ... sigh ... backwards intel */

#define vv_bcast(v0) _mm_set1_epi64x( (long)(v0) ) /* [ v0 v0 ] */

/* vv_permute returns [ l(imm_i0) l(imm_i1) ].  imm_i* should be compile
   time constants in 0:1. */

#define vv_permute( v, imm_i0, imm_i1 ) _mm_castpd_si128( _mm_permute_pd( _mm_castsi128_pd( (v) ), (imm_i0) + 2*(imm_i1) ) )

/* Predefined constants */

#define vv_zero() _mm_setzero_si128()   /* Return [ 0UL 0UL ] */
#define vv_one()  _mm_set1_epi64x( 1L ) /* Return [ 1UL 1UL ] */

/* Memory operations */

/* vv_ld return the 2 ulongs at the 16-byte aligned / 16-byte sized
   location p as a vector ulong.  vv_ldu is the same but p does not have
   to be aligned.  vv_st writes the vector ulong to the 16-byte aligned /
   16-byte sized location p as 2 ulongs.  vv_stu is the same but p does
   not have to be aligned.  In all these 64-bit lane l will be at p[l].
   FIXME: USE ATTRIBUTES ON P PASSED TO THESE?

   Note: gcc knows a __m128i may alias. */

static inline vv_t vv_ld( ulong const * p ) { return _mm_load_si128(  (__m128i const *)p ); }
static inline void vv_st( ulong * p, vv_t i ) { _mm_store_si128(  (__m128i *)p, i ); }

static inline vv_t vv_ldu( void const * p ) { return _mm_loadu_si128( (__m128i const *)p ); }
static inline void vv_stu( void * p, vv_t i ) { _mm_storeu_si128( (__m128i *)p, i ); }

/* vv_ldif is an optimized equivalent to vv_notczero(c,vv_ldu(p)) (may
   have different behavior if c is not a proper vector conditional).  It
   is provided for symmetry with the vv_stif operation.  vv_stif stores
   x(n) to p[n] if c(n) is true and leaves p[n] unchanged otherwise.
   Undefined behavior if c is not a proper vector conditional. */

#define vv_ldif(c,p)   _mm_maskload_epi64( (p),(c))
#define vv_stif(c,p,x) _mm_maskstore_epi64((p),(c),(x))

/* Element operations */

/* vv_extract extracts the ulong in lane imm from the vector ulong as a
   ulong.  vv_insert returns the vector ulong formed by replacing the
   value in lane imm of a with the provided ulong.  imm should be a
   compile time known in 0:1.  vv_extract_variable and
   vv_insert_variable are the slower but the lane n does not have to be
   known at compile time (should still be in 0:1).

   Note: C99 TC3 allows type punning through a union. */

#define vv_extract(a,imm)  ((ulong)_mm_extract_epi64( (a), (imm) ))

#define vv_insert(a,imm,v) _mm_insert_epi64( (a), (long)(v), (imm) )

static inline ulong
vv_extract_variable( vv_t a, int n ) {
  union { __m128i m[1]; ulong u[2]; } t[1];
  _mm_store_si128( t->m, a );
  return t->u[n];
}

static inline vv_t
vv_insert_variable( vv_t a, int n, ulong v ) {
  union { __m128i m[1]; ulong u[2]; } t[1];
  _mm_store_si128( t->m, a );
  t->u[n] = v;
  return _mm_load_si128( t->m );
}

/* Given [a0 a1] and/or [b0 b1], return ... */

/* Arithmetic operations */

#define vv_neg(a) _mm_sub_epi64( _mm_setzero_si128(), (a) ) /* [ -a0  -a1  ] */
#define vv_abs(a) (a)                                       /* [ |a0| |a1| ] */

/* Note: _mm_{min,max}_epu64 are missing pre AVX-512.  We emulate these
   on pre AVX-512 targets below (and use the AVX-512 versions if
   possible).  Likewise, there is no _mm_mullo_epi64 pre AVX-512.  Since
   this is not cheap to emulate, we do not provide a wl_mul for the time
   being (we could consider exposing it on AVX-512 targets though).
   There is a 64L*64L->64 multiply (where the lower 32-bits will be zero
   extended to 64-bits beforehand) though and that is very useful.  So
   we do provide that. */

#define vv_add(a,b)    _mm_add_epi64(   (a), (b) ) /* [ a0 +b0     a1 +b1     ] */
#define vv_sub(a,b)    _mm_sub_epi64(   (a), (b) ) /* [ a0 -b0     a1 -b1     ] */
//#define vv_mul(a,b)  _mm_mullo_epi64( (a), (b) ) /* [ a0 *b0     a1 *b1     ] */
#define vv_mul_ll(a,b) _mm_mul_epu32(   (a), (b) ) /* [ a0l*b0l    a1l*b1l    ] */

/* Binary operations */

/* Note: vv_shl/vv_shr/vv_shru is a left/right shift by imm bits; imm
   should be a compile time constant in 0:63.  The variable variants are
   slower but do not require the shift amount to be known at compile
   time (should still be in 0:63). */

#define vv_not(a) _mm_xor_si128( _mm_set1_epi64x( -1L ), (a) ) /* [ ~a0 ~a1 ] */

#define vv_shl(a,imm) _mm_slli_epi64( (a), (imm) ) /* [ a0<<imm a1<<imm ] */
#define vv_shr(a,imm) _mm_srli_epi64( (a), (imm) ) /* [ a0>>imm a1>>imm ] */

#define vv_shl_variable(a,n) _mm_sll_epi64( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
#define vv_shr_variable(a,n) _mm_srl_epi64( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )

#define vv_shl_vector(a,b) _mm_sllv_epi64( (a), (b) ) /* [ a0<<b0 a1<<b1 ] */
#define vv_shr_vector(a,b) _mm_srlv_epi64( (a), (b) ) /* [ a0>>b0 a1>>b1 ] */

#define vv_and(a,b)    _mm_and_si128(    (a), (b) ) /* [   a0 &b0    a1& b1 ] */
#define vv_andnot(a,b) _mm_andnot_si128( (a), (b) ) /* [ (~a0)&b0  (~a1)&b1 ] */
#define vv_or(a,b)     _mm_or_si128(     (a), (b) ) /* [   a0 |b0    a1 |b1 ] */
#define vv_xor(a,b)    _mm_xor_si128(    (a), (b) ) /* [   a0 ^b0    a1 ^b1 ] */

static inline vv_t vv_rol( vv_t a, int imm ) { return vv_or( vv_shl( a, imm & 63 ), vv_shr( a, (-imm) & 63 ) ); }
static inline vv_t vv_ror( vv_t a, int imm ) { return vv_or( vv_shr( a, imm & 63 ), vv_shl( a, (-imm) & 63 ) ); }

static inline vv_t vv_rol_variable( vv_t a, int n ) { return vv_or( vv_shl_variable( a, n&63 ), vv_shr_variable( a, (-n)&63 ) ); }
static inline vv_t vv_ror_variable( vv_t a, int n ) { return vv_or( vv_shr_variable( a, n&63 ), vv_shl_variable( a, (-n)&63 ) ); }

static inline vv_t vv_rol_vector( vv_t a, vl_t b ) {
  vl_t m = vl_bcast( 63L );
  return vv_or( vv_shl_vector( a, vl_and( b, m ) ), vv_shr_vector( a, vl_and( vl_neg( b ), m ) ) );
}

static inline vv_t vv_ror_vector( vv_t a, vl_t b ) {
  vl_t m = vl_bcast( 63L );
  return vv_or( vv_shr_vector( a, vl_and( b, m ) ), vv_shl_vector( a, vl_and( vl_neg( b ), m ) ) );
}

#define vv_bswap(a) vu_to_vv_raw( vu_bswap( vv_to_vu_raw( vv_rol( (a), 32 ) ) ) )

/* Logical operations */

/* Like noted below in the converters, Intel clearly has the hardware to
   do a _mm_cmpgt_epu64 given that _mm_cmpgt_epi64 exists but doesn't
   expose it in the ISA pre AVX-512.  Sigh ... twos complement bit
   tricks to the rescue for wu_{gt,lt,ge,le}. */

#define vv_lnot(a)    _mm_cmpeq_epi64( (a), _mm_setzero_si128() )                                          /* [  !a0  !a1 ] */
#define vv_lnotnot(a) _mm_xor_si128( _mm_set1_epi64x( -1L ), _mm_cmpeq_epi64( (a), _mm_setzero_si128() ) ) /* [ !!a0 !!a1 ] */

#define vv_eq(a,b) _mm_cmpeq_epi64( (a), (b) )                                                 /* [ a0==b0 a1==b1 ] */
#define vv_gt(a,b) _mm_cmpgt_epi64( _mm_sub_epi64( (a), _mm_set1_epi64x( (long)(1UL<<63) ) ),  /* [ a0> b0 a1> b1 ] */ \
                                    _mm_sub_epi64( (b), _mm_set1_epi64x( (long)(1UL<<63) ) ) )
#define vv_lt(a,b) vv_gt( (b), (a) )                                                           /* [ a0< b0 a1< b1 ] */
#define vv_ne(a,b) _mm_xor_si128( _mm_set1_epi64x( -1L ), _mm_cmpeq_epi64( (a), (b) ) )        /* [ a0!=b0 a1!=b1 ] */
#define vv_ge(a,b) _mm_xor_si128( _mm_set1_epi64x( -1L ), vv_gt( (b), (a) ) )                  /* [ a0>=b0 a1>=b1 ] */
#define vv_le(a,b) _mm_xor_si128( _mm_set1_epi64x( -1L ), vv_gt( (a), (b) ) )                  /* [ a0<=b0 a1<=b1 ] */

/* Conditional operations */

#define vv_czero(c,f)    _mm_andnot_si128( (c), (f) )  /* [ c0?0UL:f0 c1?0UL:f1 ] */
#define vv_notczero(c,f) _mm_and_si128(    (c), (f) )  /* [ c0?f0:0UL c1?f1:0UL ] */

#define vv_if(c,t,f) _mm_blendv_epi8(  (f), (t), (c) ) /* [ c0?t0:f0  c1?t1:f1  ] */

#if defined(__AVX512F__) && defined(__AVX512VL__) /* See note above */
#define vv_min(a,b) _mm_min_epu64( (a), (b) )
#define vv_max(a,b) _mm_max_epu64( (a), (b) )
#else
static inline vv_t vv_min( vv_t a, vv_t b ) { return vv_if( vv_lt( a, b ), a, b ); }
static inline vv_t vv_max( vv_t a, vv_t b ) { return vv_if( vv_gt( a, b ), a, b ); }
#endif

/* Conversion operations */

/* Summarizing:

   vv_to_vc(d)     returns [ !!v0 !!v0 !!v1 !!v1 ]

   vv_to_vf(l,i,0) returns [ (float)v0 (float)v1 f2 f3 ]
   vv_to_vf(l,i,1) returns [ f0 f1 (float)v0 (float)v1 ]

   vv_to_vi(l,i,0) returns [ (int)v0 (int)v1 i2 i3 ]
   vv_to_vi(l,i,1) returns [ i0 i1 (int)v0 (int)v1 ]

   vv_to_vu(l,u,0) returns [ (uint)v0 (uint)v1 u2 u3 ]
   vv_to_vu(l,u,1) returns [ u0 u1 (uint)v0 (uint)v1 ]

   vv_to_vd(l)     returns [ (double)v0 (double)v1 ]

   vv_to_vl(l)     returns [ (long)v0 (long)v1 ]

   The raw variants just treat the raw bits as the corresponding vector
   type.  For vv_to_vc_raw, the user promises vv contains a proper
   vector conditional (e.g. 0 or -1 in each lane).  The others are
   provided to facilitate doing advanced bit tricks on floating point
   values. */

#define vv_to_vc(a) _mm_xor_si128( _mm_set1_epi64x( -1L ), _mm_cmpeq_epi64( (a), _mm_setzero_si128() ) )

static inline vf_t vv_to_vf( vv_t v, vf_t f, int imm_hi ) {
  float f0 = (float)vv_extract( v, 0 );
  float f1 = (float)vv_extract( v, 1 );
  return imm_hi ? vf_insert( vf_insert( f, 2, f0 ), 3, f1 ) : vf_insert( vf_insert( f, 0, f0 ), 1, f1 ); /* Compile time */
}

static inline vv_t vv_to_vi( vv_t v, vi_t i, int imm_hi ) {
  vf_t _v = _mm_castsi128_ps( v ); /* [ x0l x0h x1l x1h ] */
  vf_t _i = _mm_castsi128_ps( i );
  if( imm_hi ) _v = _mm_shuffle_ps( _i, _v, _MM_SHUFFLE(2,0,1,0) ); /* Compile time */
  else         _v = _mm_shuffle_ps( _v, _i, _MM_SHUFFLE(3,2,2,0) );
  return _mm_castps_si128( _v );
}

static inline vv_t vv_to_vu( vv_t v, vu_t u, int imm_hi ) {
  vf_t _v = _mm_castsi128_ps( v ); /* [ x0l x0h x1l x1h ] */
  vf_t _u = _mm_castsi128_ps( u );
  if( imm_hi ) _v = _mm_shuffle_ps( _u, _v, _MM_SHUFFLE(2,0,1,0) ); /* Compile time */
  else         _v = _mm_shuffle_ps( _v, _u, _MM_SHUFFLE(3,2,2,0) );
  return _mm_castps_si128( _v );
}

static inline vd_t vv_to_vd( vv_t v ) {
  return _mm_setr_pd( (double)(ulong)_mm_extract_epi64( v, 0 ), (double)(ulong)_mm_extract_epi64( v, 1 ) );
}

#define vv_to_vl(a) (a)

#define vv_to_vc_raw(a) (a)
#define vv_to_vf_raw(a) _mm_castsi128_ps( (a) )
#define vv_to_vi_raw(a) (a)
#define vv_to_vu_raw(a) (a)
#define vv_to_vd_raw(a) _mm_castsi128_pd( (a) )
#define vv_to_vl_raw(a) (a)

/* Reduction operations */

static inline vv_t
vv_sum_all( vv_t x ) { /* Returns vv_bcast( sum( x ) ) */
  return vv_add( x, vv_permute( x, 1, 0 ) );
}

static inline vv_t
vv_min_all( vv_t x ) { /* Returns vv_bcast( min( x ) ) */
  return vv_min( x, vv_permute( x, 1, 0 ) );
}

static inline vv_t
vv_max_all( vv_t x ) { /* Returns vv_bcast( max( x ) ) */
  return vv_max( x, vv_permute( x, 1, 0 ) );
}

/* Misc operations */

/* vv_gather(b,i,imm_i0,imm_i1) returns [ b[i(imm_i0)] b[i(imm_i1)] ]
   where b is a  "ulong const *" and i is a vi_t and imm_i0,imm_i1 are
   compile time constants in 0:3.  We use a static inline here instead
   of a define to keep strict type checking while working around yet
   another Intel intrinsic type mismatch issue.  And we use a define to
   workaround clang sadness with passing a compile time constant into a
   static inline. */

static inline vv_t _vv_gather( ulong const * b, vi_t i ) {
  return _mm_i32gather_epi64( (long long const *)b, i, 8 );
}

#define vv_gather(b,i,imm_i0,imm_i1) _vv_gather( (b), _mm_shuffle_epi32( (i), _MM_SHUFFLE(3,2,(imm_i1),(imm_i0)) ) )

/* vv_transpose_2x2 transposes the 2x2 matrix stored in vv_t r0,r1
   and stores the result in 2x2 matrix vv_t c0,c1.  All c0,c1 should be
   different for a well defined result.  Otherwise, in-place operation
   and/or using the same vv_t to specify multiple rows of r is fine. */

#define vv_transpose_2x2( r0,r1, c0,c1 ) do {                        \
    vv_t _vv_transpose_r0 = (r0); vv_t _vv_transpose_r1 = (r1);      \
    (c0) = _mm_unpacklo_epi64( _vv_transpose_r0, _vv_transpose_r1 ); \
    (c1) = _mm_unpackhi_epi64( _vv_transpose_r0, _vv_transpose_r1 ); \
  } while(0)
