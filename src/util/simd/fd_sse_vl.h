#ifndef HEADER_fd_src_util_simd_fd_sse_h
#error "Do not include this directly; use fd_sse.h"
#endif

/* Vector long API ****************************************************/

/* A vl_t is a vector where each adjacent pair of 32-bit wide lanes
   (e.g. 0-1 / 2-3) holds a signed 64-bit twos-complement integer (a
   "long").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define vl_t __m128i

/* Constructors */

/* Given the long values, return ... */

#define vl(l0,l1) _mm_set_epi64x( (l1), (l0) ) /* [ l0 l1 ] ... sigh ... backwards intel */

#define vl_bcast(l0) _mm_set1_epi64x( (l0) ) /* [ l0 l0 ] */

/* vl_permute returns [ l(imm_l0) l(imm_l1) ].  imm_l* should be compile
   time constants in 0:1. */

#define vl_permute( d, imm_l0, imm_l1 ) _mm_castpd_si128( _mm_permute_pd( _mm_castsi128_pd( (d) ), (imm_l0) + 2*(imm_l1) ) )

/* Predefined constants */

#define vl_zero() _mm_setzero_si128()   /* Return [ 0L 0L ] */
#define vl_one()  _mm_set1_epi64x( 1L ) /* Return [ 1L 1L ] */

/* Memory operations */

/* vl_ld return the 2 longs at the 16-byte aligned / 16-byte sized
   location p as a vector long.  vl_ldu is the same but p does not have
   to be aligned.  vl_st writes the vector long to the 16-byte aligned /
   16-byte sized location p as 2 longs.  vl_stu is the same but p does
   not have to be aligned.  In all these 64-bit lane l vlll be at p[l].
   FIXME: USE ATTRIBUTES ON P PASSED TO THESE?
   
   Note: gcc knows a __m128i may alias. */

static inline vl_t vl_ld(  long const * p   ) { return _mm_load_si128(  (__m128i const *)p ); }
static inline vl_t vl_ldu( long const * p   ) { return _mm_loadu_si128( (__m128i const *)p ); }
static inline void vl_st(  long * p, vl_t i ) { _mm_store_si128(  (__m128i *)p, i ); }
static inline void vl_stu( long * p, vl_t i ) { _mm_storeu_si128( (__m128i *)p, i ); }

/* vl_ldif is an optimized equivalent to vl_notczero(c,vl_ldu(p)) (may
   have different behavior if c is not a proper vector conditional).  It
   is provided for symmetry with the vl_stif operation.  vl_stif stores
   x(n) to p[n] if c(n) is true and leaves p[n] unchanged otherwise.
   Undefined behavior if c is not a proper vector conditional. */

#define vl_ldif(c,p)   _mm_maskload_epi64( (p),(c))
#define vl_stif(c,p,x) _mm_maskstore_epi64((p),(c),(x))

/* Element operations */

/* vl_extract extracts the long in lane imm from the vector long as a
   long.  vl_insert returns the vector long formed by replacing the
   value in lane imm of a with the provided long.  imm should be a
   compile time known in 0:1.  vl_extract_variable and
   vl_insert_variable are the slower but the lane n does not have to be
   known at compile time (should still be in 0:1).
   
   Note: C99 TC3 allows type punning through a union. */

#define vl_extract(a,imm)  _mm_extract_epi64( (a), (imm) )

#define vl_insert(a,imm,v) _mm_insert_epi64( (a), (v), (imm) )

static inline long
vl_extract_variable( vl_t a, long n ) {
  union { __m128i m[1]; long l[2]; } t[1];
  _mm_store_si128( t->m, a );
  return t->l[n];
}

static inline vl_t
vl_insert_variable( vl_t a, long n, long v ) {
  union { __m128i m[1]; long l[2]; } t[1];
  _mm_store_si128( t->m, a );
  t->l[n] = v;
  return _mm_load_si128( t->m );
}

/* Given [a0 a1] and/or [b0 b1], return ... */

/* Arithmetic operations */

/* Note: _mm_{abs,min,max}_epi64 are missing in AVX.  We emulate these
   below.  Likewise, there is no _mm_mullo_epi64 in AVX.  Since this is
   not cheap to emulate, we do not provide a wl_mul for the time being.
   There is a 64L*64L->64 multiply (where the lower 32-bits will be sign
   extended to 64-bits beforehand) though and that is very useful.  So
   we do provide that. */

#define vl_neg(a)   _mm_sub_epi64( _mm_setzero_si128(), (a) ) /* [ -a0  -a1  ] (twos complement handling) */
//#define vl_abs(a) _mm_abs_epi64( (a) )                      /* [ |a0| |a1| ] (twos complement handling) */

//#define vl_min(a,b)  _mm_min_epi64(   (a), (b) ) /* [ min(a0,b0) min(a1,b1) ] */
//#define vl_max(a,b)  _mm_max_epi64(   (a), (b) ) /* [ max(a0,b0) max(a1,b1) ] */
#define vl_add(a,b)    _mm_add_epi64(   (a), (b) ) /* [ a0 +b0     a1 +b1     ] */
#define vl_sub(a,b)    _mm_sub_epi64(   (a), (b) ) /* [ a0 -b0     a1 -b1     ] */
//#define vl_mul(a,b)  _mm_mullo_epi64( (a), (b) ) /* [ a0 *b0     a1 *b1     ] */
#define vl_mul_ll(a,b) _mm_mul_epi32(   (a), (b) ) /* [ a0l*b0l    a1l*b1l    ] */

/* Binary operations */

/* Note: vl_shl/vl_shr/vl_shru is a left/signed right/unsigned right
   shift by imm bits; imm should be a compile time constant in 0:63.
   The variable variants are slower but do not require the shift amount
   to be known at compile time (should still be in 0:63).  Also, AVX is
   missing _mm_sra*_epi64 intrinsics.  We emulate these below. */

#define vl_not(a) _mm_xor_si128( _mm_set1_epi64x( -1L ), (a) ) /* [ ~a0 ~a1 ] */

#define vl_shl(a,imm)   _mm_slli_epi64( (a), (imm) ) /* [ a0<<imm a1<<imm ] */
//#define vl_shr(a,imm) _mm_srai_epi64( (a), (imm) ) /* [ a0>>imm a1>>imm ] (treat a as signed)*/
#define vl_shru(a,imm)  _mm_srli_epi64( (a), (imm) ) /* [ a0>>imm a1>>imm ] (treat a as unsigned) */

#define vl_shl_variable(a,n)   _mm_sll_epi64( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
//#define vl_shr_variable(a,n) _mm_sra_epi64( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
#define vl_shru_variable(a,n)  _mm_srl_epi64( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )

#define vl_shl_vector(a,b)   _mm_sllv_epi64( (a), (b) ) /* [ a0<<b0 a1<<b1 ] */
//#define vl_shr_vector(a,b) _mm_srav_epi64( (a), (b) ) /* [ a0>>b0 a1>>b1 ] (treat a as signed) */
#define vl_shru_vector(a,b)  _mm_srlv_epi64( (a), (b) ) /* [ a0>>b0 a1>>b1 ] (treat a as unsigned) */

#define vl_and(a,b)    _mm_and_si128(    (a), (b) ) /* [   a0 &b0    a1& b1 ] */
#define vl_andnot(a,b) _mm_andnot_si128( (a), (b) ) /* [ (~a0)&b0  (~a1)&b1 ] */
#define vl_or(a,b)     _mm_or_si128(     (a), (b) ) /* [   a0 |b0    a1 |b1 ] */
#define vl_xor(a,b)    _mm_xor_si128(    (a), (b) ) /* [   a0 ^b0    a1 ^b1 ] */

/* Logical operations */

#define vl_lnot(a)    _mm_cmpeq_epi64( (a), _mm_setzero_si128() )                                          /* [  !a0  !a1 ] */
#define vl_lnotnot(a) _mm_xor_si128( _mm_set1_epi64x( -1L ), _mm_cmpeq_epi64( (a), _mm_setzero_si128() ) ) /* [ !!a0 !!a1 ] */

#define vl_eq(a,b) _mm_cmpeq_epi64( (a), (b) )                                          /* [ a0==b0 a1==b1 ] */
#define vl_gt(a,b) _mm_cmpgt_epi64( (a), (b) )                                          /* [ a0> b0 a1> b1 ] */
#define vl_lt(a,b) _mm_cmpgt_epi64( (b), (a) )                                          /* [ a0< b0 a1< b1 ] */
#define vl_ne(a,b) _mm_xor_si128( _mm_set1_epi64x( -1L ), _mm_cmpeq_epi64( (a), (b) ) ) /* [ a0!=b0 a1!=b1 ] */
#define vl_ge(a,b) _mm_xor_si128( _mm_set1_epi64x( -1L ), _mm_cmpgt_epi64( (b), (a) ) ) /* [ a0>=b0 a1>=b1 ] */
#define vl_le(a,b) _mm_xor_si128( _mm_set1_epi64x( -1L ), _mm_cmpgt_epi64( (a), (b) ) ) /* [ a0<=b0 a1<=b1 ] */

/* Conditional operations */

#define vl_czero(c,f)    _mm_andnot_si128( (c), (f) ) /* [ c0?0L:f0 c1? 0:f1 ] */
#define vl_notczero(c,f) _mm_and_si128(    (c), (f) ) /* [ c0?f0:0L c1?f1:0L ] */

#define vl_if(c,t,f) _mm_blendv_epi8(  (f), (t), (c) ) /* [ c0?t0:f0 c1?t1:f1 ] */

/* See note above */
static inline vl_t vl_abs( vl_t a )         { return vl_if( vl_lt( a, vl_zero() ), vl_neg( a ), a ); }
static inline vl_t vl_min( vl_t a, vl_t b ) { return vl_if( vl_lt( a, b ), a, b ); } 
static inline vl_t vl_max( vl_t a, vl_t b ) { return vl_if( vl_gt( a, b ), a, b ); }
static inline vl_t vl_shr( vl_t a, int imm ) {
  vc_t c = vl_lt( a, vl_zero() ); /* Note that vc_t is binary compat with vl_t */
  return _mm_xor_si128( _mm_srli_epi64( _mm_xor_si128( a, c ), imm ), c );
}
static inline vl_t vl_shr_variable( vl_t a, int n ) {
  vc_t c = vl_lt( a, vl_zero() ); /* Note that vc_t is binary compat with vl_t */
  return _mm_xor_si128( _mm_srl_epi64( _mm_xor_si128( a, c ), _mm_insert_epi64( _mm_setzero_si128(), n, 0 ) ), c );
}
static inline vl_t vl_shr_vector( vl_t a, vl_t n ) {
  vc_t c = vl_lt( a, vl_zero() ); /* Note that vc_t is binary compat with vl_t */
  return _mm_xor_si128( _mm_srlv_epi64( _mm_xor_si128( a, c ), n ), c );
}

/* Conversion operations */

/* Summarizing:

   vl_to_vc(d)     returns [ !!l0 !!l0 !!l1 !!l1 ] 

   vl_to_vf(l,i,0) returns [ (float)l0 (float)l1 l2 l3 ]
   vl_to_vf(l,i,1) returns [ f0 f1 (float)l0 (float)l1 ]

   vl_to_vi(l,i,0) returns [ (int)l0 (int)l1 i2 i3 ]
   vl_to_vi(l,i,1) returns [ i0 i1 (int)l0 (int)l1 ]

   vl_to_vu(l,u,0) returns [ (uint)l0 (uint)l1 u2 u3 ]
   vl_to_vu(l,u,1) returns [ u0 u1 (uint)l2 (uint)l3 ]

   vl_to_vd(l)     returns [ (double)l0 (double)l1 ]

   The raw variants just treat the raw bits as the corresponding vector
   type.  For vl_to_vc_raw, the user promises vl contains a proper
   vector conditional (e.g. 0 or -1 in each lane).  The others are
   provided to facilitate doing advanced bit tricks on floating point
   values. */

#define vl_to_vc(a) _mm_xor_si128( _mm_set1_epi64x( -1L ), _mm_cmpeq_epi64( (a), _mm_setzero_si128() ) )

static inline vf_t vl_to_vf( vl_t l, vf_t f, int imm_hi ) {
  float f0 = (float)_mm_extract_epi64( l, 0 );
  float f1 = (float)_mm_extract_epi64( l, 1 );
  return imm_hi ? vf_insert( vf_insert( f, 2, f0 ), 3, f1 ) : vf_insert( vf_insert( f, 0, f0 ), 1, f1 ); /* Compile time */
}

static inline vl_t vl_to_vi( vl_t l, vi_t i, int imm_hi ) {
  vf_t _l = _mm_castsi128_ps( l ); /* [ x0l x0h x1l x1h ] */
  vf_t _i = _mm_castsi128_ps( i );
  if( imm_hi ) _l = _mm_shuffle_ps( _i, _l, _MM_SHUFFLE(2,0,1,0) ); /* Compile time */
  else         _l = _mm_shuffle_ps( _l, _i, _MM_SHUFFLE(3,2,2,0) );
  return _mm_castps_si128( _l );
}

static inline vl_t vl_to_vu( vl_t l, vu_t u, int imm_hi ) {
  vf_t _l = _mm_castsi128_ps( l ); /* [ x0l x0h x1l x1h ] */
  vf_t _u = _mm_castsi128_ps( u );
  if( imm_hi ) _l = _mm_shuffle_ps( _u, _l, _MM_SHUFFLE(2,0,1,0) ); /* Compile time */
  else         _l = _mm_shuffle_ps( _l, _u, _MM_SHUFFLE(3,2,2,0) );
  return _mm_castps_si128( _l );
}

static inline vd_t vl_to_vd( vl_t l ) {
  return _mm_setr_pd( (double)_mm_extract_epi64( l, 0 ), (double)_mm_extract_epi64( l, 1 ) );
}

#define vl_to_vc_raw(a) (a)
#define vl_to_vf_raw(a) _mm_castsi128_ps( (a) )
#define vl_to_vi_raw(a) (a)
#define vl_to_vd_raw(a) _mm_castsi128_pd( (a) )

/* Reduction operations */

static inline vl_t
vl_sum_all( vl_t x ) { /* Returns vl_bcast( sum( x ) ) */
  return vl_add( x, vl_permute( x, 1, 0 ) );
}

static inline vl_t
vl_min_all( vl_t x ) { /* Returns vl_bcast( min( x ) ) */
  return vl_min( x, vl_permute( x, 1, 0 ) );
}

static inline vl_t
vl_max_all( vl_t x ) { /* Returns vl_bcast( max( x ) ) */
  return vl_max( x, vl_permute( x, 1, 0 ) );
}

/* Misc operations */

/* vl_gather(b,i,imm_l0,imm_l1) returns [ b[i(imm_l0)] b[i(imm_l1)] ]
   where b is a  "long const *" and i is a vi_t and imm_l0,imm_l1 are
   compile time constants in 0:3.  The fd_type_pun is to workaround
   various intrinsic and linguistic dubiousness (API takes a long long
   const * but incoming type is a long const * and, though these are
   nominally the same thing, from a linguistic POV, they are
   incompatible ...  more Intel intrinsic hell ... and this also
   degrades the optimizer near wherever this gets used as a result). */

#define vl_gather(b,i,imm_l0,imm_l1) \
  _mm_i32gather_epi64( (long long const *)fd_type_pun( (b) ), _mm_shuffle_epi32( (i), _MM_SHUFFLE(3,2,(imm_l1),(imm_l0))), 8 )

