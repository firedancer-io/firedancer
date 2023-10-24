#ifndef HEADER_fd_src_util_simd_fd_sse_h
#error "Do not include this directly; use fd_sse.h"
#endif

/* TODO: the below is much very designed for a 32-bit SIMD lane world
   (with 64-bit SIMD lane support hacked on afterward).  Revamp these to
   be more general for 8, 16, 32 and 64 bit lanes. */

/* Vector conditional API *********************************************/

/* A vc_t is a vector conditional.  This is, it is a vector of integers
   where each 32-bit wide lane is either 0 (all zero bits), indicating
   the condition is true for that lane or -1 (all one bits), indicating
   the condition is false for that lane.  This allows fast bit
   operations to mask other types of vectors.  If this API is used on
   vectors that aren't proper vector conditionals, results are
   undefined.  When vector conditional are applied to vector doubles,
   longs and ulongs, adjacent lanes (0-1 / 2-3) should have identical
   values, otherwise results will be undefined.

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define vc_t __m128i

/* Constructors */

/* vc returns a vc_t corresponding to the c-style logical values c0:c3.
   This will always create a proper vector conditional regardless how
   logical values were presented to them.  That is, the provided values
   will be treated as c-style logical values such that zero/false will
   become zero/false in the vector and non-zero/true will become -1/true
   in the vector conditional).  Similarly for vc_bcast*.  Summarizing:

     vc(c0,c1,c2,c3)      return [c0 c1 c2 c3]
     vc_bcast(c0)         return [c0 c0 c0 c0]
     vc_bcast_pair(c0,c1) return [c0 c1 c0 c1]
     vc_bcast_wide(c0,c1) return [c0 c0 c1 c1] */

#define vc(c0,c1,c2,c3) _mm_setr_epi32( -!!(c0), -!!(c1), -!!(c2), -!!(c3) )

#if 0 /* Compiler sometimes tries to turn this into branches ... sigh */
#define vc_bcast(c0) _mm_set1_epi32( -!!(c0) )
#else
static inline __m128i
vc_bcast( int c0 ) {
  c0 = -!!c0; FD_COMPILER_FORGET( c0 );
  return _mm_set1_epi32( c0 );
}
#endif

static inline vc_t
vc_bcast_pair( int c0, int c1 ) {
  c0 = -!!c0; c1 = -!!c1;
  return _mm_setr_epi32( c0, c1, c0, c1 );
}

static inline vc_t
vc_bcast_wide( int c0, int c1 ) {
  c0 = -!!c0; c1 = -!!c1;
  return _mm_setr_epi32( c0, c0, c1, c1 );
}

/* vc_permute(c,imm_i0,imm_i1,imm_i2,imm_i3) returns
   [ c(imm_i0) c(imm_i1) c(imm_i2) c(imm_i3) ].  imm_i* should be
   compile time constants in 0:3. */

#define vc_permute(c,imm_i0,imm_i1,imm_i2,imm_i3) _mm_shuffle_epi32( (c), _MM_SHUFFLE( (imm_i3), (imm_i2), (imm_i1), (imm_i0) ) )

/* Predefined constants. */

#define vc_false() _mm_setzero_si128()  /* vc_false() returns [ f f f f ] */
#define vc_true()  _mm_set1_epi32( -1 ) /* vc_true()  returns [ t t t t ] */

/* Memory operations */

/* vc_ld returns the 4 integers at the 16-byte aligned / 16-byte sized
   location p as a proper vector conditional (see above note about
   c-style logicals).  vc_ldu is the same but p does not have to be
   aligned.  In the fast variants, the caller promises that p already
   holds a proper vector conditions (e.g. 0/-1 for true/false).  vc_st
   writes the vector conditional c at the 16-byte aligned / 16-byte size
   location p (0/-1 for true/false).  vc_stu is the same but p does not
   have to be aligned.  Lane l will be at p[l].  FIXME: USE ATTRIBUTES
   ON P PASSED TO THESE?

   Note: gcc knows that __m128i may alias. */

static inline vc_t
vc_ld( int const * p ) {
  return _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_cmpeq_epi32( _mm_load_si128(  (__m128i const *)p ), _mm_setzero_si128() ) );
}
static inline vc_t vc_ld_fast( int const * p ) { return _mm_load_si128(  (__m128i const *)p ); }
static inline void vc_st( int * p, vc_t c ) { _mm_store_si128(  (__m128i *)p, c ); }

static inline vc_t
vc_ldu( void const * p ) {
  return _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_cmpeq_epi32( _mm_loadu_si128( (__m128i const *)p ), _mm_setzero_si128() ) );
}
static inline vc_t vc_ldu_fast( void const * p ) { return _mm_loadu_si128( (__m128i const *)p ); }
static inline void vc_stu( void * p, vc_t c ) { _mm_storeu_si128( (__m128i *)p, c ); }

/* vc_ldif is an optimized equivalent to vc_and(c,vc_ldu(p)).  Similarly
   for vc_ldif_fast (either may have different behavior if c is not a
   proper vector conditional).  vc_ldif_fast assumes p already holds a
   proper vector conditional.  These are provided for symmetry with the
   vc_stif operation.  vc_stif stores x(n) to p[n] if c(n) is true and
   leaves p[n] unchanged otherwise.  Undefined behavior if c is not a
   proper vector conditional. */

#define vc_ldif(c,p)      _mm_xor_si128(_mm_set1_epi32(-1),_mm_cmpeq_epi32( _mm_maskload_epi32((p),(c)),_mm_setzero_si128()))
#define vc_ldif_fast(c,p) _mm_maskload_epi32((p),(c))
#define vc_stif(c,p,x)    _mm_maskstore_epi32((p),(c),(x))

/* Element operations */

/* vc_extract extracts the value of lane imm from the vector conditional
   as an int 0 (false) or 1 (true).  vc_insert returns the vector
   conditional formed by replacing the value in lane imm of a with the
   provided c-style logical.  imm should be a compile time constant in
   0:3.  vc_extract_variable and vc_insert_variable are the slower but
   the lane does not have to be known at compile time (should still be
   in 0:3). */

#define vc_extract(c,imm)  ((_mm_movemask_ps( _mm_castsi128_ps( (c) ) ) >> (imm)) & 1)
#define vc_insert(a,imm,c) _mm_insert_epi32( (a), -!!(c), (imm) )

#define vc_extract_variable(c,n) ((_mm_movemask_ps( _mm_castsi128_ps( (c) ) ) >> (n)  ) & 1)
#define vc_insert_variable(a,n,c)                                                                                              \
  _mm_cmpgt_epi32( _mm_and_si128( _mm_set1_epi32( (_mm_movemask_ps( _mm_castsi128_ps( (a) ) ) & (~(1<<(n)))) | ((!!(c))<<n) ), \
                                  _mm_setr_epi32( 1<<0, 1<<1, 1<<2, 1<<3 ) ), _mm_setzero_si128() )

/* Given [ a0 a1 a2 a3 ] and/or [ b0 b1 b2 b3 ], return ... */

/* Arithmetic operations */

/* Note: arithmetic and shift operations are not well defined for a vc_t
   as it isn't clear if user would like to treat the vector conditional
   these as 4 1-bit signed ints (0/-1), 4 1-bit unsigned ints (0/1) or
   4-GF2 elements (f/t but sign is meaningless) or do cross lane motion
   of the condition.  Instead, the user should use vc_to_{vi,vl}[_raw]
   as necessary and use the appropriate binary, arithmetic, permute
   and/or shift operations there. */

/* Binary operations */

#define vc_not(a)      _mm_xor_si128( _mm_set1_epi32( -1 ), (a) ) /* [ ~a0 ~a1 ... ~a3 ] */

#define vc_and(a,b)    _mm_and_si128(   (a),(b)) /* [   a0 &b0   a1 &b1 ...   a3 &b3 ] */
#define vc_or(a,b)     _mm_or_si128(    (a),(b)) /* [   a0 |b0   a1 |b1 ...   a3 |b3 ] */
#define vc_xor(a,b)    _mm_xor_si128(   (a),(b)) /* [   a0 ^b0   a1 ^b1 ...   a3 ^b3 ] */
#define vc_andnot(a,b) _mm_andnot_si128((a),(b)) /* [ (~a0)&b0 (~a1)&b1 ... (~a3)&b3 ] */

/* Logical operations */

/* Note: vc_{gt,lt,ge,le} are provided for completeness and treat
   true>false. */

#define vc_lnot(a)    _mm_xor_si128( _mm_set1_epi32( -1 ), (a) ) /* [ ~a0 ~a1 ... ~a3 ] */
#define vc_lnotnot(a) (a)                                        /* [  a0  a1 ...  a3 ] */

#define vc_eq(a,b) _mm_cmpeq_epi32( (a),(b))                                           /* [ a0==b0  a1==b1 ... a3==b3 ] */
#define vc_gt(a,b) _mm_andnot_si128((b),(a))                                           /* [ a0> b0  a1> b1 ... a3> b3 ] */
#define vc_lt(a,b) _mm_andnot_si128((a),(b))                                           /* [ a0< b0  a1< b1 ... a3< b3 ] */
#define vc_ne(a,b) _mm_xor_si128(   (a),(b))                                           /* [ a0!=b0  a1!=b1 ... a3!=b3 ] */
#define vc_ge(a,b) _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_andnot_si128( (a), (b) ) ) /* [ a0>=b0  a1>=b1 ... a3>=b3 ] */
#define vc_le(a,b) _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_andnot_si128( (b), (a) ) ) /* [ a0<=b0  a1<=b1 ... a3<=b3 ] */

/* Conditional operations */

/* FIXME: Define vc_czero / vc_notczero?  Equivalent TO vc_andnot and
   vc_and but have arithmetic connotations.  */

#define vc_if(c,t,f) _mm_blendv_epi8( (f), (t), (c) ) /* [ c0?t0:f0 c1?t1:f1 ... c3?t3:f3 ] */

/* Conversion operations */

/* vc_to_{vf,vi,vu,vd,vl,vv} convert a proper vector conditional into a
   vector float/int/double/long/ulong with f mapping to 0 and t mapping
   to 1 in each lane.

   vc_to_{vf,vi,vu,vd,vl,vv}_raw just treat the raw bits in the vector
   conditional as the corresponding vector type.  vc_to_{vi,vu}_raw map
   false(true) to 0(-1) and similarly for vc_to_{vl,vv}_raw when c has
   paired lanes.  vc_to_{vf,vd}_raw probably are not useful in practice
   but are provided for completeness; vc_to_vf_raw maps false(true) to
   0(-nan) and similarly for vc_to_vd_raw when c has paired lanes. */

#define vc_to_vf(a) _mm_and_ps( _mm_castsi128_ps( (a) ), _mm_set1_ps( 1.f ) )
#define vc_to_vi(a) _mm_and_si128( (a), _mm_set1_epi32( 1 ) )
#define vc_to_vu(a) _mm_and_si128( (a), _mm_set1_epi32( 1 ) )
#define vc_to_vd(a) _mm_and_pd( _mm_castsi128_pd( (a) ), _mm_set1_pd( 1. ) ) /* vc should have paired lanes */
#define vc_to_vl(a) _mm_and_si128( (a), _mm_set1_epi64x( 1L ) )              /* vc should have paired lanes */
#define vc_to_vv(a) _mm_and_si128( (a), _mm_set1_epi64x( 1L ) )              /* vc should have paired lanes */

#define vc_to_vf_raw(a) _mm_castsi128_ps( (a) )
#define vc_to_vi_raw(a) (a)
#define vc_to_vu_raw(a) (a)
#define vc_to_vd_raw(a) _mm_castsi128_pd( (a) )
#define vc_to_vl_raw(a) (a)
#define vc_to_vv_raw(a) (a)

/* Reduction operations */

/* vc_any/vc_all returns logical true if any/all conditions in c is true */

#define vc_any(c) (_mm_movemask_ps( _mm_castsi128_ps( (c) ) )!=0x0)
#define vc_all(c) (_mm_movemask_ps( _mm_castsi128_ps( (c) ) )==0xf)

/* Misc operations */

/* vc_pack returns an int where bit i equals 0(1) if lane i of c is
   false(true) for i in [0,4).  Vice versa for vc_unpack. */

#define vc_pack(c)   _mm_movemask_ps( _mm_castsi128_ps( (c) ) )
#define vc_unpack(b) _mm_cmpgt_epi32( _mm_and_si128( _mm_set1_epi32( (b) ), _mm_setr_epi32( 1<<0, 1<<1, 1<<2, 1<<3 ) ), \
                                      _mm_setzero_si128() )

/* vc_expand expands c0:c1 (imm_hi==0) or c2:c3 (imm_hi==1) into a
   paired lane conditional.  That is:

     vc_expand(c,0) returns [ c0 c0 c1 c1 ]
     vc_expand(c,1) returns [ c2 c2 c3 c3 ]

   Conversely:

     vc_narrow(a,b) returns [ a0 a2 b0 b2 ]

   which is useful for turning two paired lane conditionals into a
   single lane conditional.  U.B. if a, b, and/or c are not proper
   vector conditional.  These are useful, for example, for vectorizing
   64-bit pointer arithmetic used in 32-bit lane SIMD. */

static inline vc_t vc_expand( vc_t c, int imm_hi ) {
  return _mm_cvtepi32_epi64( imm_hi ? _mm_shuffle_epi32( c, _MM_SHUFFLE(3,2,3,2) ) : c ); /* compile time */
}

#define vc_narrow(a,b) _mm_castps_si128( _mm_shuffle_ps( _mm_castsi128_ps( (a) ), _mm_castsi128_ps( (b) ), _MM_SHUFFLE(2,0,2,0) ) )

/* vc_gather(b,i) returns [ -!!b[i(0)] -!!b[i(1)] ... -!!b[i(3)] ] where
   b is an "int const *" (0/non-zero map to false/true) and i is a vi_t.

   vc_gather_fast(b,i) returns [ b[i(0)] b[i(1)] ... b[i(3)] ] where b s
   an "int const *".   User promises b[i(:)] values are already either 0
   or -1.  i here is a vi_t.  */

#define vc_gather(b,i)      _mm_xor_si128( _mm_set1_epi32( -1 ), \
                                           _mm_cmpeq_epi32( _mm_i32gather_epi32( (b), (i), 4 ), _mm_setzero_si128() ) )
#define vc_gather_fast(b,i) _mm_i32gather_epi32( (b), (i), 4 )

/* vc_transpose_4x4 transposes the 4x4 matrix stored in vc_t r0,r1,r2,r3
   and stores the result in 4x4 matrix vc_t c0,c1,c2,c3.  All
   c0,c1,c2,c3 should be different for a well defined result.
   Otherwise, in-place operation and/or using the same vc_t to specify
   multiple rows of r is fine. */

#define vc_transpose_4x4( r0,r1,r2,r3, c0,c1,c2,c3 ) do {                                                                   \
    vc_t _vc_transpose_r0 = (r0); vc_t _vc_transpose_r1 = (r1); vc_t _vc_transpose_r2 = (r2); vc_t _vc_transpose_r3 = (r3); \
    vc_t _vc_transpose_t;                                                                                                   \
    /* Transpose 2x2 blocks */                                                                                              \
    _vc_transpose_t = _vc_transpose_r0; _vc_transpose_r0 = _mm_unpacklo_epi32( _vc_transpose_t,  _vc_transpose_r2 );        \
    /**/                                _vc_transpose_r2 = _mm_unpackhi_epi32( _vc_transpose_t,  _vc_transpose_r2 );        \
    _vc_transpose_t = _vc_transpose_r1; _vc_transpose_r1 = _mm_unpacklo_epi32( _vc_transpose_t,  _vc_transpose_r3 );        \
    /**/                                _vc_transpose_r3 = _mm_unpackhi_epi32( _vc_transpose_t,  _vc_transpose_r3 );        \
    /* Transpose 1x1 blocks */                                                                                              \
    /**/                                (c0)             = _mm_unpacklo_epi32( _vc_transpose_r0, _vc_transpose_r1 );        \
    /**/                                (c1)             = _mm_unpackhi_epi32( _vc_transpose_r0, _vc_transpose_r1 );        \
    /**/                                (c2)             = _mm_unpacklo_epi32( _vc_transpose_r2, _vc_transpose_r3 );        \
    /**/                                (c3)             = _mm_unpackhi_epi32( _vc_transpose_r2, _vc_transpose_r3 );        \
  } while(0)
