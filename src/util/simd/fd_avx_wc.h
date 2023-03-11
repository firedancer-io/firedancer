#ifndef HEADER_fd_src_util_simd_fd_avx_h
#error "Do not include this directly; use fd_avx.h"
#endif

/* Vector conditional API *********************************************/

/* A wc_t is a vector conditional.  This is, it is a vector of integers
   where each 32-bit wide lane is either 0 (all zero bits), indicating
   the condition is true for that lane or -1 (all one bits), indicating
   the condition is false for that lane.  This allows fast bit
   operations to mask other types of vectors.  If this API is used on
   vectors that aren't proper vector conditionals, results are
   undefined.  When vector conditional are applied to vector doubles,
   longs and ulongs, adjacent lanes (0-1 / 2-3 / 4-5 / 6-7) should have
   identical values, otherwise results will be undefined.

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wc_t __m256i

/* Constructors */

/* wc returns a wc_t corresponding to the c-style logical values c0:c7.
   This will always create a proper vector conditional regardless how
   logical values were presented to them.  That is, the provided values
   will be treated as c-style logical values such that zero/false will
   become zero/false in the vector and non-zero/true will become -1/true
   in the vector conditional).  Similarly for wc_bcast*.  Summarizing:

     wc(c0,c1,c2,c3)            return [c0 c1 c2 c3 c4 c5 c6 c7]
     wc_bcast(c0)               return [c0 c0 c0 c0 c0 c0 c0 c0]
     wc_bcast_pair(c0,c1)       return [c0 c1 c0 c1 c0 c1 c0 c1]
     wc_bcast_lohi(c0,c1)       return [c0 c0 c0 c1 c1 c1 c1 c1]
     wc_bcast_quad(c0,c1,c2,c3) return [c0 c1 c2 c3 c0 c1 c2 c3]
     wc_bcast_wide(c0,c1,c2,c3) return [c0 c0 c1 c1 c2 c2 c3 c3] */

#define wc(c0,c1,c2,c3,c4,c5,c6,c7) _mm256_setr_epi32( -!!(c0), -!!(c1), -!!(c2), -!!(c3), -!!(c4), -!!(c5), -!!(c6), -!!(c7) )

#if 0 /* Compiler sometimes tries to turn this into branches ... sigh */
#define wc_bcast(c0) _mm256_set1_epi32( -!!(c0) )
#else
static inline __m256i
wc_bcast( int c0 ) {
  c0 = -!!c0; FD_COMPILER_FORGET( c0 );
  return _mm256_set1_epi32( c0 );
}
#endif

static inline wc_t
wc_bcast_pair( int c0, int c1 ) {
  c0 = -!!c0; c1 = -!!c1;
  return _mm256_setr_epi32( c0, c1, c0, c1, c0, c1, c0, c1 );
}

static inline wc_t
wc_bcast_lohi( int c0, int c1 ) {
  c0 = -!!c0; c1 = -!!c1;
  return _mm256_setr_epi32( c0, c0, c0, c0, c1, c1, c1, c1 );
}

static inline wc_t
wc_bcast_quad( int c0, int c1, int c2, int c3 ) {
  c0 = -!!c0; c1 = -!!c1; c2 = -!!c2; c3 = -!!c3;
  return _mm256_setr_epi32( c0, c1, c2, c3, c0, c1, c2, c3 );
}

static inline wc_t
wc_bcast_wide( int c0, int c1, int c2, int c3 ) {
  c0 = -!!c0; c1 = -!!c1; c2 = -!!c2; c3 = -!!c3;
  return _mm256_setr_epi32( c0, c0, c1, c1, c2, c2, c3, c3 );
}

/* No general vc_permute due to cross-128-bit lane limitations in AVX.
   Useful cases are provided below.  Given [ c0 c1 c2 c3 c4 c5 c6 c7 ],
   return ... */

#define wc_bcast_even(c)      /* [ c0 c0 c2 c2 c4 c4 c6 c6 ] */ \
  _mm256_castps_si256( _mm256_permute_ps( _mm256_castsi256_ps( (c) ), _MM_SHUFFLE(2,2,0,0) ) )

#define wc_bcast_odd(c)       /* [ c1 c1 c3 c3 c5 c5 c7 c7 ] */ \
  _mm256_castps_si256( _mm256_permute_ps( _mm256_castsi256_ps( (c) ), _MM_SHUFFLE(3,3,1,1) ) )

#define wc_exch_adj(c)        /* [ c1 c0 c3 c2 c5 c4 c7 c6 ] */ \
  _mm256_castps_si256( _mm256_permute_ps( _mm256_castsi256_ps( (c) ), _MM_SHUFFLE(2,3,0,1) ) )

#define wc_exch_adj_pair(c)   /* [ c2 c3 c0 c1 c6 c7 c4 c5 ] */ \
  _mm256_castps_si256( _mm256_permute_ps( _mm256_castsi256_ps( (c) ), _MM_SHUFFLE(1,0,3,2) ) )

static inline wc_t
wc_exch_adj_quad( wc_t c ) { /* [ c4 c5 c6 c7 c0 c1 c2 c3 ] */
  return _mm256_permute2f128_si256( c, c, 1 );
}

/* Predefined constants */

#define wc_false() _mm256_setzero_si256()  /* Return [ f f f f f f f f ] */
#define wc_true()  _mm256_set1_epi32( -1 ) /* Return [ t t t t t t t t ] */

/* Memory operations */

/* wc_ld returns the 8 integers at the 32-byte aligned / 32-byte sized
   location p as a proper vector conditional (see above note about
   c-style logicals).  wc_ldu is the same but p does not have to be
   aligned.  In the fast variants, the caller promises that p already
   holds a proper vector conditions (e.g. 0/-1 for true/false).  wc_st
   writes the vector conditional c at the 32-byte aligned / 32-byte size
   location p (0/-1 for true/false).  wc_stu is the same but p does not
   have to be aligned.  Lane l will be at p[l].  FIXME: USE ATTRIBUTES
   ON P PASSED TO THESE?
   
   Note: gcc knows that __m256i may alias. */

static inline wc_t
wc_ld( int const * p ) {
  return _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_cmpeq_epi32( _mm256_load_si256(  (__m256i const *)p ),
                                                                        _mm256_setzero_si256() ) );
}

static inline wc_t
wc_ldu( int const * p ) {
  return _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_cmpeq_epi32( _mm256_loadu_si256( (__m256i const *)p ),
                                                                        _mm256_setzero_si256() ) );
}

static inline wc_t wc_ld_fast(  int const * p ) { return _mm256_load_si256(  (__m256i const *)p ); }
static inline wc_t wc_ldu_fast( int const * p ) { return _mm256_loadu_si256( (__m256i const *)p ); }

static inline void wc_st(  int * p, wc_t c ) { _mm256_store_si256(  (__m256i *)p, c ); }
static inline void wc_stu( int * p, wc_t c ) { _mm256_storeu_si256( (__m256i *)p, c ); }

/* wc_ldif is an optimized equivalent to wc_and(c,wc_ldu(p)).  Similarly
   for wc_ldif_fast (either may have different behavior if c is not a
   proper vector conditional).  wc_ldif_fast assumes p already holds a
   proper vector conditional.  These are provided for symmetry with the
   wc_stif operation.  wc_stif stores x(n) to p[n] if c(n) is true and
   leaves p[n] unchanged otherwise.  Undefined behavior if c is not a
   proper vector conditional. */

#define wc_ldif(c,p)      _mm256_xor_si128( _mm256_set1_epi32(-1), _mm256_cmpeq_epi32( _mm256_maskload_epi32( (p), (c) ), \
                                                                                       _mm256_setzero_si128()) )
#define wc_ldif_fast(c,p) _mm256_maskload_epi32((p),(c))
#define wc_stif(c,p,x)    _mm256_maskstore_epi32((p),(c),(x))

/* Element operations */

/* wc_extract extracts the value of lane imm from the vector conditional
   as an int 0 (false) or 1 (true).  wc_insert returns the vector
   conditional formed by replacing the value in lane imm of a with the
   provided c-style logical.  imm should be a compile time constant in
   0:7.  wc_extract_variable and wc_insert_variable are the slower but
   the lane does not have to be compile-time known static value (should
   still be in 0:7). */

#define wc_extract(c,imm)        ((_mm256_movemask_ps( _mm256_castsi256_ps( (c) ) ) >> (imm)) & 1)
#define wc_insert(a,imm,c)       _mm256_insert_epi32( (a), -!!(c), (imm) )

#define wc_extract_variable(c,n) ((_mm256_movemask_ps( _mm256_castsi256_ps( (c) ) ) >> (n)  ) & 1)
#define wc_insert_variable(a,n,c)                                                                                             \
  _mm256_cmpgt_epi32( _mm256_and_si256( _mm256_set1_epi32( (_mm256_movemask_ps( _mm256_castsi256_ps( (a) ) ) & (~(1<<(n)))) | \
                                                           ((!!(c))<<n) ),                                                    \
                                        _mm256_setr_epi32( 1<<0, 1<<1, 1<<2, 1<<3, 1<<4, 1<<5, 1<<6, 1<<7 ) ),                \
                      _mm256_setzero_si256() )

/* Given [ a0 a1 a2 a3 a4 a5 a6 a7 ] and/or [ b0 b1 b2 b3 b4 b5 b6 b7 ],
   return ... */

/* Arithmetic operations */

/* Note: arithmetic and shift operations are not well defined for a wc_t
   as it isn't clear if user would like to treat the vector conditional
   these as 8 1-bit signed ints (0/-1), 8 1-bit unsigned ints (0/1) or
   8-GF2 elements (f/t but sign is meaningless) or do cross lane motion
   of the condition.  Instead, the user should use wc_to_{wi,wl}[_raw]
   as necessary and use the appropriate binary, arithmetic, permute
   and/or shift operations there. */

/* Binary operations */

#define wc_not(a)      _mm256_xor_si256( _mm256_set1_epi32( -1 ), (a) ) /* [ ~a0 ~a1 ...  ~a7 ] */

#define wc_and(a,b)    _mm256_and_si256(   (a),(b)) /* [   a0 &b0   a1 &b1 ...   a7 &b7 ] */
#define wc_or(a,b)     _mm256_or_si256(    (a),(b)) /* [   a0 |b0   a1 |b1 ...   a7 |b7 ] */
#define wc_xor(a,b)    _mm256_xor_si256(   (a),(b)) /* [   a0 ^b0   a1 ^b1 ...   a7 ^b7 ] */
#define wc_andnot(a,b) _mm256_andnot_si256((a),(b)) /* [ (~a0)&b0 (~a1)&b1 ... (~a7)&b7 ] */

/* Logical operations */

/* Note: wc_{gt,lt,ge,le} are provided for completeness and treat
   true>false. */

#define wc_lnot(a)    _mm256_xor_si256( _mm256_set1_epi32( -1 ), (a) ) /* [ ~a0 ~a1 ... ~a7 ] */
#define wc_lnotnot(a) (a)                                              /* [  a0  a1 ...  a7 ] */

#define wc_eq(a,b) _mm256_cmpeq_epi32( (a),(b))                                /* [ a0==b0 a1==b1 ... a7==b7 ] */
#define wc_gt(a,b) _mm256_andnot_si256((b),(a))                                /* [ a0> b0 a1> b1 ... a7> b7 ] */
#define wc_lt(a,b) _mm256_andnot_si256((a),(b))                                /* [ a0< b0 a1< b1 ... a7< b7 ] */
#define wc_ne(a,b) _mm256_xor_si256(   (a),(b))                                /* [ a0!=b0 a1!=b1 ... a7!=b7 ] */
#define wc_ge(a,b)                                                             /* [ a0>=b0 a1>=b1 ... a7>=b7 ] */ \
  _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_andnot_si256( (a), (b) ) )
#define wc_le(a,b)                                                             /* [ a0<=b0 a1<=b1 ... a7<=b7 ] */ \
  _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_andnot_si256( (b), (a) ) )

/* Conditional operations */

/* FIXME: Define wc_czero / wc_notczero?  Equivalent TO wc_andnot and
   wc_and but have arithmetic connotations.  */

#define wc_if(c,t,f) _mm256_blendv_epi8( (f), (t), (c) ) /* [ c0?t0:f0 c1?t1:f1 ... c7?t7:f7 ] */

/* Conversion operations */

/* wc_to_{wf,wi,wu,wd,wl,wv} convert a proper vector conditional into a
   vector float/int/double/long/ulong with f mapping to 0 and t mapping
   to 1 in each lane.

   wc_to_{wf,wi,wu,wd,wl,wv}_raw just treat the raw bits in the vector
   conditional as the corresponding vector type.  wc_to_{wi,wu}_raw map
   false(true) to 0(-1) and similarly for wc_to_{wl,wv}_raw when c has
   paired lanes.  wc_to_{wf,wd}_raw probably are not useful in practice
   but are provided for completeness; wc_to_wf_raw maps false(true) to
   0(-nan) and similarly for wc_to_wd_raw when c has paired lanes. */

#define wc_to_wf(a) _mm256_and_ps( _mm256_castsi256_ps( (a) ), _mm256_set1_ps( 1.f ) )
#define wc_to_wi(a) _mm256_and_si256( (a), _mm256_set1_epi32( 1 ) )
#define wc_to_wu(a) _mm256_and_si256( (a), _mm256_set1_epi32( 1 ) )
#define wc_to_wd(a) _mm256_and_pd( _mm256_castsi256_pd( (a) ), _mm256_set1_pd( 1. ) ) /* wc should have paired lanes */
#define wc_to_wl(a) _mm256_and_si256( (a), _mm256_set1_epi64x( 1L ) )                 /* wc should have paired lanes */
#define wc_to_wv(a) _mm256_and_si256( (a), _mm256_set1_epi64x( 1L ) )                 /* wc should have paired lanes */

#define wc_to_wf_raw(a) _mm256_castsi256_ps( (a) )
#define wc_to_wi_raw(a) (a)
#define wc_to_wu_raw(a) (a)
#define wc_to_wd_raw(a) _mm256_castsi256_pd( (a) )
#define wc_to_wl_raw(a) (a)
#define wc_to_wv_raw(a) (a)

/* Reduction operations */

/* wc_any/wc_all returns logical true if any/all conditions in c is true */

#define wc_any(c) (_mm256_movemask_ps( _mm256_castsi256_ps( (c) ) )!=0x00)
#define wc_all(c) (_mm256_movemask_ps( _mm256_castsi256_ps( (c) ) )==0xff)

/* Misc operations */

/* vc_pack returns an int where bit i equals 0(1) if lane i of c is
   false(true) for i in [0,4).  Vice versa for vc_unpack. */

#define wc_pack(c)   _mm256_movemask_ps( _mm256_castsi256_ps( (c) ) )
#define wc_unpack(b) _mm256_cmpgt_epi32( _mm256_and_si256( _mm256_set1_epi32( (b) ),                                              \
                                                           _mm256_setr_epi32( 1<<0, 1<<1, 1<<2, 1<<3, 1<<4, 1<<5, 1<<6, 1<<7 ) ), \
                                         _mm256_setzero_si256() )

/* wc_gather(b,i) returns [ -!!b[i(0)] -!!b[i(1)] ... -!!b[i(7)] ] where
   b is an "int const *" (0/non-zero map to false/true) and i is a wi_t.

   wc_gather_fast(b,i) returns [ b[i(0)] b[i(1)] ... b[i(7)] ] where b s
   an "int const *".   User promises b[i(:)] values are already either 0
   or -1.  i here is a wi_t.  */

#define wc_gather(b,i)      _mm256_xor_si256( _mm256_set1_epi32( -1 ), \
                                              _mm256_cmpeq_epi32( _mm256_i32gather_epi32( (b), (i), 4 ), _mm256_setzero_si256() ) )
#define wc_gather_fast(b,i) _mm256_i32gather_epi32( (b), (i), 4 )

