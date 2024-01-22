#ifndef HEADER_fd_src_util_simd_fd_sse_h
#error "Do not include this directly; use fd_sse.h"
#endif

/* Vector int API *****************************************************/

/* A vi_t is a vector where each 32-bit wide lane holds a signed 32-bit
   twos-complement integer (an "int").  These mirror vc and vf as much
   as possible.

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define vi_t __m128i

/* Constructors */

/* Given the int values, return ... */

#define vi(i0,i1,i2,i3) _mm_setr_epi32( (i0), (i1), (i2), (i3) ) /* [ i0 i1 i2 i3 ] */

#define vi_bcast(i0) _mm_set1_epi32( (i0) ) /* [ i0 i0 i0 i0 ] */

static inline vi_t /* [ i0 i1 i0 i1 ] */
vi_bcast_pair( int i0, int i1 ) {
  return _mm_setr_epi32( i0, i1, i0, i1 );
}

static inline vi_t /* [ i0 i0 i1 i1 ] */
vi_bcast_wide( int i0, int i1 ) {
  return _mm_setr_epi32( i0, i0, i1, i1 );
}

/* vi_permute returns [ i(imm_i0) i(imm_i1) i(imm_i2) i(imm_i3) ].
   imm_i* should be compile time constants in 0:3. */

#define vi_permute(x,imm_i0,imm_i1,imm_i2,imm_i3) _mm_shuffle_epi32( (x), _MM_SHUFFLE( (imm_i3), (imm_i2), (imm_i1), (imm_i0) ) )

/* Predefined constants */

#define vi_zero() _mm_setzero_si128() /* Return [ 0 0 0 0 ] */
#define vi_one()  _mm_set1_epi32( 1 ) /* Return [ 1 1 1 1 ] */

/* Memory operations */

/* vi_ld return the 4 ints at the 16-byte aligned / 16-byte sized
   location p as a vector int.  vi_ldu is the same but p does not have
   to be aligned.  vi_st writes the vector int to the 16-byte aligned /
   16-byte sized location p as 4 ints.  vi_stu is the same but p does
   not have to be aligned.  In all these lane l will be at p[l].  FIXME:
   USE ATTRIBUTES ON P PASSED TO THESE?

   Note: gcc knows a __m128i may alias. */

static inline vi_t vi_ld( int const * p ) { return _mm_load_si128(  (__m128i const *)p ); }
static inline void vi_st( int * p, vi_t i ) { _mm_store_si128(  (__m128i *)p, i ); }

static inline vi_t vi_ldu( void const * p ) { return _mm_loadu_si128( (__m128i const *)p ); }
static inline void vi_stu( void * p, vi_t i ) { _mm_storeu_si128( (__m128i *)p, i ); }

/* vi_ldif is an optimized equivalent to vi_notczero(c,vi_ldu(p)) (may
   have different behavior if c is not a proper vector conditional).  It
   is provided for symmetry with the vi_stif operation.  vi_stif stores
   x(n) to p[n] if c(n) is true and leaves p[n] unchanged otherwise.
   Undefined behavior if c is not a proper vector conditional. */

#define vi_ldif(c,p)   _mm_maskload_epi32( (p),(c))
#define vi_stif(c,p,x) _mm_maskstore_epi32((p),(c),(x))

/* Element operations */

/* vi_extract extracts the int in lane imm from the vector int as an int.
   vi_insert returns the vector int formed by replacing the value in
   lane imm of a with the provided int.  imm should be a compile time
   constant in 0:3.  vi_extract_variable and vi_insert_variable are the
   slower but the lane n does not have to be known at compile time
   (should be in 0:3).

   Note: C99 TC3 allows type punning through a union. */

#define vi_extract(a,imm)  _mm_extract_epi32( (a), (imm) )
#define vi_insert(a,imm,v) _mm_insert_epi32( (a), (v), (imm) )

static inline int
vi_extract_variable( vi_t a, int n ) {
  union { __m128i m[1]; int i[4]; } t[1];
  _mm_store_si128( t->m, a );
  return t->i[n];
}

static inline vi_t
vi_insert_variable( vi_t a, int n, int v ) {
  union { __m128i m[1]; int i[4]; } t[1];
  _mm_store_si128( t->m, a );
  t->i[n] = v;
  return _mm_load_si128( t->m );
}

/* Given [a0 a1 a2 a3] and/or [b0 b1 b2 b3], return ... */

/* Arithmetic operations */

#define vi_neg(a) _mm_sub_epi32( _mm_setzero_si128(), (a) ) /* [ -a0  -a1  ... -a3  ] (twos complement handling) */
#define vi_abs(a) _mm_abs_epi32( (a) )                      /* [ |a0| |a1| ... |a3| ] (twos complement handling) */

#define vi_min(a,b) _mm_min_epi32(   (a), (b) ) /* [ min(a0,b0) min(a1,b1) ... min(a3,b3) ] */
#define vi_max(a,b) _mm_max_epi32(   (a), (b) ) /* [ max(a0,b0) max(a1,b1) ... max(a3,b3) ] */
#define vi_add(a,b) _mm_add_epi32(   (a), (b) ) /* [ a0 +b0     a1 +b1     ... a3 +b3     ] */
#define vi_sub(a,b) _mm_sub_epi32(   (a), (b) ) /* [ a0 -b0     a1 -b1     ... a3 -b3     ] */
#define vi_mul(a,b) _mm_mullo_epi32( (a), (b) ) /* [ a0 *b0     a1 *b1     ... a3 *b3     ] */

/* Binary operations */

/* Note: vi_shl/vi_shr/vi_shru is a left/signed right/unsigned right
   shift by imm bits; imm should be a compile time constant in 0:31.
   The variable variants are slower but do not require the shift amount
   to be known at compile time (should still be in 0:31). */

#define vi_not(a) _mm_xor_si128( _mm_set1_epi32( -1 ), (a) ) /* [ ~a0 ~a1 ... ~a3 ] */

#define vi_shl(a,imm)  _mm_slli_epi32( (a), (imm) ) /* [ a0<<imm a1<<imm ... a3<<imm ] */
#define vi_shr(a,imm)  _mm_srai_epi32( (a), (imm) ) /* [ a0>>imm a1>>imm ... a3>>imm ] (treat a as signed) */
#define vi_shru(a,imm) _mm_srli_epi32( (a), (imm) ) /* [ a0>>imm a1>>imm ... a3>>imm ] (treat a as unsigned) */

#define vi_shl_variable(a,n)  _mm_sll_epi32( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
#define vi_shr_variable(a,n)  _mm_sra_epi32( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
#define vi_shru_variable(a,n) _mm_srl_epi32( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )

#define vi_shl_vector(a,b)  _mm_sllv_epi32( (a), (b) ) /* [ a0<<b0 a1<<b1 ... a3<<b3 ] */
#define vi_shr_vector(a,b)  _mm_srav_epi32( (a), (b) ) /* [ a0>>b0 a1>>b1 ... a3>>b3 ] (treat a as signed) */
#define vi_shru_vector(a,b) _mm_srlv_epi32( (a), (b) ) /* [ a0>>b0 a1>>b1 ... a3>>b3 ] (treat a as unsigned) */

#define vi_and(a,b)    _mm_and_si128(    (a), (b) ) /* [   a0 &b0    a1& b1 ...   a3& b3 ] */
#define vi_andnot(a,b) _mm_andnot_si128( (a), (b) ) /* [ (~a0)&b0  (~a1)&b1 ... (~a3)&b3 ] */
#define vi_or(a,b)     _mm_or_si128(     (a), (b) ) /* [   a0 |b0    a1 |b1 ...   a3 |b3 ] */
#define vi_xor(a,b)    _mm_xor_si128(    (a), (b) ) /* [   a0 ^b0    a1 ^b1 ...   a3 ^b3 ] */

static inline vi_t vi_rol( vi_t a, int imm ) { return vi_or( vi_shl(  a, imm & 31 ), vi_shru( a, (-imm) & 31 ) ); }
static inline vi_t vi_ror( vi_t a, int imm ) { return vi_or( vi_shru( a, imm & 31 ), vi_shl(  a, (-imm) & 31 ) ); }

static inline vi_t vi_rol_variable( vi_t a, int n ) { return vi_or( vi_shl_variable(  a, n&31 ), vi_shru_variable( a, (-n)&31 ) ); }
static inline vi_t vi_ror_variable( vi_t a, int n ) { return vi_or( vi_shru_variable( a, n&31 ), vi_shl_variable(  a, (-n)&31 ) ); }

static inline vi_t vi_rol_vector( vi_t a, vi_t b ) {
  vi_t m = vi_bcast( 31 );
  return vi_or( vi_shl_vector(  a, vi_and( b, m ) ), vi_shru_vector( a, vi_and( vi_neg( b ), m ) ) );
}

static inline vi_t vi_ror_vector( vi_t a, vi_t b ) {
  vi_t m = vi_bcast( 31 );
  return vi_or( vi_shru_vector( a, vi_and( b, m ) ), vi_shl_vector(  a, vi_and( vi_neg( b ), m ) ) );
}

/* Logical operations */

#define vi_lnot(a)     _mm_cmpeq_epi32( (a), _mm_setzero_si128() ) /* [  !a0  !a1 ...  !a3 ] */
#define vi_lnotnot(a)                                              /* [ !!a0 !!a1 ... !!a3 ] */ \
  _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_cmpeq_epi32( (a), _mm_setzero_si128() ) )

#define vi_eq(a,b) _mm_cmpeq_epi32( (a), (b) )                                        /* [ a0==b0 a1==b1 ... a3==b3 ] */
#define vi_gt(a,b) _mm_cmpgt_epi32( (a), (b) )                                        /* [ a0> b0 a1> b1 ... a3> b3 ] */
#define vi_lt(a,b) _mm_cmpgt_epi32( (b), (a) )                                        /* [ a0< b0 a1< b1 ... a3> b3 ] */
#define vi_ne(a,b) _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_cmpeq_epi32( (a), (b) ) ) /* [ a0!=b0 a1!=b1 ... a3!=b3 ] */
#define vi_ge(a,b) _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_cmpgt_epi32( (b), (a) ) ) /* [ a0>=b0 a1>=b1 ... a3>=b3 ] */
#define vi_le(a,b) _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_cmpgt_epi32( (a), (b) ) ) /* [ a0<=b0 a1<=b1 ... a3<=b3 ] */

/* Conditional operations */

#define vi_czero(c,f)    _mm_andnot_si128( (c), (f) ) /* [ c0? 0:f0 c1? 0:f1 ... c3? 0:f3 ] */
#define vi_notczero(c,f) _mm_and_si128(    (c), (f) ) /* [ c0?f0: 0 c1?f1: 0 ... c3?f3: 0 ] */

#define vi_if(c,t,f) _mm_blendv_epi8(  (f), (t), (c) ) /* [ c0?t0:f0 c1?t1:f1 ... c3?t3:f3 ] */

/* Conversion operations */

/* Summarizing:

   vi_to_vc(a)               returns [ !!a0 !!a1 ... !!a3 ]

   vi_to_vu(a)               returns [ (uint)a0 (uint)a1 ... (uint)a3 ]

   vi_to_vf(a)               returns [ (float)a0 (float)a1 ... (float)a3 ]

   vi_to_vd(a,imm_i0,imm_i1) returns [ (double)a(imm_i0) (double)a(imm_i1) ]

   vi_to_vl(a,imm_i0,imm_i1) returns [ (long)a(imm_i0) (long)a(imm_i1) ]

   vi_to_vv(a,imm_i0,imm_i1) returns [ (ulong)a(imm_i0) (ulong)a(imm_i1) ]

   where imm_i* should be a compile time constant in 0:3.

   The raw variants just treat the raw bits as the corresponding vector
   type.  For vi_to_vc_raw, the user promises vi contains a proper
   vector conditional (i.e. 0 or -1 in each lane).  vi_to_vf_raw is
   useful for doing advanced bit tricks on floating point values.  The
   others are probably dubious but are provided for completness. */

#define vi_to_vc(a)               _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_cmpeq_epi32( (a), _mm_setzero_si128() ) )
#define vi_to_vf(a)               _mm_cvtepi32_ps( (a) )
#define vi_to_vu(a)               (a)
#define vi_to_vd(a,imm_i0,imm_i1) _mm_cvtepi32_pd   ( _mm_shuffle_epi32( (a), _MM_SHUFFLE(3,2,(imm_i1),(imm_i0)) ) )
#define vi_to_vl(a,imm_i0,imm_i1) _mm_cvtepi32_epi64( _mm_shuffle_epi32( (a), _MM_SHUFFLE(3,2,(imm_i1),(imm_i0)) ) )
#define vi_to_vv(a,imm_i0,imm_i1) _mm_cvtepi32_epi64( _mm_shuffle_epi32( (a), _MM_SHUFFLE(3,2,(imm_i1),(imm_i0)) ) )

#define vi_to_vc_raw(a) (a)
#define vi_to_vf_raw(a) _mm_castsi128_ps( (a) )
#define vi_to_vu_raw(a) (a)
#define vi_to_vd_raw(a) _mm_castsi128_pd( (a) )
#define vi_to_vl_raw(a) (a)
#define vi_to_vv_raw(a) (a)

/* Reduction operations */

static inline vi_t
vi_sum_all( vi_t x ) { /* Returns vi_bcast( sum( x ) ) */
  x = _mm_hadd_epi32( x, x );    /* x01 x23 ... */
  return _mm_hadd_epi32( x, x ); /* xsum ...    */
}

static inline vi_t
vi_min_all( vi_t x ) { /* Returns vi_bcast( min( x ) ) */
  __m128i y;
  y = _mm_shuffle_epi32( x, _MM_SHUFFLE( 1, 0, 3, 2 ) ); /* x2  x3  x0  x1 */
  x = _mm_min_epi32( x, y );                             /* x02 x13 ...    */
  y = _mm_shuffle_epi32( x, _MM_SHUFFLE( 2, 3, 0, 1 ) ); /* x13 x02 ...    */
  x = _mm_min_epi32( x, y );                             /* xmin ...       */
  return x;
}

static inline vi_t
vi_max_all( vi_t x ) { /* Returns vi_bcast( max( x ) ) */
  __m128i y;
  y = _mm_shuffle_epi32( x, _MM_SHUFFLE( 1, 0, 3, 2 ) ); /* x2  x3  x0  x1 */
  x = _mm_max_epi32( x, y );                             /* x02 x13 ...    */
  y = _mm_shuffle_epi32( x, _MM_SHUFFLE( 2, 3, 0, 1 ) ); /* x13 x02 ...    */
  x = _mm_max_epi32( x, y );                             /* xmax ...       */
  return x;
}

/* Misc operations */

/* vi_gather(b,i) returns [ b[i(0)] b[i(1)] ... b[i(3)] ] where b is a
   "int const *"  and i is a vi_t. */

#define vi_gather(b,i) _mm_i32gather_epi32( (b), (i), 4 )

/* vi_transpose_4x4 transposes the 4x4 matrix stored in vi_t r0,r1,r2,r3
   and stores the result in 4x4 matrix vi_t c0,c1,c2,c3.  All
   c0,c1,c2,c3 should be different for a well defined result.
   Otherwise, in-place operation and/or using the same vi_t to specify
   multiple rows of r is fine. */

#define vi_transpose_4x4( r0,r1,r2,r3, c0,c1,c2,c3 ) do {                                                                   \
    vi_t _vi_transpose_r0 = (r0); vi_t _vi_transpose_r1 = (r1); vi_t _vi_transpose_r2 = (r2); vi_t _vi_transpose_r3 = (r3); \
    vi_t _vi_transpose_t;                                                                                                   \
    /* Transpose 2x2 blocks */                                                                                              \
    _vi_transpose_t = _vi_transpose_r0; _vi_transpose_r0 = _mm_unpacklo_epi32( _vi_transpose_t,  _vi_transpose_r2 );        \
    /**/                                _vi_transpose_r2 = _mm_unpackhi_epi32( _vi_transpose_t,  _vi_transpose_r2 );        \
    _vi_transpose_t = _vi_transpose_r1; _vi_transpose_r1 = _mm_unpacklo_epi32( _vi_transpose_t,  _vi_transpose_r3 );        \
    /**/                                _vi_transpose_r3 = _mm_unpackhi_epi32( _vi_transpose_t,  _vi_transpose_r3 );        \
    /* Transpose 1x1 blocks */                                                                                              \
    /**/                                (c0)             = _mm_unpacklo_epi32( _vi_transpose_r0, _vi_transpose_r1 );        \
    /**/                                (c1)             = _mm_unpackhi_epi32( _vi_transpose_r0, _vi_transpose_r1 );        \
    /**/                                (c2)             = _mm_unpacklo_epi32( _vi_transpose_r2, _vi_transpose_r3 );        \
    /**/                                (c3)             = _mm_unpackhi_epi32( _vi_transpose_r2, _vi_transpose_r3 );        \
  } while(0)
