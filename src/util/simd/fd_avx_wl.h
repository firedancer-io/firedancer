#ifndef HEADER_fd_src_util_simd_fd_avx_h
#error "Do not include this directly; use fd_avx.h"
#endif

/* Vector long API ****************************************************/

/* A wl_t is a vector where each adjacent pair of 32-bit wide lanes
   (e.g. 0-1 / 2-3 / 4-5 / 6-7) holds a signed 64-bit twos-complement
   integer (a "long").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wl_t __m256i

/* Constructors */

/* Given the long values, return ... */

#define wl(l0,l1,l2,l3) _mm256_setr_epi64x( (l0), (l1), (l2), (l3) ) /* [ l0 l1 l2 l3 ] */

#define wl_bcast(l0) _mm256_set1_epi64x( (l0) ) /* [ l0 l0 l0 l0 ] */

static inline wl_t /* [ l0 l1 l0 l1 ] */
wl_bcast_pair( long l0, long l1 ) {
  return _mm256_setr_epi64x( l0, l1, l0, l1 );
}

static inline wl_t /* [ l0 l0 l1 l1 ] */
wl_bcast_wide( long l0, long l1 ) {
  return _mm256_setr_epi64x( l0, l0, l1, l1 );
}

/* wl_permute returns [ l(imm_i0) l(imm_i1) l(imm_i2) l(imm_i3) ].
   imm_i* should be compile time constants in 0:3. */

#if FD_USING_CLANG /* Sigh ... clang is sad and can't handle passing compile time const expressions through a static inline */

static inline wl_t
wl_permute( wl_t x, int imm_i0, int imm_i1, int imm_i2, int imm_i3 ) {
  union { long l[4]; __m256i v[1]; } t, u;
  _mm256_store_si256( t.v, x );
  u.l[0] = t.l[ imm_i0 ];
  u.l[1] = t.l[ imm_i1 ];
  u.l[2] = t.l[ imm_i2 ];
  u.l[3] = t.l[ imm_i3 ];
  return _mm256_load_si256( u.v );
}

#else

#define wl_permute(x,imm_i0,imm_i1,imm_i2,imm_i3) _mm256_permute4x64_epi64( (x), (imm_i0)+4*(imm_i1)+16*(imm_i2)+64*(imm_i3) )

#endif

/* Predefined constants */

#define wl_zero() _mm256_setzero_si256()   /* Return [ 0L 0L 0L 0L ] */
#define wl_one()  _mm256_set1_epi64x( 1L ) /* Return [ 1L 1L 1L 1L ] */

/* Memory operations */

/* wl_ld return the 4 longs at the 32-byte aligned / 32-byte sized
   location p as a vector long.  wl_ldu is the same but p does not have
   to be aligned.  wl_st writes the vector long to the 32-byte aligned /
   32-byte sized location p as 4 longs.  wl_stu is the same but p does
   not have to be aligned.  In all these 64-bit lane l wlll be at p[l].
   FIXME: USE ATTRIBUTES ON P PASSED TO THESE?

   Note: gcc knows a __m256i may alias. */

static inline wl_t wl_ld( long const * p ) { return _mm256_load_si256(  (__m256i const *)p ); }
static inline void wl_st( long * p, wl_t i ) { _mm256_store_si256(  (__m256i *)p, i ); }

static inline wl_t wl_ldu( void const * p ) { return _mm256_loadu_si256( (__m256i const *)p ); }
static inline void wl_stu( void * p, wl_t i ) { _mm256_storeu_si256( (__m256i *)p, i ); }

/* wl_ldif is an optimized equivalent to wl_notczero(c,wl_ldu(p)) (may
   have different behavior if c is not a proper vector conditional).  It
   is provided for symmetry with the wl_stif operation.  wl_stif stores
   x(n) to p[n] if c(n) is true and leaves p[n] unchanged otherwise.
   Undefined behavior if c is not a proper vector conditional. */

#define wl_ldif(c,p)   _mm256_maskload_epi64( (p),(c))
#define wl_stif(c,p,x) _mm256_maskstore_epi64((p),(c),(x))

/* Element operations */

/* wl_extract extracts the long in lane imm from the vector long as a
   long.  wl_insert returns the vector long formed by replacing the
   value in lane imm of a with the provided long.  imm should be a
   compile time known in 0:3.  wl_extract_variable and
   wl_insert_variable are the slower but the lane n does not have to be
   known at compile time (should still be in 0:3).

   Note: C99 TC3 allows type punning through a union. */

#define wl_extract(a,imm)  _mm256_extract_epi64( (a), (imm) )

#define wl_insert(a,imm,v) _mm256_insert_epi64( (a), (v), (imm) )

static inline long
wl_extract_variable( wl_t a, int n ) {
  union { __m256i m[1]; long l[4]; } t[1];
  _mm256_store_si256( t->m, a );
  return t->l[n];
}

static inline wl_t
wl_insert_variable( wl_t a, int n, long v ) {
  union { __m256i m[1]; long l[4]; } t[1];
  _mm256_store_si256( t->m, a );
  t->l[n] = v;
  return _mm256_load_si256( t->m );
}

/* Given [a0 a1 a2 a3] and/or [b0 b1 b2 b3], return ... */

/* Arithmetic operations */

#define wl_neg(a)   _mm256_sub_epi64( _mm256_setzero_si256(), (a) ) /* [ -a0  -a1  ... -a3  ] (twos complement handling) */

/* Note: _mm256_{abs,min,max}_epi64 are missing pre AVX-512.  We emulate
   these below (and use the AVX-512 versions if possible).  Likewise,
   there is no _mm256_mullo_epi64 pre AVX-512.  Since this is not cheap to
   emulate, we do not provide a wl_mul for the time being (we could
   consider exposing it on AVX-512 targets though).  There is a
   64L*64L->64 multiply (where the lower 32-bits will be sign extended
   to 64-bits beforehand) though and that is very useful.  So we do
   provide that. */

#define wl_add(a,b)    _mm256_add_epi64(   (a), (b) ) /* [ a0 +b0     a1 +b1     ... a3 +b3     ] */
#define wl_sub(a,b)    _mm256_sub_epi64(   (a), (b) ) /* [ a0 -b0     a1 -b1     ... a3 -b3     ] */
//#define wl_mul(a,b)  _mm256_mullo_epi64( (a), (b) ) /* [ a0 *b0     a1 *b1     ... a3 *b3     ] */
#define wl_mul_ll(a,b) _mm256_mul_epi32(   (a), (b) ) /* [ a0l*b0l    a1l*b1l    ... a3l *b3l   ] */

/* Binary operations */

/* Note: wl_shl/wl_shr/wl_shru is a left/signed right/unsigned right
   shift by imm bits; imm should be a compile time constant in 0:63.
   The variable variants are slower but do not require the shift amount
   to be known at compile time (should still be in 0:63).  Also, AVX is
   missing _mm256_sra*_epi64 intrinsics.  We emulate these below. */

#define wl_not(a) _mm256_xor_si256( _mm256_set1_epi64x( -1L ), (a) ) /* [ ~a0 ~a1 ... ~a3 ] */

#define wl_shl(a,imm)   _mm256_slli_epi64( (a), (imm) ) /* [ a0<<imm a1<<imm ... a3<<imm ] */
//#define wl_shr(a,imm) _mm256_srai_epi64( (a), (imm) ) /* [ a0>>imm a1>>imm ... a3>>imm ] (treat a as signed)*/
#define wl_shru(a,imm)  _mm256_srli_epi64( (a), (imm) ) /* [ a0>>imm a1>>imm ... a3>>imm ] (treat a as unsigned) */

#define wl_shl_variable(a,n)   _mm256_sll_epi64( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
//#define wl_shr_variable(a,n) _mm256_sra_epi64( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
#define wl_shru_variable(a,n)  _mm256_srl_epi64( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )

#define wl_shl_vector(a,b)   _mm256_sllv_epi64( (a), (b) ) /* [ a0<<b0 a1<<b1 ... a3<<b3 ] */
//#define wl_shr_vector(a,b) _mm256_srav_epi64( (a), (b) ) /* [ a0>>b0 a1>>b1 ... a3>>b3 ] (treat a as signed) */
#define wl_shru_vector(a,b)  _mm256_srlv_epi64( (a), (b) ) /* [ a0>>b0 a1>>b1 ... a3>>b3 ] (treat a as unsigned) */

#define wl_and(a,b)    _mm256_and_si256(    (a), (b) ) /* [   a0 &b0    a1& b1 ...   a3& b3 ] */
#define wl_andnot(a,b) _mm256_andnot_si256( (a), (b) ) /* [ (~a0)&b0  (~a1)&b1 ... (~a3)&b3 ] */
#define wl_or(a,b)     _mm256_or_si256(     (a), (b) ) /* [   a0 |b0    a1 |b1 ...   a3 |b3 ] */
#define wl_xor(a,b)    _mm256_xor_si256(    (a), (b) ) /* [   a0 ^b0    a1 ^b1 ...   a3 ^b3 ] */

static inline wl_t wl_rol( wl_t a, int imm ) { return wl_or( wl_shl(  a, imm & 63 ), wl_shru( a, (-imm) & 63 ) ); }
static inline wl_t wl_ror( wl_t a, int imm ) { return wl_or( wl_shru( a, imm & 63 ), wl_shl(  a, (-imm) & 63 ) ); }

static inline wl_t wl_rol_variable( wl_t a, int n ) { return wl_or( wl_shl_variable(  a, n&63 ), wl_shru_variable( a, (-n)&63 ) ); }
static inline wl_t wl_ror_variable( wl_t a, int n ) { return wl_or( wl_shru_variable( a, n&63 ), wl_shl_variable(  a, (-n)&63 ) ); }

static inline wl_t wl_rol_vector( wl_t a, wl_t b ) {
  wl_t m = wl_bcast( 63L );
  return wl_or( wl_shl_vector(  a, wl_and( b, m ) ), wl_shru_vector( a, wl_and( wl_neg( b ), m ) ) );
}

static inline wl_t wl_ror_vector( wl_t a, wl_t b ) {
  wl_t m = wl_bcast( 63L );
  return wl_or( wl_shru_vector( a, wl_and( b, m ) ), wl_shl_vector(  a, wl_and( wl_neg( b ), m ) ) );
}

/* Logical operations */

#define wl_lnot(a)    _mm256_cmpeq_epi64( (a), _mm256_setzero_si256() ) /* [  !a0  !a1 ...  !a3 ] */
#define wl_lnotnot(a)                                                   /* [ !!a0 !!a1 ... !!a3 ] */ \
  _mm256_xor_si256( _mm256_set1_epi64x( -1L ), _mm256_cmpeq_epi64( (a), _mm256_setzero_si256() ) )

#define wl_eq(a,b) _mm256_cmpeq_epi64( (a), (b) )                                                /* [ a0==b0 a1==b1 ... a3==b3 ] */
#define wl_gt(a,b) _mm256_cmpgt_epi64( (a), (b) )                                                /* [ a0> b0 a1> b1 ... a3> b3 ] */
#define wl_lt(a,b) _mm256_cmpgt_epi64( (b), (a) )                                                /* [ a0< b0 a1< b1 ... a3< b3 ] */
#define wl_ne(a,b) _mm256_xor_si256( _mm256_set1_epi64x( -1L ), _mm256_cmpeq_epi64( (a), (b) ) ) /* [ a0!=b0 a1!=b1 ... a3!=b3 ] */
#define wl_ge(a,b) _mm256_xor_si256( _mm256_set1_epi64x( -1L ), _mm256_cmpgt_epi64( (b), (a) ) ) /* [ a0>=b0 a1>=b1 ... a3>=b3 ] */
#define wl_le(a,b) _mm256_xor_si256( _mm256_set1_epi64x( -1L ), _mm256_cmpgt_epi64( (a), (b) ) ) /* [ a0<=b0 a1<=b1 ... a3<=b3 ] */

/* Conditional operations */

#define wl_czero(c,f)    _mm256_andnot_si256( (c), (f) ) /* [ c0?0L:f0 c1?0L:f1 ... c3?0L:f3 ] */
#define wl_notczero(c,f) _mm256_and_si256(    (c), (f) ) /* [ c0?f0:0L c1?f1:0L ... c3?f3:0L ] */

#define wl_if(c,t,f) _mm256_blendv_epi8(  (f), (t), (c) ) /* [ c0?t0:f0 c1?t1:f1 ... c3?t3:f3 ] */

#if defined(__AVX512F__) && defined(__AVX512VL__) /* See note above */
#define wl_abs(a)   _mm256_abs_epi64( (a) )
#define wl_min(a,b) _mm256_min_epi64( (a), (b) )
#define wl_max(a,b) _mm256_max_epi64( (a), (b) )
#else
static inline wl_t wl_abs( wl_t a )         { return wl_if( wl_lt( a, wl_zero() ), wl_neg( a ), a ); }
static inline wl_t wl_min( wl_t a, wl_t b ) { return wl_if( wl_lt( a, b ), a, b ); }
static inline wl_t wl_max( wl_t a, wl_t b ) { return wl_if( wl_gt( a, b ), a, b ); }
#endif

static inline wl_t wl_shr( wl_t a, int imm ) {
  wc_t c = wl_lt( a, wl_zero() ); /* Note that wc_t is binary compat with wl_t */
  return _mm256_xor_si256( _mm256_srli_epi64( _mm256_xor_si256( a, c ), imm ), c );
}
static inline wl_t wl_shr_variable( wl_t a, int n ) {
  wc_t c = wl_lt( a, wl_zero() ); /* Note that wc_t is binary compat with wl_t */
  return _mm256_xor_si256( _mm256_srl_epi64( _mm256_xor_si256( a, c ), _mm_insert_epi64( _mm_setzero_si128(), n, 0 ) ), c );
}
static inline wl_t wl_shr_vector( wl_t a, wl_t n ) {
  wc_t c = wl_lt( a, wl_zero() ); /* Note that wc_t is binary compat with wl_t */
  return _mm256_xor_si256( _mm256_srlv_epi64( _mm256_xor_si256( a, c ), n ), c );
}

/* Conversion operations */

/* Summarizing:

   wl_to_wc(d)     returns [ !!l0 !!l0 !!l1 !!l1 ... !!l3 !!l3 ]

   wl_to_wf(l,i,0) returns [ (float)l0 (float)l1 (float)l2 (float)l3 f4 f5 f6 f7 ]
   wl_to_wf(l,i,1) returns [ f0 f1 f2 f3 (float)l0 (float)l1 (float)l2 (float)l3 ]

   wl_to_wi(l,i,0) returns [ (int)l0 (int)l1 (int)l2 (int)l3 i4 i5 i6 i7 ]
   wl_to_wi(l,i,1) returns [ i0 i1 i2 i3 (int)l0 (int)l1 (int)l2 (int)l3 ]

   wl_to_wu(l,u,0) returns [ (uint)l0 (uint)l1 (uint)l2 (uint)l3 u4 u5 u6 u7 ]
   wl_to_wu(l,u,1) returns [ u0 u1 u2 u3 (uint)l0 (uint)l1 (uint)l2 (uint)l3 ]

   wl_to_wd(l)     returns [ (double)l0 (double)l1 (double)l2 (double)l3 ]

   wl_to_wv(l)     returns [ (ulong)l0 (ulong)l1 (ulong)l2 (ulong)l3 ]

   The raw variants just treat the raw bits as the corresponding vector
   type.  For wl_to_wc_raw, the user promises wl contains a proper
   vector conditional (e.g. 0 or -1 in each lane).  The others are
   provided to facilitate doing advanced bit tricks on floating point
   values. */

#define wl_to_wc(a) _mm256_xor_si256( _mm256_set1_epi64x( -1L ), _mm256_cmpeq_epi64( (a), _mm256_setzero_si256() ) )

static inline wf_t wl_to_wf( wl_t l, wf_t f, int imm_hi ) {
  union { long  l[4]; __m256i v[1]; } t[1];
  union { float f[4]; __m128  v[1]; } u[1];
  _mm256_store_si256( t->v, l );
  u->f[0] = (float)t->l[0];
  u->f[1] = (float)t->l[1];
  u->f[2] = (float)t->l[2];
  u->f[3] = (float)t->l[3];
  __m128 v = _mm_load_ps( u->f );
  return imm_hi ? _mm256_insertf128_ps( f, v, 1 ) : _mm256_insertf128_ps( f, v, 0 ); /* compile time */
}

static inline wl_t wl_to_wi( wl_t l, wi_t i, int imm_hi ) {
  __m128  v01 = _mm_castsi128_ps( _mm256_extractf128_si256( l, 0 ) ); /* [ l0l l0h l1l l1h ] */
  __m128  v23 = _mm_castsi128_ps( _mm256_extractf128_si256( l, 1 ) ); /* [ l2l l2h l3l l3h ] */
  __m128i v   = _mm_castps_si128( _mm_shuffle_ps( v01, v23, _MM_SHUFFLE(2,0,2,0) ) );
  return imm_hi ? _mm256_insertf128_si256( i, v, 1 ) : _mm256_insertf128_si256( i, v, 0 ); /* compile time */
}

static inline wu_t wl_to_wu( wl_t l, wu_t u, int imm_hi ) {
  __m128  v01 = _mm_castsi128_ps( _mm256_extractf128_si256( l, 0 ) ); /* [ l0l l0h l1l l1h ] */
  __m128  v23 = _mm_castsi128_ps( _mm256_extractf128_si256( l, 1 ) ); /* [ l2l l2h l3l l3h ] */
  __m128i v   = _mm_castps_si128( _mm_shuffle_ps( v01, v23, _MM_SHUFFLE(2,0,2,0) ) );
  return imm_hi ? _mm256_insertf128_si256( u, v, 1 ) : _mm256_insertf128_si256( u, v, 0 ); /* compile time */
}

/* FIXME: IS IT FASTER TO USE INSERT / EXTRACT HERE? */
static inline wd_t wl_to_wd( wl_t l ) {
  union { long   l[4]; __m256i v[1]; } t[1];
  union { double d[4]; __m256d v[1]; } u[1];
  _mm256_store_si256( t->v, l );
  u->d[0] = (double)t->l[0];
  u->d[1] = (double)t->l[1];
  u->d[2] = (double)t->l[2];
  u->d[3] = (double)t->l[3];
  return _mm256_load_pd( u->d );
}

#define wl_to_wv(a) (a)

#define wl_to_wc_raw(a) (a)
#define wl_to_wf_raw(a) _mm256_castsi256_ps( (a) )
#define wl_to_wi_raw(a) (a)
#define wl_to_wu_raw(a) (a)
#define wl_to_wd_raw(a) _mm256_castsi256_pd( (a) )
#define wl_to_wv_raw(a) (a)

/* Reduction operations */

static inline wl_t
wl_sum_all( wl_t x ) { /* Returns wl_bcast( sum( x ) ) */
  x = _mm256_add_epi64( x, _mm256_permute2f128_si256( x, x, 1 ) );
  return _mm256_add_epi64( x, _mm256_castpd_si256( _mm256_permute_pd( _mm256_castsi256_pd( x ), 5 ) ) );
}

static inline wl_t
wl_min_all( wl_t x ) { /* Returns wl_bcast( min( x ) ) */
  x = wl_min( x, _mm256_permute2f128_si256( x, x, 1 ) );
  return wl_min( x, _mm256_castpd_si256( _mm256_permute_pd( _mm256_castsi256_pd( x ), 5 ) ) );
}

static inline wl_t
wl_max_all( wl_t x ) { /* Returns wl_bcast( max( x ) ) */
  x = wl_max( x, _mm256_permute2f128_si256( x, x, 1 ) );
  return wl_max( x, _mm256_castpd_si256( _mm256_permute_pd( _mm256_castsi256_pd( x ), 5 ) ) );
}

/* Misc operations */

/* wl_gather(b,i,imm_hi) returns
     [ b[i(0)] b[i(1)] b[i(2)] b[i(3)] ] if imm_hi is 0 and
     [ b[i(4)] b[i(5)] b[i(6)] b[i(7)] ] o.w.
   where b is a "long const*", i is wi_t and imm_hi is a compile time
   constant.  We use a static inline here instead of a define to keep
   strict type checking while working around yet another Intel intrinsic
   type mismatch issue. */

static inline wl_t wl_gather( long const * b, wi_t i, int imm_hi ) {
  /* A compile time branch, but older versions of GCC can't handle the
     ternary operator with -O0 */
  if( imm_hi ) return _mm256_i32gather_epi64( (long long const *)b, _mm256_extractf128_si256( i, 1 ), 8 );
  else         return _mm256_i32gather_epi64( (long long const *)b, _mm256_extractf128_si256( i, 0 ), 8 );
}

/* wl_transpose_4x4 transposes the 4x4 matrix stored in wl_t r0,r1,r2,r3
   and stores the result in 4x4 matrix wl_t c0,c1,c2,c3.  All
   c0,c1,c2,c3 should be different for a well defined result.
   Otherwise, in-place operation and/or using the same wl_t to specify
   multiple rows of r is fine. */

#define wl_transpose_4x4( r0,r1,r2,r3, c0,c1,c2,c3 ) do {                                                                         \
    wl_t _wl_transpose_r0 = (r0); wl_t _wl_transpose_r1 = (r1); wl_t _wl_transpose_r2 = (r2); wl_t _wl_transpose_r3 = (r3);       \
    wl_t _wl_transpose_t;                                                                                                         \
    /* Transpose 2x2 blocks */                                                                                                    \
    _wl_transpose_t = _wl_transpose_r0; _wl_transpose_r0 = _mm256_permute2f128_si256( _wl_transpose_t,  _wl_transpose_r2, 0x20 ); \
    /**/                                _wl_transpose_r2 = _mm256_permute2f128_si256( _wl_transpose_t,  _wl_transpose_r2, 0x31 ); \
    _wl_transpose_t = _wl_transpose_r1; _wl_transpose_r1 = _mm256_permute2f128_si256( _wl_transpose_t,  _wl_transpose_r3, 0x20 ); \
    /**/                                _wl_transpose_r3 = _mm256_permute2f128_si256( _wl_transpose_t,  _wl_transpose_r3, 0x31 ); \
    /* Transpose 1x1 blocks */                                                                                                    \
    /**/                                (c0)             = _mm256_unpacklo_epi64(     _wl_transpose_r0, _wl_transpose_r1 );       \
    /**/                                (c1)             = _mm256_unpackhi_epi64(     _wl_transpose_r0, _wl_transpose_r1 );       \
    /**/                                (c2)             = _mm256_unpacklo_epi64(     _wl_transpose_r2, _wl_transpose_r3 );       \
    /**/                                (c3)             = _mm256_unpackhi_epi64(     _wl_transpose_r2, _wl_transpose_r3 );       \
  } while(0)
