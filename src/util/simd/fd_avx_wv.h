#ifndef HEADER_fd_src_util_simd_fd_avx_h
#error "Do not include this directly; use fd_avx.h"
#endif

/* Vector ulong API ***************************************************/

/* A wv_t is a vector where each adjacent pair of 32-bit wide lanes
   (e.g. 0-1 / 2-3 / 4-5 / 6-7) holds an unsigned 64-bit integer (a
   "ulong").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wv_t __m256i

/* Constructors */

/* Given the ulong values, return ... */

#define wv(v0,v1,v2,v3) _mm256_setr_epi64x( (long)(v0), (long)(v1), (long)(v2), (long)(v3) ) /* [ v0 v1 v2 v3 ] */

#define wv_bcast(v0) _mm256_set1_epi64x( (long)(v0) ) /* [ v0 v0 v0 v0 ] */

static inline wv_t /* [ v0 v1 v0 v1 ] */
wv_bcast_pair( ulong v0, ulong v1 ) {
  return _mm256_setr_epi64x( (long)v0, (long)v1, (long)v0, (long)v1 );
}

static inline wv_t /* [ v0 v0 v1 v1 ] */
wv_bcast_wide( ulong v0, ulong v1 ) {
  return _mm256_setr_epi64x( (long)v0, (long)v0, (long)v1, (long)v1 );
}

/* wv_permute returns [ l(imm_v0) l(imm_i1) l(imm_i2) l(imm_i3) ].
   imm_i* should be compile time constants in 0:3. */

#if FD_USING_CLANG /* Sigh ... clang is sad and can't handle passing compile time const expressions through a static inline */

static inline wv_t
wv_permute( wv_t x, int imm_i0, int imm_i1, int imm_i2, int imm_i3 ) {
  union { ulong u[4]; __m256i v[1]; } t, u;
  _mm256_store_si256( t.v, x );
  u.u[0] = t.u[ imm_i0 ];
  u.u[1] = t.u[ imm_i1 ];
  u.u[2] = t.u[ imm_i2 ];
  u.u[3] = t.u[ imm_i3 ];
  return _mm256_load_si256( u.v );
}

#else

#define wv_permute(x,imm_i0,imm_i1,imm_i2,imm_i3) _mm256_permute4x64_epi64( (x), (imm_i0)+4*(imm_i1)+16*(imm_i2)+64*(imm_i3) )

#endif

/* Predefined constants */

#define wv_zero() _mm256_setzero_si256()   /* Return [ 0UL 0UL 0UL 0UL ] */
#define wv_one()  _mm256_set1_epi64x( 1L ) /* Return [ 1UL 1UL 1UL 1UL ] */

/* Memory operations */

/* wv_ld return the 4 ulongs at the 32-byte aligned / 32-byte sized
   location p as a vector ulong.  wv_ldu is the same but p does not have
   to be aligned.  wv_st writes the vector ulong to the 32-byte aligned
   / 32-byte sized location p as 4 ulongs.  wv_stu is the same but p
   does not have to be aligned.  In all these 64-bit lane l wvll be at
   p[l].  FIXME: USE ATTRIBUTES ON P PASSED TO THESE?

   Note: gcc knows a __m256i may alias. */

static inline wv_t wv_ld( ulong const * p ) { return _mm256_load_si256(  (__m256i const *)p ); }
static inline void wv_st( ulong * p, wv_t i ) { _mm256_store_si256(  (__m256i *)p, i ); }

static inline wv_t wv_ldu( void const * p ) { return _mm256_loadu_si256( (__m256i const *)p ); }
static inline void wv_stu( void * p, wv_t i ) { _mm256_storeu_si256( (__m256i *)p, i ); }

/* wv_ldif is an optimized equivalent to wv_notczero(c,wv_ldu(p)) (may
   have different behavior if c is not a proper vector conditional).  It
   is provided for symmetry with the wv_stif operation.  wv_stif stores
   x(n) to p[n] if c(n) is true and leaves p[n] unchanged otherwise.
   Undefined behavior if c is not a proper vector conditional. */

#define wv_ldif(c,p)   _mm256_maskload_epi64( (p),(c))
#define wv_stif(c,p,x) _mm256_maskstore_epi64((p),(c),(x))

/* Element operations */

/* wv_extract extracts the ulong in lane imm from the vector ulong as a
   ulong.  wv_insert returns the vector ulong formed by replacing the
   value in lane imm of a with the provided ulong.  imm should be a
   compile time known in 0:3.  wv_extract_variable and
   wv_insert_variable are the slower but the lane n does not have to be
   known at compile time (should still be in 0:3).

   Note: C99 TC3 allows type punning through a union. */

#define wv_extract(a,imm)  ((ulong)_mm256_extract_epi64( (a), (imm) ))

#define wv_insert(a,imm,v) _mm256_insert_epi64( (a), (long)(v), (imm) )

static inline ulong
wv_extract_variable( wv_t a, int n ) {
  union { __m256i m[1]; ulong u[4]; } t[1];
  _mm256_store_si256( t->m, a );
  return t->u[n];
}

static inline wv_t
wv_insert_variable( wv_t a, int n, ulong v ) {
  union { __m256i m[1]; ulong u[4]; } t[1];
  _mm256_store_si256( t->m, a );
  t->u[n] = v;
  return _mm256_load_si256( t->m );
}

/* Given [a0 a1 a2 a3] and/or [b0 b1 b2 b3], return ... */

/* Arithmetic operations */

#define wv_neg(a) _mm256_sub_epi64( _mm256_setzero_si256(), (a) ) /* [ -a0  -a1  ... -a3  ] */
#define wv_abs(a) (a)                                             /* [ |a0| |a1| ... |a3| ] */

/* Note: _mm256_{min,max}_epu64 are missing pre AVX-512.  We emulate
   these on pre AVX-512 targets below (and use the AVX-512 versions if
   possible).  Likewise, there is no _mm256_mullo_epi64 pre AVX-512.
   Since this is not cheap to emulate, we do not provide a wv_mul for
   the time being (we could consider exposing it on AVX-512 targets
   though).  There is a 64L*64L->64 multiply (where the lower 32-bits of
   the inputs will be zero extended to 64-bits beforehand) though and
   that is very useful.  So we do provide that. */

#define wv_add(a,b)    _mm256_add_epi64(   (a), (b) ) /* [ a0 +b0     a1 +b1     ... a3 +b3     ] */
#define wv_sub(a,b)    _mm256_sub_epi64(   (a), (b) ) /* [ a0 -b0     a1 -b1     ... a3 -b3     ] */
//#define wv_mul(a,b)  _mm256_mullo_epi64( (a), (b) ) /* [ a0 *b0     a1 *b1     ... a3 *b3     ] */
#define wv_mul_ll(a,b) _mm256_mul_epu32(   (a), (b) ) /* [ a0l*b0l    a1l*b1l    ... a3l *b3l   ] */

/* Binary operations */

/* Note: wv_shl/wv_shr is a left/right shift by imm bits; imm should be
   a compile time constant in 0:63.  The variable variants are slower
   but do not require the shift amount to be known at compile time
   (should still be in 0:63). */

#define wv_not(a) _mm256_xor_si256( _mm256_set1_epi64x( -1L ), (a) ) /* [ ~a0 ~a1 ... ~a3 ] */

#define wv_shl(a,imm) _mm256_slli_epi64( (a), (imm) ) /* [ a0<<imm a1<<imm ... a3<<imm ] */
#define wv_shr(a,imm) _mm256_srli_epi64( (a), (imm) ) /* [ a0>>imm a1>>imm ... a3>>imm ] */

#define wv_shl_variable(a,n) _mm256_sll_epi64( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
#define wv_shr_variable(a,n) _mm256_srl_epi64( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )

#define wv_shl_vector(a,b) _mm256_sllv_epi64( (a), (b) ) /* [ a0<<b0 a1<<b1 ... a3<<b3 ] */
#define wv_shr_vector(a,b) _mm256_srlv_epi64( (a), (b) ) /* [ a0>>b0 a1>>b1 ... a3>>b3 ] */

#define wv_and(a,b)    _mm256_and_si256(    (a), (b) ) /* [   a0 &b0    a1& b1 ...   a3& b3 ] */
#define wv_andnot(a,b) _mm256_andnot_si256( (a), (b) ) /* [ (~a0)&b0  (~a1)&b1 ... (~a3)&b3 ] */
#define wv_or(a,b)     _mm256_or_si256(     (a), (b) ) /* [   a0 |b0    a1 |b1 ...   a3 |b3 ] */
#define wv_xor(a,b)    _mm256_xor_si256(    (a), (b) ) /* [   a0 ^b0    a1 ^b1 ...   a3 ^b3 ] */

static inline wv_t wv_rol( wv_t a, int imm ) { return wv_or( wv_shl( a, imm & 63 ), wv_shr( a, (-imm) & 63 ) ); }
static inline wv_t wv_ror( wv_t a, int imm ) { return wv_or( wv_shr( a, imm & 63 ), wv_shl( a, (-imm) & 63 ) ); }

static inline wv_t wv_rol_variable( wv_t a, int n ) { return wv_or( wv_shl_variable( a, n&63 ), wv_shr_variable( a, (-n)&63 ) ); }
static inline wv_t wv_ror_variable( wv_t a, int n ) { return wv_or( wv_shr_variable( a, n&63 ), wv_shl_variable( a, (-n)&63 ) ); }

static inline wv_t wv_rol_vector( wv_t a, wl_t b ) {
  wl_t m = wl_bcast( 63L );
  return wv_or( wv_shl_vector( a, wl_and( b, m ) ), wv_shr_vector( a, wl_and( wl_neg( b ), m ) ) );
}

static inline wv_t wv_ror_vector( wv_t a, wl_t b ) {
  wl_t m = wl_bcast( 63L );
  return wv_or( wv_shr_vector( a, wl_and( b, m ) ), wv_shl_vector( a, wl_and( wl_neg( b ), m ) ) );
}

#define wv_bswap(a) wu_to_wv_raw( wu_bswap( wv_to_wu_raw( wv_rol( (a), 32 ) ) ) )

/* Logical operations */

/* Like noted below in the converters, Intel clearly has the hardware to
   do a _mm256_cmpgt_epu64 given that _mm256_cmpgt_epi64 exists but
   doesn't expose it in the ISA pre AVX-512.  Sigh ... twos complement
   bit tricks to the rescue for wu_{gt,lt,ge,le}. */

#define wv_lnot(a) _mm256_cmpeq_epi64( (a), _mm256_setzero_si256() )                           /* [  !a0  !a1 ...  !a3 ] */
#define wv_lnotnot(a)                                                                          /* [ !!a0 !!a1 ... !!a3 ] */ \
  _mm256_xor_si256( _mm256_set1_epi64x( -1L ), _mm256_cmpeq_epi64( (a), _mm256_setzero_si256() ) )

#define wv_eq(a,b) _mm256_cmpeq_epi64( (a), (b) )                                              /* [ a0==b0 a1==b1 ... a3==b3 ] */
#define wv_gt(a,b)                                                                             /* [ a0> b0 a1> b1 ... a3> b3 ] */ \
  _mm256_cmpgt_epi64( _mm256_sub_epi64( (a), _mm256_set1_epi64x( (long)(1UL<<63) ) ),                                             \
                      _mm256_sub_epi64( (b), _mm256_set1_epi64x( (long)(1UL<<63) ) ) )
#define wv_lt(a,b) wv_gt( (b), (a) )                                                           /* [ a0< b0 a1< b1 ... a3< b3 ] */
#define wv_ne(a,b) _mm256_xor_si256( _mm256_set1_epi64x(-1L), _mm256_cmpeq_epi64( (a), (b) ) ) /* [ a0!=b0 a1!=b1 ... a3!=b3 ] */
#define wv_ge(a,b) _mm256_xor_si256( _mm256_set1_epi64x(-1L), wv_gt( (b), (a) ) )              /* [ a0>=b0 a1>=b1 ... a3>=b3 ] */
#define wv_le(a,b) _mm256_xor_si256( _mm256_set1_epi64x(-1L), wv_gt( (a), (b) ) )              /* [ a0<=b0 a1<=b1 ... a3<=b3 ] */

/* Conditional operations */

#define wv_czero(c,f)    _mm256_andnot_si256( (c), (f) )     /* [ c0?0UL:f0 c1?0UL:f1 ... c3?0UL:f3 ] */
#define wv_notczero(c,f) _mm256_and_si256(    (c), (f) )     /* [ c0?f0:0UL c1?f1:0UL ... c3?f3:0UL ] */

#define wv_if(c,t,f)     _mm256_blendv_epi8( (f), (t), (c) ) /* [ c0?t0:f0  c1?t1:f1  ... c3?t3:f3 ] */

#if defined(__AVX512F__) && defined(__AVX512VL__) /* See note above */
#define wv_min(a,b) _mm256_min_epu64( (a), (b) )
#define wv_max(a,b) _mm256_max_epu64( (a), (b) )
#else
static inline wv_t wv_min( wv_t a, wv_t b ) { return wv_if( wv_lt( a, b ), a, b ); }
static inline wv_t wv_max( wv_t a, wv_t b ) { return wv_if( wv_gt( a, b ), a, b ); }
#endif

/* Conversion operations */

/* Summarizing:

   wv_to_wc(d)     returns [ !!v0 !!v0 !!v1 !!v1 ... !!v3 !!v3 ]

   wv_to_wf(l,i,0) returns [ (float)v0 (float)v1 (float)v2 (float)v3 f4 f5 f6 f7 ]
   wv_to_wf(l,i,1) returns [ f0 f1 f2 f3 (float)v0 (float)v1 (float)v2 (float)v3 ]

   wv_to_wi(l,i,0) returns [ (int)v0 (int)v1 (int)v2 (int)v3 i4 i5 i6 i7 ]
   wv_to_wi(l,i,1) returns [ i0 i1 i2 i3 (int)v0 (int)v1 (int)v2 (int)v3 ]

   wv_to_wu(l,u,0) returns [ (uint)v0 (uint)v1 (uint)v2 (uint)v3 u4 u5 u6 u7 ]
   wv_to_wu(l,u,1) returns [ v0 v1 v2 v3 (uint)v0 (uint)v1 (uint)v2 (uint)v3 ]

   wv_to_wd(l)     returns [ (double)v0 (double)v1 (double)v2 (double)v3 ]

   wv_to_wl(l)     returns [ (long)v0 (long)v1 (long)v2 (long)v3 ]

   The raw variants just treat the raw bits as the corresponding vector
   type.  For wv_to_wc_raw, the user promises wv contains a proper
   vector conditional (e.g. 0 or -1 in each lane).  The others are
   provided to facilitate doing advanced bit tricks on floating point
   values. */

#define wv_to_wc(a) _mm256_xor_si256( _mm256_set1_epi64x( -1L ), _mm256_cmpeq_epi64( (a), _mm256_setzero_si256() ) )

static inline wf_t wv_to_wf( wv_t v, wf_t f, int imm_hi ) {
  union { ulong u[4]; __m256i v[1]; } t[1];
  union { float f[4]; __m128  v[1]; } u[1];
  _mm256_store_si256( t->v, v );
  u->f[0] = (float)t->u[0];
  u->f[1] = (float)t->u[1];
  u->f[2] = (float)t->u[2];
  u->f[3] = (float)t->u[3];
  __m128 w = _mm_load_ps( u->f );
  return imm_hi ? _mm256_insertf128_ps( f, w, 1 ) : _mm256_insertf128_ps( f, w, 0 ); /* compile time */
}

static inline wv_t wv_to_wi( wv_t v, wi_t i, int imm_hi ) {
  __m128  v01 = _mm_castsi128_ps( _mm256_extractf128_si256( v, 0 ) ); /* [ v0l v0h v1l v1h ] */
  __m128  v23 = _mm_castsi128_ps( _mm256_extractf128_si256( v, 1 ) ); /* [ v2l v2h v3l v3h ] */
  __m128i w   = _mm_castps_si128( _mm_shuffle_ps( v01, v23, _MM_SHUFFLE(2,0,2,0) ) );
  return imm_hi ? _mm256_insertf128_si256( i, w, 1 ) : _mm256_insertf128_si256( i, w, 0 ); /* compile time */
}

static inline wu_t wv_to_wu( wv_t v, wu_t u, int imm_hi ) {
  __m128  v01 = _mm_castsi128_ps( _mm256_extractf128_si256( v, 0 ) ); /* [ v0l v0h v1l v1h ] */
  __m128  v23 = _mm_castsi128_ps( _mm256_extractf128_si256( v, 1 ) ); /* [ v2l v2h v3l v3h ] */
  __m128i w   = _mm_castps_si128( _mm_shuffle_ps( v01, v23, _MM_SHUFFLE(2,0,2,0) ) );
  return imm_hi ? _mm256_insertf128_si256( u, w, 1 ) : _mm256_insertf128_si256( u, w, 0 ); /* compile time */
}

/* FIXME: IS IT FASTER TO USE INSERT / EXTRACT HERE? */
static inline wd_t wv_to_wd( wv_t v ) {
  union { ulong  u[4]; __m256i v[1]; } t[1];
  union { double d[4]; __m256d v[1]; } u[1];
  _mm256_store_si256( t->v, v );
  u->d[0] = (double)t->u[0];
  u->d[1] = (double)t->u[1];
  u->d[2] = (double)t->u[2];
  u->d[3] = (double)t->u[3];
  return _mm256_load_pd( u->d );
}

#define wv_to_wl(a) (a)

#define wv_to_wc_raw(a) (a)
#define wv_to_wf_raw(a) _mm256_castsi256_ps( (a) )
#define wv_to_wi_raw(a) (a)
#define wv_to_wu_raw(a) (a)
#define wv_to_wd_raw(a) _mm256_castsi256_pd( (a) )
#define wv_to_wl_raw(a) (a)

/* Reduction operations */

static inline wv_t
wv_sum_all( wv_t x ) { /* Returns wv_bcast( sum( x ) ) */
  x = _mm256_add_epi64( x, _mm256_permute2f128_si256( x, x, 1 ) );
  return _mm256_add_epi64( x, _mm256_castpd_si256( _mm256_permute_pd( _mm256_castsi256_pd( x ), 5 ) ) );
}

static inline wv_t
wv_min_all( wv_t x ) { /* Returns wv_bcast( min( x ) ) */
  x = wv_min( x, _mm256_permute2f128_si256( x, x, 1 ) );
  return wv_min( x, _mm256_castpd_si256( _mm256_permute_pd( _mm256_castsi256_pd( x ), 5 ) ) );
}

static inline wv_t
wv_max_all( wv_t x ) { /* Returns wv_bcast( max( x ) ) */
  x = wv_max( x, _mm256_permute2f128_si256( x, x, 1 ) );
  return wv_max( x, _mm256_castpd_si256( _mm256_permute_pd( _mm256_castsi256_pd( x ), 5 ) ) );
}

/* Misc operations */

/* wv_gather(b,i,imm_hi) returns
     [ b[i(0)] b[i(1)] b[i(2)] b[i(3)] ] if imm_hi is 0 and
     [ b[i(4)] b[i(5)] b[i(6)] b[i(7)] ] o.w.
   where b is a "ulong const*", i is wi_t and imm_hi is a compile time
   constant.  We use a static inline here instead of a define to keep
   strict type checking while working around yet another Intel intrinsic
   type mismatch issue. */

static inline wv_t wv_gather( ulong const * b, wi_t i, int imm_hi ) {
  /* A compile time branch, but older versions of GCC can't handle the
     ternary operator with -O0 */
  if( imm_hi ) return _mm256_i32gather_epi64( (long long const *)b, _mm256_extractf128_si256( i, 1 ), 8 );
  else         return _mm256_i32gather_epi64( (long long const *)b, _mm256_extractf128_si256( i, 0 ), 8 );
}

/* wv_transpose_4x4 transposes the 4x4 matrix stored in wv_t r0,r1,r2,r3
   and stores the result in 4x4 matrix wv_t c0,c1,c2,c3.  All
   c0,c1,c2,c3 should be different for a well defined result.
   Otherwise, in-place operation and/or using the same wv_t to specify
   multiple rows of r is fine. */

#define wv_transpose_4x4( r0,r1,r2,r3, c0,c1,c2,c3 ) do {                                                                         \
    wv_t _wv_transpose_r0 = (r0); wv_t _wv_transpose_r1 = (r1); wv_t _wv_transpose_r2 = (r2); wv_t _wv_transpose_r3 = (r3);       \
    wv_t _wv_transpose_t;                                                                                                         \
    /* Transpose 2x2 blocks */                                                                                                    \
    _wv_transpose_t = _wv_transpose_r0; _wv_transpose_r0 = _mm256_permute2f128_si256( _wv_transpose_t,  _wv_transpose_r2, 0x20 ); \
    /**/                                _wv_transpose_r2 = _mm256_permute2f128_si256( _wv_transpose_t,  _wv_transpose_r2, 0x31 ); \
    _wv_transpose_t = _wv_transpose_r1; _wv_transpose_r1 = _mm256_permute2f128_si256( _wv_transpose_t,  _wv_transpose_r3, 0x20 ); \
    /**/                                _wv_transpose_r3 = _mm256_permute2f128_si256( _wv_transpose_t,  _wv_transpose_r3, 0x31 ); \
    /* Transpose 1x1 blocks */                                                                                                    \
    /**/                                (c0)             = _mm256_unpacklo_epi64(     _wv_transpose_r0, _wv_transpose_r1 );       \
    /**/                                (c1)             = _mm256_unpackhi_epi64(     _wv_transpose_r0, _wv_transpose_r1 );       \
    /**/                                (c2)             = _mm256_unpacklo_epi64(     _wv_transpose_r2, _wv_transpose_r3 );       \
    /**/                                (c3)             = _mm256_unpackhi_epi64(     _wv_transpose_r2, _wv_transpose_r3 );       \
  } while(0)
