#ifndef HEADER_fd_src_util_simd_fd_sse_h
#error "Do not include this directly; use fd_sse.h"
#endif

/* Vector byte API *****************************************************/

/* A vb_t is a vector where each 8-bit wide lane holds an unsigned 8-bit
   integer (a "uchar").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define vb_t __m128i

/* Constructors */

/* Given the uchar values, return ... */

#define vb(b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10,b11,b12,b13,b14,b15 ) /* [ b0 b1 ... b15 ] */                     \
  _mm_setr_epi8( (char)( b0), (char)( b1), (char)( b2), (char)( b3), (char)( b4), (char)( b5), (char)( b6), (char)( b7), \
                 (char)( b8), (char)( b9), (char)(b10), (char)(b11), (char)(b12), (char)(b13), (char)(b14), (char)(b15) )

#define vb_bcast(b0) _mm_set1_epi8( (char)(b0) ) /* [ b0 b0 ... b0 ] */

static inline vb_t /* [ b0 b1 b0 b1 ... b0 b1 ] */
vb_bcast_pair( uchar b0, uchar b1 ) {
  return _mm_setr_epi8( (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1),
                        (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1) );
}

static inline vb_t /* [ b0 b1 b2 b3 b0 b1 b2 b3 ... b0 b1 b2 b3 ] */
vb_bcast_quad( uchar b0, uchar b1, uchar b2, uchar b3 ) {
  return _mm_setr_epi8( (char)(b0), (char)(b1), (char)(b2), (char)(b3), (char)(b0), (char)(b1), (char)(b2), (char)(b3),
                        (char)(b0), (char)(b1), (char)(b2), (char)(b3), (char)(b0), (char)(b1), (char)(b2), (char)(b3) );
}

static inline vb_t /* [ b0 b1 ... b7 b0 b1 ... b7 ] */
vb_bcast_oct( uchar b0, uchar b1, uchar b2, uchar b3, uchar b4, uchar b5, uchar b6, uchar b7 ) {
  return _mm_setr_epi8( (char)(b0), (char)(b1), (char)(b2), (char)(b3), (char)(b4), (char)(b5), (char)(b6), (char)(b7),
                        (char)(b0), (char)(b1), (char)(b2), (char)(b3), (char)(b4), (char)(b5), (char)(b6), (char)(b7) );
}

static inline vb_t /* [ b0 b0 ... b0 b1 b1 ... b1 ] */
vb_expand_pair( uchar b0, uchar b1 ) {
  return _mm_setr_epi8( (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0),
                        (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1) );
}

static inline vb_t /* [ b0 b0 b1 b1 ... b7 b7 ] */
vb_expand_quad( uchar b0, uchar b1, uchar b2, uchar b3 ) {
  return _mm_setr_epi8( (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b1), (char)(b1), (char)(b1), (char)(b1),
                        (char)(b2), (char)(b2), (char)(b2), (char)(b2), (char)(b3), (char)(b3), (char)(b3), (char)(b3) );
}

static inline vb_t /* [ b0 b0 b1 b1 ... b7 b7 ] */
vb_expand_oct( uchar b0, uchar b1, uchar b2, uchar b3, uchar b4, uchar b5, uchar b6, uchar b7 ) {
  return _mm_setr_epi8( (char)(b0), (char)(b0), (char)(b1), (char)(b1), (char)(b2), (char)(b2), (char)(b3), (char)(b3),
                        (char)(b4), (char)(b4), (char)(b5), (char)(b5), (char)(b6), (char)(b6), (char)(b7), (char)(b7) );
}

#define vb_permute(x,i0,i1,i2,i3,i4,i5,i6,i7,i8,i9,i10,i11,i12,i13,i14,i15) /* [ x[i0] x[i1] ... x[i15] ] */ \
  _mm_shuffle_epi8( (x), vb( (i0), (i1), (i2),  (i3),  (i4),  (i5),  (i6),  (i7),                            \
                             (i8), (i9), (i10), (i11), (i12), (i13), (i14), (i15) ) )

/* Useful cases are provided below.  Given [ b0 b1 b2 b3 b4 ... b15 ], return ... */

#define vb_exch_adj(x)        /* [ b1 b0 b3 b2 ... b15 b14 ] */ \
  _mm_shuffle_epi8( (x), vb( 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14 ) )

#define vb_exch_adj_pair(x)   /* [ b2 b3 b0 b1 .. b14 b15 b12 b13 ] */ \
  _mm_shuffle_epi8( (x), vb( 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13 ) )

#define vb_exch_adj_quad(x)   /* [ b4 b5 b6 b7 b0 b1 b2 b3 .. b8 b9 b10 b11 ] */ \
  _mm_shuffle_epi8( (x), vb( 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11 ) )

#define vb_exch_adj_oct(x)    /* [ b8 b9 ... b15 b0 b1 ... b7 */ \
  _mm_shuffle_epi8( (x), vb( 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7 ) )

#define vb_bcast_even(x)      /* [ b0 b0 b2 b2 b4 b4 .. b12 b12 b14 b14 ] */ \
  _mm_shuffle_epi8( (x), vb( 0, 0, 2, 2, 4, 4, 6, 6, 8, 8, 10, 10, 12, 12, 14, 14 ) )

#define vb_bcast_odd(x)       /* [ b1 b1 b3 b3 b5 b5 .. b13 b13 b15 b15 ] */ \
  _mm_shuffle_epi8( (x), vb( 1, 1, 3, 3, 5, 5, 7, 7, 9, 9, 11, 11, 13, 13, 15, 15 ) )

/* Predefined constants */

#define vb_zero() _mm_setzero_si128() /* Return [ 0 0 ... 0 ] */
#define vb_one()  _mm_set1_epi8( 1 )  /* Return [ 1 1 ... 1 ] */

/* Memory operations */

/* vb_ld return the 16 uchars at the 16-byte aligned / 16-byte sized
   location p as a vector uchar.  vb_ldu is the same but p does not have
   to be aligned.  vb_st writes the vector uchar to the 16-byte aligned /
   16-byte sized location p as 16 uchars.  vb_stu is the same but p does
   not have to be aligned.  In all these lane l will be at p[l].  FIXME:
   USE ATTRIBUTES ON P PASSED TO THESE?

   Note: gcc knows a __m128i may alias. */

static inline vb_t vb_ld( uchar const * p ) { return _mm_load_si128(  (__m128i const *)p ); }
static inline void vb_st( uchar * p, vb_t i ) { _mm_store_si128(  (__m128i *)p, i ); }

static inline vb_t vb_ldu( void const * p ) { return _mm_loadu_si128( (__m128i const *)p ); }
static inline void vb_stu( void * p, vb_t i ) { _mm_storeu_si128( (__m128i *)p, i ); }

/* Sadly, no maskload_epi8, so we can't provide a vb_ldif or vb_stif.
   TODO: consider emulating this? */

/* Element operations */

/* vb_extract extracts the uchar in lane imm from the vector uchar.
   vb_insert returns the vector uchar formed by replacing the value in
   lane imm of a vbth the provided uchar.  imm should be a compile time
   constant in 0:15.  vb_extract_variable and vb_insert_variable are the
   slower but the lane n does not have to be known at compile time
   (should still be in 0:15).

   Note: C99 TC3 allows type punning through a union. */

#define vb_extract(a,imm)  ((uchar)_mm_extract_epi8( (a), (imm) ))
#define vb_insert(a,imm,v) _mm_insert_epi8( (a), (char)(v), (imm) )

static inline uchar
vb_extract_variable( vb_t a, int n ) {
  union { __m128i m[1]; uchar i[16]; } t[1];
  _mm_store_si128( t->m, a );
  return t->i[n];
}

static inline vb_t
vb_insert_variable( vb_t a, int n, uchar v ) {
  union { __m128i m[1]; uchar i[16]; } t[1];
  _mm_store_si128( t->m, a );
  t->i[n] = v;
  return _mm_load_si128( t->m );
}

/* Given [a0 a1 ... a15] and/or [b0 b1 ... b15], return ... */

/* Arithmetic operations */

#define vb_neg(a) _mm_sub_epi8( _mm_setzero_si128(), (a) ) /* [ -a0  -a1  ... -a15  ] (twos complement handling) */
#define vb_abs(a) (a)                                      /* [ |a0| |a1| ... |a15| ] (unsigned type, so identity) */

#define vb_min(a,b) _mm_min_epu8( (a), (b) ) /* [ min(a0,b0) min(a1,b1) ... min(a15,b15) ] */
#define vb_max(a,b) _mm_max_epu8( (a), (b) ) /* [ max(a0,b0) max(a1,b1) ... max(a15,b15) ] */
#define vb_add(a,b) _mm_add_epi8( (a), (b) ) /* [ a0 +b0     a1 +b1     ... a15 +b15     ] */
#define vb_sub(a,b) _mm_sub_epi8( (a), (b) ) /* [ a0 -b0     a1 -b1     ... a15 -b15     ] */

/* No vb_mul because there's no instruction for multiplying uchars.  You
   can build one with two invocations to _mm_mullo_epi16, but it won't
   be particularly fast.  Multiplication by add and shift might be
   faster honestly.  TODO: consider emulating for completeness? */

/* Bit operations */

/* Note: vb_shl/vb_shr is an unsigned left/right shift by imm bits; imm
   must be a compile time constant in 0:7.  The variable variants are
   slower but do not require the shift amount to be known at compile
   time (should still be in 0:7). */

#define vb_not(a) _mm_xor_si128( _mm_set1_epi32( -1 ), (a) ) /* [ ~a0 ~a1 ... ~a15 ] */

#define vb_shl(a,imm) vb_and( _mm_slli_epi16( (a), (imm) ), vb_bcast( (uchar)(0xFFUL << (imm)) ) ) /* [ a0<<imm a1<<imm ... a15<<imm ] */
#define vb_shr(a,imm) vb_and( _mm_srli_epi16( (a), (imm) ), vb_bcast( (uchar)(0xFFUL >> (imm)) ) ) /* [ a0>>imm a1>>imm ... a15>>imm ] (treat a as unsigned) */

#define vb_shl_variable(a,n) vb_and( _mm_sll_epi16( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) ), \
                                     vb_bcast( (uchar)(0xFFUL << (n)) ) )
#define vb_shr_variable(a,n) vb_and( _mm_srl_epi16( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) ), \
                                     vb_bcast( (uchar)(0xFFUL >> (n)) ) )

#define vb_and(a,b)    _mm_and_si128(    (a), (b) ) /* [   a0 &b0    a1& b1 ...   a15& b15 ] */
#define vb_andnot(a,b) _mm_andnot_si128( (a), (b) ) /* [ (~a0)&b0  (~a1)&b1 ... (~a15)&b15 ] */
#define vb_or(a,b)     _mm_or_si128(     (a), (b) ) /* [   a0 |b0    a1 |b1 ...   a15 |b15 ] */
#define vb_xor(a,b)    _mm_xor_si128(    (a), (b) ) /* [   a0 ^b0    a1 ^b1 ...   a15 ^b15 ] */

static inline vb_t vb_rol( vb_t a, int imm ) { return vb_or( vb_shl( a, imm & 7 ), vb_shr( a, (-imm) & 7 ) ); }
static inline vb_t vb_ror( vb_t a, int imm ) { return vb_or( vb_shr( a, imm & 7 ), vb_shl( a, (-imm) & 7 ) ); }

static inline vb_t vb_rol_variable( vb_t a, int n ) { return vb_or( vb_shl_variable( a, n&7 ), vb_shr_variable( a, (-n)&7 ) ); }
static inline vb_t vb_ror_variable( vb_t a, int n ) { return vb_or( vb_shr_variable( a, n&7 ), vb_shl_variable( a, (-n)&7 ) ); }

/* Logical operations */

#define vb_lnot(a)    _mm_cmpeq_epi8( (a), _mm_setzero_si128() ) /* [  !a0  !a1 ...  !a15 ] */
#define vb_lnotnot(a)                                            /* [ !!a0 !!a1 ... !!a15 ] */ \
  _mm_xor_si128( _mm_set1_epi32( -1 ), vb_lnot( (a) ) )

#define vb_eq(a,b) _mm_cmpeq_epi8( (a), (b) )                                            /* [ a0==b0 a1==b1 ... a15==b15 ] */
#define vb_gt(a,b) _mm_cmpgt_epi8( _mm_sub_epi8( (a), _mm_set1_epi8( (char)(1U<<7) ) ),  /* [ a0> b0 a1> b1 ... a15> b15 ] */ \
                                   _mm_sub_epi8( (b), _mm_set1_epi8( (char)(1U<<7) ) ) )
#define vb_lt(a,b) vb_gt( (b), (a) )                                                     /* [ a0< b0 a1< b1 ... a15< b15 ] */
#define vb_ne(a,b) _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_cmpeq_epi8( (a), (b) ) )     /* [ a0!=b0 a1!=b1 ... a15!=b15 ] */
#define vb_ge(a,b) _mm_xor_si128( _mm_set1_epi32( -1 ), vb_gt( (b), (a) ) )              /* [ a0>=b0 a1>=b1 ... a15>=b15 ] */
#define vb_le(a,b) _mm_xor_si128( _mm_set1_epi32( -1 ), vb_gt( (a), (b) ) )              /* [ a0<=b0 a1<=b1 ... a15<=b15 ] */

/* Conditional operations */

#define vb_czero(c,f)    _mm_andnot_si128( (c), (f) ) /* [ c0? 0:f0 c1? 0:f1 ... c15? 0:f15 ] */
#define vb_notczero(c,f) _mm_and_si128(    (c), (f) ) /* [ c0?f0: 0 c1?f1: 0 ... c15?f15: 0 ] */

#define vb_if(c,t,f) _mm_blendv_epi8( (f), (t), (c) ) /* [ c0?t0:f0 c1?t1:f1 ... c15?t15:f15 ] */

/* Conversion operations */

/* Summarizing:

   vb_to_vc(a, 0)   returns [ !!a0  !!a1  !!a2  !!a3  ]
   vb_to_vc(a, 1)   returns [ !!a4  !!a5  !!a6  !!a7  ]
   vb_to_vc(a, 2)   returns [ !!a8  !!a9  !!a10 !!a11 ]
   vb_to_vc(a, 3)   returns [ !!a12 !!a13 !!a14 !!a15 ]

   vb_to_vf(a, 0)   returns [ (float)a0  (float)a1  (float)a2  (float)a3  ]
   vb_to_vf(a, 1)   returns [ (float)a4  (float)a5  (float)a6  (float)a7  ]
   vb_to_vf(a, 2)   returns [ (float)a8  (float)a9  (float)a10 (float)a11 ]
   vb_to_vf(a, 3)   returns [ (float)a12 (float)a13 (float)a14 (float)a15 ]

   vb_to_vi(a, 0)   returns [ (int)a0  (int)a1  (int)a2  (int)a3  ]
   vb_to_vi(a, 1)   returns [ (int)a4  (int)a5  (int)a6  (int)a7  ]
   vb_to_vi(a, 2)   returns [ (int)a8  (int)a9  (int)a10 (int)a11 ]
   vb_to_vi(a, 3)   returns [ (int)a12 (int)a13 (int)a14 (int)a15 ]

   vb_to_vu(a, 0)   returns [ (uint)a0  (uint)a1  (uint)a2  (uint)a3  ]
   vb_to_vu(a, 1)   returns [ (uint)a4  (uint)a5  (uint)a6  (uint)a7  ]
   vb_to_vu(a, 2)   returns [ (uint)a8  (uint)a9  (uint)a10 (uint)a11 ]
   vb_to_vu(a, 3)   returns [ (uint)a12 (uint)a13 (uint)a14 (uint)a15 ]

   vb_to_vd(a,0) returns [ (double)a0  (double)a1  ]
   vb_to_vd(a,1) returns [ (double)a2  (double)a3  ]
   ...
   vb_to_vd(a,7) returns [ (double)a14 (double)a15 ]

   vb_to_vl(a,0) returns [ (long)a0  (long)a1  ]
   vb_to_vl(a,1) returns [ (long)a2  (long)a3  ]
   ...
   vb_to_vl(a,7) returns [ (long)a14 (long)a15 ]

   vb_to_vv(a,0) returns [ (ulong)a0  (ulong)a1  ]
   vb_to_vv(a,1) returns [ (ulong)a2  (ulong)a3  ]
   ...
   vb_to_vv(a,7) returns [ (ulong)a14 (ulong)a15 ]

   where the above values should be compile time constants. */

#define vb_to_vc( a, imm ) _mm_xor_si128( _mm_set1_epi32( -1 ), _mm_cmpeq_epi32( _mm_cvtepu8_epi32( _mm_bsrli_si128( (a), 4*(imm) ) ) , _mm_setzero_si128() ) )
#define vb_to_vf( a, imm ) _mm_cvtepi32_ps( _mm_cvtepu8_epi32( _mm_bsrli_si128( (a), 4*(imm) ) ) )
#define vb_to_vi( a, imm ) _mm_cvtepu8_epi32( _mm_bsrli_si128( (a), 4*(imm) ) )
#define vb_to_vu( a, imm ) _mm_cvtepu8_epi32( _mm_bsrli_si128( (a), 4*(imm) ) )
#define vb_to_vd( a, imm ) _mm_cvtepi32_pd( _mm_cvtepu8_epi32( _mm_bsrli_si128( (a), 2*(imm) ) ) )
#define vb_to_vl( a, imm ) _mm_cvtepu8_epi64( _mm_bsrli_si128( (a), 2*(imm) ) )
#define vb_to_vv( a, imm ) _mm_cvtepu8_epi64( _mm_bsrli_si128( (a), 2*(imm) ) )

#define vb_to_vc_raw(a) (a)
#define vb_to_vf_raw(a) _mm_castsi128_ps( (a) )
#define vb_to_vi_raw(a) (a)
#define vb_to_vu_raw(a) (a)
#define vb_to_vd_raw(a) _mm_castsi128_pd( (a) )
#define vb_to_vl_raw(a) (a)
#define vb_to_vv_raw(a) (a)

/* Reduction operations */

static inline vb_t
vb_sum_all( vb_t x ) { /* Returns vb_bcast( sum( x ) ) */
  x = _mm_sad_epu8( x, _mm_setzero_si128() );                /* x[0-7]       x[8-15]  (each stored in 64 bits) */
  return _mm_add_epi8( _mm_shuffle_epi8( x, vb_bcast( 0 ) ) , _mm_shuffle_epi8( x, vb_bcast( 8 ) ) ); /* Grab the low byte of each sum, broadcast it, then sum */
}

static inline vb_t
vb_min_all( vb_t x ) { /* Returns vb_bcast( min( x ) ) */
  x = _mm_min_epu8( x, _mm_shuffle_epi8( x, vb( 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7 ) ) ); /* x0,8    x1,9  .. x7,15  (repeats 1 more time) */
  x = _mm_min_epu8( x, _mm_shuffle_epi8( x, vb( 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3 ) ) ); /* x0,4,8,12  .. x3,7,11,15 (repeats 3 more times)*/
  x = _mm_min_epu8( x, _mm_shuffle_epi8( x, vb_bcast_quad( 2, 3, 0, 1 ) ) ); /* x_even x_odd (repeats 7 more times) */
  x = _mm_min_epu8( x, _mm_shuffle_epi8( x, vb_bcast_pair( 1, 0 ) ) ); /* x_all (repeats 15 more times) */
  return x;
}

static inline vb_t
vb_max_all( vb_t x ) { /* Returns vb_bcast( max( x ) ) */
  x = _mm_max_epu8( x, _mm_shuffle_epi8( x, vb( 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7 ) ) ); /* x0,8    x1,9  .. x7,15  (repeats 1 more time) */
  x = _mm_max_epu8( x, _mm_shuffle_epi8( x, vb( 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3 ) ) ); /* x0,4,8,12  .. x3,7,11,15 (repeats 3 more times)*/
  x = _mm_max_epu8( x, _mm_shuffle_epi8( x, vb_bcast_quad( 2, 3, 0, 1 ) ) ); /* x_even x_odd (repeats 7 more times) */
  x = _mm_max_epu8( x, _mm_shuffle_epi8( x, vb_bcast_pair( 1, 0 ) ) ); /* x_all (repeats 15 more times) */
  return x;
}

/* Misc operations */

/* TODO: These are probably are actually part of the vc post
   generalization to different width SIMD types. */

/* vb_{any, all} return 1 if any/all of the elements are non-zero.  The
   _fast variants are suitable for use with the return value of any of
   the vb comparison functions (e.g. vb_gt ). */

#define vb_any_fast( x ) ( 0 != _mm_movemask_epi8( x ) )
#define vb_any( x ) vb_any_fast( vb_ne( (x), vb_zero( ) ) )
#define vb_all_fast( x ) ( 0xFFFF == _mm_movemask_epi8( x ) )
#define vb_all( x ) vb_all_fast( vb_ne( (x), vb_zero( ) ) )
