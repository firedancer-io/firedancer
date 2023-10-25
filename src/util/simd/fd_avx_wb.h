#ifndef HEADER_fd_src_util_simd_fd_avx_h
#error "Do not include this directly; use fd_avx.h"
#endif

/* Vector byte API *****************************************************/

/* A wb_t is a vector where each 8-bit wide lane holds an unsigned 8-bit
   integer (a "uchar").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wb_t __m256i

/* Constructors */

/* TODO: update older SIMD modules to follow the more general convention
   below. */

/* Given the uchar values, return ... */

#define wb(b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10,b11,b12,b13,b14,b15,                                                 \
           b16,b17,b18,b19,b20,b21,b22,b23,b24,b25,b26,b27,b28,b29,b30,b31) /* [ b0 b1 ... b31 ] */                         \
  _mm256_setr_epi8( (char)( b0), (char)( b1), (char)( b2), (char)( b3), (char)( b4), (char)( b5), (char)( b6), (char)( b7), \
                    (char)( b8), (char)( b9), (char)(b10), (char)(b11), (char)(b12), (char)(b13), (char)(b14), (char)(b15), \
                    (char)(b16), (char)(b17), (char)(b18), (char)(b19), (char)(b20), (char)(b21), (char)(b22), (char)(b23), \
                    (char)(b24), (char)(b25), (char)(b26), (char)(b27), (char)(b28), (char)(b29), (char)(b30), (char)(b31) )

#define wb_bcast(b0) _mm256_set1_epi8( (char)(b0) ) /* [ b0 b0 ... b0 ] */

static inline wb_t /* [ b0 b1 b0 b1 ... b0 b1 ] */
wb_bcast_pair( uchar b0, uchar b1 ) {
  return _mm256_setr_epi8( (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1),
                           (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1),
                           (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1),
                           (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1) );
}

static inline wb_t /* [ b0 b1 b2 b3 b0 b1 b2 b3 ... b0 b1 b2 b3 ] */
wb_bcast_quad( uchar b0, uchar b1, uchar b2, uchar b3 ) {
  return _mm256_setr_epi8( (char)(b0), (char)(b1), (char)(b2), (char)(b3), (char)(b0), (char)(b1), (char)(b2), (char)(b3),
                           (char)(b0), (char)(b1), (char)(b2), (char)(b3), (char)(b0), (char)(b1), (char)(b2), (char)(b3),
                           (char)(b0), (char)(b1), (char)(b2), (char)(b3), (char)(b0), (char)(b1), (char)(b2), (char)(b3),
                           (char)(b0), (char)(b1), (char)(b2), (char)(b3), (char)(b0), (char)(b1), (char)(b2), (char)(b3) );
}

static inline wb_t /* [ b0 b1 ... b7 b0 b1 ... b7 b0 b1 ... b7 b0 b1 ... b7 ] */
wb_bcast_oct( uchar b0, uchar b1, uchar b2, uchar b3, uchar b4, uchar b5, uchar b6, uchar b7 ) {
  return _mm256_setr_epi8( (char)(b0), (char)(b1), (char)(b2), (char)(b3), (char)(b4), (char)(b5), (char)(b6), (char)(b7),
                           (char)(b0), (char)(b1), (char)(b2), (char)(b3), (char)(b4), (char)(b5), (char)(b6), (char)(b7),
                           (char)(b0), (char)(b1), (char)(b2), (char)(b3), (char)(b4), (char)(b5), (char)(b6), (char)(b7),
                           (char)(b0), (char)(b1), (char)(b2), (char)(b3), (char)(b4), (char)(b5), (char)(b6), (char)(b7) );
}

static inline wb_t /* [ b0 b1 ... b15 b0 b1 ... b15 ] */
wb_bcast_hex( uchar b0, uchar b1, uchar b2,  uchar b3,  uchar b4,  uchar b5,  uchar b6,  uchar b7,
              uchar b8, uchar b9, uchar b10, uchar b11, uchar b12, uchar b13, uchar b14, uchar b15 ) {
  return _mm256_setr_epi8( (char)(b0), (char)(b1), (char)(b2),  (char)(b3),  (char)(b4),  (char)(b5),  (char)(b6),  (char)(b7),
                           (char)(b8), (char)(b9), (char)(b10), (char)(b11), (char)(b12), (char)(b13), (char)(b14), (char)(b15),
                           (char)(b0), (char)(b1), (char)(b2),  (char)(b3),  (char)(b4),  (char)(b5),  (char)(b6),  (char)(b7),
                           (char)(b8), (char)(b9), (char)(b10), (char)(b11), (char)(b12), (char)(b13), (char)(b14), (char)(b15) );
}

static inline wb_t /* [ b0 b0 ... b0 b1 b1 ... b1 ] */
wb_expand_pair( uchar b0, uchar b1 ) {
  return _mm256_setr_epi8( (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0),
                           (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0),
                           (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1),
                           (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1) );
}

static inline wb_t /* [ b0 b0 ... b0 b1 b1 ... b1 b2 b2 ... b2 b3 b3 ... b3 ] */
wb_expand_quad( uchar b0, uchar b1, uchar b2, uchar b3 ) {
  return _mm256_setr_epi8( (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b0),
                           (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1), (char)(b1),
                           (char)(b2), (char)(b2), (char)(b2), (char)(b2), (char)(b2), (char)(b2), (char)(b2), (char)(b2),
                           (char)(b3), (char)(b3), (char)(b3), (char)(b3), (char)(b3), (char)(b3), (char)(b3), (char)(b3) );
}

static inline wb_t /* [ b0 b0 b0 b0 b1 b1 b1 b1 ... b7 b7 b7 b7 ] */
wb_expand_oct( uchar b0, uchar b1, uchar b2, uchar b3, uchar b4, uchar b5, uchar b6, uchar b7 ) {
  return _mm256_setr_epi8( (char)(b0), (char)(b0), (char)(b0), (char)(b0), (char)(b1), (char)(b1), (char)(b1), (char)(b1),
                           (char)(b2), (char)(b2), (char)(b2), (char)(b2), (char)(b3), (char)(b3), (char)(b3), (char)(b3),
                           (char)(b4), (char)(b4), (char)(b4), (char)(b4), (char)(b5), (char)(b5), (char)(b5), (char)(b5),
                           (char)(b6), (char)(b6), (char)(b6), (char)(b6), (char)(b7), (char)(b7), (char)(b7), (char)(b7) );
}

static inline wb_t /* [ b0 b0 b1 b1 ... b15 b15 ] */
wb_expand_hex( uchar b0, uchar b1, uchar  b2, uchar  b3, uchar  b4, uchar  b5, uchar  b6, uchar b7,
               uchar b8, uchar b9, uchar b10, uchar b11, uchar b12, uchar b13, uchar b14, uchar b15 ) {
  return _mm256_setr_epi8( (char)( b0), (char)( b0), (char)( b1), (char)( b1), (char)( b2), (char)( b2), (char)( b3), (char)( b3),
                           (char)( b4), (char)( b4), (char)( b5), (char)( b5), (char)( b6), (char)( b6), (char)( b7), (char)( b7),
                           (char)( b8), (char)( b8), (char)( b9), (char)( b9), (char)(b10), (char)(b10), (char)(b11), (char)(b11),
                           (char)(b12), (char)(b12), (char)(b13), (char)(b13), (char)(b14), (char)(b14), (char)(b15), (char)(b15) );
}

/* No general wb_permute due to cross-128-bit lane limitations in AVX.
   Useful cases are provided below.  Given [ b0 b1 ... b31 ], return ...  */

#define wb_exch_adj(x)      /* [ b1 b0 b3 b2 ... b31 b30 ] */ \
  _mm256_shuffle_epi8( (x), wb( 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, \
                                1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14 ) )

#define wb_exch_adj_pair(x) /* [ b2 b3 b0 b1 .. b30 b31 b28 b29 ] */ \
  _mm256_shuffle_epi8( (x), wb( 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, \
                                2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13 ) )

#define wb_exch_adj_quad(x) /* [ b4 b5 b6 b7 b0 b1 b2 b3 .. b28 b29 b30 b31 ] */      \
  _mm256_shuffle_epi8( (x), wb( 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11, \
                                4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11 ) )

#define wb_exch_adj_oct(x)  /* [ b8 b9 ... b15 b0 b1 ... b7 b24 b25 ... b31 b16 b17 ... b23 ] */ \
  _mm256_shuffle_epi8( (x), wb( 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7,            \
                                8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7 ) )

static inline wb_t          /* [ b16 b17 ... b31 b0 b1 ... b15 ] */
wb_exch_adj_hex( wb_t x ) {
  return _mm256_permute2f128_si256( x, x, 1 );
}

#define wb_bcast_even(x)    /* [ b0 b0 b2 b2 ... b30 b30 ] */                            \
  _mm256_shuffle_epi8( (x), wb( 0, 0, 2, 2, 4, 4, 6, 6, 8, 8, 10, 10, 12, 12, 14, 14,    \
                                0, 0, 2, 2, 4, 4, 6, 6, 8, 8, 10, 10, 12, 12, 14, 14 ) )

#define wb_bcast_odd(x)     /* [ b1 b1 b3 b3 ... b31 b31 ] */                            \
  _mm256_shuffle_epi8( (x), wb( 1, 1, 3, 3, 5, 5, 7, 7, 9, 9, 11, 11, 13, 13, 15, 15,    \
                                1, 1, 3, 3, 5, 5, 7, 7, 9, 9, 11, 11, 13, 13, 15, 15 ) )

/* Predefined constants */

#define wb_zero() _mm256_setzero_si256() /* Return [ 0 0 ... 0 ] */
#define wb_one()  _mm256_set1_epi8( 1 )  /* Return [ 1 1 ... 1 ] */

/* Memory operations */

/* wb_ld return the 32 uchars at the 32-byte aligned / 32-byte sized
   location p as a vector uchar.  wb_ldu is the same but p does not have
   to be aligned.  wb_st writes the vector uchar to the 32-byte aligned /
   32-byte sized location p as 32 uchars.  wb_stu is the same but p does not
   have to be aligned.  In all these lane l will be at p[l].  FIXME: USE
   ATTRIBUTES ON P PASSED TO THESE?

   Note: gcc knows a __m256i may alias. */

static inline wb_t wb_ld( uchar const * p ) { return _mm256_load_si256(  (__m256i const *)p ); }
static inline void wb_st( uchar * p, wb_t i ) { _mm256_store_si256(  (__m256i *)p, i ); }

static inline wb_t wb_ldu( void const * p ) { return _mm256_loadu_si256( (__m256i const *)p ); }
static inline void wb_stu( void * p, wb_t i ) { _mm256_storeu_si256( (__m256i *)p, i ); }

/* Sadly, no maskload_epi8, so we can't provide a wb_ldif or wb_stif.
   TODO: consider emulating this? */

/* Element operations */

/* wb_extract extracts the uchar in lane imm from the vector uchar.
   wb_insert returns the vector uchar formed by replacing the value in
   lane imm of a wb_t with the provided uchar.  imm should be a compile
   time constant in 0:31.  wb_extract_variable and wb_insert_variable
   are the slower but the lane n does not have to be known at compile
   time (should still be in 0:31).

   Note: C99 TC3 allows type punning through a union. */

#define wb_extract(a,imm)  ((uchar)_mm256_extract_epi8( (a), (imm) ))
#define wb_insert(a,imm,v) _mm256_insert_epi8( (a), (char)(v), (imm) )

static inline uchar
wb_extract_variable( wb_t a, int n ) {
  union { __m256i m[1]; uchar i[32]; } t[1];
  _mm256_store_si256( t->m, a );
  return t->i[n];
}

static inline wb_t
wb_insert_variable( wb_t a, int n, uchar v ) {
  union { __m256i m[1]; uchar i[32]; } t[1];
  _mm256_store_si256( t->m, a );
  t->i[n] = v;
  return _mm256_load_si256( t->m );
}

/* Given [a0 a1 ... a31] and/or [b0 b1 ... b31], return ... */

/* Arithmetic operations */

#define wb_neg(a) _mm256_sub_epi8( _mm256_setzero_si256(), (a) ) /* [ -a0  -a1  ... -a31  ] (twos complement handling) */
#define wb_abs(a) (a)                                            /* [ |a0| |a1| ... |a31| ] (unsigned type, so identity) */

#define wb_min(a,b) _mm256_min_epu8( (a), (b) ) /* [ min(a0,b0) min(a1,b1) ... min(a31,b31) ] */
#define wb_max(a,b) _mm256_max_epu8( (a), (b) ) /* [ max(a0,b0) max(a1,b1) ... max(a31,b31) ] */
#define wb_add(a,b) _mm256_add_epi8( (a), (b) ) /* [ a0 +b0     a1 +b1     ... a31 +b31     ] */
#define wb_sub(a,b) _mm256_sub_epi8( (a), (b) ) /* [ a0 -b0     a1 -b1     ... a31 -b31     ] */

/* No wb_mul because there's no instruction for multiplying uchars.  You
   can build one with two invocations to _mm_mullo_epi16, but it won't
   be particularly fast.  Multiplication by add and shift might be
   faster honestly.  TODO: consider emulating for completeness? */

/* Bit operations */

/* Note: wb_shl/wb_shr is an unsigned left/right shift by imm bits; imm
   must be a compile time constant in 0:7.  The variable variants are
   slower but do not require the shift amount to be known at compile
   time (should still be in 0:7).

   vector shift amount variants are omitted for the time being as these
   are rarely needed and there seems to be little support for it.
   Probably could be done via two 16-wide vector shifts for the even/odd
   lanes and some masking tricks. */

#define wb_not(a) _mm256_xor_si256( _mm256_set1_epi32( -1 ), (a) ) /* [ ~a0 ~a1 ... ~a31 ] */

#define wb_shl(a,imm) wb_and( _mm256_slli_epi16( (a), (imm) ), wb_bcast( (uchar)(0xFFUL << (imm)) ) ) /* [ a0<<imm a1<<imm ... a31<<imm ] */
#define wb_shr(a,imm) wb_and( _mm256_srli_epi16( (a), (imm) ), wb_bcast( (uchar)(0xFFUL >> (imm)) ) ) /* [ a0>>imm a1>>imm ... a31>>imm ] */

#define wb_shl_variable(a,n) wb_and( _mm256_sll_epi16( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) ), \
                                     wb_bcast( (uchar)(0xFFUL << (n)) ) )
#define wb_shr_variable(a,n) wb_and( _mm256_srl_epi16( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) ), \
                                     wb_bcast( (uchar)(0xFFUL >> (n)) ) )

#define wb_and(a,b)    _mm256_and_si256(    (a), (b) ) /* [   a0 &b0    a1& b1 ...   a31& b31 ] */
#define wb_andnot(a,b) _mm256_andnot_si256( (a), (b) ) /* [ (~a0)&b0  (~a1)&b1 ... (~a31)&b31 ] */
#define wb_or(a,b)     _mm256_or_si256(     (a), (b) ) /* [   a0 |b0    a1 |b1 ...   a31 |b31 ] */
#define wb_xor(a,b)    _mm256_xor_si256(    (a), (b) ) /* [   a0 ^b0    a1 ^b1 ...   a31 ^b31 ] */

static inline wb_t wb_rol( wb_t a, int imm ) { return wb_or( wb_shl( a, imm & 7 ), wb_shr( a, (-imm) & 7 ) ); }
static inline wb_t wb_ror( wb_t a, int imm ) { return wb_or( wb_shr( a, imm & 7 ), wb_shl( a, (-imm) & 7 ) ); }

static inline wb_t wb_rol_variable( wb_t a, int n ) { return wb_or( wb_shl_variable( a, n&7 ), wb_shr_variable( a, (-n)&7 ) ); }
static inline wb_t wb_ror_variable( wb_t a, int n ) { return wb_or( wb_shr_variable( a, n&7 ), wb_shl_variable( a, (-n)&7 ) ); }

/* Logical operations */

#define wb_lnot(a)    _mm256_cmpeq_epi8( (a), _mm256_setzero_si256() ) /* [  !a0  !a1 ...  !a31 ] */
#define wb_lnotnot(a)                                                  /* [ !!a0 !!a1 ... !!a31 ] */ \
  _mm256_xor_si256( _mm256_set1_epi32( -1 ), wb_lnot( (a) ) )

#define wb_eq(a,b) _mm256_cmpeq_epi8( (a), (b) )                                              /* [ a0==b0 a1==b1 ... a31==b31 ] */
#define wb_gt(a,b)                                                                            /* [ a0> b0 a1> b1 ... a31> b31 ] */\
  _mm256_cmpgt_epi8( _mm256_sub_epi8( (a), _mm256_set1_epi8( (char)(1U<<7) ) ),                                                   \
                     _mm256_sub_epi8( (b), _mm256_set1_epi8( (char)(1U<<7) ) ) )
#define wb_lt(a,b) wb_gt( (b), (a) )                                                          /* [ a0< b0 a1< b1 ... a31< b31 ] */
#define wb_ne(a,b) _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_cmpeq_epi8( (a), (b) ) ) /* [ a0!=b0 a1!=b1 ... a31!=b31 ] */
#define wb_ge(a,b) _mm256_xor_si256( _mm256_set1_epi32( -1 ), wb_gt( (b), (a) ) )             /* [ a0>=b0 a1>=b1 ... a31>=b31 ] */
#define wb_le(a,b) _mm256_xor_si256( _mm256_set1_epi32( -1 ), wb_gt( (a), (b) ) )             /* [ a0<=b0 a1<=b1 ... a31<=b31 ] */

/* Conditional operations */

#define wb_czero(c,f)    _mm256_andnot_si256( (c), (f) ) /* [ c0? 0:f0 c1? 0:f1 ... c31? 0:f31 ] */
#define wb_notczero(c,f) _mm256_and_si256(    (c), (f) ) /* [ c0?f0: 0 c1?f1: 0 ... c31?f31: 0 ] */

#define wb_if(c,t,f) _mm256_blendv_epi8( (f), (t), (c) ) /* [ c0?t0:f0 c1?t1:f1 ... c31?t31:f31 ] */

/* Conversion operations */

/* Summarizing:

   wb_to_wc(a, 0)   returns [ !!a0  !!a1  ... !!a7  ]
   wb_to_wc(a, 1)   returns [ !!a8  !!a9  ... !!a15 ]
   wb_to_wc(a, 2)   returns [ !!a16 !!a17 ... !!a23 ]
   wb_to_wc(a, 3)   returns [ !!a24 !!a25 ... !!a31 ]
   // TODO: wc varints for 8, 16, and 64 wide SIMD conditionals

   wb_to_wf(a, 0)   returns [ (float)a0  (float)a1  ... (float)a7  ]
   wb_to_wf(a, 1)   returns [ (float)a8  (float)a9  ... (float)a15 ]
   wb_to_wf(a, 2)   returns [ (float)a16 (float)a17 ... (float)a23 ]
   wb_to_wf(a, 3)   returns [ (float)a24 (float)a25 ... (float)a31 ]

   wb_to_wi(a, 0)   returns [ (int)a0  (int)a1  ... (int)a7  ]
   wb_to_wi(a, 1)   returns [ (int)a8  (int)a9  ... (int)a15 ]
   wb_to_wi(a, 2)   returns [ (int)a16 (int)a17 ... (int)a23 ]
   wb_to_wi(a, 3)   returns [ (int)a24 (int)a25 ... (int)a31 ]

   wb_to_wu(a, 0)   returns [ (uint)a0  (uint)a1  ... (uint)a7  ]
   wb_to_wu(a, 1)   returns [ (uint)a8  (uint)a9  ... (uint)a15 ]
   wb_to_wu(a, 2)   returns [ (uint)a16 (uint)a17 ... (uint)a23 ]
   wb_to_wu(a, 3)   returns [ (uint)a24 (uint)a25 ... (uint)a31 ]

   wb_to_wd(a,0) returns [ (double)a0  (double)a1  (double)a2  (double)a3  ]
   wb_to_wd(a,1) returns [ (double)a4  (double)a5  (double)a6  (double)a7  ]
   ...
   wb_to_wd(a,7) returns [ (double)a28 (double)a29 (double)a30 (double)a31 ]

   wb_to_wl(a,0) returns [ (long)a0  (long)a1  (long)a2  (long)a3  ]
   wb_to_wl(a,1) returns [ (long)a4  (long)a5  (long)a6  (long)a7  ]
   ...
   wb_to_wl(a,7) returns [ (long)a28 (long)a29 (long)a30 (long)a31 ]

   wb_to_wv(a,0) returns [ (ulong)a0  (ulong)a1  (ulong)a2  (ulong)a3  ]
   wb_to_wv(a,1) returns [ (ulong)a4  (ulong)a5  (ulong)a6  (ulong)a7  ]
   ...
   wb_to_wv(a,7) returns [ (ulong)a28 (ulong)a29 (ulong)a30 (ulong)a31 ]

   where the above values should be compile time constants. */

/* wb_expand_internal_{4, 8} selects the right group of {4,8} x 32 bits
   (zero extending it) */

static inline __m256i
wb_expand_internal_8( wb_t a, int imm ) {
  switch( imm ) {
  case 0: return _mm256_cvtepu8_epi32( _mm256_extractf128_si256( a, 0 ) );
  case 1: return _mm256_cvtepu8_epi32( _mm_bsrli_si128( _mm256_extractf128_si256( a, 0 ), 8 ) );
  case 2: return _mm256_cvtepu8_epi32( _mm256_extractf128_si256( a, 1 ) );
  case 3: return _mm256_cvtepu8_epi32( _mm_bsrli_si128( _mm256_extractf128_si256( a, 1 ), 8 ) );
  }
  return _mm256_setzero_si256(); /* Unreachable */
}

static inline __m128i
wb_expand_internal_4( wb_t a, int imm ) {
  switch( imm ) {
  case 0: return _mm_cvtepu8_epi32( _mm256_extractf128_si256( a, 0 ) );
  case 1: return _mm_cvtepu8_epi32( _mm_bsrli_si128( _mm256_extractf128_si256( a, 0 ),  4 ) );
  case 2: return _mm_cvtepu8_epi32( _mm_bsrli_si128( _mm256_extractf128_si256( a, 0 ),  8 ) );
  case 3: return _mm_cvtepu8_epi32( _mm_bsrli_si128( _mm256_extractf128_si256( a, 0 ), 12 ) );
  case 4: return _mm_cvtepu8_epi32( _mm256_extractf128_si256( a, 1 ) );
  case 5: return _mm_cvtepu8_epi32( _mm_bsrli_si128( _mm256_extractf128_si256( a, 1 ),  4 ) );
  case 6: return _mm_cvtepu8_epi32( _mm_bsrli_si128( _mm256_extractf128_si256( a, 1 ),  8 ) );
  case 7: return _mm_cvtepu8_epi32( _mm_bsrli_si128( _mm256_extractf128_si256( a, 1 ), 12 ) );
  }
  return _mm_setzero_si128(); /* Unreachable */
}

#define wb_to_wc( a, imm ) _mm256_xor_si256( _mm256_set1_epi32( -1 ), _mm256_cmpeq_epi32( wb_expand_internal_8( (a), (imm) ), _mm256_setzero_si256() ) )
#define wb_to_wf( a, imm ) _mm256_cvtepi32_ps( wb_expand_internal_8( (a), (imm) ) )
#define wb_to_wi( a, imm ) wb_expand_internal_8( (a), (imm) )
#define wb_to_wu( a, imm ) wb_expand_internal_8( (a), (imm) )
#define wb_to_wd( a, imm ) _mm256_cvtepi32_pd   ( wb_expand_internal_4( (a), (imm) ) )
#define wb_to_wl( a, imm ) _mm256_cvtepu32_epi64( wb_expand_internal_4( (a), (imm) ) ) /* This could be slightly faster with _mm256_cvtepu8_epi64 */
#define wb_to_wv( a, imm ) _mm256_cvtepu32_epi64( wb_expand_internal_4( (a), (imm) ) ) /* This could be slightly faster with _mm256_cvtepu8_epi64 */

#define wb_to_wc_raw(a) (a)
#define wb_to_wf_raw(a) _mm256_castsi256_ps( (a) )
#define wb_to_wi_raw(a) (a)
#define wb_to_wu_raw(a) (a)
#define wb_to_wd_raw(a) _mm256_castsi256_pd( (a) )
#define wb_to_wv_raw(a) (a)
#define wb_to_wl_raw(a) (a)

/* Reduction operations */

static inline wb_t
wb_sum_all( wb_t x ) { /* Returns wb_bcast( sum( x ) ) */
  x = _mm256_sad_epu8( x, _mm256_setzero_si256() );                /* x[0-7]       x[8-15]       x[16-23]      x[24-31]      (each stored in 64 bits) */
  x = _mm256_add_epi64( x, _mm256_permute2f128_si256( x, x, 1 ) ); /* x[0-7,16-23] x[8-15,24-31] x[0-7,16-23]  x[8-15,24-31] (each stored in 64 bits) */
  return _mm256_add_epi8( _mm256_shuffle_epi8( x, wb_bcast( 0 ) ) , _mm256_shuffle_epi8( x, wb_bcast( 8 ) ) ); /* Grab the low byte of each sum, broadcast it, then sum */
}

static inline wb_t
wb_min_all( wb_t x ) { /* Returns wb_bcast( min( x ) ) */
  x = _mm256_min_epu8( x, _mm256_permute2f128_si256( x, x, 1 ) );    /* x0,16    x1,17  .. x15,31 x0,16  x1,17  ... x15,31 */
  x = _mm256_min_epu8( x, _mm256_shuffle_epi8( x, wb( 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7,
                                                      8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7 ) ) );    /* x0,8,16,24    x1,9,17,25  .. x7,15,23,31  (repeats 3 more times) */
  x = _mm256_min_epu8( x, _mm256_shuffle_epi8( x, wb( 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3,
                                                      4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3 ) ) );          /* x0,4,8,12,16,20,24,28  .. x3,7,11,15,19,23,27,31 (repeats 7 more times)*/
  x = _mm256_min_epu8( x, _mm256_shuffle_epi8( x, wb_bcast_quad( 2, 3, 0, 1 ) ) );
  x = _mm256_min_epu8( x, _mm256_shuffle_epi8( x, wb_bcast_pair( 1, 0 ) ) );
  return x;
}

static inline wb_t
wb_max_all( wb_t x ) { /* Returns wb_bcast( max( x ) ) */
  x = _mm256_max_epu8( x, _mm256_permute2f128_si256( x, x, 1 ) );    /* x0,16    x1,17  .. x15,31 x0,16  x1,17  ... x15,31 */
  x = _mm256_max_epu8( x, _mm256_shuffle_epi8( x, wb( 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7,
                                                      8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7 ) ) );    /* x0,8,16,24    x1,9,17,25  .. x7,15,23,31  (repeats 3 more times) */
  x = _mm256_max_epu8( x, _mm256_shuffle_epi8( x, wb( 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3,
                                                      4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3 ) ) );          /* x0,4,8,12,16,20,24,28  .. x3,7,11,15,19,23,27,31 (repeats 7 more times)*/
  x = _mm256_max_epu8( x, _mm256_shuffle_epi8( x, wb_bcast_quad( 2, 3, 0, 1 ) ) );
  x = _mm256_max_epu8( x, _mm256_shuffle_epi8( x, wb_bcast_pair( 1, 0 ) ) );
  return x;
}

/* Misc operations */

/* TODO: These probably are actually part of the wc post generalization
   to different width SIMD types. */

/* wb_{any, all} return 1 if any/all of the elements are non-zero.  The
   _fast variants are suitable for use with the return value of any of
   the wb comparison functions (e.g. wb_gt ). */

#define wb_any_fast( x ) ( 0 != _mm256_movemask_epi8( x ) )
#define wb_any( x ) wb_any_fast( wb_ne( (x), wb_zero( ) ) )
#define wb_all_fast( x ) ( -1 == _mm256_movemask_epi8( x ) )
#define wb_all( x ) wb_all_fast( wb_ne( (x), wb_zero( ) ) )
