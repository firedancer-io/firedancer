#ifndef HEADER_fd_src_util_simd_fd_avx_h
#error "Do not include this directly; use fd_avx.h"
#endif

/* Vector ushort API **************************************************/

/* A wh_t is a vector where each 16-bit wide lane holds an unsigned
   16-bit integer (a "ushort").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wh_t __m256i

/* Constructors */

/* Given the ushort values, return ... */

#define wh(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9,h10,h11,h12,h13,h14,h15) /* [ h0 h1 ... h15 ] */ \
  _mm256_setr_epi16( (short)( h0), (short)( h1), (short)( h2), (short)( h3),                       \
                     (short)( h4), (short)( h5), (short)( h6), (short)( h7),                       \
                     (short)( h8), (short)( h9), (short)(h10), (short)(h11),                       \
                     (short)(h12), (short)(h13), (short)(h14), (short)(h15) )

#define wh_bcast(h0) _mm256_set1_epi16( (short)(h0) ) /* [ h0 h0 ... h0 ] */

/* Predefined constants */

#define wh_zero() _mm256_setzero_si256() /* Return [ 0 0 ... 0 ] */
#define wh_one()  _mm256_set1_epi16( 1 ) /* Return [ 1 1 ... 1 ] */

/* Memory operations */

/* wh_ld return the 16 ushorts at the 32-byte aligned / 32-byte sized
   location p as a vector ushort.  wh_ldu is the same but p does not
   have to be aligned.  wh_st writes the vector ushort to the 32-byte
   aligned / 32-byte sized location p as 16 ushorts.  wh_stu is the same
   but p does not have to be aligned.  In all these lane l will be at
   p[l].

   Note: gcc knows a __m256i may alias. */

static inline wh_t wh_ld( ushort const * p ) { return _mm256_load_si256( (__m256i const *)p ); }
static inline void wh_st( ushort * p, wh_t i ) { _mm256_store_si256( (__m256i *)p, i ); }

static inline wh_t wh_ldu( void const * p ) { return _mm256_loadu_si256( (__m256i const *)p ); }
static inline void wh_stu( void * p, wh_t i ) { _mm256_storeu_si256( (__m256i *)p, i ); }

/* Element operations */

/* wh_extract extracts the ushort in lane imm from the vector ushort.
   wh_insert returns the vector ushort formed by replacing the value in
   lane imm of a with the provided ushort.  imm should be a compile time
   constant in 0:15.  wh_extract_variable and wh_insert_variable are the
   slower but the lane n does not have to eb known at compile time
   (should still be in 0:15).

   Note: C99 TC3 allows type punning through a union. */

#define wh_extract(a,imm)  ((ushort)_mm256_extract_epi16( (a), (imm) ))
#define wh_insert(a,imm,v) _mm256_insert_epi16( (a), (int)(v), (imm) )

static inline ushort
wh_extract_variable( wh_t a, int n ) {
  union { __m256i m[1]; ushort h[16]; } t[1];
  _mm256_store_si256( t->m, a );
  return (ushort)t->h[n];
}

static inline wh_t
wh_insert_variable( wh_t a, int n, ushort v ) {
  union { __m256i m[1]; ushort h[16]; } t[1];
  _mm256_store_si256( t->m, a );
  t->h[n] = v;
  return _mm256_load_si256( t->m );
}

/* Arithmetic operations */

#define wh_neg(a) _mm256_sub_epi16( _mm256_setzero_si256(), (a) ) /* [ -a0  -a1  ... -a15]   (twos complement handling) */
#define wh_abs(a) (a)                                             /* [ |a0| |a1| ... |a15| ] (twos complement handling) */

#define wh_min(a,b)   _mm256_min_epu16(   (a), (b) ) /* [ min(a0,b0)  min(a1,b1)  ... min(a15,a15)  ] */
#define wh_max(a,b)   _mm256_max_epu16(   (a), (b) ) /* [ max(a0,b0)  max(a1,b1)  ... max(a15,a15)  ] */
#define wh_add(a,b)   _mm256_add_epi16(   (a), (b) ) /* [ a0+b0       a1+b1       ... a15+b15       ] */
#define wh_sub(a,b)   _mm256_sub_epi16(   (a), (b) ) /* [ a0-b0       a1-b1       ... a15-b15       ] */
#define wh_mullo(a,b) _mm256_mullo_epi16( (a), (b) ) /* [ a0*b0       a1*b1       ... a15*b15       ] */
#define wh_mulhi(a,b) _mm256_mulhi_epu16( (a), (b) ) /* [ (a0*b0)>>16 (a1*b1)>>16 ... (a15*b15)>>16 ] */
#define wh_mul(a,b)   wh_mullo((a),(b))

/* Binary operations */

/* Note: wh_shl/wh_shr is an unsigned left/right shift by imm bits; imm
   must be a compile time constant in [0,15].  The variable variants are
   slower but do not require the shift amount to be known at compile
   time (should still be in [0,15]). */

#define wh_not(a) _mm256_xor_si256( _mm256_set1_epi16( -1 ), (a) ) /* [ ~a0 ~a1 ... ~a15 ] */

#define wh_shl(a,imm)  _mm256_slli_epi16( (a), (imm) ) /* [ a0<<imm a1<<imm ... a15<<imm ] */
#define wh_shr(a,imm)  _mm256_srli_epi16( (a), (imm) ) /* [ a0>>imm a1>>imm ... a15>>imm ] */

#define wh_shl_variable(a,n) _mm256_sll_epi16( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
#define wh_shr_variable(a,n) _mm256_srl_epi16( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )

#define wh_shl_vector(a,b)   _mm256_sllv_epi16( (a), (b) ) /* [ a0<<b0 a1<<b1 ... a15<<b15 ] */
#define wh_shr_vector(a,b)   _mm256_srlv_epi16( (a), (b) ) /* [ a0>>b0 a1>>b1 ... a15>>b15 ] */

#define wh_and(a,b)    _mm256_and_si256(    (a), (b) ) /* [   a0 &b0    a1& b1 ...   a15& b15 ] */
#define wh_andnot(a,b) _mm256_andnot_si256( (a), (b) ) /* [ (~a0)&b0  (~a1)&b1 ... (~a15)&b15 ] */
#define wh_or(a,b)     _mm256_or_si256(     (a), (b) ) /* [   a0 |b0    a1 |b1 ...   a15 |b15 ] */
#define wh_xor(a,b)    _mm256_xor_si256(    (a), (b) ) /* [   a0 ^b0    a1 ^b1 ...   a15 ^b15 ] */

/* wh_rol(x,n) returns wh( rotate_left (x0,n), rotate_left (x1,n), ... )
   wh_ror(x,n) returns wh( rotate_right(x0,n), rotate_right(x1,n), ... ) */

static inline wh_t wh_rol( wh_t a, int imm ) { return wh_or( wh_shl( a, imm & 15 ), wh_shr( a, (-imm) & 15 ) ); }
static inline wh_t wh_ror( wh_t a, int imm ) { return wh_or( wh_shr( a, imm & 15 ), wh_shl( a, (-imm) & 15 ) ); }

static inline wh_t wh_rol_variable( wh_t a, int n ) { return wh_or( wh_shl_variable( a, n&15 ), wh_shr_variable( a, (-n)&15 ) ); }
static inline wh_t wh_ror_variable( wh_t a, int n ) { return wh_or( wh_shr_variable( a, n&15 ), wh_shl_variable( a, (-n)&15 ) ); }

/* Logical operations */

#define wh_eq(a,b) _mm256_cmpeq_epi16( (a), (b) )                                              /* [ a0==b0 a1==b1 ... a15==b15 ] */
#define wh_ne(a,b) _mm256_xor_si256( _mm256_set1_epi16( -1 ), _mm256_cmpeq_epi16( (a), (b) ) ) /* [ a0!=b0 a1!=b1 ... a15!=b15 ] */
