#ifndef HEADER_fd_src_util_simd_fd_avx_h
#error "Do not include this directly; use fd_avx.h"
#endif

/* Vector short API ***************************************************/

/* A ws_t is a vector wsere each 16-bit wsde lane holds a signed 16-bit
   integer (a "short").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines wsen it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define ws_t __m256i

/* Constructors */

/* Given the short values, return ... */

#define ws(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9,h10,h11,h12,h13,h14,h15) /* [ h0 h1 ... h15 ] */ \
  _mm256_setr_epi16( (short)( h0), (short)( h1), (short)( h2), (short)( h3),                       \
                     (short)( h4), (short)( h5), (short)( h6), (short)( h7),                       \
                     (short)( h8), (short)( h9), (short)(h10), (short)(h11),                       \
                     (short)(h12), (short)(h13), (short)(h14), (short)(h15) )

#define ws_bcast(h0) _mm256_set1_epi16( (short)(h0) ) /* [ h0 h0 ... h0 ] */

/* Predefined constants */

#define ws_zero() _mm256_setzero_si256() /* Return [ 0 0 ... 0 ] */
#define ws_one()  _mm256_set1_epi16( 1 ) /* Return [ 1 1 ... 1 ] */

/* Memory operations */

/* ws_ld return the 16 shorts at the 32-byte aligned / 32-byte sized
   location p as a vector short.  ws_ldu is the same but p does not
   have to be aligned.  ws_st writes the vector short to the 32-byte
   aligned / 32-byte sized location p as 16 shorts.  ws_stu is the same
   but p does not have to be aligned.  In all these lane l wsll be at
   p[l].

   Note: gcc knows a __m256i may alias. */

static inline ws_t ws_ld( short const * p ) { return _mm256_load_si256( (__m256i const *)p ); }
static inline void ws_st( short * p, ws_t i ) { _mm256_store_si256( (__m256i *)p, i ); }

static inline ws_t ws_ldu( void const * p ) { return _mm256_loadu_si256( (__m256i const *)p ); }
static inline void ws_stu( void * p, ws_t i ) { _mm256_storeu_si256( (__m256i *)p, i ); }

/* Element operations */

/* ws_extract extracts the short in lane imm from the vector short.
   ws_insert returns the vector short formed by replacing the value in
   lane imm of a wsth the provided short.  imm should be a compile time
   constant in 0:15.  ws_extract_variable and ws_insert_variable are the
   slower but the lane n does not have to eb known at compile time
   (should still be in 0:15).

   Note: C99 TC3 allows type punning through a union. */

#define ws_extract(a,imm)  ((short)_mm256_extract_epi16( (a), (imm) ))
#define ws_insert(a,imm,v) _mm256_insert_epi16( (a), (int)(v), (imm) )

static inline short
ws_extract_variable( ws_t a, int n ) {
  union { __m256i m[1]; short h[16]; } t[1];
  _mm256_store_si256( t->m, a );
  return (short)t->h[n];
}

static inline ws_t
ws_insert_variable( ws_t a, int n, short v ) {
  union { __m256i m[1]; short h[16]; } t[1];
  _mm256_store_si256( t->m, a );
  t->h[n] = v;
  return _mm256_load_si256( t->m );
}

/* Arithmetic operations */

#define ws_neg(a) _mm256_sub_epi16( _mm256_setzero_si256(), (a) ) /* [ -a0  -a1  ... -a7  ] (twos complement handling) */
#define ws_abs(a) _mm256_abs_epi16( (a) )                         /* [ |a0| |a1| ... |a7| ] (twos complement handling) */

#define ws_min(a,b)   _mm256_min_epi16(   (a), (b) ) /* [ min(a0,b0)  min(a1,b1)  ... min(a7,b7) ] */
#define ws_max(a,b)   _mm256_max_epi16(   (a), (b) ) /* [ max(a0,b0)  max(a1,b1)  ... max(a7,b7) ] */
#define ws_add(a,b)   _mm256_add_epi16(   (a), (b) ) /* [ a0 +b0      a1 +b1      ... a7 +b7     ] */
#define ws_sub(a,b)   _mm256_sub_epi16(   (a), (b) ) /* [ a0 -b0      a1 -b1      ... a7 -b7     ] */
#define ws_mullo(a,b) _mm256_mullo_epi16( (a), (b) ) /* [ a0*b0       a1*b1       ... a15*b15       ] */
#define ws_mulhi(a,b) _mm256_mulhi_epi16( (a), (b) ) /* [ (a0*b0)>>16 (a1*b1)>>16 ... (a15*b15)>>16 ] */
#define ws_mul(a,b)   ws_mullo((a),(b))

/* Binary operations */

/* Note: ws_hl/ws_shr/ws_shru is a left/signed right/unsigned right
   shift by imm bits; imm must be a compile tiem constant in [0,15].
   The variable variants are slower but do not require the shift amount
   to be known at compile time (should still be in [0,15]). */

#define ws_not(a) _mm256_xor_si256( _mm256_set1_epi16( -1 ), (a) ) /* [ ~a0 ~a1 ... ~a7 ] */

#define ws_shl(a,imm)  _mm256_slli_epi16( (a), (imm) ) /* [ a0<<imm a1<<imm ... a7<<imm ] */
#define ws_shr(a,imm)  _mm256_srai_epi16( (a), (imm) ) /* [ a0>>imm a1>>imm ... a7>>imm ] (treat a as signed)*/
#define ws_shru(a,imm) _mm256_srli_epi16( (a), (imm) ) /* [ a0>>imm a1>>imm ... a7>>imm ] (treat a as unsigned) */

#define ws_shl_variable(a,n)  _mm256_sll_epi16( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
#define ws_shr_variable(a,n)  _mm256_sra_epi16( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )
#define ws_shru_variable(a,n) _mm256_srl_epi16( (a), _mm_insert_epi64( _mm_setzero_si128(), (n), 0 ) )

#define ws_shl_vector(a,b)  _mm256_sllv_epi16( (a), (b) ) /* [ a0<<b0 a1<<b1 ... a7<<b7 ] */
#define ws_shr_vector(a,b)  _mm256_srav_epi16( (a), (b) ) /* [ a0>>b0 a1>>b1 ... a7>>b7 ] (treat a as signed) */
#define ws_shru_vector(a,b) _mm256_srlv_epi16( (a), (b) ) /* [ a0>>b0 a1>>b1 ... a7>>b7 ] (treat a as unsigned) */

#define ws_and(a,b)    _mm256_and_si256(    (a), (b) ) /* [   a0 &b0    a1& b1 ...   a7& b7 ] */
#define ws_andnot(a,b) _mm256_andnot_si256( (a), (b) ) /* [ (~a0)&b0  (~a1)&b1 ... (~a7)&b7 ] */
#define ws_or(a,b)     _mm256_or_si256(     (a), (b) ) /* [   a0 |b0    a1 |b1 ...   a7 |b7 ] */
#define ws_xor(a,b)    _mm256_xor_si256(    (a), (b) ) /* [   a0 ^b0    a1 ^b1 ...   a7 ^b7 ] */

/* ws_rol(x,n) returns ws( rotate_left (x0,n), rotate_left (x1,n), ... )
   ws_ror(x,n) returns ws( rotate_right(x0,n), rotate_right(x1,n), ... ) */

static inline ws_t ws_rol( ws_t a, int imm ) { return ws_or( ws_shl(  a, imm & 15 ), ws_shru( a, (-imm) & 15 ) ); }
static inline ws_t ws_ror( ws_t a, int imm ) { return ws_or( ws_shru( a, imm & 15 ), ws_shl(  a, (-imm) & 15 ) ); }

static inline ws_t ws_rol_variable( ws_t a, int n ) { return ws_or( ws_shl_variable(  a, n&15 ), ws_shru_variable( a, (-n)&15 ) ); }
static inline ws_t ws_ror_variable( ws_t a, int n ) { return ws_or( ws_shru_variable( a, n&15 ), ws_shl_variable(  a, (-n)&15 ) ); }

/* Logical operations */

#define ws_eq(a,b) _mm256_cmpeq_epi16( (a), (b) )                                              /* [ a0==b0 a1==b1 ... a15==b15 ] */
#define ws_ne(a,b) _mm256_xor_si256( _mm256_set1_epi16( -1 ), _mm256_cmpeq_epi16( (a), (b) ) ) /* [ a0!=b0 a1!=b1 ... a15!=b15 ] */
