#ifndef HEADER_fd_src_util_simd_fd_avx512_h
#error "Do not include this directly; use fd_avx512.h"
#endif

/* Vector byte API *****************************************************/

/* A wwb_t is a vector where each 8-bit wide lane holds an unsigned
   8-bit integer (a "uchar").

   These mirror the other APIs as much as possible.  Macros are
   preferred over static inlines when it is possible to do it robustly
   to reduce the risk of the compiler mucking it up. */

#define wwb_t __m512i

/* Constructors */

/* Given the uchar values, return ... */

#define wwb(b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10,b11,b12,b13,b14,b15,                                                \
            b16,b17,b18,b19,b20,b21,b22,b23,b24,b25,b26,b27,b28,b29,b30,b31,                                                \
            b32,b33,b34,b35,b36,b37,b38,b39,b40,b41,b42,b43,b44,b45,b46,b47,                                                \
            b48,b49,b50,b51,b52,b53,b54,b55,b56,b57,b58,b59,b60,b61,b62,b63) /* [ b0 b1 ... b63 ] */                        \
  _mm512_set_epi8( (char)(b63), (char)(b62), (char)(b61), (char)(b60), (char)(b59), (char)(b58), (char)(b57), (char)(b56), \
                   (char)(b55), (char)(b54), (char)(b53), (char)(b52), (char)(b51), (char)(b50), (char)(b49), (char)(b48), \
                   (char)(b47), (char)(b46), (char)(b45), (char)(b44), (char)(b43), (char)(b42), (char)(b41), (char)(b40), \
                   (char)(b39), (char)(b38), (char)(b37), (char)(b36), (char)(b35), (char)(b34), (char)(b33), (char)(b32), \
                   (char)(b31), (char)(b30), (char)(b29), (char)(b28), (char)(b27), (char)(b26), (char)(b25), (char)(b24), \
                   (char)(b23), (char)(b22), (char)(b21), (char)(b20), (char)(b19), (char)(b18), (char)(b17), (char)(b16), \
                   (char)(b15), (char)(b14), (char)(b13), (char)(b12), (char)(b11), (char)(b10), (char)( b9), (char)( b8), \
                   (char)( b7), (char)( b6), (char)( b5), (char)( b4), (char)( b3), (char)( b2), (char)( b1), (char)( b0) )

#define wwb_bcast(b0) _mm512_set1_epi8( (char)(b0) ) /* [ b0 b0 ... b0 ] */

static inline wwb_t /* [ b0 b1 b0 b1 ... b0 b1 ] */
wwb_bcast_pair( uchar b0, uchar b1 ) {
  return _mm512_set_epi8( (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0),
                          (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0),
                          (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0),
                          (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0),
                          (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0),
                          (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0),
                          (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0),
                          (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0), (char)(b1), (char)(b0) );
}

static inline wwb_t /* [ b0 b1 b2 b3 b0 b1 b2 b3 ... b0 b1 b2 b3 ] */
wwb_bcast_quad( uchar b0, uchar b1, uchar b2, uchar b3 ) {
  return _mm512_set_epi8( (char)(b3), (char)(b2), (char)(b1), (char)(b0), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b3), (char)(b2), (char)(b1), (char)(b0), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b3), (char)(b2), (char)(b1), (char)(b0), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b3), (char)(b2), (char)(b1), (char)(b0), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b3), (char)(b2), (char)(b1), (char)(b0), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b3), (char)(b2), (char)(b1), (char)(b0), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b3), (char)(b2), (char)(b1), (char)(b0), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b3), (char)(b2), (char)(b1), (char)(b0), (char)(b3), (char)(b2), (char)(b1), (char)(b0) );
}

static inline wwb_t /* [ b0 b1 ... b7 b0 b1 ... b7 b0 b1 ... b7 b0 b1 ... b7 ] */
wwb_bcast_oct( uchar b0, uchar b1, uchar b2, uchar b3, uchar b4, uchar b5, uchar b6, uchar b7 ) {
  return _mm512_set_epi8( (char)(b7), (char)(b6), (char)(b5), (char)(b4), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b7), (char)(b6), (char)(b5), (char)(b4), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b7), (char)(b6), (char)(b5), (char)(b4), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b7), (char)(b6), (char)(b5), (char)(b4), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b7), (char)(b6), (char)(b5), (char)(b4), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b7), (char)(b6), (char)(b5), (char)(b4), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b7), (char)(b6), (char)(b5), (char)(b4), (char)(b3), (char)(b2), (char)(b1), (char)(b0),
                          (char)(b7), (char)(b6), (char)(b5), (char)(b4), (char)(b3), (char)(b2), (char)(b1), (char)(b0) );
}

static inline wwb_t /* [ b0 b1 ... b15 b0 b1 ... b15 ] */
wwb_bcast_hex( uchar b0, uchar b1, uchar b2,  uchar b3,  uchar b4,  uchar b5,  uchar b6,  uchar b7,
               uchar b8, uchar b9, uchar b10, uchar b11, uchar b12, uchar b13, uchar b14, uchar b15 ) {
  return _mm512_set_epi8( (char)(b15), (char)(b14), (char)(b13), (char)(b12), (char)(b11), (char)(b10), (char)(b9), (char)(b8),
                          (char)(b7),  (char)(b6),  (char)(b5),  (char)(b4),  (char)(b3),  (char)(b2),  (char)(b1), (char)(b0),
                          (char)(b15), (char)(b14), (char)(b13), (char)(b12), (char)(b11), (char)(b10), (char)(b9), (char)(b8),
                          (char)(b7),  (char)(b6),  (char)(b5),  (char)(b4),  (char)(b3),  (char)(b2),  (char)(b1), (char)(b0),
                          (char)(b15), (char)(b14), (char)(b13), (char)(b12), (char)(b11), (char)(b10), (char)(b9), (char)(b8),
                          (char)(b7),  (char)(b6),  (char)(b5),  (char)(b4),  (char)(b3),  (char)(b2),  (char)(b1), (char)(b0),
                          (char)(b15), (char)(b14), (char)(b13), (char)(b12), (char)(b11), (char)(b10), (char)(b9), (char)(b8),
                          (char)(b7),  (char)(b6),  (char)(b5),  (char)(b4),  (char)(b3),  (char)(b2),  (char)(b1), (char)(b0) );
}


#define wwb_exch_adj(x)      /* [ b1 b0 b3 b2 ... b63 b62 ] */ \
  _mm512_shuffle_epi8( (x), wwb_bcast_hex( 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14 ) )

#define wwb_exch_adj_pair(x) /* [ b2 b3 b0 b1 .. b62 b63 b60 b61 ] */ \
  _mm512_shuffle_epi8( (x), wwb_bcast_hex( 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13 ) )

/* Predefined constants */

#define wwb_zero() _mm512_setzero_si512() /* Return [ 0 0 ... 0 ] */
#define wwb_one()  _mm512_set1_epi8( 1 )  /* Return [ 1 1 ... 1 ] */

/* Bit operations */

#define wwb_not(a) _mm512_xor_si512( _mm512_set1_epi32( -1 ), (a) ) /* [ ~a0 ~a1 ... ~a63 ] */

#define wwb_shl(a,imm) wwb_and( _mm512_slli_epi16( (a), (imm) ), wwb_bcast( (uchar)(0xFFUL << (imm)) ) ) /* [ a0<<imm a1<<imm ... a63<<imm ] */
#define wwb_shr(a,imm) wwb_and( _mm512_srli_epi16( (a), (imm) ), wwb_bcast( (uchar)(0xFFUL >> (imm)) ) ) /* [ a0>>imm a1>>imm ... a63>>imm ] */

#define wwb_and(a,b)    _mm512_and_si512(    (a), (b) ) /* [   a0 &b0    a1& b1 ...   a63& b63 ] */
#define wwb_andnot(a,b) _mm512_andnot_si512( (a), (b) ) /* [ (~a0)&b0  (~a1)&b1 ... (~a63)&b63 ] */
#define wwb_or(a,b)     _mm512_or_si512(     (a), (b) ) /* [   a0 |b0    a1 |b1 ...   a63 |b63 ] */
#define wwb_xor(a,b)    _mm512_xor_si512(    (a), (b) ) /* [   a0 ^b0    a1 ^b1 ...   a63 ^b63 ] */

/* Memory operations */

/* wwb_ld returns the 64 uchars at the 64-byte aligned / 64-byte sized
   location p as a vector uchar.  wwb_ldu is the same but p does not
   have to be aligned.  wwb_st writes the vector uchar to the 64-byte
   aligned / 64-byte sized location p as 64 uchars.  wwb_stu is the same
   but p does not have to be aligned.  In all these lane l will be at
   p[l].  FIXME: USE ATTRIBUTES ON P PASSED TO THESE?

   Note: gcc knows a __m512i may alias. */

static inline wwb_t wwb_ld( uchar const * p ) { return _mm512_load_si512( (__m512i const *)p ); }
static inline void  wwb_st( uchar * p, wwb_t i ) { _mm512_store_si512( (__m512i *)p, i ); }

static inline wwb_t wwb_ldu( uchar const * p ) { return _mm512_loadu_si512( (__m512i const *)p ); }
static inline void  wwb_stu( uchar * p, wwb_t i ) { _mm512_storeu_si512( (__m512i *)p, i ); }
