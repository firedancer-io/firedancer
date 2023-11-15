#include "fd_reedsol_private.h"

/* TODO: Move this high-level overview

   The main Lin, et al. paper proposes a clever method for dealing with
   erasures.  Suppose there is a polynomial P(x) of degree <k, and we
   know it's value at k inputs, but not necessarily at inputs 0, 1, ...
   k-1.  We construct a polynomial Pi(x) (that's the uppercase Greek
   letter, not shorthand for P_i) with zeros at the erasures, i.e.  at
   the x in [0, n) for which we don't know P(x).  We don't care what the
   value of Pi(x) is at the non-erasures other than that we know the
   value.  This means we know the value of the product P(x)Pi(x) for
   each x in [0, n).  Additionally, since the order of Pi(x) is n-k, the
   order of P(x)Pi(x) is <n.  Now we're back in the regime of
   Reed-Solomon encoding: we know the first n values of a polynomial of
   order <n, so we can use the FFT and IFFT operators to evaluate this
   polynomial computationally efficiently wherever we please.

   However, we don't actually care about the value of P(x)Pi(x); we want
   the value of P(x).  To accomplish this, we take the formal derivative
   ("formal" in the sense that these are polynomials over a finite field
   not real numbers, but we ignore that for a minute):
        (P(x)Pi(x))' = P'(x)Pi(x) + P(x)Pi'(x).
   At erasures, Pi(x) = 0 by construction, so
        P(x) = (P(x)Pi(x))' / Pi'(x)

   Now then, all we need is a fast way to compute the value of the
   formal derivative at some points given its value at 0, 1, ..., n-1.
   It turns out, the special basis we use for the rest of the
   Reed-Solomon computation gives us a computationally efficient way to
   compute formal derivatives.

   Thus, the overall algorithm is this:
     1. Compute the value of P(x)Pi(x) at x in [0, n)
     2. Use the IFFT to represent the polynomial in the coefficient basis.
     3. Take the formal derivative in the coefficient basis.
     4. Use the FFT to compute the value of (P(x)Pi(x))' for x in [0, n).
     5. Compute Pi'(x) directly.
     6. Divide the results of step 4 and 5.

   That's roughly the approach this implementation uses. The paper gives
   some tips on how to optimize the computation of Pi and Pi' using the
   Fast Walsh-Hadamard transform in Appendix A that the code in this
   implementation also uses. */

#if FD_REEDSOL_ARITH_IMPL>0

/* When using AVX, the representation used for internal computation can
   be done with unsigned chars or with shorts.  They give the same
   result in the end, but have different performance characteristics.
   It's not always obvious which is faster, so this is a compile-time
   switch for it.

   When FD_REEDSOL_PI_USE_SHORT==1, the FWHT operates on signed
   integers, so some care is needed to make sure overflow can't happen.

   When FD_REESOL_PI_USE_SHORT==0, the FWHT operates on a slightly
   overcomplete representation of the integers mod 255 (yes,
   unfortunately not mod 256).  In particular, the value 255 is allowed,
   which is interchangeable with 0. */

#ifndef FD_REEDSOL_PI_USE_SHORT
#define FD_REEDSOL_PI_USE_SHORT 0
#endif

/* Define some helper macros like what we have in util/simd for a vector
   of shorts.  */

#include "../../util/simd/fd_sse.h"

#define ws_t __m256i
#define ws_add(a,b)         _mm256_add_epi16( (a), (b) )
#define ws_sub(a,b)         _mm256_sub_epi16( (a), (b) )
#define ws_bcast(s0)        _mm256_set1_epi16( (s0) )
#define ws_adjust_sign(a,b) _mm256_sign_epi16( (a), (b) ) /* scales elements in a by the sign of the corresponding element of b */
#define ws_mullo(a,b)       _mm256_mullo_epi16( (a), (b) )
#define ws_mulhi(a,b)       _mm256_mulhi_epu16( (a), (b) )
#define ws_shl(a,imm)       _mm256_slli_epi16( (a), (imm) )
#define ws_and(a,b)         _mm256_and_si256(    (a), (b) )
#define ws_shru(a,imm)      _mm256_srli_epi16( (a), (imm) )
#define ws_zero()           _mm256_setzero_si256() /* Return [ 0 0 0 0 0 ... 0 0 ] */

FD_FN_UNUSED static inline ws_t ws_ld(  short const * p   ) { return _mm256_load_si256(  (__m256i const *)p ); }
FD_FN_UNUSED static inline ws_t ws_ldu( short const * p   ) { return _mm256_loadu_si256( (__m256i const *)p ); }
FD_FN_UNUSED static inline void ws_st(  short * p, ws_t i ) { _mm256_store_si256(  (__m256i *)p, i ); }
FD_FN_UNUSED static inline void ws_stu( short * p, ws_t i ) { _mm256_storeu_si256( (__m256i *)p, i ); }

static inline ws_t
ws_mod255( ws_t x ) {
  /* GCC informs me that for a ushort x,
     (x%255) == 0xFF & ( x + (x*0x8081)>>23).
     We need at least 31 bits of precision for the product, so
     mulh_epu16 is perfect. */
  return ws_and( ws_bcast( 0xFF ), ws_add( x, ws_shru( ws_mulhi( x, ws_bcast( (short)0x8081 ) ), 7 ) ) );
}

/* The following macros implement the unscaled Fast Walsh-Hadamard
   transform.  As alluded to above, this gives us a way to compute Pi
   and Pi' in O(n lg n) time.  These are designed for use within this
   file, not external use.

   Unlike the rest of the similar-seeming components in fd_reedsol (e.g.
   FFT, PPT), this computes the transform within a single (or few) AVX
   vectors, not in parallel across each component of the vector. I.e. if
   FD_REEDSOL_ARITH_IMPL>0, to compute a 16-element FWHD, you pass one
   AVX vector (16*short), not 16 vectors.

   Also unlike the rest of the similar-seeming components in fd_reedsol,
   this works on the group Z/255Z (integers mod 255).  Since 255 is not
   a prime, this is not a field, but the FD_REEDSOL_FWHT only needs addition,
   subtraction, and division by powers of 2 (which have inverses mod
   255), so it's not a problem.

   The typical FWHT multiplies by a factor of 1/sqrt(2) at each step.
   To convert the unscaled version to the scaled version, divide the
   result by sqrt(2)^lg(N).  Since we often do two transforms, we need
   to divide by N ( = (sqrt(2)^lg(N))^2 ).
   */

#if FD_REEDSOL_PI_USE_SHORT

#define FD_REEDSOL_FWHT_16( x )  do { ws_t _x = (x);                                                                  \
  _x = ws_add( _mm256_setr_m128i( _mm256_extracti128_si256( _x, 1 ), _mm256_extracti128_si256( _x, 0 ) ), \
      ws_adjust_sign( _x, _mm256_setr_epi16( 1,1,1,1, 1,1,1,1, -1,-1,-1,-1, -1,-1,-1,-1 ) ) ); \
  _x = ws_add( _mm256_shuffle_epi32( _x, 0x4E ), \
      ws_adjust_sign( _x, _mm256_setr_epi16( 1,1,1,1, -1,-1,-1,-1, 1,1,1,1, -1,-1,-1,-1 ) ) ); \
  _x = ws_add( _mm256_shuffle_epi32( _x, 0xB1 ), \
      ws_adjust_sign( _x, _mm256_setr_epi16( 1,1,-1,-1, 1,1,-1,-1, 1,1,-1,-1, 1,1,-1,-1 ) ) ); \
  _x = ws_add( _mm256_shuffle_epi8( _x, _mm256_setr_epi8( 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, \
                                                          2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13 ) ), \
          ws_adjust_sign( _x, _mm256_setr_epi16( 1,-1,1,-1, 1,-1,1,-1, 1,-1,1,-1, 1,-1,1,-1 ) ) ); \
  (x) = _x; } while( 0 )

#define FD_REEDSOL_FWHT_32( x0, x1 )  do { \
  ws_t _y0i = (x0);                  ws_t _y1i = (x1);  \
  ws_t _y0  = ws_add( _y0i, _y1i );  ws_t _y1  = ws_sub( _y0i, _y1i ); \
  FD_REEDSOL_FWHT_16( _y0 );         FD_REEDSOL_FWHT_16( _y1 ); \
  (x0) = _y0;                        (x1) = _y1; \
} while( 0 )

#define FD_REEDSOL_FWHT_64( x0, x1, x2, x3 )  do { \
  ws_t _z0, _z1, _z2, _z3; ws_t _z0i, _z1i, _z2i, _z3i; \
  _z0i = (x0);                  _z1i = (x1);                  _z2i = (x2);                  _z3i = (x3);  \
  _z0  = ws_add( _z0i, _z2i );  _z1  = ws_add( _z1i, _z3i );  _z2  = ws_sub( _z0i, _z2i );  _z3  = ws_sub( _z1i, _z3i );   \
  FD_REEDSOL_FWHT_32( _z0, _z1 );                             FD_REEDSOL_FWHT_32( _z2, _z3 ); \
  (x0) = _z0;                   (x1) = _z1;                   (x2) = _z2;                   (x3) = _z3; \
} while( 0 )

#define FD_REEDSOL_FWHT_128( x0, x1, x2, x3, x4, x5, x6, x7 )  do { \
  ws_t _w0,  _w1,  _w2,  _w3,  _w4,  _w5,  _w6,  _w7; \
  ws_t _w0i, _w1i, _w2i, _w3i, _w4i, _w5i, _w6i, _w7i; \
  _w0i = (x0);                  _w1i = (x1);                  _w2i = (x2);                  _w3i = (x3);  \
  _w4i = (x4);                  _w5i = (x5);                  _w6i = (x6);                  _w7i = (x7);  \
  _w0  = ws_add( _w0i, _w4i );  _w1  = ws_add( _w1i, _w5i );  _w2  = ws_add( _w2i, _w6i );  _w3  = ws_add( _w3i, _w7i );   \
  _w4  = ws_sub( _w0i, _w4i );  _w5  = ws_sub( _w1i, _w5i );  _w6  = ws_sub( _w2i, _w6i );  _w7  = ws_sub( _w3i, _w7i );   \
  FD_REEDSOL_FWHT_64( _w0, _w1, _w2, _w3 );                   FD_REEDSOL_FWHT_64( _w4, _w5, _w6, _w7 ); \
  (x0) = _w0; (x1) = _w1; (x2) = _w2; (x3) = _w3; (x4) = _w4; (x5) = _w5; (x6) = _w6; (x7) = _w7; \
} while( 0 )

#define FD_REEDSOL_FWHT_256( x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 )  do { \
  ws_t _v0,  _v1,  _v2,  _v3,  _v4,  _v5,  _v6,  _v7,  _v8,  _v9,  _v10,  _v11,  _v12,  _v13,  _v14,  _v15; \
  ws_t _v0i, _v1i, _v2i, _v3i, _v4i, _v5i, _v6i, _v7i, _v8i, _v9i, _v10i, _v11i, _v12i, _v13i, _v14i, _v15i; \
  _v0i  = (x0);                 _v1i  = (x1);                  _v2i  = (x2);                  _v3i  = (x3);  \
  _v4i  = (x4);                 _v5i  = (x5);                  _v6i  = (x6);                  _v7i  = (x7);  \
  _v8i  = (x8);                 _v9i  = (x9);                  _v10i = (x10);                 _v11i = (x11);  \
  _v12i = (x12);                _v13i = (x13);                 _v14i = (x14);                 _v15i = (x15);  \
  _v0  = ws_add( _v0i, _v8i  ); _v1   = ws_add( _v1i, _v9i  ); _v2   = ws_add( _v2i, _v10i ); _v3   = ws_add( _v3i, _v11i );   \
  _v4  = ws_add( _v4i, _v12i ); _v5   = ws_add( _v5i, _v13i ); _v6   = ws_add( _v6i, _v14i ); _v7   = ws_add( _v7i, _v15i );   \
  _v8  = ws_sub( _v0i, _v8i  ); _v9   = ws_sub( _v1i, _v9i  ); _v10  = ws_sub( _v2i, _v10i ); _v11  = ws_sub( _v3i, _v11i );   \
  _v12 = ws_sub( _v4i, _v12i ); _v13  = ws_sub( _v5i, _v13i ); _v14  = ws_sub( _v6i, _v14i ); _v15  = ws_sub( _v7i, _v15i );   \
  FD_REEDSOL_FWHT_128( _v0, _v1, _v2, _v3, _v4, _v5, _v6, _v7 ); FD_REEDSOL_FWHT_128( _v8, _v9, _v10, _v11, _v12, _v13, _v14, _v15 ); \
  (x0) = _v0; (x1) = _v1; (x2)  = _v2;  (x3)  = _v3;  (x4)  = _v4;  (x5)  = _v5;  (x6)  = _v6;  (x7)  = _v7; \
  (x8) = _v8; (x9) = _v9; (x10) = _v10; (x11) = _v11; (x12) = _v12; (x13) = _v13; (x14) = _v14; (x15) = _v15; \
} while( 0 )

#else /* FD_REEDSOL_PI_USE_SHORT */

static inline wb_t
add_mod_255( wb_t a, wb_t b ) {
  wb_t sum = wb_add( a, b );
  wb_t overflowed = wb_lt( sum, a );
  return wb_sub( sum, overflowed );
}

#define FD_REEDSOL_FWHT_16( x ) do { wb_t _x = (x); \
  wb_t negated, unshifted, shifted; \
  /* Shift by 8 elements (8B) */ \
  negated = wb_sub( wb_bcast( 0xFF ), _x ); \
  unshifted = _mm256_blend_epi32( _x, negated, 0xCC ); \
  shifted = _mm256_shuffle_epi32( _x, 0x4E ); \
  _x = add_mod_255( unshifted, shifted ); \
  /* Shift by 4 elements (4B) */ \
  negated = wb_sub( wb_bcast( 0xFF ), _x ); \
  unshifted = _mm256_blend_epi32( _x, negated, 0xAA ); \
  shifted = _mm256_shuffle_epi32( _x, 0xB1 ); \
  _x = add_mod_255( unshifted, shifted ); \
  /* Shift by 2 elements (2B) */ \
  negated = wb_sub( wb_bcast( 0xFF ), _x ); \
  unshifted = _mm256_blend_epi16( _x, negated, 0xAA ); \
  shifted = wb_exch_adj_pair( _x ); \
  _x = add_mod_255( unshifted, shifted ); \
  /* Shift by 1 element (1B) */ \
  negated = wb_sub( wb_bcast( 0xFF ), _x ); \
  unshifted = _mm256_blendv_epi8( _x, negated, wb_bcast_pair( 0x01, 0xFF ) ); \
  shifted = wb_exch_adj( _x ); \
  _x = add_mod_255( unshifted, shifted ); \
  (x) = _x; \
} while( 0 )

#define FD_REEDSOL_FWHT_32( x ) do { wb_t _y = (x); \
  wb_t negated, unshifted, shifted; \
  /* Shift by 16 elements (16B) */ \
  negated = wb_sub( wb_bcast( 0xFF ), _y ); \
  unshifted = _mm256_blend_epi32( _y, negated, 0xF0 ); \
  shifted = _mm256_setr_m128i( _mm256_extracti128_si256( _y, 1 ), _mm256_extracti128_si256( _y, 0 ) ); \
  _y = add_mod_255( unshifted, shifted ); \
  FD_REEDSOL_FWHT_16( _y ); \
  (x) = _y; \
} while( 0 )

#define FD_REEDSOL_FWHT_64( x0, x1 ) do { wb_t _z0i = (x0); wb_t _z1i = (x1);  \
  wb_t _z0 = add_mod_255( _z0i, _z1i );  wb_t _z1 = add_mod_255( _z0i, wb_sub( wb_bcast( 0xFF ), _z1i ) ); \
  FD_REEDSOL_FWHT_32( _z0 );             FD_REEDSOL_FWHT_32( _z1 ); \
  (x0) = _z0;                            (x1) = _z1; \
} while( 0 )

#define FD_REEDSOL_FWHT_128( x0, x1, x2, x3 ) do { wb_t _w0i = (x0); wb_t _w1i = (x1); wb_t _w2i = (x2); wb_t _w3i = (x3);  \
  wb_t _w0, _w1, _w2, _w3; \
  _w0 = add_mod_255( _w0i, _w2i );                               _w1 = add_mod_255( _w1i, _w3i ); \
  _w2 = add_mod_255( _w0i, wb_sub( wb_bcast( 0xFF ), _w2i ) );   _w3 = add_mod_255( _w1i, wb_sub( wb_bcast( 0xFF ), _w3i ) ); \
  FD_REEDSOL_FWHT_64( _w0, _w1 );                                FD_REEDSOL_FWHT_64( _w2, _w3 ); \
  (x0) = _w0; (x1) = _w1; (x2) = _w2; (x3) = _w3; \
} while( 0 )

#define FD_REEDSOL_FWHT_256( x0, x1, x2, x3, x4, x5, x6, x7 )  do { \
  wb_t _v0,  _v1,  _v2,  _v3,  _v4,  _v5,  _v6,  _v7; \
  wb_t _v0i, _v1i, _v2i, _v3i, _v4i, _v5i, _v6i, _v7i; \
  _v0i = (x0);                  _v1i = (x1);                  _v2i = (x2);                  _v3i = (x3);  \
  _v4i = (x4);                  _v5i = (x5);                  _v6i = (x6);                  _v7i = (x7);  \
  _v0 = add_mod_255( _v0i, _v4i );                               _v1 = add_mod_255( _v1i, _v5i ); \
  _v2 = add_mod_255( _v2i, _v6i );                               _v3 = add_mod_255( _v3i, _v7i ); \
  _v4 = add_mod_255( _v0i, wb_sub( wb_bcast( 0xFF ), _v4i ) );   _v5 = add_mod_255( _v1i, wb_sub( wb_bcast( 0xFF ), _v5i ) ); \
  _v6 = add_mod_255( _v2i, wb_sub( wb_bcast( 0xFF ), _v6i ) );   _v7 = add_mod_255( _v3i, wb_sub( wb_bcast( 0xFF ), _v7i ) ); \
  FD_REEDSOL_FWHT_128( _v0, _v1, _v2, _v3 );                   FD_REEDSOL_FWHT_128( _v4, _v5, _v6, _v7 ); \
  (x0) = _v0; (x1) = _v1; (x2) = _v2; (x3) = _v3; (x4) = _v4; (x5) = _v5; (x6) = _v6; (x7) = _v7; \
} while( 0 )
#endif

/* Casts each element of a to a uchar, forming a 16-element uchar vector.  Then
 * casts each element of b to a uchar, forming a second 16-element uchar
 * vector. Concatenates the two 16-element vectors to form a single
 * 32-element wb_t (a first, then b). */
static inline wb_t
compact_ws( ws_t a, ws_t b ) {
  /* There's also _mm256_packus_epi16, but it's no better than this */
  wb_t shuffled0 = _mm256_shuffle_epi8(a, wb(  0,  2,  4,  6,  8, 10, 12, 14, 128,128,128,128,128,128,128,128,
                                             128, 128,128,128,128,128,128,128,  0,  2,  4,  6,  8, 10, 12, 14 ) );
  wb_t shuffled1 = _mm256_shuffle_epi8(b, wb(  0,  2,  4,  6,  8, 10, 12, 14, 128,128,128,128,128,128,128,128,
                                             128, 128,128,128,128,128,128,128,  0,  2,  4,  6,  8, 10, 12, 14 ) );
  return _mm256_setr_m128i(
      _mm_or_si128( _mm256_extracti128_si256( shuffled0, 0 ), _mm256_extracti128_si256( shuffled0, 1 ) ),
      _mm_or_si128( _mm256_extracti128_si256( shuffled1, 0 ), _mm256_extracti128_si256( shuffled1, 1 ) ) );
}

/* exp_{n}( x ) computes n^x_i in GF(2^8) for each byte x_i in the
   vector x.  That's exponentiation, not xor. For example, exp_76
   interprets 76 as an element of GF(2^8) and x_i as an integer, and
   computes the product of multiplying GF(76) times itself x_i times.
   Recall that exponentiation is an operator from (GF(2^8) x (Z/255Z))
   -> GF(2^8), so x is interpreted mod 255.  (equivalently, observe
   n^255=1). As an input, x^255 is okay and is the same as x^0. */
static inline wb_t
exp_76( wb_t x ) {
  /* Decompose x = xh3*0x80 + xh2*0x40 + xh1*0x20 + xh0*0x10 + xl
     where 0<=xl<16 and 0<=xh_j<1 for each j.  Then

       76^x = (76^xl) * (76^0x10)^xh0 * (76^0x20)^xh1 *
                        (76^0x40)^xh2 (76^0x80)^xh3
             = (76^xl) * 2^xh0 * 4^xh1 * 16^xh2 * 29^xh3.

    We use vpshub to implement the 4-bit lookup table 76^xl.  The for
    the rest, we're either multiplying by a constant or not doing the
    multiply, so we can use our normal GF_MUL with a blend. */

  wb_t low = wb_and( x, wb_bcast( 0xF ) );
  wb_t exp_low = _mm256_shuffle_epi8( wb( 1,  76, 157,  70,  95, 253, 217, 129, 133, 168, 230, 227, 130,  81, 18,  44,
                                          1,  76, 157,  70,  95, 253, 217, 129, 133, 168, 230, 227, 130,  81, 18,  44 ),
                                      low );
  wb_t with0 = _mm256_blendv_epi8( exp_low, GF_MUL( exp_low,  2 ), _mm256_slli_epi16( x, 3 ) );
  wb_t with1 = _mm256_blendv_epi8( with0,   GF_MUL( with0,    4 ), _mm256_slli_epi16( x, 2 ) );
  wb_t with2 = _mm256_blendv_epi8( with1,   GF_MUL( with1,   16 ), _mm256_slli_epi16( x, 1 ) );
  wb_t with3 = _mm256_blendv_epi8( with2,   GF_MUL( with2,   29 ),                    x      );
  return with3;
}

static inline wb_t
exp_29( wb_t x ) {
  wb_t low = wb_and( x, wb_bcast( 0xF ) );
  wb_t exp_low = _mm256_shuffle_epi8( wb( 1,  29,  76, 143, 157, 106,  70,  93,  95, 101, 253, 254, 217,  13, 129,  59,
                                          1,  29,  76, 143, 157, 106,  70,  93,  95, 101, 253, 254, 217,  13, 129,  59 ),
                                      low );
  wb_t with0 = _mm256_blendv_epi8( exp_low, GF_MUL( exp_low, 133 ), _mm256_slli_epi16( x, 3 ) );
  wb_t with1 = _mm256_blendv_epi8( with0,   GF_MUL( with0,     2 ), _mm256_slli_epi16( x, 2 ) );
  wb_t with2 = _mm256_blendv_epi8( with1,   GF_MUL( with1,     4 ), _mm256_slli_epi16( x, 1 ) );
  wb_t with3 = _mm256_blendv_epi8( with2,   GF_MUL( with2,    16 ),                    x      );
  return with3;
}
static inline wb_t
exp_16( wb_t x ) {
  wb_t low = wb_and( x, wb_bcast( 0xF ) );
  wb_t exp_low = _mm256_shuffle_epi8( wb( 1,  16,  29, 205,  76, 180, 143,  24, 157,  37, 106, 238,  70,  20,  93, 185,
                                          1,  16,  29, 205,  76, 180, 143,  24, 157,  37, 106, 238,  70,  20,  93, 185 ),
                                      low );
  wb_t with0 = _mm256_blendv_epi8( exp_low, GF_MUL( exp_low,  95 ), _mm256_slli_epi16( x, 3 ) );
  wb_t with1 = _mm256_blendv_epi8( with0,   GF_MUL( with0,   133 ), _mm256_slli_epi16( x, 2 ) );
  wb_t with2 = _mm256_blendv_epi8( with1,   GF_MUL( with1,     2 ), _mm256_slli_epi16( x, 1 ) );
  wb_t with3 = _mm256_blendv_epi8( with2,   GF_MUL( with2,     4 ),                    x      );
  return with3;
}
static inline wb_t
exp_4( wb_t x ) {
  wb_t low = wb_and( x, wb_bcast( 0xF ) );
  wb_t exp_low = _mm256_shuffle_epi8( wb( 1,   4,  16,  64,  29, 116, 205,  19,  76,  45, 180, 234, 143,   6,  24,  96,
                                          1,   4,  16,  64,  29, 116, 205,  19,  76,  45, 180, 234, 143,   6,  24,  96 ),
                                      low );
  wb_t with0 = _mm256_blendv_epi8( exp_low, GF_MUL( exp_low, 157 ), _mm256_slli_epi16( x, 3 ) );
  wb_t with1 = _mm256_blendv_epi8( with0,   GF_MUL( with0,    95 ), _mm256_slli_epi16( x, 2 ) );
  wb_t with2 = _mm256_blendv_epi8( with1,   GF_MUL( with1,   133 ), _mm256_slli_epi16( x, 1 ) );
  wb_t with3 = _mm256_blendv_epi8( with2,   GF_MUL( with2,     2 ),                    x      );
  return with3;
}

static inline wb_t
exp_2( wb_t x ) {
  wb_t low = wb_and( x, wb_bcast( 0xF ) );
  wb_t exp_low = _mm256_shuffle_epi8( wb(   1,   2,   4,   8,  16,  32,  64, 128,  29,  58, 116, 232, 205, 135,  19,  38,
                                            1,   2,   4,   8,  16,  32,  64, 128,  29,  58, 116, 232, 205, 135,  19,  38),
                                      low );
  wb_t with0 = _mm256_blendv_epi8( exp_low, GF_MUL( exp_low,  76 ), _mm256_slli_epi16( x, 3 ) );
  wb_t with1 = _mm256_blendv_epi8( with0,   GF_MUL( with0,   157 ), _mm256_slli_epi16( x, 2 ) );
  wb_t with2 = _mm256_blendv_epi8( with1,   GF_MUL( with1,    95 ), _mm256_slli_epi16( x, 1 ) );
  wb_t with3 = _mm256_blendv_epi8( with2,   GF_MUL( with2,   133 ),                    x      );
  return with3;
}

#endif /* FD_REEDSOL_ARITH_IMPL>0 */

/* l_twiddle_{N} stores the size N FWHT of what the paper calls L~, i.e.
         ( 0, Log(1), Log(2), Log(3), ... Log(N-1) )

   The discrete log uses a primitive element of 2, and the FWHT is taken
   mod 255, which means all of the values can fit in a uchar.  However,
   Intel doesn't give us a multiplication instruction for 8-bit
   integers, which means that we'd have to zero-extend these values
   anyways.

   Although L~ for a smaller size is a subset of that for a larger size,
   because we also precompute the value of the FWHT, we store the
   variables separately.  Perhaps a good compiler could
   constant-propagate through the AVX instructions, but it's just 5
   values of N, so I prefer not to depend on that. */
static const short fwht_l_twiddle_16 [  16 ] = {0xca,0xa1,0x6a,0xa9,0x73,0xfc,0xe2,0x44,0x93,0x74,0x08,0x7f,0x96,0x8c,0x42,0xf2};
static const short fwht_l_twiddle_32 [  32 ] = {0x24,0x8f,0xc2,0x7e,0x49,0x89,0x74,0xdc,0x4f,0x95,0x43,0xb4,0x09,0xba,0x03,0x83,
                                                0x71,0xb3,0x12,0xd4,0x9d,0x70,0x51,0xab,0xd7,0x53,0xcc,0x4a,0x24,0x5e,0x81,0x62};
static const short fwht_l_twiddle_64 [  64 ] = {0x05,0x81,0x9a,0x82,0x07,0x7c,0x3c,0xbe,0xd3,0xbc,0xed,0x23,0xc2,0x24,0xee,0xc8,
                                                0x3f,0x5d,0x11,0x18,0x8a,0xf9,0x1c,0x4b,0x0e,0x02,0x8e,0xe4,0x77,0x8c,0x97,0x6d,
                                                0x43,0x9d,0xea,0x7a,0x8b,0x96,0xac,0xfa,0xca,0x6e,0x98,0x46,0x4f,0x51,0x17,0x3e,
                                                0xa3,0x0a,0x13,0x91,0xb0,0xe6,0x86,0x0c,0xa1,0xa4,0x0b,0xaf,0xd0,0x30,0x6b,0x57};
static const short fwht_l_twiddle_128[ 128 ] = {0xfe,0x89,0x15,0xeb,0x48,0xea,0x04,0xfe,0x32,0xd9,0xca,0x2c,0x1e,0x58,0x8d,0xed,
                                                0x6f,0x36,0x53,0x24,0xb2,0x27,0x3e,0x06,0xec,0x96,0x41,0x05,0xbe,0x1d,0xb1,0xdd,
                                                0x18,0x64,0xf4,0xc3,0x16,0x0a,0x2e,0x00,0xde,0x34,0xaf,0x42,0xd7,0x5e,0x92,0x02,
                                                0xbf,0x5a,0x6a,0x97,0xe1,0x39,0xd0,0xf6,0x66,0x86,0xb5,0x61,0x8a,0xa2,0x8f,0x49,
                                                0x0b,0x79,0x20,0x19,0xc5,0x0e,0x74,0x7e,0x75,0x9f,0x11,0x1a,0x67,0xef,0x50,0xa3,
                                                0x0f,0x84,0xce,0x0c,0x62,0xcc,0xf9,0x90,0x2f,0x6d,0xdb,0xc4,0x30,0xfb,0x7d,0xfc,
                                                0x6e,0xd6,0xe0,0x31,0x01,0x23,0x2b,0xf5,0xb6,0xa8,0x81,0x4a,0xc6,0x44,0x9b,0x7a,
                                                0x87,0xb9,0xbb,0x8b,0x7f,0x94,0x3c,0x21,0xdc,0xc2,0x60,0xfd,0x17,0xbd,0x47,0x65};
static const short fwht_l_twiddle_256[ 256 ] = {0x00,0xfc,0xfb,0x15,0x2d,0xfa,0xc1,0x14,0x62,0x2c,0xd9,0xf9,0xc0,0x45,0x13,0xe8,
                                                0x01,0x61,0x86,0x2b,0xd8,0xba,0xf8,0x5d,0xbf,0x7a,0x44,0x6a,0x07,0x12,0xf1,0xe7,
                                                0x00,0xdc,0x60,0x0a,0x1f,0x85,0x1c,0x2a,0x8b,0xd7,0x92,0xb9,0xf7,0x82,0x5c,0xad,
                                                0x19,0xbe,0xb1,0x79,0x43,0x3d,0x69,0x9e,0x06,0x75,0x11,0x27,0x70,0xf0,0xd2,0xe6,
                                                0xfe,0x2f,0xdb,0xea,0x88,0x5f,0x7c,0x09,0x0c,0x1e,0x8d,0x84,0x1b,0x3f,0x29,0xd4,
                                                0x31,0x8a,0x8f,0xd6,0x91,0xcb,0xb8,0xc9,0xf6,0xb6,0x81,0x39,0xc7,0x5b,0x55,0xac,
                                                0x18,0x65,0xbd,0xf4,0x22,0xb0,0xb4,0x78,0x7f,0x42,0x34,0x3c,0x68,0x37,0x9d,0x4e,
                                                0xc5,0x05,0x96,0x74,0x10,0x59,0x26,0x9a,0x6f,0xa3,0xef,0x53,0x4b,0xd1,0xaa,0xe5,
                                                0xfd,0x16,0x2e,0xc2,0x63,0xda,0x46,0xe9,0x02,0x87,0xbb,0x5e,0x7b,0x6b,0x08,0xf2,
                                                0xdd,0x0b,0x20,0x1d,0x8c,0x93,0x83,0xae,0x1a,0xb2,0x3e,0x9f,0x76,0x28,0x71,0xd3,
                                                0x30,0xeb,0x89,0x7d,0x0d,0x8e,0x40,0xd5,0x32,0x90,0xcc,0xca,0xb7,0x3a,0xc8,0x56,
                                                0x66,0xf5,0x23,0xb5,0x80,0x35,0x38,0x4f,0xc6,0x97,0x5a,0x9b,0xa4,0x54,0x4c,0xab,
                                                0x17,0xc3,0x64,0x47,0x03,0xbc,0x6c,0xf3,0xde,0x21,0x94,0xaf,0xb3,0xa0,0x77,0x72,
                                                0xec,0x7e,0x0e,0x41,0x33,0xcd,0x3b,0x57,0x67,0x24,0x36,0x50,0x98,0x9c,0xa5,0x4d,
                                                0xc4,0x48,0x04,0x6d,0xdf,0x95,0xa1,0x73,0xed,0x0f,0xce,0x58,0x25,0x51,0x99,0xa6,
                                                0x49,0x6e,0xe0,0xa2,0xee,0xcf,0x52,0xa7,0x4a,0xe1,0xd0,0xa8,0xe2,0xa9,0xe3,0xe4};

#if FD_REEDSOL_ARITH_IMPL==0
static void
gen_pi_noavx_generic( uchar const * is_erased,
                      uchar       * output,
                      ulong         sz,
                      const short * l_twiddle ) {
  long scratch[ 256 ];

  for( ulong i=0UL; i<sz; i++ ) scratch[ i ] = is_erased[ i ];

  /* Unscaled FWHT */
  for( ulong h=1UL; h<sz; h<<=1 ) {
    for( ulong i=0UL; i<sz; i += 2UL*h ) for( ulong j=i; j<i+h; j++ ) {
      long x = scratch[ j   ];
      long y = scratch[ j+h ];
      scratch[ j   ] = x+y;
      scratch[ j+h ] = x-y;
    }
  }

  for( ulong i=0UL; i<sz; i++ ) scratch[ i ] *= l_twiddle[ i ];

  for( ulong h=1UL; h<sz; h<<=1 ) {
    for( ulong i=0UL; i<sz; i += 2UL*h ) for( ulong j=i; j<i+h; j++ ) {
      long x = scratch[ j   ];
      long y = scratch[ j+h ];
      scratch[ j   ] = x+y;
      scratch[ j+h ] = x-y;
    }
  }

  /* Negate the ones corresponding to erasures to compute 1/Pi' */
  for( ulong i=0UL; i<sz; i++ ) scratch[ i ] *= fd_long_if( is_erased[ i ], -1L, 1L );

  /* To fix the FWHT scaling, we need to multiply by sz^-1 mod 255.
     Given that sz is always a power of 2, this is not too bad.
     Let s = lg(sz).  Note that 2^8 == 256 == 1 (mod 255),
     so then (2^s) * (2^(8-s)) == 1    (mod 255).
     This implies that sz^-1 = 2^(8-s) (mod 255), and we can compute
     2^(8-s) by 256/s with normal integer division. */
  long sz_inv = 256L/(long)sz;
  /* The % operator in C doesn't work like the mathematical mod
     operation for negative numbers, so we need to add in a shift to
     make any input non-negative.  We can compute the smallest possible
     value at this point and it's -142397, so we add 255*559=142545. */
  for( ulong i=0UL; i<sz; i++ ) scratch[ i ] = (sz_inv*(scratch[ i ] + 255L*559L)) % 255L;

  for( ulong i=0UL; i<sz; i++ ) output[ i ] = (uchar)gf_arith_invlog_tbl[ scratch[ i ] ];
}
#endif

void
fd_reedsol_private_gen_pi_16( uchar const * is_erased,
                              uchar       * output ) {
#if FD_REEDSOL_ARITH_IMPL>0
#if FD_REEDSOL_PI_USE_SHORT
  ws_t erased_vec = _mm256_cvtepu8_epi16( vb_ld( is_erased ) );

  ws_t transformed = erased_vec;
  FD_REEDSOL_FWHT_16( transformed ); /* FWHT( R~ ) */
  /* |transformed| <= 16 */

  /* product is congruent to FWHT( R~) * FWHT( L~ ) mod 255 .
     |product| <= 16*255, but definitely may be negative */
  ws_t product = ws_mullo( transformed, ws_ld( fwht_l_twiddle_16 ) );

  /* log_pi is congruent (mod 255) to what the paper calls
     R_w = FWHT( FWHT( L~ ) * FWHT( R~ ) ).
     Let H be the 16x16 Hadamard matrix.  Then
         log_pi = (H * diag( fwht_l_twiddle_16 ) * H) * erased_vec
                  |---------------------------------|
                                M
     The part labeled M is a matrix known ahead of time, so we can bound
     log_pi relatively easily when combined with the fact
     0<=erased_vec<=1 (just set the negative entries to 0, and multiply
     by all 1s. Then do the same, setting the positive entries to 0
     instead).  This tells us |log_pi| <= 4489 */
  FD_REEDSOL_FWHT_16( product );
  ws_t log_pi = product;

  /* Negate the ones corresponding to erasures to compute 1/Pi' */
  log_pi = ws_adjust_sign( log_pi, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec, 1 ) ) );

  log_pi = ws_add( log_pi, ws_bcast( (short)(255*18) ) ); /* Now 0<= log_pi <= 9079 < 2^15 */

  /* GCC informs me that for a ushort x,
     (x%255) == 0xFF & ( x + (x*0x8081)>>23).
     We need at least 31 bits of precision for the product, so
     mulh_epu16 is perfect. */
  log_pi = ws_and( ws_bcast( 0xFF ), ws_add( log_pi, ws_shru( ws_mulhi( log_pi, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  /* Now 0<=log_pi < 255 */

  /* Since our FWHT implementation is unscaled, we've computed a value
     16 times larger than what we'd like.  16^-1 == 16 (mod 255), but
     we're just going to use this in the exponentiation, so we can
     compute this implicitly.
       2^(log_pi * 16^-1) = 2^(16*log_pi) = (2^16)^log_pi = 76^log_pi
     (where 2 is the primitive element we used for the logs, an element
     of GF(2^8) ). */

  wb_t compact_log_pi = compact_ws( log_pi, ws_zero() );
  wb_t pi = exp_76( compact_log_pi );

  vb_st( output, _mm256_extracti128_si256( pi, 0 ) );

#else
  wb_t erased_vec = _mm256_setr_m128i( vb_ldu( is_erased ), _mm_setzero_si128() );
  wb_t to_transform = erased_vec;
  FD_REEDSOL_FWHT_16( to_transform );
  ws_t transformed = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform, 0 ) );
  /* product is congruent to FWHT( R~) * FWHT( L~ ) mod 255.
     0<=product<256*255, so product is interpreted as unsigned. */
  ws_t product = ws_mullo( transformed, ws_ld( fwht_l_twiddle_16 ) );

  /* Compute mod 255, using the same approach as above. */
  product = ws_and( ws_bcast( 0xFF ), ws_add( product, ws_shru( ws_mulhi( product, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  wb_t compact_product = compact_ws( product, ws_zero() );

  FD_REEDSOL_FWHT_16( compact_product );

  /* Negate the ones corresponding to erasures */
  compact_product = wb_if( wb_eq( erased_vec, wb_zero() ), compact_product, wb_sub( wb_bcast( 255 ), compact_product ) );

  wb_t pi = exp_76( compact_product );
  vb_st( output, _mm256_extracti128_si256( pi, 0 ) );
#endif
#else /* No AVX implementation */

  gen_pi_noavx_generic( is_erased, output, 16UL, fwht_l_twiddle_16 );

#endif
}

void
fd_reedsol_private_gen_pi_32( uchar const * is_erased,
                              uchar       * output ) {
#if FD_REEDSOL_ARITH_IMPL>0
#if FD_REEDSOL_PI_USE_SHORT
  ws_t erased_vec0 = _mm256_cvtepu8_epi16( vb_ld( is_erased        ) );
  ws_t erased_vec1 = _mm256_cvtepu8_epi16( vb_ld( is_erased + 16UL ) );

  ws_t transformed0 = erased_vec0;
  ws_t transformed1 = erased_vec1;
  FD_REEDSOL_FWHT_32( transformed0, transformed1 ); /* FWHT( R~ ) */
  /* |transformed| <= 32 */

  /* product is congruent to FWHT( R~) * FWHT( L~ ) mod 255 .
     |product| <= 32*255, but definitely may be negative */
  ws_t product0 = ws_mullo( transformed0, ws_ld( fwht_l_twiddle_32        ) );
  ws_t product1 = ws_mullo( transformed1, ws_ld( fwht_l_twiddle_32 + 16UL ) );

  /* log_pi is congruent (mod 255) to what the paper calls
     R_w = FWHT( FWHT( L~ ) * FWHT( R~ ) ).
     |log_pi| <= 6945 using the same approach as above. */
  FD_REEDSOL_FWHT_32( product0, product1 );
  ws_t log_pi0 = product0;
  ws_t log_pi1 = product1;

  /* Negate the ones corresponding to erasures to compute 1/Pi' */
  log_pi0 = ws_adjust_sign( log_pi0, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec0, 1 ) ) );
  log_pi1 = ws_adjust_sign( log_pi1, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec1, 1 ) ) );

  log_pi0 = ws_add( log_pi0, ws_bcast( (short)(255*28) ) );
  log_pi1 = ws_add( log_pi1, ws_bcast( (short)(255*28) ) ); /* Now 0<= log_pi <= 14085 < 2^15 */

  /* GCC informs me that for a ushort x,
     (x%255) == 0xFF & ( x + (x*0x8081)>>23).
     We need at least 31 bits of precision for the product, so
     mulh_epu16 is perfect. */
  log_pi0 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi0, ws_shru( ws_mulhi( log_pi0, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  log_pi1 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi1, ws_shru( ws_mulhi( log_pi1, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  /* Now 0<=log_pi < 255 */

  /* Since our FWHT implementation is unscaled, we've computed a value
     32 times larger than what we'd like.  32^-1 == 8 (mod 255), but
     we're just going to use this in the exponentiation, so we can
     compute this implicitly.
       2^(log_pi * 32^-1) = 2^(8*log_pi) = (2^8)^log_pi = 29^log_pi
     (where 2 is the primitive element we used for the logs, an element
     of GF(2^8) ). */

  wb_t compact_log_pi = compact_ws( log_pi0, log_pi1 );
  wb_t pi = exp_29( compact_log_pi );

  wb_st( output, pi );

#else
  wb_t erased_vec = wb_ld( is_erased );
  wb_t to_transform = erased_vec;
  FD_REEDSOL_FWHT_32( to_transform );
  ws_t transformed0 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform, 0 ) );
  ws_t transformed1 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform, 1 ) );

  /* product is congruent to FWHT( R~) * FWHT( L~ ) mod 255.
     0<=product<256*255, so product is interpreted as unsigned. */
  ws_t product0 = ws_mullo( transformed0, ws_ld( fwht_l_twiddle_32        ) );
  ws_t product1 = ws_mullo( transformed1, ws_ld( fwht_l_twiddle_32 + 16UL ) );

  /* Compute mod 255, using the same approach as above. */
  product0 = ws_and( ws_bcast( 0xFF ), ws_add( product0, ws_shru( ws_mulhi( product0, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product1 = ws_and( ws_bcast( 0xFF ), ws_add( product1, ws_shru( ws_mulhi( product1, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  wb_t compact_product = compact_ws( product0, product1 );

  FD_REEDSOL_FWHT_32( compact_product );

  /* Negate the ones corresponding to erasures */
  compact_product = wb_if( wb_eq( erased_vec, wb_zero() ), compact_product, wb_sub( wb_bcast( 255 ), compact_product ) );

  wb_t pi = exp_29( compact_product );
  wb_st( output, pi );
#endif
#else /* No AVX implementation */

  gen_pi_noavx_generic( is_erased, output, 32UL, fwht_l_twiddle_32 );

#endif
}

void
fd_reedsol_private_gen_pi_64( uchar const * is_erased,
                              uchar       * output ) {
#if FD_REEDSOL_ARITH_IMPL>0
#if FD_REEDSOL_PI_USE_SHORT
  ws_t erased_vec0 = _mm256_cvtepu8_epi16( vb_ld( is_erased        ) );
  ws_t erased_vec1 = _mm256_cvtepu8_epi16( vb_ld( is_erased + 16UL ) );
  ws_t erased_vec2 = _mm256_cvtepu8_epi16( vb_ld( is_erased + 32UL ) );
  ws_t erased_vec3 = _mm256_cvtepu8_epi16( vb_ld( is_erased + 48UL ) );

  ws_t transformed0 = erased_vec0;
  ws_t transformed1 = erased_vec1;
  ws_t transformed2 = erased_vec2;
  ws_t transformed3 = erased_vec3;
  FD_REEDSOL_FWHT_64( transformed0, transformed1, transformed2, transformed3 ); /* FWHT( R~ ) */
  /* |transformed| <= 64 */

  /* product is congruent to FWHT( R~) * FWHT( L~ ) mod 255 .
     |product| <= 64*255, but definitely may be negative */
  ws_t product0 = ws_mullo( transformed0, ws_ld( fwht_l_twiddle_64        ) );
  ws_t product1 = ws_mullo( transformed1, ws_ld( fwht_l_twiddle_64 + 16UL ) );
  ws_t product2 = ws_mullo( transformed2, ws_ld( fwht_l_twiddle_64 + 32UL ) );
  ws_t product3 = ws_mullo( transformed3, ws_ld( fwht_l_twiddle_64 + 48UL ) );

  /* log_pi is congruent (mod 255) to what the paper calls
     R_w = FWHT( FWHT( L~ ) * FWHT( R~ ) ).
     |log_pi| <= 18918 using the same approach as above. */
  FD_REEDSOL_FWHT_64( product0, product1, product2, product3 );
  ws_t log_pi0 = product0;
  ws_t log_pi1 = product1;
  ws_t log_pi2 = product2;
  ws_t log_pi3 = product3;

  /* Negate the ones corresponding to erasures to compute 1/Pi' */
  log_pi0 = ws_adjust_sign( log_pi0, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec0, 1 ) ) );
  log_pi1 = ws_adjust_sign( log_pi1, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec1, 1 ) ) );
  log_pi2 = ws_adjust_sign( log_pi2, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec2, 1 ) ) );
  log_pi3 = ws_adjust_sign( log_pi3, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec3, 1 ) ) );

  log_pi0 = ws_add( log_pi0, ws_bcast( (short)(255*75) ) );
  log_pi1 = ws_add( log_pi1, ws_bcast( (short)(255*75) ) );
  log_pi2 = ws_add( log_pi2, ws_bcast( (short)(255*75) ) );
  log_pi3 = ws_add( log_pi3, ws_bcast( (short)(255*75) ) );
  /* Now 0<= log_pi <= 38043 < 2^16 (okay, since the next step treats it as unsigned */

  /* GCC informs me that for a ushort x,
     (x%255) == 0xFF & ( x + (x*0x8081)>>23).
     We need at least 31 bits of precision for the product, so
     mulh_epu16 is perfect. */
  log_pi0 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi0, ws_shru( ws_mulhi( log_pi0, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  log_pi1 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi1, ws_shru( ws_mulhi( log_pi1, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  log_pi2 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi2, ws_shru( ws_mulhi( log_pi2, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  log_pi3 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi3, ws_shru( ws_mulhi( log_pi3, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  /* Now 0<=log_pi < 255 */

  /* Since our FWHT implementation is unscaled, we've computed a value
     64 times larger than what we'd like.  64^-1 == 4 (mod 255), but
     we're just going to use this in the exponentiation, so we can
     compute this implicitly.
       2^(log_pi * 64^-1) = 2^(4*log_pi) = (2^4)^log_pi = 16^log_pi
     (where 2 is the primitive element we used for the logs, an element
     of GF(2^8) ). */

  wb_t compact_log_pi0 = compact_ws( log_pi0, log_pi1 );
  wb_t compact_log_pi1 = compact_ws( log_pi2, log_pi3 );
  wb_t pi0 = exp_16( compact_log_pi0 );
  wb_t pi1 = exp_16( compact_log_pi1 );

  wb_st( output,      pi0 );
  wb_st( output+32UL, pi1 );

#else
  wb_t erased_vec0 = wb_ld( is_erased        );
  wb_t erased_vec1 = wb_ld( is_erased + 32UL );
  wb_t to_transform0 = erased_vec0;
  wb_t to_transform1 = erased_vec1;

  FD_REEDSOL_FWHT_64( to_transform0, to_transform1 );

  ws_t transformed0 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform0, 0 ) );
  ws_t transformed1 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform0, 1 ) );
  ws_t transformed2 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform1, 0 ) );
  ws_t transformed3 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform1, 1 ) );

  /* product is congruent to FWHT( R~) * FWHT( L~ ) mod 255.
     0<=product<256*255, so product is interpreted as unsigned. */
  ws_t product0 = ws_mullo( transformed0, ws_ld( fwht_l_twiddle_64        ) );
  ws_t product1 = ws_mullo( transformed1, ws_ld( fwht_l_twiddle_64 + 16UL ) );
  ws_t product2 = ws_mullo( transformed2, ws_ld( fwht_l_twiddle_64 + 32UL ) );
  ws_t product3 = ws_mullo( transformed3, ws_ld( fwht_l_twiddle_64 + 48UL ) );

  /* Compute mod 255, using the same approach as above. */
  product0 = ws_and( ws_bcast( 0xFF ), ws_add( product0, ws_shru( ws_mulhi( product0, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product1 = ws_and( ws_bcast( 0xFF ), ws_add( product1, ws_shru( ws_mulhi( product1, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product2 = ws_and( ws_bcast( 0xFF ), ws_add( product2, ws_shru( ws_mulhi( product2, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product3 = ws_and( ws_bcast( 0xFF ), ws_add( product3, ws_shru( ws_mulhi( product3, ws_bcast( (short)0x8081 ) ), 7 ) ) );

  wb_t compact_product0 = compact_ws( product0, product1 );
  wb_t compact_product1 = compact_ws( product2, product3 );

  FD_REEDSOL_FWHT_64( compact_product0, compact_product1 );

  /* Negate the ones corresponding to erasures */
  compact_product0 = wb_if( wb_eq( erased_vec0, wb_zero() ), compact_product0, wb_sub( wb_bcast( 255 ), compact_product0 ) );
  compact_product1 = wb_if( wb_eq( erased_vec1, wb_zero() ), compact_product1, wb_sub( wb_bcast( 255 ), compact_product1 ) );

  wb_t pi0 = exp_16( compact_product0 );
  wb_t pi1 = exp_16( compact_product1 );
  wb_st( output       , pi0 );
  wb_st( output + 32UL, pi1 );
#endif
#else /* No AVX implementation */

  gen_pi_noavx_generic( is_erased, output, 64UL, fwht_l_twiddle_64 );

#endif
}

void
fd_reedsol_private_gen_pi_128( uchar const * is_erased,
                               uchar       * output ) {
#if FD_REEDSOL_ARITH_IMPL>0
#if FD_REEDSOL_PI_USE_SHORT
  ws_t erased_vec0 = _mm256_cvtepu8_epi16( vb_ld( is_erased         ) );
  ws_t erased_vec1 = _mm256_cvtepu8_epi16( vb_ld( is_erased +  16UL ) );
  ws_t erased_vec2 = _mm256_cvtepu8_epi16( vb_ld( is_erased +  32UL ) );
  ws_t erased_vec3 = _mm256_cvtepu8_epi16( vb_ld( is_erased +  48UL ) );
  ws_t erased_vec4 = _mm256_cvtepu8_epi16( vb_ld( is_erased +  64UL ) );
  ws_t erased_vec5 = _mm256_cvtepu8_epi16( vb_ld( is_erased +  80UL ) );
  ws_t erased_vec6 = _mm256_cvtepu8_epi16( vb_ld( is_erased +  96UL ) );
  ws_t erased_vec7 = _mm256_cvtepu8_epi16( vb_ld( is_erased + 112UL ) );

  ws_t transformed0 = erased_vec0;
  ws_t transformed1 = erased_vec1;
  ws_t transformed2 = erased_vec2;
  ws_t transformed3 = erased_vec3;
  ws_t transformed4 = erased_vec4;
  ws_t transformed5 = erased_vec5;
  ws_t transformed6 = erased_vec6;
  ws_t transformed7 = erased_vec7;
  FD_REEDSOL_FWHT_128( transformed0, transformed1, transformed2, transformed3, transformed4, transformed5, transformed6, transformed7 ); /* FWHT( R~ ) */
  /* |transformed| <= 128 */

  /* product is congruent to FWHT( R~) * FWHT( L~ ) mod 255 .
     -16256 <= product <= 32512 */
  ws_t product0 = ws_mullo( transformed0, ws_ld( fwht_l_twiddle_128         ) );
  ws_t product1 = ws_mullo( transformed1, ws_ld( fwht_l_twiddle_128 +  16UL ) );
  ws_t product2 = ws_mullo( transformed2, ws_ld( fwht_l_twiddle_128 +  32UL ) );
  ws_t product3 = ws_mullo( transformed3, ws_ld( fwht_l_twiddle_128 +  48UL ) );
  ws_t product4 = ws_mullo( transformed4, ws_ld( fwht_l_twiddle_128 +  64UL ) );
  ws_t product5 = ws_mullo( transformed5, ws_ld( fwht_l_twiddle_128 +  80UL ) );
  ws_t product6 = ws_mullo( transformed6, ws_ld( fwht_l_twiddle_128 +  96UL ) );
  ws_t product7 = ws_mullo( transformed7, ws_ld( fwht_l_twiddle_128 + 112UL ) );

  /* We need to reduce these mod 255 to prevent overflow in the next
     step. 0 <= product+64*255 <= 48832 < 2^16.  The mod operation
     treats the input as unsigned though, so this is okay. */
  product0 = ws_add( product0, ws_bcast( (short)64*255 ) );
  product1 = ws_add( product1, ws_bcast( (short)64*255 ) );
  product2 = ws_add( product2, ws_bcast( (short)64*255 ) );
  product3 = ws_add( product3, ws_bcast( (short)64*255 ) );
  product4 = ws_add( product4, ws_bcast( (short)64*255 ) );
  product5 = ws_add( product5, ws_bcast( (short)64*255 ) );
  product6 = ws_add( product6, ws_bcast( (short)64*255 ) );
  product7 = ws_add( product7, ws_bcast( (short)64*255 ) );

  product0 = ws_and( ws_bcast( 0xFF ), ws_add( product0, ws_shru( ws_mulhi( product0, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product1 = ws_and( ws_bcast( 0xFF ), ws_add( product1, ws_shru( ws_mulhi( product1, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product2 = ws_and( ws_bcast( 0xFF ), ws_add( product2, ws_shru( ws_mulhi( product2, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product3 = ws_and( ws_bcast( 0xFF ), ws_add( product3, ws_shru( ws_mulhi( product3, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product4 = ws_and( ws_bcast( 0xFF ), ws_add( product4, ws_shru( ws_mulhi( product4, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product5 = ws_and( ws_bcast( 0xFF ), ws_add( product5, ws_shru( ws_mulhi( product5, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product6 = ws_and( ws_bcast( 0xFF ), ws_add( product6, ws_shru( ws_mulhi( product6, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product7 = ws_and( ws_bcast( 0xFF ), ws_add( product7, ws_shru( ws_mulhi( product7, ws_bcast( (short)0x8081 ) ), 7 ) ) );

  /* Now 0 <= product < 255 */

  /* log_pi is congruent (mod 255) to what the paper calls
     R_w = FWHT( FWHT( L~ ) * FWHT( R~ ) ).
     |log_pi| <= 128*255 */
  FD_REEDSOL_FWHT_128( product0, product1, product2, product3, product4, product5, product6, product7 );
  ws_t log_pi0 = product0;
  ws_t log_pi1 = product1;
  ws_t log_pi2 = product2;
  ws_t log_pi3 = product3;
  ws_t log_pi4 = product4;
  ws_t log_pi5 = product5;
  ws_t log_pi6 = product6;
  ws_t log_pi7 = product7;

  /* Negate the ones corresponding to erasures to compute 1/Pi' */
  log_pi0 = ws_adjust_sign( log_pi0, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec0, 1 ) ) );
  log_pi1 = ws_adjust_sign( log_pi1, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec1, 1 ) ) );
  log_pi2 = ws_adjust_sign( log_pi2, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec2, 1 ) ) );
  log_pi3 = ws_adjust_sign( log_pi3, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec3, 1 ) ) );
  log_pi4 = ws_adjust_sign( log_pi4, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec4, 1 ) ) );
  log_pi5 = ws_adjust_sign( log_pi5, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec5, 1 ) ) );
  log_pi6 = ws_adjust_sign( log_pi6, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec6, 1 ) ) );
  log_pi7 = ws_adjust_sign( log_pi7, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec7, 1 ) ) );

  log_pi0 = ws_add( log_pi0, ws_bcast( (short)(255*128) ) );
  log_pi1 = ws_add( log_pi1, ws_bcast( (short)(255*128) ) );
  log_pi2 = ws_add( log_pi2, ws_bcast( (short)(255*128) ) );
  log_pi3 = ws_add( log_pi3, ws_bcast( (short)(255*128) ) );
  log_pi4 = ws_add( log_pi4, ws_bcast( (short)(255*128) ) );
  log_pi5 = ws_add( log_pi5, ws_bcast( (short)(255*128) ) );
  log_pi6 = ws_add( log_pi6, ws_bcast( (short)(255*128) ) );
  log_pi7 = ws_add( log_pi7, ws_bcast( (short)(255*128) ) ); /* Now 0<= log_pi <= 65152 < 2^16 */

  /* GCC informs me that for a ushort x,
     (x%255) == 0xFF & ( x + (x*0x8081)>>23).
     We need at least 31 bits of precision for the product, so
     mulh_epu16 is perfect. */
  log_pi0 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi0, ws_shru( ws_mulhi( log_pi0, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  log_pi1 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi1, ws_shru( ws_mulhi( log_pi1, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  log_pi2 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi2, ws_shru( ws_mulhi( log_pi2, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  log_pi3 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi3, ws_shru( ws_mulhi( log_pi3, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  log_pi4 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi4, ws_shru( ws_mulhi( log_pi4, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  log_pi5 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi5, ws_shru( ws_mulhi( log_pi5, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  log_pi6 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi6, ws_shru( ws_mulhi( log_pi6, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  log_pi7 = ws_and( ws_bcast( 0xFF ), ws_add( log_pi7, ws_shru( ws_mulhi( log_pi7, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  /* Now 0<=log_pi < 255 */

  /* Since our FWHT implementation is unscaled, we've computed a value
     128 times larger than what we'd like.  128^-1 == 2 (mod 255), but
     we're just going to use this in the exponentiation, so we can
     compute this implicitly.
       2^(log_pi * 128^-1) = 2^(2*log_pi) = (2^2)^log_pi = 4^log_pi
     (where 2 is the primitive element we used for the logs, an element
     of GF(2^8) ). */

  wb_t compact_log_pi0 = compact_ws( log_pi0, log_pi1 );
  wb_t compact_log_pi1 = compact_ws( log_pi2, log_pi3 );
  wb_t compact_log_pi2 = compact_ws( log_pi4, log_pi5 );
  wb_t compact_log_pi3 = compact_ws( log_pi6, log_pi7 );
  wb_t pi0 = exp_4( compact_log_pi0 );
  wb_t pi1 = exp_4( compact_log_pi1 );
  wb_t pi2 = exp_4( compact_log_pi2 );
  wb_t pi3 = exp_4( compact_log_pi3 );

  wb_st( output,        pi0 );
  wb_st( output + 32UL, pi1 );
  wb_st( output + 64UL, pi2 );
  wb_st( output + 96UL, pi3 );

#else
  wb_t erased_vec0 = wb_ld( is_erased        );
  wb_t erased_vec1 = wb_ld( is_erased + 32UL );
  wb_t erased_vec2 = wb_ld( is_erased + 64UL );
  wb_t erased_vec3 = wb_ld( is_erased + 96UL );
  wb_t to_transform0 = erased_vec0;
  wb_t to_transform1 = erased_vec1;
  wb_t to_transform2 = erased_vec2;
  wb_t to_transform3 = erased_vec3;

  FD_REEDSOL_FWHT_128( to_transform0, to_transform1, to_transform2, to_transform3 );

  ws_t transformed0 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform0, 0 ) );
  ws_t transformed1 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform0, 1 ) );
  ws_t transformed2 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform1, 0 ) );
  ws_t transformed3 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform1, 1 ) );
  ws_t transformed4 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform2, 0 ) );
  ws_t transformed5 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform2, 1 ) );
  ws_t transformed6 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform3, 0 ) );
  ws_t transformed7 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform3, 1 ) );

  /* product is congruent to FWHT( R~) * FWHT( L~ ) mod 255.
     0<=product<256*255, so product is interpreted as unsigned. */
  ws_t product0 = ws_mullo( transformed0, ws_ld( fwht_l_twiddle_128         ) );
  ws_t product1 = ws_mullo( transformed1, ws_ld( fwht_l_twiddle_128 +  16UL ) );
  ws_t product2 = ws_mullo( transformed2, ws_ld( fwht_l_twiddle_128 +  32UL ) );
  ws_t product3 = ws_mullo( transformed3, ws_ld( fwht_l_twiddle_128 +  48UL ) );
  ws_t product4 = ws_mullo( transformed4, ws_ld( fwht_l_twiddle_128 +  64UL ) );
  ws_t product5 = ws_mullo( transformed5, ws_ld( fwht_l_twiddle_128 +  80UL ) );
  ws_t product6 = ws_mullo( transformed6, ws_ld( fwht_l_twiddle_128 +  96UL ) );
  ws_t product7 = ws_mullo( transformed7, ws_ld( fwht_l_twiddle_128 + 112UL ) );

  /* Compute mod 255, using the same approach as above. */
  product0 = ws_and( ws_bcast( 0xFF ), ws_add( product0, ws_shru( ws_mulhi( product0, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product1 = ws_and( ws_bcast( 0xFF ), ws_add( product1, ws_shru( ws_mulhi( product1, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product2 = ws_and( ws_bcast( 0xFF ), ws_add( product2, ws_shru( ws_mulhi( product2, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product3 = ws_and( ws_bcast( 0xFF ), ws_add( product3, ws_shru( ws_mulhi( product3, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product4 = ws_and( ws_bcast( 0xFF ), ws_add( product4, ws_shru( ws_mulhi( product4, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product5 = ws_and( ws_bcast( 0xFF ), ws_add( product5, ws_shru( ws_mulhi( product5, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product6 = ws_and( ws_bcast( 0xFF ), ws_add( product6, ws_shru( ws_mulhi( product6, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  product7 = ws_and( ws_bcast( 0xFF ), ws_add( product7, ws_shru( ws_mulhi( product7, ws_bcast( (short)0x8081 ) ), 7 ) ) );
  wb_t compact_product0 = compact_ws( product0, product1 );
  wb_t compact_product1 = compact_ws( product2, product3 );
  wb_t compact_product2 = compact_ws( product4, product5 );
  wb_t compact_product3 = compact_ws( product6, product7 );

  FD_REEDSOL_FWHT_128( compact_product0, compact_product1, compact_product2, compact_product3 );

  /* Negate the ones corresponding to erasures */
  compact_product0 = wb_if( wb_eq( erased_vec0, wb_zero() ), compact_product0, wb_sub( wb_bcast( 255 ), compact_product0 ) );
  compact_product1 = wb_if( wb_eq( erased_vec1, wb_zero() ), compact_product1, wb_sub( wb_bcast( 255 ), compact_product1 ) );
  compact_product2 = wb_if( wb_eq( erased_vec2, wb_zero() ), compact_product2, wb_sub( wb_bcast( 255 ), compact_product2 ) );
  compact_product3 = wb_if( wb_eq( erased_vec3, wb_zero() ), compact_product3, wb_sub( wb_bcast( 255 ), compact_product3 ) );

  wb_t pi0 = exp_4( compact_product0 );
  wb_t pi1 = exp_4( compact_product1 );
  wb_t pi2 = exp_4( compact_product2 );
  wb_t pi3 = exp_4( compact_product3 );
  wb_st( output,        pi0 );
  wb_st( output + 32UL, pi1 );
  wb_st( output + 64UL, pi2 );
  wb_st( output + 96UL, pi3 );
#endif
#else /* No AVX implementation */

  gen_pi_noavx_generic( is_erased, output, 128UL, fwht_l_twiddle_128 );

#endif
}

void
fd_reedsol_private_gen_pi_256( uchar const * is_erased,
                               uchar       * output ) {
#if FD_REEDSOL_ARITH_IMPL>0
#if FD_REEDSOL_PI_USE_SHORT
  ws_t erased_vec0  = _mm256_cvtepu8_epi16( vb_ld( is_erased         ) );
  ws_t erased_vec1  = _mm256_cvtepu8_epi16( vb_ld( is_erased +  16UL ) );
  ws_t erased_vec2  = _mm256_cvtepu8_epi16( vb_ld( is_erased +  32UL ) );
  ws_t erased_vec3  = _mm256_cvtepu8_epi16( vb_ld( is_erased +  48UL ) );
  ws_t erased_vec4  = _mm256_cvtepu8_epi16( vb_ld( is_erased +  64UL ) );
  ws_t erased_vec5  = _mm256_cvtepu8_epi16( vb_ld( is_erased +  80UL ) );
  ws_t erased_vec6  = _mm256_cvtepu8_epi16( vb_ld( is_erased +  96UL ) );
  ws_t erased_vec7  = _mm256_cvtepu8_epi16( vb_ld( is_erased + 112UL ) );
  ws_t erased_vec8  = _mm256_cvtepu8_epi16( vb_ld( is_erased + 128UL ) );
  ws_t erased_vec9  = _mm256_cvtepu8_epi16( vb_ld( is_erased + 144UL ) );
  ws_t erased_vec10 = _mm256_cvtepu8_epi16( vb_ld( is_erased + 160UL ) );
  ws_t erased_vec11 = _mm256_cvtepu8_epi16( vb_ld( is_erased + 176UL ) );
  ws_t erased_vec12 = _mm256_cvtepu8_epi16( vb_ld( is_erased + 192UL ) );
  ws_t erased_vec13 = _mm256_cvtepu8_epi16( vb_ld( is_erased + 208UL ) );
  ws_t erased_vec14 = _mm256_cvtepu8_epi16( vb_ld( is_erased + 224UL ) );
  ws_t erased_vec15 = _mm256_cvtepu8_epi16( vb_ld( is_erased + 240UL ) );

  ws_t transformed0 = erased_vec0;
  ws_t transformed1 = erased_vec1;
  ws_t transformed2 = erased_vec2;
  ws_t transformed3 = erased_vec3;
  ws_t transformed4 = erased_vec4;
  ws_t transformed5 = erased_vec5;
  ws_t transformed6 = erased_vec6;
  ws_t transformed7 = erased_vec7;
  ws_t transformed8 = erased_vec8;
  ws_t transformed9 = erased_vec9;
  ws_t transformed10 = erased_vec10;
  ws_t transformed11 = erased_vec11;
  ws_t transformed12 = erased_vec12;
  ws_t transformed13 = erased_vec13;
  ws_t transformed14 = erased_vec14;
  ws_t transformed15 = erased_vec15;
  FD_REEDSOL_FWHT_256( transformed0, transformed1, transformed2, transformed3, transformed4, transformed5, transformed6, transformed7,
      transformed8, transformed9, transformed10, transformed11, transformed12, transformed13, transformed14, transformed15 ); /* FWHT( R~ ) */
  /* |transformed| <= 256 */

  /* product is congruent to FWHT( R~) * FWHT( L~ ) mod 255 .
     -32512 <= product <= 32512 */
  ws_t product0  = ws_mullo( transformed0,  ws_ld( fwht_l_twiddle_256         ) );
  ws_t product1  = ws_mullo( transformed1,  ws_ld( fwht_l_twiddle_256 +  16UL ) );
  ws_t product2  = ws_mullo( transformed2,  ws_ld( fwht_l_twiddle_256 +  32UL ) );
  ws_t product3  = ws_mullo( transformed3,  ws_ld( fwht_l_twiddle_256 +  48UL ) );
  ws_t product4  = ws_mullo( transformed4,  ws_ld( fwht_l_twiddle_256 +  64UL ) );
  ws_t product5  = ws_mullo( transformed5,  ws_ld( fwht_l_twiddle_256 +  80UL ) );
  ws_t product6  = ws_mullo( transformed6,  ws_ld( fwht_l_twiddle_256 +  96UL ) );
  ws_t product7  = ws_mullo( transformed7,  ws_ld( fwht_l_twiddle_256 + 112UL ) );
  ws_t product8  = ws_mullo( transformed8,  ws_ld( fwht_l_twiddle_256 + 128UL ) );
  ws_t product9  = ws_mullo( transformed9,  ws_ld( fwht_l_twiddle_256 + 144UL ) );
  ws_t product10 = ws_mullo( transformed10, ws_ld( fwht_l_twiddle_256 + 160UL ) );
  ws_t product11 = ws_mullo( transformed11, ws_ld( fwht_l_twiddle_256 + 176UL ) );
  ws_t product12 = ws_mullo( transformed12, ws_ld( fwht_l_twiddle_256 + 192UL ) );
  ws_t product13 = ws_mullo( transformed13, ws_ld( fwht_l_twiddle_256 + 208UL ) );
  ws_t product14 = ws_mullo( transformed14, ws_ld( fwht_l_twiddle_256 + 224UL ) );
  ws_t product15 = ws_mullo( transformed15, ws_ld( fwht_l_twiddle_256 + 240UL ) );

  /* We need to reduce these mod 255 to prevent overflow in the next
     step. 0 <= product+128*255 <= 65152 < 2^16.  The mod operation
     treats the input as unsigned though, so this is okay (but hanging
     in there by a thread!). */
  product0  = ws_mod255( ws_add( product0,  ws_bcast( (short)128*255 ) ) );
  product1  = ws_mod255( ws_add( product1,  ws_bcast( (short)128*255 ) ) );
  product2  = ws_mod255( ws_add( product2,  ws_bcast( (short)128*255 ) ) );
  product3  = ws_mod255( ws_add( product3,  ws_bcast( (short)128*255 ) ) );
  product4  = ws_mod255( ws_add( product4,  ws_bcast( (short)128*255 ) ) );
  product5  = ws_mod255( ws_add( product5,  ws_bcast( (short)128*255 ) ) );
  product6  = ws_mod255( ws_add( product6,  ws_bcast( (short)128*255 ) ) );
  product7  = ws_mod255( ws_add( product7,  ws_bcast( (short)128*255 ) ) );
  product8  = ws_mod255( ws_add( product8,  ws_bcast( (short)128*255 ) ) );
  product9  = ws_mod255( ws_add( product9,  ws_bcast( (short)128*255 ) ) );
  product10 = ws_mod255( ws_add( product10, ws_bcast( (short)128*255 ) ) );
  product11 = ws_mod255( ws_add( product11, ws_bcast( (short)128*255 ) ) );
  product12 = ws_mod255( ws_add( product12, ws_bcast( (short)128*255 ) ) );
  product13 = ws_mod255( ws_add( product13, ws_bcast( (short)128*255 ) ) );
  product14 = ws_mod255( ws_add( product14, ws_bcast( (short)128*255 ) ) );
  product15 = ws_mod255( ws_add( product15, ws_bcast( (short)128*255 ) ) );

  /* Now 0 <= product < 255 */

  /* log_pi is congruent (mod 255) to what the paper calls
     R_w = FWHT( FWHT( L~ ) * FWHT( R~ ) ).
     If we do the FWHT in the normal way, it might overflow, so we need to inline it and stick a mod in the middle */
  ws_t log_pi0  = ws_mod255( ws_add( product0, product8  ) );  ws_t log_pi1 = ws_mod255( ws_add( product1, product9  ) );
  ws_t log_pi2  = ws_mod255( ws_add( product2, product10 ) );  ws_t log_pi3 = ws_mod255( ws_add( product3, product11 ) );
  ws_t log_pi4  = ws_mod255( ws_add( product4, product12 ) );  ws_t log_pi5 = ws_mod255( ws_add( product5, product13 ) );
  ws_t log_pi6  = ws_mod255( ws_add( product6, product14 ) );  ws_t log_pi7 = ws_mod255( ws_add( product7, product15 ) );
  ws_t log_pi8  = ws_mod255( ws_add( ws_sub( product0, product8 ), ws_bcast( (short)255*2 ) ) );
  ws_t log_pi9  = ws_mod255( ws_add( ws_sub( product1, product9 ), ws_bcast( (short)255*2 ) ) );
  ws_t log_pi10 = ws_mod255( ws_add( ws_sub( product2, product10 ), ws_bcast( (short)255*2 ) ) );
  ws_t log_pi11 = ws_mod255( ws_add( ws_sub( product3, product11 ), ws_bcast( (short)255*2 ) ) );
  ws_t log_pi12 = ws_mod255( ws_add( ws_sub( product4, product12 ), ws_bcast( (short)255*2 ) ) );
  ws_t log_pi13 = ws_mod255( ws_add( ws_sub( product5, product13 ), ws_bcast( (short)255*2 ) ) );
  ws_t log_pi14 = ws_mod255( ws_add( ws_sub( product6, product14 ), ws_bcast( (short)255*2 ) ) );
  ws_t log_pi15 = ws_mod255( ws_add( ws_sub( product7, product15 ), ws_bcast( (short)255*2 ) ) );

  FD_REEDSOL_FWHT_128( log_pi0, log_pi1, log_pi2,  log_pi3,  log_pi4,  log_pi5,  log_pi6,  log_pi7 );
  FD_REEDSOL_FWHT_128( log_pi8, log_pi9, log_pi10, log_pi11, log_pi12, log_pi13, log_pi14, log_pi15 );
  /* Now |log_pi| <= 128*255 */

  /* Negate the ones corresponding to erasures to compute 1/Pi' */
  log_pi0  = ws_adjust_sign( log_pi0,  ws_sub( ws_bcast( 1 ), ws_shl( erased_vec0,  1 ) ) );
  log_pi1  = ws_adjust_sign( log_pi1,  ws_sub( ws_bcast( 1 ), ws_shl( erased_vec1,  1 ) ) );
  log_pi2  = ws_adjust_sign( log_pi2,  ws_sub( ws_bcast( 1 ), ws_shl( erased_vec2,  1 ) ) );
  log_pi3  = ws_adjust_sign( log_pi3,  ws_sub( ws_bcast( 1 ), ws_shl( erased_vec3,  1 ) ) );
  log_pi4  = ws_adjust_sign( log_pi4,  ws_sub( ws_bcast( 1 ), ws_shl( erased_vec4,  1 ) ) );
  log_pi5  = ws_adjust_sign( log_pi5,  ws_sub( ws_bcast( 1 ), ws_shl( erased_vec5,  1 ) ) );
  log_pi6  = ws_adjust_sign( log_pi6,  ws_sub( ws_bcast( 1 ), ws_shl( erased_vec6,  1 ) ) );
  log_pi7  = ws_adjust_sign( log_pi7,  ws_sub( ws_bcast( 1 ), ws_shl( erased_vec7,  1 ) ) );
  log_pi8  = ws_adjust_sign( log_pi8,  ws_sub( ws_bcast( 1 ), ws_shl( erased_vec8,  1 ) ) );
  log_pi9  = ws_adjust_sign( log_pi9,  ws_sub( ws_bcast( 1 ), ws_shl( erased_vec9,  1 ) ) );
  log_pi10 = ws_adjust_sign( log_pi10, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec10, 1 ) ) );
  log_pi11 = ws_adjust_sign( log_pi11, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec11, 1 ) ) );
  log_pi12 = ws_adjust_sign( log_pi12, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec12, 1 ) ) );
  log_pi13 = ws_adjust_sign( log_pi13, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec13, 1 ) ) );
  log_pi14 = ws_adjust_sign( log_pi14, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec14, 1 ) ) );
  log_pi15 = ws_adjust_sign( log_pi15, ws_sub( ws_bcast( 1 ), ws_shl( erased_vec15, 1 ) ) );

  /* After the addition below, 0<= log_pi <= 65152 < 2^16. The mod
     brings it back to 0 <= log_pi < 255. */
  log_pi0  = ws_mod255( ws_add( log_pi0,  ws_bcast( (short)(255*128) ) ) );
  log_pi1  = ws_mod255( ws_add( log_pi1,  ws_bcast( (short)(255*128) ) ) );
  log_pi2  = ws_mod255( ws_add( log_pi2,  ws_bcast( (short)(255*128) ) ) );
  log_pi3  = ws_mod255( ws_add( log_pi3,  ws_bcast( (short)(255*128) ) ) );
  log_pi4  = ws_mod255( ws_add( log_pi4,  ws_bcast( (short)(255*128) ) ) );
  log_pi5  = ws_mod255( ws_add( log_pi5,  ws_bcast( (short)(255*128) ) ) );
  log_pi6  = ws_mod255( ws_add( log_pi6,  ws_bcast( (short)(255*128) ) ) );
  log_pi7  = ws_mod255( ws_add( log_pi7,  ws_bcast( (short)(255*128) ) ) );
  log_pi8  = ws_mod255( ws_add( log_pi8,  ws_bcast( (short)(255*128) ) ) );
  log_pi9  = ws_mod255( ws_add( log_pi9,  ws_bcast( (short)(255*128) ) ) );
  log_pi10 = ws_mod255( ws_add( log_pi10, ws_bcast( (short)(255*128) ) ) );
  log_pi11 = ws_mod255( ws_add( log_pi11, ws_bcast( (short)(255*128) ) ) );
  log_pi12 = ws_mod255( ws_add( log_pi12, ws_bcast( (short)(255*128) ) ) );
  log_pi13 = ws_mod255( ws_add( log_pi13, ws_bcast( (short)(255*128) ) ) );
  log_pi14 = ws_mod255( ws_add( log_pi14, ws_bcast( (short)(255*128) ) ) );
  log_pi15 = ws_mod255( ws_add( log_pi15, ws_bcast( (short)(255*128) ) ) );

  /* Since our FWHT implementation is unscaled, we've computed a value
     256 times larger than what we'd like.  256^-1==1^-1 == 1 (mod 255),
     so we don't need to do anything special. */

  wb_t compact_log_pi0 = compact_ws( log_pi0,  log_pi1  );
  wb_t compact_log_pi1 = compact_ws( log_pi2,  log_pi3  );
  wb_t compact_log_pi2 = compact_ws( log_pi4,  log_pi5  );
  wb_t compact_log_pi3 = compact_ws( log_pi6,  log_pi7  );
  wb_t compact_log_pi4 = compact_ws( log_pi8,  log_pi9  );
  wb_t compact_log_pi5 = compact_ws( log_pi10, log_pi11 );
  wb_t compact_log_pi6 = compact_ws( log_pi12, log_pi13 );
  wb_t compact_log_pi7 = compact_ws( log_pi14, log_pi15 );
  wb_t pi0 = exp_2( compact_log_pi0 );
  wb_t pi1 = exp_2( compact_log_pi1 );
  wb_t pi2 = exp_2( compact_log_pi2 );
  wb_t pi3 = exp_2( compact_log_pi3 );
  wb_t pi4 = exp_2( compact_log_pi4 );
  wb_t pi5 = exp_2( compact_log_pi5 );
  wb_t pi6 = exp_2( compact_log_pi6 );
  wb_t pi7 = exp_2( compact_log_pi7 );

  wb_st( output,         pi0 );
  wb_st( output +  32UL, pi1 );
  wb_st( output +  64UL, pi2 );
  wb_st( output +  96UL, pi3 );
  wb_st( output + 128UL, pi4 );
  wb_st( output + 160UL, pi5 );
  wb_st( output + 192UL, pi6 );
  wb_st( output + 224UL, pi7 );

#else
  wb_t erased_vec0 = wb_ld( is_erased         );
  wb_t erased_vec1 = wb_ld( is_erased +  32UL );
  wb_t erased_vec2 = wb_ld( is_erased +  64UL );
  wb_t erased_vec3 = wb_ld( is_erased +  96UL );
  wb_t erased_vec4 = wb_ld( is_erased + 128UL );
  wb_t erased_vec5 = wb_ld( is_erased + 160UL );
  wb_t erased_vec6 = wb_ld( is_erased + 192UL );
  wb_t erased_vec7 = wb_ld( is_erased + 224UL );
  wb_t to_transform0 = erased_vec0;
  wb_t to_transform1 = erased_vec1;
  wb_t to_transform2 = erased_vec2;
  wb_t to_transform3 = erased_vec3;
  wb_t to_transform4 = erased_vec4;
  wb_t to_transform5 = erased_vec5;
  wb_t to_transform6 = erased_vec6;
  wb_t to_transform7 = erased_vec7;

  FD_REEDSOL_FWHT_256( to_transform0, to_transform1, to_transform2, to_transform3,
                       to_transform4, to_transform5, to_transform6, to_transform7 );

  ws_t transformed0  = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform0, 0 ) );
  ws_t transformed1  = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform0, 1 ) );
  ws_t transformed2  = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform1, 0 ) );
  ws_t transformed3  = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform1, 1 ) );
  ws_t transformed4  = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform2, 0 ) );
  ws_t transformed5  = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform2, 1 ) );
  ws_t transformed6  = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform3, 0 ) );
  ws_t transformed7  = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform3, 1 ) );
  ws_t transformed8  = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform4, 0 ) );
  ws_t transformed9  = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform4, 1 ) );
  ws_t transformed10 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform5, 0 ) );
  ws_t transformed11 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform5, 1 ) );
  ws_t transformed12 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform6, 0 ) );
  ws_t transformed13 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform6, 1 ) );
  ws_t transformed14 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform7, 0 ) );
  ws_t transformed15 = _mm256_cvtepu8_epi16( _mm256_extracti128_si256( to_transform7, 1 ) );

  /* product is congruent to FWHT( R~) * FWHT( L~ ) mod 255.
     0<=product<256*255, so product is interpreted as unsigned. */
  ws_t product0  = ws_mod255( ws_mullo( transformed0,  ws_ld( fwht_l_twiddle_256         ) ) );
  ws_t product1  = ws_mod255( ws_mullo( transformed1,  ws_ld( fwht_l_twiddle_256 +  16UL ) ) );
  ws_t product2  = ws_mod255( ws_mullo( transformed2,  ws_ld( fwht_l_twiddle_256 +  32UL ) ) );
  ws_t product3  = ws_mod255( ws_mullo( transformed3,  ws_ld( fwht_l_twiddle_256 +  48UL ) ) );
  ws_t product4  = ws_mod255( ws_mullo( transformed4,  ws_ld( fwht_l_twiddle_256 +  64UL ) ) );
  ws_t product5  = ws_mod255( ws_mullo( transformed5,  ws_ld( fwht_l_twiddle_256 +  80UL ) ) );
  ws_t product6  = ws_mod255( ws_mullo( transformed6,  ws_ld( fwht_l_twiddle_256 +  96UL ) ) );
  ws_t product7  = ws_mod255( ws_mullo( transformed7,  ws_ld( fwht_l_twiddle_256 + 112UL ) ) );
  ws_t product8  = ws_mod255( ws_mullo( transformed8,  ws_ld( fwht_l_twiddle_256 + 128UL ) ) );
  ws_t product9  = ws_mod255( ws_mullo( transformed9,  ws_ld( fwht_l_twiddle_256 + 144UL ) ) );
  ws_t product10 = ws_mod255( ws_mullo( transformed10, ws_ld( fwht_l_twiddle_256 + 160UL ) ) );
  ws_t product11 = ws_mod255( ws_mullo( transformed11, ws_ld( fwht_l_twiddle_256 + 176UL ) ) );
  ws_t product12 = ws_mod255( ws_mullo( transformed12, ws_ld( fwht_l_twiddle_256 + 192UL ) ) );
  ws_t product13 = ws_mod255( ws_mullo( transformed13, ws_ld( fwht_l_twiddle_256 + 208UL ) ) );
  ws_t product14 = ws_mod255( ws_mullo( transformed14, ws_ld( fwht_l_twiddle_256 + 224UL ) ) );
  ws_t product15 = ws_mod255( ws_mullo( transformed15, ws_ld( fwht_l_twiddle_256 + 240UL ) ) );

  wb_t compact_product0 = compact_ws( product0,  product1  );
  wb_t compact_product1 = compact_ws( product2,  product3  );
  wb_t compact_product2 = compact_ws( product4,  product5  );
  wb_t compact_product3 = compact_ws( product6,  product7  );
  wb_t compact_product4 = compact_ws( product8,  product9  );
  wb_t compact_product5 = compact_ws( product10, product11 );
  wb_t compact_product6 = compact_ws( product12, product13 );
  wb_t compact_product7 = compact_ws( product14, product15 );

  FD_REEDSOL_FWHT_256( compact_product0, compact_product1, compact_product2, compact_product3,
                       compact_product4, compact_product5, compact_product6, compact_product7 );

  /* Negate the ones corresponding to erasures */
  compact_product0 = wb_if( wb_eq( erased_vec0, wb_zero() ), compact_product0, wb_sub( wb_bcast( 255 ), compact_product0 ) );
  compact_product1 = wb_if( wb_eq( erased_vec1, wb_zero() ), compact_product1, wb_sub( wb_bcast( 255 ), compact_product1 ) );
  compact_product2 = wb_if( wb_eq( erased_vec2, wb_zero() ), compact_product2, wb_sub( wb_bcast( 255 ), compact_product2 ) );
  compact_product3 = wb_if( wb_eq( erased_vec3, wb_zero() ), compact_product3, wb_sub( wb_bcast( 255 ), compact_product3 ) );
  compact_product4 = wb_if( wb_eq( erased_vec4, wb_zero() ), compact_product4, wb_sub( wb_bcast( 255 ), compact_product4 ) );
  compact_product5 = wb_if( wb_eq( erased_vec5, wb_zero() ), compact_product5, wb_sub( wb_bcast( 255 ), compact_product5 ) );
  compact_product6 = wb_if( wb_eq( erased_vec6, wb_zero() ), compact_product6, wb_sub( wb_bcast( 255 ), compact_product6 ) );
  compact_product7 = wb_if( wb_eq( erased_vec7, wb_zero() ), compact_product7, wb_sub( wb_bcast( 255 ), compact_product7 ) );

  wb_t pi0 = exp_2( compact_product0 );
  wb_t pi1 = exp_2( compact_product1 );
  wb_t pi2 = exp_2( compact_product2 );
  wb_t pi3 = exp_2( compact_product3 );
  wb_t pi4 = exp_2( compact_product4 );
  wb_t pi5 = exp_2( compact_product5 );
  wb_t pi6 = exp_2( compact_product6 );
  wb_t pi7 = exp_2( compact_product7 );
  wb_st( output,         pi0 );
  wb_st( output +  32UL, pi1 );
  wb_st( output +  64UL, pi2 );
  wb_st( output +  96UL, pi3 );
  wb_st( output + 128UL, pi4 );
  wb_st( output + 160UL, pi5 );
  wb_st( output + 192UL, pi6 );
  wb_st( output + 224UL, pi7 );
#endif
#else /* No AVX implementation */

  gen_pi_noavx_generic( is_erased, output, 256UL, fwht_l_twiddle_256 );

#endif
}
