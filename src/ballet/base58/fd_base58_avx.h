#include "../../util/simd/fd_avx.h"
#include <immintrin.h>

/* This is not a proper header and so should not be included from
   anywhere besides fd_base58.c and test_base58_avx.c.  As such, it has
   no include guard. */

#define wuc_t __m256i
static inline wuc_t wuc_ld(  uchar const * p   ) { return _mm256_load_si256(  (__m256i const *)p ); }
static inline wuc_t wuc_ldu( uchar const * p   ) { return _mm256_loadu_si256( (__m256i const *)p ); }
static inline void wuc_st(  uchar * p, wuc_t i ) { _mm256_store_si256(  (__m256i *)p, i ); }
static inline void wuc_stu( uchar * p, wuc_t i ) { _mm256_storeu_si256( (__m256i *)p, i ); }

/* Converts a vector with 4 terms in intermediate form ( digits in
   [0,58^5) ) into 20 digits of raw base58 (<58) stored in two groups of
   10 in the lower 10 bytes of each 128-bit half of the vector. */

static inline wuc_t
intermediate_to_raw( wl_t intermediate ) {

  /* The computation we need to do here mathematically is
     y=(floor(x/58^k) % 58) for various values of k.  It seems that the
     best way to compute it (at least what the compiler generates in the
     scalar case) is by computing z = floor(x/58^k). y = z -
     58*floor(z/58).  Simplifying, gives, y = floor(x/58^k) -
     58*floor(x/58^(k+1)) (Note, to see that the floors simplify like
     that, represent x in its base58 expansion and then consider that
     dividing by 58^k is just shifting right by k places.) This means we
     can reuse a lot of values!

     We can do the divisions with "magic multiplication" (i.e. multiply
     and shift).  There's a tradeoff between ILP and register pressure
     to make here: we can load a constant for each value of k and just
     compute the division directly, or we could use one constant for
     division by 58 and apply it repeatedly.  I don't know if this is
     optimal, but I use two constants, one for /58 and the other for
     /58^2.  We need to take advantage of the fact the input is
     <58^5<2^32 to produce constants that fit in uints so that we can
     use mul_epu32. */

  wl_t cA  = wl_bcast( (long)2369637129U ); /* =2^37/58 */
  wl_t cB  = wl_bcast( (long)1307386003U ); /* =2^42/58^2 */
  wl_t _58 = wl_bcast( (long)58UL );

  /* Divide each ulong in r by {58, 58^2=3364}, taking the floor of the
     division.  I used gcc to convert the division to magic
     multiplication. */

# define DIV58(r)    wl_shru( _mm256_mul_epu32( r,               cA ), 37)
# define DIV3364(r)  wl_shru( _mm256_mul_epu32( wl_shru( r, 2 ), cB ), 40)

  /* div(k) stores floor(x/58^k). rem(k) stores div(k) % 58 */
  wl_t div0 = intermediate;
  wl_t div1 = DIV58(div0);
  wl_t rem0 = wl_sub( div0, _mm256_mul_epu32( div1, _58 ) );

  wl_t div2 = DIV3364(div0);
  wl_t rem1 = wl_sub( div1, _mm256_mul_epu32( div2, _58 ) );

  wl_t div3 = DIV3364(div1);
  wl_t rem2 = wl_sub( div2, _mm256_mul_epu32( div3, _58 ) );

  wl_t div4 = DIV3364(div2);
  wl_t rem3 = wl_sub( div3, _mm256_mul_epu32( div4, _58 ) );

  wl_t rem4 = div4; /* We know the values are less than 58 at this point */

# undef DIV58
# undef DIV3364

  /* Okay, we have all 20 terms we need at this point, but they're
     spread out over 5 registers. Each value is stored as an 8B long,
     even though it's less than 58, so 7 of those bytes are 0.  That
     means we're only taking up 4 bytes in each register.  We need to
     get them to a more compact form, but the correct order (in terms of
     place value and recalling where the input vector comes from) is:
     (letters in the right column correspond to diagram below)

        the first value in rem4  (a)
        the first value in rem3  (b)
        ...
        the first value in rem0  (e)
        the second value in rem4 (f)
        ...
        the fourth value in rem0 (t)

     The fact that moves that cross the 128 bit boundary are tricky in
     AVX makes this difficult, forcing an inconvenient output format.

     First, we'll use _mm256_shuffle_epi8 to move the second value in
     each half to byte 5:

       [ a 0 0 0 0 0 0 0  f 0 0 0 0 0 0 0 | k 0 0 0 0 0 0 0  p 0 0 0 0 0 0 0 ] ->
       [ a 0 0 0 0 f 0 0  0 0 0 0 0 0 0 0 | k 0 0 0 0 p 0 0  0 0 0 0 0 0 0 0 ]

     Then for the vectors other than rem4, we'll shuffle them the same
     way, but then shift them left (which corresponds to right in the
     picture...) and OR them together.  */

  __m256i shuffle1 = _mm256_setr_epi8( 0, 1, 1, 1, 1, 8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                       0, 1, 1, 1, 1, 8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 );

  wuc_t shift4 =                    _mm256_shuffle_epi8( rem4, shuffle1);
  wuc_t shift3 = _mm256_slli_si256( _mm256_shuffle_epi8( rem3, shuffle1), 1);
  wuc_t shift2 = _mm256_slli_si256( _mm256_shuffle_epi8( rem2, shuffle1), 2);
  wuc_t shift1 = _mm256_slli_si256( _mm256_shuffle_epi8( rem1, shuffle1), 3);
  wuc_t shift0 = _mm256_slli_si256( _mm256_shuffle_epi8( rem0, shuffle1), 4);
  wuc_t shift  = _mm256_or_si256( _mm256_or_si256(
                                      _mm256_or_si256( shift4, shift3),
                                      _mm256_or_si256( shift2, shift1) ),
                                  shift0 );

  /* The final value is:
    [ a b c d e f g h i j 0 0 0 0 0 0 | k l m n o p q r s t 0 0 0 0 0 0 ]
    */

  return shift;
}

/* Converts each byte in the AVX2 register from raw base58 [0,58) to
   base58 digits ('1'-'z', with some skips).  Anything not in the range
   [0, 58) will be mapped arbitrarily, but won't affect other bytes. */

static inline wuc_t raw_to_base58( wuc_t in ) {

  /* <30 cycles for two vectors (64 conversions) */
  /* We'll perform the map as an arithmetic expression,
     b58ch(x) = '1' + x + 7*[x>8] + [x>16] + [x>21] + 6*[x>32] + [x>43]
     (using Knuth bracket notation, which maps true/false to 1/0).

     cmpgt uses 0xFF for true and 0x00 for false.  This is very
     convenient, because most of the time we just want to skip one
     character, so we can add 1 by subtracting 0xFF (=-1). */

  __m256i gt0 = _mm256_cmpgt_epi8( in, _mm256_set1_epi8( 8) ); /* skip 7 */
  __m256i gt1 = _mm256_cmpgt_epi8( in, _mm256_set1_epi8(16) );
  __m256i gt2 = _mm256_cmpgt_epi8( in, _mm256_set1_epi8(21) );
  __m256i gt3 = _mm256_cmpgt_epi8( in, _mm256_set1_epi8(32) ); /* skip 6*/
  __m256i gt4 = _mm256_cmpgt_epi8( in, _mm256_set1_epi8(43) );

  /* Intel doesn't give us an epi8 multiplication instruction, but since
     we know the input is all in {0, -1}, we can just AND both values
     with -7 to get {0, -7}. Similarly for 6. */

  __m256i gt0_7 = _mm256_and_si256( gt0, _mm256_set1_epi8( -7 ) );
  __m256i gt3_6 = _mm256_and_si256( gt3, _mm256_set1_epi8( -6 ) );

  /* Add up all the negative offsets. */
  __m256i sum = _mm256_add_epi8(
                  _mm256_add_epi8(
                    _mm256_add_epi8( _mm256_set1_epi8( -'1' ), gt1 ), /* Yes, that's the negative character value of '1' */
                    _mm256_add_epi8( gt2,                      gt4 ) ),
                  _mm256_add_epi8(   gt0_7,                    gt3_6 ) );

  return _mm256_sub_epi8( in, sum );
}

/* count_leading_zeros_{n} counts the number of zero bytes prior to the
   first non-zero byte in the first n bytes.  If all n bytes are zero,
   returns n.  Return value is in [0, n].  For the two-vector cases, in0
   contains the first 32 bytes and in1 contains the second 32 bytes. */

static inline ulong
count_leading_zeros_26( wuc_t in ) {
  ulong mask0 = (ulong)(uint)_mm256_movemask_epi8( _mm256_cmpeq_epi8( in, _mm256_setzero_si256() ));
  ulong mask  = fd_ulong_mask_lsb( 27 ) ^ (mask0 & fd_ulong_mask_lsb( 26 )); /* Flips the low 26 bits and puts a 1 in bit 26 */
  return (ulong)fd_ulong_find_lsb( mask );
}

static inline ulong
count_leading_zeros_32( wuc_t in ) {
  ulong mask = fd_ulong_mask_lsb( 33 ) ^ (ulong)(uint)_mm256_movemask_epi8( _mm256_cmpeq_epi8( in, _mm256_setzero_si256() ));
  return (ulong)fd_ulong_find_lsb( mask );
}

static inline ulong
count_leading_zeros_45( wuc_t in0,
                        wuc_t in1 ) {
  ulong mask0 = (ulong)(uint)_mm256_movemask_epi8( _mm256_cmpeq_epi8( in0, _mm256_setzero_si256() ));
  ulong mask1 = (ulong)(uint)_mm256_movemask_epi8( _mm256_cmpeq_epi8( in1, _mm256_setzero_si256() ));
  ulong mask = fd_ulong_mask_lsb( 46 ) ^ (((mask1 & fd_ulong_mask_lsb( 13 ))<<32) | mask0);
  return (ulong)fd_ulong_find_lsb( mask );
}

static inline ulong
count_leading_zeros_64( wuc_t in0,
                        wuc_t in1 ) {
  ulong mask0 = (ulong)(uint)_mm256_movemask_epi8( _mm256_cmpeq_epi8( in0, _mm256_setzero_si256() ));
  ulong mask1 = (ulong)(uint)_mm256_movemask_epi8( _mm256_cmpeq_epi8( in1, _mm256_setzero_si256() ));
  ulong mask = ~((mask1<<32) | mask0);
  return (ulong)fd_ulong_find_lsb_w_default( mask, 64 );
}

/* ten_per_slot_down_{32,64}: Packs {45,90} raw base58 digits stored in
   the bizarre groups of 10 format from intermediate_to_raw into {2,3}
   AVX2 registers with the digits stored contiguously. */

/* In this diagram, one letter represents one byte.
    [ aaaaaaaaaa000000 bbbbbbbbbb000000 ]
                                        [ cccccccccc000000 dddddddddd000000 ]
                                                                            [ eeeee00000000000 0 ]
    [ aaaaaaaaaa000000 ]
    [ 0000000000bbbbbb ] ( >> 10B)
                     [ bbbb000000000000 ] (<< 6B)
                     [ 0000cccccccccc00 ] (>> 4B)
                     [ 00000000000000dd ] (>> 14B)
                                        [ dddddddd00000000 ] (<< 2)
                                        [ 00000000eeeee000 ] (>> 8)
        0                   1                   2
    In the diagram above, memory addresses increase from left to right.
    AVX instructions see the world from a little-endian perspective,
    where shifting left by one byte increases the numerical value, which
    is equivalent to moving the data one byte later in memory, which
    would show in the diagram as moving the values to the right. */

#define ten_per_slot_down_32( in0, in1, in2, out0, out1 )                           \
  do {                                                                              \
    __m128i lo0 = _mm256_extractf128_si256( in0, 0 );                               \
    __m128i hi0 = _mm256_extractf128_si256( in0, 1 );                               \
    __m128i lo1 = _mm256_extractf128_si256( in1, 0 );                               \
    __m128i hi1 = _mm256_extractf128_si256( in1, 1 );                               \
    __m128i lo2 = _mm256_extractf128_si256( in2, 0 );                               \
                                                                                    \
    __m128i o0 = _mm_or_si128( lo0, _mm_slli_si128( hi0, 10 ));                     \
    __m128i o1 = _mm_or_si128( _mm_or_si128(                                        \
                                    _mm_srli_si128( hi0, 6 ),                       \
                                    _mm_slli_si128( lo1, 4 )                        \
                                    ), _mm_slli_si128( hi1, 14 ));                  \
    __m128i o2 = _mm_or_si128( _mm_srli_si128( hi1, 2 ), _mm_slli_si128( lo2, 8 )); \
    out0 = _mm256_set_m128i( o1, o0 );                                              \
    out1 = _mm256_set_m128i( _mm_setzero_si128( ), o2 );                            \
  } while( 0 )

/* In this diagram, one letter represents one byte.
   (... snip (see diagram above) ... )
    [ eeeeeeeeee000000 ffffffffff000000 ]
                                        [ gggggggggg000000 hhhhhhhhhh000000 ]
                                                                            [ iiiiiiiiii000000 0 ]
    [ 00000000eeeeeeee ] (>> 8)
                     [ ee00000000000000 ] (<< 8)
                     [ 00ffffffffff0000 ] (>> 2)
                     [ 000000000000gggg ] (>> 12)
                                        [ gggggg0000000000 ] (<< 4)
                                        [ 000000hhhhhhhhhh ] (>> 6)
                                                           [ iiiiiiiiii000000 ]
          2               3                   4                   5
*/

#define ten_per_slot_down_64( in0, in1, in2, in3, in4, out0, out1, out2 )           \
  do {                                                                              \
    __m128i lo0 = _mm256_extractf128_si256( in0, 0 );                               \
    __m128i hi0 = _mm256_extractf128_si256( in0, 1 );                               \
    __m128i lo1 = _mm256_extractf128_si256( in1, 0 );                               \
    __m128i hi1 = _mm256_extractf128_si256( in1, 1 );                               \
    __m128i lo2 = _mm256_extractf128_si256( in2, 0 );                               \
    __m128i hi2 = _mm256_extractf128_si256( in2, 1 );                               \
    __m128i lo3 = _mm256_extractf128_si256( in3, 0 );                               \
    __m128i hi3 = _mm256_extractf128_si256( in3, 1 );                               \
    __m128i lo4 = _mm256_extractf128_si256( in4, 0 );                               \
                                                                                    \
    __m128i o0 = _mm_or_si128( lo0, _mm_slli_si128( hi0, 10 ));                     \
    __m128i o1 = _mm_or_si128( _mm_or_si128(                                        \
                                    _mm_srli_si128( hi0, 6 ),                       \
                                    _mm_slli_si128( lo1, 4 )                        \
                                    ), _mm_slli_si128( hi1, 14 ));                  \
    __m128i o2 = _mm_or_si128( _mm_srli_si128( hi1, 2 ), _mm_slli_si128( lo2, 8 )); \
    __m128i o3 = _mm_or_si128( _mm_or_si128(                                        \
                                    _mm_srli_si128( lo2, 8 ),                       \
                                    _mm_slli_si128( hi2, 2 )                        \
                                    ), _mm_slli_si128( lo3, 12 ));                  \
    __m128i o4 = _mm_or_si128( _mm_srli_si128( lo3, 4 ), _mm_slli_si128( hi3, 6 )); \
    out0 = _mm256_set_m128i( o1, o0  );                                             \
    out1 = _mm256_set_m128i( o3, o2  );                                             \
    out2 = _mm256_set_m128i( lo4, o4 );                                             \
  } while( 0 )

