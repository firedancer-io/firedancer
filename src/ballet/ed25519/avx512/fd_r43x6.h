#ifndef HEADER_fd_src_ballet_ed25519_avx512_r43x6_h
#define HEADER_fd_src_ballet_ed25519_avx512_r43x6_h

#if FD_HAS_AVX512

#include "../../../util/simd/fd_avx.h"
#include <x86intrin.h>

/* A r43x6_t represents a GF(p) element, where p = 2^255-19, in a little
   endian 6 long radix 2^43 limb representation.  The 6 limbs are held
   in the lanes of an AVX-512 vector.  That is, given a r43x6_t x, the
   field element represented by x is:

     ( x0 + x1 2^43 + x2 2^86 + x3 2^129 + x4 2^172 + x5 2^215 ) mod p

   where xn is the n-th 64-bit vector lane treated as a long.  Lanes 6
   and 7 are ignored.  The below will often use the shorthand:

     <x0,x1,x2,x3,x4,x5>

   for the above expression.

   This representation is redundant: multiple r43x6_t can represent the
   same element.  Most functions have restrictions on the which
   representations can be used for inputs and which representations they
   produce to support high performance implementation and composability.

   Frequently used representations are:

   - arbitrary:      limbs     are in [-2^63,2^63)
   - signed:         limbs     are in [-2^62,2^62)
   - unsigned:       limbs     are in [0,2^62)
   - unreduced:      limbs     are in [0,2^47)
   - unpacked:       limbs 0-4 are in [0,2^43), limb 5 is in [0,2^41)
   - nearly reduced: limbs 0-4 are in [0,2^43), limb 5 is in [0,2^41), the packed uint256 value is in [0,2*p)
   - reduced:        limbs 0-4 are in [0,2^43), limb 5 is in [0,2^40), the packed uint256 value is in [0,p)

   Note:

   - There is only one reduced r43x6_t for each element.

   - There are two nearly reduced r43x6_t for each element.

   - reduced is a subset of nearly reduced is a subset of unpacked is a
     subset of unreduced is a subset of unsigned is a subset of signed
     is a subset arbitrary.

   - unpacked, nearly reduced and reduced r43x6_t be quickly converted
     into a packed uint256 value used by various cryptographic protocols
     and vice versa.

   - Cheat sheat:

       unpack maps uint256 to unpacked
       pack   maps unpacked to uint256

       * These are used to interface with external protocols.

       fold_unsigned maps unsigned to unreduced
       fold_signed   maps   signed to unreduced

       * fold_* are fast and typically used to keep the ranges of limbs
         reasonable in long running calculations without needing to do
         more expensive approx_mod_* or mod_* operations.

       approx_mod           maps arbitrary to nearly reduced
       approx_mod_signed    maps signed    to nearly reduced
       approx_mod_unsigned  maps unsigned  to nearly reduced
       approx_mod_unreduced maps unreduced to nearly reduced
       approx_mod_unpacked  maps unpacked  to nearly reduced

       * approx_mod_* are typically used to get inputs to a long running
         calculation into a suitable form or by mod_* below.

       mod                maps arbitrary      to reduced (equiv to approx_mod           / mod_nearly_reduced)
       mod_signed         maps signed         to reduced (equiv to approx_mod_signed    / mod_nearly_reduced)
       mod_unsigned       maps unsigned       to reduced (equiv to approx_mod_unsigned  / mod_nearly_reduced)
       mod_unreduced      maps unreduced      to reduced (equiv to approx_mod_unreduced / mod_nearly_reduced)
       mod_unpacked       maps unpacked       to reduced (equiv to approx_mod_unpacked  / mod_nearly_reduced)
       mod_nearly_reduced maps nearly reduced to reduced

       * mod_* are typically used for produce a final unique result at
         the end of a long running calculation.

       add    maps unreduced x unreduced to unsigned (among others), see fold_* above
       sub    maps unreduced x unreduced to   signed (among others), see fold_* above
       mul    maps unreduced x unreduced to unreduced
       sqr    maps unreduced to unreduced
       repsqr maps unreduced to unreduced
       scale  maps [0,2^47) x unreduced to unreduced
       invert maps unreduced to unreduced

       * These are used to implement HPC calculations on GF(p) elements. */

#define r43x6_t __m512i

FD_PROTOTYPES_BEGIN

/* r43x6(x0,x1,x2,x3,x4,x5) constructs an arbitrary r43x6_t from the
   given limbs.  Lanes 6 and 7 will be zero.  This macro is robust.
   Note: implementing via setr was benchmarked as slightly faster than
   loading from a stack tmp (probably due to better compiler code gen). */

#define r43x6(x0,x1,x2,x3,x4,x5) _mm512_setr_epi64( (x0),(x1),(x2),(x3),(x4),(x5), 0L,0L )

/* r43x6_extract_limbs(x,y) extracts the limbs of an arbitrary r43x6_t x
   into the longs y0-y5.  This is primarily for use in operations that
   are not vectorized.  This macro is robust.  Note: implementing via
   extract was benchmarked as slightly faster than storing to a stack
   tmp and reloading (probably due to better compiler code gen). */

#define r43x6_extract_limbs(x,y) do {                 \
    __m512i _x = (x);                                 \
    __m256i _xl = _mm512_extracti64x4_epi64( _x, 0 ); \
    __m256i _xh = _mm512_extracti64x4_epi64( _x, 1 ); \
    y##0 = _mm256_extract_epi64( _xl, 0 );            \
    y##1 = _mm256_extract_epi64( _xl, 1 );            \
    y##2 = _mm256_extract_epi64( _xl, 2 );            \
    y##3 = _mm256_extract_epi64( _xl, 3 );            \
    y##4 = _mm256_extract_epi64( _xh, 0 );            \
    y##5 = _mm256_extract_epi64( _xh, 1 );            \
  } while(0)

/* r43x6_zero() and r43x6_one() returns the reduced r43x6_t for zero and
   one.  These macros are robust.  Lanes 6 and 7 will be zero. */

#define r43x6_zero() _mm512_setzero_si512()
#define r43x6_one()  _mm512_setr_epi64( 1L,0L,0L,0L,0L,0L, 0L,0L )

/* r43x6_unpack(u) returns an unpacked r43x6_t corresponding to an
   arbitrary uint256 stored little endian 4 ulong radix 2^64 limb
   representation held in an AVX-2 vector:

     u = u0 + u1 2^64 + u2 2^128 + u3 2^192

   where un is the n-th 64-bit vector lane treated as a ulong.  Returned
   lanes 6 and 7 will be zero.  If u is in [0,2*p), the return will be a
   nearly reduced r43x6_t.  If u is in [0,p), the return will be a
   reduced r43x6_t. */

FD_FN_CONST static inline r43x6_t
r43x6_unpack( wv_t u ) {
  __m512i const zero   = _mm512_setzero_si512();
  __m512i const perm   = _mm512_setr_epi64( 0x3f3f050403020100UL,   // r0 = bits   0: 42 (43 bits, zero extend to 64 bits)
                                            0x3f3f0a0908070605UL,   // r1 = bits  43: 85 (43 bits, zero extend to 64 bits)
                                            0x3f100f0e0d0c0b0aUL,   // r2 = bits  86:128 (43 bits, zero extend to 64 bits)
                                            0x3f3f151413121110UL,   // r3 = bits 129:171 (43 bits, zero extend to 64 bits)
                                            0x3f3f1a1918171615UL,   // r4 = bits 172:214 (43 bits, zero extend to 64 bits)
                                            0x3f3f1f1e1d1c1b1aUL,   // r5 = bits 215:255 (41 bits, zero extend to 64 bits)
                                            0x3f3f3f3f3f3f3f3fUL,   // r6 = zero
                                            0x3f3f3f3f3f3f3f3fUL ); // r7 = zero
  __m512i const rshift = _mm512_setr_epi64( 0L, 3L, 6L, 1L, 4L, 7L, 0L, 0L ); // r0/r1/r2/r3/r4/r5 bit 0 is u bit 0/43/86/129/172
  __m512i const mask   = _mm512_set1_epi64( (1L<<43)-1L );                    // Keep 43 least significant bits for each lane
  return _mm512_and_epi64( _mm512_srlv_epi64( _mm512_permutexvar_epi8( perm, _mm512_inserti64x4( zero, u, 0 ) ), rshift ), mask );
}

/* r43x6_pack(r) is the inverse of r43x6_unpack.  r should be an
   unpacked r43x6_t.  If r is also nearly reduced, the return will be in
   [0,2*p).  If r is also reduced r43x6_t, the return will be in [0,p).
   Ignores lanes 6 and 7. */

FD_FN_CONST static inline wv_t
r43x6_pack( r43x6_t r ) {

  /*                  43              21
                0            42 43          63
     u0 =       r0_0  ... r0_42 r1_0 ... r1_20

                      22              42
                0            21 22          63
     u1 =       r1_21 ... r1_42 r2_0 ... r2_41

            1         43              20
            0   1            43 44          63
     u2 = r2_42 r3_0  ... r3_42 r4_0 ... r4_19

                      23              41
                0            22 23          63
     u3 =       r4_20 ... r3_42 r5_0 ... r5_40

             t0         t1         t2
     u0 = (r0>> 0) | (r1<<43) | (r1<<43); ... Last term redundant to keep vectorized
     u1 = (r1>>21) | (r2<<22) | (r2<<22); ... "
     u2 = (r2>>42) | (r3<< 1) | (r4<<44);
     u3 = (r4>>20) | (r5<<23) | (r5<<23); ... " */

  __m512i t0 = _mm512_srlv_epi64( _mm512_permutexvar_epi64( _mm512_setr_epi64(  0L, 1L, 2L, 4L, 0L,0L,0L,0L ), r ),
                                                            _mm512_setr_epi64(  0L,21L,42L,20L, 0L,0L,0L,0L ) );
  __m512i t1 = _mm512_sllv_epi64( _mm512_permutexvar_epi64( _mm512_setr_epi64(  1L, 2L, 3L, 5L, 0L,0L,0L,0L ), r ),
                                                            _mm512_setr_epi64( 43L,22L, 1L,23L, 0L,0L,0L,0L ) );
  __m512i t2 = _mm512_sllv_epi64( _mm512_permutexvar_epi64( _mm512_setr_epi64(  1L, 2L, 4L, 5L, 0L,0L,0L,0L ), r ),
                                                            _mm512_setr_epi64( 43L,22L,44L,23L, 0L,0L,0L,0L ) );

  return _mm512_extracti64x4_epi64( _mm512_or_epi64( _mm512_or_epi64( t0, t1 ), t2 ), 0 );
}

/* r43x6_approx_carry_propagate_limbs(x,y) computes a signed r43x6_t
   equivalent to an arbitrary r43x6_t that has been extracted into the
   longs x0-x5 and stores the result into the longs y0-y5.  On return:

     y0    in [-19*2^23,2^43+19*(2^23-1))
     y1-y4 in [   -2^20,2^43+   (2^20-1))
     y5    in [   -2^20,2^40+   (2^20-1))

   In-place operation fine.  This macro is robust.

   If x is unsigned or more generally x0-x5 in [0,2^63), the result will
   be an unreduced r43x6_t with:

     y0    in [0,2^43+19*(2^23-1))
     y1-y4 in [0,2^43+   (2^20-1))
     y5    in [0,2^40+   (2^20-1))

   Theory:

     x = <x0,x1,x2,x3,x4,x5>
       = <x0l,x1l,x2l,x3l,x4l,x5l> + <2^43*x0h,2^43*x1h,2^43*x2h,2^43*x3h,2^43*x4h,2^40*x5h>
       = <x0l,x1l,x2l,x3l,x4l,x5l> + <19*x5h,x0h,x1h,x2h,x3h,x4h>

   where x0h=floor(x0/2^43) and x0l = x0-2^43*x0h and similarly for
   x1-x4 while x5h = floor(x5/2^40) and x5l=x5-2^40*x5h.

   Above we used:

     2^215*2^40*x5h = 2^255*x5h = (p+19)*x5h mod p = 19*x5h mod p.

   Equivalently, x0l-x5l are the least significant {43,43,43,43,43,40}
   bits of x0-x5 and x0h-x5l are the sign extending right shifts of
   x0-x5 by the same.

   For arbitrary x we have:

     x0l-x4l in [0,2^43), x0h-x4h in [-2^20,2^20)
     x5l     in [0,2^40), x5h     in [-2^23,2^23)

   while for x0-x5 in [0,2^63) (which includes unsigned) we have:

     x0l-x4l in [0,2^43), x0h-x4h in [0,2^20)
     x5l     in [0,2^40), x5h     in [0,2^23)

   This yields the above ranges for y0-y5.  There are no intermediate
   overflows in the computation.

   This is a building block for more complex mappings where x's limbs
   have already been extracted in order to minimize the number of limb
   extracts and r43x6 constructs.

   Note that if we used ulongs (and thus zero padding right shifts)
   below, this same style calculation could be used on an arbitrary
   _ulong_ limbed x.  The result would still be an unreduced r43x6_t
   with:

     y0-y4 in [0,2^43+19*(2^24-1))
     y5    in [0,2^40+    2^21-1 ) */

#define r43x6_approx_carry_propagate_limbs(x,y) do { \
    long const _m43 = (1L<<43)-1L;                   \
    long const _m40 = (1L<<40)-1L;                   \
    long _x0 = (x##0);                               \
    long _x1 = (x##1);                               \
    long _x2 = (x##2);                               \
    long _x3 = (x##3);                               \
    long _x4 = (x##4);                               \
    long _x5 = (x##5);                               \
    (y##0) = (_x0 & _m43) + 19L*(_x5>>40);           \
    (y##1) = (_x1 & _m43) +     (_x0>>43);           \
    (y##2) = (_x2 & _m43) +     (_x1>>43);           \
    (y##3) = (_x3 & _m43) +     (_x2>>43);           \
    (y##4) = (_x4 & _m43) +     (_x3>>43);           \
    (y##5) = (_x5 & _m40) +     (_x4>>43);           \
  } while(0)

/* r43x6_approx_carry_propagate is a vectorized version of the above.
   Returned lanes 6 and 7 are zero.  If we've already extracted x's
   limbs and/or need the resulting limbs after, it is usually faster to
   do the extract and then use the scalar implementation.

   The fold_unsigned variant is the same but assumes x is unsigned or
   more generally x0-x5 in [0,2^63).  This allows a faster madd52lo to
   be used instead of a slower mullo.  (Hat tip to Philip Taffet for
   pointing this out.)

   The fold_signed variant assumes x is signed or more generally:

     x0    in [-2^63+19*2^23,2^63)
     x1-x5 in [-2^63   +2^20,2^63)

   and subtracts x by <19*2^23,2^20,2^20,2^20,2^20,2^20> (which will not
   overflow) before the approx carry propagate and add it back after.
   This will not overflow and will not change the element represented.
   But it does yield an unreduced result with limbs:

     y0    in [0,2^43+19*(2^24-1))
     y1-y4 in [0,2^43+   (2^21-1))
     y5    in [0,2^40+   (2^21-1))

   These variants are particularly useful for mapping results of a
   additions and subtractions into unreduced results for subsequent
   operations. */

#if 0 /* A mullo based implementation is slightly slower ... */
#define r43x6_approx_carry_propagate( x ) (__extension__({                                                         \
    long const _m43 = (1L<<43)-1L;                                                                                 \
    long const _m40 = (1L<<40)-1L;                                                                                 \
    __m512i    _x   = (x);                                                                                         \
    _mm512_add_epi64( _mm512_and_epi64( _x, _mm512_setr_epi64( _m43,_m43,_m43,_m43,_m43,_m40, 0L,0L ) ),           \
                      _mm512_mullo_epi64( _mm512_setr_epi64( 19L,1L,1L,1L,1L,1L, 0L,0L ),                          \
                                          _mm512_permutexvar_epi64( _mm512_setr_epi64( 5L,0L,1L,2L,3L,4L, 6L,7L ), \
                                              _mm512_srav_epi64( _x, _mm512_setr_epi64( 43L,43L,43L,43L,43L,40L, 0L,0L ) ) ) ) ); \
  }))
#else /* ... than a more obtuse shift-and-add based implementation */
#define r43x6_approx_carry_propagate( x ) (__extension__({                                                                     \
    long const _m43 = (1L<<43)-1L;                                                                                             \
    long const _m40 = (1L<<40)-1L;                                                                                             \
    __m512i    _x   = (x);                                                                                                     \
    __m512i    _xl  = _mm512_and_epi64( _x, _mm512_setr_epi64( _m43,_m43,_m43,_m43,_m43,_m40, 0L,0L ) );                       \
    __m512i    _xh  = _mm512_srav_epi64( _x, _mm512_setr_epi64( 43L,43L,43L,43L,43L,40L, 0L,0L ) );                            \
    __m512i    _c   = _mm512_permutex2var_epi64( _xh, _mm512_setr_epi64( 5L,0L,1L,2L,3L,4L, 8L,8L ), _mm512_setzero_si512() ); \
    __m512i    _d   = _mm512_and_epi64( _mm512_add_epi64( _mm512_slli_epi64( _c, 1 ), _mm512_slli_epi64( _c, 4 ) ),            \
                                        _mm512_setr_epi64( -1L,0L,0L,0L,0L,0L, 0L,0L ) );                                      \
    /* _xl = <   x0l,x1l,x2l,x3l,x4l,x5l, 0,0> */                                                                              \
    /* _c  = <   x5h,x0h,x1h,x2h,x3h,x4h, 0,0> */                                                                              \
    /* _d  = <18*x5h,  0,  0,  0,  0,  0, 0,0> */                                                                              \
    _mm512_add_epi64( _mm512_add_epi64( _xl, _c ), _d );                                                                       \
  }))
#endif

#define r43x6_fold_unsigned( x ) (__extension__({                                                             \
    long const _m43 = (1L<<43)-1L;                                                                            \
    long const _m40 = (1L<<40)-1L;                                                                            \
    __m512i    _x   = (x);                                                                                    \
    _mm512_madd52lo_epu64( _mm512_and_epi64( _x, _mm512_setr_epi64( _m43,_m43,_m43,_m43,_m43,_m40, 0L,0L ) ), \
                           _mm512_setr_epi64( 19L,1L,1L,1L,1L,1L, 0L,0L ),                                    \
                           _mm512_permutexvar_epi64( _mm512_setr_epi64( 5L,0L,1L,2L,3L,4L, 6L,7L ),           \
                                                _mm512_srav_epi64( _x, _mm512_setr_epi64( 43L,43L,43L,43L,43L,40L, 0L,0L ) ) ) ); \
  }))

#define r43x6_fold_signed( x ) (__extension__({                                                \
    __m512i const _b = _mm512_setr_epi64( 19L<<23,1L<<20,1L<<20,1L<<20,1L<<20,1L<<20, 0L,0L ); \
    _mm512_add_epi64( r43x6_approx_carry_propagate( _mm512_sub_epi64( (x), _b ) ), _b );       \
  }))

/* r43x6_bias_carry_propagate_limbs computes an equivalent r43x6_t to a
   signed r43x6_t that has been extracted into the longs x0-x5 and
   stores the result into the longs y0-y5.  x5 is subtracted by a small
   bias in [0,2^20] before that is added back after.  This has no impact
   on the element represented but can impact the range needed for limb
   5.  In-place operation fine.  This macro is robust.

   IMPORTANT!  THIS SHOULD NOT BE APPLIED TO ARBITRARY X.

   If x is signed or more generally:

     x0    in [-2^63+19*2^23,2^63-19*(2^23-1))
     x1-x4 in [-2^63+   2^20,2^63-   (2^20-1))
     x5    in [-2^63+b,      2^63            )

   On return y will be signed but only in one limb such that it is
   almost nearly reduced:

     y0-y4 in [0,      2^43         )
     y5    in [-2^20+b,2^40+2^20-1+b)

   Thus, with b=2^20, if x is signed or more generally

     x0    in [-2^63+19*2^23,2^63-19*(2^23-1))
     x1-x4 in [-2^63+   2^20,2^63-   (2^20-1))
     x5    in [-2^63+   2^20,2^63            )

   On return y will be nearly reduced with y5 in [0,2^40+2^21-1).

   And, with b=0, if x is unsigned or more generally:

     x0    in [0,2^63-19*(2^23-1))
     x1-x4 in [0,2^63-   (2^20-1))
     x5    in [0,2^63            )

   On return y will be nearly reduced with y5 in [0,2^40+2^20-1).

   With b=0, the more restricted x is, the tighter the y5 range.  If x
   is {unreduced,unpacked,nearly reduced}, with b=0, on return, y will
   be nearly reduced with y5 in {[0,2^40+2^5-1),[0,2^40+1),[0,2^40+1)}.
   If x is reduced, on return, y will be reduced.

   Under the hood, this does a serial carry propagate on the limbs.

   Theory:

   Break an arbitrary x5 into its lower and upper bits as was done for
   approx_carry_propagate.  Then:

     x = <x0,x1,x2,x3,x4,x5l> + 2^40 <0,0,0,0,0,x5h>
       = <x0,x1,x2,x3,x4,x5l> + 19 <x5h,0,0,0,0,0>
       = <x0l+19*x5h,x1,x2,x3,x4,x5l>

   As x5h will be in [-2^23,2^23), if the initial x0 is in
   [-2^63+19*2^23,2^63-19*(2^23-1)), this new representation can be
   computed without intermediate overflow with limb 4 in [0,2^40) and
   limb 0 in [-2^63,2^63).

   Now break an arbitrary x0 into its lower and upper bits.  Then:

       x = <x0,x1,x2,x3,x4,x5>
         = <x0l,x1,x2,x3,x4,x5> + 2^43 <x0h,0,0,0,0,0>
         = <x0l,x1,x2,x3,x4,x5> + <0,x0h,0,0,0,0>
         = <x0l,x1+x0h,x2,x3,x5>

   As x0h will be in [-2^20,2^20), if the initial x1 is in
   [-2^63+2^20,2^63-(2^20-1)), this new representation can be computed
   without intermediate overflow with limb 0 in [0,2^43) and limb 1 in
   [-2^63,2^63).

   We can similarly serially propagate limb 1's carries to 2, 2 to 3, 3
   to 4 and 4 to 5.  As x4h will be in [-2^20,2^20), the limb 5's final
   value will be in [-2^20,2^40+2^20-1).

   If x is in unsigned or in the unsigned range described above, limb 4's
   carry will be in [0,2^20) such that the result will be nearly reduced
   with limb 5 in [0,2^40+2^20-1).

   If x is {unreduced,unpacked,nearly reduced}, limb 4's carry will be
   in {[0,2^5),[0,1],[0,1]} such that limb 5 will be be in
   {[0,2^40+2^5-1),[0,2^40+1),[0,2^40+1)}.

   If x was reduced, all carries will be zero such that y will have the
   same limbs as x.

   This yields the above.

   Like approx_carry_propagate, this is a building block for more
   complex mappings where x's limbs have already been extracted in order
   to minimize the number of limb extracts and r43x6 constructs. */

#define r43x6_biased_carry_propagate_limbs(x,y,b) do { \
    long const _m43 = (1L<<43)-1L;                     \
    long const _m40 = (1L<<40)-1L;                     \
    long _y0 = (x##0);                                 \
    long _y1 = (x##1);                                 \
    long _y2 = (x##2);                                 \
    long _y3 = (x##3);                                 \
    long _y4 = (x##4);                                 \
    long _y5 = (x##5);                                 \
    long _b  = (b);                                    \
    long _c;                                           \
    _y5 -= _b;                                         \
    _c = _y5>>40; _y5 &= _m40; _y0 += 19L*_c;          \
    _c = _y0>>43; _y0 &= _m43; _y1 +=     _c;          \
    _c = _y1>>43; _y1 &= _m43; _y2 +=     _c;          \
    _c = _y2>>43; _y2 &= _m43; _y3 +=     _c;          \
    _c = _y3>>43; _y3 &= _m43; _y4 +=     _c;          \
    _c = _y4>>43; _y4 &= _m43; _y5 +=     _c;          \
    _y5 += _b;                                         \
    (y##0) = _y0;                                      \
    (y##1) = _y1;                                      \
    (y##2) = _y2;                                      \
    (y##3) = _y3;                                      \
    (y##4) = _y4;                                      \
    (y##5) = _y5;                                      \
  } while(0)

/* Note: r43x6_biased_carry_propagate_limbs does not have a good AVX-512
   implementation (it is highly sequential). */

/* r43x6_mod_nearly_reduced_limbs computes the reduced r43x6_t for a
   nearly reduced r43x6_t that has been extracted into the longs x0-x5
   and stores the limbs in the longs y0-y5.  In-place operation fine.
   This macro is robust.  Theory:

   Let x = q p + r where q is an integer and r is in [0,p).  Since x is
   in [0,2*p), q is in [0,1].  If x<p, q=0 and r=x, otherwise, q=1 and
   r=x-p.  Using p = 2^255 - 19, x<p implies x+19<2^255.  Thus, if x+19
   has bit 255 (limb 5 bit 40) clear, r=x, otherwise, r=x-p.

   In pseudo code:
     y = x + 19                ... < 2*p+19 = 2^256-19 < 2^256
     q = y>>255                ... in [0,1]
     if !q, r = x              ... x in [0,p  ) -> r in [0,p)
     else   r = x - (2^255-19) ... x in [p,2*p) -> r in [0,p)

   Simplifying:
     y = x + 19
     q = y>>255
     if !q, r = y - 19
     else   r = y - 2^255

   Or:
     y  = x + 19
     q  = y>>255
     y -= q<<255       ... clear bit 255
     if !q, r = y - 19
     else   r = y

   Or, branchless for deterministic performance:
     y  = x + 19
     q  = y>>255
     y -= q<<255
     r  = y - if(!q,19,0) */

#define r43x6_mod_nearly_reduced_limbs(x,y) do { \
    long const _m43 = (1L<<43)-1L;               \
    long const _m40 = (1L<<40)-1L;               \
    long _y0 = (x##0);                           \
    long _y1 = (x##1);                           \
    long _y2 = (x##2);                           \
    long _y3 = (x##3);                           \
    long _y4 = (x##4);                           \
    long _y5 = (x##5);                           \
    long _c;                                     \
                                                 \
    /* y = x + 19, q = y>>255, y -= q<<255 */    \
    _y0 += 19L;                                  \
    _c = _y0 >> 43; _y0 &= _m43; _y1 += _c;      \
    _c = _y1 >> 43; _y1 &= _m43; _y2 += _c;      \
    _c = _y2 >> 43; _y2 &= _m43; _y3 += _c;      \
    _c = _y3 >> 43; _y3 &= _m43; _y4 += _c;      \
    _c = _y4 >> 43; _y4 &= _m43; _y5 += _c;      \
    _c = _y5 >> 40; _y5 &= _m40;                 \
                                                 \
    /* r = y - if(!q,19,0) */                    \
    _y0 -= fd_long_if( !_c, 19L, 0L );           \
    _c = _y0 >> 43; _y0 &= _m43; _y1 += _c;      \
    _c = _y1 >> 43; _y1 &= _m43; _y2 += _c;      \
    _c = _y2 >> 43; _y2 &= _m43; _y3 += _c;      \
    _c = _y3 >> 43; _y3 &= _m43; _y4 += _c;      \
    _c = _y4 >> 43; _y4 &= _m43; _y5 += _c;      \
                                                 \
    (y##0) = _y0;                                \
    (y##1) = _y1;                                \
    (y##2) = _y2;                                \
    (y##3) = _y3;                                \
    (y##4) = _y4;                                \
    (y##5) = _y5;                                \
  } while(0)

/* Note: r43x6_mod_nearly_reduced_limbs does not have a good AVX-512
   implementation (it is highly sequential). */

/* r43x6_approx_mod(x) returns a nearly reduced r43x6_t equivalent to
   an arbitrary r43x6_t x.  On return y5 will be in [0,2^40+2).

   r43x6_approx_mod_signed(x) does the same for signed x or, more
   generally:

     x0    in [-2^63+19*2^23,2^63-19*(2^23-1))
     x1-x4 in [-2^63+   2^20,2^63-   (2^20-1))
     x5    in [-2^63+   2^20,2^63            )

   r43x6_approx_mod_unsigned(x) does the same for unsigned x or, more
   generally:

     x0    in [0,2^63-19*(2^23-1))
     x1-x4 in [0,2^63-   (2^20-1))
     x5    in [0,2^63            )

   On return y5 will be in [0,2^40+2^20-1).

   r43x6_approx_mod_unreduced(x) does the same for unreduced x.  On
   return y5 will be in [0,2^40+2^5-1).

   r43x6_approx_mod_unpacked(x) does the same for unpacked x.  On return
   y5 will be in [0,2^40+1). */

FD_FN_UNUSED FD_FN_CONST static r43x6_t /* Work around -Winline */
r43x6_approx_mod( r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  r43x6_extract_limbs( x, y );

  /* At this point y is arbitrary.  We do an approx carry propagate to
     reduce the range of limbs suitable for a biased carry propagate.
     (Note: it is faster here to do extract then approx-cp than
     vector-approx-cp then extract.) */

  r43x6_approx_carry_propagate_limbs( y, y );

  /* At this point y has:

       y0    in [-19*2^23,2^43+19*(2^23-1))
       y1-y4 in [   -2^20,2^43+   (2^20-1))
       y5    in [   -2^20,2^40+   (2^20-1))

     An unbiased carry propagate could produce y5=-1.  So, we use a
     biased c-p with a b=1.  TODO: CONSIDER JUST USING 2^20 BIAS ALWAYS? */

  r43x6_biased_carry_propagate_limbs( y, y, 1L );

  return r43x6( y0, y1, y2, y3, y4, y5 );
}

FD_FN_UNUSED FD_FN_CONST static r43x6_t /* Work around -Winline */
r43x6_approx_mod_signed( r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  r43x6_extract_limbs( x, y );

  /* At this point y has:

       x0    in [-2^63+19*2^23,2^63-19*(2^23-1))
       x1-x4 in [-2^63+   2^20,2^63-   (2^20-1))
       x5    in [-2^63+   2^20,2^63            )

     so we can do a biased carry propagate y with b=2^20 as described
     above. */

  r43x6_biased_carry_propagate_limbs( y, y, 1L<<20 );

  return r43x6( y0, y1, y2, y3, y4, y5 );
}

FD_FN_UNUSED FD_FN_CONST static r43x6_t /* Work around -Winline */
r43x6_approx_mod_unsigned( r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  r43x6_extract_limbs( x, y );

  /* At this point y has:

       x0    in [0,2^63-19*(2^23-1))
       x1-x4 in [0,2^63-   (2^20-1))
       x5    in [0,2^63            )

     so we can do an unbiased carry propagate as described above. */

  r43x6_biased_carry_propagate_limbs( y, y, 0L );

  return r43x6( y0, y1, y2, y3, y4, y5 );
}

#define r43x6_approx_mod_unreduced r43x6_approx_mod_unsigned /* no difference in impl, tighter y5 result as described above */
#define r43x6_approx_mod_unpacked  r43x6_approx_mod_unsigned /* no difference in impl, tighter y5 result as described above */

/* r43x6_mod(x) returns the reduced r43x6_t equivalent to an arbitrary
   r43x6_t x.

   r43x6_approx_mod_signed(x) does the same for signed x or more
   generally:

     x0    in [-2^63+19*2^23,2^63-19*(2^23-1))
     x1-x4 in [-2^63+   2^20,2^63-   (2^20-1))
     x5    in [-2^63+   2^20,2^63            )

   r43x6_mod_unreduced(x) does the same for unreduced x, or, more
   generally:

     x0    in [0,2^63-19*(2^23-1))
     x1-x4 in [0,2^63-   (2^20-1))
     x5    in [0,2^63            )

   r43x6_mod_unpacked(x) does the same for unpacked x.

   r43x6_mod_nearly_reduced(x) does the same for nearly reduced x. */

FD_FN_UNUSED FD_FN_CONST static r43x6_t /* Work around -Winline */
r43x6_mod( r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  r43x6_extract_limbs( x, y );
  r43x6_approx_carry_propagate_limbs( y, y );
  r43x6_biased_carry_propagate_limbs( y, y, 1L );
  /* At this point, x is nearly reduced */
  r43x6_mod_nearly_reduced_limbs( y, y );
  return r43x6( y0, y1, y2, y3, y4, y5 );
}

FD_FN_UNUSED FD_FN_CONST static r43x6_t /* Work around -Winline */
r43x6_mod_signed( r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  r43x6_extract_limbs( x, y );
  r43x6_biased_carry_propagate_limbs( y, y, 1L<<20 );
  /* At this point, x is nearly reduced */
  r43x6_mod_nearly_reduced_limbs( y, y );
  return r43x6( y0, y1, y2, y3, y4, y5 );
}

FD_FN_UNUSED FD_FN_CONST static r43x6_t /* Work around -Winline */
r43x6_mod_unsigned( r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  r43x6_extract_limbs( x, y );
  r43x6_biased_carry_propagate_limbs( y, y, 0L );
  /* At this point, x is nearly reduced */
  r43x6_mod_nearly_reduced_limbs( y, y );
  return r43x6( y0, y1, y2, y3, y4, y5 );
}

#define r43x6_mod_unreduced r43x6_mod_unsigned /* no difference in impl */
#define r43x6_mod_unpacked  r43x6_mod_unsigned /* no difference in impl */

FD_FN_UNUSED FD_FN_CONST static r43x6_t /* Work around -Winline */
r43x6_mod_nearly_reduced( r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  r43x6_extract_limbs( x, y );
  /* At this point, x is already nearly reduced */
  r43x6_mod_nearly_reduced_limbs( y, y );
  return r43x6( y0, y1, y2, y3, y4, y5 );
}

/* r43x6_add_fast(x,y) returns z = x + y (including lanes 6 and 7).
   Similarly for r43x6_sub_fast(x,y).  These assume that the
   corresponding limbs of x and y when added / subtracted will produce a
   result that doesn't overflow the range of a long.  For example, it is
   safe to add a large (but bounded) number of unpacked x to produce an
   unreduced sum and then do a single mod at the end to produce the
   reduced result.  These macros are robust.

   Note that when a large but bounded number of unreduced elements, the
   result might end up as an unsigned element.  r43x6_fold_unsigned can
   quickly fold an unsigned elements into an unreduced equivalent.

   Likewise, when subtracting unreduced elements, the result might end
   up as a signed element.  r43x6_fold_signed can quickly fold a signed
   elements into an unreduced equivalent. */

#define r43x6_add_fast( x, y ) _mm512_add_epi64( (x), (y) )
#define r43x6_sub_fast( x, y ) _mm512_sub_epi64( (x), (y) )

/* r43x6_mul_fast(x,y) returns z = x*y as an unreduced r43x6_t where x
   and y are unreduced r43x6_t's.  Ignores lanes 6 and 7 of x.  Assumes
   lanes 6 and 7 of y are zero.  Lanes 6 and 7 of z will be zero.
   The returned limbs will have:
     z0    in [0,2^43+19*(2^23-1))
     z1-z4 in [0,2^43+   (2^20-1))
     z5    in [0,2^40+   (2^20-1))
   or, more simply (but not as tight), in [0,2^44).  This is a subset of
   unreduced r43x6_t such that, for example, the results of several
   multiplies can be added without needing to fold every single add. */

FD_FN_UNUSED FD_FN_CONST static r43x6_t /* Work around -Winline */
r43x6_mul_fast( r43x6_t x,
                r43x6_t y ) {

  /* 5x5 grade school-ish multiplication accelerated with AVX512 integer
     madd52 instructions.  The basic algorithm is:

       x*y = (sum_i xi 2^(43*i))*(sum_j yj 2^(43*j))
           = sum_i sum_j xi*xj 2^(43*(i+j))
           = sum_i sum_j (pijl + 2^43 pijh) 2^(43*(i+j))
           = sum_i sum_j ( pijl 2^(43*(i+j)) + pijh 2^(43*(i+j+1)) )
           = sum_k       zk 2^43 k

     where the product of xi*xj has been split such that:

       pijl + 2^43 pijh = xi*xj

     and zk has grouped all terms with the same scale factor:

        zk = sum_i sum_j ( pijl ((i+j)==k) + pijh ((i+j+1)==k) )

     Or graphically:

                                       x5   x4   x3   x2   x1   x0
                                  x    y5   y4   y3   y2   y1   y0
                                  --------------------------------
                                     p50l p40l p30l p20l p10l p00l -> t0
                                p50h p40h p30h p20h p10h p00h      \
                                p51l p41l p31l p21l p11l p01l      /  t1
                           p51h p41h p31h p21h p11h p01h           \
                           p52l p42l p32l p22l p12l p02l           /  t2
                      p52h p42h p32h p22h p12h p02h                \
                      p53l p43l p33l p23l p13l p03l                /  t3
                 p53h p43h p33h p23h p13h p03h                     \
                 p54l p44l p34l p24l p14l p04l                     /  t4
            p54h p44h p34h p24h p14h p04h                          \
            p55l p45l p35l p25l p15l p05l                          /  t5
       p55h p45h p35h p25h p15h p05h                               -> t6
       -----------------------------------------------------------
       z11  z10   z9   z8   z7   z6   z5   z4   z3   z2   z1   z0
       \----------------/   \-----------------------------------/
               zh                            zl

    The conventional split would require xi and xj to be in [0,2^43) and
    yield pijl and pijh in [0,2^43).  But we need to use a different
    split to exploit the madd52 instructions:

      ul = madd52lo(al,x,y) = LO64( al + LO52( LO52(x)*LO52(y) ) )
      uh = madd52hi(ah,x,y) = LO64( ah + HI52( LO52(x)*LO52(y) ) )

    Consider when al and ah are zero.  Since x and y here are unreduced
    and thus in [0,2^47), we have:

      ul = LO52( x*y )
      uh = HI52( x*y )
      --> ul + 2^52 uh       = x*y
      --> ul + 2^43 (2^9 uh) = x*y

    Thus, we can use pl=ul and and ph=2^9 uh from these instructions as
    a split for the above.  With this we have:

      pl in [0,2^52)
      ph in [0,2^51)

    so:

      z{0,1,2,3, 4, 5} < { 2, 5, 8,11,14,17} 2^51
      z{6,7,8,9,10,11} < {16,13,10, 7, 4, 1} 2^51

    Note: the [0,2^47) range for unreduced r43x6_t was picked to yield
    pl and ph with similar ranges while allowing for fast reduction
    below.

    Note: It might seem even better to use a 5 long radix 52 limb
    representation such that madd naturally produces the desired
    splitting.  If the only consideration is the above, this is correct.

    But this calculation is frequently used in long sequential chains
    (e.g. the repeated squarings done to compute the multiplicative
    inverse).  In the 52x5 case, the zk reduction required to produce an
    output representation that can be fed into the next multiplication
    has no "headroom".  All carries from limbs 0-3 must be fully
    propagated to limb 4 such that all limbs are in [0,2^52) to be able
    to use madd52 subsequent multiply operations.  This requires then
    extracting all the limbs and doing a slow sequential calculation as
    part of the zk reduction.  This throws away most of the advantage of
    using instructions like madd52 in the first place.

    Using 43x6 is nearly the same cost as 52x5 for the above because we
    have unused AVX512 lanes and the scaling needed to tweak the
    madd52hi result is a fast shift operation.  Critically, the needed
    zk reduction (described below) can be done with a fast approximate
    carry propagate to get a result that can be immediately fed into
    subsequent multiplications.

    The overall impact is that this is typically ~2-3x faster than, for
    example, the fd_ed25519_fe_t scalar multiplier on platforms with
    AVX512 support.

    This implementation is not the "textbook" style found in the
    literature.  The textbook implementations accumulate zh and zl by
    interleaving alignr with the madds.  The putative benefit of such is
    that it can make use of the madd52hi adder to save some adds over
    the below.  Unfortunately, such requires more alignr / more
    instruction footprint / more sequential dependencies and has less
    ILP.  In practice, adds are much cheaper than alignr (remember, data
    motion has been more expensive than computation for decades).  So
    spending some adds to buy fewer alignr, a smaller instruction
    footprint and more ILP is a great trade and yields the faster than
    textbook implementation below. */

  __m512i const zero = _mm512_setzero_si512();

  __m512i x0  = _mm512_permutexvar_epi64( zero,                   x );
  __m512i x1  = _mm512_permutexvar_epi64( _mm512_set1_epi64( 1 ), x );
  __m512i x2  = _mm512_permutexvar_epi64( _mm512_set1_epi64( 2 ), x );
  __m512i x3  = _mm512_permutexvar_epi64( _mm512_set1_epi64( 3 ), x );
  __m512i x4  = _mm512_permutexvar_epi64( _mm512_set1_epi64( 4 ), x );
  __m512i x5  = _mm512_permutexvar_epi64( _mm512_set1_epi64( 5 ), x );

  __m512i t0  = _mm512_madd52lo_epu64( zero,                                                         x0, y );
  __m512i t1  = _mm512_madd52lo_epu64( _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x0, y ), 9 ), x1, y );
  __m512i t2  = _mm512_madd52lo_epu64( _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x1, y ), 9 ), x2, y );
  __m512i t3  = _mm512_madd52lo_epu64( _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x2, y ), 9 ), x3, y );
  __m512i t4  = _mm512_madd52lo_epu64( _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x3, y ), 9 ), x4, y );
  __m512i t5  = _mm512_madd52lo_epu64( _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x4, y ), 9 ), x5, y );
  __m512i t6  =                        _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x5, y ), 9 );

  __m512i p0j =                      t0;            /* note: q0j = 0 */
  __m512i p1j = _mm512_alignr_epi64( t1, zero, 7 ); /* note: q1j = 0 */
  __m512i p2j = _mm512_alignr_epi64( t2, zero, 6 ); /* note: q2j = 0 */
  __m512i p3j = _mm512_alignr_epi64( t3, zero, 5 ); __m512i q3j = _mm512_alignr_epi64( zero, t3, 5 );
  __m512i p4j = _mm512_alignr_epi64( t4, zero, 4 ); __m512i q4j = _mm512_alignr_epi64( zero, t4, 4 );
  __m512i p5j = _mm512_alignr_epi64( t5, zero, 3 ); __m512i q5j = _mm512_alignr_epi64( zero, t5, 3 );
  __m512i p6j = _mm512_alignr_epi64( t6, zero, 2 ); __m512i q6j = _mm512_alignr_epi64( zero, t6, 2 );

  __m512i zl  = _mm512_add_epi64( _mm512_add_epi64( _mm512_add_epi64( p0j, p1j ), _mm512_add_epi64( p2j, p3j ) ),
                                  _mm512_add_epi64( _mm512_add_epi64( p4j, p5j ), p6j ) );
  __m512i zh  = _mm512_add_epi64( _mm512_add_epi64( q3j, q4j ), _mm512_add_epi64( q5j, q6j ) );

  /* At this point:
       z = <zl0,zl1,zl2,zl3,zl4,zl5,zl6,zl7> + 2^344 <zh0,zh1,zh2,zh3,0,0,0,0> */

  __m512i za  = _mm512_and_epi64( zl, _mm512_setr_epi64( -1L,-1L,-1L,-1L,-1L,-1L, 0L,0L ) );
  __m512i zb  = _mm512_alignr_epi64( zh, zl, 6 );

  /* At this point:

       z = <za0,za1,za2,za3,za4,za5> + 2^258 <zb0,zb1,zb2,zb3,zb4,zb5>

     where (as shown above):

       za{0,1,2,3,4,5} < 2^51 { 2, 5, 8,11,14,17}
       zb{0,1,2,3,4,5) < 2^51 {16,13,10, 7, 4, 1}

     Using:

       2^258 mod p = (p+19) 2^3 mod p = 19*2^3 = 152

     we can reduce this to 6 limbs via:

       z = <za0,za1,za2,za3,za4,za5> + 152 <zb0,zb1,zb2,zb3,zb4,zb5>

     We can do the sum directly because:

       z{0,1,2,3,4,5} < 2^51 {2434,1981,1528,1075,622,169} < 2^63

     These limbs are too large to use in a subsequent multiply but they
     are in the range where we can do a fold_unsigned, yielding:

       z0    in [0,2^43+19*(2^23-1))
       z1-z4 in [0,2^43+   (2^20-1))
       z5    in [0,2^40+   (2^20-1))

     This is an unreduced r43x6_t and thus suitable direct use in
     subsequent multiply operations.

     Note that mullo is slow.  Since 152 = 2^7 + 2^4 + 2^3 and is
     applied to all lanes, we can compute za+152*zb slightly faster via
     shift and add techniques. */

  return r43x6_fold_unsigned( _mm512_add_epi64( _mm512_add_epi64(                    za,      _mm512_slli_epi64( zb, 7 ) ),
                                                _mm512_add_epi64( _mm512_slli_epi64( zb, 4 ), _mm512_slli_epi64( zb, 3 ) ) ) );
}

/* TODO: CONSIDER FMA IN STYLE OF SCALEADD BELOW */

/* r43x6_sqr_fast(x) returns z = x^2 as an unreduced r43x6_t where x is
   an unreduced r43x6_t.  Assumes lanes 6 and 7 of x are zero.  Lanes 6
   and 7 of z will be zero.  The returned limbs will have the same range
   as mul_fast. */

FD_FN_CONST static inline r43x6_t r43x6_sqr_fast( r43x6_t x ) {
  __m512i const zero = _mm512_setzero_si512();

  /* The goal of this implmentation is to compute each product once, but
     to make sure each product gets generated in the right AVX lane so
     that we don't have to do a ton of shuffling at the end.  In
     exchange, we do a lot of permutevars upfront to get everything
     setup.  It's possible trading permutevars for madd52s might improve
     performance.

     We'll compute
         p0 = x{0,0,0,0,0,0,3,3} * x{0,1,2,3,4,5,3,4}
         p1 = x{4,4,1,1,1,1,1,-} * x{4,5,1,2,3,4,5,-}
         p2 = x{3,-,5,-,2,2,2,2} * x{5,-,5,-,2,3,4,5}
     with the scaling of non-square terms omitted above.  A dash
     indicates a don't care value, since we have to do 24
     multiplications but there are only 21 unique terms.

     All the terms of p0 belong in the low final result, but the first
     two terms of p1, and the first and third terms of p2 belong in the
     high final result.  The other gotcha is that each multiplication
     has a high and a low component, so we confusingly have two
     different notions of high/low.
     */
  __m512i x0 = _mm512_permutexvar_epi64( _mm512_setr_epi64( 0L, 0L, 0L, 0L, 0L, 0L, 3L, 3L ), x );
  __m512i x1 = _mm512_permutexvar_epi64( _mm512_setr_epi64( 0L, 1L, 2L, 3L, 4L, 5L, 3L, 4L ), x );
  __m512i x2 = _mm512_permutexvar_epi64( _mm512_setr_epi64( 4L, 4L, 1L, 1L, 1L, 1L, 1L, 7L ), x );
  __m512i x3 = _mm512_permutexvar_epi64( _mm512_setr_epi64( 4L, 5L, 1L, 2L, 3L, 4L, 5L, 7L ), x );
  __m512i x4 = _mm512_permutexvar_epi64( _mm512_setr_epi64( 3L, 7L, 5L, 7L, 2L, 2L, 2L, 2L ), x );
  __m512i x5 = _mm512_permutexvar_epi64( _mm512_setr_epi64( 5L, 7L, 5L, 7L, 2L, 3L, 4L, 5L ), x );

  /* Double the non-square terms. */
  x0 = _mm512_sllv_epi64( x0, _mm512_setr_epi64( 0L, 1L, 1L, 1L, 1L, 1L, 0L, 1L ) );
  x2 = _mm512_sllv_epi64( x2, _mm512_setr_epi64( 0L, 1L, 0L, 1L, 1L, 1L, 1L, 1L ) );
  x4 = _mm512_sllv_epi64( x4, _mm512_setr_epi64( 1L, 1L, 0L, 1L, 0L, 1L, 1L, 1L ) );

  __m512i p0l = _mm512_madd52lo_epu64( zero, x0, x1 );
  __m512i p1l = _mm512_madd52lo_epu64( zero, x2, x3 );
  __m512i p2l = _mm512_madd52lo_epu64( zero, x4, x5 );

  /* Use the same approach as in the multiply to generate the high bits
     of each individual product. */
  __m512i p0h = _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x0, x1 ), 9 );
  __m512i p1h = _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x2, x3 ), 9 );
  __m512i p2h = _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x4, x5 ), 9 );

  /* Generate masks to split p_i into the terms that belong in the high
     word and low word. */
  __m512i mask1 = _mm512_setr_epi64( -1L, -1L, 0L, 0L, 0L, 0L, 0L, 0L );
  __m512i mask2 = _mm512_setr_epi64( -1L, 0L, -1L, 0L, 0L, 0L, 0L, 0L );
  __m512i zll = _mm512_add_epi64( p0l,
                      _mm512_add_epi64( _mm512_andnot_epi32( mask1, p1l ),
                                        _mm512_andnot_epi32( mask2, p2l ) ) );
  __m512i zlh = _mm512_add_epi64( p0h,
                      _mm512_add_epi64( _mm512_andnot_epi32( mask1, p1h ),
                                        _mm512_andnot_epi32( mask2, p2h ) ) );
  __m512i zhl = _mm512_add_epi64( _mm512_and_epi32( mask1, p1l ),
                                  _mm512_and_epi32( mask2, p2l ) );
  __m512i zhh = _mm512_add_epi64( _mm512_and_epi32( mask1, p1h ),
                                  _mm512_and_epi32( mask2, p2h ) );

  /* Generate zl and zh as in mul */
  __m512i zl = _mm512_add_epi64( zll, _mm512_alignr_epi64( zlh, zero, 7 ) );
  __m512i zh = _mm512_add_epi64( zhl, _mm512_add_epi64( _mm512_alignr_epi64( zhh, zero, 7 ),
                                                        _mm512_alignr_epi64( zero, zlh, 7 ) ) );

  __m512i za  = _mm512_and_epi64( zl, _mm512_setr_epi64( -1L,-1L,-1L,-1L,-1L,-1L, 0L,0L ) );
  __m512i zb  = _mm512_alignr_epi64( zh, zl, 6 );

  return r43x6_fold_unsigned( _mm512_add_epi64( _mm512_add_epi64(                    za,      _mm512_slli_epi64( zb, 7 ) ),
                                                _mm512_add_epi64( _mm512_slli_epi64( zb, 4 ), _mm512_slli_epi64( zb, 3 ) ) ) );

}

/* r43x6_repsqr_fast(x,n) returns z = x^(2^n) of an unreduced r43x6_t
   where x is an unreduced r43x6_t.  Computed via n repeated squarings,
   yielding a cost of n sqr.  Assumes lanes 6 and 7 of x are zero.
   Lanes 6 and 7 of z will be zero.  The returned limbs will have the
   same range as mul_fast. */

FD_FN_CONST static inline r43x6_t
r43x6_repsqr_fast( r43x6_t x,
                   ulong   n ) {

 /* The below is r43x6_sqr_fast wrapped in a loop to force inlining of
    the loop body and encourage the compiler to hoist various compile
    time constants out of the loop and possibly unroll the loop if
    useful in context.  See r43x6_sqr_fast for detailed explanation how
    this works. */

  for( ; n; n-- ) {
    __m512i const zero = _mm512_setzero_si512();

    __m512i x0 = _mm512_permutexvar_epi64( _mm512_setr_epi64( 0L, 0L, 0L, 0L, 0L, 0L, 3L, 3L ), x );
    __m512i x1 = _mm512_permutexvar_epi64( _mm512_setr_epi64( 0L, 1L, 2L, 3L, 4L, 5L, 3L, 4L ), x );
    __m512i x2 = _mm512_permutexvar_epi64( _mm512_setr_epi64( 4L, 4L, 1L, 1L, 1L, 1L, 1L, 7L ), x );
    __m512i x3 = _mm512_permutexvar_epi64( _mm512_setr_epi64( 4L, 5L, 1L, 2L, 3L, 4L, 5L, 7L ), x );
    __m512i x4 = _mm512_permutexvar_epi64( _mm512_setr_epi64( 3L, 7L, 5L, 7L, 2L, 2L, 2L, 2L ), x );
    __m512i x5 = _mm512_permutexvar_epi64( _mm512_setr_epi64( 5L, 7L, 5L, 7L, 2L, 3L, 4L, 5L ), x );

    x0 = _mm512_sllv_epi64( x0, _mm512_setr_epi64( 0L, 1L, 1L, 1L, 1L, 1L, 0L, 1L ) );
    x2 = _mm512_sllv_epi64( x2, _mm512_setr_epi64( 0L, 1L, 0L, 1L, 1L, 1L, 1L, 1L ) );
    x4 = _mm512_sllv_epi64( x4, _mm512_setr_epi64( 1L, 1L, 0L, 1L, 0L, 1L, 1L, 1L ) );

    __m512i p0l = _mm512_madd52lo_epu64( zero, x0, x1 );
    __m512i p1l = _mm512_madd52lo_epu64( zero, x2, x3 );
    __m512i p2l = _mm512_madd52lo_epu64( zero, x4, x5 );

    __m512i p0h = _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x0, x1 ), 9 );
    __m512i p1h = _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x2, x3 ), 9 );
    __m512i p2h = _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x4, x5 ), 9 );

    __m512i mask1 = _mm512_setr_epi64( -1L, -1L, 0L, 0L, 0L, 0L, 0L, 0L );
    __m512i mask2 = _mm512_setr_epi64( -1L, 0L, -1L, 0L, 0L, 0L, 0L, 0L );
    __m512i zll = _mm512_add_epi64( p0l,
                        _mm512_add_epi64( _mm512_andnot_epi32( mask1, p1l ),
                                          _mm512_andnot_epi32( mask2, p2l ) ) );
    __m512i zlh = _mm512_add_epi64( p0h,
                        _mm512_add_epi64( _mm512_andnot_epi32( mask1, p1h ),
                                          _mm512_andnot_epi32( mask2, p2h ) ) );
    __m512i zhl = _mm512_add_epi64( _mm512_and_epi32( mask1, p1l ),
                                    _mm512_and_epi32( mask2, p2l ) );
    __m512i zhh = _mm512_add_epi64( _mm512_and_epi32( mask1, p1h ),
                                    _mm512_and_epi32( mask2, p2h ) );

    __m512i zl = _mm512_add_epi64( zll, _mm512_alignr_epi64( zlh, zero, 7 ) );
    __m512i zh = _mm512_add_epi64( zhl, _mm512_add_epi64( _mm512_alignr_epi64( zhh, zero, 7 ),
                                                          _mm512_alignr_epi64( zero, zlh, 7 ) ) );

    __m512i za  = _mm512_and_epi64( zl, _mm512_setr_epi64( -1L,-1L,-1L,-1L,-1L,-1L, 0L,0L ) );
    __m512i zb  = _mm512_alignr_epi64( zh, zl, 6 );

    x = r43x6_fold_unsigned( _mm512_add_epi64( _mm512_add_epi64(                    za,      _mm512_slli_epi64( zb, 7 ) ),
                                               _mm512_add_epi64( _mm512_slli_epi64( zb, 4 ), _mm512_slli_epi64( zb, 3 ) ) ) );
  }

  return x;
}

/* r43x6_scale_fast(x0,y) returns z = <x0,0,0,0,0>*y as an unreduced
   r43x6_t where x is in [0,2^47) and y is an unreduced r43x6_t.
   Assumes y lanes 6-7 are zero.  Lanes 6-7 of z will be zero.  The
   returned limbs will have the same range as mul_fast. */

FD_FN_CONST static inline r43x6_t
r43x6_scale_fast( long    _x0,
                  r43x6_t y ) {

  /* This is r43x6_mul_fast with x = <_x0,0,0,0,0> and zeros values
     optimized out.  See r43x6_mul_fast for detailed explanation how
     this works. */

  __m512i const zero = _mm512_setzero_si512();

  __m512i x0  = _mm512_set1_epi64( _x0 );

  __m512i t0  =                    _mm512_madd52lo_epu64( zero, x0, y );
  __m512i t1  = _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x0, y ), 9 );

  __m512i p0j =                      t0;
  __m512i p1j = _mm512_alignr_epi64( t1, zero, 7 );

  __m512i zl  = _mm512_add_epi64( p0j, p1j );

  __m512i za = _mm512_and_epi64( zl, _mm512_setr_epi64( -1L,-1L,-1L,-1L,-1L,-1L, 0L,0L ) );
  __m512i zb = _mm512_alignr_epi64( zero, zl, 6 );

  /* At this point:

       za{0,1,2,3,4,5} < 2^51 {2,3,3,3,3,3}
       zb0             < 2^51

     such that:

       z{0,1,2,3,4,5} < 2^51 {154,3,3,3,3,3} < 2^63 */

  return r43x6_fold_unsigned( _mm512_add_epi64( _mm512_add_epi64(                    za,      _mm512_slli_epi64( zb, 7 ) ),
                                                _mm512_add_epi64( _mm512_slli_epi64( zb, 4 ), _mm512_slli_epi64( zb, 3 ) ) ) );
}

/* r43x6_scaleadd_fast(a,x0,y) returns z = a+<x0,0,0,0,0>*y as an
   unreduced r43x6_t where a is an unreduced r43x6_t, x is in [0,2^47),
   y is an unreduced r43x6_t.  Assumes y lanes 6-7 are zero.  Lanes 6-7
   of z will be zero.  The returned limbs will have the same range as
   mul_fast. */

FD_FN_CONST static inline r43x6_t
r43x6_scaleadd_fast( r43x6_t a,
                     long    _x0,
                     r43x6_t y ) {

  /* This is r43x6_mul_fast with x = <_x0,0,0,0,0> and zeros values
     optimized out.  See r43x6_mul_fast for detailed explanation how
     this works. */

  __m512i const zero = _mm512_setzero_si512();

  __m512i x0  = _mm512_set1_epi64( _x0 );

  __m512i t0  =                    _mm512_madd52lo_epu64( zero, x0, y );
  __m512i t1  = _mm512_slli_epi64( _mm512_madd52hi_epu64( zero, x0, y ), 9 );

  __m512i p0j =                      t0;
  __m512i p1j = _mm512_alignr_epi64( t1, zero, 7 );

  __m512i zl  = _mm512_add_epi64( p0j, p1j );

  __m512i za = _mm512_and_epi64( zl, _mm512_setr_epi64( -1L,-1L,-1L,-1L,-1L,-1L, 0L,0L ) );
  __m512i zb = _mm512_alignr_epi64( zero, zl, 6 );

  /* At this point:

       za{0,1,2,3,4,5} < 2^51 {2,3,3,3,3,3}
       zb0             < 2^51

     such that:

       z{0,1,2,3,4,5} < 2^51 {154,3,3,3,3,3} < 2^63

     As such, adding an unreduced value to this will not overflow. */

  return r43x6_fold_unsigned( _mm512_add_epi64( _mm512_add_epi64( _mm512_add_epi64( a, za ),  _mm512_slli_epi64( zb, 7 ) ),
                                                _mm512_add_epi64( _mm512_slli_epi64( zb, 4 ), _mm512_slli_epi64( zb, 3 ) ) ) );
}

/* r43x6_invert_fast(z) returns the multiplicative inverse of z in GF(p)
   where z is an unreduced r43x6_t.  Assumes lanes 6 and 7 of z are
   zero.  The return will be an unreduced r43x6_t with lanes 6 and 7
   zero.  The returned limbs will have the same range as mul_fast.  */

FD_FN_UNUSED FD_FN_CONST static r43x6_t /* Work around -Winline */
r43x6_invert_fast( r43x6_t z ) {

  /* Theory:

          z^p       = z in GF(p)
       -> z^(p-1) z = z
       -> z^(p-1)   = 1
       -> z^(p-2) z = 1
       -> z^(p-2) is the multiplicative inverse of z in GF(p).

     Since p-2 is impractically large, we have to do this indirectly.
     This technique is adapted from the OpenSSL implementation.

       z^(p-2) = z^(2^255-21)
               = z^[(2^255)-(2^5)+11]
               = z^[(2^250)(2^5)-(2^5)+11]
               = z^[(2^250-1)(2^5) + 11]
               = [z^(2^250-1)]^(2^5) z^11

     z^11 is straightforward to compute directly.  [...]^(2^5) is
     straightforward to compute by repeated squaring.  z^(2^n-1) can be
     computed by a combination of repeated squaring and factorizations
     like:

       z^(2^n-1) = z^[(2^(n/2)+1)(2^(n/2)-1)]
                 = z^[2^(n/2) (2^(n/2)-1) + (2^(n/2)-1)]
                 = [z^(2^(n/2)-1)]^(2^(n/2)) z^(2^(n/2)-1)

     where the first term is the n/2 repeated squaring of z^(2^(n/2)-1)
     and the second term is the same factor that initialized the
     repeated squaring. */

  /* Compute z^11 (and z^9 along the way) */

  r43x6_t z2  = r43x6_repsqr_fast( z, 1UL );
  r43x6_t z9  = r43x6_mul_fast( r43x6_repsqr_fast( z2, 2UL ), z );
  r43x6_t z11 = r43x6_mul_fast( z9, z2 );

  /* Compute z^(2^250-1) */

  r43x6_t z2e5m1   = r43x6_mul_fast( r43x6_repsqr_fast( z11,        1UL ), z9       );
  r43x6_t z2e10m1  = r43x6_mul_fast( r43x6_repsqr_fast( z2e5m1,     5UL ), z2e5m1   );
  r43x6_t z2e20m1  = r43x6_mul_fast( r43x6_repsqr_fast( z2e10m1,   10UL ), z2e10m1  );
  r43x6_t z2e40m1  = r43x6_mul_fast( r43x6_repsqr_fast( z2e20m1,   20UL ), z2e20m1  );
  r43x6_t z2e50m1  = r43x6_mul_fast( r43x6_repsqr_fast( z2e40m1,   10UL ), z2e10m1  );
  r43x6_t z2e100m1 = r43x6_mul_fast( r43x6_repsqr_fast( z2e50m1,   50UL ), z2e50m1  );
  r43x6_t z2e200m1 = r43x6_mul_fast( r43x6_repsqr_fast( z2e100m1, 100UL ), z2e100m1 );
  r43x6_t z2e250m1 = r43x6_mul_fast( r43x6_repsqr_fast( z2e200m1,  50UL ), z2e50m1  );

  /* Combine z^(2^250-1) and z^11 */

  return r43x6_mul_fast( r43x6_repsqr_fast( z2e250m1, 5UL ), z11 );
}

/* r43x6_swap_if(c,x,y) will swap the contents of x and y if c is
   non-zero and leave the contents of x and y unchanged otherwise.
   Branchless for deterministic timing.  This macro is robust. */

#define r43x6_swap_if(c,x,y) do {                                                                  \
    __m512i _x = (x);                                                                              \
    __m512i _y = (y);                                                                              \
    __m512i _c = _mm512_and_epi64( _mm512_xor_epi64( _x, _y ), _mm512_set1_epi64( (long)-!(c) ) ); \
    (x)        = _mm512_xor_epi64( _y, _c );                                                       \
    (y)        = _mm512_xor_epi64( _x, _c );                                                       \
  } while(0)

FD_PROTOTYPES_END

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_ed25519_avx512_r43x6_h */
