#ifndef HEADER_fd_src_ballet_ed25519_avx512_fd_r43x6_h
#define HEADER_fd_src_ballet_ed25519_avx512_fd_r43x6_h

#if FD_HAS_AVX512

#include "../../../util/simd/fd_avx.h"
#include "../../../util/simd/fd_avx512.h"

/* A fd_r43x6_t represents a GF(p) element, where p = 2^255-19, in a
   little endian 6 long radix 2^43 limb representation.  The 6 limbs are
   held in lanes 0 through 5 of an AVX-512 vector.  That is, given a
   fd_r43x6_t x, the field element represented by x is:

     ( x0 + x1 2^43 + x2 2^86 + x3 2^129 + x4 2^172 + x5 2^215 ) mod p

   where xn is the n-th 64-bit vector lane treated as a long.  Lanes 6
   and 7 are ignored.  The below will often use the shorthand:

     <x0,x1,x2,x3,x4,x5>

   for the above expression.

   This representation is redundant: multiple fd_r43x6_t can represent
   the same element.  Most functions have restrictions on the which
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

   As a frequently used shorthand when analyzing range of limbs, unn
   indicates limbs are in [0,2^nn) and snn indicates limbs aer in
   (-2^nn,2^nn).

   Note:

   - There is only one reduced fd_r43x6_t for each element.

   - There are two nearly reduced fd_r43x6_t for each element.

   - reduced is a subset of nearly reduced is a subset of unpacked is a
     subset of unreduced is a subset of unsigned is a subset of signed
     is a subset arbitrary.

   - unpacked, nearly reduced and reduced fd_r43x6_t be quickly
     converted into a packed uint256 value used by various cryptographic
     protocols and vice versa.

   - Cheat sheat

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

       add_fast   maps unreduced x unreduced             to unsigned (among others), see fold_unsigned above
       sub_fast   maps unreduced x unreduced             to signed   (among others), see fold_signed   above
       mul_fast   maps unreduced x unreduced             to unsigned,                see fold_unsigned above
       sqr_fast   maps unreduced                         to unsigned,                see fold_unsigned above
       neg        maps unreduced                         to unreduced
       add        maps unreduced x unreduced             to unreduced
       sub        maps unreduced x unreduced             to unreduced
       mul        maps unreduced x unreduced             to unreduced
       sqr        maps unreduced                         to unreduced
       scale      maps [0,2^47)  x unreduced             to unreduced
       scaleadd   maps unreduced x [0,2^47)  x unreduced to unreduced
       invert     maps unreduced                         to unreduced
       is_nonzero maps signed                            to [0,1]
       diagnose   maps signed                            to [-1,0,1]
       pow22523   maps unreduced                         to unreduced

       * These are used to implement HPC calculations on GF(p) elements. */

#define fd_r43x6_t wwl_t

FD_PROTOTYPES_BEGIN

/* fd_r43x6(x0,x1,x2,x3,x4,x5) constructs an arbitrary r43x6_t from the
   given limbs.  Lanes 6 and 7 will be zero.  This macro is robust.
   Note: implementing via setr was benchmarked as slightly faster than
   loading from a stack tmp (probably due to better compiler code gen). */

#define fd_r43x6(x0,x1,x2,x3,x4,x5) wwl( (x0),(x1),(x2),(x3),(x4),(x5), 0L,0L )

/* fd_r43x6_extract_limbs(x,y) extracts the limbs of an arbitrary
   fd_r43x6_t x into the longs y0-y5.  This is primarily for use in
   operations that are not vectorized.  This macro is robust.  Note:
   implementing via extract was benchmarked as slightly faster than
   storing to a stack tmp and reloading (probably due to better compiler
   code gen). */

#define fd_r43x6_extract_limbs(x,y) do {              \
    wwl_t _x = (x);                                   \
    __m256i _xl = _mm512_extracti64x4_epi64( _x, 0 ); \
    __m256i _xh = _mm512_extracti64x4_epi64( _x, 1 ); \
    y##0 = _mm256_extract_epi64( _xl, 0 );            \
    y##1 = _mm256_extract_epi64( _xl, 1 );            \
    y##2 = _mm256_extract_epi64( _xl, 2 );            \
    y##3 = _mm256_extract_epi64( _xl, 3 );            \
    y##4 = _mm256_extract_epi64( _xh, 0 );            \
    y##5 = _mm256_extract_epi64( _xh, 1 );            \
  } while(0)

/* fd_r43x6_zero(), fd_r43x6_one(), fd_r43x6_p(), fd_r43x6_d(),
   fd_r43x6_2d(), fd_r43x6_imag() returns the reduced fd_r43x6_t for
   zero (reduced), one (reduced), 2^255-19 (the non-trivial nearly
   reduced representation), d (reduced), 2*d (reduced) and sqrt(-1)
   (reduced) respectively.  d is defined as per IETF RFC 8032 Section
   5.1 (page 9) as -121665/121666.  imag^2 = -1 mod p = p-1.  These
   macros are robust.  Lanes 6 and 7 will be zero. */

#define fd_r43x6_zero() wwl_zero()
#define fd_r43x6_one()  wwl(             1L,            0L,            0L,            0L,            0L,            0L, 0L,0L )
#define fd_r43x6_p()    wwl( 8796093022189L,8796093022207L,8796093022207L,8796093022207L,8796093022207L,1099511627775L, 0L,0L )
#define fd_r43x6_d()    wwl( 6365466163363L, 253762649449L,   7518893317L, 260847760460L,7696165686388L, 704489577558L, 0L,0L )
#define fd_r43x6_2d()   wwl( 3934839304537L, 507525298899L,  15037786634L, 521695520920L,6596238350568L, 309467527341L, 0L,0L )
#define fd_r43x6_imag() wwl( 3467281080496L,6582290652611L,5210002954932L, 329084955603L,4526638806224L, 373767602335L, 0L,0L )

/* fd_r43x6_unpack(u) returns an unpacked r43x6_t corresponding to an
   arbitrary uint256 stored little endian 4 ulong radix 2^64 limb
   representation held in an AVX-2 vector:

     u = u0 + u1 2^64 + u2 2^128 + u3 2^192

   where un is the n-th 64-bit vector lane treated as a ulong.  Returned
   lanes 6 and 7 will be zero.  If u is in [0,2*p), the return will be a
   nearly reduced fd_r43x6_t.  If u is in [0,p), the return will be a
   reduced fd_r43x6_t. */

FD_FN_CONST static inline fd_r43x6_t
fd_r43x6_unpack( wv_t u ) {
  wwl_t const zero   = wwl_zero();
  wwl_t const perm   = wwl( 0x3f3f050403020100L,   // r0 = bits   0: 42 (43 bits, zero extend to 64 bits)
                            0x3f3f0a0908070605L,   // r1 = bits  43: 85 (43 bits, zero extend to 64 bits)
                            0x3f100f0e0d0c0b0aL,   // r2 = bits  86:128 (43 bits, zero extend to 64 bits)
                            0x3f3f151413121110L,   // r3 = bits 129:171 (43 bits, zero extend to 64 bits)
                            0x3f3f1a1918171615L,   // r4 = bits 172:214 (43 bits, zero extend to 64 bits)
                            0x3f3f1f1e1d1c1b1aL,   // r5 = bits 215:255 (41 bits, zero extend to 64 bits)
                            0x3f3f3f3f3f3f3f3fL,   // r6 = zero
                            0x3f3f3f3f3f3f3f3fL ); // r7 = zero
  wwl_t const rshift = wwl( 0L, 3L, 6L, 1L, 4L, 7L, 0L, 0L ); // r0/r1/r2/r3/r4/r5 bit 0 is u bit 0/43/86/129/172
  wwl_t const mask   = wwl_bcast( (1L<<43)-1L );                    // Keep 43 least significant bits for each lane
  return wwl_and( wwl_shru_vector( _mm512_permutexvar_epi8( perm, _mm512_inserti64x4( zero, u, 0 ) ), rshift ), mask );
}

/* fd_r43x6_pack(r) is the inverse of fd_r43x6_unpack.  r should be an
   unpacked fd_r43x6_t.  If r is also nearly reduced, the return will be
   in [0,2*p).  If r is also reduced fd_r43x6_t, the return will be in
   [0,p).  Ignores lanes 6 and 7. */

FD_FN_CONST static inline wv_t
fd_r43x6_pack( fd_r43x6_t r ) {

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

  wwl_t t0 = wwl_shru_vector( wwl_permute( wwl(  0L, 1L, 2L, 4L, 0L,0L,0L,0L ), r ), wwl(  0L,21L,42L,20L, 0L,0L,0L,0L ) );
  wwl_t t1 = wwl_shl_vector ( wwl_permute( wwl(  1L, 2L, 3L, 5L, 0L,0L,0L,0L ), r ), wwl( 43L,22L, 1L,23L, 0L,0L,0L,0L ) );
  wwl_t t2 = wwl_shl_vector ( wwl_permute( wwl(  1L, 2L, 4L, 5L, 0L,0L,0L,0L ), r ), wwl( 43L,22L,44L,23L, 0L,0L,0L,0L ) );

  return _mm512_extracti64x4_epi64( wwl_or( wwl_or( t0, t1 ), t2 ), 0 );
}

/* fd_r43x6_approx_carry_propagate_limbs(x,y) computes a signed
   fd_r43x6_t equivalent to an arbitrary fd_r43x6_t that has been
   extracted into the longs x0-x5 and stores the result into the longs
   y0-y5.  On return:

     y0    in [-19*2^23,2^43+19*(2^23-1))
     y1-y4 in [   -2^20,2^43+   (2^20-1))
     y5    in [   -2^20,2^40+   (2^20-1))

   In-place operation fine.  This macro is robust.

   If x is unsigned or more generally x0-x5 in [0,2^63), the result will
   be an unreduced fd_r43x6_t with:

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
   extracts and fd_r43x6 constructs.

   Note that if we used ulongs (and thus zero padding right shifts)
   below, this same style calculation could be used on an arbitrary
   _ulong_ limbed x.  The result would still be an unreduced fd_r43x6_t
   with:

     y0-y4 in [0,2^43+19*(2^24-1))
     y5    in [0,2^40+    2^21-1 ) */

#define fd_r43x6_approx_carry_propagate_limbs(x,y) do { \
    long const _m43 = (1L<<43)-1L;                      \
    long const _m40 = (1L<<40)-1L;                      \
    long _x0 = (x##0);                                  \
    long _x1 = (x##1);                                  \
    long _x2 = (x##2);                                  \
    long _x3 = (x##3);                                  \
    long _x4 = (x##4);                                  \
    long _x5 = (x##5);                                  \
    (y##0) = (_x0 & _m43) + 19L*(_x5>>40);              \
    (y##1) = (_x1 & _m43) +     (_x0>>43);              \
    (y##2) = (_x2 & _m43) +     (_x1>>43);              \
    (y##3) = (_x3 & _m43) +     (_x2>>43);              \
    (y##4) = (_x4 & _m43) +     (_x3>>43);              \
    (y##5) = (_x5 & _m40) +     (_x4>>43);              \
  } while(0)

/* fd_r43x6_approx_carry_propagate is a vectorized version of the above.
   Returned lanes 6 and 7 are zero.  If we've already extracted x's
   limbs and/or need the resulting limbs after, it is usually faster to
   do the extract and then use the scalar implementation.

   The fold_unsigned variant is the same but assumes x is unsigned or
   more generally x0-x5 in [0,2^63).  This allows a faster madd52lo to
   be used instead of a slower mullo.  (Hat tip to Philip Taffet for
   pointing this out.) It will also work for an arbitrary limbed ulong
   x.

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
#define fd_r43x6_approx_carry_propagate( x ) (__extension__({                                         \
    long const _m43 = (1L<<43)-1L;                                                                    \
    long const _m40 = (1L<<40)-1L;                                                                    \
    wwl_t    _x   = (x);                                                                              \
    wwl_add( wwl_and( _x, wwl( _m43,_m43,_m43,_m43,_m43,_m40, 0L,0L ) ),                              \
             wwl_mul( wwl( 19L,1L,1L,1L,1L,1L, 0L,0L ),                                               \
                      wwl_permute( wwl( 5L,0L,1L,2L,3L,4L, 6L,7L ),                                   \
                                   wwl_shr_vector( _x, wwl( 43L,43L,43L,43L,43L,40L, 0L,0L ) ) ) ) ); \
  }))
#else /* ... than a more obtuse shift-and-add based implementation */
#define fd_r43x6_approx_carry_propagate( x ) (__extension__({                                                \
    long const _m43 = (1L<<43)-1L;                                                                           \
    long const _m40 = (1L<<40)-1L;                                                                           \
    wwl_t _x   = (x);                                                                                        \
    wwl_t _xl  = wwl_and( _x, wwl( _m43,_m43,_m43,_m43,_m43,_m40, 0L,0L ) );                                 \
    wwl_t _xh  = wwl_shr_vector( _x, wwl( 43L,43L,43L,43L,43L,40L, 0L,0L ) );                                \
    wwl_t _c   = wwl_select( wwl( 5L,0L,1L,2L,3L,4L, 8L,8L ), _xh, wwl_zero() );                             \
    wwl_t _d   = wwl_and( wwl_add( wwl_shl( _c, 1 ), wwl_shl( _c, 4 ) ), wwl( -1L,0L,0L,0L,0L,0L, 0L,0L ) ); \
    /* _xl = <   x0l,x1l,x2l,x3l,x4l,x5l, 0,0> */                                                            \
    /* _c  = <   x5h,x0h,x1h,x2h,x3h,x4h, 0,0> */                                                            \
    /* _d  = <18*x5h,  0,  0,  0,  0,  0, 0,0> */                                                            \
    wwl_add( wwl_add( _xl, _c ), _d );                                                                       \
  }))
#endif

#define fd_r43x6_fold_unsigned( x ) (__extension__({                                             \
    long const _m43 = (1L<<43)-1L;                                                               \
    long const _m40 = (1L<<40)-1L;                                                               \
    wwl_t _x = (x);                                                                              \
    wwl_madd52lo( wwl_and( _x, wwl( _m43,_m43,_m43,_m43,_m43,_m40, 0L,0L ) ),                    \
                  wwl( 19L,1L,1L,1L,1L,1L, 0L,0L ),                                              \
                  wwl_permute( wwl( 5L,0L,1L,2L,3L,4L, 6L,7L ),                                  \
                               wwl_shru_vector( _x, wwl( 43L,43L,43L,43L,43L,40L, 0L,0L ) ) ) ); \
  }))

#define fd_r43x6_fold_signed( x ) (__extension__({                             \
    wwl_t const _b = wwl( 19L<<23,1L<<20,1L<<20,1L<<20,1L<<20,1L<<20, 0L,0L ); \
    wwl_add( fd_r43x6_approx_carry_propagate( wwl_sub( (x), _b ) ), _b );      \
  }))

/* fd_r43x6_biased_carry_propagate_limbs computes an equivalent
   fd_r43x6_t to a signed fd_r43x6_t that has been extracted into the
   longs x0-x5 and stores the result into the longs y0-y5.  x5 is
   subtracted by a small bias in [0,2^20] before that is added back
   after.  This has no impact on the element represented but can impact
   the range needed for limb 5.  In-place operation fine.  This macro is
   robust.

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
   to minimize the number of limb extracts and fd_r43x6 constructs. */

#define fd_r43x6_biased_carry_propagate_limbs(x,y,b) do { \
    long const _m43 = (1L<<43)-1L;                        \
    long const _m40 = (1L<<40)-1L;                        \
    long _y0 = (x##0);                                    \
    long _y1 = (x##1);                                    \
    long _y2 = (x##2);                                    \
    long _y3 = (x##3);                                    \
    long _y4 = (x##4);                                    \
    long _y5 = (x##5);                                    \
    long _b  = (b);                                       \
    long _c;                                              \
    _y5 -= _b;                                            \
    _c = _y5>>40; _y5 &= _m40; _y0 += 19L*_c;             \
    _c = _y0>>43; _y0 &= _m43; _y1 +=     _c;             \
    _c = _y1>>43; _y1 &= _m43; _y2 +=     _c;             \
    _c = _y2>>43; _y2 &= _m43; _y3 +=     _c;             \
    _c = _y3>>43; _y3 &= _m43; _y4 +=     _c;             \
    _c = _y4>>43; _y4 &= _m43; _y5 +=     _c;             \
    _y5 += _b;                                            \
    (y##0) = _y0;                                         \
    (y##1) = _y1;                                         \
    (y##2) = _y2;                                         \
    (y##3) = _y3;                                         \
    (y##4) = _y4;                                         \
    (y##5) = _y5;                                         \
  } while(0)

/* Note: fd_r43x6_biased_carry_propagate_limbs does not have a good
   AVX-512 implementation (it is highly sequential). */

/* fd_r43x6_mod_nearly_reduced_limbs computes the reduced fd_r43x6_t for
   a nearly reduced fd_r43x6_t that has been extracted into the longs
   x0-x5 and stores the limbs in the longs y0-y5.  In-place operation
   fine.  This macro is robust.  Theory:

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

#define fd_r43x6_mod_nearly_reduced_limbs(x,y) do { \
    long const _m43 = (1L<<43)-1L;                  \
    long const _m40 = (1L<<40)-1L;                  \
    long _y0 = (x##0);                              \
    long _y1 = (x##1);                              \
    long _y2 = (x##2);                              \
    long _y3 = (x##3);                              \
    long _y4 = (x##4);                              \
    long _y5 = (x##5);                              \
    long _c;                                        \
                                                    \
    /* y = x + 19, q = y>>255, y -= q<<255 */       \
    _y0 += 19L;                                     \
    _c = _y0 >> 43; _y0 &= _m43; _y1 += _c;         \
    _c = _y1 >> 43; _y1 &= _m43; _y2 += _c;         \
    _c = _y2 >> 43; _y2 &= _m43; _y3 += _c;         \
    _c = _y3 >> 43; _y3 &= _m43; _y4 += _c;         \
    _c = _y4 >> 43; _y4 &= _m43; _y5 += _c;         \
    _c = _y5 >> 40; _y5 &= _m40;                    \
                                                    \
    /* r = y - if(!q,19,0) */                       \
    _y0 -= fd_long_if( !_c, 19L, 0L );              \
    _c = _y0 >> 43; _y0 &= _m43; _y1 += _c;         \
    _c = _y1 >> 43; _y1 &= _m43; _y2 += _c;         \
    _c = _y2 >> 43; _y2 &= _m43; _y3 += _c;         \
    _c = _y3 >> 43; _y3 &= _m43; _y4 += _c;         \
    _c = _y4 >> 43; _y4 &= _m43; _y5 += _c;         \
                                                    \
    (y##0) = _y0;                                   \
    (y##1) = _y1;                                   \
    (y##2) = _y2;                                   \
    (y##3) = _y3;                                   \
    (y##4) = _y4;                                   \
    (y##5) = _y5;                                   \
  } while(0)

/* Note: fd_r43x6_mod_nearly_reduced_limbs does not have a good AVX-512
   implementation (it is highly sequential). */

/* fd_r43x6_approx_mod(x) returns a nearly reduced fd_r43x6_t equivalent
   to an arbitrary fd_r43x6_t x.  On return y5 will be in [0,2^40+2).

   fd_r43x6_approx_mod_signed(x) does the same for signed x or, more
   generally:

     x0    in [-2^63+19*2^23,2^63-19*(2^23-1))
     x1-x4 in [-2^63+   2^20,2^63-   (2^20-1))
     x5    in [-2^63+   2^20,2^63            )

   fd_r43x6_approx_mod_unsigned(x) does the same for unsigned x or, more
   generally:

     x0    in [0,2^63-19*(2^23-1))
     x1-x4 in [0,2^63-   (2^20-1))
     x5    in [0,2^63            )

   On return y5 will be in [0,2^40+2^20-1).

   fd_r43x6_approx_mod_unreduced(x) does the same for unreduced x.  On
   return y5 will be in [0,2^40+2^5-1).

   fd_r43x6_approx_mod_unpacked(x) does the same for unpacked x.  On
   return y5 will be in [0,2^40+1). */

FD_FN_UNUSED FD_FN_CONST static fd_r43x6_t /* Work around -Winline */
fd_r43x6_approx_mod( fd_r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  fd_r43x6_extract_limbs( x, y );

  /* At this point y is arbitrary.  We do an approx carry propagate to
     reduce the range of limbs suitable for a biased carry propagate.
     (Note: it is faster here to do extract then approx-cp than
     vector-approx-cp then extract.) */

  fd_r43x6_approx_carry_propagate_limbs( y, y );

  /* At this point y has:

       y0    in [-19*2^23,2^43+19*(2^23-1))
       y1-y4 in [   -2^20,2^43+   (2^20-1))
       y5    in [   -2^20,2^40+   (2^20-1))

     An unbiased carry propagate could produce y5=-1.  So, we use a
     biased c-p with a b=1.  TODO: CONSIDER JUST USING 2^20 BIAS ALWAYS? */

  fd_r43x6_biased_carry_propagate_limbs( y, y, 1L );

  return fd_r43x6( y0, y1, y2, y3, y4, y5 );
}

FD_FN_UNUSED FD_FN_CONST static fd_r43x6_t /* Work around -Winline */
fd_r43x6_approx_mod_signed( fd_r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  fd_r43x6_extract_limbs( x, y );

  /* At this point y has:

       x0    in [-2^63+19*2^23,2^63-19*(2^23-1))
       x1-x4 in [-2^63+   2^20,2^63-   (2^20-1))
       x5    in [-2^63+   2^20,2^63            )

     so we can do a biased carry propagate y with b=2^20 as described
     above. */

  fd_r43x6_biased_carry_propagate_limbs( y, y, 1L<<20 );

  return fd_r43x6( y0, y1, y2, y3, y4, y5 );
}

FD_FN_UNUSED FD_FN_CONST static fd_r43x6_t /* Work around -Winline */
fd_r43x6_approx_mod_unsigned( fd_r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  fd_r43x6_extract_limbs( x, y );

  /* At this point y has:

       x0    in [0,2^63-19*(2^23-1))
       x1-x4 in [0,2^63-   (2^20-1))
       x5    in [0,2^63            )

     so we can do an unbiased carry propagate as described above. */

  fd_r43x6_biased_carry_propagate_limbs( y, y, 0L );

  return fd_r43x6( y0, y1, y2, y3, y4, y5 );
}

#define fd_r43x6_approx_mod_unreduced fd_r43x6_approx_mod_unsigned /* no difference in impl, tighter y5 result described above */
#define fd_r43x6_approx_mod_unpacked  fd_r43x6_approx_mod_unsigned /* no difference in impl, tighter y5 result described above */

/* fd_r43x6_mod(x) returns the reduced fd_r43x6_t equivalent to an
   arbitrary fd_r43x6_t x.

   fd_r43x6_approx_mod_signed(x) does the same for signed x or more
   generally:

     x0    in [-2^63+19*2^23,2^63-19*(2^23-1))
     x1-x4 in [-2^63+   2^20,2^63-   (2^20-1))
     x5    in [-2^63+   2^20,2^63            )

   fd_r43x6_mod_unreduced(x) does the same for unreduced x, or, more
   generally:

     x0    in [0,2^63-19*(2^23-1))
     x1-x4 in [0,2^63-   (2^20-1))
     x5    in [0,2^63            )

   fd_r43x6_mod_unpacked(x) does the same for unpacked x.

   fd_r43x6_mod_nearly_reduced(x) does the same for nearly reduced x. */

FD_FN_UNUSED FD_FN_CONST static fd_r43x6_t /* Work around -Winline */
fd_r43x6_mod( fd_r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  fd_r43x6_extract_limbs( x, y );
  fd_r43x6_approx_carry_propagate_limbs( y, y );
  fd_r43x6_biased_carry_propagate_limbs( y, y, 1L );
  /* At this point, x is nearly reduced */
  fd_r43x6_mod_nearly_reduced_limbs( y, y );
  return fd_r43x6( y0, y1, y2, y3, y4, y5 );
}

FD_FN_UNUSED FD_FN_CONST static fd_r43x6_t /* Work around -Winline */
fd_r43x6_mod_signed( fd_r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  fd_r43x6_extract_limbs( x, y );
  fd_r43x6_biased_carry_propagate_limbs( y, y, 1L<<20 );
  /* At this point, x is nearly reduced */
  fd_r43x6_mod_nearly_reduced_limbs( y, y );
  return fd_r43x6( y0, y1, y2, y3, y4, y5 );
}

FD_FN_UNUSED FD_FN_CONST static fd_r43x6_t /* Work around -Winline */
fd_r43x6_mod_unsigned( fd_r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  fd_r43x6_extract_limbs( x, y );
  fd_r43x6_biased_carry_propagate_limbs( y, y, 0L );
  /* At this point, x is nearly reduced */
  fd_r43x6_mod_nearly_reduced_limbs( y, y );
  return fd_r43x6( y0, y1, y2, y3, y4, y5 );
}

#define fd_r43x6_mod_unreduced fd_r43x6_mod_unsigned /* no difference in impl */
#define fd_r43x6_mod_unpacked  fd_r43x6_mod_unsigned /* no difference in impl */

FD_FN_UNUSED FD_FN_CONST static fd_r43x6_t /* Work around -Winline */
fd_r43x6_mod_nearly_reduced( fd_r43x6_t x ) {
  long y0, y1, y2, y3, y4, y5;
  fd_r43x6_extract_limbs( x, y );
  /* At this point, x is already nearly reduced */
  fd_r43x6_mod_nearly_reduced_limbs( y, y );
  return fd_r43x6( y0, y1, y2, y3, y4, y5 );
}

/* fd_r43x6_neg_fast(x)   returns z = -x
   fd_r43x6_add_fast(x,y) returns z = x + y
   fd_r43x6_sub_fast(x,y) returns z = x - y

   These will be applied to lanes 6 and 7 and these assume that the
   corresponding limbs of x and y when added / subtracted will produce a
   result that doesn't overflow the range of a long.

   For example, it is safe to add a large (but bounded) number of
   unpacked x to produce an unreduced sum and then do a single mod at
   the end to produce the reduced result.  With 0 < ll <= mm < 63 and
   letting nn = mm+1, given the input ranges, the below give
   conservative output ranges.

      -ull -> sll
      -sll -> sll

      ull + umm -> unn, umm + ull -> unn
      ull + smm -> snn, umm + sll -> snn
      sll + umm -> snn, smm + ull -> snn
      sll + smm -> snn, smm + sll -> snn

      ull - umm -> smm, umm - ull -> smm
      ull - smm -> snn, umm - sll -> snn
      sll - umm -> snn, smm - ull -> snn
      sll - smm -> snn, smm - sll -> snn */

#define fd_r43x6_neg_fast( x )    wwl_sub( wwl_zero(), (x) )
#define fd_r43x6_add_fast( x, y ) wwl_add( (x), (y) )
#define fd_r43x6_sub_fast( x, y ) wwl_sub( (x), (y) )

/* fd_r43x6_mul_fast(x,y) returns z = x*y as an unsigned fd_r43x6_t
   with lanes 6 and 7 zero where x and y are unreduced fd_r43x6_t's
   (i.e. in u47).  Ignores lanes 6 and 7 of x and assumes lanes 6 and 7
   of y are zero.  More specifically, u44/u45/u46/u47 inputs produce a
   u62/u62/u62/u63 output. */

FD_FN_UNUSED FD_FN_CONST static fd_r43x6_t /* Work around -Winline */
fd_r43x6_mul_fast( fd_r43x6_t x,
                   fd_r43x6_t y ) {

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

    Note: the [0,2^47) range for unreduced fd_r43x6_t was picked to
    yield pl and ph with similar ranges while allowing for fast
    reduction below.

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

  wwl_t const zero = wwl_zero();

  wwl_t x0  = wwl_permute( zero,            x );
  wwl_t x1  = wwl_permute( wwl_one(),       x );
  wwl_t x2  = wwl_permute( wwl_bcast( 2L ), x );
  wwl_t x3  = wwl_permute( wwl_bcast( 3L ), x );
  wwl_t x4  = wwl_permute( wwl_bcast( 4L ), x );
  wwl_t x5  = wwl_permute( wwl_bcast( 5L ), x );

  wwl_t t0  = wwl_madd52lo( zero,                                      x0, y );
  wwl_t t1  = wwl_madd52lo( wwl_shl( wwl_madd52hi( zero, x0, y ), 9 ), x1, y );
  wwl_t t2  = wwl_madd52lo( wwl_shl( wwl_madd52hi( zero, x1, y ), 9 ), x2, y );
  wwl_t t3  = wwl_madd52lo( wwl_shl( wwl_madd52hi( zero, x2, y ), 9 ), x3, y );
  wwl_t t4  = wwl_madd52lo( wwl_shl( wwl_madd52hi( zero, x3, y ), 9 ), x4, y );
  wwl_t t5  = wwl_madd52lo( wwl_shl( wwl_madd52hi( zero, x4, y ), 9 ), x5, y );
  wwl_t t6  =               wwl_shl( wwl_madd52hi( zero, x5, y ), 9 );

  wwl_t p0j =                  t0;      /* note: q0j = 0 */
  wwl_t p1j = wwl_slide( zero, t1, 7 ); /* note: q1j = 0 */
  wwl_t p2j = wwl_slide( zero, t2, 6 ); /* note: q2j = 0 */
  wwl_t p3j = wwl_slide( zero, t3, 5 ); wwl_t q3j = wwl_slide( t3, zero, 5 );
  wwl_t p4j = wwl_slide( zero, t4, 4 ); wwl_t q4j = wwl_slide( t4, zero, 4 );
  wwl_t p5j = wwl_slide( zero, t5, 3 ); wwl_t q5j = wwl_slide( t5, zero, 3 );
  wwl_t p6j = wwl_slide( zero, t6, 2 ); wwl_t q6j = wwl_slide( t6, zero, 2 );

  wwl_t zl  = wwl_add( wwl_add( wwl_add( p0j, p1j ), wwl_add( p2j, p3j ) ), wwl_add( wwl_add( p4j, p5j ), p6j ) );
  wwl_t zh  = wwl_add( wwl_add( q3j, q4j ), wwl_add( q5j, q6j ) );

  /* At this point:
       z = <zl0,zl1,zl2,zl3,zl4,zl5,zl6,zl7> + 2^344 <zh0,zh1,zh2,zh3,0,0,0,0> */

  wwl_t za  = wwl_and( zl, wwl( -1L,-1L,-1L,-1L,-1L,-1L, 0L,0L ) );
  wwl_t zb  = wwl_slide( zl, zh, 6 );

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

     (These limbs are too large to use in a subsequent multiply but they
     are in the range where we can do a fd_r43x6_fold_unsigned,
     yielding:

       z0    in [0,2^43+19*(2^23-1))
       z1-z4 in [0,2^43+   (2^20-1))
       z5    in [0,2^40+   (2^20-1))

     This is an unreduced fd_r43x6_t and thus suitable direct use in
     subsequent multiply operations.  See fd_r43x6_mul.)

     Note that mullo is slow.  Since 152 = 2^7 + 2^4 + 2^3 and is
     applied to all lanes, we can compute za+152*zb slightly faster via
     shift and add techniques. */

  return wwl_add( wwl_add( za, wwl_shl( zb, 7 ) ), wwl_add( wwl_shl( zb, 4 ), wwl_shl( zb, 3 ) ) );
}

/* fd_r43x6_sqr_fast(x) returns z = x^2 as an unsigned fd_r43x6_t with
   lanes 6 and 7 zero where x is an unreduced fd_r43x6_t (i.e. in u47).
   Assumes lanes 6 and 7 of x are zero.  More specifically,
   u44/u45/u46/u47 inputs produce a u61/u61/u62/u62 output.

   IMPORTANT!  z may not be the same representation returned by
   fd_r43x6_mul_fast(x,x).  This is because doubling of the off-diagonal
   partial products is done _before_ the multiplications while it is
   done _after_ the multiplications in fd_r43x6_mul.  This is faster for
   sqr and reduces the range of the outputs slightly (which can then be
   used to further optimize code using sqr). */

FD_FN_UNUSED FD_FN_CONST static fd_r43x6_t /* Work around -Winline */
fd_r43x6_sqr_fast( fd_r43x6_t x ) {
  wwl_t const zero = wwl_zero();

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
     different notions of high/low. */

  wwl_t x0 = wwl_permute( wwl( 0L, 0L, 0L, 0L, 0L, 0L, 3L, 3L ), x );
  wwl_t x1 = wwl_permute( wwl( 0L, 1L, 2L, 3L, 4L, 5L, 3L, 4L ), x );
  wwl_t x2 = wwl_permute( wwl( 4L, 4L, 1L, 1L, 1L, 1L, 1L, 7L ), x );
  wwl_t x3 = wwl_permute( wwl( 4L, 5L, 1L, 2L, 3L, 4L, 5L, 7L ), x );
  wwl_t x4 = wwl_permute( wwl( 3L, 7L, 5L, 7L, 2L, 2L, 2L, 2L ), x );
  wwl_t x5 = wwl_permute( wwl( 5L, 7L, 5L, 7L, 2L, 3L, 4L, 5L ), x );

  /* Double the non-square terms. */

  x0 = wwl_shl_vector( x0, wwl( 0L, 1L, 1L, 1L, 1L, 1L, 0L, 1L ) );
  x2 = wwl_shl_vector( x2, wwl( 0L, 1L, 0L, 1L, 1L, 1L, 1L, 1L ) );
  x4 = wwl_shl_vector( x4, wwl( 1L, 1L, 0L, 1L, 0L, 1L, 1L, 1L ) );

  wwl_t p0l = wwl_madd52lo( zero, x0, x1 );
  wwl_t p1l = wwl_madd52lo( zero, x2, x3 );
  wwl_t p2l = wwl_madd52lo( zero, x4, x5 );

  /* Use the same approach as in the multiply to generate the high bits
     of each individual product. */

  wwl_t p0h = wwl_shl( wwl_madd52hi( zero, x0, x1 ), 9 );
  wwl_t p1h = wwl_shl( wwl_madd52hi( zero, x2, x3 ), 9 );
  wwl_t p2h = wwl_shl( wwl_madd52hi( zero, x4, x5 ), 9 );

  /* Generate masks to split p_i into the terms that belong in the high
     word and low word. */

  wwl_t const mask1 = wwl( -1L,-1L, 0L, 0L, 0L, 0L, 0L,0L );
  wwl_t const mask2 = wwl( -1L, 0L,-1L, 0L, 0L, 0L, 0L,0L );
  wwl_t zll = wwl_add( p0l, wwl_add( wwl_andnot( mask1, p1l ), wwl_andnot( mask2, p2l ) ) );
  wwl_t zlh = wwl_add( p0h, wwl_add( wwl_andnot( mask1, p1h ), wwl_andnot( mask2, p2h ) ) );
  wwl_t zhl =               wwl_add( wwl_and   ( mask1, p1l ), wwl_and   ( mask2, p2l ) );
  wwl_t zhh =               wwl_add( wwl_and   ( mask1, p1h ), wwl_and   ( mask2, p2h ) );

  /* Generate zl and zh as in fd_r43x6_mul_fast */

  wwl_t zl  = wwl_add( zll,          wwl_slide( zero, zlh, 7 ) );
  wwl_t zh  = wwl_add( zhl, wwl_add( wwl_slide( zero, zhh, 7 ), wwl_slide( zlh, zero, 7 ) ) );

  wwl_t za  = wwl_and( zl, wwl( -1L,-1L,-1L,-1L,-1L,-1L, 0L,0L ) );
  wwl_t zb  = wwl_slide( zl, zh, 6 );

  /* By the same type of analysis above, we can still do the sum
     directly as:

       z{0,1,2,3,4,5} < 2^51 {1826,1675,1222,767,618,163} < 2^62

     (Note that the result is fits into u62 instead of u63 like for
     mul_fast.) */

  return wwl_add( wwl_add( za, wwl_shl( zb, 7 ) ), wwl_add( wwl_shl( zb, 4 ), wwl_shl( zb, 3 ) ) );
}

/* fd_r43x6_scale_fast(x0,y) returns z = <x0,0,0,0,0>*y as an unsigned
   fd_r43x6_t with lanes 6 and 7 zero where x is in [0,2^47) and y is an
   unreduced fd_r43x6_t (i.e. in u47).  Assumes lanes 6 and 7 of y are
   zero.  More specifically, u47 inputs produce a u59 output. */

FD_FN_CONST static inline fd_r43x6_t
fd_r43x6_scale_fast( long       _x0,
                     fd_r43x6_t y ) {

  /* This is fd_r43x6_mul with x = <_x0,0,0,0,0> and zeros values
     optimized out.  See fd_r43x6_mul for detailed explanation how this
     works. */

  wwl_t const zero = wwl_zero();

  wwl_t x0  = wwl_bcast( _x0 );

  wwl_t t0  =          wwl_madd52lo( zero, x0, y );
  wwl_t t1  = wwl_shl( wwl_madd52hi( zero, x0, y ), 9 );

  wwl_t p0j =            t0;
  wwl_t p1j = wwl_slide( zero, t1, 7 );

  wwl_t zl  = wwl_add( p0j, p1j );

  wwl_t za  = wwl_and( zl, wwl( -1L,-1L,-1L,-1L,-1L,-1L, 0L,0L ) );
  wwl_t zb  = wwl_slide( zl, zero, 6 );

  /* At this point:

       za{0,1,2,3,4,5} < 2^51 {2,3,3,3,3,3}
       zb0             < 2^51

     such that:

       z{0,1,2,3,4,5} < 2^51 {154,3,3,3,3,3} < 2^63 */

  return wwl_add( wwl_add( za, wwl_shl( zb, 7 ) ), wwl_add( wwl_shl( zb, 4 ), wwl_shl( zb, 3 ) ) );
}

/* fd_r43x6_neg/add/sub/mul/scale fold the results of their fast
   counterparts above.  Given unreduced r43x6_t's (i.e. in u47) with
   lanes 6 and 7 zero and/or x0 in [0,2^47), these return unreduced
   results (in u44) with lanes 6 and 7 zero. */

#define fd_r43x6_neg( x )       fd_r43x6_fold_signed  ( fd_r43x6_neg_fast  ( (x) ) )
#define fd_r43x6_add( x, y )    fd_r43x6_fold_unsigned( fd_r43x6_add_fast  ( (x), (y) ) )
#define fd_r43x6_sub( x, y )    fd_r43x6_fold_signed  ( fd_r43x6_sub_fast  ( (x), (y) ) )
#define fd_r43x6_mul( x, y )    fd_r43x6_fold_unsigned( fd_r43x6_mul_fast  ( (x), (y) ) )
#define fd_r43x6_sqr( x )       fd_r43x6_fold_unsigned( fd_r43x6_sqr_fast  ( (x) ) )
#define fd_r43x6_scale( x0, y ) fd_r43x6_fold_unsigned( fd_r43x6_scale_fast( (x0), (y) ) )

/* fd_r43x6_invert(z) returns the multiplicative inverse of z in GF(p)
   as an unreduced fd_r43x6_t (in u44) with lanes 6 and 7 zero where z
   is an unreduced fd_r43x6_t (i.e. in u47) with lanes 6 and 7 zero. */

FD_FN_CONST fd_r43x6_t
fd_r43x6_invert( fd_r43x6_t z );

/* Miscellaneous APIs *************************************************/

/* fd_r43x6_if(c,x,y) returns x if c is non-zero and y if not.
   Branchless for deterministic timing.  This macro is robust. */

#define fd_r43x6_if(c,x,y) wwl_blend( (-!(c)) & 0xff, (x), (y) )

/* fd_r43x6_swap_if(c,x,y) will swap the contents of x and y if c is
   non-zero and leave the contents of x and y unchanged otherwise.
   Branchless for deterministic timing.  This macro is robust. */

#define fd_r43x6_swap_if(c,x,y) do {    \
    wwl_t _x = (x);                     \
    wwl_t _y = (y);                     \
    int   _m = (-!(c)) & 0xff;          \
    (x)      = wwl_blend( _m, _y, _x ); \
    (y)      = wwl_blend( _m, _x, _y ); \
  } while(0)

/* fd_r43x6_is_nonzero(x) reduces a signed fd_r43x6_t x (i.e. in s62)
   and returns 0 if the result is zero and 1 if the result is non-zero. */

FD_FN_UNUSED FD_FN_CONST static int /* Work around -Winline */
fd_r43x6_is_nonzero( fd_r43x6_t x ) {
  long l0, l1, l2, l3, l4, l5;
  fd_r43x6_extract_limbs( x, l );                        /* l is signed */
  fd_r43x6_biased_carry_propagate_limbs( l, l, 1L<<20 ); /* l is nearly reduced */
  fd_r43x6_mod_nearly_reduced_limbs( l, l );             /* l is reduced */
  return !!(l0|l1|l2|l3|l4|l5);
}

/* fd_r43x6_diagnose(x) reduces a signed r43x6_t x (i.e. in s62) and
   returns -1 if the result is zero and the least significant bit of the
   reduced result otherwise. */

FD_FN_UNUSED FD_FN_CONST static int /* Work around -Winline */
fd_r43x6_diagnose( fd_r43x6_t x ) {
  long l0, l1, l2, l3, l4, l5;
  fd_r43x6_extract_limbs( x, l );                               /* l is signed */
  fd_r43x6_biased_carry_propagate_limbs( l, l, 1L<<20 );        /* l is nearly reduced */
  fd_r43x6_mod_nearly_reduced_limbs( l, l );                    /* l is reduced */
  return fd_int_if( !(l0|l1|l2|l3|l4|l5), -1, (int)(l0 & 1L) ); /* cmov */
}

/* fd_r43x6_pow22523(z) returns z^((p-5)/8) = z^(2^252 - 3) as an unreduced
   fd_r43x6_t (in u44) with lanes 6 and 7 zero where z is an unreduced
   r43x6_t (i.e. in u47) with lanes 6 and 7 of zero. */

FD_FN_CONST fd_r43x6_t
fd_r43x6_pow22523( fd_r43x6_t z );

FD_PROTOTYPES_END

#include "fd_r43x6_inl.h"

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_ed25519_avx512_fd_r43x6_h */
