#ifndef HEADER_fd_src_flamenco_types_fd_cast_h
#define HEADER_fd_src_flamenco_types_fd_cast_h

#include "../../util/bits/fd_float.h"

/* From https://doc.rust-lang.org/rust-by-example/types/cast.html

   Since Rust 1.45, the `as` keyword performs a *saturating cast*
   when casting from float to int. If the floating point value exceeds
   the upper bound or is less than the lower bound, the returned value
   will be equal to the bound crossed. */

FD_PROTOTYPES_BEGIN

#if FD_HAS_DOUBLE

/* Cast a double to unsigned long with identical behaviour to Rust's
   saturating "as" case.
   Saturate to 0 if the value is negative or NaN.
   Saturate to ULONG_MAX if the value is greater than ULONG_MAX. */
FD_FN_CONST static inline ulong
fd_rust_cast_double_to_ulong( double f ) {
  ulong u = fd_dblbits( f );

  /* NaN saturates to 0. */
  if( FD_UNLIKELY( fd_dblbits_bexp( u )==0x7FFUL && fd_dblbits_mant( u )!=0 ) ) {
    return 0;
  }

  /* Negative values (including -Inf and -0.0) saturate to 0. */
  if( FD_UNLIKELY( fd_dblbits_sign( u )==1 ) ) {
    return 0;
  }

  /* +Inf or values >= 2^64 saturate to ULONG_MAX.
      A positive double has value 1.mant * 2^(bexp-1023).
      When bexp >= 1087 (exponent >= 64), the value is >= 2^64
      and cannot fit in a ulong. bexp=0x7FF (+Inf) also caught here
      but NaN was already handled above. */
  ulong bexp = fd_dblbits_bexp( u );
  if( FD_UNLIKELY( bexp>=1087UL ) ) {
    return ULONG_MAX;
  }

  /* Subnormals (bexp==0) have value < 1.0 and truncate to 0. */
  if( FD_UNLIKELY( bexp==0UL ) ) {
    return 0;
  }

  /* Normal value in [0, 2^64), is safe to convert.

     value = (1 << 52 | mantissa) >> (52 - (bexp - 1023))
     when bexp-1023 > 52, shift left instead
     bexp is within [1, 1086], so exponent = bexp-1023 is within [-1022, 63]
     shift = 52 - exponent is within [-11, 1074]
     For shift >= 64, result is 0 (very small positive numbers). */
  ulong mant = fd_dblbits_mant( u ) | (1UL << 52);
  int  shift = 52 - (int)( bexp-1023UL );

  if( shift >= 64 ) {
    return 0;
  } else if( shift>=0 ) {
    return mant >> shift;
  } else {
    return mant << (-shift);
  }
}

#endif /* FD_HAS_DOUBLE */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_types_fd_cast_h */
