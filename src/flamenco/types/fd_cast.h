#ifndef HEADER_fd_src_flamenco_types_fd_cast_h
#define HEADER_fd_src_flamenco_types_fd_cast_h

#include "../../util/bits/fd_float.h"

/* From https://doc.rust-lang.org/rust-by-example/types/cast.html

   Since Rust 1.45, the `as` keyword performs a *saturating cast*
   when casting from float to int. If the floating point value exceeds
   the upper bound or is less than the lower bound, the returned value
   will be equal to the bound crossed. */

FD_PROTOTYPES_BEGIN

/* Cast a double to unsigned long the same way as rust by suturating.
   Saturate to 0 if the value is negative or NaN.
   Saturate to ULONG_MAX if the value is greater than ULONG_MAX. */
FD_FN_CONST static inline ulong
fd_rust_cast_double_to_ulong( double f ) {
  ulong u = fd_dblbits( f );
  /* Check if the exponent is all 1s (infinity or NaN )*/
  if( fd_dblbits_bexp( u ) == 0x7FFUL ) {
    /* Check if the mantissa is 0 (infinity) */
    if( fd_dblbits_mant( u ) == 0 ) {
      return ULONG_MAX;
    } else {
      /* NaN case */
      return 0;
    }
  }

  /* If the value is negative saturate to 0 */
  if( fd_dblbits_sign( u ) == 1 ) {
    return 0;
  }

  /* Saturate to max unsigned long value */
  if( f > (double)ULONG_MAX ) {
    return ULONG_MAX;
  }

  /* Normal value, cast to unsigned long */
  return (ulong)f;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_types_fd_cast_h */
