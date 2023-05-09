#ifndef HEADER_fd_src_util_bits_fd_sat_h
#define HEADER_fd_src_util_bits_fd_sat_h

#include "fd_bits.h"

/* Set of primitives for saturating math operations, mimicing the behaviour
   of Rust's primitive `saturating_add`, `saturating_sub`, `saturating_mul` operations.
   These saturate at the boundaries of the integer representation, instead of overflowing
   or underflowing.
   
   Note that this is a placeholder API, and the implementations will be optimised and hardened in future.
   The intent of this is to to provide an abstraction for saturating operations which
   can be used throughout the codebase, providing a single place to optimize these. */

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_ulong_sat_add( ulong x, ulong y ) {
  ulong res = x + y;
  return fd_ulong_if( res < x, ULONG_MAX, res );
}

FD_FN_CONST static inline ulong
fd_ulong_sat_mul( ulong x, ulong y ) {
  ulong res = x * y;
  uchar overflow = ( x != 0 ) && ( y != 0 ) && ( ( res < x ) || ( res < y ) || ( ( x / res ) != y ) );
  return fd_ulong_if( overflow, ULONG_MAX, res );
}

FD_FN_CONST static inline ulong
fd_ulong_sat_sub( ulong x, ulong y ) {
  ulong res = x - y;
  return fd_ulong_if( res > x, 0, res );
}

FD_FN_CONST static inline uint
fd_uint_sat_add( uint x, uint y ) {
  uint res = x + y;
  return fd_uint_if( res < x, UINT_MAX, res );
}

FD_FN_CONST static inline uint
fd_uint_sat_mul( uint x, uint y ) {
  uint res = x * y;
  uchar overflow = ( x != 0 ) && ( y != 0 ) && ( ( res < x ) || ( res < y ) || ( ( x / res ) != y ) );
  return fd_uint_if( overflow, UINT_MAX, res );
}

FD_FN_CONST static inline uint
fd_uint_sat_sub( uint x, uint y ) {
  uint res = x - y;
  return fd_uint_if( res > x, 0, res );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_bits_fd_sat_h */
