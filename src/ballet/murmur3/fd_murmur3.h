#ifndef HEADER_fd_src_ballet_murmur3_fd_murmur3_h
#define HEADER_fd_src_ballet_murmur3_fd_murmur3_h

/* fd_murmur3 provides APIs for Murmur3 hashing of messages. */

#include "../fd_ballet_base.h"

FD_PROTOTYPES_BEGIN

/* fd_murmur3_32 computes the Murmur3-32 hash given a hash seed and a
   contiguous memory region to serve as input of size sz.  data points
   to the first byte of the input and may be freed on return.  Returns
   the hash digest as a 32-bit integer.  Is idempotent (Guaranteed to
   return the same hash given the same seed and input byte stream) */

FD_FN_PURE uint
fd_murmur3_32( void const * data,
               ulong        sz,
               uint         seed );

/* fd_pchash computes the hash of a program counter suitable for use as
   the call instruction immediate.  Equivalent to fd_murmur3_32 with
   zero seed and pc serialized to little-endian ulong. */

uint
fd_pchash( uint pc );

/* Inverse of the above.  E.g.:
     fd_pchash_inverse( fd_pchash( (uint)x ) )==(uint)x
   and:
     fd_pchash( fd_pchash_inverse( (uint)x ) )==(uint)x */

static inline uint
fd_pchash_inverse( uint hash ) {
  uint x = hash;
  x ^= x >> 16;
  x *= 0x7ed1b41dU;
  x ^= (x >> 13) ^ (x >> 26);
  x *= 0xa5cb9243U;
  x ^= x >> 16;
  x ^= 8;
  x -= 0xe6546b64U;
  x *= 0xcccccccdU;
  x  = fd_uint_rotate_right( x, 13 );
  x -= 0xe6546b64U;
  x *= 0xcccccccdU;
  x  = fd_uint_rotate_right( x, 13 );
  x *= 0x56ed309bU;
  x  = fd_uint_rotate_right( x, 15 );
  x *= 0xdee13bb1U;
  return x;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_murmur3_fd_murmur3_h */
