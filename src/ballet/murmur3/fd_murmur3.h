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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_murmur3_fd_murmur3_h */
