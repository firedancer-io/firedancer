#ifndef HEADER_fd_src_ballet_hex_fd_hex_h
#define HEADER_fd_src_ballet_hex_fd_hex_h

/* fd_hex.h provides methods for converting between binary and hex.

   Each byte is encoded to two chars matching `[0-9a-f]`.
   Decoding is case-insensitive and will convert each two chars matching
   `[0-9a-fA-F]` into one byte. */

#include "../fd_ballet_base.h"

/* fd_hex_decode reads up to sz*2 chars from the hex-encoded buffer at
   src.  Up to sz decoded bytes are written to dst.  Returns sz on
   success.  Returns the byte index in [0;sz) at which decoding failed
   on failure. */

ulong
fd_hex_decode( void *       FD_RESTRICT dst,
               char const * FD_RESTRICT src,
               ulong                    sz );

char *
fd_hex_encode( char *       FD_RESTRICT dst,
               void const * FD_RESTRICT src,
               ulong                    sz );

#endif /* HEADER_fd_src_ballet_hex_fd_hex_h */

