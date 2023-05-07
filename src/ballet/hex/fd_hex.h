#ifndef HEADER_fd_src_ballet_hex_fd_hex_h
#define HEADER_fd_src_ballet_hex_fd_hex_h

/* fd_hex.h provides methods for converting between binary and hex. */

#include "../fd_ballet_base.h"

ulong
fd_hex_decode( void *       dst,
               char const * hex,
               ulong        sz );

#endif /* HEADER_fd_src_ballet_hex_fd_hex_h */

