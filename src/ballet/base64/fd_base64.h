#ifndef HEADER_fd_src_ballet_base64_fd_base64_h
#define HEADER_fd_src_ballet_base64_fd_base64_h

/* fd_base64.h provides methods for converting between binary and
   base64. */

#include "../fd_ballet_base.h"

FD_PROTOTYPES_BEGIN

long
fd_base64_decode( uchar *      out,
                  char const * in,
                  ulong        in_len );

ulong
fd_base64_encode( const uchar * data,
                  int           data_len,
                  char *        encoded );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_base64_fd_base64_h */

