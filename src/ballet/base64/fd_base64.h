#ifndef HEADER_fd_src_ballet_base64_fd_base64_h
#define HEADER_fd_src_ballet_base64_fd_base64_h

/* fd_base64.h provides methods for converting between binary and base64. */
#include "../fd_ballet_base.h"
int
fd_base64_decode( const char *  encoded,
                  uchar *       decoded );

ulong
fd_base64_encode( const uchar * data,
                  int           data_len,
                  char *        encoded );

#endif /* HEADER_fd_src_ballet_base64_fd_base64_h */
