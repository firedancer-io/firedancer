#ifndef HEADER_fd_src_waltz_http_fd_http_h
#define HEADER_fd_src_waltz_http_fd_http_h

/* Shared HTTP utilities for servers and clients. */

#include "../../util/fd_util_base.h"

#define FD_HTTP_PARSE_CONTENT_LEN_OK        ( 0)
#define FD_HTTP_PARSE_CONTENT_LEN_OVERFLOW  (-1)
#define FD_HTTP_PARSE_CONTENT_LEN_MALFORMED (-2)

FD_PROTOTYPES_BEGIN

/* fd_http_parse_content_len parses an HTTP Content-Length header
   value from the buffer s[0,s_len) into *out.

   Every byte in the range must be an ASCII decimal digit ('0'-'9')
   and the resulting value must fit in a ulong.  This implies the
   buffer should not be null-terminated.

   Returns FD_HTTP_PARSE_CONTENT_LEN_OK (0) on success (*out is
   populated), FD_HTTP_PARSE_CONTENT_LEN_OVERFLOW (-1) if all
   bytes are digits but the value exceeds ULONG_MAX (*out is not
   modified), or FD_HTTP_PARSE_CONTENT_LEN_MALFORMED (-2) on
   empty input or a non-digit byte (*out is not modified). */

static inline int
fd_http_parse_content_len( char const * s,
                           ulong        s_len,
                           ulong *      out ) {
  if( FD_UNLIKELY( !s_len ) ) return FD_HTTP_PARSE_CONTENT_LEN_MALFORMED;
  ulong val = 0UL;
  for( ulong i=0UL; i<s_len; i++ ) {
    char c = s[i];
    if( FD_UNLIKELY( (c<'0') | (c>'9') ) ) return FD_HTTP_PARSE_CONTENT_LEN_MALFORMED;
    ulong digit = (ulong)(c-'0');
    if( FD_UNLIKELY( val>(ULONG_MAX-digit)/10UL ) ) return FD_HTTP_PARSE_CONTENT_LEN_OVERFLOW;
    val = val*10UL + digit;
  }
  *out = val;
  return FD_HTTP_PARSE_CONTENT_LEN_OK;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_http_fd_http_h */
