#ifndef HEADER_fd_src_waltz_http_fd_http_h
#define HEADER_fd_src_waltz_http_fd_http_h

/* Shared HTTP utilities for servers and clients. */

#include "../../util/fd_util_base.h"

#define FD_HTTP_PARSE_CONTENT_LEN_OK        ( 0)
#define FD_HTTP_PARSE_CONTENT_LEN_OVERFLOW  (-1)
#define FD_HTTP_PARSE_CONTENT_LEN_MALFORMED (-2)

#define FD_HTTP_CORS_ORIGIN_MAX ( 16UL)
#define FD_HTTP_CORS_ORIGIN_SZ  (256UL)

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

/* fd_http_cors_match_origin resolves the Access-Control-Allow-Origin
   value to send for a request with the given Origin header against a
   configured allowlist.  Returns "*" if the allowlist contains "*", the
   matching entry from the allowlist if request_origin is present in it,
   or NULL if CORS should not be applied to this response. */

static inline char const *
fd_http_cors_match_origin( char const   allowlist[][ FD_HTTP_CORS_ORIGIN_SZ ],
                           ulong        allowlist_cnt,
                           char const * request_origin ) {
  if( FD_LIKELY( !allowlist_cnt ) ) return NULL; /* CORS disabled; do not inspect request_origin */
  for( ulong i=0UL; i<allowlist_cnt; i++ ) {
    if( FD_UNLIKELY( !strcmp( allowlist[ i ], "*" ) ) ) return "*";
  }
  if( FD_UNLIKELY( !request_origin || !request_origin[ 0 ] ) ) return NULL;
  for( ulong i=0UL; i<allowlist_cnt; i++ ) {
    if( !strcmp( allowlist[ i ], request_origin ) ) return allowlist[ i ];
  }
  return NULL;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_waltz_http_fd_http_h */
